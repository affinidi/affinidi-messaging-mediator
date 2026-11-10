//! DID multiplexing on a **raw-TSP** socket: the `tsp-mux` subprotocol (spec
//! `messaging/mux/event`, "Raw-TSP sockets"; design §4.10).
//!
//! The SDK has no `tsp-mux` client, so the socket is driven directly with
//! `tokio-tungstenite`, as `tsp_websocket.rs` drives `tsp` / `tsp-ack`. Grants
//! are stored through the mediator's own grant operation, as in
//! `mux_connection.rs`. Mux events arrive as TSP Direct messages from the
//! mediator's VID to the principal's, which the principal unpacks with the
//! SDK.
#![cfg(feature = "tsp")]

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_mediator::mux::{
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{store::mux::MuxLimits, types::acls::MediatorACLSet};
use affinidi_messaging_sdk::{messages::fetch::FetchOptions, protocols::tsp::RelationshipState};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use common::init_tracing;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn mux_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

/// `member` grants `principal` `scope`, stored as `messaging/mux/grant` would.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser, scope: &[&str]) {
    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .expect("member's Ed25519 authentication key");
    let t = now();
    let statement = sign_trust_task(
        &json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(),
            "principal": principal.did,
            "scope": scope,
            "epoch": 0,
            "iat": t,
            "exp": t + 3600,
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign grant");
    let store = env.mediator.store();
    let verifier = StatementVerifier::new(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap(),
    );
    let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
    let ctx = Ctx {
        store: &*store,
        verifier: &verifier,
        mediator_did: env.mediator.did(),
        limits: MuxLimits::default(),
        default_acl: &acl,
        now: now(),
    };
    store_grant(&ctx, &member.did, &statement)
        .await
        .unwrap_or_else(|e| panic!("store grant: {e}"));
}

/// Open a raw socket for `user` offering `protocols` (after the bearer entry),
/// returning it, the selected subprotocol and the access token.
async fn connect(
    env: &TestEnvironment,
    user: &TestUser,
    protocols: &[&str],
) -> (Ws, Option<String>, String) {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let mut request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    for p in protocols {
        request = request.with_sub_protocol(*p);
    }
    let (ws, response) = connect_async(request).await.expect("upgrade");
    let selected = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (ws, selected, tokens.access_token)
}

/// The client's offer, in the order the spec requires.
const MUX_OFFER: [&str; 3] = ["tsp", "tsp-ack", "tsp-mux"];

/// The next Binary frame, skipping pings; panics on a close.
async fn next_binary(ws: &mut Ws) -> Vec<u8> {
    loop {
        match timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5s")
            .expect("socket open")
            .expect("frame")
        {
            Message::Binary(b) => return b.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a Binary TSP frame, got {other:?}"),
        }
    }
}

/// Nothing but pings for `wait`.
async fn assert_quiet(ws: &mut Ws, wait: Duration, why: &str) {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(other) => panic!("{why}: got {other:?}"),
        }
    }
}

/// The TSP receiver a frame names in the clear.
fn receiver(qb2: &[u8]) -> String {
    affinidi_tsp::MetaEnvelope::parse(qb2)
        .expect("a TSP envelope")
        .receiver
}

/// A TSP client that talks to its mediator holds a relationship with it
/// (§7.2.2); seeded here rather than handshaken, as `trust_tasks_transport.rs`
/// does.
async fn relate_to_mediator(env: &TestEnvironment, user: &TestUser) {
    let mediator = env.mediator.did().to_string();
    for (ours, theirs) in [(&user.did, &mediator), (&mediator, &user.did)] {
        env.relationship_store
            .set(ours, theirs, RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship with the mediator");
    }
}

/// Unpack a mux event sealed to `principal`, check it came from the mediator
/// and matches the spec's generated type, and return the document.
async fn open_event(env: &TestEnvironment, principal: &TestUser, qb2: &[u8]) -> Value {
    assert_eq!(receiver(qb2), principal.did, "events go to the principal");
    let (payload, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&principal.profile, qb2)
        .await
        .expect("principal unpacks the mux event");
    assert_eq!(sender, env.mediator.did(), "events come from the mediator");
    let doc: Value = serde_json::from_slice(&payload).expect("event is JSON");
    use affinidi_messaging_mediator::task_specs::messaging::mux::event::v0_1::Payload;
    serde_json::from_value::<trust_tasks_rs::TrustTask<Payload>>(doc.clone())
        .unwrap_or_else(|e| panic!("mux/event does not match the spec: {e}\n{doc:#}"));
    doc
}

/// `ready`, then `attached` naming exactly `members`.
async fn expect_ready_and_attached(
    env: &TestEnvironment,
    ws: &mut Ws,
    principal: &TestUser,
    members: &[&TestUser],
) {
    let ready = open_event(env, principal, &next_binary(ws).await).await;
    assert_eq!(
        ready["payload"]["event"], "ready",
        "`ready` is the first frame"
    );
    assert!(
        ready["payload"]["muxNonce"]
            .as_str()
            .is_some_and(|n| !n.is_empty())
    );
    let attached = open_event(env, principal, &next_binary(ws).await).await;
    assert_eq!(attached["payload"]["event"], "attached");
    let mut dids: Vec<String> = attached["payload"]["dids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["did"].as_str().unwrap().to_string())
        .collect();
    dids.sort();
    let mut want: Vec<String> = members.iter().map(|m| m.did.clone()).collect();
    want.sort();
    assert_eq!(dids, want, "attached names the granted members");
}

/// Acknowledge frames as a `tsp-ack` client does: delete by the SHA-256 of
/// the stored body (base64url of the frame), over REST with the socket's
/// token. Returns (deleted, refused) ids.
async fn ack(env: &TestEnvironment, token: &str, frames: &[Vec<u8>]) -> (Vec<String>, Vec<String>) {
    let ids: Vec<String> = frames
        .iter()
        .map(|f| sha256::digest(BASE64_URL_SAFE_NO_PAD.encode(f)))
        .collect();
    let resp: Value = reqwest::Client::new()
        .delete(env.mediator.endpoint().join("delete").unwrap())
        .bearer_auth(token)
        .json(&json!({ "message_ids": ids }))
        .send()
        .await
        .expect("delete request")
        .json()
        .await
        .expect("delete response");
    let success = resp["data"]["success"]
        .as_array()
        .unwrap_or_else(|| panic!("unexpected delete response: {resp:#}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let errors = resp["data"]["errors"]
        .as_array()
        .map(|es| {
            es.iter()
                .map(|e| e[0].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default();
    (success, errors)
}

/// How many TSP messages wait in `user`'s inbox. Only TSP: a member that
/// authenticates directly is also sent a durable mux notice, which is not
/// what these tests count.
async fn inbox_len(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .expect("fetch")
        .success
        .iter()
        .filter(|m| {
            m.msg
                .as_deref()
                .and_then(|b| BASE64_URL_SAFE_NO_PAD.decode(b).ok())
                .is_some_and(|b| affinidi_tsp::is_tsp(&b))
        })
        .count()
}

#[tokio::test]
async fn tsp_mux_is_selected_only_when_mux_is_enabled() {
    init_tracing();

    // Enabled: `tsp-mux` is selected though the client lists it last.
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let (_ws, selected, _) = connect(&env, &principal, &MUX_OFFER).await;
    assert_eq!(selected.as_deref(), Some("tsp-mux"));
    env.shutdown().await.expect("shutdown");

    // Disabled: the client is told mux is unavailable, never that it is on.
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn without mux");
    let principal = env.add_user("device").await.unwrap();
    let (_ws, selected, _) = connect(&env, &principal, &MUX_OFFER).await;
    assert_eq!(
        selected.as_deref(),
        Some("tsp-ack"),
        "mux off: delete-to-ack, without mux"
    );
    let (_ws, selected, _) = connect(&env, &principal, &["tsp", "tsp-mux"]).await;
    assert_eq!(
        selected.as_deref(),
        Some("tsp"),
        "mux off: a `tsp-mux` offer is not reflected back"
    );
    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn one_tsp_mux_socket_carries_live_delivery_for_every_granted_did() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &home] {
        env.relate_directly(&sender, m).await.unwrap();
        grant(&env, m, &principal, &["receive", "pickup", "delete"]).await;
    }

    let (mut ws, selected, token) = connect(&env, &principal, &MUX_OFFER).await;
    assert_eq!(selected.as_deref(), Some("tsp-mux"));
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work, &home]).await;

    // Live frames for each member arrive untagged; the receiver routes them.
    for (m, text) in [(&work, "for work"), (&home, "for home")] {
        env.atm
            .tsp()
            .send(&sender.profile, &m.did, text.as_bytes())
            .await
            .expect("sender sends");
    }
    let frames = [next_binary(&mut ws).await, next_binary(&mut ws).await];
    let mut got: Vec<String> = frames.iter().map(|f| receiver(f)).collect();
    got.sort();
    let mut want = vec![work.did.clone(), home.did.clone()];
    want.sort();
    assert_eq!(got, want, "one frame for each member");
    for f in &frames {
        let m = if receiver(f) == work.did {
            &work
        } else {
            &home
        };
        let (payload, from) = env
            .atm
            .tsp()
            .unpack_bytes(&m.profile, f)
            .await
            .expect("member unpacks its frame");
        assert_eq!(from, sender.did);
        assert_eq!(
            payload,
            if m.did == work.did {
                b"for work".to_vec()
            } else {
                b"for home".to_vec()
            }
        );
    }

    // `tsp-mux` implies `tsp-ack`: delivered, still held until acked.
    assert_eq!(inbox_len(&env, &work).await, 1, "kept until acked");
    let (deleted, refused) = ack(&env, &token, &frames).await;
    assert_eq!(deleted.len(), 2, "members with `delete` are acked");
    assert!(refused.is_empty());

    // A DID that granted nothing is not carried.
    let stranger = env.add_user("stranger").await.unwrap();
    env.relate_directly(&sender, &stranger).await.unwrap();
    env.atm
        .tsp()
        .send(&sender.profile, &stranger.did, b"not yours")
        .await
        .expect("send to stranger");
    assert_quiet(
        &mut ws,
        Duration::from_millis(500),
        "nothing for a non-member reaches the principal",
    )
    .await;
    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn a_refused_frame_is_reported_in_band_and_the_socket_stays_open() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    env.relate_directly(&sender, &work).await.unwrap();
    grant(&env, &work, &principal, &["receive", "pickup", "delete"]).await;

    let (mut ws, _, _) = connect(&env, &principal, &MUX_OFFER).await;
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work]).await;

    // A frame whose sender is neither the principal nor a member: refused by
    // the session binding.
    let bad = env
        .atm
        .tsp()
        .pack(&sender.profile, &work.did, b"not the principal's to send")
        .await
        .expect("pack");
    ws.send(Message::Binary(bad.clone().into()))
        .await
        .expect("write the frame");

    let refused = open_event(&env, &principal, &next_binary(&mut ws).await).await;
    let p = &refused["payload"];
    assert_eq!(p["event"], "refused");
    assert_eq!(
        p["frameId"],
        sha256::digest(&bad[..]),
        "frameId is the SHA-256 of the frame's exact bytes"
    );
    assert!(p["code"].as_str().is_some_and(|c| !c.is_empty()));
    assert_eq!(p["sender"], sender.did);
    assert_eq!(p["receiver"], work.did);

    // Still open, and still delivering.
    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"after the refusal")
        .await
        .expect("send");
    let frame = next_binary(&mut ws).await;
    assert_eq!(receiver(&frame), work.did);

    // The same frame on a plain `tsp-ack` socket closes it, as before.
    let (mut plain, selected, _) = connect(&env, &principal, &["tsp", "tsp-ack"]).await;
    assert_eq!(selected.as_deref(), Some("tsp-ack"));
    plain
        .send(Message::Binary(bad.into()))
        .await
        .expect("write");
    let closed = loop {
        match timeout(Duration::from_secs(5), plain.next())
            .await
            .expect("a frame within 5s")
        {
            Some(Ok(Message::Close(frame))) => break frame,
            Some(Ok(_)) => continue,
            other => panic!("expected a close, got {other:?}"),
        }
    };
    assert_eq!(
        closed.map(|c| u16::from(c.code)),
        Some(1008),
        "plain tsp-ack keeps close-on-refuse"
    );
    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn the_drain_honours_pickup_and_acks_honour_delete() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    // Drained and deletable; drained but not deletable; neither.
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let gym = env.add_user("gym").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &home, &gym] {
        env.relate_directly(&sender, m).await.unwrap();
    }
    // No `receive`, so only the drain can deliver these.
    grant(&env, &work, &principal, &["pickup", "delete"]).await;
    grant(&env, &home, &principal, &["pickup"]).await;
    grant(&env, &gym, &principal, &["delete"]).await;

    // Stored before the principal connects.
    for m in [&work, &home, &gym] {
        for i in 0..2 {
            env.atm
                .tsp()
                .send(&sender.profile, &m.did, format!("stored {i}").as_bytes())
                .await
                .expect("send");
        }
    }

    let (mut ws, _, token) = connect(&env, &principal, &MUX_OFFER).await;
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work, &home, &gym]).await;

    let mut frames = Vec::new();
    for _ in 0..4 {
        frames.push(next_binary(&mut ws).await);
    }
    assert_quiet(
        &mut ws,
        Duration::from_millis(700),
        "a member without `pickup` is not drained",
    )
    .await;
    let count = |did: &str| frames.iter().filter(|f| receiver(f) == did).count();
    assert_eq!(count(&work.did), 2, "work has pickup");
    assert_eq!(count(&home.did), 2, "home has pickup");
    assert_eq!(count(&gym.did), 0, "gym has no pickup");

    // Acks are authorised against the owning member's `delete`.
    let (deleted, refused) = ack(&env, &token, &frames).await;
    assert_eq!(deleted.len(), 2, "work's frames are deleted");
    assert_eq!(refused.len(), 2, "home's frames are not");
    assert_eq!(inbox_len(&env, &work).await, 0);
    assert_eq!(
        inbox_len(&env, &home).await,
        2,
        "without `delete`, frames stay in the member's inbox"
    );
    assert_eq!(inbox_len(&env, &gym).await, 2, "gym's were never sent");

    // Un-acked frames are not sent again on the same connection.
    assert_quiet(
        &mut ws,
        Duration::from_millis(500),
        "no redelivery within a connection",
    )
    .await;
    env.shutdown().await.expect("shutdown");
}

/// The `send` scope works on a raw-TSP mux socket too: a frame whose sender
/// is a member granting `send` is accepted on the principal's socket (no
/// `refused` event) and reaches its recipient as the member's.
#[tokio::test]
async fn a_member_with_send_sends_on_the_tsp_mux_socket() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let peer = env.add_user("peer").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    env.relate_directly(&work, &peer).await.unwrap();
    grant(&env, &work, &principal, &["receive", "send"]).await;

    let (mut ws, _, _) = connect(&env, &principal, &MUX_OFFER).await;
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work]).await;

    let frame = env
        .atm
        .tsp()
        .pack(&work.profile, &peer.did, b"sent by work via the principal")
        .await
        .expect("pack as the member");
    ws.send(Message::Binary(frame.into()))
        .await
        .expect("write the frame");
    assert_quiet(
        &mut ws,
        Duration::from_millis(500),
        "a member with `send` is not refused",
    )
    .await;

    let stored = env
        .atm
        .fetch_messages(&peer.profile, &FetchOptions::default())
        .await
        .expect("fetch")
        .success;
    let body = stored
        .iter()
        .filter_map(|m| m.msg.as_deref())
        .find(|b| {
            BASE64_URL_SAFE_NO_PAD
                .decode(b)
                .is_ok_and(|q| affinidi_tsp::is_tsp(&q))
        })
        .expect("the member's frame reached its recipient");
    let (payload, from) = env
        .atm
        .tsp()
        .unpack(&peer.profile, body)
        .await
        .expect("peer unpacks");
    assert_eq!(from, work.did);
    assert_eq!(payload, b"sent by work via the principal");
    env.shutdown().await.expect("shutdown");
}

/// The SDK's `tsp-mux` client (affinidi-messaging-sdk 0.45.4) against this
/// mediator, end to end: negotiation and `ready`, typed `attached` events,
/// member frames tagged with their receiver, per-member ack results, and an
/// in-band `refused` event matched to the frame id `send` returned.
#[tokio::test]
async fn the_sdk_client_drives_a_tsp_mux_connection() {
    use affinidi_messaging_sdk::protocols::{
        mux::MuxRefused,
        tsp_mux::{TspMuxFrame, frame_id},
    };
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &home] {
        env.relate_directly(&sender, m).await.unwrap();
    }
    grant(&env, &work, &principal, &["receive", "pickup", "delete"]).await;
    grant(&env, &home, &principal, &["receive", "pickup"]).await;

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("the SDK opens a tsp-mux connection");
    assert_eq!(sock.ready().mux_nonce.len(), 43, "ready came first");
    assert_eq!(sock.principal(), principal.did);

    let next = async |sock: &mut affinidi_messaging_sdk::protocols::tsp_mux::TspMuxWebSocket| {
        timeout(Duration::from_secs(5), sock.recv())
            .await
            .expect("a frame within 5s")
            .expect("socket readable")
            .expect("socket open")
    };

    // `attached` for both members, typed.
    let attached = match next(&mut sock).await {
        TspMuxFrame::Event(e) => serde_json::to_value(&*e).unwrap(),
        other => panic!("expected the attached event, got {other:?}"),
    };
    assert_eq!(attached["event"], "attached");
    let mut dids: Vec<String> = attached["dids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["did"].as_str().unwrap().to_string())
        .collect();
    dids.sort();
    let mut want = vec![work.did.clone(), home.did.clone()];
    want.sort();
    assert_eq!(dids, want);

    // Member frames come back unopened, tagged with their receiver.
    for (m, text) in [(&work, "for work"), (&home, "for home")] {
        env.atm
            .tsp()
            .send(&sender.profile, &m.did, text.as_bytes())
            .await
            .expect("sender sends");
    }
    let mut frames = Vec::new();
    for _ in 0..2 {
        match next(&mut sock).await {
            TspMuxFrame::Data {
                receiver, frame, ..
            } => frames.push((receiver, frame)),
            other => panic!("expected a member frame, got {other:?}"),
        }
    }
    for (to, frame) in &frames {
        let m = if *to == work.did { &work } else { &home };
        assert_eq!(*to, m.did);
        let (payload, from) = env
            .atm
            .tsp()
            .unpack_bytes(&m.profile, frame)
            .await
            .expect("the member opens its own frame");
        assert_eq!(from, sender.did);
        assert_eq!(
            payload,
            if m.did == work.did {
                b"for work".to_vec()
            } else {
                b"for home".to_vec()
            }
        );
    }

    // Acks report exactly what the mediator did: work has `delete`, home not.
    let refs: Vec<&[u8]> = frames.iter().map(|(_, f)| f.as_slice()).collect();
    let acked = sock.ack(&refs).await.expect("ack request");
    assert_eq!(acked.acked.len(), 1, "{acked:?}");
    assert_eq!(acked.refused.len(), 1, "{acked:?}");
    assert!(!acked.is_complete());
    assert_eq!(inbox_len(&env, &work).await, 0);
    assert_eq!(inbox_len(&env, &home).await, 1, "kept without `delete`");

    // A frame the session may not send is refused in-band; the event names
    // the id `send` returned, and the socket stays open.
    let bad = env
        .atm
        .tsp()
        .pack(&sender.profile, &work.did, b"not the principal's to send")
        .await
        .expect("pack");
    let id = sock.send(&bad).await.expect("write the frame");
    assert_eq!(id, frame_id(&bad));
    let refused = match next(&mut sock).await {
        TspMuxFrame::Event(e) => MuxRefused::from_event(&e).expect("a refused event"),
        other => panic!("expected the refused event, got {other:?}"),
    };
    assert_eq!(refused.frame_id, id);
    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"after the refusal")
        .await
        .expect("send");
    match next(&mut sock).await {
        TspMuxFrame::Data { receiver, .. } => assert_eq!(receiver, work.did),
        other => panic!("expected a member frame, got {other:?}"),
    }
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}
