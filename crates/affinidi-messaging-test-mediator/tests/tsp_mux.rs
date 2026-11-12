//! DID multiplexing on a **raw-TSP** socket: the `tsp-mux` subprotocol (spec
//! `messaging/mux/event`, "Raw-TSP sockets"; design §4.10).
//!
//! Most tests drive the socket directly with `tokio-tungstenite`, as
//! `tsp_websocket.rs` drives `tsp` / `tsp-ack`, to check the wire itself; the
//! rest use the SDK's `tsp-mux` client (`TspOps::connect_websocket_mux`).
//! Grants are stored through the mediator's own grant operation, as in
//! `mux_connection.rs`. Mux events arrive as TSP Direct messages from the
//! mediator's VID to the principal's. The cross-instance paths are in
//! `tsp_mux_two_instances.rs`.
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

/// A member holding `pickup` but not `receive` is told about new mail while
/// the principal is connected: the mediator raises its resync, and on raw
/// TSP the resync is a drain of that member's inbox. Before, its mail waited
/// for the next reconnect. A member with neither still gets nothing.
#[tokio::test]
async fn a_pickup_only_member_is_drained_when_new_mail_arrives() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let gym = env.add_user("gym").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &gym] {
        env.relate_directly(&sender, m).await.unwrap();
    }
    grant(&env, &work, &principal, &["pickup", "delete"]).await;
    grant(&env, &gym, &principal, &["delete"]).await;

    let (mut ws, _, token) = connect(&env, &principal, &MUX_OFFER).await;
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work, &gym]).await;
    assert_quiet(&mut ws, Duration::from_millis(500), "nothing stored yet").await;

    // Mail for both arrives while connected.
    for m in [&work, &gym] {
        env.atm
            .tsp()
            .send(&sender.profile, &m.did, b"arrived while connected")
            .await
            .expect("send");
    }
    let frame = timeout(Duration::from_secs(10), next_binary(&mut ws))
        .await
        .expect("work's mail is drained while connected");
    assert_eq!(receiver(&frame), work.did, "only the pickup member's mail");
    assert_quiet(
        &mut ws,
        Duration::from_millis(700),
        "a member with neither receive nor pickup gets nothing",
    )
    .await;

    let (deleted, _) = ack(&env, &token, &[frame]).await;
    assert_eq!(deleted.len(), 1);
    assert_eq!(inbox_len(&env, &gym).await, 1, "gym's stays stored");
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

// ─── Member lifecycle on a tsp-mux socket, through the SDK client ───────────

type SdkMux = affinidi_messaging_sdk::protocols::tsp_mux::TspMuxWebSocket;
use affinidi_messaging_sdk::protocols::tsp_mux::TspMuxFrame;

/// The next frame on the SDK socket, within 5 s.
async fn sdk_next(sock: &mut SdkMux) -> TspMuxFrame {
    timeout(Duration::from_secs(5), sock.recv())
        .await
        .expect("a frame within 5s")
        .expect("socket readable")
        .expect("socket open")
}

/// The next `event` naming `did`, as JSON, skipping data frames and other
/// events; also returns the data frames skipped on the way.
async fn sdk_event_for(
    sock: &mut SdkMux,
    event: &str,
    did: &str,
) -> (Value, Vec<(String, Vec<u8>)>) {
    let mut data = Vec::new();
    loop {
        match sdk_next(sock).await {
            TspMuxFrame::Event(e) => {
                let e = serde_json::to_value(&*e).unwrap();
                if e["event"] == event
                    && e["dids"]
                        .as_array()
                        .is_some_and(|ds| ds.iter().any(|d| d["did"] == did))
                {
                    let entry = e["dids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|d| d["did"] == did)
                        .unwrap()
                        .clone();
                    return (entry, data);
                }
            }
            TspMuxFrame::Data {
                receiver, frame, ..
            } => data.push((receiver, frame)),
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
}

/// The next data frame on the SDK socket.
async fn sdk_data(sock: &mut SdkMux) -> (String, Vec<u8>) {
    loop {
        if let TspMuxFrame::Data {
            receiver, frame, ..
        } = sdk_next(sock).await
        {
            return (receiver, frame);
        }
    }
}

/// A member's revoke and a full connection both reach the tsp-mux
/// socket as `detached` events, sealed for TSP.
#[tokio::test]
async fn revokes_and_a_full_connection_are_reported_on_a_tsp_mux_socket() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .mux_max_dids_per_connection(2)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let spare = env.add_user("spare").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    // Three grants, room for two: the connection reports the one left out.
    grant(&env, &work, &principal, &["receive", "pickup", "delete"]).await;
    grant(&env, &home, &principal, &["receive", "pickup", "delete"]).await;
    grant(&env, &spare, &principal, &["receive"]).await;

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    let mut left_out = None;
    while left_out.is_none() {
        match sdk_next(&mut sock).await {
            TspMuxFrame::Event(e) => {
                let e = serde_json::to_value(&*e).unwrap();
                if e["event"] == "detached" {
                    left_out = Some(e["dids"][0].clone());
                }
            }
            other => panic!("expected events only, got {other:?}"),
        }
    }
    let left_out = left_out.unwrap();
    assert_eq!(left_out["reason"], "connectionFull", "{left_out:#}");
    assert_eq!(sock.members().len(), 2);
    // Revoke one of the two carried.
    let home = if sock.members().is_reachable(&home.did) {
        home
    } else if sock.members().is_reachable(&work.did) && left_out["did"] == home.did {
        // `home` was the one left out: revoke `work` instead and check `spare`
        // stays out.
        work
    } else {
        home
    };

    // `home` revokes its grant; the event comes on the tsp-mux socket. (The
    // member asks, not the principal: the SDK's TSP request would wait for its
    // reply in the principal's inbox, which this socket drains first.)
    // Its request goes over its own websocket, which supersedes it here
    // first.
    env.atm
        .profile_add(&home.profile, true)
        .await
        .expect("home's own websocket");
    env.atm
        .trust_tasks()
        .mux_revoke(&home.profile, true, vec![], vec![principal.did.clone()])
        .await
        .expect("mux_revoke");
    let entry = loop {
        let (entry, _) = sdk_event_for(&mut sock, "detached", &home.did).await;
        if entry["reason"] != "superseded" {
            break entry;
        }
    };
    assert_eq!(entry["reason"], "revokedByMember", "{entry:#}");
    assert!(!sock.members().is_reachable(&home.did));
    assert_eq!(sock.members().len(), 1);
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// The member's own socket takes the DID (`superseded`); when it closes the
/// member is `reactivated` on the tsp-mux socket, and what arrived meanwhile,
/// never acknowledged, is redelivered there as TSP frames.
#[tokio::test]
async fn a_superseded_member_comes_back_with_its_mail() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    env.relate_directly(&sender, &work).await.unwrap();
    grant(&env, &work, &principal, &["receive", "pickup", "delete"]).await;

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    sdk_event_for(&mut sock, "attached", &work.did).await;

    // `work`'s own raw-TSP socket (ack mode: nothing it is sent is deleted
    // until acknowledged) outranks the mux entry.
    let (mut own, selected, _) = connect(&env, &work, &["tsp", "tsp-ack"]).await;
    assert_eq!(selected.as_deref(), Some("tsp-ack"));
    let (entry, _) = sdk_event_for(&mut sock, "detached", &work.did).await;
    assert_eq!(entry["reason"], "superseded", "{entry:#}");

    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"while superseded")
        .await
        .expect("send");
    let on_own = next_binary(&mut own).await;
    assert_eq!(receiver(&on_own), work.did, "pushed to work's own socket");

    // `work` goes; the mux entry takes the DID back and redelivers.
    own.close(None).await.ok();
    drop(own);
    let (entry, mut data) = sdk_event_for(&mut sock, "attached", &work.did).await;
    assert_eq!(entry["reason"], "reactivated", "{entry:#}");
    while data.is_empty() {
        data.push(sdk_data(&mut sock).await);
    }
    let (to, frame) = &data[0];
    assert_eq!(*to, work.did);
    assert_eq!(*frame, on_own, "the unacknowledged frame is redelivered");
    let (payload, _) = env
        .atm
        .tsp()
        .unpack_bytes(&work.profile, frame)
        .await
        .expect("work opens it");
    assert_eq!(payload, b"while superseded");

    // And new mail is pushed live again.
    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"after")
        .await
        .expect("send");
    let (to, frame) = sdk_data(&mut sock).await;
    assert_eq!(to, work.did);
    assert_ne!(frame, on_own);
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// A tsp-mux socket replaced by the principal's next one is closed with a
/// close frame only: a raw-TSP socket never gets a DIDComm Text frame.
#[tokio::test]
async fn a_replaced_tsp_mux_socket_closes_without_a_text_frame() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    relate_to_mediator(&env, &principal).await;

    let (mut first, selected, _) = connect(&env, &principal, &MUX_OFFER).await;
    assert_eq!(selected.as_deref(), Some("tsp-mux"));
    let ready = open_event(&env, &principal, &next_binary(&mut first).await).await;
    assert_eq!(ready["payload"]["event"], "ready");

    let (_second, _, _) = connect(&env, &principal, &MUX_OFFER).await;
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match first.next().await {
                None | Some(Err(_)) => return None,
                Some(Ok(Message::Close(frame))) => return Some(frame),
                Some(Ok(Message::Text(t))) => panic!("a Text frame on a raw-TSP socket: {t}"),
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .expect("the replaced socket closes");
    let frame = closed.expect("with a close frame").expect("and a reason");
    assert!(!frame.reason.is_empty(), "the close frame says why");
    env.shutdown().await.expect("shutdown");
}

/// The drain writes TSP frames only, and records as delivered only what it
/// wrote: a DIDComm message in the principal's inbox is left unstamped, for
/// a client that can read it.
#[tokio::test]
async fn the_drain_stamps_only_what_it_writes() {
    use affinidi_messaging_didcomm::message::Message as DidcommMessage;
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    env.relate_directly(&sender, &principal).await.unwrap();

    // A DIDComm message, then a TSP one, wait in the principal's inbox.
    let t = now();
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "didcomm" }),
    )
    .to(principal.did.clone())
    .from(sender.did.clone())
    .created_time(t)
    .expires_time(t + 300)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &principal.did, Some(&sender.did), Some(&sender.did))
        .await
        .unwrap();
    env.atm
        .send_message(&sender.profile, &packed, &msg.id, false, false)
        .await
        .unwrap();
    env.atm
        .tsp()
        .send(&sender.profile, &principal.did, b"tsp")
        .await
        .expect("send");

    let store = env.mediator.store();
    for m in store
        .fetch_messages("test", &principal.did_hash(), &FetchOptions::default())
        .await
        .expect("fetch")
        .success
    {
        let state = store.delivery_state(&m.msg_id).await.unwrap().unwrap();
        assert!(
            state.first_delivered_at_ms.is_none(),
            "nothing is stamped before the socket opens: {}",
            m.msg_id
        );
    }

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    let (to, _) = sdk_data(&mut sock).await;
    assert_eq!(to, principal.did, "the TSP message is drained");

    let inbox = store
        .fetch_messages("test", &principal.did_hash(), &FetchOptions::default())
        .await
        .expect("fetch");
    let mut checked = (0, 0);
    for m in inbox.success {
        let tsp = m
            .msg
            .as_deref()
            .and_then(|b| BASE64_URL_SAFE_NO_PAD.decode(b).ok())
            .is_some_and(|b| affinidi_tsp::is_tsp(&b));
        let state = store
            .delivery_state(&m.msg_id)
            .await
            .expect("delivery state")
            .expect("exists");
        if tsp {
            assert!(
                state.first_delivered_at_ms.is_some(),
                "the written frame is stamped"
            );
            checked.0 += 1;
        } else {
            assert!(
                state.first_delivered_at_ms.is_none(),
                "a DIDComm message the drain skipped is not stamped"
            );
            checked.1 += 1;
        }
    }
    assert_eq!(checked, (1, 1), "one of each");
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// The `messaging/mux/notice` in a frame from the mediator to `principal`,
/// if it is one.
async fn notice_in(env: &TestEnvironment, principal: &TestUser, frame: &[u8]) -> Option<Value> {
    if receiver(frame) != principal.did {
        return None;
    }
    let (payload, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&principal.profile, frame)
        .await
        .ok()?;
    if sender != env.mediator.did() {
        return None;
    }
    let doc: Value = serde_json::from_slice(&payload).ok()?;
    (doc["type"] == "https://trusttasks.org/spec/messaging/mux/notice/0.1").then_some(doc)
}

/// The next notice on the SDK socket, skipping events and other frames.
async fn sdk_notice(env: &TestEnvironment, principal: &TestUser, sock: &mut SdkMux) -> Value {
    loop {
        match sdk_next(sock).await {
            // The SDK opens and verifies a notice itself; the frame it came in
            // is still sealed for the principal over TSP.
            TspMuxFrame::Notice { notice, frame } => {
                assert!(
                    notice_in(env, principal, &frame).await.is_some(),
                    "a TSP frame from the mediator, to the principal"
                );
                return serde_json::to_value(&*notice).expect("notice as JSON");
            }
            TspMuxFrame::Data { frame, .. } => assert!(
                notice_in(env, principal, &frame).await.is_none(),
                "the SDK hands a notice over as a notice"
            ),
            _ => {}
        }
    }
}

/// A notice reaches a principal on the wire it uses. One stored while the
/// principal's wire was unknown (DIDComm) is re-issued as TSP when the
/// principal opens a `tsp-mux` connection, and the DIDComm copy goes; one
/// stored once the principal is known to use TSP is sealed for TSP at once.
#[tokio::test]
async fn notices_reach_a_tsp_principal_sealed_for_tsp() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    grant(&env, &work, &principal, &["receive"]).await;
    grant(&env, &home, &principal, &["receive"]).await;

    // `home` revokes while the principal is offline: a `grantsRevoked`
    // notice, stored for DIDComm (the principal's wire is not known yet).
    env.atm
        .profile_add(&home.profile, true)
        .await
        .expect("home's own websocket");
    env.atm
        .trust_tasks()
        .mux_revoke(&home.profile, true, vec![], vec![principal.did.clone()])
        .await
        .expect("home revokes");

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    assert_eq!(sock.ready().pending_notices, Some(1), "{:?}", sock.ready());
    let notice = sdk_notice(&env, &principal, &mut sock).await;
    assert_eq!(notice["payload"]["notice"], "grantsRevoked", "{notice:#}");
    assert_eq!(notice["payload"]["revocations"][0]["did"], home.did);

    // One copy left in the inbox, in TSP form.
    let store = env.mediator.store();
    let bodies: Vec<String> = store
        .fetch_messages("test", &principal.did_hash(), &FetchOptions::default())
        .await
        .expect("fetch")
        .success
        .into_iter()
        .filter_map(|m| m.msg)
        .collect();
    assert_eq!(bodies.len(), 1, "the DIDComm copy is gone");
    assert!(
        BASE64_URL_SAFE_NO_PAD
            .decode(&bodies[0])
            .is_ok_and(|b| affinidi_tsp::is_tsp(&b)),
        "the copy left is TSP"
    );

    // `work` revokes while the principal is connected over TSP: sealed for
    // TSP from the start.
    env.atm
        .profile_add(&work.profile, true)
        .await
        .expect("work's own websocket");
    env.atm
        .trust_tasks()
        .mux_revoke(&work.profile, true, vec![], vec![principal.did.clone()])
        .await
        .expect("work revokes");
    let notice = sdk_notice(&env, &principal, &mut sock).await;
    assert_eq!(notice["payload"]["notice"], "grantsRevoked", "{notice:#}");
    assert_eq!(notice["payload"]["revocations"][0]["did"], work.did);
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

// ─── messaging/mux/ack on the socket ────────────────────────────────────────

const ACK_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/ack/0.1";

/// The id `messaging/mux/ack` names a frame by.
fn frame_message_id(qb2: &[u8]) -> String {
    sha256::digest(BASE64_URL_SAFE_NO_PAD.encode(qb2))
}

/// Send `messaging/mux/ack` for `ids` on the socket as `principal`, and
/// return the answer's document, read off the socket. Frames read on the way
/// are returned too.
async fn ack_on_socket(
    env: &TestEnvironment,
    principal: &TestUser,
    ws: &mut Ws,
    ids: &[String],
) -> (Value, Vec<Vec<u8>>) {
    let request_id = format!("urn:uuid:{}", Uuid::new_v4());
    let doc = json!({
        "id": request_id,
        "type": ACK_TYPE,
        "issuer": principal.did,
        "recipient": env.mediator.did(),
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "messageIds": ids },
    });
    let frame = env
        .atm
        .tsp()
        .pack(
            &principal.profile,
            env.mediator.did(),
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("pack the ack");
    ws.send(Message::Binary(frame.into()))
        .await
        .expect("write the ack");
    let mut others = Vec::new();
    loop {
        let f = next_binary(ws).await;
        if receiver(&f) == principal.did
            && let Ok((payload, sender)) = env.atm.tsp().unpack_bytes(&principal.profile, &f).await
            && sender == env.mediator.did()
            && let Ok(answer) = serde_json::from_slice::<Value>(&payload)
            && answer["threadId"] == request_id
        {
            return (answer, others);
        }
        others.push(f);
    }
}

/// `messaging/mux/ack` on a tsp-mux socket deletes the principal's own frame
/// and a member's with `delete`, refuses a member's without it
/// (`notPermitted`) and an id nobody here holds (`notFound`), and its answer
/// comes on the socket without being stored. A member carried only to send
/// is not told apart: its message is `notFound`, though the principal knows
/// the id, as the sender of a message would.
#[tokio::test]
async fn acks_on_the_socket_follow_each_members_delete_scope() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let outbox = env.add_user("outbox").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &home, &principal, &outbox] {
        env.relate_directly(&sender, m).await.unwrap();
    }
    grant(&env, &work, &principal, &["receive", "delete"]).await;
    grant(&env, &home, &principal, &["receive"]).await;
    grant(&env, &outbox, &principal, &["send"]).await;

    let (mut ws, _, _) = connect(&env, &principal, &MUX_OFFER).await;
    expect_ready_and_attached(&env, &mut ws, &principal, &[&work, &home, &outbox]).await;

    // Mail for the send-only member is not delivered here; its id is known
    // all the same (read from the member's own inbox, as its sender could
    // compute it).
    env.atm
        .tsp()
        .send(&sender.profile, &outbox.did, b"not yours")
        .await
        .expect("send");
    let outbox_id = timeout(Duration::from_secs(5), async {
        loop {
            let listed = env
                .atm
                .fetch_messages(&outbox.profile, &FetchOptions::default())
                .await
                .expect("fetch");
            if let Some(m) = listed.success.first() {
                return m.msg_id.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("stored for the send-only member");

    let mut frames = std::collections::HashMap::new();
    for to in [&principal, &work, &home] {
        env.atm
            .tsp()
            .send(&sender.profile, &to.did, b"ack me")
            .await
            .expect("send");
        let f = next_binary(&mut ws).await;
        frames.insert(receiver(&f), f);
    }
    let id = |u: &TestUser| frame_message_id(&frames[&u.did]);
    let unknown = sha256::digest("no such message");
    let (answer, _) = ack_on_socket(
        &env,
        &principal,
        &mut ws,
        &[
            id(&principal),
            id(&work),
            id(&home),
            unknown.clone(),
            outbox_id.clone(),
        ],
    )
    .await;
    assert_eq!(answer["type"], format!("{ACK_TYPE}#response"), "{answer:#}");
    use affinidi_messaging_mediator::task_specs::messaging::mux::ack::v0_1::Response;
    serde_json::from_value::<Response>(answer["payload"].clone())
        .unwrap_or_else(|e| panic!("the answer does not match the spec: {e}\n{answer:#}"));
    let mut acked: Vec<String> = answer["payload"]["acked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    acked.sort();
    let mut want = vec![id(&principal), id(&work)];
    want.sort();
    assert_eq!(acked, want);
    let refused: Vec<(String, String)> = answer["payload"]["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["messageId"].as_str().unwrap().to_string(),
                r["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        refused.contains(&(id(&home), "notPermitted".into())),
        "{refused:?}"
    );
    assert!(
        refused.contains(&(unknown, "notFound".into())),
        "{refused:?}"
    );
    assert!(
        refused.contains(&(outbox_id, "notFound".into())),
        "a send-only member's mail is not confirmed: {refused:?}"
    );

    assert_eq!(
        inbox_len(&env, &principal).await,
        0,
        "deleted, and the answer is not stored"
    );
    assert_eq!(inbox_len(&env, &work).await, 0, "deleted with `delete`");
    assert_eq!(inbox_len(&env, &home).await, 1, "kept without `delete`");
    assert_eq!(inbox_len(&env, &outbox).await, 1, "kept, never shown here");

    // Asking again changes nothing.
    let (answer, _) = ack_on_socket(&env, &principal, &mut ws, &[id(&work)]).await;
    assert_eq!(answer["payload"]["refused"][0]["reason"], "notFound");
    env.shutdown().await.expect("shutdown");
}

/// Not on a mux connection, the ack is refused (`notMuxConnection`). A plain
/// `tsp-ack` socket reports a refused frame by closing, as it always has; only
/// `tsp-mux` reports refusals in band.
#[tokio::test]
async fn an_ack_off_a_mux_connection_is_refused() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    let (mut ws, selected, _) = connect(&env, &principal, &["tsp", "tsp-ack"]).await;
    assert_eq!(selected.as_deref(), Some("tsp-ack"));
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": ACK_TYPE,
        "issuer": principal.did,
        "recipient": env.mediator.did(),
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "messageIds": [sha256::digest("x")] },
    });
    let frame = env
        .atm
        .tsp()
        .pack(
            &principal.profile,
            env.mediator.did(),
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("pack the ack");
    ws.send(Message::Binary(frame.into())).await.expect("write");
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(f))) => return f,
                Some(Ok(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .expect("refused");
    assert!(
        closed.is_some_and(|f| f.code
            == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy)
    );
    env.shutdown().await.expect("shutdown");
}

/// Fair queuing on a raw-TSP mux socket (design §7.2 "Back-pressure", §10
/// "Fairness"), as `mux_fair_queue.rs` shows it for DIDComm: the principal
/// stops reading while one member (`busy`) is sent far more live frames than
/// the socket buffers hold, so the writer stalls and `busy`'s share of the
/// send queue fills. A frame for a second member (`quiet`) then arrives. When
/// the principal reads again, `quiet`'s frame arrives live, promptly, and not
/// behind the whole of `busy`'s backlog.
///
/// On raw TSP the resync for `busy`'s dropped pushes is a drain of `busy`'s
/// inbox (`drain_tsp_inbox`). The drain stops between pages whenever live
/// frames are waiting, so `quiet`'s frame goes first; before that it ran to
/// completion (up to 1000 frames) with `quiet`'s frame queued behind it.
#[tokio::test]
async fn a_flooded_member_does_not_starve_another_on_a_tsp_mux_socket() {
    use std::time::Instant;
    const FLOOD: usize = 80;
    const FLOOD_BYTES: usize = 256 * 1024;
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .queue_send_limit_per_peer(-1)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let busy = env.add_user("busy").await.unwrap();
    let quiet = env.add_user("quiet").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&busy, &quiet] {
        env.relate_directly(&sender, m).await.unwrap();
        grant(&env, m, &principal, &["receive", "pickup", "delete"]).await;
    }

    let (mut ws, selected, _) = connect(&env, &principal, &MUX_OFFER).await;
    assert_eq!(selected.as_deref(), Some("tsp-mux"));
    expect_ready_and_attached(&env, &mut ws, &principal, &[&busy, &quiet]).await;

    // Stop reading, and flood the busy member.
    let filler = "x".repeat(FLOOD_BYTES);
    for i in 0..FLOOD {
        env.atm
            .tsp()
            .send(
                &sender.profile,
                &busy.did,
                format!("{i}:{filler}").as_bytes(),
            )
            .await
            .expect("send to busy");
    }
    // Let the streaming task push (and drop) the flood before the quiet
    // member's frame arrives behind it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    env.atm
        .tsp()
        .send(&sender.profile, &quiet.did, b"for quiet")
        .await
        .expect("send to quiet");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Read again, recording each frame's receiver in order, until idle.
    let resumed = Instant::now();
    let mut seen: Vec<char> = Vec::new();
    let mut quiet_after = None;
    while let Ok(Some(frame)) = timeout(Duration::from_secs(3), ws.next()).await {
        let Message::Binary(b) = frame.expect("frame") else {
            continue;
        };
        let to = receiver(&b);
        seen.push(if to == busy.did {
            'B'
        } else if to == quiet.did {
            quiet_after.get_or_insert(resumed.elapsed());
            'Q'
        } else {
            '?'
        });
    }
    let summary: String = seen.iter().collect();
    let busy_seen = seen.iter().filter(|c| **c == 'B').count();
    assert!(
        busy_seen > 1,
        "the flood must reach the socket for this test to mean anything: {summary}"
    );

    // The quiet member's frame arrived live, promptly...
    let quiet_at = seen
        .iter()
        .position(|c| *c == 'Q')
        .unwrap_or_else(|| panic!("the quiet member's frame never arrived: {summary}"));
    assert!(
        quiet_after.is_some_and(|d| d < Duration::from_secs(5)),
        "the quiet member's frame took {quiet_after:?}: {summary}"
    );
    // ...and not behind the busy member's whole backlog: busy frames were
    // still queued behind it.
    assert!(
        seen[quiet_at..].contains(&'B'),
        "the quiet member's frame waited out the busy member's whole queue: {summary}"
    );
    // ...and the drain, cut short for it, resumed: every busy frame arrived,
    // once each.
    assert_eq!(
        busy_seen, FLOOD,
        "the busy member's backlog must be delivered in full, without repeats: {summary}"
    );
    env.shutdown().await.expect("shutdown");
}
