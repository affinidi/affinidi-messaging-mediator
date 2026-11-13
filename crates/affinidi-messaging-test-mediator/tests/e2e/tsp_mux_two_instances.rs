//! DID multiplexing on a raw-TSP socket (`tsp-mux`) across two instances of
//! one mediator sharing one Redis database, as two replicas behind a load
//! balancer.
//!
//! The principal's `tsp-mux` socket is on instance B; the member's mail and
//! its own socket go through instance A. Each change must reach B's socket as
//! a TSP frame:
//!
//! 1. a member's message stored through A is pushed on B, live;
//! 2. the member's own raw-TSP socket on A takes the DID: B reports it
//!    `superseded`, and the member's mail goes to its own socket;
//! 3. that socket closes: B reports the member `reactivated` and redelivers,
//!    as a TSP frame, what arrived meanwhile, without sending again what it
//!    already sent on this connection;
//! 4. the principal acknowledges the member's frames with
//!    `messaging/mux/ack` on its socket on B, and they are deleted there. A
//!    REST delete may land on an instance that does not hold the connection,
//!    and so cannot see its members.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend,tsp --test e2e -- tsp_mux_two_instances::
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(all(feature = "redis-backend", feature = "tsp"))]

use crate::common;
use crate::common::store_grant as grant;

use std::time::Duration;

use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
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
use uuid::Uuid;

/// A logical DB no other test-mediator test uses.
const DB: u8 = 15;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A raw socket on `ws_uri` for `user`, authenticated through instance A,
/// offering `protocols`; returns it and the selected subprotocol.
async fn connect(
    env: &TestEnvironment,
    user: &TestUser,
    ws_uri: Uri,
    protocols: &[&str],
) -> (Ws, Option<String>) {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
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
    (ws, selected)
}

/// The next Binary frame, skipping pings; panics on a close or a Text frame.
async fn next_binary(ws: &mut Ws) -> Vec<u8> {
    loop {
        match timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("a frame within 10s")
            .expect("socket open")
            .expect("frame")
        {
            Message::Binary(b) => return b.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a Binary TSP frame, got {other:?}"),
        }
    }
}

fn receiver(qb2: &[u8]) -> String {
    affinidi_tsp::MetaEnvelope::parse(qb2)
        .expect("a TSP envelope")
        .receiver
}

async fn relate_to_mediator(env: &TestEnvironment, user: &TestUser) {
    let mediator = env.mediator.did().to_string();
    for (ours, theirs) in [(&user.did, &mediator), (&mediator, &user.did)] {
        env.relationship_store
            .set(ours, theirs, RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship with the mediator");
    }
}

/// The payload of a mux event sealed to `principal`.
async fn open_event(env: &TestEnvironment, principal: &TestUser, qb2: &[u8]) -> Value {
    let (payload, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&principal.profile, qb2)
        .await
        .expect("principal unpacks the mux event");
    assert_eq!(sender, env.mediator.did(), "events come from the mediator");
    let doc: Value = serde_json::from_slice(&payload).expect("event is JSON");
    doc["payload"].clone()
}

/// Read frames until an `event` naming `did` whose entry `matches`; returns
/// the entry and the member frames read on the way.
async fn event_for(
    env: &TestEnvironment,
    ws: &mut Ws,
    principal: &TestUser,
    event: &str,
    did: &str,
    matches: impl Fn(&Value) -> bool,
) -> (Value, Vec<Vec<u8>>) {
    let mut data = Vec::new();
    loop {
        let frame = next_binary(ws).await;
        if receiver(&frame) != principal.did {
            data.push(frame);
            continue;
        }
        let e = open_event(env, principal, &frame).await;
        if e["event"] != event {
            continue;
        }
        if let Some(entry) = e["dids"]
            .as_array()
            .and_then(|ds| ds.iter().find(|d| d["did"] == did))
            && matches(entry)
        {
            return (entry.clone(), data);
        }
    }
}

#[tokio::test]
async fn a_tsp_mux_socket_on_one_instance_follows_a_member_on_another() {
    init_tracing();
    let Some(store_a) = common::redis_store(DB, true).await else {
        return;
    };
    let store_b = common::redis_store(DB, false).await.unwrap();
    let a = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_a)
        .spawn()
        .await
        .expect("instance A");
    let b = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_b)
        .replica_of(a.replica_identity())
        .spawn()
        .await
        .expect("instance B");
    let a_ws: Uri = a.ws_endpoint().as_str().parse().unwrap();
    let b_ws: Uri = b.ws_endpoint().as_str().parse().unwrap();

    let env = TestEnvironment::new(a).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    env.relate_directly(&sender, &work).await.unwrap();
    grant(&env, &work, &principal, &["receive", "pickup", "delete"]).await;

    let (mut ws, selected) = connect(&env, &principal, b_ws, &["tsp", "tsp-ack", "tsp-mux"]).await;
    assert_eq!(selected.as_deref(), Some("tsp-mux"));
    let ready = open_event(&env, &principal, &next_binary(&mut ws).await).await;
    assert_eq!(ready["event"], "ready");
    event_for(&env, &mut ws, &principal, "attached", &work.did, |_| true).await;

    // 1. Stored through A, pushed on B.
    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"via A, to B")
        .await
        .expect("send");
    let frame = next_binary(&mut ws).await;
    assert_eq!(receiver(&frame), work.did);
    let (payload, _) = env
        .atm
        .tsp()
        .unpack_bytes(&work.profile, &frame)
        .await
        .expect("work opens it");
    assert_eq!(payload, b"via A, to B");

    // 2. `work`'s own socket on A takes the DID; B's entry stands by.
    let (mut own, selected) = connect(&env, &work, a_ws, &["tsp", "tsp-ack"]).await;
    assert_eq!(selected.as_deref(), Some("tsp-ack"));
    event_for(&env, &mut ws, &principal, "detached", &work.did, |e| {
        e["reason"] == "superseded"
    })
    .await;
    env.atm
        .tsp()
        .send(&sender.profile, &work.did, b"while superseded")
        .await
        .expect("send");
    // `work`'s own socket gets its inbox (the first message was never
    // acknowledged) and the new one.
    let mut on_own = Vec::new();
    while on_own.len() < 2 {
        let f = next_binary(&mut own).await;
        assert_eq!(receiver(&f), work.did);
        if !on_own.contains(&f) {
            on_own.push(f);
        }
    }

    // 3. It goes: B takes the DID back and redelivers what this connection
    //    has not had. The first message is still unacknowledged, but B sent it
    //    on this connection already, so it is not sent again here.
    own.close(None).await.ok();
    drop(own);
    let (_, mut data) = event_for(&env, &mut ws, &principal, "attached", &work.did, |e| {
        e["reason"] == "reactivated"
    })
    .await;
    let missed = on_own
        .iter()
        .find(|f| **f != frame)
        .expect("the message sent while superseded")
        .clone();
    while !data.contains(&missed) {
        let f = next_binary(&mut ws).await;
        if receiver(&f) == work.did {
            data.push(f);
        }
    }
    assert!(!data.contains(&frame), "not sent twice on one connection");
    let (payload, _) = env
        .atm
        .tsp()
        .unpack_bytes(&work.profile, &missed)
        .await
        .expect("work opens it");
    assert_eq!(payload, b"while superseded");

    // 4. Acknowledged on the socket on B.
    let ids: Vec<String> = [&frame, &missed]
        .iter()
        .map(|f| sha256::digest(BASE64_URL_SAFE_NO_PAD.encode(f)))
        .collect();
    let request_id = format!("urn:uuid:{}", Uuid::new_v4());
    let doc = json!({
        "id": request_id,
        "type": "https://trusttasks.org/spec/messaging/mux/ack/0.1",
        "issuer": principal.did,
        "recipient": env.mediator.did(),
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "messageIds": ids },
    });
    let ack = env
        .atm
        .tsp()
        .pack(
            &principal.profile,
            env.mediator.did(),
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("pack the ack");
    ws.send(Message::Binary(ack.into()))
        .await
        .expect("write the ack");
    let answer = loop {
        let f = next_binary(&mut ws).await;
        if receiver(&f) != principal.did {
            continue;
        }
        let (payload, _) = env
            .atm
            .tsp()
            .unpack_bytes(&principal.profile, &f)
            .await
            .expect("unpack");
        let doc: Value = serde_json::from_slice(&payload).unwrap();
        if doc["threadId"] == request_id {
            break doc;
        }
    };
    let mut acked: Vec<String> = answer["payload"]["acked"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer:#}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    acked.sort();
    let mut want = ids.clone();
    want.sort();
    assert_eq!(acked, want, "{answer:#}");
    for id in &ids {
        assert!(
            env.mediator
                .store()
                .delivery_state(&work.did_hash(), id)
                .await
                .unwrap()
                .is_none(),
            "deleted"
        );
    }
    env.shutdown().await.expect("shutdown");
}
