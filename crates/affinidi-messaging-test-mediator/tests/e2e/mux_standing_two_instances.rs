//! A mux member's account change made on one instance reaches the
//! principal's connection on another within one pub/sub hop, not at that
//! instance's next standing pass: an administrator blocks the member through
//! instance A, and the principal's connection on instance B detaches it.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test e2e -- mux_standing_two_instances::
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

use crate::common;

use std::time::Duration;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::{
    protocols::mux::{MuxCapability, sign_grant},
    tasks::messaging::account::update::v0_2::MediatorAcl,
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::Value;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

/// A logical DB no other test-mediator test uses.
const DB: u8 = 14;

const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

/// What arrived on the principal's socket, unpacked.
enum Frame {
    /// A `messaging/mux/event` payload.
    Event(Value),
    /// Anything else.
    Other,
}

async fn next_frame<S>(env: &TestEnvironment, ws: &mut S, within: Duration) -> Option<Frame>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let frame = match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(f) => f.expect("socket open").expect("frame"),
        };
        let Message::Text(t) = frame else { continue };
        let (msg, _) = env.atm.unpack(t.as_str()).await.expect("unpack");
        if msg.body["type"] == EVENT_TYPE {
            return Some(Frame::Event(msg.body["payload"].clone()));
        }
        return Some(Frame::Other);
    }
}

/// The next mux event, skipping other frames.
async fn next_event<S>(env: &TestEnvironment, ws: &mut S, within: Duration) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match next_frame(env, ws, left).await {
            Some(Frame::Event(e)) => return e,
            Some(Frame::Other) => continue,
            None => panic!("no mux event within {within:?}"),
        }
    }
}

#[tokio::test]
async fn blocking_a_member_on_one_instance_detaches_it_on_another() {
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
    let b_ws: Uri = b.ws_endpoint().as_str().parse().unwrap();

    let env = TestEnvironment::new(a).await.expect("env");
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let admin = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin websocket on A");
    let mediator_did = env.mediator.did().to_string();

    // `work` grants the device through A while the device's mux socket is
    // open on B.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(device.did.clone(), mediator_did.clone(), 3, None)
        .await
        .expect("authenticate through A");
    let request = ClientRequestBuilder::new(b_ws)
        .with_sub_protocol("didcomm-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("B accepts A's token");
    let quick = Duration::from_secs(5);
    assert_eq!(next_event(&env, &mut ws, quick).await["event"], "ready");
    let (g, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .profile_add(&work.profile, true)
        .await
        .expect("work's websocket on A");
    env.atm
        .trust_tasks()
        .mux_grant(&work.profile, vec![g])
        .await
        .expect("grant");
    work.profile.stop_websocket().await.expect("stop work");
    loop {
        let e = next_event(&env, &mut ws, quick).await;
        if e["event"] == "attached" && e["dids"][0]["did"] == work.did.as_str() {
            break;
        }
    }

    // Blocked through A: B's connection drops it within moments, far inside
    // its 30-second standing pass.
    let blocked: MediatorAcl = MediatorAcl::builder()
        .blocked(Some(true))
        .try_into()
        .expect("MediatorAcl has no required member");
    env.atm
        .trust_tasks()
        .account_update(
            &admin.profile,
            Some(work.did_hash()),
            None,
            Some(blocked),
            None,
        )
        .await
        .expect("admin blocks work on A");
    let reason = loop {
        let e = next_event(&env, &mut ws, quick).await;
        if e["event"] == "detached"
            && let Some(d) = e["dids"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["did"] == work.did.as_str())
        {
            break d["reason"].clone();
        }
    };
    assert_eq!(reason, "accountBlocked");
}
