//! Mux membership monitor events across two instances of one mediator
//! sharing one Redis database: an administrator subscribed on instance A
//! sees a member attach to a principal's connection on instance B, once,
//! and a change on A's own connection once too (A does not hear its own
//! event back from the channel).
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test e2e -- monitor_membership_two_instances::
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

use crate::common;

use std::time::Duration;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

/// A logical DB no other cross-instance test uses.
const DB: u8 = 9;

const SUBSCRIBE_V0_2: &str = "https://trusttasks.org/spec/messaging/monitor/subscribe/0.2";
const EVENT_V0_3: &str = "https://trusttasks.org/spec/messaging/monitor/event/0.3";
const MUX_EVENT: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

/// Send one Trust Task document by hand as `user` and return the reply body.
async fn send_raw_task(
    env: &TestEnvironment,
    user: &TestUser,
    type_uri: &str,
    payload: Value,
) -> Value {
    use affinidi_messaging_didcomm::message::Message;
    use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
    use affinidi_messaging_sdk::transports::SendMessageResponse;

    let mediator_did = env.mediator.did().to_string();
    let now = chrono::Utc::now();
    let task = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": user.did,
        "recipient": mediator_did,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    let secs = now.timestamp() as u64;
    let msg = Message::build(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        task,
    )
    .to(mediator_did.clone())
    .from(user.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&user.did), None)
        .await
        .expect("authcrypt the task");
    match env
        .atm
        .send_message(&user.profile, &packed, &msg_id, true, true)
        .await
    {
        Ok(SendMessageResponse::Message(reply)) => reply.body,
        Ok(other) => panic!("expected a response message, got {other:?}"),
        Err(e) => panic!("subscribe refused: {e:?}"),
    }
}

/// `member` grants `principal` receive, stored through A from the member's
/// own socket there, which it then closes so the grant is what carries it.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) {
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &principal.did,
        env.mediator.did(),
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .expect("sign grant");
    env.atm
        .profile_add(&member.profile, true)
        .await
        .expect("member websocket on A");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&member.profile, vec![g])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    member
        .profile
        .stop_websocket()
        .await
        .expect("stop member websocket");
}

/// The batch payloads of subscription `sub` reaching `user`'s live stream
/// until `done` holds over their membership events, or `deadline` passes.
async fn batches_until(
    env: &TestEnvironment,
    user: &TestUser,
    sub: &Value,
    deadline: Duration,
    done: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let mut seen: Vec<Value> = Vec::new();
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until && !done(&membership_of(&seen)) {
        let Some((message, _)) = env
            .atm
            .message_pickup()
            .live_stream_next(&user.profile, Some(Duration::from_millis(500)), false)
            .await
            .expect("live stream")
        else {
            continue;
        };
        if message.body["type"] == EVENT_V0_3 && message.body["payload"]["subscriptionId"] == *sub {
            seen.push(message.body["payload"].clone());
        }
    }
    seen
}

/// The membership events across `batches`.
fn membership_of(batches: &[Value]) -> Vec<Value> {
    batches
        .iter()
        .flat_map(|b| b["membership"].as_array().cloned().unwrap_or_default())
        .collect()
}

fn attached<'a>(events: &'a [Value], member: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|e| e["change"] == "attached" && e["member"] == member)
        .collect()
}

#[tokio::test]
async fn a_monitor_on_one_instance_sees_members_attach_on_another() {
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
    let admin = env.add_user("admin").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin websocket on A");
    let remote_principal = env.add_user("remote-principal").await.unwrap();
    let remote_member = env.add_user("remote-member").await.unwrap();
    let local_principal = env.add_user("local-principal").await.unwrap();
    let local_member = env.add_user("local-member").await.unwrap();

    // The administrator opts in on A, for the two members only.
    let body = send_raw_task(
        &env,
        &admin,
        SUBSCRIBE_V0_2,
        json!({
            "membership": { "dids": [remote_member.did_hash(), local_member.did_hash()] },
            "traffic": false,
            "leaseSeconds": 120,
        }),
    )
    .await;
    assert_eq!(body["type"], format!("{SUBSCRIBE_V0_2}#response"), "{body}");
    let sub = body["payload"]["subscriptionId"].clone();
    // Stored before either principal connects: each connection carries its
    // grant on connect (`attached`, reason `connect`).
    grant(&env, &remote_member, &remote_principal).await;
    grant(&env, &local_member, &local_principal).await;

    // The remote principal authenticates through A and opens its mux socket
    // on B with that token. A announced its subscriber when it opened, but
    // nothing here can see when B heard it, so the connect is repeated (a
    // fresh connection, a fresh `attached`) until A reports one, within a
    // bounded deadline. Each connection's event must arrive at most once.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            remote_principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate through A");
    let remote_hash = remote_member.did_hash();
    let local_hash = local_member.did_hash();
    let deadline = tokio::time::Instant::now() + common::EVENT_WAIT;
    let mut batches = Vec::new();
    let mut attempts = 0;
    let _ws = loop {
        attempts += 1;
        let request = ClientRequestBuilder::new(b_ws.clone())
            .with_sub_protocol("didcomm-mux")
            .with_sub_protocol(format!("bearer.{}", tokens.access_token));
        let (mut ws, _) = connect_async(request).await.expect("B accepts A's token");
        timeout(Duration::from_secs(10), async {
            loop {
                let Some(Ok(Message::Text(t))) = ws.next().await else {
                    panic!("socket closed before ready");
                };
                let (msg, _) = env.atm.unpack(t.as_str()).await.expect("unpack");
                if msg.body["type"] == MUX_EVENT && msg.body["payload"]["event"] == "ready" {
                    break;
                }
            }
        })
        .await
        .expect("ready on B");
        batches.extend(
            batches_until(&env, &admin, &sub, Duration::from_secs(3), |e| {
                !attached(e, &remote_hash).is_empty()
            })
            .await,
        );
        if !attached(&membership_of(&batches), &remote_hash).is_empty() {
            break ws;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no attach on B reached A's monitor in {attempts} connections"
        );
        let _ = ws.close(None).await;
    };

    // The local principal connects to A.
    env.atm
        .profile_enable_mux_websocket(&local_principal.profile)
        .await
        .expect("mux websocket on A");
    batches.extend(
        batches_until(&env, &admin, &sub, common::EVENT_WAIT, |e| {
            !attached(e, &local_hash).is_empty()
        })
        .await,
    );
    // Anything still in flight, to count duplicates.
    batches.extend(batches_until(&env, &admin, &sub, Duration::from_secs(3), |_| false).await);
    let events = membership_of(&batches);

    let remote = attached(&events, &remote_hash);
    let mut sessions: Vec<&str> = remote
        .iter()
        .map(|e| e["sessionId"].as_str().expect("sessionId"))
        .collect();
    let seen = sessions.len();
    sessions.sort();
    sessions.dedup();
    assert_eq!(
        sessions.len(),
        seen,
        "each of B's connections seen on A once: {events:#?}"
    );
    assert!(
        seen <= attempts,
        "{seen} events from {attempts} connections"
    );
    for e in &remote {
        assert_eq!(e["principal"], remote_principal.did_hash().as_str());
        assert_eq!(e["reason"], "connect", "{e}");
        assert_eq!(e["wire"], "didcomm");
        assert_eq!(e["source"], "grant");
        assert!(e["occurredAt"].is_string(), "{e}");
    }
    // The batch that brought B's event came while the fan-out was up, so
    // it does not claim this-instance-only coverage.
    let carrying = batches
        .iter()
        .find(|b| !attached(&membership_of(std::slice::from_ref(b)), &remote_hash).is_empty())
        .unwrap();
    assert!(carrying.get("ext").is_none(), "{carrying:#}");

    assert_eq!(
        attached(&events, &local_hash).len(),
        1,
        "A's own change seen once, not again from the channel: {events:#?}"
    );
}
