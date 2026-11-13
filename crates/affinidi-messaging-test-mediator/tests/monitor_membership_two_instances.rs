//! Mux membership monitor events across two instances of one mediator
//! sharing one Redis database: an administrator subscribed on instance A
//! sees a member attach to a principal's connection on instance B, once,
//! and a change on A's own connection once too (A does not hear its own
//! event back from the channel).
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test monitor_membership_two_instances
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator_common::{store::MediatorStore, types::accounts::AccountType};
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

/// One instance's own connection to the shared database.
async fn redis_store(flush: bool) -> Option<Arc<dyn MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP monitor_membership_two_instances: REDIS_URL not set");
            return None;
        }
    };
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../affinidi-messaging-mediator/conf/atm-functions.lua"
            )
            .to_string(),
        ),
        database_url: format!("{}/{DB}", base.trim_end_matches('/')),
        database_timeout: 2,
        cluster_mode: std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true"),
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };
    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL");
    let store = RedisStore::new(handler, 5, 10, config.functions_file.clone());
    if flush {
        let mut conn = store.get_connection().await.expect("redis connection");
        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .expect("FLUSHDB");
    }
    Some(Arc::new(store))
}

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

/// The membership events of subscription `sub` reaching `user`'s live
/// stream until `done` holds over them, or `deadline` passes.
async fn membership_until(
    env: &TestEnvironment,
    user: &TestUser,
    sub: &Value,
    deadline: Duration,
    done: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let mut seen = Vec::new();
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until && !done(&seen) {
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
            seen.extend(
                message.body["payload"]["membership"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
        }
    }
    seen
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
    let Some(store_a) = redis_store(true).await else {
        return;
    };
    let store_b = redis_store(false).await.unwrap();

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
    // A announces its subscriber at once; give the announcement the moment
    // it takes to reach B (well inside B's 10 s beacon period).
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Stored before either principal connects: each connection carries its
    // grant on connect (`attached`, reason `connect`).
    grant(&env, &remote_member, &remote_principal).await;
    grant(&env, &local_member, &local_principal).await;

    // The remote principal authenticates through A and opens its mux socket
    // on B with that token.
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
    let request = ClientRequestBuilder::new(b_ws)
        .with_sub_protocol("didcomm-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("B accepts A's token");
    timeout(Duration::from_secs(5), async {
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

    // The local principal connects to A.
    env.atm
        .profile_enable_mux_websocket(&local_principal.profile)
        .await
        .expect("mux websocket on A");

    let remote_hash = remote_member.did_hash();
    let local_hash = local_member.did_hash();
    let mut events = membership_until(&env, &admin, &sub, common::EVENT_WAIT, |e| {
        !attached(e, &remote_hash).is_empty() && !attached(e, &local_hash).is_empty()
    })
    .await;
    // Anything still in flight, to count duplicates.
    events.extend(membership_until(&env, &admin, &sub, Duration::from_secs(3), |_| false).await);

    let remote = attached(&events, &remote_hash);
    assert_eq!(remote.len(), 1, "B's change seen on A, once: {events:#?}");
    let remote = remote[0];
    assert_eq!(remote["principal"], remote_principal.did_hash().as_str());
    assert_eq!(remote["reason"], "connect", "{remote}");
    assert_eq!(remote["wire"], "didcomm");
    assert_eq!(remote["source"], "grant");
    assert!(remote["sessionId"].is_string(), "{remote}");
    assert!(remote["occurredAt"].is_string(), "{remote}");

    assert_eq!(
        attached(&events, &local_hash).len(),
        1,
        "A's own change seen once, not again from the channel: {events:#?}"
    );
    drop(ws);
}
