//! DID multiplexing across two instances of one mediator, each a full
//! mediator with its own server, streaming task and Redis connections,
//! sharing one Redis database, one DID and one session-token key, as two
//! replicas behind a load balancer do.
//!
//! The principal authenticates through the endpoint the mediator's DID
//! advertises (instance A) and opens its mux socket on instance B with that
//! token. A member grants, sends and revokes through A. Each change must
//! reach the principal's connection on B: through B's real handlers and A's
//! real publish, not a hand-written store write.
//!
//! `mux_cross_instance.rs` plays instance A with a bare `RedisStore`; this
//! test runs both.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test mux_two_instances
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message as DidcommMessage;
use affinidi_messaging_mediator_common::store::MediatorStore;
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
use uuid::Uuid;

/// A logical DB no other test-mediator test uses.
const DB: u8 = 13;

const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";
const BASIC: &str = "https://didcomm.org/basicmessage/2.0/message";

/// One instance's own connection to the shared database.
async fn redis_store(flush: bool) -> Option<Arc<dyn MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP mux_two_instances: REDIS_URL not set");
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
        // CI's cluster job runs this against a cluster-mode server too.
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

/// What arrived on the principal's socket, unpacked.
enum Frame {
    /// A `messaging/mux/event` payload.
    Event(Value),
    /// Anything else, with the DID it was encrypted to.
    Message(Box<DidcommMessage>, Option<String>),
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
        let (msg, meta) = env.atm.unpack(t.as_str()).await.expect("unpack");
        if msg.body["type"] == EVENT_TYPE {
            return Some(Frame::Event(msg.body["payload"].clone()));
        }
        let to = affinidi_messaging_sdk::protocols::mux::mux_recipient(&meta);
        return Some(Frame::Message(Box::new(msg), to));
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
            Some(Frame::Message(..)) => continue,
            None => panic!("no mux event within {within:?}"),
        }
    }
}

/// `member` runs `f` over its own websocket to instance A (the endpoint
/// the mediator's DID advertises), then goes offline again so its own
/// socket does not take its live traffic from the principal's connection.
async fn as_member_on_a<T, F>(env: &TestEnvironment, member: &TestUser, f: F) -> T
where
    F: AsyncFnOnce() -> T,
{
    env.atm
        .profile_add(&member.profile, true)
        .await
        .expect("member websocket on A");
    let out = f().await;
    member
        .profile
        .stop_websocket()
        .await
        .expect("stop member websocket");
    out
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        BASIC.to_string(),
        json!({ "content": text }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .unwrap();
    env.atm
        .send_message(&from.profile, &packed, &msg.id, false, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_member_on_one_instance_reaches_a_principal_on_another() {
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
    assert_eq!(a.did(), b.did(), "one mediator");
    assert_ne!(a.bound_addr(), b.bound_addr(), "two instances");
    let b_ws: Uri = b.ws_endpoint().as_str().parse().unwrap();

    let env = TestEnvironment::new(a).await.expect("env");
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    // Authenticated through A; the socket is opened on B with A's token.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(device.did.clone(), mediator_did.clone(), 3, None)
        .await
        .expect("authenticate through A");
    let request = ClientRequestBuilder::new(b_ws)
        .with_sub_protocol("didcomm-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, response) = connect_async(request).await.expect("B accepts A's token");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("didcomm-mux")
    );
    assert_eq!(
        next_event(&env, &mut ws, Duration::from_secs(5)).await["event"],
        "ready"
    );

    // 1. `work` grants the device through A, from its own socket there. B's
    //    connection takes the member, well inside the 30 s periodic
    //    re-check (over A's publish), but inactive: `work`'s own socket on
    //    A outranks a mux entry on B, as it would on one instance. The grant
    //    reply reaches that socket; before cross-instance precedence it went
    //    to B's connection and the request timed out.
    let (g, grant_id) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive, MuxCapability::Delete],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .profile_add(&work.profile, true)
        .await
        .expect("work's own websocket on A");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&work.profile, vec![g])
        .await
        .expect("the grant reply reaches work's own socket");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    let quick = Duration::from_secs(5);
    let entry = |e: &Value| e["dids"][0].clone();
    let mut granted = None;
    let inactive = loop {
        let e = next_event(&env, &mut ws, quick).await;
        if e["event"] != "attached" || entry(&e)["did"] != work.did.as_str() {
            continue;
        }
        granted.get_or_insert(entry(&e));
        if entry(&e)["deliveryActive"] == false {
            break entry(&e);
        }
    };
    assert_eq!(granted.unwrap()["grantId"], grant_id.as_str());
    assert_eq!(inactive["grantId"], grant_id.as_str());

    // An administrator asking instance A (where its own socket goes) is
    // told the answer covers that instance only: the device's connection is
    // on B, so A lists nothing and must not pass that off as the whole
    // mediator's view.
    {
        use affinidi_messaging_mediator_common::types::accounts::AccountType;
        use affinidi_messaging_sdk::protocols::trust_tasks::MuxConnectionsQuery;
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
        let page = env
            .atm
            .trust_tasks()
            .mux_connections(&admin.profile, &MuxConnectionsQuery::all())
            .await
            .expect("mux_connections on A");
        let page = serde_json::to_value(&page).unwrap();
        assert_eq!(page["coverage"], "thisInstance", "{page:#}");
        assert_eq!(
            page["connections"],
            json!([]),
            "B's connection is not A's to list"
        );
    }

    // 2. While `work`'s own socket is up, its mail goes there, not to B.
    send(&env, &sender, &work, "to work's own socket").await;
    let own = timeout(quick, async {
        loop {
            let (m, _) = env
                .atm
                .message_pickup()
                // Acknowledged (deleted), as a client does once it has a
                // message; otherwise B redelivers it on reactivation.
                .live_stream_next(&work.profile, Some(quick), true)
                .await
                .expect("live stream")
                .expect("a message on work's own socket");
            if m.typ == BASIC {
                return m;
            }
        }
    })
    .await
    .expect("work's own socket gets its message");
    assert_eq!(own.body["content"], "to work's own socket");
    let on_b = timeout(Duration::from_millis(800), async {
        loop {
            match next_frame(&env, &mut ws, Duration::from_millis(800)).await {
                Some(Frame::Message(m, _)) if m.typ == BASIC => return Some(m),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();
    assert!(on_b.is_none(), "an inactive member is not pushed: {on_b:?}");

    // 3. `work`'s own socket closes: A releases the DID, and B takes it back.
    work.profile
        .stop_websocket()
        .await
        .expect("stop work's websocket");
    let back = loop {
        let e = next_event(&env, &mut ws, quick).await;
        if e["event"] == "attached"
            && entry(&e)["did"] == work.did.as_str()
            && entry(&e)["reason"] == "reactivated"
        {
            break entry(&e);
        }
    };
    assert_eq!(back["deliveryActive"], true);

    // 4. Now a message for `work`, stored through A, is pushed live on B.
    send(&env, &sender, &work, "via A, to B").await;
    let pushed = timeout(quick, async {
        loop {
            match next_frame(&env, &mut ws, quick).await {
                Some(Frame::Message(m, to)) if m.typ == BASIC => return (m, to),
                Some(_) => continue,
                None => panic!("no push on B"),
            }
        }
    })
    .await
    .expect("work's message reaches B's connection");
    assert_eq!(pushed.0.body["content"], "via A, to B");
    assert_eq!(pushed.1.as_deref(), Some(work.did.as_str()));

    // 5. `work` revokes through A (its socket there takes the DID from B for
    //    the moment: `superseded`). B detaches it, and pushes stop.
    as_member_on_a(&env, &work, async || {
        env.atm
            .trust_tasks()
            .mux_revoke(&work.profile, true, vec![], vec![device.did.clone()])
            .await
            .expect("mux_revoke on A")
    })
    .await;
    let detached = loop {
        let e = next_event(&env, &mut ws, quick).await;
        if e["event"] == "detached"
            && e["dids"][0]["did"] == work.did.as_str()
            && e["dids"][0]["reason"] != "superseded"
        {
            break e;
        }
    };
    assert_eq!(detached["dids"][0]["reason"], "revokedByMember");
    send(&env, &sender, &work, "after revoke").await;
    let after = timeout(Duration::from_millis(1500), async {
        loop {
            match next_frame(&env, &mut ws, Duration::from_millis(1500)).await {
                Some(Frame::Message(m, _)) if m.typ == BASIC => return Some(m),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();
    assert!(
        after.is_none(),
        "a revoked member's message must not reach B's connection: {after:?}"
    );
    b.shutdown();
}
