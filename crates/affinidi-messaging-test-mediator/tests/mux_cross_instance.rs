//! DID multiplexing across mediator instances sharing one Redis (design
//! §7.4): a grant change handled by another instance reaches this one's live
//! mux connections over the store's pub/sub channel, within moments rather
//! than at the 30-second periodic re-check.
//!
//! "Instance A" is a second `RedisStore` on the same database doing what a
//! second mediator's handler does: commit the change, then publish a
//! `MuxChangeRecord`. The mediator under test is instance B, holding the
//! principal's mux socket.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test mux_cross_instance
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_mediator::mux::{
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{
    store::{
        MediatorStore,
        mux::{self, MuxChange, MuxChangeRecord, MuxGrant, MuxLimits},
    },
    types::acls::MediatorACLSet,
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

/// A logical DB no other test-mediator test uses.
const DB: u8 = 12;

async fn redis_store(flush: bool) -> Option<Arc<dyn MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP mux_cross_instance: REDIS_URL not set");
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `member` grants `principal` receive + pickup, stored in `store` as the
/// `messaging/mux/grant` task would store it.
async fn grant(
    env: &TestEnvironment,
    store: &dyn MediatorStore,
    member: &TestUser,
    principal: &TestUser,
) -> MuxGrant {
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
            "scope": ["receive", "pickup"],
            "epoch": 0,
            "iat": t,
            "exp": t + 3600,
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign grant");

    let verifier = StatementVerifier::new(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap(),
    );
    let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
    let ctx = Ctx {
        store,
        verifier: &verifier,
        mediator_did: env.mediator.did(),
        limits: MuxLimits::default(),
        default_acl: &acl,
        now: now(),
    };
    store_grant(&ctx, &member.did, &statement)
        .await
        .unwrap_or_else(|e| panic!("store grant: {e}"))
        .grant
}

/// The next `messaging/mux/event` payload on the socket.
async fn next_event<S>(env: &TestEnvironment, ws: &mut S, within: Duration) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let frame = match timeout(within, ws.next())
            .await
            .expect("an event in time")
            .expect("socket open")
            .expect("frame")
        {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };
        let (msg, _) = env.atm.unpack(&frame).await.expect("unpack event");
        return msg.body["payload"].clone();
    }
}

#[tokio::test]
async fn changes_on_another_instance_reach_this_ones_connections() {
    init_tracing();
    let Some(store_b) = redis_store(true).await else {
        return;
    };
    let store_a = redis_store(false).await.unwrap();

    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_b)
        .spawn()
        .await
        .expect("spawn mediator with mux on redis");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate principal");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("upgrade");
    assert_eq!(
        next_event(&env, &mut ws, Duration::from_secs(5)).await["event"],
        "ready"
    );

    // Well inside the 30 s periodic re-check: only the pub/sub path is fast
    // enough to meet it.
    let quick = Duration::from_secs(3);
    let publish = |changes: Vec<MuxChange>| {
        let store_a = store_a.clone();
        async move {
            store_a
                .mux_changes_publish(&MuxChangeRecord {
                    origin: "instance-a".into(),
                    changes,
                })
                .await
                .expect("publish");
        }
    };

    // A grant stored on instance A is carried on B's live connection.
    let g = grant(&env, &*store_a, &work, &principal).await;
    publish(vec![MuxChange::of(&g, true)]).await;
    let attached = next_event(&env, &mut ws, quick).await;
    assert_eq!(attached["event"], "attached", "{attached:#}");
    assert_eq!(attached["dids"][0]["did"], work.did.as_str());

    // Suspended on instance A (the unknown-key rule): B drops the member.
    let t = now();
    let suspended = mux::modify(
        &*store_a,
        &work.did_hash(),
        &MuxLimits::default(),
        t,
        None,
        |rec, _| {
            Ok(mux::suspend_unless_known_kid(
                rec,
                "did:example:new-controller#key-1",
                t,
            ))
        },
    )
    .await
    .expect("suspend");
    assert_eq!(suspended.len(), 1);
    publish(vec![MuxChange::of(&g, false)]).await;
    let detached = next_event(&env, &mut ws, quick).await;
    assert_eq!(detached["event"], "detached", "{detached:#}");
    assert_eq!(detached["dids"][0]["did"], work.did.as_str());
    assert_eq!(detached["dids"][0]["reason"], "suspendedUnknownKey");
}
