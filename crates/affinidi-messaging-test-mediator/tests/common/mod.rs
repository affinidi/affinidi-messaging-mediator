//! Shared helpers for the e2e integration tests.
//!
//! Compiled into the `e2e` binary and into each test binary that keeps a
//! process of its own, none of which uses every helper.
#![allow(dead_code)]
// The mediator serves the 0.1 `messaging/*` tasks these helpers read, which
// `trust-tasks-rs` 0.35 marks superseded (dtgwg-trust-tasks-tf#921).
#![allow(deprecated)]

use std::sync::Once;

static TRACING_INIT: Once = Once::new();

/// Install a single `tracing_subscriber` for all tests in the process.
/// `RUST_LOG` controls the level; default is `warn`. Idempotent — safe
/// to call from every test.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_test_writer()
            .try_init();
    });
}

/// How long to wait for a monitor event that should arrive. Generous on
/// purpose: [`await_monitor_event`] returns on the first match, so this only
/// matters on a loaded runner, where 10 s was not always enough.
pub const EVENT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read the admin's live stream until a monitor batch shows an event matching
/// `wanted`, or `deadline` passes.
pub async fn await_monitor_event(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    watcher: &affinidi_messaging_test_mediator::TestUser,
    wanted: impl Fn(&serde_json::Value) -> bool,
    deadline: std::time::Duration,
) -> Option<serde_json::Value> {
    use affinidi_messaging_sdk::protocols::trust_tasks::decode_monitor_event;
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until {
        let next = env
            .atm
            .message_pickup()
            .live_stream_next(
                &watcher.profile,
                Some(std::time::Duration::from_millis(500)),
                false,
            )
            .await
            .expect("live stream");
        let Some((message, _)) = next else { continue };
        let Some(batch) = decode_monitor_event(&message) else {
            continue;
        };
        assert!(
            batch.proof.is_some(),
            "every monitor batch is signed by the mediator"
        );
        for event in &batch.payload.events {
            let event = serde_json::to_value(event).unwrap();
            assert!(
                event.get("message").is_none(),
                "metadata only, never a body"
            );
            if wanted(&event) {
                return Some(event);
            }
        }
    }
    None
}

/// Seconds since the Unix epoch, by the system clock.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

/// A DIDComm basic message from `from` to `to` carrying `text`.
pub fn basic_message(from: &str, to: &str, text: &str) -> affinidi_messaging_didcomm::Message {
    affinidi_messaging_didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        serde_json::json!({ "content": text }),
    )
    .to(to.to_string())
    .from(from.to_string())
    .finalize()
}

/// `member` grants `principal` exactly `scope`, stored in `env`'s mediator
/// as the `messaging/mux/grant` task would store it. Signed with the
/// member's `#key-1`, valid for an hour.
pub async fn store_grant(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    member: &affinidi_messaging_test_mediator::TestUser,
    principal: &affinidi_messaging_test_mediator::TestUser,
    scope: &[&str],
) {
    let store = env.mediator.store();
    store_grant_in(env, &*store, member, principal, scope).await;
}

/// [`store_grant`] into `store`, which need not be `env`'s own (another
/// instance's connection to a shared database). Returns the stored grant.
pub async fn store_grant_in(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    store: &dyn affinidi_messaging_mediator_common::store::MediatorStore,
    member: &affinidi_messaging_test_mediator::TestUser,
    principal: &affinidi_messaging_test_mediator::TestUser,
    scope: &[&str],
) -> affinidi_messaging_mediator_common::store::mux::MuxGrant {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_messaging_mediator::mux::{
        grants::{Ctx, store_grant},
        proof::StatementVerifier,
    };
    use affinidi_messaging_mediator_common::{store::mux::MuxLimits, types::acls::MediatorACLSet};
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .expect("member's Ed25519 authentication key");
    let t = now();
    let statement = sign_trust_task(
        &serde_json::json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": uuid::Uuid::new_v4().to_string(),
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

/// Poll `check` every 50 ms until it returns `Some`, or `deadline` passes.
///
/// For waiting on something a test can observe, in place of a fixed sleep:
/// it returns as soon as the condition holds, and only a loaded runner ever
/// waits out the deadline.
pub async fn poll_until<T, F, Fut>(deadline: std::time::Duration, mut check: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let until = tokio::time::Instant::now() + deadline;
    loop {
        if let Some(value) = check().await {
            return Some(value);
        }
        if tokio::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// How many messages `user`'s mailbox holds, by a plain fetch.
pub async fn inbox_len(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    user: &affinidi_messaging_test_mediator::TestUser,
) -> usize {
    env.atm
        .fetch_messages(
            &user.profile,
            &affinidi_messaging_sdk::messages::fetch::FetchOptions::default(),
        )
        .await
        .expect("fetch mailbox")
        .success
        .len()
}

/// Authenticate `user` against the mediator and return a fresh access token
/// plus the `ws://…/ws` upgrade URI (the same shape a browser would use).
pub async fn token_and_ws_uri(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    user: &affinidi_messaging_test_mediator::TestUser,
) -> (String, tokio_tungstenite::tungstenite::http::Uri) {
    let mediator_did = env.mediator.did().to_string();
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), mediator_did, 3, None)
        .await
        .expect("authenticate user");
    let ws_uri = env
        .mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");
    (tokens.access_token, ws_uri)
}

/// Wait until the mediator has a websocket registered for `did` with its
/// streaming task — with live delivery switched on when `live` — and
/// panic after 10 s. Replaces "give the socket a moment" sleeps.
pub async fn await_streaming(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    did: &str,
    live: bool,
) {
    let store = env.mediator.store();
    let did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(did);
    poll_until(std::time::Duration::from_secs(10), || {
        let store = store.clone();
        let did_hash = did_hash.clone();
        async move { store.streaming_is_client_live(&did_hash, !live).await }
    })
    .await
    .unwrap_or_else(|| panic!("{did} never registered for streaming"));
}

/// A Redis store on logical DB `db` of the server `REDIS_URL` names, or
/// `None` when it is unset (the caller skips). `flush` empties the DB first.
///
/// Tests in one binary run in parallel, so no two may share a `db`: each
/// flushes its own. `REDIS_CLUSTER_MODE=true` selects cluster mode, which
/// CI's Valkey-cluster job sets.
#[cfg(feature = "redis-backend")]
pub async fn redis_store(
    db: u8,
    flush: bool,
) -> Option<std::sync::Arc<dyn affinidi_messaging_mediator_common::store::MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP (redis db {db}): REDIS_URL not set");
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
        database_url: format!("{}/{db}", base.trim_end_matches('/')),
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
    Some(std::sync::Arc::new(store))
}
