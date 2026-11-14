//! Recovery after the database drops the mediator's connections, as
//! ElastiCache Serverless may when it rebalances or replaces a node.
//!
//! Redis only, and a test binary of its own: it kills every client
//! connection on the server, which would break the conformance checks if
//! they ran beside it (cargo runs test binaries one after another). Gated on
//! `REDIS_URL`, like the conformance suite; set `REDIS_CLUSTER_MODE=true` for
//! a cluster-mode server. Needs `CLIENT KILL`, so it cannot run against
//! ElastiCache Serverless itself.
#![cfg(feature = "redis-backend")]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator::store::RedisStore;
use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};
use affinidi_messaging_mediator_common::store::prelude::*;
use affinidi_messaging_mediator_common::store::types::{ForwardQueueEntry, StreamingClientState};
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tokio::sync::broadcast::error::RecvError;

/// Long enough for a client to notice the drop and reconnect.
const RECOVERY: Duration = Duration::from_secs(10);

/// Drop every client connection on the server except this one; returns how
/// many were dropped.
async fn drop_all_connections(url: &str) -> i64 {
    let client = redis::Client::open(url).expect("admin client");
    let mut admin = client
        .get_multiplexed_async_connection()
        .await
        .expect("admin connection");
    let mut dropped = 0;
    for kind in ["normal", "pubsub"] {
        dropped += redis::cmd("CLIENT")
            .arg("KILL")
            .arg("TYPE")
            .arg(kind)
            .arg("SKIPME")
            .arg("yes")
            .query_async::<i64>(&mut admin)
            .await
            .expect("CLIENT KILL");
    }
    dropped
}

/// Retry `op` until it succeeds or `RECOVERY` runs out.
async fn recovers<T, E: std::fmt::Debug, F, Fut>(what: &str, mut op: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let deadline = tokio::time::Instant::now() + RECOVERY;
    loop {
        match op().await {
            Ok(value) => return value,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("{what}: not yet recovered: {err:?}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(err) => panic!("{what} did not recover within {RECOVERY:?}: {err:?}"),
        }
    }
}

/// Publish until `rx` receives (pub/sub does not replay), within `RECOVERY`.
async fn delivered(
    store: &Arc<dyn MediatorStore>,
    rx: &mut tokio::sync::broadcast::Receiver<
        affinidi_messaging_mediator_common::store::types::PubSubRecord,
    >,
    did: &str,
    uuid: &str,
) -> bool {
    tokio::time::timeout(RECOVERY, async {
        loop {
            let _ = store
                .streaming_publish_message(did, uuid, "reconnect-notification", false)
                .await;
            if let Ok(Ok(record)) =
                tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
            {
                return record.message == "reconnect-notification";
            }
        }
    })
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn redis_store_recovers_after_connections_drop() {
    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis reconnect: REDIS_URL not set");
            return;
        }
    };
    let database_url = format!("{}/0", base.trim_end_matches('/'));
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(env!("CARGO_MANIFEST_DIR"), "/conf/atm-functions.lua").to_string(),
        ),
        database_url: database_url.clone(),
        database_timeout: 2,
        cluster_mode: std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true"),
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };
    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL — is the server reachable?");
    let store: Arc<dyn MediatorStore> = Arc::new(RedisStore::new(
        handler,
        config.circuit_breaker_threshold,
        config.circuit_breaker_recovery_secs,
        config.functions_file.clone(),
    ));
    store.initialize().await.expect("store initialize");

    let did = "did_hash_reconnect";
    let uuid = "reconnect-mediator-uuid";
    store
        .account_add(did, &MediatorACLSet::default(), None)
        .await
        .expect("account_add");
    for state in [StreamingClientState::Registered, StreamingClientState::Live] {
        store
            .streaming_set_state(did, uuid, state)
            .await
            .expect("streaming_set_state");
    }
    let mut rx = store
        .streaming_subscribe(uuid)
        .await
        .expect("streaming_subscribe");
    assert!(
        delivered(&store, &mut rx, did, uuid).await,
        "live delivery works before the drop"
    );

    assert!(
        drop_all_connections(&database_url).await >= 2,
        "the store's connections, pub/sub included, were dropped"
    );

    // Main connection: reads and writes work again without a restart.
    recovers("account_get", || store.account_get(did)).await;
    let acls = MediatorACLSet::default();
    recovers("account_add", || {
        store.account_add("did_hash_reconnect_2", &acls, None)
    })
    .await;

    // Blocking reads: the forwarding queue is read on a connection of its own.
    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "reconnect-envelope".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: 9_999_999_999,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    };
    recovers("forward_queue_enqueue", || {
        store.forward_queue_enqueue(&entry, 1000)
    })
    .await;
    let read = recovers("forward_queue_read", || {
        store.forward_queue_read(
            "reconnect-group",
            "consumer-1",
            10,
            Duration::from_millis(100),
        )
    })
    .await;
    assert!(
        read.iter().any(|e| e.message == "reconnect-envelope"),
        "the forwarding queue reads its entry after the drop"
    );

    // Live delivery: the old subscription closes visibly (the streaming task
    // resubscribes on `Closed`), and a new one delivers.
    let closed = tokio::time::timeout(RECOVERY, async {
        loop {
            match rx.recv().await {
                Err(RecvError::Closed) => return true,
                Err(RecvError::Lagged(_)) | Ok(_) => continue,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        closed,
        "a dropped pub/sub connection closes the subscription, so the streaming task resubscribes"
    );
    let mut rx = recovers("streaming_subscribe", || store.streaming_subscribe(uuid)).await;
    assert!(
        delivered(&store, &mut rx, did, uuid).await,
        "live delivery works again after resubscribing"
    );
}
