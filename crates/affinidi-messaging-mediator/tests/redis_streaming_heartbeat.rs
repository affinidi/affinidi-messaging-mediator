//! Streaming heartbeats on Redis: an instance that keeps one and lets it
//! expire is dead, and its streaming entries can be taken over; an instance
//! that never kept one (a release before heartbeats) is never dead.
//!
//! Redis only: the single-process stores have no other instance to watch.
//! Gated on `REDIS_URL`, like the conformance suite; set
//! `REDIS_CLUSTER_MODE=true` for a cluster-mode server. Every key it writes
//! is named by a fresh uuid, so it shares the database safely.
#![cfg(feature = "redis-backend")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator::store::RedisStore;
use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};
use affinidi_messaging_mediator_common::store::{StreamingKind, StreamingWrite, prelude::*};
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

#[tokio::test]
async fn an_expired_heartbeat_lets_another_instance_take_over() {
    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis streaming heartbeat: REDIS_URL not set");
            return;
        }
    };
    let cluster = std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true");
    let database_url = format!("{}/0", base.trim_end_matches('/'));
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(env!("CARGO_MANIFEST_DIR"), "/conf/atm-functions.lua").to_string(),
        ),
        database_url: database_url.clone(),
        database_timeout: 2,
        cluster_mode: cluster,
        circuit_breaker_threshold: 50,
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

    let run = Uuid::new_v4();
    let (here, dying, legacy) = (
        format!("hb-here-{run}"),
        format!("hb-dying-{run}"),
        format!("hb-legacy-{run}"),
    );
    let (dying_did, legacy_did, mux_did, absent_did) = (
        format!("hb-did-dying-{run}"),
        format!("hb-did-legacy-{run}"),
        format!("hb-did-mux-{run}"),
        format!("hb-did-absent-{run}"),
    );
    let claim = |did: String, uuid: String, kind: StreamingKind| {
        let store = store.clone();
        async move {
            store
                .streaming_claim(&did, &uuid, true, kind, StreamingWrite::Claim)
                .await
                .expect("streaming_claim")
        }
    };

    // An instance nobody has heard a heartbeat from is not dead.
    assert_eq!(
        store
            .streaming_dead_instances(std::slice::from_ref(&dying))
            .await
            .unwrap(),
        vec![false]
    );

    // `dying` beats, briefly, and streams a DID.
    assert!(
        !store
            .streaming_heartbeat(&dying, Duration::from_millis(400), DAY)
            .await
            .unwrap(),
        "a first beat has not lapsed"
    );
    claim(dying_did.clone(), dying.clone(), StreamingKind::Direct).await;
    assert_eq!(
        store
            .streaming_dead_instances(std::slice::from_ref(&dying))
            .await
            .unwrap(),
        vec![false],
        "alive while its heartbeat lasts"
    );
    assert!(
        !store.streaming_evict(&dying_did, &dying).await.unwrap(),
        "an alive instance's entry stays"
    );

    // `legacy` streams a DID but never beats, as an older release.
    claim(legacy_did.clone(), legacy.clone(), StreamingKind::Direct).await;

    tokio::time::sleep(Duration::from_millis(700)).await;

    assert_eq!(
        store
            .streaming_dead_instances(&[dying.clone(), legacy.clone(), here.clone()])
            .await
            .unwrap(),
        vec![true, false, false],
        "only the instance whose heartbeat expired is dead"
    );
    assert!(
        !store.streaming_evict(&legacy_did, &legacy).await.unwrap(),
        "an instance that never kept a heartbeat is never taken over"
    );
    assert!(
        !store.streaming_evict(&legacy_did, &dying).await.unwrap(),
        "a dead instance can only lose the entries it owns"
    );
    assert!(store.streaming_evict(&dying_did, &dying).await.unwrap());
    assert_eq!(
        store
            .streaming_owners(&[dying_did.clone(), legacy_did.clone()])
            .await
            .unwrap(),
        vec![None, Some(legacy.clone())],
        "the dead instance's entry is gone; the other stays"
    );
    assert!(
        !store.streaming_evict(&dying_did, &dying).await.unwrap(),
        "removed once"
    );

    // Its next beat reports the lapse, and it is alive again.
    assert!(
        store
            .streaming_heartbeat(&dying, Duration::from_secs(30), DAY)
            .await
            .unwrap(),
        "the beat after an expiry has lapsed"
    );
    assert_eq!(
        store
            .streaming_dead_instances(std::slice::from_ref(&dying))
            .await
            .unwrap(),
        vec![false]
    );

    // Which DIDs a mux entry holds.
    claim(mux_did.clone(), here.clone(), StreamingKind::Mux).await;
    assert_eq!(
        store
            .streaming_mux_owned(&[mux_did.clone(), legacy_did.clone(), absent_did.clone()])
            .await
            .unwrap(),
        vec![true, false, false]
    );

    // An instance whose last beat is older than the prune horizon leaves the
    // list on the next beat by anyone, and so is no longer taken for dead.
    let stale = format!("hb-stale-{run}");
    let instances = if cluster {
        "STREAMING_INSTANCES:{streaming}"
    } else {
        "STREAMING_INSTANCES"
    };
    let mut raw = redis::Client::open(database_url.as_str())
        .expect("raw client")
        .get_multiplexed_async_connection()
        .await
        .expect("raw connection");
    redis::cmd("HSET")
        .arg(instances)
        .arg(&stale)
        .arg(1)
        .exec_async(&mut raw)
        .await
        .unwrap();
    assert_eq!(
        store
            .streaming_dead_instances(std::slice::from_ref(&stale))
            .await
            .unwrap(),
        vec![true],
        "listed, with no heartbeat"
    );
    store
        .streaming_heartbeat(&here, Duration::from_secs(30), DAY)
        .await
        .unwrap();
    let listed: bool = redis::cmd("HEXISTS")
        .arg(instances)
        .arg(&stale)
        .query_async(&mut raw)
        .await
        .unwrap();
    assert!(!listed, "pruned");
    assert_eq!(
        store
            .streaming_dead_instances(std::slice::from_ref(&stale))
            .await
            .unwrap(),
        vec![false]
    );

    // Leave the shared hashes as they were.
    for (did, uuid) in [(&legacy_did, &legacy), (&mux_did, &here)] {
        store.streaming_release(did, uuid).await.unwrap();
    }
    redis::cmd("HDEL")
        .arg(instances)
        .arg(&dying)
        .arg(&here)
        .exec_async(&mut raw)
        .await
        .unwrap();
}
