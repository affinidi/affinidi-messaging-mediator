//! A full database is reported as `storage.full`, worked out from the Redis
//! error itself, never from its wording.
//!
//! Redis only, and a test binary of its own: it lowers `maxmemory` on the
//! whole server so that every write is refused, which would break the
//! conformance checks if they ran beside it (cargo runs test binaries one
//! after another). The old limit is restored when the test ends, even when it
//! fails. Gated on `REDIS_URL`, like the conformance suite; set
//! `REDIS_CLUSTER_MODE=true` for a cluster-mode server. Needs `CONFIG SET`,
//! so it cannot run against ElastiCache Serverless itself.
#![cfg(feature = "redis-backend")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator::store::RedisStore;
use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::prelude::*;
use affinidi_messaging_mediator_common::store::types::{DeletionAuthority, Session};
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;

/// Puts the server's `maxmemory` back as it was when dropped.
struct MaxMemory {
    url: String,
    restore: String,
}

impl MaxMemory {
    /// Set `maxmemory` to one byte: past it at once, so with the default
    /// `noeviction` policy every write is refused.
    fn fill(url: &str) -> Self {
        let mut admin = redis::Client::open(url)
            .expect("admin client")
            .get_connection()
            .expect("admin connection");
        let (_, restore): (String, String) = redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory")
            .query(&mut admin)
            .expect("CONFIG GET maxmemory");
        let policy: (String, String) = redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query(&mut admin)
            .expect("CONFIG GET maxmemory-policy");
        assert_eq!(policy.1, "noeviction", "the server must refuse, not evict");
        let guard = Self {
            url: url.to_string(),
            restore,
        };
        redis::cmd("CONFIG")
            .arg("SET")
            .arg("maxmemory")
            .arg(1)
            .exec(&mut admin)
            .expect("CONFIG SET maxmemory");
        guard
    }
}

impl Drop for MaxMemory {
    fn drop(&mut self) {
        let restored = redis::Client::open(self.url.as_str())
            .and_then(|client| client.get_connection())
            .and_then(|mut admin| {
                redis::cmd("CONFIG")
                    .arg("SET")
                    .arg("maxmemory")
                    .arg(&self.restore)
                    .exec(&mut admin)
            });
        if let Err(err) = restored {
            eprintln!(
                "couldn't restore maxmemory to {}: {err}; set it by hand",
                self.restore
            );
        }
    }
}

/// The problem code and HTTP status of a refusal, or the error itself when
/// it is not a problem report.
fn refusal<T: std::fmt::Debug>(result: Result<T, MediatorError>) -> (String, u16) {
    match result {
        Err(MediatorError::MediatorError(_, _, _, report, status, _)) => (report.code, status),
        other => panic!("expected a problem report, got {other:?}"),
    }
}

#[tokio::test]
async fn a_full_database_is_reported_as_storage_full() {
    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis storage full: REDIS_URL not set");
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

    let did = "did_hash_storage_full";
    store
        .account_add(did, &MediatorACLSet::default(), None)
        .await
        .expect("account_add");
    let stored = store
        .store_message("NA", "{}", did, None, u64::MAX / 2, 0)
        .await
        .expect("store_message");

    let full = ("e.m.me.res.storage.full".to_string(), 507);
    {
        let _full = MaxMemory::fill(&database_url);

        // A multi-command write: in standalone mode a transaction the server
        // aborts, its cause carried by each refused command.
        assert_eq!(
            refusal(
                store
                    .account_add("did_hash_storage_full_2", &MediatorACLSet::default(), None)
                    .await
            ),
            full,
            "account_add"
        );
        // A Lua function that writes.
        assert_eq!(
            refusal(
                store
                    .store_message("NA", "{}", did, None, u64::MAX / 2, 0)
                    .await
            ),
            full,
            "store_message"
        );
        assert_eq!(
            refusal(
                store
                    .delete_message(
                        &stored,
                        DeletionAuthority::Owner {
                            did_hash: did.to_string()
                        }
                    )
                    .await
            ),
            full,
            "delete_message"
        );
        // A login: a session write.
        let session = Session {
            session_id: "storage-full-session".to_string(),
            did_hash: did.to_string(),
            ..Default::default()
        };
        assert_eq!(
            refusal(store.put_session(&session, Duration::from_secs(60)).await),
            full,
            "put_session"
        );

        // Reads still work on a full database.
        assert!(
            store.account_get(did).await.expect("account_get").is_some(),
            "reads are not refused"
        );
    }

    // Once space is freed, writes work again, and the refused delete
    // changed nothing.
    store
        .delete_message(
            &stored,
            DeletionAuthority::Owner {
                did_hash: did.to_string(),
            },
        )
        .await
        .expect("delete_message after space is freed");
    store
        .account_add("did_hash_storage_full_2", &MediatorACLSet::default(), None)
        .await
        .expect("account_add after space is freed");
}
