//! did:scid version floors that survive a restart (VTI-KEY-162).
//!
//! A did:scid identity is the bare DID; the `?src=` a peer presents is its own
//! choice. The resolver refuses a log older than one it has verified for that
//! SCID, and checks an unknown source against the known ones — but it keeps
//! that in memory. A portable log that has moved still names its former host in
//! its early entries, so after a restart that host could serve the pre-move log
//! (with keys its controller has since rotated away) to an empty resolver.
//!
//! So the mediator persists the resolver's record of every did:scid identity it
//! authorises — every account, and its own DID — and seeds them back at boot:
//!
//! - [`seed`] loads the stored records into the resolver, before any
//!   connection is accepted;
//! - [`persist`] hooks the resolver so a newer version or a new source for an
//!   account's did:scid is written as it is verified;
//! - [`remember`] writes an account's record when it authenticates, which
//!   covers an identity first resolved before its account existed.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, network_resolvers::ScidSourceRecord};
use affinidi_messaging_mediator_common::{
    did_identity, errors::MediatorError, store::MediatorStore,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Records waiting to be written. The resolver's listener runs on the
/// resolving task and must not block, so it hands records over here and drops
/// one (with a warning) when the writer is this far behind.
const PENDING_WRITES: usize = 1024;

/// Seeds every stored record into `resolver`. Returns how many were seeded.
///
/// A store that cannot be read is logged rather than fatal: the resolver
/// then starts with no floors, exactly as before this was persisted.
pub async fn seed(store: &dyn MediatorStore, resolver: &DIDCacheClient) -> usize {
    let records = match store.scid_source_list().await {
        Ok(records) => records,
        Err(e) => {
            warn!("did:scid source records could not be read; starting without them: {e}");
            return 0;
        }
    };
    let mut seeded = 0;
    for raw in records {
        match serde_json::from_str::<ScidSourceRecord>(&raw) {
            Ok(record) if resolver.scid_sources().seed(&record) => seeded += 1,
            Ok(record) => {
                warn!(did = %record.did, "stored did:scid source record is not a did:scid")
            }
            Err(e) => warn!("stored did:scid source record is unreadable: {e}"),
        }
    }
    debug!(seeded, "did:scid source records seeded");
    seeded
}

/// Writes the resolver's record for `did` if it is a did:scid with an account
/// here, or the mediator's own DID. Returns whether a record was written.
async fn write(
    store: &dyn MediatorStore,
    own_hash: &str,
    record: &ScidSourceRecord,
) -> Result<bool, MediatorError> {
    let hash = did_identity::did_hash(&record.did);
    if hash != own_hash && !store.account_exists(&hash).await? {
        return Ok(false);
    }
    let json = serde_json::to_string(record).map_err(|e| {
        MediatorError::InternalError(14, "NA".into(), format!("did:scid source record: {e}"))
    })?;
    store.scid_source_put(&hash, &json).await?;
    Ok(true)
}

/// Hooks `resolver` so every change to the record of a did:scid that has an
/// account here — or is `mediator_did` — is written to `store`. The writer
/// stops on `shutdown`.
pub fn persist(
    store: Arc<dyn MediatorStore>,
    resolver: &DIDCacheClient,
    mediator_did: &str,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    let (tx, mut rx) = mpsc::channel::<ScidSourceRecord>(PENDING_WRITES);
    resolver
        .scid_sources()
        .set_listener(Arc::new(move |record: &ScidSourceRecord| {
            if tx.try_send(record.clone()).is_err() {
                warn!(did = %record.did, "did:scid source record not persisted: the writer is behind");
            }
        }));
    let own_hash = did_identity::did_hash(mediator_did);
    tokio::spawn(async move {
        loop {
            let record = tokio::select! {
                _ = shutdown.cancelled() => break,
                record = rx.recv() => match record {
                    Some(record) => record,
                    None => break,
                },
            };
            if let Err(e) = write(&*store, &own_hash, &record).await {
                warn!(did = %record.did, "did:scid source record not persisted: {e}");
            }
        }
    })
}

/// Writes the record the resolver holds for `did`, when it is a did:scid with
/// an account here. Called when an account authenticates, so an identity
/// resolved before its account existed still has its floor persisted.
pub async fn remember(store: &dyn MediatorStore, resolver: &DIDCacheClient, did: &str) {
    if !did.starts_with("did:scid:") {
        return;
    }
    let Some(record) = resolver.scid_sources().record(did) else {
        return;
    };
    // No own-DID exemption here: the mediator does not authenticate to itself.
    if let Err(e) = write(store, "", &record).await {
        warn!(did = %record.did, "did:scid source record not persisted: {e}");
    }
}

#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use affinidi_did_resolver_cache_sdk::{
        config::DIDCacheConfigBuilder, network_resolvers::ScidVersion,
    };
    use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;

    const ACCOUNT: &str = "did:scid:vh:1:QmAccount";
    const STRANGER: &str = "did:scid:vh:1:QmStranger";

    fn record(did: &str, number: u32) -> ScidSourceRecord {
        ScidSourceRecord {
            did: did.to_string(),
            sources: vec!["example.com/alice".to_string()],
            version: Some(ScidVersion {
                number,
                id: format!("{number}-Qm"),
            }),
        }
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver")
    }

    async fn store_with_account() -> Arc<dyn MediatorStore> {
        let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ruleset");
        store
            .account_add(&did_identity::did_hash(ACCOUNT), &acls, None)
            .await
            .expect("account");
        store
    }

    #[tokio::test]
    async fn only_an_account_or_the_mediator_is_persisted() {
        let store = store_with_account().await;
        assert!(write(&*store, "", &record(ACCOUNT, 3)).await.unwrap());
        assert!(!write(&*store, "", &record(STRANGER, 3)).await.unwrap());
        let own = did_identity::did_hash(STRANGER);
        assert!(write(&*store, &own, &record(STRANGER, 3)).await.unwrap());
        assert_eq!(store.scid_source_list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_persisted_floor_seeds_a_fresh_resolver() {
        let store = store_with_account().await;
        write(&*store, "", &record(ACCOUNT, 7)).await.unwrap();

        // The restart: a resolver that has verified nothing.
        let fresh = resolver().await;
        assert!(fresh.scid_sources().record(ACCOUNT).is_none());
        assert_eq!(seed(&*store, &fresh).await, 1);
        let seeded = fresh.scid_sources().record(ACCOUNT).expect("seeded");
        assert_eq!(seeded.version.map(|v| v.number), Some(7));
        assert_eq!(seeded.sources, vec!["example.com/alice".to_string()]);
    }

    #[tokio::test]
    async fn a_change_the_resolver_reports_is_written() {
        let store = store_with_account().await;
        let resolver = resolver().await;
        let shutdown = CancellationToken::new();
        let writer = persist(
            store.clone(),
            &resolver,
            "did:example:mediator",
            shutdown.clone(),
        );

        // A new source for the account's did:scid notifies the listener.
        assert!(
            resolver
                .scid_sources()
                .add_source(&format!("{ACCOUNT}?src=example.com/alice"))
        );
        // And one for a DID with no account here, which must not be written.
        assert!(
            resolver
                .scid_sources()
                .add_source(&format!("{STRANGER}?src=example.com/bob"))
        );

        let mut stored = Vec::new();
        for _ in 0..50 {
            stored = store.scid_source_list().await.unwrap();
            if !stored.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(stored.len(), 1, "{stored:?}");
        let written: ScidSourceRecord = serde_json::from_str(&stored[0]).unwrap();
        assert_eq!(written.did, ACCOUNT);

        shutdown.cancel();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn remember_writes_an_account_s_record_and_ignores_other_methods() {
        let store = store_with_account().await;
        let resolver = resolver().await;
        resolver.scid_sources().seed(&record(ACCOUNT, 4));

        remember(&*store, &resolver, "did:webvh:Qm:example.com").await;
        assert!(store.scid_source_list().await.unwrap().is_empty());

        remember(
            &*store,
            &resolver,
            &format!("{ACCOUNT}?src=example.com/alice"),
        )
        .await;
        assert_eq!(store.scid_source_list().await.unwrap().len(), 1);
    }
}
