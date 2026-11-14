//! The [`MuxStore`] capability of a storage backend.

use crate::error_codes;
use crate::errors::MediatorError;
use crate::store::mux;
use async_trait::async_trait;
use tokio::sync::broadcast;

/// DID multiplexing (mux) grants.
///
/// Two primitives only. Every grant rule lives in [`mux`] as a pure function
/// over a [`mux::MuxDidRecord`], so the backends cannot drift apart on them.
#[async_trait]
pub trait MuxStore: Send + Sync + std::fmt::Debug {
    /// Whether this backend implements the mux primitives below. Defaults to
    /// `false`; the mediator refuses to start with mux enabled on a backend
    /// that returns `false`.
    fn supports_mux(&self) -> bool {
        false
    }

    /// The mux record for member DID `did_hash`, or `None` if it has none.
    async fn mux_record_get(
        &self,
        _did_hash: &str,
    ) -> Result<Option<mux::MuxDidRecord>, MediatorError> {
        Ok(None)
    }

    /// Replace the mux record for `did_hash` **only if** its stored version is
    /// still `expected_version` (`None` = no record may exist). `new = None`
    /// deletes the record. In the same atomic step, add `did_hash` to the
    /// principal index of every hash in `index.add` and remove it from every
    /// hash in `index.remove`.
    ///
    /// Returns `false`, writing nothing, when the version did not match.
    async fn mux_record_cas(
        &self,
        _did_hash: &str,
        _expected_version: Option<u64>,
        _new: Option<&mux::MuxDidRecord>,
        _index: &mux::MuxIndexDelta,
    ) -> Result<bool, MediatorError> {
        Err(MediatorError::NotImplemented(
            error_codes::CONFIG_ERROR,
            "NA".into(),
            "this storage backend does not implement DID multiplexing".into(),
        ))
    }

    /// Member DID hashes in `principal_hash`'s index, ascending, strictly
    /// after `after`, at most `limit`.
    async fn mux_principal_dids(
        &self,
        _principal_hash: &str,
        _after: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<String>, MediatorError> {
        Ok(Vec::new())
    }

    /// How many member DIDs `principal_hash`'s index holds.
    async fn mux_principal_count(&self, _principal_hash: &str) -> Result<usize, MediatorError> {
        Ok(0)
    }

    /// Tell every other mediator instance sharing this store that the grants
    /// in `record` changed, so they reconcile their live mux connections
    /// (design §7.4). Best-effort: delivery is at most once, and receivers
    /// fall back to their periodic grant re-check for anything missed.
    ///
    /// The default does nothing, which suits a single-process backend
    /// (Memory, Fjall): there is no other instance to tell.
    async fn mux_changes_publish(
        &self,
        _record: &mux::MuxChangeRecord,
    ) -> Result<(), MediatorError> {
        Ok(())
    }

    /// Subscribe to [`mux_changes_publish`](Self::mux_changes_publish)
    /// records from every instance, this one's included. `Ok(None)` when the
    /// backend is single-process (the default) and there is nothing to hear.
    ///
    /// A receiver that sees [`broadcast::error::RecvError::Lagged`] missed
    /// records; one that sees `Closed` lost the subscription and must
    /// subscribe again. Either way it must re-check its connections in full.
    async fn mux_changes_subscribe(
        &self,
    ) -> Result<Option<broadcast::Receiver<mux::MuxChangeRecord>>, MediatorError> {
        Ok(None)
    }
}
