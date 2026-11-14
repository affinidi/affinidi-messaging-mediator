//! The [`AuxiliaryStore`] capability of a storage backend.

use crate::error_codes;
use crate::errors::MediatorError;
use crate::store::TrustTaskClaim;
use async_trait::async_trait;

/// Small keyed records outside the message and account model: OOB invitations, Trust Task duplicate-execution claims, did:scid source records and the stored configuration overrides.
#[async_trait]
pub trait AuxiliaryStore: Send + Sync + std::fmt::Debug {
    /// Store an OOB Discovery invitation. The caller is responsible for
    /// serialising the DIDComm `Message` to JSON and base64-url-encoding
    /// it (so the trait doesn't depend on the didcomm crate, which is
    /// optional in the mediator). The caller also resolves the final
    /// `expires_at` (Unix seconds) from the invitation's `expires_time`
    /// and the configured `oob_invite_ttl`.
    ///
    /// Returns the invitation hash used as its lookup key. Increments
    /// the global "invites created" counter.
    async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite_b64: &str,
        expires_at: u64,
    ) -> Result<String, MediatorError>;

    /// Retrieve an OOB invitation by hash. Returns `Some((invite_b64,
    /// did_hash))` when the invitation exists and hasn't expired,
    /// `None` otherwise. Increments the global "invites claimed" counter.
    async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError>;

    /// Delete an OOB invitation. Returns `true` when an entry was deleted.
    async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError>;

    /// Claim a Trust Task for execution — the Trust Tasks §7.2 item 11
    /// duplicate-execution record.
    ///
    /// `key` identifies the document (the caller scopes it to the issuer, so
    /// one party cannot burn another's ids); `digest` is the document's
    /// content digest. The first claim of a key records `digest` until
    /// `retain_until` (Unix seconds) and is [`TrustTaskClaim::Fresh`]; a later
    /// claim of the same key before then is [`TrustTaskClaim::Duplicate`] when
    /// the digest matches and [`TrustTaskClaim::Conflict`] when it does not. A
    /// record whose `retain_until` has passed (by `now`) is treated as absent.
    ///
    /// The check-and-record must be atomic across every mediator instance
    /// sharing the store — that is what makes a replay to a *second* instance
    /// fail too.
    ///
    /// **The default refuses.** A store that does not implement this cannot
    /// say whether a document was already executed, and executing anyway is
    /// the double execution the rule forbids; the caller fails closed on the
    /// error. Every built-in backend overrides it.
    async fn trust_task_claim(
        &self,
        key: &str,
        digest: &str,
        retain_until: u64,
        now: u64,
    ) -> Result<TrustTaskClaim, MediatorError> {
        let _ = (key, digest, retain_until, now);
        Err(MediatorError::InternalError(
            error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            "this store keeps no Trust Task duplicate-execution record".into(),
        ))
    }

    /// Drop Trust Task claims whose `retain_until` is at or before `now`.
    /// Returns how many were removed. Backends with native key expiry (Redis)
    /// keep the default no-op.
    async fn sweep_expired_trust_task_claims(&self, now: u64) -> Result<usize, MediatorError> {
        let _ = now;
        Ok(0)
    }

    /// Record where the did:scid account `did_hash` has been found, and the
    /// latest version of its log verified — `record` is the resolver's
    /// serialised `ScidSourceRecord`, opaque here — replacing any earlier one.
    ///
    /// This is the floor VTI-KEY-162 requires a node to persist for every
    /// did:scid identity it authorises: seeded back into the resolver at boot,
    /// it keeps a restart from accepting an older copy of the log (a moved log's
    /// former host can serve its pre-move state under the same did:scid).
    ///
    /// **The default refuses**, as the floor is then not durable; the caller
    /// logs it. Every built-in backend overrides it.
    async fn scid_source_put(&self, did_hash: &str, record: &str) -> Result<(), MediatorError> {
        let _ = (did_hash, record);
        Err(MediatorError::InternalError(
            error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            "this store keeps no did:scid source records".into(),
        ))
    }

    /// Every did:scid source record [`Self::scid_source_put`] stored, for
    /// seeding the resolver at boot. The default holds none.
    async fn scid_source_list(&self) -> Result<Vec<String>, MediatorError> {
        Ok(Vec::new())
    }

    /// The mediator's stored configuration overrides, as a JSON object of
    /// `key → value` (keys like `limits.queued_send_messages_hard`), or `None`
    /// when none have been stored. Written by `config/patch` and layered over
    /// the file/env configuration at startup.
    ///
    /// The default has none, which is the truth for a store that cannot keep
    /// them.
    async fn config_overrides_get(&self) -> Result<Option<String>, MediatorError> {
        Ok(None)
    }

    /// Replace the stored configuration overrides with `overrides`, a JSON
    /// object. An empty object clears them.
    ///
    /// This replaces the whole document, so a caller changing it must read,
    /// modify and write under one lock; the mediator does all of that under
    /// its patch lock (`LiveLimits::lock_for_patch`).
    ///
    /// **The default refuses**: a patch must not report a value as stored when
    /// the store kept nothing. Every built-in backend overrides it.
    async fn config_overrides_set(&self, overrides: &str) -> Result<(), MediatorError> {
        let _ = overrides;
        Err(MediatorError::InternalError(
            error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            "this store cannot keep configuration overrides".into(),
        ))
    }
}
