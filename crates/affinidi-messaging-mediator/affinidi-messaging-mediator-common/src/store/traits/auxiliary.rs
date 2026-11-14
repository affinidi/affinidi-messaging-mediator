//! The [`AuxiliaryStore`] capability of a storage backend.

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
    /// A store that cannot answer must return an error: executing anyway is
    /// the double execution the rule forbids, and the caller fails closed on
    /// the error.
    async fn trust_task_claim(
        &self,
        key: &str,
        digest: &str,
        retain_until: u64,
        now: u64,
    ) -> Result<TrustTaskClaim, MediatorError>;

    /// Drop Trust Task claims whose `retain_until` is at or before `now`.
    /// Returns how many were removed. A backend with native key expiry (Redis)
    /// answers `0`.
    async fn sweep_expired_trust_task_claims(&self, now: u64) -> Result<usize, MediatorError>;

    /// Record where the did:scid account `did_hash` has been found, and the
    /// latest version of its log verified — `record` is the resolver's
    /// serialised `ScidSourceRecord`, opaque here — replacing any earlier one.
    ///
    /// This is the floor VTI-KEY-162 requires a node to persist for every
    /// did:scid identity it authorises: seeded back into the resolver at boot,
    /// it keeps a restart from accepting an older copy of the log (a moved log's
    /// former host can serve its pre-move state under the same did:scid).
    ///
    /// A store that cannot keep it must return an error, as the floor is then
    /// not durable; the caller logs it.
    async fn scid_source_put(&self, did_hash: &str, record: &str) -> Result<(), MediatorError>;

    /// Every did:scid source record [`Self::scid_source_put`] stored, for
    /// seeding the resolver at boot.
    async fn scid_source_list(&self) -> Result<Vec<String>, MediatorError>;

    /// Replace the wake record held for the account `did_hash` with `record`,
    /// or remove it when `record` is `None` (`messaging/wake/set`). `record` is
    /// the mediator's serialised wake record, opaque here. One record per
    /// account: a set supersedes the previous one whole, and no history is
    /// kept. Removing the account removes its record (Consumer rule 7).
    ///
    /// A store that cannot keep it must refuse a set: the account must not
    /// believe it is wakeable when nothing was kept.
    async fn wake_handle_set(
        &self,
        did_hash: &str,
        record: Option<&str>,
    ) -> Result<(), MediatorError>;

    /// The wake record [`Self::wake_handle_set`] stored for `did_hash`, if
    /// any.
    async fn wake_handle_get(&self, did_hash: &str) -> Result<Option<String>, MediatorError>;

    /// The mediator's stored configuration overrides, as a JSON object of
    /// `key → value` (keys like `limits.queued_send_messages_hard`), or `None`
    /// when none have been stored. Written by `config/patch` and layered over
    /// the file/env configuration at startup.
    async fn config_overrides_get(&self) -> Result<Option<String>, MediatorError>;

    /// Replace the stored configuration overrides with `overrides`, a JSON
    /// object. An empty object clears them.
    ///
    /// This replaces the whole document, so a caller changing it must read,
    /// modify and write under one lock; the mediator does all of that under
    /// its patch lock (`LiveLimits::lock_for_patch`).
    ///
    /// A store that cannot keep them must return an error: a patch must not
    /// report a value as stored when the store kept nothing.
    async fn config_overrides_set(&self, overrides: &str) -> Result<(), MediatorError>;
}
