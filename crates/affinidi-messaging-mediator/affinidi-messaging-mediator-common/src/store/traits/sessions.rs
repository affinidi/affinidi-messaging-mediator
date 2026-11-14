//! The [`SessionStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::{RefreshRotation, Session, SessionSweepReport};
use async_trait::async_trait;
use std::time::Duration;

/// Authentication sessions and their refresh tokens.
#[async_trait]
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    /// Upsert a session record with an explicit TTL.
    ///
    /// Covers all session writes: initial challenge creation (typical TTL
    /// 900s), promotion to authenticated (TTL 86400s, written under a new
    /// `session_id`), and refresh-token rotation (write back the same
    /// session with a new `refresh_token_hash`).
    ///
    /// The post-auth rename is fail-closed: the default
    /// [`update_session_authenticated`](Self::update_session_authenticated)
    /// does `delete_session(old)` *then* `put_session(new)`, so an
    /// interruption can only lose the new session, never leave both. Redis
    /// and Fjall override it with a single atomic operation.
    async fn put_session(&self, session: &Session, ttl: Duration) -> Result<(), MediatorError>;

    /// Retrieve a session by ID and join with the corresponding `DID:`
    /// record so the returned `Session` has populated `acls` and
    /// `account_type` fields. The handler uses these to authorise
    /// downstream requests without a separate account lookup.
    ///
    /// A `ChallengeSent` session may have no account yet (accounts are
    /// created once the challenge is answered) and is returned with default
    /// ACLs. Any other session whose DID has no account fails with
    /// [`account_gone`]; a DID record without a role or ACLs is not an
    /// account. An empty `did` skips the join (store-internal use).
    ///
    /// A session that does not exist (or has expired) fails with
    /// [`session_not_found`]. Every other error is a storage failure.
    async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError>;

    /// Delete a session record. Used for logout and as the *first* step
    /// of the fail-closed post-auth rename (delete old, then write new).
    async fn delete_session(&self, session_id: &str) -> Result<(), MediatorError>;

    /// Run one pass of the session expiry sweep, removing session
    /// records whose TTL has elapsed (`expires_at <= now_secs`).
    ///
    /// Backends with native TTL (Redis `EXPIRE`) reclaim expired
    /// sessions themselves, so the default is a no-op. Backends without
    /// (Fjall, memory) expire sessions lazily on [`get_session`](Self::get_session), which
    /// means a session that is created but never read again — e.g. a
    /// one-off DID that runs `/authenticate/challenge` and disappears —
    /// lingers on disk/in the map indefinitely. The session processor
    /// calls this on a fixed cadence so those orphaned records are
    /// reclaimed regardless of whether they're ever read.
    ///
    /// `now_secs` contract (note the backend divergence, asserted by the
    /// `store_conformance` suite): `FjallStore` honors it as the wall-clock
    /// cutoff (`expires_at_unix <= now_secs`). `MemoryStore` **ignores** it and
    /// sweeps against its own monotonic `Instant::now()` — its TTLs are tracked
    /// as `Instant`s, which can't be compared to a unix `now_secs`. Production
    /// callers (`tasks::session_expiry`) always pass the real clock, so the two
    /// reclaim the same lapsed sessions; only a caller passing a *synthetic*
    /// `now_secs` would observe the difference.
    async fn sweep_expired_sessions(
        &self,
        now_secs: u64,
    ) -> Result<SessionSweepReport, MediatorError> {
        let _ = now_secs;
        Ok(SessionSweepReport::default())
    }

    /// Promote a `ChallengeSent` session to `Authenticated` under
    /// `new_session_id`, recording the refresh-token hash, and count it in
    /// [`StatCounter::SessionsSuccess`].
    ///
    /// One atomic step: the challenge session must still exist and still be
    /// waiting for its answer (a challenge is answered once), else
    /// [`session_not_awaiting_answer`](crate::store::session_not_awaiting_answer);
    /// the old id stops working in the same step as the new one starts, so
    /// the two never coexist. Redis renames and rewrites in one script,
    /// Fjall in one batch, memory under its lock.
    ///
    /// `did` is the **raw DID string** (e.g. `did:peer:2.*`), not its hash:
    /// it is what the rewritten session records.
    async fn update_session_authenticated(
        &self,
        old_session_id: &str,
        new_session_id: &str,
        did: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError>;

    /// Legacy: rotate the refresh-token hash on an existing session.
    /// Loads, updates, writes back with a 24h TTL.
    async fn update_refresh_token_hash(
        &self,
        session_id: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError> {
        // We don't know the DID at this layer; pass empty so the
        // join-with-account in `get_session` is best-effort. Backends
        // that need the DID for the refresh path should override. A session
        // that has ended is not recreated: the update fails.
        let mut session = self.get_session(session_id, "").await?;
        session.refresh_token_hash = Some(refresh_token_hash.to_string());
        self.put_session(&session, std::time::Duration::from_secs(86_400))
            .await
    }

    /// Exchange a refresh token: if the session's stored refresh-token hash
    /// equals `presented_hash`, replace it with `new_hash`; otherwise write
    /// nothing. The compare and the write must be one atomic step, so two
    /// requests presenting the same token can never both see
    /// [`RefreshRotation::Rotated`].
    ///
    /// The default is NOT atomic (read, compare, write) and exists only so
    /// out-of-tree backends keep compiling; every in-tree backend overrides
    /// it. A missing session or a missing stored hash is
    /// [`RefreshRotation::Missing`], never a match.
    async fn rotate_refresh_token_hash(
        &self,
        session_id: &str,
        presented_hash: &str,
        new_hash: &str,
    ) -> Result<RefreshRotation, MediatorError> {
        match self.get_refresh_token_hash(session_id).await? {
            None => Ok(RefreshRotation::Missing),
            Some(stored) if stored != presented_hash => Ok(RefreshRotation::Mismatch),
            Some(_) => {
                self.update_refresh_token_hash(session_id, new_hash).await?;
                Ok(RefreshRotation::Rotated)
            }
        }
    }

    /// Legacy: read just the refresh-token hash for a session. Default
    /// impl loads the whole session and returns the field.
    async fn get_refresh_token_hash(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, MediatorError> {
        match self.get_session(session_id, "").await {
            Ok(s) => Ok(s.refresh_token_hash),
            Err(_) => Ok(None),
        }
    }
}
