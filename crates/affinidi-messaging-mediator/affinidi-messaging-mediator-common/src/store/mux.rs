//! DID multiplexing (mux) grant storage.
//!
//! A **grant** is a member DID's signed statement that a *principal* may
//! collect its messages over the principal's own connection. See the design
//! note `design-docs/mediator-did-multiplexing-design.md` (§4.4, §5, §6).
//!
//! # Why the rules live here and not in each backend
//!
//! The backends cannot share code with each other (Redis logic would have to
//! be Lua), and a rule that drifts between them is a security bug, not a
//! cosmetic one. So every grant rule — epoch, replay floor, quotas,
//! narrow-only updates, suspension, expiry — is a pure function over one
//! [`MuxDidRecord`](crate::store::mux::MuxDidRecord) in this module, and a backend provides only two
//! primitives:
//!
//! - [`MediatorStore::mux_record_get`] — read a member DID's record;
//! - [`MediatorStore::mux_record_cas`] — replace it if its version is still
//!   the one that was read, updating the principal index in the same atomic
//!   step.
//!
//! [`modify`](crate::store::mux::modify) runs the read → rule → compare-and-swap loop.
//!
//! # Unit of atomicity
//!
//! Everything about one member DID — its epoch, all its grants (at most
//! `max_grants_per_did`) and its replay floors — is one record, so every rule
//! that has to be atomic is atomic for free. The only cross-record state is
//! the principal → member-DID index, which the CAS maintains alongside the
//! record. `max_grants_per_principal` is checked against that index *before*
//! the CAS, so concurrent grants to one principal can overshoot it by the
//! number racing; it is a resource bound, not an authorization gate.

use crate::errors::MediatorError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

use super::MediatorStore;

/// How many times [`modify`] retries a compare-and-swap that lost a race
/// before giving up with [`MuxStoreError::Contended`].
const CAS_ATTEMPTS: usize = 8;

// ─── Types ───────────────────────────────────────────────────────────────────

/// One thing a grant or attach allows the principal to do for a member DID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MuxCapability {
    /// Live delivery of the member's messages.
    Receive,
    /// Message-pickup status / delivery requests for the member.
    Pickup,
    /// Deleting (acknowledging) the member's messages.
    Delete,
    /// Sending frames whose sender is the member, over this connection.
    Send,
}

/// A non-empty set of [`MuxCapability`].
///
/// Empty is not representable through [`MuxScope::new`]: an empty scope means
/// nothing, and "nothing" must never be read as "everything" (R5.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<MuxCapability>", into = "Vec<MuxCapability>")]
pub struct MuxScope(BTreeSet<MuxCapability>);

impl MuxScope {
    /// A scope of exactly these capabilities. Duplicates collapse.
    pub fn new(caps: impl IntoIterator<Item = MuxCapability>) -> Result<Self, MuxStoreError> {
        let set: BTreeSet<_> = caps.into_iter().collect();
        if set.is_empty() {
            return Err(MuxStoreError::EmptyScope);
        }
        Ok(Self(set))
    }

    pub fn contains(&self, cap: MuxCapability) -> bool {
        self.0.contains(&cap)
    }

    pub fn is_subset(&self, other: &MuxScope) -> bool {
        self.0.is_subset(&other.0)
    }

    pub fn iter(&self) -> impl Iterator<Item = MuxCapability> + '_ {
        self.0.iter().copied()
    }
}

impl TryFrom<Vec<MuxCapability>> for MuxScope {
    type Error = MuxStoreError;
    fn try_from(v: Vec<MuxCapability>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<MuxScope> for Vec<MuxCapability> {
    fn from(s: MuxScope) -> Self {
        s.0.into_iter().collect()
    }
}

/// Lifecycle state of a stored grant.
///
/// `Expired` is never stored: it is what [`MuxGrant::state_at`] reports for an
/// `Active` grant whose effective expiry has passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MuxGrantState {
    Active,
    /// The member proved control with a key no active grant was signed with
    /// (§5.3). Terminal: recreating needs a fresh member signature.
    Suspended,
    /// The signing key is no longer in the member's authentication
    /// relationship (§5.1). Terminal, even if the key comes back.
    StaleKey,
    Expired,
    /// Voided by a `revoke-all` epoch bump (§5.2). Terminal.
    EpochRevoked,
}

/// Who advanced the epoch that voided an `EpochRevoked` grant
/// ([`MuxGrant::voided_by`]): what labels the `grantsRevoked` notice and the
/// detach for it — `epochBumped` for the member, `admin` for an
/// administrator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MuxVoidedBy {
    /// The member's own `messaging/mux/revoke-all`.
    Member,
    /// An administrator's `messaging/mux/admin-revoke-all`.
    Admin,
    /// A value a later version wrote that this one does not know. Read as
    /// the member's, the label used before the field existed.
    #[serde(other)]
    Unknown,
}

impl MuxGrantState {
    /// Whether a grant in this state still counts against
    /// `max_grants_per_did`. Dead grants are kept only so they can be listed.
    fn counts_against_quota(self) -> bool {
        matches!(self, MuxGrantState::Active)
    }
}

/// A stored grant: who may collect whose messages, as proven by `jws`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxGrant {
    pub grant_id: String,
    /// The member DID, and its hash (the record key).
    pub did: String,
    pub did_hash: String,
    pub principal: String,
    pub principal_hash: String,
    /// The verification method that signed the grant, and its public-key
    /// fingerprint, as resolved when it was stored (§5.1).
    pub kid: String,
    pub key_fp: String,
    /// The member DID's document version at signing, where the method has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_version: Option<String>,
    /// The member's epoch the grant was issued under (§5.2).
    pub epoch: u64,
    pub scope: MuxScope,
    pub iat: u64,
    pub exp: u64,
    /// Set by a narrow-only update (§4.7). Never wider than `scope`/`exp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrowed_scope: Option<MuxScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrowed_exp: Option<u64>,
    pub state: MuxGrantState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<u64>,
    /// The grant statement exactly as the member signed it (with its Data
    /// Integrity proof), kept for audit and returned verbatim by listings.
    pub statement: serde_json::Value,
    /// Whether the durable notice for this grant's dead state (`suspended`
    /// or `epochRevoked`) is in its principal's inbox. A notice lost to a
    /// crash between the state change and the notice is re-sent while this
    /// is false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub noticed: bool,
    /// Fingerprints (SHA-256 of the public key) of the member DID's
    /// `keyAgreement` keys when the grant was stored: the known keys a direct
    /// DIDComm authentication, which proves a key-agreement key, is compared
    /// with (the unknown-key rule). Empty when the DID listed none; a grant
    /// whose keys could not be read is refused, never stored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement_fps: Vec<String>,
    /// Whether the `grantsExpiring` notice for this grant is stored.
    #[serde(default, skip_serializing_if = "is_false")]
    pub expiring_noticed: bool,
    /// Who voided the grant, set with `EpochRevoked`, so a notice re-sent
    /// after a crash, or a detach decided from the record alone, carries the
    /// reason the live one did. Absent on records stored before the field
    /// existed, or by an instance that predates it: read as the member's
    /// (`epochBumped`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voided_by: Option<MuxVoidedBy>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl MuxGrant {
    pub fn effective_scope(&self) -> &MuxScope {
        self.narrowed_scope.as_ref().unwrap_or(&self.scope)
    }

    pub fn effective_exp(&self) -> u64 {
        self.narrowed_exp.map_or(self.exp, |n| n.min(self.exp))
    }

    /// The state as of `now`, reporting an active-but-lapsed grant as
    /// `Expired`.
    pub fn state_at(&self, now: u64) -> MuxGrantState {
        if self.state == MuxGrantState::Active && self.effective_exp() <= now {
            MuxGrantState::Expired
        } else {
            self.state
        }
    }

    /// Whether the grant authorises anything at `now`.
    pub fn is_usable(&self, now: u64) -> bool {
        self.state_at(now) == MuxGrantState::Active
    }

    /// Whether the grant is active and past about three quarters of its
    /// lifetime (`grantsExpiring`).
    pub fn is_expiring(&self, now: u64) -> bool {
        let exp = self.effective_exp();
        let lifetime = exp.saturating_sub(self.iat);
        self.is_usable(now) && now >= self.iat.saturating_add(lifetime / 4 * 3)
    }

    fn set_state(&mut self, state: MuxGrantState, now: u64) {
        self.state = state;
        self.state_changed_at = Some(now);
    }
}

/// A floor below which no grant for `principal_hash` is accepted again.
///
/// Set when a grant is revoked or replaced, so the same (or an older) signed
/// grant cannot be replayed to bring it back. Self-pruning: a grant whose
/// `iat` is at or below the floor has `exp ≤ floor + max_grant_lifetime`, so
/// once that has passed no such grant can be valid anyway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxReplayFloor {
    pub principal_hash: String,
    /// A grant must have `iat` strictly greater than this.
    pub iat_floor: u64,
}

/// Everything stored about one member DID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxDidRecord {
    /// Compare-and-swap version. Bumped by every write.
    pub version: u64,
    pub epoch: u64,
    pub grants: Vec<MuxGrant>,
    #[serde(default)]
    pub replay_floors: Vec<MuxReplayFloor>,
    /// Ids of `messaging/mux/notice` messages stored in this DID's own inbox
    /// (as a principal, or as a member for `grantsPresent`), newest last, so
    /// a `ready` event can say how many still wait. Bounded by
    /// [`MAX_TRACKED_NOTICES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<String>,
    /// The grant set ([`MuxDidRecord::grants_digest`]) this DID was last told
    /// about in a `grantsPresent` notice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_told: Option<String>,
    /// The wire this DID last used with the mediator: its last mux
    /// connection's, or its last direct login's. Its notices are sealed for
    /// it; `None` means DIDComm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<NoticeWire>,
    /// The recent notices in [`notices`](Self::notices) that can be sealed
    /// again: the wire each was stored for and its payload. When this DID
    /// connects on the other wire, they are re-issued for it. Bounded by
    /// [`MAX_NOTICE_FORMS`] and [`MAX_NOTICE_FORM_BYTES`]; an older notice is
    /// still counted, but stays in the form it was stored in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notice_forms: Vec<NoticeForm>,
}

/// The wire a notice is sealed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NoticeWire {
    /// Packed as DIDComm, authcrypted from the mediator.
    #[serde(rename = "didcomm")]
    DidComm,
    /// Sealed as a TSP Direct message from the mediator's VID.
    Tsp,
}

/// A stored notice that can be sealed again for the other wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeForm {
    /// The stored message's id, as in [`MuxDidRecord::notices`].
    pub id: String,
    pub wire: NoticeWire,
    /// The notice's `payload`, before it was signed and sealed.
    pub payload: serde_json::Value,
}

/// The most notices a record keeps re-sealable.
pub const MAX_NOTICE_FORMS: usize = 32;

/// The most bytes of notice payloads a record keeps; past it, the oldest go.
pub const MAX_NOTICE_FORM_BYTES: usize = 64 * 1024;

/// The most notice ids a record tracks; older ones are forgotten (the notices
/// themselves stay in the inbox until deleted).
pub const MAX_TRACKED_NOTICES: usize = 256;

impl MuxDidRecord {
    /// Principals that currently have an entry (in any state) for this DID —
    /// exactly the set the principal index must hold for it.
    fn principals(&self) -> BTreeSet<String> {
        self.grants
            .iter()
            .map(|g| g.principal_hash.clone())
            .collect()
    }

    /// Whether the record holds nothing worth keeping. An epoch above zero is
    /// worth keeping: dropping it would bring back grants it voided.
    fn is_empty(&self) -> bool {
        self.epoch == 0
            && self.grants.is_empty()
            && self.replay_floors.is_empty()
            && self.notices.is_empty()
            && self.present_told.is_none()
    }

    /// Remember a notice stored in this DID's inbox, sealed for `wire` from
    /// `payload`.
    pub fn track_notice(&mut self, msg_id: String, wire: NoticeWire, payload: serde_json::Value) {
        self.notices.push(msg_id.clone());
        let over = self.notices.len().saturating_sub(MAX_TRACKED_NOTICES);
        self.notices.drain(..over);
        self.notice_forms.push(NoticeForm {
            id: msg_id,
            wire,
            payload,
        });
        self.bound_notice_forms();
    }

    /// Replace the tracked notice `old` with `new`, the same notice stored
    /// again for `wire`.
    pub fn retrack_notice(&mut self, old: &str, new: String, wire: NoticeWire) {
        for id in self.notices.iter_mut().filter(|id| *id == old) {
            *id = new.clone();
        }
        for form in self.notice_forms.iter_mut().filter(|f| f.id == old) {
            form.id = new.clone();
            form.wire = wire;
        }
    }

    /// Forget the notices in `gone` (deleted from the inbox).
    pub fn forget_notices(&mut self, gone: &HashSet<String>) {
        self.notices.retain(|id| !gone.contains(id));
        self.notice_forms.retain(|f| !gone.contains(&f.id));
    }

    fn bound_notice_forms(&mut self) {
        let tracked: HashSet<&String> = self.notices.iter().collect();
        self.notice_forms.retain(|f| tracked.contains(&f.id));
        let over = self.notice_forms.len().saturating_sub(MAX_NOTICE_FORMS);
        self.notice_forms.drain(..over);
        let size = |f: &NoticeForm| f.payload.to_string().len();
        let mut total: usize = self.notice_forms.iter().map(size).sum();
        while total > MAX_NOTICE_FORM_BYTES && !self.notice_forms.is_empty() {
            total -= size(&self.notice_forms.remove(0));
        }
    }

    /// A digest of the grant set on this DID (ids and states), so a
    /// `grantsPresent` notice is sent once per change rather than on every
    /// authentication.
    pub fn grants_digest(&self, now: u64) -> String {
        let mut entries: Vec<String> = self
            .grants
            .iter()
            .map(|g| format!("{}:{:?}", g.grant_id, g.state_at(now)))
            .collect();
        entries.sort();
        sha256::digest(format!("{}|{}", self.epoch, entries.join(",")))
    }

    /// Mark these grants' dead-state notices as stored.
    pub fn mark_noticed(&mut self, grant_ids: &HashSet<String>) {
        for g in self.grants.iter_mut() {
            if grant_ids.contains(&g.grant_id) {
                g.noticed = true;
            }
        }
    }

    fn floor_for(&self, principal_hash: &str) -> Option<u64> {
        self.replay_floors
            .iter()
            .find(|f| f.principal_hash == principal_hash)
            .map(|f| f.iat_floor)
    }

    fn raise_floor(&mut self, principal_hash: &str, iat_floor: u64) {
        match self
            .replay_floors
            .iter_mut()
            .find(|f| f.principal_hash == principal_hash)
        {
            Some(f) => f.iat_floor = f.iat_floor.max(iat_floor),
            None => self.replay_floors.push(MuxReplayFloor {
                principal_hash: principal_hash.to_string(),
                iat_floor,
            }),
        }
    }
}

/// Principal-index changes that must be applied atomically with a record
/// write: the member DID is added to / removed from each listed principal's
/// index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MuxIndexDelta {
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// Grants that changed on one mediator instance, published so the other
/// instances sharing the store apply the change to their own live mux
/// connections within moments rather than at their next periodic re-check
/// (design §7.4).
///
/// Carries hashes only — never statements, DIDs or keys. A receiver re-reads
/// each member's record and acts on what the store holds, so a record is a
/// hint to look, not an instruction: a stale, duplicated or reordered one
/// does no harm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuxChangeRecord {
    /// The instance that made the change (its streaming UUID), so it can
    /// ignore its own records: it applied the change before publishing.
    pub origin: String,
    pub changes: Vec<MuxChange>,
    /// Changes of which instance streams a DID, for the instances holding a
    /// mux entry for it. Absent from records that carry none; an instance
    /// that predates the field ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streaming: Vec<StreamingHandoff>,
    /// Changes to a member DID itself rather than to one grant: its account
    /// standing, or its `revoke-all`. Absent from records that carry none;
    /// an instance that predates the field ignores it, and its standing pass
    /// applies the change within one interval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<MemberHint>,
}

/// A change to a member DID that every instance carrying it applies to its
/// live mux connections. Hashes and times only; a receiver re-reads the
/// store where the hint names something the store holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "event",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum MemberHint {
    /// The member's account was blocked, removed or had its ACLs changed:
    /// re-check its standing wherever it is carried.
    StandingChanged { did_hash: String },
    /// The member DID's epoch advanced at `at` (unix seconds), by its own
    /// `revoke-all` or an administrator's `admin-revoke-all`: end its
    /// session attaches admitted at or before then.
    AttachesEnded {
        did_hash: String,
        at: u64,
        /// The `messaging/mux` detach reason the originating instance used
        /// (`admin` for an administrator's advance). Absent means
        /// `epochBumped`, which is all an instance that predates the field
        /// sends.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// A change of which instance streams a DID's live traffic, for the mux
/// entries the store's ordering cannot reach on its own: a direct socket on
/// one instance outranks a mux entry on another, and the newest registration
/// otherwise wins (design §7.2). Hashes and instance ids only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "event",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum StreamingHandoff {
    /// `instance`'s mux entry for `did_hash` lost the DID to a newer
    /// registration elsewhere. That instance stands its entry by and tells
    /// its connection the member is inactive (`superseded`).
    Taken { did_hash: String, instance: String },
    /// The DID's owner left, and a mux entry waits for it. An instance
    /// holding one on standby takes the DID back (`reactivated`).
    Released { did_hash: String },
}

/// One changed (member DID, principal) pair in a [`MuxChangeRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MuxChange {
    /// The member DID's hash: whose record to re-read.
    pub did_hash: String,
    /// The principal's hash: whose live connections to reconcile.
    pub principal_hash: String,
    /// A grant was just stored for this pair, so a receiver may carry it on
    /// the principal's live connections, as the originating instance does.
    /// Without it a receiver only drops or narrows: a grant it did not just
    /// see stored may be one its connection refused on connect (key not
    /// checkable, member blocked), and only a reconnect re-runs those checks.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stored: bool,
    /// The `messaging/mux` detach reason the originating instance used for a
    /// grant it removed or voided on this pair (`revokedByPrincipal`,
    /// `admin`, …). The store still decides whether a receiver detaches; this
    /// only labels the detach it reports, which the store alone cannot tell
    /// (a deleted grant looks the same whoever revoked it). Absent from
    /// records that carry none, and from an instance that predates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MuxChange {
    pub fn of(grant: &MuxGrant, stored: bool) -> Self {
        Self {
            did_hash: grant.did_hash.clone(),
            principal_hash: grant.principal_hash.clone(),
            stored,
            reason: None,
        }
    }

    /// This change, labelled with the detach reason the originating
    /// instance used.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Operator limits the grant rules enforce. See `[limits.mux]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxLimits {
    pub max_grants_per_did: usize,
    pub max_grants_per_principal: usize,
    pub max_grant_lifetime_secs: u64,
    /// How long a dead (suspended, stale, revoked, expired) grant stays
    /// listable after its effective expiry before it is pruned.
    pub dead_retention_secs: u64,
}

impl Default for MuxLimits {
    fn default() -> Self {
        Self {
            max_grants_per_did: 16,
            max_grants_per_principal: 5000,
            max_grant_lifetime_secs: 30 * 24 * 3600,
            dead_retention_secs: 7 * 24 * 3600,
        }
    }
}

/// Why a grant operation was refused. Each variant maps to one stable wire
/// error code in the `messaging/mux/*` specs.
#[derive(Debug, thiserror::Error)]
pub enum MuxStoreError {
    #[error("scope must name at least one capability")]
    EmptyScope,
    #[error("grant is for a different DID than the record it was written to")]
    DidMismatch,
    #[error("grant was issued under epoch {grant}, the DID's current epoch is {current}")]
    EpochMismatch { grant: u64, current: u64 },
    #[error("grant has already expired")]
    Expired,
    #[error("grant lifetime {requested}s exceeds the maximum of {max}s")]
    LifetimeTooLong { requested: u64, max: u64 },
    #[error(
        "grant is not newer than one already stored or revoked for this principal (iat must be > {floor})"
    )]
    Replayed { floor: u64 },
    #[error("grant id is already in use for this DID")]
    GrantIdReused,
    #[error("this DID already has the maximum of {max} active grants")]
    DidQuota { max: usize },
    #[error("this principal already holds the maximum of {max} grants")]
    PrincipalQuota { max: usize },
    #[error("no such grant")]
    UnknownGrant,
    #[error("grant is not active")]
    NotActive,
    #[error("an update may only narrow a grant; widening needs a new grant")]
    WidenRefused,
    #[error("the record kept changing underneath; retry")]
    Contended,
    #[error(transparent)]
    Store(#[from] MediatorError),
}

// ─── Pure rules ──────────────────────────────────────────────────────────────

/// Drop what no longer needs keeping: dead grants past their retention, and
/// replay floors no grant could still get under.
pub fn prune(rec: &mut MuxDidRecord, limits: &MuxLimits, now: u64) {
    rec.grants.retain(|g| {
        g.state_at(now) == MuxGrantState::Active
            || g.effective_exp().saturating_add(limits.dead_retention_secs) > now
    });
    rec.replay_floors
        .retain(|f| f.iat_floor.saturating_add(limits.max_grant_lifetime_secs) >= now);
}

/// Store `grant` (state forced to `Active`), replacing the principal's earlier
/// grant on this DID if any. Returns the grant it replaced.
///
/// `principal_count` is how many DIDs the principal's index holds right now;
/// it gates `max_grants_per_principal` for a principal new to this DID.
pub fn put_grant(
    rec: &mut MuxDidRecord,
    mut grant: MuxGrant,
    limits: &MuxLimits,
    now: u64,
    principal_count: usize,
) -> Result<Option<MuxGrant>, MuxStoreError> {
    if grant.exp <= now {
        return Err(MuxStoreError::Expired);
    }
    let lifetime = grant.exp.saturating_sub(grant.iat);
    if lifetime > limits.max_grant_lifetime_secs {
        return Err(MuxStoreError::LifetimeTooLong {
            requested: lifetime,
            max: limits.max_grant_lifetime_secs,
        });
    }
    if grant.epoch != rec.epoch {
        return Err(MuxStoreError::EpochMismatch {
            grant: grant.epoch,
            current: rec.epoch,
        });
    }
    if let Some(floor) = rec.floor_for(&grant.principal_hash)
        && grant.iat <= floor
    {
        return Err(MuxStoreError::Replayed { floor });
    }
    if rec.grants.iter().any(|g| g.grant_id == grant.grant_id) {
        return Err(MuxStoreError::GrantIdReused);
    }

    let existing = rec
        .grants
        .iter()
        .position(|g| g.principal_hash == grant.principal_hash);
    if let Some(i) = existing
        && grant.iat <= rec.grants[i].iat
    {
        return Err(MuxStoreError::Replayed {
            floor: rec.grants[i].iat,
        });
    }

    let active_others = rec
        .grants
        .iter()
        .enumerate()
        .filter(|(i, g)| Some(*i) != existing && g.state_at(now).counts_against_quota())
        .count();
    if active_others >= limits.max_grants_per_did {
        return Err(MuxStoreError::DidQuota {
            max: limits.max_grants_per_did,
        });
    }
    if existing.is_none() && principal_count >= limits.max_grants_per_principal {
        return Err(MuxStoreError::PrincipalQuota {
            max: limits.max_grants_per_principal,
        });
    }

    grant.narrowed_scope = None;
    grant.narrowed_exp = None;
    grant.state = MuxGrantState::Active;
    grant.state_changed_at = Some(now);

    let replaced = existing.map(|i| rec.grants.remove(i));
    if let Some(old) = &replaced {
        // The replaced grant's JWS must not be replayable once it is gone.
        rec.raise_floor(&old.principal_hash, old.iat);
    }
    rec.grants.push(grant);
    Ok(replaced)
}

/// The unknown-key rule (§5.3): if `kid` signed none of the DID's active
/// grants, suspend all of them. Returns the grants it suspended — empty when
/// the key is known, or when there are no active grants (so a DID's first
/// grant never trips it).
pub fn suspend_unless_known_kid(rec: &mut MuxDidRecord, kid: &str, now: u64) -> Vec<MuxGrant> {
    let mut active = rec.grants.iter().filter(|g| g.is_usable(now)).peekable();
    if active.peek().is_none() || rec.grants.iter().any(|g| g.is_usable(now) && g.kid == kid) {
        return Vec::new();
    }
    let mut suspended = Vec::new();
    for g in rec.grants.iter_mut().filter(|g| g.is_usable(now)) {
        g.set_state(MuxGrantState::Suspended, now);
        suspended.push(g.clone());
    }
    suspended
}

/// Remove the grants held by these principals on this DID. Each removed
/// grant's principal gets a replay floor at `now`.
pub fn revoke_principals(
    rec: &mut MuxDidRecord,
    principal_hashes: &HashSet<String>,
    now: u64,
) -> Vec<MuxGrant> {
    revoke_where(rec, now, |g| principal_hashes.contains(&g.principal_hash))
}

/// The unknown-key rule for a direct DIDComm authentication, which proves a
/// key-agreement key (`ka_fp`): suspend every active grant unless some active
/// grant recorded that key. Each grant recorded the DID's key-agreement keys
/// when it was stored, so a key listed then is known; one added since is
/// not, including the first key of a DID that listed none.
pub fn suspend_unless_known_key_agreement(
    rec: &mut MuxDidRecord,
    ka_fp: &str,
    now: u64,
) -> Vec<MuxGrant> {
    let mut active = rec.grants.iter().filter(|g| g.is_usable(now)).peekable();
    if active.peek().is_none()
        || rec
            .grants
            .iter()
            .any(|g| g.is_usable(now) && g.key_agreement_fps.iter().any(|f| f == ka_fp))
    {
        return Vec::new();
    }
    suspend_active(rec, now)
}

/// The unknown-key rule for a direct TSP authentication, which proves a
/// signing key (`signing_fp`): suspend every active grant unless one was
/// signed by that key.
pub fn suspend_unless_known_signing_key(
    rec: &mut MuxDidRecord,
    signing_fp: &str,
    now: u64,
) -> Vec<MuxGrant> {
    let mut active = rec.grants.iter().filter(|g| g.is_usable(now)).peekable();
    if active.peek().is_none()
        || rec
            .grants
            .iter()
            .any(|g| g.is_usable(now) && g.key_fp == signing_fp)
    {
        return Vec::new();
    }
    suspend_active(rec, now)
}

fn suspend_active(rec: &mut MuxDidRecord, now: u64) -> Vec<MuxGrant> {
    let mut suspended = Vec::new();
    for g in rec.grants.iter_mut().filter(|g| g.is_usable(now)) {
        g.set_state(MuxGrantState::Suspended, now);
        suspended.push(g.clone());
    }
    suspended
}

/// Remove the grants with these ids on this DID.
pub fn revoke_grant_ids(
    rec: &mut MuxDidRecord,
    grant_ids: &HashSet<String>,
    now: u64,
) -> Vec<MuxGrant> {
    revoke_where(rec, now, |g| grant_ids.contains(&g.grant_id))
}

fn revoke_where(
    rec: &mut MuxDidRecord,
    now: u64,
    pred: impl Fn(&MuxGrant) -> bool,
) -> Vec<MuxGrant> {
    let (removed, kept): (Vec<_>, Vec<_>) =
        std::mem::take(&mut rec.grants).into_iter().partition(&pred);
    rec.grants = kept;
    for g in &removed {
        rec.raise_floor(&g.principal_hash, now.max(g.iat));
    }
    removed
}

/// `revoke-all` (§5.2): bump the epoch and mark every live grant
/// `EpochRevoked`, voided by `by`. Returns the new epoch and the grants it
/// voided.
pub fn revoke_all(rec: &mut MuxDidRecord, now: u64, by: MuxVoidedBy) -> (u64, Vec<MuxGrant>) {
    rec.epoch += 1;
    let mut voided = Vec::new();
    for g in rec.grants.iter_mut().filter(|g| g.is_usable(now)) {
        g.set_state(MuxGrantState::EpochRevoked, now);
        g.voided_by = Some(by);
        voided.push(g.clone());
    }
    (rec.epoch, voided)
}

/// Narrow-only update (§4.7). `exp`, if given, must be in the future.
pub fn narrow(
    rec: &mut MuxDidRecord,
    grant_id: &str,
    scope: Option<MuxScope>,
    exp: Option<u64>,
    now: u64,
) -> Result<MuxGrant, MuxStoreError> {
    let g = rec
        .grants
        .iter_mut()
        .find(|g| g.grant_id == grant_id)
        .ok_or(MuxStoreError::UnknownGrant)?;
    if !g.is_usable(now) {
        return Err(MuxStoreError::NotActive);
    }
    if let Some(s) = &scope
        && !s.is_subset(g.effective_scope())
    {
        return Err(MuxStoreError::WidenRefused);
    }
    if let Some(e) = exp {
        if e > g.effective_exp() {
            return Err(MuxStoreError::WidenRefused);
        }
        if e <= now {
            return Err(MuxStoreError::Expired);
        }
    }
    if let Some(s) = scope {
        g.narrowed_scope = Some(s);
    }
    if let Some(e) = exp {
        g.narrowed_exp = Some(e);
    }
    Ok(g.clone())
}

/// Mark an active grant's signing key stale (§5.1).
pub fn mark_stale_key(rec: &mut MuxDidRecord, grant_id: &str, now: u64) -> Option<MuxGrant> {
    let g = rec
        .grants
        .iter_mut()
        .find(|g| g.grant_id == grant_id && g.is_usable(now))?;
    g.set_state(MuxGrantState::StaleKey, now);
    Some(g.clone())
}

// ─── Store-backed operations ─────────────────────────────────────────────────

/// Read a member DID's record (pruned as of `now`), or an empty one.
pub async fn load<S: MediatorStore + ?Sized>(
    store: &S,
    did_hash: &str,
    limits: &MuxLimits,
    now: u64,
) -> Result<MuxDidRecord, MuxStoreError> {
    let mut rec = store.mux_record_get(did_hash).await?.unwrap_or_default();
    prune(&mut rec, limits, now);
    Ok(rec)
}

/// Apply `rule` to a member DID's record atomically, retrying if another
/// writer got there first. `rule` may run more than once, so it must not have
/// side effects outside the record.
///
/// `principal_hash`, if given, is the principal whose index size `rule`
/// receives (for `max_grants_per_principal`); otherwise it receives 0.
pub async fn modify<S, T, F>(
    store: &S,
    did_hash: &str,
    limits: &MuxLimits,
    now: u64,
    principal_hash: Option<&str>,
    mut rule: F,
) -> Result<T, MuxStoreError>
where
    S: MediatorStore + ?Sized,
    F: FnMut(&mut MuxDidRecord, usize) -> Result<T, MuxStoreError>,
{
    for _ in 0..CAS_ATTEMPTS {
        let current = store.mux_record_get(did_hash).await?;
        let expected = current.as_ref().map(|r| r.version);
        let mut rec = current.clone().unwrap_or_default();
        let before = rec.principals();

        let principal_count = match principal_hash {
            Some(p) => store.mux_principal_count(p).await?,
            None => 0,
        };

        prune(&mut rec, limits, now);
        let out = rule(&mut rec, principal_count)?;

        let after = rec.principals();
        let delta = MuxIndexDelta {
            add: after.difference(&before).cloned().collect(),
            remove: before.difference(&after).cloned().collect(),
        };

        // Nothing changed at all: no write needed.
        if current.as_ref() == Some(&rec) || (current.is_none() && rec.is_empty()) {
            return Ok(out);
        }

        rec.version = expected.unwrap_or(0) + 1;
        let new = (!rec.is_empty()).then_some(&rec);
        if store
            .mux_record_cas(did_hash, expected, new, &delta)
            .await?
        {
            return Ok(out);
        }
    }
    Err(MuxStoreError::Contended)
}

/// One page of the grants a principal holds, ordered by member DID hash.
/// `after` is the last DID hash of the previous page.
pub async fn grants_for_principal<S: MediatorStore + ?Sized>(
    store: &S,
    principal_hash: &str,
    after: Option<&str>,
    limit: usize,
    limits: &MuxLimits,
    now: u64,
) -> Result<(Vec<MuxGrant>, Option<String>), MuxStoreError> {
    let dids = store
        .mux_principal_dids(principal_hash, after, limit)
        .await?;
    let next = (dids.len() == limit)
        .then(|| dids.last().cloned())
        .flatten();
    let mut out = Vec::with_capacity(dids.len());
    for did_hash in dids {
        let rec = load(store, &did_hash, limits, now).await?;
        out.extend(
            rec.grants
                .into_iter()
                .filter(|g| g.principal_hash == principal_hash),
        );
    }
    Ok((out, next))
}

/// Remove everything mux holds about an account being removed, both as a
/// member DID and as a principal.
///
/// Returns the grants that were usable on the account as a member DID: their
/// principals are detached from it and told (`grantsRevoked`,
/// `accountRemoved`). Grants the account held as a principal need no notice:
/// the account and its inbox are gone.
pub async fn remove_account<S: MediatorStore + ?Sized>(
    store: &S,
    did_hash: &str,
    limits: &MuxLimits,
    now: u64,
) -> Result<Vec<MuxGrant>, MuxStoreError> {
    let mut as_member = Vec::new();
    // As a member: the whole record goes, and with it every principal's index
    // entry for it. The epoch goes too — the account itself is gone, and a
    // re-created account starts from nothing.
    for _ in 0..CAS_ATTEMPTS {
        let Some(rec) = store.mux_record_get(did_hash).await? else {
            break;
        };
        let delta = MuxIndexDelta {
            add: Vec::new(),
            remove: rec.principals().into_iter().collect(),
        };
        if store
            .mux_record_cas(did_hash, Some(rec.version), None, &delta)
            .await?
        {
            as_member = rec
                .grants
                .into_iter()
                .filter(|g| g.is_usable(now))
                .collect();
            break;
        }
    }

    // As a principal: drop its grant on every DID that delegated to it.
    // Paged by cursor rather than "re-read until empty": an index entry whose
    // record holds no grant for this principal would otherwise never go away
    // and the loop would never end.
    let me: HashSet<String> = [did_hash.to_string()].into();
    let mut after: Option<String> = None;
    loop {
        let page = store
            .mux_principal_dids(did_hash, after.as_deref(), 100)
            .await?;
        let Some(last) = page.last().cloned() else {
            break;
        };
        after = Some(last);
        for member in page {
            modify(store, &member, limits, now, None, |rec, _| {
                Ok(revoke_principals(rec, &me, now))
            })
            .await?;
        }
    }
    Ok(as_member)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn scope(caps: &[MuxCapability]) -> MuxScope {
        MuxScope::new(caps.iter().copied()).unwrap()
    }

    fn grant(id: &str, principal: &str, kid: &str, iat: u64, epoch: u64) -> MuxGrant {
        MuxGrant {
            grant_id: id.into(),
            did: "did:example:member".into(),
            did_hash: "m".into(),
            principal: format!("did:example:{principal}"),
            principal_hash: principal.into(),
            kid: kid.into(),
            key_fp: "fp".into(),
            did_version: None,
            epoch,
            scope: scope(&[MuxCapability::Receive, MuxCapability::Pickup]),
            iat,
            exp: iat + 3600,
            narrowed_scope: None,
            narrowed_exp: None,
            state: MuxGrantState::Active,
            state_changed_at: None,
            statement: serde_json::json!({}),
            noticed: false,
            key_agreement_fps: Vec::new(),
            expiring_noticed: false,
            voided_by: None,
        }
    }

    fn limits() -> MuxLimits {
        MuxLimits::default()
    }

    #[test]
    fn grant_states_use_the_spec_wire_names() {
        assert_eq!(
            serde_json::to_string(&MuxGrantState::StaleKey).unwrap(),
            r#""staleKey""#
        );
        assert_eq!(
            serde_json::to_string(&MuxGrantState::EpochRevoked).unwrap(),
            r#""epochRevoked""#
        );
    }

    #[test]
    fn empty_scope_is_refused() {
        assert!(matches!(MuxScope::new([]), Err(MuxStoreError::EmptyScope)));
        assert!(serde_json::from_str::<MuxScope>("[]").is_err());
    }

    #[test]
    fn scope_wire_form_is_camel_case_array() {
        let s = scope(&[MuxCapability::Pickup, MuxCapability::Receive]);
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"["receive","pickup"]"#
        );
    }

    #[test]
    fn notice_forms_follow_the_tracked_notices_within_their_bounds() {
        let mut rec = MuxDidRecord::default();
        rec.track_notice(
            "n1".into(),
            NoticeWire::DidComm,
            serde_json::json!({"n": 1}),
        );
        rec.track_notice("n2".into(), NoticeWire::Tsp, serde_json::json!({"n": 2}));
        assert_eq!(rec.notices, vec!["n1", "n2"]);
        assert_eq!(rec.notice_forms.len(), 2);

        // Re-issued for the other wire under a new id.
        rec.retrack_notice("n1", "n1b".into(), NoticeWire::Tsp);
        assert_eq!(rec.notices, vec!["n1b", "n2"]);
        assert_eq!(rec.notice_forms[0].id, "n1b");
        assert_eq!(rec.notice_forms[0].wire, NoticeWire::Tsp);

        // Forgotten with the notice.
        rec.forget_notices(&HashSet::from(["n2".to_string()]));
        assert_eq!(rec.notices, vec!["n1b"]);
        assert_eq!(rec.notice_forms.len(), 1);

        // Bounded by count, oldest first.
        for i in 0..MAX_NOTICE_FORMS + 5 {
            rec.track_notice(format!("c{i}"), NoticeWire::Tsp, serde_json::json!({}));
        }
        assert_eq!(rec.notice_forms.len(), MAX_NOTICE_FORMS);
        assert_eq!(
            rec.notice_forms.last().unwrap().id,
            format!("c{}", MAX_NOTICE_FORMS + 4)
        );
        assert!(
            rec.notices.len() > MAX_NOTICE_FORMS,
            "older notices stay counted"
        );

        // And by payload bytes.
        let big = serde_json::json!({ "x": "y".repeat(MAX_NOTICE_FORM_BYTES / 2) });
        for i in 0..3 {
            rec.track_notice(format!("b{i}"), NoticeWire::Tsp, big.clone());
        }
        let total: usize = rec
            .notice_forms
            .iter()
            .map(|f| f.payload.to_string().len())
            .sum();
        assert!(total <= MAX_NOTICE_FORM_BYTES, "{total}");
        assert_eq!(rec.notice_forms.last().unwrap().id, "b2");
    }

    #[test]
    fn a_record_from_before_notice_forms_reads_and_round_trips() {
        let old = r#"{"version":3,"epoch":0,"grants":[],"notices":["n1"]}"#;
        let rec: MuxDidRecord = serde_json::from_str(old).unwrap();
        assert_eq!(rec.notices, vec!["n1"]);
        assert!(rec.notice_forms.is_empty() && rec.wire.is_none());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains("noticeForms") && !json.contains("wire"),
            "{json}"
        );
        let mut rec = rec;
        rec.wire = Some(NoticeWire::DidComm);
        assert!(
            serde_json::to_string(&rec)
                .unwrap()
                .contains(r#""wire":"didcomm""#)
        );
    }

    #[test]
    fn a_grant_under_a_stale_epoch_is_refused() {
        let mut rec = MuxDidRecord {
            epoch: 2,
            ..Default::default()
        };
        let err =
            put_grant(&mut rec, grant("g1", "p", "k1", NOW, 1), &limits(), NOW, 0).unwrap_err();
        assert!(matches!(
            err,
            MuxStoreError::EpochMismatch {
                grant: 1,
                current: 2
            }
        ));
    }

    #[test]
    fn replacing_a_grant_needs_a_newer_one_and_blocks_replay_of_the_old() {
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();

        // Same or older iat: refused.
        let err =
            put_grant(&mut rec, grant("g2", "p", "k1", NOW, 0), &limits(), NOW, 1).unwrap_err();
        assert!(matches!(err, MuxStoreError::Replayed { .. }));

        let replaced = put_grant(
            &mut rec,
            grant("g2", "p", "k1", NOW + 1, 0),
            &limits(),
            NOW + 1,
            1,
        )
        .unwrap()
        .expect("replaced g1");
        assert_eq!(replaced.grant_id, "g1");

        // g1 again (a new id, but its iat): below the floor.
        let err = put_grant(
            &mut rec,
            grant("g1b", "p", "k1", NOW, 0),
            &limits(),
            NOW + 1,
            1,
        )
        .unwrap_err();
        assert!(matches!(err, MuxStoreError::Replayed { .. }));
    }

    #[test]
    fn a_revoked_grant_cannot_be_replayed() {
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        let gone = revoke_principals(&mut rec, &["p".to_string()].into(), NOW + 5);
        assert_eq!(gone.len(), 1);
        assert!(rec.grants.is_empty());

        let err = put_grant(
            &mut rec,
            grant("g1", "p", "k1", NOW, 0),
            &limits(),
            NOW + 6,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, MuxStoreError::Replayed { floor } if floor == NOW + 5));
        // A grant signed after the revoke is fine.
        put_grant(
            &mut rec,
            grant("g3", "p", "k1", NOW + 6, 0),
            &limits(),
            NOW + 6,
            0,
        )
        .unwrap();
    }

    #[test]
    fn voided_by_reads_old_records_and_unknown_values() {
        // A record stored before the field existed has none, and one without
        // it serializes as before.
        let g = grant("g1", "p", "k1", NOW, 0);
        let v = serde_json::to_value(&g).unwrap();
        assert!(v.get("voidedBy").is_none());
        assert_eq!(
            serde_json::from_value::<MuxGrant>(v.clone())
                .unwrap()
                .voided_by,
            None
        );
        let mut admin = v.clone();
        admin["voidedBy"] = "admin".into();
        assert_eq!(
            serde_json::from_value::<MuxGrant>(admin).unwrap().voided_by,
            Some(MuxVoidedBy::Admin)
        );
        // A value a later version writes does not make the record unreadable.
        let mut later = v;
        later["voidedBy"] = "somethingNew".into();
        assert_eq!(
            serde_json::from_value::<MuxGrant>(later).unwrap().voided_by,
            Some(MuxVoidedBy::Unknown)
        );
    }

    #[test]
    fn revoke_all_bumps_the_epoch_and_voids_live_grants() {
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        put_grant(&mut rec, grant("g2", "q", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        let (epoch, voided) = revoke_all(&mut rec, NOW + 1, MuxVoidedBy::Admin);
        assert_eq!(epoch, 1);
        assert_eq!(voided.len(), 2);
        assert!(
            rec.grants
                .iter()
                .all(|g| g.state == MuxGrantState::EpochRevoked
                    && g.voided_by == Some(MuxVoidedBy::Admin))
        );
        // The old grant can't come back under the old epoch.
        let err = put_grant(
            &mut rec,
            grant("g4", "r", "k1", NOW + 2, 0),
            &limits(),
            NOW + 2,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, MuxStoreError::EpochMismatch { .. }));
    }

    #[test]
    fn an_unknown_key_suspends_active_grants_but_a_known_one_does_not() {
        let mut rec = MuxDidRecord::default();
        // First grant: nothing to suspend.
        assert!(suspend_unless_known_kid(&mut rec, "k1", NOW).is_empty());
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        put_grant(&mut rec, grant("g2", "q", "k1", NOW, 0), &limits(), NOW, 0).unwrap();

        assert!(suspend_unless_known_kid(&mut rec, "k1", NOW).is_empty());
        let suspended = suspend_unless_known_kid(&mut rec, "k2", NOW + 1);
        assert_eq!(suspended.len(), 2);
        assert!(
            rec.grants
                .iter()
                .all(|g| g.state == MuxGrantState::Suspended)
        );
        // Suspended grants are not usable and are not resurrected by narrow.
        assert!(matches!(
            narrow(&mut rec, "g1", None, Some(NOW + 10), NOW + 2),
            Err(MuxStoreError::NotActive)
        ));
    }

    #[test]
    fn a_new_grant_from_a_new_key_survives_the_suspension_it_causes() {
        // The caller runs suspend-then-put; the new grant lands active.
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        let s = suspend_unless_known_kid(&mut rec, "k2", NOW + 1);
        assert_eq!(s.len(), 1);
        put_grant(
            &mut rec,
            grant("g2", "q", "k2", NOW + 1, 0),
            &limits(),
            NOW + 1,
            0,
        )
        .unwrap();
        let g2 = rec.grants.iter().find(|g| g.grant_id == "g2").unwrap();
        assert_eq!(g2.state, MuxGrantState::Active);
        // And the suspended principal can recreate with a newer grant.
        put_grant(
            &mut rec,
            grant("g3", "p", "k2", NOW + 2, 0),
            &limits(),
            NOW + 2,
            1,
        )
        .unwrap();
        assert!(
            rec.grants
                .iter()
                .filter(|g| g.principal_hash == "p")
                .all(|g| g.is_usable(NOW + 2))
        );
    }

    #[test]
    fn narrow_only() {
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        let g = narrow(
            &mut rec,
            "g1",
            Some(scope(&[MuxCapability::Receive])),
            Some(NOW + 60),
            NOW,
        )
        .unwrap();
        assert_eq!(g.effective_exp(), NOW + 60);
        assert!(!g.effective_scope().contains(MuxCapability::Pickup));
        // Widening back is refused, for scope and for exp.
        assert!(matches!(
            narrow(
                &mut rec,
                "g1",
                Some(scope(&[MuxCapability::Receive, MuxCapability::Pickup])),
                None,
                NOW
            ),
            Err(MuxStoreError::WidenRefused)
        ));
        assert!(matches!(
            narrow(&mut rec, "g1", None, Some(NOW + 120), NOW),
            Err(MuxStoreError::WidenRefused)
        ));
    }

    #[test]
    fn lifetime_and_expiry_are_enforced() {
        let mut rec = MuxDidRecord::default();
        let mut g = grant("g1", "p", "k1", NOW, 0);
        g.exp = NOW + limits().max_grant_lifetime_secs + 1;
        assert!(matches!(
            put_grant(&mut rec, g, &limits(), NOW, 0),
            Err(MuxStoreError::LifetimeTooLong { .. })
        ));
        let g = grant("g1", "p", "k1", NOW - 7200, 0);
        assert!(matches!(
            put_grant(&mut rec, g, &limits(), NOW, 0),
            Err(MuxStoreError::Expired)
        ));
    }

    #[test]
    fn quotas() {
        let l = MuxLimits {
            max_grants_per_did: 1,
            max_grants_per_principal: 1,
            ..limits()
        };
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &l, NOW, 0).unwrap();
        assert!(matches!(
            put_grant(&mut rec, grant("g2", "q", "k1", NOW, 0), &l, NOW, 0),
            Err(MuxStoreError::DidQuota { max: 1 })
        ));
        // Replacing your own grant doesn't count against either quota.
        put_grant(&mut rec, grant("g3", "p", "k1", NOW + 1, 0), &l, NOW + 1, 1).unwrap();

        let mut other = MuxDidRecord::default();
        assert!(matches!(
            put_grant(&mut other, grant("g4", "p", "k1", NOW, 0), &l, NOW, 1),
            Err(MuxStoreError::PrincipalQuota { max: 1 })
        ));
    }

    #[test]
    fn dead_grants_are_listed_until_retention_then_pruned() {
        let l = limits();
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &l, NOW, 0).unwrap();
        let exp = rec.grants[0].exp;
        assert_eq!(rec.grants[0].state_at(exp), MuxGrantState::Expired);
        prune(&mut rec, &l, exp + l.dead_retention_secs - 1);
        assert_eq!(rec.grants.len(), 1);
        prune(&mut rec, &l, exp + l.dead_retention_secs);
        assert!(rec.grants.is_empty());
    }

    #[test]
    fn replay_floors_prune_once_nothing_could_still_be_valid() {
        let l = limits();
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &l, NOW, 0).unwrap();
        revoke_principals(&mut rec, &["p".to_string()].into(), NOW);
        prune(&mut rec, &l, NOW + l.max_grant_lifetime_secs);
        assert_eq!(rec.replay_floors.len(), 1);
        prune(&mut rec, &l, NOW + l.max_grant_lifetime_secs + 1);
        assert!(rec.replay_floors.is_empty());
    }

    #[test]
    fn stale_key_is_terminal() {
        let mut rec = MuxDidRecord::default();
        put_grant(&mut rec, grant("g1", "p", "k1", NOW, 0), &limits(), NOW, 0).unwrap();
        assert!(mark_stale_key(&mut rec, "g1", NOW).is_some());
        assert_eq!(rec.grants[0].state, MuxGrantState::StaleKey);
        assert!(mark_stale_key(&mut rec, "g1", NOW).is_none());
        // The same key "coming back" changes nothing: the grant stays stale.
        assert!(suspend_unless_known_kid(&mut rec, "k1", NOW).is_empty());
        assert!(!rec.grants[0].is_usable(NOW));
    }

    #[test]
    fn a_direct_didcomm_login_is_compared_with_recorded_key_agreement_keys() {
        let mut rec = MuxDidRecord::default();
        let mut g1 = grant("g1", "p1", "k1", NOW - 10, 0);
        g1.key_agreement_fps = vec!["ka1".into(), "ka2".into()];
        let mut g2 = grant("g2", "p2", "k1", NOW - 10, 0);
        g2.key_agreement_fps = vec!["ka1".into()];
        rec.grants = vec![g1, g2];

        // A key-agreement key listed when the grants were stored is known,
        // whichever grant recorded it.
        assert!(suspend_unless_known_key_agreement(&mut rec, "ka1", NOW).is_empty());
        assert!(suspend_unless_known_key_agreement(&mut rec, "ka2", NOW).is_empty());
        // A key added since is not: every active grant is suspended.
        let s = suspend_unless_known_key_agreement(&mut rec, "ka3", NOW);
        assert_eq!(s.len(), 2);
        assert!(
            rec.grants
                .iter()
                .all(|g| g.state == MuxGrantState::Suspended)
        );
        // With nothing active, nothing more fires.
        assert!(suspend_unless_known_key_agreement(&mut rec, "ka9", NOW).is_empty());
    }

    #[test]
    fn a_grant_that_recorded_no_keys_does_not_exempt_the_others() {
        // One grant recorded the key-agreement key, the other recorded none
        // (its DID listed none then): an unknown key still suspends both.
        let mut rec = MuxDidRecord::default();
        let mut g1 = grant("g1", "p1", "k1", NOW - 10, 0);
        g1.key_agreement_fps = vec!["ka1".into()];
        rec.grants = vec![g1, grant("g2", "p2", "k1", NOW - 10, 0)];
        assert!(suspend_unless_known_key_agreement(&mut rec, "ka1", NOW).is_empty());
        assert_eq!(
            suspend_unless_known_key_agreement(&mut rec, "ka3", NOW).len(),
            2
        );
        assert!(rec.grants.iter().all(|g| !g.is_usable(NOW)));
    }

    #[test]
    fn the_first_key_agreement_key_of_a_did_that_listed_none_is_unknown() {
        let mut rec = MuxDidRecord {
            grants: vec![grant("g1", "p1", "k1", NOW - 10, 0)],
            ..Default::default()
        };
        assert_eq!(
            suspend_unless_known_key_agreement(&mut rec, "ka1", NOW).len(),
            1
        );
    }

    #[test]
    fn a_direct_tsp_login_is_compared_with_the_grants_signing_keys() {
        let mut rec = MuxDidRecord::default();
        let mut g = grant("g1", "p1", "k1", NOW - 10, 0);
        g.key_fp = "fp1".into();
        rec.grants = vec![g];
        assert!(suspend_unless_known_signing_key(&mut rec, "fp1", NOW).is_empty());
        assert_eq!(
            suspend_unless_known_signing_key(&mut rec, "fp2", NOW).len(),
            1
        );
    }

    #[test]
    fn a_grant_is_expiring_from_three_quarters_of_its_lifetime() {
        // iat NOW, exp NOW + 3600: expiring from NOW + 2700 until it lapses.
        let g = grant("g1", "p1", "k1", NOW, 0);
        assert!(!g.is_expiring(NOW + 2699));
        assert!(g.is_expiring(NOW + 2700));
        assert!(g.is_expiring(NOW + 3599));
        assert!(
            !g.is_expiring(NOW + 3600),
            "an expired grant is not expiring"
        );
        let mut narrowed = g.clone();
        narrowed.narrowed_exp = Some(NOW + 400);
        assert!(
            narrowed.is_expiring(NOW + 300),
            "the effective expiry counts"
        );
        let mut dead = g;
        dead.state = MuxGrantState::Suspended;
        assert!(!dead.is_expiring(NOW + 3000));
    }
}
