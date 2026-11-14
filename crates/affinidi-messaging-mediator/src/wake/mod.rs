//! Waking an account's device when a sender with mail queued for it asks
//! (OpenVTC/verifiable-trust-infrastructure#2663; VTI-TRN-070 – 074).
//!
//! Two Trust Tasks, both served here:
//!
//! - **`messaging/wake/set/0.1`** — an account gives this mediator the opaque
//!   wake handle its push gateway issued, or takes it back (`wake::set`). One
//!   record per account, kept in the store and removed with the account.
//! - **`messaging/wake/request/0.1`** — any sender that has just queued mail
//!   for an account asks this mediator to ring it (`wake::request`). The sender is
//!   usually not an account here and its request usually arrives relayed by
//!   its own mediator, so it is accepted from a sender with no account, for
//!   this one type only, and never makes an account.
//!
//! The mediator alone decides whether to ring (the seven rules in
//! `wake::request`), rings the gateway **as itself** with `push/wake/0.2`, and
//! answers every request with the same empty `{}` whatever it decided, so the
//! task cannot be used to learn whether a DID is an account here, is wakeable,
//! is online or was rung. What happened is visible only to the operator, in
//! [`WAKE_REQUESTS_TOTAL`](crate::common::metrics::names::WAKE_REQUESTS_TOTAL).
//!
//! # What lives where
//!
//! The handle record is durable and shared by every instance (the store).
//! The per-message "has rung" marker is the store's duplicate-execution
//! record, so it is atomic across instances too. The rate-limit counters,
//! the armed requests and the rings awaiting a gateway answer are in this
//! instance's memory: a mediator running several instances applies the
//! limits per instance, and a gateway answer that reaches another instance
//! is not acted on (the next ring meets the same answer).

// Ringing is a DIDComm send: without DIDComm the ring and answer state is
// kept but never used, and every request is evaluated to `disabled`.
#![cfg_attr(not(feature = "didcomm"), allow(dead_code))]

#[cfg(feature = "didcomm")]
pub(crate) mod didcomm;
pub(crate) mod limits;
pub(crate) mod request;
#[cfg(feature = "didcomm")]
pub(crate) mod ring;
pub(crate) mod set;

use std::collections::HashMap;
use std::sync::Mutex;

use affinidi_messaging_mediator_common::errors::MediatorError;
use serde::{Deserialize, Serialize};

use crate::SharedData;

/// How long after it was stored a message may still be named in a wake
/// request (`messaging/wake/request/0.1` Consumer rule 2).
pub(crate) const MAX_MESSAGE_AGE_SECS: u64 = 600;

/// How long a request naming messages not stored yet is held for them
/// (`messaging/wake/request/0.1` "Arming").
pub(crate) const ARM_SECS: u64 = 120;

/// The most requests held armed at once. A request that would exceed it is
/// dropped, which costs a wake and nothing else: the mail is still queued.
pub(crate) const MAX_ARMED: usize = 1024;

/// The most rings awaiting a gateway answer at once.
pub(crate) const MAX_PENDING_RINGS: usize = 4096;

/// How long a ring waits for the gateway's answer before it is forgotten.
pub(crate) const PENDING_RING_SECS: u64 = 300;

/// What the mediator holds for an account that set a wake handle.
///
/// Stored as JSON through [`MediatorStore::wake_handle_set`]; opaque to the
/// store.
///
/// [`MediatorStore::wake_handle_set`]: affinidi_messaging_mediator_common::store::MediatorStore::wake_handle_set
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WakeRecord {
    /// The gateway that issued the handle, and the only party the handle is
    /// ever sent to.
    pub gateway: String,
    /// The opaque handle. Never disclosed to anyone but `gateway`.
    pub handle: String,
    /// The gateway answered a ring `notAllowed`: this mediator is not on the
    /// handle's allowlist, so it does not ring the handle again until the
    /// account sets one (`messaging/wake/set/0.1` Consumer rule 6).
    #[serde(default)]
    pub not_allowed: bool,
}

impl WakeRecord {
    /// The record held for `did_hash`, if any. A record that does not parse
    /// is treated as absent: ringing on a guess would be worse.
    pub(crate) async fn load(
        state: &SharedData,
        did_hash: &str,
    ) -> Result<Option<WakeRecord>, MediatorError> {
        Ok(state
            .database
            .wake_handle_get(did_hash)
            .await?
            .and_then(|json| serde_json::from_str(&json).ok()))
    }

    /// Store this record for `did_hash`, replacing whatever was held.
    pub(crate) async fn save(
        &self,
        state: &SharedData,
        did_hash: &str,
    ) -> Result<(), MediatorError> {
        let json = serde_json::to_string(self).map_err(|e| {
            MediatorError::InternalError(
                crate::error_codes::INTERNAL_ERROR,
                "NA".into(),
                format!("wake record: {e}"),
            )
        })?;
        state.database.wake_handle_set(did_hash, Some(&json)).await
    }
}

/// One wake request, verified, as the rules evaluate it.
#[derive(Clone, Debug)]
pub(crate) struct WakeRequest {
    /// The requester `W`: the verified proof's issuer, which the transport
    /// authenticated too.
    pub requester: String,
    pub requester_hash: String,
    /// The account to ring, by DID hash.
    pub addressee_hash: String,
    /// The stored ids named, distinct, 1 to 8.
    pub msg_ids: Vec<String>,
    /// `interactive` / `background`, passed to the gateway as is.
    pub urgency: Option<String>,
}

/// A request waiting for its messages to be stored.
#[derive(Clone, Debug)]
pub(crate) struct Armed {
    pub request: WakeRequest,
    /// Unix seconds after which it is discarded.
    pub deadline: u64,
}

/// A ring sent to a gateway and not yet answered.
#[derive(Clone, Debug)]
pub(crate) struct PendingRing {
    pub addressee_hash: String,
    pub gateway: String,
    pub handle: String,
    /// Unix seconds after which the answer is no longer awaited.
    pub expires: u64,
}

/// This instance's wake state: rate limits, armed requests, unanswered rings.
#[derive(Default)]
pub struct WakeService {
    pub(crate) limiter: Mutex<limits::Limiter>,
    pub(crate) armed: Mutex<Vec<Armed>>,
    pub(crate) pending: Mutex<HashMap<String, PendingRing>>,
}

impl std::fmt::Debug for WakeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeService").finish_non_exhaustive()
    }
}

impl WakeService {
    /// Hold `armed` until its messages are stored. `false` when too many
    /// requests are already held.
    pub(crate) fn arm(&self, armed: Armed) -> bool {
        let mut held = self.armed.lock().unwrap_or_else(|e| e.into_inner());
        if held.len() >= MAX_ARMED {
            return false;
        }
        held.push(armed);
        true
    }

    /// Take every armed request for `to_did_hash` that names `msg_id`, for
    /// evaluation now that the message is stored.
    pub(crate) fn take_matching(&self, to_did_hash: &str, msg_id: &str) -> Vec<Armed> {
        let mut held = self.armed.lock().unwrap_or_else(|e| e.into_inner());
        if held.is_empty() {
            return Vec::new();
        }
        let (taken, kept): (Vec<_>, Vec<_>) = held.drain(..).partition(|a| {
            a.request.addressee_hash == to_did_hash
                && a.request.msg_ids.iter().any(|id| id == msg_id)
        });
        *held = kept;
        taken
    }

    /// Take every armed request, for the periodic re-evaluation that catches
    /// a message stored by another instance.
    pub(crate) fn take_all(&self) -> Vec<Armed> {
        std::mem::take(&mut *self.armed.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Remember a ring until the gateway answers it. Forgets expired ones
    /// first; `false` when the table is still full.
    pub(crate) fn await_answer(&self, ring_id: String, ring: PendingRing, now: u64) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.len() >= MAX_PENDING_RINGS {
            pending.retain(|_, r| r.expires > now);
        }
        if pending.len() >= MAX_PENDING_RINGS {
            return false;
        }
        pending.insert(ring_id, ring);
        true
    }

    /// The ring `thread_id` answers, if it is awaited from `sender`. Taken
    /// only when it is, so a third party naming the thread cannot discard it.
    pub(crate) fn take_answered(
        &self,
        thread_id: &str,
        sender: &str,
        now: u64,
    ) -> Option<PendingRing> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let ring = pending.get(thread_id)?;
        if ring.expires <= now
            || !affinidi_messaging_mediator_common::did_identity::same_account(
                &ring.gateway,
                sender,
            )
        {
            return None;
        }
        pending.remove(thread_id)
    }

    /// Whether a ring with this id is awaited (from anyone).
    pub(crate) fn awaits(&self, thread_id: &str) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(thread_id)
    }
}

/// Count a wake request's outcome. Aggregate only: no requester or addressee
/// is ever a label (`messaging/wake/request/0.1` "Retention").
pub(crate) fn count_outcome(outcome: &'static str) {
    tracing::debug!(outcome, "wake request evaluated");
    metrics::counter!(
        crate::common::metrics::names::WAKE_REQUESTS_TOTAL,
        "outcome" => outcome
    )
    .increment(1);
}
