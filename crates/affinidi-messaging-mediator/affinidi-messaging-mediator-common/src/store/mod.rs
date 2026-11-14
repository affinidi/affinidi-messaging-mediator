//! Storage backend trait for the Affinidi Messaging Mediator.
//!
//! [`MediatorStore`] is the semantic interface every backend must satisfy.
//! It is shaped from the *consumer* perspective — what the mediator's
//! request handlers, background tasks, and processors actually need —
//! rather than wrapping any one backend's primitives.
//!
//! # Backend selection
//!
//! Three feature-flagged implementations live alongside this trait:
//!
//! | Feature           | Backend       | Use case                                          |
//! |-------------------|---------------|---------------------------------------------------|
//! | `redis-backend`   | `RedisStore`  | Multi-mediator clusters, cross-process pub/sub    |
//! | `fjall-backend`   | `FjallStore`  | Single-node persistent deployments (no Redis dep) |
//! | `memory-backend`  | `MemoryStore` | Tests; in-process only, no persistence            |
//!
//! Default backend for the mediator binary is `redis-backend`. The mediator
//! binary instantiates one impl, boxes it as `Arc<dyn MediatorStore>`, and
//! wires it through `MediatorBuilder`.
//!
//! # Multi-process semantics
//!
//! Only `RedisStore` supports multiple mediator processes sharing one
//! storage backend. `FjallStore` and `MemoryStore` are single-process by
//! construction — their pub/sub channels and consumer-group semantics
//! exist only within the running mediator. Methods whose contract differs
//! between single-process and multi-process backends call this out.
//!
//! # Atomicity
//!
//! Every method is atomic at its own scope: a single trait method either
//! succeeds in full or fails leaving no partial state. Composite operations
//! that span multiple methods are not transactional — callers must accept
//! that intermediate states are observable.
//!
//! # Error model
//!
//! All methods return [`MediatorError`]. Backends translate native errors
//! (Redis `RedisError`, Fjall `Error`, Tokio sync errors) into the
//! mediator's error type. The error variants carry enough context for
//! request handlers to map them to HTTP/DIDComm problem reports.

use crate::error_codes;
use crate::errors::MediatorError;
use crate::types::messages::{Folder, MessageListElement};
pub mod fair_pickup;

/// How much of the queue a fair pickup looks at, as a multiple of the caller's
/// limit.
///
/// Enough to see past one sender's burst without reading the whole queue: at
/// the default per-relationship cap of 50, a window of ten times a typical
/// pickup limit reaches well past any single sender's share.
pub const FAIR_WINDOW_FACTOR: usize = 10;

/// Hard ceiling on that window, so a caller asking for a large limit cannot
/// turn one pickup into a queue scan.
pub const MAX_FAIR_WINDOW: usize = 500;

/// How many handovers make a message worth reporting as possibly poison.
///
/// A threshold for **classification only**. Nothing is evicted because of it,
/// and that is deliberate: `attempts` is driven by the recipient, which decides
/// when to fetch, so acting on it would let a recipient destroy a sender's
/// messages by doing nothing but collecting them repeatedly. See
/// [`DeliveryState::attempts`](crate::store::types::DeliveryState::attempts).
pub const POISON_ATTEMPTS: u32 = 5;

/// Metric names emitted by [`MediatorStore::fetch_messages_delivering`].
///
/// Defined here, beside the code that emits them, and re-exported from the
/// mediator's own `metrics::names` where every other metric is documented —
/// one definition, discoverable in the usual place.
pub mod delivery_metrics {
    /// counter: messages handed to a recipient for the first time.
    pub const FIRST_DELIVERED: &str = "messages_first_delivered_total";
    /// counter: handovers of a message that had already been delivered.
    pub const REDELIVERED: &str = "messages_redelivered_total";
    /// counter: handovers of a message already delivered at least
    /// [`POISON_ATTEMPTS`](super::POISON_ATTEMPTS) times.
    pub const POISON_SUSPECTED: &str = "messages_poison_suspected_total";
    /// counter: messages whose expiry was brought forward because they had
    /// been delivered.
    pub const DELIVERED_EXPIRY_ADVANCED: &str = "messages_delivered_expiry_advanced_total";
}

/// What one [`mark_delivered`](MediatorStore::mark_delivered) call did.
///
/// Returned rather than logged so the caller decides what to do with it — the
/// shared fetch wrapper turns it into counters, and a backend that records
/// nothing returns it empty.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryMarkReport {
    /// Messages handed over for the first time.
    pub first_delivered: usize,
    /// Messages that had been handed over before.
    pub redelivered: usize,
    /// Redeliveries of a message already past [`POISON_ATTEMPTS`].
    pub poison_suspected: usize,
    /// Messages whose expiry was brought forward.
    pub expiry_advanced: usize,
    /// Bytes of the messages handed over (first deliveries and
    /// redeliveries), for the global sent counters.
    pub bytes: usize,
}

/// Turn a [`DeliveryMarkReport`] into counters.
///
/// Only non-zero fields are touched, so a deployment with the delivered-expiry
/// shortening off never emits that series at all rather than emitting a flat
/// zero — the two look different on a dashboard and mean different things.
pub(crate) fn publish_delivery_metrics(report: &DeliveryMarkReport) {
    for (name, value) in [
        (delivery_metrics::FIRST_DELIVERED, report.first_delivered),
        (delivery_metrics::REDELIVERED, report.redelivered),
        (delivery_metrics::POISON_SUSPECTED, report.poison_suspected),
        (
            delivery_metrics::DELIVERED_EXPIRY_ADVANCED,
            report.expiry_advanced,
        ),
    ] {
        if value > 0 {
            metrics::counter!(name).increment(value as u64);
        }
    }
}

/// Ceiling on messages one filtered purge will examine.
///
/// A filtered purge walks the folder, and a **dry run walks it without
/// shrinking it** — so, unlike the real purge, it is perfectly repeatable at
/// full cost. That makes it the most expensive thing an authenticated DID can
/// ask for per request, by roughly two orders of magnitude over `/list`, which
/// is capped at 100. The per-DID rate limiter bounds how often a caller may
/// ask; this bounds how much each ask costs.
///
/// A caller with a deeper queue than this gets a partial purge that reports
/// itself as such, and re-running continues against a folder that is now
/// shorter.
pub const MAX_PURGE_SCAN: usize = 10_000;

/// Which messages a [`purge_folder_filtered`](MediatorStore::purge_folder_filtered)
/// call should remove.
///
/// An empty filter matches everything, which is what the unfiltered
/// [`purge_folder`](MediatorStore::purge_folder) already does faster — so a
/// caller with nothing to narrow by should use that instead.
#[derive(Debug, Default, Clone)]
pub struct PurgeFilter {
    /// Only messages exchanged with this counterparty (a DID *hash*).
    ///
    /// "Counterparty" rather than "recipient" because which end that is
    /// depends on the folder: in an outbox it is who the message was sent to,
    /// in an inbox who sent it. Naming it for one of those would be wrong half
    /// the time.
    pub peer: Option<String>,
    /// Only messages that arrived at or before this Unix millisecond.
    ///
    /// Arrival, not expiry: expiry is `min(client_expires_time, now + TTL)`
    /// and a client may set a short one, so ordering by it does not order by
    /// age. The stream id carries the arrival stamp and a client cannot
    /// reorder it.
    pub arrived_before_ms: Option<u64>,
    /// Count what would be removed and remove nothing.
    ///
    /// A purge is destructive and unrecoverable, and the operator reaching for
    /// it is usually reacting to an incident. Being able to ask first is the
    /// difference between a recovery tool and a second incident.
    pub dry_run: bool,
}

impl PurgeFilter {
    /// Whether `element` in `folder` is in scope.
    pub fn matches(&self, element: &MessageListElement, folder: &Folder) -> bool {
        if let Some(peer) = &self.peer {
            let counterparty = match folder {
                Folder::Inbox => element.from_address.as_deref(),
                Folder::Outbox => element.to_address.as_deref(),
            };
            // A message whose counterparty is unrecorded (an anonymous sender)
            // never matches a `peer` filter: it cannot be shown to be the peer
            // asked for, and a purge must not delete on a maybe.
            if counterparty != Some(peer.as_str()) {
                return false;
            }
        }
        if let Some(before) = self.arrived_before_ms
            && element.timestamp > before
        {
            return false;
        }
        true
    }
}

/// For account removal: an error when the inbox purge left messages queued,
/// so the account is not removed with messages still stored for it. The
/// account stays blocked; running the removal again retries them.
pub fn purge_left_messages(did_hash: &str, report: &PurgeReport) -> Result<(), MediatorError> {
    if report.failed == 0 {
        return Ok(());
    }
    Err(MediatorError::DatabaseError(
        error_codes::DB_OPERATION_ERROR,
        "NA".into(),
        format!(
            "Account ({did_hash}) is blocked but not removed: {} of its queued messages could not be deleted; retry the removal",
            report.failed
        ),
    ))
}

/// Messages one purge page lists and deletes together.
const PURGE_PAGE: u32 = 100;

/// The purge every backend runs ([`MediatorStore::purge_folder_by`]): one
/// algorithm, so the backends cannot disagree on what a purge does.
///
/// - Pages through the folder by cursor (the exclusive successor of the
///   last stream id seen), deleting each page's messages together — on
///   Redis one pipelined batch per page rather than a round trip each.
/// - A message already gone (a concurrent pickup, the expiry sweep) is not
///   a failure: it is absent, as asked. Its stream entry, which names
///   nothing, is removed explicitly.
/// - Any other refusal is counted in [`PurgeReport::failed`] and the walk
///   goes on, so one undeletable message cannot hold up the rest. Its entry
///   stays: only entries whose message was removed leave the folder, so a
///   message still stored is never left unlisted.
///
/// `count`/`bytes` are what this call removed. Public so the conformance
/// suite can run it directly.
pub async fn purge_folder_by_listing<S: MediatorStore + ?Sized>(
    store: &S,
    _session_id: &str,
    did_hash: &str,
    folder: Folder,
    by: DeletionAuthority,
) -> Result<PurgeReport, MediatorError> {
    let mut report = PurgeReport::default();
    let mut cursor = "-".to_string();
    let mut orphans: Vec<String> = Vec::new();
    loop {
        let page = store
            .list_messages(did_hash, folder.clone(), Some((&cursor, "+")), PURGE_PAGE)
            .await?;
        if page.is_empty() {
            break;
        }
        let outcomes = futures_util::future::join_all(page.iter().map(|element| {
            // The copy in this folder, named by its recipient: the owner in
            // an inbox, the listed recipient in an outbox.
            let scope = match (&folder, element.to_address.as_deref()) {
                (Folder::Inbox, _) => MessageScope::Recipient(did_hash),
                (Folder::Outbox, Some(to)) => MessageScope::Recipient(to),
                (Folder::Outbox, None) => MessageScope::Party(did_hash),
            };
            let by = by.clone();
            async move { store.delete_message_in(&element.msg_id, scope, by).await }
        }))
        .await;

        let mut last_id = None;
        for (element, outcome) in page.iter().zip(outcomes) {
            let stream_id = match folder {
                Folder::Inbox => element.receive_id.as_deref(),
                Folder::Outbox => element.send_id.as_deref(),
            };
            last_id = stream_id.map(str::to_string).or(last_id);
            report.scanned += 1;
            match outcome {
                Ok(_) => {
                    report.count += 1;
                    report.bytes += element.size as usize;
                }
                Err(e) if ops::is_delete_not_found(&e) => {
                    if let Some(id) = stream_id {
                        orphans.push(id.to_string());
                    }
                }
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(
                        msg_id = %element.msg_id,
                        error = %e,
                        "purge could not remove a message; it stays queued"
                    );
                }
            }
        }

        let Some(next) = last_id.as_deref().and_then(exclusive_successor) else {
            break;
        };
        cursor = next;
    }

    if !orphans.is_empty() {
        store
            .delete_folder_entries(did_hash, folder, &orphans)
            .await?;
    }
    Ok(report)
}

/// What a filtered purge did, or would have done.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// Messages matched **and actually removed** — or, for a dry run, matched
    /// and would have been.
    ///
    /// Deliberately not "matched": a purge that reported a message it had
    /// failed to delete would be telling the caller the queue is emptier than
    /// it is, which is the one lie a recovery tool must not tell.
    pub count: usize,
    /// Bytes counted in [`count`](Self::count).
    pub bytes: usize,
    /// Messages examined. `scanned` far above `count` means the filter is
    /// narrow, which is the point; it is reported so a caller can tell "the
    /// filter matched nothing" from "the folder was empty".
    pub scanned: usize,
    /// Messages that matched the filter but could **not** be removed.
    ///
    /// A message that was already gone is not counted here — the caller asked
    /// for it to be absent and it is. This is for real refusals: a backend
    /// error, or an authorisation failure. Non-zero means the queue is not as
    /// empty as `count` alone would suggest, and the operator should look
    /// before concluding the recovery worked.
    pub failed: usize,
    /// The walk stopped at its scan ceiling with messages still unexamined.
    ///
    /// The purge is partial, not wrong: everything reported was really removed.
    /// Re-running the same filter continues from a folder that is now shorter.
    pub truncated: bool,
}

/// The next stream id strictly after `id`, for paging a filtered walk.
///
/// Stream ids are `"<unix-ms>-<sequence>"` in every backend — Redis natively,
/// and the Fjall and in-memory stores format their `(ms, seq)` pairs the same
/// way — so incrementing the sequence gives the exclusive successor without
/// needing a backend-specific exclusive-range syntax.
pub(crate) fn exclusive_successor(id: &str) -> Option<String> {
    let (ms, seq) = id.split_once('-')?;
    let ms: u64 = ms.parse().ok()?;
    let seq: u64 = seq.parse().ok()?;
    Some(format!("{ms}-{}", seq.checked_add(1)?))
}
use std::time::Duration;

pub mod types;

/// Backend-agnostic decision logic (authorization checks shared by the
/// in-process Rust backends), extracted so it can't drift between them.
pub mod ops;

/// DID multiplexing grant rules, shared by every backend. See [`mux`].
pub mod mux;

/// Single-process answers for the cross-process parts of the streaming
/// contract, shared by the in-process backends.
pub mod single_process;

#[cfg(feature = "redis-backend")]
pub mod redis;

pub use types::{
    DeletionAuthority, DeliveryDecision, DeliveryState, ExpiryReport, ForwardQueueClaimPage,
    ForwardQueueEntry, InboxStatusReply, MessageMetaData, MessageRef, MessageScope, MetadataStats,
    OutboxReceipt, PubSubRecord, RefreshRotation, RemovalReason, RemovedCopy, SentMessageState,
    Session, SessionClaims, SessionState, SessionSweepReport, StatCounter, StoreHealth,
    StoredMessageRef, StreamingClaim, StreamingClientState, StreamingKind, StreamingWrite,
};

/// The error every backend's `get_session` returns for a session past the
/// challenge step whose DID no longer has an account: the account was
/// removed, so its sessions are over and the client must authenticate again.
pub fn account_gone(session_id: &str) -> MediatorError {
    MediatorError::Unauthorized(
        error_codes::SESSION_INVALID_STATE,
        session_id.into(),
        "The session's account no longer exists; please re-authenticate".into(),
    )
}

/// The error every backend's `get_session` returns for a session that does
/// not exist: never created, expired, deleted, or lost with the store (a
/// flush, a memory-backed mediator's restart). Not a server fault: the
/// client's token outlived its session and it must authenticate again.
pub fn session_not_found(session_id: &str) -> MediatorError {
    MediatorError::Unauthorized(
        error_codes::AUTH_SESSION_INVALID,
        session_id.into(),
        "Session not found or expired; please re-authenticate".into(),
    )
}

/// Whether `err` is the [`session_not_found`] or [`account_gone`] answer of
/// `get_session`: the session is over, and the client must authenticate
/// again. Anything else from `get_session` is a storage failure.
pub fn is_session_over(err: &MediatorError) -> bool {
    matches!(
        err,
        MediatorError::Unauthorized(
            error_codes::SESSION_INVALID_STATE | error_codes::AUTH_SESSION_INVALID,
            ..
        )
    )
}

/// The error `update_session_authenticated` returns when the challenge
/// session is gone, expired, or no longer waiting for its answer (it was
/// already answered). The client must ask for a new challenge.
pub fn session_not_awaiting_answer(session_id: &str) -> MediatorError {
    MediatorError::SessionError(
        error_codes::DB_OPERATION_ERROR,
        session_id.into(),
        format!("Session ({session_id}) is not waiting for a challenge answer"),
    )
}

/// How long a sender's [`OutboxReceipt`] is kept after its message leaves the
/// queue (`messaging/message/status/0.1` asks for at least 24 hours).
///
/// Long enough that a sender polling on a delivery window of minutes or hours
/// reliably finds it; bounded because a receipt is one record per removed
/// message. After it, the sender's answer for that message is `Unknown`, which
/// it must treat as no evidence either way.
pub const OUTBOX_RECEIPT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long an acknowledgement is remembered
/// ([`MediatorStore::acknowledged`]) for a copy whose own expiry is not
/// known: one stored with no expiry, or by an earlier build that did not
/// record it. The default `limits.message_expiry_seconds`.
pub const ACKNOWLEDGED_FALLBACK_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Until when (Unix seconds) an acknowledgement of a copy expiring at
/// `copy_expires_at` (`0` = unknown) is remembered, from `now_secs`.
pub fn acknowledged_until(copy_expires_at: u64, now_secs: u64) -> u64 {
    if copy_expires_at > now_secs {
        copy_expires_at
    } else if copy_expires_at == 0 {
        now_secs + ACKNOWLEDGED_FALLBACK_TTL.as_secs()
    } else {
        // Already past its expiry: nothing can redeliver it, but keep the
        // record briefly so a delete racing the removal still reads it.
        now_secs + 60
    }
}

/// Outcome of [`AuxiliaryStore::trust_task_claim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustTaskClaim {
    /// First sight of this document: execute it.
    Fresh,
    /// The same document again: do not execute it a second time.
    Duplicate,
    /// A different document under an id already used: refuse it.
    Conflict,
}

/// Told of each message the expiry sweep removes: its id, and its metadata as
/// it was just before the delete. See
/// [`MediatorStore::sweep_expired_messages_observed`].
pub type OnExpired<'a> = &'a (dyn Fn(&str, &MessageMetaData) + Send + Sync);

// ─── Traits ──────────────────────────────────────────────────────────────────

mod traits;

pub use traits::{
    AccountStore, AclStore, AuditStore, AuxiliaryStore, ForwardQueueStore, MediatorStore,
    MediatorStoreExt, MessageStore, MuxStore, SessionStore, StatsStore, StoreLifecycle,
    StreamingStore, V1RoutingKeyStore,
};

/// Every storage trait, for `use ...::store::prelude::*`: a method of a
/// capability trait is callable on `dyn MediatorStore` only with that trait
/// in scope.
pub mod prelude {
    pub use super::traits::{
        AccountStore, AclStore, AuditStore, AuxiliaryStore, ForwardQueueStore, MediatorStore,
        MediatorStoreExt, MessageStore, MuxStore, SessionStore, StatsStore, StoreLifecycle,
        StreamingStore, V1RoutingKeyStore,
    };
}

#[cfg(test)]
mod tests {
    use super::{PurgeFilter, exclusive_successor};
    use crate::types::messages::{Folder, MessageListElement};

    fn element(ts: u64, from: Option<&str>, to: Option<&str>) -> MessageListElement {
        MessageListElement {
            msg_id: "m".into(),
            timestamp: ts,
            size: 10,
            from_address: from.map(str::to_string),
            to_address: to.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let f = PurgeFilter::default();
        assert!(f.matches(&element(1, Some("alice"), Some("bob")), &Folder::Inbox));
        assert!(f.matches(&element(u64::MAX, None, None), &Folder::Outbox));
    }

    /// Which end "peer" means depends on the folder: in an outbox it is who
    /// the message went to, in an inbox who sent it. Getting this backwards
    /// would purge the wrong messages.
    #[test]
    fn peer_is_the_counterparty_for_the_folder() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            ..Default::default()
        };
        let msg = element(1, Some("alice"), Some("bob"));
        assert!(
            f.matches(&msg, &Folder::Outbox),
            "in an outbox, the peer is the recipient"
        );
        assert!(
            !f.matches(&msg, &Folder::Inbox),
            "in an inbox, the peer is the sender — bob did not send this"
        );

        let f = PurgeFilter {
            peer: Some("alice".into()),
            ..Default::default()
        };
        assert!(f.matches(&msg, &Folder::Inbox));
        assert!(!f.matches(&msg, &Folder::Outbox));
    }

    /// A purge is unrecoverable, so an unrecorded counterparty never matches a
    /// `peer` filter — it cannot be shown to be the peer asked for.
    #[test]
    fn an_unknown_counterparty_never_matches_a_peer_filter() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            ..Default::default()
        };
        assert!(!f.matches(&element(1, None, None), &Folder::Inbox));
        assert!(!f.matches(&element(1, None, None), &Folder::Outbox));
    }

    #[test]
    fn the_age_cutoff_is_inclusive_and_keeps_newer_messages() {
        let f = PurgeFilter {
            arrived_before_ms: Some(1_000),
            ..Default::default()
        };
        assert!(f.matches(&element(999, None, None), &Folder::Inbox));
        assert!(f.matches(&element(1_000, None, None), &Folder::Inbox));
        assert!(
            !f.matches(&element(1_001, None, None), &Folder::Inbox),
            "a message newer than the cutoff must survive"
        );
    }

    /// Both narrowings apply together: "this peer AND older than that".
    #[test]
    fn peer_and_age_are_both_required_when_both_are_set() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            arrived_before_ms: Some(1_000),
            ..Default::default()
        };
        assert!(f.matches(&element(500, None, Some("bob")), &Folder::Outbox));
        assert!(
            !f.matches(&element(2_000, None, Some("bob")), &Folder::Outbox),
            "right peer, too new"
        );
        assert!(
            !f.matches(&element(500, None, Some("carol")), &Folder::Outbox),
            "old enough, wrong peer"
        );
    }

    /// Paging a *filtered* walk cannot restart from the beginning: entries that
    /// did not match stay in place, so it would spin on them forever. The
    /// successor must be strictly greater than the id it came from.
    #[test]
    fn the_cursor_advances_past_the_id_it_came_from() {
        assert_eq!(
            exclusive_successor("1700000000000-0").as_deref(),
            Some("1700000000000-1")
        );
        assert_eq!(exclusive_successor("5-41").as_deref(), Some("5-42"));
    }

    #[test]
    fn an_unparseable_cursor_stops_the_walk_rather_than_guessing() {
        assert_eq!(exclusive_successor("not-a-stream-id"), None);
        assert_eq!(exclusive_successor("12345"), None);
        assert_eq!(exclusive_successor(""), None);
        // Sequence at the ceiling: no successor exists, so stop rather than wrap
        // back to the start of the stream and re-walk it.
        assert_eq!(exclusive_successor(&format!("1-{}", u64::MAX)), None);
    }
}
