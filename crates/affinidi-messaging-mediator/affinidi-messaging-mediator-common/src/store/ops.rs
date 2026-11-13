//! Backend-agnostic decision logic for the store layer.
//!
//! The storage backends reduce to persistence primitives; the *decisions*
//! they share — authorization checks and the like — live here as pure,
//! unit-tested functions so they cannot drift between backends. `FjallStore`
//! and `MemoryStore` previously each carried their own copy of these checks.
//!
//! The Redis backend performs the equivalent checks server-side in Lua and is
//! necessarily separate (Lua can't call Rust), so these functions cover the
//! in-process Rust backends; the conformance suite (`store_conformance`) is
//! what keeps Redis aligned with them.

use crate::error_codes;
use crate::errors::MediatorError;
use crate::store::types::{
    DeletionAuthority, MessageScope, OutboxReceipt, RemovalReason, SentMessageState,
};
use crate::types::acls::{AccessListModeType, MediatorACLSet};
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::http::StatusCode;

/// Whether `authority` may delete a message addressed to `to_did_hash` and
/// (optionally) from `from_did_hash`.
///
/// - [`DeletionAuthority::Admin`] always may — the message-expiry processor and
///   account removal delete on the owner's behalf.
/// - [`DeletionAuthority::Owner`] may only delete a message it is a party to:
///   its DID hash must be the recipient or the (non-anonymous) sender.
pub fn delete_message_permitted(
    authority: &DeletionAuthority,
    to_did_hash: &str,
    from_did_hash: Option<&str>,
) -> bool {
    match authority {
        DeletionAuthority::Admin { .. } => true,
        DeletionAuthority::Owner { did_hash } => {
            did_hash == to_did_hash || from_did_hash == Some(did_hash.as_str())
        }
    }
}

/// Why a permitted removal removed the message, for the sender's receipt.
///
/// Decided by **who** removed it. The recipient is checked first, so a message
/// a DID sent to itself and then removed counts as collected. An admin removal
/// (expiry, account removal) is `Discarded` even when the admin is also a
/// party, because it did not act as the recipient. `None` when the principal
/// is neither party and not an admin, which a permitted removal never is.
///
/// Shared by all three backends — the Redis wrapper applies it in Rust around
/// the Lua delete — so they cannot disagree about what "collected" means.
pub fn removal_reason(
    authority: &DeletionAuthority,
    to_did_hash: &str,
    from_did_hash: Option<&str>,
) -> Option<RemovalReason> {
    match authority {
        DeletionAuthority::Admin { .. } => Some(RemovalReason::Discarded),
        DeletionAuthority::Owner { did_hash } if did_hash == to_did_hash => {
            Some(RemovalReason::Collected)
        }
        DeletionAuthority::Owner { did_hash } if from_did_hash == Some(did_hash.as_str()) => {
            Some(RemovalReason::Withdrawn)
        }
        DeletionAuthority::Owner { .. } => None,
    }
}

/// A prospective sender, from the recipient's access-control perspective.
pub enum Sender {
    /// An anonymous sender (no authenticated DID).
    Anonymous,
    /// A known (authenticated) sender, with whether it is currently on the
    /// recipient's access list.
    Known { on_access_list: bool },
}

/// Whether `sender` is allowed to deliver a message to a recipient whose
/// ACLs are `recipient_acls`.
///
/// - [`Sender::Anonymous`] is allowed iff the recipient's `anon_receive`
///   ACL bit is set.
/// - [`Sender::Known`] is judged by the recipient's access-list mode:
///   `ExplicitAllow` admits only senders on the list; `ExplicitDeny` admits
///   everyone except those on the list.
///
/// The caller is responsible for the (backend-specific) lookups that produce
/// `recipient_acls` and the `on_access_list` membership flag; this function
/// is the pure decision the in-process backends previously each inlined.
pub fn access_list_allowed(recipient_acls: &MediatorACLSet, sender: Sender) -> bool {
    match sender {
        Sender::Anonymous => recipient_acls.get_anon_receive().0,
        Sender::Known { on_access_list } => match recipient_acls.get_access_list_mode().0 {
            AccessListModeType::ExplicitAllow => on_access_list,
            AccessListModeType::ExplicitDeny => !on_access_list,
        },
    }
}

/// A copy a backend still holds, as far as a sender's status needs it.
pub struct HeldMessage<'a> {
    /// The recipient the copy is held for.
    pub to_did_hash: &'a str,
    pub from_did_hash: Option<&'a str>,
    pub first_delivered_at_ms: Option<u64>,
}

/// Where a message stands for `sender`, over every copy of it: the copies
/// still held (`held`, every record under the id) and the receipts the sender
/// holds for copies removed (`receipts`, `(recipient, receipt)`; a receipt
/// written before receipts were per recipient has an empty recipient).
///
/// Only copies whose recorded sender is `sender` count, so a DID learns
/// nothing about messages it did not send — not even that they exist. A
/// held copy stands for its recipient over that recipient's receipt (the same
/// bytes were stored for it again). The answer, in order:
///
/// 1. `Removed` with the latest receipt that is **not** `collected`, when
///    any copy was withdrawn or discarded: at least one recipient will never
///    get it, and that must not be hidden behind the others;
/// 2. `Queued`, while any held copy waits for its first handover;
/// 3. `Delivered` at the latest first handover, once every held copy has
///    been handed over (and every removed one collected);
/// 4. `Removed` with the latest `collected` receipt, once every copy is
///    collected;
/// 5. `Unknown` when nothing is held and no receipt is kept.
pub fn sent_message_state(
    sender: &str,
    held: &[HeldMessage<'_>],
    receipts: &[(String, OutboxReceipt)],
) -> SentMessageState {
    let held: Vec<&HeldMessage<'_>> = held
        .iter()
        .filter(|held| held.from_did_hash == Some(sender))
        .collect();
    let removed: Vec<OutboxReceipt> = receipts
        .iter()
        .filter(|(to, _)| to.is_empty() || !held.iter().any(|h| h.to_did_hash == to))
        .map(|(_, receipt)| *receipt)
        .collect();
    let latest = |want_collected: bool| {
        removed
            .iter()
            .filter(|r| (r.reason == RemovalReason::Collected) == want_collected)
            .max_by_key(|r| r.at_ms)
            .copied()
    };
    if let Some(lost) = latest(false) {
        return SentMessageState::Removed(lost);
    }
    if !held.is_empty() {
        if held.iter().any(|h| h.first_delivered_at_ms.is_none()) {
            return SentMessageState::Queued;
        }
        let at_ms = held
            .iter()
            .filter_map(|h| h.first_delivered_at_ms)
            .max()
            .unwrap_or_default();
        return SentMessageState::Delivered { at_ms };
    }
    latest(true).map_or(SentMessageState::Unknown, SentMessageState::Removed)
}

/// Whether `id` can be a message id: a SHA-256 digest in lowercase hex.
///
/// Checked before an id is used to name storage, so an id carrying the
/// separator that joins an id to a recipient (`:`), or anything else, can
/// never address a record it does not name. Anything else is answered as
/// not found.
pub fn is_message_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The parties of one stored record, for [`select_records`].
#[derive(Clone, Copy, Debug)]
pub struct RecordParties<'a> {
    pub to_did_hash: &'a str,
    pub from_did_hash: Option<&'a str>,
}

/// Why [`select_records`] chose nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectError {
    /// No record in scope: the message is not in the queues asked about.
    NotFound,
    /// A record exists but the requester is not a party to it.
    PermissionDenied,
}

impl SelectError {
    /// The delete error every backend returns for this outcome.
    pub fn into_delete_error(self, message_hash: &str) -> MediatorError {
        match self {
            SelectError::NotFound => delete_not_found(message_hash, None),
            SelectError::PermissionDenied => delete_permission_denied(message_hash, None),
        }
    }
}

/// Which of the records stored under one message id a delete (or read) acts
/// on, as indexes into `records`.
///
/// The one place the resolution rules live for the in-process backends; the
/// Redis library and cluster path implement the same rules and the
/// conformance suite holds them to it:
///
/// - [`MessageScope::Recipient`]: the record held for that recipient, if the
///   authority may delete it.
/// - [`MessageScope::Party`]: the record held for the party as recipient when
///   there is one, else every record it sent. None of either is not-found,
///   whatever other accounts hold under the id.
/// - [`MessageScope::All`]: every record, for an admin; an owner is resolved
///   as `Party` of itself.
///
/// Every chosen record is also checked with [`delete_message_permitted`].
pub fn select_records(
    scope: MessageScope<'_>,
    by: &DeletionAuthority,
    records: &[RecordParties<'_>],
) -> Result<Vec<usize>, SelectError> {
    let scope = match (scope, by) {
        (MessageScope::All, DeletionAuthority::Owner { did_hash }) => {
            MessageScope::Party(did_hash.as_str())
        }
        (scope, _) => scope,
    };
    let chosen: Vec<usize> = match scope {
        MessageScope::Recipient(to) => records
            .iter()
            .position(|r| r.to_did_hash == to)
            .into_iter()
            .collect(),
        MessageScope::Party(party) => match records.iter().position(|r| r.to_did_hash == party) {
            Some(own) => vec![own],
            None => (0..records.len())
                .filter(|&i| records[i].from_did_hash == Some(party))
                .collect(),
        },
        MessageScope::All => (0..records.len()).collect(),
    };
    if chosen.is_empty() {
        // Nothing in the queues asked about. Not-found even when other
        // accounts hold copies under the id: a recipient deleting its own
        // copy a second time (a redelivered message) must hear "already
        // gone", which clients treat as success, not a refusal they would
        // retry and report for as long as another recipient's copy lives —
        // and a non-party learns nothing about other accounts' messages.
        return Err(SelectError::NotFound);
    }
    if chosen
        .iter()
        .any(|&i| !delete_message_permitted(by, records[i].to_did_hash, records[i].from_did_hash))
    {
        return Err(SelectError::PermissionDenied);
    }
    Ok(chosen)
}

/// Whether an expiry-index entry at `slot_secs` is due for a record whose
/// current expiry is `expires_at` (`0` = none).
///
/// An entry is left by every expiry a record has had: its original deadline,
/// a delivered-TTL deadline brought forward by `mark_delivered`, and the
/// deadlines of earlier copies of the same bytes for the same recipient that
/// were removed and stored again. Only an entry at or after the record's
/// current expiry may remove it; an earlier one belongs to a deadline the
/// record no longer has, and the sweeper drops it instead of the record.
pub fn expiry_entry_is_due(expires_at: u64, slot_secs: u64) -> bool {
    expires_at != 0 && expires_at <= slot_secs
}

/// Problem-report descriptor for "delete: there is no such message".
///
/// A client told this deletes nothing and loses nothing — the message is
/// already gone — so it is the one refusal a client may treat as success.
/// Clients recognise it by this descriptor, which is why every backend must
/// produce exactly it (see [`delete_not_found`]).
pub const DELETE_NOT_FOUND: &str = "database.message.delete.not_found";

/// Problem-report descriptor for "delete: this DID is not a party to it".
pub const DELETE_PERMISSION_DENIED: &str = "database.message.delete.permission_denied";

/// The error every backend returns for a delete of a message that is not there.
///
/// # Why one constructor
///
/// The Redis backend has always answered with a problem report under
/// [`DELETE_NOT_FOUND`]; the Fjall and memory stores answered with a bare
/// `InternalError` reading `NOT_FOUND: message_hash (…)`. The per-id error
/// text is what `DELETE /messages` hands back to the client, so the same
/// already-gone message looked different depending on the storage backend —
/// and a client that recognises the descriptor (the SDK's deletion handler,
/// which drops redelivered duplicates quietly) logged every one from a Fjall
/// mediator as a real refusal.
pub fn delete_not_found(message_hash: &str, request_msg_id: Option<&str>) -> MediatorError {
    MediatorError::problem(
        error_codes::MESSAGE_NOT_FOUND,
        "NA",
        request_msg_id.map(str::to_string),
        ProblemReportSorter::Warning,
        ProblemReportScope::Message,
        DELETE_NOT_FOUND,
        "Message ({1}) not found",
        vec![message_hash.to_string()],
        StatusCode::NOT_FOUND,
    )
}

/// The error every backend returns when the requester may not delete a
/// message — see [`delete_message_permitted`].
pub fn delete_permission_denied(message_hash: &str, request_msg_id: Option<&str>) -> MediatorError {
    MediatorError::problem(
        error_codes::MESSAGE_DELETE_DENIED,
        "NA",
        request_msg_id.map(str::to_string),
        ProblemReportSorter::Warning,
        ProblemReportScope::Message,
        DELETE_PERMISSION_DENIED,
        "Not authorized to delete message ({1})",
        vec![message_hash.to_string()],
        StatusCode::FORBIDDEN,
    )
}

/// One bound of a [`list_messages`](crate::store::MediatorStore::list_messages)
/// range, as `(ms, seq)`: `-` (the start of the stream), `+` (its end), a
/// stream id `<ms>-<seq>`, or a bare `<ms>`, which as a start means
/// `<ms>-0` and as an end `<ms>-<max>` (Redis's reading). Anything else is
/// refused, the same on every backend, rather than read as unbounded.
pub fn parse_range_bound(bound: &str, is_end: bool) -> Result<(u64, u64), MediatorError> {
    let refuse = || {
        MediatorError::RequestDataError(
            22,
            "NA".into(),
            format!("Invalid message range bound ({bound}): expected -, +, <ms> or <ms>-<seq>"),
        )
    };
    match bound {
        "-" => Ok((0, 0)),
        "+" => Ok((u64::MAX, u64::MAX)),
        _ => match bound.split_once('-') {
            Some((ms, seq)) => Ok((
                ms.parse().map_err(|_| refuse())?,
                seq.parse().map_err(|_| refuse())?,
            )),
            None => {
                let ms = bound.parse().map_err(|_| refuse())?;
                Ok((ms, if is_end { u64::MAX } else { 0 }))
            }
        },
    }
}

/// Whether a delete failed only because the message was already gone.
///
/// Matched on the problem report's descriptor, not on its rendered text, so a
/// rewording of the comment cannot turn an already-gone message into a failure.
pub fn is_delete_not_found(err: &MediatorError) -> bool {
    matches!(
        err,
        MediatorError::MediatorError(_, _, _, report, _, _)
            if report.code.ends_with(DELETE_NOT_FOUND)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_bounds_parse_the_same_everywhere() {
        assert_eq!(parse_range_bound("-", false).unwrap(), (0, 0));
        assert_eq!(parse_range_bound("+", true).unwrap(), (u64::MAX, u64::MAX));
        assert_eq!(parse_range_bound("12-3", false).unwrap(), (12, 3));
        assert_eq!(parse_range_bound("12", false).unwrap(), (12, 0));
        assert_eq!(parse_range_bound("12", true).unwrap(), (12, u64::MAX));
        assert!(parse_range_bound("(12-3", false).is_err());
        assert!(parse_range_bound("abc", true).is_err());
        assert!(parse_range_bound("1-x", true).is_err());
    }

    #[test]
    fn the_recipient_removing_it_is_collection() {
        assert_eq!(
            removal_reason(&owner("to"), "to", Some("from")),
            Some(RemovalReason::Collected)
        );
    }

    #[test]
    fn the_sender_removing_it_is_withdrawal() {
        assert_eq!(
            removal_reason(&owner("from"), "to", Some("from")),
            Some(RemovalReason::Withdrawn)
        );
    }

    #[test]
    fn an_admin_removal_is_never_collection_even_by_a_party() {
        assert_eq!(
            removal_reason(&admin("to"), "to", Some("from")),
            Some(RemovalReason::Discarded)
        );
    }

    #[test]
    fn a_message_sent_to_oneself_and_removed_is_collected() {
        assert_eq!(
            removal_reason(&owner("me"), "me", Some("me")),
            Some(RemovalReason::Collected)
        );
    }

    #[test]
    fn a_stranger_has_no_reason() {
        assert_eq!(removal_reason(&owner("x"), "to", Some("from")), None);
    }

    #[test]
    fn a_held_message_answers_only_to_its_sender() {
        let held = || {
            [HeldMessage {
                to_did_hash: "to",
                from_did_hash: Some("from"),
                first_delivered_at_ms: Some(7),
            }]
        };
        assert_eq!(
            sent_message_state("from", &held(), &[]),
            SentMessageState::Delivered { at_ms: 7 }
        );
        assert_eq!(
            sent_message_state("to", &held(), &[]),
            SentMessageState::Unknown
        );
        let queued = HeldMessage {
            to_did_hash: "to",
            from_did_hash: Some("from"),
            first_delivered_at_ms: None,
        };
        assert_eq!(
            sent_message_state("from", &[queued], &[]),
            SentMessageState::Queued
        );
    }

    #[test]
    fn a_removed_message_answers_from_its_receipt() {
        let receipt = OutboxReceipt {
            reason: RemovalReason::Collected,
            at_ms: 9,
        };
        assert_eq!(
            sent_message_state("from", &[], &[("to".to_string(), receipt)]),
            SentMessageState::Removed(receipt)
        );
        assert_eq!(
            sent_message_state("from", &[], &[]),
            SentMessageState::Unknown
        );
    }

    #[test]
    fn a_receipt_round_trips_and_rejects_anything_else() {
        let receipt = OutboxReceipt {
            reason: RemovalReason::Discarded,
            at_ms: 1_726_912_345_000,
        };
        assert_eq!(OutboxReceipt::decode(&receipt.encode()), Some(receipt));
        assert_eq!(OutboxReceipt::decode("delivered:1"), None);
        assert_eq!(OutboxReceipt::decode("collected"), None);
    }

    #[test]
    fn copies_for_several_recipients_answer_together() {
        let copy = |to: &'static str, at: Option<u64>| HeldMessage {
            to_did_hash: to,
            from_did_hash: Some("from"),
            first_delivered_at_ms: at,
        };
        let receipt = |reason, at_ms| OutboxReceipt { reason, at_ms };
        assert_eq!(
            sent_message_state("from", &[copy("a", Some(5)), copy("b", None)], &[]),
            SentMessageState::Queued,
            "one copy still waiting"
        );
        assert_eq!(
            sent_message_state("from", &[copy("a", Some(5)), copy("b", Some(9))], &[]),
            SentMessageState::Delivered { at_ms: 9 }
        );
        // a's copy discarded, b's held and delivered: never `delivered`.
        let discarded = receipt(RemovalReason::Discarded, 3);
        assert_eq!(
            sent_message_state(
                "from",
                &[copy("b", Some(9))],
                &[("a".to_string(), discarded)]
            ),
            SentMessageState::Removed(discarded)
        );
        // a's copy discarded, then b collects: the discard still wins.
        let collected = receipt(RemovalReason::Collected, 20);
        assert_eq!(
            sent_message_state(
                "from",
                &[],
                &[("a".to_string(), discarded), ("b".to_string(), collected)]
            ),
            SentMessageState::Removed(discarded)
        );
        // Every copy collected: the latest collection.
        let earlier = receipt(RemovalReason::Collected, 4);
        assert_eq!(
            sent_message_state(
                "from",
                &[],
                &[("a".to_string(), earlier), ("b".to_string(), collected)]
            ),
            SentMessageState::Removed(collected)
        );
        // A copy stored again for a recipient stands over its old receipt.
        assert_eq!(
            sent_message_state("from", &[copy("a", None)], &[("a".to_string(), discarded)]),
            SentMessageState::Queued
        );
    }

    #[test]
    fn only_a_lowercase_digest_is_a_message_id() {
        let id = "a".repeat(64);
        assert!(is_message_id(&id));
        assert!(!is_message_id(&"A".repeat(64)));
        assert!(!is_message_id(&format!("{}:x", "a".repeat(62))));
        assert!(!is_message_id("abc"));
        assert!(!is_message_id(""));
    }

    fn parties<'a>(to: &'a str, from: Option<&'a str>) -> RecordParties<'a> {
        RecordParties {
            to_did_hash: to,
            from_did_hash: from,
        }
    }

    #[test]
    fn a_recipient_scope_names_one_record() {
        let records = [parties("a", Some("s")), parties("b", Some("s"))];
        assert_eq!(
            select_records(MessageScope::Recipient("b"), &owner("b"), &records),
            Ok(vec![1])
        );
        assert_eq!(
            select_records(MessageScope::Recipient("b"), &owner("s"), &records),
            Ok(vec![1]),
            "the sender may remove one recipient's copy"
        );
        assert_eq!(
            select_records(MessageScope::Recipient("b"), &owner("a"), &records),
            Err(SelectError::PermissionDenied)
        );
        assert_eq!(
            select_records(MessageScope::Recipient("c"), &admin("x"), &records),
            Err(SelectError::NotFound)
        );
    }

    #[test]
    fn a_party_scope_prefers_its_own_inbox_then_what_it_sent() {
        let records = [
            parties("a", Some("s")),
            parties("s", Some("s")),
            parties("b", Some("s")),
        ];
        assert_eq!(
            select_records(MessageScope::Party("s"), &owner("s"), &records),
            Ok(vec![1]),
            "its own inbox copy only"
        );
        let records = [parties("a", Some("s")), parties("b", Some("s"))];
        assert_eq!(
            select_records(MessageScope::Party("s"), &owner("s"), &records),
            Ok(vec![0, 1]),
            "every copy it sent"
        );
        assert_eq!(
            select_records(MessageScope::Party("x"), &owner("x"), &records),
            Err(SelectError::NotFound),
            "nothing in x's queues, though others hold copies"
        );
        assert_eq!(
            select_records(MessageScope::Party("x"), &owner("x"), &[]),
            Err(SelectError::NotFound)
        );
        assert_eq!(
            select_records(MessageScope::Party("x"), &admin("adm"), &records),
            Err(SelectError::NotFound),
            "not in the queues an admin asked about"
        );
    }

    #[test]
    fn an_all_scope_is_every_copy_for_an_admin_only() {
        let records = [parties("a", Some("s")), parties("b", None)];
        assert_eq!(
            select_records(MessageScope::All, &admin("adm"), &records),
            Ok(vec![0, 1])
        );
        assert_eq!(
            select_records(MessageScope::All, &owner("b"), &records),
            Ok(vec![1])
        );
    }

    #[test]
    fn only_an_entry_at_or_after_the_current_expiry_is_due() {
        assert!(expiry_entry_is_due(100, 100));
        assert!(expiry_entry_is_due(100, 150));
        assert!(!expiry_entry_is_due(200, 100), "an earlier deadline");
        assert!(!expiry_entry_is_due(0, 100), "no expiry at all");
    }

    fn owner(h: &str) -> DeletionAuthority {
        DeletionAuthority::Owner {
            did_hash: h.to_string(),
        }
    }
    fn admin(h: &str) -> DeletionAuthority {
        DeletionAuthority::Admin {
            admin_did_hash: h.to_string(),
        }
    }

    #[test]
    fn admin_may_delete_anything() {
        assert!(delete_message_permitted(
            &admin("anyone"),
            "to",
            Some("from")
        ));
        assert!(delete_message_permitted(&admin("anyone"), "to", None));
    }

    #[test]
    fn owner_must_be_a_party_to_the_message() {
        // The recipient may delete.
        assert!(delete_message_permitted(&owner("to"), "to", Some("from")));
        // The sender may delete.
        assert!(delete_message_permitted(&owner("from"), "to", Some("from")));
        // An unrelated third party may not.
        assert!(!delete_message_permitted(
            &owner("other"),
            "to",
            Some("from")
        ));
    }

    #[test]
    fn anonymous_message_only_the_recipient_qualifies() {
        // With no sender, only the recipient is a party.
        assert!(delete_message_permitted(&owner("to"), "to", None));
        assert!(!delete_message_permitted(&owner("from"), "to", None));
    }

    fn acls(mode: AccessListModeType, anon_receive: bool) -> MediatorACLSet {
        let mut a = MediatorACLSet::default();
        // admin = true so the change is always permitted in the test.
        a.set_access_list_mode(mode, false, true).unwrap();
        a.set_anon_receive(anon_receive, false, true).unwrap();
        a
    }

    #[test]
    fn explicit_allow_admits_only_listed_known_senders() {
        let a = acls(AccessListModeType::ExplicitAllow, false);
        assert!(access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: true
            }
        ));
        assert!(!access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: false
            }
        ));
    }

    #[test]
    fn explicit_deny_admits_everyone_except_listed() {
        let a = acls(AccessListModeType::ExplicitDeny, false);
        assert!(!access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: true
            }
        ));
        assert!(access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: false
            }
        ));
    }

    #[test]
    fn anonymous_sender_follows_the_anon_receive_bit() {
        // Mode is irrelevant for anonymous senders — only the anon_receive bit.
        assert!(access_list_allowed(
            &acls(AccessListModeType::ExplicitAllow, true),
            Sender::Anonymous
        ));
        assert!(!access_list_allowed(
            &acls(AccessListModeType::ExplicitAllow, false),
            Sender::Anonymous
        ));
        assert!(access_list_allowed(
            &acls(AccessListModeType::ExplicitDeny, true),
            Sender::Anonymous
        ));
    }
}
