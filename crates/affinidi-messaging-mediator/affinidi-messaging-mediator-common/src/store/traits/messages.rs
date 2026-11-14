//! The [`MessageStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::{
    DeletionAuthority, DeliveryMarkReport, DeliveryState, ExpiryReport, InboxStatusReply,
    MessageMetaData, MessageRef, MessageScope, OnExpired, OutboxReceipt, RemovedCopy,
    SentMessageState,
};
use crate::types::messages::{
    FetchOptions, Folder, GetMessagesResponse, MessageList, MessageListElement,
};
use async_trait::async_trait;

/// Stored messages: the per-recipient records, the inbox and outbox streams that list them, delivery bookkeeping, outbox receipts and the expiry sweep.
#[async_trait]
pub trait MessageStore: Send + Sync + std::fmt::Debug {
    /// Store a message in the database and enqueue it on both the
    /// recipient's inbox and (if non-anonymous) the sender's outbox.
    ///
    /// Returns the message ID (SHA-256 of the message body). Storing the same
    /// body again **for the same recipient** returns the same ID and is a
    /// no-op: one record, queued and counted once.
    ///
    /// The same body stored for a **different** recipient gets a record of
    /// its own, under the same ID — see [`MessageRef`]. Each record has its
    /// own sender, queue entries, counters and expiry, and is removed on its
    /// own; the ID alone no longer names one record, so the operations below
    /// say which record they act on ([`MessageScope`]).
    ///
    /// `queue_maxlen` bounds the per-DID inbox/outbox stream; `0` means
    /// unbounded. Backends may apply approximate trimming for performance.
    ///
    /// `expires_at` is a Unix timestamp in seconds. The message expiry
    /// processor deletes the message after this time.
    async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        queue_maxlen: usize,
    ) -> Result<String, MediatorError>;

    /// Delete the records of `message_hash` that `scope` names
    /// ([`ops::select_records`](crate::store::ops::select_records) gives the rules, which every backend follows).
    ///
    /// Each chosen record is removed exactly once with its queue entries,
    /// counters and expiry entry, and leaves its sender a receipt, as
    /// [`delete_message`](crate::store::MediatorStoreExt::delete_message) describes. Returns
    /// `not_found` when no record is in scope (or `message_hash` is not a
    /// message id, [`ops::is_message_id`](crate::store::ops::is_message_id)), `permission_denied` when `by` may
    /// not remove one that is. On success, the copies removed. Several records are removed together
    /// where the backend can (one Lua call, one Fjall batch, one lock), and
    /// otherwise each on its own, never leaving one half-removed.
    ///
    /// Callers that know the recipient — a fetch, a purge of an inbox, the
    /// expiry sweep — pass [`MessageScope::Recipient`], so they never touch
    /// another recipient's copy of the same bytes.
    async fn delete_message_in(
        &self,
        message_hash: &str,
        scope: MessageScope<'_>,
        by: DeletionAuthority,
    ) -> Result<Vec<RemovedCopy>, MediatorError>;

    /// Whether `to_did_hash` removed its own copy of `msg_id` itself — an
    /// acknowledgement — while that copy could still have been redelivered.
    ///
    /// Every backend records this when an owner's delete removes the copy
    /// held for that owner, and keeps it until the copy's own expiry (or
    /// [`ACKNOWLEDGED_FALLBACK_TTL`](crate::store::ACKNOWLEDGED_FALLBACK_TTL) for a copy stored without one): no
    /// redelivery of that copy can arrive later. Removals by the sender or
    /// the mediator (withdrawal, expiry, admin, account removal) record
    /// nothing. A client delete uses it to tell a repeated acknowledgement
    /// from a withdrawal (`messages::client_delete` in the mediator).
    async fn acknowledged(&self, to_did_hash: &str, msg_id: &str) -> Result<bool, MediatorError>;

    /// The receipts `from_did_hash` holds for the copies of `msg_id` removed
    /// within [`OUTBOX_RECEIPT_TTL`](crate::store::OUTBOX_RECEIPT_TTL), one per recipient:
    /// `(recipient, receipt)`. Receipts are per recipient, so one copy's
    /// removal never stands for another's.
    async fn outbox_receipts(
        &self,
        from_did_hash: &str,
        msg_id: &str,
    ) -> Result<Vec<(String, OutboxReceipt)>, MediatorError>;

    /// Where each of `msg_ids` stands for `sender_did_hash`, in the order asked
    /// (`messaging/message/status/0.1`). An id the sender stored for several
    /// recipients answers for all of its copies, held and removed
    /// ([`ops::sent_message_state`](crate::store::ops::sent_message_state)).
    ///
    /// A held message answers `Queued` or `Delivered`, and a removed one
    /// answers from its receipt, but only when `sender_did_hash` is the
    /// message's recorded sender: anything else is `Unknown`, identically, so
    /// the answer cannot be used to learn whether another account's message
    /// exists. See [`ops::sent_message_state`](crate::store::ops::sent_message_state).
    async fn sent_message_states(
        &self,
        sender_did_hash: &str,
        msg_ids: &[String],
    ) -> Result<Vec<SentMessageState>, MediatorError>;

    /// Retrieve one message by ID with the body and metadata, resolved as
    /// [`MessageScope::Party`] of `did_hash`: its own inbox copy when it has
    /// one, else a copy it sent (the body is the same in every copy; the
    /// metadata is that copy's).
    ///
    /// Returns `None` when the requesting DID is neither sender nor
    /// recipient — leaking a permission-denied error here would reveal
    /// that the message exists.
    async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError>;

    /// Several messages by id, with bodies, in the order asked.
    ///
    /// The single-message [`get_message`](Self::get_message) is a round trip
    /// each; a fair pickup needs a whole batch, so backends that can read them
    /// together should. The default loops: correct for every backend, and no
    /// worse than the caller doing it, so overriding it is an optimisation
    /// only.
    ///
    /// A message that has gone since it was listed comes back as `None` rather
    /// than an error — a concurrent delete is normal, not a failure.
    async fn get_messages(
        &self,
        did_hash: &str,
        msg_ids: &[String],
    ) -> Result<Vec<Option<MessageListElement>>, MediatorError> {
        let mut out = Vec::with_capacity(msg_ids.len());
        for id in msg_ids {
            out.push(self.get_message(did_hash, id).await?);
        }
        Ok(out)
    }

    /// Record that `msg_ids` have been handed to `recipient_did_hash`: stamp
    /// the first-delivery time on that recipient's copy if unset, and bump its
    /// attempt count. Another recipient's copy of the same bytes is untouched.
    ///
    /// Called by the mediator after a pickup or a live push, **not** inside the
    /// read itself. On Redis the read is a stored Lua function, so stamping
    /// atomically would mean putting it in `atm-functions.lua` — and that is
    /// exactly where it must not be.
    ///
    /// Not because operators would have to reload: they would not.
    /// `Database::load_scripts` issues `FUNCTION LOAD REPLACE` at boot from
    /// whatever `functions_file` names, unattended, and fails loudly if Redis
    /// rejects it. The hazard is narrower and worse — **the file it loads can
    /// be stale**, and then the load succeeds, correctly and loudly, with the
    /// wrong library. That is what happened when the per-relationship
    /// accounting was added to one copy of the file and not the copy a test
    /// deployment pointed at.
    ///
    /// Which is the argument for keeping the stamp out of the Lua, and it is
    /// the opposite of "this field does not matter much". Eviction of
    /// delivered-but-unacknowledged messages, poison-message detection and
    /// tiered expiry are all meant to be built on it. A stale library would
    /// silently not stamp, and every one of those would silently not work — a
    /// *mechanism* that quietly does nothing, where the earlier casualty was a
    /// *gate* that failed safe. It belongs in Rust precisely **because** things
    /// will depend on it.
    ///
    /// The cost is that marking is not atomic with the read, and the test that
    /// makes that acceptable is that **both** error directions are safe: a
    /// crash in between leaves `first_delivered_at_ms` unset, so eviction does
    /// not fire early, and it undercounts `attempts`, so poison detection stays
    /// lenient. Nothing becomes more aggressive when an update is lost. A
    /// future field on this record that fails that test — one where a missed
    /// update makes the mediator *do* something rather than not do it — needs
    /// different treatment and should not be added here without saying so.
    ///
    /// Best-effort by contract: an implementation that cannot record this
    /// returns `Ok(())` having done nothing, and callers must not treat the
    /// absence of a stamp as evidence a message was never delivered.
    ///
    /// # `delivered_ttl_secs`
    ///
    /// When non-zero, a message marked delivered **for the first time** also
    /// has its expiry brought forward to `now + delivered_ttl_secs`, so a
    /// message the recipient has already collected stops occupying its
    /// sender's queue allowance for a full week. `0` disables that and is the
    /// default.
    ///
    /// The record's expiry becomes the deadline, and an index entry is
    /// **added** for it; the original entry is left. Every sweeper removes a
    /// record only from an entry at or after the record's current expiry
    /// ([`ops::expiry_entry_is_due`](crate::store::ops::expiry_entry_is_due)), so the deadline's entry removes it and
    /// the original, reached later, finds it gone (`already_deleted`) and is
    /// dropped. The same rule keeps an entry left by an earlier copy of the
    /// same bytes for the same recipient from removing a later copy early.
    ///
    /// **Only the first delivery moves it.** A redelivery must not keep pushing
    /// the deadline out, or a client that reconnects often would pin its
    /// sender's allowance indefinitely — the mirror of the bug this exists to
    /// fix. It is also the reason this cannot be driven by `attempts`: that
    /// number is recipient-controlled, and anything keyed on it alone lets a
    /// recipient decide when a sender's messages die.
    async fn mark_delivered(
        &self,
        recipient_did_hash: &str,
        msg_ids: &[String],
        now_ms: u64,
        delivered_ttl_secs: u64,
    ) -> Result<DeliveryMarkReport, MediatorError>;

    /// What the mediator knows about `msg_id` having been handed to
    /// `recipient_did_hash`.
    ///
    /// `None` when that recipient holds no copy of the message. A message that exists but has
    /// never been delivered returns a default [`DeliveryState`], which is the
    /// honest answer — not an error, and not the same as "not found".
    async fn delivery_state(
        &self,
        recipient_did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<DeliveryState>, MediatorError>;

    /// Delivery state for several messages at once, in the order asked.
    ///
    /// The single-message [`delivery_state`](Self::delivery_state) is one round
    /// trip per message, which is fine for a lookup and wrong for a sample of a
    /// hundred. This is the batched form; a backend with no batching answers by
    /// looping, which is no worse than the caller doing it.
    async fn delivery_states(
        &self,
        records: &[MessageRef],
    ) -> Result<Vec<Option<DeliveryState>>, MediatorError> {
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            out.push(
                self.delivery_state(&record.to_did_hash, &record.msg_id)
                    .await?,
            );
        }
        Ok(out)
    }

    /// Retrieve the metadata of the copy of `message_hash` held for
    /// `recipient_did_hash`, without the body.
    async fn get_message_metadata(
        &self,
        recipient_did_hash: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError>;

    /// List messages in a folder (inbox or outbox) with stream-ID range
    /// filtering. Returns lightweight metadata only — bodies are fetched
    /// separately via [`fetch_messages`](Self::fetch_messages) or [`get_message`](Self::get_message).
    ///
    /// `range = None` is equivalent to `("-", "+")` (the full stream).
    async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<MessageList, MediatorError>;

    /// Fetch messages with bodies and apply the configured delete policy.
    /// Honours [`FetchOptions::start_id`] as an exclusive cursor and
    /// [`FetchOptions::limit`] as the maximum batch size.
    ///
    /// When `delete_policy = Optimistic`, each message is deleted after
    /// successful retrieval; failures are reported in
    /// [`GetMessagesResponse::delete_errors`] and do not abort the fetch.
    async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError>;

    /// Remove the entries `stream_ids` from `did_hash`'s `folder` stream,
    /// leaving the messages they name alone. A purge uses it for entries
    /// whose message is already gone. An id not in the stream is ignored.
    async fn delete_folder_entries(
        &self,
        did_hash: &str,
        folder: Folder,
        stream_ids: &[String],
    ) -> Result<(), MediatorError>;

    /// Remove the stream key for a folder without purging the messages
    /// it references. Used when account removal needs to drop the
    /// recipient's inbox view but leave the actual messages in place
    /// (e.g., they may still need to be read by their senders).
    async fn delete_folder_stream(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(), MediatorError>;

    /// Build the Message Pickup 3.0 status reply for one DID.
    async fn inbox_status(&self, did_hash: &str) -> Result<InboxStatusReply, MediatorError>;

    /// How many messages `from_hash` currently has queued **for `to_hash`
    /// specifically** — the per-relationship counterpart to the per-DID
    /// totals on [`Account`](crate::types::accounts::Account).
    ///
    /// This exists because a per-DID send total cannot tell fan-out from
    /// flooding. A community sending one membership card each to two hundred
    /// members, none of whom have collected yet, is indistinguishable from a
    /// sender aiming two hundred messages at a single victim — and capping the
    /// total punishes the first case, silencing a sender because *somebody
    /// else* went offline. The pair count separates them: flooding one peer
    /// moves it, fanning out to many peers does not.
    ///
    /// The count covers messages actually queued, so it falls as the recipient
    /// collects and the entries are deleted.
    ///
    /// Required: a backend answering `0` would leave the per-relationship gate
    /// silently inert.
    async fn peer_queue_count(&self, from_hash: &str, to_hash: &str) -> Result<u32, MediatorError>;

    /// Run one pass of the message expiry sweep. Inspects all expiry
    /// indices whose timestamp is `<= now_secs`, deletes the messages
    /// they reference using `Admin { admin_did_hash }` authorisation,
    /// and drops the now-empty indices.
    ///
    /// Backends may chunk the work internally to avoid blocking the
    /// runtime — the processor calls this on a fixed cadence and
    /// accepts that one call may not drain everything overdue.
    async fn sweep_expired_messages(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
    ) -> Result<ExpiryReport, MediatorError>;

    /// [`sweep_expired_messages`](Self::sweep_expired_messages), telling
    /// `on_expired` (when given) the id and metadata of each message it
    /// removes. The metadata is read before the delete, and only when an
    /// observer is given, so an unobserved sweep costs no more than before.
    async fn sweep_expired_messages_observed(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
        on_expired: Option<OnExpired<'_>>,
    ) -> Result<ExpiryReport, MediatorError>;
}
