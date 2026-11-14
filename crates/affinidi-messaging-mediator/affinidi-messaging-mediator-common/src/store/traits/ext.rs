//! The [`MediatorStoreExt`] capability of a storage backend.

use crate::error_codes;
use crate::errors::MediatorError;
use crate::store::MediatorStore;
use crate::store::{
    DeletionAuthority, FAIR_WINDOW_FACTOR, MAX_FAIR_WINDOW, MAX_PURGE_SCAN, MessageScope,
    PurgeFilter, PurgeReport, Session, StatCounter, exclusive_successor, fair_pickup, ops,
    publish_delivery_metrics, purge_folder_by_listing,
};
use crate::types::accounts::{Account, AccountType};
use crate::types::acls::MediatorACLSet;
use crate::types::messages::{FetchDeletePolicy, FetchOptions, Folder, GetMessagesResponse};
use async_trait::async_trait;

/// Algorithms built on the capability traits, the same for every backend.
///
/// Implemented for every [`MediatorStore`] and not overridable, so a backend
/// cannot drift from them: a backend changes their behaviour only through the
/// primitives they call.
#[async_trait]
pub trait MediatorStoreExt: MediatorStore {
    /// Delete a message by ID alone, acting on the records
    /// [`MessageScope::for_authority`] names: an owner's own inbox copy only
    /// (an acknowledgement); for an admin, every copy. A sender withdrawing
    /// what it sent asks for it with
    /// [`delete_message_in`](crate::store::MessageStore::delete_message_in) and
    /// [`MessageScope::Party`].
    ///
    /// Authorisation is encoded in [`DeletionAuthority`]:
    /// - `Owner { did_hash }`: must match the message's TO or FROM, else
    ///   the backend returns `permission_denied`.
    /// - `Admin { admin_did_hash }`: bypasses ownership (used by the
    ///   expiry processor and account removal).
    ///
    /// Returns `not_found` when the message is unknown. Tracing context
    /// (session_id, request_msg_id) comes from `tracing::span` at the
    /// call site and is not part of the storage contract.
    ///
    /// Removes the message body, both stream entries (inbox + outbox),
    /// and the metadata record atomically.
    ///
    /// When the message has a recorded sender, also leaves that sender an
    /// [`OutboxReceipt`] saying why it left ([`ops::removal_reason`]), kept for
    /// [`OUTBOX_RECEIPT_TTL`] and read by
    /// [`sent_message_states`](crate::store::MessageStore::sent_message_states). Every removal goes
    /// through here — a recipient's acknowledgement, a fetch with delete, a
    /// purge, the expiry sweep, account removal — which is what makes the
    /// receipt a complete record rather than a sample.
    async fn delete_message(
        &self,
        message_hash: &str,
        by: DeletionAuthority,
    ) -> Result<(), MediatorError> {
        let scope = MessageScope::for_authority(&by);
        self.delete_message_in(message_hash, scope, by.clone())
            .await
            .map(|_| ())
    }

    /// Fetch, giving each sender a turn rather than serving the queue strictly
    /// head-first.
    ///
    /// # Why this is a separate path
    ///
    /// An inbox is an arrival-ordered stream and a plain fetch reads it from
    /// the head, so a sender that queued fifty messages ahead of another's is
    /// fifty messages the recipient must get through first — and if it cannot
    /// process them and does not delete them, it never reaches the other
    /// sender at all. The per-relationship cap bounds how bad that gets; it
    /// does not change its shape.
    ///
    /// Order **within** a sender is preserved exactly. Only the interleaving
    /// between senders changes, which no ordering guarantee covers — two
    /// senders' messages arrive in whatever order the network delivered them.
    ///
    /// # Cost, and why it is two round trips rather than one
    ///
    /// Listing is cheap and bodies are not, so this lists a window, chooses
    /// from it, and reads only the chosen bodies: one listing plus one batched
    /// get, against the single stored-function call a plain fetch makes. The
    /// window is `limit * `[`FAIR_WINDOW_FACTOR`], capped at
    /// [`MAX_FAIR_WINDOW`], so the extra cost is bounded and does not grow with
    /// the queue.
    ///
    /// # It ignores `start_id`, and the caller must not pass one
    ///
    /// A round-robin selection is not a contiguous stream range, so "continue
    /// after the last id I got" has no meaning against it — a client paging
    /// that way would skip messages. Callers use this only for a fresh pickup;
    /// a paging drain wants stream order anyway and should call
    /// [`fetch_messages`](crate::store::MessageStore::fetch_messages).
    async fn fetch_messages_fair(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        let window_size = options
            .limit
            .saturating_mul(FAIR_WINDOW_FACTOR)
            .min(MAX_FAIR_WINDOW);

        let window = self
            .list_messages(
                did_hash,
                Folder::Inbox,
                Some(("-", "+")),
                window_size as u32,
            )
            .await?;
        let chosen = fair_pickup::round_robin_select(&window, options.limit);
        if chosen.is_empty() {
            return Ok(GetMessagesResponse::default());
        }

        let mut response = GetMessagesResponse::default();
        for (id, message) in chosen
            .iter()
            .zip(self.get_messages(did_hash, &chosen).await?)
        {
            // Listed a moment ago and gone now: a concurrent pickup or the
            // expiry sweeper. Not an error, and not something to report as a
            // failed read.
            let Some(message) = message else { continue };
            response.success.push(message);

            if matches!(options.delete_policy, FetchDeletePolicy::Optimistic)
                && let Err(e) = self
                    .delete_message_in(
                        id,
                        MessageScope::Recipient(did_hash),
                        DeletionAuthority::Owner {
                            did_hash: did_hash.to_string(),
                        },
                    )
                    .await
            {
                response.delete_errors.push((id.clone(), e.to_string()));
            }
        }

        let _ = session_id;
        Ok(response)
    }

    /// Fetch messages and record that they were handed over.
    ///
    /// The delivery paths call this rather than [`fetch_messages`] so the
    /// marking lives in one place. There are five call sites — REST fetch, the
    /// websocket handler, the streaming task, message-pickup and v1 mediation
    /// — and a stamp that five callers have to remember is a stamp that will be
    /// missing from the sixth.
    ///
    /// Marking failures are swallowed by [`mark_delivered`]'s contract, so this
    /// returns exactly what `fetch_messages` returned. A pickup that succeeded
    /// is not failed because its bookkeeping did not.
    ///
    /// [`fetch_messages`]: crate::store::MessageStore::fetch_messages
    /// [`mark_delivered`]: crate::store::MessageStore::mark_delivered
    async fn fetch_messages_delivering(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
        now_ms: u64,
        delivered_ttl_secs: u64,
        round_robin: bool,
    ) -> Result<GetMessagesResponse, MediatorError> {
        // A round-robin selection is not a contiguous stream range, so a caller
        // that is paging with `start_id` must get stream order — "continue
        // after the last id I got" has no meaning against an interleaved
        // result, and honouring it would skip messages. A paging drain wants
        // stream order anyway.
        let response = if round_robin && options.start_id.is_none() {
            self.fetch_messages_fair(session_id, did_hash, options)
                .await?
        } else {
            self.fetch_messages(session_id, did_hash, options).await?
        };

        // An optimistic fetch deletes each message as it reads it, so by the
        // time this runs there is nothing left to stamp — and stamping anyway
        // is not merely wasted work. On Redis the delivery fields live on the
        // message's own `MSG:META` hash, and `HSETNX` against a **missing** key
        // creates it, so marking a message the fetch has already deleted would
        // resurrect an orphaned hash with no body — on every message, for ever.
        //
        // Checked here rather than in each backend because this is where the
        // policy is known, and because a backend that merely skips absent
        // messages (as the in-memory and Fjall stores do) would still be doing
        // a pointless read per message.
        if matches!(options.delete_policy, FetchDeletePolicy::Optimistic) {
            let bytes = response.success.iter().map(|m| m.size as usize).sum();
            self.count_sent(response.success.len(), bytes).await;
            return Ok(response);
        }

        // Only what actually came back: `get_errors` are messages the fetch
        // could not read, and stamping those would record a handover that
        // never happened.
        let delivered: Vec<String> = response.success.iter().map(|m| m.msg_id.clone()).collect();
        self.record_delivered(did_hash, &delivered, now_ms, delivered_ttl_secs)
            .await?;
        Ok(response)
    }

    /// Stamp `msg_ids` as handed over to `recipient_did_hash` (that
    /// recipient's copy only), as
    /// [`fetch_messages_delivering`](Self::fetch_messages_delivering) does for
    /// what it returns, and publish the delivery metrics. For a caller that
    /// fetches with [`fetch_messages`](crate::store::MessageStore::fetch_messages) and writes the
    /// messages itself: it stamps only what it actually wrote (R1.1), so a
    /// message it skips keeps its expiry.
    async fn record_delivered(
        &self,
        recipient_did_hash: &str,
        msg_ids: &[String],
        now_ms: u64,
        delivered_ttl_secs: u64,
    ) -> Result<(), MediatorError> {
        if !msg_ids.is_empty() {
            let report = self
                .mark_delivered(recipient_did_hash, msg_ids, now_ms, delivered_ttl_secs)
                .await?;
            publish_delivery_metrics(&report);
            self.count_sent(report.first_delivered + report.redelivered, report.bytes)
                .await;
        }
        Ok(())
    }

    /// Add a handover of `count` messages totalling `bytes` to the global
    /// `SENT_COUNT` / `SENT_BYTES` counters.
    ///
    /// The contract every backend shares: the sent counters move when a
    /// handover is recorded — by [`record_delivered`](Self::record_delivered)
    /// (which [`fetch_messages_delivering`](Self::fetch_messages_delivering)
    /// uses), or by an optimistic `fetch_messages_delivering`, which deletes
    /// what it hands over — never on a plain read. Best-effort, like the
    /// delivery stamp: a failure is logged and the handover stands.
    async fn count_sent(&self, count: usize, bytes: usize) {
        if count == 0 {
            return;
        }
        if let Err(e) = self
            .stats_increment(StatCounter::SentCount, count as i64)
            .await
        {
            tracing::warn!("Couldn't count {count} sent message(s): {e}");
        }
        if bytes > 0
            && let Err(e) = self
                .stats_increment(StatCounter::SentBytes, bytes as i64)
                .await
        {
            tracing::warn!("Couldn't count {bytes} sent byte(s): {e}");
        }
    }

    /// Delete every message in a folder for the given DID, with the owner's
    /// authority. See [`purge_folder_by`](Self::purge_folder_by).
    async fn purge_folder(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<PurgeReport, MediatorError> {
        self.purge_folder_by(
            session_id,
            did_hash,
            folder,
            DeletionAuthority::Owner {
                did_hash: did_hash.to_string(),
            },
        )
        .await
    }

    /// [`purge_folder`](Self::purge_folder), deleting with `by`'s authority.
    ///
    /// The authority decides the outbox receipt each sender gets (see
    /// [`ops::removal_reason`]): a purge by the folder's owner reads as
    /// `collected` (inbox) or `withdrawn` (outbox), while one the mediator
    /// does on someone else's behalf — an admin purging another account, or
    /// account removal — must pass [`DeletionAuthority::Admin`] so senders see
    /// `discarded`, not a collection that never happened.
    ///
    /// Every backend runs the one algorithm in [`purge_folder_by_listing`]:
    /// paged, already-gone counts as removed, other refusals counted in
    /// [`PurgeReport::failed`] without stopping the purge, and only the
    /// entries of removed messages leave the folder. A caller must check
    /// `failed`: non-zero means messages are still queued.
    async fn purge_folder_by(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
        by: DeletionAuthority,
    ) -> Result<PurgeReport, MediatorError> {
        purge_folder_by_listing(self, session_id, did_hash, folder, by).await
    }

    /// Purge only the messages in a folder that match `filter`, and report
    /// what was (or would be) removed.
    ///
    /// # Why this is not `purge_folder`
    ///
    /// [`purge_folder`](Self::purge_folder) is all-or-nothing, and the queue
    /// that strands a deployment is rarely one where destroying everything is
    /// the right answer. The operation an operator actually wants is "drop what
    /// I have been holding for this dead peer" or "drop anything older than a
    /// week" — with, first, "tell me what that would be". Without those, the
    /// only recovery from a full queue is to destroy an entire outbox including
    /// the messages that were about to be delivered.
    ///
    /// # Implementation
    ///
    /// Defaulted here rather than implemented per backend, over
    /// [`list_messages`](crate::store::MessageStore::list_messages) and
    /// [`delete_message`](Self::delete_message). Those are the same primitives
    /// the paged client-side workaround used, so every backend gets this with
    /// no new storage code and no new invariants to keep true — the cost is one
    /// paged walk of the folder, which is the right trade for a recovery path
    /// that runs when something has already gone wrong.
    ///
    /// Paging advances by the exclusive successor of the last stream id seen,
    /// because a filtered purge leaves non-matching entries in place: restarting
    /// from the beginning each round, as the unfiltered purge can, would spin on
    /// them forever.
    async fn purge_folder_filtered(
        &self,
        did_hash: &str,
        folder: Folder,
        filter: &PurgeFilter,
    ) -> Result<PurgeReport, MediatorError> {
        self.purge_folder_filtered_by(
            did_hash,
            folder,
            filter,
            DeletionAuthority::Owner {
                did_hash: did_hash.to_string(),
            },
        )
        .await
    }

    /// [`purge_folder_filtered`](Self::purge_folder_filtered), deleting with
    /// `by`'s authority — which decides the senders' outbox receipts, as
    /// [`purge_folder_by`](Self::purge_folder_by) explains.
    async fn purge_folder_filtered_by(
        &self,
        did_hash: &str,
        folder: Folder,
        filter: &PurgeFilter,
        by: DeletionAuthority,
    ) -> Result<PurgeReport, MediatorError> {
        const PAGE: u32 = 100;
        let mut report = PurgeReport::default();
        let mut cursor = "-".to_string();

        loop {
            // Bound the work one call can ask for. A filtered purge walks the
            // folder, and a dry run walks it without shrinking it — so, unlike
            // the real purge, it is perfectly repeatable at full cost. That
            // makes it the most expensive thing an authenticated DID can ask
            // for per request, by roughly two orders of magnitude over `/list`,
            // which is capped at 100.
            //
            // The per-DID rate limiter bounds how often; this bounds how much.
            // A caller with more than this queued gets a partial purge that
            // says so, and re-running continues — the same shape the queue
            // survey uses, for the same reason.
            if report.scanned >= MAX_PURGE_SCAN {
                report.truncated = true;
                break;
            }

            let page = self
                .list_messages(did_hash, folder.clone(), Some((&cursor, "+")), PAGE)
                .await?;
            if page.is_empty() {
                break;
            }

            let mut last_id = None;
            for element in &page {
                let stream_id = match folder {
                    Folder::Inbox => element.receive_id.as_deref(),
                    Folder::Outbox => element.send_id.as_deref(),
                };
                last_id = stream_id.map(str::to_string).or(last_id);
                report.scanned += 1;

                if !filter.matches(element, &folder) {
                    continue;
                }
                if filter.dry_run {
                    report.count += 1;
                    report.bytes += element.size as usize;
                    continue;
                }

                // The copy in this folder, named by its recipient: the owner
                // in an inbox, the listed recipient in an outbox. Never
                // another recipient's copy of the same bytes.
                let scope = match (&folder, element.to_address.as_deref()) {
                    (Folder::Inbox, _) => MessageScope::Recipient(did_hash),
                    (Folder::Outbox, Some(to)) => MessageScope::Recipient(to),
                    (Folder::Outbox, None) => MessageScope::Party(did_hash),
                };
                match self
                    .delete_message_in(&element.msg_id, scope, by.clone())
                    .await
                {
                    Ok(_) => {
                        report.count += 1;
                        report.bytes += element.size as usize;
                    }
                    // A message already gone — a concurrent pickup, or the
                    // expiry sweeper — is not a failure: the caller asked for
                    // it to be absent and it is. It is not counted as removed
                    // either, because this call did not remove it.
                    Err(e) if ops::is_delete_not_found(&e) => {}
                    // Anything else is a message still sitting in the queue.
                    // Counting it as purged would report the queue emptier
                    // than it is, to an operator who is reaching for this
                    // precisely because a full queue is causing an outage.
                    Err(e) => {
                        report.failed += 1;
                        tracing::warn!(
                            msg_id = %element.msg_id,
                            error = %e,
                            "filtered purge could not remove a matching message"
                        );
                    }
                }
            }

            // No usable stream id on the whole page: refuse to loop rather
            // than page from the same place for ever.
            let Some(last_id) = last_id else { break };
            let Some(next) = exclusive_successor(&last_id) else {
                break;
            };
            cursor = next;
        }

        Ok(report)
    }

    /// Make sure the DID has an account: create it as
    /// [`account_create`](crate::store::AccountStore::account_create) does, or return the existing
    /// account unchanged (the given ACLs and limit then do not apply).
    async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError> {
        if let Some(created) = self.account_create(did_hash, acls, queue_limit).await? {
            return Ok(created);
        }
        self.account_get(did_hash).await?.ok_or_else(|| {
            MediatorError::InternalError(
                error_codes::DB_OPERATION_ERROR,
                "NA".to_string(),
                format!("account {did_hash} was removed while it was being added"),
            )
        })
    }

    /// Legacy: increment the GLOBAL "sent" counters in one call.
    /// Records `bytes` against `SentBytes` and `1` against `SentCount`.
    /// Both increments are independent — if one fails the other still
    /// completes (or both fail — caller doesn't get partial-success
    /// signal).
    async fn update_send_stats(&self, sent_bytes: i64) -> Result<(), MediatorError> {
        self.stats_increment(StatCounter::SentBytes, sent_bytes)
            .await?;
        self.stats_increment(StatCounter::SentCount, 1).await
    }

    /// Legacy: promote up to `accounts.len()` standard accounts to
    /// `Admin`. Default impl loops over [`setup_admin_account`](crate::store::AccountStore::setup_admin_account).
    async fn add_admin_accounts(
        &self,
        accounts: Vec<String>,
        acls: &MediatorACLSet,
    ) -> Result<usize, MediatorError> {
        let count = accounts.len();
        for did_hash in &accounts {
            self.setup_admin_account(did_hash, AccountType::Admin, acls)
                .await?;
        }
        Ok(count)
    }

    /// Legacy: demote up to `accounts.len()` admin accounts to
    /// `Standard`. Default impl loops over [`account_set_role`](crate::store::AccountStore::account_set_role).
    async fn strip_admin_accounts(&self, accounts: Vec<String>) -> Result<i32, MediatorError> {
        let mut count: i32 = 0;
        for did_hash in &accounts {
            self.account_set_role(did_hash, &AccountType::Standard)
                .await?;
            count += 1;
        }
        Ok(count)
    }

    /// Legacy: `create_session` was the original challenge-creation
    /// entry point. Maps onto [`put_session`](crate::store::SessionStore::put_session) with the standard 15-minute
    /// TTL and bumps the `SessionsCreated` counter (which the original
    /// implementation did inline).
    async fn create_session(&self, session: &Session) -> Result<(), MediatorError> {
        self.put_session(session, std::time::Duration::from_secs(900))
            .await?;
        self.stats_increment(StatCounter::SessionsCreated, 1).await
    }
}

impl<T: MediatorStore + ?Sized> MediatorStoreExt for T {}
