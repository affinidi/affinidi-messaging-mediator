//! The [`ForwardQueueStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::{ForwardQueueClaimPage, ForwardQueueEntry};
use async_trait::async_trait;
use std::time::Duration;

/// The forwarding queue: a consumer-group stream of messages waiting to be relayed to another mediator.
#[async_trait]
pub trait ForwardQueueStore: Send + Sync + std::fmt::Debug {
    /// Enqueue a message for forwarding. `max_len = 0` means unbounded;
    /// otherwise the backend approximately trims the queue at that length.
    /// Returns the assigned stream ID.
    async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError>;

    /// Length of the forwarding queue. Used by load-shedding decisions
    /// and surfaced in `/readyz`.
    async fn forward_queue_len(&self) -> Result<usize, MediatorError>;

    /// Read up to `count` queued messages, blocking up to `block` waiting
    /// for new entries. Reads claim ownership of returned entries until
    /// they're acked (see [`forward_queue_ack`](Self::forward_queue_ack)) or autoclaimed.
    ///
    /// The backend lazily creates the consumer group on first call; no
    /// separate `ensure_group` step is required.
    ///
    /// Multi-process backends share the queue across consumers; single-
    /// process backends serve only consumers within the same process.
    ///
    /// Returns an empty `Vec` on timeout.
    async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block: Duration,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError>;

    /// Acknowledge that a batch of stream IDs were processed successfully.
    /// Removes them from the consumer's pending list.
    async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError>;

    /// Delete acked entries from the queue's storage to free space.
    /// Separate from `ack` because some pipelines want to keep audit logs
    /// of acked-but-not-yet-deleted entries.
    async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError>;

    /// [`Self::forward_queue_ack`] then [`Self::forward_queue_delete`], for
    /// a consumer that is finished with the entries. A backend that can
    /// commit both as one write should: a crash between a separate ack and
    /// delete leaves an entry that no consumer holds and the group has read
    /// past, so it is never read, claimed or deleted again. Every backend
    /// commits both as one write.
    async fn forward_queue_ack_and_delete(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError>;

    /// Remove consumers of `group_name` that hold no entries and have been
    /// idle for at least `min_idle`, other than `keep_consumer` (the
    /// caller's own). Every processor run reads under a consumer name of its
    /// own, so a backend that records consumers would otherwise keep one per
    /// restart for ever. A consumer still holding entries is never removed:
    /// its entries are handed on by
    /// [`forward_queue_autoclaim`](Self::forward_queue_autoclaim). Returns
    /// how many were removed. A backend that keeps no consumer records
    /// answers `0`.
    async fn forward_queue_prune_consumers(
        &self,
        group_name: &str,
        keep_consumer: &str,
        min_idle: Duration,
    ) -> Result<usize, MediatorError>;

    /// Reclaim entries idle for longer than `min_idle` (typical: a
    /// crashed/timed-out consumer). The reclaiming consumer becomes the
    /// new owner of the returned entries.
    ///
    /// One call examines a bounded stretch of the pending list, starting at
    /// `cursor` (`"0-0"` for the start), and returns up to `count` entries
    /// with the cursor to continue from. A scan of the whole list follows
    /// `next_cursor` until it is `None`; stopping at the first short or empty
    /// page would never reach idle entries behind a long run of busy ones.
    async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle: Duration,
        count: usize,
        cursor: &str,
    ) -> Result<ForwardQueueClaimPage, MediatorError>;

    /// Finish with one entry, but only if `consumer_name` still has it
    /// claimed: ack and delete it, and with `requeue`, enqueue that entry in
    /// its place, all as one write. Returns `false`, changing nothing, when
    /// the entry is claimed by another consumer or no longer pending — the
    /// other consumer now owns its fate, and acking or re-queuing it here
    /// would delete its claim or duplicate its delivery.
    async fn forward_queue_finish(
        &self,
        group_name: &str,
        consumer_name: &str,
        stream_id: &str,
        requeue: Option<&ForwardQueueEntry>,
    ) -> Result<bool, MediatorError>;

    /// Reset the idle time of each of `stream_ids` that `consumer_name` still
    /// has claimed, so another consumer's
    /// [`forward_queue_autoclaim`](Self::forward_queue_autoclaim) does not take
    /// an entry this one is still working on. An entry claimed by another
    /// consumer is left alone: the refresh never moves a claim.
    ///
    /// Returns the ids `consumer_name` no longer holds — claimed by another
    /// consumer, acked, or gone from the queue. The caller must not deliver
    /// those.
    async fn forward_queue_refresh_claims(
        &self,
        group_name: &str,
        consumer_name: &str,
        stream_ids: &[&str],
    ) -> Result<Vec<String>, MediatorError>;
}
