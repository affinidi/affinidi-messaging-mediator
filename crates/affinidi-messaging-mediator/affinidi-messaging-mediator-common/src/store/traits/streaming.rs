//! The [`StreamingStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::{
    PubSubRecord, StoredMessageRef, StreamingClaim, StreamingClientState, StreamingKind,
    StreamingWrite,
};
use async_trait::async_trait;
use tokio::sync::broadcast;

/// Live streaming: which instance holds which DID's socket, and the pub/sub channels that push deliveries to it.
#[async_trait]
pub trait StreamingStore: Send + Sync + std::fmt::Debug {
    /// Tell every mediator instance sharing this store, this one included,
    /// `payload`: one traffic-monitor record (JSON the mediator defines) on
    /// the channel for `scope`, which names the mediator so that two
    /// deployments sharing one server never hear each other. Best-effort and
    /// at most once.
    ///
    /// A single-process backend does nothing: it has no other instance whose
    /// monitor subscribers could hear it.
    async fn monitor_fanout_publish(&self, scope: &str, payload: &str)
    -> Result<(), MediatorError>;

    /// Subscribe to [`monitor_fanout_publish`](Self::monitor_fanout_publish)
    /// records for `scope` from every instance, this one's included.
    /// `Ok(None)` when the backend is single-process.
    ///
    /// `Lagged` means records were missed; `Closed` means the subscription
    /// was lost and must be opened again.
    async fn monitor_fanout_subscribe(
        &self,
        scope: &str,
    ) -> Result<Option<broadcast::Receiver<String>>, MediatorError>;

    /// Reset the streaming session set for this mediator instance.
    /// Called once at startup to clean up state from previous runs.
    async fn streaming_clean_start(&self, mediator_uuid: &str) -> Result<(), MediatorError>;

    /// Set the streaming state for a DID on this mediator instance.
    ///
    /// State transitions:
    /// - `Registered`: client connected via WebSocket, queue messages normally
    /// - `Live`: client enabled live delivery, push instead of (or in
    ///   addition to) queueing
    /// - `Deregistered`: client disconnected, drop all streaming state
    ///
    /// Idempotent; safe to set the same state repeatedly.
    async fn streaming_set_state(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        state: StreamingClientState,
    ) -> Result<(), MediatorError>;

    /// Register `did_hash` on this instance (`live`: with live delivery on),
    /// as `kind`, and say whether this instance now holds it. Across
    /// instances sharing a store, a direct socket outranks a mux entry and
    /// otherwise the newest registration wins; `write` says whether this is a
    /// new registration or a change to one (see [`StreamingWrite`]).
    ///
    /// A single-process store, where the streaming task already orders its
    /// own entries, sets the state and holds the DID
    /// ([`single_process::streaming_claim`](crate::store::single_process::streaming_claim)).
    async fn streaming_claim(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        live: bool,
        kind: StreamingKind,
        write: StreamingWrite,
    ) -> Result<StreamingClaim, MediatorError>;

    /// Deregister `did_hash` from this instance, removing its entry only
    /// while this instance owns it. Returns whether a mux entry on another
    /// instance waits for the DID, so the caller tells it to take the DID
    /// back. A single-process store deregisters, and nobody waits
    /// ([`single_process::streaming_release`](crate::store::single_process::streaming_release)).
    async fn streaming_release(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
    ) -> Result<bool, MediatorError>;

    /// Whether `did_hash` has a streaming subscriber on any mediator
    /// instance, returning the mediator UUID hosting the subscriber.
    /// With `force_delivery = true`, returns the UUID even when the
    /// subscriber is `Registered` but not `Live` (used to push status
    /// messages on live-delivery transitions).
    async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String>;

    /// The instance holding each of `did_hashes`, in the order asked: its
    /// streaming uuid for a DID with an entry (live or not), `None` for a DID
    /// no instance has registered. Unlike
    /// [`streaming_is_client_live`](Self::streaming_is_client_live), a failed
    /// read is an error, never "nobody", so a caller can act on a missing
    /// entry.
    ///
    /// The default asks one DID at a time, which is correct for every
    /// backend; a store shared between processes overrides it to read them in
    /// batches.
    async fn streaming_owners(
        &self,
        did_hashes: &[String],
    ) -> Result<Vec<Option<String>>, MediatorError> {
        let mut owners = Vec::with_capacity(did_hashes.len());
        for did_hash in did_hashes {
            owners.push(self.streaming_is_client_live(did_hash, true).await);
        }
        Ok(owners)
    }

    /// Renew this instance's heartbeat for `lifetime`, so the other
    /// instances sharing the store know it is alive; a listed instance whose
    /// last beat is older than `prune_after` is forgotten. Returns whether
    /// the heartbeat had lapsed, so other instances may have taken over this
    /// instance's entries meanwhile.
    ///
    /// A store used by one process has no other instance to tell: it does
    /// nothing and answers `false`.
    async fn streaming_heartbeat(
        &self,
        mediator_uuid: &str,
        lifetime: std::time::Duration,
        prune_after: std::time::Duration,
    ) -> Result<bool, MediatorError>;

    /// Whether each of `mediator_uuids` is a dead instance, in the order
    /// asked: one that kept a heartbeat ([`streaming_heartbeat`](Self::streaming_heartbeat))
    /// and let it expire. An instance that never kept one (an older release)
    /// is never dead. A failed read is an error.
    ///
    /// In a single-process store nobody is dead.
    async fn streaming_dead_instances(
        &self,
        mediator_uuids: &[String],
    ) -> Result<Vec<bool>, MediatorError>;

    /// Remove `did_hash`'s streaming entry if `dead_uuid` still owns it and
    /// is still dead, both checked in the same step as the removal. Returns
    /// whether it was removed; the caller then claims the DID as for a
    /// missing entry.
    ///
    /// A single-process store has nothing to remove.
    async fn streaming_evict(&self, did_hash: &str, dead_uuid: &str)
    -> Result<bool, MediatorError>;

    /// Whether each of `did_hashes` is held by a mux entry rather than the
    /// DID's own socket, in the order asked; `false` for a DID with no
    /// entry. A failed read is an error.
    ///
    /// A single-process store answers `false` for every DID: its streaming
    /// task orders its own entries, so nothing needs it.
    async fn streaming_mux_owned(&self, did_hashes: &[String]) -> Result<Vec<bool>, MediatorError>;

    /// Publish a delivery notification to the streaming channel for
    /// `mediator_uuid`. Subscribers (the WebSocket task on that mediator
    /// instance) deliver the message to the connected client.
    ///
    /// On `RedisStore` this delivers cross-process via `PUBLISH`; on
    /// `MemoryStore`/`FjallStore` it delivers in-process only.
    async fn streaming_publish_message(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError>;

    /// [`streaming_publish_message`](Self::streaming_publish_message) for a
    /// message that is in the recipient's inbox, tagged with `stored` so the
    /// streaming task can report its delivery once the notification is
    /// actually queued to the socket (R1.1).
    async fn streaming_publish_stored(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
        stored: StoredMessageRef,
    ) -> Result<(), MediatorError>;

    /// Publish a frame to be delivered to the client **as it is**, rather
    /// than as a notification to go and fetch what is stored.
    ///
    /// This is for a body that exists nowhere else: a monitor batch is pushed
    /// and never stored, so a raw-TSP socket's usual answer to a notification
    /// — drain the inbox — would deliver nothing at all. Ordinary deliveries
    /// keep using [`streaming_publish_message`](Self::streaming_publish_message).
    ///
    /// A store that cannot carry the distinction must refuse, so the caller
    /// counts the batch as dropped rather than report a frame delivered that
    /// the socket then discards.
    async fn streaming_publish_verbatim(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
    ) -> Result<(), MediatorError>;

    /// Subscribe to live-streaming delivery notifications for one
    /// mediator UUID. Returns a [`broadcast::Receiver`]; lagged
    /// subscribers see [`broadcast::error::RecvError::Lagged`] which
    /// matches Redis pub/sub's "late subscribers miss messages" model.
    /// Dropping the receiver unsubscribes; backends keep the underlying
    /// channel alive as long as the store is alive.
    ///
    /// Called once per mediator instance by the WebSocket streaming task.
    async fn streaming_subscribe(
        &self,
        mediator_uuid: &str,
    ) -> Result<broadcast::Receiver<PubSubRecord>, MediatorError>;
}
