//! The [`StreamingStore`] capability of a storage backend.

use crate::error_codes;
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
    /// The default does nothing: a single-process backend has no other
    /// instance whose monitor subscribers could hear it.
    async fn monitor_fanout_publish(
        &self,
        _scope: &str,
        _payload: &str,
    ) -> Result<(), MediatorError> {
        Ok(())
    }

    /// Subscribe to [`monitor_fanout_publish`](Self::monitor_fanout_publish)
    /// records for `scope` from every instance, this one's included.
    /// `Ok(None)` when the backend is single-process (the default).
    ///
    /// `Lagged` means records were missed; `Closed` means the subscription
    /// was lost and must be opened again.
    async fn monitor_fanout_subscribe(
        &self,
        _scope: &str,
    ) -> Result<Option<broadcast::Receiver<String>>, MediatorError> {
        Ok(None)
    }

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
    /// The default is for a single-instance store, where the streaming task
    /// already orders its own entries: it sets the state and holds the DID.
    async fn streaming_claim(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        live: bool,
        _kind: StreamingKind,
        _write: StreamingWrite,
    ) -> Result<StreamingClaim, MediatorError> {
        let state = if live {
            StreamingClientState::Live
        } else {
            StreamingClientState::Registered
        };
        self.streaming_set_state(did_hash, mediator_uuid, state)
            .await?;
        Ok(StreamingClaim {
            held_here: true,
            displaced_mux: None,
        })
    }

    /// Deregister `did_hash` from this instance, removing its entry only
    /// while this instance owns it. Returns whether a mux entry on another
    /// instance waits for the DID, so the caller tells it to take the DID
    /// back. The default (single instance): deregister, nobody waits.
    async fn streaming_release(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
    ) -> Result<bool, MediatorError> {
        self.streaming_set_state(did_hash, mediator_uuid, StreamingClientState::Deregistered)
            .await?;
        Ok(false)
    }

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
    /// The default asks one DID at a time; a store shared between processes
    /// reads them in batches.
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
    /// The default does nothing: a store used by one process has no other
    /// instance to tell.
    async fn streaming_heartbeat(
        &self,
        _mediator_uuid: &str,
        _lifetime: std::time::Duration,
        _prune_after: std::time::Duration,
    ) -> Result<bool, MediatorError> {
        Ok(false)
    }

    /// Whether each of `mediator_uuids` is a dead instance, in the order
    /// asked: one that kept a heartbeat ([`streaming_heartbeat`](Self::streaming_heartbeat))
    /// and let it expire. An instance that never kept one (an older release)
    /// is never dead. A failed read is an error.
    ///
    /// The default (one process): nobody is dead.
    async fn streaming_dead_instances(
        &self,
        mediator_uuids: &[String],
    ) -> Result<Vec<bool>, MediatorError> {
        Ok(vec![false; mediator_uuids.len()])
    }

    /// Remove `did_hash`'s streaming entry if `dead_uuid` still owns it and
    /// is still dead, both checked in the same step as the removal. Returns
    /// whether it was removed; the caller then claims the DID as for a
    /// missing entry.
    ///
    /// The default (one process): nothing to remove.
    async fn streaming_evict(
        &self,
        _did_hash: &str,
        _dead_uuid: &str,
    ) -> Result<bool, MediatorError> {
        Ok(false)
    }

    /// Whether each of `did_hashes` is held by a mux entry rather than the
    /// DID's own socket, in the order asked; `false` for a DID with no
    /// entry. A failed read is an error.
    ///
    /// The default (one process): the streaming task orders its own entries,
    /// so nothing needs it.
    async fn streaming_mux_owned(&self, did_hashes: &[String]) -> Result<Vec<bool>, MediatorError> {
        Ok(vec![false; did_hashes.len()])
    }

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
    ///
    /// The default publishes an untagged notification: delivery is
    /// unaffected, but no `delivered` monitor event is reported for it —
    /// under-reporting rather than claiming a delivery nobody saw. Every
    /// built-in backend implements it.
    async fn streaming_publish_stored(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
        stored: StoredMessageRef,
    ) -> Result<(), MediatorError> {
        let _ = stored;
        self.streaming_publish_message(did_hash, mediator_uuid, message, force_delivery)
            .await
    }

    /// Publish a frame to be delivered to the client **as it is**, rather
    /// than as a notification to go and fetch what is stored.
    ///
    /// This is for a body that exists nowhere else: a monitor batch is pushed
    /// and never stored, so a raw-TSP socket's usual answer to a notification
    /// — drain the inbox — would deliver nothing at all. Ordinary deliveries
    /// keep using [`streaming_publish_message`](Self::streaming_publish_message).
    ///
    /// **The default refuses**, so a store that cannot carry the distinction
    /// makes the caller count the batch as dropped rather than report a frame
    /// delivered that the socket then discards. Every built-in backend
    /// implements it.
    async fn streaming_publish_verbatim(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
    ) -> Result<(), MediatorError> {
        let _ = (did_hash, mediator_uuid, message);
        Err(MediatorError::InternalError(
            error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            "this store cannot publish a verbatim frame".into(),
        ))
    }

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
