//! A connection's share of the mediator-wide connection state, released by
//! construction on every exit path.

use super::*;

/// Releases a DID's reserved per-DID WebSocket slot on drop, so the count is
/// decremented on *every* `handle_socket` return path (including the early
/// returns before the main loop). The entry is removed once it reaches zero
/// so the registry doesn't accumulate idle DIDs.
pub(super) struct PerDidConnectionGuard {
    pub(super) registry: Arc<DashMap<String, u32>>,
    pub(super) did_hash: String,
}

impl Drop for PerDidConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.registry.get_mut(&self.did_hash) {
            *count = count.saturating_sub(1);
        }
        self.registry
            .remove_if(&self.did_hash, |_, &count| count == 0);
    }
}

/// One WebSocket's share of the mediator-wide connection state: its slot in
/// the global count, its per-DID slot, its place on the
/// `ACTIVE_WEBSOCKET_CONNECTIONS` gauge, its streaming registration and its
/// close stat.
///
/// Each part is taken on as the connection reaches it and given back by this
/// one value, so no exit path from `handle_socket` skips or repeats one of
/// these releases. [`ConnectionSlot::release`] gives everything back in order
/// and awaits it; dropping the slot without it (an early return, a panic, the
/// task being cancelled) releases the same parts, sending what needs a task
/// in the background.
///
/// A mux connection's members are not held here: they are closed by
/// `mux::connection::close` on the handler's own exit paths, so a panic or a
/// cancelled task leaves them to the registry's sweep.
pub(super) struct ConnectionSlot {
    pub(super) count: Arc<AtomicUsize>,
    /// Counted on the gauge.
    pub(super) on_gauge: bool,
    /// Counted as opened, so a close stat is owed.
    pub(super) close_stat: Option<Arc<dyn MediatorStore>>,
    /// Registered with the streaming task, so a deregistration is owed.
    pub(super) registration: Option<(Sender<StreamingUpdate>, StreamingUpdate)>,
    /// The DID's per-DID slot, released with the global one.
    pub(super) per_did: Option<PerDidConnectionGuard>,
    /// A relay socket's per-address slot, released with the global one.
    pub(super) per_source: Option<PerDidConnectionGuard>,
}

impl ConnectionSlot {
    /// Reserve a place in the global count. `Err` carries the count already
    /// in use when it is at `max` (`0` = no limit); the reservation is backed
    /// out by then.
    pub(super) fn acquire(count: &Arc<AtomicUsize>, max: usize) -> Result<Self, usize> {
        let current = count.fetch_add(1, Ordering::Relaxed);
        let slot = Self {
            count: count.clone(),
            on_gauge: false,
            close_stat: None,
            registration: None,
            per_did: None,
            per_source: None,
        };
        // 0 is "unlimited", as documented and as the per-DID cap reads it.
        if max != 0 && current >= max {
            Err(current)
        } else {
            Ok(slot)
        }
    }

    /// The connection is admitted: count it on the gauge and in the open
    /// stat, which this slot then owes a matching close for.
    pub(super) async fn open(&mut self, database: &Arc<dyn MediatorStore>) {
        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).increment(1.0);
        self.on_gauge = true;
        let _ = database
            .stats_increment(StatCounter::WebsocketOpen, 1)
            .await;
        self.close_stat = Some(database.clone());
    }

    /// Hold the DID's per-DID slot until this slot is released.
    pub(super) fn hold_per_did(&mut self, guard: PerDidConnectionGuard) {
        self.per_did = Some(guard);
    }

    /// Hold a relay socket's per-address slot until this slot is released.
    pub(super) fn hold_per_source(&mut self, guard: PerDidConnectionGuard) {
        self.per_source = Some(guard);
    }

    /// The streaming task holds a registration for this socket, made with
    /// the send queue `client`. The deregistration names that queue, so it
    /// can only ever remove this socket's entry: another socket for the same
    /// DID may share the session id.
    pub(super) fn registered(
        &mut self,
        channel: Sender<StreamingUpdate>,
        did_hash: &str,
        session_id: &str,
        client: &Sender<QueuedCommand>,
    ) {
        self.registration = Some((
            channel,
            StreamingUpdate {
                did_hash: did_hash.to_string(),
                state: StreamingUpdateState::Deregister {
                    session_id: session_id.to_string(),
                    channel: client.downgrade(),
                },
            },
        ));
    }

    /// The streaming task closed this socket and has already let its
    /// registration go. Deregistering now could remove the newer socket
    /// that took the slot.
    pub(super) fn deregistered_by_streaming(&mut self) {
        self.registration = None;
    }

    /// Give everything back now, awaiting the parts that go to other tasks.
    pub(super) async fn release(mut self) {
        if let Some((channel, stop)) = self.registration.take() {
            let _ = channel.send(stop).await;
        }
        if let Some(database) = self.close_stat.take() {
            let _ = database
                .stats_increment(StatCounter::WebsocketClose, 1)
                .await;
        }
        // The count, the per-DID slot and the gauge go in `drop`.
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
        if self.on_gauge {
            metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).decrement(1.0);
        }
        let registration = self.registration.take();
        let close_stat = self.close_stat.take();
        if registration.is_none() && close_stat.is_none() {
            return;
        }
        // Dropped without `release`. The deregistration is tried without
        // waiting first; only a full control channel needs a task.
        let registration = registration.and_then(|(channel, stop)| match channel.try_send(stop) {
            Err(mpsc::error::TrySendError::Full(stop)) => Some((channel, stop)),
            _ => None,
        });
        if registration.is_none() && close_stat.is_none() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Some((channel, stop)) = registration {
                        let _ = channel.send(stop).await;
                    }
                    if let Some(database) = close_stat {
                        let _ = database
                            .stats_increment(StatCounter::WebsocketClose, 1)
                            .await;
                    }
                });
            }
            Err(_) => warn!(
                "WebSocket connection released outside a runtime; streaming deregistration and close stat not sent"
            ),
        }
    }
}

#[cfg(all(test, feature = "memory-backend"))]
mod connection_slot_tests {
    use super::ConnectionSlot;
    use super::PerDidConnectionGuard;
    use crate::store::memory_store::MemoryStore;
    use crate::tasks::websocket_streaming::{QueuedCommand, StreamingUpdate, StreamingUpdateState};
    use affinidi_messaging_mediator_common::store::prelude::*;
    use dashmap::DashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    async fn closes(database: &Arc<dyn MediatorStore>) -> (i64, i64) {
        let stats = database.get_global_stats().await.expect("stats");
        (stats.websocket_open, stats.websocket_close)
    }

    /// Wait for the background release a dropped slot spawns.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_slot_over_the_limit_gives_its_count_back() {
        let count = Arc::new(AtomicUsize::new(2));
        assert_eq!(ConnectionSlot::acquire(&count, 2).err(), Some(2));
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    /// #147: `max_websocket_connections = 0` is "unlimited", as documented,
    /// not "refuse every socket".
    #[tokio::test]
    async fn a_limit_of_zero_admits_every_socket() {
        let count = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> = (0..3)
            .map(|_| ConnectionSlot::acquire(&count, 0).expect("0 is no limit"))
            .collect();
        assert_eq!(count.load(Ordering::Relaxed), 3);
        drop(slots);
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_dropped_slot_releases_everything_it_took() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        // An early return: the slot is dropped, never released by hand.
        drop(slot);
        settle().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        match rx.try_recv().expect("a deregistration is sent") {
            StreamingUpdate {
                did_hash,
                state: StreamingUpdateState::Deregister { session_id, .. },
            } => {
                assert_eq!(did_hash, "did-hash");
                assert_eq!(session_id, "session-1");
            }
            _ => panic!("expected a Deregister"),
        }
        assert!(rx.try_recv().is_err(), "deregistered exactly once");
        assert_eq!(closes(&database).await, (1, 1));
    }

    #[tokio::test]
    async fn a_released_slot_releases_once() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        slot.release().await;
        settle().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "deregistered exactly once");
        assert_eq!(closes(&database).await, (1, 1));
    }

    /// A socket the streaming task closed has no registration of its own left;
    /// deregistering it could remove the socket that replaced it.
    #[tokio::test]
    async fn a_slot_closed_by_the_streaming_task_does_not_deregister() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        slot.deregistered_by_streaming();
        slot.release().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err());
        assert_eq!(closes(&database).await, (1, 1));
    }

    /// The per-DID slot goes back with the global one, when the connection
    /// is released rather than when the handler finally returns.
    #[tokio::test]
    async fn a_released_slot_gives_back_the_per_did_slot() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let registry: Arc<DashMap<String, u32>> = Arc::new(DashMap::new());
        registry.insert("did-hash".to_string(), 1);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.hold_per_did(PerDidConnectionGuard {
            registry: registry.clone(),
            did_hash: "did-hash".to_string(),
        });
        slot.open(&database).await;
        slot.release().await;

        assert!(registry.get("did-hash").is_none());
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    /// A slot that was never admitted owes no close stat.
    #[tokio::test]
    async fn an_unopened_slot_records_no_close() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        drop(ConnectionSlot::acquire(&count, 10).expect("under the limit"));
        settle().await;
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert_eq!(closes(&database).await, (0, 0));
    }
}
