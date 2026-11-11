/*!
 A task that listens for streaming notifications from the storage
 backend and sends them to clients over a websocket.

 It maintains a HashMap of channels keyed by DID hash. If a duplicate
 WebSocket is opened for the same DID the older session is forcibly
 closed so only the most recent one receives messages.

 The recipient's undelivered inbox is redelivered (see
 `spawn_inbox_redelivery`) at **two** points, for the same underlying
 reason: the store both live-pushes *and* persists every non-ephemeral
 message, but nothing ever streams a message that was persisted without
 being pushed. A client relying on live delivery then hangs until timeout
 while the message sits in its inbox.

 - **A duplicate replaces an existing session.** A notification published
   in the instant the old socket is torn down would otherwise be stranded
   on a socket nobody is reading. See issue #374.
 - **A socket enables live delivery.** Messages that arrived between
   registration and activation were stored and not pushed, because the
   client was not live when they landed. Under load that window is wide
   enough to strand a message for a full minute — see VTI#918, where the
   mediator reported `queued=1, live_delivery=true` while the recipient
   polled the live stream and saw nothing.

 Both are at-least-once, consistent with the message-pickup delete-to-ack
 contract. Disabling live delivery deliberately does *not* redeliver.

 The notification stream comes from `MediatorStore::streaming_subscribe`,
 so the task runs unchanged whether the backend is Redis pub/sub,
 Fjall's in-process broadcast, or the test MemoryStore.
*/
use crate::common::metrics::names::{
    MUX_QUEUE_FAIRNESS_SKIPS_TOTAL, WEBSOCKET_CHURN_REFUSED_TOTAL, WEBSOCKET_DUPLICATE_CHURN_TOTAL,
    WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL, WEBSOCKET_REDELIVERED_MESSAGES_TOTAL,
    WS_LIVE_DELIVERY_DROPPED,
};
use crate::common::ws_budget::{SendPermit, WsSendBudget};
use crate::mux::fair_queue::{MuxSlots, SlotCredit, SlotRefusal};
use crate::tasks::supervisor::TaskSupervisor;
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{
        MediatorStore, StreamingClaim, StreamingKind, StreamingWrite,
        mux::{MuxChangeRecord, StreamingHandoff},
        types::PubSubRecord,
    },
    types::messages::FetchOptions,
};
use ahash::AHashMap as HashMap;
use dashmap::DashSet;
use std::{
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::{Mutex, broadcast, mpsc},
    time::sleep,
};
use tracing::{Instrument, Level, debug, error, info, span, warn};

/// A duplicate replacement arriving within this window of the previous
/// registration for the same DID is counted as socket *churn* (the
/// flip-flop signal in issue #374).
const CHURN_WINDOW: Duration = Duration::from_secs(5);

/// Consecutive in-window replacements for one DID before the duel damper in
/// `_handle_registration` starts holding the slot for the incumbent. Two is a
/// hand-off (A replaced by B, B replaced by A); three or more is a duel.
const CHURN_REFUSE_STREAK: u32 = 3;

/// Page size for the inbox-redelivery drain.
const REDELIVERY_PAGE: usize = 50;

/// Safety bound on how many messages a single redelivery will re-push,
/// so a pathologically large inbox can't pin the drain task. If hit, the
/// remainder is left for the client to pick up via normal message-pickup.
const REDELIVERY_MAX: usize = 1000;

/// How often the task re-reads, for each of its mux entries, which instance
/// the store says streams the DID. The `Taken`/`Released` handoffs normally
/// keep the two in step; this catches one that was lost (an instance dying
/// between its store write and its publish, or a dropped pub/sub message), so
/// a member is never reported in the wrong state for longer than this.
const OWNERSHIP_RECHECK: Duration = Duration::from_secs(60);

/// Slots in a single connection's send queue.
///
/// This is the per-connection *depth* cap; the aggregate *byte* cap is the
/// shared [`WsSendBudget`]. Depth still matters: without it one client could
/// reserve the entire global pool for itself. Together they bound a connection
/// at `WS_CHANNEL_SLOTS × message_size` and all connections at the pool size.
pub const WS_CHANNEL_SLOTS: usize = 8;

/// How a client entry reaches its DID.
///
/// A DID can be carried by its own (*direct*) socket, or as a member of a
/// principal's multiplexed connection (*mux*, design §7.2). A direct socket
/// always takes precedence: a mux entry yields to it and waits on standby.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryKind {
    #[default]
    Direct,
    Mux,
}

impl From<EntryKind> for StreamingKind {
    fn from(kind: EntryKind) -> Self {
        match kind {
            EntryKind::Direct => StreamingKind::Direct,
            EntryKind::Mux => StreamingKind::Mux,
        }
    }
}

/// What happened to one member DID on a mux connection, told to that
/// connection's socket so it can emit `messaging/mux/event` (R6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberChange {
    /// The member's live delivery moved to another socket (its own direct
    /// socket, or a newer mux connection). It stays on this connection,
    /// inactive, and comes back if that socket goes away.
    Superseded { did_hash: String },
    /// The member registered behind a live socket and is waiting on standby.
    Inactive { did_hash: String },
    /// The socket that held the member went away; this connection carries it
    /// again.
    Reactivated { did_hash: String },
}

/// One registered streaming client for a DID.
struct ClientEntry {
    /// Channel to the per-connection websocket handler.
    tx: mpsc::Sender<QueuedCommand>,
    /// Session id of the owning websocket (used for churn/diagnostic logs).
    session_id: String,
    /// Whether live delivery is currently active for this client.
    active: bool,
    /// When this client registered — used to detect rapid replacement churn.
    registered_at: Instant,
    /// Raised when a live notification for this client was dropped, and
    /// lowered by the socket handler once it has told the client to drain.
    ///
    /// A dropped notification loses nothing durable — the message stays in the
    /// inbox — but a client that only *listens* never learns it is there, and
    /// so never collects it. The flag is the missing half: the drop stays
    /// silent on the wire, the fact of it does not.
    ///
    /// It is a flag rather than a queued frame because the drop happens
    /// precisely when there is no room to queue anything. Many drops collapse
    /// into one signal, which is the right shape: the client's response to any
    /// number of them is the same single drain.
    resync: Arc<AtomicBool>,
    /// Consecutive in-churn-window replacements this DID's slot has seen.
    /// Carried across replacements and reset by any registration that arrives
    /// outside the window. Drives the duel damper in `_handle_registration`.
    churn_streak: u32,
    /// Direct socket, or a member of a mux connection.
    kind: EntryKind,
    /// The connection's per-DID slot accounting when it is a mux connection
    /// (design §7.2 fair queuing); `None` on a direct socket, whose queue is
    /// the plain bounded channel.
    slots: Option<Arc<MuxSlots>>,
}

/// Used when updating the streaming state.
/// Register: Creates the hash map entry for the DID hash and TX Channel
/// Start: Start streaming messages to clients.
/// Stop: Stop streaming messages to clients.
/// Deregister: Remove the hash map entry for the DID hash.
pub enum StreamingUpdateState {
    Register {
        channel: mpsc::Sender<QueuedCommand>,
        session_id: String,
        did: String,
        /// Set by this task when a live notification for the DID had to be
        /// dropped, and observed by the socket handler that owns the
        /// connection. See `ClientEntry::resync`.
        resync: Arc<AtomicBool>,
        /// Direct socket, or a mux member (design §7.2).
        kind: EntryKind,
        /// Set for every entry on a mux connection, the principal's own
        /// included: the slots its queued frames hold. `None` for a direct
        /// socket.
        slots: Option<Arc<MuxSlots>>,
    },
    /// Enable live delivery for the socket owned by `session_id`.
    ///
    /// Session-scoped for the same reason [`Deregister`](Self::Deregister) is:
    /// `clients` is keyed by DID hash, so an update that doesn't name its
    /// session acts on whichever connection currently holds the slot — which
    /// may not be the one that sent it.
    Start { session_id: String },
    /// Disable live delivery for the socket owned by `session_id`.
    Stop { session_id: String },
    /// Remove the map entry for this DID — but only if it is still *this*
    /// session's entry. `clients` is keyed by DID hash, not by connection, so a
    /// deregistration must name the session it belongs to: a socket that has
    /// already been replaced (one DID, one slot) would otherwise evict its
    /// successor on the way out. See the session-id check in the handler.
    Deregister { session_id: String },
    /// A registration on another instance took this DID from this
    /// instance's mux entry: a direct socket there outranks it, or a newer
    /// mux connection there carries it. The entry stands by, and its
    /// connection is told the member is inactive (`superseded`).
    RemoteTaken,
    /// The DID's owner on another instance left. A mux entry standing by
    /// here takes the DID back (`reactivated`).
    RemoteReleased,
}

/// Used to send commands from the streaming task to the websocket handler
pub enum WebSocketCommands {
    /// Send a message to the client.
    Message(String),
    /// Send this body to the client as it is.
    ///
    /// [`Message`](Self::Message) is a *notification*: a raw-TSP socket
    /// answers it by draining the client's stored inbox and discards the body.
    /// A monitor batch is never stored, so that answer would deliver nothing —
    /// it is sent as the frame instead.
    Verbatim(String),
    /// A mux member's delivery moved; the socket reports it to its client.
    /// Never sent to a direct socket.
    MemberChange(MemberChange),
    /// Close this socket for the stated reason.
    ///
    /// The reason is carried rather than assumed. It used to be a bare `Close`,
    /// and the handler answered every one of them with the same problem report
    /// and the same close reason — "replaced by a newer connection" — across
    /// three situations that are not the same thing. A client that was *refused*
    /// was told it had been *replaced*, which is not merely unhelpful but
    /// backwards, and left it with nothing better to show a user than a
    /// transport error.
    Close(CloseReason),
}

/// Why the streaming task is closing a socket.
///
/// Each variant maps to its own problem-report code and close reason, so a
/// client can tell "you have this open twice" from "your session lost its slot"
/// from "you are not authenticated" — and say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// This socket held the DID's slot and a newer connection took it.
    ///
    /// Newest-wins is deliberate for an isolated duplicate: a client whose
    /// previous socket half-opened must be able to reclaim its slot. The
    /// recipient of this is the *incumbent*.
    Replaced,
    /// This socket asked for a slot that a live incumbent holds, and the duel
    /// damper refused it.
    ///
    /// The recipient is the *newcomer*, and nothing of its own was displaced —
    /// which is exactly what the old shared wording got wrong. Refusal is not a
    /// fault: something is running a second live session for this DID, and only
    /// the client can say what.
    Refused,
    /// The session reached registration with no authenticated DID.
    ///
    /// An upstream auth bug rather than anything the client did with its
    /// connection; kept distinct so it cannot be mistaken for a duplicate.
    Unauthenticated,
}

/// A command sitting in a connection's send queue, together with the byte
/// reservation it holds against the global [`WsSendBudget`].
///
/// The permit is owned by the queue item on purpose: it is released exactly when
/// the item is dropped, which is when the connection's writer has taken it off
/// the queue. There is no separate "release" call to forget.
pub struct QueuedCommand {
    pub cmd: WebSocketCommands,
    /// A stored message's delivery, for the socket loop to report once the
    /// frame is on the wire (R1.1). `None` for control, ephemeral pushes and
    /// monitor batches.
    pub report: Option<DeliveryReport>,
    /// The DID this payload is for. A mux connection carries many DIDs, so its
    /// handler needs to know which one to drain, resync or drop frames for.
    /// `None` for control commands.
    pub did_hash: Option<String>,
    /// `None` for control commands (`Close`), which carry no payload and must
    /// never be refused for want of buffer bytes.
    _permit: Option<SendPermit>,
    /// The DID's slot on a mux connection, held, like the permit, until the
    /// socket loop takes the item. `None` on a direct socket and for control.
    _slot: Option<SlotCredit>,
}

impl QueuedCommand {
    /// A control command. Always admissible — it holds no bytes.
    fn control(cmd: WebSocketCommands) -> Self {
        Self {
            cmd,
            report: None,
            did_hash: None,
            _permit: None,
            _slot: None,
        }
    }

    /// An empty payload tagged for `did_hash`, for tests of queue ordering.
    #[cfg(test)]
    pub(crate) fn for_test(did_hash: Option<&str>) -> Self {
        Self {
            cmd: WebSocketCommands::Message(String::new()),
            report: None,
            did_hash: did_hash.map(str::to_string),
            _permit: None,
            _slot: None,
        }
    }
}

/// A stored message's delivery to report to the traffic monitor. It rides
/// with the queued frame, and the socket loop emits it only once the frame
/// is written: a frame dropped from the queue, or for a mux member that left,
/// or a write that fails, is not a delivery (R1.1).
#[derive(Debug, Clone)]
pub struct DeliveryReport {
    pub msg_id: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub size: u64,
    /// The frame's protocol, read from the body when the report is made. The
    /// report holds no copy of the body: the monitor never publishes one.
    pub protocol: crate::monitor::Protocol,
}

impl DeliveryReport {
    /// Report the delivery: call once the frame is on the wire.
    pub fn emit(self, monitor: &crate::monitor::TrafficMonitor) {
        monitor.delivered_as(
            &self.msg_id,
            self.from.as_deref(),
            self.to.as_deref(),
            self.size,
            crate::monitor::Channel::Websocket,
            self.protocol,
        );
    }
}

/// Queue a payload to one client without blocking.
///
/// Returns `false` if the message was dropped — either the global byte pool is
/// exhausted or this connection's queue is full. Both mean the client is not
/// keeping up; the message is already durable in its inbox, so it will arrive on
/// the next poll or on reconnect redelivery.
///
/// Non-blocking is the whole point: this is called from the single streaming
/// loop that serves every DID, so awaiting one slow client here would stall live
/// delivery for all of them.
fn try_queue_message(
    tx: &mpsc::Sender<QueuedCommand>,
    slots: Option<&Arc<MuxSlots>>,
    budget: &WsSendBudget,
    did_hash: &str,
    message: String,
    report: Option<DeliveryReport>,
) -> bool {
    try_queue(tx, slots, budget, did_hash, message, false, report)
}

/// [`try_queue_message`], with `verbatim` choosing the command the socket
/// handler receives.
///
/// On a mux connection (`slots` set) the payload must first take one of its
/// DID's slots: a DID that already holds its share is refused here, so it is
/// the busy member whose push drops, not whichever member happened to arrive
/// once the shared queue was full (design §7.2).
fn try_queue(
    tx: &mpsc::Sender<QueuedCommand>,
    slots: Option<&Arc<MuxSlots>>,
    budget: &WsSendBudget,
    did_hash: &str,
    message: String,
    verbatim: bool,
    report: Option<DeliveryReport>,
) -> bool {
    let slot = match slots.map(|s| s.try_acquire(did_hash)) {
        None => None,
        Some(Ok(slot)) => Some(slot),
        Some(Err(why)) => {
            debug!(did_hash = %did_hash, refusal = ?why, "mux send share full; dropping live notification");
            if why == SlotRefusal::Member {
                metrics::counter!(MUX_QUEUE_FAIRNESS_SKIPS_TOTAL).increment(1);
            }
            metrics::counter!(WS_LIVE_DELIVERY_DROPPED).increment(1);
            return false;
        }
    };
    let Some(permit) = budget.try_reserve(message.len()) else {
        warn!(
            "WebSocket send buffer exhausted ({} bytes total); dropping live notification for {}. \
             Client will pick the message up from its inbox.",
            budget.total_bytes(),
            did_hash
        );
        metrics::counter!(WS_LIVE_DELIVERY_DROPPED).increment(1);
        return false;
    };

    let queued = QueuedCommand {
        cmd: if verbatim {
            WebSocketCommands::Verbatim(message)
        } else {
            WebSocketCommands::Message(message)
        },
        report,
        did_hash: Some(did_hash.to_string()),
        _permit: Some(permit),
        _slot: slot,
    };

    if tx.try_send(queued).is_err() {
        // Channel full (slow consumer) or closed (socket gone). Either way the
        // push is dropped; a closed channel is reaped by the caller.
        debug!("Send queue unavailable for {did_hash}; dropping live notification");
        metrics::counter!(WS_LIVE_DELIVERY_DROPPED).increment(1);
        return false;
    }
    true
}

/// Tell the socket that `did_hash` has stored mail it was not pushed, so the
/// client is prompted to collect it (a pickup `status` on DIDComm, a drain on
/// raw TSP).
///
/// On a mux connection the resync is owed to this DID, not the socket:
/// recorded before the shared flag goes up, so the socket finds it. Repeated
/// raises collapse into one signal, which is the right shape: the client's
/// answer to any number of them is the same single collection.
fn raise_resync(slots: Option<&Arc<MuxSlots>>, resync: &AtomicBool, did_hash: &str) {
    if let Some(slots) = slots {
        slots.raise_resync(did_hash);
    }
    resync.store(true, Ordering::Relaxed);
}

/// Push one live notification to a registered client, raising its resync flag
/// if the push could not be queued.
///
/// The two halves belong together: a drop loses nothing durable — the message
/// is in the recipient's inbox — but a client that only *listens* has no way to
/// learn it is there, so a drop that does not raise the flag is a message the
/// client never collects. Keeping them in one place is what stops a future
/// caller doing the first without the second.
///
/// Returns whether the notification was queued.
fn deliver_live(
    entry: &ClientEntry,
    budget: &WsSendBudget,
    did_hash: &str,
    message: String,
    verbatim: bool,
    report: Option<DeliveryReport>,
) -> bool {
    if try_queue(
        &entry.tx,
        entry.slots.as_ref(),
        budget,
        did_hash,
        message,
        verbatim,
        report,
    ) {
        debug!("Sent message to client ({did_hash})");
        return true;
    }
    raise_resync(entry.slots.as_ref(), &entry.resync, did_hash);
    debug!(
        did_hash = %did_hash,
        "live notification dropped; resync raised for the socket handler"
    );
    false
}

/// Used to update the streaming state.
/// did_hash: The DID hash to update the state for.
/// state: The state to update to.
pub struct StreamingUpdate {
    pub did_hash: String,
    pub state: StreamingUpdateState,
}

#[derive(Clone)]
pub struct StreamingTask {
    pub uuid: String,
    pub channel: mpsc::Sender<StreamingUpdate>,
    /// Global byte pool shared by every connection's send queue.
    pub send_budget: WsSendBudget,
    /// `limits.delivered_expiry_seconds`, carried so the redelivery drain
    /// records handovers on the same terms as every other delivery path. `0`
    /// leaves expiry untouched, which is the default.
    pub delivered_expiry_seconds: u64,
}

impl StreamingTask {
    /// Create the streaming task's command channel and register the task with
    /// the [`TaskSupervisor`], so a panic or startup error restarts it with
    /// backoff (and surfaces as a `degraded` component in `/readyz`) instead of
    /// dying silently with a dropped `JoinHandle`.
    ///
    /// The returned [`StreamingTask`] holds the `tx` side of the command
    /// channel (cloned into `SharedData` and every WebSocket handler). The `rx`
    /// side is wrapped in an `Arc<Mutex<_>>` so it survives restarts: the
    /// supervisor builds a fresh future each restart, but it re-locks the
    /// *same* receiver, so queued commands and the live `tx` clones stay valid.
    /// `tokio`'s `Mutex` doesn't poison, so a panicking run releases the guard
    /// cleanly for the next restart.
    ///
    /// Not load-bearing: if streaming is down, clients fall back to
    /// message-pickup polling, so it degrades `/readyz` rather than failing it.
    pub fn spawn_supervised(
        supervisor: &TaskSupervisor,
        database: Arc<dyn MediatorStore>,
        mediator_uuid: &str,
        send_budget: WsSendBudget,
        delivered_expiry_seconds: u64,
    ) -> Self {
        // Control-plane channel (register/start/stop/deregister). Carries no
        // message bodies — a handful of small structs — so a slot count is the
        // right bound here and 10 is plenty.
        let (tx, rx) = mpsc::channel(10);
        let task = StreamingTask {
            channel: tx,
            uuid: mediator_uuid.to_string(),
            send_budget,
            delivered_expiry_seconds,
        };
        let rx = Arc::new(Mutex::new(rx));

        let supervised = task.clone();
        supervisor.spawn("websocket_streaming", false, move || {
            let task = supervised.clone();
            let database = database.clone();
            let rx = rx.clone();
            async move {
                let mut rx = rx.lock().await;
                task.ws_streaming_task(database, &mut rx).await
            }
        });

        task
    }

    /// Streams messages to subscribed clients over websocket.
    /// Is spawned as a task
    async fn ws_streaming_task(
        self,
        database: Arc<dyn MediatorStore>,
        channel: &mut mpsc::Receiver<StreamingUpdate>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming_task", uuid = &self.uuid);

        async move {
            info!("WebSocket streaming task starting");

            // Clean up any existing sessions left over from previous runs
            database.streaming_clean_start(&self.uuid).await?;

            // Create a hashmap to store the clients keyed by did_hash.
            let mut clients: HashMap<String, ClientEntry> = HashMap::new();
            // Entries that yielded the live slot to another socket for the same
            // DID (design §7.2): a mux member behind its DID's direct socket,
            // or behind a newer mux connection. Newest last. Promoted when the
            // live entry goes away.
            let mut standby: HashMap<String, Vec<ClientEntry>> = HashMap::new();

            // DIDs with an inbox-redelivery drain currently in flight. Used to
            // damp duplicate-socket flip-flop: a duel that replaces the socket
            // every couple of seconds must not re-dump the whole inbox on each
            // replacement. A replay already running for a DID covers the current
            // inbox state, so concurrent replacements skip spawning another.
            let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());

            // Subscribe to delivery notifications via the trait. Backends
            // are responsible for the wire-level transport (Redis pub/sub,
            // in-process broadcast, etc.) — the task just consumes
            // already-decoded `PubSubRecord`s.
            let mut rx = database.streaming_subscribe(&self.uuid).await?;
            let mut ownership = tokio::time::interval_at(
                tokio::time::Instant::now() + OWNERSHIP_RECHECK,
                OWNERSHIP_RECHECK,
            );
            ownership.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                select! {
                    _ = ownership.tick() => {
                        self.recheck_ownership(&database, &mut clients, &mut standby, &replay_in_progress).await;
                    }
                    value = rx.recv() => {
                        match value {
                            Ok(payload) => {
                                self.dispatch_payload(&database, &mut clients, &mut standby, &replay_in_progress, payload).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                // Subscriber fell behind; backend's broadcast capacity
                                // was exceeded. Live messages were dropped, but the
                                // queueing path still picked them up — clients just
                                // won't get a real-time push for those entries.
                                warn!(
                                    "Streaming subscriber lagged, dropped {} live notifications",
                                    skipped
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                error!("Streaming subscription closed, attempting to resubscribe");
                                rx = loop {
                                    sleep(Duration::from_secs(1)).await;
                                    match database.streaming_subscribe(&self.uuid).await {
                                        Ok(rx) => break rx,
                                        Err(err) => {
                                            error!("Error resubscribing to streaming channel: {err}");
                                            continue;
                                        }
                                    }
                                };
                            }
                        }
                    }
                    value = channel.recv() => { // mpsc command channel
                        if let Some(value) = &value {
                            match &value.state {
                                StreamingUpdateState::Register { .. } => {
                                    self._handle_registration(&database, &mut clients, &mut standby, &replay_in_progress, value).await;
                                },
                                StreamingUpdateState::Start { session_id } => {
                                    self._handle_activation(&database, &mut clients, &mut standby, &replay_in_progress, &value.did_hash, session_id, true).await;
                                },
                                StreamingUpdateState::Stop { session_id } => {
                                    self._handle_activation(&database, &mut clients, &mut standby, &replay_in_progress, &value.did_hash, session_id, false).await;
                                },
                                StreamingUpdateState::Deregister { session_id } => {
                                    // A standby entry leaving takes nothing live with it.
                                    if remove_standby(&mut standby, &value.did_hash, session_id) {
                                        debug!(did_hash = %value.did_hash, leaving_session = %session_id, "Deregistered a standby entry");
                                        continue;
                                    }
                                    // Only the session that currently owns the slot may
                                    // vacate it. One DID has one entry, so a socket that
                                    // was already replaced still runs its own teardown —
                                    // and an unconditional remove here would take the
                                    // *successor's* channel out with it. Dropping that
                                    // `tx` closes the live socket's command channel, so
                                    // its handler exits with "streaming task unavailable"
                                    // and the client sees the connection closed for no
                                    // reason it can act on. Common whenever one DID hands
                                    // off between transports (a DIDComm session closing
                                    // as a raw-TSP socket opens).
                                    match clients.get(value.did_hash.as_str()) {
                                        Some(entry) if entry.session_id != *session_id => {
                                            debug!(
                                                did_hash = %value.did_hash,
                                                leaving_session = %session_id,
                                                current_session = %entry.session_id,
                                                "Ignoring deregistration from a replaced session; the slot belongs to a newer connection",
                                            );
                                        }
                                        Some(_) => {
                                            clients.remove(value.did_hash.as_str());
                                            info!("Deregistered streaming for DID: ({}) registered_clients({})", value.did_hash, clients.len());
                                            if !self.promote_standby(&database, &mut clients, &mut standby, &replay_in_progress, &value.did_hash).await {
                                                self.release(&database, &value.did_hash).await;
                                            }
                                        }
                                        None => {
                                            debug!(
                                                did_hash = %value.did_hash,
                                                leaving_session = %session_id,
                                                "Deregistration for a DID with no registered client",
                                            );
                                        }
                                    }
                                }
                                StreamingUpdateState::RemoteTaken => {
                                    stand_by_taken(&mut clients, &mut standby, &value.did_hash);
                                }
                                StreamingUpdateState::RemoteReleased => {
                                    if !clients.contains_key(&value.did_hash)
                                        && self.promote_standby(&database, &mut clients, &mut standby, &replay_in_progress, &value.did_hash).await
                                    {
                                        debug!(did_hash = %value.did_hash, "the DID's owner elsewhere left; its mux entry here took it back");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Forward one streaming notification to the WebSocket sender for
    /// its target DID, dropping clients whose channels have closed.
    ///
    /// Never awaits a client's send queue: this runs in the single loop that
    /// serves every DID, so blocking on one slow socket would stall live
    /// delivery for all of them. A client that cannot keep up has its push
    /// dropped (see [`try_queue_message`]).
    async fn dispatch_payload(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
        payload: PubSubRecord,
    ) {
        let PubSubRecord {
            did_hash,
            message,
            force_delivery,
            verbatim,
            stored,
        } = payload;
        match clients.get(&did_hash) {
            Some(entry) => {
                if force_delivery || entry.active {
                    // A closed channel means the socket is gone and the entry is
                    // stale; a *full* one means a slow client, which is not a
                    // reason to tear the connection down. Distinguish them, or a
                    // brief burst would evict a perfectly healthy client.
                    if entry.tx.is_closed() {
                        warn!("Dead WebSocket channel for ({did_hash}), cleaning up");
                        clients.remove(&did_hash);
                        if self
                            .promote_standby(
                                database,
                                clients,
                                standby,
                                replay_in_progress,
                                &did_hash,
                            )
                            .await
                        {
                            return;
                        }
                        self.release(database, &did_hash).await;
                    } else {
                        // A stored message's delivery rides with the frame;
                        // the socket loop reports it once it is written
                        // (R1.1). Taken before the body is moved.
                        let report = stored.map(|stored| DeliveryReport {
                            msg_id: stored.msg_id,
                            from: stored.from_did_hash,
                            to: Some(did_hash.clone()),
                            size: message.len() as u64,
                            protocol: crate::monitor::Protocol::detect(&message),
                        });
                        // Moved, not cloned: the body already exists in the
                        // broadcast ring slot, and `payload` is owned here.
                        deliver_live(
                            entry,
                            &self.send_budget,
                            &did_hash,
                            message,
                            verbatim,
                            report,
                        );
                    }
                } else {
                    debug!("pub/sub msg received for did_hash({did_hash}) but it is not active");
                    let kind = entry.kind;
                    if let Err(err) = database
                        .streaming_claim(
                            &did_hash,
                            &self.uuid,
                            false,
                            kind.into(),
                            StreamingWrite::Update,
                        )
                        .await
                    {
                        error!("Error stopping streaming for client ({did_hash}): {err}");
                    }
                }
            }
            None => {
                warn!(
                    "pub/sub msg received for did_hash({did_hash}) but it doesn't exist in clients HashMap"
                );
            }
        }
    }

    /// Turn live delivery on or off for **the session that owns the DID's slot**.
    ///
    /// `clients` is keyed by DID hash, not by connection, so an update that
    /// doesn't name its session acts on whoever holds the slot now. That is a
    /// real hazard for a DID whose sessions overlap: a `live-delivery-change`
    /// from a connection that has since been replaced would otherwise flip
    /// delivery for its *successor* — and a stale `Stop` is the bad one,
    /// because it clears both `active` and the stored `Live` state, so the
    /// healthy socket stays connected and simply stops receiving pushes. That
    /// is the same silent stop-delivering failure as the `Deregister` bug, and
    /// just as hard to see from either end.
    ///
    /// An update whose session no longer owns the slot — or that arrives when
    /// there is no slot at all — is dropped. A slot-less `Start` is worth
    /// dropping in its own right: marking a DID `Live` with no channel to
    /// deliver on only produces "not in clients HashMap" warnings when messages
    /// arrive. Ordering makes this safe for legitimate traffic: `Register` and
    /// `Start` travel the same FIFO channel, so a live session's own `Start`
    /// always finds its entry.
    #[allow(clippy::too_many_arguments)]
    async fn _handle_activation(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
        did_hash: &str,
        session_id: &str,
        active: bool,
    ) {
        // The socket to flush to, captured while the entry is borrowed.
        let (client_tx, client_slots, client_resync, kind) = match clients.get_mut(did_hash) {
            Some(entry) if entry.session_id == session_id => {
                entry.active = active;
                (
                    entry.tx.clone(),
                    entry.slots.clone(),
                    entry.resync.clone(),
                    entry.kind,
                )
            }
            Some(entry) => {
                // A standby entry keeps its wish, so that it is honoured if
                // it is promoted; nothing is delivered to it meanwhile.
                if let Some(waiting) = standby
                    .get_mut(did_hash)
                    .and_then(|v| v.iter_mut().find(|e| e.session_id == session_id))
                {
                    waiting.active = active;
                    return;
                }
                debug!(
                    did_hash = %did_hash,
                    requesting_session = %session_id,
                    current_session = %entry.session_id,
                    active,
                    "Ignoring a live-delivery change from a session that no longer owns this DID's slot",
                );
                return;
            }
            None => {
                // A mux entry standing by while a direct socket on another
                // instance holds the DID keeps its wish too, for when the
                // DID is released to it.
                if let Some(waiting) = standby
                    .get_mut(did_hash)
                    .and_then(|v| v.iter_mut().find(|e| e.session_id == session_id))
                {
                    waiting.active = active;
                    return;
                }
                debug!(
                    did_hash = %did_hash,
                    requesting_session = %session_id,
                    active,
                    "Ignoring a live-delivery change for a DID with no registered client",
                );
                return;
            }
        };

        let verb = if active { "Starting" } else { "Stopping" };
        info!("{verb} streaming for DID: ({did_hash})");
        match database
            .streaming_claim(
                did_hash,
                &self.uuid,
                active,
                kind.into(),
                StreamingWrite::Update,
            )
            .await
        {
            Err(err) => {
                error!("Error changing streaming state for client ({did_hash}): {err}");
            }
            // Another instance took the DID between this entry's registration
            // and this change. A mux entry stands by, as it would have had
            // the store refused its registration; a direct socket keeps its
            // entry (the newest connection elsewhere has the DID's traffic).
            Ok(claim) if !claim.held_here => {
                if kind == EntryKind::Mux
                    && let Some(entry) = clients.remove(did_hash)
                {
                    let _ =
                        entry
                            .tx
                            .try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
                                MemberChange::Inactive {
                                    did_hash: did_hash.to_string(),
                                },
                            )));
                    standby.entry(did_hash.to_string()).or_default().push(entry);
                }
                return;
            }
            Ok(_) => {}
        }

        // Turning live delivery *on* must also deliver what is already queued.
        //
        // `_store_message` streams a message only if the recipient is live at
        // the instant it arrives, and always stores it. Nothing streams a
        // stored message afterwards — so every message that lands in the window
        // between a socket registering and that socket enabling live delivery
        // is queued and never pushed. The client sees silence; the mediator
        // reports `queued=1, live_delivery=true`; only an explicit
        // delivery-request retrieves it.
        //
        // That window is small and widens under load, which is exactly the
        // profile of the flake this fixes (VTI#918): a credential sat queued
        // for a full 60s while its recipient polled the live stream, and a
        // delivery request returned it immediately. Reproduced on demand only
        // once the test ran 6-way concurrent on a loaded runner.
        //
        // Reuses the redelivery already written for socket replacement
        // (issue #374): fetched `DoNotDelete`, at-least-once, idempotent by
        // message id, guarded by `replay_in_progress` so concurrent triggers
        // drain once. A client that already had a message simply sees it
        // again and deletes it as usual.
        if active {
            if replay_in_progress.insert(did_hash.to_string()) {
                spawn_inbox_redelivery(
                    Arc::clone(database),
                    client_tx,
                    client_slots,
                    client_resync,
                    self.send_budget.clone(),
                    did_hash.to_string(),
                    session_id.to_string(),
                    Arc::clone(replay_in_progress),
                    self.delivered_expiry_seconds,
                );
            } else {
                debug!(
                    did_hash = %did_hash,
                    "Inbox redelivery already in progress for DID; skipping the activation drain"
                );
            }
        }
    }

    /// Helper function to handle the registration of a new client.
    /// Handles if this is a duplicate channel for a DID
    async fn _handle_registration(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
        value: &StreamingUpdate,
    ) {
        let StreamingUpdateState::Register {
            channel: client_tx,
            session_id: new_session_id,
            did,
            resync: client_resync,
            kind,
            slots: client_slots,
        } = &value.state
        else {
            // Only `Register` updates reach this helper.
            return;
        };
        let new_session_id = new_session_id.as_str();
        let did = did.as_str();

        // Defensive guard: an empty `did` means the upstream session
        // arrived without an authenticated DID populated. Registering
        // it would index this client under
        // `did_hash = sha256("") = e3b0c44...` and silently misroute
        // every subsequent message. Refuse and log loudly so the
        // upstream auth bug surfaces immediately.
        if did.is_empty() || value.did_hash.is_empty() {
            error!(
                session = new_session_id,
                did_hash = %value.did_hash,
                "Refusing to register streaming client with empty DID — \
                 the upstream session is missing its authenticated DID. \
                 Closing the channel."
            );
            let _ = client_tx
                .send(QueuedCommand::control(WebSocketCommands::Close(
                    CloseReason::Unauthenticated,
                )))
                .await;
            return;
        }

        let new_entry = |churn_streak| ClientEntry {
            tx: client_tx.clone(),
            session_id: new_session_id.to_string(),
            active: false,
            registered_at: Instant::now(),
            resync: client_resync.clone(),
            churn_streak,
            kind: *kind,
            slots: client_slots.clone(),
        };

        // Mux precedence (design §7.2). A direct socket outranks a mux member,
        // and among mux connections the newest carries the DID. A displaced
        // or outranked mux entry is never *closed*: its connection carries
        // other DIDs too. It waits on standby instead, and is told so.
        if let Some(old) = clients.get(&value.did_hash) {
            match (old.kind, *kind) {
                (EntryKind::Direct, EntryKind::Mux) => {
                    let _ = client_tx.try_send(QueuedCommand::control(
                        WebSocketCommands::MemberChange(MemberChange::Inactive {
                            did_hash: value.did_hash.clone(),
                        }),
                    ));
                    standby
                        .entry(value.did_hash.clone())
                        .or_default()
                        .push(new_entry(0));
                    debug!(
                        did = did,
                        session = new_session_id,
                        "Mux member registered behind a direct socket; standing by"
                    );
                    return;
                }
                (EntryKind::Mux, _) => {
                    // The live mux entry yields: to a direct socket always, and
                    // to a newer mux connection by newest-wins.
                    let old = clients.remove(&value.did_hash).expect("present above");
                    let _ =
                        old.tx
                            .try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
                                MemberChange::Superseded {
                                    did_hash: value.did_hash.clone(),
                                },
                            )));
                    standby.entry(value.did_hash.clone()).or_default().push(old);
                    self.install(
                        database,
                        clients,
                        standby,
                        replay_in_progress,
                        &value.did_hash,
                        new_entry(0),
                        true,
                    )
                    .await;
                    return;
                }
                (EntryKind::Direct, EntryKind::Direct) => {}
            }
        }

        // Is this replacing an existing session for the same DID?
        let mut churn_streak = 0;
        let replacing = if let Some(old) = clients.get_mut(&value.did_hash) {
            let since_last = old.registered_at.elapsed();
            let churn = since_last < CHURN_WINDOW;
            let since_last_ms = since_last.as_millis() as u64;
            churn_streak = if churn { old.churn_streak + 1 } else { 0 };

            // Duel damper. Newest-wins is the right rule for an isolated
            // duplicate — a client that reconnected after a half-open socket
            // must be able to take its slot back. It is the wrong rule for a
            // *sustained* duel: with two or more live sessions for one DID,
            // every takeover evicts a peer that immediately reconnects and
            // takes the slot straight back, and the pair (or the pack) saturate
            // the server with connect/close churn indefinitely.
            //
            // Past a short streak, hold the slot for the incumbent instead —
            // but only while the incumbent's channel is demonstrably alive, so
            // a stale entry can never lock a DID out. This is self-limiting:
            // refusals don't touch the incumbent's `registered_at`, so once it
            // ages past `CHURN_WINDOW` the next contender is accepted normally.
            // Worst case is one takeover per window rather than one per
            // round-trip.
            if churn && churn_streak >= CHURN_REFUSE_STREAK && !old.tx.is_closed() {
                old.churn_streak = churn_streak;
                metrics::counter!(WEBSOCKET_CHURN_REFUSED_TOTAL).increment(1);
                // Warn once as the duel starts, then stay quiet — the refusal
                // path is hot by definition and the metric is the live signal.
                if churn_streak == CHURN_REFUSE_STREAK {
                    warn!(
                        did = did,
                        incumbent_session = old.session_id,
                        refused_session = new_session_id,
                        since_last_ms,
                        churn_streak,
                        "Sustained duplicate-WebSocket duel for this DID: holding the \
                         incumbent session and refusing new connections for up to {}s. \
                         Something is running more than one live session for this DID.",
                        CHURN_WINDOW.as_secs(),
                    );
                } else {
                    debug!(
                        did = did,
                        incumbent_session = old.session_id,
                        refused_session = new_session_id,
                        churn_streak,
                        "Refusing duplicate WebSocket registration (duel damper)",
                    );
                }
                let _ = client_tx
                    .send(QueuedCommand::control(WebSocketCommands::Close(
                        CloseReason::Refused,
                    )))
                    .await;
                return;
            }

            let msg = "Duplicate WebSocket connection: closing old session in favour of new one";
            // A churning DID replaces its own socket every few seconds
            // (e.g. two client sessions for the same DID dueling over the
            // one-socket-per-DID slot). Logging every flip at WARN buries
            // the log — a two-hour duel emits thousands of identical lines.
            // Emit churn at DEBUG and let the dedicated
            // `WEBSOCKET_DUPLICATE_CHURN_TOTAL` counter be the operator
            // signal (rate-alert on it). A genuine, spaced-out duplicate
            // (non-churn) is still noteworthy, so keep it at WARN.
            if churn {
                debug!(
                    did = did,
                    old_session = old.session_id,
                    new_session = new_session_id,
                    since_last_ms,
                    churn,
                    "{msg}",
                );
            } else {
                warn!(
                    did = did,
                    old_session = old.session_id,
                    new_session = new_session_id,
                    since_last_ms,
                    churn,
                    "{msg}",
                );
            }
            metrics::counter!(WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL).increment(1);
            if churn {
                // Rapid replacement for the same DID — surface the flip-flop
                // via a metric. The newest socket still wins (the one-socket
                // invariant is unchanged); only the redelivery is damped below.
                metrics::counter!(WEBSOCKET_DUPLICATE_CHURN_TOTAL).increment(1);
            }
            // Channel already exists, close the old one.
            let _ = old
                .tx
                .send(QueuedCommand::control(WebSocketCommands::Close(
                    CloseReason::Replaced,
                )))
                .await;
            true
        } else {
            false
        };

        self.install(
            database,
            clients,
            standby,
            replay_in_progress,
            &value.did_hash,
            new_entry(churn_streak),
            replacing,
        )
        .await;
    }

    /// Make `entry` the DID's live entry, record it, and — when it took the
    /// slot from another socket — redeliver the inbox to it, since a message in
    /// flight to the displaced socket would otherwise be stranded (#374).
    #[allow(clippy::too_many_arguments)]
    async fn install(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
        did_hash: &str,
        entry: ClientEntry,
        replacing: bool,
    ) -> bool {
        // Across instances the store orders the DID's owners as this task
        // orders its own entries: a mux entry never takes the DID from a
        // direct socket on another instance. Refused, it stands by, and its
        // connection is told the member is inactive; the direct socket
        // leaving tells this instance to take it back (`RemoteReleased`).
        let claim = match database
            .streaming_claim(
                did_hash,
                &self.uuid,
                entry.active,
                entry.kind.into(),
                StreamingWrite::Claim,
            )
            .await
        {
            Ok(claim) => claim,
            Err(err) => {
                // As before this check existed: the entry is installed, and
                // the store will catch up on its next state change.
                error!("Error starting streaming to client ({did_hash}) streaming: {err}");
                StreamingClaim {
                    held_here: true,
                    displaced_mux: None,
                }
            }
        };
        if !claim.held_here {
            let _ = entry
                .tx
                .try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
                    MemberChange::Inactive {
                        did_hash: did_hash.to_string(),
                    },
                )));
            debug!(
                did_hash = %did_hash,
                session = %entry.session_id,
                "a direct socket on another instance holds this DID; the mux entry stands by"
            );
            standby.entry(did_hash.to_string()).or_default().push(entry);
            return false;
        }
        if let Some(instance) = claim.displaced_mux {
            self.handoff(
                database,
                StreamingHandoff::Taken {
                    did_hash: did_hash.to_string(),
                    instance,
                },
            )
            .await;
        }

        // Count after this registration lands. A replacement swaps a map entry
        // rather than adding one, so `len() + 1` would over-report. `clients`
        // is keyed by DID hash, so this is the number of DIDs with a live
        // socket, not the number of sockets.
        let registered_clients = if clients.contains_key(did_hash) {
            clients.len()
        } else {
            clients.len() + 1
        };
        info!(
            session = %entry.session_id,
            kind = ?entry.kind,
            "Registered streaming for DID: ({did_hash}) registered_clients({registered_clients})",
        );
        let client_tx = entry.tx.clone();
        let client_slots = entry.slots.clone();
        let client_resync = entry.resync.clone();
        let session_id = entry.session_id.clone();
        clients.insert(did_hash.to_string(), entry);

        // Skip if a redelivery for this DID is already running, so a
        // flip-flop duel can't amplify into a repeated whole-inbox dump.
        if replacing {
            if replay_in_progress.insert(did_hash.to_string()) {
                spawn_inbox_redelivery(
                    Arc::clone(database),
                    client_tx,
                    client_slots,
                    client_resync,
                    self.send_budget.clone(),
                    did_hash.to_string(),
                    session_id,
                    Arc::clone(replay_in_progress),
                    self.delivered_expiry_seconds,
                );
            } else {
                debug!(
                    did_hash = %did_hash,
                    "Inbox redelivery already in progress for DID; skipping duplicate drain"
                );
            }
        }
        true
    }

    /// Bring this instance's mux entries in step with the store's owners,
    /// for a handoff that never arrived ([`OWNERSHIP_RECHECK`]):
    ///
    /// - a live mux entry whose DID another instance now streams stands by
    ///   (`superseded`), as on `RemoteTaken`;
    /// - a mux entry standing by for a DID nobody streams any more takes it
    ///   (`reactivated`), as on `RemoteReleased`.
    ///
    /// Direct sockets are left alone: they take their DID on registration,
    /// and a newer one elsewhere replaces them by the newest-wins rule.
    async fn recheck_ownership(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
    ) {
        let live: Vec<String> = clients
            .iter()
            .filter(|(_, e)| e.kind == EntryKind::Mux)
            .map(|(d, _)| d.clone())
            .collect();
        for did_hash in live {
            if let Some(owner) = database.streaming_is_client_live(&did_hash, true).await
                && owner != self.uuid
                && stand_by_taken(clients, standby, &did_hash)
            {
                info!(did_hash = %did_hash, "a lost handoff: another instance streams this DID; mux entry stood by");
            }
        }
        let waiting: Vec<String> = standby
            .keys()
            .filter(|d| !clients.contains_key(*d))
            .cloned()
            .collect();
        for did_hash in waiting {
            if database
                .streaming_is_client_live(&did_hash, true)
                .await
                .is_none()
                && self
                    .promote_standby(database, clients, standby, replay_in_progress, &did_hash)
                    .await
            {
                info!(did_hash = %did_hash, "a lost handoff: nobody streams this DID; mux entry took it back");
            }
        }
    }

    /// Deregister `did_hash` from this instance's store entry, and when a mux
    /// entry elsewhere waits for the DID, tell it to take the DID back.
    async fn release(&self, database: &Arc<dyn MediatorStore>, did_hash: &str) {
        match database.streaming_release(did_hash, &self.uuid).await {
            Ok(true) => {
                self.handoff(
                    database,
                    StreamingHandoff::Released {
                        did_hash: did_hash.to_string(),
                    },
                )
                .await;
            }
            Ok(false) => {}
            Err(err) => error!("Error stopping streaming for client ({did_hash}): {err}"),
        }
    }

    /// Tell the other instances sharing the store of a change in which of
    /// them streams a DID. Lost on a store without cross-instance pub/sub,
    /// which has no other instance to tell.
    async fn handoff(&self, database: &Arc<dyn MediatorStore>, handoff: StreamingHandoff) {
        let record = MuxChangeRecord {
            origin: self.uuid.clone(),
            changes: Vec::new(),
            streaming: vec![handoff],
        };
        if let Err(err) = database.mux_changes_publish(&record).await {
            warn!("couldn't tell the other instances of a streaming handoff: {err}");
        }
    }

    /// After the live entry for `did_hash` went away, promote the newest
    /// standby entry whose socket is still open, tell it, and redeliver.
    /// Returns whether one was promoted.
    async fn promote_standby(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<DashSet<String>>,
        did_hash: &str,
    ) -> bool {
        let Some(waiting) = standby.get_mut(did_hash) else {
            return false;
        };
        let mut promoted = None;
        while let Some(candidate) = waiting.pop() {
            if !candidate.tx.is_closed() {
                promoted = Some(candidate);
                break;
            }
        }
        if waiting.is_empty() {
            standby.remove(did_hash);
        }
        let Some(mut entry) = promoted else {
            return false;
        };
        entry.registered_at = Instant::now();
        // Redeliver only to an entry that wants live delivery; an inactive
        // one collects by pickup, as it would have on its own.
        let replay = entry.active;
        let tx = entry.tx.clone();
        // A direct socket on another instance may hold the DID: then the
        // entry goes back on standby, still inactive.
        if !self
            .install(
                database,
                clients,
                standby,
                replay_in_progress,
                did_hash,
                entry,
                replay,
            )
            .await
        {
            return false;
        }
        let _ = tx.try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
            MemberChange::Reactivated {
                did_hash: did_hash.to_string(),
            },
        )));
        true
    }
}

/// Another instance took `did_hash` from this instance's live mux entry: the
/// entry stands by, and its connection is told the member is inactive. Only
/// a mux entry yields to another instance; the store never displaces a
/// direct socket on a mux registration's behalf. Returns whether one did.
fn stand_by_taken(
    clients: &mut HashMap<String, ClientEntry>,
    standby: &mut HashMap<String, Vec<ClientEntry>>,
    did_hash: &str,
) -> bool {
    if !clients
        .get(did_hash)
        .is_some_and(|e| e.kind == EntryKind::Mux)
    {
        return false;
    }
    let entry = clients.remove(did_hash).expect("present above");
    let _ = entry
        .tx
        .try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
            MemberChange::Superseded {
                did_hash: did_hash.to_string(),
            },
        )));
    standby.entry(did_hash.to_string()).or_default().push(entry);
    debug!(did_hash = %did_hash, "another instance took this DID; its mux entry stands by");
    true
}

/// Remove `session_id`'s standby entry for `did_hash`, if it has one.
fn remove_standby(
    standby: &mut HashMap<String, Vec<ClientEntry>>,
    did_hash: &str,
    session_id: &str,
) -> bool {
    let Some(waiting) = standby.get_mut(did_hash) else {
        return false;
    };
    let before = waiting.len();
    waiting.retain(|e| e.session_id != session_id);
    let removed = waiting.len() != before;
    if waiting.is_empty() {
        standby.remove(did_hash);
    }
    removed
}

/// Drain the recipient's undelivered inbox to a freshly-registered socket
/// after it displaced a duplicate, re-pushing each stored (but not yet
/// deleted) message as a live-stream frame. Runs as a detached task so the
/// streaming `select!` loop — which services every DID — never blocks on a
/// multi-page database drain.
///
/// Messages are fetched with `DoNotDelete`: redelivery is a notification
/// re-cover, not an ack. The client deletes what it has processed via the
/// normal message-pickup path, so this is at-least-once and idempotent by
/// message id.
///
/// A drain that stops before the end of the inbox (the socket's queue or the
/// byte budget is full, the safety cap is reached, or a fetch fails) raises
/// the client's resync, as a dropped live push does: what is left is still
/// stored, and a client that only listens would otherwise never learn of it.
#[allow(clippy::too_many_arguments)]
fn spawn_inbox_redelivery(
    database: Arc<dyn MediatorStore>,
    client_tx: mpsc::Sender<QueuedCommand>,
    client_slots: Option<Arc<MuxSlots>>,
    client_resync: Arc<AtomicBool>,
    budget: WsSendBudget,
    did_hash: String,
    session_id: String,
    replay_in_progress: Arc<DashSet<String>>,
    delivered_expiry_seconds: u64,
) {
    tokio::spawn(async move {
        let mut start_id: Option<String> = None;
        let mut total: usize = 0;
        // Set when the drain stops with messages possibly left behind.
        let mut cut_short = false;

        'drain: loop {
            let options = FetchOptions {
                limit: REDELIVERY_PAGE,
                start_id: start_id.clone(),
                ..Default::default() // delete_policy defaults to DoNotDelete
            };
            let page = match database
                .fetch_messages_delivering(
                    &session_id,
                    &did_hash,
                    &options,
                    affinidi_messaging_mediator_common::time::unix_timestamp_millis() as u64,
                    delivered_expiry_seconds,
                    // This drain pages with `start_id` and wants stream order:
                    // it is re-covering a socket's whole inbox, not choosing
                    // between competing senders.
                    false,
                )
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    warn!(
                        did_hash = %did_hash,
                        "Inbox redelivery fetch failed, aborting drain: {err}"
                    );
                    cut_short = true;
                    break 'drain;
                }
            };
            if page.success.is_empty() {
                break 'drain;
            }
            let page_len = page.success.len();

            for element in page.success {
                // Advance the cursor regardless of body presence so a missing
                // body can't pin the drain on the same page forever.
                if let Some(receive_id) = &element.receive_id {
                    start_id = Some(receive_id.clone());
                }
                let Some(msg) = element.msg else { continue };
                let report = DeliveryReport {
                    msg_id: element.msg_id,
                    from: element.from_address,
                    to: element.to_address,
                    size: element.size,
                    protocol: crate::monitor::Protocol::detect(&msg),
                };

                // Fetched with `DoNotDelete`, so anything not queued here stays
                // in the inbox. Stopping the drain early is therefore lossless,
                // and the resync raised below tells the client to collect the
                // remainder through message-pickup.
                if !try_queue_message(
                    &client_tx,
                    client_slots.as_ref(),
                    &budget,
                    &did_hash,
                    msg,
                    Some(report),
                ) {
                    debug!(
                        did_hash = %did_hash,
                        "Send queue or byte budget unavailable mid-redelivery; \
                         stopping drain, remainder left for message-pickup"
                    );
                    cut_short = true;
                    break 'drain;
                }
                metrics::counter!(WEBSOCKET_REDELIVERED_MESSAGES_TOTAL).increment(1);
                total += 1;

                if total >= REDELIVERY_MAX {
                    warn!(
                        did_hash = %did_hash,
                        max = REDELIVERY_MAX,
                        "Inbox redelivery hit its safety cap; remaining messages \
                         left for normal message-pickup"
                    );
                    cut_short = true;
                    break 'drain;
                }
            }

            // A short page means the stream is exhausted.
            if page_len < REDELIVERY_PAGE {
                break 'drain;
            }
        }

        if cut_short {
            raise_resync(client_slots.as_ref(), &client_resync, &did_hash);
            debug!(did_hash = %did_hash, total, "Inbox redelivery stopped early; resync raised");
        } else if total > 0 {
            debug!(did_hash = %did_hash, total, "Inbox redelivery complete");
        }
        replay_in_progress.remove(&did_hash);
    });
}

// MemoryStore (the in-process backend used here) is only compiled under the
// `memory-backend` feature, so gate these tests on it.
#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::store::memory_store::MemoryStore;
    use sha256::digest;
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;

    fn streaming_task() -> StreamingTask {
        // The command channel is unused by `_handle_registration` directly; a
        // throwaway sender keeps the struct well-formed.
        let (tx, _rx) = mpsc::channel(1);
        StreamingTask {
            uuid: "test-mediator".to_string(),
            channel: tx,
            // Generous budget: these tests exercise registration/redelivery, not
            // buffer exhaustion (which `ws_budget` covers directly).
            send_budget: WsSendBudget::new(16 * 1024 * 1024),
            delivered_expiry_seconds: 0,
        }
    }

    /// Build a client map holding one entry, owned by `session_id`.
    fn clients_with(
        did_hash: &str,
        session_id: &str,
        active: bool,
    ) -> HashMap<String, ClientEntry> {
        let (tx, _rx) = mpsc::channel(5);
        let mut clients = HashMap::new();
        clients.insert(
            did_hash.to_string(),
            ClientEntry {
                tx,
                session_id: session_id.to_string(),
                active,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
            },
        );
        clients
    }

    /// A `Stop` from a session that has already been replaced must not switch
    /// live delivery off for the connection that replaced it.
    ///
    /// This is the bad direction of the bug: `clients` is keyed by DID hash, so
    /// an unscoped `Stop` clears both `active` and the stored `Live` state for
    /// whoever holds the slot. The healthy socket stays connected and simply
    /// stops receiving pushes — the same silent stop-delivering failure as the
    /// `Deregister` bug, invisible from both ends.
    /// A live notification that cannot be queued raises the client's resync
    /// flag — the KR-30 / VTI-30 regression.
    ///
    /// The drop itself was never the bug: the message stays in the recipient's
    /// inbox and the counter for it already existed. The bug was that a client
    /// which only listens is told nothing, so it never collects what it was
    /// never informed about. This asserts the telling.
    #[tokio::test]
    async fn a_dropped_live_notification_raises_resync() {
        let (tx, _rx) = mpsc::channel::<QueuedCommand>(1);
        let resync = Arc::new(AtomicBool::new(false));
        let entry = ClientEntry {
            tx: tx.clone(),
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
        };
        let budget = WsSendBudget::new(1_000_000);

        // First push fits the single slot.
        assert!(deliver_live(
            &entry,
            &budget,
            "did-hash",
            "one".to_string(),
            false,
            None,
        ));
        assert!(
            !resync.load(Ordering::Relaxed),
            "a delivered notification must not ask the client to resync"
        );

        // Nothing is reading `_rx`, so the slot stays taken and the next push
        // is dropped — the slow-consumer case.
        assert!(!deliver_live(
            &entry,
            &budget,
            "did-hash",
            "two".to_string(),
            false,
            None,
        ));
        assert!(
            resync.load(Ordering::Relaxed),
            "a dropped notification must raise resync, or the client never learns"
        );
    }

    /// On a mux connection a busy member fills only its own share of the
    /// queue: its next push is dropped and *it* is owed the resync, while
    /// another member on the same socket still queues (design §7.2).
    #[tokio::test]
    async fn a_busy_mux_member_drops_only_its_own_pushes() {
        use crate::mux::fair_queue::{MEMBER_SLOTS, MuxSlots};
        let slots = MuxSlots::new(512);
        let (tx, mut rx) = mpsc::channel::<QueuedCommand>(slots.channel_capacity());
        let resync = Arc::new(AtomicBool::new(false));
        let entry = || ClientEntry {
            tx: tx.clone(),
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Mux,
            slots: Some(slots.clone()),
        };
        let (busy, quiet) = (entry(), entry());
        let budget = WsSendBudget::new(1_000_000);

        for i in 0..MEMBER_SLOTS {
            assert!(deliver_live(
                &busy,
                &budget,
                "busy",
                format!("b{i}"),
                false,
                None
            ));
        }
        assert!(
            !deliver_live(&busy, &budget, "busy", "over".into(), false, None),
            "the busy member is refused past its share"
        );
        assert!(resync.load(Ordering::Relaxed), "the socket is woken");
        assert_eq!(slots.take_resync(), vec!["busy".to_string()]);

        assert!(
            deliver_live(&quiet, &budget, "quiet", "q".into(), false, None),
            "another member still has room on the same socket"
        );
        assert!(slots.take_resync().is_empty(), "and owes no resync");

        // Taking a frame off the queue returns the busy member's slot.
        let taken = rx.recv().await.unwrap();
        assert_eq!(taken.did_hash.as_deref(), Some("busy"));
        drop(taken);
        assert!(deliver_live(
            &busy,
            &budget,
            "busy",
            "again".into(),
            false,
            None
        ));
    }

    /// A stored message's push carries its delivery report to the socket,
    /// which reports it only once the frame is written (R1.1): nothing is
    /// reported when the push is queued, a dropped push carries nothing, and
    /// an untagged push (a monitor batch, an ephemeral message) has no report,
    /// or the monitor would report its own batches.
    #[tokio::test]
    async fn a_stored_push_carries_its_delivery_report_to_the_socket() {
        use affinidi_messaging_mediator_common::store::StoredMessageRef;

        let task = streaming_task();
        let monitor = crate::monitor::TrafficMonitor::new();
        let mut events = monitor.tap();
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        // One slot: the first push is queued, the next is dropped.
        let (tx, mut rx) = mpsc::channel::<QueuedCommand>(1);
        let mut clients = HashMap::from([(
            "bob".to_string(),
            ClientEntry {
                tx,
                session_id: "S".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
            },
        )]);
        let record = |msg_id: Option<&str>| PubSubRecord {
            did_hash: "bob".to_string(),
            message: "body".to_string(),
            force_delivery: false,
            verbatim: false,
            stored: msg_id.map(|msg_id| StoredMessageRef {
                msg_id: msg_id.to_string(),
                from_did_hash: Some("alice".to_string()),
            }),
        };
        macro_rules! dispatch {
            ($r:expr) => {
                task.dispatch_payload(
                    &database,
                    &mut clients,
                    &mut HashMap::new(),
                    &Arc::new(DashSet::new()),
                    $r,
                )
                .await
            };
        }

        dispatch!(record(Some("m1")));
        dispatch!(record(Some("m2")));
        assert!(
            events.try_recv().is_err(),
            "queueing a push is not a delivery"
        );
        let queued = rx.try_recv().expect("the first push is queued");
        let report = queued.report.expect("a stored push carries its report");
        assert_eq!(report.msg_id, "m1");
        assert_eq!(report.from.as_deref(), Some("alice"));
        assert_eq!(report.to.as_deref(), Some("bob"));
        // The report keeps the frame's protocol, never a copy of its body.
        assert_eq!(report.protocol, crate::monitor::Protocol::Other);
        assert!(rx.try_recv().is_err(), "the second push was dropped");

        // The socket loop emits it once the frame is written.
        report.emit(&monitor);
        let event = events.try_recv().expect("reported after the write");
        assert_eq!(event.stage, crate::monitor::Stage::Delivered);
        assert_eq!(event.msg_id.as_deref(), Some("m1"));
        assert_eq!(event.to.as_deref(), Some("bob"));

        dispatch!(record(None));
        let queued = rx.try_recv().expect("the untagged push is queued");
        assert!(
            queued.report.is_none(),
            "an untagged push is not a stored message's delivery"
        );
    }

    /// Repeated drops collapse into one signal rather than queueing one signal
    /// per drop. The client's response to any number of them is the same single
    /// drain, and a congested socket is the worst place to add traffic.
    #[tokio::test]
    async fn repeated_drops_collapse_into_one_signal() {
        let (tx, _rx) = mpsc::channel::<QueuedCommand>(1);
        let resync = Arc::new(AtomicBool::new(false));
        let entry = ClientEntry {
            tx,
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
        };
        let budget = WsSendBudget::new(1_000_000);

        assert!(deliver_live(
            &entry,
            &budget,
            "did-hash",
            "fills".to_string(),
            false,
            None,
        ));
        for i in 0..5 {
            assert!(!deliver_live(
                &entry,
                &budget,
                "did-hash",
                format!("drop-{i}"),
                false,
                None,
            ));
        }

        // The handler takes the signal exactly once; it does not find five.
        assert!(resync.swap(false, Ordering::Relaxed), "signal is pending");
        assert!(
            !resync.swap(false, Ordering::Relaxed),
            "five drops leave one signal, not five"
        );
    }

    #[tokio::test]
    async fn a_stale_sessions_stop_does_not_deactivate_the_current_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:alice");
        let task = streaming_task();

        // Session B currently owns the slot and is live.
        let mut clients = clients_with(&did_hash, "B", true);
        database
            .streaming_set_state(
                &did_hash,
                &task.uuid,
                affinidi_messaging_mediator_common::store::StreamingClientState::Live,
            )
            .await
            .expect("mark live");

        // Session A — long since replaced — disables live delivery on its way out.
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "A",
            false,
        )
        .await;

        assert!(
            clients.get(&did_hash).expect("entry still present").active,
            "a replaced session must not deactivate its successor"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_some(),
            "the stored Live state belongs to the owning session and must survive"
        );
    }

    /// The mirror: a stale `Start` must not switch delivery on for a socket
    /// that deliberately turned it off.
    #[tokio::test]
    async fn a_stale_sessions_start_does_not_activate_the_current_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:bob");
        let task = streaming_task();

        let mut clients = clients_with(&did_hash, "B", false);

        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "A",
            true,
        )
        .await;

        assert!(
            !clients.get(&did_hash).expect("entry still present").active,
            "a replaced session must not activate its successor"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "no Live state may be written on behalf of a session that does not own the slot"
        );
    }

    /// The owning session still works — without this, "ignore everything" would
    /// satisfy the two tests above.
    #[tokio::test]
    async fn the_owning_sessions_activation_is_applied() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:carol");
        let task = streaming_task();

        let mut clients = clients_with(&did_hash, "B", false);

        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "B",
            true,
        )
        .await;
        assert!(
            clients.get(&did_hash).expect("entry").active,
            "the owning session's start must apply"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_some(),
            "and must be reflected in the stored streaming state"
        );

        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "B",
            false,
        )
        .await;
        assert!(
            !clients.get(&did_hash).expect("entry").active,
            "and its stop must apply too"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "stopping must clear the stored Live state"
        );
    }

    /// An activation for a DID with no registered client is dropped. Marking a
    /// DID `Live` with no channel to deliver on only produces "not in clients
    /// HashMap" warnings when messages arrive for it.
    #[tokio::test]
    async fn an_activation_without_a_registered_client_is_ignored() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:dave");
        let task = streaming_task();

        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "A",
            true,
        )
        .await;

        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "a DID with no socket must not be marked live"
        );
    }

    /// Issue #374: a duplicate connect for a DID with an in-flight (stored but
    /// not yet delivered) message must close the old socket *and* redeliver the
    /// stored message to the surviving socket.
    #[tokio::test]
    async fn duplicate_replacement_redelivers_inbox_to_new_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:alice";
        let did_hash = digest(did);
        let stored = "packed-in-flight-message";

        // A message is sitting in the inbox (the store persists every
        // non-ephemeral message, even when live-streamed).
        database
            .store_message("sess-store", stored, &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Client A is the existing live session.
        let (a_tx, mut a_rx) = mpsc::channel(5);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx: a_tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
            },
        );

        // Client B connects for the same DID (the duplicate).
        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
            },
        };

        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &update,
        )
        .await;

        // The old socket is told to close, and told that it was *replaced* —
        // the one situation where that wording is true.
        match timeout(StdDuration::from_secs(1), a_rx.recv())
            .await
            .expect("A receives a command")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Close(CloseReason::Replaced),
                ..
            }) => {}
            other => panic!(
                "expected Close(Replaced) on the displaced socket, got {:?}",
                other.is_some()
            ),
        }

        // The surviving socket receives the stranded message via redelivery.
        match timeout(StdDuration::from_secs(2), b_rx.recv())
            .await
            .expect("B receives the redelivered message")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Message(msg),
                ..
            }) => assert_eq!(msg, stored),
            _ => panic!("expected redelivered Message on the surviving socket"),
        }

        // And the new client is now the registered entry.
        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some("B")
        );
    }

    /// Enabling live delivery must deliver what is **already queued**.
    ///
    /// The gap this closes: `_store_message` streams a message only if the
    /// recipient is live at the instant it arrives, and always stores it.
    /// Nothing streams a stored message afterwards. So a message that lands
    /// between a socket registering and that socket turning live delivery on
    /// is queued and never pushed — the client waits on a live stream that
    /// will never carry it, while the mediator reports `queued=1,
    /// live_delivery=true` and hands it over instantly to a delivery request.
    ///
    /// That window is small, and widens under load: VTI#918 took six-way
    /// concurrent test streams on a loaded runner to reproduce, where a
    /// credential sat queued for a full 60s.
    #[tokio::test]
    async fn activation_redelivers_messages_queued_before_it() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:carol";
        let did_hash = digest(did);
        let stored = "queued-before-live-delivery";

        // Arrived while the socket was registered but not yet live: stored,
        // never streamed.
        database
            .store_message("sess-store", stored, &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let (tx, mut rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx,
                session_id: "A".to_string(),
                active: false,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
            },
        );

        // The client now enables live delivery.
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "A",
            true,
        )
        .await;

        match timeout(StdDuration::from_secs(2), rx.recv())
            .await
            .expect("the queued message is pushed on activation")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Message(msg),
                ..
            }) => assert_eq!(msg, stored),
            _ => panic!("expected the queued message to be redelivered on activation"),
        }
    }

    /// A handoff that never arrives is caught by the periodic recheck: a mux
    /// entry whose DID the store now gives to another instance stands by
    /// (`superseded`), and one standing by for a DID nobody holds takes it
    /// back (`reactivated`).
    #[tokio::test]
    async fn the_ownership_recheck_catches_a_lost_handoff() {
        use affinidi_messaging_mediator_common::store::StreamingClientState;
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let task = streaming_task();
        let replay: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let did = "did_hash_member";
        let (tx, mut rx) = mpsc::channel(8);
        let mut clients = HashMap::from([(
            did.to_string(),
            ClientEntry {
                tx,
                session_id: "M".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Mux,
                slots: None,
            },
        )]);
        let mut standby = HashMap::new();
        let change = |rx: &mut mpsc::Receiver<QueuedCommand>| match rx.try_recv() {
            Ok(QueuedCommand {
                cmd: WebSocketCommands::MemberChange(c),
                ..
            }) => Some(c),
            _ => None,
        };

        // Ours in the store: nothing changes.
        database
            .streaming_set_state(did, &task.uuid, StreamingClientState::Live)
            .await
            .unwrap();
        task.recheck_ownership(&database, &mut clients, &mut standby, &replay)
            .await;
        assert!(clients.contains_key(did));
        assert!(change(&mut rx).is_none());

        // Another instance took it, and its `Taken` was lost.
        database
            .streaming_set_state(did, "another-instance", StreamingClientState::Live)
            .await
            .unwrap();
        task.recheck_ownership(&database, &mut clients, &mut standby, &replay)
            .await;
        assert!(!clients.contains_key(did), "the mux entry stood by");
        assert_eq!(standby.get(did).map(Vec::len), Some(1));
        assert!(matches!(
            change(&mut rx),
            Some(MemberChange::Superseded { .. })
        ));

        // That instance left, and its `Released` was lost.
        database
            .streaming_set_state(did, "another-instance", StreamingClientState::Deregistered)
            .await
            .unwrap();
        task.recheck_ownership(&database, &mut clients, &mut standby, &replay)
            .await;
        assert!(clients.contains_key(did), "the mux entry took the DID back");
        assert!(standby.get(did).is_none());
        assert!(matches!(
            change(&mut rx),
            Some(MemberChange::Reactivated { .. })
        ));
        assert_eq!(
            database
                .streaming_is_client_live(did, false)
                .await
                .as_deref(),
            Some(task.uuid.as_str())
        );
    }

    /// A redelivery that cannot queue everything (here a send queue with room
    /// for one) stops, and raises the client's resync so the rest is
    /// collected through message-pickup. Before, it stopped silently, and a
    /// client that only listens never learned the rest was there. A drain
    /// that reaches the end raises nothing.
    #[tokio::test]
    async fn a_redelivery_cut_short_raises_the_resync() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:dave");
        for i in 0..3 {
            database
                .store_message("sess-store", &format!("m{i}"), &did_hash, None, 0, 1000)
                .await
                .expect("store message");
        }
        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());

        for (room, cut_short) in [(1, true), (5, false)] {
            let (tx, mut rx) = mpsc::channel(room);
            let resync = Arc::new(AtomicBool::new(false));
            let mut clients = HashMap::from([(
                did_hash.clone(),
                ClientEntry {
                    tx,
                    session_id: "A".to_string(),
                    active: false,
                    registered_at: Instant::now(),
                    resync: resync.clone(),
                    churn_streak: 0,
                    kind: EntryKind::Direct,
                    slots: None,
                },
            )]);
            task._handle_activation(
                &database,
                &mut clients,
                &mut HashMap::new(),
                &replay_in_progress,
                &did_hash,
                "A",
                true,
            )
            .await;
            // The drain runs detached; it is done once its guard is released.
            timeout(StdDuration::from_secs(2), async {
                while replay_in_progress.contains(&did_hash) {
                    tokio::time::sleep(StdDuration::from_millis(10)).await;
                }
            })
            .await
            .expect("the redelivery finishes");
            let mut queued = 0;
            while rx.try_recv().is_ok() {
                queued += 1;
            }
            assert_eq!(queued, room.min(3), "room for {room}");
            assert_eq!(
                resync.load(Ordering::Relaxed),
                cut_short,
                "room for {room}: resync raised only when messages were left behind"
            );
        }
    }

    /// Turning live delivery *off* must not drain the inbox: the client has
    /// just said it does not want pushes, and a redelivery would both defeat
    /// that and race the socket it is about to stop using.
    #[tokio::test]
    async fn deactivation_does_not_redeliver() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:dave";
        let did_hash = digest(did);

        database
            .store_message("sess-store", "queued", &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let (tx, mut rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
            },
        );

        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &did_hash,
            "A",
            false,
        )
        .await;

        assert!(
            timeout(StdDuration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "no redelivery may follow a live-delivery stop"
        );
    }

    /// A fresh (non-duplicate) registration must NOT trigger an inbox
    /// redelivery — only replacements re-cover in-flight messages.
    #[tokio::test]
    async fn fresh_registration_does_not_redeliver() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:bob";
        let did_hash = digest(did);

        database
            .store_message("sess-store", "some-message", &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
            },
        };

        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &update,
        )
        .await;

        // No replacement ⇒ no redelivery push within the window.
        assert!(
            timeout(StdDuration::from_millis(300), b_rx.recv())
                .await
                .is_err(),
            "fresh registration must not redeliver the inbox"
        );
    }

    /// Newest-wins is correct for an isolated duplicate, but under a sustained
    /// duel it makes both sides reconnect forever. Past `CHURN_REFUSE_STREAK`
    /// in-window replacements the incumbent keeps the slot and the contender is
    /// closed instead.
    #[tokio::test]
    async fn sustained_duel_holds_the_slot_for_the_incumbent() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:duellist";
        let did_hash = digest(did);

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Keep every receiver alive: a live incumbent channel is a precondition
        // of the damper (see the dead-incumbent test below).
        let mut keepalive = Vec::new();

        let register = |session: &str, tx: mpsc::Sender<QueuedCommand>| StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: tx,
                session_id: session.to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
            },
        };

        // First connection takes the slot uncontested.
        let (tx, rx) = mpsc::channel(5);
        keepalive.push(rx);
        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &register("s0", tx),
        )
        .await;

        // Contenders arrive back-to-back, well inside CHURN_WINDOW. The first
        // few take the slot (a genuine reconnect must still be able to).
        for i in 1..CHURN_REFUSE_STREAK {
            let session = format!("s{i}");
            let (tx, rx) = mpsc::channel(5);
            keepalive.push(rx);
            task._handle_registration(
                &database,
                &mut clients,
                &mut HashMap::new(),
                &replay_in_progress,
                &register(&session, tx),
            )
            .await;
            assert_eq!(
                clients.get(&did_hash).map(|e| e.session_id.as_str()),
                Some(session.as_str()),
                "replacement {i} is below the streak threshold and must be accepted"
            );
        }

        // This one crosses the threshold: it must be refused, not honoured.
        let incumbent = clients
            .get(&did_hash)
            .map(|e| e.session_id.clone())
            .expect("an incumbent is registered");
        let (late_tx, mut late_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &register("refused", late_tx),
        )
        .await;

        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some(incumbent.as_str()),
            "the incumbent must keep the slot once the duel is detected"
        );
        // …and is told it was REFUSED, not replaced. Nothing of the contender's
        // was displaced — the incumbent kept the slot — so the wording it
        // receives is the difference between a client rendering "you already
        // have this open" and a client rendering a transport error.
        match timeout(StdDuration::from_secs(1), late_rx.recv())
            .await
            .expect("the refused contender is answered")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Close(CloseReason::Refused),
                ..
            }) => {}
            other => panic!(
                "expected Close(Refused) on the refused socket, got {:?}",
                other.is_some()
            ),
        }
    }

    /// The damper must never be able to strand a DID. If the incumbent's channel
    /// is gone, the slot is handed over however long the streak is.
    #[tokio::test]
    async fn duel_damper_yields_to_a_dead_incumbent() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:ghost";
        let did_hash = digest(did);

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Incumbent deep in a churn streak, but its receiver is dropped — the
        // socket behind it is gone.
        let (dead_tx, dead_rx) = mpsc::channel(5);
        drop(dead_rx);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx: dead_tx,
                session_id: "ghost".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: CHURN_REFUSE_STREAK * 10,
                kind: EntryKind::Direct,
                slots: None,
            },
        );

        let (tx, _rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: tx,
                session_id: "live".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
            },
        };
        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &update,
        )
        .await;

        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some("live"),
            "a dead incumbent must never hold the slot against a live client"
        );
    }

    // ─── DID multiplexing (design §7.2) ──────────────────────────────────

    fn reg(
        did: &str,
        session: &str,
        tx: mpsc::Sender<QueuedCommand>,
        kind: EntryKind,
    ) -> StreamingUpdate {
        StreamingUpdate {
            did_hash: digest(did),
            state: StreamingUpdateState::Register {
                channel: tx,
                session_id: session.to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind,
                slots: None,
            },
        }
    }

    async fn next_cmd(rx: &mut mpsc::Receiver<QueuedCommand>) -> QueuedCommand {
        timeout(StdDuration::from_secs(2), rx.recv())
            .await
            .expect("a command arrives")
            .expect("channel open")
    }

    #[tokio::test]
    async fn a_mux_member_stands_by_behind_a_direct_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let task = streaming_task();
        let replay = Arc::new(DashSet::new());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();
        let did = "did:example:mux-a";

        let (d_tx, mut d_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "direct", d_tx, EntryKind::Direct),
        )
        .await;
        let (m_tx, mut m_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "mux", m_tx, EntryKind::Mux),
        )
        .await;

        assert_eq!(clients.get(&digest(did)).unwrap().session_id, "direct");
        assert_eq!(standby.get(&digest(did)).unwrap().len(), 1);
        match next_cmd(&mut m_rx).await.cmd {
            WebSocketCommands::MemberChange(MemberChange::Inactive { did_hash }) => {
                assert_eq!(did_hash, digest(did))
            }
            _ => panic!("mux member must be told it is inactive"),
        }
        // The direct socket is not disturbed.
        assert!(d_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_direct_socket_supersedes_a_mux_member_without_closing_its_connection() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:mux-b";
        database
            .store_message("s", "in-flight", &digest(did), None, 0, 1000)
            .await
            .unwrap();
        let task = streaming_task();
        let replay = Arc::new(DashSet::new());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();

        let (m_tx, mut m_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "mux", m_tx, EntryKind::Mux),
        )
        .await;
        let (d_tx, mut d_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "direct", d_tx, EntryKind::Direct),
        )
        .await;

        match next_cmd(&mut m_rx).await.cmd {
            WebSocketCommands::MemberChange(MemberChange::Superseded { .. }) => {}
            WebSocketCommands::Close(_) => {
                panic!("a mux connection carries other DIDs and must never be closed for one")
            }
            _ => panic!("expected Superseded"),
        }
        assert_eq!(clients.get(&digest(did)).unwrap().session_id, "direct");
        // The direct socket gets the inbox, as for any replacement (#374).
        let cmd = next_cmd(&mut d_rx).await;
        assert!(matches!(cmd.cmd, WebSocketCommands::Message(ref m) if m == "in-flight"));
        assert_eq!(cmd.did_hash.as_deref(), Some(digest(did).as_str()));
    }

    #[tokio::test]
    async fn when_the_direct_socket_leaves_the_mux_member_is_reactivated() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:mux-c";
        let task = streaming_task();
        let replay = Arc::new(DashSet::new());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();

        let (d_tx, _d_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "direct", d_tx, EntryKind::Direct),
        )
        .await;
        let (m_tx, mut m_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &reg(did, "mux", m_tx, EntryKind::Mux),
        )
        .await;
        let _inactive = next_cmd(&mut m_rx).await;
        // The member asked for live delivery while standing by.
        task._handle_activation(
            &database,
            &mut clients,
            &mut standby,
            &replay,
            &digest(did),
            "mux",
            true,
        )
        .await;
        assert!(
            !clients.get(&digest(did)).unwrap().active,
            "the direct socket's state is untouched"
        );

        clients.remove(&digest(did));
        assert!(
            task.promote_standby(&database, &mut clients, &mut standby, &replay, &digest(did))
                .await
        );
        let live = clients.get(&digest(did)).unwrap();
        assert_eq!(live.session_id, "mux");
        assert!(live.active, "the remembered live-delivery wish is honoured");
        assert!(standby.is_empty());
        match next_cmd(&mut m_rx).await.cmd {
            WebSocketCommands::MemberChange(MemberChange::Reactivated { .. }) => {}
            _ => panic!("expected Reactivated"),
        }
    }

    #[tokio::test]
    async fn a_standby_entry_leaving_does_not_touch_the_live_one() {
        let mut standby: HashMap<String, Vec<ClientEntry>> = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        standby.insert(
            "h".into(),
            vec![ClientEntry {
                tx,
                session_id: "mux".into(),
                active: false,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Mux,
                slots: None,
            }],
        );
        assert!(!remove_standby(&mut standby, "h", "someone-else"));
        assert!(remove_standby(&mut standby, "h", "mux"));
        assert!(standby.is_empty());
    }

    #[tokio::test]
    async fn one_mux_connection_carries_many_dids_and_tags_each_frame() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let task = streaming_task();
        let replay = Arc::new(DashSet::new());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();
        let (tx, mut rx) = mpsc::channel(16);
        for did in ["did:example:m1", "did:example:m2"] {
            task._handle_registration(
                &database,
                &mut clients,
                &mut standby,
                &replay,
                &reg(did, "mux", tx.clone(), EntryKind::Mux),
            )
            .await;
            task._handle_activation(
                &database,
                &mut clients,
                &mut standby,
                &replay,
                &digest(did),
                "mux",
                true,
            )
            .await;
        }
        for did in ["did:example:m1", "did:example:m2"] {
            let record = PubSubRecord {
                did_hash: digest(did),
                message: format!("for {did}"),
                force_delivery: false,
                verbatim: false,
                stored: None,
            };
            task.dispatch_payload(&database, &mut clients, &mut standby, &replay, record)
                .await;
        }
        let mut seen = Vec::new();
        while let Ok(Some(cmd)) = timeout(StdDuration::from_millis(200), rx.recv()).await {
            if let WebSocketCommands::Message(m) = cmd.cmd {
                seen.push((cmd.did_hash.unwrap(), m));
            }
        }
        assert!(seen.contains(&(digest("did:example:m1"), "for did:example:m1".into())));
        assert!(seen.contains(&(digest("did:example:m2"), "for did:example:m2".into())));
    }
}
