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
    MUX_QUEUE_FAIRNESS_SKIPS_TOTAL, STREAMING_ENTRIES_EVICTED_TOTAL,
    STREAMING_ENTRIES_RECLAIMED_TOTAL, STREAMING_HEARTBEAT_LAPSES_TOTAL,
    WEBSOCKET_CHURN_REFUSED_TOTAL, WEBSOCKET_DUPLICATE_CHURN_TOTAL,
    WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL, WEBSOCKET_REDELIVERED_MESSAGES_TOTAL,
    WS_LIVE_DELIVERY_DROPPED, WS_STREAMING_LAGGED_TOTAL,
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
use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use dashmap::DashMap;
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

/// Slots in the streaming task's control channel. See `spawn_supervised`.
const CONTROL_CHANNEL_CAPACITY: usize = 1024;

/// Inbox redeliveries that may read the store at once, across every DID.
///
/// A mux connection opening with a thousand live members starts a thousand
/// drains, each a page fetch and a delivered-mark; unbounded, they all hit
/// the store together. A drain waiting for a permit has already claimed its
/// DID (`Redeliveries`), so a newer socket asking meanwhile still hands it
/// over rather than starting a second one (#128).
const REDELIVERY_CONCURRENCY: usize = 32;

/// Page size for the inbox-redelivery drain.
const REDELIVERY_PAGE: usize = 50;

/// Safety bound on how many messages a single redelivery will re-push,
/// so a pathologically large inbox can't pin the drain task. If hit, the
/// remainder is left for the client to pick up via normal message-pickup.
const REDELIVERY_MAX: usize = 1000;

/// How long the redelivery drain waits for room (in the socket's queue, its
/// mux share or the global byte budget) for one frame before it stops and
/// raises the client's resync. The drain is a task of its own, so waiting
/// paces it to the socket rather than holding up anyone else.
#[cfg(not(test))]
const REDELIVERY_FRAME_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const REDELIVERY_FRAME_WAIT: Duration = Duration::from_millis(300);

/// How often the drain re-tries a mux share or the byte budget, neither of
/// which can be awaited, while it waits for room.
const REDELIVERY_RETRY: Duration = Duration::from_millis(20);

/// How often the task re-reads, for each of its mux entries, which instance
/// the store says streams the DID. The `Taken`/`Released` handoffs normally
/// keep the two in step; this catches one that was lost (an instance dying
/// between its store write and its publish, or a dropped pub/sub message), so
/// a member is never reported in the wrong state for longer than this.
const OWNERSHIP_RECHECK: Duration = Duration::from_secs(60);

/// How often the task renews its heartbeat in the store, so the instances
/// sharing it can tell it is alive.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);

/// How long a heartbeat lasts without renewal. An instance whose heartbeat
/// has expired is dead: the next ownership recheck on another instance that
/// carries one of its DIDs takes that DID over. Several missed renewals in a
/// row, so a brief store hiccup doesn't count.
const HEARTBEAT_LIFETIME: Duration = Duration::from_secs(45);

/// How long a dead instance stays listed among those that keep a heartbeat.
/// Streaming uuids are random per start unless configured, so the list would
/// otherwise grow with every restart. An instance forgotten this way is
/// treated as on an older release (never dead); its entries are long gone by
/// then, taken over or deregistered.
const HEARTBEAT_PRUNE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the streaming task proves it is alive to the other instances
/// sharing its store, and rechecks which instance streams each DID it
/// carries. A DID held by a dead instance is taken over within about
/// `heartbeat_lifetime + ownership_recheck`.
///
/// The defaults suit production; set others through
/// [`MediatorBuilder::streaming_liveness`](crate::builder::MediatorBuilder::streaming_liveness),
/// mainly to make tests that kill an instance quick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamingLiveness {
    /// How often the heartbeat is renewed. Default 10 s.
    pub heartbeat_every: Duration,
    /// How long a heartbeat lasts without renewal; an instance whose
    /// heartbeat has expired is dead. Keep it several times
    /// `heartbeat_every`, so a brief store hiccup doesn't count. Default 45 s.
    pub heartbeat_lifetime: Duration,
    /// How often the entries this instance carries are rechecked against the
    /// store's owners. Default 60 s.
    pub ownership_recheck: Duration,
}

impl Default for StreamingLiveness {
    fn default() -> Self {
        StreamingLiveness {
            heartbeat_every: HEARTBEAT_EVERY,
            heartbeat_lifetime: HEARTBEAT_LIFETIME,
            ownership_recheck: OWNERSHIP_RECHECK,
        }
    }
}

/// Why [`StreamingTask::reclaim`] claims a DID back.
#[derive(Clone, Copy, Debug)]
enum ReclaimReason {
    /// The store had no entry for the DID.
    Missing,
    /// The entry belonged to a dead instance and was just removed.
    DeadOwner,
    /// A direct socket here found the DID held by a mux entry elsewhere.
    OutranksMux,
    /// The streaming task restarted, and its clean start removed the entry.
    Restart,
}

impl ReclaimReason {
    fn label(self) -> &'static str {
        match self {
            ReclaimReason::Missing => "missing",
            ReclaimReason::DeadOwner => "dead_owner",
            ReclaimReason::OutranksMux => "outranks_mux",
            ReclaimReason::Restart => "restart",
        }
    }
}

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
    /// Set once a notification for this inactive entry has corrected the
    /// store's state to not-live, and cleared by the next activation change.
    /// Every notification still in flight from before the correction would
    /// otherwise issue the same store write again, inline on the loop that
    /// serves every DID (#128).
    store_demoted: bool,
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
    /// The socket answers any notification by draining the DID's whole
    /// stored inbox itself (a raw-TSP socket), so an inbox redelivery to it
    /// is one wake-up, not a push of every stored message.
    wake_only: bool,
}

impl ClientEntry {
    /// Where an inbox redelivery for this entry pushes.
    fn drain_target(&self) -> DrainTarget {
        DrainTarget {
            tx: self.tx.clone(),
            slots: self.slots.clone(),
            resync: self.resync.clone(),
            session_id: self.session_id.clone(),
            wake_only: self.wake_only,
        }
    }

    /// Whether this entry is the one the connection with `session_id` and
    /// send queue `channel` registered.
    fn is_registered_by(
        &self,
        session_id: &str,
        channel: &mpsc::WeakSender<QueuedCommand>,
    ) -> bool {
        self.session_id == session_id
            && channel
                .upgrade()
                .is_some_and(|tx| tx.same_channel(&self.tx))
    }
}

/// The sockets registered with the streaming task: kept outside each run of
/// the task, so a supervised restart does not forget them (see
/// [`StreamingTask::spawn_supervised`]).
#[derive(Default)]
pub(crate) struct Registered {
    /// The live entry for each DID, keyed by DID hash.
    clients: HashMap<String, ClientEntry>,
    /// Entries that yielded the live slot to another socket for the same
    /// DID (design §7.2): a mux member behind its DID's direct socket, or
    /// behind a newer mux connection. Newest last. Promoted when the live
    /// entry goes away.
    standby: HashMap<String, Vec<ClientEntry>>,
}

/// Where an inbox redelivery pushes: one registered entry's queue.
#[derive(Clone)]
struct DrainTarget {
    tx: mpsc::Sender<QueuedCommand>,
    slots: Option<Arc<MuxSlots>>,
    resync: Arc<AtomicBool>,
    /// The entry's session, which the store's fetch is made for.
    session_id: String,
    /// See [`ClientEntry::wake_only`].
    wake_only: bool,
}

/// The inbox redeliveries in flight: at most one drain per DID.
///
/// One per DID damps a duplicate-socket duel, which replaces the socket
/// every couple of seconds and must not start a whole-inbox dump for each
/// replacement. But a drain pushes to the socket that asked for it, and once
/// that socket is replaced its pushes go nowhere. So a request while a drain
/// runs is not skipped: it is left for the running drain, which hands itself
/// over to the newest socket and starts the inbox again for it. Whoever holds
/// the DID's slot last is the one the drain finishes on.
pub(crate) struct Redeliveries {
    /// DIDs with a drain running, each with the newer socket it should move
    /// to, if one asked meanwhile.
    running: DashMap<String, Option<DrainTarget>>,
    /// Bounds the drains reading the store at once
    /// ([`REDELIVERY_CONCURRENCY`]).
    permits: Arc<tokio::sync::Semaphore>,
}

impl Default for Redeliveries {
    fn default() -> Self {
        Self {
            running: DashMap::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(REDELIVERY_CONCURRENCY)),
        }
    }
}

impl Redeliveries {
    /// Whether a drain is running for `did_hash`.
    #[cfg(all(test, feature = "memory-backend"))]
    pub(crate) fn contains(&self, did_hash: &str) -> bool {
        self.running.contains_key(did_hash)
    }

    /// Record a drain for `did_hash` to `target`. Returns `target` when no
    /// drain was running and the caller must start one for it; `None` when
    /// the running drain takes `target` over.
    fn claim(&self, did_hash: &str, target: DrainTarget) -> Option<DrainTarget> {
        use dashmap::mapref::entry::Entry;
        match self.running.entry(did_hash.to_string()) {
            Entry::Occupied(mut running) => {
                running.insert(Some(target));
                None
            }
            Entry::Vacant(free) => {
                free.insert(None);
                Some(target)
            }
        }
    }

    /// The newer socket the running drain for `did_hash` should move to.
    fn handover(&self, did_hash: &str) -> Option<DrainTarget> {
        self.running
            .get_mut(did_hash)
            .and_then(|mut next| next.take())
    }

    /// The drain for `did_hash` is done with its socket: release it, or
    /// return the newer socket it must start over for.
    fn finish(&self, did_hash: &str) -> Option<DrainTarget> {
        if self
            .running
            .remove_if(did_hash, |_, next| next.is_none())
            .is_some()
        {
            return None;
        }
        self.handover(did_hash)
    }
}

/// Raise the resync of every live entry: told to collect, each client finds
/// whatever live notification it missed. For when the notifications that
/// were missed cannot be named (the subscription lagged).
fn raise_resync_all(clients: &HashMap<String, ClientEntry>) {
    for (did_hash, entry) in clients {
        if entry.active {
            raise_resync(entry.slots.as_ref(), &entry.resync, did_hash);
        }
    }
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
        /// The socket drains the DID's stored inbox itself on any
        /// notification (raw TSP). See `ClientEntry::wake_only`.
        wake_only: bool,
        /// Register with live delivery already on: the same as `Register`
        /// followed by a [`Start`](Self::Start) for the same session, in one
        /// command and **one** store write rather than two. A mux connection
        /// admitting many members at once sends this, so a connect with a
        /// thousand grants is a thousand writes on the streaming loop, not two
        /// thousand (#128).
        live: bool,
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
    /// connection's entry. `clients` is keyed by DID hash, not by connection,
    /// so a deregistration must name the connection it belongs to: a socket
    /// that has already been replaced (one DID, one slot) would otherwise
    /// evict its successor on the way out.
    ///
    /// The session id alone does not name a connection: every socket opened
    /// with the same access token shares it. `channel` is the send queue the
    /// connection registered, held weakly so it does not keep that queue
    /// open; an entry is this connection's only if it holds that queue.
    Deregister {
        session_id: String,
        channel: mpsc::WeakSender<QueuedCommand>,
    },
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
    /// Record the message as handed over in the store once it is written, as
    /// a pickup does (`limits.delivered_expiry_seconds`). Set by the inbox
    /// redelivery, which re-sends stored mail; a live push is not stamped.
    /// Holds the DID hash of the recipient whose copy is stamped: the same
    /// bytes held for another recipient are a separate copy.
    pub stamp: Option<String>,
}

impl DeliveryReport {
    /// The frame is on the wire: stamp the message when [`stamp`](Self::stamp)
    /// says so, then report the delivery.
    pub async fn written(self, state: &crate::SharedData) {
        if let Some(recipient) = &self.stamp
            && let Err(err) = state
                .database
                .record_delivered(
                    recipient,
                    std::slice::from_ref(&self.msg_id),
                    state.clock.unix_millis() as u64,
                    state.config.limits.delivered_expiry_seconds,
                )
                .await
        {
            warn!(msg_id = %self.msg_id, "couldn't record a redelivered message as delivered: {err}");
        }
        self.emit(&state.monitor);
    }

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

/// Queue a live payload to one client without blocking, `verbatim` choosing
/// the command the socket handler receives.
///
/// Returns `false` if the message was dropped — either the global byte pool is
/// exhausted or this connection's queue is full. Both mean the client is not
/// keeping up; the message is already durable in its inbox, so it will arrive on
/// the next poll or on reconnect redelivery.
///
/// Non-blocking is the whole point: this is called from the single streaming
/// loop that serves every DID, so awaiting one slow client here would stall live
/// delivery for all of them.
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

/// Tell a client's socket to close, without waiting on its send queue.
///
/// This runs in the single loop that serves every DID, so it must not await a
/// queue a slow client may never drain. A `Close` goes behind the frames
/// already queued, so when the queue is full it is handed to a task of its
/// own, which holds the sender until the socket takes the `Close` or goes
/// away. That task is bounded by the socket: once the handler exits (at the
/// latest when a write times out) the send fails and the task ends.
fn send_close(tx: &mpsc::Sender<QueuedCommand>, why: CloseReason) {
    match tx.try_send(QueuedCommand::control(WebSocketCommands::Close(why))) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(close)) => {
            debug!(reason = ?why, "Send queue full; queuing close in the background");
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(close).await;
            });
        }
        // The socket has already gone; there is nothing to close.
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
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

/// Tell a mux connection's socket that one of its members' delivery moved,
/// so it can report it (R6.2).
///
/// Recorded on the connection's shared slots and the socket woken, rather
/// than queued: the queue is shared with every member's frames and can be
/// full, and a member change that is dropped leaves the principal with the
/// wrong picture of which members it carries live, and `deliveryActive`
/// wrong with it. The record cannot be dropped, and keeps its order. An entry
/// without mux slots (a mux entry always has them) falls back to its queue.
fn tell_member(
    tx: &mpsc::Sender<QueuedCommand>,
    slots: Option<&Arc<MuxSlots>>,
    change: MemberChange,
) {
    if let Some(slots) = slots {
        slots.push_member_change(change);
        return;
    }
    if tx
        .try_send(QueuedCommand::control(WebSocketCommands::MemberChange(
            change,
        )))
        .is_err()
    {
        warn!("couldn't queue a mux member change: the send queue is full or closed");
    }
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
    /// Heartbeat and ownership-recheck timing.
    pub liveness: StreamingLiveness,
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
        liveness: StreamingLiveness,
    ) -> Self {
        // Control-plane channel (register/start/stop/deregister). Carries no
        // message bodies, only small structs, so a slot count is the right
        // bound. Sized for a mux connection opening or closing with its whole
        // member set (`max_dids_per_connection`, 1000 by default) without each
        // send waiting on the loop in turn (#128).
        let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let task = StreamingTask {
            channel: tx,
            uuid: mediator_uuid.to_string(),
            send_budget,
            liveness,
        };
        let rx = Arc::new(Mutex::new(rx));
        // The registered sockets outlive a restart for the same reason the
        // receiver does. Were they locals of the run, a restart would forget
        // every one: a direct socket would notice (its queue closes) and
        // reconnect, but a mux connection's queue is held open by the mux
        // registry too, so it would stay up and silently receive nothing.
        // Kept here, the next run claims them back in the store and
        // redelivers what arrived while it was down.
        let registered = Arc::new(Mutex::new(Registered::default()));
        let replays = Arc::new(Redeliveries::default());

        let supervised = task.clone();
        supervisor.spawn("websocket_streaming", false, move || {
            let task = supervised.clone();
            let database = database.clone();
            let rx = rx.clone();
            let registered = registered.clone();
            let replays = replays.clone();
            async move {
                let mut rx = rx.lock().await;
                let mut registered = registered.lock().await;
                task.ws_streaming_task(database, &mut rx, &mut registered, replays)
                    .await
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
        registered: &mut Registered,
        replay_in_progress: Arc<Redeliveries>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming_task", uuid = &self.uuid);

        async move {
            info!("WebSocket streaming task starting");

            // Clean up any existing sessions left over from previous runs
            database.streaming_clean_start(&self.uuid).await?;

            let Registered { clients, standby } = registered;
            // A restart: the sockets registered with the previous run are
            // still here, but the clean start above just removed their
            // entries from the store. Claim them back.
            self.restore(&database, clients, standby, &replay_in_progress)
                .await;

            // Subscribe to delivery notifications via the trait. Backends
            // are responsible for the wire-level transport (Redis pub/sub,
            // in-process broadcast, etc.) — the task just consumes
            // already-decoded `PubSubRecord`s.
            let mut rx = database.streaming_subscribe(&self.uuid).await?;
            let mut ownership = tokio::time::interval_at(
                tokio::time::Instant::now() + self.liveness.ownership_recheck,
                self.liveness.ownership_recheck,
            );
            ownership.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick is immediate, so the instance is listed as alive
            // before it serves anyone.
            let mut heartbeat = tokio::time::interval(self.liveness.heartbeat_every);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // A lapse before this run's first beat is the previous run's (a
            // restart with the same uuid): its entries went in the clean
            // start above, so there is nothing to take back.
            let mut first_beat = true;

            loop {
                select! {
                    _ = heartbeat.tick() => {
                        let beat = database
                            .streaming_heartbeat(&self.uuid, self.liveness.heartbeat_lifetime, HEARTBEAT_PRUNE_AFTER)
                            .await;
                        let fresh = std::mem::replace(&mut first_beat, false);
                        match beat {
                            Ok(true) if !fresh => {
                                warn!(
                                    "this instance's streaming heartbeat had lapsed; other instances may have taken over its DIDs. Rechecking ownership now"
                                );
                                metrics::counter!(STREAMING_HEARTBEAT_LAPSES_TOTAL).increment(1);
                                self.recheck_ownership(&database, clients, standby, &replay_in_progress).await;
                            }
                            Ok(_) => {}
                            Err(err) => warn!("couldn't renew the streaming heartbeat: {err}"),
                        }
                    }
                    _ = ownership.tick() => {
                        self.recheck_ownership(&database, clients, standby, &replay_in_progress).await;
                    }
                    value = rx.recv() => {
                        match value {
                            Ok(payload) => {
                                self.dispatch_payload(&database, clients, standby, &replay_in_progress, payload).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                // Subscriber fell behind; backend's broadcast capacity
                                // was exceeded. The skipped notifications' messages
                                // are stored, but nobody can say whose they were, so
                                // every live client is told to collect: a client that
                                // only listens would otherwise never learn of them
                                // (R6.2). The socket's resync floor rate-limits it.
                                warn!(
                                    "Streaming subscriber lagged, dropped {} live notifications; raising resync for every live client",
                                    skipped
                                );
                                metrics::counter!(WS_STREAMING_LAGGED_TOTAL).increment(1);
                                raise_resync_all(clients);
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
                                    self._handle_registration(&database, clients, standby, &replay_in_progress, value).await;
                                },
                                StreamingUpdateState::Start { session_id } => {
                                    self._handle_activation(&database, clients, standby, &replay_in_progress, &value.did_hash, session_id, true).await;
                                },
                                StreamingUpdateState::Stop { session_id } => {
                                    self._handle_activation(&database, clients, standby, &replay_in_progress, &value.did_hash, session_id, false).await;
                                },
                                StreamingUpdateState::Deregister { session_id, channel } => {
                                    self._handle_deregistration(&database, clients, standby, &replay_in_progress, &value.did_hash, session_id, channel).await;
                                }
                                StreamingUpdateState::RemoteTaken => {
                                    stand_by_taken(clients, standby, &value.did_hash);
                                }
                                StreamingUpdateState::RemoteReleased => {
                                    if !clients.contains_key(&value.did_hash)
                                        && self.promote_standby(&database, clients, standby, &replay_in_progress, &value.did_hash).await
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
    /// dropped (see [`try_queue`]).
    async fn dispatch_payload(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<Redeliveries>,
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
                            stamp: None,
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
                } else if entry.store_demoted {
                    // Already corrected once since the entry last went
                    // inactive: a notification in flight from before the
                    // correction landed, not a reason for another write.
                    debug!("pub/sub msg received for did_hash({did_hash}) but it is not active");
                } else {
                    debug!("pub/sub msg received for did_hash({did_hash}) but it is not active");
                    let kind = entry.kind;
                    match database
                        .streaming_claim(
                            &did_hash,
                            &self.uuid,
                            false,
                            kind.into(),
                            StreamingWrite::Update,
                        )
                        .await
                    {
                        Ok(_) => {
                            if let Some(entry) = clients.get_mut(&did_hash) {
                                entry.store_demoted = true;
                            }
                        }
                        Err(err) => {
                            error!("Error stopping streaming for client ({did_hash}): {err}");
                        }
                    }
                }
            }
            None => {
                // Routed here because the store still names this instance as
                // the DID's live streamer, but no socket here holds it: a
                // stale claim. Not the sender's problem (the message is in the
                // inbox), so not a warning; release the claim so later
                // messages stop being routed here (#148).
                debug!(
                    "pub/sub msg received for did_hash({did_hash}) with no client here; releasing its stale streaming claim"
                );
                if !self
                    .promote_standby(database, clients, standby, replay_in_progress, &did_hash)
                    .await
                {
                    self.release(database, &did_hash).await;
                }
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
        replay_in_progress: &Arc<Redeliveries>,
        did_hash: &str,
        session_id: &str,
        active: bool,
    ) {
        // The socket to flush to, captured while the entry is borrowed, and
        // whether live delivery was already on: a repeated `Start` changes
        // nothing, and must not drain the inbox again.
        let (target, kind, was_active) = match clients.get_mut(did_hash) {
            Some(entry) if entry.session_id == session_id => {
                let was_active = std::mem::replace(&mut entry.active, active);
                // This change writes the store's state itself.
                entry.store_demoted = false;
                (entry.drain_target(), entry.kind, was_active)
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
                    tell_member(
                        &entry.tx,
                        entry.slots.as_ref(),
                        MemberChange::Inactive {
                            did_hash: did_hash.to_string(),
                        },
                    );
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
        // message id, one drain per DID at a time (`Redeliveries`). A client
        // that already had a message simply sees it again and deletes it as
        // usual.
        //
        // Only when delivery turns on: a `Start` for a socket already live
        // has nothing new to cover, and a client repeating it must not be
        // able to re-dump its inbox each time.
        if active && !was_active {
            self.redeliver(database, replay_in_progress, did_hash, target);
        } else if active {
            debug!(did_hash = %did_hash, "live delivery already on; no redelivery");
        }
    }

    /// Remove the entry `channel` registered for `did_hash`, if it still has
    /// one: from standby, or from the live slot, promoting a standby entry in
    /// its place.
    #[allow(clippy::too_many_arguments)]
    async fn _handle_deregistration(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<Redeliveries>,
        did_hash: &str,
        session_id: &str,
        channel: &mpsc::WeakSender<QueuedCommand>,
    ) {
        // A standby entry leaving takes nothing live with it.
        if remove_standby(standby, did_hash, session_id, channel) {
            debug!(did_hash = %did_hash, leaving_session = %session_id, "Deregistered a standby entry");
            return;
        }
        // Only the connection that currently owns the slot may vacate it. One
        // DID has one entry, so a socket that was already replaced still runs
        // its own teardown — and an unconditional remove here would take the
        // *successor's* channel out with it. Dropping that `tx` closes the
        // live socket's command channel, so its handler exits with "streaming
        // task unavailable" and the client sees the connection closed for no
        // reason it can act on. Common whenever one DID hands off between
        // transports (a DIDComm session closing as a raw-TSP socket opens),
        // and when a client reconnects with the token it already holds while
        // its previous socket is still winding down.
        match clients.get(did_hash) {
            Some(entry) if !entry.is_registered_by(session_id, channel) => {
                debug!(
                    did_hash = %did_hash,
                    leaving_session = %session_id,
                    current_session = %entry.session_id,
                    "Ignoring deregistration from a replaced connection; the slot belongs to a newer one",
                );
            }
            Some(_) => {
                clients.remove(did_hash);
                info!(
                    "Deregistered streaming for DID: ({}) registered_clients({})",
                    did_hash,
                    clients.len()
                );
                if !self
                    .promote_standby(database, clients, standby, replay_in_progress, did_hash)
                    .await
                {
                    self.release(database, did_hash).await;
                }
            }
            None => {
                debug!(
                    did_hash = %did_hash,
                    leaving_session = %session_id,
                    "Deregistration for a DID with no registered client",
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
        replay_in_progress: &Arc<Redeliveries>,
        value: &StreamingUpdate,
    ) {
        let StreamingUpdateState::Register {
            channel: client_tx,
            session_id: new_session_id,
            did,
            resync: client_resync,
            kind,
            slots: client_slots,
            wake_only,
            live: start_live,
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
            send_close(client_tx, CloseReason::Unauthenticated);
            return;
        }

        let new_entry = |churn_streak| ClientEntry {
            tx: client_tx.clone(),
            store_demoted: false,
            session_id: new_session_id.to_string(),
            // A `live` registration is its own `Start`.
            active: *start_live,
            registered_at: Instant::now(),
            resync: client_resync.clone(),
            churn_streak,
            kind: *kind,
            slots: client_slots.clone(),
            wake_only: *wake_only,
        };

        // The connection that already holds this DID's entry registering it
        // again (a mux connection renewing a member it carries): an in-place
        // update, not a duplicate. Superseding its own entry would tell the
        // client its member had moved when it had not, leave a standby entry
        // behind for the live one, and redeliver the inbox for nothing.
        if let Some(live) = clients.get_mut(&value.did_hash)
            && live.session_id == new_session_id
            && live.tx.same_channel(client_tx)
        {
            live.resync = client_resync.clone();
            live.kind = *kind;
            live.slots = client_slots.clone();
            live.wake_only = *wake_only;
            debug!(
                did = did,
                session = new_session_id,
                "re-registration of the live entry; updated in place"
            );
            if *start_live {
                self._handle_activation(
                    database,
                    clients,
                    standby,
                    replay_in_progress,
                    &value.did_hash,
                    new_session_id,
                    true,
                )
                .await;
            }
            return;
        }
        if let Some(waiting) = standby.get_mut(&value.did_hash).and_then(|v| {
            v.iter_mut()
                .find(|e| e.session_id == new_session_id && e.tx.same_channel(client_tx))
        }) {
            waiting.resync = client_resync.clone();
            waiting.kind = *kind;
            waiting.slots = client_slots.clone();
            waiting.wake_only = *wake_only;
            if *start_live {
                waiting.active = true;
            }
            // Still behind another socket: say so again, since a
            // registration is the connection's cue to forget it was.
            tell_member(
                client_tx,
                client_slots.as_ref(),
                MemberChange::Inactive {
                    did_hash: value.did_hash.clone(),
                },
            );
            debug!(
                did = did,
                session = new_session_id,
                "re-registration of a standby entry; updated in place"
            );
            return;
        }

        // Mux precedence (design §7.2). A direct socket outranks a mux member,
        // and among mux connections the newest carries the DID. A displaced
        // or outranked mux entry is never *closed*: its connection carries
        // other DIDs too. It waits on standby instead, and is told so.
        if let Some(old) = clients.get(&value.did_hash) {
            match (old.kind, *kind) {
                (EntryKind::Direct, EntryKind::Mux) => {
                    tell_member(
                        client_tx,
                        client_slots.as_ref(),
                        MemberChange::Inactive {
                            did_hash: value.did_hash.clone(),
                        },
                    );
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
                    tell_member(
                        &old.tx,
                        old.slots.as_ref(),
                        MemberChange::Superseded {
                            did_hash: value.did_hash.clone(),
                        },
                    );
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
                send_close(client_tx, CloseReason::Refused);
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
            send_close(&old.tx, CloseReason::Replaced);
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
            // A `live` registration redelivers what queued before it, as its
            // `Start` would have.
            replacing || *start_live,
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
        replay_in_progress: &Arc<Redeliveries>,
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
            tell_member(
                &entry.tx,
                entry.slots.as_ref(),
                MemberChange::Inactive {
                    did_hash: did_hash.to_string(),
                },
            );
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
        let target = entry.drain_target();
        clients.insert(did_hash.to_string(), entry);

        // One drain per DID at a time, so a flip-flop duel can't amplify
        // into concurrent whole-inbox dumps: a drain already running for the
        // displaced socket is handed over to this one (`Redeliveries`).
        if replacing {
            self.redeliver(database, replay_in_progress, did_hash, target);
        }
        true
    }

    /// Redeliver `did_hash`'s stored inbox to `target`, the socket that now
    /// holds the DID (see [`spawn_inbox_redelivery`]).
    ///
    /// A socket that drains the inbox itself on any notification (raw TSP)
    /// is sent one wake-up, its resync, rather than a push per stored
    /// message: each push would only make it drain again, and it records as
    /// delivered just what it writes.
    fn redeliver(
        &self,
        database: &Arc<dyn MediatorStore>,
        replays: &Arc<Redeliveries>,
        did_hash: &str,
        target: DrainTarget,
    ) {
        if target.wake_only {
            raise_resync(target.slots.as_ref(), &target.resync, did_hash);
            debug!(did_hash = %did_hash, "redelivery to a socket that drains itself; woken");
            return;
        }
        match replays.claim(did_hash, target) {
            Some(target) => spawn_inbox_redelivery(
                Arc::clone(database),
                target,
                self.send_budget.clone(),
                did_hash.to_string(),
                Arc::clone(replays),
            ),
            None => debug!(
                did_hash = %did_hash,
                "inbox redelivery already running for this DID; handed over to the newest socket"
            ),
        }
    }

    /// After a restart, claim back every socket the previous run had
    /// registered: the clean start removed their entries from the store, and
    /// any message that arrived meanwhile was stored but not pushed. An entry
    /// whose socket has gone is dropped; one standing by for a DID nobody now
    /// holds takes it.
    async fn restore(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replays: &Arc<Redeliveries>,
    ) {
        clients.retain(|_, e| !e.tx.is_closed());
        standby.retain(|_, waiting| {
            waiting.retain(|e| !e.tx.is_closed());
            !waiting.is_empty()
        });
        if clients.is_empty() && standby.is_empty() {
            return;
        }
        warn!(
            live = clients.len(),
            standing_by = standby.len(),
            "streaming task restarted; claiming back the sockets registered before it"
        );
        let live: Vec<String> = clients.keys().cloned().collect();
        for did_hash in live {
            self.reclaim(
                database,
                clients,
                standby,
                replays,
                &did_hash,
                ReclaimReason::Restart,
            )
            .await;
        }
        let waiting: Vec<String> = standby
            .keys()
            .filter(|d| !clients.contains_key(*d))
            .cloned()
            .collect();
        // Only for a DID nobody holds: one held elsewhere stays as it was,
        // and its connection has already been told so.
        let owners = match database.streaming_owners(&waiting).await {
            Ok(owners) => owners,
            Err(err) => {
                warn!(
                    "couldn't read who streams the DIDs standing by; the ownership recheck will: {err}"
                );
                return;
            }
        };
        for (did_hash, owner) in waiting.into_iter().zip(owners) {
            if owner.is_none() {
                self.promote_standby(database, clients, standby, replays, &did_hash)
                    .await;
            }
        }
    }

    /// Bring this instance's entries in step with the store's owners
    /// ([`OWNERSHIP_RECHECK`]), for a handoff that never arrived, for an
    /// entry that went missing, and for an owner that died:
    ///
    /// - an entry this instance holds whose DID nobody holds any more is
    ///   claimed back, with an inbox redelivery: messages for it were stored
    ///   but not pushed while its record was gone. The record goes when an
    ///   instance that doesn't check owners removes it (one on the previous
    ///   release, during a rolling upgrade), or when the store loses data;
    /// - a DID held by a dead instance (its heartbeat expired) is treated
    ///   the same way, once its entry is removed: the entry here claims it,
    ///   or a mux entry standing by for it takes it;
    /// - a live mux entry whose DID another instance now streams stands by
    ///   (`superseded`), as on `RemoteTaken`;
    /// - a direct socket here whose DID a mux entry elsewhere holds claims it
    ///   back, since a direct socket outranks a mux entry. That happens after
    ///   this instance was taken for dead while still serving;
    /// - a mux entry standing by for a DID nobody streams any more takes it
    ///   (`reactivated`), as on `RemoteReleased`.
    ///
    /// A direct socket whose DID another instance's direct socket holds is
    /// left alone: a newer socket there replaced it by the newest-wins rule.
    /// The owners are read in batches; a failed read changes nothing until
    /// the next pass.
    async fn recheck_ownership(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<Redeliveries>,
    ) {
        let held: Vec<String> = clients.keys().cloned().collect();
        let owners = match database.streaming_owners(&held).await {
            Ok(owners) => owners,
            Err(err) => {
                warn!("couldn't recheck which instance streams each DID: {err}");
                return;
            }
        };
        let dead = self.dead_owners(database, &owners).await;
        let mut behind_other: Vec<String> = Vec::new();
        for (did_hash, owner) in held.into_iter().zip(owners) {
            match owner {
                Some(owner) if owner == self.uuid => {}
                Some(owner) if dead.contains(&owner) => {
                    if self.evict(database, &did_hash, &owner).await {
                        self.reclaim(
                            database,
                            clients,
                            standby,
                            replay_in_progress,
                            &did_hash,
                            ReclaimReason::DeadOwner,
                        )
                        .await;
                    }
                }
                Some(_) => {
                    if clients
                        .get(&did_hash)
                        .is_some_and(|e| e.kind == EntryKind::Direct)
                    {
                        behind_other.push(did_hash);
                    } else if stand_by_taken(clients, standby, &did_hash) {
                        info!(did_hash = %did_hash, "a lost handoff: another instance streams this DID; mux entry stood by");
                    }
                }
                None => {
                    self.reclaim(
                        database,
                        clients,
                        standby,
                        replay_in_progress,
                        &did_hash,
                        ReclaimReason::Missing,
                    )
                    .await;
                }
            }
        }

        // A direct socket here behind another instance's mux entry takes the
        // DID back; behind a direct socket it stays (newest wins).
        match database.streaming_mux_owned(&behind_other).await {
            Ok(mux_owned) => {
                for (did_hash, mux) in behind_other.into_iter().zip(mux_owned) {
                    if mux {
                        self.reclaim(
                            database,
                            clients,
                            standby,
                            replay_in_progress,
                            &did_hash,
                            ReclaimReason::OutranksMux,
                        )
                        .await;
                    }
                }
            }
            Err(err) => warn!("couldn't recheck which DIDs mux entries hold: {err}"),
        }

        let waiting: Vec<String> = standby
            .keys()
            .filter(|d| !clients.contains_key(*d))
            .cloned()
            .collect();
        let owners = match database.streaming_owners(&waiting).await {
            Ok(owners) => owners,
            Err(err) => {
                warn!("couldn't recheck the DIDs mux entries wait for: {err}");
                return;
            }
        };
        let dead = self.dead_owners(database, &owners).await;
        for (did_hash, owner) in waiting.into_iter().zip(owners) {
            let free = match owner {
                None => true,
                Some(owner) if dead.contains(&owner) => {
                    self.evict(database, &did_hash, &owner).await
                }
                Some(_) => false,
            };
            if free
                && self
                    .promote_standby(database, clients, standby, replay_in_progress, &did_hash)
                    .await
            {
                info!(did_hash = %did_hash, "nobody live streams this DID; mux entry took it back");
            }
        }
    }

    /// Which of the instances in `owners` (other than this one) are dead. A
    /// failed read counts nobody dead, so a store outage takes nothing over.
    async fn dead_owners(
        &self,
        database: &Arc<dyn MediatorStore>,
        owners: &[Option<String>],
    ) -> HashSet<String> {
        let mut others: Vec<String> = owners
            .iter()
            .flatten()
            .filter(|o| **o != self.uuid)
            .cloned()
            .collect();
        others.sort_unstable();
        others.dedup();
        match database.streaming_dead_instances(&others).await {
            Ok(dead) => others
                .into_iter()
                .zip(dead)
                .filter_map(|(uuid, dead)| dead.then_some(uuid))
                .collect(),
            Err(err) => {
                warn!("couldn't check which streaming instances are alive: {err}");
                HashSet::new()
            }
        }
    }

    /// Remove `did_hash`'s entry, held by the dead instance `owner`. Returns
    /// whether it was removed; when the instance beat again, or another
    /// instance took the DID meanwhile, it is left alone.
    async fn evict(&self, database: &Arc<dyn MediatorStore>, did_hash: &str, owner: &str) -> bool {
        match database.streaming_evict(did_hash, owner).await {
            Ok(true) => {
                warn!(
                    did_hash = %did_hash,
                    dead_instance = %owner,
                    "the instance streaming this DID stopped renewing its heartbeat; took over its entry"
                );
                metrics::counter!(STREAMING_ENTRIES_EVICTED_TOTAL).increment(1);
                true
            }
            Ok(false) => false,
            Err(err) => {
                warn!(did_hash = %did_hash, "couldn't take over a dead instance's streaming entry: {err}");
                false
            }
        }
    }

    /// Claim `did_hash` back for its live entry here, whose store record has
    /// gone, and redeliver the inbox to it when it wants live delivery. An
    /// entry whose socket has closed is left to its deregistration, already on
    /// its way.
    async fn reclaim(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        standby: &mut HashMap<String, Vec<ClientEntry>>,
        replay_in_progress: &Arc<Redeliveries>,
        did_hash: &str,
        reason: ReclaimReason,
    ) {
        if clients.get(did_hash).is_none_or(|e| e.tx.is_closed()) {
            return;
        }
        let Some(entry) = clients.remove(did_hash) else {
            return;
        };
        let kind = entry.kind;
        warn!(
            did_hash = %did_hash,
            kind = ?kind,
            reason = ?reason,
            "claiming this instance's streaming entry back"
        );
        metrics::counter!(
            STREAMING_ENTRIES_RECLAIMED_TOTAL,
            "kind" => match kind {
                EntryKind::Direct => "direct",
                EntryKind::Mux => "mux",
            },
            "reason" => reason.label()
        )
        .increment(1);
        let replay = entry.active;
        // Refused (a direct socket elsewhere registered the DID meanwhile), a
        // mux entry stands by, as on any registration.
        self.install(
            database,
            clients,
            standby,
            replay_in_progress,
            did_hash,
            entry,
            replay,
        )
        .await;
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
            members: Vec::new(),
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
        replay_in_progress: &Arc<Redeliveries>,
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
        let slots = entry.slots.clone();
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
        tell_member(
            &tx,
            slots.as_ref(),
            MemberChange::Reactivated {
                did_hash: did_hash.to_string(),
            },
        );
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
    tell_member(
        &entry.tx,
        entry.slots.as_ref(),
        MemberChange::Superseded {
            did_hash: did_hash.to_string(),
        },
    );
    standby.entry(did_hash.to_string()).or_default().push(entry);
    debug!(did_hash = %did_hash, "another instance took this DID; its mux entry stands by");
    true
}

/// Remove `session_id`'s standby entry for `did_hash`, if it has one.
fn remove_standby(
    standby: &mut HashMap<String, Vec<ClientEntry>>,
    did_hash: &str,
    session_id: &str,
    channel: &mpsc::WeakSender<QueuedCommand>,
) -> bool {
    let Some(waiting) = standby.get_mut(did_hash) else {
        return false;
    };
    let before = waiting.len();
    waiting.retain(|e| !e.is_registered_by(session_id, channel));
    let removed = waiting.len() != before;
    if waiting.is_empty() {
        standby.remove(did_hash);
    }
    removed
}

/// Drain the recipient's undelivered inbox to the socket that now holds the
/// DID (it displaced a duplicate, turned live delivery on, or was claimed
/// back), re-pushing each stored (but not yet deleted) message as a
/// live-stream frame. Runs as a detached task so the streaming `select!` loop
/// — which services every DID — never blocks on a multi-page database drain.
///
/// Messages are fetched with `DoNotDelete` and without stamping:
/// redelivery is a notification re-cover, not an ack, and queueing is not
/// delivery. Each frame carries its [`DeliveryReport`], so the socket loop
/// records the message as delivered only once it has written it (R1.1). The
/// client deletes what it has processed via the normal message-pickup path,
/// so this is at-least-once and idempotent by message id.
///
/// Being a task of its own, the drain waits for room in the socket's queue
/// (and its mux share, and the global byte budget) rather than giving up on
/// the first full queue, so it is paced to the socket and the paging and
/// [`REDELIVERY_MAX`] take effect. A socket that makes no room for
/// [`REDELIVERY_FRAME_WAIT`], a fetch that fails, or the cap being reached
/// stops the drain with messages possibly left behind: the client's resync is
/// raised, as a dropped live push does, since a client that only listens
/// would otherwise never learn of them.
///
/// A newer socket for the DID asking for a drain meanwhile takes this one
/// over (see [`Redeliveries`]): it starts the inbox again for that socket.
fn spawn_inbox_redelivery(
    database: Arc<dyn MediatorStore>,
    first: DrainTarget,
    budget: WsSendBudget,
    did_hash: String,
    redeliveries: Arc<Redeliveries>,
) {
    tokio::spawn(async move {
        // Held for the whole drain, handovers included. The semaphore is
        // never closed, so acquiring cannot fail.
        let _permit = Arc::clone(&redeliveries.permits).acquire_owned().await;
        let mut target = first;
        loop {
            match drain_inbox(&database, &target, &budget, &did_hash, &redeliveries).await {
                DrainEnd::HandedOver(next) => {
                    debug!(did_hash = %did_hash, "inbox redelivery handed over to a newer socket");
                    target = next;
                    continue;
                }
                DrainEnd::Complete(total) => {
                    if total > 0 {
                        debug!(did_hash = %did_hash, total, "Inbox redelivery complete");
                    }
                }
                DrainEnd::CutShort(total) => {
                    raise_resync(target.slots.as_ref(), &target.resync, &did_hash);
                    debug!(did_hash = %did_hash, total, "Inbox redelivery stopped early; resync raised");
                }
            }
            match redeliveries.finish(&did_hash) {
                Some(next) => target = next,
                None => break,
            }
        }
    });
}

/// How one pass of [`drain_inbox`] ended.
enum DrainEnd {
    /// The whole inbox was queued; this many messages.
    Complete(usize),
    /// Stopped with messages possibly left behind, after this many.
    CutShort(usize),
    /// A newer socket for the DID asked for a drain: start again for it.
    HandedOver(DrainTarget),
}

/// Queue `did_hash`'s stored inbox to `target`, page by page.
async fn drain_inbox(
    database: &Arc<dyn MediatorStore>,
    target: &DrainTarget,
    budget: &WsSendBudget,
    did_hash: &str,
    redeliveries: &Redeliveries,
) -> DrainEnd {
    let mut start_id: Option<String> = None;
    let mut total: usize = 0;
    loop {
        if let Some(next) = redeliveries.handover(did_hash) {
            return DrainEnd::HandedOver(next);
        }
        let options = FetchOptions {
            limit: REDELIVERY_PAGE,
            start_id: start_id.clone(),
            ..Default::default() // delete_policy defaults to DoNotDelete
        };
        // Fetched without stamping, in stream order (this drain re-covers a
        // socket's whole inbox, paging with `start_id`). Each message is
        // stamped by the socket once its frame is written
        // (`DeliveryReport::stamp`): queueing is not delivery (R1.1).
        let page = match database
            .fetch_messages(&target.session_id, did_hash, &options)
            .await
        {
            Ok(page) => page,
            Err(err) => {
                warn!(did_hash = %did_hash, "Inbox redelivery fetch failed, aborting drain: {err}");
                return DrainEnd::CutShort(total);
            }
        };
        if page.success.is_empty() {
            return DrainEnd::Complete(total);
        }
        let page_len = page.success.len();

        for element in page.success {
            // Advance the cursor regardless of body presence so a missing
            // body can't pin the drain on the same page forever.
            if let Some(receive_id) = &element.receive_id {
                start_id = Some(receive_id.clone());
            }
            let Some(msg) = element.msg else { continue };
            if let Some(next) = redeliveries.handover(did_hash) {
                return DrainEnd::HandedOver(next);
            }
            let report = DeliveryReport {
                msg_id: element.msg_id,
                from: element.from_address,
                to: element.to_address,
                size: element.size,
                protocol: crate::monitor::Protocol::detect(&msg),
                stamp: Some(did_hash.to_string()),
            };

            // Fetched with `DoNotDelete`, so anything not queued here stays
            // in the inbox. Stopping early is therefore lossless, and the
            // resync the caller raises tells the client to collect the rest.
            if !queue_redelivered(target, budget, did_hash, msg, report, REDELIVERY_FRAME_WAIT)
                .await
            {
                debug!(
                    did_hash = %did_hash,
                    "no room on the socket for a redelivered message; \
                     stopping drain, remainder left for message-pickup"
                );
                return DrainEnd::CutShort(total);
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
                return DrainEnd::CutShort(total);
            }
        }

        // A short page means the stream is exhausted.
        if page_len < REDELIVERY_PAGE {
            return DrainEnd::Complete(total);
        }
    }
}

/// Queue one redelivered message to `target`, waiting up to `wait` for room:
/// a slot of the DID's share on a mux connection, bytes in the global budget,
/// then a place in the socket's queue. Returns `false` when there was none in
/// time, or the socket has gone.
///
/// The share and the budget cannot be awaited, so they are re-tried; the
/// queue is awaited. The share and bytes are taken first, so a place in the
/// queue is never held while waiting on them.
async fn queue_redelivered(
    target: &DrainTarget,
    budget: &WsSendBudget,
    did_hash: &str,
    message: String,
    report: DeliveryReport,
    wait: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    let slot = loop {
        match target.slots.as_ref().map(|s| s.try_acquire(did_hash)) {
            None => break None,
            Some(Ok(slot)) => break Some(slot),
            Some(Err(_)) => {}
        }
        if target.tx.is_closed() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(REDELIVERY_RETRY).await;
    };
    let permit = loop {
        if let Some(permit) = budget.try_reserve(message.len()) {
            break permit;
        }
        if target.tx.is_closed() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(REDELIVERY_RETRY).await;
    };
    let place = match tokio::time::timeout_at(deadline, target.tx.reserve()).await {
        Ok(Ok(place)) => place,
        // Closed, or no room in time.
        _ => return false,
    };
    place.send(QueuedCommand {
        cmd: WebSocketCommands::Message(message),
        report: Some(report),
        did_hash: Some(did_hash.to_string()),
        _permit: Some(permit),
        _slot: slot,
    });
    true
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
            liveness: StreamingLiveness::default(),
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
                store_demoted: false,
                tx,
                session_id: session_id.to_string(),
                active,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
            },
        );
        clients
    }

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
            store_demoted: false,
            tx: tx.clone(),
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
            wake_only: false,
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
            store_demoted: false,
            tx: tx.clone(),
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Mux,
            slots: Some(slots.clone()),
            wake_only: false,
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
                store_demoted: false,
                tx,
                session_id: "S".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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
                    &Arc::new(Redeliveries::default()),
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

    /// A notification for a DID no socket here holds means the store's claim
    /// that this instance streams it is stale. It is released, so later
    /// messages stop being routed here; it used to log a WARN per message and
    /// stay `Live` for good (#148).
    #[tokio::test]
    async fn a_notification_for_an_unknown_did_releases_its_stale_claim() {
        let task = streaming_task();
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        database
            .streaming_set_state(
                "bob",
                &task.uuid,
                affinidi_messaging_mediator_common::store::types::StreamingClientState::Live,
            )
            .await
            .unwrap();
        assert!(
            database
                .streaming_is_client_live("bob", false)
                .await
                .is_some()
        );

        task.dispatch_payload(
            &database,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &Arc::new(Redeliveries::default()),
            PubSubRecord {
                did_hash: "bob".to_string(),
                message: "body".to_string(),
                force_delivery: false,
                verbatim: false,
                stored: None,
            },
        )
        .await;

        assert!(
            database
                .streaming_is_client_live("bob", true)
                .await
                .is_none(),
            "the stale claim is released"
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
            store_demoted: false,
            tx,
            session_id: "S".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: resync.clone(),
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
            wake_only: false,
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

    /// A `Stop` from a session that has already been replaced must not switch
    /// live delivery off for the connection that replaced it.
    ///
    /// This is the bad direction of the bug: `clients` is keyed by DID hash, so
    /// an unscoped `Stop` clears both `active` and the stored `Live` state for
    /// whoever holds the slot. The healthy socket stays connected and simply
    /// stops receiving pushes — the same silent stop-delivering failure as the
    /// `Deregister` bug, invisible from both ends.
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
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

        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
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

        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
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

        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Client A is the existing live session.
        let (a_tx, mut a_rx) = mpsc::channel(5);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx: a_tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
            },
        );

        // Client B connects for the same DID (the duplicate).
        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                live: false,
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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

    /// Replacing a socket whose send queue is full returns at once: the
    /// registration path runs in the loop that serves every DID, so it must
    /// not wait for the old socket to drain. The old socket still gets its
    /// `Close(Replaced)`, behind the frames already queued, once it reads.
    #[tokio::test]
    async fn replacing_a_socket_with_a_full_queue_does_not_wait_for_it() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:full-queue";
        let did_hash = digest(did);
        let task = streaming_task();
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        let (a_tx, mut a_rx) = mpsc::channel(1);
        a_tx.try_send(QueuedCommand::for_test(Some(&did_hash)))
            .expect("fill A's queue");
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx: a_tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now() - CHURN_WINDOW,
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
            },
        );

        let (b_tx, _b_rx) = mpsc::channel(5);
        timeout(
            StdDuration::from_secs(1),
            task._handle_registration(
                &database,
                &mut clients,
                &mut HashMap::new(),
                &replay_in_progress,
                &reg(did, "B", b_tx, EntryKind::Direct),
            ),
        )
        .await
        .expect("registration must not wait on the old socket's full queue");

        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some("B")
        );

        // A drains: first the frame it already had, then the close.
        assert!(matches!(
            next_cmd(&mut a_rx).await.cmd,
            WebSocketCommands::Message(_)
        ));
        assert!(matches!(
            next_cmd(&mut a_rx).await.cmd,
            WebSocketCommands::Close(CloseReason::Replaced)
        ));
    }

    /// Two sockets opened with one access token share its session id. The
    /// replaced one's teardown must not take the slot from the socket that
    /// replaced it, even when its `Close` never reached it (its queue was
    /// full, and it went away before reading).
    #[tokio::test]
    async fn a_replaced_socket_sharing_the_session_id_does_not_deregister_its_successor() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:shared-session";
        let did_hash = digest(did);
        let task = streaming_task();
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        let mut standby: HashMap<String, Vec<ClientEntry>> = HashMap::new();

        let (a_tx, a_rx) = mpsc::channel(1);
        let a_channel = a_tx.downgrade();
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay_in_progress,
            &reg(did, "S", a_tx.clone(), EntryKind::Direct),
        )
        .await;
        a_tx.try_send(QueuedCommand::for_test(Some(&did_hash)))
            .expect("fill A's queue");
        clients
            .get_mut(&did_hash)
            .expect("A registered")
            .registered_at = Instant::now() - CHURN_WINDOW;

        let (b_tx, _b_rx) = mpsc::channel(5);
        let b_channel = b_tx.downgrade();
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replay_in_progress,
            &reg(did, "S", b_tx, EntryKind::Direct),
        )
        .await;

        // A goes away without reading its queue, then tears down.
        drop(a_rx);
        drop(a_tx);
        task._handle_deregistration(
            &database,
            &mut clients,
            &mut standby,
            &replay_in_progress,
            &did_hash,
            "S",
            &a_channel,
        )
        .await;
        let b = clients.get(&did_hash).expect("B keeps the slot");
        assert!(b.is_registered_by("S", &b_channel));

        // B's own teardown does remove it.
        task._handle_deregistration(
            &database,
            &mut clients,
            &mut standby,
            &replay_in_progress,
            &did_hash,
            "S",
            &b_channel,
        )
        .await;
        assert!(clients.get(&did_hash).is_none());
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let (tx, mut rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx,
                session_id: "A".to_string(),
                active: false,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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

    /// A `live` registration (#128) is its own `Start`: the entry is live,
    /// the store says so after one write, and what queued before it is
    /// redelivered, as the separate `Start` would have done.
    #[tokio::test]
    async fn a_live_registration_activates_and_redelivers_in_one_command() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:dave";
        let did_hash = digest(did);
        let stored = "queued-before-registration";
        database
            .store_message("sess-store", stored, &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let (tx, mut rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        task._handle_registration(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            &StreamingUpdate {
                did_hash: did_hash.clone(),
                state: StreamingUpdateState::Register {
                    channel: tx,
                    session_id: "M".to_string(),
                    did: did.to_string(),
                    resync: Arc::new(AtomicBool::new(false)),
                    kind: EntryKind::Mux,
                    slots: None,
                    wake_only: false,
                    live: true,
                },
            },
        )
        .await;

        assert!(clients.get(&did_hash).is_some_and(|e| e.active));
        assert_eq!(
            database.streaming_is_client_live(&did_hash, false).await,
            Some(task.uuid.clone()),
            "the store records the DID live without a separate Start"
        );
        match timeout(StdDuration::from_secs(2), rx.recv())
            .await
            .expect("the queued message is pushed on registration")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Message(msg),
                ..
            }) => assert_eq!(msg, stored),
            _ => panic!("expected the queued message to be redelivered"),
        }
    }

    /// A notification for a registered-but-inactive DID corrects the store's
    /// state once; further notifications in flight do not write again until
    /// the entry's live state changes (#128).
    #[tokio::test]
    async fn an_inactive_entry_is_demoted_in_the_store_once() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:erin");
        let task = streaming_task();
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let (tx, _rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx,
                session_id: "A".to_string(),
                active: false,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
            },
        );
        let record = || PubSubRecord {
            did_hash: did_hash.clone(),
            message: "m".to_string(),
            force_delivery: false,
            verbatim: false,
            stored: None,
        };
        task.dispatch_payload(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            record(),
        )
        .await;
        assert!(clients[&did_hash].store_demoted);

        // Something else marks it live behind the entry's back; a second
        // notification must not write (the flag holds) ...
        database
            .streaming_set_state(
                &did_hash,
                &task.uuid,
                affinidi_messaging_mediator_common::store::StreamingClientState::Live,
            )
            .await
            .expect("set");
        task.dispatch_payload(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replay_in_progress,
            record(),
        )
        .await;
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_some(),
            "no second demotion write while the flag is set"
        );

        // ... and an activation change clears it.
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
        assert!(!clients[&did_hash].store_demoted);
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
        let replay: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let did = "did_hash_member";
        let (tx, mut rx) = mpsc::channel(8);
        let mut clients = HashMap::from([(
            did.to_string(),
            ClientEntry {
                store_demoted: false,
                tx,
                session_id: "M".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Mux,
                slots: None,
                wake_only: false,
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

    /// An entry whose store record went missing (removed by an instance that
    /// doesn't check owners, as one on the previous release does during a
    /// rolling upgrade) is claimed back by the recheck, and the inbox that
    /// arrived meanwhile is redelivered. A direct socket whose DID another
    /// instance holds, and an entry whose socket closed, are left alone.
    #[tokio::test]
    async fn the_ownership_recheck_claims_back_a_missing_entry() {
        use affinidi_messaging_mediator_common::store::StreamingClientState;
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let task = streaming_task();
        let replay: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let entry = |tx: mpsc::Sender<QueuedCommand>| ClientEntry {
            store_demoted: false,
            tx,
            session_id: "D".to_string(),
            active: true,
            registered_at: Instant::now(),
            resync: Arc::new(AtomicBool::new(false)),
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
            wake_only: false,
        };
        let (gone, elsewhere, closed) = (
            digest("did:example:gone"),
            digest("did:example:elsewhere"),
            digest("did:example:closed"),
        );
        let (tx, mut rx) = mpsc::channel(8);
        let (tx_elsewhere, mut rx_elsewhere) = mpsc::channel(8);
        let (tx_closed, rx_closed) = mpsc::channel(8);
        drop(rx_closed);
        let mut clients = HashMap::from([
            (gone.clone(), entry(tx)),
            (elsewhere.clone(), entry(tx_elsewhere)),
            (closed.clone(), entry(tx_closed)),
        ]);
        let mut standby = HashMap::new();
        database
            .streaming_set_state(&elsewhere, "another-instance", StreamingClientState::Live)
            .await
            .unwrap();
        // Stored while `gone` had no record: not pushed.
        let stored = "while-the-record-was-gone";
        database
            .store_message("sess-store", stored, &gone, None, 0, 1000)
            .await
            .expect("store message");

        task.recheck_ownership(&database, &mut clients, &mut standby, &replay)
            .await;

        assert_eq!(
            database
                .streaming_is_client_live(&gone, false)
                .await
                .as_deref(),
            Some(task.uuid.as_str()),
            "the missing record is claimed back, live"
        );
        match timeout(StdDuration::from_secs(2), rx.recv())
            .await
            .expect("the inbox is redelivered")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Message(msg),
                ..
            }) => assert_eq!(msg, stored),
            _ => panic!("expected the stored message to be redelivered"),
        }
        assert_eq!(
            database
                .streaming_is_client_live(&elsewhere, false)
                .await
                .as_deref(),
            Some("another-instance"),
            "a newer socket elsewhere keeps the DID"
        );
        assert!(rx_elsewhere.try_recv().is_err());
        assert!(
            database
                .streaming_is_client_live(&closed, true)
                .await
                .is_none(),
            "a closed socket is left to its deregistration"
        );
        assert!(clients.contains_key(&gone) && clients.contains_key(&elsewhere));
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());

        for (room, cut_short) in [(1, true), (5, false)] {
            let (tx, mut rx) = mpsc::channel(room);
            let resync = Arc::new(AtomicBool::new(false));
            let mut clients = HashMap::from([(
                did_hash.clone(),
                ClientEntry {
                    store_demoted: false,
                    tx,
                    session_id: "A".to_string(),
                    active: false,
                    registered_at: Instant::now(),
                    resync: resync.clone(),
                    churn_streak: 0,
                    kind: EntryKind::Direct,
                    slots: None,
                    wake_only: false,
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let (tx, mut rx) = mpsc::channel(5);
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                live: false,
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Keep every receiver alive: a live incumbent channel is a precondition
        // of the damper (see the dead-incumbent test below).
        let mut keepalive = Vec::new();

        let register = |session: &str, tx: mpsc::Sender<QueuedCommand>| StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                live: false,
                channel: tx,
                session_id: session.to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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
        let replay_in_progress: Arc<Redeliveries> = Arc::new(Redeliveries::default());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Incumbent deep in a churn streak, but its receiver is dropped — the
        // socket behind it is gone.
        let (dead_tx, dead_rx) = mpsc::channel(5);
        drop(dead_rx);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                store_demoted: false,
                tx: dead_tx,
                session_id: "ghost".to_string(),
                active: true,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: CHURN_REFUSE_STREAK * 10,
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
            },
        );

        let (tx, _rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                live: false,
                channel: tx,
                session_id: "live".to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind: EntryKind::Direct,
                slots: None,
                wake_only: false,
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
                live: false,
                channel: tx,
                session_id: session.to_string(),
                did: did.to_string(),
                resync: Arc::new(AtomicBool::new(false)),
                kind,
                slots: None,
                wake_only: false,
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
        let replay = Arc::new(Redeliveries::default());
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
        let replay = Arc::new(Redeliveries::default());
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
        let replay = Arc::new(Redeliveries::default());
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
        let channel = tx.downgrade();
        let (other_tx, _other_rx) = mpsc::channel::<QueuedCommand>(1);
        standby.insert(
            "h".into(),
            vec![ClientEntry {
                store_demoted: false,
                tx,
                session_id: "mux".into(),
                active: false,
                registered_at: Instant::now(),
                resync: Arc::new(AtomicBool::new(false)),
                churn_streak: 0,
                kind: EntryKind::Mux,
                slots: None,
                wake_only: false,
            }],
        );
        assert!(!remove_standby(&mut standby, "h", "someone-else", &channel));
        // Same session, another connection's queue.
        assert!(!remove_standby(
            &mut standby,
            "h",
            "mux",
            &other_tx.downgrade()
        ));
        assert!(remove_standby(&mut standby, "h", "mux", &channel));
        assert!(standby.is_empty());
    }

    #[tokio::test]
    async fn one_mux_connection_carries_many_dids_and_tags_each_frame() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let task = streaming_task();
        let replay = Arc::new(Redeliveries::default());
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

    // ─── review fixes (#113 #115 #118 #121 #124 #136) ─────────────────────

    /// A live entry for `did_hash`, its queue `tx`.
    fn live_entry(
        tx: mpsc::Sender<QueuedCommand>,
        session_id: &str,
        resync: Arc<AtomicBool>,
    ) -> ClientEntry {
        ClientEntry {
            store_demoted: false,
            tx,
            session_id: session_id.to_string(),
            active: false,
            registered_at: Instant::now(),
            resync,
            churn_streak: 0,
            kind: EntryKind::Direct,
            slots: None,
            wake_only: false,
        }
    }

    /// Wait until no redelivery runs for `did_hash`.
    async fn drained(replays: &Redeliveries, did_hash: &str) {
        timeout(StdDuration::from_secs(5), async {
            while replays.contains(did_hash) {
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("the redelivery finishes");
    }

    /// #113: the drain waits for the socket to make room instead of giving up
    /// on the first full queue, so an inbox far larger than the queue (and
    /// than one page) reaches the socket in full, in order, and nothing is
    /// stamped delivered until the socket reports it written.
    #[tokio::test]
    async fn a_redelivery_waits_for_room_and_pages_through_the_inbox() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:big-inbox");
        let count = REDELIVERY_PAGE + 25;
        for i in 0..count {
            database
                .store_message("s", &format!("m{i:03}"), &did_hash, None, 0, 1000)
                .await
                .unwrap();
        }
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        // The size of a real socket's queue.
        let (tx, mut rx) = mpsc::channel(WS_CHANNEL_SLOTS);
        let resync = Arc::new(AtomicBool::new(false));
        let mut clients = HashMap::from([(did_hash.clone(), live_entry(tx, "A", resync.clone()))]);
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replays,
            &did_hash,
            "A",
            true,
        )
        .await;

        let mut seen = Vec::new();
        while seen.len() < count {
            let cmd = timeout(StdDuration::from_secs(2), rx.recv())
                .await
                .expect("the drain keeps going as the socket reads")
                .expect("queue open");
            let report = cmd.report.expect("a redelivered frame carries its report");
            assert_eq!(report.stamp.as_deref(), Some(did_hash.as_str()));
            if let WebSocketCommands::Message(m) = cmd.cmd {
                seen.push(m);
            }
        }
        drained(&replays, &did_hash).await;
        let expected: Vec<String> = (0..count).map(|i| format!("m{i:03}")).collect();
        assert_eq!(seen, expected);
        assert!(!resync.load(Ordering::Relaxed), "nothing was left behind");
    }

    /// #113: a `Start` for a socket whose live delivery is already on does
    /// not drain the inbox again, so a client cannot re-dump it at will.
    #[tokio::test]
    async fn a_repeated_start_does_not_redeliver_again() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:repeat");
        database
            .store_message("s", "stored", &did_hash, None, 0, 1000)
            .await
            .unwrap();
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        let (tx, mut rx) = mpsc::channel(8);
        let mut clients = HashMap::from([(
            did_hash.clone(),
            live_entry(tx, "A", Arc::new(AtomicBool::new(false))),
        )]);
        for _ in 0..3 {
            task._handle_activation(
                &database,
                &mut clients,
                &mut HashMap::new(),
                &replays,
                &did_hash,
                "A",
                true,
            )
            .await;
            drained(&replays, &did_hash).await;
        }
        let mut frames = 0;
        while rx.try_recv().is_ok() {
            frames += 1;
        }
        assert_eq!(frames, 1, "one drain, on the first Start only");
    }

    /// #113: a socket that drains its inbox itself on any notification (raw
    /// TSP) is redelivered to with one wake-up, its resync: no stored message
    /// is fetched or queued for it.
    #[tokio::test]
    async fn a_socket_that_drains_itself_gets_one_wake_up() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:raw-tsp");
        for i in 0..5 {
            database
                .store_message("s", &format!("m{i}"), &did_hash, None, 0, 1000)
                .await
                .unwrap();
        }
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        let (tx, mut rx) = mpsc::channel(8);
        let resync = Arc::new(AtomicBool::new(false));
        let mut entry = live_entry(tx, "A", resync.clone());
        entry.wake_only = true;
        let mut clients = HashMap::from([(did_hash.clone(), entry)]);
        task._handle_activation(
            &database,
            &mut clients,
            &mut HashMap::new(),
            &replays,
            &did_hash,
            "A",
            true,
        )
        .await;
        assert!(resync.load(Ordering::Relaxed), "woken once");
        assert!(!replays.contains(&did_hash), "no drain was started");
        assert!(rx.try_recv().is_err(), "nothing was queued");
    }

    /// #118: a socket that replaces one whose redelivery is still running
    /// takes the drain over and gets the whole inbox, instead of the drain
    /// being skipped as a duplicate and running on to the closed socket.
    #[tokio::test]
    async fn a_replacing_socket_takes_over_a_running_redelivery() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:handover";
        let did_hash = digest(did);
        for i in 0..3 {
            database
                .store_message("s", &format!("m{i}"), &did_hash, None, 0, 1000)
                .await
                .unwrap();
        }
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        let mut standby = HashMap::new();
        // A's queue has room for one frame, and A never reads: its drain
        // waits for room.
        let (a_tx, _a_rx) = mpsc::channel(1);
        let mut clients = HashMap::from([(
            did_hash.clone(),
            live_entry(a_tx, "A", Arc::new(AtomicBool::new(false))),
        )]);
        task._handle_activation(
            &database,
            &mut clients,
            &mut standby,
            &replays,
            &did_hash,
            "A",
            true,
        )
        .await;
        assert!(replays.contains(&did_hash), "A's drain is running");

        let (b_tx, mut b_rx) = mpsc::channel(8);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replays,
            &reg(did, "B", b_tx, EntryKind::Direct),
        )
        .await;
        let mut seen = Vec::new();
        while seen.len() < 3 {
            match next_cmd(&mut b_rx).await.cmd {
                WebSocketCommands::Message(m) => seen.push(m),
                _ => panic!("expected a redelivered message"),
            }
        }
        assert_eq!(seen, ["m0", "m1", "m2"], "B gets the whole inbox");
        drained(&replays, &did_hash).await;
    }

    /// #115: a lagged subscription raises the resync of every live client,
    /// and the owed DID on a mux connection; a client with live delivery off
    /// collects by pickup anyway and is left alone.
    #[tokio::test]
    async fn a_lag_raises_resync_for_every_live_client() {
        use crate::mux::fair_queue::MuxSlots;
        let (tx, _rx) = mpsc::channel(1);
        let live = Arc::new(AtomicBool::new(false));
        let idle = Arc::new(AtomicBool::new(false));
        let member = Arc::new(AtomicBool::new(false));
        let slots = MuxSlots::new(64);
        let mut a = live_entry(tx.clone(), "A", live.clone());
        a.active = true;
        let b = live_entry(tx.clone(), "B", idle.clone());
        let mut m = live_entry(tx, "M", member.clone());
        m.active = true;
        m.kind = EntryKind::Mux;
        m.slots = Some(slots.clone());
        let clients = HashMap::from([
            ("a".to_string(), a),
            ("b".to_string(), b),
            ("m".to_string(), m),
        ]);
        raise_resync_all(&clients);
        assert!(live.load(Ordering::Relaxed));
        assert!(!idle.load(Ordering::Relaxed));
        assert!(member.load(Ordering::Relaxed));
        assert_eq!(slots.take_resync(), vec!["m".to_string()]);
    }

    /// #121: the connection that holds a DID's mux entry registering it again
    /// (an attach renewal) updates it in place: it is not told the member was
    /// superseded, no standby entry is left behind, and it stays live.
    #[tokio::test]
    async fn a_same_connection_re_registration_is_an_update_in_place() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:renewed";
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();
        let (tx, mut rx) = mpsc::channel(8);
        for _ in 0..2 {
            task._handle_registration(
                &database,
                &mut clients,
                &mut standby,
                &replays,
                &reg(did, "mux", tx.clone(), EntryKind::Mux),
            )
            .await;
            task._handle_activation(
                &database,
                &mut clients,
                &mut standby,
                &replays,
                &digest(did),
                "mux",
                true,
            )
            .await;
        }
        drained(&replays, &digest(did)).await;
        assert!(rx.try_recv().is_err(), "no superseded, no redelivery");
        assert!(standby.is_empty(), "no zombie standby entry");
        assert!(clients.get(&digest(did)).is_some_and(|e| e.active));
    }

    /// #136: a member change reaches a mux connection even when its queue is
    /// full: it is recorded on the connection's slots, in order.
    #[tokio::test]
    async fn a_member_change_is_not_lost_to_a_full_queue() {
        use crate::mux::fair_queue::MuxSlots;
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:busy-mux";
        let task = streaming_task();
        let replays = Arc::new(Redeliveries::default());
        let mut clients = HashMap::new();
        let mut standby = HashMap::new();
        let slots = MuxSlots::new(64);
        // A full queue.
        let (m_tx, _m_rx) = mpsc::channel(1);
        m_tx.try_send(QueuedCommand::for_test(None)).unwrap();
        let mut update = reg(did, "mux", m_tx, EntryKind::Mux);
        if let StreamingUpdateState::Register { slots: s, .. } = &mut update.state {
            *s = Some(slots.clone());
        }
        task._handle_registration(&database, &mut clients, &mut standby, &replays, &update)
            .await;
        let (d_tx, _d_rx) = mpsc::channel(8);
        task._handle_registration(
            &database,
            &mut clients,
            &mut standby,
            &replays,
            &reg(did, "direct", d_tx, EntryKind::Direct),
        )
        .await;
        assert_eq!(
            slots.take_member_changes(),
            vec![MemberChange::Superseded {
                did_hash: digest(did)
            }]
        );
    }

    /// #124: the sockets registered before a restart of the streaming task
    /// are kept, claimed back in the store (which the restart's clean start
    /// wiped), and redelivered what arrived while it was down.
    #[tokio::test]
    async fn a_restarted_streaming_task_claims_back_its_sockets() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:restart");
        database
            .store_message("s", "while-down", &did_hash, None, 0, 1000)
            .await
            .unwrap();
        let task = streaming_task();
        let (tx, mut rx) = mpsc::channel(8);
        let mut entry = live_entry(tx, "A", Arc::new(AtomicBool::new(false)));
        entry.active = true;
        let registered = Arc::new(Mutex::new(Registered::default()));
        registered
            .lock()
            .await
            .clients
            .insert(did_hash.clone(), entry);
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        let cmd_rx = Arc::new(Mutex::new(cmd_rx));

        let run = {
            let database = database.clone();
            let registered = registered.clone();
            tokio::spawn(async move {
                let mut rx = cmd_rx.lock().await;
                let mut registered = registered.lock().await;
                task.ws_streaming_task(
                    database,
                    &mut rx,
                    &mut registered,
                    Arc::new(Redeliveries::default()),
                )
                .await
            })
        };
        match next_cmd(&mut rx).await.cmd {
            WebSocketCommands::Message(m) => assert_eq!(m, "while-down"),
            _ => panic!("expected the stored message"),
        }
        assert!(
            database
                .streaming_is_client_live(&did_hash, true)
                .await
                .is_some(),
            "claimed back as live"
        );
        run.abort();
    }
}
