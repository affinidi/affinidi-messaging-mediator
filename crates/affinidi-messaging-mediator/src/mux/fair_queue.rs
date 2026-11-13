//! Per-member fair queuing on a mux connection (design §7.2, "Back-pressure",
//! implementation step 3).
//!
//! A mux connection carries live delivery for many DIDs over one socket, and
//! every member's streaming entry feeds the socket's one send queue. Left as a
//! plain FIFO, one busy member fills that queue and every other member's
//! pushes are dropped behind it. Two pieces stop that:
//!
//! - [`MuxSlots`], on the **producer** side. Every frame queued for a DID on
//!   the connection holds one of that DID's slots ([`SlotCredit`]) until the
//!   socket loop takes it, at most [`MEMBER_SLOTS`] per DID and at most
//!   `limits.mux.max_channel_slots` in all. So a connection holds at most
//!   `min(8 × DIDs, max_channel_slots)` frames, and a member whose own share
//!   is full has *its* push dropped and *its* resync raised; the others keep
//!   their room. The decision is made where `try_queue` makes it today, so
//!   "queued" keeps meaning exactly what it means on a direct socket. (The
//!   `delivered` monitor event is not emitted on queueing: the socket loop
//!   emits it once the frame is written, R1.1.)
//! - [`FairOrder`], on the **writer** side. The socket loop moves what is in
//!   the channel into one lane per DID and writes round-robin across the lanes
//!   with something pending, so a member's frame waits behind at most one
//!   frame of each other busy DID rather than behind a busy member's whole
//!   share. Control commands (untagged: member changes, close) have a lane of
//!   their own that is always written first.
//!
//! Neither piece writes anything, acknowledges anything or deletes anything:
//! the socket loop still writes one frame at a time, after its `live_frame`
//! check, exactly as before. Direct sockets use neither and are unchanged.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::tasks::websocket_streaming::{QueuedCommand, WS_CHANNEL_SLOTS};

/// Frames one DID may have queued on a mux connection: the depth a direct
/// socket has, so a member is never worse off than it would be on its own.
pub const MEMBER_SLOTS: usize = WS_CHANNEL_SLOTS;

/// Channel capacity kept free of member frames for control commands, which
/// hold no slot. Member frames can never fill it (their slots are capped
/// below the channel's capacity), so a `MemberChange` or `Close` always fits.
const CONTROL_HEADROOM: usize = WS_CHANNEL_SLOTS;

/// Why a frame could not take a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRefusal {
    /// This DID already holds its [`MEMBER_SLOTS`]: it is the busy one, and
    /// fairness is what refused it.
    Member,
    /// The connection holds `max_channel_slots` frames across its DIDs.
    Connection,
}

#[derive(Default)]
struct SlotsInner {
    held: HashMap<String, usize>,
    total: usize,
    /// DIDs owed a resync: a push for them was dropped.
    resync: HashSet<String>,
}

/// Slot accounting for one mux connection, shared by its streaming entries
/// (producers) and its socket loop.
pub struct MuxSlots {
    inner: Mutex<SlotsInner>,
    max_total: usize,
}

/// One queued frame's slot. Released on drop, so the queue item owns it, the
/// same way it owns its byte permit: the slot comes back exactly when the
/// socket loop has taken the frame (written it, or dropped it for a detached
/// member).
pub struct SlotCredit {
    slots: Arc<MuxSlots>,
    did_hash: String,
}

impl Drop for SlotCredit {
    fn drop(&mut self) {
        let mut inner = self.slots.lock();
        inner.total = inner.total.saturating_sub(1);
        if let Some(n) = inner.held.get_mut(&self.did_hash) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.held.remove(&self.did_hash);
            }
        }
    }
}

impl MuxSlots {
    /// `max_total` is `limits.mux.max_channel_slots`; never below one DID's
    /// share, or a single member could not use its own slots.
    pub fn new(max_total: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(SlotsInner::default()),
            max_total: max_total.max(MEMBER_SLOTS),
        })
    }

    /// Capacity of the connection's channel: every slot, plus room that only
    /// control commands can use.
    pub fn channel_capacity(&self) -> usize {
        self.max_total + CONTROL_HEADROOM
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotsInner> {
        // The critical sections cannot panic part-way; a poisoned lock still
        // holds consistent counts.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take one of `did_hash`'s slots, without blocking.
    pub fn try_acquire(self: &Arc<Self>, did_hash: &str) -> Result<SlotCredit, SlotRefusal> {
        let mut inner = self.lock();
        let held = inner.held.get(did_hash).copied().unwrap_or(0);
        if held >= MEMBER_SLOTS {
            return Err(SlotRefusal::Member);
        }
        if inner.total >= self.max_total {
            return Err(SlotRefusal::Connection);
        }
        inner.total += 1;
        *inner.held.entry(did_hash.to_string()).or_insert(0) += 1;
        Ok(SlotCredit {
            slots: self.clone(),
            did_hash: did_hash.to_string(),
        })
    }

    /// Record that `did_hash` is owed a resync. Called *before* the socket's
    /// shared wake-up flag is raised, so a socket that sees the flag finds the
    /// DID here.
    pub fn raise_resync(&self, did_hash: &str) {
        self.lock().resync.insert(did_hash.to_string());
    }

    /// The DIDs owed a resync, clearing them.
    pub fn take_resync(&self) -> Vec<String> {
        self.lock().resync.drain().collect()
    }

    /// Slots `did_hash` holds now. Diagnostics and tests.
    pub fn held(&self, did_hash: &str) -> usize {
        self.lock().held.get(did_hash).copied().unwrap_or(0)
    }
}

/// Writer-side ordering for a mux connection's queue: a control lane, written
/// first, and one lane per DID, written round-robin.
pub struct FairOrder<T> {
    control: VecDeque<T>,
    lanes: HashMap<String, VecDeque<T>>,
    /// DIDs with something pending, in the order they are next served.
    ring: VecDeque<String>,
}

impl<T> Default for FairOrder<T> {
    fn default() -> Self {
        Self {
            control: VecDeque::new(),
            lanes: HashMap::new(),
            ring: VecDeque::new(),
        }
    }
}

impl<T> FairOrder<T> {
    /// Queue `item` in `lane` (`None` for a control command).
    pub fn push(&mut self, lane: Option<&str>, item: T) {
        let Some(did) = lane else {
            self.control.push_back(item);
            return;
        };
        match self.lanes.get_mut(did) {
            Some(q) => q.push_back(item),
            None => {
                self.lanes.insert(did.to_string(), VecDeque::from([item]));
                self.ring.push_back(did.to_string());
            }
        }
    }

    /// The next item to write: any control command, else the head of the next
    /// lane in turn, which then goes to the back of the ring if it has more.
    pub fn pop(&mut self) -> Option<T> {
        if let Some(item) = self.control.pop_front() {
            return Some(item);
        }
        let did = self.ring.pop_front()?;
        let q = self.lanes.get_mut(&did)?;
        let item = q.pop_front();
        if q.is_empty() {
            self.lanes.remove(&did);
        } else {
            self.ring.push_back(did);
        }
        item
    }

    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.ring.is_empty()
    }
}

impl FairOrder<QueuedCommand> {
    fn take_ready(&mut self, rx: &mut mpsc::Receiver<QueuedCommand>) {
        while let Ok(item) = rx.try_recv() {
            let lane = item.did_hash.clone();
            self.push(lane.as_deref(), item);
        }
    }

    /// The next command for the socket loop to handle, in fair order.
    ///
    /// Moves everything already in the channel into the lanes first, so a
    /// frame that arrived behind a burst is ordered against it rather than
    /// after it. Cancel-safe for `select!`: it only awaits `rx.recv()`, and
    /// anything taken off the channel before that lives in `self`.
    pub async fn next(&mut self, rx: &mut mpsc::Receiver<QueuedCommand>) -> Option<QueuedCommand> {
        self.take_ready(rx);
        if let Some(item) = self.pop() {
            return Some(item);
        }
        let first = rx.recv().await?;
        let lane = first.did_hash.clone();
        self.push(lane.as_deref(), first);
        self.take_ready(rx);
        self.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_holds_at_most_its_share() {
        let slots = MuxSlots::new(512);
        let mut held: Vec<_> = (0..MEMBER_SLOTS)
            .map(|_| slots.try_acquire("busy").expect("within its share"))
            .collect();
        assert_eq!(
            slots.try_acquire("busy").err(),
            Some(SlotRefusal::Member),
            "the busy member is refused past its share"
        );
        // Others are unaffected by the busy member.
        let quiet = slots.try_acquire("quiet").expect("another member has room");
        assert_eq!(slots.held("busy"), MEMBER_SLOTS);
        assert_eq!(slots.held("quiet"), 1);

        // Taking a frame off the queue gives its slot back.
        drop(held.pop());
        assert_eq!(slots.held("busy"), MEMBER_SLOTS - 1);
        assert!(slots.try_acquire("busy").is_ok());
        drop(quiet);
        assert_eq!(slots.held("quiet"), 0);
    }

    #[test]
    fn the_connection_total_is_capped() {
        // Two members' worth of slots.
        let slots = MuxSlots::new(2 * MEMBER_SLOTS);
        let _a: Vec<_> = (0..MEMBER_SLOTS)
            .map(|_| slots.try_acquire("a").unwrap())
            .collect();
        let _b: Vec<_> = (0..MEMBER_SLOTS)
            .map(|_| slots.try_acquire("b").unwrap())
            .collect();
        assert_eq!(slots.try_acquire("c").err(), Some(SlotRefusal::Connection));
    }

    #[test]
    fn the_total_is_never_below_one_share() {
        let slots = MuxSlots::new(0);
        for _ in 0..MEMBER_SLOTS {
            std::mem::forget(slots.try_acquire("a").expect("one share fits"));
        }
        assert!(slots.channel_capacity() > MEMBER_SLOTS);
    }

    #[test]
    fn resync_is_per_member_and_taken_once() {
        let slots = MuxSlots::new(64);
        slots.raise_resync("a");
        slots.raise_resync("a");
        slots.raise_resync("b");
        let mut owed = slots.take_resync();
        owed.sort();
        assert_eq!(owed, vec!["a".to_string(), "b".to_string()]);
        assert!(slots.take_resync().is_empty());
    }

    #[test]
    fn lanes_are_served_round_robin() {
        let mut q = FairOrder::default();
        for i in 0..5 {
            q.push(Some("busy"), format!("busy-{i}"));
        }
        q.push(Some("quiet"), "quiet-0".to_string());
        q.push(Some("other"), "other-0".to_string());
        let order: Vec<String> = std::iter::from_fn(|| q.pop()).collect();
        assert_eq!(
            order,
            [
                "busy-0", "quiet-0", "other-0", "busy-1", "busy-2", "busy-3", "busy-4"
            ]
        );
        assert!(q.is_empty());
    }

    #[test]
    fn a_late_arrival_waits_behind_one_frame_not_a_backlog() {
        let mut q = FairOrder::default();
        for i in 0..8 {
            q.push(Some("busy"), format!("busy-{i}"));
        }
        assert_eq!(q.pop().as_deref(), Some("busy-0"));
        q.push(Some("quiet"), "quiet-0".to_string());
        assert_eq!(q.pop().as_deref(), Some("busy-1"));
        assert_eq!(
            q.pop().as_deref(),
            Some("quiet-0"),
            "the quiet member is served next, ahead of the busy backlog"
        );
    }

    #[test]
    fn control_is_never_behind_members() {
        let mut q = FairOrder::default();
        q.push(Some("a"), "a-0");
        q.push(Some("b"), "b-0");
        q.push(None, "close");
        assert_eq!(q.pop(), Some("close"));
        q.push(Some("a"), "a-1");
        q.push(None, "member-change");
        assert_eq!(q.pop(), Some("member-change"));
        assert_eq!(q.pop(), Some("a-0"));
    }

    #[test]
    fn order_within_a_lane_is_kept() {
        let mut q = FairOrder::default();
        for i in 0..3 {
            q.push(Some("a"), i);
            q.push(Some("b"), 10 + i);
        }
        let order: Vec<i32> = std::iter::from_fn(|| q.pop()).collect();
        assert_eq!(order, [0, 10, 1, 11, 2, 12]);
    }

    #[tokio::test]
    async fn next_drains_the_channel_into_lanes_before_choosing() {
        let (tx, mut rx) = mpsc::channel(32);
        for _ in 0..4 {
            tx.try_send(QueuedCommand::for_test(Some("busy"))).unwrap();
        }
        tx.try_send(QueuedCommand::for_test(Some("quiet"))).unwrap();
        let mut q = FairOrder::default();
        let first = q.next(&mut rx).await.unwrap();
        let second = q.next(&mut rx).await.unwrap();
        assert_eq!(first.did_hash.as_deref(), Some("busy"));
        assert_eq!(
            second.did_hash.as_deref(),
            Some("quiet"),
            "the quiet member's frame is taken ahead of the busy backlog"
        );
        drop(tx);
        let mut rest = 0;
        while q.next(&mut rx).await.is_some() {
            rest += 1;
        }
        assert_eq!(
            rest, 3,
            "nothing is lost, and the end of the channel ends it"
        );
    }
}
