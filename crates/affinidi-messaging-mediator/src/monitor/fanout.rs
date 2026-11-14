//! Mux membership events across the instances of one mediator.
//!
//! A principal's mux connection lives on one instance, and its member
//! changes are emitted there ([`TrafficMonitor::emit_membership`]). Behind a
//! shared Redis, a membership subscriber may be connected to another
//! instance. This module carries the events between them over one pub/sub
//! channel per mediator (`StreamingStore::monitor_fanout_publish`):
//!
//! - **Only while someone listens.** An instance with an opted-in
//!   subscription announces it ([`Record::Listening`]) when one opens and
//!   every [`BEACON`] after; any instance that heard an announcement within
//!   [`LISTENER_TTL`] publishes its membership events. With no membership
//!   subscriber anywhere, the channel carries one query per instance start
//!   and nothing else. A starting instance asks ([`Record::Query`]) so that
//!   listeners announce at once rather than at their next beacon.
//! - **Never on the connection path.** `emit_membership` only `try_send`s
//!   into a bounded hand-off ([`HANDOFF_CAPACITY`]); the task here does the
//!   publishing. A full hand-off drops the event for the other instances and
//!   counts it (`monitor_fanout_dropped_total{cause="overflow"}`).
//! - **Once each.** A record carries its origin instance; the origin ignores
//!   its own, having put the event on its local bus already. A received
//!   event goes straight onto the local bus, never back out.
//! - **The subscriber's rules apply.** A received event is put on the same
//!   bus as local ones, so every subscription's membership filter, its
//!   non-administrator narrowing (made at subscribe) and its standing check
//!   apply to it unchanged.
//! - **Losses are visible to subscribers.** Events an instance could not
//!   hand over or publish are counted and announced in a [`Record::Lost`]
//!   once publishing works again; a receiver that lagged on the channel
//!   counts what it missed. Either way the count is added to the
//!   `membershipDropped` of every opted-in subscription on the receiving
//!   instance (an upper bound: the lost events' filters cannot be known).
//! - **Redis down degrades to local only.** A failed publish is counted
//!   (`cause="publish"`) and logged once per outage; a lost subscription
//!   ends the task with an error, so the supervisor restarts it and readiness
//!   shows it degraded meanwhile (R6.2). While it is down nothing is offered
//!   (no announcement is current), local events are unaffected, and each
//!   opted-in batch says so under `ext["com.affinidi.mediator"]` with
//!   `membershipCoverage: "thisInstance"` (event 0.3 allows a batch-level
//!   `ext`; it has no member of its own for this).
//!
//! The events carry no instance tag: `messaging/monitor/event` 0.3's
//! `MonitorMembershipEvent` admits no further members.
//!
//! Traffic events are not fanned out: each instance's subscribers see that
//! instance's traffic, as before. They could ride the same channel and
//! announcement scheme with a record kind of their own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use affinidi_messaging_mediator_common::time::unix_timestamp_millis;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, broadcast::error::RecvError, mpsc};
use tracing::{debug, info, warn};

use super::{MembershipChange, MembershipEvent, TrafficMonitor};
use crate::SharedData;
use crate::common::metrics::names::{MONITOR_FANOUT_DROPPED_TOTAL, MONITOR_FANOUT_RECEIVED_TOTAL};

/// Events waiting for the publishing task. Past this, they are dropped (for
/// the other instances only) and counted.
pub(crate) const HANDOFF_CAPACITY: usize = 1_024;
/// How often an instance with a membership subscriber says so.
const BEACON: Duration = Duration::from_secs(10);
/// How long one announcement keeps another instance publishing: a few
/// beacons, so one lost announcement does not stop the events.
const LISTENER_TTL: Duration = Duration::from_secs(35);

/// The fan-out state a [`TrafficMonitor`] holds.
#[derive(Default)]
pub(crate) struct Fanout {
    /// The hand-off to the publishing task, while it runs.
    out: std::sync::RwLock<Option<mpsc::Sender<Arc<MembershipEvent>>>>,
    /// Until when (Unix ms) another instance is known to have a membership
    /// subscriber. 0 while the task is not running.
    remote_until_ms: AtomicU64,
    /// A membership subscription opened here: announce it now.
    announce: Notify,
    /// Membership events this instance owes the others but could not hand
    /// over (overflow) or publish: reported in the next [`Record::Lost`].
    unsent: AtomicU64,
    /// The store spans processes, so a fan-out task should be running.
    expected: AtomicBool,
    /// The fan-out task is running (subscribed, hand-off installed).
    live: AtomicBool,
}

fn now_ms() -> u64 {
    unix_timestamp_millis() as u64
}

impl Fanout {
    /// Whether another instance wants this one's membership events.
    pub(crate) fn wanted(&self) -> bool {
        now_ms() < self.remote_until_ms.load(Ordering::Relaxed)
    }

    /// Hand `event` to the publishing task without waiting.
    pub(crate) fn offer(&self, event: Arc<MembershipEvent>) {
        let out = self.out.read().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = out.as_ref() else {
            return;
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
            metrics::counter!(MONITOR_FANOUT_DROPPED_TOTAL, "cause" => "overflow").increment(1);
            self.unsent.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether this instance's subscribers see only this instance's
    /// membership events right now: the store spans processes but the
    /// fan-out task is not running (it lost its subscription, or has not
    /// opened it yet).
    pub(crate) fn degraded(&self) -> bool {
        self.expected.load(Ordering::Relaxed) && !self.live.load(Ordering::Relaxed)
    }

    /// A subscription here opted in to membership events.
    pub(crate) fn listening_changed(&self) {
        // A stored permit: an opening between two waits is not lost.
        self.announce.notify_one();
    }

    fn heard_listener(&self) {
        let until = now_ms() + LISTENER_TTL.as_millis() as u64;
        self.remote_until_ms.fetch_max(until, Ordering::Relaxed);
    }
}

/// Installs the hand-off for as long as the task runs, and takes it away
/// (forgetting every announcement) however the task ends.
struct Installed<'a>(&'a Fanout);

impl<'a> Installed<'a> {
    fn new(fanout: &'a Fanout, tx: mpsc::Sender<Arc<MembershipEvent>>) -> Self {
        *fanout.out.write().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        fanout.live.store(true, Ordering::Relaxed);
        Installed(fanout)
    }
}

impl Drop for Installed<'_> {
    fn drop(&mut self) {
        self.0.live.store(false, Ordering::Relaxed);
        self.0.remote_until_ms.store(0, Ordering::Relaxed);
        *self.0.out.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// One record on the channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Record {
    /// `origin` has a membership subscriber.
    Listening { origin: String },
    /// `origin` just started: any instance with a subscriber, say so.
    Query { origin: String },
    /// A membership event emitted on `origin`.
    Membership { origin: String, event: WireEvent },
    /// `origin` emitted `count` membership events it could not publish.
    Lost { origin: String, count: u64 },
}

/// A [`MembershipEvent`] on the channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireEvent {
    at: DateTime<Utc>,
    change: String,
    principal: String,
    member: String,
    wire: String,
    source: String,
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

const WIRES: &[&str] = &["didcomm", "tsp"];
const SOURCES: &[&str] = &["grant", "attach"];
/// `MemberChangeReason` (mux/_shared 0.1).
const REASONS: &[&str] = &[
    "connect",
    "grant",
    "attach",
    "reactivated",
    "revokedByMember",
    "revokedByPrincipal",
    "epochBumped",
    "suspendedUnknownKey",
    "keyRotated",
    "expired",
    "accountBlocked",
    "superseded",
    "admin",
    "detachRequested",
    "accountRemoved",
    "resolutionFailed",
    "connectionFull",
];

fn known(set: &[&'static str], value: &str) -> Option<&'static str> {
    set.iter().copied().find(|v| *v == value)
}

impl From<&MembershipEvent> for WireEvent {
    fn from(e: &MembershipEvent) -> Self {
        WireEvent {
            at: e.at,
            change: e.change.as_str().to_string(),
            principal: e.principal.clone(),
            member: e.member.clone(),
            wire: e.wire.to_string(),
            source: e.source.to_string(),
            reason: e.reason.to_string(),
            session_id: e.session_id.clone(),
        }
    }
}

impl WireEvent {
    /// The event, if every enumerated value is one this instance knows: an
    /// unknown one would reach a subscriber as an event 0.3 does not allow.
    fn into_event(self) -> Option<MembershipEvent> {
        Some(MembershipEvent {
            at: self.at,
            change: match self.change.as_str() {
                "attached" => MembershipChange::Attached,
                "detached" => MembershipChange::Detached,
                _ => return None,
            },
            principal: self.principal,
            member: self.member,
            wire: known(WIRES, &self.wire)?,
            source: known(SOURCES, &self.source)?,
            reason: known(REASONS, &self.reason)?,
            session_id: self.session_id,
        })
    }
}

impl TrafficMonitor {
    /// Handle one record from the channel; `me` is this instance. Returns
    /// whether this instance should announce its subscribers now.
    fn receive(&self, me: &str, payload: &str) -> bool {
        let record = match serde_json::from_str::<Record>(payload) {
            Ok(r) => r,
            // A newer instance's record kind, or garbage: not ours to read.
            Err(e) => {
                debug!("monitor fan-out: record not read: {e}");
                return false;
            }
        };
        match record {
            Record::Listening { origin }
            | Record::Query { origin }
            | Record::Membership { origin, .. }
            | Record::Lost { origin, .. }
                if origin == me =>
            {
                false
            }
            Record::Listening { .. } => {
                self.fanout.heard_listener();
                false
            }
            Record::Query { .. } => self.has_membership_subscribers(),
            Record::Lost { count, .. } => {
                self.membership_lost(count);
                false
            }
            Record::Membership { event, .. } => {
                match event.into_event() {
                    Some(event) => {
                        metrics::counter!(MONITOR_FANOUT_RECEIVED_TOTAL).increment(1);
                        self.inject_membership(event);
                    }
                    None => debug!("monitor fan-out: membership event with an unknown value"),
                }
                false
            }
        }
    }
}

/// Publishes records, logging an outage once rather than per record.
struct Publisher<'a> {
    state: &'a SharedData,
    scope: String,
    failing: bool,
}

impl Publisher<'_> {
    async fn publish(&mut self, record: &Record) -> bool {
        let payload = match serde_json::to_string(record) {
            Ok(p) => p,
            Err(e) => {
                warn!("monitor fan-out: record not encoded: {e}");
                return false;
            }
        };
        match self
            .state
            .database
            .monitor_fanout_publish(&self.scope, &payload)
            .await
        {
            Ok(()) => {
                if std::mem::take(&mut self.failing) {
                    info!("monitor fan-out: publishing to the other instances again");
                }
                true
            }
            Err(e) => {
                if !std::mem::replace(&mut self.failing, true) {
                    warn!(
                        "monitor fan-out: publish failed; other instances' monitor subscribers \
                         miss this instance's membership events until it recovers (local ones \
                         are unaffected): {e}"
                    );
                }
                false
            }
        }
    }
}

/// Tell the other instances' subscribers how many of this instance's
/// membership events they missed, so it shows in their `membershipDropped`.
/// Kept for the next try if the publish fails.
async fn report_unsent(monitor: &TrafficMonitor, publisher: &mut Publisher<'_>, me: &str) {
    let count = monitor.fanout.unsent.swap(0, Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let record = Record::Lost {
        origin: me.to_string(),
        count,
    };
    if !publisher.publish(&record).await {
        monitor.fanout.unsent.fetch_add(count, Ordering::Relaxed);
    }
}

/// The fan-out task: run under the task supervisor while mux is enabled and
/// the store spans processes. Returns `Err` only when the subscription
/// cannot be opened or is lost, so the supervisor restarts it and readiness
/// shows it degraded; local membership events go on meanwhile.
pub async fn run(state: SharedData) -> Result<(), String> {
    // Degraded until subscribed (and again whenever this returns).
    state.monitor.fanout.expected.store(true, Ordering::Relaxed);
    let scope =
        affinidi_messaging_mediator_common::did_identity::did_hash(&state.config.mediator_did);
    let Some(mut inbound) = state
        .database
        .monitor_fanout_subscribe(&scope)
        .await
        .map_err(|e| format!("monitor fan-out subscription failed: {e}"))?
    else {
        debug!("store is single-process; no monitor events to share between instances");
        state
            .monitor
            .fanout
            .expected
            .store(false, Ordering::Relaxed);
        state.shutdown_token.cancelled().await;
        return Ok(());
    };
    let monitor = state.monitor.clone();
    let me = state.config.streaming_uuid.clone();
    let (tx, mut out) = mpsc::channel(HANDOFF_CAPACITY);
    let _installed = Installed::new(&monitor.fanout, tx);
    let mut publisher = Publisher {
        state: &state,
        scope,
        failing: false,
    };
    info!("sharing mux membership monitor events with the other mediator instances");

    // Announcements made before this subscription were not heard.
    publisher
        .publish(&Record::Query { origin: me.clone() })
        .await;
    let mut beacon = tokio::time::interval(BEACON);
    beacon.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let announce = tokio::select! {
            _ = state.shutdown_token.cancelled() => return Ok(()),
            received = inbound.recv() => match received {
                Ok(payload) => monitor.receive(&me, &payload),
                Err(RecvError::Lagged(missed)) => {
                    warn!(missed, "monitor fan-out fell behind; other instances' membership events were missed");
                    metrics::counter!(MONITOR_FANOUT_DROPPED_TOTAL, "cause" => "lagged")
                        .increment(missed);
                    // Records, not all of them events: an upper bound, as a
                    // subscription's own lag on the local bus is counted.
                    monitor.membership_lost(missed);
                    false
                }
                Err(RecvError::Closed) => {
                    return Err("monitor fan-out subscription lost".into());
                }
            },
            Some(event) = out.recv() => {
                let record = Record::Membership {
                    origin: me.clone(),
                    event: WireEvent::from(event.as_ref()),
                };
                if !publisher.publish(&record).await {
                    metrics::counter!(MONITOR_FANOUT_DROPPED_TOTAL, "cause" => "publish")
                        .increment(1);
                    monitor.fanout.unsent.fetch_add(1, Ordering::Relaxed);
                }
                report_unsent(&monitor, &mut publisher, &me).await;
                false
            }
            _ = beacon.tick() => {
                report_unsent(&monitor, &mut publisher, &me).await;
                monitor.has_membership_subscribers()
            }
            _ = monitor.fanout.announce.notified() => monitor.has_membership_subscribers(),
        };
        if announce {
            publisher
                .publish(&Record::Listening { origin: me.clone() })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> MembershipEvent {
        MembershipEvent {
            at: Utc::now(),
            change: MembershipChange::Detached,
            principal: "p".into(),
            member: "m".into(),
            wire: "tsp",
            source: "attach",
            reason: "revokedByPrincipal",
            session_id: Some("s".into()),
        }
    }

    fn record(origin: &str) -> String {
        serde_json::to_string(&Record::Membership {
            origin: origin.into(),
            event: WireEvent::from(&event()),
        })
        .unwrap()
    }

    #[test]
    fn an_event_survives_the_channel() {
        let e = event();
        let wire: WireEvent =
            serde_json::from_str(&serde_json::to_string(&WireEvent::from(&e)).unwrap()).unwrap();
        let back = wire.into_event().expect("known values");
        assert_eq!(back.to_json(), e.to_json());
    }

    #[test]
    fn an_unknown_value_is_not_passed_on() {
        let mut wire = WireEvent::from(&event());
        wire.reason = "somethingNew".into();
        assert!(wire.into_event().is_none());
    }

    #[test]
    fn a_remote_event_reaches_the_local_bus_and_an_own_one_does_not() {
        let monitor = TrafficMonitor::new();
        let mut rx = monitor.tap_membership();
        assert!(!monitor.receive("me", &record("me")), "own record ignored");
        assert!(rx.try_recv().is_err());
        monitor.receive("me", &record("other"));
        assert_eq!(rx.try_recv().unwrap().member, "m");
        assert!(!monitor.fanout.wanted(), "an event is not an announcement");
    }

    #[test]
    fn events_are_offered_only_while_another_instance_listens() {
        let monitor = TrafficMonitor::new();
        let (tx, mut out) = mpsc::channel(2);
        let _installed = Installed::new(&monitor.fanout, tx);
        // Nobody anywhere: not even built.
        monitor.emit_membership(|| panic!("nobody listens"));

        let own = serde_json::to_string(&Record::Listening {
            origin: "me".into(),
        })
        .unwrap();
        monitor.receive("me", &own);
        assert!(!monitor.fanout.wanted(), "this instance's own announcement");

        let other = serde_json::to_string(&Record::Listening { origin: "b".into() }).unwrap();
        monitor.receive("me", &other);
        assert!(monitor.fanout.wanted());
        monitor.emit_membership(event);
        assert_eq!(
            out.try_recv().unwrap().member,
            "m",
            "offered for publishing"
        );

        // A full hand-off drops rather than waits.
        monitor.emit_membership(event);
        monitor.emit_membership(event);
        monitor.emit_membership(event);
        assert!(out.try_recv().is_ok() && out.try_recv().is_ok());
        assert!(out.try_recv().is_err(), "the overflow was dropped");
    }

    #[test]
    fn the_task_ending_forgets_every_listener() {
        let monitor = TrafficMonitor::new();
        let (tx, _out) = mpsc::channel(1);
        {
            let _installed = Installed::new(&monitor.fanout, tx);
            monitor.fanout.heard_listener();
            assert!(monitor.fanout.wanted());
        }
        assert!(!monitor.fanout.wanted());
        monitor.emit_membership(|| panic!("nobody listens"));
    }

    #[test]
    fn unsent_events_are_counted_and_lost_reports_ignore_their_origin() {
        let monitor = TrafficMonitor::new();
        let (tx, _out) = mpsc::channel(1);
        let _installed = Installed::new(&monitor.fanout, tx);
        monitor.fanout.heard_listener();
        monitor.emit_membership(event);
        monitor.emit_membership(event);
        monitor.emit_membership(event);
        assert_eq!(
            monitor.fanout.unsent.load(Ordering::Relaxed),
            2,
            "overflow is owed"
        );

        let own = serde_json::to_string(&Record::Lost {
            origin: "me".into(),
            count: 5,
        })
        .unwrap();
        assert!(!monitor.receive("me", &own));
    }

    #[test]
    fn degraded_only_while_the_expected_task_is_down() {
        let monitor = TrafficMonitor::new();
        assert!(
            !monitor.fanout.degraded(),
            "single-process: nothing expected"
        );
        monitor.fanout.expected.store(true, Ordering::Relaxed);
        assert!(monitor.fanout.degraded());
        let (tx, _out) = mpsc::channel(1);
        {
            let _installed = Installed::new(&monitor.fanout, tx);
            assert!(!monitor.fanout.degraded());
        }
        assert!(monitor.fanout.degraded(), "the task ended");
    }

    #[test]
    fn a_query_is_answered_only_with_a_subscriber_here() {
        let monitor = TrafficMonitor::new();
        let q = serde_json::to_string(&Record::Query { origin: "b".into() }).unwrap();
        assert!(!monitor.receive("me", &q));
    }
}
