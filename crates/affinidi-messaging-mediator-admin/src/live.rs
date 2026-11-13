//! The console's live stream, and the traffic-monitor feeds read from it.
//!
//! One task owns the connection's live stream (R1.7): it is the only
//! `live_stream_next` reader, and it routes each `messaging/monitor/event`
//! batch to the feed its subscription belongs to. Request/response calls are
//! unaffected — the SDK hands a reply to the call waiting on it before any
//! `next` reader sees it. Anything else pushed to the console (it is not a
//! mail client) is left in the queue, untouched.
//!
//! Feeds subscribe with `messaging/monitor/subscribe` 0.2, which can add mux
//! membership events, and read every batch as `messaging/monitor/event` 0.3.
//! A mediator that predates 0.2 is asked at 0.1 instead, for traffic only;
//! its batches are read as 0.3 too, with no membership in them.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::trust_tasks::{
    MonitorSubscription, decode_monitor_event_v0_3,
};
use affinidi_messaging_sdk::tasks::messaging::monitor;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::error::{ConsoleError, Result};

/// A monitor filter (DIDs, directions, stages, protocols, channels, message
/// type prefixes, failures only).
pub type MonitorFilter = monitor::subscribe::v0_2::MonitorFilter;
/// Which mux membership changes a feed reports (DIDs, attached or detached,
/// grant or attach, wire). An empty filter selects every change the session
/// may see.
pub type MembershipFilter = monitor::subscribe::v0_2::MembershipFilter;
/// One observed step in a message's life.
pub type MonitorEvent = monitor::event::v0_3::MonitorEvent;
/// A member DID attached to or detached from a principal's mux connection.
pub type MembershipEvent = monitor::event::v0_3::MonitorMembershipEvent;

/// Lease requested for a monitor subscription; the feed renews well before it
/// lapses.
const LEASE_SECONDS: u32 = 300;
/// Renew this long before expiry.
const RENEW_MARGIN: Duration = Duration::from_secs(60);
/// First wait before retrying a renewal that failed in transit; it doubles.
const RENEW_RETRY: Duration = Duration::from_secs(2);
/// Longest wait between renewal retries.
const RENEW_RETRY_MAX: Duration = Duration::from_secs(15);
/// Batches buffered per feed before the oldest are dropped (and counted).
const FEED_BUFFER: usize = 64;

/// What a monitor feed yields.
#[derive(Debug, Clone)]
pub enum MonitorUpdate {
    /// A batch of events, and how many the mediator dropped since the last
    /// one (rate ceiling, or this console briefly offline).
    Events {
        events: Vec<MonitorEvent>,
        dropped: u64,
    },
    /// Mux membership changes from a batch, on a feed opened with a
    /// membership filter, and how many of them the mediator dropped since the
    /// last batch. Comes after the same batch's [`MonitorUpdate::Events`].
    Membership {
        events: Vec<MembershipEvent>,
        dropped: u64,
    },
    /// Batches were lost in transit: `missing` sequence numbers never arrived.
    Gap { missing: u64 },
    /// An empty batch: the tap is alive and nothing matched.
    Heartbeat,
    /// The subscription ended — lease renewal failed, or it was cancelled.
    Ended(String),
}

type Payload = monitor::event::v0_3::Payload;

/// The `monitor/subscribe` version a feed was opened with. Its renewals use
/// the same one, so its batches keep their shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubscribeVersion {
    /// 0.2: traffic and, opted in, mux membership.
    V0_2,
    /// 0.1, for a mediator that predates 0.2: traffic only.
    V0_1,
}

/// What the mediator granted, at either version.
struct Granted {
    id: String,
    expires_at: DateTime<Utc>,
    filter: MonitorFilter,
    membership: Option<MembershipFilter>,
}

/// Whether `e` is the mediator saying it doesn't serve the request's type.
fn is_unsupported_type(e: &ATMError) -> bool {
    matches!(
        e,
        ATMError::ProblemReport(code, ..) if code.ends_with("protocol.trust_task.unsupported")
    )
}

/// Open (or, with `renew`, renew and re-filter) a subscription at `version`.
async fn subscribe(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    version: SubscribeVersion,
    filter: &MonitorFilter,
    membership: Option<&MembershipFilter>,
    renew: Option<&str>,
) -> std::result::Result<Granted, ATMError> {
    match version {
        SubscribeVersion::V0_2 => {
            let mut request = MonitorSubscription::new()
                .filter(filter.clone())
                .lease_seconds(LEASE_SECONDS);
            if let Some(m) = membership {
                request = request.membership(m.clone());
            }
            if let Some(id) = renew {
                request = request.renew(id);
            }
            let granted = atm
                .trust_tasks()
                .monitor_subscribe_with(profile, &request)
                .await?;
            Ok(Granted {
                id: granted.subscription_id.to_string(),
                expires_at: granted.expires_at,
                filter: granted.filter,
                membership: granted.membership,
            })
        }
        SubscribeVersion::V0_1 => subscribe_v0_1(atm, profile, filter, renew).await,
    }
}

/// `monitor/subscribe` 0.1, for a mediator that predates 0.2. The SDK marks
/// the 0.1 types deprecated (superseded by 0.2), but they are what such a
/// mediator speaks, so this one fallback uses them on purpose.
#[allow(deprecated)]
async fn subscribe_v0_1(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    filter: &MonitorFilter,
    renew: Option<&str>,
) -> std::result::Result<Granted, ATMError> {
    // 0.2's traffic filter is 0.1's: the same members and shapes.
    let granted = atm
        .trust_tasks()
        .monitor_subscribe(
            profile,
            Some(convert(filter)?),
            Some(LEASE_SECONDS),
            None,
            renew.map(str::to_string),
        )
        .await?;
    Ok(Granted {
        id: granted.subscription_id.to_string(),
        expires_at: granted.expires_at,
        filter: convert(&granted.filter)?,
        membership: None,
    })
}

/// One generated type to another with the same JSON shape.
fn convert<A: serde::Serialize, B: serde::de::DeserializeOwned>(
    a: &A,
) -> std::result::Result<B, ATMError> {
    serde_json::to_value(a)
        .and_then(serde_json::from_value)
        .map_err(|e| ATMError::MsgSendError(format!("monitor filter: {e}")))
}

/// The single reader of a console's live stream.
pub(crate) struct LiveStream {
    feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>>,
    stop: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl LiveStream {
    pub(crate) fn start(atm: ATM, profile: Arc<ATMProfile>) -> Self {
        let feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let feeds = feeds.clone();
            let stop = stop.clone();
            async move {
                while !stop.load(Ordering::Relaxed) {
                    let next = atm
                        .message_pickup()
                        .live_stream_next(&profile, Some(Duration::from_millis(500)), false)
                        .await;
                    match next {
                        Ok(Some((message, _))) => {
                            // Every batch version reads as 0.3; one from a 0.1
                            // subscription simply has no membership in it.
                            let Some(batch) = decode_monitor_event_v0_3(&message) else {
                                // Not a monitor batch: leave it in the queue.
                                continue;
                            };
                            let id = batch.payload.subscription_id.to_string();
                            if let Some(tx) = feeds.lock().await.get(&id) {
                                // A full feed means its reader has stalled; the
                                // batch is dropped here, as the mediator would.
                                let _ = tx.try_send(batch.payload);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!("live stream read failed, retrying: {e}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        });
        Self { feeds, stop, task }
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.abort();
    }

    /// Subscribe and return a feed that renews itself.
    ///
    /// `membership` opts in to mux membership events, which only
    /// `monitor/subscribe` 0.2 offers. Without it, a mediator that refuses
    /// 0.2 as an unsupported type is asked again at 0.1; `v0_2` false (its
    /// version is known to predate 0.2) asks at 0.1 straight away.
    pub(crate) async fn open_feed(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        filter: MonitorFilter,
        membership: Option<MembershipFilter>,
        v0_2: bool,
    ) -> Result<MonitorFeed> {
        let mut version = if v0_2 || membership.is_some() {
            SubscribeVersion::V0_2
        } else {
            SubscribeVersion::V0_1
        };
        let first = subscribe(atm, profile, version, &filter, membership.as_ref(), None).await;
        let granted = match first {
            Err(e)
                if version == SubscribeVersion::V0_2
                    && membership.is_none()
                    && is_unsupported_type(&e) =>
            {
                version = SubscribeVersion::V0_1;
                subscribe(atm, profile, version, &filter, None, None).await
            }
            other => other,
        }
        .map_err(ConsoleError::from_call)?;
        let id = granted.id.clone();

        let (batch_tx, batch_rx) = mpsc::channel(FEED_BUFFER);
        self.feeds.lock().await.insert(id.clone(), batch_tx);
        let (end_tx, end_rx) = mpsc::channel(1);

        let renew = tokio::spawn({
            let atm = atm.clone();
            let profile = profile.clone();
            let id = id.clone();
            let mut expires_at = granted.expires_at;
            // A renewal re-filters: one without the filters in force would
            // widen the feed to everything the session may see.
            let filter = granted.filter.clone();
            let membership = granted.membership.clone();
            async move {
                let mut wait = until_renewal(expires_at);
                let mut failures = 0;
                loop {
                    tokio::time::sleep(wait).await;
                    match subscribe(
                        &atm,
                        &profile,
                        version,
                        &filter,
                        membership.as_ref(),
                        Some(&id),
                    )
                    .await
                    .map_err(ConsoleError::from_call)
                    {
                        Ok(renewed) => {
                            expires_at = renewed.expires_at;
                            wait = until_renewal(expires_at);
                            failures = 0;
                        }
                        // The renewal runs a minute ahead of expiry, so a
                        // connection that drops and comes back inside that
                        // minute keeps the subscription.
                        Err(e) => match retry_renewal(&e, failures, expires_at, Utc::now()) {
                            Some(after) => {
                                tracing::debug!("monitor lease renewal failed, retrying: {e}");
                                wait = after;
                                failures += 1;
                            }
                            None => {
                                let _ = end_tx.send(format!("lease renewal failed: {e}")).await;
                                return;
                            }
                        },
                    }
                }
            }
        });

        Ok(MonitorFeed {
            id,
            filter: granted.filter,
            membership: granted.membership,
            batches: batch_rx,
            ended: end_rx,
            pending: VecDeque::new(),
            last_seq: 0,
            renew,
            feeds: self.feeds.clone(),
            atm: atm.clone(),
            profile: profile.clone(),
        })
    }
}

/// How long to sleep before renewing a lease that ends at `expires_at`.
fn until_renewal(expires_at: DateTime<Utc>) -> Duration {
    let left = (expires_at - Utc::now()).to_std().unwrap_or_default();
    left.saturating_sub(RENEW_MARGIN)
        .max(Duration::from_secs(5))
}

/// When to try a failed renewal again: after a backoff, while the lease has
/// not lapsed and the failure was in transit. `None` for a refusal (the
/// mediator's answer won't change) or once the retry would land after expiry
/// (the subscription is gone by then).
fn retry_renewal(
    error: &ConsoleError,
    failures: u32,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<Duration> {
    if matches!(
        error,
        ConsoleError::Refused { .. } | ConsoleError::NotPermitted(_)
    ) {
        return None;
    }
    let after = RENEW_RETRY
        .saturating_mul(2u32.saturating_pow(failures.min(8)))
        .min(RENEW_RETRY_MAX);
    let left = (expires_at - now).to_std().ok()?;
    (after < left).then_some(after)
}

/// A live traffic-monitor subscription.
///
/// Read it with [`MonitorFeed::next`]. It renews its lease on its own and
/// unsubscribes when dropped.
pub struct MonitorFeed {
    id: String,
    filter: MonitorFilter,
    membership: Option<MembershipFilter>,
    batches: mpsc::Receiver<Payload>,
    ended: mpsc::Receiver<String>,
    pending: VecDeque<MonitorUpdate>,
    last_seq: u64,
    renew: JoinHandle<()>,
    feeds: Arc<Mutex<HashMap<String, mpsc::Sender<Payload>>>>,
    atm: ATM,
    profile: Arc<ATMProfile>,
}

impl MonitorFeed {
    pub fn subscription_id(&self) -> &str {
        &self.id
    }

    /// The filter in force — narrowed by the mediator to what this session may
    /// see.
    pub fn filter(&self) -> &MonitorFilter {
        &self.filter
    }

    /// The membership filter in force, when the feed carries mux membership
    /// events. `None` when none were asked for, or the mediator sends none
    /// (mux is not enabled there).
    pub fn membership(&self) -> Option<&MembershipFilter> {
        self.membership.as_ref()
    }

    /// The next update. `None` once the feed has ended and been drained.
    pub async fn next(&mut self) -> Option<MonitorUpdate> {
        if let Some(update) = self.pending.pop_front() {
            return Some(update);
        }
        tokio::select! {
            batch = self.batches.recv() => {
                let batch = batch?;
                let updates = sequence(&mut self.last_seq, batch);
                self.pending.extend(updates);
                self.pending.pop_front()
            }
            reason = self.ended.recv() => reason.map(MonitorUpdate::Ended),
        }
    }
}

/// Turn one batch into updates, reporting any sequence gap before it.
fn sequence(last_seq: &mut u64, batch: Payload) -> Vec<MonitorUpdate> {
    let seq = batch.seq.get();
    let mut out = Vec::new();
    if *last_seq > 0 && seq > *last_seq + 1 {
        out.push(MonitorUpdate::Gap {
            missing: seq - *last_seq - 1,
        });
    }
    if seq > *last_seq {
        *last_seq = seq;
    }
    let membership_dropped = batch.membership_dropped.unwrap_or(0);
    let traffic = !batch.events.is_empty() || batch.dropped > 0;
    let membership = !batch.membership.is_empty() || membership_dropped > 0;
    if traffic {
        out.push(MonitorUpdate::Events {
            events: batch.events,
            dropped: batch.dropped,
        });
    }
    if membership {
        out.push(MonitorUpdate::Membership {
            events: batch.membership,
            dropped: membership_dropped,
        });
    }
    if !traffic && !membership {
        out.push(MonitorUpdate::Heartbeat);
    }
    out
}

impl Drop for MonitorFeed {
    fn drop(&mut self) {
        self.renew.abort();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (feeds, atm, profile, id) = (
            self.feeds.clone(),
            self.atm.clone(),
            self.profile.clone(),
            self.id.clone(),
        );
        runtime.spawn(async move {
            feeds.lock().await.remove(&id);
            let _ = atm.trust_tasks().monitor_unsubscribe(&profile, &id).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic_event() -> serde_json::Value {
        serde_json::json!({
            "occurredAt": "2026-09-21T00:00:00Z", "direction": "inbound",
            "stage": "received", "channel": "rest", "protocol": "didcomm",
        })
    }

    fn membership_event() -> serde_json::Value {
        serde_json::json!({
            "occurredAt": "2026-09-21T00:00:00Z", "change": "attached",
            "principal": "did:example:principal", "member": "did:example:member",
            "reason": "grant", "source": "grant", "wire": "didcomm",
        })
    }

    fn batch(seq: u64, events: usize, dropped: u64) -> Payload {
        let events: Vec<serde_json::Value> = (0..events).map(|_| traffic_event()).collect();
        serde_json::from_value(serde_json::json!({
            "subscriptionId": "urn:uuid:s", "seq": seq, "events": events,
            "dropped": dropped, "expiresAt": "2026-09-21T01:00:00Z",
        }))
        .unwrap()
    }

    fn membership_batch(seq: u64, traffic: usize, members: usize, dropped: u64) -> Payload {
        let events: Vec<serde_json::Value> = (0..traffic).map(|_| traffic_event()).collect();
        let membership: Vec<serde_json::Value> = (0..members).map(|_| membership_event()).collect();
        serde_json::from_value(serde_json::json!({
            "subscriptionId": "urn:uuid:s", "seq": seq, "events": events,
            "dropped": 0, "expiresAt": "2026-09-21T01:00:00Z",
            "membership": membership, "membershipDropped": dropped,
        }))
        .unwrap()
    }

    #[test]
    fn in_order_batches_yield_events_and_heartbeats() {
        let mut last = 0;
        assert!(matches!(
            sequence(&mut last, batch(1, 2, 0))[..],
            [MonitorUpdate::Events { .. }]
        ));
        assert!(matches!(
            sequence(&mut last, batch(2, 0, 0))[..],
            [MonitorUpdate::Heartbeat]
        ));
        assert_eq!(last, 2);
    }

    #[test]
    fn a_skipped_sequence_is_reported_as_a_gap_first() {
        let mut last = 3;
        let updates = sequence(&mut last, batch(6, 1, 4));
        assert!(matches!(updates[0], MonitorUpdate::Gap { missing: 2 }));
        assert!(matches!(
            updates[1],
            MonitorUpdate::Events { dropped: 4, .. }
        ));
    }

    #[test]
    fn membership_follows_the_batch_s_traffic_and_alone_is_no_heartbeat() {
        let mut last = 0;
        let updates = sequence(&mut last, membership_batch(1, 1, 2, 0));
        assert!(matches!(
            &updates[..],
            [MonitorUpdate::Events { .. }, MonitorUpdate::Membership { events, dropped: 0 }]
                if events.len() == 2
        ));
        // A membership-only batch, and one that only dropped membership.
        assert!(matches!(
            &sequence(&mut last, membership_batch(2, 0, 1, 0))[..],
            [MonitorUpdate::Membership { .. }]
        ));
        assert!(matches!(
            &sequence(&mut last, membership_batch(3, 0, 0, 3))[..],
            [MonitorUpdate::Membership { dropped: 3, .. }]
        ));
        // Empty membership with nothing dropped is a heartbeat.
        assert!(matches!(
            &sequence(&mut last, membership_batch(4, 0, 0, 0))[..],
            [MonitorUpdate::Heartbeat]
        ));
    }

    #[test]
    fn an_unsupported_type_is_told_apart_from_other_refusals() {
        let unsupported = ATMError::ProblemReport(
            "e.p.protocol.trust_task.unsupported".into(),
            "no such type".into(),
            "NONE".into(),
        );
        let denied = ATMError::ProblemReport(
            "e.p.authorization.admin_required".into(),
            "no".into(),
            "NONE".into(),
        );
        assert!(is_unsupported_type(&unsupported));
        assert!(!is_unsupported_type(&denied));
    }

    #[test]
    fn a_traffic_filter_converts_between_the_subscribe_versions() {
        let filter: MonitorFilter = serde_json::from_value(serde_json::json!({
            "dids": ["abc"], "failuresOnly": true,
        }))
        .unwrap();
        #[allow(deprecated)]
        let v0_1: monitor::subscribe::v0_1::MonitorFilter = convert(&filter).unwrap();
        let back: MonitorFilter = convert(&v0_1).unwrap();
        assert_eq!(
            serde_json::to_value(back).unwrap(),
            serde_json::to_value(filter).unwrap()
        );
    }

    #[test]
    fn a_renewal_lost_in_transit_is_retried_until_the_lease_lapses() {
        let now = Utc::now();
        let transit = ConsoleError::Connect("socket closed".into());
        let lease = now + chrono::Duration::seconds(60);
        let waits: Vec<_> = (0..5)
            .map(|n| retry_renewal(&transit, n, lease, now))
            .collect();
        assert_eq!(
            waits,
            [2, 4, 8, 15, 15].map(|s| Some(Duration::from_secs(s)))
        );
        // Too close to expiry to be worth it, or already past it.
        let closing = now + chrono::Duration::seconds(10);
        assert_eq!(retry_renewal(&transit, 3, closing, now), None);
        let lapsed = now - chrono::Duration::seconds(1);
        assert_eq!(retry_renewal(&transit, 0, lapsed, now), None);
    }

    #[test]
    fn a_refused_renewal_is_not_retried() {
        let now = Utc::now();
        let refused = ConsoleError::Refused {
            code: "e.p.req.not-found".into(),
            comment: "no such subscription".into(),
        };
        let lease = now + chrono::Duration::seconds(60);
        assert_eq!(retry_renewal(&refused, 0, lease, now), None);
    }

    #[test]
    fn renewal_is_ahead_of_expiry_but_never_immediate() {
        let soon = Utc::now() + chrono::Duration::seconds(30);
        assert_eq!(until_renewal(soon), Duration::from_secs(5));
        let later = Utc::now() + chrono::Duration::seconds(300);
        let wait = until_renewal(later);
        assert!(wait <= Duration::from_secs(240) && wait >= Duration::from_secs(230));
    }
}
