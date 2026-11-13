//! Live traffic monitor — the `messaging/monitor/*` Trust Tasks.
//!
//! The data plane emits one [`TrafficEvent`] per step in a message's life
//! (received, stored, delivered, forwarded, refused, deleted, purged) onto an
//! in-process broadcast bus. Each subscription runs its own delivery task that
//! filters, rate-limits and batches those events, signs each batch as a
//! `messaging/monitor/event` document and pushes it **only** over the
//! subscriber's live connection.
//!
//! A subscription is served over the transport it was opened on. A batch for
//! a DIDComm subscriber is authcrypted to it; one for a TSP subscriber is
//! sealed to its VID as the mediator and published *verbatim* — the frame
//! itself, because a raw-TSP socket answers an ordinary push by draining its
//! stored inbox, and a batch is never stored. Either way the subscriber needs
//! a live connection.
//!
//! Three rules keep a monitor from hurting what it watches:
//!
//! - **Emitting is free when nobody listens.** [`TrafficMonitor::emit`] takes a
//!   closure and builds the event only when a subscription exists.
//! - **It never queues.** An event over the rate ceiling, a lagging receiver or
//!   a subscriber that is not connected is *counted* (`dropped`), never
//!   buffered or stored — a monitor must not fill the queue it observes, nor
//!   slow or fail delivery.
//! - **It never watches itself.** Monitor batches go straight to the streaming
//!   publisher, which emits nothing; and by default a subscriber does not see
//!   its own management traffic with the mediator (its console polling), which
//!   would otherwise dominate the feed.
//!
//! Events carry metadata only — never a message body. Scope is per instance:
//! behind a shared Redis, a subscriber sees the traffic of the instance it is
//! connected to.
//!
//! # Membership events
//!
//! A subscription opened with `messaging/monitor/subscribe` 0.2 may opt in,
//! with a `membership` filter, to mux membership events: one
//! [`MembershipEvent`] per member change the mediator reports to a mux
//! connection's principal in an `attached` or `detached`
//! `messaging/mux/event` (see `crate::mux::connection`, which emits them where
//! it builds those events). They ride the same batches, as
//! `messaging/monitor/event` 0.3's `membership` array with its own
//! `membershipDropped` count, under the same rate ceiling, and are never sent
//! to a subscription that did not ask. A 0.1 subscription is served exactly as
//! before: event 0.2 batches, traffic only. Unlike traffic, membership is
//! not per instance behind a shared Redis: every instance's changes reach
//! every instance's opted-in subscribers (see the `fanout` module), under the same
//! filters and standing checks as local ones.
//!
//! # What a subscription reveals
//!
//! Correspondence metadata: who exchanged messages with whom (as DID hashes),
//! when, over which channel and protocol, how large, and which were refused and
//! with what code. A non-administrator is confined to events in which its own
//! account is a party, so it learns only its own correspondents — which it
//! already knows from its own traffic. An administrator can watch every
//! account; that reach is the feature, and it is why every administrator
//! subscribe, renew and unsubscribe is written to the audit log. That reach
//! lasts only while its owner is an administrator: it is re-checked before
//! each batch, and a subscription whose owner has lost it ends there (see
//! `DeliveryTask::deliver_if_standing`). Refusals
//! carry the problem-report code and comment the sender was already sent; an
//! internal failure is reported as `internalError` with no detail.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::SharedData;

pub(crate) mod fanout;
use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;
use affinidi_messaging_mediator_common::tasks::forwarding::{ForwardOutcome, ForwardingObserver};
use affinidi_messaging_mediator_common::time::unix_timestamp_millis;

/// How many events the bus holds for a slow subscriber before it lags (and
/// counts the overflow as dropped).
const BUS_CAPACITY: usize = 4_096;
/// Most subscriptions one account may hold at once.
pub(crate) const MAX_SUBSCRIPTIONS_PER_OWNER: usize = 3;
pub(crate) const DEFAULT_LEASE_SECONDS: u64 = 300;
pub(crate) const MAX_LEASE_SECONDS: u64 = 3_600;
pub(crate) const DEFAULT_MAX_EVENTS_PER_SECOND: u64 = 100;
pub(crate) const MAX_EVENTS_PER_SECOND: u64 = 1_000;
/// Most events in one `monitor/event` batch.
const MAX_BATCH: usize = 500;
/// Pending events are flushed at least this often.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// An empty batch is sent at least this often, so a dead tap is visible.
const HEARTBEAT: Duration = Duration::from_secs(30);

/// The `messaging/monitor/event` version a subscription's batches are sent
/// in: 0.2 for a subscription opened (or last renewed) with subscribe 0.1,
/// 0.3 for one opened with subscribe 0.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventVersion {
    V0_2,
    V0_3,
}

impl EventVersion {
    fn type_uri(self) -> &'static str {
        match self {
            EventVersion::V0_2 => "https://trusttasks.org/spec/messaging/monitor/event/0.2",
            EventVersion::V0_3 => "https://trusttasks.org/spec/messaging/monitor/event/0.3",
        }
    }
}

/// Which way traffic moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Received,
    Stored,
    Delivered,
    Forwarded,
    Refused,
    Deleted,
    Expired,
    Purged,
}

/// How the traffic reached or left the mediator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Websocket,
    Rest,
    PeerMediator,
    Internal,
}

/// The wire protocol a message travelled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    DidComm,
    DidCommV1,
    Tsp,
    Other,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Internal => "internal",
        }
    }
}
impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Stage::Received => "received",
            Stage::Stored => "stored",
            Stage::Delivered => "delivered",
            Stage::Forwarded => "forwarded",
            Stage::Refused => "refused",
            Stage::Deleted => "deleted",
            Stage::Expired => "expired",
            Stage::Purged => "purged",
        }
    }
}
impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Channel::Websocket => "websocket",
            Channel::Rest => "rest",
            Channel::PeerMediator => "peerMediator",
            Channel::Internal => "internal",
        }
    }
}
impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Protocol::DidComm => "didcomm",
            Protocol::DidCommV1 => "didcommV1",
            Protocol::Tsp => "tsp",
            Protocol::Other => "other",
        }
    }

    /// Classify a stored or received message body.
    pub fn detect(body: &str) -> Self {
        use affinidi_messaging_mediator_common::types::messages::MessageProtocol;
        match MessageProtocol::detect(body) {
            MessageProtocol::DidComm => Protocol::DidComm,
            MessageProtocol::Tsp => Protocol::Tsp,
            _ => Protocol::Other,
        }
    }
}

/// One observed step in one message's life. Metadata only.
#[derive(Clone, Debug)]
pub struct TrafficEvent {
    pub at: DateTime<Utc>,
    pub direction: Direction,
    pub stage: Stage,
    pub channel: Channel,
    pub protocol: Protocol,
    pub msg_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub size: Option<u64>,
    pub message_type: Option<String>,
    /// `(code, detail)` for a refusal or failure.
    pub outcome: Option<(String, Option<String>)>,
    pub latency_ms: Option<u64>,
}

impl TrafficEvent {
    /// A bare event; set the optional members with struct update syntax.
    pub fn new(direction: Direction, stage: Stage, channel: Channel, protocol: Protocol) -> Self {
        Self {
            at: Utc::now(),
            direction,
            stage,
            channel,
            protocol,
            msg_id: None,
            from: None,
            to: None,
            size: None,
            message_type: None,
            outcome: None,
            latency_ms: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut v = json!({
            "occurredAt": self.at,
            "direction": self.direction.as_str(),
            "stage": self.stage.as_str(),
            "channel": self.channel.as_str(),
            "protocol": self.protocol.as_str(),
        });
        let set = |v: &mut Value, k: &str, val: Option<Value>| {
            if let Some(val) = val {
                v[k] = val;
            }
        };
        set(&mut v, "msgId", self.msg_id.clone().map(Value::String));
        set(&mut v, "from", self.from.clone().map(Value::String));
        set(&mut v, "to", self.to.clone().map(Value::String));
        set(&mut v, "size", self.size.map(|s| json!(s)));
        set(
            &mut v,
            "messageType",
            self.message_type.clone().map(Value::String),
        );
        set(&mut v, "latencyMs", self.latency_ms.map(|l| json!(l)));
        if let Some((code, detail)) = &self.outcome {
            let mut o = json!({ "code": truncate(code, 256) });
            if let Some(d) = detail {
                o["detail"] = json!(truncate(d, 1024));
            }
            v["outcome"] = o;
        }
        v
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// What happened to a member's place on a mux connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipChange {
    Attached,
    Detached,
}

impl MembershipChange {
    fn as_str(self) -> &'static str {
        match self {
            MembershipChange::Attached => "attached",
            MembershipChange::Detached => "detached",
        }
    }
}

/// One member change on one mux connection, as its `messaging/mux/event`
/// reported it to the principal. Metadata only: no statement, nonce, scope or
/// key material. Accounts are DID hashes, as in [`TrafficEvent`].
#[derive(Clone, Debug)]
pub struct MembershipEvent {
    pub at: DateTime<Utc>,
    pub change: MembershipChange,
    /// The connection's principal (DID hash).
    pub principal: String,
    /// The member (DID hash).
    pub member: String,
    /// `didcomm` or `tsp`.
    pub wire: &'static str,
    /// `grant` or `attach`.
    pub source: &'static str,
    /// The reason the `messaging/mux/event` entry carries.
    pub reason: &'static str,
    pub session_id: Option<String>,
}

impl MembershipEvent {
    fn to_json(&self) -> Value {
        let mut v = json!({
            "occurredAt": self.at,
            "change": self.change.as_str(),
            "principal": self.principal,
            "member": self.member,
            "wire": self.wire,
            "source": self.source,
            "reason": self.reason,
        });
        if let Some(id) = self.session_id.as_deref().filter(|id| !id.is_empty()) {
            v["sessionId"] = json!(truncate(id, 256));
        }
        v
    }
}

tokio::task_local! {
    /// The channel the inbound frame being handled arrived on — set around each
    /// inbound entry point, read by protocol handlers (a pickup, say) that
    /// report a delivery but are not told how the request came in.
    static CHANNEL: Channel;
}

/// Run `f` with `channel` as the current inbound channel.
pub(crate) async fn with_channel<F: std::future::Future>(channel: Channel, f: F) -> F::Output {
    CHANNEL.scope(channel, f).await
}

/// The channel the current inbound frame arrived on; `Internal` outside one.
#[cfg(feature = "didcomm")]
pub(crate) fn current_channel() -> Channel {
    CHANNEL.try_with(|c| *c).unwrap_or(Channel::Internal)
}

/// The recipient account (DID hash) a frame is addressed to, read from its
/// cleartext header only — never by decrypting, and only when a subscriber
/// will see it. A DIDComm v2 JWE names its recipients' key ids; a TSP envelope
/// its receiver VID. A DIDComm v1 envelope names only verkeys, and a signed or
/// plaintext DIDComm message no recipient in its header, so those are `None`.
pub(crate) fn frame_recipient(frame: &[u8], protocol: Protocol) -> Option<String> {
    let did = match protocol {
        Protocol::DidComm => didcomm_recipient(frame)?,
        #[cfg(feature = "tsp")]
        Protocol::Tsp => affinidi_tsp::MetaEnvelope::parse(frame).ok()?.receiver,
        _ => return None,
    };
    Some(affinidi_messaging_mediator_common::did_identity::did_hash(
        did.as_str(),
    ))
}

/// The DID of a DIDComm JWE's first recipient: `recipients[0].header.kid` in the
/// JSON serialisation, the protected header's `kid` in the compact one.
fn didcomm_recipient(frame: &[u8]) -> Option<String> {
    let kid = if frame.first() == Some(&b'{') {
        let v: Value = serde_json::from_slice(frame).ok()?;
        v["recipients"][0]["header"]["kid"].as_str()?.to_string()
    } else {
        use base64::Engine as _;
        let header = std::str::from_utf8(frame).ok()?.split('.').next()?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .ok()?;
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        v["kid"].as_str()?.to_string()
    };
    Some(kid.split('#').next().unwrap_or(&kid).to_string())
}

/// `(code, detail)` for a refusal: the problem-report code when the error
/// carries one, else the error's own text.
pub(crate) fn refusal_outcome(
    e: &affinidi_messaging_mediator_common::errors::MediatorError,
) -> (String, Option<String>) {
    use affinidi_messaging_mediator_common::errors::MediatorError;
    match e {
        MediatorError::MediatorError(_, _, _, report, _, _) => {
            (report.code.clone(), Some(report.comment.clone()))
        }
        // Anything else is an internal failure whose text can carry backend
        // detail (store errors, internal identifiers). Subscribers get a stable
        // code only; the full text stays in the server log.
        other => {
            tracing::debug!(error = %other, "refusal reported to the monitor as internalError");
            ("internalError".to_string(), None)
        }
    }
}

impl TrafficMonitor {
    /// A frame arrived from `sender` (the session's DID hash).
    pub(crate) fn received(
        &self,
        sender: &str,
        channel: Channel,
        protocol: Protocol,
        frame: &[u8],
    ) {
        self.emit(|| TrafficEvent {
            msg_id: Some(sha256::digest(frame)),
            from: Some(sender.to_string()),
            to: frame_recipient(frame, protocol),
            size: Some(frame.len() as u64),
            ..TrafficEvent::new(Direction::Inbound, Stage::Received, channel, protocol)
        });
    }

    /// A frame from `sender` was refused with `error`.
    pub(crate) fn refused(
        &self,
        sender: &str,
        channel: Channel,
        protocol: Protocol,
        frame: &[u8],
        error: &affinidi_messaging_mediator_common::errors::MediatorError,
    ) {
        self.emit(|| TrafficEvent {
            msg_id: Some(sha256::digest(frame)),
            from: Some(sender.to_string()),
            to: frame_recipient(frame, protocol),
            size: Some(frame.len() as u64),
            outcome: Some(refusal_outcome(error)),
            ..TrafficEvent::new(Direction::Inbound, Stage::Refused, channel, protocol)
        });
    }

    /// A stored message was handed to its recipient on pickup.
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    pub(crate) fn delivered(
        &self,
        msg_id: &str,
        from: Option<&str>,
        to: Option<&str>,
        size: u64,
        channel: Channel,
        body: Option<&str>,
    ) {
        self.delivered_as(
            msg_id,
            from,
            to,
            size,
            channel,
            body.map_or(Protocol::Other, Protocol::detect),
        );
    }

    /// [`delivered`](Self::delivered), with the protocol already known: for
    /// a report made before the write, which keeps the protocol rather than
    /// a copy of the body.
    pub(crate) fn delivered_as(
        &self,
        msg_id: &str,
        from: Option<&str>,
        to: Option<&str>,
        size: u64,
        channel: Channel,
        protocol: Protocol,
    ) {
        self.emit(|| TrafficEvent {
            msg_id: Some(msg_id.to_string()),
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            size: Some(size),
            ..TrafficEvent::new(Direction::Outbound, Stage::Delivered, channel, protocol)
        });
    }

    /// A message was deleted from `account`'s queues (by its owner or an
    /// administrator). `from`/`to` are set when the caller knows them;
    /// otherwise `account` stands in as `to`, so a filter on the account
    /// still sees it.
    pub(crate) fn deleted(
        &self,
        msg_id: &str,
        account: &str,
        from: Option<&str>,
        to: Option<&str>,
        channel: Channel,
        body: Option<&str>,
    ) {
        self.emit(|| TrafficEvent {
            msg_id: Some(msg_id.to_string()),
            from: from.map(str::to_string),
            to: Some(to.unwrap_or(account).to_string()),
            ..TrafficEvent::new(
                Direction::Internal,
                Stage::Deleted,
                channel,
                // Same derivation as `delivered`: the deleted message's own
                // wire form. `other` is left for a caller that genuinely has
                // no body to hand — it means unclassified, not "a REST call".
                body.map_or(Protocol::Other, Protocol::detect),
            )
        });
    }

    /// The expiry sweep removed `msg_id`, whose metadata was `meta`.
    pub(crate) fn expired(
        &self,
        msg_id: &str,
        meta: &affinidi_messaging_mediator_common::store::types::MessageMetaData,
    ) {
        self.emit(|| TrafficEvent {
            msg_id: Some(msg_id.to_string()),
            from: meta.from_did_hash.clone(),
            to: Some(meta.to_did_hash.clone()),
            size: Some(meta.bytes as u64),
            ..TrafficEvent::new(
                Direction::Internal,
                Stage::Expired,
                Channel::Internal,
                Protocol::Other,
            )
        });
    }

    /// `account`'s queue was purged of `count` messages, `bytes` in total.
    pub(crate) fn purged(&self, account: &str, count: usize, bytes: usize, channel: Channel) {
        if count == 0 {
            return;
        }
        self.emit(|| TrafficEvent {
            to: Some(account.to_string()),
            size: Some(bytes as u64),
            ..TrafficEvent::new(Direction::Internal, Stage::Purged, channel, Protocol::Other)
        });
    }

    /// A message was queued for relay to another mediator: `stored` on the
    /// peer-mediator channel. It is `forwarded` only once the peer accepts it
    /// (see the [`ForwardingObserver`] impl below) — a queued relay is not a
    /// relayed one.
    pub(crate) fn queued_for_relay(&self, from: &str, to: &str, body: &str, protocol: Protocol) {
        self.emit(|| TrafficEvent {
            msg_id: Some(sha256::digest(body)),
            from: Some(from.to_string()),
            to: Some(to.to_string()),
            size: Some(body.len() as u64),
            ..TrafficEvent::new(
                Direction::Outbound,
                Stage::Stored,
                Channel::PeerMediator,
                protocol,
            )
        });
    }

    /// A message was stored for `to`.
    ///
    /// Its live delivery, if any, is reported separately, by the socket loop
    /// once the frame is written to the recipient's socket — not here, where
    /// a publish can still be dropped, nor when the frame is queued (R1.1).
    pub(crate) fn stored(&self, msg_id: &str, from: Option<&str>, to: &str, body: &str) {
        let protocol = Protocol::detect(body);
        self.emit(|| TrafficEvent {
            msg_id: Some(msg_id.to_string()),
            from: from.map(str::to_string),
            to: Some(to.to_string()),
            size: Some(body.len() as u64),
            ..TrafficEvent::new(
                Direction::Internal,
                Stage::Stored,
                Channel::Internal,
                protocol,
            )
        });
    }
}

/// A subscriber's filter, as normalised by [`TrafficMonitor::subscribe`].
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Filter {
    pub dids: Option<Vec<String>>,
    pub directions: Option<Vec<String>>,
    pub stages: Option<Vec<String>>,
    pub protocols: Option<Vec<String>>,
    pub channels: Option<Vec<String>>,
    pub message_type_prefixes: Option<Vec<String>>,
    pub failures_only: Option<bool>,
}

impl Filter {
    fn matches(&self, e: &TrafficEvent) -> bool {
        let in_set = |set: &Option<Vec<String>>, val: &str| {
            set.as_ref().is_none_or(|s| s.iter().any(|x| x == val))
        };
        if let Some(dids) = &self.dids {
            let hit = |p: &Option<String>| p.as_ref().is_some_and(|p| dids.contains(p));
            if !hit(&e.from) && !hit(&e.to) {
                return false;
            }
        }
        if !in_set(&self.directions, e.direction.as_str())
            || !in_set(&self.stages, e.stage.as_str())
            || !in_set(&self.protocols, e.protocol.as_str())
            || !in_set(&self.channels, e.channel.as_str())
        {
            return false;
        }
        if let Some(prefixes) = &self.message_type_prefixes {
            let Some(t) = &e.message_type else {
                return false;
            };
            if !prefixes.iter().any(|p| t.starts_with(p)) {
                return false;
            }
        }
        if self.failures_only == Some(true) && e.outcome.is_none() {
            return false;
        }
        true
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut v = json!({});
        let set = |v: &mut Value, k: &str, val: &Option<Vec<String>>| {
            if let Some(val) = val {
                v[k] = json!(val);
            }
        };
        set(&mut v, "dids", &self.dids);
        set(&mut v, "directions", &self.directions);
        set(&mut v, "stages", &self.stages);
        set(&mut v, "protocols", &self.protocols);
        set(&mut v, "channels", &self.channels);
        set(&mut v, "messageTypePrefixes", &self.message_type_prefixes);
        if let Some(f) = self.failures_only {
            v["failuresOnly"] = json!(f);
        }
        v
    }
}

/// A subscriber's membership filter (`MembershipFilter`). Present means the
/// subscription receives membership events; members narrow which (ANDed,
/// values ORed).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MembershipFilter {
    pub dids: Option<Vec<String>>,
    pub changes: Option<Vec<String>>,
    pub wires: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
}

impl MembershipFilter {
    fn matches(&self, e: &MembershipEvent) -> bool {
        let in_set = |set: &Option<Vec<String>>, val: &str| {
            set.as_ref().is_none_or(|s| s.iter().any(|x| x == val))
        };
        if let Some(dids) = &self.dids
            && !dids.iter().any(|d| *d == e.principal || *d == e.member)
        {
            return false;
        }
        in_set(&self.changes, e.change.as_str())
            && in_set(&self.wires, e.wire)
            && in_set(&self.sources, e.source)
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut v = json!({});
        for (k, val) in [
            ("dids", &self.dids),
            ("changes", &self.changes),
            ("wires", &self.wires),
            ("sources", &self.sources),
        ] {
            if let Some(val) = val {
                v[k] = json!(val);
            }
        }
        v
    }
}

/// What a subscription taps, as normalised by
/// `mediator_ops::consume_monitor_subscribe`: the traffic filter, whether
/// traffic events are on, the membership filter (its presence is the opt-in)
/// and the event version its batches are sent in.
#[derive(Clone, Debug)]
pub(crate) struct Tap {
    pub filter: Filter,
    pub traffic: bool,
    pub membership: Option<MembershipFilter>,
    pub version: EventVersion,
}

impl Tap {
    /// Whether this tap shows anything beyond `owner`'s own account, which
    /// only an administrator may open. Traffic counts only while it is on;
    /// membership only when opted in.
    fn reaches_beyond(&self, owner: &str) -> bool {
        let own = |dids: &Option<Vec<String>>| {
            dids.as_ref().is_some_and(|d| d.iter().all(|x| x == owner))
        };
        (self.traffic && !own(&self.filter.dids))
            || self.membership.as_ref().is_some_and(|m| !own(&m.dids))
    }
}

/// Why a subscribe or unsubscribe was refused.
#[derive(Debug)]
pub(crate) enum MonitorError {
    /// The id names no subscription this requester may act on.
    UnknownSubscription,
    /// The requester already holds [`MAX_SUBSCRIPTIONS_PER_OWNER`].
    TooManySubscriptions,
}

/// Mutable state of one subscription.
struct Settings {
    tap: Tap,
    expires_at: DateTime<Utc>,
    max_eps: u64,
    /// Set, under this lock, when the subscription ends because its owner's
    /// standing lapsed: a renewal that already holds this subscription is
    /// then refused as unknown rather than reviving it.
    ended: bool,
}

/// How a subscriber's batches are sealed and pushed.
///
/// A subscription is served over the transport it was opened on: the batches
/// a TSP client can read are TSP, and its socket needs the frame itself
/// rather than a notification to drain an inbox the batch was never put in.
#[derive(Clone, Debug)]
pub(crate) enum Delivery {
    /// Authcrypt to the subscriber and push over its live connection.
    #[cfg(feature = "didcomm")]
    DidComm,
    /// Seal to the subscriber's VID as the mediator, and push the frame.
    #[cfg(feature = "tsp")]
    Tsp {
        /// The subscriber's X25519 public key, resolved when the subscription
        /// was opened — sealing every batch would otherwise resolve the VID
        /// again for each one.
        encryption_key: [u8; 32],
    },
}

struct Subscription {
    owner_did_hash: String,
    /// Whether its tap opted in to membership events, kept beside the
    /// settings so the fan-out task can ask without taking their lock.
    membership: Arc<AtomicBool>,
    /// Membership events other instances' reports say this subscription
    /// may have missed; taken into `membershipDropped` at the next flush.
    membership_lost: Arc<AtomicU64>,
    settings: Arc<Mutex<Settings>>,
    cancel: CancellationToken,
    sent: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

/// The forwarding processor's report of each relay attempt, correlated with
/// the `stored` event of `TrafficMonitor::queued_for_relay` by `msgId`:
///
/// - accepted by the peer → `forwarded`, with the time spent queued;
/// - failed, to be retried → `forwarded` with outcome `forwardingRetry`;
/// - dropped undelivered → `forwarded` with outcome
///   `e.p.me.res.forwarding.abandoned`, the code the sender's problem report
///   carries;
/// - refused by the peer, not retried → `forwarded` with outcome
///   `e.p.me.res.forwarding.refused`, likewise;
/// - next hop not a permitted endpoint, not retried → `forwarded` with
///   outcome `e.p.me.res.forwarding.endpoint-not-permitted`, likewise;
/// - expired in the queue → `expired`.
///
/// The peer's error text is not passed on: it stays in the server log.
impl ForwardingObserver for TrafficMonitor {
    fn observe(&self, entry: &ForwardQueueEntry, outcome: ForwardOutcome) {
        self.emit(|| {
            let (stage, outcome, latency_ms) = match outcome {
                ForwardOutcome::Relayed { .. } => {
                    let queued = unix_timestamp_millis().saturating_sub(entry.received_at_ms);
                    (Stage::Forwarded, None, Some(queued as u64))
                }
                ForwardOutcome::Retrying {
                    attempt,
                    max_retries,
                } => (
                    Stage::Forwarded,
                    Some((
                        "forwardingRetry".to_string(),
                        Some(format!(
                            "attempt {attempt} failed; {} retries left",
                            (max_retries + 1).saturating_sub(attempt)
                        )),
                    )),
                    None,
                ),
                ForwardOutcome::Abandoned { attempts } => (
                    Stage::Forwarded,
                    Some((
                        "e.p.me.res.forwarding.abandoned".to_string(),
                        Some(format!("dropped undelivered after {attempts} attempt(s)")),
                    )),
                    None,
                ),
                ForwardOutcome::Refused { status } => (
                    Stage::Forwarded,
                    Some((
                        "e.p.me.res.forwarding.refused".to_string(),
                        Some(format!("refused by the peer mediator (HTTP {status})")),
                    )),
                    None,
                ),
                ForwardOutcome::NotPermitted => (
                    Stage::Forwarded,
                    Some((
                        "e.p.me.res.forwarding.endpoint-not-permitted".to_string(),
                        Some("the next-hop endpoint is not a permitted target".to_string()),
                    )),
                    None,
                ),
                ForwardOutcome::Expired => (Stage::Expired, None, None),
                _ => (Stage::Forwarded, None, None),
            };
            TrafficEvent {
                msg_id: Some(sha256::digest(entry.message.as_str())),
                from: (!entry.from_did_hash.is_empty()).then(|| entry.from_did_hash.clone()),
                to: Some(entry.to_did_hash.clone()),
                size: Some(entry.message.len() as u64),
                outcome,
                latency_ms,
                ..TrafficEvent::new(
                    Direction::Outbound,
                    stage,
                    Channel::PeerMediator,
                    Protocol::detect(&entry.message),
                )
            }
        });
    }
}

/// The buses and the subscriptions reading them. Cheap to clone.
#[derive(Clone)]
pub struct TrafficMonitor {
    tx: broadcast::Sender<Arc<TrafficEvent>>,
    /// Mux membership events, on their own bus: a subscription that did not
    /// opt in ignores them, and they cannot crowd traffic out of `tx`.
    membership_tx: broadcast::Sender<Arc<MembershipEvent>>,
    subscriptions: Arc<DashMap<String, Subscription>>,
    /// Membership events shared with the other instances behind one store.
    fanout: Arc<fanout::Fanout>,
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TrafficMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficMonitor")
            .field("subscriptions", &self.subscriptions.len())
            .finish()
    }
}

/// What a successful subscribe returns.
pub(crate) struct Granted {
    pub subscription_id: String,
    pub expires_at: DateTime<Utc>,
    pub tap: Tap,
    pub max_eps: u64,
}

impl TrafficMonitor {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        let (membership_tx, _) = broadcast::channel(BUS_CAPACITY);
        Self {
            tx,
            membership_tx,
            subscriptions: Arc::new(DashMap::new()),
            fanout: Arc::default(),
        }
    }

    /// Whether anyone is listening — for a hook that would have to do extra
    /// work (a store read) to fill an event in.
    pub fn is_active(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    /// Every event on the bus, unfiltered — for tests of the code that emits.
    /// Its one caller, the streaming task's tests, needs the memory store.
    #[cfg(all(test, feature = "memory-backend"))]
    pub(crate) fn tap(&self) -> broadcast::Receiver<Arc<TrafficEvent>> {
        self.tx.subscribe()
    }

    /// Emit an event if anyone is listening. `build` runs only then, so an
    /// unwatched mediator pays one atomic load per call site.
    pub fn emit(&self, build: impl FnOnce() -> TrafficEvent) {
        if self.tx.receiver_count() > 0 {
            // No receiver between the check and the send is harmless.
            let _ = self.tx.send(Arc::new(build()));
        }
    }

    /// Emit a mux membership event if any subscription could see it. Called
    /// once per member change reported in `messaging/mux/event`, after the
    /// change is made (`crate::mux::connection`).
    ///
    /// Also offered, without waiting, to the fan-out task while another
    /// instance has a membership subscriber (see the `fanout` module); never awaited,
    /// so the connection path it is called from is not slowed by the store.
    pub fn emit_membership(&self, build: impl FnOnce() -> MembershipEvent) {
        let local = self.membership_tx.receiver_count() > 0;
        let remote = self.fanout.wanted();
        if !local && !remote {
            return;
        }
        let event = Arc::new(build());
        if remote {
            self.fanout.offer(event.clone());
        }
        if local {
            let _ = self.membership_tx.send(event);
        }
    }

    /// Put a membership event another instance reported on this instance's
    /// bus, where every subscription's own filter and standing check apply
    /// to it as to a local one. Not offered back to the fan-out.
    fn inject_membership(&self, event: MembershipEvent) {
        if self.membership_tx.receiver_count() > 0 {
            let _ = self.membership_tx.send(Arc::new(event));
        }
    }

    /// Count `n` membership events lost on the way from another instance
    /// against every subscription here that opted in.
    fn membership_lost(&self, n: u64) {
        for s in self.subscriptions.iter() {
            if s.membership.load(Ordering::Relaxed) {
                s.membership_lost.fetch_add(n, Ordering::Relaxed);
            }
        }
    }

    /// Whether any subscription here has opted in to membership events.
    fn has_membership_subscribers(&self) -> bool {
        self.subscriptions
            .iter()
            .any(|s| s.membership.load(Ordering::Relaxed))
    }

    /// Every membership event on the bus, unfiltered: for tests of the code
    /// that emits.
    #[cfg(test)]
    pub(crate) fn tap_membership(&self) -> broadcast::Receiver<Arc<MembershipEvent>> {
        self.membership_tx.subscribe()
    }

    /// Open a subscription, or renew and re-filter an existing one owned by
    /// the same account. `tap` must already be narrowed to what the owner
    /// may see (see `mediator_ops::consume_monitor_subscribe`).
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn subscribe(
        &self,
        state: &SharedData,
        owner_did: &str,
        owner_did_hash: &str,
        renew: Option<&str>,
        tap: Tap,
        lease_seconds: u64,
        max_eps: u64,
        delivery: Delivery,
    ) -> Result<Granted, MonitorError> {
        let expires_at = Utc::now() + chrono::Duration::seconds(lease_seconds as i64);

        if let Some(id) = renew {
            let sub = self
                .subscriptions
                .get(id)
                .filter(|s| s.owner_did_hash == owner_did_hash)
                .ok_or(MonitorError::UnknownSubscription)?;
            let settings = sub.settings.clone();
            let opted_in = sub.membership.clone();
            drop(sub);
            let mut guard = settings.lock().await;
            if guard.ended {
                return Err(MonitorError::UnknownSubscription);
            }
            opted_in.store(tap.membership.is_some(), Ordering::Relaxed);
            if tap.membership.is_some() {
                self.fanout.listening_changed();
            }
            guard.tap = tap.clone();
            guard.expires_at = expires_at;
            guard.max_eps = max_eps;
            return Ok(Granted {
                subscription_id: id.to_string(),
                expires_at,
                tap,
                max_eps,
            });
        }

        let held = self
            .subscriptions
            .iter()
            .filter(|s| s.owner_did_hash == owner_did_hash)
            .count();
        if held >= MAX_SUBSCRIPTIONS_PER_OWNER {
            return Err(MonitorError::TooManySubscriptions);
        }

        let id = format!("urn:uuid:{}", Uuid::new_v4());
        let settings = Arc::new(Mutex::new(Settings {
            tap: tap.clone(),
            expires_at,
            max_eps,
            ended: false,
        }));
        let cancel = CancellationToken::new();
        let sent = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let membership_lost = Arc::new(AtomicU64::new(0));
        self.subscriptions.insert(
            id.clone(),
            Subscription {
                owner_did_hash: owner_did_hash.to_string(),
                membership: Arc::new(AtomicBool::new(tap.membership.is_some())),
                membership_lost: membership_lost.clone(),
                settings: settings.clone(),
                cancel: cancel.clone(),
                sent: sent.clone(),
                dropped: dropped.clone(),
            },
        );

        if tap.membership.is_some() {
            self.fanout.listening_changed();
        }
        let task = DeliveryTask {
            state: state.clone(),
            subscription_id: id.clone(),
            owner_did: owner_did.to_string(),
            owner_did_hash: owner_did_hash.to_string(),
            mediator_did_hash: affinidi_messaging_mediator_common::did_identity::did_hash(
                &state.config.mediator_did,
            ),
            delivery,
            settings,
            cancel,
            sent,
            dropped,
            rx: self.tx.subscribe(),
            membership_rx: self.membership_tx.subscribe(),
            membership_lost,
            fanout: self.fanout.clone(),
            subscriptions: self.subscriptions.clone(),
        };
        tokio::spawn(task.run());

        Ok(Granted {
            subscription_id: id,
            expires_at,
            tap,
            max_eps,
        })
    }

    /// End a subscription. The owner may end its own; a rootAdmin any.
    /// Returns `(sent, dropped)` totals.
    pub(crate) fn unsubscribe(
        &self,
        id: &str,
        requester_did_hash: &str,
        requester_is_root: bool,
    ) -> Result<(u64, u64), MonitorError> {
        let permitted = self
            .subscriptions
            .get(id)
            .is_some_and(|s| requester_is_root || s.owner_did_hash == requester_did_hash);
        if !permitted {
            return Err(MonitorError::UnknownSubscription);
        }
        let (_, sub) = self
            .subscriptions
            .remove(id)
            .ok_or(MonitorError::UnknownSubscription)?;
        sub.cancel.cancel();
        Ok((
            sub.sent.load(Ordering::Relaxed),
            sub.dropped.load(Ordering::Relaxed),
        ))
    }
}

/// Test-only switches, compiled only with the `test-hooks` feature.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex};

    static STANDING_UNREADABLE: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Default::default);

    /// Make every standing read for subscriptions owned by `did_hash` fail as
    /// an unreadable store would (`unreadable`), or read normally again.
    pub fn set_standing_unreadable(did_hash: &str, unreadable: bool) {
        let mut set = STANDING_UNREADABLE.lock().expect("hook set");
        if unreadable {
            set.insert(did_hash.to_string());
        } else {
            set.remove(did_hash);
        }
    }

    pub(super) fn standing_unreadable(did_hash: &str) -> bool {
        STANDING_UNREADABLE
            .lock()
            .expect("hook set")
            .contains(did_hash)
    }
}

/// [`DeliveryTask::standing`]'s answer.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
#[derive(Debug, PartialEq, Eq)]
enum SubscriberStanding {
    Good,
    /// What the subscription was granted on no longer holds; why.
    Lapsed(&'static str),
    /// The store could not be read.
    Unknown,
}

/// One subscription's filter-rate-batch-deliver loop.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
struct DeliveryTask {
    state: SharedData,
    subscription_id: String,
    owner_did: String,
    owner_did_hash: String,
    mediator_did_hash: String,
    delivery: Delivery,
    settings: Arc<Mutex<Settings>>,
    cancel: CancellationToken,
    sent: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    rx: broadcast::Receiver<Arc<TrafficEvent>>,
    membership_rx: broadcast::Receiver<Arc<MembershipEvent>>,
    /// See [`Subscription::membership_lost`].
    membership_lost: Arc<AtomicU64>,
    fanout: Arc<fanout::Fanout>,
    subscriptions: Arc<DashMap<String, Subscription>>,
}

/// What a subscription has gathered since its last batch.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
#[derive(Default)]
struct Pending {
    events: Vec<Value>,
    /// Traffic events discarded since the last batch.
    dropped: u64,
    membership: Vec<Value>,
    /// Membership events discarded since the last batch.
    membership_dropped: u64,
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
impl Pending {
    fn is_empty(&self) -> bool {
        self.events.is_empty()
            && self.membership.is_empty()
            && self.dropped == 0
            && self.membership_dropped == 0
    }

    fn full(&self) -> bool {
        self.events.len() >= MAX_BATCH || self.membership.len() >= MAX_BATCH
    }

    /// Discard the gathered events, counting each as dropped in its own
    /// count. Returns how many were discarded.
    fn discard(&mut self) -> u64 {
        let traffic = std::mem::take(&mut self.events).len() as u64;
        let membership = std::mem::take(&mut self.membership).len() as u64;
        self.dropped += traffic;
        self.membership_dropped += membership;
        traffic + membership
    }
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
impl DeliveryTask {
    async fn run(mut self) {
        let mut pending = Pending::default();
        let mut seq: u64 = 0;
        let mut window_start = tokio::time::Instant::now();
        let mut in_window: u64 = 0;
        let mut last_sent = tokio::time::Instant::now();
        let mut flush = tokio::time::interval(FLUSH_INTERVAL);
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // One rate ceiling over traffic and membership events together.
        let mut admit = |max_eps: u64| {
            if window_start.elapsed() >= Duration::from_secs(1) {
                window_start = tokio::time::Instant::now();
                in_window = 0;
            }
            if in_window >= max_eps {
                return false;
            }
            in_window += 1;
            true
        };

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                received = self.rx.recv() => match received {
                    Ok(event) => {
                        let (keep, max_eps) = {
                            let s = self.settings.lock().await;
                            (
                                s.tap.traffic
                                    && s.tap.filter.matches(&event)
                                    && !self.is_own_management(&event),
                                s.max_eps,
                            )
                        };
                        if !keep {
                            continue;
                        }
                        if !admit(max_eps) {
                            pending.dropped += 1;
                            continue;
                        }
                        pending.events.push(event.to_json());
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        if self.settings.lock().await.tap.traffic {
                            pending.dropped += n;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                received = self.membership_rx.recv() => match received {
                    Ok(event) => {
                        let (keep, max_eps) = {
                            let s = self.settings.lock().await;
                            (
                                s.tap.membership.as_ref().is_some_and(|f| f.matches(&event)),
                                s.max_eps,
                            )
                        };
                        if !keep {
                            continue;
                        }
                        if !admit(max_eps) {
                            pending.membership_dropped += 1;
                            continue;
                        }
                        pending.membership.push(event.to_json());
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        if self.settings.lock().await.tap.membership.is_some() {
                            pending.membership_dropped += n;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = flush.tick() => {
                    let expired = self.settings.lock().await.expires_at <= Utc::now();
                    if expired {
                        break;
                    }
                    pending.membership_dropped +=
                        self.membership_lost.swap(0, Ordering::Relaxed);
                    if !pending.is_empty() || last_sent.elapsed() >= HEARTBEAT {
                        if !self.deliver_if_standing(&mut pending, &mut seq).await {
                            break;
                        }
                        last_sent = tokio::time::Instant::now();
                    }
                    continue;
                }
            }
            // A full batch goes at once rather than at the next tick.
            if pending.full() {
                if !self.deliver_if_standing(&mut pending, &mut seq).await {
                    break;
                }
                last_sent = tokio::time::Instant::now();
            }
        }
        self.subscriptions.remove(&self.subscription_id);
    }

    /// The subscriber's standing now, re-read from the store. A subscription
    /// keeps the reach it was granted for its whole lease (up to
    /// [`MAX_LEASE_SECONDS`]), so what it was granted on is checked again
    /// before each batch leaves:
    ///
    /// - the subscriber's account still exists and is not blocked;
    /// - a subscription whose filter reaches beyond the subscriber's own
    ///   account (which only an administrator may open) still belongs to an
    ///   administrator, by the store's own check (`check_admin_account`).
    ///
    /// Returns the standing and whether the filter it was judged against
    /// reaches beyond the owner's own account.
    async fn standing(&self) -> (SubscriberStanding, bool) {
        let reaches = self
            .settings
            .lock()
            .await
            .tap
            .reaches_beyond(&self.owner_did_hash);
        (self.standing_for(reaches).await, reaches)
    }

    async fn standing_for(&self, reaches: bool) -> SubscriberStanding {
        use affinidi_messaging_mediator_common::types::{
            accounts::AccountType, acls::MediatorACLSet,
        };
        #[cfg(feature = "test-hooks")]
        if test_hooks::standing_unreadable(&self.owner_did_hash) {
            return SubscriberStanding::Unknown;
        }
        let db = &self.state.database;
        let account = match db.account_get(&self.owner_did_hash).await {
            Ok(Some(a)) => a,
            Ok(None) => return SubscriberStanding::Lapsed("the subscriber's account was removed"),
            Err(e) => {
                tracing::debug!(subscription = %self.subscription_id, "monitor standing re-check deferred: {e}");
                return SubscriberStanding::Unknown;
            }
        };
        if MediatorACLSet::from_u64(account.acls).get_blocked() {
            return SubscriberStanding::Lapsed("the subscriber's account is blocked");
        }
        if reaches {
            // The same rule a Trust Task caller's role is read by. Once
            // `common::roles` lands (#218), this is
            // `roles::can_administer(roles::effective_role(account._type, listed))`.
            let admin = matches!(account._type, AccountType::Admin | AccountType::RootAdmin)
                && match db.check_admin_account(&self.owner_did_hash).await {
                    Ok(listed) => listed,
                    Err(e) => {
                        tracing::debug!(subscription = %self.subscription_id, "monitor standing re-check deferred: {e}");
                        return SubscriberStanding::Unknown;
                    }
                };
            if !admin {
                return SubscriberStanding::Lapsed("the subscriber is no longer an administrator");
            }
        }
        SubscriberStanding::Good
    }

    /// [`Self::deliver`] the batch if the subscriber still stands. Returns
    /// `false` when the subscription must end:
    ///
    /// - standing lapsed: the pending events are discarded (counted as
    ///   dropped), the subscription is ended and removed so a renewal finds
    ///   none, and one last batch with `expiresAt` cut to now tells the
    ///   subscriber it has ended (R6.2). An administrator's reach is on the
    ///   audit log when it opens, so its end is too.
    /// - standing unreadable (store failure): this batch is withheld and
    ///   counted as dropped; the next one checks again.
    async fn deliver_if_standing(&self, pending: &mut Pending, seq: &mut u64) -> bool {
        let (standing, reached) = self.standing().await;
        match standing {
            SubscriberStanding::Good => {
                self.deliver(pending, seq).await;
                true
            }
            SubscriberStanding::Unknown => {
                let n = pending.discard();
                self.dropped.fetch_add(n, Ordering::Relaxed);
                true
            }
            SubscriberStanding::Lapsed(why) => {
                let n = pending.discard();
                self.dropped.fetch_add(n, Ordering::Relaxed);
                // Ended first, under the settings lock a renewal takes, and
                // out of the map: no renewal succeeds from here on. Only then
                // is the subscriber told.
                {
                    let mut s = self.settings.lock().await;
                    s.ended = true;
                    s.expires_at = Utc::now();
                }
                self.subscriptions.remove(&self.subscription_id);
                self.deliver(pending, seq).await;
                tracing::info!(subscription = %self.subscription_id, owner = %self.owner_did_hash, "monitor subscription ended: {why}");
                if reached {
                    use affinidi_messaging_mediator_common::types::audit::{
                        AuditAction, AuditLogEntry,
                    };
                    let entry = AuditLogEntry {
                        timestamp: self.state.clock.unix_secs(),
                        actor_did_hash: self.mediator_did_hash.clone(),
                        target_did_hash: self.owner_did_hash.clone(),
                        action: AuditAction::MonitorUnsubscribe,
                        detail: format!(
                            "ended monitor {} ({} events sent, {} dropped): {why}",
                            self.subscription_id,
                            self.sent.load(Ordering::Relaxed),
                            self.dropped.load(Ordering::Relaxed),
                        ),
                    };
                    if let Err(e) = self.state.database.audit_log_record(&entry).await {
                        metrics::counter!(
                            crate::common::metrics::names::AUDIT_WRITE_FAILURES_TOTAL
                        )
                        .increment(1);
                        tracing::warn!(subscription = %self.subscription_id, "Failed to record audit-log entry: {e}");
                    }
                }
                false
            }
        }
    }

    /// The subscriber's own management traffic with the mediator — its
    /// console's Trust Tasks and their replies. Hidden by default: it would
    /// otherwise be most of what a console's monitor shows.
    fn is_own_management(&self, e: &TrafficEvent) -> bool {
        let party = |p: &Option<String>, who: &str| p.as_deref() == Some(who);
        (party(&e.from, &self.owner_did_hash) && party(&e.to, &self.mediator_did_hash))
            || (party(&e.from, &self.mediator_did_hash) && party(&e.to, &self.owner_did_hash))
    }

    /// Sign and push one batch over the live connection. If the subscriber is
    /// not live, nothing is sent and the batch's events are counted as dropped
    /// — `seq` only advances for a batch actually handed to the connection, so
    /// the subscriber sees a gap only when a sent batch was lost.
    async fn deliver(&self, pending: &mut Pending, seq: &mut u64) {
        let (expires_at, traffic, membership, version) = {
            let s = self.settings.lock().await;
            (
                s.expires_at,
                s.tap.traffic,
                s.tap.membership.is_some(),
                s.tap.version,
            )
        };
        // A renewal may have turned a kind off since these were gathered:
        // they are not sent, and count as dropped toward the totals only.
        if !traffic {
            let n = std::mem::take(&mut pending.events).len() as u64;
            pending.dropped = 0;
            self.dropped.fetch_add(n, Ordering::Relaxed);
        }
        if !membership {
            let n = std::mem::take(&mut pending.membership).len() as u64;
            pending.membership_dropped = 0;
            self.dropped.fetch_add(n, Ordering::Relaxed);
        }
        let count = (pending.events.len() + pending.membership.len()) as u64;

        let Some(uuid) = self
            .state
            .database
            .streaming_is_client_live(&self.owner_did_hash, true)
            .await
        else {
            self.dropped.fetch_add(pending.discard(), Ordering::Relaxed);
            return;
        };

        let next_seq = *seq + 1;
        let mediator_did = &self.state.config.mediator_did;
        let mut payload = json!({
            "subscriptionId": self.subscription_id,
            "seq": next_seq,
            "events": pending.events,
            "dropped": pending.dropped,
            "expiresAt": expires_at,
        });
        // `membership` and `membershipDropped` go on every batch of a
        // subscription that opted in, and on no other (event 0.3 rule 7).
        if membership && version == EventVersion::V0_3 {
            payload["membership"] = json!(pending.membership);
            payload["membershipDropped"] = json!(pending.membership_dropped);
            // Event 0.3 has no member for it; its batch-level `ext` carries
            // that this instance cannot hear the others' changes right now.
            if self.fanout.degraded() {
                payload["ext"] = json!({
                    "com.affinidi.mediator": { "membershipCoverage": "thisInstance" }
                });
            }
        }
        let doc = json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": version.type_uri(),
            "issuer": mediator_did,
            "recipient": self.owner_did,
            "payload": payload,
        });
        let packed = match self.pack(doc).await {
            Ok(packed) => packed,
            Err(e) => {
                tracing::debug!(subscription = %self.subscription_id, "monitor batch not sent: {e}");
                self.dropped.fetch_add(pending.discard(), Ordering::Relaxed);
                return;
            }
        };
        let published = match self.delivery {
            #[cfg(feature = "didcomm")]
            Delivery::DidComm => {
                self.state
                    .database
                    .streaming_publish_message(&self.owner_did_hash, &uuid, &packed, true)
                    .await
            }
            // The batch is the frame: it is stored nowhere, so a notification
            // would tell a raw-TSP socket to drain an inbox that holds nothing
            // of ours.
            #[cfg(feature = "tsp")]
            Delivery::Tsp { .. } => {
                self.state
                    .database
                    .streaming_publish_verbatim(&self.owner_did_hash, &uuid, &packed)
                    .await
            }
        };
        match published {
            Ok(()) => {
                *seq = next_seq;
                *pending = Pending::default();
                self.sent.fetch_add(count, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::debug!(subscription = %self.subscription_id, "monitor batch not published: {e}");
                self.dropped.fetch_add(pending.discard(), Ordering::Relaxed);
            }
        }
    }

    /// Sign the `monitor/event` document as the mediator and wrap it for the
    /// subscriber's transport.
    async fn pack(&self, doc: Value) -> Result<String, String> {
        let signed = crate::messages::protocols::trust_task_sign::sign_response(doc, &self.state)
            .await
            .map_err(|e| e.to_string())?;
        match &self.delivery {
            #[cfg(feature = "tsp")]
            Delivery::Tsp { encryption_key } => self.seal_tsp(&signed, encryption_key).await,
            #[cfg(feature = "didcomm")]
            Delivery::DidComm => self.pack_didcomm(signed).await,
        }
    }

    /// Authcrypt a signed batch in the Trust Tasks DIDComm binding envelope.
    #[cfg(feature = "didcomm")]
    async fn pack_didcomm(&self, signed: Value) -> Result<String, String> {
        let now = Utc::now().timestamp().max(0) as u64;
        let mediator_did = &self.state.config.mediator_did;
        let message = Message::build(
            Uuid::new_v4().to_string(),
            crate::messages::protocols::trust_tasks::ENVELOPE_TYPE.to_string(),
            signed,
        )
        .to(self.owner_did.clone())
        .from(mediator_did.clone())
        .created_time(now)
        .expires_time(now + 60)
        .finalize();
        crate::didcomm_compat::pack_encrypted(
            &message,
            &self.owner_did,
            Some(mediator_did),
            &self.state.did_resolver,
            &*self.state.config.security.mediator_secrets,
        )
        .await
        .map(|(packed, _)| packed)
        .map_err(|e| e.to_string())
    }

    /// Seal the signed batch to the subscriber's VID as the mediator, in the
    /// same Direct envelope a TSP Trust Task response uses, and encode it the
    /// way every TSP frame rides the live channel: base64url of the qb2 bytes.
    #[cfg(feature = "tsp")]
    async fn seal_tsp(&self, signed: &Value, encryption_key: &[u8; 32]) -> Result<String, String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let identity = self
            .state
            .tsp_identity()
            .await
            .map_err(|e| format!("mediator TSP identity: {e}"))?;
        let payload = serde_json::to_vec(signed).map_err(|e| e.to_string())?;
        let packed = affinidi_tsp::message::direct::pack(
            &payload,
            affinidi_tsp::MessageType::Direct,
            &identity.vid,
            &self.owner_did,
            &identity.signing_key,
            encryption_key,
        )
        .map_err(|e| format!("sealing the monitor batch: {e}"))?;
        Ok(URL_SAFE_NO_PAD.encode(&packed.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(stage: Stage, from: &str, to: &str) -> TrafficEvent {
        TrafficEvent {
            from: Some(from.into()),
            to: Some(to.into()),
            ..TrafficEvent::new(
                Direction::Inbound,
                stage,
                Channel::Websocket,
                Protocol::DidComm,
            )
        }
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        assert!(Filter::default().matches(&event(Stage::Stored, "a", "b")));
    }

    #[test]
    fn dids_match_either_party() {
        let f = Filter {
            dids: Some(vec!["b".into()]),
            ..Default::default()
        };
        assert!(f.matches(&event(Stage::Stored, "a", "b")));
        assert!(f.matches(&event(Stage::Stored, "b", "c")));
        assert!(!f.matches(&event(Stage::Stored, "a", "c")));
    }

    #[test]
    fn members_are_anded_and_values_ored() {
        let f = Filter {
            stages: Some(vec!["stored".into(), "delivered".into()]),
            protocols: Some(vec!["tsp".into()]),
            ..Default::default()
        };
        assert!(
            !f.matches(&event(Stage::Stored, "a", "b")),
            "wrong protocol"
        );
        let tsp = TrafficEvent {
            protocol: Protocol::Tsp,
            ..event(Stage::Delivered, "a", "b")
        };
        assert!(f.matches(&tsp));
    }

    #[test]
    fn failures_only_and_message_type_prefixes() {
        let failures = Filter {
            failures_only: Some(true),
            ..Default::default()
        };
        assert!(!failures.matches(&event(Stage::Received, "a", "b")));
        let refused = TrafficEvent {
            outcome: Some(("authorization.send".into(), None)),
            ..event(Stage::Refused, "a", "b")
        };
        assert!(failures.matches(&refused));

        let typed = Filter {
            message_type_prefixes: Some(vec!["https://didcomm.org/routing".into()]),
            ..Default::default()
        };
        assert!(
            !typed.matches(&event(Stage::Received, "a", "b")),
            "no type, no match"
        );
        let forward = TrafficEvent {
            message_type: Some("https://didcomm.org/routing/2.0/forward".into()),
            ..event(Stage::Received, "a", "b")
        };
        assert!(typed.matches(&forward));
    }

    #[tokio::test]
    async fn a_deleted_event_names_the_wire_the_message_travelled_in() {
        let monitor = TrafficMonitor::new();
        let mut rx = monitor.tx.subscribe();

        // A TSP body (CESR qb64) and a DIDComm one (JSON), as they are stored.
        monitor.deleted("m1", "acct", None, None, Channel::Rest, Some("-EABCD"));
        monitor.deleted("m2", "acct", None, None, Channel::Rest, Some("{\"x\":1}"));
        // Nothing in hand: unclassified, which is what `other` means.
        monitor.deleted("m3", "acct", None, None, Channel::Rest, None);

        let mut seen = Vec::new();
        for _ in 0..3 {
            let event = rx.recv().await.expect("event");
            seen.push((event.msg_id.clone().unwrap(), event.protocol));
        }
        assert_eq!(
            seen,
            vec![
                ("m1".to_string(), Protocol::Tsp),
                ("m2".to_string(), Protocol::DidComm),
                ("m3".to_string(), Protocol::Other),
            ],
            "a delete reports the deleted message's own protocol"
        );
    }

    #[test]
    fn emitting_with_no_subscriber_builds_nothing() {
        let monitor = TrafficMonitor::new();
        monitor.emit(|| panic!("the event must not be built with nobody listening"));
    }

    #[test]
    fn a_json_jwe_names_its_recipient() {
        let frame = br#"{"protected":"x","recipients":[{"header":{"kid":"did:example:bob#key-1"},"encrypted_key":"x"}],"iv":"x","ciphertext":"x","tag":"x"}"#;
        assert_eq!(
            frame_recipient(frame, Protocol::DidComm),
            Some(sha256::digest("did:example:bob"))
        );
    }

    #[test]
    fn a_compact_jwe_names_its_recipient_in_the_protected_header() {
        use base64::Engine as _;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ECDH-ES+A256KW","kid":"did:example:carol#key-2"}"#);
        let frame = format!("{header}.a.b.c.d");
        assert_eq!(
            frame_recipient(frame.as_bytes(), Protocol::DidComm),
            Some(sha256::digest("did:example:carol"))
        );
    }

    #[test]
    fn frames_without_a_recipient_header_have_none() {
        // A signed-only JWS names no recipient; v1 envelopes carry verkeys, not DIDs.
        assert_eq!(
            frame_recipient(br#"{"payload":"x","signatures":[]}"#, Protocol::DidComm),
            None
        );
        assert_eq!(frame_recipient(b"anything", Protocol::DidCommV1), None);
        assert_eq!(frame_recipient(b"not json", Protocol::DidComm), None);
    }

    #[cfg(feature = "didcomm")]
    #[tokio::test]
    async fn the_inbound_channel_is_visible_inside_its_scope_only() {
        assert_eq!(current_channel(), Channel::Internal);
        let inside = with_channel(Channel::Websocket, async { current_channel() }).await;
        assert_eq!(inside, Channel::Websocket);
        assert_eq!(current_channel(), Channel::Internal);
    }

    fn queued_entry(message: &str, received_at_ms: u128) -> ForwardQueueEntry {
        ForwardQueueEntry {
            stream_id: "1-0".into(),
            message: message.into(),
            to_did_hash: "bob".into(),
            from_did_hash: "alice".into(),
            from_did: "did:example:alice".into(),
            to_did: String::new(),
            endpoint_url: "https://peer.example/inbound".into(),
            received_at_ms,
            delay_milli: 0,
            expires_at: u64::MAX,
            retry_count: 0,
            hop_count: 1,
            not_before_ms: 0,
        }
    }

    /// Each forwarding outcome, as the monitor reports it.
    #[test]
    fn forwarding_outcomes_become_events_correlated_with_the_queued_one() {
        let monitor = TrafficMonitor::new();
        let mut rx = monitor.tx.subscribe();
        let body = r#"{"ciphertext":"x"}"#;
        let queued_at = unix_timestamp_millis() - 1_500;
        let entry = queued_entry(body, queued_at);

        monitor.queued_for_relay("alice", "bob", body, Protocol::DidComm);
        let queued = rx.try_recv().unwrap();
        assert_eq!(queued.stage, Stage::Stored);
        assert_eq!(queued.channel, Channel::PeerMediator);

        let outcomes = [
            ForwardOutcome::Retrying {
                attempt: 1,
                max_retries: 3,
            },
            ForwardOutcome::Relayed {
                transport:
                    affinidi_messaging_mediator_common::tasks::forwarding::ForwardTransport::Rest,
            },
            ForwardOutcome::Abandoned { attempts: 4 },
            ForwardOutcome::Refused { status: 403 },
            ForwardOutcome::NotPermitted,
            ForwardOutcome::Expired,
        ];
        for outcome in outcomes {
            monitor.observe(&entry, outcome);
        }
        let retry = rx.try_recv().unwrap();
        let relayed = rx.try_recv().unwrap();
        let abandoned = rx.try_recv().unwrap();
        let refused = rx.try_recv().unwrap();
        let not_permitted = rx.try_recv().unwrap();
        let expired = rx.try_recv().unwrap();

        for e in [
            &retry,
            &relayed,
            &abandoned,
            &refused,
            &not_permitted,
            &expired,
        ] {
            assert_eq!(e.msg_id, queued.msg_id, "one message, one id");
            assert_eq!(e.from.as_deref(), Some("alice"));
            assert_eq!(e.to.as_deref(), Some("bob"));
            assert_eq!(e.channel, Channel::PeerMediator);
        }

        assert_eq!(retry.stage, Stage::Forwarded);
        let (code, detail) = retry.outcome.clone().unwrap();
        assert_eq!(code, "forwardingRetry");
        assert_eq!(detail.as_deref(), Some("attempt 1 failed; 3 retries left"));

        assert_eq!(relayed.stage, Stage::Forwarded);
        assert!(relayed.outcome.is_none());
        assert!(relayed.latency_ms.unwrap() >= 1_500, "time spent queued");

        assert_eq!(abandoned.stage, Stage::Forwarded);
        assert_eq!(
            abandoned.outcome.clone().unwrap().0,
            "e.p.me.res.forwarding.abandoned"
        );

        assert_eq!(refused.stage, Stage::Forwarded);
        assert_eq!(
            refused.outcome.clone().unwrap(),
            (
                "e.p.me.res.forwarding.refused".to_string(),
                Some("refused by the peer mediator (HTTP 403)".to_string())
            )
        );

        assert_eq!(not_permitted.stage, Stage::Forwarded);
        assert_eq!(
            not_permitted.outcome.clone().unwrap().0,
            "e.p.me.res.forwarding.endpoint-not-permitted"
        );

        assert_eq!(expired.stage, Stage::Expired);
        assert!(expired.outcome.is_none());
    }

    #[test]
    fn an_internal_error_reaches_the_monitor_without_its_text() {
        use affinidi_messaging_mediator_common::errors::MediatorError;
        let internal = MediatorError::InternalError(
            crate::error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            "redis://:secret@db.internal:6379 connection refused".into(),
        );
        let (code, detail) = refusal_outcome(&internal);
        assert_eq!(code, "internalError");
        assert!(detail.is_none(), "backend text must not reach a subscriber");
    }

    fn membership(change: MembershipChange, principal: &str, member: &str) -> MembershipEvent {
        MembershipEvent {
            at: Utc::now(),
            change,
            principal: principal.into(),
            member: member.into(),
            wire: "didcomm",
            source: "grant",
            reason: match change {
                MembershipChange::Attached => "grant",
                MembershipChange::Detached => "revokedByPrincipal",
            },
            session_id: Some("ses_1".into()),
        }
    }

    #[test]
    fn an_empty_membership_filter_matches_every_change() {
        let f = MembershipFilter::default();
        assert!(f.matches(&membership(MembershipChange::Attached, "p", "m")));
        assert!(f.matches(&membership(MembershipChange::Detached, "p", "m")));
    }

    #[test]
    fn membership_dids_match_principal_or_member_and_members_are_anded() {
        let f = MembershipFilter {
            dids: Some(vec!["m".into()]),
            changes: Some(vec!["detached".into()]),
            ..Default::default()
        };
        assert!(f.matches(&membership(MembershipChange::Detached, "p", "m")));
        assert!(f.matches(&membership(MembershipChange::Detached, "m", "x")));
        assert!(!f.matches(&membership(MembershipChange::Detached, "p", "x")));
        assert!(
            !f.matches(&membership(MembershipChange::Attached, "p", "m")),
            "wrong change"
        );
        let tsp = MembershipFilter {
            wires: Some(vec!["tsp".into()]),
            ..Default::default()
        };
        assert!(!tsp.matches(&membership(MembershipChange::Attached, "p", "m")));
        let attach = MembershipFilter {
            sources: Some(vec!["attach".into()]),
            ..Default::default()
        };
        assert!(!attach.matches(&membership(MembershipChange::Attached, "p", "m")));
    }

    #[test]
    fn a_tap_reaches_beyond_its_owner_only_through_what_it_shows() {
        let own = |o: &str| Some(vec![o.to_string()]);
        let tap = |traffic, filter_dids, membership: Option<Option<Vec<String>>>| Tap {
            filter: Filter {
                dids: filter_dids,
                ..Default::default()
            },
            traffic,
            membership: membership.map(|dids| MembershipFilter {
                dids,
                ..Default::default()
            }),
            version: EventVersion::V0_3,
        };
        assert!(!tap(true, own("me"), None).reaches_beyond("me"));
        assert!(tap(true, None, None).reaches_beyond("me"));
        assert!(
            !tap(false, None, Some(own("me"))).reaches_beyond("me"),
            "traffic off: its empty filter shows nothing"
        );
        assert!(tap(false, None, Some(None)).reaches_beyond("me"));
        assert!(tap(true, own("me"), Some(own("other"))).reaches_beyond("me"));
    }

    #[test]
    fn membership_events_match_the_spec_and_carry_metadata_only() {
        use crate::task_specs::messaging::monitor::event::v0_3::Payload;
        let attached = membership(MembershipChange::Attached, "p", "m").to_json();
        let detached = MembershipEvent {
            session_id: None,
            ..membership(MembershipChange::Detached, "p", "m")
        }
        .to_json();
        assert!(detached.get("sessionId").is_none());
        for key in ["scope", "muxNonce", "statement", "proof", "grantId"] {
            assert!(attached.get(key).is_none(), "{key} is not monitor metadata");
        }
        let batch = json!({
            "subscriptionId": "s",
            "seq": 1,
            "events": [],
            "dropped": 0,
            "membership": [attached, detached],
            "membershipDropped": 0,
            "expiresAt": Utc::now(),
        });
        serde_json::from_value::<Payload>(batch.clone())
            .unwrap_or_else(|e| panic!("not an event 0.3 batch: {e}\n{batch:#}"));
        // A batch saying the fan-out is down (see `fanout`) is one too.
        let mut degraded = batch;
        degraded["ext"] = json!({
            "com.affinidi.mediator": { "membershipCoverage": "thisInstance" }
        });
        let parsed = serde_json::from_value::<Payload>(degraded.clone())
            .unwrap_or_else(|e| panic!("not an event 0.3 batch: {e}\n{degraded:#}"));
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["ext"],
            degraded["ext"],
            "the ext survives the typed payload"
        );
    }

    #[test]
    fn membership_is_emitted_only_while_someone_listens() {
        let monitor = TrafficMonitor::new();
        monitor.emit_membership(|| panic!("nobody listens"));
        let mut rx = monitor.tap_membership();
        monitor.emit_membership(|| membership(MembershipChange::Attached, "p", "m"));
        assert_eq!(rx.try_recv().unwrap().member, "m");
        assert!(rx.try_recv().is_err(), "one change, one event");
    }

    #[test]
    fn event_json_carries_metadata_only() {
        let e = TrafficEvent {
            msg_id: Some("m".into()),
            size: Some(42),
            outcome: Some(("code".into(), Some("detail".into()))),
            ..event(Stage::Refused, "a", "b")
        };
        let v = e.to_json();
        assert_eq!(v["stage"], "refused");
        assert_eq!(v["outcome"]["code"], "code");
        assert!(v.get("body").is_none() && v.get("message").is_none());
    }
}
