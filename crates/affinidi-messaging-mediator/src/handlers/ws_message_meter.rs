//! Inbound message rate on authenticated WebSockets.
//!
//! Every text or binary frame read from an established, authenticated
//! WebSocket is one message, charged to two budgets:
//!
//! - **the socket's own** — `limits.ws_messages_per_second`, with
//!   `limits.ws_message_burst` above it (on by default; unset, they inherit
//!   the per-IP HTTP limits when those are above 0, else 100 / 50; only an
//!   explicit `0` turns it off). One budget per socket, however many DIDs it
//!   carries: a DID-multiplexing connection's members all share it;
//! - **the DID's** — the per-DID limiter (`limits.did_rate_limit_per_second`)
//!   that also meters authenticated HTTP requests, when it is enabled. One DID
//!   holding many sockets shares one DID budget across all of them.
//!
//! Control frames (ping, pong, close) are not counted; the liveness logic in
//! `handlers::websocket` deals with them.
//!
//! # Over the rate
//!
//! A message over either budget is held — never dropped and never queued
//! behind others: the connection loop keeps the one message it has read and
//! stops reading until it is due ([`Verdict::Wait`]). The client's further
//! frames stay in its own send buffer, so a fast sender is slowed down to the
//! rate rather than buffered for. Live delivery to the client continues
//! meanwhile.
//!
//! A socket that stays over the rate for `limits.ws_message_throttle_close_secs`
//! (`10` by default; `0` = never) is closed with 1008 ([`Verdict::Close`]). The
//! clock starts at the first message that has to wait and resets only when a
//! message is admitted without waiting, so a one-off burst is slowed and a
//! client that keeps sending faster than the rate is disconnected.
//!
//! Each message that has to wait is counted once per budget in
//! `rate_limited_total` — `scope="ws"` for the socket's budget, `scope="did"`
//! for the DID's.
//!
//! # Not metered
//!
//! - the mediator's own DID and the configured admin DID (the per-DID
//!   limiter's exemption; throttling the operator's management plane is how an
//!   incident response locks itself out);
//! - anonymous inter-mediator relay sockets, which carry no DID and have their
//!   own frame and byte budget (`limits.relay_*`).

use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};

use governor::{
    DefaultDirectRateLimiter, Quota, RateLimiter,
    clock::{Clock, DefaultClock},
};
use tracing::{debug, warn};

use crate::common::{
    config::limits::LimitsConfig,
    did_rate_limiter::{DidRateLimiter, PER_DID_SCOPE},
    metrics::names::RATE_LIMITED_TOTAL,
};

/// `rate_limited_total` label for the per-socket message budget.
pub(crate) const PER_SOCKET_SCOPE: &str = "ws";

/// The close reason sent with 1008 when a socket stays over its rate.
pub(crate) const CLOSE_REASON: &str = "message rate limit exceeded";

/// Longest single pause before the budgets are checked again. A per-DID
/// capacity refusal hints at a minute; checking again sooner lets the message
/// through as soon as there is room, and keeps the close deadline prompt.
const MAX_PAUSE: Duration = Duration::from_secs(1);

/// Shortest pause, so a refusal never turns into a busy loop.
const MIN_PAUSE: Duration = Duration::from_millis(1);

/// What to do with the message in hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Process it now.
    Admit,
    /// Keep it, stop reading for this long, then charge it again.
    Wait(Duration),
    /// The socket has been over its rate for too long: close with 1008.
    Close,
}

/// One socket's message meter. See the module docs.
pub(crate) struct WsMessageMeter {
    per_socket: Option<DefaultDirectRateLimiter>,
    per_did: Option<(DidRateLimiter, String)>,
    close_after: Option<Duration>,
    /// When this socket's current run of waiting messages began.
    throttled_since: Option<Instant>,
    // The budgets the message in hand has already been charged to, and the
    // ones it was refused by, so a held message is charged and counted once.
    socket_paid: bool,
    did_paid: bool,
    socket_refused: bool,
    did_refused: bool,
    /// Messages this socket has had to wait for; the first is logged at warn.
    slowed: u64,
}

impl WsMessageMeter {
    /// The meter for a socket authenticated as `did_hash`, or `None` when no
    /// budget applies to it: an anonymous session, an exempt DID, or both
    /// budgets off.
    pub(crate) fn new(
        limits: &LimitsConfig,
        did_limiter: &DidRateLimiter,
        did_hash: &str,
    ) -> Option<Self> {
        if did_hash.is_empty() || did_limiter.is_exempt(did_hash) {
            return None;
        }
        let per_socket = NonZeroU32::new(limits.ws_messages_per_second).map(|rate| {
            let burst = NonZeroU32::new(limits.ws_message_burst).unwrap_or(NonZeroU32::MIN);
            RateLimiter::direct(Quota::per_second(rate).allow_burst(burst))
        });
        let per_did = did_limiter
            .is_enabled()
            .then(|| (did_limiter.clone(), did_hash.to_owned()));
        if per_socket.is_none() && per_did.is_none() {
            return None;
        }
        Some(Self {
            per_socket,
            per_did,
            close_after: (limits.ws_message_throttle_close_secs > 0)
                .then(|| Duration::from_secs(limits.ws_message_throttle_close_secs)),
            throttled_since: None,
            socket_paid: false,
            did_paid: false,
            socket_refused: false,
            did_refused: false,
            slowed: 0,
        })
    }

    /// Charge the message in hand (a new one, or one returned with
    /// [`Verdict::Wait`]) at `now`.
    pub(crate) fn charge(&mut self, now: Instant) -> Verdict {
        if !self.socket_paid {
            if let Some(limiter) = &self.per_socket
                && let Err(not_until) = limiter.check()
            {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                if !self.socket_refused {
                    self.socket_refused = true;
                    self.refused(PER_SOCKET_SCOPE, wait);
                }
                return self.wait(now, wait);
            }
            self.socket_paid = true;
        }
        if !self.did_paid {
            if let Some((limiter, did_hash)) = &self.per_did
                && let Err(wait) = limiter.try_acquire_wait(did_hash)
            {
                if !self.did_refused {
                    self.did_refused = true;
                    self.refused(PER_DID_SCOPE, wait);
                }
                return self.wait(now, wait);
            }
            self.did_paid = true;
        }

        let waited = self.socket_refused || self.did_refused;
        self.socket_paid = false;
        self.did_paid = false;
        self.socket_refused = false;
        self.did_refused = false;
        if !waited {
            // Within the rate again: the run of waiting messages is over.
            self.throttled_since = None;
        }
        Verdict::Admit
    }

    fn refused(&mut self, scope: &'static str, wait: Duration) {
        metrics::counter!(RATE_LIMITED_TOTAL, "scope" => scope).increment(1);
        self.slowed += 1;
        if self.slowed == 1 {
            warn!(
                scope,
                wait_ms = wait.as_millis() as u64,
                "WebSocket message over its rate; reading paused. Further pauses on this socket are logged at debug"
            );
        } else {
            debug!(
                scope,
                wait_ms = wait.as_millis() as u64,
                "WebSocket message over its rate; reading paused"
            );
        }
    }

    fn wait(&mut self, now: Instant, wait: Duration) -> Verdict {
        let since = *self.throttled_since.get_or_insert(now);
        if let Some(limit) = self.close_after
            && now.saturating_duration_since(since) >= limit
        {
            return Verdict::Close;
        }
        Verdict::Wait(wait.clamp(MIN_PAUSE, MAX_PAUSE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_second: u32, burst: u32, close_secs: u64) -> LimitsConfig {
        LimitsConfig {
            ws_messages_per_second: per_second,
            ws_message_burst: burst,
            ws_message_throttle_close_secs: close_secs,
            ..LimitsConfig::default()
        }
    }

    fn off() -> DidRateLimiter {
        DidRateLimiter::new(0, 1)
    }

    /// Admit messages until one has to wait; returns how many were admitted.
    fn admitted_before_wait(meter: &mut WsMessageMeter, now: Instant) -> u32 {
        for n in 0..10_000 {
            match meter.charge(now) {
                Verdict::Admit => continue,
                Verdict::Wait(_) => return n,
                Verdict::Close => panic!("closed after {n} messages"),
            }
        }
        panic!("no message had to wait");
    }

    #[test]
    fn defaults_are_on() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.ws_messages_per_second, 100);
        assert_eq!(limits.ws_message_burst, 50);
        assert_eq!(limits.ws_message_throttle_close_secs, 10);
        assert!(WsMessageMeter::new(&limits, &off(), "did-hash").is_some());
    }

    #[test]
    fn messages_within_the_burst_are_admitted_and_the_next_waits() {
        let mut meter = WsMessageMeter::new(&limits(1, 5, 10), &off(), "a").unwrap();
        let now = Instant::now();
        assert_eq!(admitted_before_wait(&mut meter, now), 5);
        match meter.charge(now) {
            Verdict::Wait(pause) => {
                assert!(pause >= MIN_PAUSE && pause <= MAX_PAUSE, "{pause:?}")
            }
            other => panic!("expected a wait, got {other:?}"),
        }
    }

    #[test]
    fn steady_traffic_under_the_rate_never_waits() {
        // 1000/s with a burst of 1: a message every 5 ms is well within it.
        let mut meter = WsMessageMeter::new(&limits(1_000, 1, 1), &off(), "a").unwrap();
        for i in 0..20 {
            assert_eq!(meter.charge(Instant::now()), Verdict::Admit, "message {i}");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(meter.throttled_since.is_none());
    }

    #[test]
    fn a_held_message_is_admitted_once_its_token_is_due() {
        let mut meter = WsMessageMeter::new(&limits(100, 1, 10), &off(), "a").unwrap();
        assert_eq!(meter.charge(Instant::now()), Verdict::Admit);
        let Verdict::Wait(pause) = meter.charge(Instant::now()) else {
            panic!("the second message must wait");
        };
        std::thread::sleep(pause);
        assert_eq!(meter.charge(Instant::now()), Verdict::Admit);
    }

    #[test]
    fn staying_over_the_rate_closes_the_socket() {
        let mut meter = WsMessageMeter::new(&limits(1, 1, 10), &off(), "a").unwrap();
        let start = Instant::now();
        assert_eq!(meter.charge(start), Verdict::Admit);
        assert!(matches!(meter.charge(start), Verdict::Wait(_)));
        // Still waiting just under the limit.
        assert!(matches!(
            meter.charge(start + Duration::from_millis(9_999)),
            Verdict::Wait(_)
        ));
        assert_eq!(
            meter.charge(start + Duration::from_secs(10)),
            Verdict::Close
        );
    }

    #[test]
    fn a_message_admitted_without_waiting_resets_the_close_clock() {
        let mut meter = WsMessageMeter::new(&limits(100, 1, 1), &off(), "a").unwrap();
        let start = Instant::now();
        assert_eq!(meter.charge(start), Verdict::Admit);
        assert!(matches!(meter.charge(start), Verdict::Wait(_)));
        assert!(meter.throttled_since.is_some());
        // The held message goes once its token is due — it waited, so the run
        // goes on.
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(meter.charge(Instant::now()), Verdict::Admit);
        assert!(meter.throttled_since.is_some());
        // The next one arrives within the rate: the run is over.
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(meter.charge(Instant::now()), Verdict::Admit);
        assert!(meter.throttled_since.is_none());
    }

    #[test]
    fn zero_close_secs_only_slows() {
        let mut meter = WsMessageMeter::new(&limits(1, 1, 0), &off(), "a").unwrap();
        let start = Instant::now();
        assert_eq!(meter.charge(start), Verdict::Admit);
        assert!(matches!(
            meter.charge(start + Duration::from_secs(3_600)),
            Verdict::Wait(_)
        ));
    }

    #[test]
    fn zero_rate_with_the_did_limit_off_meters_nothing() {
        assert!(WsMessageMeter::new(&limits(0, 1, 10), &off(), "a").is_none());
    }

    #[test]
    fn an_anonymous_session_is_not_metered() {
        assert!(WsMessageMeter::new(&limits(1, 1, 10), &DidRateLimiter::new(1, 1), "").is_none());
    }

    #[test]
    fn exempt_dids_are_not_metered() {
        let did_limiter = DidRateLimiter::new(1, 1)
            .with_exempt_did_hashes(["mediator".to_string(), "admin".to_string()]);
        for exempt in ["mediator", "admin"] {
            assert!(WsMessageMeter::new(&limits(1, 1, 10), &did_limiter, exempt).is_none());
        }
        assert!(WsMessageMeter::new(&limits(1, 1, 10), &did_limiter, "user").is_some());
        // Exempt with the per-DID limit off, too.
        let did_limiter = off().with_exempt_did_hashes(["admin".to_string()]);
        assert!(WsMessageMeter::new(&limits(1, 1, 10), &did_limiter, "admin").is_none());
    }

    /// Two sockets of one DID share the DID's budget, while each has a
    /// per-socket budget of its own.
    #[test]
    fn sockets_of_one_did_share_the_did_budget() {
        let did_limiter = DidRateLimiter::new(1, 3);
        let socket_limits = limits(1_000, 1_000, 10);
        let mut first = WsMessageMeter::new(&socket_limits, &did_limiter, "a").unwrap();
        let mut second = WsMessageMeter::new(&socket_limits, &did_limiter, "a").unwrap();
        let now = Instant::now();
        assert_eq!(first.charge(now), Verdict::Admit);
        assert_eq!(first.charge(now), Verdict::Admit);
        assert_eq!(second.charge(now), Verdict::Admit);
        assert!(
            matches!(second.charge(now), Verdict::Wait(_)),
            "the DID's burst of 3 is spent across both sockets"
        );
        // Another DID is unaffected.
        let mut other = WsMessageMeter::new(&socket_limits, &did_limiter, "b").unwrap();
        assert_eq!(other.charge(now), Verdict::Admit);
    }

    /// A message refused by the DID budget after paying the socket budget is
    /// not charged to the socket again when it is retried.
    #[test]
    fn a_held_message_is_charged_to_each_budget_once() {
        let did_limiter = DidRateLimiter::new(1, 1);
        let mut meter = WsMessageMeter::new(&limits(1, 2, 10), &did_limiter, "a").unwrap();
        let now = Instant::now();
        assert_eq!(meter.charge(now), Verdict::Admit); // socket 1/2, DID 1/1
        assert!(matches!(meter.charge(now), Verdict::Wait(_))); // socket 2/2, DID refused
        assert!(meter.socket_paid);
        // Retrying it does not touch the (now empty) socket budget: it waits
        // only for the DID.
        assert!(matches!(meter.charge(now), Verdict::Wait(_)));
        assert!(meter.socket_paid && !meter.did_paid);
    }
}
