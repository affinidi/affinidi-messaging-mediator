//! The wake rate limits (`messaging/wake/request/0.1` Consumer rule 7): a
//! budget per (requester, addressee) pair and one per addressee, in fixed
//! windows of the mediator's clock.
//!
//! Charged only when a ring is otherwise due, so a request refused by an
//! earlier rule costs nothing. Kept in memory: each instance applies them on
//! its own (see the module docs of [`super`]).

use std::collections::HashMap;

use crate::common::config::WakeConfig;

/// Entries kept before the windows that have closed are swept out. Bounds the
/// memory a stream of distinct requesters can take.
const SWEEP_AT: usize = 10_000;

const MINUTE: u64 = 60;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

/// Why a ring was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Limited {
    /// The requester's budget for this addressee is spent.
    Pair,
    /// The addressee was rung within the coalescing window: this request is
    /// covered by that ring.
    Coalesced,
    /// The addressee's hourly budget is spent.
    Addressee,
}

impl Limited {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Limited::Pair => "rate_limited",
            Limited::Coalesced => "coalesced",
            Limited::Addressee => "addressee_limited",
        }
    }
}

/// One fixed window: `count` rings since `start`.
#[derive(Clone, Copy, Debug, Default)]
struct Window {
    start: u64,
    count: u32,
}

impl Window {
    fn allows(&self, now: u64, len: u64, max: u32) -> bool {
        now >= self.start.saturating_add(len) || self.count < max
    }

    fn take(&mut self, now: u64, len: u64) {
        if now >= self.start.saturating_add(len) {
            self.start = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
    }

    fn closed(&self, now: u64, len: u64) -> bool {
        now >= self.start.saturating_add(len)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Pair {
    minute: Window,
    day: Window,
}

#[derive(Clone, Copy, Debug, Default)]
struct Addressee {
    last_ring: Option<u64>,
    hour: Window,
}

/// The counters, keyed by DID hash.
#[derive(Debug, Default)]
pub(crate) struct Limiter {
    pairs: HashMap<(String, String), Pair>,
    addressees: HashMap<String, Addressee>,
}

impl Limiter {
    /// Charge one ring from `requester` to `addressee` at `now` (Unix
    /// seconds), or say why it may not happen. Nothing is charged on a
    /// refusal.
    pub(crate) fn try_ring(
        &mut self,
        config: &WakeConfig,
        requester: &str,
        addressee: &str,
        now: u64,
    ) -> Result<(), Limited> {
        self.sweep(now);
        let key = (requester.to_string(), addressee.to_string());
        let pair = self.pairs.get(&key).copied().unwrap_or_default();
        if !pair.minute.allows(now, MINUTE, config.pair_per_minute)
            || !pair.day.allows(now, DAY, config.pair_per_day)
        {
            return Err(Limited::Pair);
        }
        let to = self.addressees.get(addressee).copied().unwrap_or_default();
        if let Some(last) = to.last_ring
            && now < last.saturating_add(config.addressee_coalesce_seconds)
        {
            return Err(Limited::Coalesced);
        }
        if !to.hour.allows(now, HOUR, config.addressee_per_hour) {
            return Err(Limited::Addressee);
        }

        let pair = self.pairs.entry(key).or_default();
        pair.minute.take(now, MINUTE);
        pair.day.take(now, DAY);
        let to = self.addressees.entry(addressee.to_string()).or_default();
        to.hour.take(now, HOUR);
        to.last_ring = Some(now);
        Ok(())
    }

    /// Drop entries whose every window has closed, once there are many.
    fn sweep(&mut self, now: u64) {
        if self.pairs.len() + self.addressees.len() < SWEEP_AT {
            return;
        }
        self.pairs.retain(|_, p| !p.day.closed(now, DAY));
        self.addressees.retain(|_, a| !a.hour.closed(now, HOUR));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WakeConfig {
        WakeConfig::default()
    }

    #[test]
    fn a_pair_rings_once_a_minute() {
        let mut l = Limiter::default();
        let c = WakeConfig {
            addressee_coalesce_seconds: 0,
            ..config()
        };
        assert_eq!(l.try_ring(&c, "w", "d", 1_000), Ok(()));
        assert_eq!(l.try_ring(&c, "w", "d", 1_030), Err(Limited::Pair));
        assert_eq!(l.try_ring(&c, "w", "d", 1_060), Ok(()));
    }

    #[test]
    fn a_pair_rings_ten_times_a_day() {
        let mut l = Limiter::default();
        let c = WakeConfig {
            addressee_coalesce_seconds: 0,
            addressee_per_hour: 1_000,
            ..config()
        };
        let start = 10_000;
        for i in 0..10 {
            assert_eq!(l.try_ring(&c, "w", "d", start + i * 61), Ok(()), "ring {i}");
        }
        assert_eq!(
            l.try_ring(&c, "w", "d", start + 10 * 61),
            Err(Limited::Pair)
        );
        assert_eq!(l.try_ring(&c, "w", "d", start + DAY), Ok(()));
    }

    #[test]
    fn rings_for_one_addressee_coalesce_whoever_asks() {
        let mut l = Limiter::default();
        let c = config();
        assert_eq!(l.try_ring(&c, "w1", "d", 100), Ok(()));
        assert_eq!(l.try_ring(&c, "w2", "d", 110), Err(Limited::Coalesced));
        assert_eq!(l.try_ring(&c, "w2", "d", 115), Ok(()));
    }

    #[test]
    fn an_addressee_rings_at_most_thirty_times_an_hour() {
        let mut l = Limiter::default();
        let c = config();
        let start = 50_000;
        for i in 0..30 {
            let requester = format!("w{i}");
            assert_eq!(
                l.try_ring(&c, &requester, "d", start + i * 15),
                Ok(()),
                "ring {i}"
            );
        }
        assert_eq!(
            l.try_ring(&c, "another", "d", start + 30 * 15),
            Err(Limited::Addressee)
        );
        assert_eq!(l.try_ring(&c, "another", "d", start + HOUR), Ok(()));
    }

    #[test]
    fn a_refusal_charges_nothing() {
        let mut l = Limiter::default();
        let c = config();
        assert_eq!(l.try_ring(&c, "w1", "d", 100), Ok(()));
        // Coalesced: w2's pair budget is untouched by the refusal.
        assert_eq!(l.try_ring(&c, "w2", "d", 101), Err(Limited::Coalesced));
        assert_eq!(l.try_ring(&c, "w2", "d", 116), Ok(()));
    }

    #[test]
    fn one_pair_does_not_spend_another_addressees_budget() {
        let mut l = Limiter::default();
        let c = config();
        assert_eq!(l.try_ring(&c, "w", "d1", 100), Ok(()));
        assert_eq!(l.try_ring(&c, "w", "d2", 100), Ok(()));
    }
}
