//! The wake rate limits (`messaging/wake/request/0.1` Consumer rule 7): a
//! budget per (requester, addressee) pair and one per addressee, in fixed
//! windows of the mediator's clock.
//!
//! Charged only when a ring is otherwise due, so a request refused by an
//! earlier rule costs nothing. Kept in memory: each instance applies them on
//! its own (see the module docs of [`super`]).

use std::collections::HashMap;

use crate::common::config::WakeConfig;

/// Entries kept before the windows that have closed are swept out.
const SWEEP_AT: usize = 10_000;

/// Pair entries kept at most. A pair entry is only made by a ring that passed
/// every earlier rule (queued, undelivered mail the requester stored for an
/// account with a wake handle) and spent that addressee's hourly budget, so
/// live entries are already bounded by the wake-capable accounts times their
/// budgets; this is a hard ceiling on top. Past it, the entry whose day
/// window started first is dropped. That only resets one requester's budget
/// for one addressee (a requester minting enough DIDs could reset its own):
/// the addressee's own coalescing and hourly budget still hold, because the
/// addressee counters are never evicted. They are keyed by addressee only, and
/// an addressee entry is only made for a local account with a wake handle that
/// was rung, so they are bounded by those accounts, not by requesters.
const MAX_PAIRS: usize = 100_000;

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
    /// No sweep before this instant, so a map full of live entries is not
    /// rescanned on every request.
    next_sweep: u64,
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

        if !self.pairs.contains_key(&key) && self.pairs.len() >= MAX_PAIRS {
            self.evict_oldest_pair();
        }
        let pair = self.pairs.entry(key).or_default();
        pair.minute.take(now, MINUTE);
        pair.day.take(now, DAY);
        let to = self.addressees.entry(addressee.to_string()).or_default();
        to.hour.take(now, HOUR);
        to.last_ring = Some(now);
        Ok(())
    }

    /// Drop entries whose every window has closed, once there are many, at
    /// most once a minute.
    fn sweep(&mut self, now: u64) {
        if self.pairs.len() + self.addressees.len() < SWEEP_AT || now < self.next_sweep {
            return;
        }
        self.next_sweep = now.saturating_add(MINUTE);
        self.pairs.retain(|_, p| !p.day.closed(now, DAY));
        self.addressees.retain(|_, a| !a.hour.closed(now, HOUR));
    }

    /// Drop the pair whose day window started first.
    fn evict_oldest_pair(&mut self) {
        if let Some(oldest) = self
            .pairs
            .iter()
            .min_by_key(|(_, p)| p.day.start)
            .map(|(k, _)| k.clone())
        {
            self.pairs.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Past the ceiling, a new pair replaces the oldest; the map never grows
    /// beyond it.
    #[test]
    fn the_pair_map_is_bounded() {
        let mut l = Limiter::default();
        let c = WakeConfig {
            addressee_coalesce_seconds: 0,
            addressee_per_hour: u32::MAX,
            ..config()
        };
        // Unix-like instants, all within one day, so no sweep removes them;
        // "oldest" rang first.
        const T: u64 = 1_800_000_000;
        assert_eq!(l.try_ring(&c, "oldest", "d", T), Ok(()));
        for i in 1..MAX_PAIRS {
            let now = T + 1 + (i as u64) / 4;
            assert_eq!(l.try_ring(&c, &format!("r{i}"), "d", now), Ok(()));
        }
        assert_eq!(l.pairs.len(), MAX_PAIRS);
        assert_eq!(l.try_ring(&c, "newcomer", "d", T + 40_000), Ok(()));
        assert_eq!(l.pairs.len(), MAX_PAIRS);
        assert!(
            !l.pairs
                .contains_key(&("oldest".to_string(), "d".to_string()))
        );
        assert!(
            l.pairs
                .contains_key(&("newcomer".to_string(), "d".to_string()))
        );
    }

    /// Evicting a pair at the ceiling resets only that requester's pair
    /// budget: the addressee's hourly budget is never evicted, so a requester
    /// that churns the pair map still cannot ring past it.
    #[test]
    fn pair_eviction_does_not_lift_the_addressee_budget() {
        let mut l = Limiter::default();
        let c = WakeConfig {
            addressee_coalesce_seconds: 0,
            addressee_per_hour: 2,
            ..config()
        };
        const T: u64 = 1_800_000_000;
        assert_eq!(l.try_ring(&c, "a", "victim", T), Ok(()));
        assert_eq!(l.try_ring(&c, "b", "victim", T + 1), Ok(()));
        // However the pair map is churned, eviction only ever removes pair
        // entries; take the extreme case where every pair has been evicted.
        while !l.pairs.is_empty() {
            l.evict_oldest_pair();
        }
        assert!(l.addressees.contains_key("victim"));
        // Fresh pair budgets, but the victim's hourly budget is spent.
        assert_eq!(
            l.try_ring(&c, "a", "victim", T + 2),
            Err(Limited::Addressee)
        );
        assert_eq!(
            l.try_ring(&c, "fresh", "victim", T + 3),
            Err(Limited::Addressee)
        );
    }

    /// A map of live entries above the sweep threshold is scanned at most once
    /// a minute, not on every request.
    #[test]
    fn a_full_map_is_swept_at_most_once_a_minute() {
        let mut l = Limiter::default();
        for i in 0..SWEEP_AT {
            l.pairs
                .insert((format!("r{i}"), "d".into()), Pair::default());
        }
        l.sweep(10);
        assert_eq!(l.next_sweep, 10 + MINUTE);
        l.sweep(20);
        assert_eq!(
            l.next_sweep,
            10 + MINUTE,
            "no second sweep within the minute"
        );
    }

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
