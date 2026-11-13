//! Simple circuit breaker for Redis connections.
//!
//! States:
//! - **Closed**: Normal operation. All requests go through.
//! - **Open**: Redis is known to be down. Requests fail fast without trying.
//! - **HalfOpen**: Testing if Redis has recovered. One request goes through.
//!
//! Transitions:
//! - Closed → Open: after `failure_threshold` consecutive failures
//! - Open → HalfOpen: after `open_duration` has elapsed
//! - HalfOpen → Closed: on success
//! - HalfOpen → Open: on failure (resets the timer)
//! - HalfOpen → HalfOpen, with another probe let through: when the probe has
//!   reported nothing within `open_duration` (it was cancelled, or never sent
//!   a command), so a lost probe cannot leave the breaker failing every
//!   request until restart.
//!
//! The Redis store reports the outcome of every command it sends (see
//! `RedisConnection::with_breaker`), so the breaker follows the database's
//! actual health.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tracing::{error, info, warn};

/// Circuit breaker state values
const STATE_CLOSED: u32 = 0;
const STATE_OPEN: u32 = 1;
const STATE_HALF_OPEN: u32 = 2;

// Prometheus metric names emitted by the breaker. Mirrors the
// constants in the mediator's `common::metrics::names` module — kept
// here as raw strings so the breaker can live in mediator-common
// without depending on the mediator's full metrics registry.
const METRIC_CIRCUIT_BREAKER_STATE: &str = "circuit_breaker_state";
const METRIC_CIRCUIT_BREAKER_TRIPS_TOTAL: &str = "circuit_breaker_trips_total";

/// A lock-free circuit breaker using atomics.
pub struct CircuitBreaker {
    state: AtomicU32,
    consecutive_failures: AtomicU32,
    failure_threshold: u32,
    /// When the circuit was opened, or the current HalfOpen probe let
    /// through (unix timestamp seconds)
    opened_at: AtomicU64,
    /// How long to wait before transitioning from Open to HalfOpen
    open_duration_secs: u64,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, open_duration_secs: u64) -> Self {
        Self {
            state: AtomicU32::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            failure_threshold,
            opened_at: AtomicU64::new(0),
            open_duration_secs,
        }
    }

    /// Check if a request should be allowed through.
    /// Returns `true` if allowed, `false` if the circuit is open.
    pub fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED => true,
            STATE_OPEN => {
                let now = now_secs();
                let opened = self.opened_at.load(Ordering::Relaxed);
                if now.saturating_sub(opened) >= self.open_duration_secs {
                    // Transition to HalfOpen
                    if self
                        .state
                        .compare_exchange(
                            STATE_OPEN,
                            STATE_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        self.opened_at.store(now, Ordering::Release);
                        info!("Circuit breaker: Open → HalfOpen (testing Redis connectivity)");
                        return true;
                    }
                }
                false
            }
            STATE_HALF_OPEN => {
                // One probe at a time; others fail fast. A probe that has
                // reported nothing for `open_duration` is taken as lost (its
                // task was cancelled, or it never sent a command), and the
                // next request becomes the probe.
                let now = now_secs();
                let started = self.opened_at.load(Ordering::Acquire);
                now.saturating_sub(started) >= self.open_duration_secs.max(1)
                    && self
                        .opened_at
                        .compare_exchange(started, now, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
            }
            _ => true,
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let prev = self.state.swap(STATE_CLOSED, Ordering::AcqRel);
        if prev == STATE_HALF_OPEN {
            metrics::gauge!(METRIC_CIRCUIT_BREAKER_STATE).set(0.0);
            info!("Circuit breaker: HalfOpen → Closed (Redis recovered)");
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED if failures >= self.failure_threshold => {
                self.state.store(STATE_OPEN, Ordering::Release);
                self.opened_at.store(now_secs(), Ordering::Release);
                metrics::counter!(METRIC_CIRCUIT_BREAKER_TRIPS_TOTAL).increment(1);
                metrics::gauge!(METRIC_CIRCUIT_BREAKER_STATE).set(1.0);
                error!(
                    "Circuit breaker: Closed → Open (threshold {} reached, {} consecutive failures)",
                    self.failure_threshold, failures
                );
            }
            STATE_HALF_OPEN => {
                self.state.store(STATE_OPEN, Ordering::Release);
                self.opened_at.store(now_secs(), Ordering::Release);
                warn!("Circuit breaker: HalfOpen → Open (probe failed)");
            }
            _ => {}
        }
    }

    /// Check if the circuit is currently open (failing fast)
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Relaxed) == STATE_OPEN
    }

    /// Get current state as a string (for health checks)
    pub fn state_str(&self) -> &'static str {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

fn now_secs() -> u64 {
    super::time::unix_timestamp_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_closed() {
        let cb = CircuitBreaker::new(3, 5);
        assert!(cb.allow_request());
        assert_eq!(cb.state_str(), "closed");
    }

    #[test]
    fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, 5);
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow_request()); // Still closed
        cb.record_failure(); // 3rd failure = threshold
        assert!(!cb.allow_request()); // Now open
        assert_eq!(cb.state_str(), "open");
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(3, 5);
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // Reset
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow_request()); // Still closed (only 2 consecutive)
    }

    #[test]
    fn test_half_open_success_closes() {
        let cb = CircuitBreaker::new(1, 0); // Opens after 1 failure, 0s recovery
        cb.record_failure();
        // With 0 second open_duration, allow_request immediately transitions to HalfOpen
        assert!(cb.allow_request()); // Open → HalfOpen, allows probe
        assert_eq!(cb.state_str(), "half_open");
        cb.record_success();
        assert_eq!(cb.state_str(), "closed");
        assert!(cb.allow_request());
    }

    #[test]
    fn a_lost_probe_lets_another_through_after_the_recovery_time() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure();
        // Pretend the circuit opened long ago, so the next request probes.
        cb.opened_at.store(0, Ordering::Release);
        assert!(cb.allow_request());
        assert_eq!(cb.state_str(), "half_open");
        // The probe never reports. Within the recovery time nothing passes.
        assert!(!cb.allow_request());
        // Past it, the next request becomes the probe, once.
        cb.opened_at.store(now_secs() - 2, Ordering::Release);
        assert!(cb.allow_request());
        assert!(!cb.allow_request());
        cb.record_success();
        assert_eq!(cb.state_str(), "closed");
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(1, 0);
        cb.record_failure();
        // With 0 second open_duration, allow_request immediately transitions to HalfOpen
        assert!(cb.allow_request()); // Open → HalfOpen probe
        assert_eq!(cb.state_str(), "half_open");
        cb.record_failure(); // Probe failed
        assert_eq!(cb.state_str(), "open");
    }
}
