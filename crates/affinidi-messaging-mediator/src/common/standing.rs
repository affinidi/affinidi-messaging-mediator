//! When a live socket must re-read its account's role and ACLs.
//!
//! A WebSocket re-reads the account behind its session before handling a
//! frame (see `handlers::websocket::refresh_standing`), so a demotion or a
//! block reaches a socket that is already open. Doing that read on **every**
//! frame made store load scale with frame rate (#159). It is now skipped when
//! both hold:
//!
//! - no account change has been handled on this instance, or announced to it
//!   by another instance, since the socket last read (the [`epoch`]); and
//! - that read is younger than [`STANDING_FRESH`].
//!
//! So a change made through any mediator instance sharing the store (an ACL
//! set, a role change, an account removal: each is published to the others)
//! reaches the socket on its next frame, as before. Only a change that no
//! instance's handlers saw, made in the store directly, waits up to
//! [`STANDING_FRESH`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long a socket's last account read stands when no account change has
/// been seen since.
pub const STANDING_FRESH: Duration = Duration::from_secs(2);

static EPOCH: AtomicU64 = AtomicU64::new(0);

/// The current account-change epoch.
pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}

/// An account's role or ACLs changed, or it was removed: every socket
/// re-reads its own on its next frame. Process-wide on purpose. It cannot
/// name the socket to refresh without a registry of sockets by DID, and an
/// extra read on each open socket after an admin change is cheap next to a
/// read on every frame.
pub fn account_changed() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// A socket's last account read.
#[derive(Debug, Clone, Copy)]
pub struct StandingRead {
    at: Instant,
    epoch: u64,
}

impl StandingRead {
    /// A read taken now, against `epoch` as it was **before** the read: a
    /// change landing during the read then still counts as unseen.
    pub fn taken(epoch: u64) -> Self {
        Self {
            at: Instant::now(),
            epoch,
        }
    }

    /// Whether `last` (if any) must be refreshed before the next frame.
    pub fn is_stale(last: Option<&Self>) -> bool {
        Self::stale_against(last, epoch())
    }

    fn stale_against(last: Option<&Self>, now_epoch: u64) -> bool {
        last.is_none_or(|r| r.epoch != now_epoch || r.at.elapsed() >= STANDING_FRESH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Against explicit epochs: the process-wide one is bumped by any test
    // that changes an account, concurrently with this one.
    #[test]
    fn a_fresh_read_stands_until_an_account_changes() {
        assert!(StandingRead::stale_against(None, 7), "never read: read now");
        let read = StandingRead::taken(7);
        assert!(!StandingRead::stale_against(Some(&read), 7));
        assert!(
            StandingRead::stale_against(Some(&read), 8),
            "an account change is seen on the next frame"
        );
    }

    #[test]
    fn a_read_goes_stale_with_age() {
        let read = StandingRead {
            at: Instant::now() - STANDING_FRESH,
            epoch: 7,
        };
        assert!(StandingRead::stale_against(Some(&read), 7));
    }

    #[test]
    fn account_changed_moves_the_epoch() {
        let before = epoch();
        account_changed();
        assert!(epoch() > before);
    }
}
