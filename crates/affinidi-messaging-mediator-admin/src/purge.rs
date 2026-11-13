//! Preview-then-confirm purges.
//!
//! A purge removes messages for good, so the console never runs one blind:
//! [`MediatorConsole::purge_preview`](crate::MediatorConsole::purge_preview)
//! counts what would go and returns a [`PurgePlan`]; the user confirms the
//! count; [`MediatorConsole::purge`](crate::MediatorConsole::purge) carries it
//! out, pinned to the preview's instant: it never removes a message that
//! arrived after the preview. It may remove fewer than were counted (some may
//! have been delivered meanwhile), and its answer says how many went.

use affinidi_messaging_sdk::tasks::messaging::queue::purge::v0_1::Queue;
use chrono::{DateTime, Utc};

use crate::console::Target;

/// What to purge.
#[derive(Clone, Debug)]
pub struct PurgeRequest {
    /// Whose queue: `None` is the console's own account.
    pub target: Target,
    pub queue: Queue,
    /// Only messages exchanged with this counterparty.
    pub peer: Option<String>,
    /// Only messages queued at least this long.
    pub older_than_seconds: Option<u64>,
}

/// A counted purge, ready to confirm.
#[derive(Clone, Debug)]
pub struct PurgePlan {
    pub request: PurgeRequest,
    /// Messages the preview matched — what the user is asked to confirm. The
    /// purge removes at most these.
    pub matched: u64,
    pub matched_bytes: u64,
    /// When the preview was asked for (just before it was sent). The purge
    /// is pinned to this instant.
    pub previewed_at: DateTime<Utc>,
}

/// `plan`'s request as the purge sends it at `now`: aged so that only
/// messages already old enough at the preview can match.
///
/// A message matched the preview when it had been queued `older_than` (zero
/// without one) by `previewed_at`. At `now` that same set is the messages
/// queued `older_than + (now - previewed_at)`. The elapsed time is rounded up
/// to whole seconds (the member's unit) and is at least one, so the cutoff
/// never moves past the preview: the rounding can only leave a message out.
pub(crate) fn pinned_to_preview(plan: &PurgePlan, now: DateTime<Utc>) -> PurgeRequest {
    let elapsed_ms = (now - plan.previewed_at).num_milliseconds().max(0) as u64;
    let elapsed = elapsed_ms.div_ceil(1_000).max(1);
    PurgeRequest {
        older_than_seconds: Some(
            plan.request
                .older_than_seconds
                .unwrap_or(0)
                .saturating_add(elapsed),
        ),
        ..plan.request.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(older_than_seconds: Option<u64>, previewed_at: DateTime<Utc>) -> PurgePlan {
        PurgePlan {
            request: PurgeRequest {
                target: Some("abc".into()),
                queue: Queue::Receive,
                peer: Some("peer".into()),
                older_than_seconds,
            },
            matched: 3,
            matched_bytes: 30,
            previewed_at,
        }
    }

    #[test]
    fn the_purge_reaches_back_no_later_than_the_preview() {
        let at = Utc::now();
        let ms = chrono::Duration::milliseconds;
        // 2.3 s after the preview: 3 s back, rounded up.
        let r = pinned_to_preview(&plan(None, at), at + ms(2_300));
        assert_eq!(r.older_than_seconds, Some(3));
        assert_eq!(r.peer.as_deref(), Some("peer"));
        assert_eq!(r.target.as_deref(), Some("abc"));
        // Whole seconds stay whole.
        let r = pinned_to_preview(&plan(None, at), at + ms(4_000));
        assert_eq!(r.older_than_seconds, Some(4));
        // At once, or with the clock stepped back: still a second.
        let r = pinned_to_preview(&plan(None, at), at - ms(500));
        assert_eq!(r.older_than_seconds, Some(1));
    }

    #[test]
    fn a_requested_age_is_measured_from_the_preview() {
        // "Older than an hour" at the preview is an hour plus the time since
        // at the purge, so nothing that turned an hour old meanwhile goes.
        let at = Utc::now();
        let r = pinned_to_preview(
            &plan(Some(3_600), at),
            at + chrono::Duration::milliseconds(10_001),
        );
        assert_eq!(r.older_than_seconds, Some(3_611));
    }
}
