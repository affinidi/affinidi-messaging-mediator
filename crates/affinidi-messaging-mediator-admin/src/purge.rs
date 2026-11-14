//! Preview-then-confirm purges.
//!
//! A purge removes messages for good, so the console never runs one blind:
//! [`MediatorConsole::purge_preview`](crate::MediatorConsole::purge_preview)
//! counts what would go and returns a [`PurgePlan`]; the user confirms the
//! count; [`MediatorConsole::purge`](crate::MediatorConsole::purge) carries it
//! out, pinned to the preview's instant: it never removes a message that
//! arrived after the preview. It may remove fewer than were counted (some may
//! have been delivered meanwhile, and the pin keeps a safety margin), and its
//! answer says how many went.

use affinidi_messaging_sdk::tasks::messaging::queue::purge::v0_1::Queue;
use chrono::{DateTime, Utc};

use crate::console::Target;

/// Seconds added to a confirming purge's age on top of the time since the
/// preview, to cover the request's transit and queueing before the mediator
/// runs it. The age is measured on the mediator's clock when it executes, so
/// without a margin a purge that executes more than about a second after it
/// was sent could match a message stored just after the preview. This is the
/// least margin; a console whose request timeout is longer uses that instead
/// (see `MediatorConsole::purge`), since a purge still being waited for
/// executes within it. The cost is that messages stored in this window before
/// the preview are spared too. The exact fix is the purge task's
/// `storedBefore` member, which the console will send once the SDK supports
/// it.
pub const PURGE_TRANSIT_MARGIN_SECS: u64 = 30;

/// The margin a console with `request_timeout` adds to a confirming purge:
/// the timeout in whole seconds, rounded up, and at least
/// [`PURGE_TRANSIT_MARGIN_SECS`].
pub(crate) fn transit_margin_secs(request_timeout: std::time::Duration) -> u64 {
    let secs = request_timeout
        .as_millis()
        .div_ceil(1_000)
        .try_into()
        .unwrap_or(u64::MAX);
    secs.max(PURGE_TRANSIT_MARGIN_SECS)
}

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
/// to whole seconds (the member's unit) and is at least one, and
/// `margin_secs` (from [`transit_margin_secs`]) is added for the time the
/// request takes to execute, so the cutoff never moves past the preview: the
/// rounding and the margin can only leave a message out.
pub(crate) fn pinned_to_preview(
    plan: &PurgePlan,
    now: DateTime<Utc>,
    margin_secs: u64,
) -> PurgeRequest {
    let elapsed_ms = (now - plan.previewed_at).num_milliseconds().max(0) as u64;
    let elapsed = elapsed_ms
        .div_ceil(1_000)
        .max(1)
        .saturating_add(margin_secs);
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
        let margin = PURGE_TRANSIT_MARGIN_SECS;
        // 2.3 s after the preview: 3 s back, rounded up, plus the margin.
        let r = pinned_to_preview(&plan(None, at), at + ms(2_300), PURGE_TRANSIT_MARGIN_SECS);
        assert_eq!(r.older_than_seconds, Some(3 + margin));
        assert_eq!(r.peer.as_deref(), Some("peer"));
        assert_eq!(r.target.as_deref(), Some("abc"));
        // Whole seconds stay whole.
        let r = pinned_to_preview(&plan(None, at), at + ms(4_000), PURGE_TRANSIT_MARGIN_SECS);
        assert_eq!(r.older_than_seconds, Some(4 + margin));
        // At once, or with the clock stepped back: still a second.
        let r = pinned_to_preview(&plan(None, at), at - ms(500), PURGE_TRANSIT_MARGIN_SECS);
        assert_eq!(r.older_than_seconds, Some(1 + margin));
    }

    /// A message stored just after the preview is not selected even when the
    /// purge executes well after it was sent, as long as it executes within
    /// the margin.
    #[test]
    fn a_message_stored_after_the_preview_survives_a_slow_purge() {
        let at = Utc::now();
        let sent = at + chrono::Duration::milliseconds(2_000);
        let r = pinned_to_preview(&plan(None, at), sent, PURGE_TRANSIT_MARGIN_SECS);
        let age_cutoff = r.older_than_seconds.unwrap() as i64;
        // Stored 1 ms after the preview; the mediator runs the purge 29 s
        // after the console sent it.
        let stored = at + chrono::Duration::milliseconds(1);
        let executes = sent + chrono::Duration::seconds(29);
        let age = (executes - stored).num_seconds();
        assert!(age < age_cutoff, "age {age} must stay under {age_cutoff}");
    }

    #[test]
    fn a_requested_age_is_measured_from_the_preview() {
        // "Older than an hour" at the preview is an hour plus the time since
        // at the purge, so nothing that turned an hour old meanwhile goes.
        let at = Utc::now();
        let r = pinned_to_preview(
            &plan(Some(3_600), at),
            at + chrono::Duration::milliseconds(10_001),
            PURGE_TRANSIT_MARGIN_SECS,
        );
        assert_eq!(
            r.older_than_seconds,
            Some(3_611 + PURGE_TRANSIT_MARGIN_SECS)
        );
    }

    /// A console whose request timeout is longer than the least margin
    /// waits longer for a purge, so its margin grows to match.
    #[test]
    fn the_margin_is_at_least_the_request_timeout() {
        use std::time::Duration;
        assert_eq!(
            transit_margin_secs(Duration::from_secs(5)),
            PURGE_TRANSIT_MARGIN_SECS
        );
        assert_eq!(transit_margin_secs(Duration::from_secs(30)), 30);
        assert_eq!(transit_margin_secs(Duration::from_millis(90_001)), 91);
    }
}
