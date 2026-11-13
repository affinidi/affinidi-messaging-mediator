//! Which background requests are in flight, so their answers land where they
//! were asked for.
//!
//! Every request a screen sends is tagged with a [`Ticket`]: what it loads
//! ([`Job`]), a sequence number, and the view it was asked for — the account
//! and queue on the Account screen, the ranking on Queues, and so on. An
//! answer is applied only while its ticket is still the latest for its job
//! *and* the screen still shows that view; anything else is a late answer
//! for something the user has moved away from, and is dropped. A view also
//! sends one request per job at a time: a refresh while one is pending is
//! skipped, so a slow mediator does not pile up a batch per tick.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What a background request loads or does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Job {
    Stats,
    Queues,
    Status,
    Messages,
    AccountInfo,
    Audit,
    Accounts,
    Mux,
    Grants,
    Config,
    /// The next page of a list, added to what is shown.
    More(crate::app::List),
    /// A message opened for reading.
    Inspect,
    /// A purge counted for confirmation.
    PurgePreview,
}

/// Which request an [`Update`](crate::Update) answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub(crate) job: Job,
    seq: u64,
    /// The view it was asked for.
    pub(crate) view: String,
}

/// A request pending longer than this is taken as lost, and asked again.
const STUCK: Duration = Duration::from_secs(90);

/// The requests in flight, by job.
#[derive(Default)]
pub(crate) struct InFlight {
    next: u64,
    pending: HashMap<Job, (u64, String, Instant)>,
}

impl InFlight {
    /// Start `job` for `view`. `None` when the same request is already
    /// pending (and not stuck): a refresh then waits for it rather than
    /// sending another. A request for another view replaces the pending one,
    /// whose answer will be dropped.
    pub(crate) fn begin(&mut self, job: Job, view: String, now: Instant) -> Option<Ticket> {
        if let Some((_, pending, at)) = self.pending.get(&job)
            && *pending == view
            && now.duration_since(*at) < STUCK
        {
            return None;
        }
        Some(self.force(job, view, now))
    }

    /// Start `job` for `view` whatever is pending: a user's action, which
    /// supersedes an earlier one of the same kind.
    pub(crate) fn force(&mut self, job: Job, view: String, now: Instant) -> Ticket {
        self.next += 1;
        self.pending.insert(job, (self.next, view.clone(), now));
        Ticket {
            job,
            seq: self.next,
            view,
        }
    }

    /// Whether `ticket` answers the latest request for its job. Either way the
    /// job is no longer pending once its latest request is answered.
    pub(crate) fn finish(&mut self, ticket: &Ticket) -> bool {
        match self.pending.get(&ticket.job) {
            Some((seq, _, _)) if *seq == ticket.seq => {
                self.pending.remove(&ticket.job);
                true
            }
            _ => false,
        }
    }

    /// Whether `job` has a request pending.
    pub(crate) fn is_pending(&self, job: Job) -> bool {
        self.pending.contains_key(&job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refresh_waits_for_the_same_request() {
        let mut f = InFlight::default();
        let now = Instant::now();
        let first = f.begin(Job::Messages, "a/recv".into(), now).unwrap();
        assert!(f.begin(Job::Messages, "a/recv".into(), now).is_none());
        assert!(f.finish(&first));
        assert!(f.begin(Job::Messages, "a/recv".into(), now).is_some());
    }

    #[test]
    fn a_late_answer_for_another_view_is_dropped() {
        let mut f = InFlight::default();
        let now = Instant::now();
        let for_a = f.begin(Job::Status, "a".into(), now).unwrap();
        // The user moved to account b before a's answer came.
        let for_b = f.begin(Job::Status, "b".into(), now).unwrap();
        assert!(!f.finish(&for_a), "a's answer is stale");
        assert!(f.finish(&for_b));
        assert!(!f.finish(&for_b), "answered once");
    }

    #[test]
    fn a_stuck_request_is_asked_again() {
        let mut f = InFlight::default();
        let then = Instant::now();
        f.begin(Job::Stats, String::new(), then).unwrap();
        assert!(f.begin(Job::Stats, String::new(), then + STUCK).is_some());
    }

    #[test]
    fn jobs_are_tracked_apart() {
        let mut f = InFlight::default();
        let now = Instant::now();
        let stats = f.begin(Job::Stats, String::new(), now).unwrap();
        let queues = f.begin(Job::Queues, "recv/count".into(), now).unwrap();
        assert!(f.is_pending(Job::Stats));
        assert!(f.finish(&queues));
        assert!(f.finish(&stats));
        assert!(!f.is_pending(Job::Stats));
    }
}
