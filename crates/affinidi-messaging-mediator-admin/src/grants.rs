//! Stored mux grants, as an administrator manages them: which grants a
//! revocation names, what one did, and what the mediator's refusals mean.
//!
//! The calls are on [`MediatorConsole`](crate::MediatorConsole):
//! [`mux_grants`](crate::MediatorConsole::mux_grants),
//! [`mux_revoke`](crate::MediatorConsole::mux_revoke),
//! [`mux_epoch`](crate::MediatorConsole::mux_epoch) and
//! [`mux_bump_epoch`](crate::MediatorConsole::mux_bump_epoch).

use affinidi_messaging_sdk::protocols::trust_tasks::{MuxAdminRevokeOutcome, MuxAdminRevokeStop};

use crate::error::{ConsoleError, Result};

/// Which stored grants a revocation names: a principal DID's, a member DID's,
/// those between the two, or chosen grants of one member.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantSelection {
    pub principal: Option<String>,
    pub member: Option<String>,
    /// Only these grants of `member`; empty for every grant the DIDs select.
    pub grant_ids: Vec<String>,
}

impl GrantSelection {
    /// Every grant `principal` holds.
    pub fn principal(did: impl Into<String>) -> Self {
        Self {
            principal: Some(did.into()),
            ..Self::default()
        }
    }

    /// Every grant `member` has given.
    pub fn member(did: impl Into<String>) -> Self {
        Self {
            member: Some(did.into()),
            ..Self::default()
        }
    }

    /// The grants `member` gave `principal`.
    pub fn between(principal: impl Into<String>, member: impl Into<String>) -> Self {
        Self {
            principal: Some(principal.into()),
            member: Some(member.into()),
            ..Self::default()
        }
    }

    /// Only the grants `grant_ids` of `member`.
    pub fn grants(member: impl Into<String>, grant_ids: Vec<String>) -> Self {
        Self {
            member: Some(member.into()),
            grant_ids,
            ..Self::default()
        }
    }

    /// Refuse, before sending, a selection the mediator would refuse: one
    /// naming no DID, or grant ids without their member.
    pub fn check(&self) -> Result<()> {
        if self.principal.is_none() && self.member.is_none() {
            return Err(ConsoleError::Invalid(
                "name a principal DID, a member DID, or both".into(),
            ));
        }
        if !self.grant_ids.is_empty() && self.member.is_none() {
            return Err(ConsoleError::Invalid(
                "grant ids are a member's: name the member DID too".into(),
            ));
        }
        Ok(())
    }

    /// What the selection revokes, for a confirmation: "every grant of
    /// principal did:…", "2 grants of member did:…".
    pub fn describe(&self) -> String {
        let grants = match self.grant_ids.len() {
            0 => "every grant".to_string(),
            1 => "1 grant".to_string(),
            n => format!("{n} grants"),
        };
        match (&self.principal, &self.member) {
            (Some(p), Some(m)) => format!("{grants} member {m} gave principal {p}"),
            (Some(p), None) => format!("{grants} of principal {p}"),
            (None, Some(m)) => format!("{grants} of member {m}"),
            (None, None) => "nothing (no DID named)".into(),
        }
    }
}

/// What a revocation did, in a sentence: how many were revoked, how many
/// still match and, when it stopped short, why.
pub fn revoke_summary(outcome: &MuxAdminRevokeOutcome) -> String {
    summarise(
        outcome.revoked.len(),
        outcome.unmatched_grant_ids.len(),
        outcome.remaining,
        &outcome.stopped,
    )
}

fn summarise(
    revoked: usize,
    unmatched: usize,
    remaining: u64,
    stopped: &MuxAdminRevokeStop,
) -> String {
    let mut out = format!("revoked {revoked} grant(s)");
    if unmatched > 0 {
        out.push_str(&format!(", {unmatched} id(s) named no stored grant"));
    }
    let why = match stopped {
        MuxAdminRevokeStop::Done => None,
        MuxAdminRevokeStop::MaxRounds => {
            Some("stopped at the round limit; revoke again for the rest".to_string())
        }
        MuxAdminRevokeStop::NoProgress => {
            Some("the last round revoked nothing, so it stopped".to_string())
        }
        MuxAdminRevokeStop::Failed(e) => {
            let e = match crate::error::refusal(e) {
                Some((code, comment, epoch)) => {
                    crate::error::explain_refusal(&code, &comment, epoch)
                        .unwrap_or_else(|| format!("{comment} ({code})"))
                }
                None => e.to_string(),
            };
            Some(format!("a later round failed: {e}"))
        }
        _ => Some("stopped".to_string()),
    };
    match why {
        None => out.push_str("; none remain"),
        Some(why) => out.push_str(&format!("; {remaining} still match — {why}")),
    }
    out
}

/// One stored grant, by the member DID that gave it and its id — unique on
/// that member's record. What a bulk revocation names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantKey {
    pub member: String,
    pub grant_id: String,
}

impl GrantKey {
    pub fn new(member: impl Into<String>, grant_id: impl Into<String>) -> Self {
        Self {
            member: member.into(),
            grant_id: grant_id.into(),
        }
    }
}

/// What a bulk revocation did to one grant.
#[derive(Debug)]
pub enum GrantRevokeResult {
    /// The mediator revoked it.
    Revoked,
    /// It named no stored grant: already revoked or expired, by this
    /// console or anyone else. Nothing was revoked by this request.
    NotStored,
    /// The mediator refused, or the console knew it would: nothing about
    /// this grant changed. A `…:protectedAccount` refusal is a rootAdmin
    /// party's grant, which only a rootAdmin may revoke.
    Refused(ConsoleError),
    /// The request or its answer was lost in transit: the grant may or may
    /// not be revoked. List the grants again to see.
    Unconfirmed(ConsoleError),
    /// Not sent: an earlier grant's request was lost in transit, so the
    /// rest were left for another try rather than each waiting out the
    /// same failure.
    NotAttempted,
}

impl GrantRevokeResult {
    /// One grant's revocation, read from what `admin-revoke` answered for
    /// it alone: revoked only when the answer lists it as revoked.
    pub fn from_round(
        grant_id: &str,
        revoked: &[String],
        unmatched: &[String],
        stopped: &MuxAdminRevokeStop,
    ) -> Self {
        if revoked.iter().any(|g| g == grant_id) {
            return Self::Revoked;
        }
        if unmatched.iter().any(|g| g == grant_id) {
            return Self::NotStored;
        }
        match stopped {
            MuxAdminRevokeStop::Failed(e) => {
                Self::from_error(ConsoleError::from_call(clone_atm_error(e)))
            }
            // Answered, but it was neither revoked nor reported missing.
            _ => Self::Refused(ConsoleError::Unexpected(format!(
                "grant {grant_id} was neither revoked nor reported missing"
            ))),
        }
    }

    /// A failed request for one grant: a refusal changed nothing; anything
    /// else leaves the outcome unknown.
    pub fn from_error(e: ConsoleError) -> Self {
        match e {
            ConsoleError::Refused { .. }
            | ConsoleError::NotPermitted(_)
            | ConsoleError::Invalid(_) => Self::Refused(e),
            other => Self::Unconfirmed(other),
        }
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// The result in a few words, for a per-grant line.
    pub fn describe(&self) -> String {
        match self {
            Self::Revoked => "revoked".into(),
            Self::NotStored => "no longer stored (nothing revoked)".into(),
            Self::Refused(e) => format!("refused: {}", e.explain()),
            Self::Unconfirmed(e) => {
                format!("not confirmed (list again to see): {}", e.explain())
            }
            Self::NotAttempted => "not sent (an earlier request was lost)".into(),
        }
    }
}

/// The ATM error a stop carried, as an owned value (`ATMError` is not
/// `Clone`): a problem report keeps its code and comment, anything else its
/// text.
fn clone_atm_error(
    e: &affinidi_messaging_sdk::errors::ATMError,
) -> affinidi_messaging_sdk::errors::ATMError {
    use affinidi_messaging_sdk::errors::ATMError;
    match e {
        ATMError::ProblemReport(code, comment, escalate) => {
            ATMError::ProblemReport(code.clone(), comment.clone(), escalate.clone())
        }
        other => ATMError::MsgSendError(other.to_string()),
    }
}

/// What a bulk revocation did, grant by grant, in the order asked.
#[derive(Debug, Default)]
pub struct BulkRevokeOutcome {
    pub results: Vec<(GrantKey, GrantRevokeResult)>,
}

impl BulkRevokeOutcome {
    /// The grants the mediator revoked.
    pub fn revoked(&self) -> impl Iterator<Item = &GrantKey> {
        self.results
            .iter()
            .filter(|(_, r)| r.is_revoked())
            .map(|(k, _)| k)
    }

    /// Whether every grant was revoked.
    pub fn all_revoked(&self) -> bool {
        self.results.iter().all(|(_, r)| r.is_revoked())
    }

    /// What it did, in a sentence: how many of how many were revoked, and
    /// how many of the rest were missing, refused, unconfirmed or not sent.
    /// Never counts a grant as revoked that the mediator did not report.
    pub fn summary(&self) -> String {
        let count =
            |f: fn(&GrantRevokeResult) -> bool| self.results.iter().filter(|(_, r)| f(r)).count();
        let revoked = count(|r| matches!(r, GrantRevokeResult::Revoked));
        let mut out = format!("revoked {revoked} of {} grant(s)", self.results.len());
        let rest = [
            (
                count(|r| matches!(r, GrantRevokeResult::NotStored)),
                "no longer stored",
            ),
            (
                count(|r| matches!(r, GrantRevokeResult::Refused(_))),
                "refused",
            ),
            (
                count(|r| matches!(r, GrantRevokeResult::Unconfirmed(_))),
                "not confirmed",
            ),
            (
                count(|r| matches!(r, GrantRevokeResult::NotAttempted)),
                "not sent",
            ),
        ];
        let rest: Vec<String> = rest
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| format!("{n} {what}"))
            .collect();
        if !rest.is_empty() {
            out.push_str(&format!("; {}", rest.join(", ")));
        }
        out
    }

    /// One line per grant that was not revoked: which grant, and why.
    pub fn failures(&self) -> Vec<String> {
        self.results
            .iter()
            .filter(|(_, r)| !r.is_revoked())
            .map(|(k, r)| format!("{} of {}: {}", k.grant_id, k.member, r.describe()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_sdk::errors::ATMError;

    #[test]
    fn a_selection_names_a_did_and_grant_ids_need_their_member() {
        assert!(GrantSelection::principal("did:p").check().is_ok());
        assert!(GrantSelection::member("did:m").check().is_ok());
        assert!(GrantSelection::between("did:p", "did:m").check().is_ok());
        assert!(
            GrantSelection::grants("did:m", vec!["g1".into()])
                .check()
                .is_ok()
        );
        assert!(matches!(
            GrantSelection::default().check(),
            Err(ConsoleError::Invalid(_))
        ));
        let orphan = GrantSelection {
            principal: Some("did:p".into()),
            grant_ids: vec!["g1".into()],
            ..GrantSelection::default()
        };
        assert!(matches!(orphan.check(), Err(ConsoleError::Invalid(_))));
    }

    #[test]
    fn a_selection_describes_itself_for_a_confirmation() {
        assert_eq!(
            GrantSelection::principal("did:p").describe(),
            "every grant of principal did:p"
        );
        assert_eq!(
            GrantSelection::grants("did:m", vec!["a".into(), "b".into()]).describe(),
            "2 grants of member did:m"
        );
        assert_eq!(
            GrantSelection::grants("did:m", vec!["a".into()]).describe(),
            "1 grant of member did:m"
        );
        assert_eq!(
            GrantSelection::between("did:p", "did:m").describe(),
            "every grant member did:m gave principal did:p"
        );
    }

    #[test]
    fn a_revocation_says_what_it_did_and_why_it_stopped() {
        assert_eq!(
            summarise(3, 0, 0, &MuxAdminRevokeStop::Done),
            "revoked 3 grant(s); none remain"
        );
        assert_eq!(
            summarise(1, 2, 0, &MuxAdminRevokeStop::Done),
            "revoked 1 grant(s), 2 id(s) named no stored grant; none remain"
        );
        assert_eq!(
            summarise(500, 0, 40, &MuxAdminRevokeStop::MaxRounds),
            "revoked 500 grant(s); 40 still match — stopped at the round limit; revoke again for the rest"
        );
        assert!(summarise(0, 0, 2, &MuxAdminRevokeStop::NoProgress).contains("revoked nothing"));
        let contended = MuxAdminRevokeStop::Failed(ATMError::ProblemReport(
            "e.p.messaging/mux/admin-revoke:contended".into(),
            "send it again".into(),
            "NONE".into(),
        ));
        let s = summarise(2, 0, 5, &contended);
        assert!(s.starts_with("revoked 2 grant(s); 5 still match"), "{s}");
        assert!(s.contains("busy"), "{s}");
    }

    fn refusal(code: &str) -> ConsoleError {
        ConsoleError::Refused {
            code: code.into(),
            comment: "no".into(),
        }
    }

    #[test]
    fn a_grant_counts_as_revoked_only_when_the_answer_lists_it() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let done = MuxAdminRevokeStop::Done;
        assert!(GrantRevokeResult::from_round("g1", &ids(&["g1"]), &[], &done).is_revoked());
        assert!(matches!(
            GrantRevokeResult::from_round("g1", &[], &ids(&["g1"]), &done),
            GrantRevokeResult::NotStored
        ));
        // A different grant revoked is not this one.
        assert!(!GrantRevokeResult::from_round("g1", &ids(&["g2"]), &[], &done).is_revoked());
        // A later round's refusal is a refusal of this grant.
        let failed = MuxAdminRevokeStop::Failed(ATMError::ProblemReport(
            "e.p.messaging/mux/admin-revoke:protectedAccount".into(),
            "rootAdmin".into(),
            "NONE".into(),
        ));
        assert!(matches!(
            GrantRevokeResult::from_round("g1", &[], &[], &failed),
            GrantRevokeResult::Refused(ConsoleError::Refused { code, .. })
                if code.ends_with(":protectedAccount")
        ));
    }

    #[test]
    fn a_refusal_changed_nothing_but_a_lost_request_is_unconfirmed() {
        assert!(matches!(
            GrantRevokeResult::from_error(refusal("e.p.x:protectedAccount")),
            GrantRevokeResult::Refused(_)
        ));
        assert!(matches!(
            GrantRevokeResult::from_error(ConsoleError::NotPermitted("admins only")),
            GrantRevokeResult::Refused(_)
        ));
        assert!(matches!(
            GrantRevokeResult::from_error(ConsoleError::Sdk(ATMError::TransportError(
                "socket closed".into()
            ))),
            GrantRevokeResult::Unconfirmed(_)
        ));
    }

    #[test]
    fn a_bulk_outcome_reports_every_grant_and_claims_only_what_was_revoked() {
        let outcome = BulkRevokeOutcome {
            results: vec![
                (GrantKey::new("did:m1", "g1"), GrantRevokeResult::Revoked),
                (
                    GrantKey::new("did:root", "g2"),
                    GrantRevokeResult::Refused(refusal(
                        "e.p.messaging/mux/admin-revoke:protectedAccount",
                    )),
                ),
                (GrantKey::new("did:m1", "g3"), GrantRevokeResult::NotStored),
                (
                    GrantKey::new("did:m2", "g4"),
                    GrantRevokeResult::Unconfirmed(ConsoleError::Connect("gone".into())),
                ),
                (
                    GrantKey::new("did:m2", "g5"),
                    GrantRevokeResult::NotAttempted,
                ),
            ],
        };
        assert!(!outcome.all_revoked());
        assert_eq!(
            outcome.summary(),
            "revoked 1 of 5 grant(s); 1 no longer stored, 1 refused, 1 not confirmed, 1 not sent"
        );
        assert_eq!(
            outcome.revoked().collect::<Vec<_>>(),
            [&GrantKey::new("did:m1", "g1")]
        );
        let failures = outcome.failures();
        assert_eq!(failures.len(), 4);
        assert!(
            failures[0].starts_with("g2 of did:root: refused"),
            "{failures:?}"
        );
        assert!(failures[0].contains("only a rootAdmin"), "{failures:?}");
        assert!(failures[2].contains("not confirmed"), "{failures:?}");

        let clean = BulkRevokeOutcome {
            results: vec![(GrantKey::new("did:m", "g"), GrantRevokeResult::Revoked)],
        };
        assert!(clean.all_revoked());
        assert_eq!(clean.summary(), "revoked 1 of 1 grant(s)");
        assert!(clean.failures().is_empty());
    }
}
