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
            let e = match e {
                affinidi_messaging_sdk::errors::ATMError::ProblemReport(code, comment, _) => {
                    crate::error::explain_refusal(code, comment)
                        .unwrap_or_else(|| format!("{comment} ({code})"))
                }
                other => other.to_string(),
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
}
