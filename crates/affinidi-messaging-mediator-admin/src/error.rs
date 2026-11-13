//! Errors from the console.

use affinidi_messaging_sdk::errors::ATMError;

/// Why a console operation failed.
///
/// The variants separate what a caller does next: an identity that cannot be
/// used is fixed by choosing another; a refusal is the mediator's answer and is
/// shown as such; a transport failure is retried; `NotPermitted` means the
/// console knows in advance the mediator would refuse, so no request was sent.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleError {
    /// The identity could not be loaded or has nothing to connect with.
    #[error("identity: {0}")]
    Identity(String),
    /// No mediator was given and none could be found from the DID document.
    #[error("no mediator for {0}: pass one explicitly or publish a DIDCommMessaging service")]
    NoMediator(String),
    /// The connection to the mediator could not be established.
    #[error("connecting to the mediator: {0}")]
    Connect(String),
    /// The mediator answered with a problem report: a refusal, with the stable
    /// code a caller can act on and the mediator's explanation.
    #[error("the mediator refused ({code}): {comment}")]
    Refused { code: String, comment: String },
    /// The console's session cannot do this, so nothing was sent.
    #[error("not permitted for this session: {0}")]
    NotPermitted(&'static str),
    /// A purge plan was confirmed against a queue that has since changed.
    #[error("the queue changed since the purge was previewed ({previewed} then, {now} now)")]
    PlanStale { previewed: u64, now: u64 },
    /// The request was malformed, so nothing was sent.
    #[error("{0}")]
    Invalid(String),
    /// The mediator answered, but not as its specification says it would.
    #[error("unexpected answer from the mediator: {0}")]
    Unexpected(String),
    /// Anything else the SDK reported.
    #[error(transparent)]
    Sdk(#[from] ATMError),
}

impl ConsoleError {
    /// Classify an SDK error: a problem report from the mediator is a
    /// [`ConsoleError::Refused`], everything else stays an SDK error.
    pub(crate) fn from_call(e: ATMError) -> Self {
        match e {
            ATMError::ProblemReport(code, comment, _) => ConsoleError::Refused { code, comment },
            other => ConsoleError::Sdk(other),
        }
    }

    /// The mediator's problem code, when this is a refusal.
    pub fn refusal_code(&self) -> Option<&str> {
        match self {
            ConsoleError::Refused { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The member's epoch in force, when this is a
    /// `messaging/mux/admin-revoke-all:epochMismatch` refusal: the request
    /// named a later epoch than the current one.
    pub fn current_epoch(&self) -> Option<u64> {
        match self {
            ConsoleError::Refused { code, comment } if code.ends_with(":epochMismatch") => {
                epoch_in(comment)
            }
            _ => None,
        }
    }

    /// The error in words an operator can act on: what a known refusal of
    /// the stored-grant tasks means, and what to do; anything else as
    /// [`Display`](std::fmt::Display) renders it.
    pub fn explain(&self) -> String {
        match self {
            ConsoleError::Refused { code, comment } => {
                explain_refusal(code, comment).unwrap_or_else(|| self.to_string())
            }
            other => other.to_string(),
        }
    }
}

/// Shorthand for console results.
pub type Result<T> = std::result::Result<T, ConsoleError>;

/// What a refusal of a stored-grant task means, by its code; `None` for a
/// code without a plainer reading.
pub(crate) fn explain_refusal(code: &str, comment: &str) -> Option<String> {
    let text = if code.ends_with(":epochMismatch") {
        match epoch_in(comment) {
            Some(n) => format!(
                "the epoch changed after it was read: the current epoch is {n}. \
                 Read it again and confirm that one"
            ),
            None => format!("the epoch named is not the current one ({comment})"),
        }
    } else if code.ends_with(":protectedAccount") {
        "a party is a rootAdmin account: only a rootAdmin may revoke its grants \
         or advance its epoch. Nothing changed"
            .into()
    } else if code.ends_with(":unknownAccount") {
        "that DID has no account at this mediator, so it has no epoch to advance".into()
    } else if code.ends_with(":contended") {
        "the member's record was busy with other changes and this request changed \
         nothing; try again"
            .into()
    } else if code.ends_with(":cursorInvalid") {
        "the page cursor is no longer valid; list again from the first page".into()
    } else if code.ends_with("admin_required") {
        "permission denied: only an administrator account may manage stored grants".into()
    } else if code.ends_with("permissionDenied") || code.contains("unauthorized") {
        format!("permission denied: {comment}")
    } else if code.ends_with("protocol.trust_task.unsupported") {
        format!(
            "the mediator does not serve this task — mux is not enabled there, or it \
             predates affinidi-messaging-mediator 0.52.0 ({comment})"
        )
    } else {
        return None;
    };
    Some(text)
}

/// The number after "current epoch is" in an `epochMismatch` message.
fn epoch_in(comment: &str) -> Option<u64> {
    let (_, rest) = comment.split_once("current epoch is ")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: &str, comment: &str) -> ConsoleError {
        ConsoleError::Refused {
            code: code.into(),
            comment: comment.into(),
        }
    }

    #[test]
    fn an_epoch_mismatch_gives_the_current_epoch() {
        let e = refused(
            "e.p.messaging/mux/admin-revoke-all:epochMismatch",
            "the request names epoch 5; the current epoch is 3",
        );
        assert_eq!(e.current_epoch(), Some(3));
        assert!(
            e.explain().contains("the current epoch is 3"),
            "{}",
            e.explain()
        );
        // Other refusals carry no epoch, even when the text mentions one.
        let other = refused(
            "e.p.messaging/mux/admin-revoke:contended",
            "current epoch is 3",
        );
        assert_eq!(other.current_epoch(), None);
    }

    #[test]
    fn known_refusals_are_explained_and_others_left_as_they_are() {
        let protected = refused(
            "e.p.messaging/mux/admin-revoke-all:protectedAccount",
            "the member DID is a rootAdmin",
        );
        assert!(protected.explain().contains("only a rootAdmin"));
        let denied = refused("e.p.authorization.admin_required", "admins only");
        assert!(denied.explain().starts_with("permission denied"));
        let unknown = refused(
            "e.p.messaging/mux/admin-revoke-all:unknownAccount",
            "no account",
        );
        assert!(unknown.explain().contains("no account at this mediator"));
        let other = refused("e.p.something.else", "why");
        assert_eq!(other.explain(), other.to_string());
        let local = ConsoleError::Invalid("name a DID".into());
        assert_eq!(local.explain(), "name a DID");
    }
}
