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
    /// The mediator refused the request, with a problem report or a
    /// `trust-task-error` document: the stable code a caller can act on (the
    /// mediator's own, whichever form the refusal came in; see
    /// [`ATMError::mediator_code`]), its explanation, and, for an
    /// `…:epochMismatch`, the epoch in force.
    #[error("the mediator refused ({code}): {comment}")]
    Refused {
        code: String,
        comment: String,
        current_epoch: Option<u64>,
    },
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
    /// Classify an SDK error: a refusal from the mediator, as a problem
    /// report or a `trust-task-error`, is a [`ConsoleError::Refused`];
    /// everything else stays an SDK error.
    pub(crate) fn from_call(e: ATMError) -> Self {
        match refusal(&e) {
            Some((code, comment, current_epoch)) => ConsoleError::Refused {
                code,
                comment,
                current_epoch,
            },
            None => ConsoleError::Sdk(e),
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
            ConsoleError::Refused { current_epoch, .. } => *current_epoch,
            _ => None,
        }
    }

    /// The error in words an operator can act on: what a known refusal of
    /// the stored-grant tasks means, and what to do; anything else as
    /// [`Display`](std::fmt::Display) renders it.
    pub fn explain(&self) -> String {
        match self {
            ConsoleError::Refused {
                code,
                comment,
                current_epoch,
            } => display_safe(
                &explain_refusal(code, comment, *current_epoch).unwrap_or_else(|| self.to_string()),
            ),
            other => display_safe(&other.to_string()),
        }
    }
}

/// `s` with control characters, line and paragraph separators and
/// bidirectional formatting marks escaped (`\u{1b}`), so text a mediator
/// sent cannot drive the operator's terminal: no ANSI or OSC sequences, no
/// rewritten lines, no reordered words in a confirmation. Other text,
/// non-ASCII included, is kept as is. Escaping twice changes nothing more.
pub(crate) fn display_safe(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let unsafe_char = c.is_control()
            || matches!(
                c,
                '\u{2028}'
                    | '\u{2029}'
                    | '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            );
        if unsafe_char {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Shorthand for console results.
pub type Result<T> = std::result::Result<T, ConsoleError>;

/// A refusal by the mediator, in either form: its code (the mediator's own,
/// [`ATMError::mediator_code`]; a problem report's keeps its `e.p.` prefix, as
/// before), its explanation, and the epoch in force for an `epochMismatch`.
/// `None` for any other failure.
pub(crate) fn refusal(e: &ATMError) -> Option<(String, String, Option<u64>)> {
    let comment = match e {
        ATMError::ProblemReport(code, comment, _) => {
            return Some((display_safe(code), display_safe(comment), e.current_epoch()));
        }
        ATMError::TrustTaskError(r) => r.message.clone().unwrap_or_else(|| r.code.clone()),
        _ => return None,
    };
    Some((
        display_safe(e.mediator_code()?),
        display_safe(&comment),
        e.current_epoch(),
    ))
}

/// What a refusal of a stored-grant task means, by its code; `None` for a
/// code without a plainer reading.
pub(crate) fn explain_refusal(
    code: &str,
    comment: &str,
    current_epoch: Option<u64>,
) -> Option<String> {
    let text = if code.ends_with(":epochMismatch") {
        match current_epoch {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: &str, comment: &str) -> ConsoleError {
        ConsoleError::from_call(ATMError::ProblemReport(
            code.into(),
            comment.into(),
            "NONE".into(),
        ))
    }

    fn document(code: &str, message: &str, details: serde_json::Value) -> ConsoleError {
        let refusal =
            affinidi_messaging_sdk::errors::TrustTaskRefusal::from_document(&serde_json::json!({
                "id": "e1",
                "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                "payload": {
                    "code": code, "retryable": false, "message": message, "details": details,
                },
            }))
            .expect("a trust-task-error");
        ConsoleError::from_call(ATMError::TrustTaskError(Box::new(refusal)))
    }

    #[test]
    fn mediator_text_cannot_drive_the_terminal() {
        let e = refused(
            "e.p.authorization.permissionDenied",
            "no\u{1b}]0;owned\u{7}\r\nconfirm? [y]\u{202e}",
        );
        let ConsoleError::Refused { comment, .. } = &e else {
            panic!("a refusal");
        };
        assert!(!comment.chars().any(char::is_control), "{comment:?}");
        assert!(!comment.contains('\u{202e}'), "{comment:?}");
        assert!(comment.contains("\\u{1b}]0;owned"), "{comment:?}");
        let shown = e.explain();
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert_eq!(
            display_safe(&shown),
            shown,
            "escaping twice changes nothing"
        );
        assert_eq!(display_safe("épée ok"), "épée ok");
        // Not a refusal: what the SDK reported is escaped when shown too.
        let other = ConsoleError::Unexpected("bad\u{1b}[2J".into());
        assert!(!other.explain().chars().any(char::is_control));
    }

    #[test]
    fn a_trust_task_error_is_a_refusal_with_its_typed_epoch() {
        let e = document(
            "messaging/mux/admin-revoke-all:epochMismatch",
            "the request names epoch 5",
            serde_json::json!({ "currentEpoch": 3 }),
        );
        assert_eq!(e.current_epoch(), Some(3));
        assert_eq!(
            e.refusal_code(),
            Some("messaging/mux/admin-revoke-all:epochMismatch")
        );
        assert!(
            e.explain().contains("the current epoch is 3"),
            "{}",
            e.explain()
        );
    }

    #[test]
    fn a_translated_code_is_explained_by_the_mediator_code() {
        let e = document(
            "permissionDenied",
            "admin only",
            serde_json::json!({ "mediatorCode": "authorization.admin_required" }),
        );
        assert_eq!(e.refusal_code(), Some("authorization.admin_required"));
        assert!(
            e.explain().contains("only an administrator"),
            "{}",
            e.explain()
        );
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
