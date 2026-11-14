//! Refusing a Trust Task with a `trust-task-error` document (Trust Tasks SPEC
//! §8) instead of a DIDComm problem report.
//!
//! Every Trust Task refusal carries a Trust Task error code: one of the
//! framework's standard codes (SPEC §8.3: `permissionDenied`,
//! `malformedRequest`, `unavailable`, …) or a `<task>:<code>` the task's
//! specification declares (`messaging/account/get:unknownAccount`). Handlers
//! refuse with [`tt_problem`](super::trust_tasks::tt_problem), and
//! [`normalize`] turns anything else a handler's helpers return (a storage
//! failure, an authorization check shared with DIDComm) into the standard
//! code that says the same thing, at the one boundary every transport passes
//! through ([`consume`](super::trust_tasks::consume)).
//!
//! A refusal is sent as a `trust-task-error` document, signed by the mediator
//! as a response is, over whichever transport carried the request (DIDComm
//! over REST or WebSocket, TSP, a mux connection). It falls back to a problem
//! report `e.p.<code>`, with the same code, only where no document can be
//! sent:
//!
//! - the request is not a Trust Task document (there is no `id` or `type` to
//!   answer), or it arrived without an authenticated sender;
//! - the sender is not the session's own authenticated DID (a relay-only
//!   session, or a TSP frame signed by another DID). A document costs a
//!   signature and a stored message, as a response does, and a sender that
//!   could never get a response must not be able to make the mediator sign
//!   and store anything;
//! - the document could not be built or signed: the refusal is then never
//!   lost to its own encoding.
//!
//! The DIDComm binding is explicit that a problem report is not an error
//! response (`didcomm/0.2` §4.1), which is why the document is the answer.
//! A request may still carry `x-errorFormat: trust-task-error` (SDK 0.46
//! sends it); it is no longer needed.
//!
//! An internal failure says only that there was one: its text stays in the
//! log, as it does for an HTTP client.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde_json::{Value, json};
use std::str::FromStr;
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask, TrustTaskCode};
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::error_codes;
use crate::messages::protocols::trust_task_sign;

/// `message` is bounded by the `trust-task-error` schema.
const MESSAGE_MAX: usize = 1024;

/// What a refusal needs from the request it refuses, kept before the
/// request is consumed.
pub(crate) struct Refusing {
    /// The request without its payload: the builders read its `id`, `type`,
    /// `threadId` and `ceremony`.
    request: TrustTask<Value>,
}

impl Refusing {
    /// Keep what a refusal of `doc` needs.
    pub(crate) fn of(doc: &TrustTask<Value>) -> Self {
        let mut request = TrustTask::new(doc.id.clone(), doc.type_uri.clone(), Value::Null);
        request.thread_id = doc.thread_id.clone();
        request.parent_thread_id = doc.parent_thread_id.clone();
        request.ceremony = doc.ceremony.clone();
        Self { request }
    }

    /// The `trust-task-error` refusing the request with `e`, from the
    /// mediator to `sender_did` (the transport-authenticated sender, which is
    /// also the address SPEC §8.1 requires under `identityMismatch`), signed
    /// as a success response is.
    ///
    /// `None` when `e` is not a refusal of the task (a session or transport
    /// failure), when `session` is not an authenticated session of
    /// `sender_did`, or when the document could not be built or signed: the
    /// request is then refused with `e` as a problem report (see the module
    /// documentation).
    pub(crate) async fn document(
        &self,
        e: &MediatorError,
        session: &Session,
        sender_did: &str,
        state: &SharedData,
    ) -> Option<Value> {
        if crate::common::authz::require_session_sender(session, Some(sender_did), None).is_err() {
            return None;
        }
        let payload = error_payload(e)?;
        let code = payload.code.to_string();
        let mut doc = self.request.reject_with_recipient(
            Uuid::new_v4().to_string(),
            payload,
            Some(sender_did.to_string()),
        );
        doc.issuer = Some(state.config.mediator_did.clone());
        let value = match serde_json::to_value(&doc) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(error = %err, "couldn't serialise a trust-task-error; refusing with a problem report");
                return None;
            }
        };
        match trust_task_sign::sign_response(value, state).await {
            Ok(signed) => {
                if is_server_side(e) {
                    tracing::warn!(code, request = %self.request.type_uri, error = %e, "Trust Task failed; answered with a trust-task-error");
                } else {
                    tracing::info!(code, request = %self.request.type_uri, refusal = %e, "Trust Task refused with a trust-task-error");
                }
                Some(signed)
            }
            Err(err) => {
                tracing::warn!(error = %err, "couldn't sign a trust-task-error; refusing with a problem report");
                None
            }
        }
    }
}

/// A failure on the mediator's side rather than a refusal of the request.
fn is_server_side(e: &MediatorError) -> bool {
    match e {
        MediatorError::MediatorError(_, _, _, _, status, _) => *status >= 500,
        MediatorError::PermissionError(..)
        | MediatorError::ACLDenied(..)
        | MediatorError::RequestDataError(..)
        | MediatorError::ParseError(..) => false,
        _ => true,
    }
}

/// `e` as a refusal under a Trust Task error code, so the problem report a
/// transport falls back to carries the same code a `trust-task-error` would.
///
/// A refusal that already carries one is returned as it is. Any other
/// refusal becomes the standard code that says the same thing (a storage
/// failure `unavailable`, a shared authorization check `permissionDenied`,
/// an internal error `internalError` with its text kept for the log only).
/// A session or transport failure, which is not a refusal of the task, is
/// left as it is.
pub(crate) fn normalize(e: MediatorError) -> MediatorError {
    if let MediatorError::MediatorError(_, _, _, report, _, _) = &e
        && error_codes::trust_task_code(descriptor(&report.code)).is_some()
    {
        return e;
    }
    let Some(payload) = error_payload(&e) else {
        return e;
    };
    let code = payload.code.to_string();
    let message = payload.message.clone().unwrap_or_default();
    let (session, msg_id, status) = match &e {
        MediatorError::MediatorError(_, session, msg_id, _, status, _) => {
            (session.clone(), msg_id.clone(), *status)
        }
        MediatorError::PermissionError(_, session, _) => {
            (session.clone(), None, StatusCode::FORBIDDEN.as_u16())
        }
        MediatorError::ACLDenied(..) => (String::new(), None, StatusCode::FORBIDDEN.as_u16()),
        MediatorError::RequestDataError(_, session, _)
        | MediatorError::ParseError(_, session, ..) => {
            (session.clone(), None, StatusCode::BAD_REQUEST.as_u16())
        }
        MediatorError::DatabaseError(_, session, _) => (
            session.clone(),
            None,
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        ),
        MediatorError::InternalError(_, session, _)
        | MediatorError::ErrorHandlingError(_, session, _)
        | MediatorError::ConfigError(_, session, _)
        | MediatorError::MessagePackError(_, session, _) => (
            session.clone(),
            None,
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        ),
        _ => return e,
    };
    tracing::debug!(code, cause = %e, "Trust Task refusal under its Trust Task code");
    MediatorError::problem_with_log(
        error_codes::trust_task_code(&code).unwrap_or(error_codes::TT_TASK_FAILED),
        session,
        msg_id,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        &code,
        &message,
        vec![],
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        e.to_string(),
    )
}

/// The `trust-task-error` payload for `e`. `None` for a failure this module
/// leaves in its old form (a session or transport failure, which is not a
/// refusal of the task).
pub(crate) fn error_payload(e: &MediatorError) -> Option<ErrorPayload> {
    let (payload, message) = match e {
        MediatorError::MediatorError(_, _, _, report, status, _) => {
            let descriptor = descriptor(&report.code);
            let code = match TrustTaskCode::from_str(descriptor) {
                Ok(code) if error_codes::trust_task_code(descriptor).is_some() => code,
                _ => TrustTaskCode::Standard(translate(descriptor, *status)),
            };
            let server_side = matches!(code, TrustTaskCode::Standard(StandardCode::InternalError));
            let payload = match declared_details(descriptor, &report.args) {
                Some(details) => ErrorPayload::new(code).with_details(details),
                None => ErrorPayload::new(code),
            };
            let payload = if retryable_status(*status) {
                payload.with_retryable(true)
            } else {
                payload
            };
            let message = match payload.code {
                // SPEC §8.1: never echo either identity to a contested sender.
                TrustTaskCode::Standard(StandardCode::IdentityMismatch) => {
                    "in-band identity does not match the transport-authenticated sender".to_string()
                }
                _ if server_side => "internal error".to_string(),
                _ => report.interpolation(),
            };
            (payload, message)
        }
        MediatorError::PermissionError(_, _, msg) => (
            ErrorPayload::new(StandardCode::PermissionDenied),
            msg.clone(),
        ),
        MediatorError::ACLDenied(..) => (
            ErrorPayload::new(StandardCode::PermissionDenied),
            "denied by an access control list".to_string(),
        ),
        MediatorError::RequestDataError(_, _, msg) => (
            ErrorPayload::new(StandardCode::MalformedRequest),
            msg.clone(),
        ),
        MediatorError::ParseError(_, _, what, _) => (
            ErrorPayload::new(StandardCode::MalformedRequest),
            format!("couldn't parse ({what})"),
        ),
        MediatorError::DatabaseError(..) => (
            ErrorPayload::new(StandardCode::Unavailable),
            "the mediator's store is unavailable".to_string(),
        ),
        MediatorError::InternalError(..)
        | MediatorError::ErrorHandlingError(..)
        | MediatorError::ConfigError(..)
        | MediatorError::MessagePackError(..) => (
            ErrorPayload::new(StandardCode::InternalError),
            "internal error".to_string(),
        ),
        _ => return None,
    };
    Some(payload.with_message(bounded(message)))
}

/// A problem report's code without its sorter and scope: the descriptor
/// the mediator chose (`messaging/mux/revoke-all:epochMismatch` from
/// `e.p.messaging/mux/revoke-all:epochMismatch`).
fn descriptor(code: &str) -> &str {
    let mut parts = code.splitn(3, '.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("e" | "w"), Some(_), Some(descriptor)) => descriptor,
        _ => code,
    }
}

/// The `details` a specification declares for `code`, built from the
/// problem report's `args`, where the refusal carries them. Each shape is
/// the code's `detailsSchema` in the pinned bundle.
fn declared_details(code: &str, args: &[String]) -> Option<Value> {
    let first = || args.first()?.parse::<u64>().ok();
    match code {
        "messaging/mux/revoke-all:epochMismatch"
        | "messaging/mux/admin-revoke-all:epochMismatch" => {
            Some(json!({ "currentEpoch": first()? }))
        }
        "messaging/message/get:messageTooLarge" => Some(json!({ "size": first()? })),
        _ => None,
    }
}

/// The standard code for a refusal raised outside the Trust Task handlers
/// (a storage cap, an authorization check shared with DIDComm), by what its
/// problem code and status say.
fn translate(descriptor: &str, status: u16) -> StandardCode {
    match descriptor {
        d if d.starts_with("authorization.") || d.starts_with("authentication.") => {
            StandardCode::PermissionDenied
        }
        d if d.starts_with("me.res.storage.") => StandardCode::Unavailable,
        _ => match status {
            400 | 404 | 409 | 413 | 422 => StandardCode::MalformedRequest,
            401 | 403 => StandardCode::PermissionDenied,
            429 | 502 | 503 | 504 | 507 => StandardCode::Unavailable,
            501 => StandardCode::UnsupportedType,
            _ => StandardCode::InternalError,
        },
    }
}

/// Statuses the mediator gives a refusal worth sending again.
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504 | 507)
}

fn bounded(mut message: String) -> String {
    if message.len() > MESSAGE_MAX {
        // Room for the ellipsis, which is three bytes.
        let mut end = MESSAGE_MAX - '…'.len_utf8();
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(code: &str, args: Vec<String>, status: StatusCode) -> MediatorError {
        MediatorError::problem(
            crate::error_codes::trust_task_code(code).unwrap_or(crate::error_codes::INTERNAL_ERROR),
            "s1",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            code,
            "the comment",
            args,
            status,
        )
    }

    fn wire(p: ErrorPayload) -> Value {
        serde_json::to_value(p).unwrap()
    }

    #[test]
    fn an_epoch_mismatch_carries_the_current_epoch_in_details() {
        for code in [
            "messaging/mux/revoke-all:epochMismatch",
            "messaging/mux/admin-revoke-all:epochMismatch",
        ] {
            let p = wire(
                error_payload(&problem(code, vec!["3".into()], StatusCode::BAD_REQUEST)).unwrap(),
            );
            assert_eq!(p["code"], code);
            assert_eq!(p["details"], json!({ "currentEpoch": 3 }));
            assert_eq!(p["retryable"], false);
            assert_eq!(p["message"], "the comment");
        }
    }

    #[test]
    fn a_declared_code_without_its_detail_carries_no_details() {
        let p = wire(
            error_payload(&problem(
                "messaging/mux/revoke-all:epochMismatch",
                vec![],
                StatusCode::BAD_REQUEST,
            ))
            .unwrap(),
        );
        assert!(p.get("details").is_none());
    }

    #[test]
    fn a_message_too_large_carries_its_size() {
        let p = wire(
            error_payload(&problem(
                "messaging/message/get:messageTooLarge",
                vec!["9000000".into()],
                StatusCode::PAYLOAD_TOO_LARGE,
            ))
            .unwrap(),
        );
        assert_eq!(p["details"], json!({ "size": 9_000_000 }));
    }

    #[test]
    fn a_standard_code_is_sent_as_it_is() {
        for code in [
            "permissionDenied",
            "malformedRequest",
            "unsupportedType",
            "expired",
        ] {
            let p = wire(error_payload(&problem(code, vec![], StatusCode::FORBIDDEN)).unwrap());
            assert_eq!(p["code"], code);
            assert!(
                p.get("details").is_none(),
                "{code}: no mediatorCode any more"
            );
        }
    }

    #[test]
    fn a_refusal_from_shared_code_gets_the_standard_code_that_says_the_same() {
        let cases = [
            (
                "authorization.sender.mismatch",
                StatusCode::FORBIDDEN,
                "permissionDenied",
            ),
            (
                "me.res.storage.full",
                StatusCode::INSUFFICIENT_STORAGE,
                "unavailable",
            ),
            (
                "me.res.storage.busy",
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
            ),
            (
                "something.else",
                StatusCode::BAD_REQUEST,
                "malformedRequest",
            ),
        ];
        for (shared, status, standard) in cases {
            let e = MediatorError::problem(
                crate::error_codes::INTERNAL_ERROR,
                "s1",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                shared,
                "the comment",
                vec![],
                status,
            );
            let p = wire(error_payload(&e).unwrap());
            assert_eq!(p["code"], standard, "{shared}");
            let MediatorError::MediatorError(number, _, _, report, s, _) = normalize(e) else {
                panic!("a refusal stays a problem report");
            };
            assert_eq!(report.code, format!("e.p.{standard}"), "{shared}");
            assert_eq!(Some(number), crate::error_codes::trust_task_code(standard));
            assert_eq!(s, status.as_u16());
        }
    }

    #[test]
    fn normalize_keeps_a_trust_task_code_and_its_arguments() {
        let e = problem(
            "messaging/mux/revoke-all:epochMismatch",
            vec!["3".into()],
            StatusCode::BAD_REQUEST,
        );
        let MediatorError::MediatorError(number, _, _, report, ..) = normalize(e) else {
            panic!("unchanged");
        };
        assert_eq!(number, crate::error_codes::TT_DECLARED);
        assert_eq!(report.args, vec!["3".to_string()]);
    }

    #[test]
    fn a_malformed_payload_is_a_400_malformed_request() {
        let e = normalize(MediatorError::RequestDataError(
            crate::error_codes::TT_MALFORMED_REQUEST,
            "s1".into(),
            "invalid ACL payload".into(),
        ));
        let MediatorError::MediatorError(number, _, _, report, status, _) = e else {
            panic!("a problem report");
        };
        assert_eq!(number, crate::error_codes::TT_MALFORMED_REQUEST);
        assert_eq!(report.code, "e.p.malformedRequest");
        assert_eq!(status, 400);
    }

    #[test]
    fn a_refusal_the_mediator_answers_503_is_retryable() {
        let p = wire(
            error_payload(&problem(
                "messaging/mux/revoke-all:contended",
                vec![],
                StatusCode::SERVICE_UNAVAILABLE,
            ))
            .unwrap(),
        );
        assert_eq!(p["code"], "messaging/mux/revoke-all:contended");
        assert_eq!(p["retryable"], true);
    }

    #[test]
    fn an_identity_mismatch_names_no_identity() {
        let e = MediatorError::problem(
            crate::error_codes::TT_IDENTITY_MISMATCH,
            "s1",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "identityMismatch",
            "issuer did:example:alice is not the sender did:example:mallory",
            vec![],
            StatusCode::FORBIDDEN,
        );
        let p = wire(error_payload(&e).unwrap());
        assert_eq!(p["code"], "identityMismatch");
        assert!(!p["message"].as_str().unwrap().contains("did:example"));
    }

    #[test]
    fn an_internal_failure_keeps_its_text_out_of_the_answer() {
        let p = wire(
            error_payload(&MediatorError::DatabaseError(
                crate::error_codes::DB_OPERATION_ERROR,
                "s1".into(),
                "redis://10.0.0.5:6379 refused".into(),
            ))
            .unwrap(),
        );
        assert_eq!(p["code"], "unavailable");
        assert_eq!(p["retryable"], true);
        assert!(!p["message"].as_str().unwrap().contains("redis"));

        let e = normalize(MediatorError::InternalError(
            crate::error_codes::INTERNAL_ERROR,
            "s1".into(),
            "secret detail".into(),
        ));
        let MediatorError::MediatorError(_, _, _, report, status, _) = e else {
            panic!("a problem report");
        };
        assert_eq!(report.code, "e.p.internalError");
        assert_eq!(status, 500);
        assert!(!report.comment.contains("secret"));
    }

    #[test]
    fn a_session_failure_keeps_its_old_form() {
        let e = MediatorError::SessionError(
            crate::error_codes::SESSION_INVALID_STATE,
            "s1".into(),
            "gone".into(),
        );
        assert!(error_payload(&e).is_none());
        assert!(matches!(normalize(e), MediatorError::SessionError(..)));
    }

    #[test]
    fn a_long_message_is_bounded() {
        let long = "é".repeat(2000);
        let b = bounded(long);
        assert!(b.len() <= MESSAGE_MAX);
        assert!(b.ends_with('…'));
    }
}
