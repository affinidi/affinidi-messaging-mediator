//! Refusing a Trust Task with a `trust-task-error` document (Trust Tasks SPEC
//! §8) instead of a DIDComm problem report.
//!
//! The DIDComm binding is explicit that a problem report is not an error
//! response (`didcomm/0.2` §4.1): it names a DIDComm message, not a document,
//! and carries none of `inResponseTo`, `retryable` or the `details` a
//! specification declares for its codes (`currentEpoch` for
//! `messaging/mux/revoke-all:epochMismatch`). This mediator has always
//! answered with problem reports, and its clients match on their codes, so
//! the document is sent only to a request that asks for it, with the
//! top-level member [`ERROR_FORMAT_MEMBER`] (SPEC §4.2 allows additional
//! top-level members; the proof covers it). Every other request is refused as
//! before.
//!
//! What a refusal says is decided where it was always decided, as a
//! [`MediatorError`]. This module only changes its form:
//!
//! - A code a specification declares (`messaging/mux/…:…`) or a standard code
//!   is sent as it is, with the `details` its specification declares where
//!   the refusal carries them (the problem report's `args`).
//! - The mediator's own codes (`authorization.admin_required`,
//!   `message.trust_task.stale`, …) are not valid `trust-task-error` codes.
//!   They are translated into the standard code that says the same thing,
//!   and the original goes in `details.mediatorCode`, so a client that
//!   matched it can still.
//! - An internal failure says only that there was one: its text stays in the
//!   log, as it does for an HTTP client.

use affinidi_messaging_mediator_common::errors::MediatorError;
use serde_json::{Value, json};
use std::str::FromStr;
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask, TrustTaskCode};
use uuid::Uuid;

use crate::SharedData;
use crate::messages::protocols::trust_task_sign;

/// Top-level request member asking for refusals as `trust-task-error`
/// documents. The same name as the SDK's `ERROR_FORMAT_MEMBER`.
pub(crate) const ERROR_FORMAT_MEMBER: &str = "x-errorFormat";

/// The value of [`ERROR_FORMAT_MEMBER`] that asks for them.
pub(crate) const ERROR_FORMAT_DOCUMENT: &str = "trust-task-error";

/// The `details` member naming the mediator's own code for a refusal it
/// translated into a standard one.
pub(crate) const MEDIATOR_CODE_DETAIL: &str = "mediatorCode";

/// `message` is bounded by the `trust-task-error` schema.
const MESSAGE_MAX: usize = 1024;

/// What a refusal needs from the request it refuses, kept before the
/// request is consumed. Only a request that asked for `trust-task-error`
/// documents has one.
pub(crate) struct Refusing {
    /// The request without its payload: the builders read its `id`, `type`,
    /// `threadId` and `ceremony`.
    request: TrustTask<Value>,
}

impl Refusing {
    /// `Some` when `doc` asks to be refused with a `trust-task-error`.
    pub(crate) fn asked_by(doc: &TrustTask<Value>) -> Option<Self> {
        if doc.extra.get(ERROR_FORMAT_MEMBER).and_then(Value::as_str) != Some(ERROR_FORMAT_DOCUMENT)
        {
            return None;
        }
        let mut request = TrustTask::new(doc.id.clone(), doc.type_uri.clone(), Value::Null);
        request.thread_id = doc.thread_id.clone();
        request.parent_thread_id = doc.parent_thread_id.clone();
        request.ceremony = doc.ceremony.clone();
        Some(Self { request })
    }

    /// The `trust-task-error` refusing the request with `e`, from the
    /// mediator to `sender_did` (the transport-authenticated sender, which is
    /// also the address SPEC §8.1 requires under `identityMismatch`), signed
    /// as a success response is.
    ///
    /// `None` when `e` has no form here, or the document could not be built
    /// or signed: the request is then refused as before, with `e`, so a
    /// refusal is never lost to its own encoding.
    pub(crate) async fn document(
        &self,
        e: &MediatorError,
        sender_did: &str,
        state: &SharedData,
    ) -> Option<Value> {
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

/// The `trust-task-error` payload for `e`. `None` for a failure this module
/// leaves in its old form (a session or transport failure, which is not a
/// refusal of the task).
pub(crate) fn error_payload(e: &MediatorError) -> Option<ErrorPayload> {
    let (payload, message) = match e {
        MediatorError::MediatorError(_, _, _, report, status, _) => {
            let descriptor = descriptor(&report.code);
            let payload = match TrustTaskCode::from_str(descriptor) {
                Ok(code) => {
                    let payload = ErrorPayload::new(code);
                    match declared_details(descriptor, &report.args) {
                        Some(details) => payload.with_details(details),
                        None => payload,
                    }
                }
                Err(_) => ErrorPayload::new(translate(descriptor, *status))
                    .with_details(json!({ MEDIATOR_CODE_DETAIL: descriptor })),
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

/// The standard code for one of the mediator's own codes.
fn translate(descriptor: &str, status: u16) -> StandardCode {
    match descriptor {
        "protocol.trust_task.unsupported" => StandardCode::UnsupportedType,
        "message.trust_task.stale" => StandardCode::Expired,
        "message.trust_task.identity_mismatch" => StandardCode::IdentityMismatch,
        "message.trust_task.proof_required" => StandardCode::ProofRequired,
        "message.trust_task.proof_invalid" => StandardCode::ProofInvalid,
        "message.trust_task.id_conflict" => StandardCode::IdConflict,
        "message.trust_task.unavailable" => StandardCode::Unavailable,
        "message.trust_task.rejected" | "message.trust_task.malformed" => {
            StandardCode::MalformedRequest
        }
        d if d.starts_with("authorization.") || d.ends_with(".protected") => {
            StandardCode::PermissionDenied
        }
        _ => match status {
            400 | 413 | 422 => StandardCode::MalformedRequest,
            401 | 403 => StandardCode::PermissionDenied,
            429 | 502 | 503 | 504 => StandardCode::Unavailable,
            501 => StandardCode::UnsupportedType,
            500 => StandardCode::InternalError,
            _ => StandardCode::TaskFailed,
        },
    }
}

/// Statuses the mediator gives a refusal worth sending again.
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
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
    use affinidi_messaging_sdk::messages::problem_report::{
        ProblemReportScope, ProblemReportSorter,
    };
    use http::StatusCode;

    fn problem(code: &str, args: Vec<String>, status: StatusCode) -> MediatorError {
        MediatorError::problem(
            37,
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
    fn a_mediator_code_is_translated_and_kept_in_details() {
        let cases = [
            (
                "authorization.admin_required",
                StatusCode::FORBIDDEN,
                "permissionDenied",
            ),
            (
                "protocol.trust_task.unsupported",
                StatusCode::NOT_IMPLEMENTED,
                "unsupportedType",
            ),
            (
                "message.trust_task.stale",
                StatusCode::BAD_REQUEST,
                "expired",
            ),
            (
                "message.trust_task.proof_required",
                StatusCode::BAD_REQUEST,
                "proofRequired",
            ),
            (
                "account.remove.protected",
                StatusCode::FORBIDDEN,
                "permissionDenied",
            ),
            ("account.not_found", StatusCode::NOT_FOUND, "taskFailed"),
            (
                "storageError",
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
            ),
        ];
        for (legacy, status, standard) in cases {
            let p = wire(error_payload(&problem(legacy, vec![], status)).unwrap());
            assert_eq!(p["code"], standard, "{legacy}");
            assert_eq!(p["details"][MEDIATOR_CODE_DETAIL], legacy);
        }
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
            37,
            "s1",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.trust_task.identity_mismatch",
            "issuer did:example:alice is not the sender did:example:mallory",
            vec![],
            StatusCode::BAD_REQUEST,
        );
        let p = wire(error_payload(&e).unwrap());
        assert_eq!(p["code"], "identityMismatch");
        assert!(!p["message"].as_str().unwrap().contains("did:example"));
    }

    #[test]
    fn an_internal_failure_keeps_its_text_out_of_the_answer() {
        let p = wire(
            error_payload(&MediatorError::DatabaseError(
                1,
                "s1".into(),
                "redis://10.0.0.5:6379 refused".into(),
            ))
            .unwrap(),
        );
        assert_eq!(p["code"], "unavailable");
        assert_eq!(p["retryable"], true);
        assert!(!p["message"].as_str().unwrap().contains("redis"));
    }

    #[test]
    fn a_session_failure_keeps_its_old_form() {
        assert!(
            error_payload(&MediatorError::SessionError(1, "s1".into(), "gone".into())).is_none()
        );
    }

    #[test]
    fn only_a_request_that_asks_is_refused_with_a_document() {
        let mut doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "type": "https://trusttasks.org/spec/messaging/mux/revoke-all/0.1",
            "payload": {}
        }))
        .unwrap();
        assert!(Refusing::asked_by(&doc).is_none());
        doc.extra
            .insert(ERROR_FORMAT_MEMBER.into(), json!(ERROR_FORMAT_DOCUMENT));
        assert!(Refusing::asked_by(&doc).is_some());
        doc.extra
            .insert(ERROR_FORMAT_MEMBER.into(), json!("something-else"));
        assert!(Refusing::asked_by(&doc).is_none());
    }

    #[test]
    fn a_long_message_is_bounded() {
        let long = "é".repeat(2000);
        let b = bounded(long);
        assert!(b.len() <= MESSAGE_MAX);
        assert!(b.ends_with('…'));
    }
}
