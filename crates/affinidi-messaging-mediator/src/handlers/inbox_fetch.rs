use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    GetMessagesResponse,
    fetch::FetchOptions,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use regex::Regex;
use tracing::{Instrument, Level, span};

/// Fetches available messages from the session DID's inbox.
/// ACL_MODE: Requires LOCAL access
///
/// # Parameters
/// - `session`: Session information; the inbox is the session DID's
/// - `body`: [`FetchOptions`]. `limit` must be between 1 and
///   `limits.listed_messages`; `start_id`, when given, must be a whole message
///   id (`<unix millis>-<0..999>`)
pub async fn inbox_fetch_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<FetchOptions>,
) -> Result<(StatusCode, Json<SuccessResponse<GetMessagesResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "inbox_fetch_handler",
        session = session.session_id,
        did_hash = session.did_hash,
        fetch.limit = body.limit,
        fetch.start_id = body.start_id,
        fetch.delete_policy = body.delete_policy.to_string()
    );
    async move {
        // ACL Check
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
            return Err(MediatorError::problem(
                40, session.session_id, None,
                ProblemReportSorter::Error, ProblemReportScope::Protocol,
                "authorization.local",
                "DID isn't local to the mediator",
                vec![], StatusCode::FORBIDDEN,
            )
            .into());
        }

        // Check options
        let max_limit = state.limits().listed_messages;
        if body.limit < 1 || body.limit > max_limit {
            return Err(MediatorError::problem_with_log(
                41, session.session_id, None,
                ProblemReportSorter::Error, ProblemReportScope::Protocol,
                "api.inbox_fetch.limit",
                "Invalid limit ({1}). Must be 1-{2} in range",
                vec![body.limit.to_string(), max_limit.to_string()], StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }

        // Check for valid start_id (unixtime in milliseconds including+1 digit so we are ok for another 3,114 years!)
        // Supports up to 999 messages per millisecond
        if let Some(start_id) = &body.start_id && !is_message_id(start_id) {
                return Err(MediatorError::problem_with_log(
                    42, session.session_id, None,
                    ProblemReportSorter::Error, ProblemReportScope::Protocol,
                    "api.inbox_fetch.start_id",
                    "start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {1}",
                    vec![start_id.to_string()], StatusCode::BAD_REQUEST,
                    format!("start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {start_id}"),
                )
                .into());
            }

        // Fetch messages if possible
        let mut results = state.database.fetch_messages_delivering(&session.session_id, &session.did_hash, &body, state.clock.unix_millis() as u64, state.config.limits.delivered_expiry_seconds, state.config.limits.pickup_round_robin).await.map_err(|e| {MediatorError::problem_with_log(
            14, session.session_id.clone(), None,
            ProblemReportSorter::Error, ProblemReportScope::Protocol,
            "me.res.storage.error",
            "Database transaction error: {1}",
            vec![e.to_string()], StatusCode::SERVICE_UNAVAILABLE,
            format!("Database transaction error: {e}"),
        )})?;

        // Tag each message's wire protocol (DIDComm / TSP / …) so the client can
        // route it without inspecting the body itself.
        results
            .success
            .iter_mut()
            .for_each(|m| m.detect_protocol_in_place());
        for m in &results.success {
            state.monitor.delivered(
                &m.msg_id,
                m.from_address.as_deref(),
                m.to_address.as_deref(),
                m.size,
                crate::monitor::Channel::Rest,
                m.msg.as_deref(),
            );
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(results),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// Whether `id` is a whole message id: the UNIX time in milliseconds (13 or 14
/// digits, good for another 3,000 years) and a 1-3 digit sequence number (up to
/// 999 messages per millisecond). Anchored at both ends, so an id with
/// anything before or after it is refused.
fn is_message_id(id: &str) -> bool {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^\d{13,14}-\d{1,3}$").expect("hardcoded regex is valid")
    });
    RE.is_match(id)
}

#[cfg(test)]
mod tests {
    use super::is_message_id;

    #[test]
    fn a_message_id_is_matched_whole() {
        assert!(is_message_id("1234567890123-1"));
        assert!(is_message_id("12345678901234-999"));
        // Junk before the id used to pass: the pattern was anchored only at
        // the end.
        assert!(!is_message_id("junk1234567890123-1"));
        assert!(!is_message_id("1234567890123-1junk"));
        assert!(!is_message_id("123456789012-1"));
        assert!(!is_message_id("1234567890123-1000"));
    }
}
