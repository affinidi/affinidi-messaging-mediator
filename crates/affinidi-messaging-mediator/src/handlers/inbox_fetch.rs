use crate::error_codes;
use crate::{
    SharedData,
    after_write::{AfterWrite, HandedOver, HandedOverMessage, fetch_for_handover, respond_then},
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_mediator_common::store::MediatorStoreExt;
use affinidi_messaging_mediator_common::store::{DeletionAuthority, MessageScope};
use affinidi_messaging_sdk::messages::FetchDeletePolicy;
use affinidi_messaging_sdk::messages::{
    fetch::FetchOptions,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use regex::Regex;
use tracing::{Instrument, Level, span, warn};

/// Fetches available messages from the session DID's inbox.
/// ACL_MODE: Requires LOCAL access
///
/// # Parameters
/// - `session`: Session information; the inbox is the session DID's
/// - `body`: [`FetchOptions`]. `limit` must be between 1 and
///   `limits.listed_messages`; `start_id`, when given, must be a whole message
///   id (`<unix millis>-<0..999>`)
///
/// What the response carries is stamped delivered and reported `delivered` —
/// and, under `FetchDeletePolicy::Optimistic`, deleted — only once the
/// response body has been written (R1.1). A response that is never fully
/// written leaves every message queued and unreported. A delete that fails
/// after the write is logged; `delete_errors` is always empty.
pub async fn inbox_fetch_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<FetchOptions>,
) -> Result<Response, AppError> {
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
                error_codes::AUTH_NOT_LOCAL, session.session_id, None,
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
                error_codes::API_INBOX_FETCH_LIMIT, session.session_id, None,
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
                    error_codes::API_INBOX_FETCH_START_ID, session.session_id, None,
                    ProblemReportSorter::Error, ProblemReportScope::Protocol,
                    "api.inbox_fetch.start_id",
                    "start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {1}",
                    vec![start_id.to_string()], StatusCode::BAD_REQUEST,
                    format!("start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {start_id}"),
                )
                .into());
            }

        // Fetch messages if possible. Nothing is stamped or deleted yet.
        let mut results = fetch_for_handover(&state, &session.session_id, &session.did_hash, &body).await.map_err(|e| {MediatorError::problem_with_log(
            error_codes::DB_OPERATION_ERROR, session.session_id.clone(), None,
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

        let after = AfterWrite::default();
        let ids: Vec<String> = results.success.iter().map(|m| m.msg_id.clone()).collect();
        if matches!(body.delete_policy, FetchDeletePolicy::Optimistic) {
            // Recorded, then deleted, once written.
            let reported: Vec<HandedOverMessage> = results.success.iter().map(HandedOverMessage::of).collect();
            let state = state.clone();
            let owner = session.did_hash.clone();
            after.push_completion(Box::pin(async move {
                // The handover is recorded through `record_delivered` like any
                // other written delivery (the store's delivery stamp and sent
                // counters move there), before the delete: stamping a message
                // already deleted would resurrect its metadata on Redis.
                if let Err(e) = state
                    .database
                    .record_delivered(
                        &owner,
                        &ids,
                        state.clock.unix_millis() as u64,
                        state.config.limits.delivered_expiry_seconds,
                    )
                    .await
                {
                    warn!("couldn't record {} written message(s) as delivered: {e}", ids.len());
                }
                for (msg_id, m) in ids.iter().zip(&reported) {
                    state.monitor.delivered_as(
                        &m.msg_id, m.from.as_deref(), m.to.as_deref(), m.size,
                        crate::monitor::Channel::Rest, m.protocol,
                    );
                    if let Err(e) = state
                        .database
                        .delete_message_in(
                            msg_id,
                            MessageScope::Recipient(&owner),
                            DeletionAuthority::Owner { did_hash: owner.clone() },
                        )
                        .await
                    {
                        warn!(%msg_id, "optimistic delete after a written fetch failed: {e}");
                    }
                }
            }));
        } else {
            let mut handed_over = HandedOver::new(&session.did_hash);
            handed_over.messages = results.success.iter().map(HandedOverMessage::of).collect();
            after.push_completion(handed_over.completion(&state, crate::monitor::Channel::Rest));
        }

        let response = (
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(results),
            }),
        )
            .into_response();
        Ok(respond_then(response, after))
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
