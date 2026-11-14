use crate::error_codes;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    GetMessagesRequest, GetMessagesResponse,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use tracing::{Instrument, Level, debug, span, warn};

use crate::{
    SharedData,
    after_write::{AfterWrite, HandedOver, HandedOverMessage, respond_then},
    common::authz::{self, Capability},
    common::session::Session,
    messages::client_delete::delete_for_client,
};

/// Deletes after a written response that run at once.
const DELETE_PARALLEL: usize = 8;

/// Delivers messages to the client for given message_ids
/// outbound refers to outbound from the mediator perspective
/// ACL_MODE: Rquires LOCAL access
///
/// Each message is reported `delivered` — and, with `delete`, deleted — only
/// once the response body carrying it has been written (R1.1). A response
/// that is never fully written deletes and reports nothing, so the client can
/// fetch again. A delete that then fails is logged; it cannot be reported in a
/// response that has already gone, so `delete_errors` is always empty.
pub async fn message_outbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<GetMessagesRequest>,
) -> Result<Response, AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_outbound_handler",
        session = session.session_id,
        delete = body.delete,
    );
    async move {
        // ACL Check
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
            return Err(MediatorError::problem(
                error_codes::AUTH_NOT_LOCAL,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.local",
                "DID isn't local to the mediator",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        debug!(
            "Client has asked to get ({}) messages",
            body.message_ids.len()
        );

        // Mirror the delete handler's per-request cap: each id is a database
        // round-trip, so an unbounded list lets an authenticated client tie up
        // the mediator with a single request.
        if body.message_ids.len() > state.limits().listed_messages {
            return Err(MediatorError::problem_with_log(
                error_codes::API_MESSAGE_OUTBOUND_LIMIT,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "api.message_outbound.limit",
                "Invalid limit ({1}). Maximum of {2} messages can be fetched per transaction",
                vec![
                    body.message_ids.len().to_string(),
                    state.limits().listed_messages.to_string(),
                ],
                StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }

        let mut messages = GetMessagesResponse::default();
        let mut handed_over = HandedOver::new(&session.did_hash);
        let mut to_delete: Vec<String> = Vec::new();

        // One batched read for the whole request rather than a round trip per
        // id (#159). Should the batch fail, each id is read on its own so a
        // failure is still reported against the id it belongs to.
        let fetched: Vec<Result<Option<_>, MediatorError>> = match state
            .database
            .get_messages(&session.did_hash, &body.message_ids)
            .await
        {
            Ok(found) if found.len() == body.message_ids.len() => {
                found.into_iter().map(Ok).collect()
            }
            _ => {
                let mut each = Vec::with_capacity(body.message_ids.len());
                for msg_id in &body.message_ids {
                    each.push(state.database.get_message(&session.did_hash, msg_id).await);
                }
                each
            }
        };
        for (msg_id, got) in body.message_ids.iter().zip(fetched) {
            debug!("getting message with id: {}", msg_id);
            match got {
                Ok(Some(mut msg)) => {
                    debug!(msg_id = %msg.msg_id, size = msg.size, "Got message");
                    // Tag the message's wire protocol so the client can route it.
                    msg.detect_protocol_in_place();
                    handed_over.messages.push(HandedOverMessage::of(&msg));
                    if body.delete {
                        to_delete.push(msg_id.clone());
                    }
                    messages.success.push(msg);
                }
                Ok(None) => {
                    debug!("Message not found: {}", msg_id);
                    messages
                        .get_errors
                        .push((msg_id.clone(), "Message not found".to_string()));
                }
                Err(err) => {
                    debug!("Error getting message: {:?}", err);
                    messages.get_errors.push((msg_id.clone(), err.to_string()));
                }
            }
        }

        // After the body is written: report each message delivered, then
        // delete what the client asked to have deleted.
        let after = AfterWrite::default();
        let deleted_on_write = {
            let state = state.clone();
            let owner = session.did_hash.clone();
            Box::pin(async move {
                use futures_util::StreamExt;
                // Ids are independent: a few deletes run at once rather than
                // one round trip after another (#159). Each still deletes at
                // most once (the store's delete is the arbiter).
                let results: Vec<_> = futures_util::stream::iter(to_delete)
                    .map(|msg_id| {
                        let state = &state;
                        let owner = &owner;
                        async move {
                            // As `DELETE /delete`: the caller's own copy, else
                            // what it sent unless this repeats an
                            // acknowledgement.
                            let result = delete_for_client(
                                &*state.database,
                                std::slice::from_ref(owner),
                                &msg_id,
                                true,
                            )
                            .await;
                            (msg_id, result)
                        }
                    })
                    .buffer_unordered(DELETE_PARALLEL)
                    .collect()
                    .await;
                for (msg_id, result) in results {
                    match result {
                        Ok(removed) => {
                            for copy in &removed.copies {
                                state.monitor.deleted(
                                    &msg_id,
                                    &owner,
                                    copy.from_did_hash.as_deref(),
                                    Some(copy.to_did_hash.as_str()),
                                    crate::monitor::Channel::Rest,
                                    None,
                                );
                            }
                        }
                        Err(err) => warn!(
                            msg_id = %msg_id,
                            "delete after a written /outbound response failed: {err}"
                        ),
                    }
                }
            })
        };
        after.push_completion(handed_over.completion(&state, crate::monitor::Channel::Rest));
        after.push_completion(deleted_on_write);

        let response = (
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(messages),
            }),
        )
            .into_response();
        Ok(respond_then(response, after))
    }
    .instrument(_span)
    .await
}
