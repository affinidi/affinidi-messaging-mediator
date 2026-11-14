use crate::error_codes;
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
    messages::client_delete::delete_for_client,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    DeleteMessageRequest, DeleteMessageResponse, GenericDataStruct,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, debug, span};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

/// Deletes a specific message from ATM
/// Returns a list of messages that were deleted
/// ACL_MODE: Requires LOCAL access
pub async fn message_delete_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<DeleteMessageRequest>,
) -> Result<(StatusCode, Json<SuccessResponse<DeleteMessageResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_delete_handler",
        session = session.session_id,
        did_hash = session.did_hash,
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

        debug!("Deleting ({}) messages", body.message_ids.len());
        if body.message_ids.len() > state.limits().deleted_messages {
            return Err(MediatorError::problem_with_log(
                error_codes::API_MESSAGE_DELETE_LIMIT,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "api.message_delete.limit",
                "Invalid limit ({1}). Maximum of {2} messages can be deleted per transaction",
                vec![
                    body.message_ids.len().to_string(),
                    state.limits().deleted_messages.to_string(),
                ],
                StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }
        let mut deleted: DeleteMessageResponse = DeleteMessageResponse::default();
        for r in delete_for_session(
            &state,
            &session,
            &body.message_ids,
            crate::monitor::Channel::Rest,
            DeleteKind::AcknowledgeOrWithdraw,
        )
        .await
        {
            match r.outcome {
                Ok(()) => deleted.success.push(r.id),
                Err(err) => {
                    debug!(message_id = %r.id, error = %err, "Delete failed (may already be deleted)");
                    deleted.errors.push((r.id, err.to_string()));
                }
            }
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(deleted),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// What [`delete_for_session`] did with one id.
pub(crate) struct DeleteResult {
    pub id: String,
    /// `Ok` once the message is deleted.
    pub outcome: Result<(), MediatorError>,
    /// Not deleted, but held for a member whose mail this connection reads
    /// (`receive` or `pickup`), without the `delete` scope (or whose
    /// standing has lapsed).
    pub member_without_delete: bool,
}

/// How [`delete_for_session`] reads an id (see `messages::client_delete`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeleteKind {
    /// An acknowledgement only: an owner's own copy, never a copy an owner
    /// sent to someone else (`messaging/mux/ack`).
    Acknowledge,
    /// As `DELETE /delete`: an owner's own copy, else what an owner sent,
    /// unless the delete repeats an acknowledgement.
    AcknowledgeOrWithdraw,
}

/// Delete `ids` with `session`'s authority: its own messages, and on a mux
/// connection (the same session) each member's while the member holds
/// `delete` and its account stands. Which copy of an id is removed follows
/// `kind` and `messages::client_delete`. A message held for no one this
/// session may act for is reported as not found, whoever it belongs to: an
/// id is a hash of the message, and the answer must not confirm another
/// DID's mail.
pub(crate) async fn delete_for_session(
    state: &SharedData,
    session: &Session,
    ids: &[String],
    channel: crate::monitor::Channel,
    kind: DeleteKind,
) -> Vec<DeleteResult> {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    let members =
        crate::mux::connection::members_with(state, &session.session_id, MuxCapability::Delete)
            .await;
    let watching = state.monitor.is_active();

    // Which member holds which id: one batched read per member for the whole
    // request, not one read per id per member (#159). A failed read counts
    // as "not held", as a failed single read did. Only while someone is
    // watching is a body kept, so each `deleted` event names the wire
    // protocol; it is the same in every copy.
    let mut held: Vec<Vec<bool>> = Vec::with_capacity(members.len());
    let mut bodies: Vec<Option<String>> = vec![None; ids.len()];
    for member in &members {
        let found = state
            .database
            .get_messages(member, ids)
            .await
            .unwrap_or_default();
        let mut row = vec![false; ids.len()];
        for (i, copy) in found.into_iter().enumerate().take(ids.len()) {
            let Some(copy) = copy else { continue };
            row[i] = true;
            if watching && bodies[i].is_none() {
                bodies[i] = copy.msg;
            }
        }
        held.push(row);
    }
    if watching
        && bodies.iter().any(Option::is_none)
        && let Ok(own) = state.database.get_messages(&session.did_hash, ids).await
    {
        for (i, copy) in own.into_iter().enumerate().take(ids.len()) {
            if bodies[i].is_none() {
                bodies[i] = copy.and_then(|c| c.msg);
            }
        }
    }

    // Ids are independent of each other, so a few run at once; results keep
    // the order asked.
    // In fixed-size waves of plain futures: a stream of closures borrowing
    // `state` and `session` defeats the `Send` proof the socket task needs.
    let mut results = Vec::with_capacity(ids.len());
    let mut work = ids.iter().zip(bodies).enumerate();
    loop {
        let wave: Vec<_> = work
            .by_ref()
            .take(DELETE_PARALLEL)
            .map(|(i, (message, body_seen))| {
                delete_one(
                    state, session, &members, &held, i, message, body_seen, channel, kind,
                )
            })
            .collect();
        if wave.is_empty() {
            break;
        }
        results.extend(futures_util::future::join_all(wave).await);
    }
    results
}

/// Ids [`delete_for_session`] works on at once.
const DELETE_PARALLEL: usize = 8;

/// [`delete_for_session`] for the `i`th id, `message`, given which of
/// `members` hold which id (`held[member][id]`).
#[allow(clippy::too_many_arguments)]
async fn delete_one(
    state: &SharedData,
    session: &Session,
    members: &[String],
    held: &[Vec<bool>],
    i: usize,
    message: &str,
    body_seen: Option<String>,
    channel: crate::monitor::Channel,
    kind: DeleteKind,
) -> DeleteResult {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    // The owners this id may be deleted as: the session's own DID, then each
    // member it belongs to (read first, to know it is that member's before
    // its standing is checked) while the member's own account still stands —
    // checked for the members the id belongs to, not for every member the
    // connection carries. A member that already acknowledged its copy of the
    // id is an owner too, so a repeat of that acknowledgement is told apart
    // from a withdrawal; it holds nothing, so it can remove nothing.
    let mut owners = vec![session.did_hash.clone()];
    for (member, row) in members.iter().zip(held) {
        if !row.get(i).copied().unwrap_or(false) {
            if state
                .database
                .acknowledged(member, message)
                .await
                .unwrap_or(false)
            {
                owners.push(member.clone());
            }
            continue;
        }
        if !crate::mux::connection::allows(
            state,
            &session.session_id,
            member,
            MuxCapability::Delete,
        )
        .await
        {
            continue;
        }
        owners.push(member.clone());
    }

    // An owner's own copy (an acknowledgement), else — for
    // `AcknowledgeOrWithdraw` — what an owner sent (a withdrawal) unless
    // the delete repeats an acknowledgement.
    let result = delete_for_client(
        &*state.database,
        &owners,
        message,
        kind == DeleteKind::AcknowledgeOrWithdraw,
    )
    .await;

    let mut member_without_delete = false;
    let outcome = match result {
        Ok(removed) => {
            // One event per copy removed: a withdrawal may remove
            // several, one per recipient.
            for copy in &removed.copies {
                state.monitor.deleted(
                    message,
                    &removed.owner,
                    copy.from_did_hash.as_deref(),
                    Some(copy.to_did_hash.as_str()),
                    channel,
                    body_seen.as_deref(),
                );
            }
            Ok(())
        }
        Err(err) => {
            // Held for a member whose mail this connection reads, which
            // may not delete it? Only such a member is told apart: for
            // any other, the answer would confirm a message the principal
            // was never shown (one it sent, say).
            for member in crate::mux::connection::members_reading(state, &session.session_id).await
            {
                if (!owners.contains(&member)
                    || !crate::mux::connection::allows(
                        state,
                        &session.session_id,
                        &member,
                        MuxCapability::Delete,
                    )
                    .await)
                    && let Ok(Some(_)) = state.database.get_message(&member, message).await
                {
                    member_without_delete = true;
                    break;
                }
            }
            Err(err)
        }
    };
    DeleteResult {
        id: message.to_string(),
        outcome,
        member_without_delete,
    }
}
