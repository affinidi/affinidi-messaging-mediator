use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::{
    errors::{AppError, MediatorError, SuccessResponse},
    store::DeletionAuthority,
};
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
        did = session.did,
    );
    async move {
        // ACL Check
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
            return Err(MediatorError::problem(
                40,
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
                43,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "api.message_delete.limit",
                "Invalid limit ({1}). Maximum of 100 messages can be deleted per transaction",
                vec![body.message_ids.len().to_string()],
                StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }
        let mut deleted: DeleteMessageResponse = DeleteMessageResponse::default();
        for r in delete_for_session(&state, &session, &body.message_ids, crate::monitor::Channel::Rest).await {
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

/// Delete `ids` with `session`'s authority: its own messages, and on a mux
/// connection (the same session) each member's while the member holds
/// `delete` and its account stands. The store authorises each delete; the
/// first owner it accepts wins. A message held for no one this session may
/// act for is reported as not found, whoever it belongs to: an id is a hash
/// of the message, and the answer must not confirm another DID's mail.
pub(crate) async fn delete_for_session(
    state: &SharedData,
    session: &Session,
    ids: &[String],
    channel: crate::monitor::Channel,
) -> Vec<DeleteResult> {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    let mut owners = vec![session.did_hash.clone()];
    owners.extend(
        crate::mux::connection::members_with(state, &session.session_id, MuxCapability::Delete)
            .await,
    );
    let mut results = Vec::with_capacity(ids.len());
    for message in ids {
        let mut result: Result<(), MediatorError> = Err(MediatorError::RequestDataError(
            44,
            session.session_id.clone(),
            "message not found for this session".into(),
        ));
        let mut deleted_as = session.did_hash.clone();
        let mut parties = None;
        for owner in &owners {
            let for_member = *owner != session.did_hash;
            // Read the message for a mux member, to know it is that member's
            // before its standing is checked; otherwise only while someone is
            // watching, so its `deleted` event names both parties.
            let stored = if for_member || state.monitor.is_active() {
                match state.database.get_message(owner, message).await {
                    Ok(Some(m)) => Some(m),
                    _ if for_member => continue,
                    _ => None,
                }
            } else {
                None
            };
            // A member's message is deleted only while the member's own
            // account still stands; checked for the one member the id belongs
            // to, not for every member the connection carries.
            if for_member
                && !crate::mux::connection::allows(
                    state,
                    &session.session_id,
                    owner,
                    MuxCapability::Delete,
                )
                .await
            {
                continue;
            }
            let seen = stored.map(|m| (m.from_address, m.to_address, m.msg));
            result = state
                .database
                .delete_message(
                    message,
                    DeletionAuthority::Owner {
                        did_hash: owner.clone(),
                    },
                )
                .await;
            if result.is_ok() {
                deleted_as = owner.clone();
                parties = seen;
                break;
            }
        }

        let mut member_without_delete = false;
        match &result {
            Ok(()) => {
                let (from, to, body) = parties.unwrap_or_default();
                state.monitor.deleted(
                    message,
                    &deleted_as,
                    from.as_deref(),
                    to.as_deref(),
                    channel,
                    body.as_deref(),
                );
            }
            Err(_) => {
                // Held for a member whose mail this connection reads, which
                // may not delete it? Only such a member is told apart: for
                // any other, the answer would confirm a message the principal
                // was never shown (one it sent, say).
                for member in
                    crate::mux::connection::members_reading(state, &session.session_id).await
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
            }
        }
        results.push(DeleteResult {
            id: message.clone(),
            outcome: result,
            member_without_delete,
        });
    }
    results
}
