/*!
 * Message Pickup Protocol 3.0 implementation
 *
 * NOTE: All messages generated from this protocol are ephemeral and are not stored in the database
 * They are fire and forget messages
 */
use crate::error_codes;
use affinidi_messaging_didcomm::message::{Attachment, Message};
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{DeletionAuthority, MessageScope},
};
use affinidi_messaging_sdk::{
    messages::{
        fetch::FetchOptions,
        problem_report::{ProblemReportScope, ProblemReportSorter},
    },
    protocols::message_pickup::{
        MessagePickupDeliveryRequest, MessagePickupLiveDelivery, MessagePickupMessagesReceived,
        MessagePickupStatusReply, MessagePickupStatusRequest,
    },
};
use base64::prelude::*;
use http::StatusCode;
use serde_json::json;
use tracing::{Instrument, debug, info, span};
use uuid::Uuid;

use crate::{
    SharedData,
    common::session::Session,
    messages::ProcessMessageResponse,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState},
};

const MAX_RETRIEVED_MSGS: usize = 100;
const MIN_RETRIEVED_MSGS: usize = 1;

/// Most ids one `messages-received` may acknowledge, as the v1 twin and
/// `messaging/message/delete` allow. Each id costs store round trips.
const MAX_RECEIVED_IDS: usize = 100;

/// A `delivery` carries at most this many `message_size`s of stored bodies.
///
/// `limit` alone bounds the count, not the bytes: 100 messages at the 1 MiB
/// `message_size` is ~100 MiB of bodies, base64-encoded and then encrypted
/// (base64 again) in memory for one request — two orders of magnitude over the
/// bound `message_size` is meant to give every buffer. Past the budget the
/// rest stay queued and come with the next request.
const DELIVERY_BUDGET_MESSAGES: usize = 4;

/// The byte budget for one `delivery`'s stored bodies. A delivery always
/// carries at least one message, whatever its size.
pub(crate) fn delivery_byte_budget(message_size: usize) -> usize {
    message_size.saturating_mul(DELIVERY_BUDGET_MESSAGES)
}

/// Process a Status Request message and generates a response
pub(crate) async fn status_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "status_request",);
    async move {
        _validate_msg(msg, state, session)?;
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull recipient_did from message body: (DID, its hash)
        let (recipient_did, recipient_did_hash): (String, String) = if let Ok(body) =
            serde_json::from_value::<MessagePickupStatusRequest>(msg.body.to_owned())
        {
            if let Some(recipient_did) = body.recipient_did {
                // On a mux connection a member with `pickup` may be asked
                // about too (design §7.6).
                let mux_member = crate::mux::connection::allows(
                    state,
                    &session.session_id,
                    &affinidi_messaging_mediator_common::did_identity::did_hash(&recipient_did),
                    affinidi_messaging_mediator_common::store::mux::MuxCapability::Pickup,
                )
                .await;
                if !mux_member
                    && !affinidi_messaging_mediator_common::did_identity::same_account(
                        &recipient_did,
                        &session.did,
                    )
                {
                    debug!(
                        "recipient_did: ({}) doesn't match session.did!",
                        recipient_did
                    );
                    return Err(MediatorError::problem_with_log(
                        error_codes::SESSION_DID_MISMATCH,
                        &session.session_id,
                        Some(msg.id.clone()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.did.session_mismatch",
                        "Recipient DID ({1}) does not match session DID",
                        vec![recipient_did.to_string()],
                        StatusCode::BAD_REQUEST,
                        "recipient_did doesn't match session.did",
                    ));
                } else {
                    let hash =
                        affinidi_messaging_mediator_common::did_identity::did_hash(&recipient_did);
                    (recipient_did, hash)
                }
            } else {
                (session.did.clone(), session.did_hash.clone())
            }
        } else {
            (session.did.clone(), session.did_hash.clone())
        };
        debug!("Body: recipient_did: {}", recipient_did);

        info!(
            "MessagePickup Status-Request received from: ({}) recipient_did_hash({:?})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            recipient_did_hash
        );

        generate_status_reply(
            state,
            session,
            &recipient_did_hash,
            &recipient_did,
            &thid,
            false,
            None,
        )
        .await
    }
    .instrument(_span)
    .await
}

/// Creates the reply to a valid StatusRequest message
/// did_hash / recipient_did: the account reported on — the session's own, or
///           a mux member's — and the DID the reply names, so a mux principal
///           can tell whose counts it received.
/// force_live_delivery: If true, will force the message to be live streamed even if live streaming is disabled.
///           Required due to the protocol specification to send a status update on live_streaming changes
/// override_live_delivery: If Some(bool), will override the live delivery status of the recipient
///           Because we are async handling streaming updates, we send the response before the streaming task has updated the status
async fn generate_status_reply(
    state: &SharedData,
    session: &Session,
    did_hash: &str,
    recipient_did: &str,
    thid: &str,
    force_live_delivery: bool,
    override_live_delivery: Option<bool>,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "generate_status_reply",);

    async move {
        // Pull the underlying status fields from the trait. The
        // `InboxStatusReply` mirrors the Lua function's response shape
        // so this is a structured read instead of a raw FCALL +
        // tuple-walk; backends that don't speak Redis Lua produce the
        // same data via their own implementations.
        let inbox = state.database.inbox_status(did_hash).await.map_err(|e| {
            if e.is_storage_cap() {
                return e;
            }
            MediatorError::problem_with_log(
                error_codes::DB_OPERATION_ERROR,
                &session.session_id,
                Some(thid.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.error",
                "Database transaction error: {1}",
                vec![e.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Database transaction error: {e}"),
            )
        })?;

        // Helper: a stream ID like "1700000000000-0" carries the
        // millisecond timestamp in the part before the hyphen. Convert
        // that to seconds; return None when the format doesn't match.
        let parse_stream_secs = |raw: &str| -> Option<u64> {
            let head = raw.split('-').next()?;
            head.parse::<u64>().ok().map(|ms| ms / 1000)
        };

        let mut status = MessagePickupStatusReply {
            recipient_did: recipient_did.to_string(),
            message_count: u32::try_from(inbox.message_count).unwrap_or(u32::MAX),
            total_bytes: inbox.total_bytes,
            live_delivery: inbox.live_delivery,
            newest_received_time: parse_stream_secs(&inbox.newest_received),
            oldest_received_time: parse_stream_secs(&inbox.oldest_received),
            ..Default::default()
        };

        if let Some(live_delivery) = override_live_delivery {
            status.live_delivery = live_delivery;
        }

        let now = state.clock.unix_secs();

        if let Some(t) = status.oldest_received_time {
            // Using wrapping sub because result could overflow u64
            status.longest_waited_seconds = Some(now.wrapping_sub(t));
        }

        // Build the message
        let status_msg = Message::build(
            Uuid::new_v4().to_string(),
            "https://didcomm.org/messagepickup/3.0/status".to_owned(),
            json!(status),
        )
        .thid(thid.to_owned())
        .to(session.did.clone())
        .from(state.config.mediator_did.clone())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("status message =\n{:?}", status_msg);

        Ok(ProcessMessageResponse {
            handed_over: None,
            store_message: false,
            force_live_delivery,
            data: crate::messages::WrapperType::Message(Box::new(status_msg)),
            forward_message: false,
        })
    }
    .instrument(_span)
    .await
}

/// Allows for turning on and off live delivery within ATM for a client
pub(crate) async fn toggle_live_delivery(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "toggle_live_delivery",);
    async move {
        _validate_msg(msg, state, session)?;

        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull live_delivery from message body
        let live_delivery: bool =
            match serde_json::from_value::<MessagePickupLiveDelivery>(msg.body.to_owned()) {
                Ok(body) => body.live_delivery,
                Err(e) => {
                    return Err(MediatorError::problem_with_log(
                        error_codes::MESSAGE_BODY_PARSE_ERROR,
                        &session.session_id,
                        Some(msg.id.clone()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.pickup.parse",
                        "Couldn't parse live_delivery body. Reason: {1}",
                        vec![e.to_string()],
                        StatusCode::BAD_REQUEST,
                        format!("Couldn't parse live_delivery body. Reason: {e}"),
                    ));
                }
            };
        debug!("Body: live_delivery: {}", live_delivery);

        info!(
            "MessagePickup live_delivery received from: ({}) live_delivery?({})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            live_delivery
        );

        // Live delivery needs the streaming task. Without it the mediator
        // cannot push anything, so turning it on is refused rather than
        // answered with a status claiming it is on (R6.2).
        if live_delivery && state.streaming_task.is_none() {
            return Err(MediatorError::problem(
                error_codes::STREAMING_SIGNAL_ERROR,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "protocol.pickup.live_streaming",
                "Live delivery is not available on this mediator",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
            ));
        }

        // Take action to change live delivery status
        if live_delivery {
            // Enable Live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task
                    .channel
                    .send(StreamingUpdate {
                        did_hash: session.did_hash.clone(),
                        state: StreamingUpdateState::Start {
                            session_id: session.session_id.clone(),
                        },
                    })
                    .await
                    .map_err(|e| {
                        MediatorError::problem_with_log(
                            error_codes::STREAMING_SIGNAL_ERROR,
                            &session.session_id,
                            Some(msg.id.clone()),
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "protocol.pickup.live_streaming",
                            "Couldn't send START signal to streaming task. Reason: {1}",
                            vec![e.to_string()],
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Couldn't send START signal to streaming task. Reason: {e}"),
                        )
                    })?;
            }
        } else {
            // Disable live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task
                    .channel
                    .send(StreamingUpdate {
                        did_hash: session.did_hash.clone(),
                        state: StreamingUpdateState::Stop {
                            session_id: session.session_id.clone(),
                        },
                    })
                    .await
                    .map_err(|e| {
                        MediatorError::problem_with_log(
                            error_codes::STREAMING_SIGNAL_ERROR,
                            &session.session_id,
                            Some(msg.id.clone()),
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "protocol.pickup.live_streaming",
                            "Couldn't send STOP signal to streaming task. Reason: {1}",
                            vec![e.to_string()],
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Couldn't send STOP signal to streaming task. Reason: {e}"),
                        )
                    })?;
            }
        }

        generate_status_reply(
            state,
            session,
            &session.did_hash,
            &session.did,
            &thid,
            true,
            Some(live_delivery),
        )
        .await
    }
    .instrument(_span)
    .await
}

/// Process a Delivery Request message and generates a response
pub(crate) async fn delivery_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "delivery_request",);
    async move {
        _validate_msg(msg, state, session)?;
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // A member of this mux connection with `pickup` may be collected for
        // as well as the session's own DID (design §7.6).
        let mux_member = match msg.body.get("recipient_did").and_then(|v| v.as_str()) {
            Some(r) => {
                crate::mux::connection::allows(
                    state,
                    &session.session_id,
                    &affinidi_messaging_mediator_common::did_identity::did_hash(r),
                    affinidi_messaging_mediator_common::store::mux::MuxCapability::Pickup,
                )
                .await
            }
            None => false,
        };
        // Pull recipient_did and limit from message body
        let (recipient_did, limit): (String, usize) =
            _parse_and_validate_delivery_request_body(session, msg, mux_member)?;

        let recipient_did_hash =
            affinidi_messaging_mediator_common::did_identity::did_hash(recipient_did.clone());

        debug!(
            "Body: recipient_did: {}, limit: {}",
            recipient_did_hash, limit
        );

        info!(
            "MessagePickup Delivery-Request received from: ({}) recipient_did({}) limit({})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            recipient_did_hash,
            limit
        );

        // All the parsing is done, lets attempt to retrieve messages. Nothing
        // is recorded here: what the reply carries is stamped delivered and
        // reported once the reply is written (`handed_over`, R1.1).
        let messages = crate::after_write::fetch_for_handover(
            state,
            &session.session_id,
            &recipient_did_hash,
            &FetchOptions {
                limit,
                ..Default::default()
            },
        )
        .await?;
        debug!("msgs fetched: {}", messages.success.len());

        // Only messages with a body are attached, and only up to the byte
        // budget; the rest stay queued for the next request.
        let budget = delivery_byte_budget(state.limits().message_size);
        let mut attachments: Vec<Attachment> = Vec::new();
        let mut handed_over = crate::after_write::HandedOver::new(&recipient_did_hash);
        let mut used = 0usize;
        for element in &messages.success {
            let Some(body) = element.msg.as_deref() else {
                continue;
            };
            if !attachments.is_empty() && used.saturating_add(body.len()) > budget {
                debug!(
                    "delivery byte budget ({budget}) reached after {} message(s); the rest stay queued",
                    attachments.len()
                );
                break;
            }
            used = used.saturating_add(body.len());
            attachments.push(
                Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(body))
                    .id(element.msg_id.clone())
                    .finalize(),
            );
            handed_over
                .messages
                .push(crate::after_write::HandedOverMessage::of(element));
        }

        if !attachments.is_empty() {
            let response_msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/messagepickup/3.0/delivery".to_string(),
                json!({"recipient_did": recipient_did}),
            )
            .thid(thid.clone());

            let now = state.clock.unix_secs();

            let response_msg = response_msg
                .attachments(attachments)
                .to(session.did.clone())
                .from(state.config.mediator_did.clone())
                .created_time(now)
                .expires_time(now + 300)
                .finalize();

            debug!("delivery message =\n{:?}", response_msg);

            Ok(ProcessMessageResponse {
                store_message: false,
                force_live_delivery: false,
                data: crate::messages::WrapperType::Message(Box::new(response_msg)),
                forward_message: false,
                handed_over: Some(handed_over),
            })
        } else {
            generate_status_reply(
                state,
                session,
                &recipient_did_hash,
                &recipient_did,
                &thid,
                false,
                None,
            )
            .await
        }
    }
    .instrument(_span)
    .await
}

// Process a Messages Received message and generates a response
pub(crate) async fn messages_received(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "messages_received",);
    async move {
        _validate_msg(msg, state, session)?;
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull messages ids list from message body
        let message_id_list: Vec<String> = _parse_message_received_body(session, msg)?;
        if message_id_list.len() > MAX_RECEIVED_IDS {
            return Err(MediatorError::problem_with_log(
                error_codes::INVALID_LIMIT,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.pickup.messages_received.limit",
                "message_id_list may name at most {1} messages. Received ({2})",
                vec![
                    MAX_RECEIVED_IDS.to_string(),
                    message_id_list.len().to_string(),
                ],
                StatusCode::BAD_REQUEST,
                format!(
                    "message_id_list may name at most {MAX_RECEIVED_IDS} messages. Received ({})",
                    message_id_list.len()
                ),
            ));
        }

        debug!("Messages Id list: {:?}", message_id_list);

        // Whose messages this session may delete: its own, and on a mux
        // connection each member's with `delete` (design §7.6). An id is
        // deleted as the first owner it belongs to.
        let mut owners = vec![session.did_hash.clone()];
        owners.extend(
            crate::mux::connection::members_with(
                state,
                &session.session_id,
                affinidi_messaging_mediator_common::store::mux::MuxCapability::Delete,
            )
            .await,
        );
        // A member's standing is read once per request, not once per id.
        let mut member_allowed: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        // The owners whose messages this acknowledged.
        let mut acknowledged_for: Vec<String> = Vec::new();
        for msg_id in &message_id_list {
            // The store authorises the delete itself; try each owner this
            // session may delete for until one is accepted, those whose copy
            // was handed over first (a principal and a member may both hold
            // the same bytes; the one acknowledged is the one delivered). The
            // delete reports the copy it removed, so nothing is read first.
            let mut deleted = false;
            let ordered =
                crate::messages::client_delete::ack_order(&*state.database, &owners, msg_id).await;
            for owner_hash in &ordered {
                // A mux member's message is deleted only while the member's
                // own account still stands.
                if *owner_hash != session.did_hash {
                    let allowed = match member_allowed.get(owner_hash) {
                        Some(allowed) => *allowed,
                        None => {
                            let allowed = crate::mux::connection::allows(
                                state,
                                &session.session_id,
                                owner_hash,
                                affinidi_messaging_mediator_common::store::mux::MuxCapability::Delete,
                            )
                            .await;
                            member_allowed.insert(owner_hash.clone(), allowed);
                            allowed
                        }
                    };
                    if !allowed {
                        continue;
                    }
                }
                debug!("Deleting message: {}", msg_id);
                match state
                    .database
                    // An acknowledgement: the owner's own copy only, never
                    // a copy it sent to someone else.
                    .delete_message_in(
                        msg_id,
                        MessageScope::Recipient(owner_hash),
                        DeletionAuthority::Owner {
                            did_hash: owner_hash.clone(),
                        },
                    )
                    .await
                {
                    Ok(copies) => {
                        for copy in &copies {
                            state.monitor.deleted(
                                msg_id,
                                owner_hash,
                                copy.from_did_hash.as_deref(),
                                Some(copy.to_did_hash.as_str()),
                                crate::monitor::current_channel(),
                                // Not read just to classify the event.
                                None,
                            );
                        }
                        info!("Deleted message: {}", msg_id);
                        if !acknowledged_for.contains(owner_hash) {
                            acknowledged_for.push(owner_hash.clone());
                        }
                        deleted = true;
                        break;
                    }
                    Err(err) => {
                        debug!("Delete of {msg_id} as {owner_hash} refused: {err:?}");
                    }
                }
            }
            if !deleted {
                info!("Message {msg_id} was not deleted: not this session's to delete, or already gone");
            }
        }

        // The status answered is the account whose messages were acknowledged:
        // a mux member's when they were all that member's, else the session's.
        if let [member_hash] = acknowledged_for.as_slice()
            && *member_hash != session.did_hash
            && let Some(member_did) =
                crate::mux::connection::member_did(state, &session.session_id, member_hash).await
        {
            return generate_status_reply(
                state,
                session,
                member_hash,
                &member_did,
                &thid,
                false,
                None,
            )
            .await;
        }
        generate_status_reply(
            state,
            session,
            &session.did_hash,
            &session.did,
            &thid,
            false,
            None,
        )
        .await
    }
    .instrument(_span)
    .await
}

fn _parse_message_received_body(
    session: &Session,
    msg: &Message,
) -> Result<Vec<String>, MediatorError> {
    let message_id_list: Vec<String> =
        match serde_json::from_value::<MessagePickupMessagesReceived>(msg.body.to_owned()) {
            Ok(body) => body.message_id_list,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    error_codes::MESSAGE_BODY_PARSE_ERROR,
                    &session.session_id,
                    Some(msg.id.clone()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.pickup.parse",
                    "Couldn't parse messages-received body. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't parse messages-received body. Reason: {e}"),
                ));
            }
        };

    Ok(message_id_list)
}

fn _parse_and_validate_delivery_request_body(
    session: &Session,
    msg: &Message,
    // The recipient is a member of this session's mux connection with `pickup`.
    mux_member: bool,
) -> Result<(String, usize), MediatorError> {
    let (recipient_did, limit): (String, usize) =
        match serde_json::from_value::<MessagePickupDeliveryRequest>(msg.body.to_owned()) {
            Ok(body) => (body.recipient_did, body.limit),
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    error_codes::MESSAGE_BODY_PARSE_ERROR,
                    &session.session_id,
                    Some(msg.id.clone()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.pickup.parse",
                    "Couldn't parse delivery-request body. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't parse delivery-request body. Reason: {e}"),
                ));
            }
        };

    if !mux_member
        && !affinidi_messaging_mediator_common::did_identity::same_account(
            &session.did,
            &recipient_did,
        )
    {
        return Err(MediatorError::problem_with_log(
            error_codes::SESSION_DID_MISMATCH,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.did.session_mismatch",
            "Recipient DID ({1}) does not match session DID",
            vec![recipient_did.to_string()],
            StatusCode::BAD_REQUEST,
            "recipient_did doesn't match session.did",
        ));
    }

    if !(MIN_RETRIEVED_MSGS..=MAX_RETRIEVED_MSGS).contains(&limit) {
        return Err(MediatorError::problem_with_log(
            error_codes::INVALID_LIMIT,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.pickup.delivery_request.limit",
            "limit must be between 1 and 100 inclusive. Received limit({1})",
            vec![limit.to_string()],
            StatusCode::BAD_REQUEST,
            format!("limit must be between 1 and 100 inclusive. Received limit({limit})"),
        ));
    }

    Ok((recipient_did, limit))
}

fn _validate_msg(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    // Expiry is checked for every message before it reaches a protocol
    // handler (`MessageHandler::process`), so it is not repeated here.

    // Must be addressed to Mediator
    super::addressed_to_mediator(msg, &state.config.mediator_did, session, "Message Pickup")?;

    // Message can not be anonymous
    if msg.from.is_none() {
        return Err(MediatorError::problem(
            error_codes::ANON_MESSAGE_ERROR,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.anonymous",
            "Message Pickup 3.0 requires a from: header for permission validation",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };

    // Check for extra-header `return_route`
    if let Some(header) = msg.extra.get("return_route") {
        if header.as_str() != Some("all") {
            debug!(
                "return_route: extra-header exists. Expected (all) but received ({})",
                header
            );
            return Err(MediatorError::problem_with_log(
                error_codes::PICKUP_RETURN_ROUTE_ERROR,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.pickup.return_route",
                "return_route header is incorrect. Expected (all) but it contains ({1})",
                vec![header.to_string()],
                StatusCode::BAD_REQUEST,
                format!("return_route header is incorrect. Expected (all) but received ({header})"),
            ));
        }
    } else {
        debug!("return_route: extra-header does not exist!");
        return Err(MediatorError::problem(
            error_codes::PICKUP_RETURN_ROUTE_ERROR,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.pickup.return_route",
            "return_route header is missing",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::delivery_byte_budget;

    #[test]
    fn the_delivery_budget_is_a_few_message_sizes_and_never_overflows() {
        assert_eq!(delivery_byte_budget(1_048_576), 4 * 1_048_576);
        assert_eq!(delivery_byte_budget(usize::MAX), usize::MAX);
    }
}
