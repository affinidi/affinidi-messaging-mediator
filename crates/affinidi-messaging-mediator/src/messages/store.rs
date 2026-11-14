use crate::SharedData;
use crate::common::session::Session;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::{StoredMessageRef, prelude::*};
use affinidi_messaging_sdk::messages::sending::{InboundMessageList, InboundMessageResponse};
use std::sync::Arc;
use tracing::{debug, warn};

#[cfg(feature = "didcomm")]
use super::ProcessMessageResponse;
#[cfg(feature = "didcomm")]
use crate::error_codes;
#[cfg(feature = "didcomm")]
use crate::messages::{MessageHandler, PackOptions};
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::{PackEncryptedMetadata, UnpackMetadata};
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
#[cfg(feature = "didcomm")]
use http::StatusCode;
#[cfg(feature = "didcomm")]
use tracing::{Instrument, span, trace};

/// Store `data` for `to_did_hash`, then publish the live notification.
///
/// The order matters: a raw-TSP socket answers the notification by draining
/// the inbox, so a notification that beats the store wakes a drain that finds
/// nothing and strands the message. Every path that stores into a local inbox
/// and notifies goes through here so the order can't drift between them.
async fn _store_message(
    state: &SharedData,
    session_id: &str,
    force_live_delivery: bool,
    data: &str,
    to_did_hash: &str,
    from_did_hash: Option<&str>,
    expiry: u64,
) -> Result<String, MediatorError> {
    let msg_id = state
        .database
        .store_message(
            session_id,
            data,
            to_did_hash,
            from_did_hash,
            expiry,
            state.limits().queue_stream_maxlen(),
        )
        .await?;

    state
        .monitor
        .stored(&msg_id, from_did_hash, to_did_hash, data);
    // Tagged with the stored message, so the streaming task reports the
    // delivery when (and only if) it queues the notification to the socket.
    if let Some(stream_uuid) = state
        .database
        .streaming_is_client_live(to_did_hash, force_live_delivery)
        .await
        && let Err(err) = state
            .database
            .streaming_publish_stored(
                to_did_hash,
                &stream_uuid,
                data,
                force_live_delivery,
                StoredMessageRef {
                    msg_id: msg_id.clone(),
                    from_did_hash: from_did_hash.map(str::to_string),
                },
            )
            .await
    {
        warn!("Live notification for did_hash({to_did_hash}) not published: {err}");
    }
    state.activity.received(state, to_did_hash).await;
    crate::account_stats::count_stored(state, from_did_hash, to_did_hash, data).await;
    // A wake request that arrived before this message may be waiting for it.
    crate::wake::request::on_stored(state, to_did_hash, &msg_id);
    Ok(msg_id)
}

/// Store a message the mediator authored itself (a mux notice) in a local
/// inbox, and notify a live connection, in the same order as every other
/// store. Returns the stored message's id.
pub(crate) async fn store_system_message(
    state: &SharedData,
    data: &str,
    to_did_hash: &str,
    expiry: u64,
) -> Result<String, MediatorError> {
    _store_message(
        state,
        "mediator",
        false,
        data,
        to_did_hash,
        Some(&state.config.mediator_did_hash),
        expiry,
    )
    .await
}

/// Act on what a DIDComm handler produced (see [`ProcessMessageResponse`]):
/// store a reply in its recipients' inboxes, pack an ephemeral reply for the
/// caller, or report a forward. `metadata` is the request's unpack metadata,
/// which shapes how a reply is packed.
#[cfg(feature = "didcomm")]
pub(crate) async fn store_message(
    state: &SharedData,
    session: &Session,
    response: &ProcessMessageResponse,
    metadata: &UnpackMetadata,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "store_message",);

    async move {
        match response {
            ProcessMessageResponse::Forwarded => Ok(InboundMessageResponse::Forwarded),
            ProcessMessageResponse::Reply(message) => {
                store_reply(state, session, message, metadata).await
            }
            ProcessMessageResponse::EphemeralReply {
                message,
                force_live_delivery,
                handed_over,
            } => {
                let (packed, meta) = message
                    .pack(
                        &session.session_id,
                        &session.did,
                        &state.config.mediator_did,
                        metadata,
                        &*state.config.security.mediator_secrets,
                        &state.did_resolver,
                        &PackOptions {
                            to_keys_per_recipient_limit: state.limits().to_keys_per_recipient,
                            forward: true,
                        },
                    )
                    .await?;
                trace!("Ephemeral message packed (meta):\n{:#?}", meta);
                trace!("Ephemeral message (msg):\n{:#?}", packed);
                // Live stream the message?
                let pushed = match state
                    .database
                    .streaming_is_client_live(&session.did_hash, *force_live_delivery)
                    .await
                {
                    Some(stream_uuid) => {
                        _live_stream(
                            &state.database,
                            &session.did_hash,
                            &stream_uuid,
                            &packed,
                            *force_live_delivery,
                        )
                        .await
                    }
                    None => false,
                };
                // The reply is packed; what it hands over is recorded once it is
                // written: with the REST body when it came over REST, else now
                // if the live stream took it, else not at all (R1.1).
                if let Some(handed_over) = handed_over {
                    crate::after_write::defer_or_run(
                        handed_over
                            .clone()
                            .completion(state, crate::monitor::current_channel()),
                        pushed,
                    )
                    .await;
                }
                Ok(InboundMessageResponse::Ephemeral(packed))
            }
            // The message was handled and asked for no answer (a ping with
            // `response_requested: false`, a Trust Task answered with
            // silence). That is a success with nothing in it: over REST the
            // usual `200` envelope with `data: "Empty"` — the same status
            // every other accepted `/inbound` message gets, and the SDK's
            // variant for "no response expected" — and over a WebSocket no
            // frame at all. It was once a `500 me.storage.message.error`,
            // which told the sender a handled message had failed.
            ProcessMessageResponse::Nothing => {
                debug!("Handled; nothing to answer");
                Ok(InboundMessageResponse::Empty)
            }
        }
    }
    .instrument(_span)
    .await
}

/// Pack a reply the mediator authored for each of its recipients and store it
/// in their inboxes. Answers with what was stored and the per-recipient
/// failures; a reply stored nowhere is the first failure.
#[cfg(feature = "didcomm")]
async fn store_reply(
    state: &SharedData,
    session: &Session,
    message: &affinidi_messaging_didcomm::message::Message,
    metadata: &UnpackMetadata,
) -> Result<InboundMessageResponse, MediatorError> {
    let mut stored_messages = InboundMessageList::default();
    // Pack the message for the next recipient(s)
    let Some(to_dids) = &message.to else {
        return Err(MediatorError::problem(
            error_codes::MESSAGE_RECIPIENTS_MISSING,
            &session.session_id,
            Some(message.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.recipients.missing",
            "Message has no recipients",
            vec![],
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    };
    debug!(
        "response to_dids: count({}) vec({:?})",
        to_dids.len(),
        to_dids
    );

    if to_dids.len() > state.limits().to_recipients {
        return Err(MediatorError::problem_with_log(
            error_codes::MESSAGE_RECIPIENTS_TOO_MANY,
            &session.session_id,
            Some(message.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.recipients.too_many",
            "Message has too many recipients ({1}). Max: {2}",
            vec![
                to_dids.len().to_string(),
                state.limits().to_recipients.to_string(),
            ],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Message has too many recipients ({}). Max: {}",
                to_dids.len(),
                state.limits().to_recipients
            ),
        ));
    }

    let expires_at = if let Some(expires_at) = message.expires_time {
        let now = state.clock.unix_secs();

        if expires_at > now + state.limits().message_expiry_seconds {
            now + state.limits().message_expiry_seconds
        } else {
            expires_at
        }
    } else {
        state.clock.unix_secs() + state.limits().message_expiry_seconds
    };

    // A reply to several recipients answers with what was
    // stored and the per-recipient failures; one stored
    // nowhere is a failure, not a success with a list of
    // errors the sender has to dig out (R1.1).
    let mut first_error: Option<MediatorError> = None;
    for recipient in to_dids {
        let (packed, _): (String, PackEncryptedMetadata) = message
            .pack(
                &session.session_id,
                recipient,
                &state.config.mediator_did,
                metadata,
                &*state.config.security.mediator_secrets,
                &state.did_resolver,
                &PackOptions {
                    to_keys_per_recipient_limit: state.config.limits.to_keys_per_recipient,
                    forward: true,
                },
            )
            .await?;

        match _store_message(
            state,
            &session.session_id,
            false,
            &packed,
            &affinidi_messaging_mediator_common::did_identity::did_hash(recipient),
            Some(&state.config.mediator_did_hash),
            expires_at,
        )
        .await
        {
            Ok(msg_id) => {
                debug!(
                    "message id({}) stored successfully recipient({})",
                    msg_id, recipient
                );
                stored_messages
                    .messages
                    .push((recipient.to_string(), msg_id));
            }
            Err(e) => {
                warn!("error storing message recipient({}): {:?}", recipient, e);
                stored_messages
                    .errors
                    .push((recipient.to_string(), e.to_string()));
                first_error.get_or_insert(e);
            }
        }
    }
    if stored_messages.messages.is_empty()
        && let Some(e) = first_error
    {
        return Err(e);
    }
    Ok(InboundMessageResponse::Stored(stored_messages))
}

/// Store an already-packed message (a direct delivery, a TSP or bridged
/// message) from `from_did_hash` for `to_did`, through the queue gates.
/// Returns the stored message's id; a store failure is the caller's error,
/// never a success with the failure inside it (R1.1).
///
/// Queue gates apply here and NOT to mediator replies ([`store_message`]'s
/// `Message` arm, `store_mediator_reply`), whose sender is the mediator
/// itself: those are the replies that tell a client its queue is full, so
/// gating them would make a full inbox an unreportable one. This is client
/// traffic, and before the gates it reached the store with no depth limit at
/// all — the hole that let a direct sender fill any inbox without bound, and
/// that the per-relationship gate for VTI-29 did not reach.
///
/// `from_did_hash` is the sender the caller vouches for: the session's DID for
/// a direct delivery, the verified sender for a relayed TSP message (whose
/// session may be an anonymous relay with no DID at all).
pub(crate) async fn store_envelope(
    state: &SharedData,
    session: &Session,
    to_did: &str,
    from_did_hash: &str,
    message: &str,
    expiry: u64,
    force_live_delivery: bool,
) -> Result<String, MediatorError> {
    let to_hash = affinidi_messaging_mediator_common::did_identity::did_hash(to_did);
    crate::messages::queue_limits::validate_store_queue_limits(
        state,
        session,
        None,
        from_did_hash,
        &to_hash,
    )
    .await?;
    match _store_message(
        state,
        &session.session_id,
        force_live_delivery,
        message,
        &to_hash,
        Some(from_did_hash),
        expiry,
    )
    .await
    {
        Ok(msg_id) => {
            debug!(
                "message id({}) stored successfully recipient({})",
                msg_id, to_did
            );
            Ok(msg_id)
        }
        Err(e) => {
            warn!("error storing message recipient({}): {:?}", to_did, e);
            Err(e)
        }
    }
}

/// Store a reply the mediator authored (a Trust Task answer sealed over TSP)
/// for `to_did`: sent by the mediator's own account, with no queue or
/// access-list gate — the same standing the DIDComm path gives its replies.
/// The request it answers has already run, so a gate here would refuse the
/// answer to work that was done, and a retry would then meet the
/// duplicate-execution record. A store failure is an error.
#[cfg(feature = "tsp")]
pub(crate) async fn store_mediator_reply(
    state: &SharedData,
    to_did: &str,
    data: &str,
    expiry: u64,
) -> Result<InboundMessageResponse, MediatorError> {
    let to_hash = affinidi_messaging_mediator_common::did_identity::did_hash(to_did);
    let msg_id = store_system_message(state, data, &to_hash, expiry).await?;
    let mut stored = InboundMessageList::default();
    stored.messages.push((to_did.to_string(), msg_id));
    Ok(InboundMessageResponse::Stored(stored))
}

/// Publish the live notification for a message. A failure loses nothing — the
/// message is in the inbox — so it is not an error, but it is not a live
/// delivery either: returns whether the notification was published.
async fn _live_stream(
    database: &Arc<dyn MediatorStore>,
    did_hash: &str,
    stream_uuid: &str,
    message: &str,
    force_live_delivery: bool,
) -> bool {
    match database
        .streaming_publish_message(did_hash, stream_uuid, message, force_live_delivery)
        .await
    {
        Ok(()) => {
            debug!("Live streaming message to UUID: {}", stream_uuid);
            true
        }
        Err(err) => {
            warn!("Live notification for did_hash({did_hash}) not published: {err}");
            false
        }
    }
}

/// Stores a message in the mediator's database that has been forwarded
/// handles a lot of higher order logic for storing messages
/// - state: SharedData
/// - session: Session
/// - response: ProcessMessageResponse
/// - metadata: UnpackMetadata
/// - expires_at: `Option<u64>`
///   - None: use default expiry
///   - Some: use the provided expiry time in seconds
#[cfg(feature = "didcomm")]
pub(crate) async fn store_forwarded_message(
    state: &SharedData,
    session: &Session,
    message: &str,
    sender_hash: Option<&str>,
    recipient: &str,
    expires_at: Option<u64>,
) -> Result<(), MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "store_forwarded_message",
        session = session.session_id
    );

    async move {
        let recipient_did_hash =
            affinidi_messaging_mediator_common::did_identity::did_hash(recipient);

        let expires_at = if let Some(expires_at) = expires_at {
            let now = state.clock.unix_secs();

            if expires_at > now + state.limits().message_expiry_seconds {
                now + state.limits().message_expiry_seconds
            } else {
                expires_at
            }
        } else {
            state.clock.unix_secs() + state.limits().message_expiry_seconds
        };

        match _store_message(
            state,
            &session.session_id,
            false,
            message,
            &recipient_did_hash,
            sender_hash,
            expires_at,
        )
        .await
        {
            Ok(msg_id) => {
                debug!(
                    "message id({}) stored successfully recipient({})",
                    msg_id, recipient
                );
            }
            // Not swallowed: the caller answers the sender from this result,
            // and a message that was not stored must not be reported as
            // forwarded.
            Err(e) => {
                warn!("error storing message recipient({}): {:?}", recipient, e);
                return Err(e);
            }
        }

        Ok(())
    }
    .instrument(_span)
    .await
}
