//! The DIDComm door for the two wake messages a party with no account here
//! may send this mediator: a `messaging/wake/request`, and a push gateway's
//! answer to a ring.
//!
//! Every other message addressed to the mediator needs an authenticated
//! session whose DID sent it. These two are the exceptions, and only these:
//! a wake request is usually relayed by the requester's own mediator, over an
//! anonymous relay session, and a gateway's answer arrives the same way. Each
//! still needs an authenticated envelope (authcrypt or a JWS), and nothing
//! here creates an account or lets the sender do anything else
//! (`messaging/wake/request/0.1` "Receiving the request").

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::did_identity::same_account;
use affinidi_messaging_mediator_common::errors::MediatorError;
use http::StatusCode;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::messages::ProcessMessageResponse;
use crate::messages::protocols::trust_tasks::{ENVELOPE_TYPE, tt_problem};

/// How long the answer to a wake request may wait to be collected.
const ANSWER_TTL_SECS: u64 = 300;

/// Handle `msg` if it is one of the two wake messages; `None` leaves it to the
/// mediator's ordinary handling.
///
/// `sender_did` is the DID that authenticated the envelope, if any.
pub(crate) async fn intercept(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    sender_did: Option<&str>,
) -> Result<Option<ProcessMessageResponse>, MediatorError> {
    if msg.typ != ENVELOPE_TYPE {
        return Ok(None);
    }
    let body_type = msg.body.get("type").and_then(Value::as_str);

    if body_type == Some(super::request::REQUEST_TYPE) {
        // A test standing in for a mediator that predates the task.
        if state
            .config
            .withheld_task_types
            .iter()
            .any(|t| t == super::request::REQUEST_TYPE)
        {
            return Ok(None);
        }
        let Some(sender) = sender_did else {
            return Err(tt_problem(
                session,
                "permissionDenied",
                "Trust Task envelopes require an authenticated sender".into(),
                StatusCode::BAD_REQUEST,
            ));
        };
        return answer_request(state, session, msg, sender).await.map(Some);
    }

    // A gateway answering a ring: only a document threaded to a ring this
    // mediator awaits, and only from that ring's gateway.
    if let Some(sender) = sender_did
        && let Some(thread) = msg.body.get("threadId").and_then(Value::as_str)
        && state.wake.awaits(thread)
    {
        super::ring::receive_answer(state, sender, &msg.body).await;
        return Ok(Some(handled()));
    }
    Ok(None)
}

/// Run the request and send its answer: on the requester's own session when
/// it has one here, otherwise to its own mediator, best-effort.
async fn answer_request(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    sender: &str,
) -> Result<ProcessMessageResponse, MediatorError> {
    let doc: TrustTask<Value> = serde_json::from_value(msg.body.clone()).map_err(|e| {
        tt_problem(
            session,
            "malformedRequest",
            format!("body is not a Trust Task document: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    // A session authenticated as the requester was charged to the per-DID
    // limiter when it authenticated; any other was not.
    let own_session = session.authenticated && same_account(&session.did, sender);
    let response =
        super::request::handle(state, session, doc, &msg.body, sender, !own_session).await?;
    let response =
        crate::messages::protocols::trust_task_sign::sign_response(response, state).await?;

    let now = state.clock.unix_secs();
    let mediator_did = state.config.mediator_did.clone();
    let reply = Message::build(
        Uuid::new_v4().to_string(),
        ENVELOPE_TYPE.to_string(),
        response,
    )
    .thid(msg.id.clone())
    .to(sender.to_string())
    .from(mediator_did.clone())
    .created_time(now)
    .expires_time(now + ANSWER_TTL_SECS)
    .finalize();

    if own_session {
        return Ok(ProcessMessageResponse::Reply(Box::new(reply)));
    }

    // No inbox here for the requester: the answer is sent where its DID
    // document says it collects mail. Off the request's path, and never an
    // error to the relay that brought the request.
    let st = state.clone();
    let to = sender.to_string();
    tokio::spawn(async move {
        let packed = crate::didcomm_compat::pack_encrypted(
            &reply,
            &to,
            Some(&mediator_did),
            &st.did_resolver,
            &*st.config.security.mediator_secrets,
        )
        .await;
        let result = match packed {
            Ok((packed, _)) => crate::messages::protocols::routing::send_as_mediator(
                &st,
                &to,
                &packed,
                now + ANSWER_TTL_SECS,
            )
            .await
            .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            tracing::debug!(error = %e, "wake request answer not sent");
        }
    });
    Ok(handled())
}

/// Handled here, nothing to store: the answer (if any) has its own way out.
/// Reported to the sender as accepted, like a forward — `Nothing` is a
/// refusal on this path.
fn handled() -> ProcessMessageResponse {
    ProcessMessageResponse::Forwarded
}
