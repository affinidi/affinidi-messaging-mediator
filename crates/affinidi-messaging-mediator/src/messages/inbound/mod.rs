//! Inbound message handling: the entry points every ingress path (REST
//! `POST /inbound`, WebSocket text and binary frames) calls, by protocol.
//!
//! - `didcomm` — DIDComm v2: messages to the mediator, direct delivery, and
//!   the re-wrap relay peel.
//! - `tsp` — TSP: opaque pass-through, layers addressed to the mediator,
//!   Trust Tasks over TSP.
//! - `tsp_relay` — TSP routed / nested relay: route planning, the next hop
//!   (local or remote), and the remote endpoint lookup.

use crate::error_codes;
use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use http::StatusCode;

#[cfg(feature = "didcomm")]
mod didcomm;
#[cfg(feature = "tsp")]
mod tsp;
#[cfg(feature = "tsp")]
mod tsp_relay;

#[cfg(feature = "didcomm")]
use didcomm::handle_inbound_didcomm;
#[cfg(feature = "tsp")]
pub(crate) use tsp::{handle_inbound_tsp, resolve_tsp_vid};

/// Reject a message larger than `limits.message_size`.
///
/// Every ingress path (HTTP `POST /inbound`, WebSocket text, WebSocket binary /
/// TSP) funnels through `handle_inbound` or `handle_inbound_tsp`, so this is the
/// one place the ceiling has to hold.
///
/// The transport caps (`http_size`, `ws_size`) are deliberately *larger* than
/// this — they bound a single request or frame, whereas this bounds the message
/// the mediator will copy, queue, store, and fan out. Every in-memory buffer is
/// sized against this value, so it has to be enforced for those bounds to mean
/// anything.
pub(super) fn check_message_size(
    state: &SharedData,
    session: &Session,
    len: usize,
) -> Result<(), MediatorError> {
    let limit = state.config.limits.message_size;
    if len > limit {
        return Err(MediatorError::problem(
            error_codes::MESSAGE_SIZE_EXCEEDED,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Message,
            "message.size.exceeded",
            "Message size {1} exceeds the mediator limit of {2} bytes",
            vec![len.to_string(), limit.to_string()],
            StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    Ok(())
}

pub(crate) async fn handle_inbound(
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] state: &SharedData,
    session: &Session,
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    check_message_size(state, session, message.len())?;

    // Try DIDComm first if enabled
    #[cfg(feature = "didcomm")]
    {
        return handle_inbound_didcomm(state, session, message).await;
    }

    // If only TSP is enabled, we don't support text-based inbound yet
    #[cfg(not(feature = "didcomm"))]
    {
        Err(MediatorError::problem(
            error_codes::PROTOCOL_UNSUPPORTED,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "protocol.unsupported",
            "No protocol handler available for this message format",
            vec![],
            StatusCode::BAD_REQUEST,
        ))
    }
}

/// Ensure an opaque envelope's claimed sender matches the session DID.
///
/// The mediator holds no key for the envelope it is being handed, so the sender
/// here is only a claim — the JWE `skid` header for DIDComm direct delivery, the
/// cleartext CESR sender field for TSP. In both cases it is also the value that
/// feeds the recipient's access-list lookup, so on an authenticated session it
/// has to be pinned to the DID that authenticated.
///
/// Only the caller can decide whether the session is one that can be matched
/// against: an anonymous inter-mediator relay hop has no session DID, and is
/// exempted at the call site rather than here.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub(super) fn check_direct_delivery_session_match(
    session: &Session,
    claimed_sender: Option<&str>,
) -> Result<(), MediatorError> {
    if claimed_sender == Some(session.did.as_str()) {
        return Ok(());
    }

    let claimed = claimed_sender.unwrap_or("anonymous");
    Err(MediatorError::problem_with_log(
        error_codes::SESSION_DID_MISMATCH,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![claimed.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Direct-delivery envelope sender ({claimed}) doesn't match session DID"),
    ))
}
