//! Problem reports and status messages the socket writes in-band.

use super::*;

/// Tell a DIDComm client that the message it sent was refused, with the
/// problem report the error carries (a generic error is only logged).
///
/// One path for every frame a DIDComm message can arrive in: a refusal that
/// is only logged leaves the sender believing its message went (R1.1), and
/// whether that happens must not depend on Text or Binary framing.
pub(super) async fn report_refusal(
    state: &SharedData,
    session: &Session,
    socket: &mut BoundedSocket,
    error: MediatorError,
) {
    warn!("WebSocket inbound error: {}", error);
    #[cfg(feature = "didcomm")]
    match error {
        MediatorError::MediatorError(_, _, msg_id, problem_report, _, log_message) => {
            match _package_problem_report(state, session, msg_id, *problem_report).await {
                Ok(msg) => {
                    warn!(log_message);
                    if let Err(e) = socket.send(Message::Text(msg.into())).await {
                        warn!("Failed to send problem report to WebSocket client: {e}");
                    }
                }
                Err(e) => warn!("Error packaging problem report: {:?}", e),
            }
        }
        // A generic error carries no problem report to send.
        other => warn!("Error processing message: {:?}", other),
    }
    #[cfg(not(feature = "didcomm"))]
    {
        let _ = (state, session, socket);
        warn!("Error processing message: {:?}", error);
    }
}

/// The problem report for a socket the streaming task is closing.
///
/// One report per [`CloseReason`], because the three are not the same event and
/// a client can only act on the difference. Until affinidi-tdk-rs#1028 every one of them sent
/// `duplicate-channel` / "a new duplicate connection has caused this websocket
/// to terminate" — true of [`CloseReason::Replaced`], and the exact inverse of
/// what happened on the other two.
///
/// `duplicate-channel` is preserved verbatim for `Replaced`: it is the code
/// existing clients already match on, and the socket it goes to is the one whose
/// meaning never changed.
#[cfg(feature = "didcomm")]
pub(super) fn _close_problem_report(why: CloseReason) -> ProblemReport {
    let (code, message) = match why {
        CloseReason::Replaced => (
            "duplicate-channel",
            "A new duplicate websocket connection for this DID has caused this websocket to \
             terminate"
                .to_string(),
        ),
        CloseReason::Refused => (
            "duplicate-channel-refused",
            "This DID already has a live websocket connection, which has been kept. This \
             connection was refused and nothing was displaced — something is running a second \
             live session for this DID."
                .to_string(),
        ),
        CloseReason::Unauthenticated => (
            "unauthenticated-session",
            "This session reached streaming registration without an authenticated DID, so it \
             cannot be routed to."
                .to_string(),
        ),
    };
    ProblemReport::new(
        ProblemReportSorter::Warning,
        ProblemReportScope::Other("websocket".to_string()),
        code.to_string(),
        message,
        vec![],
        None,
    )
}

/// Takes a problem report and packages it for sending to the recipient
#[cfg(feature = "didcomm")]
pub(super) async fn _package_problem_report(
    state: &SharedData,
    session: &Session,
    msg_id: Option<String>,
    problem_report: ProblemReport,
) -> Result<String, MediatorError> {
    let mut pr_msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
        json!(problem_report),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(state.clock.unix_secs());

    if let Some(msg_id) = msg_id {
        pr_msg = pr_msg.pthid(msg_id);
    }

    let (packed, _) = didcomm_compat::pack_encrypted(
        &pr_msg.finalize(),
        &session.did,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|err| {
        MediatorError::MessagePackError(
            error_codes::MESSAGE_PACK_ERROR,
            session.session_id.clone(),
            format!("Couldn't pack DIDComm message. Reason: {err}"),
        )
    })?;

    Ok(packed)
}

/// Build a packed message-pickup 3.0 `status` for this session's client.
///
/// Sent after a dropped live notification: `message_count` is read live from
/// the recipient's inbox, so the client is told what is actually waiting rather
/// than that *something* was missed. A client already understands this message
/// — it is the same one it gets for a `status-request` — so the resync needs no
/// new protocol on the client side.
///
/// It reports the inbox of `did`: the session's own DID, or a member of its
/// mux connection. Either way it is packed to the session's DID: on a mux
/// connection the principal is the party the control plane addresses
/// (design §7.5), and `recipient_did` says whose inbox it is.
#[cfg(feature = "didcomm")]
pub(super) async fn _package_status_for(
    state: &SharedData,
    session: &Session,
    did: &str,
    did_hash: &str,
) -> Result<String, MediatorError> {
    let status = state.database.inbox_status(did_hash).await?;

    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/messagepickup/3.0/status".to_string(),
        json!({
            "recipient_did": did,
            "message_count": status.message_count,
            "live_delivery": true,
        }),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(state.clock.unix_secs())
    .finalize();

    let (packed, _) = didcomm_compat::pack_encrypted(
        &msg,
        &session.did,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|err| {
        MediatorError::MessagePackError(
            error_codes::MESSAGE_PACK_ERROR,
            session.session_id.clone(),
            format!("Couldn't pack resync status. Reason: {err}"),
        )
    })?;

    Ok(packed)
}

#[cfg(all(test, feature = "didcomm"))]
mod close_report_tests {
    use super::_close_problem_report;
    use crate::tasks::websocket_streaming::CloseReason;

    /// `duplicate-channel` is a wire code clients match on; only the socket
    /// whose meaning did not change may keep it.
    ///
    /// Asserted in the qualified form `ProblemReport::new` actually emits
    /// (`<sorter>.<scope>.<code>`) rather than the bare code passed in — that
    /// string is what reaches a client, and it is the thing a client matches.
    #[test]
    fn only_replacement_keeps_the_duplicate_channel_code() {
        assert_eq!(
            _close_problem_report(CloseReason::Replaced).code,
            "w.websocket.duplicate-channel",
            "existing clients match this; the replaced socket is the one case \
             the old wording described correctly, so it must not move"
        );
        assert_eq!(
            _close_problem_report(CloseReason::Refused).code,
            "w.websocket.duplicate-channel-refused",
            "a refused connection reported as `duplicate-channel` is \
             indistinguishable from having been evicted — which is what sent a \
             real investigation to the network layer"
        );
        assert_eq!(
            _close_problem_report(CloseReason::Unauthenticated).code,
            "w.websocket.unauthenticated-session",
            "an unauthenticated session is not a duplicate at all"
        );
    }

    /// The close frame and the problem report must agree.
    ///
    /// They travel independently — the report is `didcomm`-gated and the frame
    /// is not — so a client may see either one. Two sources of truth that can
    /// disagree is how the original bug read as a network fault in the first
    /// place.
    #[test]
    fn the_report_and_the_frame_tell_the_same_story() {
        for why in [
            CloseReason::Replaced,
            CloseReason::Refused,
            CloseReason::Unauthenticated,
        ] {
            let report = _close_problem_report(why);
            let (_, frame) = super::_close_frame_reason(why);
            let describes_replacement = |s: &str| {
                s.contains("replaced") || s.contains("caused this websocket to terminate")
            };
            assert_eq!(
                describes_replacement(&report.comment),
                describes_replacement(frame),
                "report and close frame disagree for {why:?}: {:?} vs {frame:?}",
                report.comment
            );
        }
    }
}
