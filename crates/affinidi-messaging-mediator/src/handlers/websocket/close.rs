//! Close codes and the close frame each way a socket ends is reported with.

use super::*;

/// RFC 6455 close codes the mediator uses, so clients learn *why* a socket was
/// closed instead of seeing a bare close.
pub(super) mod close_code {
    /// Normal closure (graceful end / client-initiated).
    pub const NORMAL: u16 = 1000;
    /// Endpoint going away — peer unresponsive or the stream ended.
    pub const GOING_AWAY: u16 = 1001;
    /// Policy violation — auth expired, per-DID cap, duplicate displacement.
    pub const POLICY: u16 = 1008;
    /// A message larger than the mediator accepts.
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    /// Unexpected server-side condition.
    pub const SERVER_ERROR: u16 = 1011;
    /// Transient capacity limit — try again later.
    pub const TRY_AGAIN_LATER: u16 = 1013;
}

/// The close for a socket whose next frame could not be read. A frame over
/// `limits.ws_size` is refused by the WebSocket layer itself, as a capacity
/// error: that is 1009, so the client knows the message, not the connection,
/// was the problem. Anything else is the stream failing (1001).
///
/// The error is matched by its text: the WebSocket library behind axum is not
/// a direct dependency, so its error type cannot be named here.
pub(super) fn read_error_close(error: &axum::Error) -> (u16, &'static str) {
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(e) = source {
        let text = e.to_string();
        if text.contains("Space limit exceeded") || text.contains("Message too long") {
            return (close_code::MESSAGE_TOO_BIG, "message too big");
        }
        source = e.source();
    }
    (close_code::GOING_AWAY, "connection error")
}

/// The close a raw-TSP socket sends when the mediator refuses a message on it.
///
/// The code is the client's cue: 1009 (too big) and 1008 (refused) mean
/// resending the same message will not help; 1013 means it may. Every
/// server-side failure is the same 1013, so the close tells a client whether to
/// retry and nothing about the state of the mediator behind it.
#[cfg(feature = "tsp")]
pub(super) fn tsp_refusal_close(error: &MediatorError) -> (u16, &'static str) {
    let status = match error {
        MediatorError::MediatorError(_, _, _, _, status, _) => *status,
        _ => 500,
    };
    match status {
        413 => (
            close_code::MESSAGE_TOO_BIG,
            "TSP message exceeds the mediator's message size limit",
        ),
        500..=599 => (
            close_code::TRY_AGAIN_LATER,
            "TSP message not accepted now; try again later",
        ),
        _ => (close_code::POLICY, "TSP message refused"),
    }
}

/// The websocket close frame for a [`CloseReason`].
///
/// A client that never unpacks the problem report — one on the TSP-only build,
/// where the report is `didcomm`-gated and never sent at all — still has this to
/// go on, so the two must not disagree.
pub(super) fn _close_frame_reason(why: CloseReason) -> (u16, &'static str) {
    match why {
        CloseReason::Replaced => (close_code::POLICY, "replaced by a newer connection"),
        CloseReason::Refused => (close_code::POLICY, "this DID already has a live connection"),
        CloseReason::Unauthenticated => (close_code::POLICY, "session has no authenticated DID"),
    }
}

#[cfg(test)]
mod close_reason_tests {
    use super::_close_frame_reason;
    use crate::tasks::websocket_streaming::CloseReason;

    /// A refused newcomer must not be told it was replaced.
    ///
    /// This is the whole defect. Before #1028 the refusal path reused the
    /// eviction path's close frame, so a client that had been kept *out* was
    /// told its connection had been taken *over* — and, having nothing truthful
    /// to render, showed a transport error. OpenVTC reported it as a network
    /// fault; it was two instances of the app.
    #[test]
    fn refusal_does_not_claim_the_socket_was_replaced() {
        let (_, refused) = _close_frame_reason(CloseReason::Refused);
        assert!(
            !refused.contains("replaced"),
            "the refused socket was not replaced — nothing of its own was \
             displaced — but it is told: {refused:?}"
        );
        assert!(
            refused.contains("already has a live connection"),
            "a refused client can only say \"you have this open twice\" if it is \
             told that; got: {refused:?}"
        );
    }

    /// Each reason is distinguishable, which is the property a client keys on.
    ///
    /// Asserted as a set rather than three equality checks: the failure being
    /// guarded against is two reasons collapsing onto one string, and equality
    /// checks pass happily while that happens elsewhere in the match.
    #[test]
    fn every_close_reason_is_distinct() {
        let all = [
            CloseReason::Replaced,
            CloseReason::Refused,
            CloseReason::Unauthenticated,
        ];
        let mut seen: Vec<&str> = all.iter().map(|r| _close_frame_reason(*r).1).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "two close reasons render the same text, so a client cannot tell them \
             apart: {seen:?}"
        );
    }

    /// The wording that existing clients already match on is unchanged.
    ///
    /// `Replaced` is the one situation the old shared message described
    /// correctly, so it keeps its exact text: this change is meant to give the
    /// other two a truthful signal, not to move the ground under anything
    /// already parsing this one.
    #[test]
    fn the_replaced_wording_is_preserved_verbatim() {
        assert_eq!(
            _close_frame_reason(CloseReason::Replaced).1,
            "replaced by a newer connection"
        );
    }
}

/// #139: a frame the socket could not read closes it with a code that says
/// why.
#[cfg(test)]
mod read_error_tests {
    use super::read_error_close;
    use tokio_tungstenite::tungstenite::error::{CapacityError, Error as WsError};

    #[test]
    fn an_oversized_frame_closes_with_1009() {
        let e = axum::Error::new(WsError::Capacity(CapacityError::MessageTooLong {
            size: 2,
            max_size: 1,
        }));
        assert_eq!(read_error_close(&e), (1009, "message too big"));
    }

    #[test]
    fn any_other_read_error_closes_as_going_away() {
        let e = axum::Error::new(WsError::ConnectionClosed);
        assert_eq!(read_error_close(&e).0, 1001);
    }
}
