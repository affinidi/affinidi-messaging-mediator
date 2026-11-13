use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, span};
use uuid::Uuid;

use crate::{
    common::session::Session,
    messages::{ProcessMessageResponse, WrapperType},
};

/// The Trust Ping 2.0 response type.
pub(crate) const PING_RESPONSE_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

// Reads the body of an incoming trust-ping and whether to generate a return ping message
#[derive(Deserialize)]
struct Ping {
    response_requested: bool, // Defaults to true
}

impl Default for Ping {
    fn default() -> Self {
        Self {
            response_requested: true,
        }
    }
}

/// Process a trust-ping message and generates a response if needed
pub(crate) fn process(
    msg: &Message,
    session: &Session,
    mediator_did: &str,
    now: u64,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "trust_ping",
        session_id = session.session_id.as_str()
    )
    .entered();

    if let Some(expires) = msg.expires_time
        && expires <= now
    {
        return Err(MediatorError::problem_with_log(
            31,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.expired",
            "Message has expired: {1}",
            vec![expires.to_string()],
            StatusCode::BAD_REQUEST,
            "Message has expired",
        ));
    }

    let to = super::addressed_to_mediator(msg, mediator_did, session, "Trust Ping")?;
    debug!("To: {}", to);

    let respond: bool = if let Ok(body) = serde_json::from_value::<Ping>(msg.body.to_owned()) {
        body.response_requested
    } else {
        true
    };
    debug!("Response requested: {}", respond);

    info!(
        "ping received from: ({}) Respond?({})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        respond
    );

    if respond {
        let from = if let Some(from) = &msg.from {
            from.to_owned()
        } else {
            return Err(MediatorError::problem(
                50,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.anonymous",
                "Trust-Ping requires a from: header when response_requested is true",
                vec![],
                StatusCode::BAD_REQUEST,
            ));
        };

        // Build the response (we swap from and to). Trust Ping 2.0 answers
        // with `ping-response`: a peer that saw another `ping` would answer it.
        let response_msg = Message::build(
            Uuid::new_v4().to_string(),
            PING_RESPONSE_TYPE.to_owned(),
            json!({}),
        )
        .thid(msg.id.clone())
        .to(from)
        .from(to)
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("response_msg: {:?}", response_msg);

        Ok(ProcessMessageResponse {
            handed_over: None,
            store_message: true,
            force_live_delivery: false,
            data: WrapperType::Message(Box::new(response_msg)),
            forward_message: false,
        })
    } else {
        debug!("No response requested");
        Ok(ProcessMessageResponse::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{PING_RESPONSE_TYPE, process};
    use crate::{common::session::Session, messages::WrapperType};
    use affinidi_messaging_didcomm::message::Message;

    const MEDIATOR: &str = "did:example:mediator";

    fn ping(to: &str) -> Message {
        Message::build(
            "ping-1".to_string(),
            "https://didcomm.org/trust-ping/2.0/ping".to_string(),
            serde_json::json!({ "response_requested": true }),
        )
        .to(to.to_string())
        .from("did:example:alice".to_string())
        .finalize()
    }

    fn session() -> Session {
        Session {
            session_id: "s".into(),
            ..Default::default()
        }
    }

    /// The answer is a `ping-response` from the mediator, threaded to the
    /// ping: another `ping` would be answered by a conformant peer.
    #[test]
    fn a_ping_is_answered_with_a_ping_response() {
        let response = process(&ping(MEDIATOR), &session(), MEDIATOR, 1_000).unwrap();
        let WrapperType::Message(reply) = response.data else {
            panic!("a ping with response_requested is answered");
        };
        assert_eq!(reply.typ, PING_RESPONSE_TYPE);
        assert_eq!(reply.thid.as_deref(), Some("ping-1"));
        assert_eq!(reply.from.as_deref(), Some(MEDIATOR));
        assert_eq!(reply.to, Some(vec!["did:example:alice".to_string()]));
    }

    /// A ping addressed to anyone else is refused, never answered "from"
    /// the DID it named.
    #[test]
    fn a_ping_not_addressed_to_the_mediator_is_refused() {
        let err = process(&ping("did:example:bob"), &session(), MEDIATOR, 1_000)
            .expect_err("a ping to another DID is not answered");
        assert!(format!("{err:?}").contains("message.to"), "{err:?}");
    }
}
