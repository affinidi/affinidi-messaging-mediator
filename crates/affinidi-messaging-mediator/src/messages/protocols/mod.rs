//! This module contains the protocol definitions for the mediator.
//! Each protocol is defined in a separate sub-module.
//!
//! Trust Tasks and the mediator administration they drive run over DIDComm and
//! over TSP, so they build with either. The rest are DIDComm protocols.

#[cfg(feature = "didcomm")]
pub mod discover_features;
pub(crate) mod mediator;
pub(crate) mod mediator_ops;
#[cfg(feature = "didcomm")]
pub mod message_pickup;
#[cfg(feature = "didcomm")]
pub mod ping;
#[cfg(feature = "didcomm")]
pub mod routing;
pub(crate) mod trust_task_error;
pub(crate) mod trust_task_sign;
pub(crate) mod trust_task_verify;
pub(crate) mod trust_task_versions;
pub mod trust_tasks;

/// The `to` of a request the mediator answers itself (trust-ping, Discover
/// Features, Message Pickup), checked to name the mediator. Returns that DID:
/// the reply is sent from it. `protocol` names the request in the refusal.
///
/// One check for every such request, so the reply's `from` can never be a DID
/// the request merely claimed: without it a request addressed elsewhere would
/// be answered "from" whatever it named.
#[cfg(feature = "didcomm")]
pub(crate) fn addressed_to_mediator(
    msg: &affinidi_messaging_didcomm::message::Message,
    mediator_did: &str,
    session: &crate::common::session::Session,
    protocol: &str,
) -> Result<String, affinidi_messaging_mediator_common::errors::MediatorError> {
    use affinidi_messaging_mediator_common::errors::MediatorError;
    use affinidi_messaging_sdk::messages::problem_report::{
        ProblemReportScope, ProblemReportSorter,
    };
    use http::StatusCode;

    let Some(to) = msg.to.as_ref() else {
        return Err(MediatorError::problem(
            crate::error_codes::INVALID_TO_HEADER,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.to",
            "Missing to: header in message",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };
    let Some(first) = to.first() else {
        return Err(MediatorError::problem(
            crate::error_codes::INVALID_TO_HEADER,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.to",
            "Invalid to: header, couldn't get first DID from the field.",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };
    if !affinidi_messaging_mediator_common::did_identity::same_account(first, mediator_did) {
        tracing::debug!("to: ({first}) doesn't match Mediator DID ({mediator_did})");
        return Err(MediatorError::problem_with_log(
            crate::error_codes::INVALID_TO_HEADER,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.to",
            "{1} messages must be addressed to the Mediator DID. Received to: {2}",
            vec![protocol.to_string(), first.to_string()],
            StatusCode::BAD_REQUEST,
            format!("{protocol} messages must be addressed to the Mediator DID"),
        ));
    }
    Ok(first.to_owned())
}

/// Whether `from` may relay through this mediator, given the configured relay
/// peer allowlist. Shared by the DIDComm re-wrap peel and the TSP routed relay.
///
/// An empty allowlist accepts any peer (the relay capability is still gated by
/// ACLs); a non-empty list admits only its members, and rejects an anonymous
/// (`None`) peer outright.
pub(crate) fn relay_peer_trusted(allow: &ahash::AHashSet<String>, from: Option<&str>) -> bool {
    allow.is_empty() || matches!(from, Some(did) if allow.contains(did))
}

#[cfg(test)]
mod tests {
    use super::relay_peer_trusted;

    fn allowlist(entries: &[&str]) -> ahash::AHashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn relay_peer_trusted_empty_allowlist_accepts_any() {
        let empty = ahash::AHashSet::new();
        assert!(relay_peer_trusted(&empty, Some("did:peer:anyone")));
        assert!(relay_peer_trusted(&empty, None));
    }

    #[test]
    fn relay_peer_trusted_nonempty_allowlist_is_membership_only() {
        let allow = allowlist(&["did:peer:alice_mediator", "did:peer:bob_mediator"]);
        assert!(relay_peer_trusted(&allow, Some("did:peer:alice_mediator")));
        assert!(!relay_peer_trusted(&allow, Some("did:peer:stranger")));
        // A non-empty allowlist rejects an anonymous relaying peer.
        assert!(!relay_peer_trusted(&allow, None));
    }
}
