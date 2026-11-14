//! The local-delivery gate: one decision for every ingress path that stores a
//! message the mediator did not author in a local account's inbox.
//!
//! Three paths end in that store — DIDComm v2 direct delivery, TSP (opaque
//! pass-through and the relay arms), and the DIDComm v1 forward — and each used
//! to carry its own copy of these checks. The copies drifted (how the mediator
//! DID and the session DID were compared, who a stored message was attributed
//! to, which refusal a sender was given), and a fix to one copy had to be found
//! and applied to the others by hand. They now all call
//! [`authorize_local_delivery`].
//!
//! What the gate decides, in order:
//!
//! 1. **Direct delivery only** ([`Ingress::Direct`]): the operator's
//!    `local_direct_delivery_allowed` policy; then the sender's own
//!    `SEND_MESSAGES` (not the session's: the WebSocket upgrade gates only
//!    `LOCAL`), or, for a sender-less envelope, `local_direct_delivery_allow_anon`.
//! 2. **Every delivery**: the recipient — that it is an account here, that it
//!    holds `RECEIVE_MESSAGES`, and that its access list admits the sender —
//!    from one store lookup. Every recipient-side refusal is the same
//!    [`delivery_refused`], so a sender cannot tell a served DID from an
//!    unknown one. Sender checks run first for the same reason: their answer
//!    must not depend on which recipient was named.
//!
//! Binding a claimed sender to the session (`force_session_did_match`, with its
//! mux-member substitution) is not part of the gate: it decides *which session*
//! the message is sent under, so it runs before, at the call site, with
//! [`check_claimed_sender`].

use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
    error_codes,
    messages::delivery_refused,
};
use affinidi_messaging_mediator_common::{
    did_identity::{did_hash, same_account},
    errors::MediatorError,
};
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;

/// How a message reached the local-delivery store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ingress {
    /// A client handed the mediator a message for a local recipient (DIDComm
    /// direct delivery, TSP opaque pass-through). The direct-delivery policy and
    /// the sender's own permission to send apply.
    Direct,
    /// The last step of a relay the mediator has already accepted: a TSP routed
    /// or nested layer it unpacked, a TSP message to its own account, or a
    /// DIDComm v1 forward. Only the recipient's gates apply here; the relay's
    /// own admission (peer allowlist, `SEND_FORWARDED`, the v1 opt-in) ran
    /// where the layer was opened.
    #[cfg_attr(not(any(feature = "tsp", feature = "didcomm-v1")), allow(dead_code))]
    Relayed,
}

/// What the mediator knows about who sent a message it is about to store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sender<'a> {
    /// Proven cryptographically on this hop: a TSP layer `unpack` verified.
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    Verified(&'a str),
    /// Named in the clear and not verified here: a DIDComm JWE `skid`, a TSP
    /// cleartext envelope sender. On an authenticated session with
    /// `force_session_did_match` on, the caller has already bound it to the
    /// session.
    Claimed(&'a str),
    /// No sender at all: an anon-packed DIDComm envelope, an RFC 0019 v1
    /// forward.
    #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
    Anonymous,
}

impl<'a> Sender<'a> {
    fn did(self) -> Option<&'a str> {
        match self {
            Sender::Verified(did) | Sender::Claimed(did) => Some(did),
            Sender::Anonymous => None,
        }
    }
}

/// An admitted local delivery.
#[derive(Debug)]
pub(crate) struct LocalDelivery {
    /// Who the stored message is attributed to — its queue gates, its stats,
    /// the sender recorded on it. See [`attribute`].
    pub(crate) from_did_hash: String,
}

/// Decide whether `session` may store a message from `sender` in `to_did`'s
/// inbox, arriving as `ingress`. `Ok` carries what the store needs.
pub(crate) async fn authorize_local_delivery(
    state: &SharedData,
    session: &Session,
    sender: Sender<'_>,
    to_did: &str,
    ingress: Ingress,
) -> Result<LocalDelivery, MediatorError> {
    let from_hash = sender.did().map(did_hash);

    if ingress == Ingress::Direct {
        if !state.config.security.local_direct_delivery_allowed {
            return Err(MediatorError::problem(
                error_codes::DIRECT_DELIVERY_DISABLED,
                &session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Message,
                "direct_delivery.denied",
                "Mediator is not accepting direct delivery. Messages must be relayed through a \
                 routing envelope",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }
        match from_hash.as_deref() {
            Some(from_hash) => {
                let from_acls = authz::effective_acls(state, from_hash).await?;
                if authz::require_capability(&from_acls, Capability::SendMessages).is_err() {
                    return Err(MediatorError::problem(
                        error_codes::AUTH_SEND_DENIED,
                        &session.session_id,
                        None,
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.send",
                        "Sender DID is not authorized to send messages through this mediator",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }
            }
            None if !state.config.security.local_direct_delivery_allow_anon => {
                return Err(MediatorError::problem(
                    error_codes::ANON_MESSAGE_ERROR,
                    &session.session_id,
                    None,
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.anonymous",
                    "Anonymous direct delivery is not allowed by this mediator",
                    vec![],
                    StatusCode::FORBIDDEN,
                ));
            }
            None => {}
        }
    }

    // Existence, the ACL bits and the access-list verdict come from one
    // lookup of the recipient's record.
    let to_did_hash = did_hash(to_did);
    let Some(recipient) = state
        .database
        .delivery_decision(&to_did_hash, from_hash.as_deref())
        .await?
    else {
        return Err(delivery_refused(
            session,
            None,
            "recipient is not local to this mediator",
        ));
    };
    // The coarser of the two recipient gates first.
    if authz::require_capability(&recipient.acls, Capability::ReceiveMessages).is_err() {
        return Err(delivery_refused(
            session,
            None,
            "recipient is not authorized to receive messages through this mediator",
        ));
    }
    if !recipient.access_list_allows {
        return Err(delivery_refused(
            session,
            None,
            "delivery blocked by the recipient's access list",
        ));
    }

    Ok(LocalDelivery {
        from_did_hash: attribute(session, sender),
    })
}

/// Who a stored message is attributed to: the strongest identity the mediator
/// can vouch for.
///
/// 1. A sender verified on this hop.
/// 2. Otherwise the authenticated session: whoever authenticated is who
///    handed the message over, and with `force_session_did_match` on (and any
///    mux member substituted) a claimed sender already equals it. Charging a
///    message to a claim the mediator did not check would let one client spend
///    another sender's queue allowance.
/// 3. Otherwise — an anonymous relay hop, which has no DID — the claimed
///    sender, the same identity the recipient's access list was evaluated
///    against.
/// 4. Otherwise the session's own hash.
fn attribute(session: &Session, sender: Sender<'_>) -> String {
    match sender {
        Sender::Verified(did) => did_hash(did),
        _ if session.authenticated => session.did_hash.clone(),
        Sender::Claimed(did) => did_hash(did),
        Sender::Anonymous => session.did_hash.clone(),
    }
}

/// Whether `did` names this mediator: the same account, so any did:scid `src`
/// locator does not matter.
pub(crate) fn is_mediator_did(state: &SharedData, did: &str) -> bool {
    same_account(did, &state.config.mediator_did)
}

/// Refuse a message whose claimed sender is not the session's DID.
///
/// `claimed` is the sender DID without a key fragment (`None` when the message
/// names none, or names it in a shape that carries no DID); `shown` is what the
/// refusal reports. Compared as accounts ([`same_account`]), the same way
/// requests the mediator serves are matched to their session.
///
/// Only the caller can decide whether the session is one that can be matched
/// against: an anonymous inter-mediator relay hop has no session DID, and is
/// exempted at the call site rather than here.
pub(crate) fn check_claimed_sender(
    session: &Session,
    claimed: Option<&str>,
    shown: &str,
    msg_id: Option<&str>,
) -> Result<(), MediatorError> {
    if claimed.is_some_and(|did| same_account(did, &session.did)) {
        return Ok(());
    }
    Err(MediatorError::problem_with_log(
        error_codes::SESSION_DID_MISMATCH,
        &session.session_id,
        msg_id.map(str::to_string),
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![shown.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Sender DID ({shown}) doesn't match session DID"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(did: &str, authenticated: bool) -> Session {
        Session {
            did: did.to_string(),
            did_hash: did_hash(did),
            session_id: "test-session".to_string(),
            authenticated,
            ..Default::default()
        }
    }

    #[test]
    fn a_verified_sender_is_attributed_as_itself() {
        let s = session("did:example:relay", true);
        assert_eq!(
            attribute(&s, Sender::Verified("did:example:alice")),
            did_hash("did:example:alice")
        );
    }

    #[test]
    fn an_authenticated_session_is_charged_rather_than_a_claim() {
        let s = session("did:example:alice", true);
        assert_eq!(
            attribute(&s, Sender::Claimed("did:example:victim")),
            s.did_hash
        );
        assert_eq!(attribute(&s, Sender::Anonymous), s.did_hash);
    }

    #[test]
    fn an_anonymous_relay_hop_is_attributed_to_the_claim() {
        let s = session("", false);
        assert_eq!(
            attribute(&s, Sender::Claimed("did:example:alice")),
            did_hash("did:example:alice")
        );
        assert_eq!(attribute(&s, Sender::Anonymous), s.did_hash);
    }

    #[test]
    fn a_claim_matches_its_session_as_an_account() {
        let s = session("did:scid:vh:1:QmScid?src=example.com/alice", true);
        assert!(check_claimed_sender(&s, Some("did:scid:vh:1:QmScid"), "x", None).is_ok());
        assert!(check_claimed_sender(&s, Some("did:example:mallory"), "x", None).is_err());
        assert!(check_claimed_sender(&s, None, "anonymous", None).is_err());
    }
}
