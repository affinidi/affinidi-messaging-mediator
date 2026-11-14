//! DIDComm v2 ingress: messages addressed to the mediator (unpacked and
//! processed), direct delivery of an opaque envelope to a local recipient, and
//! the peel of peer-mediator re-wrap layers.

use crate::didcomm_compat::MetaEnvelope;
use crate::error_codes;
use crate::messages::MessageHandler;
use crate::messages::protocols::relay_peer_trusted;
use crate::messages::protocols::routing::rewrap_inner_attachment;
use crate::messages::store::store_message;
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::tasks::forwarding::RelayMode;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use http::StatusCode;
use tracing::{Instrument, debug, span};

use crate::messages::{ProcessMessageResponse, WrapperType};

use super::check_direct_delivery_session_match;

#[cfg(feature = "didcomm")]
pub(super) async fn handle_inbound_didcomm(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_inbound",
        session = &session.session_id
    );

    async move {
        // Re-wrap relay (RelayMode::Rewrap): a peer mediator may have wrapped the
        // message in one or more `forward`-to-us layers (see `rewrap_for_relay`).
        // Authenticate the relaying peer and strip those layers before the normal
        // path runs on the innermost envelope. In the default `Blind` mode this is
        // skipped entirely, so existing behaviour is unchanged.
        let peeled;
        // The innermost envelope as the peel already unpacked it, so the path
        // below does not decrypt the same message a second time (#198).
        let mut pre_unpacked = None;
        let (message, hop_floor): (&str, u32) =
            if state.config.processors.forwarding.relay_mode == RelayMode::Rewrap {
                let floor;
                (peeled, floor, pre_unpacked) =
                    peel_relay_rewrap_layers(state, session, message.to_string()).await?;
                (&peeled, floor)
            } else {
                (message, 0)
            };
        // A forward relayed onwards carries the peer's hop count, never one
        // its sender chose.
        crate::messages::protocols::routing::with_relay_hop_floor(hop_floor, async move {

        let envelope = match MetaEnvelope::new(message, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    error_codes::MESSAGE_ENVELOPE_READ,
                    &session.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.envelope.read",
                    "Couldn't read DIDComm envelope: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't read DIDComm envelope: {e}"),
                ));
            }
        };

        match &envelope.to_did {
            Some(to_did) => {
                if to_did == &state.config.mediator_did {
                    // Message is to the mediator
                    let unpacked = match pre_unpacked.take() {
                        Some(unpacked) => Ok(unpacked),
                        None => {
                            envelope
                                .unpack(
                                    &state.did_resolver,
                                    &*state.config.security.mediator_secrets,
                                )
                                .await
                        }
                    };
                    let (msg, metadata) = match unpacked {
                        Ok(ok) => ok,
                        Err(e) => {
                            return Err(MediatorError::problem_with_log(
                                error_codes::MESSAGE_UNPACK_FAILED,
                                &session.session_id,
                                None,
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "message.unpack",
                                "Message unpack failed: envelope sha256 {1} Reason: {2}",
                                vec![sha256::digest(message), e.to_string()],
                                StatusCode::FORBIDDEN,
                                format!("Message unpack failed. Reason: {e}"),
                            ));
                        }
                    };

                    debug!(
                        id = msg.id,
                        typ = msg.typ,
                        from = msg.from.as_deref().unwrap_or("anon"),
                        "Message unpacked"
                    );

                    // Block truly anonymous messages (no sender authentication).
                    // A message is considered authenticated if EITHER:
                    // - authcrypt (ECDH-1PU) was used (metadata.authenticated == true), OR
                    // - a JWS signature is present (metadata.sign_from.is_some())
                    if !metadata.authenticated
                        && metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        return Err(MediatorError::problem(
                            error_codes::ANON_MESSAGE_ERROR,
                            &session.session_id,
                            Some(msg.id.clone()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "message.anonymous",
                            "Mediator is not allowing anonymous messages (no authcrypt or JWS signature)",
                            vec![],
                            StatusCode::BAD_REQUEST,
                        ));
                    }

                    // `from` must name the DID that authenticated the message;
                    // the routing and ACL checks below rely on it.
                    let sender_did = match crate::messages::authenticated_sender(&msg, &metadata) {
                        Ok(sender_did) => sender_did,
                        Err(reason) => return Err(sender_mismatch(session, &msg.id, &reason)),
                    };

                    // Does the sender identity match the session DID?
                    // The sender can be identified by JWS signing (sign_from) or
                    // authcrypt encryption (encrypted_from_kid).
                    // Skip for unauthenticated sessions (e.g. inter-mediator relay):
                    // there is no session DID to match against.
                    //
                    // On a mux connection a sender other than the principal is
                    // accepted only as a member carrying `send` there, and only
                    // for a `forward`: `send` lets the member *send* through this
                    // socket, not drive the mediator (pickup, Trust Tasks, admin)
                    // on it. The sender here is the key that authenticated the
                    // envelope, so the principal cannot send as a member.
                    let member;
                    let session = if state.config.security.force_session_did_match && session.authenticated {
                        let sender_kid =
                            metadata.sign_from.as_ref().or(metadata.encrypted_from_kid.as_ref());
                        match check_session_sender_match(session, &msg.id, &sender_kid) {
                            Ok(()) => session,
                            Err(refused) => {
                                let sender_did = sender_kid.and_then(|kid| kid.split_once('#')).map(|(did, _)| did);
                                member = match sender_did {
                                    Some(did) if is_forward(&msg) => {
                                        crate::mux::connection::sender_session(state, session, did).await
                                    }
                                    _ => None,
                                };
                                match &member {
                                    Some(member) => member,
                                    None => return Err(refused),
                                }
                            }
                        }
                    } else {
                        session
                    };

                    // Anything other than a forward is a request the mediator
                    // serves for an account (pickup, ping, discovery, Trust
                    // Tasks), so it needs an authenticated session whose DID
                    // sent it. Forwards are relayed and keep the rules above,
                    // which is what lets the anonymous relay session work.
                    if !is_forward(&msg) {
                        authz::require_session_sender(session, sender_did.as_deref(), Some(&msg.id))?;
                    }

                    // Process the message
                    let response = msg.process(state, session, &metadata).await?;
                    debug!("Message processed successfully");
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::problem(
                            error_codes::DIRECT_DELIVERY_DISABLED,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "direct_delivery.denied",
                            "Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    let from_hash = envelope
                        .from_did
                        .as_ref()
                        .map(affinidi_messaging_mediator_common::did_identity::did_hash);

                    // Order matters on this branch. Every check about the
                    // *sender* — session binding, its SEND_MESSAGES bit, the
                    // anonymous-sender policy — runs before anything about the
                    // recipient is read, so its answer is the same whichever
                    // DID the envelope is addressed to. Only then is the
                    // recipient looked up, and every recipient-side refusal
                    // (unknown, may not receive, access list) is the one
                    // uniform `delivery_refused`. Checking the recipient first
                    // would let a sender tell a served DID from an unknown one
                    // by which of the two kinds of answer came back. The TSP
                    // branch orders its checks the same way.

                    // The mediator cannot decrypt a direct-delivery envelope, so the
                    // claimed sender (JWE `skid` header) is unverified. When
                    // session/sender matching is enforced, bind it to the
                    // authenticated session DID before it is trusted for ACL checks.
                    //
                    // Skipped for unauthenticated sessions, exactly as the forward
                    // branch above skips it: an inter-mediator relay hop arrives on
                    // the anonymous `ANON-INBOUND` session, whose DID is empty, so the
                    // comparison could only ever fail. It reaches *this* branch rather
                    // than the forward branch because [`RelayMode::Blind`] — the
                    // default — relays the peer's inner envelope verbatim, and that
                    // envelope is addressed to the local recipient, not to this
                    // mediator. Without the guard, blind relay cannot deliver at all.
                    //
                    // The cost is real and worth naming: on a blind relay hop the
                    // claimed sender stays unverified, and it is that claimed sender
                    // which `delivery_decision` below receives as `from_hash` for the
                    // recipient's access-list verdict. A relaying peer can therefore
                    // present any sender DID it likes. This is inherent to blind
                    // relay — by construction the receiving mediator cannot see who
                    // relayed — not something this guard gives away: the alternative
                    // is refusing the hop, which is the bug being fixed.
                    // [`RelayMode::Rewrap`] plus `relay_trusted_mediators` is the
                    // posture for deployments that need the peer authenticated.
                    //
                    // On a mux connection the claim may instead name a member
                    // carrying `send` there: by granting `send` the member
                    // vouched for frames this socket presents in its name. The
                    // frame is then the member's from here on — its queue limits,
                    // its stats — as on its own connection.
                    let member;
                    let session = if state.config.security.force_session_did_match && session.authenticated {
                        match check_direct_delivery_session_match(session, envelope.from_did.as_deref()) {
                            Ok(()) => session,
                            Err(refused) => {
                                member = match envelope.from_did.as_deref() {
                                    Some(did) => crate::mux::connection::sender_session(state, session, did).await,
                                    None => None,
                                };
                                match &member {
                                    Some(member) => member,
                                    None => return Err(refused),
                                }
                            }
                        }
                    } else {
                        session
                    };

                    // Check if the message will pass ACL Checks
                    if let Some(from_hash) = from_hash.as_deref() {
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
                    } else if !state.config.security.local_direct_delivery_allow_anon {
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
                    // Everything the recipient side needs — existence, ACL bits
                    // and the access-list verdict — comes from one lookup. The
                    // three facts all derive from the same stored record, so
                    // asking for them separately cost three reads of it.
                    let to_hash = affinidi_messaging_mediator_common::did_identity::did_hash(to_did);
                    let Some(recipient) = state
                        .database
                        .delivery_decision(&to_hash, from_hash.as_deref())
                        .await?
                    else {
                        return Err(crate::messages::delivery_refused(
                            session,
                            None,
                            "direct-delivery recipient is not known on this mediator",
                        ));
                    };

                    // Recipient-side gates, both answered from the single
                    // lookup above. RECEIVE_MESSAGES mirrors the sender's
                    // SEND_MESSAGES check: a DID whose ACLs withhold it does
                    // not accept directly-delivered messages at all, whoever
                    // the sender is. Checked before the access list because it
                    // is the coarser of the two.
                    if authz::require_capability(&recipient.acls, Capability::ReceiveMessages)
                        .is_err()
                    {
                        return Err(crate::messages::delivery_refused(
                            session,
                            None,
                            "recipient is not authorized to receive messages through this mediator",
                        ));
                    }

                    if !recipient.access_list_allows {
                        return Err(crate::messages::delivery_refused(
                            session,
                            None,
                            "delivery blocked by the recipient's access list",
                        ));
                    }

                    let data = ProcessMessageResponse {
                        handed_over: None,
                        store_message: true,
                        force_live_delivery: false,
                        forward_message: false,
                        data: WrapperType::Envelope(
                            to_did.into(),
                            message.into(),
                            state.clock.unix_secs()
                                + state.limits().message_expiry_seconds,
                        ),
                    };

                    debug!("Direct delivery message from({:?}) to({}) msg_hash({})", envelope.from_did, to_did, envelope.sha256_hash);

                    store_message(state, session, &data, &UnpackMetadata::default()).await
                }
            }
            _ =>   Err(MediatorError::problem_with_log(
                error_codes::INVALID_TO_HEADER,
                &session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.to",
                "There is no to_did on the envelope! Can't deliver an unknown message. Envelope sha256: {1}",
                vec![sha256::digest(message)],
                StatusCode::UNPROCESSABLE_ENTITY,
                "There is no to_did on the envelope! Can't deliver an unknown message.",
            ))
        }
        })
        .await
    }
    .instrument(_span)
    .await
}

/// Strip peer-mediator re-wrap layers from an inbound message (RelayMode::Rewrap).
///
/// A re-wrap layer is a `forward` addressed to this mediator whose `next` hop is
/// *also* this mediator — the envelope a peer produces in [`rewrap_for_relay`].
/// For each such layer this authenticates the relaying peer (the authcrypt
/// `from`) against the trusted-peer allowlist, then replaces the message with
/// the inner attachment and repeats, returning the innermost envelope once it is
/// no longer a re-wrap layer. Bounded by `max_hops` to stop relay loops.
///
/// Any decrypt/unpack failure here is *not* fatal: the message is handed back
/// unchanged so the normal inbound path produces the canonical error.
///
/// The third value is the returned envelope already unpacked, when it was
/// addressed to this mediator and unpacked cleanly but is not a re-wrap layer:
/// the caller uses it rather than decrypting the same envelope again.
#[cfg(feature = "didcomm")]
async fn peel_relay_rewrap_layers(
    state: &SharedData,
    session: &Session,
    message: String,
) -> Result<(String, u32, Option<PeeledUnpack>), MediatorError> {
    let mut current = message;
    let mut depth: u32 = 0;
    // The hop count the authenticated peers carried, at least one per layer
    // peeled: the floor for any onward relay.
    let mut floor: u32 = 0;
    loop {
        let envelope = match MetaEnvelope::new(&current, &state.did_resolver).await {
            Ok(e) => e,
            Err(_) => return Ok((current, floor, None)),
        };
        if envelope.to_did.as_deref() != Some(state.config.mediator_did.as_str()) {
            return Ok((current, floor, None));
        }
        let (msg, meta) = match envelope
            .unpack(
                &state.did_resolver,
                &*state.config.security.mediator_secrets,
            )
            .await
        {
            Ok(ok) => ok,
            Err(_) => return Ok((current, floor, None)),
        };
        let Some(inner) = rewrap_inner_attachment(&state.config.mediator_did, &msg) else {
            return Ok((current, floor, Some((msg, meta))));
        };

        // Authenticate the relaying peer mediator before peeling its layer:
        // the DID that signed or authcrypted the layer, never a bare `from`.
        let peer = crate::messages::authenticated_sender(&msg, &meta)
            .map_err(|reason| sender_mismatch(session, &msg.id, &reason))?;
        if !relay_peer_trusted(
            &state.config.processors.forwarding.relay_trusted_mediators,
            peer.as_deref(),
        ) {
            return Err(MediatorError::problem(
                error_codes::RELAY_UNTRUSTED_PEER,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.relay.untrusted_peer",
                "Relaying mediator is not in the trusted relay allowlist",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }

        depth += 1;
        floor = floor
            .max(crate::messages::protocols::routing::layer_hop_count(&msg))
            .max(depth);
        if depth > state.config.processors.forwarding.max_hops {
            return Err(MediatorError::problem(
                error_codes::FORWARD_LOOP_DETECTED,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "protocol.forwarding.loop_detected",
                "Re-wrap relay exceeded maximum hop count, possible loop",
                vec![],
                StatusCode::LOOP_DETECTED,
            ));
        }

        debug!(
            peer = msg.from.as_deref().unwrap_or("anon"),
            depth, "Peeled inter-mediator relay re-wrap layer"
        );
        current = inner;
    }
}

/// An envelope [`peel_relay_rewrap_layers`] unpacked and handed back.
#[cfg(feature = "didcomm")]
type PeeledUnpack = (
    affinidi_messaging_didcomm::message::Message,
    affinidi_messaging_sdk::messages::compat::UnpackMetadata,
);

/// Whether `msg` is a `routing/2.0/forward`: the one message to the mediator a
/// mux member's `send` scope admits on the principal's connection.
#[cfg(feature = "didcomm")]
fn is_forward(msg: &affinidi_messaging_didcomm::message::Message) -> bool {
    matches!(
        msg.typ
            .parse::<affinidi_messaging_sdk::messages::known::MessageType>(),
        Ok(affinidi_messaging_sdk::messages::known::MessageType::ForwardRequest)
    )
}

/// Refusal for a message whose `from` is not the DID that authenticated it.
#[cfg(feature = "didcomm")]
fn sender_mismatch(session: &Session, msg_id: &str, reason: &str) -> MediatorError {
    MediatorError::problem_with_log(
        error_codes::SENDER_MISMATCH,
        &session.session_id,
        Some(msg_id.to_string()),
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.sender.mismatch",
        "Message sender is not the authenticated sender: {1}",
        vec![reason.to_string()],
        StatusCode::FORBIDDEN,
        format!("Message sender is not the authenticated sender: {reason}"),
    )
}

/// Ensure the Session DID and the message sender DID match.
/// The sender can be identified by either a JWS signature (`sign_from`)
/// or authcrypt encryption (`encrypted_from_kid`). Both are key IDs
/// in the form `did:...#key-N` — the DID is extracted from the fragment.
#[cfg(feature = "didcomm")]
fn check_session_sender_match(
    session: &Session,
    msg_id: &str,
    sender_kid: &Option<&String>,
) -> Result<(), MediatorError> {
    if let Some(kid) = sender_kid
        && let Some((did, _fragment)) = kid.split_once('#')
        && affinidi_messaging_mediator_common::did_identity::same_account(did, &session.did)
    {
        return Ok(());
    }

    let sender_display = sender_kid.map(|s| s.as_str()).unwrap_or("anonymous");

    Err(MediatorError::problem_with_log(
        error_codes::SESSION_DID_MISMATCH,
        &session.session_id,
        Some(msg_id.to_string()),
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![sender_display.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Sender DID ({sender_display}) doesn't match session DID"),
    ))
}

#[cfg(test)]
#[cfg(feature = "didcomm")]
mod tests {
    use super::*;

    // --- check_session_sender_match tests ---
    // The function accepts a sender_kid (key ID like "did:...#key-N") and
    // checks that the DID portion matches the session DID.

    fn make_session(did: &str) -> Session {
        Session {
            did: did.to_string(),
            session_id: "test-session".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn sender_match_jws_signature_matching() {
        let session = make_session("did:example:alice");
        let kid = "did:example:alice#key-0".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_ok());
    }

    #[test]
    fn sender_match_authcrypt_kid_matching() {
        // Authcrypt encrypted_from_kid uses the same did#key format
        let session = make_session("did:webvh:Qmc572jbs:webvh.example.com:vta");
        let kid = "did:webvh:Qmc572jbs:webvh.example.com:vta#key-1".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_ok());
    }

    #[test]
    fn sender_match_wrong_did_rejected() {
        let session = make_session("did:example:alice");
        let kid = "did:example:mallory#key-0".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_err());
    }

    #[test]
    fn sender_match_none_anonymous_rejected() {
        let session = make_session("did:example:alice");
        assert!(check_session_sender_match(&session, "msg-1", &None).is_err());
    }

    #[test]
    fn sender_match_kid_without_fragment_rejected() {
        // A bare DID without #key fragment should not match
        let session = make_session("did:example:alice");
        let kid = "did:example:alice".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_err());
    }

    #[test]
    fn sender_match_different_key_same_did_ok() {
        // Different key fragments from the same DID should all be accepted
        let session = make_session("did:example:alice");
        let key0 = "did:example:alice#key-0".to_string();
        let key1 = "did:example:alice#key-1".to_string();
        let signing = "did:example:alice#signing-key".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&key0)).is_ok());
        assert!(check_session_sender_match(&session, "msg-1", &Some(&key1)).is_ok());
        assert!(check_session_sender_match(&session, "msg-1", &Some(&signing)).is_ok());
    }

    /// The `send` scope admits a member's `forward` and nothing else
    /// addressed to the mediator.
    #[test]
    fn only_a_forward_is_a_member_send() {
        let msg = |typ: &str| {
            affinidi_messaging_didcomm::message::Message::build(
                "id".to_string(),
                typ.to_string(),
                serde_json::json!({}),
            )
            .finalize()
        };
        assert!(is_forward(&msg("https://didcomm.org/routing/2.0/forward")));
        for typ in [
            "https://didcomm.org/trust-ping/2.0/ping",
            "https://didcomm.org/messagepickup/3.0/status-request",
            "https://didcomm.org/messagepickup/3.0/delivery-request",
            "https://didcomm.org/messagepickup/3.0/messages-received",
            "https://didcomm.org/basicmessage/2.0/message",
            "not a type",
        ] {
            assert!(!is_forward(&msg(typ)), "{typ}");
        }
    }

    // --- check_direct_delivery_session_match tests ---
    // The direct-delivery sibling of the above: it compares the whole claimed
    // sender DID (from the JWE `skid`) against the session DID, with no key
    // fragment involved.

    #[test]
    fn direct_delivery_sender_matching_session_ok() {
        let session = make_session("did:example:alice");
        assert!(check_direct_delivery_session_match(&session, Some("did:example:alice")).is_ok());
    }

    #[test]
    fn direct_delivery_wrong_sender_rejected() {
        let session = make_session("did:example:alice");
        assert!(
            check_direct_delivery_session_match(&session, Some("did:example:mallory")).is_err()
        );
    }

    #[test]
    fn direct_delivery_anonymous_sender_rejected() {
        let session = make_session("did:example:alice");
        assert!(check_direct_delivery_session_match(&session, None).is_err());
    }

    /// The bug this guard fixes: an inter-mediator relay hop arrives on the
    /// anonymous session, whose DID is empty, so *every* claimed sender
    /// mismatches. The call site must not run the check for such a session —
    /// this asserts the check really does fail there, which is why the
    /// `session.authenticated` guard is load-bearing rather than cosmetic.
    #[test]
    fn anonymous_relay_session_would_reject_every_sender() {
        let relay_session = Session {
            session_id: "ANON-INBOUND".to_string(),
            ..Default::default()
        };
        assert!(!relay_session.authenticated);
        assert!(
            check_direct_delivery_session_match(&relay_session, Some("did:example:alice")).is_err()
        );
        assert!(
            check_direct_delivery_session_match(&relay_session, Some("did:example:bob")).is_err()
        );
    }

    // --- anonymous message detection tests ---
    // These test the logic used in handle_inbound for the anonymous check:
    //   !metadata.authenticated && metadata.sign_from.is_none()

    /// Helper: build UnpackMetadata for the given scenario
    fn make_metadata(
        authenticated: bool,
        sign_from: Option<&str>,
        encrypted_from_kid: Option<&str>,
    ) -> UnpackMetadata {
        let mut metadata = UnpackMetadata::default();
        metadata.encrypted = true;
        metadata.authenticated = authenticated;
        metadata.anonymous_sender = !authenticated;
        metadata.sign_from = sign_from.map(String::from);
        metadata.encrypted_from_kid = encrypted_from_kid.map(String::from);
        metadata
    }

    /// Returns true if the metadata would be blocked by block_anonymous_outer_envelope
    fn is_anonymous(metadata: &UnpackMetadata) -> bool {
        !metadata.authenticated && metadata.sign_from.is_none()
    }

    /// Returns the sender_kid that would be used for session/admin checks
    fn sender_kid(metadata: &UnpackMetadata) -> Option<String> {
        metadata
            .sign_from
            .clone()
            .or(metadata.encrypted_from_kid.clone())
    }

    #[test]
    fn authcrypt_only_is_not_anonymous() {
        // ECDH-1PU (authcrypt): authenticated=true, no JWS signature
        // This is what the SDK's pack_encrypted(Some(from)) produces
        let meta = make_metadata(true, None, Some("did:example:alice#key-1"));
        assert!(!is_anonymous(&meta));
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-1".to_string())
        );
    }

    #[test]
    fn jws_signed_anoncrypt_is_not_anonymous() {
        // Anoncrypt JWE + JWS signature wrapper: authenticated=false, sign_from set
        let meta = make_metadata(false, Some("did:example:alice#key-0"), None);
        assert!(!is_anonymous(&meta));
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-0".to_string())
        );
    }

    #[test]
    fn authcrypt_plus_jws_is_not_anonymous() {
        // Both authcrypt AND JWS: the strongest authentication
        let meta = make_metadata(
            true,
            Some("did:example:alice#key-0"),
            Some("did:example:alice#key-1"),
        );
        assert!(!is_anonymous(&meta));
        // JWS sign_from takes priority over encrypted_from_kid
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-0".to_string())
        );
    }

    #[test]
    fn anoncrypt_only_is_anonymous() {
        // ECDH-ES (anoncrypt): no sender authentication at all
        let meta = make_metadata(false, None, None);
        assert!(is_anonymous(&meta));
        assert_eq!(sender_kid(&meta), None);
    }

    #[test]
    fn anoncrypt_with_encrypted_from_kid_none_is_anonymous() {
        // Anoncrypt doesn't set encrypted_from_kid either
        let meta = make_metadata(false, None, None);
        assert!(is_anonymous(&meta));
    }
}
