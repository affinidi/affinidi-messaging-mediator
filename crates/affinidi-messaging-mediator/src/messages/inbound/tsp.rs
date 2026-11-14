//! TSP ingress: opaque pass-through to a local recipient, layers addressed to
//! the mediator (relay arms, Trust Tasks, the mediator's own mail), and the
//! opaque local store every TSP delivery ends in.

use crate::error_codes;
use crate::messages::protocols::relay_peer_trusted;
use crate::messages::protocols::{trust_task_error, trust_tasks};
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use affinidi_tsp::MetaEnvelope as TspMetaEnvelope;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;

use super::check_message_size;
use super::tsp_relay::{Destination, RoutePlan, forward_to_next, plan_route_step};
use crate::messages::delivery_gate::{
    Ingress, Sender, authorize_local_delivery, check_claimed_sender, is_mediator_did,
};

/// Handle an inbound TSP message, sniffed at ingress by its CESR magic byte.
///
/// Routes on the cleartext envelope's *receiver*:
///
/// * **Not this mediator** — opaque pass-through. The message is neither
///   decrypted nor verified (the recipient authenticates the sender end to end
///   on unpack); it passes the direct-delivery gate and is stored for the local
///   recipient as base64url(qb2), its CESR qb64 text form, which rides the
///   UTF-8 store/pickup pipeline and is recognised on pickup by its `-E…`
///   prefix.
/// * **This mediator** — the layer is unpacked, which verifies its sender, and
///   acted on by kind: a Routed or Nested message is relayed (to a local
///   recipient, or enqueued for a remote TSP endpoint; the inner may be a
///   bridged DIDComm message), a management Trust Task is answered, and
///   anything else is mail for the mediator's own account.
#[cfg(feature = "tsp")]
pub(crate) async fn handle_inbound_tsp(
    state: &SharedData,
    session: &Session,
    raw: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    use affinidi_tsp::MessageType as TspMessageType;

    check_message_size(state, session, raw.len())?;

    let meta = TspMetaEnvelope::parse(raw).map_err(|e| {
        MediatorError::problem(
            error_codes::MESSAGE_ENVELOPE_READ,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Message,
            "message.tsp.malformed",
            "Malformed TSP message envelope: {1}",
            vec![e.to_string()],
            StatusCode::BAD_REQUEST,
        )
    })?;

    use affinidi_tsp::message::routed::{next_hop, pack_routed};

    // Bind the cleartext envelope sender to the identity that authenticated,
    // exactly as the DIDComm paths do. A TSP envelope names its sender in the
    // clear and the mediator does not decrypt it here, so `meta.sender` is a
    // claim; it is also what feeds the recipient's access-list lookup in
    // the delivery gate, so on an authenticated session it has to be pinned to
    // the session DID or the access list is evaluated against an attacker-chosen
    // VID. This is the TSP twin of the DIDComm direct-delivery bypass fixed in
    // mediator 0.15.5.
    //
    // Checked on the OUTER envelope, before the receiver branch, so it covers
    // relay and nested submissions too: whatever a client hands its mediator, it
    // has to have authored the layer it handed over. Inner layers are exempt by
    // construction — they are sealed to someone else and the client did not
    // write their envelopes.
    //
    // Skipped for unauthenticated sessions, exactly as the DIDComm branches skip
    // it: an inter-mediator relay hop is POSTed to `/inbound` with no
    // Authorization header, lands on the anonymous `ANON-INBOUND` session whose
    // DID is empty, and could only ever fail the comparison. The residual cost is
    // the one named on the DIDComm side: on an anonymous relay hop the claimed
    // sender stays unverified. That is inherent to relaying, not given away here.
    //
    // Which anonymous hops this leaves unverified, precisely — the two TSP
    // branches differ and it matters:
    //
    //   * A hop addressed to *this mediator* (`receiver == mediator_did`, the
    //     routed/nested relay below) is not affected. It gets unpacked, which
    //     authenticates `meta.sender` cryptographically, and the peer allowlist
    //     is applied to it there. Session binding is redundant for that branch.
    //   * A hop that is opaque pass-through (`receiver != mediator_did`) has
    //     nothing addressed to us to open, so its sender stays a bare claim.
    //     This is the true analogue of DIDComm blind relay, and no allowlist can
    //     apply to a peer we cannot identify.
    //
    // For that second case the levers are `local_direct_delivery_allowed` and
    // `security.enable_inter_mediator_relay` — anonymous inbound is opt-in (that
    // flag, or the legacy implicit `SEND_FORWARDED` in `global_acl_default`),
    // which bounds the exposure to relay-enabled deployments.
    //
    // On a mux connection the sender may instead be a member carrying `send`
    // there (see `mux::connection::sender_session`); the frame is then the
    // member's from here on. As on the DIDComm side, `send` admits only what
    // *sends*: opaque delivery and the routed / nested relay arms, never a
    // Direct or Control message to the mediator itself. The frame runs as the
    // member only once it is admitted as one of those: until then, every step
    // (resolving and unpacking a layer addressed to the mediator) runs under
    // the principal's own session, and a Direct or Control frame is refused
    // with the original mismatch (`member_refusal`).
    let mut member: Option<Session> = None;
    let mut member_refusal = None;
    if state.config.security.force_session_did_match
        && session.authenticated
        && let Err(refused) = check_claimed_sender(session, Some(&meta.sender), &meta.sender, None)
    {
        member = crate::mux::connection::sender_session(state, session, &meta.sender).await;
        if member.is_none() {
            return Err(refused);
        }
        member_refusal = Some(refused);
    }

    // The message kind (Direct/Routed/Nested/Control) now lives in the ENCRYPTED
    // payload, not the cleartext envelope, so a keys-free relay can no longer
    // dispatch on it. Route on the cleartext *receiver* instead:
    //   * receiver != this mediator → opaque pass-through: store for the local
    //     recipient to pick up (Direct/Routed/Nested/Control are all just carried).
    //   * receiver == this mediator → we hold the key, so unpack to learn the kind
    //     and act as the relay hop (Routed) / metadata-privacy intermediary (Nested).
    if !is_mediator_did(state, &meta.receiver) {
        // Opaque delivery is a send: a member admitted above sends it as itself.
        let session = member.as_ref().unwrap_or(session);
        // Direct delivery, through the same gate as DIDComm direct delivery
        // (`docs/acls.md` §6, "Direct delivery (DIDComm and TSP)"): the
        // operator's direct-delivery policy, then the sender's own
        // SEND_MESSAGES, then the recipient.
        //
        // There is no anonymous TSP case for `local_direct_delivery_allow_anon`
        // to admit: a TSP envelope always names its sender in the clear.
        return deliver_opaque(
            state,
            session,
            &meta.receiver,
            Sender::Claimed(&meta.sender),
            raw,
            Ingress::Direct,
        )
        .await;
    }

    let identity = state.tsp_identity().await?;
    let sender = resolve_tsp_vid(state, &meta.sender, &session.session_id).await?;
    let unpacked =
        affinidi_tsp::message::direct::unpack(raw, &identity.decryption_key, &sender.signing_key)
            .map_err(|e| {
            tsp_problem(
                session,
                error_codes::MESSAGE_ENVELOPE_READ,
                "message.tsp.unpack",
                format!("couldn't unpack TSP layer addressed to mediator: {e}"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    if let Some(refused) = member_refusal
        && !matches!(
            unpacked.message_type,
            TspMessageType::Routed | TspMessageType::Nested
        )
    {
        return Err(refused);
    }
    // Admitted: a relay arm, sent by the member as itself from here on.
    let session = member.as_ref().unwrap_or(session);

    // Peer-mediator allowlist for the branches where we act as a *relay*.
    //
    // `meta.sender` is safe to authorise on here, and this is the one place in
    // the TSP path where that is true. The `unpack` above verified an Ed25519
    // signature over envelope‖ciphertext against the signing key resolved from
    // `meta.sender`'s DID document, and opened the payload with HPKE **Auth**,
    // which binds the sender's static key as well. Two independent proofs, so
    // reaching this line means the peer really is who the envelope says.
    //
    // That is what the DIDComm side gets only in [`RelayMode::Rewrap`], where a
    // layer addressed to this mediator can be authcrypt-opened. TSP routed relay
    // is Rewrap-like by construction — every hop is sealed to the next and
    // authenticated as the previous — so there is no mode to choose and no blind
    // variant to except. The allowlist is simply always applicable here.
    //
    // Scoped to *inter-mediator* relay, which needs two conditions, and getting
    // either wrong breaks something:
    //
    //   * A relay arm. `Direct` and `Control` addressed to this mediator are
    //     messages *to* us, not relays through us — Trust Tasks over TSP arrive
    //     that way — so a list of trusted peer mediators must not gate them.
    //   * An anonymous session. This is the part that differs from DIDComm and
    //     is easy to get wrong: on the DIDComm side only a peer mediator ever
    //     produces a re-wrap layer, so peeling one is inter-mediator by
    //     construction. A TSP *routed* message is not — an ordinary client sends
    //     one through its own mediator for metadata privacy (§5.5), and that
    //     client is not a peer mediator. Gating those on this list would refuse
    //     every routed client the moment an operator populated it.
    //
    // An inter-mediator hop is POSTed to `/inbound` with no Authorization header
    // (see the forwarding processor), so it lands on the anonymous session —
    // which is exactly the traffic this allowlist exists to admit or refuse. An
    // authenticated peer is a known account and is governed by its ACLs instead,
    // the same as an authenticated peer using DIDComm blind relay.
    //
    // The opaque pass-through branch above (`receiver != mediator`) is the real
    // analogue of blind relay: nothing there is addressed to us, so there is no
    // layer to open and no peer identity to check. No allowlist can apply to a
    // peer we cannot identify; `local_direct_delivery_allowed` and
    // `security.enable_inter_mediator_relay` are the levers for that case.
    if !session.authenticated
        && matches!(
            unpacked.message_type,
            TspMessageType::Routed | TspMessageType::Nested
        )
        && !relay_peer_trusted(
            &state.config.processors.forwarding.relay_trusted_mediators,
            Some(meta.sender.as_str()),
        )
    {
        return Err(tsp_problem(
            session,
            error_codes::RELAY_UNTRUSTED_PEER,
            "authorization.relay.untrusted_peer",
            "Relaying peer is not in the trusted relay allowlist".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // SEND_FORWARDED gate for the relay arms — the TSP twin of the DIDComm
    // `routing/2.0/forward` capability check in `resolve_forward_sender`.
    //
    // A Routed/Nested message asks the mediator to forward on the sender's
    // behalf (the same operation as a DIDComm forward), and reaches the same
    // remote sink — `forward_tsp_remote` → `forward_queue_enqueue`. The DIDComm
    // path refuses that with 403 unless the sender holds SEND_FORWARDED; the TSP
    // path did not, so an authenticated account whose SEND_FORWARDED was never
    // granted (or was revoked) could still drive the relay. Authorise on the
    // envelope sender's own ACLs (as the SEND_MESSAGES direct-delivery gate above
    // does), not the session's — the WS ingress only gates LOCAL at upgrade.
    //
    // Anonymous relay hops are already admitted/refused by the peer allowlist
    // above and by `enable_inter_mediator_relay`; this gate is for authenticated
    // senders, whose `meta.sender` is bound to the session DID when
    // `force_session_did_match` is on.
    if session.authenticated
        && matches!(
            unpacked.message_type,
            TspMessageType::Routed | TspMessageType::Nested
        )
    {
        let from_acls = authz::effective_acls(
            state,
            &affinidi_messaging_mediator_common::did_identity::did_hash(&meta.sender),
        )
        .await?;
        if authz::require_capability(&from_acls, Capability::SendForwarded).is_err() {
            return Err(tsp_problem(
                session,
                error_codes::FORWARD_SENDER_DENIED,
                "authorization.send_forwarded",
                "Sender DID is not authorized to forward (relay) messages through this mediator"
                    .to_string(),
                StatusCode::FORBIDDEN,
            ));
        }
    }

    match unpacked.message_type {
        // We are a relay hop: unwrap our routing layer and forward the onward
        // message, re-sealing as this mediator unless we are the last hop (the
        // opaque inner is already sealed to the final recipient).
        TspMessageType::Routed => {
            let step = next_hop(&unpacked).map_err(|e| {
                tsp_problem(
                    session,
                    error_codes::MESSAGE_ENVELOPE_READ,
                    "message.tsp.route",
                    format!("malformed TSP route: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            let plan = plan_route_step(step, &meta.sender).map_err(|e| {
                tsp_problem(
                    session,
                    error_codes::MESSAGE_ENVELOPE_READ,
                    "message.tsp.malformed",
                    format!("malformed routed inner TSP envelope: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            match plan {
                // Last relay hop: `next` is the final recipient named in the route
                // and `inner` is already sealed end-to-end to them. Deliver the
                // opaque inner — which may be a TSP *or* a DIDComm message — to that
                // recipient, who handles it natively on pickup. This is the
                // TSP↔DIDComm bridge point: the mediator forwards on the route, not
                // on the inner's (possibly non-TSP) envelope.
                RoutePlan::ToNext {
                    next,
                    from_vid,
                    inner,
                } => {
                    forward_to_next(
                        state,
                        session,
                        &next,
                        &from_vid,
                        &inner,
                        Destination::Routing,
                    )
                    .await
                }
                // Intermediate hop: re-seal the onward route to the next hop,
                // authenticating as this mediator, and forward.
                RoutePlan::Reseal {
                    next,
                    remaining,
                    inner,
                } => {
                    let next_vid = resolve_tsp_vid(state, &next, &session.session_id).await?;
                    let resealed = pack_routed(
                        &inner,
                        &remaining,
                        &identity.vid,
                        &next,
                        &identity.signing_key,
                        &next_vid.encryption_key,
                    )
                    .map_err(|e| {
                        tsp_problem(
                            session,
                            error_codes::MESSAGE_PACK_ERROR,
                            "message.tsp.reseal",
                            format!("couldn't re-seal routed TSP message: {e}"),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        )
                    })?
                    .bytes;
                    forward_to_next(
                        state,
                        session,
                        &next,
                        &identity.vid,
                        &resealed,
                        Destination::Routing,
                    )
                    .await
                }
                // Empty route: `inner` is sealed to its own final recipient, who
                // is named by its envelope. See `plan_route_step` for why the
                // access list is applied against the verified hop sender.
                RoutePlan::DeliverLocal {
                    to_vid,
                    from_vid,
                    inner,
                } => {
                    deliver_opaque(
                        state,
                        session,
                        &to_vid,
                        Sender::Verified(&from_vid),
                        &inner,
                        Ingress::Relayed,
                    )
                    .await
                }
            }
        }

        // We are the metadata-privacy intermediary (TSP §5.5): reveal the inner
        // message — itself a packed TSP message sealed end-to-end to its final
        // recipient — and route it by its own (sealed) envelope.
        TspMessageType::Nested => {
            // The unpacked payload IS the inner packed message. Route it by its own
            // (sealed) envelope — its recipient may be local or on another mediator,
            // and the inner may be TSP or an opaque DIDComm bridge payload.
            let inner_meta = TspMetaEnvelope::parse(&unpacked.payload).map_err(|e| {
                tsp_problem(
                    session,
                    error_codes::MESSAGE_ENVELOPE_READ,
                    "message.tsp.malformed",
                    format!("malformed nested inner TSP envelope: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;
            // The inner receiver is the far endpoint's own VID — `VID_b2` in
            // §5.3.3's notation — so it is used to route and then dropped,
            // never written to the durable queue.
            forward_to_next(
                state,
                session,
                &inner_meta.receiver,
                &meta.sender,
                &unpacked.payload,
                Destination::EndpointToEndpoint,
            )
            .await
        }

        // Direct or Control addressed to the mediator itself.
        //
        // Two kinds of traffic arrive here and they are not interchangeable. A
        // **management Trust Task** is a request the mediator must *answer* —
        // `account/update`, `acl/get`, `access-list/update` and friends. Anything
        // else addressed to us is mail for the mediator's own account, which is
        // stored for its pickup.
        //
        // Telling them apart on the payload rather than a binding type URI is
        // deliberate: the client sends the bare Trust Task document (that is what
        // `VtaClient`'s TSP arm packs — the task document, not a `{type,
        // document}` wrapper), so there is no envelope tag to switch on. A
        // document that parses as a Trust Task *and* names a type the mediator
        // serves is unambiguous; everything else falls through unchanged.
        //
        // Direct and Control messages destined for *local accounts* never reach
        // here — they took the `receiver != mediator` opaque pass-through above.
        TspMessageType::Direct | TspMessageType::Control => {
            if let Some(doc) = trust_tasks::parse_if_served(&unpacked.payload) {
                // The proof is verified over the payload as sent, not as
                // re-serialised from `doc`. It already parsed as a document,
                // so it parses as JSON.
                let raw: serde_json::Value =
                    serde_json::from_slice(&unpacked.payload).map_err(|e| {
                        MediatorError::InternalError(
                            error_codes::DB_OPERATION_ERROR,
                            "NA".into(),
                            e.to_string(),
                        )
                    })?;
                return dispatch_tsp_trust_task(state, session, &meta.sender, doc, &raw).await;
            }
            deliver_tsp_local(state, session, &meta.sender, raw).await
        }
        // Rev 3's two new end-to-end types, which the mediator only carries.
        // `GenericControl` is control for the layer *above* TSP and
        // `PaddingOnly` carries nothing at all — so neither can be a management
        // Trust Task, and running the parse over them would be asking a question
        // whose answer is always no. They store for the recipient like a Direct
        // message and are never opened.
        TspMessageType::GenericControl | TspMessageType::PaddingOnly => {
            deliver_tsp_local(state, session, &meta.sender, raw).await
        }
    }
}

/// Answer a management Trust Task that arrived over TSP.
///
/// The mediator's management surface is one core
/// ([`trust_tasks::consume`]) with a wrapper per transport; this is the TSP
/// wrapper. It exists so a **TSP-only deployment is not a second-class one**:
/// without it a client cannot set its own account ACL over any transport, since
/// the DIDComm dispatcher (`MessageType::process`) is the only other way in and
/// takes a DIDComm `Message`.
///
/// `sender_vid` is the envelope sender, which the caller has already proven:
/// `direct::unpack` verified an Ed25519 signature over envelope‖ciphertext
/// against the key resolved from that VID's DID document, and opened the payload
/// with HPKE-Auth, which binds the sender's static key too. Two independent
/// proofs — the same standing the DIDComm path gets from authcrypt, which is
/// what lets the handlers authorise against it unchanged.
///
/// The reply is sealed back to the sender and delivered through the ordinary
/// local-delivery path, so it reaches a connected client on its existing pickup
/// socket. No second socket, and no new delivery mechanism.
#[cfg(feature = "tsp")]
async fn dispatch_tsp_trust_task(
    state: &SharedData,
    session: &Session,
    sender_vid: &str,
    doc: trust_tasks_rs::TrustTask<serde_json::Value>,
    raw: &serde_json::Value,
) -> Result<InboundMessageResponse, MediatorError> {
    let now_secs = state.clock.unix_secs();
    // A refusal is threaded to the task, as the DIDComm dispatcher threads
    // one to the message carrying it, so the caller can match it.
    let task_id = doc.id.clone();

    // The sender VID is the framework identity; TSP VIDs carry no key fragment,
    // so it is already the shape `consume` wants.
    let request_type = doc.type_uri.to_string();
    // A refusal is answered with a `trust-task-error` document, sealed back
    // like a response, where one can be sent (see `trust_task_error`).
    let refusing = trust_task_error::Refusing::of(&doc);
    let consumed = trust_tasks::consume(
        doc,
        raw,
        state,
        session,
        sender_vid,
        now_secs,
        trust_tasks::TaskTransport::Tsp,
    )
    .await;
    let response = match consumed {
        Ok(Some(response)) => response,
        // A ping identity mismatch emits nothing — same as the DIDComm path.
        Ok(None) => {
            return Ok(InboundMessageResponse::Stored(
                affinidi_messaging_sdk::messages::sending::InboundMessageList::default(),
            ));
        }
        Err(e) => match refusing.document(&e, session, sender_vid, state).await {
            Some(doc) => doc,
            None => return Err(e.threaded_to(&task_id)),
        },
    };

    let identity = state.tsp_identity().await?;
    let recipient = resolve_tsp_vid(state, sender_vid, &session.session_id).await?;

    let payload = serde_json::to_vec(&response).map_err(|e| {
        tsp_problem(
            session,
            error_codes::MESSAGE_PACK_ERROR,
            "message.tsp.trust_task.serialize",
            format!("could not serialise the Trust Task response: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;

    // Rev 3 seals under HPKE-**Base**, so the sender's own X25519 secret does
    // not enter the KEM and `pack` does not take it. Sender authenticity is the
    // ESSR sender field plus the outer Ed25519 signature instead.
    let packed = affinidi_tsp::message::direct::pack(
        &payload,
        affinidi_tsp::MessageType::Direct,
        &identity.vid,
        sender_vid,
        &identity.signing_key,
        &recipient.encryption_key,
    )
    .map_err(|e| {
        tsp_problem(
            session,
            error_codes::MESSAGE_PACK_ERROR,
            "message.tsp.trust_task.seal",
            format!("could not seal the Trust Task response: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;

    // The answer to `messaging/mux/ack`, or its refusal, is pushed to the
    // connection only, not stored: acknowledging is idempotent, so a lost answer is recovered by
    // asking again, while a stored one would itself need acknowledging, and
    // the answer to that, without end (spec, consumer rule 4).
    if crate::mux::tasks::answer_is_pushed(&response, &request_type) {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
        match state
            .database
            .streaming_is_client_live(&session.did_hash, true)
            .await
        {
            Some(uuid) => {
                if let Err(e) = state
                    .database
                    .streaming_publish_verbatim(
                        &session.did_hash,
                        &uuid,
                        &BASE64_URL_SAFE_NO_PAD.encode(&packed.bytes),
                    )
                    .await
                {
                    tracing::debug!("mux ack answer not pushed (the client may ask again): {e}");
                }
            }
            None => tracing::debug!("mux ack answer not pushed: the connection is gone"),
        }
        return Ok(InboundMessageResponse::Stored(
            affinidi_messaging_sdk::messages::sending::InboundMessageList::default(),
        ));
    }

    // The answer is the mediator's own message, stored as the DIDComm path
    // stores its replies: from the mediator's account, with no queue or
    // access-list gate. The task has already run, so a gate here would refuse
    // the answer to work that was done (and a retry would then meet the
    // duplicate-execution record); and the reply is not the client's own
    // traffic, so it is not counted against the client's queues. The requester
    // must still hold an account to keep an inbox here.
    let to_hash = affinidi_messaging_mediator_common::did_identity::did_hash(sender_vid);
    if !state.database.account_exists(&to_hash).await? {
        return Err(crate::messages::delivery_refused(
            session,
            None,
            "a Trust Task answer's requester has no account to hold it",
        ));
    }
    crate::messages::store::store_mediator_reply(
        state,
        sender_vid,
        &BASE64_URL_SAFE_NO_PAD.encode(&packed.bytes),
        state.clock.unix_secs() + state.limits().message_expiry_seconds,
    )
    .await
}

/// Deliver a TSP message addressed to the mediator to the local account named
/// in *its own envelope* (the mediator's own): parse the envelope for its
/// receiver and hand off to [`deliver_opaque`].
///
/// `from_vid` is supplied by the caller rather than read from `bytes`: it is
/// the sender `unpack` verified for the layer.
#[cfg(feature = "tsp")]
pub(super) async fn deliver_tsp_local(
    state: &SharedData,
    session: &Session,
    from_vid: &str,
    bytes: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    let meta = TspMetaEnvelope::parse(bytes).map_err(|e| {
        tsp_problem(
            session,
            error_codes::MESSAGE_ENVELOPE_READ,
            "message.tsp.malformed",
            format!("malformed TSP message: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    deliver_opaque(
        state,
        session,
        &meta.receiver,
        Sender::Verified(from_vid),
        bytes,
        Ingress::Relayed,
    )
    .await
}

/// Deliver an opaque message to a local recipient: pass the delivery gate, then
/// store the bytes for pickup. The bytes are **not** parsed — this is the
/// TSP↔DIDComm bridge primitive. A routed relay carries an opaque inner (which
/// may be a DIDComm message) and delivers it to the route's named recipient, who
/// recognises and handles it natively on pickup; the mediator never reads it.
///
/// `sender` is who the caller vouches for: the sender `unpack` verified on a
/// relay or to-mediator arm, the envelope's claim on pass-through. The
/// recipient's access list is applied against it, and the gate decides who the
/// stored message is attributed to. A remote recipient never reaches here:
/// [`forward_to_next`] sends it to `forward_tsp_remote` instead.
#[cfg(feature = "tsp")]
pub(super) async fn deliver_opaque(
    state: &SharedData,
    session: &Session,
    to_vid: &str,
    sender: Sender<'_>,
    bytes: &[u8],
    ingress: Ingress,
) -> Result<InboundMessageResponse, MediatorError> {
    let delivery = authorize_local_delivery(state, session, sender, to_vid, ingress).await?;

    // Store in the form the recipient's protocol expects, so a pickup client can
    // recognise and decode it. A TSP message is stored as base64url(qb2) = its
    // CESR qb64 text (`-E…`); a bridged DIDComm message is stored as its plain
    // JWE/JWS text. Both ride the same UTF-8 string store; the client sniffs the
    // prefix (qb64 vs `{`/`ey`) on pickup.
    let encoded = if affinidi_tsp::is_tsp(bytes) {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    } else {
        std::str::from_utf8(bytes)
            .map_err(|e| {
                tsp_problem(
                    session,
                    error_codes::MESSAGE_ENVELOPE_READ,
                    "message.bridge.malformed",
                    format!("bridged inner is neither a TSP message nor valid UTF-8 text: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?
            .to_string()
    };
    // Attributed as the gate decided: on a relay hop the session is the
    // relaying peer (often the anonymous relay session, with no DID at all),
    // so the verified sender is who the queue gates, the stats and the sender
    // recorded on the message are about.
    let msg_id = crate::messages::store::store_envelope(
        state,
        session,
        to_vid,
        &delivery.from_did_hash,
        &encoded,
        state.clock.unix_secs() + state.limits().message_expiry_seconds,
        false,
    )
    .await?;
    tracing::debug!(%to_vid, ?sender, "TSP/bridged message stored for local recipient");
    let mut stored = affinidi_messaging_sdk::messages::sending::InboundMessageList::default();
    stored.messages.push((to_vid.to_string(), msg_id));
    Ok(InboundMessageResponse::Stored(stored))
}

/// Resolve a DID-based TSP VID to its keys + endpoints.
#[cfg(feature = "tsp")]
pub(crate) async fn resolve_tsp_vid(
    state: &SharedData,
    did: &str,
    session_id: &str,
) -> Result<affinidi_tsp::ResolvedVid, MediatorError> {
    affinidi_tsp::DidVidResolver::new(state.did_resolver.clone())
        .resolve_did(did)
        .await
        .map_err(|e| {
            MediatorError::problem(
                error_codes::TSP_NEXT_HOP_UNRESOLVABLE,
                session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.tsp.resolve",
                "couldn't resolve TSP VID: {1}",
                vec![format!("{did}: {e}")],
                StatusCode::BAD_GATEWAY,
            )
        })
}

/// Build a TSP protocol problem report with a single human-readable message.
#[cfg(feature = "tsp")]
pub(super) fn tsp_problem(
    session: &Session,
    code: u16,
    code_str: &str,
    message: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        code,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        code_str,
        &message,
        vec![],
        status,
    )
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_tests {
    use affinidi_tsp::message::direct;
    use affinidi_tsp::{MessageType as TspMessageType, PrivateVid, is_tsp};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    /// The storage-format contract for TSP messages: a TSP message (raw CESR
    /// qb2, leads with the `0xD4` magic byte) is stored base64url-encoded, which
    /// is its CESR qb64 text form (`-E…`). This must round-trip exactly, stay
    /// distinguishable from a DIDComm JSON envelope (`{`), and decode back to a
    /// recognisable TSP message — so a pickup client can identify and decode it.
    #[test]
    fn tsp_storage_encoding_roundtrips_and_is_recognisable() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");

        let packed = direct::pack(
            b"hello over TSP",
            TspMessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &bob.encryption_key,
        )
        .unwrap();
        let raw = &packed.bytes;
        assert!(is_tsp(raw), "packed message leads with the TSP magic byte");

        // This is exactly what handle_inbound_tsp stores.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(raw);

        // The stored form is CESR qb64 text and is unambiguously not DIDComm JSON.
        assert!(stored.starts_with("-E"), "qb64 envelope-code prefix");
        assert!(
            !stored.starts_with('{'),
            "distinct from a DIDComm JSON envelope"
        );

        // A pickup client base64url-decodes back to the exact original bytes.
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(&decoded, raw, "decode round-trips the qb2 bytes exactly");
        assert!(
            is_tsp(&decoded),
            "decoded bytes are a recognisable TSP message"
        );
    }
}
