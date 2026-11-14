//! TSP relay: what a routed layer addressed to this mediator asks it to do,
//! and handing the onward message to the next hop — a local account, or a
//! remote TSP endpoint through the forwarding queue.

use crate::error_codes;
use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::sending::InboundMessageResponse;
use affinidi_tsp::MetaEnvelope as TspMetaEnvelope;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;

use super::tsp::{deliver_opaque, resolve_tsp_vid, tsp_problem};
use crate::messages::delivery_gate::{Ingress, Sender};

/// What the mediator does with one step of a routed TSP message addressed to it.
#[cfg(feature = "tsp")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RoutePlan {
    /// Hand `inner` to `next` (local or remote) on behalf of `from_vid`.
    ToNext {
        next: String,
        from_vid: String,
        inner: Vec<u8>,
    },
    /// Re-seal `inner` + `remaining` as this mediator and forward to `next`.
    Reseal {
        next: String,
        remaining: Vec<String>,
        inner: Vec<u8>,
    },
    /// Store `inner` for the local recipient its own envelope names, applying
    /// that recipient's access list against `from_vid`.
    DeliverLocal {
        to_vid: String,
        from_vid: String,
        inner: Vec<u8>,
    },
}

/// Turn a [`RouteStep`] into the action the mediator takes, given the sender
/// that `direct::unpack` verified for this hop (`verified_sender`).
///
/// Every arm that delivers or forwards on someone's behalf uses
/// `verified_sender`. That matters most for the empty-route step: its `inner`
/// is an opaque message sealed to its final recipient, and its envelope names
/// a sender in the clear that nothing on this hop has checked. Only the inner
/// *receiver* is read from it (to know where to deliver); the access list is
/// applied against the hop sender, the same identity the last-hop and nested
/// arms use. `affinidi-tsp` 0.3 decodes an empty route as `Nested`, so this
/// step is not produced today, but the decision is fixed here so that a
/// decoder change cannot alter it.
#[cfg(feature = "tsp")]
pub(super) fn plan_route_step(
    step: affinidi_tsp::RouteStep,
    verified_sender: &str,
) -> Result<RoutePlan, affinidi_tsp::TspError> {
    use affinidi_tsp::RouteStep;
    Ok(match step {
        RouteStep::Forward {
            next,
            remaining,
            inner,
        } if remaining.is_empty() => RoutePlan::ToNext {
            next,
            from_vid: verified_sender.to_string(),
            inner,
        },
        RouteStep::Forward {
            next,
            remaining,
            inner,
        } => RoutePlan::Reseal {
            next,
            remaining,
            inner,
        },
        RouteStep::Deliver { inner } => {
            let to_vid = TspMetaEnvelope::parse(&inner)?.receiver;
            RoutePlan::DeliverLocal {
                to_vid,
                from_vid: verified_sender.to_string(),
                inner,
            }
        }
    })
}

/// Forward a relayed message to the next hop named in the route: deliver locally
/// if it is a local account, otherwise enqueue it for delivery to the next hop's
/// remote TSP endpoint.
#[cfg(feature = "tsp")]
pub(super) async fn forward_to_next(
    state: &SharedData,
    session: &Session,
    next: &str,
    from_vid: &str,
    bytes: &[u8],
    destination: Destination,
) -> Result<InboundMessageResponse, MediatorError> {
    if state
        .database
        .account_exists(&affinidi_messaging_mediator_common::did_identity::did_hash(
            next,
        ))
        .await?
    {
        // Local delivery works entirely on hashes and persists no plaintext
        // VID, so it satisfies §5.3.3 without needing to know which kind of
        // destination this is.
        deliver_opaque(
            state,
            session,
            next,
            Sender::Verified(from_vid),
            bytes,
            Ingress::Relayed,
        )
        .await
    } else {
        forward_tsp_remote(state, session, next, from_vid, bytes, destination).await
    }
}

/// What kind of VID a forward is addressed to, which decides whether it may be
/// written to the durable forward queue in plaintext.
///
/// Rev 3 §5.3.3 draws this line: an intermediary carrying an
/// endpoint-to-endpoint message "SHOULD not process the endpoint-to-endpoint
/// VIDs `VID_a2` and `VID_b2` and MUST NOT store `VID_a2` and `VID_b2` in any
/// persistent storage". Processing them is unavoidable — the message cannot be
/// routed onward without resolving the destination — but retaining them is not,
/// and retention is the part the specification forbids outright.
///
/// The distinction is worth a type rather than a bool because it is invisible at
/// the call site otherwise: all three forwarding paths look alike, and only one
/// of them is carrying identifiers that belong to somebody else's relationship.
#[cfg(feature = "tsp")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Destination {
    /// A routing-layer VID — a route hop, or the destination's VID at its own
    /// intermediary. This mediator is addressed by it and may retain it.
    Routing,
    /// The far endpoint's own VID, revealed by unwrapping a metadata-privacy
    /// nesting. Not ours to keep.
    EndpointToEndpoint,
}

/// Enqueue a relayed message for delivery to the next hop's **remote** TSP
/// endpoint. The next hop's transport endpoint is read from its DID document
/// (`TSPTransport` service, via [`tsp_forward_endpoint`]); the message is queued
/// (as base64url(qb2)) on the shared forwarding queue, and the forwarding
/// processor POSTs the raw qb2 to the remote mediator's `/inbound`. A next hop
/// that resolves back to this mediator is rejected as a loop.
#[cfg(feature = "tsp")]
async fn forward_tsp_remote(
    state: &SharedData,
    session: &Session,
    next: &str,
    from_vid: &str,
    bytes: &[u8],
    destination: Destination,
) -> Result<InboundMessageResponse, MediatorError> {
    use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;

    let resolved = resolve_tsp_vid(state, next, &session.session_id).await?;
    let endpoint_url = tsp_forward_endpoint(state, session, next, &resolved).await?;

    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: BASE64_URL_SAFE_NO_PAD.encode(bytes),
        to_did_hash: affinidi_messaging_mediator_common::did_identity::did_hash(next),
        from_did_hash: affinidi_messaging_mediator_common::did_identity::did_hash(from_vid),
        from_did: from_vid.to_string(),
        // §5.3.3: an endpoint-to-endpoint VID is not written to the queue. The
        // hash and the resolved endpoint above are all delivery uses; the
        // plaintext only ever fed diagnostics and the abandonment report, and
        // those fall back to the hash.
        to_did: match destination {
            Destination::Routing => next.to_string(),
            Destination::EndpointToEndpoint => String::new(),
        },
        endpoint_url: endpoint_url.clone(),
        received_at_ms: state.clock.unix_millis(),
        delay_milli: 0,
        expires_at: state.clock.unix_secs() + state.limits().message_expiry_seconds,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    };

    state
        .database
        .forward_queue_enqueue(&entry, state.limits().forward_task_queue)
        .await
        .map_err(|e| {
            tsp_problem(
                session,
                error_codes::FORWARD_ENQUEUE_ERROR,
                "message.tsp.forward.enqueue",
                format!("couldn't enqueue TSP message for remote forwarding: {e}"),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })?;

    state.monitor.queued_for_relay(
        &entry.from_did_hash,
        &entry.to_did_hash,
        &entry.message,
        crate::monitor::Protocol::Tsp,
    );
    tracing::info!(%next, %endpoint_url, "TSP message enqueued for remote forwarding");
    Ok(InboundMessageResponse::Forwarded)
}

/// What a resolved `TSPTransport` advertisement tells this mediator to do with a
/// message for that VID, decided without any I/O.
#[cfg(feature = "tsp")]
#[derive(Debug, PartialEq, Eq)]
enum TspRelay {
    /// Relay to this transport URL.
    Direct(String),
    /// The VID names its mediator by **DID**. That mediator's own document
    /// carries the transport URL, one resolve away.
    ViaMediator(String),
    /// The advertisement points back at this mediator — the URL is one of our own
    /// authorities, or the named mediator is us. Carries the offending value for
    /// the error message.
    Loop(String),
    /// Nothing to go on: no `TSPTransport` service, or one this mediator has no
    /// delivery rule for.
    Nothing,
}

/// Classify a resolved VID's TSP transport advertisement.
///
/// [`affinidi_tsp::ResolvedVid`] has already split the `TSPTransport`
/// `serviceEndpoint`s by what they name — transport URLs in `endpoints`, mediator
/// DIDs in `mediators` — so this only has to decide *which* to act on and whether
/// it comes back to us.
///
/// A direct URL wins over a mediator DID when a document publishes both: the
/// document is telling us it can be reached without a relay. Within `endpoints`
/// the first entry decides, in document order — the same rule the DIDComm
/// classifier follows, where every URL it can parse is either "ours" or a remote
/// hop and the scan stops on whichever comes first. A first entry that is ours is
/// reported as a loop rather than skipped: the document has told us the message
/// belongs *here*, and quietly relaying to some later entry would send it back
/// out on a route its own document contradicts.
#[cfg(feature = "tsp")]
fn classify_tsp_relay(
    resolved: &affinidi_tsp::ResolvedVid,
    mediator_did: &str,
    self_authorities: &std::collections::HashSet<(String, u16)>,
) -> TspRelay {
    if let Some(url) = resolved.endpoints.first() {
        return if crate::server::uri_points_at_self(url.as_str(), self_authorities) {
            TspRelay::Loop(url.to_string())
        } else {
            TspRelay::Direct(url.to_string())
        };
    }

    match resolved.mediators.first() {
        // Named us as its mediator, yet reached this function — which only runs
        // when there is no local account for it. There is nowhere onward to send
        // it, and POSTing to our own `/inbound` would spin.
        Some(did) if did == mediator_did => TspRelay::Loop(did.clone()),
        Some(did) => TspRelay::ViaMediator(did.clone()),
        None => TspRelay::Nothing,
    }
}

/// The transport URL to relay a TSP message for `next` to.
///
/// A `TSPTransport` service names its transport one of two ways:
///
/// - **By URL** — relayed there directly, unless the authority is one of ours,
///   which means the message came back to us.
/// - **By DID** — the shape the VTI stack publishes: a persona's `#tsp` service
///   carries its *mediator's DID*, and the transport URL lives in that mediator's
///   own document. Resolved one hop, and that document's own `TSPTransport` URL
///   used.
///
/// Only one hop of indirection is followed, exactly as the DIDComm forward path
/// does in `protocols::routing::service_endpoint_for_remote`: a mediator's own
/// document is expected to publish a URL, and chasing further would let a chain
/// of documents steer this mediator's relay.
///
/// Before the indirection arm existed, a DID-valued endpoint was taken for a
/// transport URL — `did:` parses as a URL — and the forwarding processor was
/// handed `did:webvh:…` to POST to, which failed inside the HTTP client
/// (`builder error for url`) and retried until the message was abandoned. The
/// failure has to happen *here*, where the next hop can be named, or not at all.
#[cfg(feature = "tsp")]
async fn tsp_forward_endpoint(
    state: &SharedData,
    session: &Session,
    next: &str,
    resolved: &affinidi_tsp::ResolvedVid,
) -> Result<String, MediatorError> {
    let mediator = match classify_tsp_relay(
        resolved,
        &state.config.mediator_did,
        &state.self_authorities,
    ) {
        TspRelay::Direct(url) => {
            let blocked = &state.config.processors.forwarding;
            if crate::common::relay_target::relay_target_blocked(blocked, [url.as_str(), next]) {
                return Err(tsp_problem(
                    session,
                    error_codes::FORWARD_LOOP_DETECTED,
                    "protocol.forwarding.loop_detected",
                    format!(
                        "TSP next hop {next} ({url}) is on this mediator's forwarding block list"
                    ),
                    StatusCode::LOOP_DETECTED,
                ));
            }
            return Ok(url);
        }
        TspRelay::Loop(what) => {
            return Err(tsp_problem(
                session,
                error_codes::FORWARD_LOOP_DETECTED,
                "protocol.forwarding.loop_detected",
                format!("TSP next hop {next} resolves back to this mediator ({what})"),
                StatusCode::LOOP_DETECTED,
            ));
        }
        TspRelay::Nothing => {
            return Err(tsp_problem(
                session,
                error_codes::TSP_NO_ENDPOINT,
                "message.tsp.no_endpoint",
                format!("next hop {next} publishes no TSP transport endpoint"),
                StatusCode::NOT_FOUND,
            ));
        }
        TspRelay::ViaMediator(did) => did,
    };

    // One hop: the peer mediator's own document carries the transport URL.
    let peer = resolve_tsp_vid(state, &mediator, &session.session_id)
        .await
        .map_err(|e| {
            tsp_problem(
                session,
                error_codes::TSP_NEXT_HOP_UNRESOLVABLE,
                "message.tsp.mediator.unresolvable",
                format!("next hop {next} is mediated by {mediator}, which did not resolve: {e}"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    match classify_tsp_relay(&peer, &state.config.mediator_did, &state.self_authorities) {
        TspRelay::Direct(url) => {
            let blocked = &state.config.processors.forwarding;
            if crate::common::relay_target::relay_target_blocked(
                blocked,
                [url.as_str(), mediator.as_str(), next],
            ) {
                return Err(tsp_problem(
                    session,
                    error_codes::FORWARD_LOOP_DETECTED,
                    "protocol.forwarding.loop_detected",
                    format!(
                        "TSP next hop {next} is mediated by {mediator} ({url}), which is on \
                         this mediator's forwarding block list"
                    ),
                    StatusCode::LOOP_DETECTED,
                ));
            }
            Ok(url)
        }
        TspRelay::Loop(what) => Err(tsp_problem(
            session,
            error_codes::FORWARD_LOOP_DETECTED,
            "protocol.forwarding.loop_detected",
            format!(
                "TSP next hop {next} is mediated by {mediator}, which resolves back to this \
                 mediator ({what})"
            ),
            StatusCode::LOOP_DETECTED,
        )),
        // A second hop of indirection is deliberately not chased.
        TspRelay::ViaMediator(_) | TspRelay::Nothing => Err(tsp_problem(
            session,
            error_codes::TSP_NO_ENDPOINT,
            "message.tsp.no_endpoint",
            format!(
                "next hop {next} is mediated by {mediator}, whose document publishes no TSP \
                 transport URL"
            ),
            StatusCode::NOT_FOUND,
        )),
    }
}

/// Unit coverage for the TSP relay classifier — the DID-vs-URL decision that
/// [`forward_tsp_remote`] makes before anything is enqueued. Pure: no store, no
/// resolver, no session.
#[cfg(test)]
#[cfg(feature = "tsp")]
mod tsp_relay_tests {
    use super::{TspRelay, classify_tsp_relay};
    use crate::server::normalize_host;
    use affinidi_tsp::ResolvedVid;
    use std::collections::HashSet;

    /// This mediator.
    const US: &str = "did:web:us.example";
    /// The mediator named in the production failure, verbatim.
    const PEER_MEDIATOR: &str = "did:webvh:QmbHZC8JUpUD1XrdEcNiAPTxke4WpDyBPjjigPpEwYZiq5:dids.firstperson.dev:firstperson-mediator";
    /// The transport URL that peer mediator's own document publishes.
    const PEER_URL: &str = "https://mediator.firstperson.dev/mediator/v1";

    fn authorities(entries: &[(&str, u16)]) -> HashSet<(String, u16)> {
        entries
            .iter()
            .map(|(host, port)| (normalize_host(host), *port))
            .collect()
    }

    fn no_authorities() -> HashSet<(String, u16)> {
        HashSet::new()
    }

    /// A resolved VID advertising the given transport URLs and mediator DIDs.
    fn vid(id: &str, endpoints: &[&str], mediators: &[&str]) -> ResolvedVid {
        ResolvedVid {
            id: id.to_string(),
            signing_key: [1u8; 32],
            encryption_key: [2u8; 32],
            endpoints: endpoints
                .iter()
                .map(|u| url::Url::parse(u).expect("test endpoint parses"))
                .collect(),
            mediators: mediators.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// The production shape: a persona whose `#tsp` service names its mediator by
    /// DID is an indirection to follow, never a URL to POST to.
    #[test]
    fn a_mediator_did_is_followed_as_indirection() {
        let persona = vid("did:web:persona.example", &[], &[PEER_MEDIATOR]);
        assert_eq!(
            classify_tsp_relay(&persona, US, &no_authorities()),
            TspRelay::ViaMediator(PEER_MEDIATOR.to_string())
        );
    }

    /// And the second half of that shape: the mediator's own document publishes
    /// the transport URL, which is what the forward is actually sent to.
    #[test]
    fn the_mediators_own_document_yields_the_transport_url() {
        let mediator = vid(PEER_MEDIATOR, &[PEER_URL], &[]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::Direct(PEER_URL.to_string())
        );
    }

    /// A VID that publishes its own URL is relayed straight there — the
    /// unmediated case, unchanged.
    #[test]
    fn a_direct_url_is_relayed_as_is() {
        let peer = vid("did:web:peer.example", &["https://peer.example/v1"], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Direct("https://peer.example/v1".to_string())
        );
    }

    /// Both advertised: the URL wins. A document that can be reached without a
    /// relay is telling us so.
    #[test]
    fn a_direct_url_wins_over_a_mediator_did() {
        let peer = vid(
            "did:web:peer.example",
            &["https://peer.example/v1"],
            &[PEER_MEDIATOR],
        );
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Direct("https://peer.example/v1".to_string())
        );
    }

    /// The pre-existing loop guard, kept: a transport URL on one of our own
    /// authorities is the message coming back to us.
    #[test]
    fn a_url_on_one_of_our_authorities_is_a_loop() {
        let peer = vid("did:web:peer.example", &["http://127.0.0.1:7037/"], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &authorities(&[("127.0.0.1", 7037)])),
            TspRelay::Loop("http://127.0.0.1:7037/".to_string())
        );
    }

    /// The same guard extended to the indirection arm: a next hop that names
    /// *us* as its mediator has no account here (that is the only way this code
    /// is reached), so following it would POST to our own `/inbound`.
    #[test]
    fn naming_this_mediator_as_the_mediator_is_a_loop() {
        let peer = vid("did:web:peer.example", &[], &[US]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Loop(US.to_string())
        );
    }

    /// No `TSPTransport` service at all — nothing to relay to, and the caller
    /// turns this into a "publishes no TSP transport endpoint" problem report
    /// rather than enqueueing something undeliverable.
    #[test]
    fn no_advertisement_is_nothing() {
        let peer = vid("did:web:peer.example", &[], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Nothing
        );
    }

    /// The regression, stated end to end over the two documents: the persona
    /// classifies to its mediator's DID, and *that* document — not the persona's
    /// — is where the URL comes from. Nothing anywhere hands `did:webvh:…` on as
    /// something to connect to.
    #[test]
    fn the_two_document_indirection_resolves_to_the_mediators_url() {
        let persona = vid("did:web:persona.example", &[], &[PEER_MEDIATOR]);
        let TspRelay::ViaMediator(mediator_did) =
            classify_tsp_relay(&persona, US, &no_authorities())
        else {
            panic!("a DID-valued TSPTransport endpoint must classify as indirection");
        };
        assert_eq!(mediator_did, PEER_MEDIATOR);

        let mediator = vid(&mediator_did, &[PEER_URL], &[]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::Direct(PEER_URL.to_string())
        );
    }

    /// One hop only. If the peer mediator's own document *also* only names
    /// another mediator, the caller stops rather than chasing — a chain of
    /// documents must not be able to steer this mediator's relay.
    #[test]
    fn a_second_hop_of_indirection_is_not_chased() {
        let mediator = vid(PEER_MEDIATOR, &[], &["did:web:third.example"]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::ViaMediator("did:web:third.example".to_string())
        );
        // `tsp_forward_endpoint` maps this second-hop `ViaMediator` onto the same
        // "no transport URL" error as `Nothing`, and does not resolve again.
    }
}

#[cfg(test)]
#[cfg(feature = "tsp")]
mod route_plan_tests {
    use super::*;
    use affinidi_tsp::{PrivateVid, RouteStep, message::routed::next_hop_parts};

    const HOP_SENDER: &str = "did:example:verified-hop";

    /// A packed TSP message whose envelope claims `sender` and names `receiver`.
    fn inner_message(sender: &str, receiver: &str) -> Vec<u8> {
        let from = PrivateVid::generate(sender);
        let to = PrivateVid::generate(receiver);
        affinidi_tsp::message::direct::pack(
            b"hello",
            affinidi_tsp::MessageType::Direct,
            sender,
            receiver,
            &from.signing_key,
            &to.encryption_key,
        )
        .expect("inner message packs")
        .bytes
    }

    #[test]
    fn empty_route_delivers_as_the_verified_hop_sender() {
        // Built directly: `affinidi-tsp` 0.3 never yields an empty route from
        // `unpack`, but the step must already resolve correctly if it ever does.
        let inner = inner_message("did:example:claimed-in-inner", "did:example:bob");
        let step = next_hop_parts(&[], &inner).expect("an empty route is a valid step");
        assert!(matches!(step, RouteStep::Deliver { .. }));

        let plan = plan_route_step(step, HOP_SENDER).expect("inner envelope parses");
        assert_eq!(
            plan,
            RoutePlan::DeliverLocal {
                to_vid: "did:example:bob".to_string(),
                from_vid: HOP_SENDER.to_string(),
                inner,
            },
            "the recipient comes from the inner envelope, the sender from this hop"
        );
    }

    #[test]
    fn empty_route_with_unparseable_inner_is_refused() {
        let step = next_hop_parts(&[], b"not a TSP message").expect("step");
        assert!(plan_route_step(step, HOP_SENDER).is_err());
    }

    #[test]
    fn last_hop_forwards_as_the_verified_hop_sender() {
        let step = next_hop_parts(&["did:example:bob".to_string()], b"opaque").expect("step");
        assert_eq!(
            plan_route_step(step, HOP_SENDER).expect("plan"),
            RoutePlan::ToNext {
                next: "did:example:bob".to_string(),
                from_vid: HOP_SENDER.to_string(),
                inner: b"opaque".to_vec(),
            }
        );
    }

    #[test]
    fn intermediate_hop_is_resealed() {
        let hops = ["did:example:m2".to_string(), "did:example:bob".to_string()];
        let step = next_hop_parts(&hops, b"opaque").expect("step");
        assert_eq!(
            plan_route_step(step, HOP_SENDER).expect("plan"),
            RoutePlan::Reseal {
                next: "did:example:m2".to_string(),
                remaining: vec!["did:example:bob".to_string()],
                inner: b"opaque".to_vec(),
            }
        );
    }
}
