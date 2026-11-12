use crate::common::authz::{self, Capability};
use crate::common::storage_timeout::with_storage_timeout;
use crate::messages::queue_limits::{
    validate_peer_queue_limit, validate_recipient_queue_limit, validate_sender_queue_limit,
};
// Shared with the TSP relay path in `messages::inbound`, which cannot reach into
// this module: `protocols` only exists in a `didcomm` build.
use crate::server::uri_points_at_self;

use crate::didcomm_compat::MetaEnvelope;
use crate::{
    SharedData,
    common::session::Session,
    messages::{
        ProcessMessageResponse, WrapperType,
        error_response::generate_error_response,
        store::{store_forwarded_message, store_message},
    },
};
use affinidi_did_common::Document;
use affinidi_messaging_didcomm::message::{Attachment, Message};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;
use affinidi_messaging_mediator_common::tasks::forwarding::RelayMode;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::Account, acls::MediatorACLSet},
};
use base64::prelude::*;
use http::StatusCode;
use serde::Deserialize;
use tracing::{Instrument, debug, info, span, warn};
use uuid::Uuid;

// Reads the body of an incoming forward message
#[derive(Default, Deserialize)]
struct ForwardRequest {
    next: Option<String>, // Defaults to true
}

/// The ACL a forward sender with no account on this mediator is checked
/// against. Nothing is stored for such a sender: the ACL applies to this one
/// forward.
///
/// Least privilege: `SEND_FORWARDED` (the single capability the forward gate
/// consumes) and nothing else — and only when `global_acl_default` itself
/// grants it, so a non-relay mediator refuses the forward.
fn relay_sender_acls(global_acl_default: &MediatorACLSet) -> MediatorACLSet {
    let mut acls = MediatorACLSet::from_string_ruleset("DENY_ALL").unwrap_or_default();
    if authz::grants(global_acl_default, Capability::SendForwarded) {
        // admin = true so the bit can be set on a fresh deny-all set; the
        // self-change flag stays false (an operator/admin governs it later).
        let _ = acls.set_send_forwarded(true, false, true);
    }
    acls
}

/// Re-wrap an inner forward envelope for relay to a remote peer mediator
/// ([`RelayMode::Rewrap`]).
///
/// Produces a fresh `forward` whose single attachment is `inner`, authcrypted
/// FROM this mediator TO `next` (the peer mediator — [`RemoteHop::relay_to`],
/// which for a single forward is not the forward's own `next`) and carrying the running
/// `hop_count`. The peer mediator authenticates *this* mediator as the sender
/// (which is what makes its trusted-peer allowlist possible), sees that
/// `next == its own DID`, and peels the attachment to continue routing. Because
/// the inner envelope is now ciphertext inside this layer, on-wire observers
/// between the two mediators no longer see the original sender's key id (which
/// authcrypt otherwise carries, in the clear, in the inner JWE header).
async fn rewrap_for_relay(
    state: &SharedData,
    session: &Session,
    inner: &str,
    next: &str,
    hop_count: u32,
) -> Result<String, MediatorError> {
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(inner)).finalize();
    let mut forward = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/routing/2.0/forward".to_owned(),
        serde_json::json!({ "next": next }),
    )
    .to(next.to_owned())
    .from(state.config.mediator_did.clone())
    .attachment(attachment)
    .finalize();
    // Carry the running hop count so the peer mediator continues loop detection
    // across the re-wrap rather than resetting it.
    forward
        .extra
        .insert("hop_count".to_string(), serde_json::json!(hop_count));

    crate::didcomm_compat::pack_encrypted(
        &forward,
        next,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map(|(packed, _)| packed)
    .map_err(|e| {
        MediatorError::problem_with_log(
            47,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.pack",
            "Couldn't re-wrap forward for relay: {1}",
            vec![e.clone()],
            StatusCode::BAD_REQUEST,
            format!("Couldn't re-wrap forward for relay: {e}"),
        )
    })
}

/// If `msg` is a relay re-wrap layer — a `forward` whose `next` hop is this
/// mediator itself (the envelope produced by [`rewrap_for_relay`] on a peer) —
/// decode and return its inner attachment (the envelope to continue processing).
///
/// Returns `None` for any other message, including an ordinary `forward` bound
/// for a different next hop, so non-relay traffic is never altered.
pub(crate) fn rewrap_inner_attachment(mediator_did: &str, msg: &Message) -> Option<String> {
    if msg.typ != "https://didcomm.org/routing/2.0/forward" {
        return None;
    }
    let next = serde_json::from_value::<ForwardRequest>(msg.body.clone())
        .ok()?
        .next?;
    if next != mediator_did {
        return None;
    }
    let b64 = msg.attachments.as_ref()?.first()?.data.base64.as_ref()?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64).ok()?;
    String::from_utf8(bytes).ok()
}

/// Process a forward message, run checks and then if accepted place into FORWARD_TASKS stream
/// Parse the `next` hop DID from a routing-2.0 forward body.
fn parse_next_did(msg: &Message, session: &Session) -> Result<String, MediatorError> {
    match serde_json::from_value::<ForwardRequest>(msg.body.to_owned()) {
        Ok(body) => match body.next {
            Some(next_str) => Ok(next_str),
            None => Err(MediatorError::problem(
                56,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.next.missing",
                "Forwarding message is missing next field",
                vec![],
                StatusCode::BAD_REQUEST,
            )),
        },
        Err(e) => Err(MediatorError::problem_with_log(
            57,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.forwarding.parse",
            "Failed to parse forwarding message body. Reason: {1}",
            vec![e.to_string()],
            StatusCode::BAD_REQUEST,
            format!("Failed to parse forwarding message body. Reason: {e}"),
        )),
    }
}

/// Decode the first attachment of a forward into its inner DIDComm payload.
///
/// Supports base64 and inline JSON attachments; rejects JWS-signed JSON
/// (verification not yet implemented), linked attachments, and unknown
/// formats. Returns the decoded payload string.
fn decode_first_attachment(
    msg: &Message,
    session: &Session,
    attachments: &[Attachment],
) -> Result<String, MediatorError> {
    let attachment = match attachments.first() {
        Some(a) => a,
        None => {
            return Err(MediatorError::problem(
                59,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.attachments.missing",
                "Forward message has empty attachments list",
                vec![],
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    let data = if let Some(ref b64) = attachment.data.base64 {
        match BASE64_URL_SAFE_NO_PAD.decode(b64) {
            Ok(data) => match String::from_utf8(data) {
                Ok(data) => data,
                Err(e) => {
                    return Err(MediatorError::problem_with_log(
                        68,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.forwarding.attachments.base64",
                        "Failed to decode base64 attachment. Reason: {1}",
                        vec![e.to_string()],
                        StatusCode::BAD_REQUEST,
                        format!("Failed to decode base64 attachment. Reason: {e}"),
                    ));
                }
            },
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    68,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.attachments.base64",
                    "Failed to decode base64 attachment. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Failed to decode base64 attachment. Reason: {e}"),
                ));
            }
        }
    } else if let Some(ref json_val) = attachment.data.json {
        if attachment.data.jws.is_some() {
            // JSON-with-JWS attachments would need a full
            // verification path: parse the protected header,
            // resolve the kid via the DID resolver, extract
            // the Ed25519 verification key, then verify before
            // forwarding. Until that lands, we reject rather
            // than forward untrusted signed payloads. Most
            // DIDComm clients use base64-encoded encrypted
            // attachments instead, which don't require this
            // path. Tracked as future work in PR #286's
            // follow-up section.
            return Err(MediatorError::problem(
                66,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "JWS verified attachments are not yet supported by this mediator",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
            ));
        } else {
            match serde_json::to_string(json_val) {
                Ok(data) => data,
                Err(e) => {
                    return Err(MediatorError::problem_with_log(
                        67,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.forwarding.attachments.json.invalid",
                        "Invalid attachment JSON schema. Reason: {1}",
                        vec![e.to_string()],
                        StatusCode::BAD_REQUEST,
                        format!("Invalid attachment JSON schema. Reason: {e}"),
                    ));
                }
            }
        }
    } else if attachment.data.links.is_some() {
        return Err(MediatorError::problem(
            66,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "me.not_implemented",
            "Linked attachments are not yet supported by this mediator",
            vec![],
            StatusCode::NOT_IMPLEMENTED,
        ));
    } else {
        return Err(MediatorError::problem(
            67,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.forwarding.attachments.unknown",
            "Attachment data format is not supported",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };
    Ok(data)
}

/// Deliver an accepted forward to its next hop: live-stream it (ephemeral),
/// enqueue it for a remote mediator (re-wrapping it in `Rewrap` relay mode),
/// or store it locally. Also reads the inner envelope to enforce a local
/// recipient's anonymous-message policy before routing.
#[allow(clippy::too_many_arguments)]
async fn deliver_forward(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    next: &str,
    next_did_hash: &str,
    next_acls: Option<&MediatorACLSet>,
    sender_of_record: &str,
    sender_has_account: bool,
    data: &str,
    delay_milli: i64,
    expires_at: u64,
    ephemeral: bool,
    remote_endpoint: Option<RemoteHop>,
) -> Result<(), MediatorError> {
    debug_assert!(
        remote_endpoint.is_none() == next_acls.is_some(),
        "a local next hop has ACLs here, a remote one does not"
    );
    // Check attached message for routing information
    let next_envelope = match MetaEnvelope::new(data, &state.did_resolver).await {
        Ok(envelope) => envelope,
        Err(e) => {
            return Err(MediatorError::problem_with_log(
                37,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.envelope.read",
                "Couldn't read forward attached DIDComm envelope: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
                format!("Couldn't read DIDComm envelope: {e}"),
            ));
        }
    };

    // A remote recipient's ANON_RECEIVE is checked by its own mediator, so
    // only a local next hop carries ACLs here.
    if let Some(next_acls) = next_acls
        && next_envelope.from_did.is_none()
        && authz::require_capability(next_acls, Capability::AnonReceive).is_err()
    {
        return Err(crate::messages::delivery_refused(
            session,
            Some(msg.id.to_string()),
            "recipient is not accepting anonymous messages",
        ));
    }

    debug!(
        "Forwarded message: to_did_hash={}, ephemeral={}",
        next_did_hash, ephemeral
    );

    if ephemeral {
        // Live stream only: an ephemeral message is never stored, so it is
        // accepted only when it is actually handed to a live stream.
        let Some(stream_uuid) = state
            .database
            .streaming_is_client_live(next_did_hash, false)
            .await
        else {
            return Err(crate::messages::delivery_refused(
                session,
                Some(msg.id.to_string()),
                "ephemeral message for a recipient with no live stream",
            ));
        };
        if let Err(e) = state
            .database
            .streaming_publish_message(next_did_hash, &stream_uuid, data, false)
            .await
        {
            return Err(MediatorError::problem_with_log(
                14,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.error",
                "Database transaction error: {1}",
                vec![e.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Couldn't publish an ephemeral message to its live stream: {e}"),
            ));
        }
        debug!("Live streaming message to UUID: {}", stream_uuid);
    } else {
        if let Some(RemoteHop {
            endpoint: endpoint_url,
            relay_to,
        }) = remote_endpoint
        {
            // Remote destination — enqueue to FORWARD_Q for the forwarding processor

            // Check hop count for loop detection
            let hop_count = msg
                .extra
                .get("hop_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            if hop_count >= state.config.processors.forwarding.max_hops {
                metrics::counter!(crate::common::metrics::names::FORWARD_LOOP_DETECTED_TOTAL)
                    .increment(1);
                return Err(MediatorError::problem_with_log(
                    94,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "protocol.forwarding.loop_detected",
                    "Message exceeded maximum hop count ({1}), possible forwarding loop",
                    vec![state.config.processors.forwarding.max_hops.to_string()],
                    StatusCode::LOOP_DETECTED,
                    format!(
                        "Message exceeded maximum hop count ({}), possible forwarding loop",
                        state.config.processors.forwarding.max_hops
                    ),
                ));
            }

            let now_ms = state.clock.unix_millis();

            // The sender's full DID, for problem reports. Only a sender with an
            // account here has an inbox to receive one.
            let from_did = if sender_has_account && !sender_of_record.is_empty() {
                msg.from.as_deref().unwrap_or("").to_string()
            } else {
                String::new()
            };

            // Blind relay forwards the inner envelope verbatim; rewrap relay
            // re-encrypts it from this mediator to the peer (see
            // `rewrap_for_relay`). Default is blind — no behaviour change.
            let relay_message = match state.config.processors.forwarding.relay_mode {
                RelayMode::Blind => data.to_string(),
                RelayMode::Rewrap => {
                    rewrap_for_relay(state, session, data, &relay_to, hop_count + 1).await?
                }
            };

            let entry = ForwardQueueEntry {
                stream_id: String::new(), // Set by Redis on XADD
                message: relay_message,
                to_did_hash: next_did_hash.to_string(),
                from_did_hash: sender_of_record.to_string(),
                from_did,
                to_did: next.to_string(),
                endpoint_url: endpoint_url.clone(),
                received_at_ms: now_ms,
                delay_milli,
                expires_at,
                retry_count: 0,
                hop_count: hop_count + 1,
                not_before_ms: 0,
            };

            state
                .database
                .forward_queue_enqueue(&entry, state.limits().forward_task_queue)
                .await
                .map_err(|e| {
                    MediatorError::problem_with_log(
                        90,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.forwarding.enqueue",
                        "Failed to enqueue message for remote forwarding: {1}",
                        vec![e.to_string()],
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Failed to enqueue message for remote forwarding: {e}"),
                    )
                })?;

            metrics::counter!(crate::common::metrics::names::MESSAGES_FORWARDED_TOTAL).increment(1);
            state.monitor.queued_for_relay(
                &entry.from_did_hash,
                &entry.to_did_hash,
                &entry.message,
                crate::monitor::Protocol::DidComm,
            );
            info!(
                "FORWARD_ENQUEUED: to_did_hash={} from_did_hash={} endpoint={}",
                next_did_hash, sender_of_record, endpoint_url
            );
        } else {
            // Local destination — store as before
            store_forwarded_message(
                state,
                session,
                data,
                Some(sender_of_record),
                next,
                Some(expires_at),
            )
            .await?;
        }
    }

    Ok(())
}

/// Where a forward to a remote next hop is relayed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteHop {
    /// The transport URL the forwarding processor posts to.
    endpoint: String,
    /// The DID that terminates the relay hop: the peer mediator when `next`
    /// names one in its DID document (the single forward), otherwise `next`
    /// itself. `rewrap` mode encrypts its layer to this DID, because the
    /// receiving mediator only peels a layer addressed to itself.
    relay_to: String,
}

/// Where a forward's next hop is delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NextHop {
    /// This mediator holds the next hop's inbox (or external forwarding is
    /// off). Delivered only if the next hop has an account here.
    Local,
    /// Another mediator holds it; relay there.
    Remote(RemoteHop),
    /// No route this mediator can use. Storing the message here would never
    /// reach the recipient, so the forward is refused. `retryable` when the
    /// cause is a failure to resolve the mediator the next hop names, which
    /// may clear.
    Unroutable { reason: String, retryable: bool },
}

/// Classify a forward's next hop by resolving its DID document (and, one hop
/// further, a mediator it names). Only when external forwarding is enabled;
/// otherwise every next hop is local. A next hop whose own DID cannot be
/// resolved is local too.
async fn classify_next_hop(state: &SharedData, next: &str) -> NextHop {
    if !state.config.processors.forwarding.external_forwarding {
        return NextHop::Local;
    }
    match state.did_resolver.resolve(next).await {
        Ok(resolve_response) => {
            let hop = service_endpoint_for_remote(state, next, &resolve_response.doc).await;
            match &hop {
                NextHop::Remote(remote) => debug!(
                    "Next hop ({}) is remote, endpoint: {} (via {})",
                    next, remote.endpoint, remote.relay_to
                ),
                NextHop::Local => debug!("Next hop ({}) is local to this mediator", next),
                NextHop::Unroutable { .. } => {}
            }
            hop
        }
        // Classed as local, so it is delivered only to an account here: a
        // resolver outage does not stop local delivery, and a next hop with no
        // account gets the same `delivery_refused` either way.
        Err(e) => {
            warn!(
                "Next hop ({next}) couldn't be resolved ({e}); delivering only to a local account"
            );
            NextHop::Local
        }
    }
}

/// The refusal for a [`NextHop::Unroutable`] next hop. A resolution failure
/// may clear, so it is reported as retryable; anything else gets the uniform
/// `delivery_refused`.
fn unroutable(session: &Session, msg: &Message, reason: &str, retryable: bool) -> MediatorError {
    if retryable {
        warn!(
            session = %session.session_id,
            reason = %reason,
            "forward refused: the next hop's mediator could not be resolved"
        );
        MediatorError::problem(
            74,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "did.resolve",
            "The forward's next hop couldn't be routed; try again later",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
        )
    } else {
        crate::messages::delivery_refused(session, Some(msg.id.to_string()), reason)
    }
}

/// The recipient checks for a next hop whose inbox is on this mediator: an
/// account, `RECEIVE_FORWARDED`, its access list and its receive-queue limit.
/// Returns its ACLs, which `deliver_forward` still needs for the
/// `ANON_RECEIVE` check.
#[allow(clippy::too_many_arguments)]
async fn check_local_next_hop(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    next_did_hash: &str,
    from_account: &Account,
    attachment_count: usize,
    ephemeral: bool,
) -> Result<MediatorACLSet, MediatorError> {
    let next_account = resolve_next_account(state, session, msg, next_did_hash).await?;

    let next_acls = MediatorACLSet::from_u64(next_account.acls);
    if authz::require_capability(&next_acls, Capability::ReceiveForwarded).is_err() {
        return Err(crate::messages::delivery_refused(
            session,
            Some(msg.id.to_string()),
            "recipient is not accepting forwarded messages",
        ));
    }

    if authz::check_access_list(
        state.database.as_ref(),
        next_did_hash,
        Some(&from_account.did_hash),
    )
    .await
    .is_err()
    {
        return Err(crate::messages::delivery_refused(
            session,
            Some(msg.id.to_string()),
            "delivery blocked by the recipient's access list",
        ));
    }

    validate_recipient_queue_limit(
        Some(msg.id.as_str()),
        &next_account,
        next_did_hash,
        attachment_count,
        ephemeral,
        state,
        session,
    )?;

    Ok(next_acls)
}

/// The one recipient check a remote next hop still gets here: if it already
/// holds an account on this mediator **with access-list entries**, that list
/// is a policy someone set and is honoured. That covers a local account whose
/// DID document this mediator fails to recognise as its own (a hostname
/// missing from `server.local_endpoints`), which would otherwise skip its
/// owner's list.
///
/// An account with an empty list is not consulted: it is the placeholder an
/// earlier version registered from `global_acl_default`, and under
/// `MODE_EXPLICIT_ALLOW` it would refuse every sender. No account is created.
async fn check_remote_next_hop(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    next_did_hash: &str,
    from_account: &Account,
) -> Result<(), MediatorError> {
    let account = state
        .database
        .account_get(next_did_hash)
        .await
        .map_err(|e| {
            if e.is_storage_cap() {
                return e;
            }
            MediatorError::problem_with_log(
                14,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.error",
                "Database transaction error: {1}",
                vec![e.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Database transaction error: {e}"),
            )
        })?;
    let has_list = account.is_some_and(|a| a.access_list_count > 0);
    if has_list
        && authz::check_access_list(
            state.database.as_ref(),
            next_did_hash,
            Some(&from_account.did_hash),
        )
        .await
        .is_err()
    {
        return Err(crate::messages::delivery_refused(
            session,
            Some(msg.id.to_string()),
            "delivery blocked by the access list the next hop holds on this mediator",
        ));
    }
    Ok(())
}

/// Fetch the next-hop account. A next hop with no account is refused: a
/// forward never creates one, since only authentication (or an admin) admits
/// a DID to this mediator. Returns a storage problem report on backend
/// failure.
async fn resolve_next_account(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    next_did_hash: &str,
) -> Result<Account, MediatorError> {
    match state.database.account_get(next_did_hash).await {
        Ok(Some(next_account)) => Ok(next_account),
        Ok(None) => Err(crate::messages::delivery_refused(
            session,
            Some(msg.id.to_string()),
            "next hop has no account on this mediator",
        )),
        Err(e) => Err(MediatorError::problem_with_log(
            14,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "me.res.storage.error",
            "Database transaction error: {1}",
            vec![e.to_string()],
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Database transaction error: {e}"),
        )),
    }
}

/// Who a forward is from.
struct ForwardSender {
    /// What the sender checks run against: `SEND_FORWARDED`, the recipient's
    /// access list and the queue limits.
    account: Account,
    /// Whether the sender holds an account here. A sender without one is
    /// still counted per relationship (`limits.queue.peer`) — counters alone
    /// do not make an account in any store — but it has no inbox here for a
    /// relay failure report.
    registered: bool,
}

/// Resolve the account a forward is *from*: the DID that signed or authcrypted
/// it, or — for an anonymous forward — a synthetic account carrying the
/// global default ACL. A signing sender with no account here is checked
/// against [`relay_sender_acls`] and no account is created for it. Enforces the
/// `SEND_FORWARDED` capability on the resolved sender.
///
/// The plaintext `from` is never used on its own: it is accepted only when it
/// names that same authenticated DID.
async fn resolve_forward_sender(
    state: &SharedData,
    session: &Session,
    msg: &Message,
    metadata: &UnpackMetadata,
) -> Result<ForwardSender, MediatorError> {
    let sender = crate::messages::authenticated_sender(msg, metadata).map_err(|reason| {
        MediatorError::problem_with_log(
            96,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.sender.mismatch",
            "Message sender is not the authenticated sender: {1}",
            vec![reason.clone()],
            StatusCode::FORBIDDEN,
            format!("Message sender is not the authenticated sender: {reason}"),
        )
    })?;
    if let Some(from) = &sender {
        let from_hash = affinidi_messaging_mediator_common::did_identity::did_hash(from.as_str());
        let (from_account, registered) = match state.database.account_get(&from_hash).await {
            Ok(Some(from_account)) => (from_account, true),
            // A sender this mediator has not admitted. It is not registered
            // here: an account is created only by authentication (subject to
            // `mediator_acl_mode`) or by an admin.
            Ok(None) => (
                Account {
                    did_hash: from_hash,
                    acls: relay_sender_acls(&state.config.security.global_acl_default).to_u64(),
                    ..Default::default()
                },
                false,
            ),
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    14,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.error",
                    "Database transaction error: {1}",
                    vec![e.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Database transaction error: {e}"),
                ));
            }
        };
        let from_acls = MediatorACLSet::from_u64(from_account.acls);

        if authz::require_capability(&from_acls, Capability::SendForwarded).is_err() {
            return Err(MediatorError::problem(
                60,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.send_forwarded",
                "Sender isn't allowed to send forwarded messages",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }

        Ok(ForwardSender {
            account: from_account,
            registered,
        })
    } else if authz::require_capability(&session.acls, Capability::SendForwarded).is_err() {
        Err(MediatorError::problem(
            60,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.send_forwarded",
            "Sender isn't allowed to send forwarded messages",
            vec![],
            StatusCode::FORBIDDEN,
        ))
    } else {
        Ok(ForwardSender {
            account: Account {
                acls: state.config.security.global_acl_default.to_u64(),
                ..Default::default()
            },
            // Anonymous: stored under no sender, exactly as before.
            registered: true,
        })
    }
}

pub(crate) async fn process(
    msg: &Message,
    metadata: &UnpackMetadata,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "routing",
        session_id = session.session_id.as_str()
    );
    async move {
        let ephemeral = if let Some(ephemeral) = msg.extra.get("ephemeral") {
            match ephemeral.as_bool() {
                Some(true) => true,
                Some(false) => false,
                None => {
                    // Handle this slightly differently so that the sender gets a notification regardless that they have an incorrect header set
                    let error = generate_error_response(state, session, &msg.id, ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "message.header.ephemera.invalid".into(),
                        "Ephemeral header isn't a JSON bool value. Defaults to false and still sends message".into(),
                        vec![],
                        None,
                    ), true)?;

                    store_message(state, session, &error, metadata).await?;
                    false
                }
            }
        } else {
            false
        };

        let next = parse_next_did(msg, session)?;
        let next_did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&next);

        let attachments = if let Some(attachments) = &msg.attachments {
            attachments.to_owned()
        } else {
            return Err(MediatorError::problem(
                59,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.attachments.missing",
                "There were no attachments for this forward message",
                vec![],
                StatusCode::BAD_REQUEST,
            ));
        };
        let attachments_bytes = attachments
            .iter()
            .map(|a| a.byte_count.unwrap_or(0))
            .sum::<u64>();
        debug!(
            "Attachments: count({}) bytes({})",
            attachments.len(),
            attachments_bytes
        );

        // ****************************************************
        // Determine who the from did is
        // If message is anonymous, then use the session DID

        let sender = resolve_forward_sender(state, session, msg, metadata).await?;
        let from_account = sender.account;
        let sender_has_account = sender.registered;

        // Check queue + attachment + forward-task-queue limits before accepting.
        // Per-relationship first: when a sender is genuinely flooding one peer,
        // both this and the coarse sender total would fire, and `limits.queue.peer`
        // is the one that tells the operator which relationship is at fault.
        validate_peer_queue_limit(
            Some(msg.id.as_str()),
            &from_account.did_hash,
            &next_did_hash,
            attachments.len(),
            ephemeral,
            state,
            session,
        )
        .await?;
        validate_sender_queue_limit(Some(msg.id.as_str()), &from_account, attachments.len(), ephemeral, state, session)?;

        if attachments.len() > state.limits().attachments_max_count {
            warn!(
                "Too many attachments in message, limit is {}",
                state.limits().attachments_max_count
            );
            return Err(MediatorError::problem_with_log(
                63,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.attachments.too_many",
                "Forwarded message has too many attachments ({1}). Limit is ({2})",
                vec![
                    attachments.len().to_string(),
                    state.limits().attachments_max_count.to_string(),
                ],
                StatusCode::BAD_REQUEST,
                format!(
                    "Forwarded message has too many attachments ({}). Limit is ({})",
                    attachments.len(),
                    state.limits().attachments_max_count
                ),
            ));
        }

        if !ephemeral
            && with_storage_timeout(
                state.storage_timeout(),
                "forward_queue_len",
                &session.session_id,
                state.database.forward_queue_len(),
            )
            .await?
                >= state.limits().forward_task_queue
        {
            warn!(
                "Forward task queue is full, limit is {}",
                state.limits().forward_task_queue
            );
            return Err(MediatorError::problem(
                64,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.forwarding.queue.limit",
                "Mediator forwarding queue is at max limit, try again later",
                vec![
                    attachments.len().to_string(),
                    state.limits().attachments_max_count.to_string(),
                ],
                StatusCode::SERVICE_UNAVAILABLE,
            ));
        }

        // Check if a delay has been specified and if so, is it longer than we allow?
        let delay_milli = if let Some(delay_milli) = msg.extra.get("delay_milli") {
            debug!("forward delay requested: ({:?})", delay_milli);
            delay_milli.as_i64().unwrap_or(0)
        } else {
            0
        };

        if delay_milli.abs() > (state.config.processors.forwarding.future_time_limit as i64 * 1000)
        {
            warn!(
                "Forwarding delay is too long, limit is {}",
                state.config.processors.forwarding.future_time_limit
            );
            return Err(MediatorError::problem_with_log(
                65,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.delay_milli",
                "Forward delay_milli field isn't valid. Max field value: {1}",
                vec![(state.config.processors.forwarding.future_time_limit * 1000).to_string()],
                StatusCode::BAD_REQUEST,
                format!(
                    "Forward delay_milli field isn't valid. Max field value: {}",
                    state.config.processors.forwarding.future_time_limit * 1000
                ),
            ));
        }

        // ****************************************************
        // Local or remote next hop? This resolves `next` (and possibly its
        // mediator) over the network, so it runs only once every cheap check
        // above has passed.
        let next_hop = if ephemeral {
            NextHop::Local
        } else {
            classify_next_hop(state, &next).await
        };
        let remote_endpoint = match next_hop {
            NextHop::Local => None,
            NextHop::Remote(hop) => Some(hop),
            NextHop::Unroutable { reason, retryable } => {
                return Err(unroutable(session, msg, &reason, retryable));
            }
        };

        // ****************************************************
        // Recipient checks. A local next hop is checked here. A remote one is
        // checked by the mediator that holds its inbox: this mediator has no
        // real policy for it, only what `global_acl_default` would invent, so
        // it registers no account for it and applies no recipient ACL
        // (`crates/affinidi-messaging-mediator/docs/multi-mediator.md` §6).
        let next_acls = match &remote_endpoint {
            None => Some(
                check_local_next_hop(
                    state,
                    session,
                    msg,
                    &next_did_hash,
                    &from_account,
                    attachments.len(),
                    ephemeral,
                )
                .await?,
            ),
            Some(_) => {
                check_remote_next_hop(state, session, msg, &next_did_hash, &from_account).await?;
                None
            }
        };

        // Forward is good, lets process the attachments and add to the queues
        // First step is to determine if the next hop is local to the mediator or remote?
        //if next_did_doc.service

        let data = decode_first_attachment(msg, session, &attachments)?;

        let expires_at = if let Some(expires_at) = msg.expires_time {
            let now = state.clock.unix_secs();

            if expires_at > now + state.limits().message_expiry_seconds {
                now + state.limits().message_expiry_seconds
            } else {
                expires_at
            }
        } else {
            state.clock.unix_secs() + state.limits().message_expiry_seconds
        };

        deliver_forward(
            state,
            session,
            msg,
            &next,
            &next_did_hash,
            next_acls.as_ref(),
            &from_account.did_hash,
            sender_has_account,
            &data,
            delay_milli,
            expires_at,
            ephemeral,
            remote_endpoint,
        )
        .await?;

        Ok(ProcessMessageResponse {
            store_message: false,
            force_live_delivery: false,
            forward_message: true,
            data: WrapperType::None,
        })
    }
    .instrument(_span)
    .await
}

/// One `DIDCommMessaging` service endpoint, classified without any I/O.
#[derive(Debug, PartialEq, Eq)]
enum EndpointHop {
    /// This mediator delivers for that DID — store the forward locally.
    Local,
    /// A remote mediator, reachable at this URL — enqueue to `FORWARD_Q`.
    Remote(String),
    /// The endpoint names a mediator by **DID** rather than by URL. That
    /// mediator's own document carries the transport URL, one resolve away.
    Indirect(String),
}

/// Classify a single `DIDCommMessaging` endpoint URI.
///
/// `None` for a URI shape this mediator has no rule for — neither a DID nor an
/// HTTP-family URL.
fn classify_endpoint(
    uri: &str,
    mediator_did: &str,
    self_authorities: &std::collections::HashSet<(String, u16)>,
) -> Option<EndpointHop> {
    // Strip surrounding quotes if present (from JSON serialization)
    let uri = uri.trim_matches('"');

    // Points at this mediator's own DID — the ordinary local-account case.
    if uri == mediator_did {
        return Some(EndpointHop::Local);
    }

    // An HTTP(S)/WS(S) URL: decide local-vs-remote by comparing its authority
    // against the mediator's known self-authorities. URLs that point back at
    // this instance (different hostname, same address; or a public alias
    // declared via `local_endpoints`) are collapsed to local delivery instead
    // of being relayed through FORWARD_Q to themselves.
    if uri.starts_with("http://")
        || uri.starts_with("https://")
        || uri.starts_with("ws://")
        || uri.starts_with("wss://")
    {
        if uri_points_at_self(uri, self_authorities) {
            debug!(
                "Service endpoint {} resolves to a self-authority — treating as local",
                uri
            );
            return Some(EndpointHop::Local);
        }
        return Some(EndpointHop::Remote(uri.to_string()));
    }

    // A DID naming another mediator. This is the shape the VTI stack publishes
    // — `#didcomm`'s `serviceEndpoint` carries the *mediator's DID*, and the
    // transport URL lives in that mediator's own document — so it has to be
    // followed. Before this arm existed it fell through to "no remote endpoint
    // found", and every cross-mediator forward in that convention was stored
    // locally under a DID that would never connect here, while the sender's
    // mediator answered 200.
    if uri.starts_with("did:") {
        return Some(EndpointHop::Indirect(uri.to_string()));
    }

    None
}

/// Every `DIDCommMessaging` endpoint URI in `doc`, in document order.
fn didcomm_endpoints(doc: &Document) -> Vec<String> {
    doc.service
        .iter()
        .filter(|service| service.type_.contains(&"DIDCommMessaging".to_string()))
        .flat_map(|service| service.service_endpoint.get_uris())
        .collect()
}

/// A relay is refused when its endpoint, the DID it is relayed to, or the
/// next hop itself is on `processors.forwarding.blocked_forwarding`: this
/// mediator's own DID and published endpoints (a forward that would come back
/// here), plus the operator's `blocked_forwarding_dids` and their endpoints.
fn refuse_blocked(state: &SharedData, next: &str, hop: RemoteHop) -> NextHop {
    if blocked_relay(
        &state.config.processors.forwarding.blocked_forwarding,
        next,
        &hop,
    ) {
        return NextHop::Unroutable {
            reason: format!(
                "next hop ({next}) relays via ({}) at ({}), which is on this mediator's \
                 forwarding block list",
                hop.relay_to, hop.endpoint
            ),
            retryable: false,
        };
    }
    NextHop::Remote(hop)
}

/// Each of the endpoint, relay DID and next hop is compared in its
/// [`canonical_relay_target`](crate::common::relay_target::canonical_relay_target)
/// form, so another spelling of a listed DID or URL is still refused.
fn blocked_relay(blocked: &ahash::AHashSet<String>, next: &str, hop: &RemoteHop) -> bool {
    crate::common::relay_target::relay_target_blocked(
        blocked,
        [hop.endpoint.as_str(), hop.relay_to.as_str(), next],
    )
}

/// Decide whether a forward's next hop is served by this mediator or a remote
/// one, and — when remote — the URL to relay it to.
///
/// Returns [`NextHop::Remote`] if the next hop should be forwarded to a remote
/// mediator, [`NextHop::Local`] if it is local to this mediator, and
/// [`NextHop::Unroutable`] if it names a mediator this one cannot reach.
///
/// A `DIDCommMessaging` endpoint names its mediator one of two ways:
///
/// - **By URL** — relayed there directly, unless the authority is one of ours
///   (`state.self_authorities`: the bind address plus any operator-declared
///   `local_endpoints`), which makes it local.
/// - **By DID** — the shape the VTI stack publishes. Resolved one hop, and the
///   endpoints of *that* document classified the same way.
///
/// Only one hop of indirection is followed: a mediator's own document is
/// expected to publish a URL, and chasing further would let a chain of
/// documents steer this mediator's relay.
///
/// Anything left over is refused rather than stored: a next hop that
/// publishes a DIDComm service we could not turn into a URL is almost
/// certainly not ours, and storing it locally means it is never delivered to
/// anyone.
async fn service_endpoint_for_remote(
    state: &SharedData,
    next: &str,
    next_doc: &Document,
) -> NextHop {
    let endpoints = didcomm_endpoints(next_doc);
    if endpoints.is_empty() {
        // No DIDComm service published at all — local. A local account is
        // under no obligation to publish one.
        return NextHop::Local;
    }

    let mut peer_mediator: Option<String> = None;
    for uri in &endpoints {
        match classify_endpoint(uri, &state.config.mediator_did, &state.self_authorities) {
            Some(EndpointHop::Local) => return NextHop::Local,
            Some(EndpointHop::Remote(url)) => {
                return refuse_blocked(
                    state,
                    next,
                    RemoteHop {
                        endpoint: url,
                        relay_to: next.to_string(),
                    },
                );
            }
            // Remembered, but the scan continues: a later entry naming this
            // mediator directly still wins.
            Some(EndpointHop::Indirect(did)) if peer_mediator.is_none() => {
                peer_mediator = Some(did);
            }
            Some(EndpointHop::Indirect(_)) | None => {}
        }
    }

    let Some(peer_mediator) = peer_mediator else {
        return NextHop::Unroutable {
            reason: format!(
                "next hop ({next}) publishes a DIDCommMessaging service this mediator can't \
                 turn into an endpoint ({endpoints:?})"
            ),
            retryable: false,
        };
    };

    // One hop: the peer mediator's own document carries the transport URL.
    let peer_doc = match state.did_resolver.resolve(&peer_mediator).await {
        Ok(response) => response.doc,
        Err(e) => {
            return NextHop::Unroutable {
                reason: format!(
                    "next hop ({next}) is mediated by ({peer_mediator}), which couldn't be \
                     resolved: {e}"
                ),
                retryable: true,
            };
        }
    };

    for uri in didcomm_endpoints(&peer_doc) {
        match classify_endpoint(&uri, &state.config.mediator_did, &state.self_authorities) {
            // The peer mediator is this mediator under another name.
            Some(EndpointHop::Local) => return NextHop::Local,
            Some(EndpointHop::Remote(url)) => {
                return refuse_blocked(
                    state,
                    next,
                    RemoteHop {
                        endpoint: url,
                        relay_to: peer_mediator,
                    },
                );
            }
            // A second hop of indirection is deliberately not chased.
            Some(EndpointHop::Indirect(_)) | None => {}
        }
    }

    NextHop::Unroutable {
        reason: format!(
            "next hop ({next}) is mediated by ({peer_mediator}), whose document publishes no \
             DIDComm endpoint URL"
        ),
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointHop, RemoteHop, blocked_relay, classify_endpoint, didcomm_endpoints,
        parse_next_did, relay_sender_acls, rewrap_inner_attachment, uri_points_at_self,
    };
    use crate::common::session::Session;
    use crate::server::{compute_self_authorities_from, normalize_host};
    use affinidi_did_common::Document;
    use affinidi_messaging_didcomm::message::{Attachment, Message};
    use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
    use base64::prelude::*;
    use std::collections::HashSet;

    fn forward_to(next: &str, attachment_bytes: &[u8]) -> Message {
        let att = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(attachment_bytes)).finalize();
        Message::build(
            "id-1".to_string(),
            "https://didcomm.org/routing/2.0/forward".to_string(),
            serde_json::json!({ "next": next }),
        )
        .attachment(att)
        .finalize()
    }

    #[test]
    fn rewrap_inner_attachment_peels_forward_to_self() {
        let msg = forward_to("did:peer:this_mediator", b"INNER-ENVELOPE");
        let inner = rewrap_inner_attachment("did:peer:this_mediator", &msg);
        assert_eq!(inner.as_deref(), Some("INNER-ENVELOPE"));
    }

    #[test]
    fn rewrap_inner_attachment_ignores_forward_to_other_next() {
        // An ordinary forward bound for a different next hop must NOT be peeled.
        let msg = forward_to("did:peer:some_recipient", b"INNER");
        assert!(rewrap_inner_attachment("did:peer:this_mediator", &msg).is_none());
    }

    #[test]
    fn rewrap_inner_attachment_ignores_non_forward() {
        let msg = Message::build(
            "id-2".to_string(),
            "https://didcomm.org/basicmessage/2.0/message".to_string(),
            serde_json::json!({ "content": "hi" }),
        )
        .finalize();
        assert!(rewrap_inner_attachment("did:peer:this_mediator", &msg).is_none());
    }

    #[test]
    fn parse_next_did_extracts_next() {
        let msg = forward_to("did:peer:bob", b"x");
        assert_eq!(
            parse_next_did(&msg, &Session::default()).unwrap(),
            "did:peer:bob"
        );
    }

    #[test]
    fn parse_next_did_rejects_missing_or_unparseable_next() {
        // Body present but no `next` field.
        let no_next = Message::build(
            "id".to_string(),
            "https://didcomm.org/routing/2.0/forward".to_string(),
            serde_json::json!({}),
        )
        .finalize();
        assert!(parse_next_did(&no_next, &Session::default()).is_err());

        // Body that doesn't deserialize into a forward request at all.
        let garbage = Message::build(
            "id".to_string(),
            "https://didcomm.org/routing/2.0/forward".to_string(),
            serde_json::json!({ "next": 12345 }),
        )
        .finalize();
        assert!(parse_next_did(&garbage, &Session::default()).is_err());
    }

    #[test]
    fn relay_sender_acls_grant_only_send_forwarded_on_a_relay() {
        // Relay deployment (global default grants SEND_FORWARDED, e.g. ALLOW_ALL):
        // a sender with no account is checked against SEND_FORWARDED and nothing else — not
        // the LOCAL / RECEIVE / invite / self-manage bits ALLOW_ALL would carry.
        let global = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let acls = relay_sender_acls(&global);
        assert!(
            acls.get_send_forwarded().0,
            "relay sender needs SEND_FORWARDED"
        );
        assert!(!acls.get_local());
        assert!(!acls.get_send_messages().0);
        assert!(!acls.get_receive_messages().0);
        assert!(!acls.get_receive_forwarded().0);
        assert!(!acls.get_create_invites().0);
        assert!(!acls.get_self_manage_list());
        assert!(!acls.get_blocked());
    }

    #[test]
    fn relay_sender_acls_deny_send_forwarded_on_a_non_relay() {
        // Non-relay mediator (shipped secure default lacks SEND_FORWARDED): the
        // sender with no account must NOT gain relay capability, so the forward
        // gate keeps rejecting it exactly as before this change.
        let global =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        let acls = relay_sender_acls(&global);
        assert!(
            !acls.get_send_forwarded().0,
            "non-relay must not grant SEND_FORWARDED"
        );
        assert!(
            !acls.get_local(),
            "must not inherit LOCAL from the global default"
        );
        assert!(
            !acls.get_send_messages().0,
            "must not inherit SEND_MESSAGES"
        );
    }

    /// Build an authorities set the same way `compute_self_authorities`
    /// does — normalizing each host — so tests stay consistent with the
    /// production insertion path. Tests that want to assert the
    /// normalization itself should use `compute_self_authorities_from`.
    fn authorities(entries: &[(&str, u16)]) -> HashSet<(String, u16)> {
        entries
            .iter()
            .map(|(host, port)| (normalize_host(host), *port))
            .collect()
    }

    #[test]
    fn http_url_matches_listen_address_authority() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(uri_points_at_self(
            "http://127.0.0.1:7037/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn https_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn ws_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 80)]);
        assert!(uri_points_at_self("ws://mediator.example.com/ws", &auth));
    }

    #[test]
    fn wss_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self("wss://mediator.example.com/ws", &auth));
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self("https://Mediator.Example.COM/", &auth));
    }

    #[test]
    fn different_host_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self(
            "http://other.mediator.example.com:7037/",
            &auth
        ));
    }

    #[test]
    fn different_port_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self(
            "http://127.0.0.1:8080/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn unparseable_uri_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self("not a url", &auth));
    }

    #[test]
    fn empty_authority_set_never_matches() {
        let auth = authorities(&[]);
        assert!(!uri_points_at_self("http://127.0.0.1:7037/", &auth));
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────

    /// `Url::host_str()` returns IPv6 literals wrapped in brackets
    /// (`"[::1]"`), but `SocketAddr::ip().to_string()` returns them bare
    /// (`"::1"`). Both forms must funnel through `normalize_host` so a
    /// bracketed URL host matches a bare authority key.
    #[test]
    fn ipv6_bracketed_url_matches_bare_authority() {
        let auth = authorities(&[("::1", 7037)]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// And the reverse — a bracketed authority entry (e.g. one already
    /// pre-normalized by the operator) must also match a bracketed URL.
    #[test]
    fn ipv6_bracketed_authority_matches_bracketed_url() {
        let auth = authorities(&[("[::1]", 7037)]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// Full IPv6 address with default https port (no explicit port in URL).
    #[test]
    fn ipv6_full_address_with_default_port_matches() {
        let auth = authorities(&[("2001:db8::1", 443)]);
        assert!(uri_points_at_self(
            "https://[2001:db8::1]/mediator/v1/",
            &auth
        ));
    }

    /// Different IPv6 address must not match.
    #[test]
    fn ipv6_different_address_does_not_match() {
        let auth = authorities(&[("::1", 7037)]);
        assert!(!uri_points_at_self(
            "http://[2001:db8::1]:7037/mediator/v1/",
            &auth
        ));
    }

    // ── URI shape variants — query, path, fragment ──────────────────────

    /// Path components are irrelevant to authority matching.
    #[test]
    fn path_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/very/deep/path/",
            &auth
        ));
    }

    /// Query strings are irrelevant.
    #[test]
    fn query_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/?foo=bar&baz=1",
            &auth
        ));
    }

    /// Fragments are irrelevant.
    #[test]
    fn fragment_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/#section",
            &auth
        ));
    }

    /// Scheme without a known default port (and no explicit port) is rejected.
    #[test]
    fn unknown_scheme_without_explicit_port_does_not_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(!uri_points_at_self(
            "ftp://mediator.example.com/mediator/v1/",
            &auth
        ));
    }

    // ── compute_self_authorities_from integration ──────────────────────

    /// `listen_address` and `local_endpoints` together populate the
    /// authority set with normalized keys.
    #[test]
    fn compute_self_authorities_combines_bind_and_endpoints() {
        let auth = compute_self_authorities_from(
            "127.0.0.1:7037",
            &["https://mediator.example.com".to_string()],
        );
        assert!(auth.contains(&("127.0.0.1".to_string(), 7037)));
        assert!(auth.contains(&("mediator.example.com".to_string(), 443)));
        assert_eq!(auth.len(), 2);
    }

    /// IPv6 listen_address round-trips: a `[::1]`-shaped DID-Doc URI
    /// finds the `"::1"` authority cached from the bind address. This
    /// is the regression test for the IPv6 host-normalization bug.
    #[test]
    fn ipv6_listen_address_round_trips_through_authorities() {
        let auth = compute_self_authorities_from("[::1]:7037", &[]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// Full IPv6 listen_address with operator-declared bracketed alias —
    /// both should normalize to the same key set.
    #[test]
    fn compute_self_authorities_normalizes_ipv6_endpoints() {
        let auth = compute_self_authorities_from(
            "[2001:db8::1]:7037",
            &["http://[2001:db8::1]:7037".to_string()],
        );
        // Single entry — the bracketed endpoint normalizes to match the bind.
        assert_eq!(auth.len(), 1);
        assert!(auth.contains(&("2001:db8::1".to_string(), 7037)));
    }

    /// Malformed `local_endpoints` entries are skipped, not fatal.
    #[test]
    fn compute_self_authorities_skips_malformed_endpoints() {
        let auth = compute_self_authorities_from(
            "127.0.0.1:7037",
            &[
                "not-a-url".to_string(),
                "ftp://no-default-port-known/".to_string(),
                "https://valid.example.com".to_string(),
            ],
        );
        // Only the bind address + the one valid HTTPS endpoint survive.
        assert!(auth.contains(&("127.0.0.1".to_string(), 7037)));
        assert!(auth.contains(&("valid.example.com".to_string(), 443)));
        assert_eq!(auth.len(), 2);
    }

    /// An empty bind + empty endpoints yields an empty authority set,
    /// which by construction never matches anything.
    #[test]
    fn compute_self_authorities_with_empty_inputs_is_empty() {
        let auth = compute_self_authorities_from("", &[]);
        assert!(auth.is_empty());
    }

    const US: &str = "did:web:mediator.example.com";
    const PEER_MEDIATOR: &str =
        "did:webvh:QmYBpFiBnQg9ijbktprYwExth6z4UdCQUzQdCBQbwVWauJ:dids.peer.example:mediator";

    fn no_authorities() -> HashSet<(String, u16)> {
        HashSet::new()
    }

    /// A document with one `DIDCommMessaging` service pointing at `endpoint`,
    /// plus the neighbouring service types a real VTI document carries — so the
    /// type filter is exercised, not assumed.
    fn doc_with_didcomm_endpoint(endpoint: &str) -> Document {
        serde_json::from_value(serde_json::json!({
            "id": "did:web:recipient.example.com",
            "service": [
                {
                    "id": "did:web:recipient.example.com#tsp",
                    "type": "TSPTransport",
                    "serviceEndpoint": PEER_MEDIATOR,
                },
                {
                    "id": "did:web:recipient.example.com#didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": endpoint,
                },
                {
                    "id": "did:web:recipient.example.com#rest",
                    "type": "VTCRest",
                    "serviceEndpoint": "https://recipient.example.com",
                },
            ],
        }))
        .expect("test DID document should deserialize")
    }

    /// The regression: the VTI stack publishes `#didcomm` with the *mediator's
    /// DID* as its `serviceEndpoint`. That has to classify as indirection to
    /// follow, not as an unrecognised URI — which is what silently collapsed
    /// every cross-mediator forward to local storage.
    #[test]
    fn classify_endpoint_treats_a_did_endpoint_as_indirection() {
        assert_eq!(
            classify_endpoint(PEER_MEDIATOR, US, &no_authorities()),
            Some(EndpointHop::Indirect(PEER_MEDIATOR.to_string()))
        );
    }

    /// And it must survive the trip through `Endpoint` deserialization —
    /// a DID parses as a `Url` (scheme `did`, cannot-be-a-base), so the DID
    /// handed to the follow-up resolve has to come back byte-identical.
    #[test]
    fn a_did_endpoint_round_trips_through_the_document() {
        let doc = doc_with_didcomm_endpoint(PEER_MEDIATOR);
        let endpoints = didcomm_endpoints(&doc);
        assert_eq!(endpoints, vec![PEER_MEDIATOR.to_string()]);
        assert_eq!(
            classify_endpoint(&endpoints[0], US, &no_authorities()),
            Some(EndpointHop::Indirect(PEER_MEDIATOR.to_string()))
        );
    }

    #[test]
    fn classify_endpoint_keeps_our_own_did_local() {
        assert_eq!(
            classify_endpoint(US, US, &no_authorities()),
            Some(EndpointHop::Local)
        );
    }

    #[test]
    fn a_relay_on_the_forwarding_block_list_is_refused() {
        let blocked: ahash::AHashSet<String> = [
            "did:example:mediator".to_string(),
            "https://mediator.example/api".to_string(),
            "did:example:blocked".to_string(),
        ]
        .into_iter()
        .collect();
        let hop = |endpoint: &str, relay_to: &str| RemoteHop {
            endpoint: endpoint.to_string(),
            relay_to: relay_to.to_string(),
        };

        // Our own published endpoint, quoted or not.
        assert!(blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("https://mediator.example/api", "did:example:bob")
        ));
        assert!(blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("\"https://mediator.example/api\"", "did:example:bob")
        ));
        // A blocked mediator named by the next hop's document.
        assert!(blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("https://other.example", "did:example:blocked")
        ));
        // A blocked next hop.
        assert!(blocked_relay(
            &blocked,
            "did:example:blocked",
            &hop("https://other.example", "did:example:blocked")
        ));
        // Another spelling of a listed endpoint or DID.
        assert!(blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("HTTPS://Mediator.EXAMPLE:443/api", "did:example:bob")
        ));
        assert!(blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("https://mediator.example./api#x", "did:example:bob")
        ));
        assert!(blocked_relay(
            &blocked,
            "DID:Example:blocked#key-1",
            &hop("https://other.example", "did:example:bob")
        ));
        // Anything else relays.
        assert!(!blocked_relay(
            &blocked,
            "did:example:bob",
            &hop("https://other.example", "did:example:bob")
        ));
    }

    #[test]
    fn classify_endpoint_relays_a_foreign_url() {
        assert_eq!(
            classify_endpoint("https://peer.example.com/inbound", US, &no_authorities()),
            Some(EndpointHop::Remote(
                "https://peer.example.com/inbound".to_string()
            ))
        );
    }

    /// A URL that points back at this instance under another name is local, so
    /// the mediator never relays to itself through FORWARD_Q.
    #[test]
    fn classify_endpoint_keeps_a_self_authority_url_local() {
        let authorities =
            compute_self_authorities_from("0.0.0.0:7037", &["https://us.example.com".to_string()]);
        assert_eq!(
            classify_endpoint("https://us.example.com/inbound", US, &authorities),
            Some(EndpointHop::Local)
        );
    }

    /// Quoted URIs (the `Endpoint::Map` serialization shape) classify the same
    /// as bare ones.
    #[test]
    fn classify_endpoint_strips_json_quoting() {
        assert_eq!(
            classify_endpoint("\"https://peer.example.com\"", US, &no_authorities()),
            Some(EndpointHop::Remote("https://peer.example.com".to_string()))
        );
    }

    #[test]
    fn classify_endpoint_has_no_rule_for_other_shapes() {
        assert_eq!(classify_endpoint("not-a-url", US, &no_authorities()), None);
        assert_eq!(
            classify_endpoint("ftp://files.example.com", US, &no_authorities()),
            None
        );
    }

    /// The type filter keys on `DIDCommMessaging` only — a `TSPTransport`
    /// entry naming a mediator must not be mistaken for a DIDComm endpoint.
    #[test]
    fn didcomm_endpoints_selects_only_didcomm_services() {
        let doc = doc_with_didcomm_endpoint("https://peer.example.com");
        assert_eq!(
            didcomm_endpoints(&doc),
            vec!["https://peer.example.com/".to_string()]
        );
    }

    #[test]
    fn didcomm_endpoints_is_empty_without_a_didcomm_service() {
        let doc: Document = serde_json::from_value(serde_json::json!({
            "id": "did:web:recipient.example.com",
            "service": [{
                "id": "did:web:recipient.example.com#rest",
                "type": "VTCRest",
                "serviceEndpoint": "https://recipient.example.com",
            }],
        }))
        .expect("test DID document should deserialize");
        assert!(didcomm_endpoints(&doc).is_empty());
    }
}
