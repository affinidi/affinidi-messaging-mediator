//! `messaging/wake/request/0.1`: a sender that has just queued mail for an
//! account asks this mediator to ring the account's device.
//!
//! [`handle`] runs the checks that may be answered with an error — the
//! document, its proof, the requester's own inbound rate — and returns the
//! one answer every accepted request gets, `{}`. Whether to ring is decided
//! afterwards, off the request's path ([`evaluate`]), so neither the answer
//! nor its timing depends on any rule about the addressee
//! (`messaging/wake/request/0.1` "The answer").
//!
//! [`evaluate`] rings only when all seven rules hold:
//!
//! 1. the addressee is an account here with a wake handle set (and the
//!    gateway has not refused this mediator);
//! 2. every named id is a message queued for the addressee, not yet
//!    delivered, stored within [`MAX_MESSAGE_AGE_SECS`];
//! 3. where a stored envelope reveals its sender (the DIDComm authcrypt
//!    `skid`), it is the requester;
//! 4. the addressee's access list does not refuse the requester;
//! 5. the addressee has no live delivery connection;
//! 6. no named message has rung before;
//! 7. the per-(requester, addressee) and per-addressee limits allow it.
//!
//! A request naming a message not stored yet is armed for [`ARM_SECS`] and
//! evaluated again when that message is stored ([`on_stored`]) or by the
//! periodic sweep ([`rearm_loop`]).

use affinidi_messaging_mediator_common::did_identity::{did_hash, same_account};
use affinidi_messaging_mediator_common::errors::MediatorError;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;
use serde_json::Value;
use trust_tasks_rs::{SpecPolicy, TrustTask};
use uuid::Uuid;

use super::{ARM_SECS, Armed, MAX_MESSAGE_AGE_SECS, WakeRecord, WakeRequest, count_outcome};
use crate::SharedData;
use crate::common::session::Session;
use crate::messages::protocols::trust_task_verify;
use crate::messages::protocols::trust_tasks::{
    serialize_err, tt_problem, validate_tt_basic, vid_of,
};
use crate::task_specs::messaging::wake::request::v0_1 as wake_request;

/// The request's type URI.
pub(crate) const REQUEST_TYPE: &str = <wake_request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// How often armed requests are evaluated again, for a message another
/// instance stored.
const REARM_INTERVAL_SECS: u64 = 5;

/// Accept one `messaging/wake/request` from `sender_did` and return the
/// answer, unsigned: always the same empty `#response`.
///
/// `sender_did` MUST be the transport-authenticated sender (the DIDComm
/// authcrypt or JWS sender, or the TSP sender). `charge_rate` says the sender
/// was not charged to the per-DID inbound limiter on the way in — it holds no
/// session here — so it is charged now (`messaging/wake/request/0.1`
/// "Receiving the request").
///
/// Every error returned is decided before the addressee is looked up: the
/// document, the proof, the requester's own rate. They reveal nothing about
/// the addressee.
pub(crate) async fn handle(
    state: &SharedData,
    session: &Session,
    doc: TrustTask<Value>,
    raw: &Value,
    sender_did: &str,
    charge_rate: bool,
) -> Result<Value, MediatorError> {
    let sender = vid_of(sender_did);
    let now_secs = state.clock.unix_secs();
    let now = chrono::DateTime::from_timestamp(now_secs as i64, 0).unwrap_or_else(chrono::Utc::now);

    if charge_rate
        && state
            .did_rate_limiter
            .try_acquire(&did_hash(&sender))
            .is_err()
    {
        count_outcome("requester_rate_limited");
        return Err(tt_problem(
            session,
            // The framework's retryable refusal; it has no rate-limit code.
            "unavailable",
            "too many requests from this sender".into(),
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }

    // §7.2, enforced whatever `security.trust_task_verification` says: the
    // verified proof is what names the requester the rules act for.
    trust_task_verify::accept_strict(
        &doc,
        raw,
        SpecPolicy::of::<wake_request::Payload>(),
        &sender,
        now,
        state,
        session,
    )
    .await?;
    if !proves_authentication(raw) {
        return Err(tt_problem(
            session,
            "proofInvalid",
            "a wake request's proof must have proofPurpose authentication".into(),
            StatusCode::FORBIDDEN,
        ));
    }
    let typed: TrustTask<wake_request::Payload> =
        serde_json::from_value(raw.clone()).map_err(|e| {
            tt_problem(
                session,
                "malformedRequest",
                format!("payload does not match the task type: {e}"),
                StatusCode::BAD_REQUEST,
            )
        })?;
    validate_tt_basic(&typed, session, &state.config.mediator_did, now)?;

    let request = WakeRequest {
        requester_hash: did_hash(&sender),
        requester: sender,
        addressee_hash: did_hash(typed.payload.addressee.as_str()),
        msg_ids: typed
            .payload
            .msg_ids
            .iter()
            .map(|id| id.to_string())
            .collect(),
        urgency: typed.payload.urgency.map(|u| u.to_string()),
    };

    // Decided off the request's path: the answer below is the same, at the
    // same point, whatever the rules find.
    let st = state.clone();
    tokio::spawn(async move {
        let outcome = evaluate(&st, request, None).await;
        count_outcome(outcome.label());
    });

    let response = typed.respond_with(
        Uuid::new_v4().to_string(),
        wake_request::Response::default(),
    );
    serde_json::to_value(response).map_err(serialize_err)
}

/// Whether the document's proof (or one in its proof set) was made for
/// `authentication`, as the producer rule requires.
fn proves_authentication(raw: &Value) -> bool {
    let is_auth =
        |p: &Value| p.get("proofPurpose").and_then(Value::as_str) == Some("authentication");
    match raw.get("proof") {
        Some(Value::Array(proofs)) => proofs.iter().any(is_auth),
        Some(proof) => is_auth(proof),
        None => false,
    }
}

/// What became of one request. Only ever a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Rung,
    Armed,
    ArmExpired,
    ArmFull,
    Disabled,
    NoAccount,
    NoHandle,
    GatewayRefused,
    NotQueued,
    Delivered,
    Stale,
    ForeignSender,
    Blocked,
    Online,
    AlreadyRung,
    Limited(super::limits::Limited),
    RingFailed,
    Error,
}

impl Outcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Outcome::Rung => "rung",
            Outcome::Armed => "armed",
            Outcome::ArmExpired => "arm_expired",
            Outcome::ArmFull => "arm_full",
            Outcome::Disabled => "disabled",
            Outcome::NoAccount => "no_account",
            Outcome::NoHandle => "no_handle",
            Outcome::GatewayRefused => "gateway_refused",
            Outcome::NotQueued => "not_queued",
            Outcome::Delivered => "delivered",
            Outcome::Stale => "stale",
            Outcome::ForeignSender => "foreign_sender",
            Outcome::Blocked => "blocked",
            Outcome::Online => "online",
            Outcome::AlreadyRung => "already_rung",
            Outcome::Limited(l) => l.label(),
            Outcome::RingFailed => "ring_failed",
            Outcome::Error => "error",
        }
    }
}

/// Apply the seven rules to `request` and ring when they all hold.
///
/// `arm_deadline` is `None` for a request seen for the first time — it may be
/// armed for [`ARM_SECS`] — and the original deadline for one evaluated again,
/// which is never extended.
pub(crate) async fn evaluate(
    state: &SharedData,
    request: WakeRequest,
    arm_deadline: Option<u64>,
) -> Outcome {
    match evaluate_inner(state, &request, arm_deadline).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(error = %e, "wake request not evaluated: the store failed");
            Outcome::Error
        }
    }
}

async fn evaluate_inner(
    state: &SharedData,
    request: &WakeRequest,
    arm_deadline: Option<u64>,
) -> Result<Outcome, MediatorError> {
    let config = &state.config.processors.wake;
    if !config.enabled {
        return Ok(Outcome::Disabled);
    }
    let to = request.addressee_hash.as_str();
    let now = state.clock.unix_secs();

    // 1. A wakeable account.
    if !state.database.account_exists(to).await? {
        return Ok(Outcome::NoAccount);
    }
    let Some(record) = WakeRecord::load(state, to).await? else {
        return Ok(Outcome::NoHandle);
    };
    if record.not_allowed {
        return Ok(Outcome::GatewayRefused);
    }

    // 4. Not blocked. Before the messages are read: a refused requester
    // learns nothing either way, and it costs one lookup instead of eight.
    if !state
        .database
        .access_list_allowed(to, Some(&request.requester_hash))
        .await
    {
        return Ok(Outcome::Blocked);
    }

    // 2 and 3. Queued, fresh, undelivered mail from the requester.
    let now_ms = state.clock.unix_millis();
    let mut missing = false;
    for id in &request.msg_ids {
        let Some(delivery) = state.database.delivery_state(to, id).await? else {
            missing = true;
            continue;
        };
        if delivery.first_delivered_at_ms.is_some() {
            return Ok(Outcome::Delivered);
        }
        let Some(stored) = state.database.get_message(to, id).await? else {
            missing = true;
            continue;
        };
        if stored
            .to_address
            .as_deref()
            .is_some_and(|held_for| held_for != to)
        {
            return Ok(Outcome::NotQueued);
        }
        if now_ms.saturating_sub(u128::from(stored.timestamp))
            > u128::from(MAX_MESSAGE_AGE_SECS) * 1000
        {
            return Ok(Outcome::Stale);
        }
        if let Some(sender) = stored.msg.as_deref().and_then(revealed_sender)
            && !same_account(&sender, &request.requester)
        {
            return Ok(Outcome::ForeignSender);
        }
    }
    if missing {
        let deadline = arm_deadline.unwrap_or(now + ARM_SECS);
        if now >= deadline {
            return Ok(Outcome::ArmExpired);
        }
        let armed = state.wake.arm(Armed {
            request: request.clone(),
            deadline,
        });
        return Ok(if armed {
            Outcome::Armed
        } else {
            Outcome::ArmFull
        });
    }

    // 5. Not online: a live connection is streamed the mail instead.
    if state
        .database
        .streaming_is_client_live(to, false)
        .await
        .is_some()
    {
        return Ok(Outcome::Online);
    }

    // 6. Not rung before. The store's duplicate-execution record is atomic
    // across instances, so two requests naming one message ring once. Kept
    // until the message is too old to ring for anyway.
    let retain_until = now + MAX_MESSAGE_AGE_SECS + 60;
    for id in &request.msg_ids {
        let key = sha256::digest(format!("wake-rung\n{to}\n{id}"));
        match state
            .database
            .trust_task_claim(&key, "rung", retain_until, now)
            .await?
        {
            affinidi_messaging_mediator_common::store::TrustTaskClaim::Fresh => {}
            _ => return Ok(Outcome::AlreadyRung),
        }
    }

    // 7. Within limits.
    if let Err(limited) = state
        .wake
        .limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .try_ring(config, &request.requester_hash, to, now)
    {
        return Ok(Outcome::Limited(limited));
    }

    ring(state, request, &record).await
}

/// The sender a stored DIDComm envelope reveals: the authcrypt `skid` in its
/// protected header, as a DID. `None` for anything that reveals none (an
/// anoncrypt or nested envelope, a TSP message), where holding the id is the
/// binding (rule 3).
pub(crate) fn revealed_sender(stored: &str) -> Option<String> {
    let envelope: Value = serde_json::from_str(stored).ok()?;
    let protected = envelope.get("protected")?.as_str()?;
    let header: Value =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(protected).ok()?).ok()?;
    let skid = header.get("skid")?.as_str()?;
    Some(vid_of(skid))
}

/// A message `msg_id` was stored for `to_did_hash`: evaluate any armed
/// request waiting for it.
pub(crate) fn on_stored(state: &SharedData, to_did_hash: &str, msg_id: &str) {
    for armed in state.wake.take_matching(to_did_hash, msg_id) {
        let st = state.clone();
        tokio::spawn(async move {
            let outcome = evaluate(&st, armed.request, Some(armed.deadline)).await;
            count_outcome(outcome.label());
        });
    }
}

/// Evaluate every armed request again every few seconds, so one whose message
/// another instance stored still rings, and one whose deadline passed is
/// dropped.
pub(crate) async fn rearm_loop(state: SharedData, shutdown: tokio_util::sync::CancellationToken) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(REARM_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        let now = state.clock.unix_secs();
        for armed in state.wake.take_all() {
            let outcome = if now >= armed.deadline {
                Outcome::ArmExpired
            } else {
                evaluate(&state, armed.request, Some(armed.deadline)).await
            };
            // A request still waiting was counted when it was first armed.
            if outcome != Outcome::Armed {
                count_outcome(outcome.label());
            }
        }
    }
}

/// Ring: send `push/wake/0.2` to the handle's gateway, as this mediator.
#[cfg(feature = "didcomm")]
async fn ring(
    state: &SharedData,
    request: &WakeRequest,
    record: &WakeRecord,
) -> Result<Outcome, MediatorError> {
    match super::ring::send(
        state,
        &request.addressee_hash,
        record,
        request.urgency.as_deref(),
    )
    .await
    {
        Ok(()) => Ok(Outcome::Rung),
        Err(e) => {
            tracing::warn!(gateway = %record.gateway, error = %e, "wake ring not sent");
            Ok(Outcome::RingFailed)
        }
    }
}

/// A build without DIDComm has no way to ring.
#[cfg(not(feature = "didcomm"))]
async fn ring(
    _state: &SharedData,
    _request: &WakeRequest,
    _record: &WakeRecord,
) -> Result<Outcome, MediatorError> {
    Ok(Outcome::Disabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwe_with(header: Value) -> String {
        json!({
            "protected": BASE64_URL_SAFE_NO_PAD.encode(header.to_string()),
            "recipients": [],
            "iv": "", "ciphertext": "", "tag": "",
        })
        .to_string()
    }

    #[test]
    fn an_authcrypt_envelope_reveals_its_sender_as_a_did() {
        let stored = jwe_with(json!({"alg": "ECDH-1PU+A256KW", "skid": "did:example:w#key-2"}));
        assert_eq!(revealed_sender(&stored).as_deref(), Some("did:example:w"));
    }

    #[test]
    fn an_anoncrypt_envelope_reveals_nothing() {
        let stored = jwe_with(json!({"alg": "ECDH-ES+A256KW"}));
        assert_eq!(revealed_sender(&stored), None);
    }

    #[test]
    fn a_non_json_body_reveals_nothing() {
        assert_eq!(revealed_sender("-EABXAAA"), None);
    }

    #[test]
    fn only_an_authentication_proof_will_do() {
        assert!(proves_authentication(
            &json!({"proof": {"proofPurpose": "authentication"}})
        ));
        assert!(!proves_authentication(
            &json!({"proof": {"proofPurpose": "assertionMethod"}})
        ));
        assert!(proves_authentication(&json!({"proof": [
            {"proofPurpose": "assertionMethod"},
            {"proofPurpose": "authentication"},
        ]})));
        assert!(!proves_authentication(&json!({})));
    }
}
