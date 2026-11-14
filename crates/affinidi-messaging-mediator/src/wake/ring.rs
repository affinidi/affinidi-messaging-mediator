//! Ringing: `push/wake/0.2` to the account's gateway, as this mediator, and
//! acting on the gateway's answer (`messaging/wake/request/0.1` "Ringing";
//! `messaging/wake/set/0.1` Consumer rule 6).
//!
//! The ring goes over DIDComm, authcrypted from this mediator to the gateway
//! and delivered where the gateway's DID document says it collects its mail
//! ([`send_as_mediator`]). The gateway authenticates this mediator by the
//! document's Data Integrity proof (`proofPurpose: authentication`) and rings
//! only when this mediator is on the handle's allowlist. Its answer comes back
//! as an ordinary DIDComm message to this mediator, threaded to the ring, and
//! is read by [`receive_answer`].
//!
//! [`send_as_mediator`]: crate::messages::protocols::routing::send_as_mediator

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use serde_json::Value;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use super::{PENDING_RING_SECS, PendingRing, WakeRecord};
use crate::SharedData;
use crate::messages::protocols::trust_task_sign::signing_secret;
use crate::messages::protocols::trust_tasks::{ENVELOPE_TYPE, build};
use crate::task_specs::push::wake::v0_2 as push_wake;

/// The `push/wake` request type URI.
pub(crate) const PUSH_WAKE_TYPE: &str = <push_wake::Payload as trust_tasks_rs::Payload>::TYPE_URI;

fn internal(message: String) -> MediatorError {
    MediatorError::InternalError(crate::error_codes::INTERNAL_ERROR, "NA".into(), message)
}

/// Count a ring's outcome. Aggregate only.
pub(crate) fn count_ring(outcome: &'static str) {
    metrics::counter!(
        crate::common::metrics::names::WAKE_RINGS_TOTAL,
        "outcome" => outcome
    )
    .increment(1);
}

/// The signed `push/wake/0.2` document for `record`: the handle, `v: 1`, this
/// mediator as `mediator`, and `urgency` when the request carried one —
/// nothing else (push binding §2).
pub(crate) async fn push_wake_document(
    state: &SharedData,
    record: &WakeRecord,
    urgency: Option<&str>,
) -> Result<Value, MediatorError> {
    let mediator_did = &state.config.mediator_did;
    let urgency: Option<push_wake::PayloadUrgency> =
        urgency.and_then(|u| serde_json::from_value(Value::String(u.to_string())).ok());
    let payload: push_wake::Payload = build(
        push_wake::Payload::builder()
            .handle(record.handle.as_str())
            .v(1)
            .mediator(Some(mediator_did.clone()))
            .urgency(urgency),
    )?;
    let mut task = TrustTask::for_payload(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    task.issuer = Some(mediator_did.clone());
    task.recipient = Some(record.gateway.clone());
    task.issued_at = chrono::DateTime::from_timestamp(state.clock.unix_secs() as i64, 0);
    let doc = serde_json::to_value(&task).map_err(|e| internal(format!("push/wake: {e}")))?;

    // The gateway authenticates a trigger by the proof alone, so an unsigned
    // ring is one it refuses: no key, no ring.
    let secret = signing_secret(state).await.ok_or_else(|| {
        internal("the mediator DID has no Ed25519 signing key to ring with".into())
    })?;
    sign_trust_task(&doc, &secret, SignOptions::new())
        .await
        .map_err(|e| internal(format!("couldn't sign push/wake: {e}")))
}

/// Send one ring for the account `addressee_hash`.
pub(crate) async fn send(
    state: &SharedData,
    addressee_hash: &str,
    record: &WakeRecord,
    urgency: Option<&str>,
) -> Result<(), MediatorError> {
    let mediator_did = &state.config.mediator_did;
    let now = state.clock.unix_secs();
    let doc = push_wake_document(state, record, urgency).await?;
    let ring_id = doc
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let msg = Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_string(), doc)
        .to(record.gateway.clone())
        .from(mediator_did.clone())
        .created_time(now)
        .expires_time(now + PENDING_RING_SECS)
        .finalize();
    let (packed, _) = crate::didcomm_compat::pack_encrypted(
        &msg,
        &record.gateway,
        Some(mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|e| internal(format!("couldn't pack push/wake: {e}")))?;

    state.wake.await_answer(
        ring_id.clone(),
        PendingRing {
            addressee_hash: addressee_hash.to_string(),
            gateway: record.gateway.clone(),
            handle: record.handle.clone(),
            expires: now + PENDING_RING_SECS,
        },
        now,
    );
    match crate::messages::protocols::routing::send_as_mediator(
        state,
        &record.gateway,
        &packed,
        now + PENDING_RING_SECS,
    )
    .await
    {
        Ok(()) => {
            count_ring("sent");
            Ok(())
        }
        Err(e) => {
            state
                .wake
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&ring_id);
            count_ring("send_failed");
            Err(e)
        }
    }
}

/// What a gateway's answer to a ring says about the handle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Rung, or failed in a way that says nothing about the handle.
    Kept,
    /// `tokenUnregistered`: the device's token is dead and the gateway has
    /// dropped it. The handle goes too.
    Dead,
    /// `notAllowed`: this mediator is not on the handle's allowlist. Not rung
    /// again until the account sets a handle.
    NotAllowed,
}

/// Read a gateway's answer document.
pub(crate) fn verdict(answer: &Value) -> Verdict {
    let ty = answer
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payload = answer.get("payload");
    if ty == format!("{PUSH_WAKE_TYPE}#response") {
        let status = payload
            .and_then(|p| p.get("status"))
            .and_then(Value::as_str);
        return if status == Some("tokenUnregistered") {
            Verdict::Dead
        } else {
            Verdict::Kept
        };
    }
    if ty.starts_with("https://trusttasks.org/spec/trust-task-error/") {
        let code = payload
            .and_then(|p| p.get("code"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        // The spec names it `push/wake:notAllowed`; a gateway that answers
        // with the framework's generic refusal means the same thing.
        if code.ends_with("notAllowed") || code == "permissionDenied" {
            return Verdict::NotAllowed;
        }
    }
    Verdict::Kept
}

/// Act on `answer`, which `sender` sent threaded to a ring this mediator is
/// awaiting. Anything else is ignored.
pub(crate) async fn receive_answer(state: &SharedData, sender: &str, answer: &Value) {
    let Some(thread) = answer.get("threadId").and_then(Value::as_str) else {
        return;
    };
    let Some(ring) = state
        .wake
        .take_answered(thread, sender, state.clock.unix_secs())
    else {
        return;
    };
    let verdict = verdict(answer);
    count_ring(match verdict {
        Verdict::Kept => "answered",
        Verdict::Dead => "token_unregistered",
        Verdict::NotAllowed => "not_allowed",
    });
    if verdict == Verdict::Kept {
        return;
    }
    // Only the handle that was rung: a handle the account set since is not
    // the one the gateway is talking about.
    let current = match WakeRecord::load(state, &ring.addressee_hash).await {
        Ok(Some(record)) if record.handle == ring.handle && record.gateway == ring.gateway => {
            record
        }
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "wake handle not updated after the gateway's answer");
            return;
        }
    };
    let result = match verdict {
        Verdict::Dead => {
            state
                .database
                .wake_handle_set(&ring.addressee_hash, None)
                .await
        }
        _ => {
            WakeRecord {
                not_allowed: true,
                ..current
            }
            .save(state, &ring.addressee_hash)
            .await
        }
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "wake handle not updated after the gateway's answer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn delivered_keeps_the_handle() {
        let answer = json!({
            "type": format!("{PUSH_WAKE_TYPE}#response"),
            "payload": {"status": "delivered"},
        });
        assert_eq!(verdict(&answer), Verdict::Kept);
    }

    #[test]
    fn token_unregistered_drops_it() {
        let answer = json!({
            "type": format!("{PUSH_WAKE_TYPE}#response"),
            "payload": {"status": "tokenUnregistered"},
        });
        assert_eq!(verdict(&answer), Verdict::Dead);
    }

    #[test]
    fn not_allowed_stops_ringing_it() {
        for code in ["push/wake:notAllowed", "permissionDenied"] {
            let answer = json!({
                "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                "payload": {"code": code},
            });
            assert_eq!(verdict(&answer), Verdict::NotAllowed, "{code}");
        }
    }

    #[test]
    fn another_failure_keeps_it() {
        let answer = json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "payload": {"code": "taskFailed"},
        });
        assert_eq!(verdict(&answer), Verdict::Kept);
    }
}
