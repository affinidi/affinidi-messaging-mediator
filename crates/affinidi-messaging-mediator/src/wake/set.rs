//! `messaging/wake/set/0.1`: an account gives this mediator its wake handle,
//! or takes it back.

use affinidi_messaging_mediator_common::errors::MediatorError;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use super::WakeRecord;
use crate::SharedData;
use crate::common::authz::{self, Capability};
use crate::common::session::Session;
use crate::messages::protocols::trust_tasks::{
    build, serialize_err, tt_problem, validate_tt_basic,
};
use crate::task_specs::messaging::wake::set::v0_1 as wake_set;

/// Handle `messaging/wake/set`: replace the handle held for the requester's
/// own account, or remove it.
///
/// The account is the session's — the transport-authenticated sender, which
/// [`consume`](crate::messages::protocols::trust_tasks::consume) has already
/// required to be the session DID — never anything the payload names
/// (Consumer rule 2). `local` is required, as for the account's other queue
/// operations.
///
/// `wakeCapable: true` only when a handle is now held and this mediator will
/// ring it: waking is enabled here and the gateway is a DID this mediator can
/// reach (it advertises a `DIDCommMessaging` service, the transport the
/// mediator rings over). Otherwise nothing is held and the answer is `false`
/// (Consumer rule 4).
pub(crate) async fn consume_wake_set(
    typed: TrustTask<wake_set::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    if authz::require_capability(&session.acls, Capability::Local).is_err() {
        return Err(tt_problem(
            session,
            "authorization.local",
            "the account is not local to this mediator".into(),
            StatusCode::FORBIDDEN,
        ));
    }
    let account = session.did_hash.as_str();

    let record = match typed.payload.wake_handle.as_ref() {
        Some(handle) if state.config.processors.wake.enabled => {
            let gateway = handle.gateway.to_string();
            gateway_reachable(state, &gateway)
                .await
                .then(|| WakeRecord {
                    gateway,
                    handle: handle.handle.to_string(),
                    not_allowed: false,
                })
        }
        _ => None,
    };
    let wake_capable = match &record {
        Some(record) => {
            record.save(state, account).await?;
            true
        }
        // Absence clears: the restrictive reading (spec, Definitions).
        None => {
            state.database.wake_handle_set(account, None).await?;
            false
        }
    };

    let response: wake_set::Response =
        build(wake_set::Response::builder().wake_capable(wake_capable))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Whether this mediator can send `push/wake` to `gateway`: a DID whose
/// document advertises `DIDCommMessaging` and resolves now. A gateway named by
/// URL is refused: the mediator does not ring over HTTPS.
async fn gateway_reachable(state: &SharedData, gateway: &str) -> bool {
    #[cfg(feature = "didcomm")]
    {
        if !gateway.starts_with("did:") {
            return false;
        }
        match state.did_resolver.resolve(gateway).await {
            Ok(resolved) => {
                !crate::messages::protocols::routing::didcomm_endpoints(&resolved.doc).is_empty()
                    && !resolved.doc.key_agreement.is_empty()
            }
            Err(e) => {
                tracing::debug!(%gateway, error = %e, "wake gateway does not resolve");
                false
            }
        }
    }
    // Ringing is a DIDComm send; a build without DIDComm cannot ring.
    #[cfg(not(feature = "didcomm"))]
    {
        let _ = (state, gateway);
        false
    }
}
