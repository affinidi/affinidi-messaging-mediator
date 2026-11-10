//! Audit records for DID multiplexing (specs `messaging/mux/revoke` rule 7,
//! `revoke-all`, and the unknown-key rule in `messaging/mux/grant`).
//!
//! Written after the change is committed and its members detached, like
//! every other audit entry, and best-effort: a failure to record is logged
//! and never turns a completed change into an error (see
//! `messages::protocols::mediator::record_audit`).

use affinidi_messaging_mediator_common::store::mux::MuxGrant;
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
use serde_json::Value;
use tracing::warn;

use super::session::LeaveReason;
use super::tasks::Changed;
use crate::SharedData;

/// What fired the unknown-key rule, for the audit detail.
#[derive(Clone, Copy, Debug)]
pub enum SuspendedBy {
    /// A `messaging/mux/grant` or `attach` statement signed with a key the
    /// member's active grants do not know.
    Statement,
    /// A direct DIDComm authentication with an unknown key-agreement key.
    DirectKeyAgreement,
    /// A direct TSP authentication with an unknown signing key.
    DirectSigning,
}

impl SuspendedBy {
    fn detail(self) -> &'static str {
        match self {
            SuspendedBy::Statement => "a statement signed with a key its active grants do not list",
            SuspendedBy::DirectKeyAgreement => {
                "a direct DIDComm authentication with a key-agreement key its active grants do not list"
            }
            SuspendedBy::DirectSigning => {
                "a direct TSP authentication with a signing key its active grants do not list"
            }
        }
    }
}

async fn record(
    state: &SharedData,
    actor: &str,
    target: &str,
    action: AuditAction,
    detail: String,
) {
    let entry = AuditLogEntry {
        timestamp: state.clock.unix_secs(),
        actor_did_hash: actor.to_string(),
        target_did_hash: target.to_string(),
        action,
        detail,
    };
    if let Err(e) = state.database.audit_log_record(&entry).await {
        warn!(?action, target, "Failed to record audit-log entry: {e}");
    }
}

/// One entry per grant the unknown-key rule suspended. The actor is the
/// member DID whose key fired the rule; the target is the principal that
/// lost the grant.
pub async fn suspended(state: &SharedData, grants: &[MuxGrant], by: SuspendedBy) {
    for g in grants {
        record(
            state,
            &g.did_hash,
            &g.principal_hash,
            AuditAction::MuxGrantSuspend,
            format!("grant {} suspended: {}", g.grant_id, by.detail()),
        )
        .await;
    }
}

/// One entry per grant a `messaging/mux/revoke` removed. The actor is the
/// party that revoked (`sender_hash`); the target is the other party.
pub async fn revoked(state: &SharedData, sender_hash: &str, changed: &Changed) {
    let by_principal = changed.reason == Some(LeaveReason::RevokedByPrincipal);
    for g in &changed.removed {
        let (target, side) = if by_principal {
            (&g.did_hash, "principal")
        } else {
            (&g.principal_hash, "member")
        };
        record(
            state,
            sender_hash,
            target,
            AuditAction::MuxGrantRevoke,
            format!("grant {} revoked by its {side}", g.grant_id),
        )
        .await;
    }
}

/// One entry for a `messaging/mux/revoke-all` that advanced the member's
/// epoch, read from its response. One that changed nothing is not recorded.
pub async fn revoked_all(state: &SharedData, sender_hash: &str, response: &Value) {
    if response.get("epochAdvanced").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let Some(did) = response.get("did").and_then(Value::as_str) else {
        return;
    };
    let epoch = response.get("epoch").and_then(Value::as_u64).unwrap_or(0);
    let voided = response
        .get("revokedGrants")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    record(
        state,
        sender_hash,
        &affinidi_messaging_mediator_common::did_identity::did_hash(did),
        AuditAction::MuxRevokeAll,
        format!("epoch advanced to {epoch}; {voided} grants voided"),
    )
    .await;
}
