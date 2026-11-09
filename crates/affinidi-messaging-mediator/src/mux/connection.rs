//! The socket side of a mux connection: opening it, reporting member changes
//! to the client as `messaging/mux/event` documents, the expiry and key
//! re-validation sweeps, and teardown.
//!
//! Kept out of `handlers/websocket.rs` on purpose: the socket loop calls a
//! handful of functions here and writes the frames they return, so the mux
//! logic is testable and the hot loop's control flow barely changes.
//!
//! DIDComm only for now. A mux connection is negotiated with the
//! [`MUX_SUBPROTOCOL`] WebSocket subprotocol (a provisional name; how a
//! DIDComm socket becomes a mux connection is still open in the design, §12a).
//! Raw TSP (`tsp-mux`, design §4.10) follows.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use affinidi_messaging_mediator_common::store::mux::MuxCapability;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use super::grants::Ctx;
use super::proof::StatementVerifier;
use super::registry::MuxConn;
use super::session::{LeaveReason, MuxMember, MuxSession, MuxSource};
use crate::SharedData;
use crate::common::session::Session;
use crate::tasks::websocket_streaming::{MemberChange, QueuedCommand};

/// WebSocket subprotocol a DIDComm client offers to open a mux connection.
pub const MUX_SUBPROTOCOL: &str = "affinidi-mux";

/// `messaging/mux/event` type URI.
const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn ctx<'a>(state: &'a SharedData, verifier: &'a StatementVerifier) -> Ctx<'a> {
    Ctx {
        store: &*state.database,
        verifier,
        mediator_did: &state.config.mediator_did,
        limits: state.config.limits.mux.store_limits(),
        default_acl: &state.config.security.global_acl_default,
        now: state.clock.unix_secs(),
    }
}

/// A `MemberChange` (spec) entry.
fn change(member: &MuxMember, reason: &str, delivery_active: Option<bool>) -> Value {
    let mut v = json!({
        "did": member.did,
        "reason": reason,
        "scope": member.scope,
        "expiresAt": rfc3339(member.expires_at),
    });
    if let MuxSource::Grant { grant_id } = &member.source {
        v["grantId"] = json!(grant_id);
    }
    if let Some(a) = delivery_active {
        v["deliveryActive"] = json!(a);
    }
    v
}

/// Sign a `messaging/mux/event` payload as the mediator and pack it to the
/// principal, ready to write to the socket.
#[cfg(feature = "didcomm")]
pub async fn pack_event(state: &SharedData, principal_did: &str, payload: Value) -> Option<String> {
    use affinidi_messaging_didcomm::message::Message;
    let mediator_did = &state.config.mediator_did;
    let now = state.clock.unix_secs();
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": EVENT_TYPE,
        "issuer": mediator_did,
        "recipient": principal_did,
        "issuedAt": rfc3339(now),
        "payload": payload,
    });
    let signed = match crate::messages::protocols::trust_task_sign::sign_response(doc, state).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("mux event not signed: {e}");
            return None;
        }
    };
    let message = Message::build(
        Uuid::new_v4().to_string(),
        crate::messages::protocols::trust_tasks::ENVELOPE_TYPE.to_string(),
        signed,
    )
    .to(principal_did.to_string())
    .from(mediator_did.clone())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();
    match crate::didcomm_compat::pack_encrypted(
        &message,
        principal_did,
        Some(mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    {
        Ok((packed, _)) => Some(packed),
        Err(e) => {
            warn!("mux event not packed: {e}");
            None
        }
    }
}

#[cfg(not(feature = "didcomm"))]
pub async fn pack_event(_: &SharedData, _: &str, _: Value) -> Option<String> {
    None
}

/// Open a mux connection for `session`: admit its stored grants, register
/// every member on `tx`, publish it in the registry, and return it with the
/// `ready` and `attached` frames to write first.
pub async fn open(
    state: &SharedData,
    session: &Session,
    tx: mpsc::Sender<QueuedCommand>,
    resync: Arc<AtomicBool>,
) -> (Arc<MuxConn>, Vec<String>) {
    let limits = &state.config.limits.mux;
    let mut mux = MuxSession::new(
        &session.did,
        &session.session_id,
        limits.max_dids_per_connection,
    );
    let verifier = StatementVerifier::new(state.did_resolver.clone());
    let c = ctx(state, &verifier);

    // Loaded before the session is shared, so no lock is held across the DID
    // resolution each grant's key check needs (R1.3).
    let (admitted, refused) = match mux.load_grants(&c).await {
        Ok(r) => r,
        Err(e) => {
            warn!(principal = %session.did_hash, "mux grants could not be loaded: {e}");
            (Vec::new(), Vec::new())
        }
    };
    let nonce = mux.nonce.clone();
    let conn = Arc::new(MuxConn::new(mux, tx, resync));
    if let Some(streaming) = &state.streaming_task {
        for m in &admitted {
            conn.register_member(streaming, m).await;
        }
    }
    state
        .mux
        .insert(&session.session_id, &session.did_hash, conn.clone());

    let mut frames = Vec::new();
    let ready = json!({
        "event": "ready",
        "sessionId": session.session_id,
        "muxNonce": nonce,
        "maxDidsPerConnection": limits.max_dids_per_connection,
        "maxGrantLifetimeSeconds": limits.max_grant_lifetime_secs,
        "maxAttachLifetimeSeconds": limits.max_attach_lifetime_secs,
        "sessionExpiresAt": rfc3339(session.expires_at),
        "pendingNotices": 0,
    });
    frames.extend(pack_event(state, &session.did, ready).await);
    if !admitted.is_empty() {
        let dids: Vec<Value> = admitted
            .iter()
            .map(|m| change(m, "connect", None))
            .collect();
        frames.extend(
            pack_event(
                state,
                &session.did,
                json!({ "event": "attached", "dids": dids }),
            )
            .await,
        );
    }
    if !refused.is_empty() {
        debug!(principal = %session.did_hash, refused = refused.len(), "stored grants not carried on connect");
    }
    (conn, frames)
}

/// Report a streaming-task member change (§7.2) to the client.
pub async fn on_member_change(
    state: &SharedData,
    conn: &MuxConn,
    change_: MemberChange,
) -> Option<String> {
    let (hash, event, reason, active) = match &change_ {
        MemberChange::Superseded { did_hash } => (did_hash, "detached", "superseded", false),
        MemberChange::Inactive { did_hash } => (did_hash, "attached", "superseded", false),
        MemberChange::Reactivated { did_hash } => (did_hash, "attached", "reactivated", true),
    };
    let (member, principal) = {
        let s = conn.session.lock().await;
        (s.get(hash).cloned()?, s.principal_did.clone())
    };
    pack_event(
        state,
        &principal,
        json!({ "event": event, "dids": [change(&member, reason, Some(active))] }),
    )
    .await
}

/// Members that left since the last call, as one `detached` frame.
pub async fn drain_left(state: &SharedData, conn: &MuxConn) -> Option<String> {
    let left: Vec<(MuxMember, LeaveReason)> = std::mem::take(&mut *conn.left.lock().await);
    if left.is_empty() {
        return None;
    }
    let principal = conn.session.lock().await.principal_did.clone();
    let dids: Vec<Value> = left
        .iter()
        .map(|(m, r)| change(m, r.wire(), None))
        .collect();
    pack_event(
        state,
        &principal,
        json!({ "event": "detached", "dids": dids }),
    )
    .await
}

/// Periodic sweep: expire lapsed members and, when `revalidate` is set,
/// re-check each grant-admitted member's signing key (§5.1). Leavers are
/// queued on the connection for [`drain_left`].
pub async fn sweep(state: &SharedData, conn: &MuxConn, revalidate: bool) {
    let streaming = state.streaming_task.as_ref();
    let now = state.clock.unix_secs();
    let expired: Vec<String> = {
        let s = conn.session.lock().await;
        s.members()
            .filter(|m| m.expires_at <= now)
            .map(|m| m.did_hash.clone())
            .collect()
    };
    for h in expired {
        conn.detach(streaming, &h, LeaveReason::Expired).await;
    }
    if !revalidate {
        return;
    }
    // Snapshot, then check without the lock (DID resolution is network I/O).
    let to_check: Vec<MuxMember> = conn.session.lock().await.members().cloned().collect();
    let verifier = StatementVerifier::new(state.did_resolver.clone());
    for m in to_check {
        match verifier.key_is_current(&m.kid, &m.key_fp).await {
            Ok(true) => {}
            Ok(false) => {
                if let MuxSource::Grant { .. } = m.source {
                    // Mark the stored grant stale too, so a reconnect does not
                    // re-admit it.
                    let c = ctx(state, &verifier);
                    let rec = affinidi_messaging_mediator_common::store::mux::load(
                        c.store,
                        &m.did_hash,
                        &c.limits,
                        c.now,
                    )
                    .await;
                    if let Ok(rec) = rec
                        && let Some(g) = rec.grants.iter().find(|g| {
                            m.source
                                == (MuxSource::Grant {
                                    grant_id: g.grant_id.clone(),
                                })
                        })
                    {
                        let _ = super::grants::revalidate(&c, g).await;
                    }
                }
                conn.detach(streaming, &m.did_hash, LeaveReason::KeyRotated)
                    .await;
            }
            // Unknown is neither stale nor fine: keep the member and look
            // again next sweep.
            Err(e) => debug!(did = %m.did, "mux key re-check deferred: {e}"),
        }
    }
}

/// Whether this connection may carry pickup / delete / send for `did_hash`.
pub async fn allows(
    state: &SharedData,
    session_id: &str,
    did_hash: &str,
    cap: MuxCapability,
) -> bool {
    match state.mux.get(session_id) {
        Some(conn) => conn
            .session
            .lock()
            .await
            .allows(did_hash, cap, state.clock.unix_secs()),
        None => false,
    }
}

/// The members of `session_id`'s mux connection that may do `cap` now.
pub async fn members_with(state: &SharedData, session_id: &str, cap: MuxCapability) -> Vec<String> {
    let Some(conn) = state.mux.get(session_id) else {
        return Vec::new();
    };
    let now = state.clock.unix_secs();
    let s = conn.session.lock().await;
    s.members()
        .filter(|m| s.allows(&m.did_hash, cap, now))
        .map(|m| m.did_hash.clone())
        .collect()
}

/// Tear the connection down: every member out of the streaming task, the
/// connection out of the registry.
pub async fn close(state: &SharedData, session: &Session, conn: &MuxConn) {
    let members: Vec<String> = conn
        .session
        .lock()
        .await
        .members()
        .map(|m| m.did_hash.clone())
        .collect();
    for h in members {
        // `detach` also queues a `detached` event nobody will read; harmless.
        conn.detach(
            state.streaming_task.as_ref(),
            &h,
            LeaveReason::DetachRequested,
        )
        .await;
    }
    state.mux.remove(&session.session_id, &session.did_hash);
}
