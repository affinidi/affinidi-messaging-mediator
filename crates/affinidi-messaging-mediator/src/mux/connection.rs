//! The socket side of a mux connection: opening it, reporting member changes
//! to the client as `messaging/mux/event` documents, the expiry and key
//! re-validation sweeps, and teardown.
//!
//! Kept out of `handlers/websocket.rs` on purpose: the socket loop calls a
//! handful of functions here and writes the frames they return, so the mux
//! logic is testable and the hot loop's control flow barely changes.
//!
//! Two wires. A DIDComm socket becomes a mux connection by negotiating the
//! `didcomm-mux` WebSocket subprotocol ([`MUX_SUBPROTOCOL`]; the legacy
//! `affinidi-mux` is still accepted, see [`mux_subprotocol`]), and its events
//! are DIDComm messages (spec `messaging/mux/event/0.1`, "DIDComm sockets"). A
//! raw-TSP socket negotiates `tsp-mux` ([`TSP_MUX_SUBPROTOCOL`]; spec
//! "Raw-TSP sockets", design §4.10), and its events are TSP Direct messages
//! from the mediator's VID to the principal's, written as Binary frames
//! ([`MuxWire`]).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use affinidi_messaging_mediator_common::store::mux::{MuxCapability, MuxChange};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::{debug, warn};
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use uuid::Uuid;

use super::grants::Ctx;
use super::proof::StatementVerifier;
use super::registry::MuxConn;
use super::session::{LeaveReason, MuxMember, MuxSession, MuxSource};
use crate::SharedData;
use crate::common::session::Session;
use crate::tasks::websocket_streaming::{MemberChange, QueuedCommand};

/// WebSocket subprotocol a DIDComm client offers to open a mux connection.
pub const MUX_SUBPROTOCOL: &str = "didcomm-mux";

/// The provisional name SDK 0.45.1 and 0.45.2 offer. Still accepted, so
/// those clients keep working; no released mediator served it, and the spec
/// lets a mediator accept a token it shipped before the binding existed.
pub const LEGACY_MUX_SUBPROTOCOL: &str = "affinidi-mux";

/// The mux subprotocol to select from a client's offer, if it made one:
/// the spec's name when offered, else the legacy one.
pub fn mux_subprotocol<'a>(offered: impl IntoIterator<Item = &'a String>) -> Option<&'static str> {
    let mut legacy = false;
    for p in offered {
        if p == MUX_SUBPROTOCOL {
            return Some(MUX_SUBPROTOCOL);
        }
        legacy |= p == LEGACY_MUX_SUBPROTOCOL;
    }
    legacy.then_some(LEGACY_MUX_SUBPROTOCOL)
}

/// WebSocket subprotocol a raw-TSP client offers, after `tsp` and `tsp-ack`,
/// to open a mux connection. It implies `tsp-ack` (delete-to-ack) delivery.
pub const TSP_MUX_SUBPROTOCOL: &str = "tsp-mux";

/// `messaging/mux/event` type URI.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

/// The wire a mux connection's events travel on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxWire {
    /// `didcomm-mux`: events are DIDComm messages, written as Text frames.
    DidComm,
    /// `tsp-mux`: events are TSP Direct messages sealed to the principal's
    /// VID, written as Binary frames.
    Tsp,
}

/// One event, ready to write to the socket.
#[derive(Debug)]
pub enum EventFrame {
    /// A packed DIDComm message.
    Text(String),
    /// A sealed TSP message (qb2).
    Binary(Vec<u8>),
}

impl From<EventFrame> for axum::extract::ws::Message {
    fn from(frame: EventFrame) -> Self {
        match frame {
            EventFrame::Text(t) => Self::Text(t.into()),
            EventFrame::Binary(b) => Self::Binary(b.into()),
        }
    }
}

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

/// A `MemberChange` (spec) entry for an `attached` event: the member's
/// scope, expiry and whether its live traffic comes here.
fn attached(member: &MuxMember, reason: &str, delivery_active: bool) -> Value {
    let mut v = json!({
        "did": member.did,
        "reason": reason,
        "scope": member.scope,
        "expiresAt": rfc3339(member.expires_at),
        "deliveryActive": delivery_active,
    });
    if let MuxSource::Grant { grant_id } = &member.source {
        v["grantId"] = json!(grant_id);
    }
    v
}

/// A `MemberChange` entry for a `detached` event, which carries only the
/// DID, the reason and the grant concerned.
fn detached(did: &str, grant_id: Option<&str>, reason: LeaveReason) -> Value {
    let mut v = json!({ "did": did, "reason": reason.wire() });
    if let Some(id) = grant_id {
        v["grantId"] = json!(id);
    }
    v
}

fn grant_id(member: &MuxMember) -> Option<&str> {
    match &member.source {
        MuxSource::Grant { grant_id } => Some(grant_id),
        MuxSource::Attach => None,
    }
}

/// The signed `messaging/mux/event` document for `payload`, addressed to the
/// principal.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
async fn signed_event(state: &SharedData, principal_did: &str, payload: Value) -> Option<Value> {
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": EVENT_TYPE,
        "issuer": state.config.mediator_did,
        "recipient": principal_did,
        "issuedAt": rfc3339(state.clock.unix_secs()),
        "payload": payload,
    });
    match crate::messages::protocols::trust_task_sign::sign_response(doc, state).await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("mux event not signed: {e}");
            None
        }
    }
}

/// Sign a `messaging/mux/event` payload as the mediator and pack it to the
/// principal, ready to write to the socket.
#[cfg(feature = "didcomm")]
pub async fn pack_event(state: &SharedData, principal_did: &str, payload: Value) -> Option<String> {
    use affinidi_messaging_didcomm::message::Message;
    let mediator_did = &state.config.mediator_did;
    let now = state.clock.unix_secs();
    let signed = signed_event(state, principal_did, payload).await?;
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

/// Sign a `messaging/mux/event` payload as the mediator and seal it as a TSP
/// Direct message from the mediator's VID to the principal's — the same
/// sealing a TSP management Trust Task response gets — for a `tsp-mux`
/// socket. The signed document is the TSP payload, verbatim.
#[cfg(feature = "tsp")]
pub async fn seal_event(
    state: &SharedData,
    principal_did: &str,
    payload: Value,
) -> Option<Vec<u8>> {
    let signed = signed_event(state, principal_did, payload).await?;
    let identity = match state.tsp_identity().await {
        Ok(i) => i,
        Err(e) => {
            warn!("mux event not sealed, no mediator TSP identity: {e}");
            return None;
        }
    };
    let recipient =
        match crate::messages::inbound::resolve_tsp_vid(state, principal_did, "mux-event").await {
            Ok(r) => r,
            Err(e) => {
                warn!("mux event not sealed, principal VID unresolved: {e}");
                return None;
            }
        };
    let bytes = match serde_json::to_vec(&signed) {
        Ok(b) => b,
        Err(e) => {
            warn!("mux event not serialised: {e}");
            return None;
        }
    };
    match affinidi_tsp::message::direct::pack(
        &bytes,
        affinidi_tsp::MessageType::Direct,
        &identity.vid,
        principal_did,
        &identity.signing_key,
        &recipient.encryption_key,
    ) {
        Ok(packed) => Some(packed.bytes),
        Err(e) => {
            warn!("mux event not sealed: {e}");
            None
        }
    }
}

#[cfg(not(feature = "tsp"))]
pub async fn seal_event(_: &SharedData, _: &str, _: Value) -> Option<Vec<u8>> {
    None
}

/// `payload` as an event frame for `wire`.
pub async fn event(
    state: &SharedData,
    wire: MuxWire,
    principal_did: &str,
    payload: Value,
) -> Option<EventFrame> {
    match wire {
        MuxWire::DidComm => pack_event(state, principal_did, payload)
            .await
            .map(EventFrame::Text),
        MuxWire::Tsp => seal_event(state, principal_did, payload)
            .await
            .map(EventFrame::Binary),
    }
}

/// The `refused` event for an inbound frame refused on a `tsp-mux` socket
/// (spec `messaging/mux/event`, "In-band refusals").
///
/// `frameId` is the lowercase hex SHA-256 of the frame's exact bytes and
/// `code` the refusal code the traffic monitor reports for the same refusal;
/// the sender and receiver are read from the frame's cleartext envelope where
/// it parses. `None` when the event cannot be sealed, and then the caller
/// must report the refusal some other way (by closing the socket): a refusal
/// reported nowhere leaves the sender believing the frame went (R1.1).
#[cfg(feature = "tsp")]
pub async fn refused_event(
    state: &SharedData,
    conn: &MuxConn,
    frame: &[u8],
    error: &affinidi_messaging_mediator_common::errors::MediatorError,
) -> Option<EventFrame> {
    let payload = refused_payload(frame, error);
    let principal = conn.session.lock().await.principal_did.clone();
    seal_event(state, &principal, payload)
        .await
        .map(EventFrame::Binary)
}

/// The `refused` payload, separated out for testing.
#[cfg(feature = "tsp")]
fn refused_payload(
    frame: &[u8],
    error: &affinidi_messaging_mediator_common::errors::MediatorError,
) -> Value {
    /// The spec's `MuxDid` shape; anything else is left out rather than sent.
    fn mux_did(s: &str) -> bool {
        s.len() <= 2048
            && s.strip_prefix("did:").is_some_and(|rest| {
                rest.split_once(':').is_some_and(|(method, id)| {
                    !method.is_empty()
                        && method
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                        && !id.is_empty()
                        && !id.chars().any(char::is_whitespace)
                })
            })
    }
    let (code, reason) = crate::monitor::refusal_outcome(error);
    let mut v = json!({
        "event": "refused",
        "frameId": sha256::digest(frame),
        "code": code,
    });
    if let Ok(meta) = affinidi_tsp::MetaEnvelope::parse(frame) {
        if mux_did(&meta.sender) {
            v["sender"] = json!(meta.sender);
        }
        if mux_did(&meta.receiver) {
            v["receiver"] = json!(meta.receiver);
        }
    }
    if let Some(reason) = reason.filter(|r| !r.is_empty()) {
        v["reason"] = json!(reason.chars().take(512).collect::<String>());
    }
    v
}

/// Open a mux connection for `session`: admit its stored grants, register
/// every member on `tx`, publish it in the registry, and return it with the
/// `ready` and `attached` frames to write first, in that order.
pub async fn open(
    state: &SharedData,
    session: &Session,
    tx: mpsc::Sender<QueuedCommand>,
    resync: Arc<AtomicBool>,
    slots: Arc<super::fair_queue::MuxSlots>,
    wire: MuxWire,
) -> (Arc<MuxConn>, Vec<EventFrame>) {
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
    // Notices owed from before a crash first, so the count includes them.
    super::notice::recover(state, &session.did_hash).await;
    super::notice::expiring(state, &session.did_hash).await;
    let pending_notices = super::notice::pending(state, &session.did_hash).await;
    let nonce = mux.nonce.clone();
    let conn = Arc::new(MuxConn::new(mux, tx, resync).with_slots(slots));
    if let Some(streaming) = &state.streaming_task {
        for m in &admitted {
            conn.register_member(streaming, m).await;
        }
    }
    #[cfg(feature = "test-hooks")]
    test_hooks::on_open_before_publish(&session.did_hash).await;
    state
        .mux
        .insert(&session.session_id, &session.did_hash, conn.clone());
    // The grants were read before the connection was published, so a
    // revocation or suspension committed in between found nothing here to
    // detach. Re-read them now: any committed later finds the connection.
    sweep(state, &conn, false).await;

    let mut frames = Vec::new();
    let ready = json!({
        "event": "ready",
        "sessionId": session.session_id,
        "muxNonce": nonce,
        "maxDidsPerConnection": limits.max_dids_per_connection,
        "maxGrantLifetimeSeconds": limits.max_grant_lifetime_secs,
        "maxAttachLifetimeSeconds": limits.max_attach_lifetime_secs,
        "sessionExpiresAt": rfc3339(session.expires_at),
        "pendingNotices": pending_notices,
    });
    frames.extend(event(state, wire, &session.did, ready).await);
    if !admitted.is_empty() {
        let dids: Vec<Value> = admitted
            .iter()
            .map(|m| attached(m, "connect", true))
            .collect();
        frames.extend(
            event(
                state,
                wire,
                &session.did,
                json!({ "event": "attached", "dids": dids }),
            )
            .await,
        );
    }
    // Grants that failed re-validation, and valid ones with no room here,
    // in one `detached` event (spec event rule 4).
    if !refused.is_empty() {
        debug!(principal = %session.did_hash, refused = refused.len(), "stored grants not carried on connect");
        let dids: Vec<Value> = refused
            .iter()
            .map(|r| detached(&r.did, Some(&r.grant_id), r.reason))
            .collect();
        frames.extend(
            event(
                state,
                wire,
                &session.did,
                json!({ "event": "detached", "dids": dids }),
            )
            .await,
        );
    }
    (conn, frames)
}

/// Pause points for tests that need to land a change inside a race window.
/// Compiled only with the `test-hooks` feature, which no release build enables.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use tokio::sync::oneshot;

    struct Pause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    static OPEN_BEFORE_PUBLISH: LazyLock<Mutex<HashMap<String, Pause>>> =
        LazyLock::new(Default::default);

    /// Pause the next [`open`](super::open) for `principal_hash` after it has
    /// read the stored grants and before it publishes the connection in the
    /// registry. The first receiver fires once `open` is paused there; sending
    /// on (or dropping) the returned sender lets it go on.
    pub fn pause_open_before_publish(
        principal_hash: &str,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        OPEN_BEFORE_PUBLISH.lock().expect("hook map").insert(
            principal_hash.to_string(),
            Pause {
                reached: reached_tx,
                resume: resume_rx,
            },
        );
        (reached_rx, resume_tx)
    }

    pub(super) async fn on_open_before_publish(principal_hash: &str) {
        let pause = OPEN_BEFORE_PUBLISH
            .lock()
            .expect("hook map")
            .remove(principal_hash);
        if let Some(p) = pause {
            let _ = p.reached.send(());
            let _ = p.resume.await;
        }
    }
}

/// Report a streaming-task member change (§7.2) to the client.
pub async fn on_member_change(
    state: &SharedData,
    conn: &MuxConn,
    change_: MemberChange,
    wire: MuxWire,
) -> Option<EventFrame> {
    let hash = match &change_ {
        MemberChange::Superseded { did_hash }
        | MemberChange::Inactive { did_hash }
        | MemberChange::Reactivated { did_hash } => did_hash,
    };
    let (member, principal) = {
        let s = conn.session.lock().await;
        (s.get(hash).cloned()?, s.principal_did.clone())
    };
    {
        let mut inactive = conn.inactive.lock().await;
        match &change_ {
            MemberChange::Superseded { .. } | MemberChange::Inactive { .. } => {
                inactive.insert(hash.clone());
            }
            MemberChange::Reactivated { .. } => {
                inactive.remove(hash);
            }
        }
    }
    let payload = match change_ {
        MemberChange::Superseded { .. } => json!({
            "event": "detached",
            "dids": [detached(&member.did, grant_id(&member), LeaveReason::Superseded)],
        }),
        // Restates a member just admitted while the DID's own direct socket
        // keeps its live traffic. The reason must be an AttachReason, and
        // `superseded` is not one: name how the member joined.
        MemberChange::Inactive { .. } => {
            let reason = match member.source {
                MuxSource::Attach => "attach",
                MuxSource::Grant { .. } => "connect",
            };
            json!({ "event": "attached", "dids": [attached(&member, reason, false)] })
        }
        MemberChange::Reactivated { .. } => {
            json!({ "event": "attached", "dids": [attached(&member, "reactivated", true)] })
        }
    };
    event(state, wire, &principal, payload).await
}

/// Members that joined, changed or left since the last call, as at most one
/// `attached` and one `detached` frame. A join is reported with how the member
/// came (`grant` or `attach`) and whether its live traffic comes here.
pub async fn drain_changes(state: &SharedData, conn: &MuxConn, wire: MuxWire) -> Vec<EventFrame> {
    let joined: Vec<MuxMember> = std::mem::take(&mut *conn.joined.lock().await);
    let left: Vec<(MuxMember, LeaveReason)> = std::mem::take(&mut *conn.left.lock().await);
    let principal = conn.session.lock().await.principal_did.clone();
    let mut frames = Vec::new();
    if !joined.is_empty() {
        let inactive = conn.inactive.lock().await.clone();
        let dids: Vec<Value> = joined
            .iter()
            .map(|m| {
                let reason = match m.source {
                    MuxSource::Attach => "attach",
                    MuxSource::Grant { .. } => "grant",
                };
                attached(m, reason, !inactive.contains(&m.did_hash))
            })
            .collect();
        frames.extend(
            event(
                state,
                wire,
                &principal,
                json!({ "event": "attached", "dids": dids }),
            )
            .await,
        );
    }
    if !left.is_empty() {
        let dids: Vec<Value> = left
            .iter()
            .map(|(m, r)| detached(&m.did, grant_id(m), *r))
            .collect();
        frames.extend(
            event(
                state,
                wire,
                &principal,
                json!({ "event": "detached", "dids": dids }),
            )
            .await,
        );
    }
    frames
}

/// Periodic sweep: expire lapsed members and, when `revalidate` is set,
/// re-check each grant-admitted member's signing key (§5.1). Leavers are
/// queued on the connection for [`drain_changes`].
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

    // Grant-admitted members: is the stored grant still active? A revoke,
    // revoke-all or suspension handled on *this* instance detached them
    // already, before it answered, and one handled by another instance
    // sharing the store arrives within moments over the store's mux pub/sub
    // channel (`super::sync`). This re-check is the backstop for a change
    // whose record was lost: it reaches the connection within one sweep
    // interval (design §7.4, Q4).
    let by_grant: Vec<(String, String)> = {
        let s = conn.session.lock().await;
        s.members()
            .filter_map(|m| match &m.source {
                MuxSource::Grant { grant_id } => Some((m.did_hash.clone(), grant_id.clone())),
                MuxSource::Attach => None,
            })
            .collect()
    };
    let limits = state.config.limits.mux.store_limits();
    for (did_hash, grant_id) in by_grant {
        let rec = match affinidi_messaging_mediator_common::store::mux::load(
            &*state.database,
            &did_hash,
            &limits,
            now,
        )
        .await
        {
            Ok(rec) => rec,
            // Store unavailable: keep the member and look again next sweep.
            Err(e) => {
                debug!("mux grant re-check deferred: {e}");
                continue;
            }
        };
        let Some(reason) = grant_leave_reason(&rec, &grant_id, now) else {
            continue;
        };
        conn.detach_grant_id(streaming, &did_hash, &grant_id, reason)
            .await;
    }

    if !revalidate {
        return;
    }
    // Grants nearing expiry while the principal stays connected (spec
    // `messaging/mux/notice`: stored on a periodic check rather than at the
    // three-quarter instant).
    let principal_hash = conn.session.lock().await.principal_hash.clone();
    super::notice::expiring(state, &principal_hash).await;
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
                        && let Ok(Some(stale)) = super::grants::revalidate(&c, g).await
                    {
                        // The principal's connections on other instances
                        // drop it too.
                        super::sync::publish(state, &[MuxChange::of(&stale, false)]).await;
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

/// Why a member admitted by grant `grant_id` must leave, given its member
/// DID's record as stored now, or `None` while that grant is still active.
pub fn grant_leave_reason(
    rec: &affinidi_messaging_mediator_common::store::mux::MuxDidRecord,
    grant_id: &str,
    now: u64,
) -> Option<LeaveReason> {
    use affinidi_messaging_mediator_common::store::mux::MuxGrantState as S;
    match rec.grants.iter().find(|g| g.grant_id == grant_id) {
        Some(g) => match g.state_at(now) {
            S::Active => None,
            S::Suspended => Some(LeaveReason::SuspendedUnknownKey),
            S::EpochRevoked => Some(LeaveReason::EpochBumped),
            S::StaleKey => Some(LeaveReason::KeyRotated),
            S::Expired => Some(LeaveReason::Expired),
        },
        // Gone: revoked by one of the parties.
        None => Some(LeaveReason::RevokedByMember),
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

/// The session a frame from `sender_did` runs under when it arrives on
/// `session`'s mux connection and its sender is not the principal: the
/// member's own identity and standing, read now. `None` (refuse, exactly as a
/// foreign sender is refused on any socket) unless this connection carries
/// the member with `send` right now *and* the member's own ACLs still allow
/// what `send` needs on its own connection ([`super::grants::check_scope`]:
/// not blocked, local, `SEND_MESSAGES`). A store failure refuses too.
///
/// The caller has already established that `sender_did` is the frame's sender
/// — cryptographically for anything addressed to the mediator, and as the
/// envelope's claim for opaque direct delivery, which the member vouched for
/// by granting `send`. Everything downstream (forwarding ACLs, queue limits,
/// the recipient's ACL and access list, stats) then sees the member as the
/// sender, exactly as on the member's own connection. The returned session
/// keeps the connection's `session_id`; the socket still answers on the
/// principal's session.
pub async fn sender_session(
    state: &SharedData,
    session: &Session,
    sender_did: &str,
) -> Option<Session> {
    use affinidi_messaging_mediator_common::{
        did_identity::did_hash, store::mux::MuxScope, types::acls::MediatorACLSet,
    };

    let hash = did_hash(sender_did);
    if hash == session.did_hash
        || !allows(state, &session.session_id, &hash, MuxCapability::Send).await
    {
        return None;
    }
    // A member must have an account: a grant or attach is refused without
    // one, so a member without one now has lost it, and is refused rather than
    // given the deployment's default ACLs.
    let (acls, account_type) = match state.database.account_get(&hash).await {
        Ok(Some(account)) => (MediatorACLSet::from_u64(account.acls), account._type),
        Ok(None) => {
            debug!(principal = %session.did_hash, session_id = %session.session_id, member = %hash, "mux send refused: member has no account");
            return None;
        }
        Err(e) => {
            warn!(principal = %session.did_hash, session_id = %session.session_id, member = %hash, "mux send refused: member account unreadable: {e}");
            return None;
        }
    };
    let send = MuxScope::new([MuxCapability::Send]).ok()?;
    if let Err(e) = super::grants::check_scope(&acls, &send) {
        debug!(member = %hash, "mux send refused: {e}");
        return None;
    }
    debug!(principal = %session.did_hash, member = %hash, "frame accepted as sent by mux member");
    Some(Session {
        session_id: session.session_id.clone(),
        did: sender_did.to_string(),
        did_hash: hash,
        authenticated: true,
        acls,
        account_type,
        state: session.state,
        expires_at: session.expires_at,
        ..Default::default()
    })
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

#[cfg(all(test, feature = "tsp"))]
mod tests {
    use super::refused_payload;
    use affinidi_messaging_mediator_common::errors::MediatorError;
    use affinidi_messaging_sdk::messages::problem_report::{
        ProblemReportScope, ProblemReportSorter,
    };
    use http::StatusCode;

    fn refusal() -> MediatorError {
        MediatorError::problem(
            73,
            "s",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Message,
            "authorization.access_list.denied",
            "delivery blocked by the recipient's access list",
            vec![],
            StatusCode::FORBIDDEN,
        )
    }

    /// The payload a `tsp-mux` socket sends for a refused frame matches the
    /// spec's generated type, and names the frame by the SHA-256 of its exact
    /// bytes with the code the traffic monitor reports.
    #[test]
    fn refused_payload_matches_the_spec_and_the_monitor() {
        use crate::task_specs::messaging::mux::event::v0_1::Payload;
        let frame = b"\xf8not really a TSP frame";
        let error = refusal();
        let v = refused_payload(frame, &error);
        assert_eq!(v["event"], "refused");
        assert_eq!(v["frameId"], sha256::digest(&frame[..]));
        assert_eq!(v["code"], crate::monitor::refusal_outcome(&error).0);
        // Unreadable envelope: no sender or receiver is claimed.
        assert!(v.get("sender").is_none() && v.get("receiver").is_none());
        serde_json::from_value::<Payload>(v.clone())
            .unwrap_or_else(|e| panic!("refused payload is not the spec's shape: {e}\n{v:#}"));
    }

    /// An internal failure reports a stable code and no detail.
    #[test]
    fn an_internal_failure_is_reported_without_detail() {
        let v = refused_payload(
            b"x",
            &MediatorError::InternalError(1, "s".into(), "redis down at 10.0.0.1".into()),
        );
        assert_eq!(v["code"], "internalError");
        assert!(v.get("reason").is_none());
    }
}
