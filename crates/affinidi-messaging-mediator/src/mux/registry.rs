//! The live mux connections on this mediator instance.
//!
//! A mux connection's member set ([`MuxSession`]) is shared between its socket
//! loop (which writes frames, and must not write one for a member that has
//! left) and the Trust Task handlers that change it: `attach` and `detach`
//! arrive on the connection's own session, while `revoke`, `revoke-all`,
//! `update` and the unknown-key rule change *other* principals' connections.
//! The registry is how a handler finds those connections, so it can drop the
//! affected members **before** it answers (design §7.3, R1.1/R7.2).
//!
//! The registry's scope is one process. With several mediator processes
//! sharing one Redis, a change handled by another process arrives as a
//! `MuxChangeRecord` on the store's mux pub/sub channel, and [`super::sync`]
//! applies it here — detach, narrow or admit, as the store now says — within
//! one pub/sub hop. The periodic grant re-check in `connection::sweep`
//! remains the backstop for a record that never arrives (design §7.4).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use affinidi_messaging_mediator_common::store::{
    mux::{self, MuxGrant, MuxGrantState, MuxLimits},
    prelude::*,
};
use dashmap::DashMap;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use super::fair_queue::MuxSlots;
use super::session::{LeaveReason, MuxMember, MuxSession};
use crate::tasks::websocket_streaming::{
    EntryKind, QueuedCommand, StreamingTask, StreamingUpdate, StreamingUpdateState,
};

/// Whether a member with `scope` wants live delivery: its frames pushed
/// (`receive`), or a resync when mail waits (`pickup`).
pub fn wants_live(scope: &mux::MuxScope) -> bool {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability as Cap;
    scope.contains(Cap::Receive) || scope.contains(Cap::Pickup)
}

/// [`MuxConn::live_frame`]'s answer for one queued live frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveFrame {
    Write,
    Nudge,
    Drop,
}

/// One live mux connection.
pub struct MuxConn {
    pub session: Mutex<MuxSession>,
    /// The socket's send queue, which every member's streaming entry shares.
    pub tx: mpsc::Sender<QueuedCommand>,
    /// The socket's resync flag (shared by its members).
    pub resync: Arc<AtomicBool>,
    /// The socket's per-DID send slots (fair queuing, design §7.2).
    pub slots: Option<Arc<MuxSlots>>,
    /// Members that left since the socket last reported; the socket loop
    /// drains this into `detached` events to the client.
    pub left: Mutex<Vec<(MuxMember, LeaveReason)>>,
    /// Members admitted or changed while connected (a new grant, an attach,
    /// a narrowed grant), for `attached` events.
    pub joined: Mutex<Vec<MuxMember>>,
    /// Members whose live traffic another connection holds (the DID's own
    /// direct socket, or a newer one): reported `deliveryActive: false`.
    pub inactive: Mutex<std::collections::HashSet<String>>,
    /// Wakes the socket loop to report `left` / `joined`.
    pub notify: tokio::sync::Notify,
    /// The wire this connection speaks, for `messaging/mux/connections`.
    pub wire: super::connection::MuxWire,
    /// When the connection opened (unix seconds), for the same.
    pub opened_at: u64,
    /// Members whose account was last found in good standing, and when, so a
    /// burst of requests made for one member reads its account once
    /// (`connection::check_member`). Keyed by DID hash; an entry counts only
    /// for the admission (source and scope) it was read for.
    pub standing_seen: Mutex<std::collections::HashMap<String, StandingSeen>>,
    /// Set while a standing pass over every member is running, so a slow
    /// store never stacks one pass on another.
    pub standing_pass: AtomicBool,
    /// Set while a periodic sweep ([`super::connection::spawn_sweep`]) is
    /// running, one flag per kind, so a slow store or resolver never stacks
    /// one sweep on another.
    pub sweep_running: AtomicBool,
    pub revalidate_running: AtomicBool,
}

/// [`MuxConn::standing_seen`]: one member's last good standing check.
#[derive(Clone, Debug)]
pub struct StandingSeen {
    pub at: u64,
    pub source: super::session::MuxSource,
    pub scope: affinidi_messaging_mediator_common::store::mux::MuxScope,
}

impl MuxConn {
    pub fn new(
        session: MuxSession,
        tx: mpsc::Sender<QueuedCommand>,
        resync: Arc<AtomicBool>,
    ) -> Self {
        Self {
            session: Mutex::new(session),
            tx,
            resync,
            slots: None,
            left: Mutex::new(Vec::new()),
            joined: Mutex::new(Vec::new()),
            inactive: Mutex::new(std::collections::HashSet::new()),
            notify: tokio::sync::Notify::new(),
            wire: super::connection::MuxWire::DidComm,
            opened_at: 0,
            standing_seen: Mutex::new(std::collections::HashMap::new()),
            standing_pass: AtomicBool::new(false),
            sweep_running: AtomicBool::new(false),
            revalidate_running: AtomicBool::new(false),
        }
    }

    /// Record the wire the connection speaks and when it opened.
    pub fn with_origin(mut self, wire: super::connection::MuxWire, opened_at: u64) -> Self {
        self.wire = wire;
        self.opened_at = opened_at;
        self
    }

    /// Queue this connection's frames through `slots`, so each member gets a
    /// fair share of its send queue.
    pub fn with_slots(mut self, slots: Arc<MuxSlots>) -> Self {
        self.slots = Some(slots);
        self
    }

    /// Register `member` with the streaming task on this connection's queue,
    /// and turn live delivery on when its scope includes `receive` or
    /// `pickup`. A `pickup`-only member's frames are not written: each one
    /// becomes a resync, so the principal learns mail waits without polling
    /// ([`live_frame`](Self::live_frame)).
    pub async fn register_member(&self, streaming: &StreamingTask, member: &MuxMember) {
        // A fresh registration: the streaming task says again if another
        // connection holds the member's traffic.
        self.inactive.lock().await.remove(&member.did_hash);
        let session_id = self.session.lock().await.session_id.clone();
        // One command, and one store write, whether or not the member wants
        // live delivery: a `live` registration is its own `Start` (#128).
        let _ = streaming
            .channel
            .send(StreamingUpdate {
                did_hash: member.did_hash.clone(),
                state: StreamingUpdateState::Register {
                    channel: self.tx.clone(),
                    session_id,
                    did: member.did.clone(),
                    resync: self.resync.clone(),
                    kind: EntryKind::Mux,
                    slots: self.slots.clone(),
                    wake_only: false,
                    live: wants_live(&member.scope),
                },
            })
            .await;
    }

    /// Bring the streaming task in step with `member` after it was admitted
    /// or re-scoped. `before` is `None` for a member new to the connection,
    /// which is registered; otherwise whether it wanted live delivery before
    /// the change. A member already carried is never registered again (that
    /// would read as another connection taking its DID): its live delivery
    /// is turned on when its new scope gained `receive` or `pickup`, and off
    /// when it lost both.
    pub async fn reconcile_member(
        &self,
        streaming: Option<&StreamingTask>,
        member: &MuxMember,
        before: Option<bool>,
    ) {
        let Some(streaming) = streaming else {
            return;
        };
        let Some(was_live) = before else {
            self.register_member(streaming, member).await;
            return;
        };
        let live = wants_live(&member.scope);
        if live != was_live {
            let session_id = self.session.lock().await.session_id.clone();
            self.set_live(streaming, &member.did_hash, session_id, live)
                .await;
        }
    }

    /// Turn live delivery for member `did_hash` on (`Start`) or off (`Stop`).
    async fn set_live(
        &self,
        streaming: &StreamingTask,
        did_hash: &str,
        session_id: String,
        live: bool,
    ) {
        let state = if live {
            StreamingUpdateState::Start { session_id }
        } else {
            StreamingUpdateState::Stop { session_id }
        };
        let _ = streaming
            .channel
            .send(StreamingUpdate {
                did_hash: did_hash.to_string(),
                state,
            })
            .await;
    }

    /// Take `did_hash` off the connection: out of the member set first (so the
    /// socket writes nothing more for it), then out of the streaming task, then
    /// queued for a `detached` event.
    pub async fn detach(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        reason: LeaveReason,
    ) -> Option<MuxMember> {
        let (member, session_id) = {
            let mut s = self.session.lock().await;
            (s.detach(did_hash)?, s.session_id.clone())
        };
        self.deregister(streaming, did_hash, &session_id).await;
        self.report_left(vec![(member.clone(), reason)]).await;
        Some(member)
    }

    /// Apply a narrowed grant to the member it admitted here, and tell the
    /// principal with an `attached` event when its scope or expiry changed
    /// (spec event rule 5). A member left with neither `receive` nor
    /// `pickup` has its live delivery turned off.
    pub async fn narrow(&self, streaming: Option<&StreamingTask>, grant: &MuxGrant) {
        let (changed, before) = {
            let mut s = self.session.lock().await;
            let before = s.get(&grant.did_hash).map(|m| wants_live(&m.scope));
            (s.narrow(grant), before)
        };
        if let Some(member) = changed {
            self.reconcile_member(streaming, &member, before.or(Some(false)))
                .await;
            self.joined.lock().await.push(member);
            self.notify.notify_one();
        }
    }

    /// Take `did_hash` off the connection only if `still` holds for the
    /// member as it is now: a decision made on a snapshot must not remove a
    /// member that was re-admitted, widened or replaced in the meantime.
    pub async fn detach_if(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        reason: LeaveReason,
        still: impl FnOnce(&MuxMember) -> bool,
    ) -> Option<MuxMember> {
        let (member, session_id) = {
            let mut s = self.session.lock().await;
            if !s.get(did_hash).is_some_and(still) {
                return None;
            }
            (s.detach(did_hash)?, s.session_id.clone())
        };
        self.deregister(streaming, did_hash, &session_id).await;
        self.report_left(vec![(member.clone(), reason)]).await;
        Some(member)
    }

    /// Queue `left` for the socket's next `detached` event and count each on
    /// [`MUX_DETACH_TOTAL`](crate::common::metrics::names::MUX_DETACH_TOTAL):
    /// every member that leaves a live connection, or that a stored grant
    /// could not put on it, is reported here.
    pub async fn report_left(&self, left: Vec<(MuxMember, LeaveReason)>) {
        if left.is_empty() {
            return;
        }
        for (_, reason) in &left {
            reason.count(1);
        }
        self.left.lock().await.extend(left);
        self.notify.notify_one();
    }

    /// Take every member off the connection as it closes: out of the member
    /// set, then out of the streaming task. Nothing is reported or counted as
    /// detached; the connection ending is not a detach.
    pub async fn close_members(&self, streaming: Option<&StreamingTask>) {
        let (gone, session_id) = {
            let mut s = self.session.lock().await;
            (s.close(), s.session_id.clone())
        };
        for m in &gone {
            self.deregister(streaming, &m.did_hash, &session_id).await;
        }
    }

    async fn deregister(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        session_id: &str,
    ) {
        self.standing_seen.lock().await.remove(did_hash);
        self.inactive.lock().await.remove(did_hash);
        if let Some(streaming) = streaming {
            let _ = streaming
                .channel
                .send(StreamingUpdate {
                    did_hash: did_hash.to_string(),
                    state: StreamingUpdateState::Deregister {
                        session_id: session_id.to_string(),
                        channel: self.tx.downgrade(),
                    },
                })
                .await;
        }
    }

    /// Take `did_hash` off the connection only if grant `grant_id` still
    /// admits it: a member a newer grant took over in the meantime stays.
    pub async fn detach_grant_id(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        grant_id: &str,
        reason: LeaveReason,
    ) -> Option<MuxMember> {
        let (member, session_id) = {
            let mut s = self.session.lock().await;
            let held = s.get(did_hash).is_some_and(|m| {
                m.source
                    == (super::session::MuxSource::Grant {
                        grant_id: grant_id.to_string(),
                    })
            });
            if !held {
                return None;
            }
            (s.detach(did_hash)?, s.session_id.clone())
        };
        self.deregister(streaming, did_hash, &session_id).await;
        self.report_left(vec![(member.clone(), reason)]).await;
        Some(member)
    }

    /// Remove every member admitted by one of `grants`.
    pub async fn detach_grants(
        &self,
        streaming: Option<&StreamingTask>,
        grants: &[MuxGrant],
        reason: LeaveReason,
    ) -> Vec<MuxMember> {
        let (gone, session_id) = {
            let mut s = self.session.lock().await;
            (s.detach_grants(grants), s.session_id.clone())
        };
        for m in &gone {
            self.deregister(streaming, &m.did_hash, &session_id).await;
        }
        self.report_left(gone.iter().cloned().map(|m| (m, reason)).collect())
            .await;
        gone
    }

    /// What to do with a live frame tagged for `did_hash`, decided when the
    /// socket is about to write it, against the member's scope *now*:
    ///
    /// - the principal's own, or a member holding `receive`: write it;
    /// - a member holding `pickup` but not `receive`: do not push the frame,
    ///   but tell the principal mail waits for it (a resync: a pickup
    ///   `status` on DIDComm, a drain on raw TSP);
    /// - anything else (a member that left, whose admission has lapsed at
    ///   `now`, or that holds neither): drop it. The message stays in the
    ///   member's inbox (§7.3, R1.1).
    ///
    /// Expiry is checked here as [`MuxSession::allows`] checks it, rather
    /// than left to the next sweep to remove the member.
    pub async fn live_frame(&self, did_hash: &str, now: u64) -> LiveFrame {
        use affinidi_messaging_mediator_common::store::mux::MuxCapability as Cap;
        let s = self.session.lock().await;
        if did_hash == s.principal_hash {
            return LiveFrame::Write;
        }
        match s.get(did_hash).filter(|m| m.expires_at > now) {
            Some(m) if m.scope.contains(Cap::Receive) => LiveFrame::Write,
            Some(m) if m.scope.contains(Cap::Pickup) => LiveFrame::Nudge,
            _ => LiveFrame::Drop,
        }
    }

    /// Owe `did_hash` a resync: the socket tells the principal its mail waits.
    pub fn nudge(&self, did_hash: &str) {
        if let Some(slots) = &self.slots {
            slots.raise_resync(did_hash);
        }
        self.resync
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// [`MuxRegistry::summary`]: this instance's mux connections and members.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MuxSummary {
    pub connections: u64,
    pub members: u64,
    pub by_grant: u64,
    pub by_attach: u64,
    /// Members whose live traffic another connection holds.
    pub inactive: u64,
}

/// Move the connection gauge for `wire` by `delta`.
fn connection_gauge(wire: super::connection::MuxWire, delta: f64) {
    metrics::gauge!(crate::common::metrics::names::MUX_CONNECTIONS, "wire" => wire.label())
        .increment(delta);
}

/// All live mux connections, by session id and by principal.
#[derive(Default)]
pub struct MuxRegistry {
    conns: DashMap<String, Arc<MuxConn>>,
    by_principal: DashMap<String, HashSet<String>>,
}

impl MuxRegistry {
    /// Publish `conn`. With [`Self::remove`], the one place the
    /// [`MUX_CONNECTIONS`](crate::common::metrics::names::MUX_CONNECTIONS)
    /// gauge moves, so it always equals the connections registered here.
    pub fn insert(&self, session_id: &str, principal_hash: &str, conn: Arc<MuxConn>) {
        let wire = conn.wire;
        if let Some(old) = self.conns.insert(session_id.to_string(), conn) {
            connection_gauge(old.wire, -1.0);
        }
        connection_gauge(wire, 1.0);
        self.by_principal
            .entry(principal_hash.to_string())
            .or_default()
            .insert(session_id.to_string());
    }

    pub fn remove(&self, session_id: &str, principal_hash: &str) {
        if let Some((_, conn)) = self.conns.remove(session_id) {
            connection_gauge(conn.wire, -1.0);
        }
        if let Some(mut set) = self.by_principal.get_mut(principal_hash) {
            set.remove(session_id);
        }
        self.by_principal
            .remove_if(principal_hash, |_, s| s.is_empty());
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<MuxConn>> {
        self.conns.get(session_id).map(|c| c.clone())
    }

    /// Every live mux connection on this instance.
    pub fn all(&self) -> Vec<Arc<MuxConn>> {
        self.conns.iter().map(|c| c.value().clone()).collect()
    }

    /// Counts across every live mux connection on this instance, for
    /// `messaging/stats/show`. Each connection's session is locked in turn,
    /// never two at once.
    pub async fn summary(&self) -> MuxSummary {
        let mut out = MuxSummary::default();
        for conn in self.all() {
            out.connections += 1;
            let inactive = conn.inactive.lock().await.clone();
            let s = conn.session.lock().await;
            for m in s.members() {
                out.members += 1;
                match m.source {
                    super::session::MuxSource::Grant { .. } => out.by_grant += 1,
                    super::session::MuxSource::Attach => out.by_attach += 1,
                }
                if inactive.contains(&m.did_hash) {
                    out.inactive += 1;
                }
            }
        }
        out
    }

    /// The live mux connections of `principal_hash` on this instance.
    pub fn for_principal(&self, principal_hash: &str) -> Vec<Arc<MuxConn>> {
        self.by_principal
            .get(principal_hash)
            .map(|ids| ids.iter().filter_map(|id| self.get(id)).collect())
            .unwrap_or_default()
    }

    /// Drop, on every live connection of each grant's principal, the member
    /// that grant admitted. Returns once each is out of the member set, so the
    /// caller may then answer (§7.3).
    pub async fn detach_grants(
        &self,
        streaming: Option<&StreamingTask>,
        grants: &[MuxGrant],
        reason: LeaveReason,
    ) {
        let principals: HashSet<&str> = grants.iter().map(|g| g.principal_hash.as_str()).collect();
        for p in principals {
            for conn in self.for_principal(p) {
                let gone = conn.detach_grants(streaming, grants, reason).await;
                if !gone.is_empty() {
                    debug!(
                        principal = p,
                        count = gone.len(),
                        ?reason,
                        "detached mux members"
                    );
                }
            }
        }
    }

    /// End, on every live connection here, the session attach of `did_hash`
    /// admitted at or before `at` — the member DID's `revoke-all` at `at`
    /// ends the attaches as well as the grants (design §5.2). A member carried
    /// by a grant is left to the grant's own detach, and an attach admitted
    /// after `at` rests on a statement made since, so it stays. Returns once
    /// each is out of its member set, so the caller may then answer.
    pub async fn detach_attaches(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        at: u64,
        reason: LeaveReason,
    ) {
        for conn in self.all() {
            let gone = conn
                .detach_if(streaming, did_hash, reason, |m| {
                    m.source == super::session::MuxSource::Attach && m.attached_at <= at
                })
                .await;
            if gone.is_some() {
                debug!(member = did_hash, ?reason, "ended a mux session attach");
            }
        }
    }

    /// Carry the members of newly stored grants on every live connection of
    /// their principal, at once (design §4.4). Returns the ids of the grants
    /// some connection on this instance now carries (`attachedNow`).
    ///
    /// The store, not the order handlers finish in, decides what is carried,
    /// and no lock is held across a store read (R1.3):
    ///
    /// 1. The grant is re-read; one already replaced, revoked or suspended is
    ///    not carried. A record that cannot be read is not carried either
    ///    (fail closed); the principal's next connection carries the grant.
    /// 2. It is admitted under the session lock, unless a newer grant
    ///    already carries the member (the store keeps only the newest, by
    ///    `iat`), so out-of-order admissions settle on the newest grant.
    /// 3. It is re-read once more. If it was revoked meanwhile, it is
    ///    detached here; otherwise the revoke's own detach, which follows
    ///    its store write, runs after this admission and finds it.
    ///
    /// A grant that replaces the principal's earlier grant on the same DID
    /// sets the member's scope and expiry outright, wider or narrower: it is
    /// a new statement signed by the member DID and verified like any other
    /// (`grants::store_grant`), so a wider scope is the member's own
    /// authorisation.
    pub async fn admit_grants(
        &self,
        streaming: Option<&StreamingTask>,
        store: &dyn MediatorStore,
        limits: &MuxLimits,
        now: u64,
        grants: &[MuxGrant],
    ) -> HashSet<String> {
        let mut carried = HashSet::new();
        for g in grants {
            if self.for_principal(&g.principal_hash).is_empty() {
                continue;
            }
            let current = match current_grant(store, g, limits, now).await {
                Ok(Some(current)) => current,
                Ok(None) => continue,
                Err(e) => {
                    warn!(principal = %g.principal_hash, grant = %g.grant_id, "grant not carried live, store unreadable: {e}");
                    continue;
                }
            };
            let member = MuxMember {
                did: current.did.clone(),
                did_hash: current.did_hash.clone(),
                source: super::session::MuxSource::Grant {
                    grant_id: current.grant_id.clone(),
                },
                scope: current.effective_scope().clone(),
                kid: current.kid.clone(),
                key_fp: current.key_fp.clone(),
                expires_at: current.effective_exp(),
                grant_iat: current.iat,
                attached_at: 0,
            };
            for conn in self.for_principal(&g.principal_hash) {
                let (admitted, before) = {
                    let mut s = conn.session.lock().await;
                    let before = s.get(&member.did_hash).map(|m| wants_live(&m.scope));
                    (s.admit_grant(member.clone()), before)
                };
                match admitted {
                    Ok(Some((member, new))) => {
                        // A replacement grant may widen the scope: a member
                        // first carried for `send` only starts live delivery
                        // once it gains `receive` or `pickup`.
                        conn.reconcile_member(streaming, &member, if new { None } else { before })
                            .await;
                        conn.joined.lock().await.push(member);
                        conn.notify.notify_one();
                        carried.insert(current.grant_id.clone());
                    }
                    // Already carried by this grant (or a newer one).
                    Ok(None) => {
                        carried.insert(current.grant_id.clone());
                    }
                    // The connection is full. The grant stays stored and is
                    // carried by a connection with room, or after a
                    // reconnect; this one is told `connectionFull`.
                    Err(e) => {
                        debug!(
                            principal = %g.principal_hash,
                            grant = %g.grant_id,
                            "stored grant not carried live: {e}"
                        );
                        conn.report_left(vec![(member.clone(), LeaveReason::ConnectionFull)])
                            .await;
                    }
                }
            }
            // Step 3. Fail closed on an unreadable record too.
            if !matches!(
                current_grant(store, &current, limits, now).await,
                Ok(Some(_))
            ) {
                self.detach_grants(
                    streaming,
                    std::slice::from_ref(&current),
                    LeaveReason::RevokedByMember,
                )
                .await;
                carried.remove(&current.grant_id);
            }
        }
        carried
    }

    /// Re-scope members admitted by narrowed grants: the narrower scope or
    /// earlier expiry takes effect now.
    pub async fn narrow(&self, streaming: Option<&StreamingTask>, grants: &[MuxGrant]) {
        for g in grants {
            for conn in self.for_principal(&g.principal_hash) {
                conn.narrow(streaming, g).await;
            }
        }
    }
}

/// `g` as its member's record holds it now, if it is still there and active.
async fn current_grant(
    store: &dyn MediatorStore,
    g: &MuxGrant,
    limits: &MuxLimits,
    now: u64,
) -> Result<Option<MuxGrant>, mux::MuxStoreError> {
    let rec = mux::load(store, &g.did_hash, limits, now).await?;
    Ok(rec.grants.into_iter().find(|s| {
        s.grant_id == g.grant_id
            && s.principal_hash == g.principal_hash
            && matches!(s.state_at(now), MuxGrantState::Active)
    }))
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use crate::common::metrics::testing::{recorder, value};
    use crate::mux::connection::MuxWire;
    use crate::mux::session::{MuxSource, gauge_tests::member};

    fn conn(principal: &str, session: &str, wire: MuxWire) -> Arc<MuxConn> {
        let (tx, _rx) = mpsc::channel(8);
        Arc::new(
            MuxConn::new(
                MuxSession::new(principal, session, 10),
                tx,
                Arc::new(AtomicBool::new(false)),
            )
            .with_origin(wire, 0),
        )
    }

    /// The connection gauge counts what the registry holds, by wire: a
    /// re-insert under one session id is one connection, and removing one
    /// that is not there moves nothing (never below zero).
    #[test]
    fn the_connection_gauge_follows_the_registry() {
        let rec = recorder();
        let _local = metrics::set_default_local_recorder(&rec);
        let gauges = || {
            (
                value(&rec, "mux_connections{wire=\"didcomm\"}"),
                value(&rec, "mux_connections{wire=\"tsp\"}"),
            )
        };
        let registry = MuxRegistry::default();
        registry.insert("s1", "p", conn("did:example:p", "s1", MuxWire::DidComm));
        registry.insert("s2", "p", conn("did:example:p", "s2", MuxWire::Tsp));
        assert_eq!(gauges(), (1.0, 1.0));
        // Replaced under the same id, on another wire.
        registry.insert("s1", "p", conn("did:example:p", "s1", MuxWire::Tsp));
        assert_eq!(gauges(), (0.0, 2.0));
        registry.remove("s1", "p");
        registry.remove("s1", "p");
        registry.remove("never", "p");
        assert_eq!(gauges(), (0.0, 1.0));
        registry.remove("s2", "p");
        assert_eq!(gauges(), (0.0, 0.0));
    }

    /// Every leave from a live connection is counted once, by reason; a
    /// detach that finds nothing counts nothing; and closing the connection
    /// takes its members off the gauge without counting them as detached.
    #[tokio::test]
    async fn detaches_are_counted_and_a_close_is_not() {
        let rec = recorder();
        let _local = metrics::set_default_local_recorder(&rec);
        let reason = |r: &str| value(&rec, &format!("mux_detach_total{{reason=\"{r}\"}}"));
        let members = || value(&rec, "mux_members{source=\"attach\"}");

        let c = conn("did:example:p", "s", MuxWire::DidComm);
        {
            let mut s = c.session.lock().await;
            for d in ["did:example:a", "did:example:b", "did:example:c"] {
                s.admit(member(d, MuxSource::Attach, 100)).unwrap();
            }
        }
        assert_eq!(members(), 3.0);
        let a = member("did:example:a", MuxSource::Attach, 100).did_hash;
        c.detach(None, &a, LeaveReason::DetachRequested).await;
        c.detach(None, &a, LeaveReason::DetachRequested).await;
        let b = member("did:example:b", MuxSource::Attach, 100).did_hash;
        c.detach_if(None, &b, LeaveReason::AccountBlocked, |_| false)
            .await;
        assert_eq!(reason("detachRequested"), 1.0);
        assert_eq!(reason("accountBlocked"), 0.0);
        assert_eq!(members(), 2.0);
        assert_eq!(c.left.lock().await.len(), 1);

        c.close_members(None).await;
        assert_eq!(members(), 0.0);
        assert_eq!(reason("detachRequested"), 1.0, "a close is not a detach");
        assert_eq!(c.left.lock().await.len(), 1, "and queues no event");
    }
}

#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use affinidi_messaging_mediator_common::did_identity::did_hash;
    use affinidi_messaging_mediator_common::store::mux::{MuxCapability, MuxScope};

    fn grant(id: &str, member: &str, principal: &str) -> MuxGrant {
        MuxGrant {
            grant_id: id.into(),
            did: member.into(),
            did_hash: did_hash(member),
            principal: principal.into(),
            principal_hash: did_hash(principal),
            kid: format!("{member}#key-1"),
            key_fp: "fp".into(),
            did_version: None,
            epoch: 0,
            scope: MuxScope::new([MuxCapability::Receive]).unwrap(),
            iat: 1,
            exp: u64::MAX / 2,
            narrowed_scope: None,
            narrowed_exp: None,
            state: MuxGrantState::Active,
            state_changed_at: None,
            statement: serde_json::json!({}),
            noticed: false,
            key_agreement_fps: Vec::new(),
            expiring_noticed: false,
            voided_by: None,
        }
    }

    /// Make `g` the principal's stored grant on its member DID.
    async fn put(store: &MemoryStore, g: &MuxGrant) {
        mux::modify(store, &g.did_hash, &LIMITS, 0, None, |rec, _| {
            rec.grants.retain(|x| x.principal_hash != g.principal_hash);
            rec.grants.push(g.clone());
            Ok(())
        })
        .await
        .unwrap();
    }

    const LIMITS: MuxLimits = MuxLimits {
        max_grants_per_did: 16,
        max_grants_per_principal: 16,
        max_grant_lifetime_secs: u64::MAX,
        dead_retention_secs: 0,
    };

    fn connected(registry: &MuxRegistry, principal: &str) -> Arc<MuxConn> {
        let (tx, _rx) = mpsc::channel(8);
        let conn = Arc::new(MuxConn::new(
            MuxSession::new(principal, "sess", 10),
            tx,
            Arc::new(AtomicBool::new(false)),
        ));
        registry.insert("sess", &did_hash(principal), conn.clone());
        conn
    }

    /// A streaming task whose command channel the test reads.
    fn streaming() -> (StreamingTask, mpsc::Receiver<StreamingUpdate>) {
        let (tx, rx) = mpsc::channel(32);
        (
            StreamingTask {
                uuid: "test".into(),
                channel: tx,
                send_budget: crate::common::ws_budget::WsSendBudget::new(1 << 20),
                liveness: Default::default(),
            },
            rx,
        )
    }

    /// The commands sent so far, by kind.
    fn sent(rx: &mut mpsc::Receiver<StreamingUpdate>) -> Vec<&'static str> {
        let mut out = Vec::new();
        while let Ok(u) = rx.try_recv() {
            out.push(match u.state {
                StreamingUpdateState::Register { live: true, .. } => "register+live",
                StreamingUpdateState::Register { .. } => "register",
                StreamingUpdateState::Start { .. } => "start",
                StreamingUpdateState::Stop { .. } => "stop",
                StreamingUpdateState::Deregister { .. } => "deregister",
                _ => "other",
            });
        }
        out
    }

    /// #121: a member first carried by a `send`-only grant is registered
    /// without live delivery; a replacement grant that adds `receive` turns
    /// it on (and does not register the member again), and narrowing it back
    /// to `send` turns it off.
    #[tokio::test]
    async fn a_grant_gaining_receive_starts_live_delivery_and_losing_it_stops_it() {
        let registry = MuxRegistry::default();
        let store = MemoryStore::new();
        let principal = "did:example:device";
        let _conn = connected(&registry, principal);
        let (streaming, mut rx) = streaming();
        let send_only = MuxScope::new([MuxCapability::Send]).unwrap();

        let mut g1 = grant("g1", "did:example:work", principal);
        g1.scope = send_only.clone();
        put(&store, &g1).await;
        registry
            .admit_grants(Some(&streaming), &store, &LIMITS, 0, &[g1])
            .await;
        assert_eq!(
            sent(&mut rx),
            ["register"],
            "send-only: registered, not live"
        );

        let mut g2 = grant("g2", "did:example:work", principal);
        g2.iat = 2;
        put(&store, &g2).await;
        registry
            .admit_grants(
                Some(&streaming),
                &store,
                &LIMITS,
                0,
                std::slice::from_ref(&g2),
            )
            .await;
        assert_eq!(
            sent(&mut rx),
            ["start"],
            "gaining receive starts live delivery, without registering again"
        );

        let mut narrowed = g2.clone();
        narrowed.narrowed_scope = Some(send_only);
        registry.narrow(Some(&streaming), &[narrowed]).await;
        assert_eq!(
            sent(&mut rx),
            ["stop"],
            "losing receive and pickup stops it"
        );
    }

    /// #121: re-admitting a member the connection already carries, with the
    /// same live wish (an attach renewal), sends the streaming task nothing.
    #[tokio::test]
    async fn renewing_a_carried_member_does_not_register_it_again() {
        let registry = MuxRegistry::default();
        let conn = connected(&registry, "did:example:device");
        let (streaming, mut rx) = streaming();
        let member = super::super::session::gauge_tests::member(
            "did:example:work",
            super::super::session::MuxSource::Attach,
            1_000,
        );
        conn.reconcile_member(Some(&streaming), &member, None).await;
        // One command: a live registration is its own `Start` (#128).
        assert_eq!(sent(&mut rx), ["register+live"]);
        conn.reconcile_member(Some(&streaming), &member, Some(true))
            .await;
        assert!(sent(&mut rx).is_empty(), "a renewal is not a registration");
    }

    #[tokio::test]
    async fn a_grant_stored_while_connected_is_carried_at_once() {
        let registry = MuxRegistry::default();
        let store = MemoryStore::new();
        let principal = "did:example:device";
        let conn = connected(&registry, principal);

        let g1 = grant("g1", "did:example:work", principal);
        put(&store, &g1).await;
        registry.admit_grants(None, &store, &LIMITS, 0, &[g1]).await;
        let member = conn
            .session
            .lock()
            .await
            .get(&did_hash("did:example:work"))
            .cloned();
        assert!(matches!(
            member.map(|m| m.source),
            Some(super::super::session::MuxSource::Grant { grant_id }) if grant_id == "g1"
        ));
        assert_eq!(
            conn.joined.lock().await.len(),
            1,
            "an attached event is queued"
        );

        // A replacing grant takes over, so revoking *it* detaches the member.
        let g2 = grant("g2", "did:example:work", principal);
        put(&store, &g2).await;
        registry
            .admit_grants(None, &store, &LIMITS, 0, std::slice::from_ref(&g2))
            .await;
        registry
            .detach_grants(None, &[g2], LeaveReason::RevokedByMember)
            .await;
        assert!(conn.session.lock().await.is_empty());

        // Another principal's grant is not carried here.
        let g3 = grant("g3", "did:example:home", "did:example:other");
        put(&store, &g3).await;
        registry.admit_grants(None, &store, &LIMITS, 0, &[g3]).await;
        assert!(conn.session.lock().await.is_empty());
    }

    #[tokio::test]
    async fn only_the_grant_the_store_holds_is_carried() {
        let registry = MuxRegistry::default();
        let store = MemoryStore::new();
        let principal = "did:example:device";
        let conn = connected(&registry, principal);
        let work = did_hash("did:example:work");

        // Never stored (or already revoked): not carried.
        let ghost = grant("ghost", "did:example:work", principal);
        registry
            .admit_grants(None, &store, &LIMITS, 0, &[ghost])
            .await;
        assert!(conn.session.lock().await.is_empty());

        // Two grants for one DID finish out of order: the newer one is
        // stored, and the older one's late admission must not displace it.
        let mut old = grant("old", "did:example:work", principal);
        old.scope = MuxScope::new([MuxCapability::Receive, MuxCapability::Delete]).unwrap();
        let new = grant("new", "did:example:work", principal);
        put(&store, &new).await;
        registry
            .admit_grants(None, &store, &LIMITS, 0, &[new])
            .await;
        registry
            .admit_grants(None, &store, &LIMITS, 0, &[old])
            .await;
        let member = conn.session.lock().await.get(&work).cloned().unwrap();
        assert_eq!(
            member.source,
            super::super::session::MuxSource::Grant {
                grant_id: "new".into()
            }
        );
        assert_eq!(
            member.scope,
            MuxScope::new([MuxCapability::Receive]).unwrap()
        );

        // A suspended grant is not carried.
        let registry = MuxRegistry::default();
        let conn = connected(&registry, principal);
        let mut s = grant("sus", "did:example:home", principal);
        s.state = MuxGrantState::Suspended;
        put(&store, &s).await;
        registry.admit_grants(None, &store, &LIMITS, 0, &[s]).await;
        assert!(conn.session.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_late_admission_of_an_older_grant_does_not_displace_a_newer_one() {
        let registry = MuxRegistry::default();
        let principal = "did:example:device";
        let conn = connected(&registry, principal);
        let member = |id: &str, iat: u64, scope: MuxScope| MuxMember {
            did: "did:example:work".into(),
            did_hash: did_hash("did:example:work"),
            source: super::super::session::MuxSource::Grant {
                grant_id: id.into(),
            },
            scope,
            kid: "did:example:work#key-1".into(),
            key_fp: "fp".into(),
            expires_at: u64::MAX / 2,
            grant_iat: iat,
            attached_at: 0,
        };
        let narrow = MuxScope::new([MuxCapability::Receive]).unwrap();
        let wide = MuxScope::new([MuxCapability::Receive, MuxCapability::Delete]).unwrap();
        let mut s = conn.session.lock().await;
        assert!(
            s.admit_grant(member("new", 2, narrow.clone()))
                .unwrap()
                .is_some()
        );
        assert!(s.admit_grant(member("old", 1, wide)).unwrap().is_none());
        assert!(
            s.admit_grant(member("new", 2, narrow.clone()))
                .unwrap()
                .is_none()
        );
        let m = s.get(&did_hash("did:example:work")).unwrap();
        assert_eq!(m.scope, narrow);
        assert_eq!(m.grant_iat, 2);
    }

    /// A member whose admission has lapsed gets no more live frames, even
    /// before the sweep takes it off the connection; the principal's own
    /// frames are unaffected.
    #[tokio::test]
    async fn a_lapsed_member_gets_no_live_frames_before_the_sweep() {
        let registry = MuxRegistry::default();
        let principal = "did:example:device";
        let conn = connected(&registry, principal);
        let member = |did: &str, scope: MuxScope| MuxMember {
            did: did.into(),
            did_hash: did_hash(did),
            source: super::super::session::MuxSource::Attach,
            scope,
            kid: format!("{did}#key-1"),
            key_fp: "fp".into(),
            expires_at: 100,
            grant_iat: 0,
            attached_at: 0,
        };
        {
            let mut s = conn.session.lock().await;
            s.admit(member(
                "did:example:work",
                MuxScope::new([MuxCapability::Receive]).unwrap(),
            ))
            .unwrap();
            s.admit(member(
                "did:example:home",
                MuxScope::new([MuxCapability::Pickup]).unwrap(),
            ))
            .unwrap();
        }
        let work = did_hash("did:example:work");
        let home = did_hash("did:example:home");
        assert_eq!(conn.live_frame(&work, 99).await, LiveFrame::Write);
        assert_eq!(conn.live_frame(&home, 99).await, LiveFrame::Nudge);
        for now in [100, 101] {
            assert_eq!(conn.live_frame(&work, now).await, LiveFrame::Drop);
            assert_eq!(conn.live_frame(&home, now).await, LiveFrame::Drop);
        }
        assert_eq!(
            conn.live_frame(&did_hash(principal), u64::MAX).await,
            LiveFrame::Write
        );
    }

    fn attach_member(did: &str, attached_at: u64) -> MuxMember {
        MuxMember {
            did: did.into(),
            did_hash: did_hash(did),
            source: super::super::session::MuxSource::Attach,
            scope: MuxScope::new([MuxCapability::Receive]).unwrap(),
            kid: format!("{did}#key-1"),
            key_fp: "fp".into(),
            expires_at: u64::MAX / 2,
            grant_iat: 0,
            attached_at,
        }
    }

    /// A decision taken on a snapshot of a member removes it only while the
    /// member is still on the connection as it was seen.
    #[tokio::test]
    async fn a_conditional_detach_leaves_a_member_that_changed() {
        let registry = MuxRegistry::default();
        let conn = connected(&registry, "did:example:device");
        let snap = attach_member("did:example:work", 10);
        conn.session.lock().await.admit(snap.clone()).unwrap();
        // Widened meanwhile (a grant merged in): the stale decision misses.
        let mut wider = snap.clone();
        wider.scope = MuxScope::new([MuxCapability::Receive, MuxCapability::Delete]).unwrap();
        conn.session.lock().await.admit(wider).unwrap();
        let same = |m: &MuxMember| m.source == snap.source && m.scope == snap.scope;
        assert!(
            conn.detach_if(None, &snap.did_hash, LeaveReason::AccountBlocked, same)
                .await
                .is_none()
        );
        assert!(conn.session.lock().await.get(&snap.did_hash).is_some());
        assert!(conn.left.lock().await.is_empty(), "no event for a miss");
        // As seen: removed, with its event.
        assert!(
            conn.detach_if(None, &snap.did_hash, LeaveReason::AccountBlocked, |_| true)
                .await
                .is_some()
        );
        assert_eq!(conn.left.lock().await.len(), 1);
    }

    /// A member's `revoke-all` at `at` ends its session attaches admitted by
    /// then, on every connection, and nothing else: not an attach admitted
    /// later, not a member carried by a grant, not another DID.
    #[tokio::test]
    async fn revoke_all_ends_the_attaches_admitted_before_it() {
        let registry = MuxRegistry::default();
        let (tx, _rx) = mpsc::channel(8);
        let conn_for = |session: &str, principal: &str| {
            let conn = Arc::new(MuxConn::new(
                MuxSession::new(principal, session, 10),
                tx.clone(),
                Arc::new(AtomicBool::new(false)),
            ));
            registry.insert(session, &did_hash(principal), conn.clone());
            conn
        };
        let a = conn_for("s-a", "did:example:device-a");
        let b = conn_for("s-b", "did:example:device-b");
        let c = conn_for("s-c", "did:example:device-c");
        let d = conn_for("s-d", "did:example:device-d");
        let work = "did:example:work";
        a.session
            .lock()
            .await
            .admit(attach_member(work, 50))
            .unwrap();
        b.session
            .lock()
            .await
            .admit(attach_member(work, 100))
            .unwrap();
        // Attached after the revoke-all: stays.
        c.session
            .lock()
            .await
            .admit(attach_member(work, 101))
            .unwrap();
        // Carried by a grant: the grant's own detach handles it.
        let mut by_grant = attach_member(work, 0);
        by_grant.source = super::super::session::MuxSource::Grant {
            grant_id: "g".into(),
        };
        d.session.lock().await.admit(by_grant).unwrap();
        a.session
            .lock()
            .await
            .admit(attach_member("did:example:home", 50))
            .unwrap();

        registry
            .detach_attaches(None, &did_hash(work), 100, LeaveReason::EpochBumped)
            .await;
        let has = async |conn: &Arc<MuxConn>, did: &str| {
            conn.session.lock().await.get(&did_hash(did)).is_some()
        };
        assert!(!has(&a, work).await);
        assert!(!has(&b, work).await);
        assert!(has(&c, work).await);
        assert!(has(&d, work).await);
        assert!(has(&a, "did:example:home").await);
        let left = a.left.lock().await.clone();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].1, LeaveReason::EpochBumped);
    }
}
