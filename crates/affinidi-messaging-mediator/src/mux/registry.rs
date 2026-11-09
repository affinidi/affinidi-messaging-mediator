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
//! Scope is one process. Several mediator processes sharing one Redis would
//! need the cross-node detach of design §7.4; until that exists the mediator
//! refuses to enable mux on the Redis backend.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use affinidi_messaging_mediator_common::store::mux::MuxGrant;
use dashmap::DashMap;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use super::session::{LeaveReason, MuxMember, MuxSession};
use crate::tasks::websocket_streaming::{
    EntryKind, QueuedCommand, StreamingTask, StreamingUpdate, StreamingUpdateState,
};

/// One live mux connection.
pub struct MuxConn {
    pub session: Mutex<MuxSession>,
    /// The socket's send queue, which every member's streaming entry shares.
    pub tx: mpsc::Sender<QueuedCommand>,
    /// The socket's resync flag (shared by its members).
    pub resync: Arc<AtomicBool>,
    /// Members that left since the socket last reported; the socket loop
    /// drains this into `detached` events to the client.
    pub left: Mutex<Vec<(MuxMember, LeaveReason)>>,
    /// Wakes the socket loop to report `left`.
    pub notify: tokio::sync::Notify,
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
            left: Mutex::new(Vec::new()),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Register `member` with the streaming task on this connection's queue,
    /// and turn live delivery on when its scope includes `receive`.
    pub async fn register_member(&self, streaming: &StreamingTask, member: &MuxMember) {
        let session_id = self.session.lock().await.session_id.clone();
        let _ = streaming
            .channel
            .send(StreamingUpdate {
                did_hash: member.did_hash.clone(),
                state: StreamingUpdateState::Register {
                    channel: self.tx.clone(),
                    session_id: session_id.clone(),
                    did: member.did.clone(),
                    resync: self.resync.clone(),
                    kind: EntryKind::Mux,
                },
            })
            .await;
        if member
            .scope
            .contains(affinidi_messaging_mediator_common::store::mux::MuxCapability::Receive)
        {
            let _ = streaming
                .channel
                .send(StreamingUpdate {
                    did_hash: member.did_hash.clone(),
                    state: StreamingUpdateState::Start { session_id },
                })
                .await;
        }
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
        self.left.lock().await.push((member.clone(), reason));
        self.notify.notify_one();
        Some(member)
    }

    async fn deregister(
        &self,
        streaming: Option<&StreamingTask>,
        did_hash: &str,
        session_id: &str,
    ) {
        if let Some(streaming) = streaming {
            let _ = streaming
                .channel
                .send(StreamingUpdate {
                    did_hash: did_hash.to_string(),
                    state: StreamingUpdateState::Deregister {
                        session_id: session_id.to_string(),
                    },
                })
                .await;
        }
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
        if !gone.is_empty() {
            self.left
                .lock()
                .await
                .extend(gone.iter().cloned().map(|m| (m, reason)));
            self.notify.notify_one();
        }
        gone
    }

    /// Whether a frame tagged for `did_hash` may still be written: it is the
    /// principal's own, or a current member's.
    pub async fn may_write(&self, did_hash: &str) -> bool {
        let s = self.session.lock().await;
        did_hash == s.principal_hash || s.get(did_hash).is_some()
    }
}

/// All live mux connections, by session id and by principal.
#[derive(Default)]
pub struct MuxRegistry {
    conns: DashMap<String, Arc<MuxConn>>,
    by_principal: DashMap<String, HashSet<String>>,
}

impl MuxRegistry {
    pub fn insert(&self, session_id: &str, principal_hash: &str, conn: Arc<MuxConn>) {
        self.conns.insert(session_id.to_string(), conn);
        self.by_principal
            .entry(principal_hash.to_string())
            .or_default()
            .insert(session_id.to_string());
    }

    pub fn remove(&self, session_id: &str, principal_hash: &str) {
        self.conns.remove(session_id);
        if let Some(mut set) = self.by_principal.get_mut(principal_hash) {
            set.remove(session_id);
        }
        self.by_principal
            .remove_if(principal_hash, |_, s| s.is_empty());
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<MuxConn>> {
        self.conns.get(session_id).map(|c| c.clone())
    }

    fn for_principal(&self, principal_hash: &str) -> Vec<Arc<MuxConn>> {
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

    /// Re-scope members admitted by narrowed grants: the narrower scope or
    /// earlier expiry takes effect now.
    pub async fn narrow(&self, grants: &[MuxGrant]) {
        for g in grants {
            for conn in self.for_principal(&g.principal_hash) {
                conn.session.lock().await.narrow(g);
            }
        }
    }
}
