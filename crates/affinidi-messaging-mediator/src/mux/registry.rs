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
    MediatorStore,
    mux::{self, MuxGrant, MuxGrantState, MuxLimits},
};
use dashmap::DashMap;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

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
    /// Members admitted while connected (a new grant), for `attached` events.
    pub joined: Mutex<Vec<MuxMember>>,
    /// Wakes the socket loop to report `left` / `joined`.
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
            joined: Mutex::new(Vec::new()),
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
        self.left.lock().await.push((member.clone(), reason));
        self.notify.notify_one();
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

    /// Every live mux connection on this instance.
    pub fn all(&self) -> Vec<Arc<MuxConn>> {
        self.conns.iter().map(|c| c.value().clone()).collect()
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

    /// Carry the members of newly stored grants on every live connection of
    /// their principal, at once (design §4.4).
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
    ) {
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
            };
            for conn in self.for_principal(&g.principal_hash) {
                let admitted = conn.session.lock().await.admit_grant(member.clone());
                match admitted {
                    Ok(Some((member, new))) => {
                        if new && let Some(streaming) = streaming {
                            conn.register_member(streaming, &member).await;
                        }
                        conn.joined.lock().await.push(member);
                        conn.notify.notify_one();
                    }
                    Ok(None) => {}
                    // The connection is full. The grant stays stored and is
                    // carried by a connection with room, or after a
                    // reconnect; the client sees `stored` with no `attached`
                    // event. The spec has no event for this yet.
                    Err(e) => warn!(
                        principal = %g.principal_hash,
                        grant = %g.grant_id,
                        "stored grant not carried live: {e}"
                    ),
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
}
