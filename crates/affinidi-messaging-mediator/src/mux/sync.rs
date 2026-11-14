//! Mux grant changes across mediator instances (design §7.4).
//!
//! Each instance changes its *own* live connections before it answers a
//! revoke, suspension, update or new grant (§7.3, through
//! [`MuxRegistry`]). The same principal may be connected to another instance
//! sharing the store; that instance learns of the change here:
//!
//! 1. The handling instance, after its local update, [`publish`]es a
//!    [`MuxChangeRecord`] — (member, principal) hash pairs and its own
//!    instance id — on the store's mux pub/sub channel. Best-effort: a
//!    failure is logged and the periodic re-check in `connection::sweep`
//!    still applies the change within one sweep interval.
//! 2. Every instance's listener ([`run`]) ignores its own records and, for
//!    each pair whose principal is connected here, re-reads the member's
//!    record and [`reconcile`]s: drops a member whose grant is gone or no
//!    longer active, applies a narrowing, and carries a grant just stored.
//!    The store decides, never the record, so a late, repeated or reordered
//!    record is harmless.
//! 3. A listener that lagged or lost its subscription missed records, so it
//!    re-checks every member of every local mux connection ([`resync`]).
//!
//! A record may also carry [`MemberHint`]s: a member DID's account changed
//! (re-check its standing wherever it is carried) or it ran `revoke-all`
//! (end its session attaches). A receiver re-reads the account for the
//! first; the second names the time of the `revoke-all`, so an attach made
//! after it is kept.
//!
//! No session lock is held across a store read (R1.3).

use std::collections::HashSet;
use std::time::Duration;

use affinidi_messaging_mediator_common::store::{
    mux::{self, MemberHint, MuxChange, MuxChangeRecord, MuxGrantState, MuxLimits},
    prelude::*,
};
use tokio::sync::broadcast::{self, error::RecvError};
use tracing::{debug, info, warn};

use super::connection::grant_leave_reason;
use super::registry::MuxRegistry;
use super::session::MuxSource;
use super::tasks::Changed;
use crate::SharedData;
use crate::tasks::websocket_streaming::StreamingTask;

/// The pairs a Trust Task's [`Changed`] touched, for [`publish`]. A removed
/// pair carries the reason this instance detached it with, so the other
/// instances report the same one.
pub fn changes_of(changed: &Changed) -> Vec<MuxChange> {
    let removed = changed.removed.iter().map(|g| {
        let c = MuxChange::of(g, false);
        match changed.reason {
            Some(r) => c.with_reason(r.wire()),
            None => c,
        }
    });
    removed
        .chain(
            changed
                .suspended
                .iter()
                .chain(&changed.narrowed)
                .map(|g| MuxChange::of(g, false)),
        )
        .chain(changed.stored.iter().map(|g| MuxChange::of(g, true)))
        .collect()
}

/// One entry per pair, `stored` if any entry for it was.
fn dedupe(changes: &[MuxChange]) -> Vec<MuxChange> {
    let mut out: Vec<MuxChange> = Vec::with_capacity(changes.len());
    for c in changes {
        match out
            .iter_mut()
            .find(|o| o.did_hash == c.did_hash && o.principal_hash == c.principal_hash)
        {
            Some(o) => o.stored |= c.stored,
            None => out.push(c.clone()),
        }
    }
    out
}

/// Tell the other instances sharing the store that these pairs changed. Call
/// it after this instance's own connections are updated.
pub async fn publish(state: &SharedData, changes: &[MuxChange]) {
    if changes.is_empty() {
        return;
    }
    let record = MuxChangeRecord {
        origin: state.config.streaming_uuid.clone(),
        changes: dedupe(changes),
        streaming: Vec::new(),
        members: Vec::new(),
    };
    if let Err(e) = state.database.mux_changes_publish(&record).await {
        warn!(
            pairs = record.changes.len(),
            "mux grant change not published to other mediator instances; their periodic \
             re-check applies it within one sweep interval: {e}"
        );
    }
}

/// Tell the other instances sharing the store that these member DIDs
/// changed (account standing, `revoke-all`). Call it after this instance's
/// own connections are updated. Best-effort, as [`publish`] is: a lost
/// record leaves the change to each connection's standing pass.
pub async fn publish_members(state: &SharedData, members: &[MemberHint]) {
    if members.is_empty() {
        return;
    }
    let record = MuxChangeRecord {
        origin: state.config.streaming_uuid.clone(),
        changes: Vec::new(),
        streaming: Vec::new(),
        members: members.to_vec(),
    };
    if let Err(e) = state.database.mux_changes_publish(&record).await {
        warn!(
            members = record.members.len(),
            "mux member change not published to other mediator instances; their standing \
             pass applies it within one interval: {e}"
        );
    }
}

/// Apply member changes another instance published to this instance's live
/// connections.
async fn apply_members(state: &SharedData, members: &[MemberHint]) {
    for hint in members {
        match hint {
            MemberHint::StandingChanged { did_hash } => {
                super::connection::recheck_member(state, did_hash).await;
            }
            MemberHint::AttachesEnded {
                did_hash,
                at,
                reason,
            } => {
                use super::session::LeaveReason;
                let reason = reason
                    .as_deref()
                    .and_then(LeaveReason::removal_from_wire)
                    .unwrap_or(LeaveReason::EpochBumped);
                state
                    .mux
                    .detach_attaches(state.streaming_task.as_ref(), did_hash, *at, reason)
                    .await;
            }
        }
    }
}

/// Bring this instance's live connections in line with what the store holds
/// for each changed pair. Pairs whose principal has no connection here are
/// skipped without a read.
pub async fn reconcile(
    registry: &MuxRegistry,
    store: &dyn MediatorStore,
    streaming: Option<&StreamingTask>,
    limits: &MuxLimits,
    now: u64,
    changes: &[MuxChange],
) {
    for c in changes {
        if registry.for_principal(&c.principal_hash).is_empty() {
            continue;
        }

        // A grant just stored is carried first, so one that replaces an
        // earlier grant takes the member over in place (an `attached` event
        // and nothing else, as on the instance that stored it). `admit_grants`
        // re-reads the grant and admits it only if it is still active.
        if c.stored {
            match mux::load(store, &c.did_hash, limits, now).await {
                Ok(rec) => {
                    if let Some(g) = rec.grants.iter().find(|g| {
                        g.principal_hash == c.principal_hash
                            && matches!(g.state_at(now), MuxGrantState::Active)
                    }) {
                        registry
                            .admit_grants(streaming, store, limits, now, std::slice::from_ref(g))
                            .await;
                    }
                }
                Err(e) => warn!(
                    member = %c.did_hash,
                    principal = %c.principal_hash,
                    "stored mux grant not carried from another instance, store unreadable: {e}"
                ),
            }
        }

        // Which grant each connection holds the member by, read *before* the
        // record: a grant admitted after this snapshot was stored before it
        // was admitted, so it is never judged against a record that predates
        // it; and the detach below only removes the member if the grant it
        // judged still holds it.
        let mut held = Vec::new();
        for conn in registry.for_principal(&c.principal_hash) {
            let grant_id = {
                let s = conn.session.lock().await;
                match s.get(&c.did_hash).map(|m| &m.source) {
                    Some(MuxSource::Grant { grant_id }) => Some(grant_id.clone()),
                    _ => None,
                }
            };
            if let Some(grant_id) = grant_id {
                held.push((conn, grant_id));
            }
        }
        if held.is_empty() {
            continue;
        }

        let rec = match mux::load(store, &c.did_hash, limits, now).await {
            Ok(rec) => rec,
            // As the periodic re-check does: keep the member and let the next
            // sweep look again.
            Err(e) => {
                warn!(
                    member = %c.did_hash,
                    principal = %c.principal_hash,
                    "mux change from another instance not applied, store unreadable; the \
                     periodic re-check retries: {e}"
                );
                continue;
            }
        };
        for (conn, grant_id) in held {
            match leave_reason(&rec, &grant_id, now, c.reason.as_deref()) {
                Some(reason) => {
                    if conn
                        .detach_grant_id(streaming, &c.did_hash, &grant_id, reason)
                        .await
                        .is_some()
                    {
                        debug!(member = %c.did_hash, principal = %c.principal_hash, ?reason, "detached mux member on a change from another instance");
                    }
                }
                // Still active. Re-scope only a grant that was narrowed, as
                // `mux/update` does where it is handled: re-applying an
                // unchanged grant would strip a merged attach's extra scope.
                None => {
                    if let Some(g) = rec.grants.iter().find(|g| g.grant_id == grant_id)
                        && (g.narrowed_scope.is_some() || g.narrowed_exp.is_some())
                    {
                        conn.narrow(streaming, g).await;
                    }
                }
            }
        }
    }
}

/// Why a member admitted by `grant_id` leaves, as the store decides, labelled
/// with the reason the originating instance gave where the store cannot tell
/// it: a deleted grant reads as `revokedByMember` and a voided one as
/// `epochBumped` whoever ended it, so the hint's `revokedByPrincipal` or
/// `admin` is kept for those two. The hint never makes a member leave.
fn leave_reason(
    rec: &mux::MuxDidRecord,
    grant_id: &str,
    now: u64,
    hint: Option<&str>,
) -> Option<super::session::LeaveReason> {
    use super::session::LeaveReason;
    let from_store = grant_leave_reason(rec, grant_id, now)?;
    let hinted = hint.and_then(LeaveReason::removal_from_wire);
    Some(match (from_store, hinted) {
        (LeaveReason::RevokedByMember | LeaveReason::EpochBumped, Some(h)) => h,
        _ => from_store,
    })
}

/// [`reconcile`] against this instance's state.
async fn apply(state: &SharedData, changes: &[MuxChange]) {
    reconcile(
        &state.mux,
        &*state.database,
        state.streaming_task.as_ref(),
        &state.config.limits.mux.store_limits(),
        state.clock.unix_secs(),
        changes,
    )
    .await;
}

/// Re-check every grant-admitted member of every local mux connection, for
/// when records may have been missed.
///
/// Drops and narrows only. A grant stored elsewhere while records were being
/// missed is carried at the principal's next connection: this instance did
/// not see it stored, so it cannot tell it from one its connection refused on
/// connect (see [`MuxChange::stored`]).
pub async fn resync(state: &SharedData) {
    let mut pairs: HashSet<MuxChange> = HashSet::new();
    for conn in state.mux.all() {
        let s = conn.session.lock().await;
        for m in s.members() {
            if let MuxSource::Grant { .. } = m.source {
                pairs.insert(MuxChange {
                    did_hash: m.did_hash.clone(),
                    principal_hash: s.principal_hash.clone(),
                    stored: false,
                    reason: None,
                });
            }
        }
    }
    let pairs: Vec<MuxChange> = pairs.into_iter().collect();
    if !pairs.is_empty() {
        debug!(pairs = pairs.len(), "re-checking every mux member");
    }
    apply(state, &pairs).await;
    // Account-standing hints may have been missed too: re-check every
    // member's standing now rather than at each connection's next pass.
    for conn in state.mux.all() {
        super::connection::spawn_standing_pass(state, &conn);
    }
}

/// Delays between attempts to resubscribe after the subscription closes,
/// before giving up to the supervisor (which backs off further and restarts
/// the listener, reporting it degraded meanwhile, R6.5).
const RESUBSCRIBE_BACKOFF: [Duration; 6] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

async fn subscribe(
    state: &SharedData,
) -> Result<Option<broadcast::Receiver<MuxChangeRecord>>, String> {
    state
        .database
        .mux_changes_subscribe()
        .await
        .map_err(|e| format!("mux change subscription failed: {e}"))
}

/// The listener: run under the task supervisor for as long as mux is
/// enabled. Returns `Err` only when it cannot subscribe, so the supervisor
/// restarts it and readiness shows it degraded; the periodic re-check keeps
/// applying changes meanwhile.
pub async fn run(state: SharedData) -> Result<(), String> {
    let Some(mut rx) = subscribe(&state).await? else {
        // A single-process store: no other instance to hear from.
        debug!("store is single-process; no cross-instance mux changes to listen for");
        state.shutdown_token.cancelled().await;
        return Ok(());
    };
    info!("listening for mux grant changes from other mediator instances");
    // Changes made before (or while re-) subscribing were not heard.
    resync(&state).await;

    let me = state.config.streaming_uuid.clone();
    loop {
        match rx.recv().await {
            // Applied before it was published.
            Ok(record) if record.origin == me => {}
            Ok(record) => {
                if !record.changes.is_empty() {
                    apply(&state, &record.changes).await;
                }
                apply_members(&state, &record.members).await;
                forward_handoffs(&state, &me, &record.streaming).await;
            }
            Err(RecvError::Lagged(missed)) => {
                warn!(
                    missed,
                    "mux change listener fell behind; re-checking every mux connection"
                );
                resync(&state).await;
            }
            Err(RecvError::Closed) => {
                warn!("mux change subscription lost; resubscribing");
                rx = resubscribe(&state).await?;
                info!("mux change subscription restored; re-checking every mux connection");
                resync(&state).await;
            }
        }
    }
}

/// Hand the streaming task the handoffs meant for this instance: a mux
/// entry here that another instance's registration displaced, or a DID whose
/// owner elsewhere left while a mux entry here waited for it.
async fn forward_handoffs(
    state: &SharedData,
    me: &str,
    handoffs: &[affinidi_messaging_mediator_common::store::mux::StreamingHandoff],
) {
    use crate::tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState};
    use affinidi_messaging_mediator_common::store::mux::StreamingHandoff;
    let Some(streaming) = state.streaming_task.as_ref() else {
        return;
    };
    for handoff in handoffs {
        let (did_hash, update) = match handoff {
            StreamingHandoff::Taken { did_hash, instance } if instance == me => {
                (did_hash, StreamingUpdateState::RemoteTaken)
            }
            StreamingHandoff::Taken { .. } => continue,
            StreamingHandoff::Released { did_hash } => {
                (did_hash, StreamingUpdateState::RemoteReleased)
            }
        };
        let _ = streaming
            .channel
            .send(StreamingUpdate {
                did_hash: did_hash.clone(),
                state: update,
            })
            .await;
    }
}

async fn resubscribe(state: &SharedData) -> Result<broadcast::Receiver<MuxChangeRecord>, String> {
    let mut last = String::new();
    for delay in RESUBSCRIBE_BACKOFF {
        tokio::time::sleep(delay).await;
        match subscribe(state).await {
            Ok(Some(rx)) => return Ok(rx),
            Ok(None) => return Err("store stopped offering mux change subscriptions".into()),
            Err(e) => {
                warn!("{e}; retrying");
                last = e;
            }
        }
    }
    Err(last)
}

#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::mux::registry::MuxConn;
    use crate::mux::session::{LeaveReason, MuxSession};
    use crate::store::MemoryStore;
    use affinidi_messaging_mediator_common::did_identity::did_hash;
    use affinidi_messaging_mediator_common::store::mux::{MuxCapability, MuxGrant, MuxScope};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    const LIMITS: MuxLimits = MuxLimits {
        max_grants_per_did: 16,
        max_grants_per_principal: 16,
        max_grant_lifetime_secs: u64::MAX,
        dead_retention_secs: u64::MAX / 4,
    };
    const NOW: u64 = 100;
    const PRINCIPAL: &str = "did:example:device";
    const WORK: &str = "did:example:work";

    fn grant(id: &str, iat: u64) -> MuxGrant {
        MuxGrant {
            grant_id: id.into(),
            did: WORK.into(),
            did_hash: did_hash(WORK),
            principal: PRINCIPAL.into(),
            principal_hash: did_hash(PRINCIPAL),
            kid: format!("{WORK}#key-1"),
            key_fp: "fp".into(),
            did_version: None,
            epoch: 0,
            scope: MuxScope::new([MuxCapability::Receive, MuxCapability::Delete]).unwrap(),
            iat,
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

    /// Make the store hold exactly `g` for the principal on its member DID,
    /// or nothing when `g` is `None`.
    async fn put(store: &MemoryStore, g: Option<&MuxGrant>) {
        mux::modify(store, &did_hash(WORK), &LIMITS, NOW, None, |rec, _| {
            rec.grants
                .retain(|x| x.principal_hash != did_hash(PRINCIPAL));
            rec.grants.extend(g.cloned());
            Ok(())
        })
        .await
        .unwrap();
    }

    /// One mediator instance: its registry, with the principal connected.
    struct Instance {
        registry: MuxRegistry,
        conn: Arc<MuxConn>,
    }

    impl Instance {
        fn new(session: &str) -> Self {
            let registry = MuxRegistry::default();
            let (tx, _rx) = mpsc::channel(8);
            let conn = Arc::new(MuxConn::new(
                MuxSession::new(PRINCIPAL, session, 10),
                tx,
                Arc::new(AtomicBool::new(false)),
            ));
            registry.insert(session, &did_hash(PRINCIPAL), conn.clone());
            Self { registry, conn }
        }

        /// What `consume_mux` does locally for a new grant.
        async fn stored(&self, store: &MemoryStore, g: &MuxGrant) {
            self.registry
                .admit_grants(None, store, &LIMITS, NOW, std::slice::from_ref(g))
                .await;
        }

        /// A record from the other instance arrives.
        async fn hear(&self, store: &MemoryStore, changes: &[MuxChange]) {
            reconcile(&self.registry, store, None, &LIMITS, NOW, changes).await;
        }

        async fn member(&self) -> Option<crate::mux::session::MuxMember> {
            self.conn.session.lock().await.get(&did_hash(WORK)).cloned()
        }

        async fn left(&self) -> Vec<LeaveReason> {
            std::mem::take(&mut *self.conn.left.lock().await)
                .into_iter()
                .map(|(_, r)| r)
                .collect()
        }
    }

    /// Two instances share one store; the principal is connected to both and
    /// both carry `g`.
    async fn both_carrying(g: &MuxGrant) -> (MemoryStore, Instance, Instance) {
        let store = MemoryStore::new();
        put(&store, Some(g)).await;
        let (a, b) = (Instance::new("on-a"), Instance::new("on-b"));
        a.stored(&store, g).await;
        b.stored(&store, g).await;
        assert!(a.member().await.is_some() && b.member().await.is_some());
        (store, a, b)
    }

    #[tokio::test]
    async fn a_revoke_on_one_instance_detaches_on_the_other() {
        let g = grant("g1", 1);
        let (store, a, b) = both_carrying(&g).await;

        // Revoked on A: the store loses it and A detaches before answering.
        put(&store, None).await;
        a.registry
            .detach_grants(None, std::slice::from_ref(&g), LeaveReason::RevokedByMember)
            .await;
        assert!(a.member().await.is_none());
        assert!(b.member().await.is_some(), "B has not heard yet");

        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        assert!(b.member().await.is_none());
        assert_eq!(b.left().await, vec![LeaveReason::RevokedByMember]);
    }

    #[tokio::test]
    async fn a_suspension_maps_to_its_own_reason() {
        let g = grant("g1", 1);
        let (store, _a, b) = both_carrying(&g).await;
        let mut suspended = g.clone();
        suspended.state = MuxGrantState::Suspended;
        put(&store, Some(&suspended)).await;

        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        assert!(b.member().await.is_none());
        assert_eq!(b.left().await, vec![LeaveReason::SuspendedUnknownKey]);

        // Epoch bump (revoke-all) likewise.
        let g = grant("g2", 2);
        let (store, _a, b) = both_carrying(&g).await;
        let mut voided = g.clone();
        voided.state = MuxGrantState::EpochRevoked;
        put(&store, Some(&voided)).await;
        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        assert_eq!(b.left().await, vec![LeaveReason::EpochBumped]);

        // An administrator's advance reads as `admin` from the record alone,
        // with no hint (a resync, or a record from an older instance).
        let g = grant("g3", 3);
        let (store, _a, b) = both_carrying(&g).await;
        let mut voided = g.clone();
        voided.state = MuxGrantState::EpochRevoked;
        voided.voided_by = Some(mux::MuxVoidedBy::Admin);
        put(&store, Some(&voided)).await;
        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        assert_eq!(b.left().await, vec![LeaveReason::Admin]);
    }

    #[tokio::test]
    async fn a_narrowing_on_one_instance_narrows_on_the_other() {
        let g = grant("g1", 1);
        let (store, _a, b) = both_carrying(&g).await;
        let mut narrowed = g.clone();
        narrowed.narrowed_scope = Some(MuxScope::new([MuxCapability::Receive]).unwrap());
        narrowed.narrowed_exp = Some(NOW + 50);
        put(&store, Some(&narrowed)).await;

        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        let m = b.member().await.expect("still carried");
        assert_eq!(m.scope, MuxScope::new([MuxCapability::Receive]).unwrap());
        assert_eq!(m.expires_at, NOW + 50);
        assert!(b.left().await.is_empty());
    }

    #[tokio::test]
    async fn a_grant_stored_on_one_instance_is_carried_on_the_other() {
        let store = MemoryStore::new();
        let (a, b) = (Instance::new("on-a"), Instance::new("on-b"));
        let g = grant("g1", 1);
        put(&store, Some(&g)).await;
        a.stored(&store, &g).await;

        b.hear(&store, &[MuxChange::of(&g, true)]).await;
        let m = b.member().await.expect("carried on B");
        assert_eq!(
            m.source,
            MuxSource::Grant {
                grant_id: "g1".into()
            }
        );
        assert_eq!(b.conn.joined.lock().await.len(), 1, "B reports `attached`");

        // A replacing grant takes the member over in place on B too: no
        // detach on the way.
        let g2 = grant("g2", 2);
        put(&store, Some(&g2)).await;
        b.hear(&store, &[MuxChange::of(&g2, true)]).await;
        assert_eq!(
            b.member().await.unwrap().source,
            MuxSource::Grant {
                grant_id: "g2".into()
            }
        );
        assert!(b.left().await.is_empty());
    }

    #[tokio::test]
    async fn only_a_stored_change_carries_a_grant() {
        // B's connection is not carrying an active grant (say it refused it
        // on connect). A change that is not a new grant must not admit it.
        let store = MemoryStore::new();
        let b = Instance::new("on-b");
        let g = grant("g1", 1);
        put(&store, Some(&g)).await;
        b.hear(&store, &[MuxChange::of(&g, false)]).await;
        assert!(b.member().await.is_none());
    }

    #[tokio::test]
    async fn a_stored_change_for_a_grant_since_revoked_carries_nothing() {
        let store = MemoryStore::new();
        let b = Instance::new("on-b");
        let g = grant("g1", 1);
        // Stored then revoked before B heard of it.
        put(&store, None).await;
        b.hear(&store, &[MuxChange::of(&g, true)]).await;
        assert!(b.member().await.is_none());
        assert!(b.conn.joined.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_principal_not_connected_here_is_ignored_and_others_are_untouched() {
        let g = grant("g1", 1);
        let (store, _a, b) = both_carrying(&g).await;
        // A change for some other principal's pair, and a duplicate of one
        // for this principal that changed nothing: B keeps its member.
        let other = MuxChange {
            did_hash: did_hash(WORK),
            principal_hash: did_hash("did:example:other"),
            stored: false,
            reason: None,
        };
        b.hear(&store, &[other, MuxChange::of(&g, false)]).await;
        assert!(b.member().await.is_some());
        assert!(b.left().await.is_empty());
    }

    /// The originating instance's reason labels a detach the store cannot
    /// attribute (a deleted or voided grant), and never overrides one it can
    /// or makes a member with an active grant leave.
    #[test]
    fn a_hinted_reason_labels_only_what_the_store_cannot_attribute() {
        use mux::MuxDidRecord;
        let gone = MuxDidRecord::default();
        assert_eq!(
            leave_reason(&gone, "g1", 10, Some("admin")),
            Some(LeaveReason::Admin)
        );
        assert_eq!(
            leave_reason(&gone, "g1", 10, Some("revokedByPrincipal")),
            Some(LeaveReason::RevokedByPrincipal)
        );
        assert_eq!(
            leave_reason(&gone, "g1", 10, None),
            Some(LeaveReason::RevokedByMember)
        );
        assert_eq!(
            leave_reason(&gone, "g1", 10, Some("superseded")),
            Some(LeaveReason::RevokedByMember),
            "not a removal reason"
        );

        let mut voided = grant("g1", 1);
        voided.state = MuxGrantState::EpochRevoked;
        let mut suspended = grant("g2", 1);
        suspended.state = MuxGrantState::Suspended;
        let rec = MuxDidRecord {
            grants: vec![voided, suspended, grant("g3", 1)],
            ..Default::default()
        };
        assert_eq!(
            leave_reason(&rec, "g1", 10, Some("admin")),
            Some(LeaveReason::Admin)
        );
        assert_eq!(
            leave_reason(&rec, "g2", 10, Some("admin")),
            Some(LeaveReason::SuspendedUnknownKey)
        );
        assert_eq!(leave_reason(&rec, "g3", 10, Some("admin")), None);
    }

    #[test]
    fn records_carry_hashes_only_and_merge_duplicates() {
        let g = grant("g1", 1);
        let merged = dedupe(&[MuxChange::of(&g, false), MuxChange::of(&g, true)]);
        assert_eq!(merged, vec![MuxChange::of(&g, true)]);

        let record = MuxChangeRecord {
            origin: "instance-a".into(),
            changes: vec![MuxChange::of(&g, false)],
            streaming: Vec::new(),
            members: Vec::new(),
        };
        let wire = serde_json::to_value(&record).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "origin": "instance-a",
                "changes": [{ "did_hash": did_hash(WORK), "principal_hash": did_hash(PRINCIPAL) }],
            })
        );
        assert!(!wire.to_string().contains("did:example"));
        let back: MuxChangeRecord = serde_json::from_value(wire).unwrap();
        assert_eq!(back, record);
    }

    /// Member hints travel as hashes and times, and a record from an
    /// instance that predates them still reads (with none).
    #[test]
    fn member_hints_are_hashes_and_optional_on_the_wire() {
        let record = MuxChangeRecord {
            origin: "instance-a".into(),
            changes: Vec::new(),
            streaming: Vec::new(),
            members: vec![
                MemberHint::StandingChanged {
                    did_hash: did_hash(WORK),
                },
                MemberHint::AttachesEnded {
                    did_hash: did_hash(WORK),
                    at: 42,
                    reason: None,
                },
            ],
        };
        let wire = serde_json::to_value(&record).unwrap();
        assert_eq!(
            wire["members"],
            serde_json::json!([
                { "event": "standingChanged", "didHash": did_hash(WORK) },
                { "event": "attachesEnded", "didHash": did_hash(WORK), "at": 42 },
            ])
        );
        assert!(!wire.to_string().contains("did:example"));
        let back: MuxChangeRecord = serde_json::from_value(wire).unwrap();
        assert_eq!(back, record);

        let older: MuxChangeRecord =
            serde_json::from_value(serde_json::json!({ "origin": "b", "changes": [] })).unwrap();
        assert!(older.members.is_empty());
    }
}
