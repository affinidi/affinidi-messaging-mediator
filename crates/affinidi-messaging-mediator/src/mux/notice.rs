//! Durable notices: `messaging/mux/notice/0.1` (design §4.9).
//!
//! A notice tells a party what it must act on even if it was offline when it
//! happened. It is a signed Trust Task document, packed to the recipient and
//! stored in its inbox like any other message, so it is delivered at least
//! once and acknowledged by deletion. The live `detached` event may also have
//! been sent; the notice is what a client relies on.
//!
//! Every notice here is stored only after the change it reports is committed
//! and its members are detached (spec, producer rule 2): callers run these
//! after the store write and the registry detach.
//!
//! **Process dies on the next line (R2.1).** A `grantsSuspended` or
//! `grantsRevoked`/`epochBumped` notice lost to a crash after the commit is
//! re-sent: such grants stay on the record with `noticed == false` until the
//! notice is stored, and [`recover`] sends any still owed when the principal
//! next opens a mux connection. A grant revoked by its member, or removed
//! with its account, is deleted from the record, so its `grantsRevoked`
//! notice is best effort; `messaging/mux/list` remains the source of truth.

use std::collections::{BTreeMap, HashMap, HashSet};

use affinidi_messaging_mediator_common::store::mux::{self, MuxGrant, MuxGrantState, NoticeWire};
use serde_json::{Value, json};
use tracing::{debug, warn};

use super::session::LeaveReason;
use super::tasks::Changed;
use crate::SharedData;

pub const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

/// The spec's `maxItems` for `suspensions`, `revocations` and `grantIds`.
const MAX_ITEMS: usize = 256;

/// One notice to store.
#[derive(Debug, Clone, PartialEq)]
pub struct Notice {
    pub recipient_did: String,
    pub recipient_hash: String,
    pub payload: Value,
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Which list notice: `grantsSuspended` or `grantsRevoked`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    Suspended,
    Revoked,
}

impl ListKind {
    fn names(self) -> (&'static str, &'static str, &'static str) {
        match self {
            ListKind::Suspended => ("grantsSuspended", "suspensions", "suspendedAt"),
            ListKind::Revoked => ("grantsRevoked", "revocations", "revokedAt"),
        }
    }
}

/// Member DID → (its grant ids, the latest change instant).
type Members<'a> = BTreeMap<&'a str, (Vec<&'a str>, u64)>;

/// `grantsSuspended` / `grantsRevoked` notices for `grants`: one per
/// principal (split at the spec's item limits), each with one entry per
/// member DID. `reason` is the spec's `DetachReason`; the instant is when the
/// grant's state changed, or `now` for a grant that was deleted.
pub fn per_principal(grants: &[MuxGrant], kind: ListKind, reason: &str, now: u64) -> Vec<Notice> {
    let (notice, list, at) = kind.names();
    // principal hash → (principal DID, member DID → (grant ids, instant))
    let mut by_principal: BTreeMap<&str, (&str, Members)> = BTreeMap::new();
    for g in grants {
        let (_, members) = by_principal
            .entry(&g.principal_hash)
            .or_insert((&g.principal, BTreeMap::new()));
        let (ids, when) = members.entry(&g.did).or_insert((Vec::new(), 0));
        ids.push(&g.grant_id);
        *when = (*when).max(g.state_changed_at.unwrap_or(now));
    }

    let mut out = Vec::new();
    for (principal_hash, (principal_did, members)) in by_principal {
        let entries: Vec<Value> = members
            .into_iter()
            .flat_map(|(did, (ids, when))| {
                ids.chunks(MAX_ITEMS)
                    .map(|chunk| {
                        json!({
                            "did": did,
                            "grantIds": chunk,
                            "reason": reason,
                            at: rfc3339(when),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        for chunk in entries.chunks(MAX_ITEMS) {
            out.push(Notice {
                recipient_did: principal_did.to_string(),
                recipient_hash: principal_hash.to_string(),
                payload: json!({ "notice": notice, list: chunk }),
            });
        }
    }
    out
}

/// A `grantsPresent` notice for a member DID: how many grants on it the
/// mediator holds (in every state), how many this authentication just
/// suspended, and its epoch. Never a principal DID (producer rule 6).
pub fn grants_present(
    did: &str,
    did_hash: &str,
    count: usize,
    suspended: usize,
    epoch: u64,
) -> Notice {
    Notice {
        recipient_did: did.to_string(),
        recipient_hash: did_hash.to_string(),
        payload: json!({
            "notice": "grantsPresent",
            "did": did,
            "count": count,
            "suspended": suspended,
            "epoch": epoch,
        }),
    }
}

/// Whether `payload` is one the spec's generated type accepts. A notice the
/// schema refuses would be refused by every conforming client too.
fn conforms(payload: &Value) -> bool {
    use crate::task_specs::messaging::mux::notice::v0_1::Payload;
    match serde_json::from_value::<Payload>(payload.clone()) {
        Ok(_) => true,
        Err(e) => {
            warn!("mux notice does not match its spec, not stored: {e}");
            false
        }
    }
}

/// The wire `did_hash`'s notices are sealed for: the one its record names,
/// or the one this build carries when it names none.
async fn wire_of(state: &SharedData, did_hash: &str) -> NoticeWire {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let named = mux::load(&*state.database, did_hash, &limits, now)
        .await
        .ok()
        .and_then(|rec| rec.wire);
    usable_wire(named)
}

/// `wanted`, if this build can seal for it; otherwise the wire it can.
fn usable_wire(wanted: Option<NoticeWire>) -> NoticeWire {
    match wanted {
        Some(NoticeWire::Tsp) if cfg!(feature = "tsp") => NoticeWire::Tsp,
        Some(NoticeWire::DidComm) if cfg!(feature = "didcomm") => NoticeWire::DidComm,
        _ if cfg!(feature = "didcomm") => NoticeWire::DidComm,
        _ => NoticeWire::Tsp,
    }
}

/// Record that `did_hash` last used `wire` with the mediator, so its
/// notices are sealed for it. Written only when it changes.
pub async fn set_wire(state: &SharedData, did_hash: &str, wire: NoticeWire) {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    match mux::load(&*state.database, did_hash, &limits, now).await {
        Ok(rec) if rec.wire == Some(wire) => return,
        Ok(rec) if rec == mux::MuxDidRecord::default() => {
            // Nothing stored for this DID: it has no notice to seal, and a
            // record holding only its wire is not kept.
            return;
        }
        Ok(_) => {}
        Err(e) => {
            debug!(did_hash, "notice wire not recorded: {e}");
            return;
        }
    }
    if let Err(e) = mux::modify(&*state.database, did_hash, &limits, now, None, |rec, _| {
        rec.wire = Some(wire);
        Ok(())
    })
    .await
    {
        debug!(did_hash, "notice wire not recorded: {e}");
    }
}

/// Sign, seal and store `notice` in its recipient's inbox, for the wire the
/// recipient last used, then remember it on the recipient's record for
/// `ready.pendingNotices` and for re-sealing. Returns whether it was stored.
pub async fn store(state: &SharedData, notice: &Notice) -> bool {
    if !conforms(&notice.payload) {
        return false;
    }
    let wire = wire_of(state, &notice.recipient_hash).await;
    let Some(msg_id) = store_sealed(state, notice, wire).await else {
        return false;
    };
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    if let Err(e) = mux::modify(
        &*state.database,
        &notice.recipient_hash,
        &limits,
        now,
        None,
        |rec, _| {
            rec.track_notice(msg_id.clone(), wire, notice.payload.clone());
            Ok(())
        },
    )
    .await
    {
        // The notice is in the inbox; only the `pendingNotices` count misses it.
        warn!(recipient = %notice.recipient_hash, "mux notice stored but not tracked: {e}");
    }
    debug!(recipient = %notice.recipient_hash, kind = %notice.payload["notice"], ?wire, "mux notice stored");
    true
}

/// Seal `notice` for `wire` and store it in its recipient's inbox; returns
/// the stored message's id.
async fn store_sealed(state: &SharedData, notice: &Notice, wire: NoticeWire) -> Option<String> {
    let packed = pack(state, notice, wire).await?;
    let now = state.clock.unix_secs();
    let expiry = now + state.limits().message_expiry_seconds;
    match crate::messages::store::store_system_message(
        state,
        &packed,
        &notice.recipient_hash,
        expiry,
    )
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            warn!(recipient = %notice.recipient_hash, "mux notice not stored: {e}");
            None
        }
    }
}

/// The signed `messaging/mux/notice` document for `notice`.
async fn signed_notice(state: &SharedData, notice: &Notice) -> Option<Value> {
    use uuid::Uuid;
    let mediator_did = &state.config.mediator_did;
    let now = state.clock.unix_secs();
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": NOTICE_TYPE,
        "issuer": mediator_did,
        "recipient": notice.recipient_did,
        "issuedAt": rfc3339(now),
        "payload": notice.payload,
    });
    let signed = match crate::messages::protocols::trust_task_sign::sign_response(doc, state).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("mux notice not signed, not stored: {e}");
            return None;
        }
    };
    // The spec requires a proof: a client must verify it before acting, so an
    // unsigned notice would only be refused. `sign_response` has already
    // logged why the mediator cannot sign.
    if signed.get("proof").is_none() {
        warn!("mux notice not stored: the mediator has no key to sign it with");
        return None;
    }
    Some(signed)
}

/// The stored body of `notice` sealed for `wire`: a packed DIDComm message,
/// or the base64url of a TSP Direct message's qb2, as a TSP message is stored.
async fn pack(state: &SharedData, notice: &Notice, wire: NoticeWire) -> Option<String> {
    let signed = signed_notice(state, notice).await?;
    match wire {
        NoticeWire::DidComm => pack_didcomm(state, notice, signed).await,
        NoticeWire::Tsp => seal_tsp(state, notice, signed).await,
    }
}

#[cfg(feature = "tsp")]
async fn seal_tsp(state: &SharedData, notice: &Notice, signed: Value) -> Option<String> {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    let qb2 = super::connection::seal_document(state, &notice.recipient_did, &signed, "mux notice")
        .await?;
    Some(BASE64_URL_SAFE_NO_PAD.encode(qb2))
}

#[cfg(not(feature = "tsp"))]
async fn seal_tsp(_: &SharedData, notice: &Notice, _: Value) -> Option<String> {
    warn!(recipient = %notice.recipient_hash, "mux notice not stored: TSP is not built in");
    None
}

#[cfg(feature = "didcomm")]
async fn pack_didcomm(state: &SharedData, notice: &Notice, signed: Value) -> Option<String> {
    use affinidi_messaging_didcomm::message::Message;
    use uuid::Uuid;
    let mediator_did = &state.config.mediator_did;
    let now = state.clock.unix_secs();
    let message = Message::build(
        Uuid::new_v4().to_string(),
        crate::messages::protocols::trust_tasks::ENVELOPE_TYPE.to_string(),
        signed,
    )
    .to(notice.recipient_did.clone())
    .from(mediator_did.clone())
    .created_time(now)
    .expires_time(now + state.limits().message_expiry_seconds)
    .finalize();
    match crate::didcomm_compat::pack_encrypted(
        &message,
        &notice.recipient_did,
        Some(mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    {
        Ok((packed, _)) => Some(packed),
        Err(e) => {
            warn!(recipient = %notice.recipient_hash, "mux notice not packed: {e}");
            None
        }
    }
}

#[cfg(not(feature = "didcomm"))]
async fn pack_didcomm(_: &SharedData, notice: &Notice, _: Value) -> Option<String> {
    warn!(recipient = %notice.recipient_hash, "mux notice not stored: DIDComm is not built in");
    None
}

/// Re-issue `did_hash`'s pending notices sealed for the other wire, now that
/// it connected on `wire`: each is stored again for `wire` and the old copy
/// deleted, so the inbox holds one copy, in the form this client reads.
/// Called when a mux connection opens, before `pendingNotices` is counted.
/// A notice that cannot be re-sealed (too old to have kept its payload, or
/// the seal failed) stays as it was.
pub async fn reissue(state: &SharedData, did_hash: &str, did: &str, wire: NoticeWire) {
    let wire = usable_wire(Some(wire));
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let rec = match mux::load(&*state.database, did_hash, &limits, now).await {
        Ok(rec) => rec,
        Err(e) => {
            debug!(did_hash, "notices not re-issued: {e}");
            return;
        }
    };
    let stale: Vec<mux::NoticeForm> = rec
        .notice_forms
        .into_iter()
        .filter(|f| f.wire != wire)
        .collect();
    if stale.is_empty() {
        return;
    }
    let ids: Vec<String> = stale.iter().map(|f| f.id.clone()).collect();
    let present = match state.database.get_messages(did_hash, &ids).await {
        Ok(found) => found,
        Err(e) => {
            debug!(did_hash, "notices not re-issued: {e}");
            return;
        }
    };
    let mut moved: Vec<(String, String)> = Vec::new();
    for (form, found) in stale.into_iter().zip(present) {
        if found.is_none() {
            continue; // already deleted; `pending` forgets it
        }
        let notice = Notice {
            recipient_did: did.to_string(),
            recipient_hash: did_hash.to_string(),
            payload: form.payload,
        };
        let Some(new_id) = store_sealed(state, &notice, wire).await else {
            continue;
        };
        moved.push((form.id, new_id));
    }
    if moved.is_empty() {
        return;
    }
    // Tracked first, then the old copies go: a crash in between leaves both
    // copies, never neither.
    if let Err(e) = mux::modify(&*state.database, did_hash, &limits, now, None, |rec, _| {
        for (old, new) in &moved {
            rec.retrack_notice(old, new.clone(), wire);
        }
        Ok(())
    })
    .await
    {
        warn!(
            did_hash,
            "re-issued notices not tracked, old copies kept: {e}"
        );
        return;
    }
    for (old, _) in &moved {
        if let Err(e) = state
            .database
            .delete_message(
                old,
                affinidi_messaging_mediator_common::store::types::DeletionAuthority::Owner {
                    did_hash: did_hash.to_string(),
                },
            )
            .await
        {
            warn!(did_hash, message_id = %old, "notice re-issued, old copy not deleted: {e}");
        }
    }
    debug!(
        did_hash,
        count = moved.len(),
        ?wire,
        "pending mux notices re-issued for this wire"
    );
}

/// Store the notices a committed change owes, after its members were
/// detached. Called by the Trust Task layer once a mux task's detach is done.
pub async fn after_change(state: &SharedData, changed: &Changed) {
    let now = state.clock.unix_secs();
    if !changed.suspended.is_empty() {
        let stored = store_all(
            state,
            per_principal(
                &changed.suspended,
                ListKind::Suspended,
                "suspendedUnknownKey",
                now,
            ),
        )
        .await;
        mark_noticed(state, &changed.suspended, &stored).await;
        present_after_suspension(state, &changed.suspended).await;
    }
    if !changed.removed.is_empty() {
        let reason = match changed.reason {
            Some(LeaveReason::RevokedByMember) => "revokedByMember",
            Some(LeaveReason::EpochBumped) => "epochBumped",
            Some(LeaveReason::AccountRemoved) => "accountRemoved",
            Some(LeaveReason::Admin) => "admin",
            // A principal that revoked its own grants is not sent one.
            _ => return,
        };
        let stored = store_all(
            state,
            per_principal(&changed.removed, ListKind::Revoked, reason, now),
        )
        .await;
        // Only epoch-revoked grants stay on the record to be marked: a
        // member's `revoke-all` or an administrator's `admin-revoke-all`.
        // Deleted grants have nothing left to mark.
        let voided: Vec<MuxGrant> = changed
            .removed
            .iter()
            .filter(|g| g.state == MuxGrantState::EpochRevoked)
            .cloned()
            .collect();
        if !voided.is_empty() {
            mark_noticed(state, &voided, &stored).await;
        }
    }
}

/// Store each notice; return the principals whose notice was stored.
async fn store_all(state: &SharedData, notices: Vec<Notice>) -> HashSet<String> {
    let mut ok = HashSet::new();
    let mut failed = HashSet::new();
    for n in notices {
        if store(state, &n).await {
            ok.insert(n.recipient_hash);
        } else {
            failed.insert(n.recipient_hash);
        }
    }
    // A principal split across several notices counts as told only if all
    // of them were stored; the rest are re-sent by `recover`.
    ok.retain(|p| !failed.contains(p));
    ok
}

/// Record on each member's record that these grants' notices are stored, for
/// the principals in `told`.
async fn mark_noticed(state: &SharedData, grants: &[MuxGrant], told: &HashSet<String>) {
    let mut by_member: HashMap<&str, HashSet<String>> = HashMap::new();
    for g in grants.iter().filter(|g| told.contains(&g.principal_hash)) {
        by_member
            .entry(&g.did_hash)
            .or_default()
            .insert(g.grant_id.clone());
    }
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    for (member, ids) in by_member {
        if let Err(e) = mux::modify(&*state.database, member, &limits, now, None, |rec, _| {
            rec.mark_noticed(&ids);
            Ok(())
        })
        .await
        {
            // The notice is stored; at worst `recover` sends it again.
            warn!(member, "mux notice stored but not marked: {e}");
        }
    }
}

/// The member DID whose new key suspended grants learns that delegations of
/// it exist (`grantsPresent`), once for this grant set.
async fn present_after_suspension(state: &SharedData, suspended: &[MuxGrant]) {
    let mut per_member: BTreeMap<&str, (&str, usize)> = BTreeMap::new();
    for g in suspended {
        per_member.entry(&g.did_hash).or_insert((&g.did, 0)).1 += 1;
    }
    for (member_hash, (member_did, n)) in per_member {
        tell_present(state, member_did, member_hash, n).await;
    }
}

/// The key a direct authentication proved, as a fingerprint
/// ([`super::proof::fingerprint`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProvenKey {
    /// DIDComm: the authcrypt sender key, a `keyAgreement` key.
    KeyAgreement(String),
    /// TSP: the sender VID's signing key.
    Signing(String),
}

/// The key a direct authentication proved, as the login has it.
#[derive(Clone, Debug)]
pub enum DirectKey {
    /// DIDComm: the authcrypt sender key id; `None` when the message was not
    /// authcrypt, which proves no key-agreement key, so the rule cannot fire.
    Authcrypt(Option<String>),
    /// TSP: the sender VID's signing key bytes.
    Signing(Vec<u8>),
}

/// The unknown-key rule (spec `messaging/mux/grant`) on a direct
/// authentication, applied before the login succeeds: the key is compared
/// with the known keys of the same relationship, and every active grant on
/// the DID is suspended if it is unknown. Returns the suspended grants,
/// committed and detached from this instance's connections; pass them to
/// [`after_direct_auth`].
///
/// `Err` when the rule could not be applied — the key did not resolve, or
/// the store failed — and the login must then fail rather than leave grants
/// active that a new controller's key should have ended. A DID with no
/// active grant is never resolved and never fails here.
///
/// The read and the key resolution are bounded by [`CHECK_READ_TIMEOUT`], so
/// a slow store or resolver refuses the login (retryable) instead of holding
/// it open. The commit and detach are not cut short: a suspension the store
/// accepted is always detached before this returns. Every failure counts in
/// `mux_login_check_failures_total`.
pub async fn unknown_key_check(
    state: &SharedData,
    did_hash: &str,
    key: DirectKey,
) -> Result<Vec<MuxGrant>, String> {
    let r = check(state, did_hash, key).await;
    if r.is_err() {
        metrics::counter!(crate::common::metrics::names::MUX_LOGIN_CHECK_FAILURES_TOTAL)
            .increment(1);
    }
    r
}

/// The longest a direct login waits to read the DID's grants and resolve its
/// key for the unknown-key rule. The authcrypt sender was resolved moments
/// earlier to unpack the login, so the resolution is normally a cache hit.
pub const CHECK_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn check(
    state: &SharedData,
    did_hash: &str,
    key: DirectKey,
) -> Result<Vec<MuxGrant>, String> {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let read = async {
        let rec = mux::load(&*state.database, did_hash, &limits, now)
            .await
            .map_err(|e| e.to_string())?;
        if !rec.grants.iter().any(|g| g.is_usable(now)) {
            return Ok(None);
        }
        Ok::<_, String>(match key {
            DirectKey::Authcrypt(None) => None,
            DirectKey::Authcrypt(Some(kid)) => Some(ProvenKey::KeyAgreement(
                super::proof::StatementVerifier::new(state.did_resolver.clone())
                    .key_agreement_fp(&kid)
                    .await?,
            )),
            DirectKey::Signing(bytes) => {
                Some(ProvenKey::Signing(super::proof::fingerprint(&bytes)))
            }
        })
    };
    let proven = match tokio::time::timeout(CHECK_READ_TIMEOUT, read).await {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => return Ok(Vec::new()),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(format!(
                "grants or key not read within {}s",
                CHECK_READ_TIMEOUT.as_secs()
            ));
        }
    };
    let suspended = mux::modify(&*state.database, did_hash, &limits, now, None, |rec, _| {
        Ok(match &proven {
            ProvenKey::KeyAgreement(fp) => mux::suspend_unless_known_key_agreement(rec, fp, now),
            ProvenKey::Signing(fp) => mux::suspend_unless_known_signing_key(rec, fp, now),
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    if !suspended.is_empty() {
        state
            .mux
            .detach_grants(
                state.streaming_task.as_ref(),
                &suspended,
                LeaveReason::SuspendedUnknownKey,
            )
            .await;
        let changes: Vec<mux::MuxChange> = suspended
            .iter()
            .map(|g| mux::MuxChange::of(g, false))
            .collect();
        super::sync::publish(state, &changes).await;
        // Rare (a key change), so written here rather than in the spawned
        // follow-up, where a crash before it ran would lose the record.
        let by = match proven {
            ProvenKey::KeyAgreement(_) => super::audit::SuspendedBy::DirectKeyAgreement,
            ProvenKey::Signing(_) => super::audit::SuspendedBy::DirectSigning,
        };
        super::audit::suspended(state, &suspended, by).await;
    }
    Ok(suspended)
}

/// The notices a direct authentication owes, after [`unknown_key_check`];
/// login does not wait on them.
///
/// As a member DID: the principals of `suspended` grants are told. Otherwise
/// the DID is told, once per change of its grants, that delegations of it
/// exist (`grantsPresent`). As a principal: it is sent the `grantsExpiring`
/// notice it is owed.
pub async fn after_direct_auth(
    state: &SharedData,
    did: &str,
    did_hash: &str,
    suspended: Vec<MuxGrant>,
    wire: NoticeWire,
) {
    // A `grantsPresent` for this DID is sealed for the wire it just used.
    set_wire(state, did_hash, wire).await;
    if suspended.is_empty() {
        tell_present(state, did, did_hash, 0).await;
    } else {
        let changed = Changed {
            suspended,
            ..Default::default()
        };
        after_change(state, &changed).await;
    }
    expiring(state, did_hash).await;
}

/// Store the `grantsExpiring` notice `principal_hash` is owed: its active
/// grants past about three quarters of their lifetime, not yet told. Sent
/// for every such grant: whether the application opted into renewal is known
/// only to the client, which discards the notice for a grant it renews.
pub async fn expiring(state: &SharedData, principal_hash: &str) {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let mut due = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let (page, next) = match mux::grants_for_principal(
            &*state.database,
            principal_hash,
            after.as_deref(),
            100,
            &limits,
            now,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!(principal_hash, "grantsExpiring deferred: {e}");
                return;
            }
        };
        due.extend(
            page.into_iter()
                .filter(|g| g.is_expiring(now) && !g.expiring_noticed),
        );
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    let Some(principal_did) = due.first().map(|g| g.principal.clone()) else {
        return;
    };
    let mut all_stored = true;
    for chunk in due.chunks(MAX_ITEMS) {
        let items: Vec<Value> = chunk
            .iter()
            .map(|g| {
                json!({
                    "grantId": g.grant_id,
                    "did": g.did,
                    "expiresAt": rfc3339(g.effective_exp()),
                })
            })
            .collect();
        let notice = Notice {
            recipient_did: principal_did.clone(),
            recipient_hash: principal_hash.to_string(),
            payload: json!({ "notice": "grantsExpiring", "expiring": items }),
        };
        all_stored &= store(state, &notice).await;
    }
    if !all_stored {
        return;
    }
    let mut by_member: HashMap<&str, HashSet<&str>> = HashMap::new();
    for g in &due {
        by_member
            .entry(&g.did_hash)
            .or_default()
            .insert(&g.grant_id);
    }
    for (member, ids) in by_member {
        if let Err(e) = mux::modify(&*state.database, member, &limits, now, None, |rec, _| {
            for g in rec.grants.iter_mut() {
                if ids.contains(g.grant_id.as_str()) {
                    g.expiring_noticed = true;
                }
            }
            Ok(())
        })
        .await
        {
            // Stored but not marked: the next check may send it again.
            warn!(member, "grantsExpiring stored but not marked: {e}");
        }
    }
}

async fn tell_present(state: &SharedData, did: &str, did_hash: &str, suspended: usize) {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let rec = match mux::load(&*state.database, did_hash, &limits, now).await {
        Ok(rec) => rec,
        Err(e) => {
            debug!(did_hash, "grantsPresent deferred: {e}");
            return;
        }
    };
    if rec.grants.is_empty() {
        return;
    }
    let digest = rec.grants_digest(now);
    if rec.present_told.as_deref() == Some(digest.as_str()) {
        return;
    }
    let notice = grants_present(did, did_hash, rec.grants.len(), suspended, rec.epoch);
    if !store(state, &notice).await {
        return;
    }
    if let Err(e) = mux::modify(&*state.database, did_hash, &limits, now, None, |rec, _| {
        rec.present_told = Some(digest.clone());
        Ok(())
    })
    .await
    {
        debug!(did_hash, "grantsPresent stored but not recorded: {e}");
    }
}

/// Send the `grantsSuspended` / `grantsRevoked` (`epochBumped`) notices a
/// principal is still owed: its dead grants whose notice was never stored
/// (the process died between the commit and the notice). Called when the
/// principal opens a mux connection, before `pendingNotices` is counted.
pub async fn recover(state: &SharedData, principal_hash: &str) {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let mut suspended = Vec::new();
    let mut voided = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let (page, next) = match mux::grants_for_principal(
            &*state.database,
            principal_hash,
            after.as_deref(),
            100,
            &limits,
            now,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!(principal_hash, "mux notice recovery deferred: {e}");
                return;
            }
        };
        for g in page.into_iter().filter(|g| !g.noticed) {
            match g.state {
                MuxGrantState::Suspended => suspended.push(g),
                MuxGrantState::EpochRevoked => voided.push(g),
                _ => {}
            }
        }
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    if !suspended.is_empty() {
        let told = store_all(
            state,
            per_principal(&suspended, ListKind::Suspended, "suspendedUnknownKey", now),
        )
        .await;
        mark_noticed(state, &suspended, &told).await;
    }
    if !voided.is_empty() {
        let told = store_all(
            state,
            per_principal(&voided, ListKind::Revoked, "epochBumped", now),
        )
        .await;
        mark_noticed(state, &voided, &told).await;
    }
}

/// How many notices wait in `did_hash`'s inbox, for `ready.pendingNotices`.
/// Forgets the ids of notices already deleted.
pub async fn pending(state: &SharedData, did_hash: &str) -> u64 {
    let limits = state.config.limits.mux.store_limits();
    let now = state.clock.unix_secs();
    let rec = match mux::load(&*state.database, did_hash, &limits, now).await {
        Ok(rec) => rec,
        Err(e) => {
            warn!(did_hash, "pendingNotices unknown, reported as 0: {e}");
            return 0;
        }
    };
    if rec.notices.is_empty() {
        return 0;
    }
    let found = match state.database.get_messages(did_hash, &rec.notices).await {
        Ok(found) => found,
        Err(e) => {
            // Over-report rather than under-report: a client told of notices
            // that are gone finds none; one told of none may not look.
            warn!(
                did_hash,
                "pendingNotices not checked against the inbox: {e}"
            );
            return rec.notices.len() as u64;
        }
    };
    let gone: HashSet<String> = rec
        .notices
        .iter()
        .zip(&found)
        .filter(|(_, f)| f.is_none())
        .map(|(id, _)| id.clone())
        .collect();
    let waiting = (rec.notices.len() - gone.len()) as u64;
    if !gone.is_empty()
        && let Err(e) = mux::modify(&*state.database, did_hash, &limits, now, None, |rec, _| {
            rec.forget_notices(&gone);
            Ok(())
        })
        .await
    {
        debug!(did_hash, "deleted notices not forgotten yet: {e}");
    }
    waiting
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_common::store::mux::{MuxCapability, MuxScope};

    fn grant(id: &str, member: &str, principal: &str, at: Option<u64>) -> MuxGrant {
        MuxGrant {
            grant_id: id.into(),
            did: format!("did:example:{member}"),
            did_hash: member.into(),
            principal: format!("did:example:{principal}"),
            principal_hash: principal.into(),
            kid: format!("did:example:{member}#key-1"),
            key_fp: "fp".into(),
            did_version: None,
            epoch: 0,
            scope: MuxScope::new([MuxCapability::Receive]).unwrap(),
            iat: 1,
            exp: 10_000,
            narrowed_scope: None,
            narrowed_exp: None,
            state: MuxGrantState::Suspended,
            state_changed_at: at,
            statement: json!({}),
            noticed: false,
            key_agreement_fps: Vec::new(),
            expiring_noticed: false,
        }
    }

    #[test]
    fn one_notice_per_principal_with_an_entry_per_member() {
        let grants = [
            grant("g1", "work", "phone", Some(100)),
            grant("g2", "home", "phone", Some(100)),
            grant("g3", "work", "laptop", Some(100)),
        ];
        let notices = per_principal(&grants, ListKind::Suspended, "suspendedUnknownKey", 200);
        assert_eq!(notices.len(), 2);
        let phone = notices
            .iter()
            .find(|n| n.recipient_hash == "phone")
            .unwrap();
        assert_eq!(phone.recipient_did, "did:example:phone");
        assert_eq!(phone.payload["notice"], "grantsSuspended");
        let list = phone.payload["suspensions"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["reason"], "suspendedUnknownKey");
        assert_eq!(list[0]["suspendedAt"], "1970-01-01T00:01:40Z");
        for n in &notices {
            assert!(conforms(&n.payload), "{:#}", n.payload);
        }
    }

    #[test]
    fn revoked_notices_conform_and_use_now_for_deleted_grants() {
        let grants = [grant("g1", "work", "phone", None)];
        let notices = per_principal(&grants, ListKind::Revoked, "revokedByMember", 300);
        assert_eq!(notices.len(), 1);
        let entry = &notices[0].payload["revocations"][0];
        assert_eq!(entry["revokedAt"], "1970-01-01T00:05:00Z");
        assert_eq!(entry["grantIds"], json!(["g1"]));
        assert!(conforms(&notices[0].payload));
    }

    #[test]
    fn a_large_change_is_split_at_the_spec_limit() {
        let grants: Vec<_> = (0..300)
            .map(|i| grant(&format!("g{i}"), &format!("m{i}"), "phone", Some(1)))
            .collect();
        let notices = per_principal(&grants, ListKind::Suspended, "suspendedUnknownKey", 2);
        assert_eq!(notices.len(), 2);
        assert_eq!(
            notices[0].payload["suspensions"].as_array().unwrap().len(),
            256
        );
        assert_eq!(
            notices[1].payload["suspensions"].as_array().unwrap().len(),
            44
        );
        assert!(notices.iter().all(|n| conforms(&n.payload)));
    }

    #[test]
    fn grants_present_carries_counts_only() {
        let n = grants_present("did:example:work", "work", 3, 2, 1);
        assert!(conforms(&n.payload));
        assert_eq!(
            n.payload,
            json!({ "notice": "grantsPresent", "did": "did:example:work", "count": 3, "suspended": 2, "epoch": 1 })
        );
    }
}
