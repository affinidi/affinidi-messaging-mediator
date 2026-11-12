//! The administrator's stored-grant tasks: `messaging/mux/admin-list`,
//! `admin-revoke` and `admin-revoke-all` (design §7.8).
//!
//! Authorization (the requester's role) is the Trust Task layer's; this
//! module selects grants, applies the protected-account rule and makes the
//! change. The grant rules themselves are not repeated here: a revocation
//! goes through [`grants::revoke_grants`] (delete and raise the replay floor,
//! as every revocation does) and an epoch advance through
//! [`grants::advance_epoch`], the same compare-and-set a member's own
//! `revoke-all` makes. Both return what they changed as a [`Changed`] with
//! reason [`LeaveReason::Admin`], so the caller detaches, publishes to other
//! instances and stores notices exactly as it does for `messaging/mux/revoke`.

use std::collections::{BTreeMap, HashSet};

use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    store::mux::{self, MuxGrant, MuxStoreError},
    types::accounts::AccountType,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::grants::{self, Ctx, EpochAdvance, MuxError};
use super::session::LeaveReason;
use super::tasks::{Changed, TaskError};

/// Grants per `admin-list` page when the request does not say.
pub const DEFAULT_LIST_LIMIT: usize = 100;
/// The most grants per `admin-list` page.
pub const MAX_LIST_LIMIT: usize = 500;
/// Grants one `admin-revoke` acts on when the request does not say, and the
/// most.
pub const MAX_REVOKE_LIMIT: usize = 500;
/// How long an `admin-list` cursor stays valid.
pub const CURSOR_TTL_SECS: u64 = 600;
/// Member DIDs read per page while walking a principal's index.
const INDEX_PAGE: usize = 200;

pub const LIST_CURSOR_INVALID: &str = "messaging/mux/admin-list:cursorInvalid";
pub const REVOKE_PROTECTED: &str = "messaging/mux/admin-revoke:protectedAccount";
pub const REVOKE_CONTENDED: &str = "messaging/mux/admin-revoke:contended";
pub const REVOKE_ALL_PROTECTED: &str = "messaging/mux/admin-revoke-all:protectedAccount";
pub const REVOKE_ALL_UNKNOWN: &str = "messaging/mux/admin-revoke-all:unknownAccount";
pub const REVOKE_ALL_MISMATCH: &str = "messaging/mux/admin-revoke-all:epochMismatch";
pub const REVOKE_ALL_CONTENDED: &str = "messaging/mux/admin-revoke-all:contended";

/// Who is asking, as far as these tasks care.
pub struct Requester<'a> {
    /// A `rootAdmin` may act on any grant; anyone else is refused a grant
    /// with a protected party.
    pub root: bool,
    /// The configured root administrator's DID hash: protected whatever its
    /// stored role says.
    pub root_admin_hash: &'a str,
}

fn task_error(code: &str, message: impl Into<String>, retryable: bool) -> TaskError {
    TaskError {
        code: code.to_string(),
        message: message.into(),
        retryable,
        current_epoch: None,
    }
}

fn malformed(message: impl Into<String>) -> TaskError {
    task_error("malformedRequest", message, false)
}

/// The store could not be read or written: the request fails, retryably,
/// with the code the other `messaging/mux/*` tasks use for it.
fn store_failed(e: impl std::fmt::Display) -> TaskError {
    task_error("messaging/mux:storeUnavailable", e.to_string(), true)
}

fn rfc3339(secs: u64) -> String {
    DateTime::<Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── Selecting grants ───────────────────────────────────────────────────────

/// The grant order every admin task uses: member DID, principal DID, grant id.
fn sort_key(g: &MuxGrant) -> (&str, &str, &str) {
    (&g.did, &g.principal, &g.grant_id)
}

/// Every stored grant, in any state, whose principal is `principal` and whose
/// member DID is `member`, for each of the two given, in [`sort_key`] order;
/// and, when `member` is given, its current epoch (0 for a DID whose epoch
/// never advanced).
async fn select(
    ctx: &Ctx<'_>,
    principal: Option<&str>,
    member: Option<&str>,
) -> Result<(Vec<MuxGrant>, Option<u64>), MuxStoreError> {
    let principal_hash = principal.map(did_hash);
    let mut epoch = None;
    let mut out = match (member, &principal_hash) {
        (Some(member), _) => {
            let rec = mux::load(ctx.store, &did_hash(member), &ctx.limits, ctx.now).await?;
            epoch = Some(rec.epoch);
            rec.grants
        }
        (None, Some(p)) => {
            let mut all = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let (page, next) = mux::grants_for_principal(
                    ctx.store,
                    p,
                    after.as_deref(),
                    INDEX_PAGE,
                    &ctx.limits,
                    ctx.now,
                )
                .await?;
                all.extend(page);
                match next {
                    Some(n) => after = Some(n),
                    None => break,
                }
            }
            all
        }
        (None, None) => Vec::new(),
    };
    if let Some(p) = &principal_hash {
        out.retain(|g| &g.principal_hash == p);
    }
    out.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    Ok((out, epoch))
}

/// Whether the account `hash` is a root administrator: stored as `rootAdmin`,
/// or the configured root administrator.
async fn is_root_admin(
    ctx: &Ctx<'_>,
    requester: &Requester<'_>,
    hash: &str,
) -> Result<bool, MuxStoreError> {
    if hash == requester.root_admin_hash {
        return Ok(true);
    }
    Ok(ctx
        .store
        .account_get(hash)
        .await
        .map_err(MuxStoreError::from)?
        .is_some_and(|a| a._type == AccountType::RootAdmin))
}

/// Whether any of `hashes` is a root administrator.
async fn any_root_admin(
    ctx: &Ctx<'_>,
    requester: &Requester<'_>,
    hashes: Vec<String>,
) -> Result<bool, MuxStoreError> {
    for h in hashes {
        if is_root_admin(ctx, requester, &h).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every member and principal DID hash of `grants`, once each.
fn parties(grants: &[MuxGrant]) -> Vec<String> {
    let set: std::collections::BTreeSet<&str> = grants
        .iter()
        .flat_map(|g| [g.did_hash.as_str(), g.principal_hash.as_str()])
        .collect();
    set.into_iter().map(str::to_string).collect()
}

// ─── admin-list ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListReq {
    principal: Option<String>,
    member: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

/// Where a page stopped: the last grant returned. Its sort key when that
/// fits in a cursor (DIDs may run to 2048 characters, a cursor to 1024),
/// and always its position and a short hash of the key, to resume by when
/// the key does not fit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Position {
    #[serde(rename = "k", default, skip_serializing_if = "Option::is_none")]
    key: Option<(String, String, String)>,
    #[serde(rename = "h")]
    key_hash: String,
    #[serde(rename = "n")]
    index: usize,
}

/// The longest sort key a cursor carries verbatim.
const MAX_CURSOR_KEY: usize = 480;

fn key_hash(g: &MuxGrant) -> String {
    sha256::digest(format!("{}\n{}\n{}", g.did, g.principal, g.grant_id))[..32].to_string()
}

impl Position {
    fn after(g: &MuxGrant, index: usize) -> Self {
        let fits = g.did.len() + g.principal.len() + g.grant_id.len() <= MAX_CURSOR_KEY;
        Self {
            key: fits.then(|| (g.did.clone(), g.principal.clone(), g.grant_id.clone())),
            key_hash: key_hash(g),
            index,
        }
    }

    /// The index of the first grant after this position in `grants` (sorted).
    fn resume_at(&self, grants: &[MuxGrant]) -> usize {
        if let Some((d, p, i)) = &self.key {
            let key = (d.as_str(), p.as_str(), i.as_str());
            return grants.partition_point(|g| sort_key(g) <= key);
        }
        match grants.iter().position(|g| key_hash(g) == self.key_hash) {
            Some(i) => i + 1,
            None => (self.index + 1).min(grants.len()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CursorBody {
    #[serde(rename = "p")]
    at: Position,
    /// The request members it continues: principal, member and limit.
    #[serde(rename = "q")]
    query: String,
    /// The requester's DID hash, shortened.
    #[serde(rename = "r")]
    requester: String,
    /// When it was issued (unix seconds).
    #[serde(rename = "t")]
    issued: u64,
}

/// What an `admin-list` cursor is bound to, and the key that proves this
/// mediator issued it.
pub struct CursorBinding<'a> {
    pub requester: &'a str,
    pub now: u64,
    /// HMAC key: the same on every instance of the mediator, so a page from
    /// one instance continues on another (see the Trust Task layer).
    pub key: &'a [u8],
}

fn fingerprint(req: &ListReq, limit: usize) -> String {
    sha256::digest(format!(
        "{}\n{}\n{limit}",
        req.principal.as_deref().unwrap_or(""),
        req.member.as_deref().unwrap_or("")
    ))[..32]
        .to_string()
}

fn tag(key: &[u8], body: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    BASE64_URL_SAFE_NO_PAD.encode(&ring::hmac::sign(&key, body.as_bytes()).as_ref()[..16])
}

fn issue(at: Position, query: String, b: &CursorBinding<'_>) -> String {
    let body = serde_json::to_string(&CursorBody {
        at,
        query,
        requester: sha256::digest(b.requester)[..32].to_string(),
        issued: b.now,
    })
    .expect("cursor serialises");
    let t = tag(b.key, &body);
    BASE64_URL_SAFE_NO_PAD.encode(format!("{t}.{body}"))
}

fn redeem(cursor: &str, query: &str, b: &CursorBinding<'_>) -> Option<Position> {
    let raw = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(cursor).ok()?).ok()?;
    let (t, body) = raw.split_once('.')?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b.key);
    let expected = BASE64_URL_SAFE_NO_PAD.decode(t).ok()?;
    let full = ring::hmac::sign(&key, body.as_bytes());
    if expected.len() != 16
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            &full.as_ref()[..16],
            expected.as_slice(),
        ))
    {
        return None;
    }
    let c: CursorBody = serde_json::from_str(body).ok()?;
    let fresh = b.now.saturating_sub(c.issued) <= CURSOR_TTL_SECS && c.issued <= b.now + 60;
    (c.query == query && c.requester == sha256::digest(b.requester)[..32] && fresh).then_some(c.at)
}

/// `AdminGrantView`: what a grant delegates, never its signed statement.
fn admin_view(g: &MuxGrant, now: u64) -> Value {
    let mut v = json!({
        "grantId": g.grant_id,
        "did": g.did,
        "principal": g.principal,
        "state": g.state_at(now),
        "scope": g.effective_scope(),
        "expiresAt": rfc3339(g.effective_exp()),
        "epoch": g.epoch,
        "signedAt": rfc3339(g.iat),
    });
    if g.narrowed_scope.is_some() || g.narrowed_exp.is_some() {
        v["narrowed"] = json!(true);
    }
    v
}

/// `messaging/mux/admin-list`: one page of the stored grants of a principal,
/// of a member DID, or between the two.
pub async fn admin_list(
    ctx: &Ctx<'_>,
    payload: &Value,
    binding: &CursorBinding<'_>,
) -> Result<Value, TaskError> {
    let req: ListReq =
        serde_json::from_value(payload.clone()).map_err(|e| malformed(e.to_string()))?;
    if req.principal.is_none() && req.member.is_none() {
        return Err(malformed("name at least one of principal and member"));
    }
    let limit = req
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let query = fingerprint(&req, limit);
    let from = match &req.cursor {
        None => None,
        Some(c) => Some(redeem(c, &query, binding).ok_or_else(|| {
            task_error(
                LIST_CURSOR_INVALID,
                "the cursor was not issued for this requester and these request members, \
                 or has expired; start again without one",
                false,
            )
        })?),
    };
    let (all, epoch) = select(ctx, req.principal.as_deref(), req.member.as_deref())
        .await
        .map_err(store_failed)?;
    let start = from.map_or(0, |p| p.resume_at(&all));
    let page: Vec<&MuxGrant> = all.iter().skip(start).take(limit).collect();
    let mut out = json!({
        "grants": page.iter().map(|g| admin_view(g, ctx.now)).collect::<Vec<_>>(),
    });
    if let Some(epoch) = epoch {
        out["epoch"] = json!(epoch);
    }
    let end = start + page.len();
    if end < all.len()
        && let Some(last) = page.last()
    {
        out["nextCursor"] = json!(issue(Position::after(last, end - 1), query, binding));
    }
    Ok(out)
}

// ─── admin-revoke ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeReq {
    principal: Option<String>,
    member: Option<String>,
    grant_ids: Option<Vec<String>>,
    limit: Option<usize>,
}

/// `messaging/mux/admin-revoke`.
///
/// Returns the response, or the refusal, together with what was changed:
/// a `contended` refusal can follow grants already revoked from other
/// members' records, and those must still be detached, published and
/// notified (spec consumer rule 10), so the caller applies the [`Changed`]
/// whatever the result.
pub async fn admin_revoke(
    ctx: &Ctx<'_>,
    requester: &Requester<'_>,
    payload: &Value,
) -> (Result<Value, TaskError>, Changed) {
    let mut changed = Changed {
        reason: Some(LeaveReason::Admin),
        ..Default::default()
    };
    let result = admin_revoke_into(ctx, requester, payload, &mut changed).await;
    (result, changed)
}

async fn admin_revoke_into(
    ctx: &Ctx<'_>,
    requester: &Requester<'_>,
    payload: &Value,
    changed: &mut Changed,
) -> Result<Value, TaskError> {
    let req: RevokeReq =
        serde_json::from_value(payload.clone()).map_err(|e| malformed(e.to_string()))?;
    if req.principal.is_none() && req.member.is_none() {
        return Err(malformed("name at least one of principal and member"));
    }
    if req.grant_ids.is_some() && req.member.is_none() {
        return Err(malformed(
            "grantIds is unique only on a member's record: send it with member",
        ));
    }
    let limit = req
        .limit
        .unwrap_or(MAX_REVOKE_LIMIT)
        .clamp(1, MAX_REVOKE_LIMIT);

    let (mut matched, _) = select(ctx, req.principal.as_deref(), req.member.as_deref())
        .await
        .map_err(store_failed)?;
    let mut unmatched: Vec<String> = Vec::new();
    if let Some(ids) = &req.grant_ids {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        matched.retain(|g| wanted.contains(g.grant_id.as_str()));
        let found: HashSet<&str> = matched.iter().map(|g| g.grant_id.as_str()).collect();
        unmatched = ids
            .iter()
            .filter(|id| !found.contains(id.as_str()))
            .cloned()
            .collect();
    }

    // Every matched grant, not only the first `limit`, before anything is
    // revoked (spec consumer rule 4).
    if !requester.root
        && any_root_admin(ctx, requester, parties(&matched))
            .await
            .map_err(store_failed)?
    {
        return Err(task_error(
            REVOKE_PROTECTED,
            "a selected grant's member or principal is a rootAdmin account; only a rootAdmin \
             may revoke it",
            false,
        ));
    }

    let acting = matched.len().min(limit);
    // One atomic write per member DID's record, in member order.
    let mut by_member: BTreeMap<(&str, &str), HashSet<(String, String)>> = BTreeMap::new();
    for g in &matched[..acting] {
        by_member
            .entry((g.did.as_str(), g.did_hash.as_str()))
            .or_default()
            .insert((g.grant_id.clone(), g.principal_hash.clone()));
    }
    for ((_, member_hash), selected) in by_member {
        match grants::revoke_grants(ctx, member_hash, &selected).await {
            Ok(gone) => changed.removed.extend(gone),
            Err(MuxError::Store(MuxStoreError::Contended)) => {
                return Err(task_error(
                    REVOKE_CONTENDED,
                    "a member DID's record kept changing under concurrent writes; no grant on \
                     it was revoked. Send the request again",
                    true,
                ));
            }
            Err(e) => return Err(store_failed(e)),
        }
    }
    changed
        .removed
        .sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));

    let mut out = json!({
        "revoked": changed.removed.iter().map(|g| json!({
            "grantId": g.grant_id, "did": g.did, "principal": g.principal,
        })).collect::<Vec<_>>(),
        "remaining": matched.len() - acting,
    });
    if !unmatched.is_empty() {
        out["unmatchedGrantIds"] = json!(unmatched);
    }
    Ok(out)
}

// ─── admin-revoke-all ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RevokeAllReq {
    did: String,
    epoch: u64,
}

/// `messaging/mux/admin-revoke-all`: advance a member DID's epoch on the
/// administrator's standing, as `revoke-all` does on the member's.
pub async fn admin_revoke_all(
    ctx: &Ctx<'_>,
    requester: &Requester<'_>,
    payload: &Value,
) -> Result<(Value, Changed, Option<u64>), TaskError> {
    let req: RevokeAllReq =
        serde_json::from_value(payload.clone()).map_err(|e| malformed(e.to_string()))?;
    let hash = did_hash(&req.did);
    if !requester.root
        && is_root_admin(ctx, requester, &hash)
            .await
            .map_err(store_failed)?
    {
        return Err(task_error(
            REVOKE_ALL_PROTECTED,
            "the member DID is a rootAdmin account; only a rootAdmin may advance its epoch",
            false,
        ));
    }
    if !ctx
        .store
        .account_exists(&hash)
        .await
        .map_err(store_failed)?
    {
        return Err(task_error(
            REVOKE_ALL_UNKNOWN,
            "the member DID has no account at this mediator",
            false,
        ));
    }
    match grants::advance_epoch(ctx, &hash, req.epoch).await {
        Ok(EpochAdvance::Advanced(epoch, voided)) => Ok((
            json!({ "did": req.did, "epoch": epoch, "epochAdvanced": true, "revokedGrants": voided.len() }),
            Changed {
                removed: voided,
                reason: Some(LeaveReason::Admin),
                attaches_ended: Some(hash),
                ..Default::default()
            },
            Some(req.epoch),
        )),
        Ok(EpochAdvance::AlreadyPast(epoch)) => Ok((
            json!({ "did": req.did, "epoch": epoch, "epochAdvanced": false, "revokedGrants": 0 }),
            Changed::default(),
            None,
        )),
        Ok(EpochAdvance::Future(current)) => Err(TaskError {
            current_epoch: Some(current),
            ..task_error(
                REVOKE_ALL_MISMATCH,
                format!(
                    "the request names epoch {}; the current epoch is {current}",
                    req.epoch
                ),
                false,
            )
        }),
        Err(MuxError::Store(MuxStoreError::Contended)) => Err(task_error(
            REVOKE_ALL_CONTENDED,
            "the member DID's record kept changing under concurrent writes; nothing changed. \
             Send the request again",
            true,
        )),
        Err(e) => Err(store_failed(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_common::store::mux::{MuxCapability, MuxGrantState, MuxScope};

    fn grant(did: &str, principal: &str, id: &str) -> MuxGrant {
        MuxGrant {
            grant_id: id.into(),
            did: did.into(),
            did_hash: did_hash(did),
            principal: principal.into(),
            principal_hash: did_hash(principal),
            kid: format!("{did}#key-1"),
            key_fp: "fp".into(),
            did_version: None,
            epoch: 0,
            scope: MuxScope::new([MuxCapability::Receive]).unwrap(),
            iat: 1,
            exp: 2,
            narrowed_scope: None,
            narrowed_exp: None,
            state: MuxGrantState::Active,
            state_changed_at: None,
            statement: Value::Null,
            noticed: false,
            key_agreement_fps: Vec::new(),
            expiring_noticed: false,
        }
    }

    fn sorted(mut v: Vec<MuxGrant>) -> Vec<MuxGrant> {
        v.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        v
    }

    const B: CursorBinding<'static> = CursorBinding {
        requester: "admin",
        now: 1_000,
        key: b"k1",
    };

    #[test]
    fn a_cursor_redeems_only_for_its_requester_members_and_key() {
        let g = grant("did:m:a", "did:p:x", "g1");
        let c = issue(Position::after(&g, 0), "q".into(), &B);
        assert!(c.len() <= 1024);
        assert_eq!(redeem(&c, "q", &B), Some(Position::after(&g, 0)));
        assert_eq!(redeem(&c, "other", &B), None, "other request members");
        for b in [
            CursorBinding {
                requester: "someone",
                ..B
            },
            CursorBinding { key: b"k2", ..B },
            CursorBinding {
                now: B.now + CURSOR_TTL_SECS + 1,
                ..B
            },
        ] {
            assert_eq!(redeem(&c, "q", &b), None);
        }
        assert_eq!(redeem("garbage", "q", &B), None);
    }

    #[test]
    fn paging_resumes_after_the_last_grant_returned() {
        let all = sorted(vec![
            grant("did:m:a", "did:p:x", "g1"),
            grant("did:m:b", "did:p:x", "g2"),
            grant("did:m:c", "did:p:x", "g3"),
        ]);
        let at = Position::after(&all[0], 0);
        assert_eq!(at.resume_at(&all), 1);
        // The last grant returned was revoked before the next page: the
        // next one is still the one after it.
        assert_eq!(at.resume_at(&all[1..]), 0);
        // A grant that sorts before the position, added meanwhile, is not
        // picked up, and nothing is repeated.
        let more = sorted([vec![grant("did:m:0", "did:p:x", "g0")], all.clone()].concat());
        assert_eq!(more[at.resume_at(&more)].grant_id, "g2");
    }

    #[test]
    fn a_cursor_fits_whatever_the_dids() {
        let long = |c: char| format!("did:peer:2.{}", c.to_string().repeat(1800));
        let all = sorted(vec![
            grant(&long('a'), &long('p'), "g1"),
            grant(&long('b'), &long('p'), "g2"),
        ]);
        let at = Position::after(&all[0], 0);
        assert!(at.key.is_none(), "too long to carry");
        let c = issue(at, "q".into(), &B);
        assert!(c.len() <= 1024, "cursor is {} characters", c.len());
        assert_eq!(redeem(&c, "q", &B).unwrap().resume_at(&all), 1);
    }
}
