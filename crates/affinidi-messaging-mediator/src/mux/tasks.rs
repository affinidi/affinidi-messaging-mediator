//! The connection-independent `messaging/mux/*` Trust Tasks: `grant`, `list`,
//! `update`, `revoke` and `revoke-all`. Each takes the request payload and the
//! transport-authenticated sender and returns the response payload as JSON,
//! which the dispatcher checks against the generated `Response` type.
//!
//! `attach`, `detach` and `event` belong to a live mux connection and are
//! served by the socket, not here.
//!
//! Every operation that removes or voids grants returns them to the caller
//! through [`Changed`], so the connection layer can detach the affected DIDs
//! *before* the response is sent (design §7.3, R1.1/R7.2).

use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    store::mux::{self, MuxCapability, MuxGrant, MuxScope, MuxStoreError},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;

use super::grants::{self, Ctx, EpochAdvance, MuxError};
use super::proof::Expect;
use super::registry::MuxConn;
use super::session::{LeaveReason, MuxSource, verify_attach};
use crate::tasks::websocket_streaming::StreamingTask;

/// Grants a task removed, voided, suspended or narrowed: the connection layer
/// detaches (or re-scopes) these before the response goes out.
#[derive(Debug, Default)]
pub struct Changed {
    pub removed: Vec<MuxGrant>,
    /// Why `removed` went, for the `detached` events.
    pub reason: Option<LeaveReason>,
    pub suspended: Vec<MuxGrant>,
    pub narrowed: Vec<MuxGrant>,
    /// Grants just stored: their principal's live connections carry the
    /// member at once (design §4.4), not only after a reconnect.
    pub stored: Vec<MuxGrant>,
    /// A member DID whose `revoke-all` advanced its epoch: its session
    /// attaches end too, on every connection carrying it, before the answer
    /// (design §5.2).
    pub attaches_ended: Option<String>,
}

/// A request-level refusal: the whole task fails with this code.
#[derive(Debug)]
pub struct TaskError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    /// For an `epochMismatch`: the member DID's epoch in force, which the
    /// refusal carries for the requester to send instead.
    pub current_epoch: Option<u64>,
}

impl TaskError {
    fn new(task: &str, e: &MuxError) -> Self {
        let code = e.code();
        let prefix = if matches!(
            code,
            "unknownGrant" | "notActive" | "widenRequiresGrant" | "contended" | "epochMismatch"
        ) {
            format!("messaging/mux/{task}")
        } else {
            "messaging/mux".to_string()
        };
        Self {
            code: format!("{prefix}:{code}"),
            message: e.to_string(),
            retryable: e.retryable(),
            current_epoch: match e {
                MuxError::Store(MuxStoreError::EpochMismatch { current, .. }) => Some(*current),
                _ => None,
            },
        }
    }

    fn bad(message: impl Into<String>) -> Self {
        Self {
            code: "malformedRequest".into(),
            message: message.into(),
            retryable: false,
            current_epoch: None,
        }
    }

    fn denied(message: impl Into<String>) -> Self {
        Self {
            code: "messaging/mux:memberNotProven".into(),
            message: message.into(),
            retryable: false,
            current_epoch: None,
        }
    }
}

fn rfc3339(secs: u64) -> String {
    DateTime::<Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_rfc3339(s: &str) -> Result<u64, TaskError> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.timestamp().max(0) as u64)
        .map_err(|e| TaskError::bad(format!("expiresAt: {e}")))
}

fn grant_ref(g: &MuxGrant) -> Value {
    json!({ "grantId": g.grant_id, "did": g.did, "principal": g.principal })
}

/// `GrantView` (shared schema).
pub fn grant_view(g: &MuxGrant, now: u64, attached_now: Option<bool>) -> Value {
    let mut v = json!({
        "statement": g.statement,
        "state": g.state_at(now),
        "scope": g.effective_scope(),
        "expiresAt": rfc3339(g.effective_exp()),
        "narrowed": g.narrowed_scope.is_some() || g.narrowed_exp.is_some(),
    });
    if let Some(a) = attached_now {
        v["attachedNow"] = json!(a);
    }
    v
}

// ─── grant ──────────────────────────────────────────────────────────────────

/// `messaging/mux/grant`: store each statement; refusals are per item.
pub async fn grant(ctx: &Ctx<'_>, sender_did: &str, payload: &Value) -> (Value, Changed) {
    let mut changed = Changed::default();
    let statements = payload
        .get("grants")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut results = Vec::with_capacity(statements.len());
    for raw in &statements {
        let field = |k: &str| {
            raw.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut outcome = json!({
            "grantId": field("grantId"),
            "did": field("issuer"),
            "principal": field("principal"),
        });
        match grants::store_grant(ctx, sender_did, raw).await {
            Ok(stored) => {
                outcome["status"] = json!("stored");
                if let Some(old) = &stored.replaced {
                    outcome["replacedGrantId"] = json!(old.grant_id);
                }
                changed.suspended.extend(stored.suspended);
                changed.stored.push(stored.grant);
            }
            Err(e) => {
                outcome["status"] = json!("refused");
                let code = e.code();
                let prefix = if matches!(
                    code,
                    "epochMismatch"
                        | "replayed"
                        | "grantIdReused"
                        | "didQuota"
                        | "principalQuota"
                        | "contended"
                ) {
                    "messaging/mux/grant"
                } else {
                    "messaging/mux"
                };
                outcome["code"] = json!(format!("{prefix}:{code}"));
                match &e {
                    MuxError::Store(MuxStoreError::EpochMismatch { current, .. }) => {
                        outcome["currentEpoch"] = json!(current);
                    }
                    MuxError::Store(MuxStoreError::Replayed { floor }) => {
                        outcome["replayFloorAt"] = json!(rfc3339(*floor));
                    }
                    _ => {}
                }
            }
        }
        results.push(outcome);
    }
    (json!({ "results": results }), changed)
}

// ─── list ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListReq {
    #[serde(rename = "as")]
    role: String,
    did: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

/// `messaging/mux/list`. As principal: the grants the sender holds. As member:
/// the grants on the sender's own DID (direct authentication only; whether a
/// session attach may also list is design Q6, still open).
pub async fn list(ctx: &Ctx<'_>, sender_did: &str, payload: &Value) -> Result<Value, TaskError> {
    let req: ListReq =
        serde_json::from_value(payload.clone()).map_err(|e| TaskError::bad(e.to_string()))?;
    let limit = req.limit.unwrap_or(100).clamp(1, 500);
    match req.role.as_str() {
        "principal" => {
            if req.did.as_deref().is_some_and(|d| d != sender_did) {
                return Err(TaskError::denied("a principal lists only its own grants"));
            }
            let (page, next) = mux::grants_for_principal(
                ctx.store,
                &did_hash(sender_did),
                req.cursor.as_deref(),
                limit,
                &ctx.limits,
                ctx.now,
            )
            .await
            .map_err(|e| TaskError::new("list", &MuxError::Store(e)))?;
            let mut out = json!({
                "as": "principal",
                "grants": page.iter().map(|g| grant_view(g, ctx.now, None)).collect::<Vec<_>>(),
            });
            if let Some(n) = next {
                out["nextCursor"] = json!(n);
            }
            Ok(out)
        }
        "member" => {
            let did = req.did.unwrap_or_else(|| sender_did.to_string());
            if did != sender_did {
                return Err(TaskError::denied(
                    "a member lists only grants on its own DID",
                ));
            }
            let rec = mux::load(ctx.store, &did_hash(&did), &ctx.limits, ctx.now)
                .await
                .map_err(|e| TaskError::new("list", &MuxError::Store(e)))?;
            Ok(json!({
                "as": "member",
                "epoch": rec.epoch,
                "grants": rec.grants.iter().map(|g| grant_view(g, ctx.now, None)).collect::<Vec<_>>(),
            }))
        }
        other => Err(TaskError::bad(format!("unknown role {other:?}"))),
    }
}

/// Find the grant `grant_id` the sender may act on: on its own DID (as
/// member) or among the grants it holds (as principal).
async fn find_grant(
    ctx: &Ctx<'_>,
    sender_did: &str,
    grant_id: &str,
) -> Result<Option<MuxGrant>, TaskError> {
    let rec = mux::load(ctx.store, &did_hash(sender_did), &ctx.limits, ctx.now)
        .await
        .map_err(|e| TaskError::new("update", &MuxError::Store(e)))?;
    if let Some(g) = rec.grants.into_iter().find(|g| g.grant_id == grant_id) {
        return Ok(Some(g));
    }
    let mut after: Option<String> = None;
    loop {
        let (page, next) = mux::grants_for_principal(
            ctx.store,
            &did_hash(sender_did),
            after.as_deref(),
            200,
            &ctx.limits,
            ctx.now,
        )
        .await
        .map_err(|e| TaskError::new("update", &MuxError::Store(e)))?;
        if let Some(g) = page.into_iter().find(|g| g.grant_id == grant_id) {
            return Ok(Some(g));
        }
        match next {
            Some(n) => after = Some(n),
            None => return Ok(None),
        }
    }
}

// ─── update ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateReq {
    grant_id: String,
    scope: Option<Vec<MuxCapability>>,
    expires_at: Option<String>,
}

/// `messaging/mux/update`: narrow a grant; either party may.
pub async fn update(
    ctx: &Ctx<'_>,
    sender_did: &str,
    payload: &Value,
) -> Result<(Value, Changed), TaskError> {
    let req: UpdateReq =
        serde_json::from_value(payload.clone()).map_err(|e| TaskError::bad(e.to_string()))?;
    let scope = req
        .scope
        .map(MuxScope::new)
        .transpose()
        .map_err(|e| TaskError::new("update", &MuxError::Store(e)))?;
    let exp = req.expires_at.as_deref().map(parse_rfc3339).transpose()?;
    let Some(found) = find_grant(ctx, sender_did, &req.grant_id).await? else {
        return Err(TaskError::new(
            "update",
            &MuxError::Store(MuxStoreError::UnknownGrant),
        ));
    };
    let before = found.clone();
    let after = mux::modify(
        ctx.store,
        &found.did_hash,
        &ctx.limits,
        ctx.now,
        None,
        |rec, _| mux::narrow(rec, &req.grant_id, scope.clone(), exp, ctx.now),
    )
    .await
    .map_err(|e| {
        // An expiry in the past is the update's own code, not a statement's.
        let e = MuxError::Store(e);
        let mut te = TaskError::new("update", &e);
        if te.code.ends_with(":statementExpired") {
            te.code = "messaging/mux/update:expiryNotInFuture".into();
        }
        te
    })?;
    let changed_flag = after.effective_scope() != before.effective_scope()
        || after.effective_exp() != before.effective_exp();
    let mut changed = Changed::default();
    if changed_flag {
        changed.narrowed.push(after.clone());
    }
    Ok((
        json!({ "grant": grant_view(&after, ctx.now, None), "changed": changed_flag }),
        changed,
    ))
}

// ─── revoke ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeReq {
    #[serde(rename = "as")]
    role: String,
    did: Option<String>,
    #[serde(default)]
    grant_ids: Vec<String>,
    #[serde(default)]
    dids: Vec<String>,
}

/// `messaging/mux/revoke`.
pub async fn revoke(
    ctx: &Ctx<'_>,
    sender_did: &str,
    payload: &Value,
) -> Result<(Value, Changed), TaskError> {
    let req: RevokeReq =
        serde_json::from_value(payload.clone()).map_err(|e| TaskError::bad(e.to_string()))?;
    if req.did.as_deref().is_some_and(|d| d != sender_did) {
        return Err(TaskError::denied(
            "revoke acts only on the sender's own grants",
        ));
    }
    let err = |e: MuxError| TaskError::new("revoke", &e);
    let mut removed = Vec::new();
    let mut unmatched_ids: HashSet<String> = req.grant_ids.iter().cloned().collect();
    let mut unmatched_dids: HashSet<String> = req.dids.iter().cloned().collect();

    match req.role.as_str() {
        "principal" => {
            // DIDs named directly, plus the DIDs of named grant ids.
            let mut members: Vec<String> = req.dids.clone();
            for id in &req.grant_ids {
                if let Some(g) = find_grant(ctx, sender_did, id).await?
                    && g.principal == sender_did
                {
                    members.push(g.did.clone());
                }
            }
            let gone = grants::revoke_as_principal(ctx, sender_did, &members)
                .await
                .map_err(err)?;
            removed.extend(gone);
        }
        "member" => {
            let mut gone = grants::revoke_as_member(ctx, sender_did, &req.dids)
                .await
                .map_err(err)?;
            if !req.grant_ids.is_empty() {
                let ids: HashSet<String> = req.grant_ids.iter().cloned().collect();
                gone.extend(
                    mux::modify(
                        ctx.store,
                        &did_hash(sender_did),
                        &ctx.limits,
                        ctx.now,
                        None,
                        |rec, _| Ok(mux::revoke_grant_ids(rec, &ids, ctx.now)),
                    )
                    .await
                    .map_err(|e| err(MuxError::Store(e)))?,
                );
            }
            removed.extend(gone);
        }
        other => return Err(TaskError::bad(format!("unknown role {other:?}"))),
    }
    for g in &removed {
        unmatched_ids.remove(&g.grant_id);
        unmatched_dids.remove(&g.did);
        unmatched_dids.remove(&g.principal);
    }
    let mut out = json!({ "revoked": removed.iter().map(grant_ref).collect::<Vec<_>>() });
    if !unmatched_ids.is_empty() {
        out["unmatchedGrantIds"] = json!(unmatched_ids.into_iter().collect::<Vec<_>>());
    }
    if !unmatched_dids.is_empty() {
        out["unmatchedDids"] = json!(unmatched_dids.into_iter().collect::<Vec<_>>());
    }
    let reason = Some(if req.role == "principal" {
        LeaveReason::RevokedByPrincipal
    } else {
        LeaveReason::RevokedByMember
    });
    Ok((
        out,
        Changed {
            removed,
            reason,
            ..Default::default()
        },
    ))
}

// ─── revoke-all ─────────────────────────────────────────────────────────────

/// `messaging/mux/revoke-all`: the signed statement is the authority.
pub async fn revoke_all(ctx: &Ctx<'_>, payload: &Value) -> Result<(Value, Changed), TaskError> {
    let raw = payload
        .get("revocation")
        .ok_or_else(|| TaskError::bad("missing revocation"))?;
    let st = ctx
        .verifier
        .verify_revoke_all(
            raw,
            Expect {
                mediator_did: ctx.mediator_did,
                principal: None,
                now: ctx.now,
                max_lifetime_secs: ctx.limits.max_grant_lifetime_secs,
            },
        )
        .await
        .map_err(|e| TaskError::new("revoke-all", &MuxError::Statement(e)))?;

    let outcome = grants::advance_epoch(ctx, &st.did_hash, st.epoch)
        .await
        .map_err(|e| TaskError::new("revoke-all", &e))?;

    match outcome {
        EpochAdvance::Advanced(epoch, voided) => Ok((
            json!({ "did": st.did, "epoch": epoch, "epochAdvanced": true, "revokedGrants": voided.len() }),
            Changed {
                removed: voided,
                reason: Some(LeaveReason::EpochBumped),
                attaches_ended: Some(st.did_hash.clone()),
                ..Default::default()
            },
        )),
        EpochAdvance::AlreadyPast(epoch) => Ok((
            json!({ "did": st.did, "epoch": epoch, "epochAdvanced": false, "revokedGrants": 0 }),
            Changed::default(),
        )),
        EpochAdvance::Future(current) => Err(TaskError {
            code: "messaging/mux/revoke-all:epochMismatch".into(),
            message: format!(
                "statement voids epoch {}, the DID's current epoch is {current}",
                st.epoch
            ),
            retryable: false,
            current_epoch: Some(current),
        }),
    }
}

// ─── attach / detach (on the connection itself) ─────────────────────────────

/// `messaging/mux/attach` on mux connection `conn`. Refusals are per item.
pub async fn attach(
    ctx: &Ctx<'_>,
    conn: &MuxConn,
    streaming: Option<&StreamingTask>,
    max_attach_lifetime_secs: u64,
    payload: &Value,
) -> (Value, Changed) {
    let mut changed = Changed::default();
    let ident = conn.session.lock().await.ident();
    let statements = payload
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut results = Vec::with_capacity(statements.len());
    for raw in &statements {
        let did = raw
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let admitted = match verify_attach(ctx, &ident, raw, max_attach_lifetime_secs).await {
            Ok((member, suspended)) => {
                changed.suspended.extend(suspended);
                conn.session.lock().await.admit(member)
            }
            Err(e) => Err(e),
        };
        results.push(match admitted {
            Ok(member) => {
                if let Some(streaming) = streaming {
                    conn.register_member(streaming, &member).await;
                }
                // Reported to the principal like any join (spec event rule 5).
                conn.joined.lock().await.push(member.clone());
                conn.notify.notify_one();
                json!({
                    "did": member.did,
                    "status": "attached",
                    "scope": member.scope,
                    "expiresAt": rfc3339(member.expires_at),
                })
            }
            Err(e) => {
                let code = e.code();
                let prefix = if matches!(code, "sessionMismatch" | "memberQuota") {
                    "messaging/mux/attach"
                } else {
                    "messaging/mux"
                };
                json!({ "did": did, "status": "refused", "code": format!("{prefix}:{code}") })
            }
        });
    }
    (json!({ "results": results }), changed)
}

/// `messaging/mux/detach`: removes session attaches only. A member carried by
/// a stored grant stays (`retainedByGrant`): ending that is a revoke.
pub async fn detach(conn: &MuxConn, streaming: Option<&StreamingTask>, payload: &Value) -> Value {
    let dids: Vec<String> = payload
        .get("dids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let (mut detached, mut retained, mut not_attached) = (Vec::new(), Vec::new(), Vec::new());
    for did in dids {
        let hash = did_hash(&did);
        let source = conn
            .session
            .lock()
            .await
            .get(&hash)
            .map(|m| m.source.clone());
        match source {
            Some(MuxSource::Attach) => {
                conn.detach(streaming, &hash, LeaveReason::DetachRequested)
                    .await;
                detached.push(did);
            }
            Some(MuxSource::Grant { .. }) => retained.push(did),
            None => not_attached.push(did),
        }
    }
    json!({ "detached": detached, "retainedByGrant": retained, "notAttached": not_attached })
}

#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::mux::proof::StatementVerifier;
    use crate::store::MemoryStore;
    use crate::task_specs::messaging::mux as spec;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_messaging_mediator_common::store::{MediatorStore, mux::MuxLimits};
    use affinidi_messaging_mediator_common::types::acls::MediatorACLSet;
    use affinidi_secrets_resolver::secrets::Secret;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    const MEDIATOR: &str = "did:web:mediator.example";
    const NOW: u64 = 1_800_000_000;

    fn did_key(seed: u8) -> (String, Secret) {
        let seed = [seed; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));
        (did, secret)
    }

    async fn signed(body: Value, secret: &Secret) -> Value {
        sign_trust_task(&body, secret, SignOptions::new())
            .await
            .unwrap()
    }

    /// Each response must deserialise into the spec's generated `Response`.
    fn conforms<R: serde::de::DeserializeOwned>(v: &Value) {
        serde_json::from_value::<R>(v.clone())
            .unwrap_or_else(|e| panic!("response does not match the spec: {e}\n{v:#}"));
    }

    #[tokio::test]
    async fn grant_list_update_revoke_and_revoke_all() {
        let store = MemoryStore::new();
        let verifier = StatementVerifier::new(
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap(),
        );
        let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let ctx = Ctx {
            store: &store,
            verifier: &verifier,
            mediator_did: MEDIATOR,
            limits: MuxLimits::default(),
            default_acl: &acl,
            now: NOW,
        };
        let (principal, _) = did_key(51);
        let (member, key) = did_key(52);
        store
            .account_add(&did_hash(&member), &acl, None)
            .await
            .unwrap();

        let good = signed(
            json!({"type": "muxGrant", "issuer": member, "audience": MEDIATOR, "grantId": "g1",
                   "principal": principal, "scope": ["receive", "pickup"], "epoch": 0,
                   "iat": NOW, "exp": NOW + 3600}),
            &key,
        )
        .await;
        let wrong_epoch = signed(
            json!({"type": "muxGrant", "issuer": member, "audience": MEDIATOR, "grantId": "g2",
                   "principal": "did:example:other", "scope": ["receive"], "epoch": 9,
                   "iat": NOW, "exp": NOW + 3600}),
            &key,
        )
        .await;

        // grant: per-item outcomes.
        let (resp, _) = grant(&ctx, &principal, &json!({ "grants": [good, wrong_epoch] })).await;
        conforms::<spec::grant::v0_1::Response>(&resp);
        assert_eq!(resp["results"][0]["status"], "stored");
        assert_eq!(resp["results"][1]["status"], "refused");
        // Presented by the principal, so a statement for another principal is
        // refused before its epoch is even looked at.
        assert_eq!(
            resp["results"][1]["code"],
            "messaging/mux:principalMismatch"
        );

        // list, both ways.
        let as_principal = list(&ctx, &principal, &json!({"as": "principal"}))
            .await
            .unwrap();
        conforms::<spec::list::v0_1::Response>(&as_principal);
        assert_eq!(as_principal["grants"].as_array().unwrap().len(), 1);
        assert_eq!(as_principal["grants"][0]["state"], "active");
        let as_member = list(&ctx, &member, &json!({"as": "member"})).await.unwrap();
        conforms::<spec::list::v0_1::Response>(&as_member);
        assert_eq!(as_member["epoch"], 0);
        assert!(
            list(&ctx, &principal, &json!({"as": "member", "did": member}))
                .await
                .is_err()
        );

        // update: narrow is fine, widen is refused.
        let (resp, changed) = update(
            &ctx,
            &principal,
            &json!({"grantId": "g1", "scope": ["receive"]}),
        )
        .await
        .unwrap();
        conforms::<spec::update::v0_1::Response>(&resp);
        assert_eq!(resp["changed"], true);
        assert_eq!(changed.narrowed.len(), 1);
        let err = update(
            &ctx,
            &member,
            &json!({"grantId": "g1", "scope": ["receive", "send"]}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "messaging/mux/update:widenRequiresGrant");
        let err = update(&ctx, &principal, &json!({"grantId": "nope"}))
            .await
            .unwrap_err();
        assert_eq!(err.code, "messaging/mux/update:unknownGrant");

        // revoke-all: voids the epoch; a stale statement is a no-op, a future
        // one is refused.
        let ra = |epoch: u64| {
            json!({"type": "muxRevokeAll", "issuer": member, "audience": MEDIATOR,
                   "epoch": epoch, "iat": NOW, "exp": NOW + 300})
        };
        let st = signed(ra(0), &key).await;
        let (resp, changed) = revoke_all(&ctx, &json!({ "revocation": st }))
            .await
            .unwrap();
        conforms::<spec::revoke_all::v0_1::Response>(&resp);
        assert_eq!(resp["epochAdvanced"], true);
        assert_eq!(resp["revokedGrants"], 1);
        assert_eq!(changed.removed.len(), 1);
        let (resp, _) = revoke_all(&ctx, &json!({ "revocation": st }))
            .await
            .unwrap();
        assert_eq!(resp["epochAdvanced"], false);
        let future = signed(ra(5), &key).await;
        assert_eq!(
            revoke_all(&ctx, &json!({ "revocation": future }))
                .await
                .unwrap_err()
                .code,
            "messaging/mux/revoke-all:epochMismatch"
        );

        // revoke: a new grant under the new epoch, then the principal drops it.
        let again = signed(
            json!({"type": "muxGrant", "issuer": member, "audience": MEDIATOR, "grantId": "g3",
                   "principal": principal, "scope": ["receive"], "epoch": 1,
                   "iat": NOW + 1, "exp": NOW + 3600}),
            &key,
        )
        .await;
        let (resp, _) = grant(&ctx, &member, &json!({ "grants": [again] })).await;
        assert_eq!(resp["results"][0]["status"], "stored");
        let (resp, changed) = revoke(
            &ctx,
            &principal,
            &json!({"as": "principal", "grantIds": ["g3", "missing"]}),
        )
        .await
        .unwrap();
        conforms::<spec::revoke::v0_1::Response>(&resp);
        assert_eq!(resp["revoked"][0]["grantId"], "g3");
        assert_eq!(resp["unmatchedGrantIds"], json!(["missing"]));
        assert_eq!(changed.removed.len(), 1);
    }
}

/// The type of a `messaging/mux/ack` answer. It goes to the connection only,
/// never stored: acknowledging is idempotent, so a lost answer is recovered by
/// asking again, while a stored one would itself need acknowledging, and the
/// answer to that, without end (spec, consumer rule 4). Both wires.
pub const ACK_RESPONSE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/ack/0.1#response";

/// `messaging/mux/ack`: delete the frames named, as the connection's
/// principal may (its own, and each member's while the member holds
/// `delete`). An acknowledgement: it removes only a copy held for the
/// principal or such a member, never one they sent to someone else. Sorted into `acked` and `refused` (`notFound` /
/// `notPermitted`); a store failure fails the request, retryable, rather than
/// reporting a frame as not found.
pub async fn ack(
    state: &crate::SharedData,
    session: &crate::common::session::Session,
    payload: &Value,
) -> Result<Value, TaskError> {
    let ids: Vec<String> = payload
        .get("messageIds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let results = crate::handlers::message_delete::delete_for_session(
        state,
        session,
        &ids,
        crate::monitor::Channel::Websocket,
        crate::handlers::message_delete::DeleteKind::Acknowledge,
    )
    .await;
    let (mut acked, mut refused) = (Vec::new(), Vec::new());
    for r in results {
        match r.outcome {
            Ok(()) => acked.push(r.id),
            Err(e)
                if e.is_storage_cap()
                    || matches!(
                        e,
                        affinidi_messaging_mediator_common::errors::MediatorError::DatabaseError(
                            ..
                        )
                    ) =>
            {
                return Err(TaskError {
                    code: "storageError".into(),
                    message: format!("the store could not delete a frame: {e}"),
                    retryable: true,
                    current_epoch: None,
                });
            }
            Err(_) => refused.push(json!({
                "messageId": r.id,
                "reason": if r.member_without_delete { "notPermitted" } else { "notFound" },
            })),
        }
    }
    Ok(json!({ "acked": acked, "refused": refused }))
}
