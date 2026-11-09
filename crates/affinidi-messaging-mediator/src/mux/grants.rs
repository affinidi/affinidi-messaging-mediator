//! Storing, suspending and revoking grants: the operations the
//! `messaging/mux/*` handlers call, transport-free.
//!
//! Each operation runs the checks in the order the design fixes (§4.4, R7.5):
//! verify the statement → member account standing and scope ⊆ its ACLs →
//! unknown-key rule (§5.3) → store rules. Detaching the affected DIDs from
//! live connections is the caller's, because it owns the connections; every
//! operation returns exactly which grants it changed so the caller can.

use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    store::{
        MediatorStore,
        mux::{self, MuxCapability, MuxGrant, MuxLimits, MuxScope, MuxStoreError},
    },
    types::acls::MediatorACLSet,
};
use serde_json::Value;
use std::collections::HashSet;

use super::proof::{Expect, StatementError, StatementVerifier};
use crate::common::authz::{Capability, grants};

/// Why one grant was refused. [`MuxError::code`] is its stable wire code.
#[derive(Debug)]
pub enum MuxError {
    Statement(StatementError),
    Store(MuxStoreError),
    /// The member DID has no account at this mediator.
    UnknownMember,
    /// The member's account is blocked.
    MemberBlocked,
    /// The scope asks for something the member's own ACLs do not allow.
    ScopeExceedsAcl(MuxCapability),
}

impl MuxError {
    /// The code after `messaging/mux/<task>:`.
    pub fn code(&self) -> &'static str {
        match self {
            MuxError::Statement(e) => e.code(),
            MuxError::Store(e) => store_code(e),
            MuxError::UnknownMember => "accountUnavailable",
            MuxError::MemberBlocked => "accountUnavailable",
            MuxError::ScopeExceedsAcl(_) => "scopeNotPermitted",
        }
    }

    /// Whether retrying the same request can succeed.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            MuxError::Store(MuxStoreError::Contended | MuxStoreError::Store(_))
        )
    }
}

impl std::fmt::Display for MuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MuxError::Statement(e) => e.fmt(f),
            MuxError::Store(e) => e.fmt(f),
            MuxError::UnknownMember => {
                f.write_str("the member DID has no account at this mediator")
            }
            MuxError::MemberBlocked => f.write_str("the member DID's account is blocked"),
            MuxError::ScopeExceedsAcl(cap) => {
                write!(
                    f,
                    "scope includes {cap:?}, which the member's own ACLs do not allow"
                )
            }
        }
    }
}

impl From<StatementError> for MuxError {
    fn from(e: StatementError) -> Self {
        MuxError::Statement(e)
    }
}

impl From<MuxStoreError> for MuxError {
    fn from(e: MuxStoreError) -> Self {
        MuxError::Store(e)
    }
}

fn store_code(e: &MuxStoreError) -> &'static str {
    match e {
        MuxStoreError::EmptyScope => "emptyScope",
        MuxStoreError::DidMismatch => "malformedRequest",
        MuxStoreError::EpochMismatch { .. } => "epochMismatch",
        MuxStoreError::Expired => "statementExpired",
        MuxStoreError::LifetimeTooLong { .. } => "lifetimeTooLong",
        MuxStoreError::Replayed { .. } => "replayed",
        MuxStoreError::GrantIdReused => "grantIdReused",
        MuxStoreError::DidQuota { .. } => "didQuota",
        MuxStoreError::PrincipalQuota { .. } => "principalQuota",
        MuxStoreError::UnknownGrant => "unknownGrant",
        MuxStoreError::NotActive => "notActive",
        MuxStoreError::WidenRefused => "widenRequiresGrant",
        MuxStoreError::Contended => "contended",
        // Not a per-item outcome: a store failure fails the whole request
        // (the handler maps it to the framework's internal error).
        MuxStoreError::Store(_) => "storeUnavailable",
    }
}

/// What the member's ACLs must allow for each capability a scope asks for.
fn capability_needs(cap: MuxCapability) -> Capability {
    match cap {
        MuxCapability::Receive | MuxCapability::Pickup | MuxCapability::Delete => {
            Capability::ReceiveMessages
        }
        MuxCapability::Send => Capability::SendMessages,
    }
}

/// A scope may never exceed what the member could do on its own connection
/// (design §5.5): not blocked, local, and each capability's ACL.
pub fn check_scope(acls: &MediatorACLSet, scope: &MuxScope) -> Result<(), MuxError> {
    if !grants(acls, Capability::NotBlocked) {
        return Err(MuxError::MemberBlocked);
    }
    for cap in scope.iter() {
        if !grants(acls, Capability::Local) || !grants(acls, capability_needs(cap)) {
            return Err(MuxError::ScopeExceedsAcl(cap));
        }
    }
    Ok(())
}

/// A grant that was stored, and what storing it changed.
#[derive(Debug)]
pub struct Stored {
    pub grant: MuxGrant,
    /// The principal's earlier grant on this DID, now replaced.
    pub replaced: Option<MuxGrant>,
    /// Other principals' grants the unknown-key rule suspended (§5.3). Each
    /// needs a live detach and a durable `grants-suspended` notice.
    pub suspended: Vec<MuxGrant>,
}

/// Everything a store call needs from the mediator.
pub struct Ctx<'a> {
    pub store: &'a dyn MediatorStore,
    pub verifier: &'a StatementVerifier,
    pub mediator_did: &'a str,
    pub limits: MuxLimits,
    /// The member ACL default for a DID with no ACL record.
    pub default_acl: &'a MediatorACLSet,
    pub now: u64,
}

/// Verify and store one grant statement presented by `presenter_did`.
///
/// The presenter is either the member itself (the statement's `issuer`), in
/// which case the statement's `principal` is whoever it names, or the
/// principal, in which case the statement must name the presenter.
pub async fn store_grant(
    ctx: &Ctx<'_>,
    presenter_did: &str,
    raw: &Value,
) -> Result<Stored, MuxError> {
    let issuer = raw
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let principal = (issuer != presenter_did).then_some(presenter_did);
    let grant = ctx
        .verifier
        .verify_grant(
            raw,
            Expect {
                mediator_did: ctx.mediator_did,
                principal,
                now: ctx.now,
                max_lifetime_secs: ctx.limits.max_grant_lifetime_secs,
            },
        )
        .await?;

    // Member standing and scope, from the member's own account.
    if !ctx
        .store
        .account_exists(&grant.did_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
    {
        return Err(MuxError::UnknownMember);
    }
    let acls = ctx
        .store
        .get_did_acl(&grant.did_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
        .unwrap_or_else(|| ctx.default_acl.clone());
    check_scope(&acls, &grant.scope)?;

    // The unknown-key rule runs on any valid proof of control, before and
    // independently of whether the grant itself is then accepted: a valid
    // signature from a new authentication key is the signal, whatever else
    // is wrong with the grant.
    let suspended = suspend_unless_known_kid(ctx, &grant.did_hash, &grant.kid).await?;

    let replaced = mux::modify(
        ctx.store,
        &grant.did_hash,
        &ctx.limits,
        ctx.now,
        Some(&grant.principal_hash),
        |rec, principal_count| {
            mux::put_grant(rec, grant.clone(), &ctx.limits, ctx.now, principal_count)
        },
    )
    .await?;

    Ok(Stored {
        grant,
        replaced,
        suspended,
    })
}

/// Apply the unknown-key rule for a proof of control by `kid` over member
/// `did_hash` — from a grant, an attach, or a direct authentication.
pub async fn suspend_unless_known_kid(
    ctx: &Ctx<'_>,
    did_hash: &str,
    kid: &str,
) -> Result<Vec<MuxGrant>, MuxError> {
    Ok(
        mux::modify(ctx.store, did_hash, &ctx.limits, ctx.now, None, |rec, _| {
            Ok(mux::suspend_unless_known_kid(rec, kid, ctx.now))
        })
        .await?,
    )
}

/// A principal drops member DIDs it holds grants on.
pub async fn revoke_as_principal(
    ctx: &Ctx<'_>,
    principal_did: &str,
    member_dids: &[String],
) -> Result<Vec<MuxGrant>, MuxError> {
    let me: HashSet<String> = [did_hash(principal_did)].into();
    let mut out = Vec::new();
    for member in member_dids {
        out.extend(
            mux::modify(
                ctx.store,
                &did_hash(member),
                &ctx.limits,
                ctx.now,
                None,
                |rec, _| Ok(mux::revoke_principals(rec, &me, ctx.now)),
            )
            .await?,
        );
    }
    Ok(out)
}

/// A member removes named principals' grants on itself.
pub async fn revoke_as_member(
    ctx: &Ctx<'_>,
    member_did: &str,
    principal_dids: &[String],
) -> Result<Vec<MuxGrant>, MuxError> {
    let them: HashSet<String> = principal_dids.iter().map(did_hash).collect();
    Ok(mux::modify(
        ctx.store,
        &did_hash(member_did),
        &ctx.limits,
        ctx.now,
        None,
        |rec, _| Ok(mux::revoke_principals(rec, &them, ctx.now)),
    )
    .await?)
}

/// `revoke-all` by the member: bump the epoch, voiding every grant.
pub async fn revoke_all(ctx: &Ctx<'_>, member_did: &str) -> Result<(u64, Vec<MuxGrant>), MuxError> {
    Ok(mux::modify(
        ctx.store,
        &did_hash(member_did),
        &ctx.limits,
        ctx.now,
        None,
        |rec, _| Ok(mux::revoke_all(rec, ctx.now)),
    )
    .await?)
}

/// Re-check a grant's signing key (§5.1); mark it stale if it no longer
/// belongs to the member. Returns the grant when it was marked stale, `None`
/// when it is still current, and leaves it alone when the member's DID could
/// not be resolved — "unknown" is neither stale nor fine, so the caller keeps
/// its previous decision and retries later.
pub async fn revalidate(ctx: &Ctx<'_>, grant: &MuxGrant) -> Result<Option<MuxGrant>, String> {
    match ctx.verifier.key_is_current(&grant.kid, &grant.key_fp).await {
        Ok(true) => Ok(None),
        Ok(false) => mux::modify(
            ctx.store,
            &grant.did_hash,
            &ctx.limits,
            ctx.now,
            None,
            |rec, _| Ok(mux::mark_stale_key(rec, &grant.grant_id, ctx.now)),
        )
        .await
        .map_err(|e| e.to_string()),
        Err(unknown) => Err(unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(caps: &[MuxCapability]) -> MuxScope {
        MuxScope::new(caps.iter().copied()).unwrap()
    }

    #[test]
    fn scope_never_exceeds_the_members_acls() {
        let all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        check_scope(&all, &scope(&[MuxCapability::Receive, MuxCapability::Send])).unwrap();

        let mut no_send = all.clone();
        no_send.set_send_messages(false, false, true).unwrap();
        assert!(matches!(
            check_scope(&no_send, &scope(&[MuxCapability::Send])),
            Err(MuxError::ScopeExceedsAcl(MuxCapability::Send))
        ));
        check_scope(&no_send, &scope(&[MuxCapability::Receive])).unwrap();

        let mut blocked = all.clone();
        blocked.set_blocked(true);
        assert!(matches!(
            check_scope(&blocked, &scope(&[MuxCapability::Receive])),
            Err(MuxError::MemberBlocked)
        ));
    }

    #[cfg(feature = "memory-backend")]
    mod with_store {
        use super::super::*;
        use crate::store::MemoryStore;
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use affinidi_secrets_resolver::secrets::Secret;
        use serde_json::json;
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

        async fn grant(
            member: &str,
            secret: &Secret,
            principal: &str,
            id: &str,
            iat: u64,
        ) -> Value {
            let body = json!({
                "type": "muxGrant", "issuer": member, "audience": MEDIATOR,
                "grantId": id, "principal": principal, "scope": ["receive"],
                "epoch": 0, "iat": iat, "exp": iat + 3600,
            });
            sign_trust_task(&body, secret, SignOptions::new())
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn store_list_revoke_round_trip() {
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
            let (member, secret) = did_key(21);
            let (principal, _) = did_key(22);

            // No account for the member yet.
            let raw = grant(&member, &secret, &principal, "g1", NOW).await;
            assert!(matches!(
                store_grant(&ctx, &principal, &raw).await,
                Err(MuxError::UnknownMember)
            ));

            store
                .account_add(&did_hash(&member), &acl, None)
                .await
                .unwrap();

            // Presented by someone who is neither the member nor the principal.
            let err = store_grant(&ctx, "did:example:stranger", &raw)
                .await
                .unwrap_err();
            assert_eq!(err.code(), "principalMismatch");

            // Presented by the principal, and by the member: both fine.
            let stored = store_grant(&ctx, &principal, &raw).await.unwrap();
            assert!(stored.replaced.is_none());
            assert!(stored.suspended.is_empty());
            let raw2 = grant(&member, &secret, &principal, "g2", NOW + 1).await;
            let ctx2 = Ctx {
                now: NOW + 1,
                ..ctx
            };
            let stored = store_grant(&ctx2, &member, &raw2).await.unwrap();
            assert_eq!(stored.replaced.unwrap().grant_id, "g1");

            // Replaying the replaced statement is refused.
            assert_eq!(
                store_grant(&ctx2, &principal, &raw)
                    .await
                    .unwrap_err()
                    .code(),
                "replayed"
            );

            let (page, _) = mux::grants_for_principal(
                &store,
                &did_hash(&principal),
                None,
                10,
                &ctx2.limits,
                NOW + 1,
            )
            .await
            .unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].statement, raw2);

            // The member revokes the principal.
            let gone = revoke_as_member(&ctx2, &member, std::slice::from_ref(&principal))
                .await
                .unwrap();
            assert_eq!(gone.len(), 1);
            assert_eq!(
                store
                    .mux_principal_count(&did_hash(&principal))
                    .await
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn every_store_refusal_has_a_code() {
        for e in [
            MuxStoreError::EmptyScope,
            MuxStoreError::EpochMismatch {
                grant: 0,
                current: 1,
            },
            MuxStoreError::Replayed { floor: 1 },
            MuxStoreError::WidenRefused,
            MuxStoreError::Contended,
        ] {
            assert!(!MuxError::Store(e).code().is_empty());
        }
        assert!(MuxError::Store(MuxStoreError::Contended).retryable());
        assert!(!MuxError::Store(MuxStoreError::WidenRefused).retryable());
    }
}
