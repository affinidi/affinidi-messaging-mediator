//! One mux connection's member set (design §7.1).
//!
//! The principal stays the connection's authenticated identity. Members are
//! the DIDs it carries, each admitted by a session attach (bound to this
//! connection's `sessionId` + `muxNonce`) or a stored grant. This type holds
//! the set and answers the one question every data-plane check asks: *may
//! this connection do `cap` for DID `x` right now?* It does no I/O except
//! through the grant layer, so the socket handler owns registration with the
//! streaming task and the events that report changes.

use std::collections::HashMap;

use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    store::mux::{self, MuxCapability, MuxGrant, MuxScope},
};
use serde_json::Value;

use super::grants::{Ctx, MuxError, check_scope};
use super::proof::Expect;

/// Bytes of randomness in the per-connection attach nonce. The spec's
/// `MuxNonce` is 32 random bytes as unpadded base64url: exactly 43 characters.
const NONCE_BYTES: usize = 32;

/// A fresh `MuxNonce`.
fn new_nonce() -> String {
    use base64::Engine;
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(rand::random::<[u8; NONCE_BYTES]>())
}

/// How a member came to be on the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MuxSource {
    Attach,
    Grant { grant_id: String },
}

/// One DID this connection carries.
#[derive(Clone, Debug)]
pub struct MuxMember {
    pub did: String,
    pub did_hash: String,
    pub source: MuxSource,
    pub scope: MuxScope,
    /// The signing key that admitted it, for re-validation (§5.1).
    pub kid: String,
    pub key_fp: String,
    pub expires_at: u64,
}

/// Why a member left, or was never admitted. The wire names are the spec's
/// `DetachReason` / `MemberChangeReason` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveReason {
    Expired,
    DetachRequested,
    RevokedByMember,
    RevokedByPrincipal,
    EpochBumped,
    SuspendedUnknownKey,
    KeyRotated,
    AccountBlocked,
    ResolutionFailed,
}

impl LeaveReason {
    pub fn wire(self) -> &'static str {
        match self {
            LeaveReason::Expired => "expired",
            LeaveReason::DetachRequested => "detachRequested",
            LeaveReason::RevokedByMember => "revokedByMember",
            LeaveReason::RevokedByPrincipal => "revokedByPrincipal",
            LeaveReason::EpochBumped => "epochBumped",
            LeaveReason::SuspendedUnknownKey => "suspendedUnknownKey",
            LeaveReason::KeyRotated => "keyRotated",
            LeaveReason::AccountBlocked => "accountBlocked",
            LeaveReason::ResolutionFailed => "resolutionFailed",
        }
    }
}

/// A connection's mux state.
#[derive(Debug)]
pub struct MuxSession {
    pub principal_did: String,
    pub principal_hash: String,
    pub session_id: String,
    /// Single-connection nonce that attaches sign over (§4.2).
    pub nonce: String,
    max_members: usize,
    members: HashMap<String, MuxMember>,
}

impl MuxSession {
    pub fn new(principal_did: &str, session_id: &str, max_members: usize) -> Self {
        Self {
            principal_did: principal_did.to_string(),
            principal_hash: did_hash(principal_did),
            session_id: session_id.to_string(),
            nonce: new_nonce(),
            max_members,
            members: HashMap::new(),
        }
    }

    pub fn members(&self) -> impl Iterator<Item = &MuxMember> {
        self.members.values()
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn get(&self, did_hash: &str) -> Option<&MuxMember> {
        self.members.get(did_hash)
    }

    /// Whether this connection may do `cap` for `did_hash` at `now`. The
    /// principal itself may do everything its own session allows; that check
    /// is the caller's, as it is today.
    pub fn allows(&self, did_hash: &str, cap: MuxCapability, now: u64) -> bool {
        self.members
            .get(did_hash)
            .is_some_and(|m| m.expires_at > now && m.scope.contains(cap))
    }

    /// The connection identity an attach must be bound to, copied out so the
    /// statement can be verified without holding the session lock across the
    /// DID resolution it needs (R1.3).
    pub fn ident(&self) -> AttachIdent {
        AttachIdent {
            principal_did: self.principal_did.clone(),
            session_id: self.session_id.clone(),
            nonce: self.nonce.clone(),
        }
    }

    /// Put an already-verified member on the connection, enforcing the
    /// per-connection cap. An attach overlapping a grant keeps the wider.
    pub fn admit(&mut self, member: MuxMember) -> Result<MuxMember, MuxError> {
        if !self.members.contains_key(&member.did_hash) && self.members.len() >= self.max_members {
            return Err(MuxError::MemberQuota {
                max: self.max_members,
            });
        }
        let member = match self.members.remove(&member.did_hash) {
            Some(existing) => merge(existing, member),
            None => member,
        };
        self.members.insert(member.did_hash.clone(), member.clone());
        Ok(member)
    }

    /// [`verify_attach`] then [`Self::admit`], for callers that own the
    /// session outright.
    pub async fn attach(
        &mut self,
        ctx: &Ctx<'_>,
        raw: &Value,
        max_attach_lifetime_secs: u64,
    ) -> Result<(MuxMember, Vec<MuxGrant>), MuxError> {
        if self.members.len() >= self.max_members {
            // Cheap early refusal; `admit` re-checks.
            let did = raw
                .get("issuer")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !self.members.contains_key(&did_hash(did)) {
                return Err(MuxError::MemberQuota {
                    max: self.max_members,
                });
            }
        }
        let (member, suspended) =
            verify_attach(ctx, &self.ident(), raw, max_attach_lifetime_secs).await?;
        Ok((self.admit(member)?, suspended))
    }

    /// Admit every usable stored grant on connect (§4.5). Returns the members
    /// admitted and the DIDs refused, with why.
    pub async fn load_grants(
        &mut self,
        ctx: &Ctx<'_>,
    ) -> Result<(Vec<MuxMember>, Vec<(String, LeaveReason)>), MuxError> {
        let mut admitted = Vec::new();
        let mut refused = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let (page, next) = mux::grants_for_principal(
                ctx.store,
                &self.principal_hash,
                after.as_deref(),
                100,
                &ctx.limits,
                ctx.now,
            )
            .await?;
            for grant in page {
                if !grant.is_usable(ctx.now) {
                    continue;
                }
                if self.members.len() >= self.max_members {
                    refused.push((grant.did.clone(), LeaveReason::DetachRequested));
                    continue;
                }
                match ctx.verifier.key_is_current(&grant.kid, &grant.key_fp).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = super::grants::revalidate(ctx, &grant).await;
                        refused.push((grant.did.clone(), LeaveReason::KeyRotated));
                        continue;
                    }
                    // Unknown is not "fine": the member is not carried until
                    // its key can be checked (fail closed, R5.3).
                    Err(_) => {
                        refused.push((grant.did.clone(), LeaveReason::ResolutionFailed));
                        continue;
                    }
                }
                if member_standing(ctx, &grant.did_hash, grant.effective_scope())
                    .await
                    .is_err()
                {
                    refused.push((grant.did.clone(), LeaveReason::AccountBlocked));
                    continue;
                }
                let member = MuxMember {
                    did: grant.did.clone(),
                    did_hash: grant.did_hash.clone(),
                    source: MuxSource::Grant {
                        grant_id: grant.grant_id.clone(),
                    },
                    scope: grant.effective_scope().clone(),
                    kid: grant.kid.clone(),
                    key_fp: grant.key_fp.clone(),
                    expires_at: grant.effective_exp(),
                };
                let member = match self.members.remove(&grant.did_hash) {
                    Some(existing) => merge(existing, member),
                    None => member,
                };
                self.members.insert(grant.did_hash.clone(), member.clone());
                admitted.push(member);
            }
            match next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        Ok((admitted, refused))
    }

    /// Admit a member carried by a stored grant, while connected. A member
    /// already carried by an earlier grant takes the new one's identity (it
    /// replaced the old), so a revoke of the new grant still finds it; one
    /// carried by an attach is merged, as on connect. Returns the member and
    /// whether it is new to the connection.
    pub fn admit_grant(&mut self, member: MuxMember) -> Result<(MuxMember, bool), MuxError> {
        let existing = self.members.get(&member.did_hash).map(|m| m.source.clone());
        match existing {
            Some(MuxSource::Grant { .. }) => {
                self.members.insert(member.did_hash.clone(), member.clone());
                Ok((member, false))
            }
            Some(MuxSource::Attach) => Ok((self.admit(member)?, false)),
            None => Ok((self.admit(member)?, true)),
        }
    }

    /// Remove a member. Returns it if it was on the connection.
    pub fn detach(&mut self, did_hash: &str) -> Option<MuxMember> {
        self.members.remove(did_hash)
    }

    /// Remove members whose admission covered `grant_ids` (revoked,
    /// suspended or stale grants). Attach-admitted members are untouched.
    pub fn detach_grants(&mut self, grants: &[MuxGrant]) -> Vec<MuxMember> {
        let mut out = Vec::new();
        for g in grants {
            if g.principal_hash != self.principal_hash {
                continue;
            }
            if let Some(m) = self.members.get(&g.did_hash)
                && m.source
                    == (MuxSource::Grant {
                        grant_id: g.grant_id.clone(),
                    })
                && let Some(m) = self.members.remove(&g.did_hash)
            {
                out.push(m);
            }
        }
        out
    }

    /// Apply a narrowed grant to the member it admitted: its scope and expiry
    /// shrink now, not at the next reconnect.
    pub fn narrow(&mut self, grant: &MuxGrant) {
        if let Some(m) = self.members.get_mut(&grant.did_hash)
            && m.source
                == (MuxSource::Grant {
                    grant_id: grant.grant_id.clone(),
                })
        {
            m.scope = grant.effective_scope().clone();
            m.expires_at = m.expires_at.min(grant.effective_exp());
        }
    }

    /// Remove members whose admission has lapsed at `now`.
    pub fn expire(&mut self, now: u64) -> Vec<MuxMember> {
        let gone: Vec<String> = self
            .members
            .values()
            .filter(|m| m.expires_at <= now)
            .map(|m| m.did_hash.clone())
            .collect();
        gone.iter().filter_map(|h| self.members.remove(h)).collect()
    }
}

/// What an attach statement must be bound to.
#[derive(Clone, Debug)]
pub struct AttachIdent {
    pub principal_did: String,
    pub session_id: String,
    pub nonce: String,
}

/// Verify an attach statement for the connection `ident`, check the member's
/// standing, and apply the unknown-key rule. Returns the member to admit and
/// any grants the rule suspended. Holds no lock.
pub async fn verify_attach(
    ctx: &Ctx<'_>,
    ident: &AttachIdent,
    raw: &Value,
    max_attach_lifetime_secs: u64,
) -> Result<(MuxMember, Vec<MuxGrant>), MuxError> {
    let verified = ctx
        .verifier
        .verify_attach(
            raw,
            &ident.session_id,
            &ident.nonce,
            Expect {
                mediator_did: ctx.mediator_did,
                principal: Some(&ident.principal_did),
                now: ctx.now,
                max_lifetime_secs: max_attach_lifetime_secs,
            },
        )
        .await?;
    member_standing(ctx, &verified.did_hash, &verified.scope).await?;
    let suspended =
        super::grants::suspend_unless_known_kid(ctx, &verified.did_hash, &verified.key.kid).await?;
    Ok((
        MuxMember {
            did: verified.did,
            did_hash: verified.did_hash,
            source: MuxSource::Attach,
            scope: verified.scope,
            kid: verified.key.kid,
            key_fp: verified.key.key_fp,
            expires_at: verified.exp,
        },
        suspended,
    ))
}

/// The member must have an account, not be blocked, and its own ACLs must
/// allow every capability the scope asks for (§5.5).
async fn member_standing(
    ctx: &Ctx<'_>,
    member_hash: &str,
    scope: &MuxScope,
) -> Result<(), MuxError> {
    if !ctx
        .store
        .account_exists(member_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
    {
        return Err(MuxError::UnknownMember);
    }
    let acls = ctx
        .store
        .get_did_acl(member_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
        .unwrap_or_else(|| ctx.default_acl.clone());
    check_scope(&acls, scope)
}

/// One DID admitted twice (attach and grant): the union of scope, the later
/// expiry, and the grant as the source (it outlives the connection).
fn merge(a: MuxMember, b: MuxMember) -> MuxMember {
    let scope = MuxScope::new(a.scope.iter().chain(b.scope.iter())).expect("non-empty union");
    let (keep, _) = match (&a.source, &b.source) {
        (MuxSource::Grant { .. }, _) => (a.clone(), b.clone()),
        _ => (b.clone(), a.clone()),
    };
    MuxMember {
        scope,
        expires_at: a.expires_at.max(b.expires_at),
        ..keep
    }
}

#[cfg(test)]
mod nonce_tests {
    /// The `ready` event's `muxNonce` must match the spec's `MuxNonce`
    /// (`^[A-Za-z0-9_-]{43}$`), or a client parsing the event with the
    /// generated types refuses it.
    #[test]
    fn the_nonce_matches_the_spec_pattern() {
        for _ in 0..64 {
            let n = super::new_nonce();
            assert_eq!(n.len(), 43, "{n}");
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{n}"
            );
        }
        assert_ne!(super::new_nonce(), super::new_nonce());
    }
}

#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::mux::grants::store_grant;
    use crate::mux::proof::StatementVerifier;
    use crate::store::MemoryStore;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_messaging_mediator_common::store::{MediatorStore, mux::MuxLimits};
    use affinidi_messaging_mediator_common::types::acls::MediatorACLSet;
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

    async fn verifier() -> StatementVerifier {
        StatementVerifier::new(
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap(),
        )
    }

    async fn signed(body: Value, secret: &Secret) -> Value {
        sign_trust_task(&body, secret, SignOptions::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn attach_grants_and_scope_checks() {
        let store = MemoryStore::new();
        let v = verifier().await;
        let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let ctx = Ctx {
            store: &store,
            verifier: &v,
            mediator_did: MEDIATOR,
            limits: MuxLimits::default(),
            default_acl: &acl,
            now: NOW,
        };
        let (principal, _) = did_key(31);
        let (alice, alice_key) = did_key(32);
        let (bob, bob_key) = did_key(33);
        for d in [&alice, &bob] {
            store.account_add(&did_hash(d), &acl, None).await.unwrap();
        }

        // Bob grants the principal; it is admitted on connect.
        let g = signed(
            json!({"type": "muxGrant", "issuer": bob, "audience": MEDIATOR, "grantId": "g-bob",
                   "principal": principal, "scope": ["receive", "pickup"], "epoch": 0,
                   "iat": NOW, "exp": NOW + 3600}),
            &bob_key,
        )
        .await;
        store_grant(&ctx, &bob, &g).await.unwrap();

        let mut session = MuxSession::new(&principal, "sess-1", 10);
        let (admitted, refused) = session.load_grants(&ctx).await.unwrap();
        assert_eq!(admitted.len(), 1);
        assert!(refused.is_empty());
        assert!(session.allows(&did_hash(&bob), MuxCapability::Pickup, NOW));
        assert!(!session.allows(&did_hash(&bob), MuxCapability::Delete, NOW));

        // Alice attaches for this connection only; a nonce from another
        // connection is refused.
        let body = |nonce: &str| {
            json!({"type": "muxAttach", "issuer": alice, "audience": MEDIATOR,
                   "principal": principal, "sessionId": "sess-1", "muxNonce": nonce,
                   "scope": ["receive", "delete"], "iat": NOW, "exp": NOW + 600})
        };
        let stale = signed(body("not-this-connection"), &alice_key).await;
        assert_eq!(
            session
                .attach(&ctx, &stale, 86_400)
                .await
                .unwrap_err()
                .code(),
            "sessionMismatch"
        );
        let good = signed(body(&session.nonce.clone()), &alice_key).await;
        let (m, suspended) = session.attach(&ctx, &good, 86_400).await.unwrap();
        assert!(suspended.is_empty());
        assert_eq!(m.source, MuxSource::Attach);
        assert_eq!(session.len(), 2);
        assert!(session.allows(&did_hash(&alice), MuxCapability::Delete, NOW));
        // Nobody else rides along.
        assert!(!session.allows(&did_hash(&principal), MuxCapability::Receive, NOW));

        // The attach lapses; the grant-admitted member stays.
        let gone = session.expire(NOW + 601);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].did, alice);
        assert!(session.get(&did_hash(&bob)).is_some());

        // Revoking Bob's grant detaches him.
        let revoked =
            crate::mux::grants::revoke_as_member(&ctx, &bob, std::slice::from_ref(&principal))
                .await
                .unwrap();
        assert_eq!(session.detach_grants(&revoked).len(), 1);
        assert!(session.is_empty());
    }

    #[tokio::test]
    async fn the_member_cap_is_enforced() {
        let store = MemoryStore::new();
        let v = verifier().await;
        let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let ctx = Ctx {
            store: &store,
            verifier: &v,
            mediator_did: MEDIATOR,
            limits: MuxLimits::default(),
            default_acl: &acl,
            now: NOW,
        };
        let (principal, _) = did_key(41);
        let mut session = MuxSession::new(&principal, "s", 1);
        for seed in [42u8, 43] {
            let (m, key) = did_key(seed);
            store.account_add(&did_hash(&m), &acl, None).await.unwrap();
            let raw = signed(
                json!({"type": "muxAttach", "issuer": m, "audience": MEDIATOR,
                       "principal": principal, "sessionId": "s", "muxNonce": session.nonce.clone(),
                       "scope": ["receive"], "iat": NOW, "exp": NOW + 60}),
                &key,
            )
            .await;
            let r = session.attach(&ctx, &raw, 86_400).await;
            if seed == 42 {
                r.unwrap();
            } else {
                assert_eq!(r.unwrap_err().code(), "memberQuota");
            }
        }
    }
}
