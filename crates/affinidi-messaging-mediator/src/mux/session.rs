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
    store::{
        MediatorStore,
        mux::{self, MuxCapability, MuxGrant, MuxScope},
    },
    types::acls::MediatorACLSet,
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

impl MuxSource {
    /// The `source` label on [`MUX_MEMBERS`](crate::common::metrics::names::MUX_MEMBERS).
    pub fn label(&self) -> &'static str {
        match self {
            MuxSource::Attach => "attach",
            MuxSource::Grant { .. } => "grant",
        }
    }
}

/// Move the member gauge for `source` (a [`MuxSource::label`]) by `delta`.
fn member_gauge(source: &'static str, delta: f64) {
    metrics::gauge!(crate::common::metrics::names::MUX_MEMBERS, "source" => source)
        .increment(delta);
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
    /// The admitting grant's `iat` (0 for an attach). The store keeps only a
    /// principal's newest grant on a DID, so a live admission never replaces
    /// a member carried by a newer grant, whatever order they finish in.
    pub grant_iat: u64,
    /// When a session attach admitted it (0 for one carried by a grant). A
    /// member's `revoke-all` ends the attaches admitted before it, and only
    /// those: one admitted afterwards rests on a statement made since.
    pub attached_at: u64,
}

/// A stored grant a connection did not carry, for its `detached` event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotCarried {
    pub did: String,
    pub grant_id: String,
    pub reason: LeaveReason,
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
    AccountRemoved,
    ResolutionFailed,
    /// The member DID's own direct socket, or a newer mux connection, took
    /// its live traffic; it stays on this connection, inactive.
    Superseded,
    /// Never joined: the grant is valid and stored, but the connection
    /// already carries `max_dids_per_connection` members.
    ConnectionFull,
    /// An operator acted: `messaging/mux/admin-revoke` or
    /// `admin-revoke-all`.
    Admin,
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
            LeaveReason::AccountRemoved => "accountRemoved",
            LeaveReason::ResolutionFailed => "resolutionFailed",
            LeaveReason::Superseded => "superseded",
            LeaveReason::ConnectionFull => "connectionFull",
            LeaveReason::Admin => "admin",
        }
    }

    /// Why the members admitted by `EpochRevoked` grant `g` left, from who
    /// voided it: `admin` for an administrator's `admin-revoke-all`,
    /// otherwise (the member's own `revoke-all`, or a record that predates
    /// [`MuxGrant::voided_by`](affinidi_messaging_mediator_common::store::mux::MuxGrant::voided_by))
    /// `epochBumped`.
    pub fn voided(g: &affinidi_messaging_mediator_common::store::mux::MuxGrant) -> Self {
        use affinidi_messaging_mediator_common::store::mux::MuxVoidedBy;
        match g.voided_by {
            Some(MuxVoidedBy::Admin) => LeaveReason::Admin,
            Some(MuxVoidedBy::Member | MuxVoidedBy::Unknown) | None => LeaveReason::EpochBumped,
        }
    }

    /// The reason a grant removal or epoch advance carried across instances
    /// ([`MuxChange::reason`](affinidi_messaging_mediator_common::store::mux::MuxChange::reason)),
    /// read back. Only the reasons that end a grant from outside the
    /// receiving connection are accepted; anything else is `None`, and the
    /// receiver keeps the reason the store implies.
    pub fn removal_from_wire(wire: &str) -> Option<Self> {
        [
            LeaveReason::RevokedByMember,
            LeaveReason::RevokedByPrincipal,
            LeaveReason::EpochBumped,
            LeaveReason::AccountRemoved,
            LeaveReason::Admin,
        ]
        .into_iter()
        .find(|r| r.wire() == wire)
    }

    /// Count `members` leaving (or never joining) for this reason, on
    /// [`MUX_DETACH_TOTAL`](crate::common::metrics::names::MUX_DETACH_TOTAL).
    pub fn count(self, members: usize) {
        if members > 0 {
            metrics::counter!(crate::common::metrics::names::MUX_DETACH_TOTAL, "reason" => self.wire())
                .increment(members as u64);
        }
    }
}

/// A connection's mux state.
///
/// The member map is changed only through `put` and `take` (and dropped with
/// the session), which keep the
/// [`MUX_MEMBERS`](crate::common::metrics::names::MUX_MEMBERS) gauge in step
/// with it: every way a member joins or leaves passes through them.
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

    /// Put `member` in the map, replacing any entry for its DID, and move the
    /// member gauge to match.
    fn put(&mut self, member: MuxMember) {
        let source = member.source.label();
        match self.members.insert(member.did_hash.clone(), member) {
            Some(old) if old.source.label() == source => {}
            Some(old) => {
                member_gauge(old.source.label(), -1.0);
                member_gauge(source, 1.0);
            }
            None => member_gauge(source, 1.0),
        }
    }

    /// Take `did_hash` out of the map, moving the member gauge to match.
    fn take(&mut self, did_hash: &str) -> Option<MuxMember> {
        let m = self.members.remove(did_hash)?;
        member_gauge(m.source.label(), -1.0);
        Some(m)
    }

    /// Take every member off: the connection is closing. No member is
    /// reported or counted as detached; the gauge moves.
    pub fn close(&mut self) -> Vec<MuxMember> {
        let hashes: Vec<String> = self.members.keys().cloned().collect();
        hashes.iter().filter_map(|h| self.take(h)).collect()
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
        let member = match self.members.get(&member.did_hash) {
            Some(existing) => merge(existing.clone(), member),
            None => member,
        };
        self.put(member.clone());
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
    /// admitted and the grants not carried, with why.
    ///
    /// Grants are validated before the connection's room is checked, so a
    /// grant reported `connectionFull` is a valid one. Which grants fill the
    /// connection follows the store's order, which is stable from one connect
    /// to the next.
    pub async fn load_grants(
        &mut self,
        ctx: &Ctx<'_>,
    ) -> Result<(Vec<MuxMember>, Vec<NotCarried>), MuxError> {
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
                let refuse = |reason| NotCarried {
                    did: grant.did.clone(),
                    grant_id: grant.grant_id.clone(),
                    reason,
                };
                match super::grants::key_is_current(ctx.verifier, &grant.kid, &grant.key_fp).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = super::grants::revalidate(ctx, &grant).await;
                        refused.push(refuse(LeaveReason::KeyRotated));
                        continue;
                    }
                    // Unknown is not "fine": the member is not carried until
                    // its key can be checked (fail closed, R5.3).
                    Err(_) => {
                        refused.push(refuse(LeaveReason::ResolutionFailed));
                        continue;
                    }
                }
                if member_standing(ctx, &grant.did_hash, grant.effective_scope())
                    .await
                    .is_err()
                {
                    refused.push(refuse(LeaveReason::AccountBlocked));
                    continue;
                }
                if !self.members.contains_key(&grant.did_hash)
                    && self.members.len() >= self.max_members
                {
                    refused.push(refuse(LeaveReason::ConnectionFull));
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
                    grant_iat: grant.iat,
                    attached_at: 0,
                };
                let member = match self.members.get(&grant.did_hash) {
                    Some(existing) => merge(existing.clone(), member),
                    None => member,
                };
                self.put(member.clone());
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
    /// already carried by an earlier grant takes the new one's identity,
    /// scope and expiry (it replaced the old), so a revoke of the new grant
    /// still finds it; one carried by a *newer* grant is left alone (this
    /// admission lost a race and is stale). One carried by an attach is
    /// merged, as on connect.
    ///
    /// Returns the member and whether it is new to the connection, or `None`
    /// when nothing changed.
    pub fn admit_grant(
        &mut self,
        member: MuxMember,
    ) -> Result<Option<(MuxMember, bool)>, MuxError> {
        let existing = self
            .members
            .get(&member.did_hash)
            .map(|m| (m.source.clone(), m.grant_iat));
        match existing {
            Some((MuxSource::Grant { .. }, iat)) if iat > member.grant_iat => Ok(None),
            // The same grant again (already carried): nothing changes.
            Some((source, _)) if source == member.source => Ok(None),
            Some((MuxSource::Grant { .. }, _)) => {
                self.put(member.clone());
                Ok(Some((member, false)))
            }
            Some((MuxSource::Attach, _)) => Ok(Some((self.admit(member)?, false))),
            None => Ok(Some((self.admit(member)?, true))),
        }
    }

    /// Remove a member. Returns it if it was on the connection.
    pub fn detach(&mut self, did_hash: &str) -> Option<MuxMember> {
        self.take(did_hash)
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
                && let Some(m) = self.take(&g.did_hash)
            {
                out.push(m);
            }
        }
        out
    }

    /// Apply a narrowed grant to the member it admitted: its scope and expiry
    /// shrink now, not at the next reconnect. Returns the member when its
    /// scope or expiry changed.
    pub fn narrow(&mut self, grant: &MuxGrant) -> Option<MuxMember> {
        let m = self.members.get_mut(&grant.did_hash)?;
        if m.source
            != (MuxSource::Grant {
                grant_id: grant.grant_id.clone(),
            })
        {
            return None;
        }
        let scope = grant.effective_scope().clone();
        let expires_at = m.expires_at.min(grant.effective_exp());
        if m.scope == scope && m.expires_at == expires_at {
            return None;
        }
        m.scope = scope;
        m.expires_at = expires_at;
        Some(m.clone())
    }

    /// Remove members whose admission has lapsed at `now`.
    pub fn expire(&mut self, now: u64) -> Vec<MuxMember> {
        let gone: Vec<String> = self
            .members
            .values()
            .filter(|m| m.expires_at <= now)
            .map(|m| m.did_hash.clone())
            .collect();
        gone.iter().filter_map(|h| self.take(h)).collect()
    }
}

/// A session dropped with members still on it (a connection torn down
/// without [`MuxSession::close`], or one never published) takes them off the
/// gauge, so it never leaks.
impl Drop for MuxSession {
    fn drop(&mut self) {
        for m in self.members.values() {
            member_gauge(m.source.label(), -1.0);
        }
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
            grant_iat: 0,
            attached_at: ctx.now,
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
    standing(ctx.store, ctx.default_acl, member_hash, scope).await
}

/// `member_standing` against the store alone, for re-checking a member
/// already on a connection: at admission and again while it stays (the
/// periodic sweep, and each pickup or delete made for it).
pub async fn standing(
    store: &dyn MediatorStore,
    default_acl: &MediatorACLSet,
    member_hash: &str,
    scope: &MuxScope,
) -> Result<(), MuxError> {
    if !store
        .account_exists(member_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
    {
        return Err(MuxError::UnknownMember);
    }
    let acls = store
        .get_did_acl(member_hash)
        .await
        .map_err(|e| MuxError::Store(e.into()))?
        .unwrap_or_else(|| default_acl.clone());
    check_scope(&acls, scope)
}

/// Why a member whose standing check failed with `e` must leave, or `None`
/// when the check could not be made (a store failure): that is neither a
/// lapse nor a pass.
pub fn standing_leave_reason(e: &MuxError) -> Option<LeaveReason> {
    match e {
        MuxError::UnknownMember => Some(LeaveReason::AccountRemoved),
        MuxError::MemberBlocked | MuxError::ScopeExceedsAcl(_) => Some(LeaveReason::AccountBlocked),
        MuxError::Statement(_) | MuxError::Store(_) | MuxError::MemberQuota { .. } => None,
    }
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
        attached_at: a.attached_at.max(b.attached_at),
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

#[cfg(test)]
pub(crate) mod gauge_tests {
    use super::*;
    use crate::common::metrics::testing::{recorder, value};

    const GRANT: &str = "mux_members{source=\"grant\"}";
    const ATTACH: &str = "mux_members{source=\"attach\"}";

    pub(crate) fn member(did: &str, source: MuxSource, expires_at: u64) -> MuxMember {
        let grant_iat = match source {
            MuxSource::Grant { .. } => 1,
            MuxSource::Attach => 0,
        };
        MuxMember {
            did: did.into(),
            did_hash: did_hash(did),
            source,
            scope: MuxScope::new([MuxCapability::Receive]).unwrap(),
            kid: format!("{did}#key-1"),
            key_fp: "fp".into(),
            expires_at,
            grant_iat,
            attached_at: 0,
        }
    }

    fn grant(id: &str) -> MuxSource {
        MuxSource::Grant {
            grant_id: id.into(),
        }
    }

    /// The member gauge follows the member set through every way a member
    /// joins, changes source or leaves, and comes back to zero when the
    /// session ends with members still on it.
    #[test]
    fn the_member_gauge_follows_the_member_set() {
        let rec = recorder();
        let _local = metrics::set_default_local_recorder(&rec);
        let gauges = || (value(&rec, GRANT), value(&rec, ATTACH));

        let mut s = MuxSession::new("did:example:device", "sess", 10);
        s.admit(member("did:example:a", MuxSource::Attach, 100))
            .unwrap();
        s.admit(member("did:example:b", MuxSource::Attach, 100))
            .unwrap();
        assert_eq!(gauges(), (0.0, 2.0));

        // The same attach again: still one member.
        s.admit(member("did:example:a", MuxSource::Attach, 200))
            .unwrap();
        assert_eq!(gauges(), (0.0, 2.0));

        // A grant merged into an attach: the member counts as `grant` now.
        s.admit_grant(member("did:example:a", grant("g1"), 300))
            .unwrap();
        assert_eq!(gauges(), (1.0, 1.0));
        // A replacing grant: still one grant member.
        let mut newer = member("did:example:a", grant("g2"), 300);
        newer.grant_iat = 2;
        s.admit_grant(newer).unwrap();
        assert_eq!(gauges(), (1.0, 1.0));

        // A refused admission moves nothing.
        let mut full = MuxSession::new("did:example:other", "s2", 0);
        assert!(
            full.admit(member("did:example:c", MuxSource::Attach, 100))
                .is_err()
        );
        assert_eq!(gauges(), (1.0, 1.0));

        // Expiry, then a detach of one already gone.
        assert_eq!(s.expire(150).len(), 1);
        assert_eq!(gauges(), (1.0, 0.0));
        assert!(s.detach(&did_hash("did:example:b")).is_none());
        assert_eq!(gauges(), (1.0, 0.0));

        // Close, then drop: nothing left to count, never negative.
        s.admit(member("did:example:d", MuxSource::Attach, 400))
            .unwrap();
        assert_eq!(s.close().len(), 2);
        assert_eq!(gauges(), (0.0, 0.0));
        drop(s);
        assert_eq!(gauges(), (0.0, 0.0));

        // A session dropped with members on it gives them back.
        let mut s = MuxSession::new("did:example:device", "sess", 10);
        s.admit(member("did:example:e", grant("g3"), 400)).unwrap();
        s.admit(member("did:example:f", MuxSource::Attach, 400))
            .unwrap();
        assert_eq!(gauges(), (1.0, 1.0));
        drop(s);
        assert_eq!(gauges(), (0.0, 0.0));
    }

    /// Detach reasons are counted under the spec's wire names, and a count
    /// of none records nothing.
    #[test]
    fn detach_reasons_are_counted_by_wire_name() {
        let rec = recorder();
        let _local = metrics::set_default_local_recorder(&rec);
        LeaveReason::RevokedByMember.count(2);
        LeaveReason::Expired.count(0);
        assert_eq!(
            value(&rec, "mux_detach_total{reason=\"revokedByMember\"}"),
            2.0
        );
        assert!(!rec.handle().render().contains("reason=\"expired\""));
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

    /// The standing a member met at admission is checked again while it
    /// stays: a removed account, a blocked one, or ACLs that no longer cover
    /// the scope each give the reason it leaves; a store failure gives none.
    #[tokio::test]
    async fn a_members_standing_is_rechecked_against_the_store() {
        let store = MemoryStore::new();
        let allow = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let (member, _) = did_key(61);
        let h = did_hash(&member);
        let scope = MuxScope::new([MuxCapability::Receive]).unwrap();
        let reason = |r: Result<(), MuxError>| r.err().and_then(|e| standing_leave_reason(&e));

        // No account.
        assert_eq!(
            reason(standing(&store, &allow, &h, &scope).await),
            Some(LeaveReason::AccountRemoved)
        );
        store.account_add(&h, &allow, None).await.unwrap();
        assert!(standing(&store, &allow, &h, &scope).await.is_ok());

        // Blocked.
        let mut blocked = allow.clone();
        blocked.set_blocked(true);
        store.set_did_acl(&h, &blocked).await.unwrap();
        assert_eq!(
            reason(standing(&store, &allow, &h, &scope).await),
            Some(LeaveReason::AccountBlocked)
        );

        // Not blocked, but its ACLs no longer allow what the scope asks.
        let deny = MediatorACLSet::from_string_ruleset("DENY_ALL").unwrap();
        let mut narrowed = deny.clone();
        narrowed.set_blocked(false);
        store.set_did_acl(&h, &narrowed).await.unwrap();
        assert_eq!(
            reason(standing(&store, &allow, &h, &scope).await),
            Some(LeaveReason::AccountBlocked)
        );

        // Neither a lapse nor a pass.
        assert_eq!(
            standing_leave_reason(&MuxError::Store(
                affinidi_messaging_mediator_common::store::mux::MuxStoreError::Contended
            )),
            None
        );
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

    #[tokio::test]
    async fn a_valid_grant_with_no_room_is_reported_connection_full() {
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
        let (principal, _) = did_key(51);
        let mut members = Vec::new();
        for (seed, id) in [(52u8, "g-a"), (53, "g-b")] {
            let (m, key) = did_key(seed);
            store.account_add(&did_hash(&m), &acl, None).await.unwrap();
            let g = signed(
                json!({"type": "muxGrant", "issuer": m, "audience": MEDIATOR, "grantId": id,
                       "principal": principal, "scope": ["receive"], "epoch": 0,
                       "iat": NOW, "exp": NOW + 3600}),
                &key,
            )
            .await;
            store_grant(&ctx, &m, &g).await.unwrap();
            members.push((m, id));
        }

        let mut session = MuxSession::new(&principal, "s", 1);
        let (admitted, refused) = session.load_grants(&ctx).await.unwrap();
        assert_eq!(admitted.len(), 1);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].reason, LeaveReason::ConnectionFull);
        assert_eq!(refused[0].reason.wire(), "connectionFull");
        // The one left out is the other grant, named with its id.
        let carried = &admitted[0].did;
        let (did, id) = members.iter().find(|(m, _)| m != carried).unwrap();
        assert_eq!(&refused[0].did, did);
        assert_eq!(refused[0].grant_id, *id);

        // The same grants fill the connection on the next connect.
        let mut again = MuxSession::new(&principal, "s2", 1);
        let (admitted2, _) = again.load_grants(&ctx).await.unwrap();
        assert_eq!(&admitted2[0].did, carried);
    }
}
