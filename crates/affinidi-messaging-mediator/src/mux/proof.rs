//! Verifying the signed statements DID multiplexing rests on.
//!
//! A member DID proves it allows a principal to carry its traffic with a
//! **statement**: a JSON object whose `issuer` is the member DID, carrying an
//! embedded W3C Data Integrity `proof`. It is the same proof format, and the
//! same [`Verifier`], that Trust Tasks use, so there is one signature path to
//! get right and clients sign with the `sign_trust_task` they already have.
//!
//! Two kinds (design §4.3, §4.4):
//!
//! - **`MuxGrant`** — stored; survives reconnects until it expires or is
//!   revoked.
//! - **`MuxAttach`** — bound to one connection (`sessionId` + `muxNonce`) and
//!   gone when it closes.
//!
//! [`StatementVerifier::verify_grant`] and
//! [`StatementVerifier::verify_attach`] apply the checks in the order the design fixes
//! (verify → key state → binding → time), and the store rules
//! (`affinidi_messaging_mediator_common::store::mux`) run after it. Scope
//! against the member's ACLs and account standing is the caller's, because it
//! needs the account.

use std::sync::Arc;

use affinidi_data_integrity::VerifyOptions;
use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::did_identity::did_hash;
use affinidi_messaging_mediator_common::store::mux::{MuxGrant, MuxGrantState, MuxScope};
use serde::Deserialize;
use serde_json::Value;
use trust_tasks_proof::affinidi::{
    CachedDidResolver, ProofPurpose, ProofPurposeResolver, Verifier,
};

/// How far in the future a statement's `iat` may be, for clock skew.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Why a statement was refused. Each variant is one stable wire code
/// (`messaging/mux/*:<code>`), so a client can tell a clock problem from a
/// signing problem without parsing prose (R3.7).
#[derive(Debug, PartialEq, Eq)]
pub enum StatementError {
    Malformed(String),
    WrongType {
        expected: &'static str,
        found: String,
    },
    ProofPurposeInvalid,
    ProofInvalid(String),
    AudienceMismatch,
    PrincipalMismatch,
    SessionMismatch,
    NotYetValid,
    Expired,
    LifetimeTooLong {
        requested: u64,
        max: u64,
    },
    /// The member DID could not be resolved now.
    DidUnresolvable(String),
}

impl std::fmt::Display for StatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "statement is malformed: {why}"),
            Self::WrongType { expected, found } => {
                write!(f, "statement type is {found:?}, expected {expected:?}")
            }
            Self::ProofPurposeInvalid => f.write_str("proofPurpose must be \"authentication\""),
            Self::ProofInvalid(why) => write!(f, "proof does not verify: {why}"),
            Self::AudienceMismatch => f.write_str("statement is addressed to another mediator"),
            Self::PrincipalMismatch => {
                f.write_str("statement names a different principal than this connection's")
            }
            Self::SessionMismatch => f.write_str("statement is bound to a different connection"),
            Self::NotYetValid => f.write_str("statement is not valid yet (iat is in the future)"),
            Self::Expired => f.write_str("statement has expired"),
            Self::LifetimeTooLong { requested, max } => write!(
                f,
                "statement lifetime {requested}s exceeds the maximum of {max}s"
            ),
            Self::DidUnresolvable(why) => write!(f, "member DID could not be resolved: {why}"),
        }
    }
}

impl std::error::Error for StatementError {}

impl StatementError {
    /// The code after `messaging/mux/<task>:`.
    pub fn code(&self) -> &'static str {
        match self {
            StatementError::Malformed(_) | StatementError::WrongType { .. } => "malformedRequest",
            StatementError::ProofPurposeInvalid => "proofPurposeInvalid",
            StatementError::ProofInvalid(_) => "statementProofInvalid",
            StatementError::AudienceMismatch => "audienceMismatch",
            StatementError::PrincipalMismatch => "principalMismatch",
            StatementError::SessionMismatch => "sessionMismatch",
            StatementError::NotYetValid => "notYetValid",
            StatementError::Expired => "statementExpired",
            StatementError::LifetimeTooLong { .. } => "lifetimeTooLong",
            StatementError::DidUnresolvable(_) => "didUnresolvable",
        }
    }
}

/// `MuxGrant` statement body (design §4.4). Closed: an unknown member in a
/// statement that grants access is refused, never ignored (R3.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantStatement {
    #[serde(rename = "type")]
    kind: String,
    issuer: String,
    audience: String,
    grant_id: String,
    principal: String,
    scope: MuxScope,
    epoch: u64,
    iat: u64,
    exp: u64,
    #[allow(dead_code)] // verified by `Verifier`, kept only for the shape check
    proof: Value,
}

/// `MuxAttach` statement body (design §4.3).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachStatement {
    #[serde(rename = "type")]
    kind: String,
    issuer: String,
    audience: String,
    principal: String,
    session_id: String,
    mux_nonce: String,
    scope: MuxScope,
    iat: u64,
    exp: u64,
    #[allow(dead_code)]
    proof: Value,
}

/// `muxRevokeAll` statement body: the member voids every grant issued under
/// `epoch` (design §5.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokeAllStatement {
    #[serde(rename = "type")]
    kind: String,
    issuer: String,
    audience: String,
    epoch: u64,
    iat: u64,
    exp: u64,
    #[allow(dead_code)]
    proof: Value,
}

/// A verified revoke-all: who, and which epoch they void.
#[derive(Clone, Debug)]
pub struct VerifiedRevokeAll {
    pub did: String,
    pub did_hash: String,
    pub epoch: u64,
    pub key: SigningKey,
}

/// The `proof` member, as far as this module needs to read it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofHead {
    proof_purpose: String,
    verification_method: String,
}

/// What a statement must be bound to.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    pub mediator_did: &'a str,
    /// The DID authenticated on the connection presenting the statement. For a
    /// grant this is checked only when the principal itself presents it; a
    /// member presenting its own grant passes `None`.
    pub principal: Option<&'a str>,
    pub now: u64,
    pub max_lifetime_secs: u64,
}

/// A verified statement's signing key, as resolved now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    /// The verification method that signed (the proof's `verificationMethod`).
    pub kid: String,
    /// `sha256` hex of the public key bytes.
    pub key_fp: String,
}

/// A verified session attach.
#[derive(Clone, Debug)]
pub struct VerifiedAttach {
    pub did: String,
    pub did_hash: String,
    pub scope: MuxScope,
    pub exp: u64,
    pub key: SigningKey,
}

/// Verifies mux statements against members' current DID documents.
#[derive(Clone)]
pub struct StatementVerifier {
    resolver: Arc<CachedDidResolver>,
    verifier: Arc<Verifier>,
}

impl StatementVerifier {
    pub fn new(resolver: DIDCacheClient) -> Self {
        let resolver = Arc::new(CachedDidResolver::new(Arc::new(resolver)));
        let verifier = Verifier::with_resolver(resolver.clone()).with_options(
            VerifyOptions::new()
                // JCS only: mux statements carry no `@context`, so RDF
                // canonicalisation (eddsa-rdfc-2022) cannot apply to them.
                .with_allowed_suites(vec![CryptoSuite::EddsaJcs2022]),
        );
        Self {
            resolver,
            verifier: Arc::new(verifier),
        }
    }

    /// Verify a `MuxGrant` statement and build the grant to store. The grant
    /// is returned `Active`; the store decides whether it may be stored.
    pub async fn verify_grant(
        &self,
        raw: &Value,
        expect: Expect<'_>,
    ) -> Result<MuxGrant, StatementError> {
        let st: GrantStatement = parse(raw)?;
        check_type(&st.kind, "muxGrant")?;
        let key = self.verify_signature(raw).await?;
        if st.audience != expect.mediator_did {
            return Err(StatementError::AudienceMismatch);
        }
        if let Some(p) = expect.principal
            && st.principal != p
        {
            return Err(StatementError::PrincipalMismatch);
        }
        check_times(st.iat, st.exp, &expect)?;
        // The member's key-agreement keys now, the known keys a later direct
        // DIDComm authentication is compared with (the unknown-key rule). A
        // grant whose keys cannot be read is refused, not stored without
        // them: an empty set means the DID listed none.
        let key_agreement_fps = self
            .key_agreement_fps(&st.issuer)
            .await
            .map_err(StatementError::DidUnresolvable)?;

        Ok(MuxGrant {
            grant_id: st.grant_id,
            did_hash: did_hash(&st.issuer),
            did: st.issuer,
            principal_hash: did_hash(&st.principal),
            principal: st.principal,
            kid: key.kid,
            key_fp: key.key_fp,
            did_version: None,
            epoch: st.epoch,
            scope: st.scope,
            iat: st.iat,
            exp: st.exp,
            narrowed_scope: None,
            narrowed_exp: None,
            state: MuxGrantState::Active,
            state_changed_at: None,
            statement: raw.clone(),
            noticed: false,
            key_agreement_fps,
            expiring_noticed: false,
        })
    }

    /// Verify a `MuxAttach` statement for the connection `session_id` /
    /// `mux_nonce`, whose authenticated principal is `expect.principal`.
    pub async fn verify_attach(
        &self,
        raw: &Value,
        session_id: &str,
        mux_nonce: &str,
        expect: Expect<'_>,
    ) -> Result<VerifiedAttach, StatementError> {
        let st: AttachStatement = parse(raw)?;
        check_type(&st.kind, "muxAttach")?;
        let key = self.verify_signature(raw).await?;
        if st.audience != expect.mediator_did {
            return Err(StatementError::AudienceMismatch);
        }
        if expect.principal != Some(st.principal.as_str()) {
            return Err(StatementError::PrincipalMismatch);
        }
        if st.session_id != session_id || st.mux_nonce != mux_nonce {
            return Err(StatementError::SessionMismatch);
        }
        check_times(st.iat, st.exp, &expect)?;
        Ok(VerifiedAttach {
            did_hash: did_hash(&st.issuer),
            did: st.issuer,
            scope: st.scope,
            exp: st.exp,
            key,
        })
    }

    /// Verify a `muxRevokeAll` statement.
    pub async fn verify_revoke_all(
        &self,
        raw: &Value,
        expect: Expect<'_>,
    ) -> Result<VerifiedRevokeAll, StatementError> {
        let st: RevokeAllStatement = parse(raw)?;
        check_type(&st.kind, "muxRevokeAll")?;
        let key = self.verify_signature(raw).await?;
        if st.audience != expect.mediator_did {
            return Err(StatementError::AudienceMismatch);
        }
        check_times(st.iat, st.exp, &expect)?;
        Ok(VerifiedRevokeAll {
            did_hash: did_hash(&st.issuer),
            did: st.issuer,
            epoch: st.epoch,
            key,
        })
    }

    /// Whether `kid` is still an authentication key of its DID with the same
    /// public key it had when the grant was stored (design §5.1). `Ok(false)`
    /// means stale; `Err` means it could not be determined (resolver down),
    /// which the caller must not treat as stale *or* as fine.
    pub async fn key_is_current(&self, kid: &str, key_fp: &str) -> Result<bool, String> {
        // Resolve the DID first, on its own: failing *that* is "could not
        // find out". Once the document is in hand (and cached), any refusal
        // of the method is about the document — not listed, not controlled,
        // undecodable — which is exactly what stale means.
        let did = kid.split('#').next().unwrap_or(kid);
        self.resolver
            .client()
            .resolve(did)
            .await
            .map_err(|e| format!("resolve {did}: {e}"))?;
        Ok(
            match self
                .resolver
                .resolve_vm_for_purpose(kid, ProofPurpose::Authentication)
                .await
            {
                Ok(key) => fingerprint(&key.public_key_bytes) == key_fp,
                Err(_) => false,
            },
        )
    }

    /// Fingerprints of `did`'s `keyAgreement` keys as resolved now; empty
    /// when it lists none. `Err` when the DID cannot be resolved, which is
    /// not the same as listing none.
    pub async fn key_agreement_fps(&self, did: &str) -> Result<Vec<String>, String> {
        let resolved = self
            .resolver
            .client()
            .resolve(did)
            .await
            .map_err(|e| format!("resolve {did}: {e}"))?;
        let doc = &resolved.doc;
        Ok(doc
            .key_agreement
            .iter()
            .filter_map(|r| key_agreement_method(doc, r))
            .filter_map(|m| m.decode_public_key().ok())
            .map(|(_, bytes)| fingerprint(&bytes))
            .collect())
    }

    /// The fingerprint of the `keyAgreement` key `kid` (an authcrypt sender
    /// key), as resolved now. `Err` when it cannot be determined: the DID does
    /// not resolve, or `kid` is not one of its key-agreement keys.
    pub async fn key_agreement_fp(&self, kid: &str) -> Result<String, String> {
        let (did, fragment) = kid
            .split_once('#')
            .ok_or_else(|| format!("{kid} has no fragment"))?;
        let resolved = self
            .resolver
            .client()
            .resolve(did)
            .await
            .map_err(|e| format!("resolve {did}: {e}"))?;
        let doc = &resolved.doc;
        let method = doc
            .key_agreement
            .iter()
            .filter_map(|r| key_agreement_method(doc, r))
            .find(|m| fragment_of(m.id.as_str()) == Some(fragment))
            .ok_or_else(|| format!("{kid} is not a keyAgreement key of {did}"))?;
        let (_, bytes) = method
            .decode_public_key()
            .map_err(|e| format!("decode {kid}: {e}"))?;
        Ok(fingerprint(&bytes))
    }

    /// Signature, issuer binding and current-authentication-key checks, plus
    /// the resolved key for later re-validation.
    async fn verify_signature(&self, raw: &Value) -> Result<SigningKey, StatementError> {
        let head: ProofHead = raw
            .get("proof")
            .cloned()
            .ok_or_else(|| StatementError::Malformed("no proof".into()))
            .and_then(|p| {
                serde_json::from_value(p)
                    .map_err(|e| StatementError::Malformed(format!("proof: {e}")))
            })?;
        // Mux statements authorise a principal *as* the member, so only an
        // authentication key may sign one, never an assertion key.
        if head.proof_purpose != ProofPurpose::Authentication.as_str() {
            return Err(StatementError::ProofPurposeInvalid);
        }
        self.verifier
            .verify_raw(raw)
            .await
            .map_err(|e| StatementError::ProofInvalid(e.to_string()))?;
        let key = self
            .resolver
            .resolve_vm_for_purpose(&head.verification_method, ProofPurpose::Authentication)
            .await
            .map_err(|e| StatementError::ProofInvalid(e.to_string()))?;
        Ok(SigningKey {
            kid: head.verification_method,
            key_fp: fingerprint(&key.public_key_bytes),
        })
    }
}

fn parse<T: serde::de::DeserializeOwned>(raw: &Value) -> Result<T, StatementError> {
    serde_json::from_value(raw.clone()).map_err(|e| StatementError::Malformed(e.to_string()))
}

fn check_type(found: &str, expected: &'static str) -> Result<(), StatementError> {
    if found == expected {
        Ok(())
    } else {
        Err(StatementError::WrongType {
            expected,
            found: found.to_string(),
        })
    }
}

fn check_times(iat: u64, exp: u64, expect: &Expect<'_>) -> Result<(), StatementError> {
    if iat > expect.now + MAX_CLOCK_SKEW_SECS {
        return Err(StatementError::NotYetValid);
    }
    if exp <= expect.now {
        return Err(StatementError::Expired);
    }
    let lifetime = exp.saturating_sub(iat);
    if lifetime > expect.max_lifetime_secs {
        return Err(StatementError::LifetimeTooLong {
            requested: lifetime,
            max: expect.max_lifetime_secs,
        });
    }
    Ok(())
}

/// The fingerprint every mux key comparison uses: SHA-256 of the raw public
/// key bytes.
pub fn fingerprint(public_key: &[u8]) -> String {
    sha256::digest(public_key)
}

fn fragment_of(id: &str) -> Option<&str> {
    id.split_once('#').map(|(_, f)| f)
}

/// The method a `keyAgreement` entry names: embedded, or a reference to the
/// document's `verificationMethod` set (absolute or `#fragment`).
fn key_agreement_method(
    doc: &affinidi_did_common::Document,
    r: &affinidi_did_common::verification_method::VerificationRelationship,
) -> Option<affinidi_did_common::verification_method::VerificationMethod> {
    use affinidi_did_common::verification_method::VerificationRelationship as R;
    match r {
        R::VerificationMethod(m) => Some((**m).clone()),
        R::Reference(id) => {
            let fragment = fragment_of(id)?;
            doc.verification_method
                .iter()
                .find(|m| fragment_of(m.id.as_str()) == Some(fragment))
                .cloned()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    const MEDIATOR: &str = "did:web:mediator.example";
    const PRINCIPAL: &str = "did:example:principal";
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
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        StatementVerifier::new(client)
    }

    fn expect(principal: Option<&str>) -> Expect<'_> {
        Expect {
            mediator_did: MEDIATOR,
            principal,
            now: NOW,
            max_lifetime_secs: 30 * 24 * 3600,
        }
    }

    fn grant_body(member: &str) -> Value {
        json!({
            "type": "muxGrant",
            "issuer": member,
            "audience": MEDIATOR,
            "grantId": "g-1",
            "principal": PRINCIPAL,
            "scope": ["receive", "pickup"],
            "epoch": 0,
            "iat": NOW,
            "exp": NOW + 3600,
        })
    }

    async fn sign(body: &Value, secret: &Secret, purpose: Option<&str>) -> Value {
        let mut opts = SignOptions::new();
        if let Some(p) = purpose {
            opts = opts.with_proof_purpose(p);
        }
        sign_trust_task(body, secret, opts).await.unwrap()
    }

    #[tokio::test]
    async fn a_signed_grant_verifies_and_carries_its_key() {
        let (member, secret) = did_key(1);
        let raw = sign(&grant_body(&member), &secret, None).await;
        let g = verifier()
            .await
            .verify_grant(&raw, expect(Some(PRINCIPAL)))
            .await
            .unwrap();
        assert_eq!(g.did, member);
        assert_eq!(g.did_hash, did_hash(&member));
        assert_eq!(g.principal_hash, did_hash(PRINCIPAL));
        assert!(g.kid.starts_with(&member));
        assert_eq!(g.key_fp.len(), 64);
        assert!(g.scope.contains(MuxCapability::Pickup));
        assert_eq!(g.statement, raw);
    }

    /// A TSP authentication proves the raw Ed25519 key; a grant records the
    /// fingerprint of the same key resolved for its proof. They must agree,
    /// or every TSP login would look like an unknown key.
    #[tokio::test]
    async fn a_grant_key_fingerprint_is_the_raw_public_key_digest() {
        let (did, secret) = did_key(9);
        let v = verifier().await;
        let g = v
            .verify_grant(&sign(&grant_body(&did), &secret, None).await, expect(None))
            .await
            .unwrap();
        assert_eq!(g.key_fp, fingerprint(secret.get_public_bytes()));
    }

    #[tokio::test]
    async fn tampering_with_a_signed_grant_breaks_it() {
        let (member, secret) = did_key(2);
        let mut raw = sign(&grant_body(&member), &secret, None).await;
        raw["scope"] = json!(["receive", "pickup", "send"]);
        let err = verifier()
            .await
            .verify_grant(&raw, expect(Some(PRINCIPAL)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "statementProofInvalid");
    }

    #[tokio::test]
    async fn a_grant_signed_by_someone_else_is_refused() {
        let (member, _) = did_key(3);
        let (_, other_secret) = did_key(4);
        // Signed by another key but claiming the member as issuer: the signer
        // refuses to mint it, so forge the binding by signing as the other DID
        // and swapping the issuer afterwards.
        let (other, _) = did_key(4);
        let mut raw = sign(&grant_body(&other), &other_secret, None).await;
        raw["issuer"] = json!(member);
        let err = verifier()
            .await
            .verify_grant(&raw, expect(Some(PRINCIPAL)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "statementProofInvalid");
    }

    #[tokio::test]
    async fn only_an_authentication_proof_is_accepted() {
        let (member, secret) = did_key(5);
        let raw = sign(&grant_body(&member), &secret, Some("assertionMethod")).await;
        let err = verifier()
            .await
            .verify_grant(&raw, expect(Some(PRINCIPAL)))
            .await
            .unwrap_err();
        assert_eq!(err, StatementError::ProofPurposeInvalid);
    }

    #[tokio::test]
    async fn binding_and_time_checks() {
        let (member, secret) = did_key(6);
        let v = verifier().await;

        let mut body = grant_body(&member);
        body["audience"] = json!("did:web:other.example");
        let raw = sign(&body, &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(Some(PRINCIPAL)))
                .await
                .unwrap_err(),
            StatementError::AudienceMismatch
        );

        let raw = sign(&grant_body(&member), &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(Some("did:example:not-me")))
                .await
                .unwrap_err(),
            StatementError::PrincipalMismatch
        );
        // A member presenting its own grant does not bind the principal.
        v.verify_grant(&raw, expect(None)).await.unwrap();

        let mut body = grant_body(&member);
        body["iat"] = json!(NOW + MAX_CLOCK_SKEW_SECS + 1);
        body["exp"] = json!(NOW + 7200);
        let raw = sign(&body, &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(None)).await.unwrap_err(),
            StatementError::NotYetValid
        );

        let mut body = grant_body(&member);
        body["exp"] = json!(NOW);
        let raw = sign(&body, &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(None)).await.unwrap_err(),
            StatementError::Expired
        );
    }

    #[tokio::test]
    async fn unknown_members_and_empty_scope_are_refused() {
        let (member, secret) = did_key(7);
        let v = verifier().await;
        let mut body = grant_body(&member);
        body["extra"] = json!(true);
        let raw = sign(&body, &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(None)).await.unwrap_err().code(),
            "malformedRequest"
        );

        let mut body = grant_body(&member);
        body["scope"] = json!([]);
        let raw = sign(&body, &secret, None).await;
        assert_eq!(
            v.verify_grant(&raw, expect(None)).await.unwrap_err().code(),
            "malformedRequest"
        );
    }

    #[tokio::test]
    async fn an_attach_is_bound_to_its_connection() {
        let (member, secret) = did_key(8);
        let v = verifier().await;
        let body = json!({
            "type": "muxAttach",
            "issuer": member,
            "audience": MEDIATOR,
            "principal": PRINCIPAL,
            "sessionId": "sess-1",
            "muxNonce": "nonce-1",
            "scope": ["receive"],
            "iat": NOW,
            "exp": NOW + 600,
        });
        let raw = sign(&body, &secret, None).await;
        let a = v
            .verify_attach(&raw, "sess-1", "nonce-1", expect(Some(PRINCIPAL)))
            .await
            .unwrap();
        assert_eq!(a.did, member);
        assert_eq!(
            v.verify_attach(&raw, "sess-2", "nonce-1", expect(Some(PRINCIPAL)))
                .await
                .unwrap_err(),
            StatementError::SessionMismatch
        );
        assert_eq!(
            v.verify_attach(&raw, "sess-1", "nonce-2", expect(Some(PRINCIPAL)))
                .await
                .unwrap_err(),
            StatementError::SessionMismatch
        );
        // A grant is not an attach.
        let g = sign(&grant_body(&member), &secret, None).await;
        assert_eq!(
            v.verify_attach(&g, "sess-1", "nonce-1", expect(Some(PRINCIPAL)))
                .await
                .unwrap_err()
                .code(),
            "malformedRequest"
        );
    }

    #[tokio::test]
    async fn the_signing_key_is_current_until_it_changes() {
        let (member, secret) = did_key(9);
        let v = verifier().await;
        let raw = sign(&grant_body(&member), &secret, None).await;
        let g = v.verify_grant(&raw, expect(None)).await.unwrap();
        assert_eq!(v.key_is_current(&g.kid, &g.key_fp).await, Ok(true));
        assert_eq!(v.key_is_current(&g.kid, "0000").await, Ok(false));
    }
}
