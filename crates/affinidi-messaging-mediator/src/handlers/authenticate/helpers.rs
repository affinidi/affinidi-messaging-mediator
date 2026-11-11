use crate::SharedData;
use crate::common::authz::{self, Capability};
use crate::common::session::{SessionClaims, TokenUse};
// Production token creation now takes `now` from the injected clock; the only
// remaining caller of this helper is the test module below.
#[cfg(test)]
use crate::common::time::unix_timestamp_secs;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat::MetaEnvelope;
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use http::StatusCode;
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::{RngExt, distr::Alphanumeric};
use sha256::digest;
use tracing::{debug, info};

/// Unpack an authentication envelope and enforce the signed-AND-encrypted
/// invariant in a single place, shared by the `authenticate` response and
/// refresh handlers (the two previously carried byte-identical copies of
/// this block).
///
/// The caller builds the [`MetaEnvelope`] first (the two handlers use
/// different parse-error codes there, so that step stays handler-local) and
/// retains it for any post-unpack checks; this borrows it, so it remains
/// usable afterwards.
#[cfg(feature = "didcomm")]
pub(crate) async fn unpack_auth_message(
    envelope: &MetaEnvelope,
    state: &SharedData,
) -> Result<(Message, UnpackMetadata), MediatorError> {
    let (msg, unpack_metadata) = match envelope
        .unpack(
            &state.did_resolver,
            &*state.config.security.mediator_secrets,
        )
        .await
    {
        Ok(ok) => ok,
        Err(e) => {
            return Err(MediatorError::problem_with_log(
                32,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.unpack",
                "Failed to unpack message. Reason: {1}",
                vec![e.to_string()],
                StatusCode::FORBIDDEN,
                format!("Failed to unpack message. Reason: {e}"),
            ));
        }
    };

    // Authentication messages MUST be signed and authenticated!
    if unpack_metadata.authenticated && unpack_metadata.encrypted {
        debug!("Auth message verified: signed and encrypted")
    } else {
        return Err(MediatorError::problem_with_log(
            86,
            "",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.message.not_signed_or_encrypted",
            "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction",
            vec![
                unpack_metadata.authenticated.to_string(),
                unpack_metadata.encrypted.to_string(),
            ],
            StatusCode::BAD_REQUEST,
            format!(
                "DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction",
                unpack_metadata.authenticated, unpack_metadata.encrypted
            ),
        ));
    }

    Ok((msg, unpack_metadata))
}

/// creates a random string of up to length characters
pub fn create_random_string(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub(super) fn _create_access_token(
    did: &str,
    session_id: &str,
    expiry: u64,
    now: u64,
    encoding_key: &EncodingKey,
) -> Result<(String, u64), MediatorError> {
    // Passed all the checks, now create the JWT tokens
    let access_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: did.to_owned(),
        session_id: session_id.to_owned(),
        exp: (now + expiry),
        token_use: Some(TokenUse::Access),
        jti: None,
    };

    let access_token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &access_claims,
        encoding_key,
    )
    .map_err(|err| {
        MediatorError::problem_with_log(
            35,
            session_id.to_string(),
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.session.access_token",
            "Couldn't create JWT Access token. Reason: {1}",
            vec![err.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't create JWT Access token. Reason: {err}"),
        )
    })?;

    Ok((access_token, access_claims.exp))
}

/// Creates a JWT refresh token and returns the token string, expiry timestamp, and SHA-256 hash.
/// The hash is stored in Redis to enforce one-time use.
pub(super) fn _create_refresh_token(
    did: &str,
    session_id: &str,
    expiry: u64,
    now: u64,
    encoding_key: &EncodingKey,
) -> Result<(String, u64, String), MediatorError> {
    let refresh_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: did.to_owned(),
        session_id: session_id.to_owned(),
        exp: (now + expiry),
        token_use: Some(TokenUse::Refresh),
        // EdDSA signatures are deterministic, so without a unique claim two
        // refresh tokens issued for one session in the same second are the
        // same string, and rotating from one to the other would change
        // nothing. The `jti` makes every issued token, and so its stored
        // hash, distinct.
        jti: Some(create_random_string(22)),
    };

    let refresh_token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &refresh_claims,
        encoding_key,
    )
    .map_err(|err| {
        MediatorError::problem_with_log(
            36,
            session_id.to_string(),
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.session.refresh_token",
            "Couldn't create JWT Refresh token. Reason: {1}",
            vec![err.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't create JWT Refresh token. Reason: {err}"),
        )
    })?;

    let token_hash = digest(&refresh_token);

    Ok((refresh_token, refresh_claims.exp, token_hash))
}

/// Admit a DID that has just proved control of its keys, giving it an
/// account if it has none. Every login path (`/authenticate`,
/// `/tsp/authenticate`) calls this before issuing tokens.
///
/// `/authenticate/challenge` is unauthenticated, so it only applies the
/// admission checks and never writes an account; and the DID's standing can
/// change between the challenge and the answer, so it is checked again here.
///
/// - Registered and blocked: rejected.
/// - Registered: admitted.
/// - Unknown under `explicit_allow`: rejected. The challenge step already
///   refuses unknown DIDs in this mode, so reaching here means an admin
///   removed the account after the challenge was issued, which is a
///   revocation, not a reason to recreate it.
/// - Unknown under `explicit_deny`: registered with `global_acl_default`.
///
/// Every rejection is the `authentication.blocked` report the challenge step
/// uses, so the two steps cannot be told apart.
pub(super) async fn register_account_after_proof(
    state: &SharedData,
    did_hash: &str,
) -> Result<(), MediatorError> {
    let acls = if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow {
        match state.database.get_did_acl(did_hash).await? {
            Some(acls) => acls,
            None => {
                info!(
                    "DID({}) has no account and mediator_acl_mode is explicit_allow — rejecting",
                    did_hash
                );
                return Err(blocked());
            }
        }
    } else {
        // Create-if-absent in one atomic store step: an existing account —
        // including one an admin added or changed since the challenge — is
        // returned unchanged, and its ACLs are the ones checked below.
        let account = state
            .database
            .account_add(did_hash, &state.config.security.global_acl_default, None)
            .await?;
        MediatorACLSet::from_u64(account.acls)
    };

    if !authz::grants(&acls, Capability::NotBlocked) {
        info!("DID({}) is blocked from connecting", did_hash);
        return Err(blocked());
    }
    debug!("DID({}) admitted", did_hash);
    Ok(())
}

/// The `authentication.blocked` report, shared by every admission refusal.
fn blocked() -> MediatorError {
    MediatorError::problem(
        25,
        "",
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authentication.blocked",
        "DID is blocked",
        vec![],
        StatusCode::FORBIDDEN,
    )
}

/// The login could not apply the mux unknown-key rule; the client retries.
pub(super) fn mux_check_failed(e: String) -> MediatorError {
    MediatorError::problem_with_log(
        14,
        "",
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "me.res.storage.error",
        "Database transaction error: {1}",
        vec![e.clone()],
        StatusCode::SERVICE_UNAVAILABLE,
        format!("mux unknown-key rule not applied, login refused: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::session::SessionClaims;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Helper: generate an Ed25519 key pair and return (encoding_key, decoding_key).
    fn test_ed25519_keys() -> (EncodingKey, DecodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse pkcs8");

        let encoding_key = EncodingKey::from_ed_der(pkcs8.as_ref());
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());
        (encoding_key, decoding_key)
    }

    #[test]
    fn create_random_string_has_expected_length() {
        let s = create_random_string(32);
        assert_eq!(s.len(), 32);

        let s = create_random_string(64);
        assert_eq!(s.len(), 64);

        let s = create_random_string(0);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn create_random_string_produces_unique_values() {
        let a = create_random_string(32);
        let b = create_random_string(32);
        assert_ne!(a, b, "two random strings of length 32 should differ");
    }

    #[test]
    fn create_access_token_produces_valid_jwt() {
        let (encoding_key, decoding_key) = test_ed25519_keys();

        let (token, _exp) = _create_access_token(
            "did:example:123",
            "session-1",
            3600,
            unix_timestamp_secs(),
            &encoding_key,
        )
        .expect("should create access token");

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.sub = Some("did:example:123".to_string());

        let token_data =
            decode::<SessionClaims>(&token, &decoding_key, &validation).expect("should decode JWT");

        assert_eq!(token_data.claims.aud, "ATM");
        assert_eq!(token_data.claims.sub, "did:example:123");
        assert_eq!(token_data.claims.session_id, "session-1");
        assert_eq!(token_data.claims.token_use, Some(TokenUse::Access));
        assert_eq!(token_data.claims.jti, None);
    }

    #[test]
    fn create_access_token_sets_correct_expiry() {
        let (encoding_key, decoding_key) = test_ed25519_keys();
        let expiry_delta = 7200_u64;

        let now = unix_timestamp_secs();
        let (_token, exp) = _create_access_token(
            "did:example:456",
            "session-2",
            expiry_delta,
            now,
            &encoding_key,
        )
        .expect("should create access token");

        // The expiry is exactly the supplied `now` plus the delta.
        assert_eq!(exp, now + expiry_delta);

        // Also verify through the JWT claims
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.sub = Some("did:example:456".to_string());

        let token_data = decode::<SessionClaims>(&_token, &decoding_key, &validation)
            .expect("should decode JWT");
        assert_eq!(token_data.claims.exp, exp);
    }

    #[test]
    fn create_refresh_token_returns_token_expiry_and_hash() {
        let (encoding_key, _decoding_key) = test_ed25519_keys();

        let (token, exp, hash) = _create_refresh_token(
            "did:example:789",
            "session-3",
            3600,
            unix_timestamp_secs(),
            &encoding_key,
        )
        .expect("should create refresh token");

        assert!(!token.is_empty(), "token should not be empty");
        assert!(exp > 0, "expiry should be positive");
        assert!(!hash.is_empty(), "hash should not be empty");
    }

    #[test]
    fn refresh_tokens_issued_in_one_second_differ() {
        let (encoding_key, decoding_key) = test_ed25519_keys();
        let now = unix_timestamp_secs();
        let (a, _, hash_a) =
            _create_refresh_token("did:example:abc", "session-5", 3600, now, &encoding_key)
                .unwrap();
        let (b, _, hash_b) =
            _create_refresh_token("did:example:abc", "session-5", 3600, now, &encoding_key)
                .unwrap();
        assert_ne!(a, b);
        assert_ne!(hash_a, hash_b);

        // Still decodes as the session claims every reader expects.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        let claims = decode::<SessionClaims>(&a, &decoding_key, &validation)
            .unwrap()
            .claims;
        assert_eq!(claims.session_id, "session-5");
        assert_eq!(claims.sub, "did:example:abc");
        assert_eq!(claims.token_use, Some(TokenUse::Refresh));
        assert!(claims.jti.is_some());
    }

    #[test]
    fn create_refresh_token_hash_matches_sha256_of_token() {
        let (encoding_key, _decoding_key) = test_ed25519_keys();

        let (token, _exp, hash) = _create_refresh_token(
            "did:example:abc",
            "session-4",
            3600,
            unix_timestamp_secs(),
            &encoding_key,
        )
        .expect("should create refresh token");

        let expected_hash = digest(&token);
        assert_eq!(hash, expected_hash, "hash should be SHA-256 of the token");
    }
}
