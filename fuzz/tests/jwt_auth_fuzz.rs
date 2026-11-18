//! Technique 05 — JWT verification (`authenticate_token`) —
//! proptest + `#[tokio::test]` against the real `axum` router.
//!
//! ## Target
//! `authenticate_token`, `pub(crate) async fn`,
//! `crates/affinidi-messaging-mediator/src/common/jwt_auth.rs:151`.
//!
//! ## Real entry point (no `pub(crate)` reach-around)
//! `Session::from_request_parts` (`jwt_auth.rs:245-283`), the axum
//! extractor every authenticated REST route runs through, reached here via
//! `GET /mediator/v1/whoami` — the smallest authenticated route: it is
//! gated on nothing but `authenticate_token` itself (no further
//! `Capability` check, no body, no DB side effect beyond the session/ACL
//! read `authenticate_token` already performs). The mediator is spawned
//! via `affinidi_messaging_mediator::builder::MediatorBuilder` (the
//! crate's real, `pub`, production bootstrap — see `tests/common/mod.rs`),
//! bound to a real loopback TCP socket. Every request in this file is a
//! real HTTP request over that socket.
//!
//! ## Oracle
//! Tier 1 (no panic — any panic inside the handler surfaces as a `500`
//! from axum's `CatchPanic`-free default *or* a dropped connection; this
//! harness treats "request did not complete with some HTTP status" as a
//! Tier-1 violation) + Tier 4 (auth decision: no mutated/invalid token may
//! ever receive a non-401 "success-shaped" response; the one genuinely
//! valid baseline token must receive `200`).

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_mediator_common::types::acls::MediatorACLSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use proptest::prelude::*;
use serde::Serialize;
use serde_json::json;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Serialize)]
struct FullClaims {
    aud: String,
    sub: String,
    session_id: String,
    exp: u64,
}

/// Build a validly-signed EdDSA token from arbitrary claim values, using
/// our own `jsonwebtoken` instance and the fixture's real installed
/// signing key. Mutating the *claims* (rather than hand-splicing base64)
/// is the structured half of the fuzz strategy; `mutate_bytes` below
/// covers the unstructured half (bit flips / truncation / garbage).
fn sign(pkcs8: &[u8], aud: &str, sub: &str, session_id: &str, exp: u64) -> String {
    let key = EncodingKey::from_ed_der(pkcs8);
    encode(
        &Header::new(Algorithm::EdDSA),
        &FullClaims {
            aud: aud.to_string(),
            sub: sub.to_string(),
            session_id: session_id.to_string(),
            exp,
        },
        &key,
    )
    .expect("sign")
}

/// A `{"alg":"none"}` unsigned token — the canonical algorithm-confusion
/// attack. `jsonwebtoken::decode` is expected to reject it outright
/// because `clock_aware_validation()` fixes `algorithms = [EdDSA]`.
fn alg_none_token(aud: &str, sub: &str, session_id: &str, exp: u64) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64.encode(
        json!({"aud": aud, "sub": sub, "session_id": session_id, "exp": exp})
            .to_string()
            .as_bytes(),
    );
    format!("{header}.{payload}.")
}

/// An HS256-signed token using the mediator's own Ed25519 **public** key
/// bytes as the HMAC secret — the classic RS/ES-to-HS algorithm-confusion
/// attack, adapted for EdDSA. Expected to be rejected because the fixed
/// `algorithms = [EdDSA]` validation refuses the header's `HS256` before
/// any key material is even consulted.
fn alg_confusion_hs256_token(
    pub_key_bytes: &[u8],
    aud: &str,
    sub: &str,
    session_id: &str,
    exp: u64,
) -> String {
    let key = EncodingKey::from_secret(pub_key_bytes);
    encode(
        &Header::new(Algorithm::HS256),
        &FullClaims {
            aud: aud.to_string(),
            sub: sub.to_string(),
            session_id: session_id.to_string(),
            exp,
        },
        &key,
    )
    .expect("sign hs256")
}

/// `None` means the fuzzed token contains bytes that cannot even form a
/// valid HTTP header value (e.g. a raw NUL or control byte) — `reqwest`
/// (and every compliant HTTP client) refuses to construct the request, so
/// the bytes never reach the wire and the server's behaviour is not in
/// play. That is a client-library limitation, not a Tier-1 finding; such
/// cases are skipped rather than asserted on. Once a request IS actually
/// sent, any transport-level failure (connection reset, no response) is
/// treated as a potential server-side panic and surfaces loudly.
async fn whoami_status(base_url: &str, token: &str) -> Option<u16> {
    let header_value = match http::HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let url = format!("{base_url}whoami");
    match client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, header_value)
        .send()
        .await
    {
        Ok(resp) => Some(resp.status().as_u16()),
        // A transport-level failure *after* a byte-valid request was
        // actually written to the socket is the Tier-1 violation we're
        // watching for: a healthy server always answers with *some* HTTP
        // status, even for garbage auth input.
        Err(e) => panic!("request did not complete (possible server-side panic/crash): {e}"),
    }
}

/// Oversized bearer token, sent as a raw header value when it still forms
/// valid header bytes (ASCII, no control chars) — boundary-value class
/// ("A" × 65_535).
fn oversized_token() -> String {
    "A".repeat(65_535)
}

#[tokio::test]
async fn deterministic_boundary_matrix() {
    let fx = common::spawn().await;
    let did = "did:example:alice";
    let session_id = "fuzz-session-baseline";
    fx.register_session(
        did,
        session_id,
        MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap(),
        AccountType::Standard,
    )
    .await;

    let n = now();

    // 1. Genuinely valid baseline — MUST be 200. (Control: proves the
    //    fixture/harness itself is wired correctly; every other case in
    //    this matrix is a one-field mutation away from it.)
    let valid = sign(&fx.jwt_pkcs8, "ATM", did, session_id, n + 900);
    assert_eq!(
        whoami_status(&fx.base_url, &valid).await.unwrap(),
        200,
        "the one genuinely valid, freshly-signed token for a registered session must be accepted"
    );

    // 2. alg:none — classic algorithm-confusion attack. MUST be 401.
    let none_tok = alg_none_token("ATM", did, session_id, n + 900);
    assert_eq!(
        whoami_status(&fx.base_url, &none_tok).await.unwrap(),
        401,
        "alg:none token must never be accepted"
    );

    // 3. HS256-signed with the mediator's own Ed25519 public key bytes as
    //    the HMAC secret (RS/ES->HS confusion, adapted for EdDSA). MUST be 401.
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let keypair = Ed25519KeyPair::from_pkcs8(&fx.jwt_pkcs8).unwrap();
    let pubkey = keypair.public_key().as_ref();
    let hs_tok = alg_confusion_hs256_token(pubkey, "ATM", did, session_id, n + 900);
    assert_eq!(
        whoami_status(&fx.base_url, &hs_tok).await.unwrap(),
        401,
        "HS256-signed-with-public-key-bytes token must never be accepted"
    );

    // 4. Expired just beyond the 60s leeway. MUST be 401. (The clock only
    //    moves forward between minting and the server's check, so this
    //    cannot flake.)
    let expired = sign(&fx.jwt_pkcs8, "ATM", did, session_id, n.saturating_sub(61));
    assert_eq!(
        whoami_status(&fx.base_url, &expired).await.unwrap(),
        401,
        "a token expired beyond the leeway must be rejected"
    );

    // 5. Expired, but inside the leeway: still accepted over real HTTP. The
    //    exact inclusive boundary (exp + 60 == now) is pinned by the unit test
    //    `jwt_exp_uses_the_same_leeway_as_jsonwebtoken`; asserting it here
    //    would flake whenever the wall clock ticks between minting and the
    //    server's check, so this case keeps a few seconds of margin.
    let within_leeway = sign(&fx.jwt_pkcs8, "ATM", did, session_id, n.saturating_sub(55));
    assert_eq!(
        whoami_status(&fx.base_url, &within_leeway).await.unwrap(),
        200,
        "a token expired by less than the 60s leeway must still be accepted"
    );

    // 6. Wrong audience. MUST be 401 (decode-time required-claim check).
    let wrong_aud = sign(&fx.jwt_pkcs8, "NOT-ATM", did, session_id, n + 900);
    assert_eq!(whoami_status(&fx.base_url, &wrong_aud).await.unwrap(), 401);

    // 7. Unknown session_id (never stored) but otherwise validly signed.
    let unknown_session = sign(&fx.jwt_pkcs8, "ATM", did, "never-created-session", n + 900);
    let status = whoami_status(&fx.base_url, &unknown_session).await.unwrap();
    assert_ne!(
        status, 200,
        "an unknown session must never be treated as authenticated"
    );
    // A validly-signed token naming a session the store doesn't have is
    // 401 (unauthorized), not 500: the `get_session` `Err` path was once
    // mapped to `AuthError::InternalServerError`. Pinned so it can't regress.
    assert_eq!(
        status, 401,
        "an unknown-session JWT must map to 401 — a 500 here means the \
         status-code classification regressed"
    );

    // 8. sub/DID mismatch: valid session_id, but claims a different DID.
    let other_did = "did:example:mallory";
    let mismatched = sign(&fx.jwt_pkcs8, "ATM", other_did, session_id, n + 900);
    assert_eq!(
        whoami_status(&fx.base_url, &mismatched).await.unwrap(),
        401,
        "JWT sub not matching the session's stored DID must be rejected"
    );

    // 9. Blocked ACL with an otherwise perfectly valid token. MUST be 401.
    let blocked_did = "did:example:blocked";
    let blocked_session = "fuzz-session-blocked";
    let mut blocked_acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
    blocked_acls.set_blocked(true);
    fx.register_session(
        blocked_did,
        blocked_session,
        blocked_acls,
        AccountType::Standard,
    )
    .await;
    let blocked_tok = sign(&fx.jwt_pkcs8, "ATM", blocked_did, blocked_session, n + 900);
    assert_eq!(
        whoami_status(&fx.base_url, &blocked_tok).await.unwrap(),
        401
    );

    // 10. Oversized token (boundary-value class). Must not hang or
    //     crash the server; any terminal HTTP status is acceptable, 200 is not.
    let big = oversized_token();
    let status = whoami_status(&fx.base_url, &big).await.unwrap();
    assert_ne!(
        status, 200,
        "a 65KB garbage bearer token must never authenticate"
    );

    // 11. Empty bearer token.
    assert_ne!(whoami_status(&fx.base_url, "").await.unwrap(), 200);

    // 12. Single dot (malformed structure, 2 empty segments).
    assert_ne!(whoami_status(&fx.base_url, ".").await.unwrap(), 200);

    // 13. Only two segments (no signature at all).
    let no_sig = valid.rsplit_once('.').map(|(h, _)| h).unwrap().to_string();
    assert_ne!(whoami_status(&fx.base_url, &no_sig).await.unwrap(), 200);

    // 14. Bit-flip the last byte of a genuinely valid token's signature —
    //     tampered-signature class.
    let mut tampered = valid.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered = String::from_utf8_lossy(&tampered).to_string();
    assert_ne!(
        whoami_status(&fx.base_url, &tampered).await.unwrap(),
        200,
        "a single bit-flip in the signature must invalidate the token"
    );

    fx.shutdown();
}

/// One shared mediator + runtime per static, reused across every proptest
/// case in its property (spawning a fresh real TCP-bound mediator per
/// case would dominate wall-clock time with bootstrap cost rather than
/// actual fuzzing). The registered baseline session is fixed for the
/// property's lifetime; only the generated token varies.
static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"))
}

static CLAIM_FIXTURE: tokio::sync::OnceCell<(common::Fixture, &'static str, &'static str)> =
    tokio::sync::OnceCell::const_new();
async fn claim_fixture() -> &'static (common::Fixture, &'static str, &'static str) {
    CLAIM_FIXTURE
        .get_or_init(|| async {
            let fx = common::spawn().await;
            let did = "did:example:registered-user";
            let session_id = "registered-session";
            fx.register_session(
                did,
                session_id,
                MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap(),
                AccountType::Standard,
            )
            .await;
            (fx, did, session_id)
        })
        .await
}

static BYTE_FIXTURE: tokio::sync::OnceCell<(common::Fixture, String)> =
    tokio::sync::OnceCell::const_new();
async fn byte_fixture() -> &'static (common::Fixture, String) {
    BYTE_FIXTURE
        .get_or_init(|| async {
            let fx = common::spawn().await;
            let did = "did:example:registered-user-2";
            let session_id = "registered-session-2";
            fx.register_session(
                did,
                session_id,
                MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap(),
                AccountType::Standard,
            )
            .await;
            let valid = sign(&fx.jwt_pkcs8, "ATM", did, session_id, now() + 900);
            (fx, valid)
        })
        .await
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// Structured mutation: fuzz the *claim values* of an otherwise
    /// well-formed, validly-signed EdDSA token. None of these should ever
    /// authenticate as the registered baseline session unless the mutated
    /// claims happen to exactly reproduce it (aud="ATM", sub=the
    /// registered DID, session_id=the registered session, exp in the
    /// valid window).
    #[test]
    fn claim_mutation_never_bypasses_auth(
        aud in "[ -~]{0,40}",
        sub in "[ -~]{0,80}",
        session_id in "[ -~]{0,40}",
        exp_offset in -100_000_i64..100_000_i64,
    ) {
        rt().block_on(async {
            let (fx, did, session_id_baseline) = claim_fixture().await;
            let n = now() as i64;
            let exp = (n + exp_offset).max(0) as u64;
            let token = sign(&fx.jwt_pkcs8, &aud, &sub, &session_id, exp);

            let Some(status) = whoami_status(&fx.base_url, &token).await else {
                // Byte-invalid header value: never reached the wire, not in scope.
                return Ok(());
            };

            let is_exact_baseline_replay = aud == "ATM"
                && &sub == did
                && &session_id == session_id_baseline
                && exp >= n.max(0) as u64;

            if !is_exact_baseline_replay {
                prop_assert_ne!(
                    status,
                    200,
                    "mutated claims (aud={:?} sub={:?} session_id={:?} exp={}) must never authenticate",
                    aud, sub, session_id, exp
                );
            }
            Ok(())
        })?;
    }

    /// Unstructured mutation: random byte-level corruption of a genuinely
    /// valid token (bit flips, truncation, append garbage). Oracle:
    /// never 200, and the server must always answer (no panic / hang).
    #[test]
    fn byte_mutation_never_bypasses_auth(
        flip_positions in prop::collection::vec(any::<u8>(), 0..8),
        truncate_to in 0usize..200,
        append in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        rt().block_on(async {
            let (fx, valid) = byte_fixture().await;
            let mut bytes = valid.clone().into_bytes();

            for p in &flip_positions {
                if !bytes.is_empty() {
                    let idx = (*p as usize) % bytes.len();
                    bytes[idx] ^= 0xFF;
                }
            }
            if truncate_to < bytes.len() {
                bytes.truncate(truncate_to);
            }
            bytes.extend_from_slice(&append);

            let mutated_is_identical = &bytes == valid.as_bytes();
            // Mutated bytes may not be valid UTF-8 (reqwest header values
            // must be); when they aren't, lossily convert — still
            // attacker-shaped input the real HTTP layer would see from a
            // raw socket writer, and still must not panic the server.
            let token = String::from_utf8_lossy(&bytes).to_string();

            let Some(status) = whoami_status(&fx.base_url, &token).await else {
                // Byte-invalid header value: never reached the wire, not in scope.
                return Ok(());
            };
            if !mutated_is_identical {
                prop_assert_ne!(status, 200, "corrupted token bytes must never authenticate");
            }
            Ok(())
        })?;
    }
}
