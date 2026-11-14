//! End-to-end coverage of the HTTP authentication flow driven by hand
//! (challenge → `/authenticate` → `/authenticate/refresh`), so each step's
//! request can be shaped by the test:
//!
//! - an account is created when a DID answers its challenge, not when it asks
//!   for one, and only DID-shaped, bounded input gets a challenge;
//! - a refresh token is exchanged only by the DID it was issued to, only once,
//!   and only against a session that records it;
//! - an access token is the only bearer credential, and a refresh token the
//!   only thing `/authenticate/refresh` exchanges.

use crate::common;
use crate::common::now;

use std::{sync::Arc, time::Duration};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::store::{Session, prelude::*};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestEnvironment, TestMediator, TestMediatorHandle, acl,
};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use common::init_tracing;
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client")
}

/// POST a JSON body to `path` under the mediator's API and return
/// (status, JSON body or `Null` when the body is not JSON).
async fn post(mediator: &TestMediatorHandle, path: &str, body: String) -> (u16, JsonValue) {
    let resp = http()
        .post(format!("{}{path}", mediator.endpoint()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(JsonValue::Null);
    (status, body)
}

async fn challenge(mediator: &TestMediatorHandle, did: &str) -> (u16, JsonValue) {
    post(
        mediator,
        "authenticate/challenge",
        json!({ "did": did }).to_string(),
    )
    .await
}

/// A fresh `did:peer:2.*` whose secrets the SDK holds but which has no
/// account on the mediator.
async fn unregistered_did(env: &TestEnvironment) -> String {
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(env.mediator.did().to_string()),
    )
    .expect("generate did:peer");
    env.tdk.secrets_resolver().insert_vec(&secrets).await;
    did
}

/// Authcrypt `typ`/`body` from `from` to the mediator, with the inner `from`
/// set as the SDK sets it.
async fn packed(env: &TestEnvironment, from: &str, typ: &str, body: JsonValue) -> String {
    let mediator_did = env.mediator.did().to_string();
    let msg = Message::build(Uuid::new_v4().to_string(), typ.to_string(), body)
        .to(mediator_did.clone())
        .from(from.to_string())
        .created_time(now())
        .expires_time(now() + 60)
        .finalize();
    env.atm
        .pack_encrypted(&msg, &mediator_did, Some(from), Some(from))
        .await
        .expect("pack auth message")
        .0
}

struct Tokens {
    access: String,
    refresh: String,
}

/// Challenge + `/authenticate` for `did`; returns the status and, on 200,
/// the tokens.
async fn try_login(env: &TestEnvironment, did: &str) -> (u16, Option<Tokens>) {
    let (status, body) = challenge(&env.mediator, did).await;
    assert_eq!(status, 200, "challenge for {did}: {body}");
    let data = &body["data"];
    let response = packed(
        env,
        did,
        "https://affinidi.com/atm/1.0/authenticate",
        json!({
            "challenge": data["challenge"],
            "session_id": data["session_id"],
        }),
    )
    .await;
    let (status, body) = post(&env.mediator, "authenticate", response).await;
    if status != 200 {
        return (status, None);
    }
    (
        status,
        Some(Tokens {
            access: body["data"]["access_token"].as_str().unwrap().to_string(),
            refresh: body["data"]["refresh_token"].as_str().unwrap().to_string(),
        }),
    )
}

async fn login(env: &TestEnvironment, did: &str) -> Tokens {
    let (status, tokens) = try_login(env, did).await;
    assert_eq!(status, 200, "login for {did}");
    tokens.unwrap()
}

/// POST a refresh request for `refresh_token`, authcrypted from `from`.
async fn refresh(env: &TestEnvironment, from: &str, refresh_token: &str) -> (u16, JsonValue) {
    let request = packed(
        env,
        from,
        "https://affinidi.com/atm/1.0/authenticate/refresh",
        json!({ "refresh_token": refresh_token }),
    )
    .await;
    post(&env.mediator, "authenticate/refresh", request).await
}

fn refreshed_token(body: &JsonValue) -> String {
    body["data"]["refresh_token"]
        .as_str()
        .expect("refresh response carries a new refresh token")
        .to_string()
}

/// The `session_id` claim of a JWT (no signature check: the test minted it
/// through the mediator a moment ago).
fn session_id_of(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("JWT payload");
    let claims: JsonValue =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["session_id"].as_str().unwrap().to_string()
}

async fn spawn_env(store: Arc<MemoryStore>, mode: AccessListModeType) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .store(store)
        .acl_mode(mode)
        .spawn()
        .await
        .expect("spawn mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator")
}

// ─── Challenge ───────────────────────────────────────────────────────────────

/// In `explicit_deny` an unknown DID gets a challenge, but its account is
/// written only once it answers; its tokens then work.
#[tokio::test]
async fn account_is_created_when_the_challenge_is_answered() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitDeny).await;
    let did = unregistered_did(&env).await;
    let did_hash = sha256::digest(&did);

    let (status, body) = challenge(&env.mediator, &did).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !store.account_exists(&did_hash).await.unwrap(),
        "asking for a challenge must not create an account"
    );

    let tokens = login(&env, &did).await;
    assert!(
        store.account_exists(&did_hash).await.unwrap(),
        "answering the challenge creates the account"
    );

    // The access token is usable.
    let whoami = http()
        .get(format!("{}whoami", env.mediator.endpoint()))
        .bearer_auth(&tokens.access)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status().as_u16(), 200);

    // And so is the refresh token.
    let (status, body) = refresh(&env, &did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// In `explicit_allow` a pre-registered DID completes the hand-driven flow,
/// including a refresh.
#[tokio::test]
async fn registered_did_logs_in_and_refreshes_in_explicit_allow_mode() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store, AccessListModeType::ExplicitAllow).await;
    let alice = env.add_user("alice").await.unwrap();

    let tokens = login(&env, &alice.did).await;
    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// An account removed between the challenge and the response is not
/// recreated in `explicit_allow` mode.
#[tokio::test]
async fn account_removed_before_the_response_is_not_recreated_in_explicit_allow_mode() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitAllow).await;
    let alice = env.add_user("alice").await.unwrap();
    let did_hash = sha256::digest(&alice.did);

    let (status, body) = challenge(&env.mediator, &alice.did).await;
    assert_eq!(status, 200, "{body}");
    let data = &body["data"];
    let response = packed(
        &env,
        &alice.did,
        "https://affinidi.com/atm/1.0/authenticate",
        json!({ "challenge": data["challenge"], "session_id": data["session_id"] }),
    )
    .await;

    // Remove the account directly, as an admin would.
    let admin = Session {
        did_hash: "admin".into(),
        account_type: AccountType::RootAdmin,
        ..Default::default()
    };
    assert!(store.account_remove(&admin, &did_hash).await.unwrap());

    let (status, body) = post(&env.mediator, "authenticate", response).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(25), "{body}");
    assert!(!store.account_exists(&did_hash).await.unwrap());

    env.shutdown().await.unwrap();
}

/// Input that is not a bounded, DID-shaped string gets no challenge, no
/// session and no account.
#[tokio::test]
async fn challenge_refuses_malformed_or_oversized_dids() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitDeny).await;

    let oversized = format!("did:key:{}", "z".repeat(4096));
    for did in [
        "",
        "did:",
        "did:key:",
        "did:KEY:abc",
        "did:key:has space",
        "did:key:line\nbreak",
        oversized.as_str(),
    ] {
        let (status, body) = challenge(&env.mediator, did).await;
        assert_eq!(status, 400, "{did:?} must be refused: {body}");
        assert!(
            !store.account_exists(&sha256::digest(did)).await.unwrap(),
            "{did:?} must not be registered"
        );
    }

    // A body far larger than any DID is cut off before it is parsed.
    let huge = format!("did:key:{}", "z".repeat(64 * 1024));
    let (status, _) = challenge(&env.mediator, &huge).await;
    assert_eq!(status, 413, "an oversized challenge body is refused");

    env.shutdown().await.unwrap();
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

/// A refresh token sent by a DID other than the one it was issued to is
/// refused, and does not disturb the owner's session.
#[tokio::test]
async fn refresh_from_a_different_did_is_refused() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store, AccessListModeType::ExplicitDeny).await;
    let alice = env.add_user("alice").await.unwrap();
    let mallory = env.add_user("mallory").await.unwrap();

    let tokens = login(&env, &alice.did).await;
    // Mallory holds a session of its own, so it is a fully authenticated DID.
    let _ = login(&env, &mallory.did).await;

    let (status, body) = refresh(&env, &mallory.did, &tokens.refresh).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(33), "{body}");

    // Alice's token is untouched and still exchanges once.
    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// A refresh token is exchanged once. Presenting it again ends the session,
/// so the token issued in its place stops working too.
async fn reused_refresh_token_ends_the_session(env: TestEnvironment) {
    let alice = env.add_user("alice").await.unwrap();
    let first = login(&env, &alice.did).await;

    let (status, body) = refresh(&env, &alice.did, &first.refresh).await;
    assert_eq!(status, 200, "{body}");
    let second = refreshed_token(&body);

    let (status, body) = refresh(&env, &alice.did, &first.refresh).await;
    assert_eq!(status, 401, "a used refresh token is refused: {body}");

    let (status, body) = refresh(&env, &alice.did, &second).await;
    assert_ne!(
        status, 200,
        "the session ended, so its newer refresh token is refused too: {body}"
    );

    // The DID can still log in again from scratch.
    let again = login(&env, &alice.did).await;
    let (status, body) = refresh(&env, &alice.did, &again.refresh).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

#[tokio::test]
async fn reused_refresh_token_ends_the_session_memory() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    reused_refresh_token_ends_the_session(env).await;
}

#[cfg(feature = "fjall-backend")]
#[tokio::test]
async fn reused_refresh_token_ends_the_session_fjall() {
    init_tracing();
    let mediator = TestMediator::builder()
        .fjall_backend()
        .expect("fjall backend")
        .spawn()
        .await
        .expect("spawn fjall mediator");
    let env = TestEnvironment::new(mediator).await.unwrap();
    reused_refresh_token_ends_the_session(env).await;
}

/// Concurrent refreshes with one token: exactly one succeeds.
#[tokio::test]
async fn concurrent_refreshes_with_one_token_succeed_once() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;

    let mut requests = Vec::new();
    for _ in 0..8 {
        requests.push(
            packed(
                &env,
                &alice.did,
                "https://affinidi.com/atm/1.0/authenticate/refresh",
                json!({ "refresh_token": tokens.refresh }),
            )
            .await,
        );
    }
    let results = futures_util::future::join_all(
        requests
            .into_iter()
            .map(|r| post(&env.mediator, "authenticate/refresh", r)),
    )
    .await;
    let ok = results.iter().filter(|(status, _)| *status == 200).count();
    assert!(
        ok == 1,
        "exactly one exchange of a token succeeds: {results:?}"
    );

    env.shutdown().await.unwrap();
}

/// A session with no recorded refresh-token hash cannot be refreshed.
#[tokio::test]
async fn refresh_without_a_recorded_token_is_refused() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitDeny).await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;

    let session_id = session_id_of(&tokens.refresh);
    let mut session = store.get_session(&session_id, &alice.did).await.unwrap();
    session.refresh_token_hash = None;
    store
        .put_session(&session, Duration::from_secs(3600))
        .await
        .unwrap();

    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 401, "{body}");

    env.shutdown().await.unwrap();
}

// ─── Token use ───────────────────────────────────────────────────────────────

async fn whoami_status(env: &TestEnvironment, bearer: &str) -> u16 {
    http()
        .get(format!("{}whoami", env.mediator.endpoint()))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Whether `/ws` upgrades for `bearer`, sent as an `Authorization` header
/// and as a `bearer.<jwt>` subprotocol.
async fn ws_upgrades(env: &TestEnvironment, bearer: &str) -> (bool, bool) {
    use tokio_tungstenite::tungstenite::ClientRequestBuilder;
    let uri: tokio_tungstenite::tungstenite::http::Uri =
        env.mediator.ws_endpoint().as_str().parse().unwrap();
    let header = ClientRequestBuilder::new(uri.clone())
        .with_header("Authorization", format!("Bearer {bearer}"));
    let subprotocol = ClientRequestBuilder::new(uri)
        .with_sub_protocol("affinidi.didcomm.v1")
        .with_sub_protocol(format!("bearer.{bearer}"));
    (
        tokio_tungstenite::connect_async(header).await.is_ok(),
        tokio_tungstenite::connect_async(subprotocol).await.is_ok(),
    )
}

/// A session token as an earlier release minted it: no `token_use` claim
/// and no `jti`, signed with the mediator's key.
fn unmarked_token(env: &TestEnvironment, did: &str, session_id: &str, exp: u64) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"EdDSA"}"#);
    let claims = BASE64_URL_SAFE_NO_PAD.encode(
        json!({ "aud": "ATM", "sub": did, "session_id": session_id, "exp": exp }).to_string(),
    );
    let signing_input = format!("{header}.{claims}");
    let key =
        ring::signature::Ed25519KeyPair::from_pkcs8(&env.mediator.replica_identity().jwt_pkcs8)
            .unwrap();
    let signature = BASE64_URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

/// Login, use the access token, exchange the refresh token, and use the new
/// access token.
#[tokio::test]
async fn login_access_refresh_flow_issues_working_tokens() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;
    assert_eq!(whoami_status(&env, &tokens.access).await, 200);
    assert_eq!(ws_upgrades(&env, &tokens.access).await, (true, true));

    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");
    let access = body["data"]["access_token"].as_str().unwrap();
    assert_eq!(whoami_status(&env, access).await, 200);
    let (status, body) = refresh(&env, &alice.did, &refreshed_token(&body)).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// A refresh token is not accepted as a bearer on REST routes or `/ws`,
/// whether current or already exchanged.
#[tokio::test]
async fn refresh_token_is_not_a_bearer_credential() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;

    assert_eq!(whoami_status(&env, &tokens.refresh).await, 401);
    assert_eq!(ws_upgrades(&env, &tokens.refresh).await, (false, false));

    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(whoami_status(&env, &tokens.refresh).await, 401);
    assert_eq!(whoami_status(&env, &refreshed_token(&body)).await, 401);

    env.shutdown().await.unwrap();
}

/// An access token is not exchanged at `/authenticate/refresh`, and
/// presenting one leaves the session and its refresh token intact.
#[tokio::test]
async fn access_token_is_not_exchanged_for_new_tokens() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;

    let (status, body) = refresh(&env, &alice.did, &tokens.access).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(38), "{body}");

    assert_eq!(whoami_status(&env, &tokens.access).await, 200);
    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// Tokens minted before the `token_use` claim: an unmarked token that fits
/// within an access-token lifetime is still a bearer credential; one that
/// outlives it is not, but is still exchanged at refresh when it is the
/// session's recorded refresh token.
#[tokio::test]
async fn unmarked_tokens_from_the_previous_release() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitDeny).await;
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;
    let session_id = session_id_of(&tokens.access);

    // Default access lifetime is 900 s.
    let access = unmarked_token(&env, &alice.did, &session_id, now() + 900);
    assert_eq!(whoami_status(&env, &access).await, 200);
    assert_eq!(ws_upgrades(&env, &access).await, (true, true));

    let long_lived = unmarked_token(&env, &alice.did, &session_id, now() + 85_500);
    assert_eq!(whoami_status(&env, &long_lived).await, 401);
    assert_eq!(ws_upgrades(&env, &long_lived).await, (false, false));

    // Make the long-lived token the session's recorded refresh token, as
    // the previous release would have.
    let mut session = store.get_session(&session_id, &alice.did).await.unwrap();
    session.refresh_token_hash = Some(sha256::digest(&long_lived));
    store
        .put_session(&session, Duration::from_secs(3600))
        .await
        .unwrap();
    let (status, body) = refresh(&env, &alice.did, &long_lived).await;
    assert_eq!(status, 200, "{body}");
    let access = body["data"]["access_token"].as_str().unwrap();
    assert_eq!(whoami_status(&env, access).await, 200);

    env.shutdown().await.unwrap();
}

/// Answer a challenge for `did`, running `between` after the challenge is
/// issued and before the answer is sent. `answer` overrides the challenge
/// string sent back. Returns the `/authenticate` status and body.
async fn answer_challenge<F, Fut>(
    env: &TestEnvironment,
    did: &str,
    answer: Option<&str>,
    between: F,
) -> (u16, JsonValue)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (status, body) = challenge(&env.mediator, did).await;
    assert_eq!(status, 200, "challenge for {did}: {body}");
    let data = &body["data"];
    let challenge_str = answer
        .map(JsonValue::from)
        .unwrap_or_else(|| data["challenge"].clone());
    let response = packed(
        env,
        did,
        "https://affinidi.com/atm/1.0/authenticate",
        json!({ "challenge": challenge_str, "session_id": data["session_id"] }),
    )
    .await;
    between().await;
    post(&env.mediator, "authenticate", response).await
}

/// A DID blocked after it was issued a challenge is refused when it answers.
#[tokio::test]
async fn login_refused_when_blocked_after_the_challenge() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();

    let (status, body) = answer_challenge(&env, &alice.did, None, || async {
        let mut blocked = acl::allow_all();
        blocked.set_blocked(true);
        env.mediator.set_acl(&alice.did, blocked).await.unwrap();
    })
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(25), "{body}");

    env.shutdown().await.unwrap();
}

/// The answer must carry the challenge string the session issued.
#[tokio::test]
async fn login_refused_with_a_different_challenge_string() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();

    let (status, body) =
        answer_challenge(&env, &alice.did, Some("not-the-challenge"), || async {}).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(34), "{body}");

    // The correct answer still works.
    let _ = login(&env, &alice.did).await;

    env.shutdown().await.unwrap();
}

/// Removing an account ends its sessions: the refresh token and the access
/// token are both refused with 401, so the client authenticates again.
async fn removed_account_ends_the_session(env: TestEnvironment) {
    let alice = env.add_user("alice").await.unwrap();
    let tokens = login(&env, &alice.did).await;

    let admin = Session {
        did_hash: "admin".into(),
        account_type: AccountType::RootAdmin,
        ..Default::default()
    };
    assert!(
        env.mediator
            .store()
            .account_remove(&admin, &sha256::digest(&alice.did))
            .await
            .unwrap()
    );

    let (status, body) = refresh(&env, &alice.did, &tokens.refresh).await;
    assert_eq!(status, 401, "{body}");

    let whoami = http()
        .get(format!("{}whoami", env.mediator.endpoint()))
        .bearer_auth(&tokens.access)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status().as_u16(), 401);

    env.shutdown().await.unwrap();
}

#[tokio::test]
async fn removed_account_ends_the_session_memory() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    removed_account_ends_the_session(env).await;
}

#[cfg(feature = "fjall-backend")]
#[tokio::test]
async fn removed_account_ends_the_session_fjall() {
    init_tracing();
    let mediator = TestMediator::builder()
        .fjall_backend()
        .expect("fjall backend")
        .spawn()
        .await
        .expect("spawn fjall mediator");
    let env = TestEnvironment::new(mediator).await.unwrap();
    removed_account_ends_the_session(env).await;
}

// ─── TSP ─────────────────────────────────────────────────────────────────────

/// The Ed25519 private key behind `#key-1` of a generated `did:peer`.
#[cfg(feature = "tsp")]
fn ed25519_key(secrets: &[affinidi_secrets_resolver::secrets::Secret]) -> [u8; 32] {
    secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .unwrap()
        .get_private_bytes()
        .try_into()
        .unwrap()
}

/// The `/tsp/authenticate` body for a challenge response: the signed
/// statement addressed to `to`, valid for 60 s from now.
#[cfg(feature = "tsp")]
fn tsp_statement_body(did: &str, key: &[u8; 32], challenge: &JsonValue, to: &str) -> String {
    let session_id = challenge["data"]["session_id"].as_str().unwrap();
    let created = now();
    let statement =
        affinidi_messaging_mediator::handlers::authenticate::tsp::signed_statement_bytes(
            challenge["data"]["challenge"].as_str().unwrap(),
            session_id,
            did,
            to,
            created,
            created + 60,
        );
    let signature = affinidi_tsp::crypto::signing::sign(&statement, key).unwrap();
    json!({
        "vid": did,
        "session_id": session_id,
        "signature": BASE64_URL_SAFE_NO_PAD.encode(signature),
        "to": to,
        "created_time": created,
        "expires_time": created + 60,
    })
    .to_string()
}

/// The older `/tsp/authenticate` body: a signature over the challenge string
/// alone.
#[cfg(feature = "tsp")]
fn tsp_unbound_body(did: &str, key: &[u8; 32], challenge: &JsonValue) -> String {
    let signature = affinidi_tsp::crypto::signing::sign(
        challenge["data"]["challenge"].as_str().unwrap().as_bytes(),
        key,
    )
    .unwrap();
    json!({
        "vid": did,
        "session_id": challenge["data"]["session_id"],
        "signature": BASE64_URL_SAFE_NO_PAD.encode(signature),
    })
    .to_string()
}

/// `/tsp/authenticate` creates the account once the signed statement
/// verifies, as `/authenticate` does.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn tsp_account_is_created_when_the_challenge_is_answered() {
    init_tracing();
    let store = Arc::new(MemoryStore::new());
    let env = spawn_env(store.clone(), AccessListModeType::ExplicitDeny).await;
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(env.mediator.did().to_string()),
    )
    .unwrap();
    let did_hash = sha256::digest(&did);
    let key = ed25519_key(&secrets);

    let (status, issued) = challenge(&env.mediator, &did).await;
    assert_eq!(status, 200, "{issued}");
    assert!(!store.account_exists(&did_hash).await.unwrap());

    let (status, body) = post(
        &env.mediator,
        "tsp/authenticate",
        tsp_statement_body(&did, &key, &issued, env.mediator.did()),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(store.account_exists(&did_hash).await.unwrap());

    env.shutdown().await.unwrap();
}

/// A statement signed for a different mediator does not log in here, and
/// leaves the challenge unanswered.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn tsp_statement_for_another_mediator_is_refused() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let key = ed25519_key(&alice.secrets);

    let (status, issued) = challenge(&env.mediator, &alice.did).await;
    assert_eq!(status, 200, "{issued}");

    let (status, body) = post(
        &env.mediator,
        "tsp/authenticate",
        tsp_statement_body(
            &alice.did,
            &key,
            &issued,
            "did:web:other-mediator.example.com",
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(32), "{body}");

    // The same challenge, answered for this mediator, still works.
    let (status, body) = post(
        &env.mediator,
        "tsp/authenticate",
        tsp_statement_body(&alice.did, &key, &issued, env.mediator.did()),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    env.shutdown().await.unwrap();
}

/// A signature over the challenge alone is refused unless the operator has
/// opted in, and accepted while that opt-in has not lapsed.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn tsp_unbound_signature_needs_the_operator_opt_in() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let key = ed25519_key(&alice.secrets);
    let (_, issued) = challenge(&env.mediator, &alice.did).await;
    let (status, body) = post(
        &env.mediator,
        "tsp/authenticate",
        tsp_unbound_body(&alice.did, &key, &issued),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(32), "{body}");
    env.shutdown().await.unwrap();

    for (until, accepted) in [(now() + 3600, true), (now() - 1, false)] {
        let mediator = TestMediator::builder()
            .store(Arc::new(MemoryStore::new()))
            .acl_mode(AccessListModeType::ExplicitDeny)
            .tsp_auth_accept_unbound_until(Some(until))
            .spawn()
            .await
            .expect("spawn mediator");
        let env = TestEnvironment::new(mediator)
            .await
            .expect("wire the SDK to the mediator");
        let bob = env.add_user("bob").await.unwrap();
        let key = ed25519_key(&bob.secrets);
        let (_, issued) = challenge(&env.mediator, &bob.did).await;
        let (status, body) = post(
            &env.mediator,
            "tsp/authenticate",
            tsp_unbound_body(&bob.did, &key, &issued),
        )
        .await;
        let expected = if accepted { 200 } else { 401 };
        assert_eq!(status, expected, "until {until}: {body}");
        env.shutdown().await.unwrap();
    }
}

/// `/tsp/authenticate` refuses a DID blocked after it was issued a challenge.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn tsp_login_refused_when_blocked_after_the_challenge() {
    init_tracing();
    let env = spawn_env(
        Arc::new(MemoryStore::new()),
        AccessListModeType::ExplicitDeny,
    )
    .await;
    let alice = env.add_user("alice").await.unwrap();
    let key = ed25519_key(&alice.secrets);

    let (status, issued) = challenge(&env.mediator, &alice.did).await;
    assert_eq!(status, 200, "{issued}");

    let mut blocked = acl::allow_all();
    blocked.set_blocked(true);
    env.mediator.set_acl(&alice.did, blocked).await.unwrap();

    let (status, body) = post(
        &env.mediator,
        "tsp/authenticate",
        tsp_statement_body(&alice.did, &key, &issued, env.mediator.did()),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errorCode"].as_u64(), Some(25), "{body}");

    env.shutdown().await.unwrap();
}
