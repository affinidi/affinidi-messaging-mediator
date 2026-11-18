//! Shared fixture for the Wave-2 (JWT / ACL / SSRF-routing) real-router
//! harnesses.
//!
//! Spawns a real mediator via `affinidi_messaging_mediator::builder::
//! MediatorBuilder` — the crate's own, `pub`, production bootstrap entry
//! point (the same one `affinidi-messaging-test-mediator` itself calls) —
//! bound to a real loopback TCP socket, backed by `MemoryStore`, with a
//! JWT signing/verification keypair we generate and keep ourselves so we
//! can mint and mutate tokens. No `pub(crate)` reach-around anywhere in
//! this module: every item named below is `pub` in its crate.

#![allow(dead_code)]

use std::{net::TcpListener, sync::Arc};

use affinidi_messaging_mediator::{
    builder::{MediatorBuilder, MediatorHandle, TlsMode},
    common::config::{LimitsConfig, SecurityConfig},
    store::MemoryStore,
};
use affinidi_messaging_mediator_common::{
    MediatorSecrets,
    secrets::backends::MemoryStore as SecretsMemoryStore,
    store::{
        // `account_add` / `create_session` moved to this auto-implemented
        // extension trait (store/traits/ext.rs) since the engagement HEAD.
        MediatorStoreExt as _,
        types::{Session, SessionState},
    },
    types::{accounts::AccountType, acls::MediatorACLSet},
};
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use ring::signature::Ed25519KeyPair;
use tokio_util::sync::CancellationToken;

/// A running, real, in-process mediator plus everything needed to mint
/// tokens for it.
pub struct Fixture {
    pub base_url: String,
    pub mediator_did: String,
    pub admin_did: String,
    /// Ed25519 PKCS#8 bytes installed as the mediator's real JWT signing /
    /// verification key, via the real `pub fn
    /// SecurityConfig::set_jwt_keys_from_pkcs8`. Kept so the test can mint
    /// (and mutate) tokens with its own `jsonwebtoken` instance.
    pub jwt_pkcs8: Vec<u8>,
    pub store: Arc<MemoryStore>,
    handle: MediatorHandle,
    shutdown: CancellationToken,
}

impl Fixture {
    /// Register a fresh session + account for `did`, with `acls` and
    /// `account_type`, so a JWT naming this `did`/`session_id` is accepted
    /// past the "does the session exist" and "is the DID blocked" gates.
    /// This is ordinary test-fixture *arrangement* via the store's own
    /// `pub` `MediatorStore` trait (`create_session` / `account_add`) —
    /// the same bypass the target's own integration tests use (e.g.
    /// `explicit_allow_auth_gate.rs`'s `store.account_add`) — not a
    /// reach-around of the function under test, which still runs the real
    /// `jsonwebtoken::decode` + expiry + DID-match + ACL checks on every
    /// request.
    pub async fn register_session(
        &self,
        did: &str,
        session_id: &str,
        acls: MediatorACLSet,
        account_type: AccountType,
    ) {
        let did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(did);
        self.store
            .account_add(&did_hash, &acls, None)
            .await
            .expect("account_add");
        let session = Session {
            session_id: session_id.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            did: did.to_string(),
            did_hash,
            authenticated: true,
            acls,
            account_type,
            expires_at: 0,
            refresh_token_hash: None,
        };
        self.store
            .create_session(&session)
            .await
            .expect("create_session");
    }

    pub fn shutdown(&self) {
        self.handle.shutdown();
        self.shutdown.cancel();
    }
}

/// Spawn a fresh fixture: real mediator, real router, real `MemoryStore`,
/// real installed JWT key. ALLOW_ALL global default so a session that
/// authenticates without a pre-registered account (the `jwt_auth_fuzz`
/// baseline case) still gets a usable ACL set.
pub async fn spawn() -> Fixture {
    // Process-wide, idempotent — must run before any `jsonwebtoken` EdDSA
    // operation (ours or the mediator's own), per the crate's own doc
    // comment on this function.
    affinidi_messaging_mediator::install_jwt_crypto_provider();

    let (secrets_resolver, _task) = ThreadedSecretsResolver::new(None).await;
    let secrets_resolver: Arc<ThreadedSecretsResolver> = Arc::new(secrets_resolver);

    let mediator_did = "did:example:fuzz-mediator".to_string();
    let admin_did = "did:example:fuzz-admin".to_string();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 pkcs8");
    let jwt_pkcs8 = pkcs8_doc.as_ref().to_vec();

    let mut security = SecurityConfig::headless(secrets_resolver.clone());
    security
        .set_jwt_keys_from_pkcs8(&jwt_pkcs8)
        .expect("install jwt keys");
    security.use_ssl = false;
    security.global_acl_default =
        MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ALLOW_ALL ruleset");

    let secrets_backend = MediatorSecrets::new(Arc::new(SecretsMemoryStore::new(
        "wave2-fuzz-harness-memory",
    )));

    let store = Arc::new(MemoryStore::new());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");

    // The production per-IP rate limiter (default 100 req/s, burst 50) wraps
    // every route and is orthogonal to the JWT/ACL logic these harnesses
    // fuzz — hundreds of proptest cases against one shared loopback fixture
    // would otherwise trip it and the harness would be testing the rate
    // limiter instead of `authenticate_token`/`authz`. Raised here, not
    // disabled, so a genuine server panic still surfaces as a dropped
    // connection rather than being masked by 429s.
    let limits = LimitsConfig {
        rate_limit_per_ip: 1_000_000,
        rate_limit_burst: 1_000_000,
        ..LimitsConfig::default()
    };

    let shutdown = CancellationToken::new();
    let handle = MediatorBuilder::new(secrets_resolver.clone())
        .mediator_did(&mediator_did)
        .admin_did(&admin_did)
        .secrets_backend(secrets_backend)
        .secrets_backend_url("memory://(wave2-fuzz-harness)")
        .store(store.clone())
        .listener(listener)
        .api_prefix("/mediator/v1/")
        .security(security)
        .limits(limits)
        .tls(TlsMode::Plain)
        .start(shutdown.clone())
        .await
        .expect("mediator start");

    let base_url = handle.http_endpoint.to_string();

    Fixture {
        base_url,
        mediator_did,
        admin_did,
        jwt_pkcs8,
        store,
        handle,
        shutdown,
    }
}
