//! Target: `affinidi_messaging_mediator::didcomm_compat::MetaEnvelope::new`
//! Recon tag: T1 (P0) — re-confirms/refutes the old "triple unwrap on forward
//! attachment" finding's surrounding surface and probes the envelope-shape
//! detector (JWE/JWS/plaintext classification, recipient `kid` splitting,
//! base64url decode of the `protected` header, `alg` substring match) that
//! runs on every inbound DIDComm message over REST and WebSocket, on
//! completely unauthenticated, attacker-controlled bytes, before any
//! decryption or signature check.
//! Technique: cargo-fuzz + libFuzzer, oracle tier 1 (no-panic) + tier 2
//! (parses back to a sha256 that matches the input).
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_mediator::didcomm_compat::MetaEnvelope;

static RT: OnceLock<Runtime> = OnceLock::new();
static RESOLVER: OnceLock<DIDCacheClient> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RT.get_or_init(|| Runtime::new().expect("tokio runtime"))
}

fn resolver() -> &'static DIDCacheClient {
    RESOLVER.get_or_init(|| {
        runtime().block_on(async {
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .expect("local (no-network) DID cache client")
        })
    })
}

fuzz_target!(|data: &[u8]| {
    // The real entry points (a WebSocket Text frame, an HTTP body read as
    // `&str`) only ever hand `MetaEnvelope::new` valid UTF-8 — axum and
    // tungstenite reject anything else upstream — so non-UTF-8 inputs are
    // skipped rather than lossily converted.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let resolver = resolver();
    runtime().block_on(async {
        match MetaEnvelope::new(s, resolver).await {
            Ok(envelope) => {
                // Tier 2: the envelope's recorded hash must match the input
                // it was built from — a cheap, always-true invariant for any
                // successfully classified envelope.
                assert_eq!(envelope.sha256_hash, sha256::digest(s));
            }
            Err(_) => {
                // Any rejection is fine — this is the oracle for every
                // malformed/boundary input in the corpus.
            }
        }
    });
});
