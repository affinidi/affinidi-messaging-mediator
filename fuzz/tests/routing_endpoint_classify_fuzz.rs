//! Technique 08 — SSRF-adjacent routing-2.0 endpoint classification
//! (`classify_endpoint`, private `fn routing.rs:1093`; `uri_points_at_self`,
//! `pub(crate) fn server.rs:1294`) — proptest + `#[tokio::test]` against the
//! real `axum` router and the real forward-message pipeline.
//!
//! ## Call-path tracing (recon addendum)
//! `POST /mediator/v1/inbound` → `message_inbound_handler` → the
//! `routing/2.0/forward` branch of the message dispatch → `routing::process`
//! → `deliver_forward` → `remote_endpoint_for` → `state.did_resolver.resolve
//! (next)` (for a `did:peer:2`, this is a **local, no-network** decode — the
//! document, including its `serviceEndpoint`, is encoded directly in the DID
//! string) → `service_endpoint_for_remote` → `didcomm_endpoints` →
//! **`classify_endpoint`** (which calls **`uri_points_at_self`** for any
//! `http(s)/ws(s)` endpoint URI). This is exactly the attacker-reachable
//! trust boundary: a `did:peer:2` is self-describing and entirely
//! attacker-controlled (anyone can mint one with an arbitrary
//! `serviceEndpoint` string embedded, unvalidated at generation time — see
//! `affinidi-did-common`'s `PeerService::encode`, which never parses the
//! endpoint string; only *resolution* of the `Uri` variant later calls
//! `url::Url::from_str`, and the *`Long`* variant `affinidi_tdk::dids::
//! DID::generate_did_peer`'s plain-string convenience helper uses is never
//! URL-parsed at all before `classify_endpoint` sees it as a raw string).
//! A real sender authenticated to this mediator can therefore address a
//! `routing/2.0/forward` at a `next` DID whose document publishes any
//! string they like as its `DIDCommMessaging` endpoint, and observe whether
//! the mediator (a) stores it locally, or (b) enqueues it to `FORWARD_Q`
//! for outbound relay to that exact string — this is the live SSRF-adjacent
//! decision point.
//!
//! ## Real entry point (no `pub(crate)`/private reach-around)
//! One `routing/2.0/forward` DIDComm message, built with the SDK's real,
//! `pub` `ATM::routing().forward_message()` + `ATM::send_message()` (the
//! same calls `affinidi-messaging-test-mediator`'s own
//! `TestTopology::forward` helper and the project's own
//! `cross_mediator_forwarding.rs` integration test use), POSTed to the real
//! `/inbound` route on a real, `MediatorBuilder`-spawned mediator.
//!
//! ## Oracle
//! - Tier 1 (the pipeline keeps working) on every fuzzed endpoint string —
//!   boundary-value classes plus IPv6/transition-form/punycode/unicode/
//!   userinfo-smuggling classes. A forward the mediator refuses is a
//!   legitimate outcome; after each case, a forward to a plain foreign URL
//!   must still be accepted and classified Remote, so a crashed or wedged
//!   pipeline fails the test.
//! - Tier 2 (positive invariant): the mediator's own real, exactly-as-
//!   advertised HTTP endpoint — in several case/trailing-slash/path
//!   spellings `uri_points_at_self`'s doc comment says it normalizes — must
//!   be ACCEPTED and classified Local (`FORWARD_Q` unchanged). A refused
//!   send fails the test rather than passing as "not Remote".
//! - Not asserted: exotic transition-form self-address spellings
//!   (`[::1]`, IPv4-mapped IPv6, decimal/octal/hex IPv4) that are NOT
//!   byte-identical to the advertised authority. `uri_points_at_self`'s own
//!   contract is an exact `(host, port)` set-membership check against
//!   `self_authorities`, not an IP-equivalence oracle, so classifying these
//!   as Remote is plausibly correct-per-contract rather than a bug; this
//!   harness records the observed classification as data for human review
//!   rather than asserting a specific verdict it cannot independently prove.

mod common_routing;

use affinidi_messaging_didcomm::Message;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use proptest::prelude::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

// Separate fixtures for the deterministic matrix and the proptest property:
// reusing one `ATM`/sender across both surfaced a client-side ("sender has no
// usable key agreement key") failure in the SDK's own resolver-cache/session
// bookkeeping, not in the mediator. A fresh fixture per test removes that
// confound.
static FIXTURE_DETERMINISTIC: tokio::sync::OnceCell<common_routing::RoutingFixture> =
    tokio::sync::OnceCell::const_new();
async fn fixture_deterministic() -> &'static common_routing::RoutingFixture {
    FIXTURE_DETERMINISTIC
        .get_or_init(common_routing::spawn)
        .await
}

static FIXTURE_PROPTEST: tokio::sync::OnceCell<common_routing::RoutingFixture> =
    tokio::sync::OnceCell::const_new();
async fn fixture_proptest() -> &'static common_routing::RoutingFixture {
    FIXTURE_PROPTEST.get_or_init(common_routing::spawn).await
}

/// How the mediator handled one forward. The payloads are read through
/// `Debug` in assertion messages.
#[derive(Debug)]
#[allow(dead_code)]
enum Classified {
    /// Accepted, and nothing was added to `FORWARD_Q`: delivered locally.
    Local,
    /// Accepted and queued for relay; carries the `endpoint_url` it queued
    /// (`None` if the entry for this next hop could not be read back).
    Remote(Option<String>),
    /// The send failed: the mediator refused the forward (or the request
    /// did not complete). The SDK error does not distinguish the two.
    Refused(String),
}

/// Build a `did:peer:2` whose DIDCommMessaging service endpoint is
/// `endpoint_uri`, verbatim and unvalidated (the `Long`-variant path —
/// see module doc), then forward one `routing/2.0/forward` message
/// addressed to it from `fx`'s pre-registered sender, and report whether
/// `classify_endpoint` decided Local or Remote. `Err` is a harness-side
/// failure (DID generation, packing, or the store), not a mediator verdict.
async fn classify_via_forward(
    fx: &common_routing::RoutingFixture,
    endpoint_uri: &str,
) -> Result<Classified, String> {
    let (next_did, _secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(endpoint_uri.to_string()),
    )
    .map_err(|e| format!("generate_did_peer: {e}"))?;

    // Give the next hop an account. The mediator classifies the next hop
    // first and only then, for a Local verdict, refuses a recipient with no
    // account (`routing.rs`, `deliver_forward`), so this does not influence
    // the classification under test; it makes a Local verdict observable as
    // an accepted send rather than a `delivery.refused` that is
    // indistinguishable from any other refusal.
    fx.mediator()
        .register_local_did(&next_did)
        .await
        .map_err(|e| format!("register_local_did: {e}"))?;

    let before = fx
        .mediator()
        .store()
        .forward_queue_len()
        .await
        .map_err(|e| format!("forward_queue_len (before): {e}"))?;

    // The forwarded payload must be a real DIDComm envelope: a Local verdict
    // stores it for the next hop, and storing parses it first.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    let inner = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        serde_json::json!({ "content": "fuzz-forward-payload" }),
    )
    .to(next_did.clone())
    .from(fx.sender.did.clone())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();
    // The SDK refuses to resolve a DID over its 1000-byte size limit, so it
    // cannot pack for the oversized-endpoint cases. Those still go to the
    // mediator, carrying an opaque JWE-shaped payload: the forward's routing
    // is what is under test, and a Local verdict refusing that payload is a
    // legitimate outcome.
    let payload = match fx
        .env
        .atm
        .pack_encrypted(
            &inner,
            &next_did,
            Some(&fx.sender.did),
            Some(&fx.sender.did),
        )
        .await
    {
        Ok((payload, _)) => payload,
        Err(_) => serde_json::json!({
            "protected": "e30",
            "recipients": [{ "header": { "kid": format!("{next_did}#key-2") }, "encrypted_key": "AA" }],
            "iv": "AA",
            "ciphertext": "AA",
            "tag": "AA"
        })
        .to_string(),
    };

    let (fwd_id, packed) = fx
        .env
        .atm
        .routing()
        .forward_message(
            &fx.sender.profile,
            false,
            &payload,
            fx.mediator().did(),
            &next_did,
            None,
            None,
        )
        .await
        .map_err(|e| format!("forward_message: {e}"))?;

    // The per-IP rate limiter (production default, not configurable through
    // the test-mediator builder) answers 429 under a few hundred cases. A
    // 429 is not a verdict on the endpoint: wait it out and resend, so every
    // case actually reaches `classify_endpoint`.
    let mut attempts = 0;
    loop {
        match fx
            .env
            .atm
            .send_message(&fx.sender.profile, &packed, &fwd_id, false, false)
            .await
        {
            Ok(_) => break,
            Err(e) => {
                let e = e.to_string();
                attempts += 1;
                if e.contains("HTTP 429") && attempts < 30 {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                    continue;
                }
                return Ok(Classified::Refused(e));
            }
        }
    }

    let after = fx
        .mediator()
        .store()
        .forward_queue_len()
        .await
        .map_err(|e| format!("forward_queue_len (after): {e}"))?;

    // The forwarding processor is off (see `common_routing`), so nothing
    // else drains FORWARD_Q and its length only grows by our own enqueue.
    if after <= before {
        return Ok(Classified::Local);
    }

    // Classified Remote — read back the entry to see the endpoint
    // `classify_endpoint` actually picked.
    let entries = fx
        .mediator()
        .store()
        .forward_queue_read(
            "fuzz-consumers",
            "fuzz-consumer-1",
            16,
            Duration::from_millis(50),
        )
        .await
        .map_err(|e| format!("forward_queue_read: {e}"))?;
    let next_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&next_did);
    let endpoint = entries
        .iter()
        .find(|e| e.to_did_hash == next_hash)
        .map(|e| e.endpoint_url.clone());
    Ok(Classified::Remote(endpoint))
}

/// Liveness check: a forward to a plain foreign URL must still be accepted
/// and classified Remote. Run after each hostile endpoint, so a crashed,
/// wedged or poisoned forwarding pipeline fails the test instead of hiding
/// behind "refused is a legitimate outcome".
async fn assert_pipeline_alive(fx: &common_routing::RoutingFixture, after: &str) {
    let result = classify_via_forward(fx, "https://relay.example.com/didcomm").await;
    assert!(
        matches!(result, Ok(Classified::Remote(_))),
        "forwarding pipeline stopped working after {after}: a plain foreign endpoint \
         was not accepted and queued for relay: {result:?}"
    );
}

#[tokio::test]
async fn deterministic_self_url_and_boundary_matrix() {
    let fx = fixture_deterministic().await;
    let self_url = fx.mediator().endpoint().to_string(); // e.g. http://127.0.0.1:PORT/mediator/v1/

    // --- Tier 2: the mediator's own advertised URL, in spellings with the
    // same authority, must be accepted and classified Local. ---
    let rest = self_url
        .strip_prefix("http://")
        .expect("test mediator advertises http://");
    let self_variants: Vec<String> = vec![
        self_url.clone(),
        format!("http://{}", rest.to_uppercase()), // host/path case
        self_url.trim_end_matches('/').to_string(), // no trailing slash
        format!("{}extra/path/segment", self_url), // different path, same authority
    ];
    for variant in &self_variants {
        let result = classify_via_forward(fx, variant).await;
        assert!(
            matches!(result, Ok(Classified::Local)),
            "self URL variant {variant:?} must be accepted and classified Local \
             (FORWARD_Q unchanged); got {result:?}"
        );
    }

    // An upper-case scheme: `classify_endpoint` matches `http://` etc.
    // case-sensitively, so `HTTP://<self>` matches no rule and the forward is
    // refused. That fails closed; the invariant is only that the mediator's
    // own address is never queued for relay to itself.
    let upper_scheme = self_url.to_uppercase();
    let result = classify_via_forward(fx, &upper_scheme).await;
    assert!(
        matches!(result, Ok(Classified::Local | Classified::Refused(_))),
        "self URL {upper_scheme:?} must never be queued for relay; got {result:?}"
    );

    // --- Tier 1 boundary-value / transition-form battery: whatever the
    // classification, the pipeline must keep working (checked after each
    // URI). The classification itself is not asserted (see module doc). ---
    let long_self_prefixed = "http://example.com/".repeat(4000);
    let boundary_uris: Vec<&str> = vec![
        "",
        " ",
        "\0",
        "did:",
        "did:example:",
        "did:example:foreign-mediator",
        "http://",
        "http:///noauthority",
        "http://example.com/relay",
        "https://example.com:443/relay",
        "ws://example.com/relay",
        "wss://example.com:443/relay",
        "http://[::1]:9999/relay",              // IPv6 loopback, not bound
        "http://[::ffff:127.0.0.1]:9999/relay", // IPv4-mapped IPv6
        "http://0x7f000001:9999/relay",         // hex IPv4
        "http://017700000001:9999/relay",       // octal IPv4
        "http://2130706433:9999/relay",         // decimal IPv4
        "http://xn--nxasmq6b.example/relay",    // punycode domain
        "http://аррӏе.com/relay",               // Cyrillic homoglyph domain
        "http://attacker@127.0.0.1@evil.com/relay", // userinfo smuggling
        "http://evil.com\u{feff}/relay",        // BOM injection
        "\"http://example.com/relay\"",         // JSON-quoted (classify_endpoint strips this)
        long_self_prefixed.as_str(),            // ~76KB, max-URI boundary class
        "ht!tp://not-a-real-scheme/relay",
    ];
    for uri in &boundary_uris {
        let result = classify_via_forward(fx, uri).await;
        assert!(
            result.is_ok(),
            "harness failure on boundary URI {uri:?}: {result:?}"
        );
        assert_pipeline_alive(fx, &format!("boundary URI {uri:?}")).await;
    }

    fx.shutdown();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    /// Unstructured fuzzing of the endpoint-URI string. Oracle: Tier 1 only
    /// — these strings have no a-priori expected classification, so the
    /// invariant is "the forwarding pipeline fails closed (local or
    /// refused) or relays, and keeps working afterwards."
    #[test]
    fn fuzzed_endpoint_strings_never_crash_the_forwarding_pipeline(
        uri in "[ -~]{0,200}",
    ) {
        rt().block_on(async {
            let fx = fixture_proptest().await;
            let result = classify_via_forward(fx, &uri).await;
            prop_assert!(result.is_ok(), "harness failure on fuzzed endpoint {:?}: {:?}", uri, result);
            assert_pipeline_alive(fx, &format!("fuzzed endpoint {uri:?}")).await;
            Ok(())
        })?;
    }
}
