//! `security.did_privacy_mode`: a strict mediator answers with hashes only; a
//! permissive one adds `ext["com.affinidi.messaging"].dids`, `hash → DID`, for
//! the DIDs it has seen authenticate and those a caller offered in `ext`.

use crate::common;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::did_identity::did_hash;
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{DidPrivacyMode, TestEnvironment, TestMediator, TestUser};
use affinidi_secrets_resolver::secrets::KeyType;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const ACCOUNT_GET: &str = "https://trusttasks.org/spec/messaging/account/get/0.1";
const ACCESS_LIST_UPDATE: &str = "https://trusttasks.org/spec/messaging/access-list/update/0.1";
const ACCESS_LIST_LIST: &str = "https://trusttasks.org/spec/messaging/access-list/list/0.1";

async fn env(mode: DidPrivacyMode) -> (TestEnvironment, TestUser) {
    let mediator = TestMediator::builder()
        .did_privacy_mode(mode)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice authenticates");
    (env, alice)
}

/// Send a signed Trust Task from `from` and return the reply's payload.
async fn task(env: &TestEnvironment, from: &TestUser, type_uri: &str, payload: Value) -> Value {
    let mediator_did = env.mediator.did().to_string();
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuer": from.did,
        "recipient": mediator_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    let key = from
        .secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .expect("an Ed25519 signing key");
    let doc = sign_trust_task(&doc, key, SignOptions::new())
        .await
        .expect("sign");
    let secs = chrono::Utc::now().timestamp() as u64;
    let msg = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        doc,
    )
    .to(mediator_did.clone())
    .from(from.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&from.did), None)
        .await
        .expect("authcrypt");
    match env
        .atm
        .send_message(&from.profile, &packed, &msg_id, true, true)
        .await
    {
        Ok(SendMessageResponse::Message(reply)) => reply.body["payload"].clone(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

fn dids(payload: &Value) -> &Value {
    &payload["ext"]["com.affinidi.messaging"]["dids"]
}

#[tokio::test]
async fn a_strict_mediator_returns_hashes_only() {
    common::init_tracing();
    let (env, alice) = env(DidPrivacyMode::Strict).await;
    let carol = "did:example:carol";

    let got = task(
        &env,
        &alice,
        ACCOUNT_GET,
        json!({ "did": alice.did_hash() }),
    )
    .await;
    assert_eq!(got["account"]["did"], alice.did_hash());
    assert!(got.get("ext").is_none(), "{got:#}");

    // A DID offered in `ext` is ignored, not stored.
    let updated = task(
        &env,
        &alice,
        ACCESS_LIST_UPDATE,
        json!({
            "did": alice.did_hash(),
            "add": [did_hash(carol)],
            "ext": { "com.affinidi.messaging": { "dids": [carol] } },
        }),
    )
    .await;
    assert!(updated.get("ext").is_none(), "{updated:#}");
    assert!(
        env.mediator
            .store()
            .did_map_get(&[did_hash(carol), alice.did_hash()])
            .await
            .expect("read")
            .is_empty()
    );
}

#[tokio::test]
async fn a_permissive_mediator_returns_the_did_behind_each_hash() {
    common::init_tracing();
    let (env, alice) = env(DidPrivacyMode::Permissive).await;
    let (carol, dave) = ("did:example:carol", "did:example:dave");

    // Alice authenticated, so her DID is known; the hash field is unchanged.
    let got = task(
        &env,
        &alice,
        ACCOUNT_GET,
        json!({ "did": alice.did_hash() }),
    )
    .await;
    assert_eq!(got["account"]["did"], alice.did_hash());
    assert_eq!(dids(&got)[alice.did_hash()], alice.did.as_str(), "{got:#}");

    // Alice adds carol by hash and names her DID in `ext`. Dave is offered too
    // but not added, so the mediator doesn't keep his DID.
    let updated = task(
        &env,
        &alice,
        ACCESS_LIST_UPDATE,
        json!({
            "did": alice.did_hash(),
            "add": [did_hash(carol)],
            "ext": { "com.affinidi.messaging": { "dids": [carol, dave] } },
        }),
    )
    .await;
    assert_eq!(updated["added"], json!([did_hash(carol)]));
    assert_eq!(dids(&updated)[did_hash(carol)], carol, "{updated:#}");
    assert!(dids(&updated).get(did_hash(dave)).is_none());

    // A later listing, with no `ext` in the request, still names her.
    let listed = task(
        &env,
        &alice,
        ACCESS_LIST_LIST,
        json!({ "did": alice.did_hash() }),
    )
    .await;
    assert_eq!(listed["entries"], json!([did_hash(carol)]));
    assert_eq!(dids(&listed)[did_hash(carol)], carol, "{listed:#}");
    assert_eq!(dids(&listed)[alice.did_hash()], alice.did.as_str());
}
