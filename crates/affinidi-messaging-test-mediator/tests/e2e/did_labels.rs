//! DID labels: account and access-list tasks take a DID or a hash for each
//! account or entry, the mediator keeps the DID beside the hash (written once),
//! and returns `ext["com.affinidi.messaging"].dids`, `hash → DID`, only to a
//! request that asks with `ext["com.affinidi.messaging"].includeDids: true`.

use crate::common;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::did_identity::did_hash;
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use affinidi_secrets_resolver::secrets::KeyType;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const ACCOUNT_GET: &str = "https://trusttasks.org/spec/messaging/account/get/0.1";
const ACCESS_LIST_UPDATE: &str = "https://trusttasks.org/spec/messaging/access-list/update/0.1";
const ACCESS_LIST_LIST: &str = "https://trusttasks.org/spec/messaging/access-list/list/0.1";

/// The request `ext` that asks for the labels.
fn include_dids() -> Value {
    json!({ "com.affinidi.messaging": { "includeDids": true } })
}

async fn env() -> (TestEnvironment, TestUser) {
    let mediator = TestMediator::builder()
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
async fn a_caller_that_does_not_ask_sees_hashes_only() {
    common::init_tracing();
    let (env, alice) = env().await;
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

    // A DID in place of a hash is hashed; the reply still names the hash.
    let updated = task(
        &env,
        &alice,
        ACCESS_LIST_UPDATE,
        json!({ "did": alice.did, "add": [carol] }),
    )
    .await;
    assert_eq!(updated["added"], json!([did_hash(carol)]), "{updated:#}");
    assert!(updated.get("ext").is_none(), "{updated:#}");

    let listed = task(
        &env,
        &alice,
        ACCESS_LIST_LIST,
        json!({ "did": alice.did_hash() }),
    )
    .await;
    assert_eq!(listed["entries"], json!([did_hash(carol)]), "{listed:#}");
    assert!(listed.get("ext").is_none(), "{listed:#}");
}

#[tokio::test]
async fn a_caller_that_asks_gets_the_did_behind_each_hash() {
    common::init_tracing();
    let (env, alice) = env().await;
    let (carol, erin) = ("did:example:carol", "did:example:erin");
    let bob = env.add_user("bob").await.expect("add bob");

    // Alice authenticated, so her label is filled.
    let got = task(
        &env,
        &alice,
        ACCOUNT_GET,
        json!({ "did": alice.did_hash(), "ext": include_dids() }),
    )
    .await;
    assert_eq!(got["account"]["did"], alice.did_hash());
    assert_eq!(dids(&got)[alice.did_hash()], alice.did.as_str(), "{got:#}");

    // Carol and Bob are added by hash, Erin by DID. Only Erin's label is known.
    let updated = task(
        &env,
        &alice,
        ACCESS_LIST_UPDATE,
        json!({
            "did": alice.did_hash(),
            "add": [did_hash(carol), bob.did_hash(), erin],
            "ext": include_dids(),
        }),
    )
    .await;
    assert_eq!(
        updated["added"],
        json!([did_hash(carol), bob.did_hash(), did_hash(erin)]),
        "{updated:#}"
    );
    assert_eq!(dids(&updated)[did_hash(erin)], erin, "{updated:#}");
    assert!(dids(&updated).get(did_hash(carol)).is_none());
    assert!(dids(&updated).get(bob.did_hash()).is_none());

    // A label is written once: a later fill doesn't change it.
    let store = env.mediator.store();
    store
        .did_label_fill(&did_hash(erin), "did:example:someone-else")
        .await
        .expect("fill");
    assert_eq!(
        store.did_labels_get(&[did_hash(erin)]).await.expect("read")[&did_hash(erin)],
        erin
    );

    // Bob, added by hash only, authenticates: his label is filled now.
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob authenticates");
    let listed = task(
        &env,
        &alice,
        ACCESS_LIST_LIST,
        json!({ "did": alice.did_hash(), "ext": include_dids() }),
    )
    .await;
    let mut entries: Vec<String> = serde_json::from_value(listed["entries"].clone()).unwrap();
    entries.sort();
    let mut expected = vec![did_hash(carol), bob.did_hash(), did_hash(erin)];
    expected.sort();
    assert_eq!(entries, expected, "{listed:#}");
    assert_eq!(
        dids(&listed)[bob.did_hash()],
        bob.did.as_str(),
        "{listed:#}"
    );
    assert_eq!(dids(&listed)[did_hash(erin)], erin);
    assert!(dids(&listed).get(did_hash(carol)).is_none());
}
