//! A Trust Task that asks for it (`"x-errorFormat": "trust-task-error"`) is
//! refused with a `trust-task-error` document (Trust Tasks SPEC §8) instead of
//! a DIDComm problem report, over DIDComm and over TSP; one that does not ask
//! is refused with a problem report, as before.
//!
//! The documents are built and signed by hand, as the SDK this workspace pins
//! does not ask yet.

mod common;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::messages::FetchDeletePolicy;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::protocols::mux::sign_revoke_all;
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{
    TestEnvironment, TestMediator, TestUser, TrustTaskVerification,
};
use affinidi_secrets_resolver::secrets::KeyType;
use common::init_tracing;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const ASK: &str = "x-errorFormat";
const ERROR_TYPE: &str = "https://trusttasks.org/spec/trust-task-error/0.6";
const REVOKE_ALL: &str = "https://trusttasks.org/spec/messaging/mux/revoke-all/0.1";
const ADMIN_REVOKE_ALL: &str = "https://trusttasks.org/spec/messaging/mux/admin-revoke-all/0.1";
const ACK: &str = "https://trusttasks.org/spec/messaging/mux/ack/0.1";

async fn env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .trust_task_verification(TrustTaskVerification::Enforce)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

async fn online(env: &TestEnvironment, alias: &str, role: Option<AccountType>) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    if let Some(role) = role {
        env.mediator
            .store()
            .account_set_role(&user.did_hash(), &role)
            .await
            .expect("set role");
    }
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("websocket");
    user
}

/// A signed request from `from`, asking for `trust-task-error` documents
/// when `ask`.
async fn request(
    env: &TestEnvironment,
    from: &TestUser,
    type_uri: &str,
    payload: Value,
    ask: bool,
) -> Value {
    let now = chrono::Utc::now();
    let mut doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuer": from.did,
        "recipient": env.mediator.did(),
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    if ask {
        doc[ASK] = json!("trust-task-error");
    }
    let key = from
        .secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .expect("an Ed25519 signing key");
    sign_trust_task(&doc, key, SignOptions::new())
        .await
        .expect("sign the task")
}

/// What came back over DIDComm: the reply message, or the SDK's error.
async fn send(env: &TestEnvironment, from: &TestUser, doc: Value) -> Result<Message, String> {
    let mediator_did = env.mediator.did().to_string();
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
        Ok(SendMessageResponse::Message(reply)) => Ok(*reply),
        Ok(other) => panic!("expected a reply message, got {other:?}"),
        Err(e) => Err(e.to_string()),
    }
}

/// The reply is a `trust-task-error` for `doc`, issued by the mediator,
/// threaded to the request, naming it, and signed. Returns its payload.
fn error_for(env: &TestEnvironment, reply: &Message, doc: &Value) -> Value {
    assert_eq!(reply.typ, ENVELOPE_TYPE, "{reply:?}");
    let body = &reply.body;
    assert_eq!(body["type"], ERROR_TYPE, "{body:#}");
    assert_eq!(body["issuer"], env.mediator.did());
    assert_eq!(body["threadId"], doc["id"], "{body:#}");
    assert_eq!(body["payload"]["inResponseTo"]["typeUri"], doc["type"]);
    assert_eq!(body["payload"]["inResponseTo"]["id"], doc["id"]);
    assert!(
        body.get("proof").is_some(),
        "signed as a response is: {body:#}"
    );
    body["payload"].clone()
}

#[tokio::test]
async fn an_epoch_mismatch_carries_the_current_epoch_as_a_typed_detail() {
    init_tracing();
    let env = env().await;
    let member = online(&env, "member", None).await;
    let admin = online(&env, "admin", Some(AccountType::Admin)).await;
    let mediator_did = env.mediator.did().to_string();

    // The member's own revoke-all, naming an epoch after the current (0).
    let statement = sign_revoke_all(&env.atm, &member.did, &mediator_did, 5)
        .await
        .expect("sign revoke-all");
    let doc = request(
        &env,
        &member,
        REVOKE_ALL,
        json!({ "revocation": statement }),
        true,
    )
    .await;
    let reply = send(&env, &member, doc.clone()).await.expect("an answer");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "messaging/mux/revoke-all:epochMismatch");
    assert_eq!(p["details"], json!({ "currentEpoch": 0 }));
    assert_eq!(p["retryable"], false);
    assert!(
        p["message"]
            .as_str()
            .unwrap()
            .contains("current epoch is 0")
    );

    // The administrator's.
    let doc = request(
        &env,
        &admin,
        ADMIN_REVOKE_ALL,
        json!({ "did": member.did, "epoch": 5 }),
        true,
    )
    .await;
    let reply = send(&env, &admin, doc.clone()).await.expect("an answer");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "messaging/mux/admin-revoke-all:epochMismatch");
    assert_eq!(p["details"], json!({ "currentEpoch": 0 }));
}

#[tokio::test]
async fn a_request_that_does_not_ask_is_refused_with_a_problem_report() {
    init_tracing();
    let env = env().await;
    let member = online(&env, "member", None).await;
    let statement = sign_revoke_all(&env.atm, &member.did, env.mediator.did(), 5)
        .await
        .expect("sign revoke-all");
    let doc = request(
        &env,
        &member,
        REVOKE_ALL,
        json!({ "revocation": statement }),
        false,
    )
    .await;
    let refusal = match send(&env, &member, doc).await {
        Err(e) => e,
        Ok(reply) => {
            assert!(reply.typ.contains("problem-report"), "{reply:?}");
            reply.body.to_string()
        }
    };
    assert!(
        refusal.contains("messaging/mux/revoke-all:epochMismatch"),
        "{refusal}"
    );
    assert!(refusal.contains("current epoch is 0"), "{refusal}");
}

#[tokio::test]
async fn a_mediator_code_is_sent_as_a_standard_code_and_kept_in_details() {
    init_tracing();
    let env = env().await;
    let member = online(&env, "member", None).await;
    let someone = online(&env, "someone", None).await;
    // Not an administrator: refused before anything is looked at.
    let doc = request(
        &env,
        &someone,
        ADMIN_REVOKE_ALL,
        json!({ "did": member.did, "epoch": 0 }),
        true,
    )
    .await;
    let reply = send(&env, &someone, doc.clone()).await.expect("an answer");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "permissionDenied", "{p:#}");
    assert!(
        p["details"]["mediatorCode"]
            .as_str()
            .is_some_and(|c| c.starts_with("authorization.")),
        "{p:#}"
    );
}

/// The refusal of `messaging/mux/ack` is pushed to the connection like its
/// answer, never stored: a stored one would need acknowledging in turn.
#[tokio::test]
async fn a_refused_mux_ack_is_pushed_not_stored() {
    init_tracing();
    let env = env().await;
    let user = online(&env, "user", None).await;
    // On an ordinary connection, not a mux one.
    let doc = request(
        &env,
        &user,
        ACK,
        json!({ "messageIds": ["not-a-message"] }),
        true,
    )
    .await;
    let reply = send(&env, &user, doc.clone()).await.expect("an answer");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "messaging/mux:notMuxConnection", "{p:#}");
    let inbox = env
        .atm
        .fetch_messages(
            &user.profile,
            &FetchOptions {
                limit: 10,
                start_id: None,
                delete_policy: FetchDeletePolicy::DoNotDelete,
            },
        )
        .await
        .expect("fetch");
    assert!(
        inbox.success.is_empty(),
        "nothing stored: {:?}",
        inbox.success
    );
}

#[cfg(feature = "tsp")]
#[tokio::test]
async fn over_tsp_a_refusal_is_sealed_back_as_a_trust_task_error() {
    use affinidi_messaging_sdk::TspPolicy;
    use affinidi_messaging_sdk::protocols::tsp::RelationshipState;

    init_tracing();
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Required)
        .await
        .expect("spawn with TSP required");
    let alice = env.add_user("alice").await.expect("add alice");
    let mediator_vid = env.mediator.did().to_string();
    for (ours, theirs) in [(&alice.did, &mediator_vid), (&mediator_vid, &alice.did)] {
        env.relationship_store
            .set(ours, theirs, RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship with the mediator");
    }

    // A payload the task's schema refuses.
    let doc = request(
        &env,
        &alice,
        "https://trusttasks.org/spec/messaging/account/get/0.1",
        json!({ "notAMember": true }),
        true,
    )
    .await;
    env.atm
        .tsp()
        .send(
            &alice.profile,
            &mediator_vid,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("a refusal that asked for a document is not an error on the send");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let body = loop {
        let page = env
            .atm
            .fetch_messages(
                &alice.profile,
                &FetchOptions {
                    limit: 20,
                    start_id: None,
                    delete_policy: FetchDeletePolicy::DoNotDelete,
                },
            )
            .await
            .expect("fetch");
        let mut found = None;
        for element in &page.success {
            let Some(stored) = &element.msg else { continue };
            let Ok((payload, _)) = env.atm.tsp().unpack(&alice.profile, stored).await else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(&payload) else {
                continue;
            };
            if v["threadId"] == doc["id"] {
                found = Some(v);
            }
        }
        if let Some(v) = found {
            break v;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no trust-task-error in the inbox"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert_eq!(body["type"], ERROR_TYPE, "{body:#}");
    assert_eq!(body["payload"]["inResponseTo"]["id"], doc["id"]);
    assert_eq!(body["payload"]["code"], "malformedRequest", "{body:#}");
    assert_eq!(
        body["payload"]["details"]["mediatorCode"], "message.trust_task.malformed",
        "{body:#}"
    );
}
