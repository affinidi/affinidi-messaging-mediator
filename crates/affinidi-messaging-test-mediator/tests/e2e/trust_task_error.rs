//! A refused Trust Task is answered with a `trust-task-error` document
//! (Trust Tasks SPEC §8) instead of a DIDComm problem report, over DIDComm
//! and over TSP, whether or not it asks (`"x-errorFormat":
//! "trust-task-error"`). The code is always a Trust Task code: a standard
//! one or one the task's specification declares.
//!
//! The documents are built and signed by hand, so each test controls whether
//! the request asks.

use crate::common;

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
async fn a_request_that_does_not_ask_is_refused_with_a_document_too() {
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
    let reply = send(&env, &member, doc.clone()).await.expect("an answer");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "messaging/mux/revoke-all:epochMismatch");
    assert_eq!(p["details"], json!({ "currentEpoch": 0 }));
}

#[tokio::test]
async fn a_refusal_outside_the_task_specs_is_a_standard_code() {
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
    assert!(p.get("details").is_none(), "no mediator code: {p:#}");
}

/// Over REST the refusal document is stored for the sender, and the POST's
/// answer names it (`Stored`), as it names a response: that id is how a
/// REST client collects either (`affinidi-messaging-sdk` from 0.46.3; 0.46.2
/// asked for the request's own digest and so found neither). (TSP over REST
/// collects its reply from the inbox by thread id instead:
/// `over_tsp_a_refusal_is_sealed_back_as_a_trust_task_error`.)
#[tokio::test]
async fn over_rest_the_refusal_is_named_in_the_posts_answer() {
    use affinidi_messaging_sdk::messages::GetMessagesRequest;

    init_tracing();
    let env = env().await;
    // No websocket: the SDK sends over REST.
    let member = env.add_user("member").await.expect("add user");
    let someone = env.add_user("someone").await.expect("add user");
    let doc = request(
        &env,
        &someone,
        ADMIN_REVOKE_ALL,
        json!({ "did": member.did, "epoch": 0 }),
        true,
    )
    .await;
    let mediator_did = env.mediator.did().to_string();
    let secs = chrono::Utc::now().timestamp() as u64;
    let msg = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        doc.clone(),
    )
    .to(mediator_did.clone())
    .from(someone.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&someone.did), None)
        .await
        .expect("authcrypt");
    let answer = env
        .atm
        .send_message(&someone.profile, &packed, &msg_id, false, false)
        .await
        .expect("the POST is answered, not refused");
    let SendMessageResponse::RestAPI(answer) = answer else {
        panic!("a REST answer: {answer:?}");
    };
    let stored = answer["data"]["Stored"]["messages"]
        .as_array()
        .expect("the answer names what was stored");
    assert_eq!(stored.len(), 1, "{answer:#}");
    assert_eq!(stored[0][0], someone.did.as_str(), "stored for the sender");
    let id = stored[0][1].as_str().expect("its id").to_string();

    let fetched = env
        .atm
        .get_messages(
            &someone.profile,
            &GetMessagesRequest {
                message_ids: vec![id],
                delete: true,
            },
        )
        .await
        .expect("get");
    let packed_reply = fetched.success[0].msg.as_ref().expect("the stored reply");
    let (reply, _) = env.atm.unpack(packed_reply).await.expect("unpack");
    let p = error_for(&env, &reply, &doc);
    assert_eq!(p["code"], "permissionDenied", "{p:#}");
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
    assert!(body["payload"].get("details").is_none(), "{body:#}");
}

/// A request the session could never have had answered — a TSP frame signed
/// by another DID than the session's — is refused with a problem report on
/// the connection, never with a signed document stored for its signer.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_sender_that_is_not_the_session_gets_no_document() {
    use affinidi_messaging_sdk::protocols::tsp::RelationshipState;

    init_tracing();
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        // So the frame reaches the Trust Task pipeline rather than the
        // earlier session check.
        .force_session_did_match(false)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_vid = env.mediator.did().to_string();
    for user in [&alice, &bob] {
        for (ours, theirs) in [(&user.did, &mediator_vid), (&mediator_vid, &user.did)] {
            env.relationship_store
                .set(ours, theirs, RelationshipState::Bidirectional)
                .await
                .expect("seed the relationship with the mediator");
        }
    }

    // Bob's request, signed and sealed by bob, posted on alice's session.
    let doc = request(
        &env,
        &bob,
        "https://trusttasks.org/spec/messaging/account/get/0.1",
        json!({}),
        true,
    )
    .await;
    let frame = env
        .atm
        .tsp()
        .pack(
            &bob.profile,
            &mediator_vid,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("pack as bob");
    let sent = env.atm.tsp().send_raw(&alice.profile, &frame).await;
    assert!(sent.is_err(), "refused on the connection: {sent:?}");

    // Nothing was signed and stored for bob.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let inbox = env
        .atm
        .fetch_messages(
            &bob.profile,
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
