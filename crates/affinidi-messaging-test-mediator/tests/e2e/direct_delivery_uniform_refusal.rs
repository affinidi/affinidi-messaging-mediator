//! DIDComm direct delivery answers the same way whatever DID it is addressed
//! to, unless the message is actually delivered.
//!
//! Whether this mediator serves a DID, whether that DID may receive, and what
//! its access list says are facts about *another* DID. A sender learns none of
//! them from a refusal: every recipient-side refusal is the same
//! `delivery.refused`, and every check about the sender itself (its session
//! binding, its own permission to send, the anonymous-sender policy) runs
//! before the recipient is looked up, so its answer cannot vary with the
//! recipient either.

use crate::common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestEnvironment, TestMediator, TestUser, acl,
};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

async fn spawn_direct_delivery_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with direct delivery enabled");
    TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator")
}

/// A resolvable `did:peer` that has no account on the mediator.
fn unknown_did(env: &TestEnvironment) -> String {
    let (did, _) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(env.mediator.did().to_string()),
    )
    .expect("generate did:peer");
    did
}

/// Send a basic message from `sender`'s session straight to `recipient`, with
/// no forward. `authcrypt` false anon-packs it, so the envelope names no
/// sender. Returns the mediator's refusal as a string.
async fn send_direct(
    env: &TestEnvironment,
    sender: &TestUser,
    recipient: &str,
    authcrypt: bool,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let mut msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "direct delivery" }),
    )
    .to(recipient.to_string())
    .created_time(now)
    .expires_time(now + 60);
    if authcrypt {
        msg = msg.from(sender.did.clone());
    }
    let msg = msg.finalize();
    let msg_id = msg.id.clone();

    let from = authcrypt.then_some(sender.did.as_str());
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, recipient, from, from)
        .await
        .map_err(|e| format!("pack_encrypted failed: {e}"))?;

    env.atm
        .send_message(&sender.profile, &packed, &msg_id, false, false)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// An unknown recipient, a recipient that may not receive, and a recipient
/// whose access list excludes the sender all get one identical answer.
#[tokio::test]
async fn unknown_and_refusing_recipients_get_identical_answers() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let no_receive = env.add_user("no-receive").await.expect("add user");
    let allowlist = env.add_user("allowlist").await.expect("add user");
    let open = env.add_user("open").await.expect("add user");

    let mut acls = acl::allow_all();
    acls.set_receive_messages(false, true, true)
        .expect("revoke receive_messages");
    env.mediator
        .set_acl(&no_receive.did, acls)
        .await
        .expect("set ACLs");

    let mut acls = acl::allow_all();
    acls.set_access_list_mode(AccessListModeType::ExplicitAllow, true, true)
        .expect("allowlist mode");
    env.mediator
        .set_acl(&allowlist.did, acls)
        .await
        .expect("set ACLs");

    // Control: an open recipient accepts, so the refusals below are about
    // the recipient and not a sender that can never deliver.
    send_direct(&env, &alice, &open.did, true)
        .await
        .expect("delivery to an open recipient must be accepted");

    let unknown = send_direct(&env, &alice, &unknown_did(&env), true)
        .await
        .expect_err("an unknown recipient must be refused");
    let cannot_receive = send_direct(&env, &alice, &no_receive.did, true)
        .await
        .expect_err("a recipient that may not receive must be refused");
    let access_list = send_direct(&env, &alice, &allowlist.did, true)
        .await
        .expect_err("a recipient whose access list excludes the sender must be refused");

    assert!(
        unknown.contains("delivery.refused"),
        "expected the uniform refusal, got: {unknown}"
    );
    assert_eq!(
        unknown, cannot_receive,
        "an unknown recipient and one that may not receive must be answered identically"
    );
    assert_eq!(
        unknown, access_list,
        "an unknown recipient and one whose access list refuses must be answered identically"
    );

    env.shutdown().await.expect("shutdown");
}

/// A sender-side refusal reads the same whether the recipient exists or not.
/// Here the envelope names no sender, so it cannot be bound to the session;
/// that is the answer for a served DID and for an unknown one alike.
#[tokio::test]
async fn sender_refusals_do_not_depend_on_the_recipient() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let known = send_direct(&env, &alice, &bob.did, false)
        .await
        .expect_err("an anonymous envelope on an authenticated session must be refused");
    let unknown = send_direct(&env, &alice, &unknown_did(&env), false)
        .await
        .expect_err("an anonymous envelope on an authenticated session must be refused");

    assert_eq!(
        known, unknown,
        "whether the recipient exists must not change the answer to a sender-side refusal"
    );
    assert!(
        !known.contains("delivery.refused"),
        "the refusal is about the sender, so it is not the recipient-side one: {known}"
    );

    env.shutdown().await.expect("shutdown");
}

/// A sender without `SEND_MESSAGES` gets the same refusal whether the
/// recipient exists or not.
#[tokio::test]
async fn a_sender_that_may_not_send_is_answered_the_same_for_any_recipient() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let mut acls = acl::allow_all();
    acls.set_send_messages(false, true, true)
        .expect("revoke send_messages");
    env.mediator
        .set_acl(&alice.did, acls)
        .await
        .expect("set ACLs");

    let known = send_direct(&env, &alice, &bob.did, true)
        .await
        .expect_err("a sender without SEND_MESSAGES must be refused");
    let unknown = send_direct(&env, &alice, &unknown_did(&env), true)
        .await
        .expect_err("a sender without SEND_MESSAGES must be refused");

    assert!(
        known.contains("authorization.send"),
        "expected the sender-side refusal, got: {known}"
    );
    assert_eq!(
        known, unknown,
        "whether the recipient exists must not change the answer to a sender without SEND_MESSAGES"
    );

    env.shutdown().await.expect("shutdown");
}

/// With session matching off and anonymous direct delivery not allowed, an
/// anonymous envelope gets the same refusal whether the recipient exists or
/// not.
#[tokio::test]
async fn an_anonymous_sender_is_answered_the_same_for_any_recipient() {
    init_tracing();
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .force_session_did_match(false)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let known = send_direct(&env, &alice, &bob.did, false)
        .await
        .expect_err("anonymous direct delivery must be refused");
    let unknown = send_direct(&env, &alice, &unknown_did(&env), false)
        .await
        .expect_err("anonymous direct delivery must be refused");

    assert!(
        known.contains("message.anonymous"),
        "expected the anonymous-sender refusal, got: {known}"
    );
    assert_eq!(
        known, unknown,
        "whether the recipient exists must not change the answer to an anonymous sender"
    );

    env.shutdown().await.expect("shutdown");
}
