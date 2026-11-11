//! A forward is delivered only to a next hop the mediator already admits.
//!
//! A forward names its next hop in plaintext, so it is not evidence that the
//! next hop belongs on this mediator. These tests pin that a forward never
//! creates an account, in either `mediator_acl_mode`: a local next hop with no
//! account is refused with the uniform `delivery.refused`, and a next hop that
//! cannot be resolved is refused as retryable instead of being stored where
//! nothing would collect it.

mod common;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::store::types::Session;
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestEnvironment, TestMediator, TestUser, acl,
};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

async fn spawn(mode: AccessListModeType) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .acl_mode(mode)
        .spawn()
        .await
        .expect("spawn forwarding mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment")
}

/// Wrap a basic message from `sender` to `next` in a forward to this
/// mediator and send it. Returns the send result.
async fn send_forward(
    env: &TestEnvironment,
    sender: &TestUser,
    to: &str,
    next: &str,
) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "hello" }),
    )
    .to(to.to_string())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, to, Some(&sender.did), Some(&sender.did))
        .await
        .expect("authcrypt");
    let (_id, forward) = env
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &packed,
            env.mediator.did(),
            next,
            None,
            None,
        )
        .await
        .expect("wrap forward");
    env.atm
        .send_message(&sender.profile, &forward, &msg.id, false, false)
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[tokio::test]
async fn forward_to_a_local_did_without_an_account_is_refused() {
    init_tracing();

    for mode in [
        AccessListModeType::ExplicitDeny,
        AccessListModeType::ExplicitAllow,
    ] {
        let env = spawn(mode.clone()).await;
        let alice = env.add_user("Alice").await.expect("add Alice");
        // Dave's DID document names this mediator, but Dave has no account:
        // minted like any user, then removed.
        let dave = env.add_user("Dave").await.expect("add Dave");
        let admin = Session {
            account_type: AccountType::RootAdmin,
            ..Default::default()
        };
        env.mediator
            .store()
            .account_remove(&admin, &dave.did_hash())
            .await
            .expect("remove Dave's account");

        let error = send_forward(&env, &alice, &dave.did, &dave.did)
            .await
            .expect_err("a next hop with no account is refused");
        assert!(
            error.contains("delivery.refused"),
            "{mode:?}: expected delivery.refused, got: {error}"
        );
        assert!(
            !env.mediator
                .store()
                .account_exists(&dave.did_hash())
                .await
                .expect("account_exists"),
            "{mode:?}: the forward must not create an account for its next hop"
        );

        env.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn forward_to_an_unresolvable_next_hop_is_refused_as_retryable() {
    init_tracing();

    let env = spawn(AccessListModeType::ExplicitDeny).await;
    let alice = env.add_user("Alice").await.expect("add Alice");
    let bob = env.add_user("Bob").await.expect("add Bob");
    let nowhere = "did:example:no-such-recipient";

    let error = send_forward(&env, &alice, &bob.did, nowhere)
        .await
        .expect_err("an unresolvable next hop is refused");
    assert!(
        error.contains("did.resolve"),
        "expected did.resolve, got: {error}"
    );
    assert!(
        !env.mediator
            .store()
            .account_exists(&sha256::digest(nowhere))
            .await
            .expect("account_exists"),
        "the forward must not create an account for its next hop"
    );

    env.shutdown().await.expect("shutdown");
}
