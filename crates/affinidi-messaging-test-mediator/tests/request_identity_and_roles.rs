//! Who a request to the mediator acts for, and what each role may do.
//!
//! - A request the mediator serves (trust ping, Trust Tasks, pickup) needs an
//!   authenticated session whose DID sent it. The anonymous inter-mediator relay
//!   session may only relay, and `force_session_did_match = false` does not let
//!   one account's session carry another account's requests.
//! - Granting or changing a privileged role (admin, root admin, the mediator's
//!   own account) is for a root admin; a privileged account is changed or
//!   removed only by itself or a root admin; an account whose role is `Unknown`
//!   is gated like a standard one.

// The 0.1 `messaging/*` types are marked superseded upstream.
#![allow(deprecated)]

mod common;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::types::accounts::AccountType as StoreType;
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser, acl};
use serde_json::json;
use uuid::Uuid;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A relay-enabled mediator: requests without a bearer token are admitted as
/// the anonymous relay session.
async fn relay_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        .spawn()
        .await
        .expect("spawn relay mediator");
    TestEnvironment::new(mediator).await.expect("environment")
}

fn trust_ping(from: &str, to: &str) -> Message {
    Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping".to_string(),
        json!({ "response_requested": true }),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize()
}

/// A `messaging/account/get` Trust Task for `from`'s own account.
fn account_get_task(from: &TestUser, mediator_did: &str) -> Message {
    let issued = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let task = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/messaging/account/get/0.1",
        "issuer": from.did,
        "recipient": mediator_did,
        "issuedAt": issued,
        "payload": { "did": from.did_hash() },
    });
    Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        task,
    )
    .from(from.did.clone())
    .to(mediator_did.to_string())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize()
}

/// Authcrypt `msg` from `sender` to `to`.
async fn authcrypt(env: &TestEnvironment, msg: &Message, to: &str, sender: &TestUser) -> String {
    env.atm
        .pack_encrypted(msg, to, Some(&sender.did), None)
        .await
        .expect("authcrypt")
        .0
}

/// POST `body` to `/inbound` with no bearer token.
async fn post_anonymous(env: &TestEnvironment, body: String) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("{}inbound", env.mediator.endpoint()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("anonymous inbound");
    let status = response.status().as_u16();
    (status, response.text().await.unwrap_or_default())
}

#[tokio::test]
async fn the_anonymous_relay_session_may_only_relay() {
    common::init_tracing();
    let env = relay_env().await;
    let mediator_did = env.mediator.did().to_string();
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");

    // Requests the mediator would serve for alice are refused without a session.
    let pickup_status = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/messagepickup/3.0/status-request".to_string(),
        json!({}),
    )
    .from(alice.did.clone())
    .to(mediator_did.clone())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize();
    for (name, msg) in [
        ("trust ping", trust_ping(&alice.did, &mediator_did)),
        ("trust task", account_get_task(&alice, &mediator_did)),
        ("pickup status request", pickup_status),
    ] {
        let packed = authcrypt(&env, &msg, &mediator_did, &alice).await;
        let (status, body) = post_anonymous(&env, packed).await;
        assert_eq!(status, 401, "{name} on the relay session: {body}");
        assert!(
            body.contains("authorization.authentication_required"),
            "{name} is refused as needing authentication: {body}"
        );
    }

    // A forward is still relayed on the same session.
    let inner_msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "relayed" }),
    )
    .from(alice.did.clone())
    .to(bob.did.clone())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize();
    let inner = authcrypt(&env, &inner_msg, &bob.did, &alice).await;
    let (_, packed) = env
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &inner,
            &mediator_did,
            &bob.did,
            None,
            None,
        )
        .await
        .expect("wrap a forward");
    let (status, body) = post_anonymous(&env, packed).await;
    assert_eq!(status, 200, "a forward is relayed anonymously: {body}");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn a_request_must_come_from_the_session_did_even_without_session_matching() {
    common::init_tracing();
    let mediator = TestMediator::builder()
        .force_session_did_match(false)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let mediator_did = env.mediator.did().to_string();
    let alice = env.add_user("alice").await.expect("alice");
    let mallory = env.add_user("mallory").await.expect("mallory");

    for (name, msg) in [
        ("trust ping", trust_ping(&alice.did, &mediator_did)),
        ("trust task", account_get_task(&alice, &mediator_did)),
    ] {
        let id = msg.id.clone();
        let packed = authcrypt(&env, &msg, &mediator_did, &alice).await;
        let refused = env
            .atm
            .send_message(&mallory.profile, &packed, &id, false, false)
            .await
            .expect_err("alice's request on mallory's session is refused");
        assert!(
            format!("{refused:?}").contains("session_mismatch"),
            "{name} refused as a session mismatch: {refused:?}"
        );
    }

    // Mallory's own request on her own session is served.
    let own = trust_ping(&mallory.did, &mediator_did);
    let id = own.id.clone();
    let packed = authcrypt(&env, &own, &mediator_did, &mallory).await;
    env.atm
        .send_message(&mallory.profile, &packed, &id, false, false)
        .await
        .expect("mallory's own ping is accepted");

    env.shutdown().await.expect("shutdown");
}

/// A user with a live stream whose stored role is `role`.
async fn with_role(env: &TestEnvironment, alias: &str, role: StoreType) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("set role");
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("enable websocket");
    user
}

async fn stored_role(env: &TestEnvironment, did_hash: &str) -> StoreType {
    env.mediator
        .store()
        .account_get(did_hash)
        .await
        .expect("account_get")
        .expect("account exists")
        ._type
}

#[tokio::test]
async fn only_a_root_admin_creates_a_privileged_account() {
    use affinidi_messaging_sdk::tasks::messaging::account::add::v0_2::AccountType;

    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = with_role(&env, "admin", StoreType::Admin).await;
    let root = with_role(&env, "root", StoreType::RootAdmin).await;

    for (hash, role) in [
        ("roles-admin-by-admin", AccountType::Admin),
        ("roles-mediator-by-admin", AccountType::Mediator),
        ("roles-root-by-admin", AccountType::RootAdmin),
    ] {
        let refused = env
            .atm
            .trust_tasks()
            .account_add(&admin.profile, hash.to_string(), role, None)
            .await;
        assert!(refused.is_err(), "an admin may not create a {role} account");
        assert!(
            !env.mediator
                .store()
                .account_exists(hash)
                .await
                .expect("account_exists"),
            "no {role} account is created"
        );
    }

    // An admin still creates standard accounts; a root admin creates admins.
    env.atm
        .trust_tasks()
        .account_add(
            &admin.profile,
            "roles-standard-by-admin".to_string(),
            AccountType::Standard,
            None,
        )
        .await
        .expect("an admin creates a standard account");
    let created = env
        .atm
        .trust_tasks()
        .account_add(
            &root.profile,
            "roles-admin-by-root".to_string(),
            AccountType::Admin,
            None,
        )
        .await
        .expect("a root admin creates an admin account");
    assert_eq!(created.account_type.to_string(), "admin");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn only_a_root_admin_grants_or_changes_a_privileged_role() {
    use affinidi_messaging_sdk::tasks::messaging::account::update::v0_2::AccountType;

    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = with_role(&env, "admin", StoreType::Admin).await;
    let root = with_role(&env, "root", StoreType::RootAdmin).await;
    let other_admin = with_role(&env, "other-admin", StoreType::Admin).await;
    let bob = env.add_user("bob").await.expect("bob");
    let mediator_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.did());

    for (target, role) in [
        (bob.did_hash(), AccountType::Admin),
        (bob.did_hash(), AccountType::Mediator),
        (other_admin.did_hash(), AccountType::Standard),
        (mediator_hash.clone(), AccountType::Standard),
    ] {
        let before = stored_role(&env, &target).await;
        let refused = env
            .atm
            .trust_tasks()
            .account_update(&admin.profile, Some(target.clone()), Some(role), None, None)
            .await;
        assert!(refused.is_err(), "an admin may not set {target} to {role}");
        assert_eq!(
            stored_role(&env, &target).await,
            before,
            "{target} unchanged"
        );
    }

    env.atm
        .trust_tasks()
        .account_update(
            &root.profile,
            Some(bob.did_hash()),
            Some(AccountType::Admin),
            None,
            None,
        )
        .await
        .expect("a root admin promotes bob");
    assert_eq!(stored_role(&env, &bob.did_hash()).await, StoreType::Admin);

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn a_privileged_account_is_changed_or_removed_only_by_itself_or_a_root_admin() {
    use affinidi_messaging_sdk::tasks::messaging::account::update::v0_2::MediatorAcl;

    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = with_role(&env, "admin", StoreType::Admin).await;
    let other_admin = with_role(&env, "other-admin", StoreType::Admin).await;
    let root = with_role(&env, "root", StoreType::RootAdmin).await;
    let mediator_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.did());

    let block = || -> MediatorAcl {
        MediatorAcl::builder()
            .blocked(Some(true))
            .try_into()
            .expect("MediatorAcl has no required member")
    };
    for target in [other_admin.did_hash(), mediator_hash] {
        let refused = env
            .atm
            .trust_tasks()
            .account_update(
                &admin.profile,
                Some(target.clone()),
                None,
                Some(block()),
                None,
            )
            .await;
        assert!(refused.is_err(), "an admin may not change {target}'s ACL");
    }
    let refused = env
        .atm
        .trust_tasks()
        .account_remove(&admin.profile, Some(other_admin.did_hash()))
        .await;
    assert!(refused.is_err(), "an admin may not remove another admin");
    assert!(
        env.mediator
            .store()
            .account_exists(&other_admin.did_hash())
            .await
            .expect("account_exists"),
        "the other admin's account remains"
    );

    let removed = env
        .atm
        .trust_tasks()
        .account_remove(&root.profile, Some(other_admin.did_hash()))
        .await
        .expect("a root admin removes an admin");
    assert!(removed);

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn an_unknown_role_is_gated_like_a_standard_account() {
    let env = TestEnvironment::spawn().await.expect("environment");
    let carol = env.add_user("carol").await.expect("carol");
    let mut acls = acl::allow_all();
    acls.set_self_manage_list(false);
    env.mediator
        .set_acl(&carol.did, acls)
        .await
        .expect("withhold self-managed access list");
    let user = with_role(&env, "unknown", StoreType::Unknown).await;
    let mut acls = acl::allow_all();
    acls.set_self_manage_list(false);
    env.mediator
        .set_acl(&user.did, acls)
        .await
        .expect("withhold self-managed access list");

    let refused = env
        .atm
        .trust_tasks()
        .access_list_update(&user.profile, None, false, vec![carol.did_hash()], vec![])
        .await;
    assert!(
        refused.is_err(),
        "an account whose role did not decode may not write an access list it does not self-manage"
    );

    // Nor does it administer anything.
    let refused = env
        .atm
        .trust_tasks()
        .account_list(&user.profile, None, None, None)
        .await;
    assert!(refused.is_err(), "an Unknown role may not list accounts");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn an_admin_changes_only_its_own_or_a_standard_accounts_access_list() {
    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = with_role(&env, "admin", StoreType::Admin).await;
    let other_admin = with_role(&env, "other-admin", StoreType::Admin).await;
    let root = with_role(&env, "root", StoreType::RootAdmin).await;
    let unknown = env.add_user("unknown").await.expect("unknown");
    env.mediator
        .store()
        .account_set_role(&unknown.did_hash(), &StoreType::Unknown)
        .await
        .expect("set Unknown role");
    let bob = env.add_user("bob").await.expect("bob");
    let carol = env.add_user("carol").await.expect("carol");
    let mediator_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.did());
    let admin_did_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.admin_did());

    for target in [
        root.did_hash(),
        other_admin.did_hash(),
        mediator_hash,
        admin_did_hash,
        unknown.did_hash(),
    ] {
        for (clear, add) in [(true, vec![]), (false, vec![carol.did_hash()])] {
            let refused = env
                .atm
                .trust_tasks()
                .access_list_update(&admin.profile, Some(target.clone()), clear, add, vec![])
                .await;
            assert!(
                refused.is_err(),
                "an admin may not change {target}'s access list (clear={clear})"
            );
        }
    }

    // Its own list and a standard account's list are still the admin's to change.
    for target in [admin.did_hash(), bob.did_hash()] {
        env.atm
            .trust_tasks()
            .access_list_update(
                &admin.profile,
                Some(target),
                false,
                vec![carol.did_hash()],
                vec![],
            )
            .await
            .expect("an admin changes its own or a standard account's list");
    }
    // A root admin changes another admin's list.
    env.atm
        .trust_tasks()
        .access_list_update(
            &root.profile,
            Some(other_admin.did_hash()),
            false,
            vec![carol.did_hash()],
            vec![],
        )
        .await
        .expect("a root admin changes an admin's list");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn an_admin_may_not_change_an_account_whose_role_did_not_decode() {
    use affinidi_messaging_sdk::tasks::messaging::account::update::v0_2::AccountType;

    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = with_role(&env, "admin", StoreType::Admin).await;
    let root = with_role(&env, "root", StoreType::RootAdmin).await;
    let unknown = env.add_user("unknown").await.expect("unknown");
    env.mediator
        .store()
        .account_set_role(&unknown.did_hash(), &StoreType::Unknown)
        .await
        .expect("set Unknown role");

    let refused = env
        .atm
        .trust_tasks()
        .account_update(
            &admin.profile,
            Some(unknown.did_hash()),
            Some(AccountType::Standard),
            None,
            None,
        )
        .await;
    assert!(refused.is_err(), "an admin may not reset an Unknown role");
    assert_eq!(
        stored_role(&env, &unknown.did_hash()).await,
        StoreType::Unknown
    );

    env.atm
        .trust_tasks()
        .account_update(
            &root.profile,
            Some(unknown.did_hash()),
            Some(AccountType::Standard),
            None,
            None,
        )
        .await
        .expect("a root admin repairs it");
    assert_eq!(
        stored_role(&env, &unknown.did_hash()).await,
        StoreType::Standard
    );

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn the_configured_accounts_keep_their_roles() {
    use affinidi_messaging_sdk::tasks::messaging::account::update::v0_2::AccountType;

    let env = TestEnvironment::spawn().await.expect("environment");
    let root = with_role(&env, "root", StoreType::RootAdmin).await;
    let mediator_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.did());
    let admin_did_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(env.mediator.admin_did());

    for (target, role) in [
        (mediator_hash, AccountType::Standard),
        (admin_did_hash, AccountType::Admin),
    ] {
        let before = stored_role(&env, &target).await;
        let refused = env
            .atm
            .trust_tasks()
            .account_update(&root.profile, Some(target.clone()), Some(role), None, None)
            .await
            .expect_err("a configured account's role is not changed by a Trust Task");
        assert!(
            format!("{refused:?}").contains("account.update.protected"),
            "refused as protected: {refused:?}"
        );
        assert_eq!(
            stored_role(&env, &target).await,
            before,
            "{target} unchanged"
        );
    }

    env.shutdown().await.expect("shutdown");
}
