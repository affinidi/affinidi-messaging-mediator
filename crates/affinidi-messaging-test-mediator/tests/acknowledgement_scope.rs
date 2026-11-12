//! A client's delete by message id removes the right copies when the same
//! bytes are held for several recipients.
//!
//! An acknowledgement — the REST delete a client makes after taking a message,
//! as itself or for a mux member — removes the acknowledging recipient's own
//! copy, never a copy of the same bytes held for someone else. Repeating it (a
//! redelivered message deleted twice) answers not found. A sender deleting
//! what it queued, with no copy of its own, still withdraws it.
//!
//! The copies are stored straight into the mediator's store: the same bytes
//! for two recipients is what one multi-recipient message forwarded to two
//! local recipients produces, and the store is where that is set up exactly.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_mediator::mux::{
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{
    did_identity::did_hash, store::mux::MuxLimits, types::acls::MediatorACLSet,
};
use affinidi_messaging_sdk::messages::DeleteMessageRequest;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `member` grants `principal` receive + pickup + delete, stored as the
/// `messaging/mux/grant` task would store it.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) {
    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .expect("member's Ed25519 authentication key");
    let t = now();
    let statement = sign_trust_task(
        &json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(),
            "principal": principal.did,
            "scope": ["receive", "pickup", "delete"],
            "epoch": 0,
            "iat": t,
            "exp": t + 3600,
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign grant");

    let store = env.mediator.store();
    let verifier = StatementVerifier::new(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap(),
    );
    let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
    let ctx = Ctx {
        store: &*store,
        verifier: &verifier,
        mediator_did: env.mediator.did(),
        limits: MuxLimits::default(),
        default_acl: &acl,
        now: now(),
    };
    store_grant(&ctx, &member.did, &statement)
        .await
        .unwrap_or_else(|e| panic!("store grant: {e}"));
}

/// Stores `body` for each of `recipients`, sent by `from`. Returns the id,
/// which is the same for every copy.
async fn store_copies(
    env: &TestEnvironment,
    body: &str,
    from: &TestUser,
    recipients: &[&TestUser],
) -> String {
    let store = env.mediator.store();
    let mut id = String::new();
    for to in recipients {
        id = store
            .store_message(
                "test",
                body,
                &did_hash(&to.did),
                Some(&did_hash(&from.did)),
                now() + 3600,
                0,
            )
            .await
            .expect("store_message");
    }
    id
}

/// Stores one copy of `body` for `to`, sent by `from`. Returns the id.
async fn store_copy(env: &TestEnvironment, body: &str, from: &TestUser, to: &TestUser) -> String {
    store_copies(env, body, from, &[to]).await
}

/// Whether `to` still holds its copy of `id`.
async fn holds(env: &TestEnvironment, to: &TestUser, id: &str) -> bool {
    env.mediator
        .store()
        .get_message(&did_hash(&to.did), id)
        .await
        .expect("get_message")
        .is_some_and(|m| m.to_address.as_deref() == Some(did_hash(&to.did).as_str()))
}

/// REST delete as `user`: the ids deleted and the per-id errors.
async fn rest_delete(
    env: &TestEnvironment,
    user: &TestUser,
    id: &str,
) -> (Vec<String>, Vec<(String, String)>) {
    let response = env
        .atm
        .delete_messages_direct(
            &user.profile,
            &DeleteMessageRequest {
                message_ids: vec![id.to_string()],
            },
        )
        .await
        .expect("delete request");
    (response.success, response.errors)
}

/// A DID that sent the same bytes to itself and to another account
/// acknowledges its copy, then acknowledges it again (a redelivered copy).
/// The second delete answers not found; the other account's copy stays.
#[tokio::test]
async fn a_repeated_acknowledgement_leaves_another_recipients_copy() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let a = env.add_user("self-and-other-a").await.unwrap();
    let b = env.add_user("self-and-other-b").await.unwrap();

    let id = store_copies(&env, "{\"protected\":\"to-a-and-b\"}", &a, &[&a, &b]).await;
    assert!(holds(&env, &a, &id).await && holds(&env, &b, &id).await);

    let (deleted, errors) = rest_delete(&env, &a, &id).await;
    assert_eq!(deleted, std::slice::from_ref(&id), "{errors:?}");
    assert!(!holds(&env, &a, &id).await, "a's copy is gone");
    assert!(holds(&env, &b, &id).await, "b's copy stays");

    let (deleted, errors) = rest_delete(&env, &a, &id).await;
    assert!(deleted.is_empty(), "nothing more is deleted: {deleted:?}");
    assert!(
        errors
            .iter()
            .any(|(e_id, e)| e_id == &id && e.contains("database.message.delete.not_found")),
        "the repeat is already gone: {errors:?}"
    );
    assert!(holds(&env, &b, &id).await, "b's copy still stays");
}

/// A sender with no copy of its own deleting what it queued still withdraws
/// it — the outbox flush a service runs on start.
#[tokio::test]
async fn a_sender_still_withdraws_what_it_queued() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let sender = env.add_user("withdrawing-sender").await.unwrap();
    let x = env.add_user("withdrawn-from-x").await.unwrap();
    let y = env.add_user("withdrawn-from-y").await.unwrap();

    let id = store_copies(&env, "{\"protected\":\"withdrawn\"}", &sender, &[&x, &y]).await;
    let (deleted, errors) = rest_delete(&env, &sender, &id).await;
    assert_eq!(deleted, std::slice::from_ref(&id), "{errors:?}");
    assert!(!holds(&env, &x, &id).await, "x's copy is withdrawn");
    assert!(!holds(&env, &y, &id).await, "y's copy is withdrawn");
}

/// A mux principal sends the same bytes to a member it holds a grant for and
/// to another account, then acknowledges the member's copy over REST with its
/// session. Only the member's copy goes; acknowledging again leaves the other
/// account's copy too.
#[tokio::test]
async fn a_mux_acknowledgement_removes_the_members_copy_only() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("ack-principal").await.unwrap();
    let member = env.add_user("ack-member").await.unwrap();
    let other = env.add_user("ack-other").await.unwrap();
    grant(&env, &member, &principal).await;

    // The principal's mux connection: its session may delete for the member.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate principal");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("upgrade");
    // `ready`, then `attached` for the member: the connection is admitted.
    for _ in 0..2 {
        loop {
            match timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame within 5s")
                .expect("socket open")
                .expect("frame")
            {
                Message::Text(_) => break,
                _ => continue,
            }
        }
    }

    let id = store_copies(
        &env,
        "{\"protected\":\"member-and-other\"}",
        &principal,
        &[&member, &other],
    )
    .await;

    let delete = async || -> Value {
        reqwest::Client::new()
            .delete(env.mediator.endpoint().join("delete").unwrap())
            .bearer_auth(&tokens.access_token)
            .json(&json!({ "message_ids": [id.clone()] }))
            .send()
            .await
            .expect("delete request")
            .json()
            .await
            .expect("delete response")
    };

    let resp = delete().await;
    assert_eq!(
        resp["data"]["success"],
        json!([id.clone()]),
        "the member's copy is acknowledged: {resp:#}"
    );
    assert!(
        !holds(&env, &member, &id).await,
        "the member's copy is gone"
    );
    assert!(
        holds(&env, &other, &id).await,
        "the other account's copy stays"
    );

    let resp = delete().await;
    assert_eq!(resp["data"]["success"], json!([]), "{resp:#}");
    assert!(
        resp["data"]["errors"].to_string().contains("not_found"),
        "the repeat is already gone: {resp:#}"
    );
    assert!(
        holds(&env, &other, &id).await,
        "the other account's copy still stays"
    );
    drop(ws);
}

/// A DID that received bytes from one sender and sent the same bytes on to
/// another account acknowledges its copy twice. The repeat answers not found:
/// the copy it sent on is not withdrawn by an acknowledgement.
#[tokio::test]
async fn a_repeated_acknowledgement_never_withdraws_what_was_sent_on() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let x = env.add_user("sent-on-origin").await.unwrap();
    let owner = env.add_user("sent-on-owner").await.unwrap();
    let r = env.add_user("sent-on-recipient").await.unwrap();

    let body = "{\"protected\":\"received-and-sent-on\"}";
    let id = store_copy(&env, body, &x, &owner).await;
    store_copy(&env, body, &owner, &r).await;

    let (deleted, errors) = rest_delete(&env, &owner, &id).await;
    assert_eq!(deleted, std::slice::from_ref(&id), "{errors:?}");
    assert!(holds(&env, &r, &id).await);

    let (deleted, errors) = rest_delete(&env, &owner, &id).await;
    assert!(deleted.is_empty(), "nothing more is deleted: {deleted:?}");
    assert!(
        errors
            .iter()
            .any(|(e_id, e)| e_id == &id && e.contains("database.message.delete.not_found")),
        "the repeat is already gone: {errors:?}"
    );
    assert!(holds(&env, &r, &id).await, "the copy sent on stays");
}

/// A sender whose own copy of bytes it also sent elsewhere was removed by the
/// mediator (not acknowledged by it) can still withdraw the other copy.
#[tokio::test]
async fn a_copy_removed_by_the_mediator_does_not_block_a_withdrawal() {
    use affinidi_messaging_mediator_common::store::{DeletionAuthority, MessageScope};

    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let sender = env.add_user("discarded-self-sender").await.unwrap();
    let r = env.add_user("discarded-self-other").await.unwrap();

    let id = store_copies(
        &env,
        "{\"protected\":\"self-copy-discarded\"}",
        &sender,
        &[&sender, &r],
    )
    .await;
    env.mediator
        .store()
        .delete_message_in(
            &id,
            MessageScope::Recipient(&did_hash(&sender.did)),
            DeletionAuthority::Admin {
                admin_did_hash: did_hash(env.mediator.did()),
            },
        )
        .await
        .expect("the mediator removes the sender's own copy");

    let (deleted, errors) = rest_delete(&env, &sender, &id).await;
    assert_eq!(deleted, std::slice::from_ref(&id), "{errors:?}");
    assert!(!holds(&env, &r, &id).await, "the other copy is withdrawn");
}

/// A mux principal and its member both hold a copy of the same bytes, and
/// only the member's has been handed over. The session's acknowledgement
/// removes the member's copy, not the principal's undelivered one.
#[tokio::test]
async fn a_mux_acknowledgement_takes_the_delivered_copy() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("delivered-principal").await.unwrap();
    let member = env.add_user("delivered-member").await.unwrap();
    let sender = env.add_user("delivered-sender").await.unwrap();
    grant(&env, &member, &principal).await;

    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate principal");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("upgrade");
    for _ in 0..2 {
        loop {
            match timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame within 5s")
                .expect("socket open")
                .expect("frame")
            {
                Message::Text(_) => break,
                _ => continue,
            }
        }
    }

    let id = store_copies(
        &env,
        "{\"protected\":\"principal-and-member\"}",
        &sender,
        &[&principal, &member],
    )
    .await;
    env.mediator
        .store()
        .mark_delivered(
            &did_hash(&member.did),
            std::slice::from_ref(&id),
            now() * 1_000,
            0,
        )
        .await
        .expect("the member's copy is handed over");

    let resp: Value = reqwest::Client::new()
        .delete(env.mediator.endpoint().join("delete").unwrap())
        .bearer_auth(&tokens.access_token)
        .json(&json!({ "message_ids": [id.clone()] }))
        .send()
        .await
        .expect("delete request")
        .json()
        .await
        .expect("delete response");
    assert_eq!(resp["data"]["success"], json!([id.clone()]), "{resp:#}");
    assert!(
        !holds(&env, &member, &id).await,
        "the delivered copy is gone"
    );
    assert!(
        holds(&env, &principal, &id).await,
        "the principal's undelivered copy stays"
    );
    drop(ws);
}
