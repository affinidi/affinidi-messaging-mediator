//! What a client is told about a delivery matches what happened.
//!
//! - A trust-ping is answered with a `ping-response` (#196).
//! - A forward carrying more than one attachment is refused, not answered
//!   `Forwarded` with the extra attachments dropped (#192).
//! - A `messages-received` names at most 100 ids (#187).
//! - Turning live delivery on where the mediator cannot stream is refused,
//!   not answered with a status claiming it is on (#190).
//! - A Message Pickup `delivery` over REST records what it handed over once
//!   the body is written, and only what it carried (#181).
//! - `/outbound` with `delete` deletes once the response is written (#135).

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::message::{Attachment, Message};
use affinidi_messaging_mediator_common::{did_identity::did_hash, store::MessageRef};
use affinidi_messaging_sdk::messages::GetMessagesRequest;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use base64::prelude::*;
use common::init_tracing;
use serde_json::{Value, json};
use uuid::Uuid;

const PICKUP: &str = "https://didcomm.org/messagepickup/3.0";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn env() -> TestEnvironment {
    TestEnvironment::new(TestMediator::spawn().await.expect("spawn mediator"))
        .await
        .expect("environment")
}

/// A message from `from` to the mediator.
fn to_mediator(env: &TestEnvironment, from: &TestUser, typ: &str, body: Value) -> Message {
    Message::build(Uuid::new_v4().to_string(), typ.to_string(), body)
        .from(from.did.clone())
        .to(env.mediator.did().to_string())
        .created_time(now())
        .expires_time(now() + 60)
        .finalize()
}

/// Authcrypt `msg` from `user` to the mediator and POST it to `/inbound` on
/// `user`'s session. Returns the status and the body.
async fn post(env: &TestEnvironment, user: &TestUser, msg: &Message) -> (u16, Value) {
    let packed = env
        .atm
        .pack_encrypted(msg, env.mediator.did(), Some(&user.did), None)
        .await
        .expect("authcrypt")
        .0;
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
    let response = reqwest::Client::new()
        .post(format!("{}inbound", env.mediator.endpoint()))
        .bearer_auth(&tokens.access_token)
        .header("content-type", "application/json")
        .body(packed)
        .send()
        .await
        .expect("POST /inbound");
    let status = response.status().as_u16();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// Store `body` for `to`, from `from`, straight into the store. Returns the id.
async fn store_for(env: &TestEnvironment, body: &str, from: &TestUser, to: &TestUser) -> String {
    env.mediator
        .store()
        .store_message(
            "test",
            body,
            &did_hash(&to.did),
            Some(&did_hash(&from.did)),
            now() + 3600,
            0,
        )
        .await
        .expect("store_message")
}

/// Whether `to`'s copy of `id` is stamped delivered.
async fn stamped_delivered(env: &TestEnvironment, to: &TestUser, id: &str) -> bool {
    env.mediator
        .store()
        .delivery_states(&[MessageRef::new(did_hash(&to.did), id.to_string())])
        .await
        .expect("delivery_states")
        .first()
        .cloned()
        .flatten()
        .is_some_and(|s| s.first_delivered_at_ms.is_some())
}

/// Wait up to two seconds for `check` to hold.
async fn eventually<F: AsyncFn() -> bool>(check: F) -> bool {
    for _ in 0..40 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The mediator's replies stored in `user`'s inbox, unpacked.
async fn replies(env: &TestEnvironment, user: &TestUser) -> Vec<Message> {
    let store = env.mediator.store();
    let listed = store
        .list_messages(
            &did_hash(&user.did),
            affinidi_messaging_sdk::messages::Folder::Inbox,
            Some(("-", "+")),
            100,
        )
        .await
        .expect("list inbox");
    let mut out = Vec::new();
    for element in listed {
        let Some(stored) = store
            .get_message(&did_hash(&user.did), &element.msg_id)
            .await
            .expect("get_message")
        else {
            continue;
        };
        if let Some(body) = stored.msg
            && let Ok((msg, _)) = env.atm.unpack(&body).await
        {
            out.push(msg);
        }
    }
    out
}

#[tokio::test]
async fn a_trust_ping_is_answered_with_a_ping_response() {
    init_tracing();
    let env = env().await;
    let alice = env.add_user("ping-alice").await.unwrap();

    let ping = to_mediator(
        &env,
        &alice,
        "https://didcomm.org/trust-ping/2.0/ping",
        json!({ "response_requested": true }),
    );
    let (status, body) = post(&env, &alice, &ping).await;
    assert_eq!(status, 200, "{body}");

    let replies = replies(&env, &alice).await;
    let pong = replies
        .iter()
        .find(|m| m.thid.as_deref() == Some(ping.id.as_str()))
        .expect("the ping is answered");
    assert_eq!(pong.typ, "https://didcomm.org/trust-ping/2.0/ping-response");
    assert_eq!(pong.from.as_deref(), Some(env.mediator.did()));
}

#[tokio::test]
async fn a_forward_with_two_attachments_is_refused() {
    init_tracing();
    let env = env().await;
    let alice = env.add_user("forward-alice").await.unwrap();
    let bob = env.add_user("forward-bob").await.unwrap();

    let inner = |n: u8| {
        Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(format!("{{\"protected\":\"{n}\"}}")))
            .finalize()
    };
    let forward = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/routing/2.0/forward".to_string(),
        json!({ "next": bob.did }),
    )
    .from(alice.did.clone())
    .to(env.mediator.did().to_string())
    .attachment(inner(1))
    .attachment(inner(2))
    .created_time(now())
    .expires_time(now() + 60)
    .finalize();

    let (status, body) = post(&env, &alice, &forward).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains("protocol.forwarding.attachments.too_many"),
        "{body}"
    );
    let queued = env
        .mediator
        .store()
        .list_messages(
            &did_hash(&bob.did),
            affinidi_messaging_sdk::messages::Folder::Inbox,
            Some(("-", "+")),
            10,
        )
        .await
        .unwrap();
    assert!(queued.is_empty(), "nothing is delivered: {queued:?}");
}

#[tokio::test]
async fn messages_received_names_at_most_a_hundred_ids() {
    init_tracing();
    let env = env().await;
    let alice = env.add_user("ack-cap-alice").await.unwrap();

    let ids: Vec<String> = (0..101).map(|i| format!("1700000000000-{i}")).collect();
    let mut ack = to_mediator(
        &env,
        &alice,
        &format!("{PICKUP}/messages-received"),
        json!({ "message_id_list": ids }),
    );
    ack.extra.insert("return_route".into(), json!("all"));
    let (status, body) = post(&env, &alice, &ack).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.to_string()
            .contains("protocol.pickup.messages_received.limit"),
        "{body}"
    );
}

#[tokio::test]
async fn live_delivery_is_not_claimed_without_streaming() {
    init_tracing();
    let mediator = TestMediator::builder()
        .enable_streaming(false)
        .spawn()
        .await
        .expect("spawn mediator without streaming");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("live-alice").await.unwrap();

    let mut toggle = to_mediator(
        &env,
        &alice,
        &format!("{PICKUP}/live-delivery-change"),
        json!({ "live_delivery": true }),
    );
    toggle.extra.insert("return_route".into(), json!("all"));
    let (status, body) = post(&env, &alice, &toggle).await;
    assert_eq!(status, 501, "{body}");
    assert!(
        body.to_string().contains("protocol.pickup.live_streaming"),
        "{body}"
    );
}

/// A REST pickup stamps what its reply carried once the body is written,
/// and not a message the reply could not carry.
#[tokio::test]
async fn a_rest_pickup_records_what_it_carried() {
    init_tracing();
    let env = env().await;
    let alice = env.add_user("pickup-alice").await.unwrap();
    let bob = env.add_user("pickup-bob").await.unwrap();

    let id = store_for(&env, "{\"protected\":\"for-alice\"}", &bob, &alice).await;
    assert!(!stamped_delivered(&env, &alice, &id).await);

    let mut request = to_mediator(
        &env,
        &alice,
        &format!("{PICKUP}/delivery-request"),
        json!({ "recipient_did": alice.did, "limit": 10 }),
    );
    request.extra.insert("return_route".into(), json!("all"));
    let (status, body) = post(&env, &alice, &request).await;
    assert_eq!(status, 200, "{body}");

    assert!(
        eventually(async || stamped_delivered(&env, &alice, &id).await).await,
        "the message the written reply carried is stamped delivered"
    );
}

/// `/outbound` with `delete`: the message comes back, then is deleted once
/// the response has been written.
#[tokio::test]
async fn outbound_with_delete_deletes_after_the_response() {
    init_tracing();
    let env = env().await;
    let alice = env.add_user("outbound-alice").await.unwrap();
    let bob = env.add_user("outbound-bob").await.unwrap();

    let id = store_for(&env, "{\"protected\":\"outbound\"}", &bob, &alice).await;
    let response = env
        .atm
        .get_messages(
            &alice.profile,
            &GetMessagesRequest {
                message_ids: vec![id.clone()],
                delete: true,
            },
        )
        .await
        .expect("GET /outbound");
    assert_eq!(response.success.len(), 1);
    assert_eq!(response.success[0].msg_id, id);
    assert!(response.delete_errors.is_empty());

    let store = env.mediator.store();
    assert!(
        eventually(async || store
            .get_message(&did_hash(&alice.did), &id)
            .await
            .unwrap()
            .is_none())
        .await,
        "deleted once the response was written"
    );
}
