//! `messaging/wake/set/0.1` and `messaging/wake/request/0.1` end to end
//! (OpenVTC/verifiable-trust-infrastructure#2663; VTI-TRN-070 – 074).
//!
//! A device `D` gives its mediator a wake handle naming a gateway `G`; a
//! sender `W` queues mail for `D` and asks `D`'s mediator to ring. The gateway
//! here is a test user, so a ring is observable as the `push/wake/0.2` the
//! mediator stores in `G`'s inbox, and a gateway answer is a message `G` sends
//! back. The documents are built and signed by hand: the SDK this workspace
//! pins does not speak these tasks yet.
//!
//! Also here: the id a mediator stores a message under is `sha256` of the
//! packed message the sender built, whether it was delivered locally or
//! relayed by another mediator in either relay mode — the id `W` names in its
//! request (the SDK's `hop_id`).

use crate::common;

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator::common::config::WakeConfig;
use affinidi_messaging_mediator_common::types::messages::Folder;
use affinidi_messaging_sdk::messages::FetchDeletePolicy;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{
    RelayMode, TestClock, TestEnvironment, TestMediator, TestUser, acl,
};
use affinidi_secrets_resolver::secrets::KeyType;
use common::init_tracing;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const WAKE_SET: &str = "https://trusttasks.org/spec/messaging/wake/set/0.1";
const WAKE_REQUEST: &str = "https://trusttasks.org/spec/messaging/wake/request/0.1";
const PUSH_WAKE: &str = "https://trusttasks.org/spec/push/wake/0.2";

/// Limits loose enough that a test reaches the rule it is about.
fn loose() -> WakeConfig {
    WakeConfig {
        enabled: true,
        pair_per_minute: 100,
        pair_per_day: 100,
        addressee_coalesce_seconds: 0,
        addressee_per_hour: 100,
    }
}

/// A forwarding mediator that relays for senders homed elsewhere.
async fn relay_env(wake: WakeConfig, mode: RelayMode) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .local_direct_delivery(true, false)
        .relay_mode(mode)
        .wake_config(wake)
        .spawn()
        .await
        .expect("spawn mediator");
    TestEnvironment::new(mediator).await.expect("env")
}

async fn online(env: &TestEnvironment, alias: &str) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("websocket");
    user
}

fn signing_key(user: &TestUser) -> &affinidi_secrets_resolver::secrets::Secret {
    user.secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .expect("an Ed25519 signing key")
}

/// A Trust Task from `from` to `mediator_did`, signed for authentication.
async fn signed(
    from: &TestUser,
    mediator_did: &str,
    type_uri: &str,
    payload: Value,
    issued_at: u64,
) -> Value {
    let issued = chrono::DateTime::from_timestamp(issued_at as i64, 0).expect("time");
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuer": from.did,
        "recipient": mediator_did,
        "issuedAt": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    sign_trust_task(&doc, signing_key(from), SignOptions::new())
        .await
        .expect("sign")
}

/// Authcrypt `doc` in a Trust Task envelope from `from` to `mediator_did`.
async fn envelope(
    env: &TestEnvironment,
    from: &TestUser,
    mediator_did: &str,
    doc: Value,
) -> (String, String) {
    let secs = chrono::Utc::now().timestamp() as u64;
    let msg = Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_string(), doc)
        .to(mediator_did.to_string())
        .from(from.did.clone())
        .created_time(secs)
        .expires_time(secs + 600)
        .finalize();
    let id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, mediator_did, Some(&from.did), None)
        .await
        .expect("authcrypt");
    (id, packed)
}

/// Send a task from an online account to its own mediator and wait for the
/// answer.
async fn exchange(env: &TestEnvironment, from: &TestUser, doc: Value) -> Result<Message, String> {
    let mediator_did = env.mediator.did().to_string();
    let (id, packed) = envelope(env, from, &mediator_did, doc).await;
    match env
        .atm
        .send_message(&from.profile, &packed, &id, true, true)
        .await
    {
        Ok(SendMessageResponse::Message(reply)) => Ok(*reply),
        Ok(other) => Err(format!("no reply message: {other:?}")),
        Err(e) => Err(e.to_string()),
    }
}

/// `from` queues a basic message for `to` through `from`'s own mediator.
/// Returns the packed message the recipient's mediator stores, and its id
/// (`sha256` of it).
async fn queue(
    env: &TestEnvironment,
    from: &TestUser,
    to: &TestUser,
    authcrypt: bool,
) -> (String, String) {
    let secs = chrono::Utc::now().timestamp() as u64;
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "approve?" }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(secs)
    .expires_time(secs + 600)
    .finalize();
    let msg_id = msg.id.clone();
    let sender = authcrypt.then_some(from.did.as_str());
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, sender, None)
        .await
        .expect("pack for the recipient");
    let own_mediator = env.mediator.did().to_string();
    env.atm
        .forward_and_send_message(
            &from.profile,
            false,
            &packed,
            Some(&msg_id),
            &own_mediator,
            &to.did,
            None,
            None,
            false,
        )
        .await
        .expect("send through the sender's mediator");
    let id = sha256::digest(&packed);
    (packed, id)
}

/// Wait until `to`'s mediator holds the message `id` for it.
async fn stored(env: &TestEnvironment, to: &TestUser, id: &str) -> bool {
    let store = env.mediator.store();
    for _ in 0..100 {
        if store
            .get_message(&to.did_hash(), id)
            .await
            .expect("get_message")
            .is_some()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Give `device` a wake handle at `gateway`, straight into the store.
async fn set_handle(env: &TestEnvironment, device: &TestUser, gateway: &TestUser, handle: &str) {
    env.mediator
        .store()
        .wake_handle_set(
            &device.did_hash(),
            Some(&json!({ "gateway": gateway.did, "handle": handle }).to_string()),
        )
        .await
        .expect("store the handle");
}

/// The `push/wake` documents the mediator has stored for `gateway`, opened.
async fn rings(env: &TestEnvironment, gateway: &TestUser) -> Vec<Value> {
    let store = env.mediator.store();
    let listed = store
        .list_messages(&gateway.did_hash(), Folder::Inbox, None, 100)
        .await
        .expect("list the gateway's inbox");
    let mut out = Vec::new();
    for element in listed {
        let Some(stored) = store
            .get_message(&gateway.did_hash(), &element.msg_id)
            .await
            .expect("get")
        else {
            continue;
        };
        let body = stored.msg.expect("body");
        let (msg, _) = env.atm.unpack(&body).await.expect("the gateway opens it");
        if msg.body["type"] == PUSH_WAKE {
            out.push(msg.body);
        }
    }
    out
}

/// Wait for `n` rings at `gateway`; then give a late one a moment to show.
async fn expect_rings(env: &TestEnvironment, gateway: &TestUser, n: usize) -> Vec<Value> {
    let mut seen = Vec::new();
    for _ in 0..50 {
        seen = rings(env, gateway).await;
        if seen.len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen_after = rings(env, gateway).await;
    assert_eq!(seen_after.len(), n, "rings: {seen:#?}");
    seen_after
}

/// `W` asks `D`'s mediator (its own) to ring for `ids`, and returns the
/// answer's payload.
async fn request(env: &TestEnvironment, w: &TestUser, addressee: &str, ids: &[&str]) -> Value {
    let doc = signed(
        w,
        env.mediator.did(),
        WAKE_REQUEST,
        json!({ "addressee": addressee, "msgIds": ids, "urgency": "interactive" }),
        chrono::Utc::now().timestamp() as u64,
    )
    .await;
    let reply = exchange(env, w, doc.clone()).await.expect("an answer");
    assert_eq!(
        reply.body["type"],
        format!("{WAKE_REQUEST}#response"),
        "{:#}",
        reply.body
    );
    assert_eq!(reply.body["threadId"], doc["id"]);
    reply.body["payload"].clone()
}

// ─── messaging/wake/set ──────────────────────────────────────────────────────

#[tokio::test]
async fn wake_set_holds_a_reachable_handle_and_absence_clears_it() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let device = online(&env, "Device").await;
    let gateway = env.add_user("Gateway").await.expect("gateway");
    let mediator = env.mediator.did().to_string();
    let now = || chrono::Utc::now().timestamp() as u64;

    let set = signed(
        &device,
        &mediator,
        WAKE_SET,
        json!({ "wakeHandle": { "gateway": gateway.did, "handle": "wh_1" } }),
        now(),
    )
    .await;
    let reply = exchange(&env, &device, set).await.expect("answer");
    assert_eq!(
        reply.body["payload"],
        json!({ "wakeCapable": true }),
        "{:#}",
        reply.body
    );
    let held: Value = serde_json::from_str(
        &env.mediator
            .store()
            .wake_handle_get(&device.did_hash())
            .await
            .unwrap()
            .expect("a record"),
    )
    .unwrap();
    assert_eq!(held["gateway"], gateway.did);
    assert_eq!(held["handle"], "wh_1");

    // A gateway this mediator cannot ring (by URL) is not held.
    let set = signed(
        &device,
        &mediator,
        WAKE_SET,
        json!({ "wakeHandle": { "gateway": "https://push.example", "handle": "wh_2" } }),
        now(),
    )
    .await;
    let reply = exchange(&env, &device, set).await.expect("answer");
    assert_eq!(reply.body["payload"], json!({ "wakeCapable": false }));
    assert_eq!(
        env.mediator
            .store()
            .wake_handle_get(&device.did_hash())
            .await
            .unwrap(),
        None
    );

    // Absence clears.
    set_handle(&env, &device, &gateway, "wh_3").await;
    let clear = signed(&device, &mediator, WAKE_SET, json!({}), now()).await;
    let reply = exchange(&env, &device, clear).await.expect("answer");
    assert_eq!(reply.body["payload"], json!({ "wakeCapable": false }));
    assert_eq!(
        env.mediator
            .store()
            .wake_handle_get(&device.did_hash())
            .await
            .unwrap(),
        None
    );
    env.shutdown().await.expect("shutdown");
}

// ─── messaging/wake/request: the rules ──────────────────────────────────────

/// The ring is `push/wake/0.2` to the gateway, as the mediator, signed for
/// authentication, carrying only the handle, `v`, the mediator and urgency.
#[tokio::test]
async fn queued_mail_from_the_requester_rings_the_gateway_once() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh_ring").await;

    let (_, id) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id).await);
    assert_eq!(request(&env, &w, &device.did, &[&id]).await, json!({}));

    let ring = expect_rings(&env, &gateway, 1).await.remove(0);
    assert_eq!(ring["issuer"], env.mediator.did());
    assert_eq!(ring["recipient"], gateway.did);
    assert_eq!(
        ring["payload"],
        json!({ "handle": "wh_ring", "v": 1, "mediator": env.mediator.did(), "urgency": "interactive" })
    );
    assert_eq!(ring["proof"]["proofPurpose"], "authentication");

    // Rule 6: the same message never rings twice, whoever asks.
    assert_eq!(request(&env, &w, &device.did, &[&id]).await, json!({}));
    expect_rings(&env, &gateway, 1).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 1: no handle, or no account at all — nothing rings, same answer.
#[tokio::test]
async fn no_handle_and_no_account_ring_nothing_and_answer_the_same() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");

    let (_, id) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id).await);
    let no_handle = request(&env, &w, &device.did, &[&id]).await;

    // A DID that is no account here: an outsider learns nothing from the
    // answer.
    let no_account = request(&env, &w, "did:example:nobody-here", &[&id]).await;

    // And one that rings.
    set_handle(&env, &device, &gateway, "wh").await;
    let (_, id2) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id2).await);
    let rung = request(&env, &w, &device.did, &[&id2]).await;

    assert_eq!(no_handle, json!({}));
    assert_eq!(no_account, rung);
    assert_eq!(no_handle, rung);
    expect_rings(&env, &gateway, 1).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 2: a delivered message does not ring; rule 3: mail another sender
/// queued does not ring for this requester.
#[tokio::test]
async fn delivered_or_foreign_mail_rings_nothing() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let other = env.add_user("Other").await.expect("other");
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    // Delivered: the device fetched it (and left it queued).
    let (_, delivered) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &delivered).await);
    env.atm
        .fetch_messages(
            &device.profile,
            &FetchOptions {
                delete_policy: FetchDeletePolicy::DoNotDelete,
                ..Default::default()
            },
        )
        .await
        .expect("the device fetches");
    assert_eq!(
        request(&env, &w, &device.did, &[&delivered]).await,
        json!({})
    );

    // Foreign: authcrypted by `other`, named by `w`.
    let (_, foreign) = queue(&env, &other, &device, true).await;
    assert!(stored(&env, &device, &foreign).await);
    assert_eq!(request(&env, &w, &device.did, &[&foreign]).await, json!({}));

    expect_rings(&env, &gateway, 0).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 3's other half: an envelope that reveals no sender (anoncrypt) binds
/// by the id alone.
#[tokio::test]
async fn anoncrypt_mail_rings_for_whoever_holds_its_id() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    let (_, id) = queue(&env, &w, &device, false).await;
    assert!(stored(&env, &device, &id).await);
    request(&env, &w, &device.did, &[&id]).await;
    expect_rings(&env, &gateway, 1).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 4: a requester the device's access list refuses does not ring it.
#[tokio::test]
async fn a_blocked_requester_rings_nothing() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    let (_, id) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id).await);
    // Blocked after the mail was queued (`allow_all` is deny-list mode).
    env.mediator
        .store()
        .access_list_add(100, &device.did_hash(), &[w.did_hash()])
        .await
        .expect("block");
    assert_eq!(request(&env, &w, &device.did, &[&id]).await, json!({}));
    expect_rings(&env, &gateway, 0).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 5: a device with a live connection is streamed its mail instead.
#[tokio::test]
async fn an_online_device_is_not_rung() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = online(&env, "Device").await;
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    // Queued while the device holds its connection, so not yet taken.
    let (_, id) = queue(&env, &w, &device, true).await;
    if !stored(&env, &device, &id).await {
        // Already handed over on the live stream: rule 2 covers it.
        return;
    }
    request(&env, &w, &device.did, &[&id]).await;
    expect_rings(&env, &gateway, 0).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 7: one ring per minute for a pair, and rings for one addressee
/// coalesce.
#[tokio::test]
async fn the_rate_limits_hold() {
    init_tracing();
    let env = relay_env(WakeConfig::default(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let w2 = online(&env, "Vta2").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    let (_, first) = queue(&env, &w, &device, true).await;
    let (_, second) = queue(&env, &w, &device, true).await;
    let (_, third) = queue(&env, &w2, &device, true).await;
    for id in [&first, &second, &third] {
        assert!(stored(&env, &device, id).await);
    }
    request(&env, &w, &device.did, &[&first]).await;
    expect_rings(&env, &gateway, 1).await;
    // Same pair within the minute.
    request(&env, &w, &device.did, &[&second]).await;
    // Another requester within the coalescing window.
    request(&env, &w2, &device.did, &[&third]).await;
    expect_rings(&env, &gateway, 1).await;
    env.shutdown().await.expect("shutdown");
}

/// Rule 2's freshness: mail stored more than ten minutes ago does not ring.
#[tokio::test]
async fn stale_mail_rings_nothing() {
    init_tracing();
    let clock = TestClock::now();
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .clock(Arc::new(clock.clone()))
        .jwt_expiry(Duration::from_secs(7_200), Duration::from_secs(14_400))
        .wake_config(loose())
        .spawn()
        .await
        .expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    let (_, id) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id).await);
    clock.advance_secs(11 * 60);

    // Issued at the mediator's (advanced) time, so the request itself is
    // fresh; only the mail is old.
    use affinidi_messaging_mediator_common::types::clock::Clock;
    let doc = signed(
        &w,
        env.mediator.did(),
        WAKE_REQUEST,
        json!({ "addressee": device.did, "msgIds": [id] }),
        clock.unix_secs(),
    )
    .await;
    let mediator_did = env.mediator.did().to_string();
    let (msg_id, packed) = envelope(&env, &w, &mediator_did, doc).await;
    env.atm
        .send_message(&w.profile, &packed, &msg_id, false, true)
        .await
        .expect("sent");
    expect_rings(&env, &gateway, 0).await;
    env.shutdown().await.expect("shutdown");
}

/// Arming: a request that arrives before its message rings when the
/// message is stored.
#[tokio::test]
async fn a_request_ahead_of_its_mail_rings_when_the_mail_arrives() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh").await;

    // Build the message, name it, and only then send it.
    let secs = chrono::Utc::now().timestamp() as u64;
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "late" }),
    )
    .to(device.did.clone())
    .from(w.did.clone())
    .created_time(secs)
    .expires_time(secs + 600)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &device.did, Some(&w.did), None)
        .await
        .expect("pack");
    let id = sha256::digest(&packed);
    request(&env, &w, &device.did, &[&id]).await;
    expect_rings(&env, &gateway, 0).await;

    env.atm
        .forward_and_send_message(
            &w.profile,
            false,
            &packed,
            Some(&msg_id),
            env.mediator.did(),
            &device.did,
            None,
            None,
            false,
        )
        .await
        .expect("send the mail");
    expect_rings(&env, &gateway, 1).await;
    env.shutdown().await.expect("shutdown");
}

/// A request whose proof is not for `authentication`, or that has none, is
/// refused before any addressee is considered.
#[tokio::test]
async fn an_unproven_request_is_refused() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let mut doc = signed(
        &w,
        env.mediator.did(),
        WAKE_REQUEST,
        json!({ "addressee": device.did, "msgIds": ["x"] }),
        chrono::Utc::now().timestamp() as u64,
    )
    .await;
    doc.as_object_mut().unwrap().remove("proof");
    assert!(exchange(&env, &w, doc).await.is_err());
    env.shutdown().await.expect("shutdown");
}

// ─── The gateway's answer ───────────────────────────────────────────────────

/// `G` answers the ring `doc` with `answer`, threaded to it.
async fn answer(env: &TestEnvironment, gateway: &TestUser, answer: Value) {
    let mediator_did = env.mediator.did().to_string();
    let (id, packed) = envelope(env, gateway, &mediator_did, answer).await;
    env.atm
        .send_message(&gateway.profile, &packed, &id, false, true)
        .await
        .expect("the gateway answers");
}

#[tokio::test]
async fn token_unregistered_drops_the_handle_and_not_allowed_stops_ringing() {
    init_tracing();
    let env = relay_env(loose(), RelayMode::Blind).await;
    let w = online(&env, "Vta").await;
    let device = env.add_user("Device").await.expect("device");
    let gateway = env.add_user("Gateway").await.expect("gateway");
    set_handle(&env, &device, &gateway, "wh_dead").await;

    let (_, id) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id).await);
    request(&env, &w, &device.did, &[&id]).await;
    let ring = expect_rings(&env, &gateway, 1).await.remove(0);
    answer(
        &env,
        &gateway,
        json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": format!("{PUSH_WAKE}#response"),
            "threadId": ring["id"],
            "issuer": gateway.did,
            "recipient": env.mediator.did(),
            "payload": { "status": "tokenUnregistered" },
        }),
    )
    .await;
    let store = env.mediator.store();
    let mut dropped = false;
    for _ in 0..50 {
        if store
            .wake_handle_get(&device.did_hash())
            .await
            .unwrap()
            .is_none()
        {
            dropped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(dropped, "tokenUnregistered drops the handle");

    // notAllowed: the handle stays but is not rung again.
    set_handle(&env, &device, &gateway, "wh_refused").await;
    let (_, id2) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id2).await);
    request(&env, &w, &device.did, &[&id2]).await;
    let ring = expect_rings(&env, &gateway, 2)
        .await
        .into_iter()
        .find(|r| r["payload"]["handle"] == "wh_refused")
        .expect("the second ring");
    answer(
        &env,
        &gateway,
        json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "threadId": ring["id"],
            "issuer": gateway.did,
            "recipient": env.mediator.did(),
            "payload": { "code": "permissionDenied", "retryable": false },
        }),
    )
    .await;
    let mut refused = false;
    for _ in 0..50 {
        if let Some(record) = store.wake_handle_get(&device.did_hash()).await.unwrap() {
            let record: Value = serde_json::from_str(&record).unwrap();
            if record["notAllowed"] == true {
                refused = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(refused, "notAllowed marks the handle");
    let (_, id3) = queue(&env, &w, &device, true).await;
    assert!(stored(&env, &device, &id3).await);
    request(&env, &w, &device.did, &[&id3]).await;
    expect_rings(&env, &gateway, 2).await;
    env.shutdown().await.expect("shutdown");
}

// ─── Across mediators ───────────────────────────────────────────────────────

/// `W` homed on mediator A, the device on B. `W` queues mail through A and
/// sends its wake request to B's DID through A, as the SDK does: B accepts it
/// from a sender with no account there, rings, creates no account, and
/// answers `W` on A.
async fn relayed_request_rings(mode: RelayMode) {
    let env_a = relay_env(loose(), mode).await;
    let env_b = relay_env(loose(), mode).await;
    let w = env_a.add_user("Vta").await.expect("w");
    let device = env_b.add_user("Device").await.expect("device");
    let gateway = env_b.add_user("Gateway").await.expect("gateway");
    set_handle(&env_b, &device, &gateway, "wh_far").await;

    let (_, id) = queue(&env_a, &w, &device, true).await;
    assert!(
        stored(&env_b, &device, &id).await,
        "the mail reaches B under sha256(packed)"
    );

    let b_did = env_b.mediator.did().to_string();
    let doc = signed(
        &w,
        &b_did,
        WAKE_REQUEST,
        json!({ "addressee": device.did, "msgIds": [id] }),
        chrono::Utc::now().timestamp() as u64,
    )
    .await;
    let (msg_id, packed) = envelope(&env_a, &w, &b_did, doc).await;
    env_a
        .atm
        .forward_and_send_message(
            &w.profile,
            false,
            &packed,
            Some(&msg_id),
            env_a.mediator.did(),
            &b_did,
            None,
            None,
            false,
        )
        .await
        .expect("send through A");

    let ring = expect_rings(&env_b, &gateway, 1).await.remove(0);
    assert_eq!(ring["payload"]["mediator"], b_did);
    assert!(
        !env_b
            .mediator
            .store()
            .account_exists(&w.did_hash())
            .await
            .unwrap(),
        "a wake request never makes an account"
    );

    // The constant answer reaches W at A.
    let store_a = env_a.mediator.store();
    let mut answered = false;
    for _ in 0..100 {
        for element in store_a
            .list_messages(&w.did_hash(), Folder::Inbox, None, 100)
            .await
            .unwrap()
        {
            let Some(held) = store_a
                .get_message(&w.did_hash(), &element.msg_id)
                .await
                .unwrap()
            else {
                continue;
            };
            let (msg, _) = env_a
                .atm
                .unpack(&held.msg.unwrap())
                .await
                .expect("W opens it");
            if msg.body["type"] == format!("{WAKE_REQUEST}#response") {
                assert_eq!(msg.body["payload"], json!({}));
                answered = true;
            }
        }
        if answered {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(answered, "W is answered at its own mediator");
    env_a.shutdown().await.expect("shutdown A");
    env_b.shutdown().await.expect("shutdown B");
}

#[tokio::test]
async fn a_request_relayed_blind_rings() {
    init_tracing();
    relayed_request_rings(RelayMode::Blind).await;
}

#[tokio::test]
async fn a_request_relayed_rewrapped_rings() {
    init_tracing();
    relayed_request_rings(RelayMode::Rewrap).await;
}

/// The id a recipient's mediator stores a message under is `sha256` of the
/// packed message its sender built — the SDK's `hop_id` — locally, and after
/// a relay in either mode. That is the id `messaging/wake/request` names.
async fn stored_id_survives(mode: RelayMode) {
    let env_a = relay_env(loose(), mode).await;
    let env_b = relay_env(loose(), mode).await;
    let alice = env_a.add_user("Alice").await.expect("alice");
    let local = env_a.add_user("Local").await.expect("local");
    let bob = env_b.add_user("Bob").await.expect("bob");

    let (_, id) = queue(&env_a, &alice, &local, true).await;
    assert!(stored(&env_a, &local, &id).await, "delivered locally");
    let (_, id) = queue(&env_a, &alice, &bob, true).await;
    assert!(stored(&env_b, &bob, &id).await, "relayed {mode:?}");
    env_a.shutdown().await.expect("shutdown A");
    env_b.shutdown().await.expect("shutdown B");
}

#[tokio::test]
async fn the_stored_id_survives_a_blind_relay() {
    init_tracing();
    stored_id_survives(RelayMode::Blind).await;
}

#[tokio::test]
async fn the_stored_id_survives_a_rewrap_relay() {
    init_tracing();
    stored_id_survives(RelayMode::Rewrap).await;
}
