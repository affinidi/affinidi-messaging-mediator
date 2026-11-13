//! An administrator's revocation reaches a principal connected to another
//! instance of the mediator, with reason `admin`: `messaging/mux/admin-revoke`
//! and `admin-revoke-all` sent to instance A detach the member from the
//! principal's mux connection on instance B through A's publish, as a
//! party's own `messaging/mux/revoke` does (`mux_two_instances.rs`).
//!
//! The store alone cannot say who ended a deleted or voided grant, so B
//! reads the reason from A's change record; without it B would report
//! `revokedByMember` or `epochBumped`.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test e2e -- mux_admin_two_instances::
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

use crate::common;

use std::time::Duration;

use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use affinidi_secrets_resolver::secrets::KeyType;
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

/// A logical DB no other cross-instance mux test uses.
const DB: u8 = 10;

const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

/// The next `messaging/mux/event` payload on the socket, skipping anything
/// else.
async fn next_event<S>(env: &TestEnvironment, ws: &mut S, within: Duration) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let frame = match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => panic!("no mux event within {within:?}"),
            Ok(f) => f.expect("socket open").expect("frame"),
        };
        let Message::Text(t) = frame else { continue };
        let (msg, _) = env.atm.unpack(t.as_str()).await.expect("unpack");
        if msg.body["type"] == EVENT_TYPE {
            return msg.body["payload"].clone();
        }
    }
}

/// Wait for an `event` about `did` other than `superseded`/`reactivated`
/// (a member's own socket on A coming and going); return that member entry.
async fn event_for<S>(env: &TestEnvironment, ws: &mut S, event: &str, did: &str) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let e = next_event(env, ws, Duration::from_secs(5)).await;
        if e["event"] != event {
            continue;
        }
        if let Some(d) = e["dids"].as_array().unwrap().iter().find(|d| {
            d["did"] == did && d["reason"] != "superseded" && d["reason"] != "reactivated"
        }) {
            return d.clone();
        }
    }
}

/// Send one signed administrator task through instance A; the payload.
async fn admin_task(
    env: &TestEnvironment,
    admin: &TestUser,
    type_uri: &str,
    payload: Value,
) -> Value {
    let mediator_did = env.mediator.did().to_string();
    let now = chrono::Utc::now();
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuer": admin.did,
        "recipient": mediator_did,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    let key = admin
        .secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .expect("an Ed25519 key");
    let doc = sign_trust_task(&doc, key, SignOptions::new())
        .await
        .unwrap();
    let secs = now.timestamp() as u64;
    let msg = DidcommMessage::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        doc,
    )
    .to(mediator_did.clone())
    .from(admin.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&admin.did), None)
        .await
        .unwrap();
    let SendMessageResponse::Message(reply) = env
        .atm
        .send_message(&admin.profile, &packed, &msg.id, true, true)
        .await
        .expect("A answers")
    else {
        panic!("expected a reply");
    };
    assert_eq!(
        reply.body["type"],
        format!("{type_uri}#response"),
        "{:#}",
        reply.body
    );
    reply.body["payload"].clone()
}

/// `member` grants `principal` through A from its own socket there, which
/// it then closes so it does not take its own traffic.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) {
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &principal.did,
        env.mediator.did(),
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm.profile_add(&member.profile, true).await.unwrap();
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&member.profile, vec![g])
        .await
        .expect("grant through A");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    member.profile.stop_websocket().await.unwrap();
}

#[tokio::test]
async fn an_admin_revocation_reaches_a_principal_on_another_instance() {
    init_tracing();
    let Some(store_a) = common::redis_store(DB, true).await else {
        return;
    };
    let store_b = common::redis_store(DB, false).await.unwrap();
    let a = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_a)
        .spawn()
        .await
        .expect("instance A");
    let b = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_b)
        .replica_of(a.replica_identity())
        .spawn()
        .await
        .expect("instance B");
    let b_ws: Uri = b.ws_endpoint().as_str().parse().unwrap();

    let env = TestEnvironment::new(a).await.expect("env");
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let admin = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm.profile_add(&admin.profile, true).await.unwrap();

    // The device's mux socket is on B, authenticated through A.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(device.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate through A");
    let request = ClientRequestBuilder::new(b_ws)
        .with_sub_protocol("didcomm-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("B accepts A's token");
    assert_eq!(
        next_event(&env, &mut ws, Duration::from_secs(5)).await["event"],
        "ready"
    );

    grant(&env, &work, &device).await;
    event_for(&env, &mut ws, "attached", &work.did).await;
    grant(&env, &home, &device).await;
    event_for(&env, &mut ws, "attached", &home.did).await;

    // admin-revoke through A: B detaches `work` with reason `admin`.
    let r = admin_task(
        &env,
        &admin,
        "https://trusttasks.org/spec/messaging/mux/admin-revoke/0.1",
        json!({ "principal": device.did, "member": work.did }),
    )
    .await;
    assert_eq!(r["revoked"].as_array().unwrap().len(), 1, "{r:#}");
    let left = event_for(&env, &mut ws, "detached", &work.did).await;
    assert_eq!(left["reason"], "admin", "{left:#}");

    // admin-revoke-all through A: B detaches `home` with reason `admin`.
    let r = admin_task(
        &env,
        &admin,
        "https://trusttasks.org/spec/messaging/mux/admin-revoke-all/0.1",
        json!({ "did": home.did, "epoch": 0 }),
    )
    .await;
    assert_eq!(r["epochAdvanced"], true, "{r:#}");
    let left = event_for(&env, &mut ws, "detached", &home.did).await;
    assert_eq!(left["reason"], "admin", "{left:#}");

    b.shutdown();
}
