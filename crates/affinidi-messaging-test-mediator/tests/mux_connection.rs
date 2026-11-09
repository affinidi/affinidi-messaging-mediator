//! DID multiplexing end to end: one WebSocket carries live delivery for
//! several DIDs (design `mediator-did-multiplexing-design.md`).
//!
//! Members are admitted by stored grants, created here through the mediator's
//! own grant operation (`mux::grants::store_grant`, the code the
//! `messaging/mux/grant` Trust Task runs) because the SDK has no mux client
//! yet. Everything else is the wire: the principal's socket negotiates
//! `affinidi-mux`, receives the signed `ready` / `attached` events, and then
//! receives messages addressed to each member.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator::mux::{
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{store::mux::MuxLimits, types::acls::MediatorACLSet};
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

/// The DIDs a packed DIDComm frame is encrypted to (its JWE recipient kids).
fn recipients(frame: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(frame).unwrap_or(Value::Null);
    v["recipients"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .filter_map(|r| r["header"]["kid"].as_str())
                .map(|kid| kid.split('#').next().unwrap_or(kid).to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The event document must parse as the spec's generated
/// `messaging/mux/event` type: that is what a client using the generated
/// bindings does, so a shape the schema refuses is a broken event.
fn conforms_to_spec(doc: &Value) {
    use affinidi_messaging_mediator::task_specs::messaging::mux::event::v0_1::Payload;
    serde_json::from_value::<trust_tasks_rs::TrustTask<Payload>>(doc.clone())
        .unwrap_or_else(|e| panic!("mux/event does not match the spec: {e}\n{doc:#}"));
}

/// `member` grants `principal` receive + pickup, stored as the
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

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) {
    let t = now();
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .expect("pack");
    env.atm
        .send_message(&from.profile, &packed, &msg.id, false, false)
        .await
        .expect("send");
}

#[tokio::test]
async fn one_socket_carries_live_delivery_for_every_granted_did() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();

    grant(&env, &work, &principal).await;
    grant(&env, &home, &principal).await;

    // The principal opens ONE socket, asking for mux.
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
    let (mut ws, response) = connect_async(request).await.expect("upgrade");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("affinidi-mux"),
        "the mediator confirms the mux connection"
    );

    let mut next_text = async || -> String {
        loop {
            match timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame within 5s")
                .expect("socket open")
                .expect("frame")
            {
                Message::Text(t) => return t.to_string(),
                _ => continue,
            }
        }
    };

    // `ready`, then `attached` for the two granted DIDs, both to the
    // principal and signed by the mediator.
    let ready = next_text().await;
    assert_eq!(recipients(&ready), vec![principal.did.clone()]);
    let (ready_msg, _) = env.atm.unpack(&ready).await.expect("unpack ready");
    assert_eq!(ready_msg.body["payload"]["event"], "ready");
    conforms_to_spec(&ready_msg.body);
    assert!(
        ready_msg.body["payload"]["muxNonce"]
            .as_str()
            .is_some_and(|n| !n.is_empty())
    );

    let attached = next_text().await;
    let (attached_msg, _) = env.atm.unpack(&attached).await.expect("unpack attached");
    assert_eq!(attached_msg.body["payload"]["event"], "attached");
    conforms_to_spec(&attached_msg.body);
    let mut dids: Vec<String> = attached_msg.body["payload"]["dids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["did"].as_str().unwrap().to_string())
        .collect();
    dids.sort();
    let mut expected = vec![work.did.clone(), home.did.clone()];
    expected.sort();
    assert_eq!(dids, expected);

    // Messages for each member arrive on the principal's socket.
    send(&env, &sender, &work, "for work").await;
    send(&env, &sender, &home, "for home").await;
    let mut got = vec![
        recipients(&next_text().await),
        recipients(&next_text().await),
    ];
    got.sort();
    assert_eq!(got, {
        let mut e = vec![vec![work.did.clone()], vec![home.did.clone()]];
        e.sort();
        e
    });

    // A DID that granted nothing is not carried.
    let stranger = env.add_user("stranger").await.unwrap();
    send(&env, &sender, &stranger, "not yours").await;
    assert!(
        timeout(Duration::from_millis(500), ws.next())
            .await
            .is_err(),
        "nothing for a non-member reaches the principal"
    );
}

#[tokio::test]
async fn without_mux_enabled_the_marker_is_not_echoed() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
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
        .expect("authenticate");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (_ws, response) = connect_async(request).await.expect("upgrade");
    assert_ne!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("affinidi-mux"),
        "a mediator that will not multiplex must not say it will"
    );
}
