//! A grant suspended while a mux connection is opening (#106).
//!
//! `mux::connection::open` reads the principal's stored grants, then
//! publishes the connection in the registry. A suspension or revocation
//! committed between the two finds no connection to detach, so `open`
//! re-checks the grants once the connection is published. This test lands a
//! suspension in exactly that window, using the mediator's `test-hooks`
//! pause point, and checks the member still ends up detached.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator::mux::{
    connection::test_hooks::pause_open_before_publish,
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{
    store::mux::{self, MuxLimits},
    types::acls::MediatorACLSet,
};
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
            "scope": ["receive", "pickup"],
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
async fn a_suspension_committed_while_the_connection_opens_still_detaches() {
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
    let sender = env.add_user("sender").await.unwrap();
    grant(&env, &work, &principal).await;

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

    // Open the socket with `open` set to stop after it has read the grants
    // and before the connection is in the registry.
    let (reached, resume) = pause_open_before_publish(&principal.did_hash());
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let connecting = tokio::spawn(async move { connect_async(request).await });
    timeout(Duration::from_secs(10), reached)
        .await
        .expect("open reaches the pause point")
        .expect("pause point fired");

    // The unknown-key rule fires for the member in the window: the grant is
    // suspended in the store, and the registry has no connection to detach.
    let store = env.mediator.store();
    let t = now();
    let suspended = mux::modify(
        &*store,
        &work.did_hash(),
        &MuxLimits::default(),
        t,
        None,
        |rec, _| {
            Ok(mux::suspend_unless_known_kid(
                rec,
                "did:example:new-controller#key-1",
                t,
            ))
        },
    )
    .await
    .expect("suspend");
    assert_eq!(
        suspended.len(),
        1,
        "the grant was active and is now suspended"
    );
    resume.send(()).expect("open is waiting");

    let (mut ws, _) = connecting.await.expect("connect task").expect("upgrade");

    // Read the events up to the member's `detached`. `open` admitted the
    // member from the grants it read, so `attached` may come first; what
    // matters is that it does not stay.
    let mut detached = None;
    for _ in 0..4 {
        let frame = match timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("an event within 5s")
            .expect("socket open")
            .expect("frame")
        {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };
        let (msg, _) = env.atm.unpack(&frame).await.expect("unpack event");
        let payload: &Value = &msg.body["payload"];
        if payload["event"] == "detached" {
            detached = Some(payload.clone());
            break;
        }
    }
    let detached = detached.expect("the suspended member is reported detached");
    let dids = detached["dids"].as_array().unwrap();
    assert_eq!(dids.len(), 1, "{detached:#}");
    assert_eq!(dids[0]["did"], work.did.as_str());
    assert_eq!(dids[0]["reason"], "suspendedUnknownKey");

    // And nothing for the member reaches the principal any more.
    send(&env, &sender, &work, "not for the principal now").await;
    assert!(
        timeout(Duration::from_millis(750), ws.next())
            .await
            .is_err(),
        "no frame for a detached member"
    );
}
