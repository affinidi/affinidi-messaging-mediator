//! Mux membership events on the traffic monitor (`messaging/monitor/subscribe`
//! 0.2, `messaging/monitor/event` 0.3), end to end against a live in-process
//! mediator with mux enabled.
//!
//! A 0.2 subscription opts in with a `membership` filter and then sees one
//! event per member change the mediator reports in `messaging/mux/event`. One
//! without the filter, and every 0.1 subscription, sees none. A standard
//! account sees only the changes it is party to.
//!
//! The SDK sends subscribe 0.1 and reads event 0.2 only, so the 0.2 requests
//! here are sent by hand and the 0.3 batches read from the message body.

// The 0.1 subscribe the SDK sends is marked superseded by `trust-tasks-rs`.
#![allow(deprecated)]

use crate::common;

use std::time::Duration;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use serde_json::{Value, json};
use tokio::time::timeout;

const SUBSCRIBE_V0_2: &str = "https://trusttasks.org/spec/messaging/monitor/subscribe/0.2";
const EVENT_V0_2: &str = "https://trusttasks.org/spec/messaging/monitor/event/0.2";
const EVENT_V0_3: &str = "https://trusttasks.org/spec/messaging/monitor/event/0.3";

/// A mux-enabled mediator.
async fn mux_env() -> TestEnvironment {
    common::init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("mediator");
    TestEnvironment::new(mediator).await.expect("environment")
}

/// A user with `role` and a live websocket, to receive monitor batches.
async fn watcher(env: &TestEnvironment, alias: &str, role: AccountType) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("set role");
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("live websocket");
    user
}

/// Send one Trust Task document by hand as `user` and return the reply body.
async fn send_raw_task(
    env: &TestEnvironment,
    user: &TestUser,
    type_uri: &str,
    payload: Value,
) -> Value {
    use affinidi_messaging_didcomm::message::Message;
    use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
    use affinidi_messaging_sdk::transports::SendMessageResponse;

    let mediator_did = env.mediator.did().to_string();
    let now = chrono::Utc::now();
    let task = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": user.did,
        "recipient": mediator_did,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    let secs = now.timestamp() as u64;
    let msg = Message::build(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        task,
    )
    .to(mediator_did.clone())
    .from(user.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&user.did), None)
        .await
        .expect("authcrypt the task");
    match env
        .atm
        .send_message(&user.profile, &packed, &msg_id, true, true)
        .await
    {
        Ok(SendMessageResponse::Message(reply)) => reply.body,
        Ok(other) => panic!("expected a response message, got {other:?}"),
        // A refusal: its text names the code.
        Err(e) => json!({ "refused": format!("{e:?}") }),
    }
}

/// Subscribe at 0.2 with `payload`; the response payload.
async fn subscribe_v0_2(env: &TestEnvironment, user: &TestUser, payload: Value) -> Value {
    let body = send_raw_task(env, user, SUBSCRIBE_V0_2, payload).await;
    assert_eq!(
        body["type"],
        format!("{SUBSCRIBE_V0_2}#response"),
        "subscribe 0.2 answered: {body}"
    );
    body["payload"].clone()
}

/// Every `messaging/monitor/event` document reaching `user`'s live stream
/// until `done` holds over what has arrived, or `deadline` passes.
async fn batches_until(
    env: &TestEnvironment,
    user: &TestUser,
    deadline: Duration,
    done: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let mut seen = Vec::new();
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until && !done(&seen) {
        let Some((message, _)) = env
            .atm
            .message_pickup()
            .live_stream_next(&user.profile, Some(Duration::from_millis(500)), false)
            .await
            .expect("live stream")
        else {
            continue;
        };
        let ty = message.body["type"].as_str().unwrap_or_default();
        if ty == EVENT_V0_2 || ty == EVENT_V0_3 {
            seen.push(message.body.clone());
        }
    }
    seen
}

/// The membership events of subscription `sub` across `batches`.
fn membership_of(batches: &[Value], sub: &Value) -> Vec<Value> {
    batches
        .iter()
        .filter(|b| b["payload"]["subscriptionId"] == *sub)
        .flat_map(|b| {
            b["payload"]["membership"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

/// Open `principal`'s mux connection and wait for its `ready`.
async fn open_mux(env: &TestEnvironment, principal: &TestUser) {
    env.atm
        .profile_enable_mux_websocket(&principal.profile)
        .await
        .expect("mux websocket");
    let mut ready = principal.profile.mux_ready().await.expect("ready watch");
    timeout(Duration::from_secs(5), async {
        while ready.borrow().is_none() {
            ready.changed().await.unwrap();
        }
    })
    .await
    .expect("ready within 5s");
}

/// `member` grants `principal` receive; the grant is stored and, the
/// principal being connected, attached.
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
    .expect("sign grant");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&principal.profile, vec![g])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
}

/// `principal` revokes `member`'s grant.
async fn revoke(env: &TestEnvironment, principal: &TestUser, member: &TestUser) {
    env.atm
        .trust_tasks()
        .mux_revoke(&principal.profile, false, vec![], vec![member.did.clone()])
        .await
        .expect("mux_revoke");
}

fn change<'a>(events: &'a [Value], kind: &str, member: &str) -> Option<&'a Value> {
    events
        .iter()
        .find(|e| e["change"] == kind && e["member"] == member)
}

/// An administrator that opts in sees the grant attach and the revoke detach,
/// each with the reason `messaging/mux/event` reported, the connection's wire
/// and session, and how the member rode it.
#[tokio::test]
async fn an_opted_in_subscriber_sees_attach_and_detach_with_their_reasons() {
    let env = mux_env().await;
    let admin = watcher(&env, "admin", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let granted = subscribe_v0_2(
        &env,
        &admin,
        json!({ "membership": { "dids": [work.did_hash()] }, "leaseSeconds": 120 }),
    )
    .await;
    assert_eq!(
        granted["membership"],
        json!({ "dids": [work.did_hash()] }),
        "the effective membership filter is echoed"
    );
    assert!(granted.get("traffic").is_none(), "traffic stays on");
    let sub = granted["subscriptionId"].clone();

    open_mux(&env, &device).await;
    grant(&env, &work, &device).await;
    revoke(&env, &device, &work).await;

    let work_hash = work.did_hash();
    let batches = batches_until(&env, &admin, common::EVENT_WAIT, |b| {
        change(&membership_of(b, &sub), "detached", &work_hash).is_some()
    })
    .await;
    let events = membership_of(&batches, &sub);
    let attached = change(&events, "attached", &work_hash).expect("attached seen");
    let detached = change(&events, "detached", &work_hash).expect("detached seen");
    for (e, reason) in [(attached, "grant"), (detached, "revokedByPrincipal")] {
        assert_eq!(e["reason"], reason, "{e}");
        assert_eq!(e["principal"], device.did_hash().as_str(), "{e}");
        assert_eq!(e["wire"], "didcomm", "{e}");
        assert_eq!(e["source"], "grant", "{e}");
        assert!(e["sessionId"].is_string(), "{e}");
        assert!(e["occurredAt"].is_string(), "{e}");
        assert!(
            e.get("scope").is_none() && e.get("grantId").is_none(),
            "{e}"
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|e| e["member"] == work_hash.as_str())
            .count(),
        2,
        "one event per change: {events:#?}"
    );
    for b in batches
        .iter()
        .filter(|b| b["payload"]["subscriptionId"] == sub)
    {
        assert_eq!(b["type"], EVENT_V0_3, "{b}");
        assert!(b.get("proof").is_some(), "every batch is signed");
        assert!(
            b["payload"]["membershipDropped"].is_u64(),
            "membershipDropped rides every opted-in batch: {b}"
        );
    }
}

/// Membership events are opt-in: a 0.2 subscription without the filter, and
/// a 0.1 one, see none, and the 0.1 one is still sent event 0.2 batches.
#[tokio::test]
async fn without_the_filter_no_membership_events_are_sent() {
    use affinidi_messaging_sdk::protocols::trust_tasks::decode_monitor_event;

    let env = mux_env().await;
    let admin = watcher(&env, "admin", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let plain = subscribe_v0_2(&env, &admin, json!({ "leaseSeconds": 120 })).await;
    assert!(
        plain.get("membership").is_none(),
        "no filter asked for, none granted: {plain}"
    );
    let plain_id = plain["subscriptionId"].clone();
    let old = env
        .atm
        .trust_tasks()
        .monitor_subscribe(&admin.profile, None, Some(120), None, None)
        .await
        .expect("subscribe 0.1");
    let old_id = json!(old.subscription_id.to_string());
    // A third, opted in, shows when the changes have been reported.
    let probe = subscribe_v0_2(&env, &admin, json!({ "membership": {}, "traffic": false })).await;
    let probe_id = probe["subscriptionId"].clone();

    open_mux(&env, &device).await;
    grant(&env, &work, &device).await;
    revoke(&env, &device, &work).await;

    let work_hash = work.did_hash();
    let mut batches = batches_until(&env, &admin, common::EVENT_WAIT, |b| {
        change(&membership_of(b, &probe_id), "detached", &work_hash).is_some()
    })
    .await;
    assert!(
        change(&membership_of(&batches, &probe_id), "detached", &work_hash).is_some(),
        "the changes were reported to the subscriber that asked"
    );
    // Batches already in flight for the others.
    batches.extend(batches_until(&env, &admin, Duration::from_millis(2500), |_| false).await);

    let mine = |id: &Value| -> Vec<&Value> {
        batches
            .iter()
            .filter(|b| b["payload"]["subscriptionId"] == *id)
            .collect()
    };
    assert!(!mine(&plain_id).is_empty() && !mine(&old_id).is_empty());
    for b in mine(&plain_id) {
        assert_eq!(b["type"], EVENT_V0_3, "{b}");
        assert!(b["payload"].get("membership").is_none(), "{b}");
        assert!(b["payload"].get("membershipDropped").is_none(), "{b}");
    }
    for b in mine(&old_id) {
        assert_eq!(
            b["type"], EVENT_V0_2,
            "a 0.1 subscription gets 0.2 batches: {b}"
        );
        assert!(b["payload"].get("membership").is_none(), "{b}");
        assert!(b["payload"].get("membershipDropped").is_none(), "{b}");
    }
    // And the SDK, which reads 0.2 only, still decodes them.
    let message = affinidi_messaging_didcomm::message::Message::build(
        "x".to_string(),
        affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE.to_string(),
        mine(&old_id)[0].clone(),
    )
    .finalize();
    assert!(decode_monitor_event(&message).is_some());
}

/// A standard account is narrowed to the changes it is party to, here as the
/// member, and may not name another account.
#[tokio::test]
async fn a_standard_account_sees_only_changes_it_is_party_to() {
    let env = mux_env().await;
    let work = watcher(&env, "work", AccountType::Standard).await;
    let device = env.add_user("device").await.unwrap();
    let home = env.add_user("home").await.unwrap();

    let refused = send_raw_task(
        &env,
        &work,
        SUBSCRIBE_V0_2,
        json!({ "membership": { "dids": [home.did_hash()] }, "traffic": false }),
    )
    .await;
    assert!(
        refused.to_string().contains("permissionDenied"),
        "naming another account is refused, not narrowed: {refused}"
    );

    let granted = subscribe_v0_2(&env, &work, json!({ "membership": {}, "traffic": false })).await;
    assert_eq!(
        granted["membership"],
        json!({ "dids": [work.did_hash()] }),
        "narrowed to its own account"
    );
    assert_eq!(granted["traffic"], false);
    let sub = granted["subscriptionId"].clone();

    open_mux(&env, &device).await;
    grant(&env, &home, &device).await;
    grant(&env, &work, &device).await;
    revoke(&env, &device, &home).await;
    revoke(&env, &device, &work).await;

    let work_hash = work.did_hash();
    let batches = batches_until(&env, &work, common::EVENT_WAIT, |b| {
        change(&membership_of(b, &sub), "detached", &work_hash).is_some()
    })
    .await;
    let events = membership_of(&batches, &sub);
    assert!(
        change(&events, "attached", &work_hash).is_some(),
        "{events:#?}"
    );
    assert!(
        change(&events, "detached", &work_hash).is_some(),
        "{events:#?}"
    );
    let home_hash = home.did_hash();
    assert!(
        events.iter().all(|e| e["member"] != home_hash.as_str()),
        "another member's changes are not shown: {events:#?}"
    );
}

/// `traffic: false` is a membership-only tap: traffic flows meanwhile, and
/// none of it is sent. It must come with `membership`, and without `filter`.
#[tokio::test]
async fn traffic_off_sends_membership_and_no_traffic() {
    let env = mux_env().await;
    let admin = watcher(&env, "admin", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();

    for bad in [
        json!({ "traffic": false }),
        json!({ "traffic": false, "membership": {}, "filter": {} }),
    ] {
        let body = send_raw_task(&env, &admin, SUBSCRIBE_V0_2, bad.clone()).await;
        assert!(
            body.to_string().contains("malformedRequest"),
            "{bad} is refused: {body}"
        );
    }

    let granted = subscribe_v0_2(&env, &admin, json!({ "membership": {}, "traffic": false })).await;
    assert_eq!(granted["traffic"], false);
    assert_eq!(granted["filter"], json!({}));
    assert_eq!(granted["membership"], json!({}));
    let sub = granted["subscriptionId"].clone();

    open_mux(&env, &device).await;
    grant(&env, &work, &device).await;
    // Traffic the tap would otherwise show.
    let t = chrono::Utc::now().timestamp() as u64;
    let msg = affinidi_messaging_didcomm::message::Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "not for the tap" }),
    )
    .to(work.did.clone())
    .from(sender.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &work.did, Some(&sender.did), Some(&sender.did))
        .await
        .unwrap();
    env.atm
        .send_message(&sender.profile, &packed, &msg.id, false, false)
        .await
        .unwrap();
    revoke(&env, &device, &work).await;

    let work_hash = work.did_hash();
    let batches = batches_until(&env, &admin, common::EVENT_WAIT, |b| {
        change(&membership_of(b, &sub), "detached", &work_hash).is_some()
    })
    .await;
    let events = membership_of(&batches, &sub);
    assert!(
        change(&events, "attached", &work_hash).is_some(),
        "{events:#?}"
    );
    for b in batches
        .iter()
        .filter(|b| b["payload"]["subscriptionId"] == sub)
    {
        assert_eq!(b["payload"]["events"], json!([]), "no traffic events: {b}");
        assert_eq!(b["payload"]["dropped"], 0, "{b}");
    }
}

/// A connection ending is not a detach, so it reports nothing; a stored grant
/// re-attached on the next connect is reported `attached` with `connect`.
#[tokio::test]
async fn a_reconnect_reports_connect_and_the_close_reports_nothing() {
    let env = mux_env().await;
    let admin = watcher(&env, "admin", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let granted = subscribe_v0_2(&env, &admin, json!({ "membership": {}, "traffic": false })).await;
    let sub = granted["subscriptionId"].clone();

    open_mux(&env, &device).await;
    grant(&env, &work, &device).await;
    device
        .profile
        .stop_websocket()
        .await
        .expect("close the mux socket");
    open_mux(&env, &device).await;

    let work_hash = work.did_hash();
    let connected = |events: &[Value]| {
        events.iter().any(|e| {
            e["change"] == "attached"
                && e["member"] == work_hash.as_str()
                && e["reason"] == "connect"
        })
    };
    let batches = batches_until(&env, &admin, common::EVENT_WAIT, |b| {
        connected(&membership_of(b, &sub))
    })
    .await;
    let events = membership_of(&batches, &sub);
    assert!(connected(&events), "{events:#?}");
    assert!(
        change(&events, "detached", &work_hash).is_none(),
        "the close is not a detach: {events:#?}"
    );
    assert_eq!(
        events.len(),
        2,
        "the grant's attach, then the connect: {events:#?}"
    );
}
