//! The console's live monitor against a live in-process mediator, at both
//! `monitor/subscribe` versions: 0.2 carries traffic and, opted in, mux
//! membership (read as `monitor/event` 0.3); a mediator that refuses 0.2 as
//! an unsupported type — as one that predates it does — is asked again at
//! 0.1, and its traffic still arrives.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_admin::{
    ConsoleError, Identity, MediatorConsole, MonitorFeed, MonitorFilter, MonitorUpdate,
};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_sdk::protocols::trust_tasks::MonitorSubscription;
use affinidi_messaging_sdk::tasks::messaging::monitor;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use serde_json::{Value, json};
use tokio::time::timeout;
use trust_tasks_rs::Payload as _;

async fn env(withhold_subscribe_v0_2: bool) -> TestEnvironment {
    let mut builder = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false);
    if withhold_subscribe_v0_2 {
        builder = builder.withhold_task_types([monitor::subscribe::v0_2::Payload::TYPE_URI]);
    }
    let mediator = builder.spawn().await.expect("spawn mediator");
    TestEnvironment::new(mediator).await.expect("environment")
}

fn identity(env: &TestEnvironment, user: &TestUser) -> Identity {
    Identity {
        alias: user.alias.clone(),
        did: user.did.clone(),
        secrets: user.secrets.clone(),
        mediator_did: Some(env.mediator.did().to_string()),
    }
}

async fn admin(env: &TestEnvironment) -> (TestUser, MediatorConsole) {
    let op = env.add_user("operator").await.expect("operator");
    env.mediator
        .store()
        .account_set_role(&op.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    let console = MediatorConsole::connect(identity(env, &op))
        .await
        .expect("operator connects");
    (op, console)
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "hello from the monitor version tests" }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(now)
    .expires_time(now + 600)
    .finalize();
    let id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .expect("pack");
    env.atm
        .send_message(&from.profile, &packed, &id, false, false)
        .await
        .expect("send");
}

/// What a feed has yielded, as JSON.
#[derive(Default, Debug)]
struct Seen {
    traffic: Vec<Value>,
    membership: Vec<Value>,
}

/// Read `feed` until `done` holds over what it has yielded.
async fn read_until(feed: &mut MonitorFeed, done: impl Fn(&Seen) -> bool) -> Seen {
    let mut seen = Seen::default();
    let read = timeout(Duration::from_secs(10), async {
        while !done(&seen) {
            match feed.next().await.expect("the feed is open") {
                MonitorUpdate::Events { events, .. } => seen
                    .traffic
                    .extend(events.into_iter().map(|e| serde_json::to_value(e).unwrap())),
                MonitorUpdate::Membership { events, .. } => seen
                    .membership
                    .extend(events.into_iter().map(|e| serde_json::to_value(e).unwrap())),
                MonitorUpdate::Ended(reason) => panic!("feed ended: {reason}"),
                MonitorUpdate::Gap { .. } | MonitorUpdate::Heartbeat => {}
            }
        }
    })
    .await;
    assert!(read.is_ok(), "the feed yielded only {seen:#?}");
    seen
}

fn stored_for(seen: &Seen, to: &str, from: &str) -> bool {
    seen.traffic
        .iter()
        .any(|e| e["stage"] == "stored" && e["to"] == to && e["from"] == from)
}

fn attached(seen: &Seen, member: &str) -> bool {
    seen.membership
        .iter()
        .any(|e| e["change"] == "attached" && e["member"] == member && e["reason"] == "grant")
}

#[tokio::test(flavor = "multi_thread")]
async fn at_subscribe_0_2_a_feed_carries_traffic_and_membership() {
    let env = env(false).await;
    let (_op, console) = admin(&env).await;
    let alice = env.add_user("alice").await.unwrap();
    let bob = env.add_user("bob").await.unwrap();
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    let mut feed = console
        .monitor_with(filter, Some(serde_json::from_value(json!({})).unwrap()))
        .await
        .expect("a 0.2 feed with membership");
    assert!(feed.membership().is_some(), "mux is on: membership is sent");

    // Traffic: alice writes to bob.
    send(&env, &alice, &bob).await;
    // Membership: work grants the device's mux connection.
    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let (grant, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        env.mediator.did(),
        &[MuxCapability::Receive, MuxCapability::Pickup],
        0,
        3600,
    )
    .await
    .expect("sign grant");
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![grant])
        .await
        .expect("mux_grant");

    let (bob_hash, alice_hash, work_hash) = (bob.did_hash(), alice.did_hash(), work.did_hash());
    read_until(&mut feed, |s| {
        stored_for(s, &bob_hash, &alice_hash) && attached(s, &work_hash)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mediator_without_subscribe_0_2_is_watched_at_0_1_with_traffic_only() {
    let env = env(true).await;
    let (op, console) = admin(&env).await;
    let alice = env.add_user("alice").await.unwrap();
    let bob = env.add_user("bob").await.unwrap();

    // The mediator's release is current, so the console asks at 0.2 first:
    // the fallback below is the runtime one, on the mediator's refusal.
    assert!(console.serves_mux_admin());
    // That refusal is real: 0.2 asked directly is an unsupported type.
    let refused = env
        .atm
        .trust_tasks()
        .monitor_subscribe_with(&op.profile, &MonitorSubscription::new())
        .await
        .expect_err("0.2 is withheld");
    assert!(
        format!("{refused:?}").contains("protocol.trust_task.unsupported"),
        "{refused:?}"
    );

    // Membership needs 0.2, so asking for it is refused, not quietly
    // dropped.
    let membership = console
        .monitor_with(
            serde_json::from_value(json!({})).unwrap(),
            Some(serde_json::from_value(json!({})).unwrap()),
        )
        .await;
    assert!(
        matches!(&membership, Err(ConsoleError::Refused { code, .. })
            if code.ends_with("protocol.trust_task.unsupported")),
        "{:?}",
        membership.err()
    );

    // A traffic-only feed falls back to 0.1 and still sees traffic.
    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    let mut feed = console.monitor(filter).await.expect("a 0.1 feed");
    assert!(feed.membership().is_none(), "0.1 carries no membership");
    assert_eq!(
        serde_json::to_value(feed.filter()).unwrap()["dids"],
        json!([bob.did_hash()]),
        "the 0.1 grant's filter reads back"
    );

    send(&env, &alice, &bob).await;
    let (bob_hash, alice_hash) = (bob.did_hash(), alice.did_hash());
    let seen = read_until(&mut feed, |s| stored_for(s, &bob_hash, &alice_hash)).await;
    assert!(seen.membership.is_empty(), "{seen:#?}");
}
