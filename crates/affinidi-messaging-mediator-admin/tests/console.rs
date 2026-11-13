//! The console against a live in-process mediator: connect as an identity,
//! discover the mode, operate, and watch traffic.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_admin::{
    ConsoleError, Identity, MediatorConsole, Mode, MonitorFilter, MonitorUpdate, PurgeRequest,
    specs,
};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use serde_json::json;

async fn env() -> TestEnvironment {
    TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("environment")
}

fn identity(env: &TestEnvironment, user: &TestUser) -> Identity {
    Identity {
        alias: user.alias.clone(),
        did: user.did.clone(),
        secrets: user.secrets.clone(),
        mediator_did: Some(env.mediator.did().to_string()),
    }
}

async fn promote(env: &TestEnvironment, user: &TestUser, role: AccountType) {
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("promote");
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "hello from the console tests" }),
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

#[tokio::test(flavor = "multi_thread")]
async fn a_standard_account_manages_its_own_queue_and_reads_its_own_mail() {
    use specs::message::list::v0_1::Queue;

    let env = env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    send(&env, &alice, &bob).await;
    send(&env, &alice, &bob).await;

    let console = MediatorConsole::connect(identity(&env, &bob))
        .await
        .expect("bob connects");
    assert_eq!(console.mode(), Mode::SelfService);
    assert!(console.capabilities().local);

    // Mediator-wide views are refused locally, before any request is sent.
    assert!(matches!(
        console.stats().await,
        Err(ConsoleError::NotPermitted(_))
    ));
    assert!(matches!(
        console.queue_status(Some(alice.did_hash()), None).await,
        Err(ConsoleError::NotPermitted(_))
    ));

    let page = console
        .messages(None, Queue::Receive, None, None, None)
        .await
        .expect("bob lists his queue");
    assert_eq!(page.messages.len(), 2);

    // Bob holds his own key, so the console opens the envelope locally.
    let inspected = console
        .inspect(None, &page.messages[0].msg_id.to_string())
        .await
        .expect("bob inspects his message");
    let (opened, _) = inspected.opened.expect("bob can decrypt his own mail");
    assert_eq!(opened.body["content"], "hello from the console tests");
}

/// A private SDK instance, as `MediatorConsole::connect` makes one.
async fn fresh_atm() -> affinidi_messaging_sdk::ATM {
    use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
    let tdk = TDKSharedState::new(TDKConfig::headless().expect("tdk config"))
        .await
        .expect("tdk");
    let config = affinidi_messaging_sdk::config::ATMConfig::builder()
        .build()
        .expect("atm config");
    affinidi_messaging_sdk::ATM::new(config, std::sync::Arc::new(tdk))
        .await
        .expect("atm")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_connection_state_is_live_and_other_mail_is_handed_on() {
    use affinidi_messaging_mediator_admin::ConnState;

    let env = env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let host = env.add_user("host").await.expect("host");

    let (tx, mut unclaimed) = tokio::sync::mpsc::channel(8);
    let console =
        MediatorConsole::connect_with_unclaimed(fresh_atm().await, identity(&env, &host), tx)
            .await
            .expect("host connects");

    let mut state = console
        .connection_state()
        .expect("the console runs a websocket");
    tokio::time::timeout(
        Duration::from_secs(10),
        state.wait_for(|s| *s == ConnState::Connected),
    )
    .await
    .expect("connected within ten seconds")
    .expect("state signal");

    // Mail for the console's DID that isn't a monitor batch reaches the
    // embedding application rather than vanishing.
    // (Other pushes, a pickup status say, may come first.)
    send(&env, &alice, &host).await;
    let message = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (message, _) = unclaimed.recv().await.expect("a message");
            if message.body["content"].is_string() {
                return message;
            }
        }
    })
    .await
    .expect("handed on within ten seconds");
    assert_eq!(message.body["content"], "hello from the console tests");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_previews_then_purges_only_what_the_preview_counted() {
    use specs::queue::purge::v0_1::Queue;

    let env = env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let op = env.add_user("operator").await.expect("operator");
    promote(&env, &op, AccountType::Admin).await;
    send(&env, &alice, &bob).await;
    send(&env, &alice, &bob).await;

    let console = MediatorConsole::connect(identity(&env, &op))
        .await
        .expect("operator connects");
    assert_eq!(console.mode(), Mode::Admin { root: false });
    // The version is read from the mediator's readyz probe at connect.
    let version = console
        .mediator_version()
        .expect("the mediator reports its version");
    assert_eq!(
        version.split('.').count(),
        3,
        "a major.minor.patch release: {version}"
    );
    assert!(console.serves_operations());
    console.stats().await.expect("admin reads stats");

    let request = PurgeRequest {
        target: Some(bob.did_hash()),
        queue: Queue::Receive,
        peer: Some(alice.did_hash()),
        older_than_seconds: None,
    };

    // The purge is pinned to the preview's instant, rounded to whole seconds
    // away from it: let the counted messages age past that first.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let plan = console
        .purge_preview(request.clone())
        .await
        .expect("preview");
    assert_eq!(plan.matched, 2);

    // A message that arrives between the preview and the confirmation is
    // not what the user confirmed, so it stays.
    send(&env, &alice, &bob).await;
    let done = console.purge(plan).await.expect("purge");
    assert_eq!(done.purged, 2);

    let left = console.purge_preview(request).await.expect("preview again");
    assert_eq!(left.matched, 1, "the newer message is still queued");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_watches_traffic_through_a_monitor_feed() {
    let env = env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let op = env.add_user("operator").await.expect("operator");
    promote(&env, &op, AccountType::Admin).await;

    let console = MediatorConsole::connect(identity(&env, &op))
        .await
        .expect("operator connects");
    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    let mut feed = console.monitor(filter).await.expect("monitor");

    send(&env, &alice, &bob).await;

    let bob_hash = bob.did_hash();
    let seen = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(update) = feed.next().await {
            if let MonitorUpdate::Events { events, .. } = update {
                for e in events {
                    let e = serde_json::to_value(e).unwrap();
                    if e["stage"] == "stored" && e["to"] == bob_hash.as_str() {
                        return Some(e);
                    }
                }
            }
        }
        None
    })
    .await
    .expect("an event within ten seconds")
    .expect("a stored event for bob");
    assert_eq!(seen["from"], alice.did_hash().as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_admin_changes_a_limit_and_an_admin_is_told_it_cannot() {
    let env = env().await;
    let root = env.add_user("root").await.expect("root");
    let admin = env.add_user("admin").await.expect("admin");
    promote(&env, &root, AccountType::RootAdmin).await;
    promote(&env, &admin, AccountType::Admin).await;

    let console = MediatorConsole::connect(identity(&env, &root))
        .await
        .expect("root connects");
    assert!(console.can_patch_config());
    let mut overrides = serde_json::Map::new();
    overrides.insert("limits.listed_messages".into(), json!(50));
    let answer =
        serde_json::to_value(console.patch_config(overrides).await.expect("patch")).unwrap();
    assert_eq!(answer["applied"], json!(["limits.listed_messages"]));

    let console = MediatorConsole::connect(identity(&env, &admin))
        .await
        .expect("admin connects");
    assert!(!console.can_patch_config());
    let mut overrides = serde_json::Map::new();
    overrides.insert("limits.listed_messages".into(), json!(40));
    assert!(matches!(
        console.patch_config(overrides).await,
        Err(ConsoleError::NotPermitted(_))
    ));
}
