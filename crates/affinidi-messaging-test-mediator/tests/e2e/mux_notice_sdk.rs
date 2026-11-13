//! Durable mux notices consumed through the SDK (`affinidi-messaging-sdk`
//! 0.45.2+): a principal on a mux connection subscribes to
//! `ATMProfile::mux_notices()`, receives a verified `grantsSuspended` live,
//! and acknowledges it with `ack_mux_notice`, which deletes it from its inbox.
//! Complements `mux_notice.rs`, which reads notices from the store.
use crate::common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_sdk::messages::Folder;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, ack_mux_notice, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use serde_json::json;
use tokio::time::timeout;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

#[tokio::test]
async fn the_sdk_receives_verifies_and_acks_a_notice() {
    common::init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let member = env.add_multi_key_user("work", 2).await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&phone.profile)
        .await
        .expect("mux websocket");
    let mut notices = phone.profile.mux_notices().await.expect("notice stream");
    let mut ready_rx = phone.profile.mux_ready().await.unwrap();
    let ready = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(ready.pending_notices, Some(0));

    // key-1 grant for the phone (the SDK signs with the member's first auth key).
    let scope = [MuxCapability::Receive];
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &phone.did,
        &mediator_did,
        &scope,
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&phone.profile, vec![g])
        .await
        .expect("grant");

    // key-2 grant for the laptop: suspends the phone's.
    let key2 = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-2"))
        .unwrap();
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let g2 = sign_trust_task(
        &json!({
            "type": "muxGrant", "issuer": member.did, "audience": mediator_did,
            "grantId": Uuid::new_v4().to_string(), "principal": laptop.did,
            "scope": ["receive"], "epoch": 0, "iat": t, "exp": t + 3600,
        }),
        key2,
        SignOptions::new(),
    )
    .await
    .unwrap();
    env.atm.profile_add(&laptop.profile, true).await.unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&laptop.profile, vec![g2])
        .await
        .expect("grant 2");

    let delivery = timeout(Duration::from_secs(5), notices.recv())
        .await
        .expect("notice in 5s")
        .unwrap();
    let p = serde_json::to_value(&delivery.document.payload).unwrap();
    assert_eq!(p["notice"], "grantsSuspended", "{p:#}");
    assert_eq!(p["suspensions"][0]["did"], member.did);

    let store = env.mediator.store();
    let count = || async {
        store
            .list_messages(&phone.did_hash(), Folder::Inbox, None, 100)
            .await
            .unwrap()
            .len()
    };
    assert_eq!(
        count().await,
        1,
        "the notice waits in the inbox until acked"
    );
    ack_mux_notice(&env.atm, &phone.profile, &delivery)
        .await
        .expect("ack");
    assert_eq!(count().await, 0, "acked: deleted");
}

/// A grant for `principal` signed by `member`'s key whose id ends `#{key}`.
async fn grant_by_key(
    member: &affinidi_messaging_test_mediator::TestUser,
    key: &str,
    principal: &str,
    mediator_did: &str,
) -> serde_json::Value {
    let secret = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with(&format!("#{key}")))
        .unwrap();
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sign_trust_task(
        &json!({
            "type": "muxGrant", "issuer": member.did, "audience": mediator_did,
            "grantId": Uuid::new_v4().to_string(), "principal": principal,
            "scope": ["receive"], "epoch": 0, "iat": t, "exp": t + 3600,
        }),
        secret,
        SignOptions::new(),
    )
    .await
    .unwrap()
}

/// Two grants on one member DID, signed by different keys and presented at
/// the same moment, commit one after the other: whichever lands second
/// suspends the first, never neither and never both active.
#[tokio::test]
async fn concurrent_grants_from_different_keys_serialise() {
    use affinidi_messaging_mediator_common::store::mux::{self, MuxGrantState, MuxLimits};
    common::init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let mediator_did = env.mediator.did().to_string();
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    env.atm.profile_add(&phone.profile, true).await.unwrap();
    env.atm.profile_add(&laptop.profile, true).await.unwrap();
    let store = env.mediator.store();

    for round in 0..8 {
        let member = env
            .add_multi_key_user(&format!("work-{round}"), 2)
            .await
            .unwrap();
        let g1 = grant_by_key(&member, "key-1", &phone.did, &mediator_did).await;
        let g2 = grant_by_key(&member, "key-2", &laptop.did, &mediator_did).await;
        let tt = env.atm.trust_tasks();
        let (r1, r2) = tokio::join!(
            tt.mux_grant(&phone.profile, vec![g1]),
            tt.mux_grant(&laptop.profile, vec![g2]),
        );
        r1.expect("phone grant");
        r2.expect("laptop grant");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let rec = mux::load(&*store, &member.did_hash(), &MuxLimits::default(), now)
            .await
            .unwrap();
        let states: Vec<_> = rec.grants.iter().map(|g| g.state_at(now)).collect();
        assert_eq!(rec.grants.len(), 2, "round {round}: {states:?}");
        assert_eq!(
            states
                .iter()
                .filter(|s| **s == MuxGrantState::Active)
                .count(),
            1,
            "round {round}: exactly one active: {states:?}"
        );
        assert_eq!(
            states
                .iter()
                .filter(|s| **s == MuxGrantState::Suspended)
                .count(),
            1,
            "round {round}: the other suspended: {states:?}"
        );
    }
}

/// Acknowledging a notice twice deletes it once: the repeat reports that
/// nothing was deleted and touches no other message in the inbox.
#[tokio::test]
async fn a_repeated_ack_deletes_nothing_more() {
    common::init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&phone.profile)
        .await
        .expect("mux websocket");
    let mut notices = phone.profile.mux_notices().await.expect("notice stream");
    let mut ready_rx = phone.profile.mux_ready().await.unwrap();
    timeout(Duration::from_secs(5), async {
        while ready_rx.borrow().is_none() {
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap();

    // Two member DIDs each suspend the phone's grant, so two notices wait in
    // the phone's inbox.
    env.atm.profile_add(&laptop.profile, true).await.unwrap();
    for name in ["work", "home"] {
        let member = env.add_multi_key_user(name, 2).await.unwrap();
        let g = grant_by_key(&member, "key-1", &phone.did, &mediator_did).await;
        env.atm
            .trust_tasks()
            .mux_grant(&phone.profile, vec![g])
            .await
            .expect("phone grant");
        let g = grant_by_key(&member, "key-2", &laptop.did, &mediator_did).await;
        env.atm
            .trust_tasks()
            .mux_grant(&laptop.profile, vec![g])
            .await
            .expect("laptop grant");
    }
    let first = timeout(Duration::from_secs(5), notices.recv())
        .await
        .expect("notice in 5s")
        .unwrap();
    let store = env.mediator.store();
    let count = || async {
        store
            .list_messages(&phone.did_hash(), Folder::Inbox, None, 100)
            .await
            .unwrap()
            .len()
    };
    let before = timeout(Duration::from_secs(5), async {
        loop {
            let n = count().await;
            if n >= 2 {
                return n;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("two notices wait");

    ack_mux_notice(&env.atm, &phone.profile, &first)
        .await
        .expect("first ack");
    assert_eq!(count().await, before - 1);
    assert!(
        ack_mux_notice(&env.atm, &phone.profile, &first)
            .await
            .is_err(),
        "the repeat deletes nothing, and says so"
    );
    assert_eq!(count().await, before - 1, "no other message touched");
}
