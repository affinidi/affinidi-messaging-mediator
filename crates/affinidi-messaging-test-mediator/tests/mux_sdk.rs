//! DID multiplexing driven entirely through the SDK's mux client
//! (`affinidi-messaging-sdk` 0.45.1+): one websocket carries live delivery for
//! several member DIDs, from grants stored while connected and an attach
//! scoped to the connection, and the device acknowledges, lists and revokes
//! through the SDK. Complements `mux_connection.rs`, which drives the wire
//! protocol by hand.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_sdk::protocols::mux::{
    MemberChangeReason, MuxCapability, MuxMembers, mux_recipient, sign_attach, sign_grant,
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::json;
use tokio::time::timeout;
use uuid::Uuid;

/// Wait until the profile's mux member set satisfies `done`.
async fn members_until(
    rx: &mut tokio::sync::watch::Receiver<MuxMembers>,
    what: &str,
    done: impl Fn(&MuxMembers) -> bool,
) -> MuxMembers {
    timeout(Duration::from_secs(5), async {
        loop {
            let m = rx.borrow_and_update().clone();
            if done(&m) {
                return m;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("member set: {what}: {:?}", rx.borrow()))
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
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
        .unwrap();
    env.atm
        .send_message(&from.profile, &packed, &msg.id, false, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_sdk_drives_a_mux_connection_end_to_end() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    // 1. Open the mux connection; wait for `ready`.
    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut events = device.profile.mux_events().await.expect("mux events");
    let mut ready_rx = device.profile.mux_ready().await.expect("mux ready watch");
    let ready = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("ready within 5s");
    assert_eq!(ready.mux_nonce.len(), 43);

    // 2. Two members grant the device while it is connected.
    let scope = [
        MuxCapability::Receive,
        MuxCapability::Pickup,
        MuxCapability::Delete,
    ];
    let (g_work, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &scope,
        0,
        3600,
    )
    .await
    .unwrap();
    let (g_home, _) = sign_grant(
        &env.atm,
        &home.did,
        &device.did,
        &mediator_did,
        &scope,
        0,
        3600,
    )
    .await
    .unwrap();
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g_work, g_home])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert!(
        r["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["status"] == "stored"),
        "{r:#}"
    );

    // 3. A third DID attaches for this connection only.
    let a_temp = sign_attach(
        &env.atm,
        &temp.did,
        &device.did,
        &mediator_did,
        &ready.session_id,
        &ready.mux_nonce,
        &[MuxCapability::Receive, MuxCapability::Delete],
        600,
    )
    .await
    .unwrap();
    let r = env
        .atm
        .trust_tasks()
        .mux_attach(&device.profile, vec![a_temp])
        .await
        .expect("mux_attach");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "attached", "{r:#}");

    // `attached` events arrived for the two grants (live admission).
    let mut attached = Vec::new();
    while let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events.recv()).await {
        let v = serde_json::to_value(&ev).unwrap();
        if v["event"] == "attached" {
            for d in v["dids"].as_array().unwrap() {
                attached.push(d["did"].as_str().unwrap().to_string());
            }
        }
    }
    for d in [&work.did, &home.did] {
        assert!(attached.contains(d), "attached event for {d}: {attached:?}");
    }

    // The SDK keeps the member set from those events (0.45.5): the two
    // grants and the attach, each with its scope, the principal not among
    // them.
    let mut members_rx = device.profile.mux_members().await.expect("mux members");
    let members = members_until(&mut members_rx, "three members", |m| {
        [&work.did, &home.did, &temp.did]
            .iter()
            .all(|d| m.is_reachable(d))
    })
    .await;
    assert!(members.is_ready());
    assert_eq!(members.len(), 3, "{members:?}");
    assert!(members.get(&device.did).is_none());
    let w = members.get(&work.did).unwrap();
    assert_eq!(w.scope, scope.to_vec());
    assert!(w.grant_id.is_some(), "carried by a grant");
    let t = members.get(&temp.did).unwrap();
    assert_eq!(t.scope, vec![MuxCapability::Receive, MuxCapability::Delete]);
    assert!(t.grant_id.is_none(), "a session attach has no grant");
    assert_eq!(
        t.reason,
        MemberChangeReason::Attach,
        "reported as an attach"
    );

    // Narrowing a grant is reported too, with the new scope (spec event
    // rule 5): the device drops `pickup` from `work`.
    let narrowed = [MuxCapability::Receive, MuxCapability::Delete];
    env.atm
        .trust_tasks()
        .mux_update(
            &device.profile,
            w.grant_id.as_deref().unwrap(),
            Some(&narrowed),
            None,
        )
        .await
        .expect("mux_update");
    let members = members_until(&mut members_rx, "work narrowed", |m| {
        m.get(&work.did).is_some_and(|w| w.scope == narrowed)
    })
    .await;
    let w = members.get(&work.did).unwrap();
    assert_eq!(w.reason, MemberChangeReason::Grant);
    assert!(w.delivery_active);

    // `home` connects its own socket, which takes its live traffic: it stays
    // a member, inactive. Narrowing its grant meanwhile must not report it
    // active again; its own socket going away does.
    env.atm
        .profile_add(&home.profile, true)
        .await
        .expect("home's own websocket");
    let members = members_until(&mut members_rx, "home inactive", |m| {
        m.get(&home.did).is_some_and(|h| !h.delivery_active)
    })
    .await;
    let home_grant = members.get(&home.did).unwrap().grant_id.clone().unwrap();
    env.atm
        .trust_tasks()
        .mux_update(&device.profile, &home_grant, Some(&narrowed), None)
        .await
        .expect("mux_update home");
    let members = members_until(&mut members_rx, "home narrowed", |m| {
        m.get(&home.did).is_some_and(|h| h.scope == narrowed)
    })
    .await;
    assert!(
        !members.is_reachable(&home.did),
        "narrowing must not report an inactive member active: {:?}",
        members.get(&home.did)
    );
    home.profile.stop_websocket().await.expect("stop home");
    members_until(&mut members_rx, "home reactivated", |m| {
        m.is_reachable(&home.did)
    })
    .await;

    // 4. Messages for all three arrive on the one socket, routed by recipient,
    //    and are acknowledged (auto_delete) over REST as the device.
    for (u, t) in [(&work, "w"), (&home, "h"), (&temp, "t")] {
        send(&env, &sender, u, t).await;
    }
    let mut got = Vec::new();
    while got.len() < 3 {
        let (msg, meta) = env
            .atm
            .message_pickup()
            .live_stream_next(&device.profile, Some(Duration::from_secs(5)), true)
            .await
            .unwrap()
            .expect("a message");
        // The device's own control traffic (e.g. the pickup status answering
        // its live-delivery toggle) shares the stream; only the basic
        // messages are under test.
        if msg.typ != "https://didcomm.org/basicmessage/2.0/message" {
            continue;
        }
        got.push((
            mux_recipient(&meta).unwrap(),
            msg.body["content"].as_str().unwrap().to_string(),
        ));
    }
    got.sort();
    let mut want = vec![
        (work.did.clone(), "w".to_string()),
        (home.did.clone(), "h".to_string()),
        (temp.did.clone(), "t".to_string()),
    ];
    want.sort();
    assert_eq!(got, want);

    // Acks landed: each member's inbox drains.
    let store = env.mediator.store();
    timeout(Duration::from_secs(5), async {
        loop {
            let mut left = 0;
            for u in [&work, &home, &temp] {
                left += store
                    .inbox_status(&u.did_hash())
                    .await
                    .unwrap()
                    .message_count;
            }
            if left == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("members' inboxes drained by auto_delete");

    // 5. list, then revoke `home`: it stops being carried.
    let list = env
        .atm
        .trust_tasks()
        .mux_list(&device.profile, false, None, None)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&list).unwrap()["grants"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    env.atm
        .trust_tasks()
        .mux_revoke(&device.profile, false, vec![], vec![home.did.clone()])
        .await
        .unwrap();
    let members = members_until(&mut members_rx, "home detached", |m| {
        m.get(&home.did).is_none()
    })
    .await;
    assert!(members.is_reachable(&work.did) && members.is_reachable(&temp.did));
    send(&env, &sender, &home, "after revoke").await;
    let after = env
        .atm
        .message_pickup()
        .live_stream_next(&device.profile, Some(Duration::from_millis(800)), false)
        .await
        .unwrap();
    assert!(
        after
            .as_ref()
            .is_none_or(|(m, _)| m.typ != "https://didcomm.org/basicmessage/2.0/message"),
        "a revoked member's message must not reach the device: {after:?}"
    );
}

/// A member holding `pickup` but not `receive` is never pushed its messages,
/// but the principal is told they wait: a message-pickup `status` naming the
/// member arrives while connected. Narrowing a grant to drop `receive` stops
/// the pushes at once, checked when the frame is written, not when the
/// member joined.
#[tokio::test]
async fn pickup_only_members_get_a_status_not_a_push() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut members_rx = device.profile.mux_members().await.expect("mux members");
    let (g_work, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Pickup, MuxCapability::Delete],
        0,
        3600,
    )
    .await
    .unwrap();
    let (g_home, home_grant) = sign_grant(
        &env.atm,
        &home.did,
        &device.did,
        &mediator_did,
        &[
            MuxCapability::Receive,
            MuxCapability::Pickup,
            MuxCapability::Delete,
        ],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g_work, g_home])
        .await
        .expect("mux_grant");
    members_until(&mut members_rx, "both members", |m| {
        m.get(&work.did).is_some() && m.get(&home.did).is_some()
    })
    .await;
    // `home` narrows to pickup only: no more pushes for it.
    let pickup_only = [MuxCapability::Pickup, MuxCapability::Delete];
    env.atm
        .trust_tasks()
        .mux_update(&device.profile, &home_grant, Some(&pickup_only), None)
        .await
        .expect("mux_update");
    members_until(&mut members_rx, "home narrowed", |m| {
        m.get(&home.did).is_some_and(|h| h.scope == pickup_only)
    })
    .await;

    send(&env, &sender, &work, "for work").await;
    send(&env, &sender, &home, "for home").await;

    // Statuses for both arrive; no basic message is pushed.
    let mut told = std::collections::HashSet::new();
    timeout(Duration::from_secs(15), async {
        while told.len() < 2 {
            let Some((msg, _)) = env
                .atm
                .message_pickup()
                .live_stream_next(&device.profile, Some(Duration::from_secs(1)), false)
                .await
                .unwrap()
            else {
                continue;
            };
            assert_ne!(
                msg.typ, "https://didcomm.org/basicmessage/2.0/message",
                "a member without receive must not be pushed its message"
            );
            if msg.typ == "https://didcomm.org/messagepickup/3.0/status"
                && msg.body["message_count"].as_u64().unwrap_or(0) > 0
                && let Some(d) = msg.body["recipient_did"].as_str()
                && (d == work.did || d == home.did)
            {
                told.insert(d.to_string());
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("a status for each pickup-only member: {told:?}"));
    // The messages stay stored for pickup.
    let store = env.mediator.store();
    for u in [&work, &home] {
        assert_eq!(
            store
                .inbox_status(&u.did_hash())
                .await
                .unwrap()
                .message_count,
            1
        );
    }
}

/// `messaging/stats/show` reports this instance's mux connections and
/// members under its `com.affinidi.mux` extension, for the console's
/// dashboard.
#[tokio::test]
async fn stats_show_counts_mux_connections_and_members() {
    use affinidi_messaging_mediator_common::types::accounts::AccountType;
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let admin = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin websocket");
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut ready_rx = device.profile.mux_ready().await.unwrap();
    let ready = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("ready");
    let (g, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g])
        .await
        .expect("grant");
    let a = sign_attach(
        &env.atm,
        &temp.did,
        &device.did,
        &mediator_did,
        &ready.session_id,
        &ready.mux_nonce,
        &[MuxCapability::Receive],
        600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_attach(&device.profile, vec![a])
        .await
        .expect("attach");
    let mut members_rx = device.profile.mux_members().await.unwrap();
    members_until(&mut members_rx, "two members", |m| m.len() == 2).await;

    let stats = env
        .atm
        .trust_tasks()
        .stats_show(&admin.profile)
        .await
        .expect("stats");
    let stats = serde_json::to_value(&stats).unwrap();
    let mux = &stats["ext"]["com.affinidi.mux"];
    assert_eq!(mux["scope"], "instance", "{stats:#}");
    assert_eq!(mux["connections"], 1);
    assert_eq!(mux["members"], 2);
    assert_eq!(mux["membersByGrant"], 1);
    assert_eq!(mux["membersByAttach"], 1);
    assert_eq!(mux["membersInactive"], 0);
}
