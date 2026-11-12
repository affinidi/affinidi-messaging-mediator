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

/// `messaging/mux/connections`: an administrator lists the live mux
/// connections, with each member's source, scope and delivery state; filters
/// by member; pages under a member budget; and a non-administrator is
/// refused.
#[tokio::test]
async fn an_administrator_lists_live_mux_connections() {
    use affinidi_messaging_mediator_common::types::accounts::AccountType;
    use affinidi_messaging_sdk::protocols::trust_tasks::MuxConnectionsQuery;
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
    let (g, grant_id) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive, MuxCapability::Delete],
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

    let tasks = env.atm.trust_tasks();
    let list = |q: MuxConnectionsQuery| {
        let tasks = &tasks;
        let admin = &admin;
        async move {
            serde_json::to_value(
                tasks
                    .mux_connections(&admin.profile, &q)
                    .await
                    .expect("mux_connections"),
            )
            .unwrap()
        }
    };

    // Everything: one connection, both members, in DID order.
    let page = list(MuxConnectionsQuery::all()).await;
    assert_eq!(
        page["coverage"], "allInstances",
        "an in-process store: {page:#}"
    );
    let conns = page["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1, "{page:#}");
    let c = &conns[0];
    assert_eq!(c["principal"], device.did.as_str());
    assert_eq!(c["sessionId"], ready.session_id.as_str());
    assert_eq!(c["wire"], "didcomm");
    assert_eq!(c["memberCount"], 2);
    let mut want = [work.did.clone(), temp.did.clone()];
    want.sort();
    let dids: Vec<&str> = c["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["did"].as_str().unwrap())
        .collect();
    assert_eq!(dids, want.iter().map(String::as_str).collect::<Vec<_>>());
    let by_did = |did: &str| {
        c["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["did"] == did)
            .cloned()
            .unwrap()
    };
    let w = by_did(&work.did);
    assert_eq!(w["source"], "grant");
    assert_eq!(w["grantId"], grant_id.as_str());
    assert_eq!(w["scope"], serde_json::json!(["receive", "delete"]));
    assert_eq!(w["deliveryActive"], true);
    let t = by_did(&temp.did);
    assert_eq!(t["source"], "attach");
    assert!(t.get("grantId").is_none());

    // Filtered by member: that member alone, the count still exact.
    let page = list(MuxConnectionsQuery::all().member(&work.did)).await;
    let c = &page["connections"][0];
    assert_eq!(c["members"].as_array().unwrap().len(), 1);
    assert_eq!(c["members"][0]["did"], work.did.as_str());
    assert_eq!(c["memberCount"], 2);
    let none = list(MuxConnectionsQuery::all().principal(&work.did)).await;
    assert_eq!(none["connections"], serde_json::json!([]));

    // A member budget of one splits the connection across two pages.
    let p1 = list(MuxConnectionsQuery::all().member_limit(1)).await;
    assert_eq!(p1["connections"][0]["members"].as_array().unwrap().len(), 1);
    let cursor = p1["nextCursor"].as_str().expect("more to come").to_string();
    let p2 = list(
        MuxConnectionsQuery::all()
            .member_limit(1)
            .cursor(cursor.clone()),
    )
    .await;
    assert_eq!(p2["connections"][0]["sessionId"], ready.session_id.as_str());
    assert_ne!(
        p2["connections"][0]["members"][0]["did"],
        p1["connections"][0]["members"][0]["did"]
    );
    assert!(p2.get("nextCursor").is_none());
    // The cursor belongs to that request: other filters refuse it.
    let refused = tasks
        .mux_connections(
            &admin.profile,
            &MuxConnectionsQuery::all()
                .member_limit(1)
                .member(&work.did)
                .cursor(cursor),
        )
        .await;
    assert!(refused.is_err(), "a cursor for other filters: {refused:?}");

    // A summary without members.
    let summary = list(MuxConnectionsQuery::all().member_limit(0)).await;
    assert_eq!(summary["connections"][0]["members"], serde_json::json!([]));
    assert_eq!(summary["connections"][0]["memberCount"], 2);

    // Not an administrator: refused.
    env.atm
        .profile_add(&work.profile, true)
        .await
        .expect("work websocket");
    let refused = tasks
        .mux_connections(&work.profile, &MuxConnectionsQuery::all())
        .await;
    assert!(
        refused.is_err(),
        "a standard account is refused: {refused:?}"
    );
}

/// `messaging/mux/ack` on the DIDComm mux socket: the device acks a member's
/// message there (no REST delete), the member's inbox drains, and the answer
/// comes back on the connection without being stored, since a stored one
/// would need acknowledging in turn (spec, consumer rule 4).
#[tokio::test]
async fn an_ack_on_the_socket_is_answered_there_and_not_stored() {
    use affinidi_messaging_sdk::messages::fetch::FetchOptions;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
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
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut members_rx = device.profile.mux_members().await.expect("members");
    let (g_work, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive, MuxCapability::Delete],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g_work])
        .await
        .expect("mux_grant");
    members_until(&mut members_rx, "work attached", |m| {
        m.is_reachable(&work.did)
    })
    .await;

    send(&env, &sender, &work, "for work").await;
    let pickup = env.atm.message_pickup();
    let work_id = loop {
        let (msg, meta) = pickup
            .live_stream_next(&device.profile, Some(Duration::from_secs(5)), false)
            .await
            .unwrap()
            .expect("a message");
        if msg.typ == "https://didcomm.org/basicmessage/2.0/message" {
            assert_eq!(mux_recipient(&meta).as_deref(), Some(work.did.as_str()));
            break meta.sha256_hash.clone();
        }
    };

    // The ack, sent on the socket as the SDK sends a Trust Task.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signer = device
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .expect("device's Ed25519 key");
    let doc = sign_trust_task(
        &json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": "https://trusttasks.org/spec/messaging/mux/ack/0.1",
            "issuer": device.did,
            "recipient": mediator_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "messageIds": [work_id] },
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign the ack");
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://trusttasks.org/binding/didcomm/0.1/envelope".to_string(),
        doc,
    )
    .to(mediator_did.clone())
    .from(device.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&device.did), None)
        .await
        .unwrap();
    env.atm
        .send_message(&device.profile, &packed, &msg.id, false, false)
        .await
        .expect("ack sent on the socket");

    // The answer arrives on the connection (read without deleting it).
    let (answer, answer_meta) = loop {
        let (m, meta) = pickup
            .live_stream_next(&device.profile, Some(Duration::from_secs(5)), false)
            .await
            .unwrap()
            .expect("the ack's answer");
        if m.thid.as_deref() == Some(msg.id.as_str()) {
            break (m, meta);
        }
    };
    assert_eq!(
        answer.body["type"], "https://trusttasks.org/spec/messaging/mux/ack/0.1#response",
        "{:#}",
        answer.body
    );
    assert_eq!(answer.body["payload"]["acked"], json!([work_id]));

    let store = env.mediator.store();
    assert_eq!(
        store
            .inbox_status(&work.did_hash())
            .await
            .unwrap()
            .message_count,
        0,
        "the member's message was deleted by the ack"
    );
    let inbox = store
        .fetch_messages("test", &device.did_hash(), &FetchOptions::default())
        .await
        .unwrap();
    assert!(
        inbox
            .success
            .iter()
            .all(|m| m.msg_id != answer_meta.sha256_hash),
        "the ack's answer must not be stored"
    );
    env.shutdown().await.unwrap();
}

/// The SDK's mux connection is dropped by the mediator and the SDK reconnects
/// on its own (design §10, "Disconnect/reconnect"): the new socket gets a new
/// `ready`, the stored grant comes back attached without the device doing
/// anything, and a member's message that arrived while the SDK was off is
/// delivered after the reconnect.
///
/// The drop: a second mux socket for the same principal, opened by hand,
/// replaces the SDK's ("replaced by a newer connection"). That socket holds
/// the principal's slot while the member's message arrives (it is pushed
/// there, which proves the SDK was not connected) and never acknowledges it.
/// The SDK's own reconnect (after its ~1 s backoff for a young socket) then
/// replaces the hand-opened socket, and the unacknowledged message is
/// redelivered to it.
#[tokio::test]
async fn after_a_reconnect_stored_grants_reattach_and_missed_mail_arrives() {
    use futures_util::StreamExt;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{ClientRequestBuilder, Message, http::Uri},
    };
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
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut ready_rx = device.profile.mux_ready().await.expect("mux ready watch");
    let first = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow_and_update().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("ready within 5s");
    let (g, grant_id) = sign_grant(
        &env.atm,
        &work.did,
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
        .mux_grant(&device.profile, vec![g])
        .await
        .expect("mux_grant");
    let mut members_rx = device.profile.mux_members().await.expect("mux members");
    members_until(&mut members_rx, "work attached", |m| {
        m.is_reachable(&work.did)
    })
    .await;

    // A second mux socket for the device replaces the SDK's.
    let tokens = env
        .tdk
        .authentication()
        .authenticate(device.did.clone(), mediator_did.clone(), 3, None)
        .await
        .expect("authenticate device");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut raw, _) = connect_async(request).await.expect("upgrade");
    let mut conn = device
        .profile
        .connection_state()
        .await
        .expect("connection state");
    timeout(
        Duration::from_secs(5),
        conn.wait_for(|s| !matches!(s, affinidi_messaging_core::ConnState::Connected)),
    )
    .await
    .expect("the SDK's socket is dropped")
    .unwrap();

    // `work`'s mail arrives while the SDK is off: pushed to the socket that
    // holds the device's slot, which does not acknowledge it.
    send(&env, &sender, &work, "while away").await;
    let pushed = timeout(Duration::from_secs(5), async {
        loop {
            match raw.next().await {
                Some(Ok(Message::Text(t))) => {
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
                    let to_work = v["recipients"].as_array().is_some_and(|rs| {
                        rs.iter().any(|r| {
                            r["header"]["kid"]
                                .as_str()
                                .is_some_and(|k| k.starts_with(&work.did))
                        })
                    });
                    if to_work {
                        return;
                    }
                }
                Some(Ok(_)) => continue,
                other => panic!("the hand-opened socket went before the push: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        pushed.is_ok(),
        "the message arrived while the SDK was not connected"
    );

    // The SDK reconnects by itself: a new `ready` (a new connection nonce;
    // the session id is the login's and is kept), and the stored grant is
    // attached again without the device asking.
    timeout(Duration::from_secs(15), async {
        loop {
            if let Some(r) = ready_rx.borrow_and_update().clone()
                && r.mux_nonce != first.mux_nonce
            {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("a new ready after the SDK reconnects");
    let members = members_until(&mut members_rx, "work attached again", |m| {
        m.is_reachable(&work.did)
    })
    .await;
    let w = members.get(&work.did).unwrap();
    assert_eq!(w.grant_id.as_deref(), Some(grant_id.as_str()));
    assert!(w.delivery_active);

    // The hand-opened socket was replaced in turn.
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match raw.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the SDK's reconnect replaces the other socket"
    );

    // The message that arrived while away, never acknowledged, is
    // redelivered; new mail is pushed live.
    let next_basic = async || loop {
        let (msg, meta) = env
            .atm
            .message_pickup()
            .live_stream_next(&device.profile, Some(Duration::from_secs(5)), true)
            .await
            .unwrap()
            .expect("a message");
        if msg.typ == "https://didcomm.org/basicmessage/2.0/message" {
            return (
                mux_recipient(&meta).unwrap(),
                msg.body["content"].as_str().unwrap().to_string(),
            );
        }
    };
    assert_eq!(
        next_basic().await,
        (work.did.clone(), "while away".to_string())
    );
    send(&env, &sender, &work, "after").await;
    assert_eq!(next_basic().await, (work.did.clone(), "after".to_string()));
}
