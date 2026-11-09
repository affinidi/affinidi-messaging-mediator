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
    MuxCapability, mux_recipient, sign_attach, sign_grant,
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::json;
use tokio::time::timeout;
use uuid::Uuid;

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
