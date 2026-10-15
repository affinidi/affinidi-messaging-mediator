//! Abandoned cross-mediator forwards must be *readable* by the sender.
//!
//! When mediator A gives up on relaying a forward it stores a
//! `report-problem/2.0` in the original sender's inbox saying so. That report
//! was built as raw JSON and stored unpacked, so on a live VTC the mediator
//! logged
//!
//! ```text
//! INFO ...forwarding::processor: FORWARD_PROBLEM_REPORT: stored problem report
//!   1a23bf7e… for sender b9b77027…
//! ```
//!
//! while the sender's SDK logged
//!
//! ```text
//! ERROR affinidi_messaging_sdk::transports::websockets::websocket:
//!   Error unpacking message: UnexpectedEnvelope("envelope wrapping Plaintext is
//!   not in the accepted set [AuthcryptPlaintext, AuthcryptSignPlaintext,
//!   AnoncryptAuthcryptPlaintext]")
//! ```
//!
//! — the mediator believed it had explained itself and the sender saw nothing.
//! Every forwarding abandonment was silent, on every mediator pair, once the
//! SDK's default receive policy became authcrypt-only.
//!
//! The assertion that matters here is therefore **not** that a report was
//! stored (it always was) but that the sender can `unpack` it under the default
//! policy. Two real mediators, real `did:peer` identities, real keys — the only
//! thing arranged is that node 1 is dead before the forward is sent, so the
//! relay hop can never succeed.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestTopology, TestUser};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

/// Wait until nothing is listening on `addr`, so the relay hop is guaranteed to
/// fail on connect rather than racing the shutdown.
async fn await_port_closed(addr: std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the downed mediator's port never closed");
}

/// Take node 1 down, then have `alice` (on node 0) send `bob` (on node 1) a
/// routing-2.0 double forward. Node 0 accepts it and can never relay it.
async fn send_doomed_forward(topology: &TestTopology, alice: &TestUser, bob: &TestUser) {
    let node_a = topology.node(0).expect("node 0");
    let node_b = topology.node(1).expect("node 1");
    let mediator_a_did = node_a.mediator.did().to_string();
    let mediator_b_did = node_b.mediator.did().to_string();
    let mediator_b_addr = node_b.mediator.bound_addr();

    // Take mediator B down. Its `did:peer` still resolves (the DID carries its
    // own service endpoint), so mediator A will accept the forward, queue it,
    // and then fail every attempt to hand it over.
    node_b.mediator.shutdown();
    await_port_closed(mediator_b_addr).await;

    // The routing-2.0 double forward: authcrypt for Bob, an INNER forward to
    // Bob's (now dead) mediator, an OUTER forward to Alice's own mediator.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "this one is never going to arrive" }),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();

    let (packed, _) = node_a
        .atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("authcrypt for Bob");

    let (_inner_id, inner_fwd) = node_a
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &packed,
            &mediator_b_did,
            &bob.did,
            None,
            None,
        )
        .await
        .expect("wrap inner forward");

    let (_outer_id, outer_fwd) = node_a
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &inner_fwd,
            &mediator_a_did,
            &mediator_b_did,
            None,
            None,
        )
        .await
        .expect("wrap outer forward");

    node_a
        .atm
        .send_message(&alice.profile, &outer_fwd, &msg_id, false, false)
        .await
        .expect("send outer forward to Alice's own mediator");
}

/// A topology whose forwarding gives up on the first failed attempt.
async fn spawn_topology() -> TestTopology {
    // `max_retries = 0` abandons on the first delivery failure: the retry ladder
    // is real `sleep` inside the processor task, and the production default
    // (5 retries doubling from 1s) would put ~31s of it in front of the only
    // event these tests care about.
    TestTopology::builder()
        .mediators(2)
        .configure_each(|b| {
            b.forwarding_retry_policy(0, Duration::from_millis(50), Duration::from_millis(100))
        })
        .spawn()
        .await
        .expect("spawn 2-mediator topology")
}

#[tokio::test]
async fn abandoned_forward_report_unpacks_under_the_default_policy() {
    init_tracing();

    let topology = spawn_topology().await;

    // Users are added through the node directly rather than
    // `TestTopology::add_user`, which brings up a live WebSocket: this test
    // wants to read the report exactly as a client would on pickup.
    let node_a = topology.node(0).expect("node 0");
    let node_b = topology.node(1).expect("node 1");
    let alice = node_a.add_user("Alice").await.expect("add Alice on node 0");
    let bob = node_b.add_user("Bob").await.expect("add Bob on node 1");

    let mediator_a_did = node_a.mediator.did().to_string();
    let mediator_b_did = node_b.mediator.did().to_string();

    send_doomed_forward(&topology, &alice, &bob).await;

    // Alice picks up whatever her mediator left for her.
    let stored = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let fetched = node_a
                .atm
                .fetch_messages(&alice.profile, &FetchOptions::default())
                .await
                .expect("Alice fetches messages");
            if let Some(element) = fetched.success.first()
                && let Some(body) = element.msg.clone()
            {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("no abandonment report reached Alice's inbox");

    // THE assertion. Before the fix this is where the test fails, with the same
    // `UnexpectedEnvelope(...)` the live client logged — a version of this test
    // that only checked "a report was stored" would have passed on the bug.
    let (report, metadata) = node_a
        .atm
        .unpack(&stored)
        .await
        .expect("Alice unpacks the abandonment report under the default policy");

    assert_eq!(
        report.typ, "https://didcomm.org/report-problem/2.0/problem-report",
        "the stored message is the forwarding-abandonment problem report"
    );
    assert_eq!(
        report.body.get("code").and_then(|c| c.as_str()),
        Some("e.p.me.res.forwarding.abandoned"),
        "the report says the forward was abandoned"
    );
    assert_eq!(
        report.from.as_deref(),
        Some(mediator_a_did.as_str()),
        "the report is authored by Alice's own mediator"
    );
    assert_eq!(
        report.to.as_deref(),
        Some(&[alice.did.clone()][..]),
        "the report is addressed to the sender of the abandoned forward"
    );
    assert!(
        metadata.encrypted && metadata.authenticated,
        "the report must reach Alice authenticated, not as bare plaintext: {metadata:?}"
    );
    // The named destination is the *next hop* that could not be reached —
    // Bob's mediator — not Bob. That is the layer the sender addressed in the
    // outer forward, and the only one this mediator can speak to.
    assert!(
        report
            .body
            .get("args")
            .and_then(|a| a.as_array())
            .is_some_and(
                |args| args.first().and_then(|a| a.as_str()) == Some(mediator_b_did.as_str())
            ),
        "the report names the next hop that could not be reached: {:?}",
        report.body
    );

    topology.shutdown().await.expect("shutdown topology");
}

/// A sender with a live socket hears about the abandonment as it happens.
///
/// The report used to be written into the inbox with no live notification, so
/// a connected client — which only learns of new messages from that
/// notification — saw nothing until some unrelated message woke it.
#[tokio::test]
async fn abandoned_forward_report_reaches_a_live_sender() {
    init_tracing();

    let topology = spawn_topology().await;
    let alice = topology.add_user(0, "Alice").await.expect("add live Alice");
    let bob = topology
        .node(1)
        .expect("node 1")
        .add_user("Bob")
        .await
        .expect("add Bob on node 1");
    let node_a = topology.node(0).expect("node 0");

    send_doomed_forward(&topology, &alice, &bob).await;

    // Well under the ~30 s a stranded message waits for an unrelated wake-up.
    // Other traffic (status replies) can share the stream, so skip it.
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    let found = loop {
        let remaining = until.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break false;
        }
        let next = node_a
            .atm
            .message_pickup()
            .live_stream_next(&alice.profile, Some(remaining), false)
            .await
            .expect("live stream");
        let Some((message, _)) = next else {
            break false;
        };
        if message.body.get("code").and_then(|c| c.as_str())
            == Some("e.p.me.res.forwarding.abandoned")
        {
            break true;
        }
        seen.push(message.typ);
    };
    assert!(
        found,
        "the abandonment report was never pushed to Alice's live socket; saw {seen:?}"
    );

    topology.shutdown().await.expect("shutdown topology");
}
