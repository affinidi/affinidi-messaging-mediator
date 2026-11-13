//! Limits on anonymous inter-mediator relay WebSockets.
//!
//! Relay sockets carry no DID, so they all share one connection bucket. Two
//! bounds keep that bucket usable by every peer:
//!
//! 1. One client address may hold only `limits.relay_connections_per_ip`
//!    relay sockets; the next is closed with 1013 (try again later), and a
//!    slot freed by closing one is reusable.
//! 2. Each relay socket has an inbound frame budget. A frame over it is
//!    answered with a negative ack carrying 429, so the relaying mediator
//!    sends that message over REST instead of the frame being lost.

use crate::common;

use std::time::Duration;

use affinidi_messaging_mediator_common::tasks::forwarding::relay_ack::{
    RELAY_ACK_SUBPROTOCOL, RelayAck, frame_id,
};
use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle, acl};
use common::init_tracing;
use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message as WsMessage, http::Uri},
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn spawn_relay_mediator(
    connections_per_ip: usize,
    frames: u32,
    burst: u32,
) -> TestMediatorHandle {
    TestMediator::builder()
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        .relay_limits(connections_per_ip, frames, burst)
        .spawn()
        .await
        .expect("spawn relay mediator")
}

async fn open_relay(mediator: &TestMediatorHandle) -> Ws {
    let uri: Uri = mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");
    let request = ClientRequestBuilder::new(uri).with_sub_protocol(RELAY_ACK_SUBPROTOCOL);
    let (stream, _) = connect_async(request)
        .await
        .expect("relay upgrade must be admitted");
    stream
}

/// The close code the server sends within `wait`, or `None` if the socket
/// stays open (pings and other frames are skipped).
async fn closed_with(stream: &mut Ws, wait: Duration) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => return None,
            Ok(Some(Ok(WsMessage::Close(Some(cf))))) => return Some(u16::from(cf.code)),
            Ok(Some(Ok(WsMessage::Close(None)))) | Ok(None) | Ok(Some(Err(_))) => {
                return Some(0);
            }
            Ok(Some(Ok(_))) => continue,
        }
    }
}

async fn next_ack(stream: &mut Ws) -> RelayAck {
    loop {
        let frame = timeout(Duration::from_secs(15), stream.next())
            .await
            .expect("a relay-ack must arrive")
            .expect("the relay socket must stay open")
            .expect("the relay socket must not error");
        if let WsMessage::Text(text) = frame
            && let Ok(ack) = serde_json::from_str::<RelayAck>(&text)
        {
            return ack;
        }
    }
}

#[tokio::test]
async fn one_address_cannot_hold_more_relay_sockets_than_its_share() {
    init_tracing();
    let mediator = spawn_relay_mediator(2, 50, 100).await;

    let mut first = open_relay(&mediator).await;
    let mut second = open_relay(&mediator).await;
    // The per-address check runs after the 101 the client already saw.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut third = open_relay(&mediator).await;
    assert_eq!(
        closed_with(&mut third, Duration::from_secs(5)).await,
        Some(1013),
        "the socket over the per-address share is closed with try-again-later"
    );

    // The two within the share are untouched.
    assert_eq!(
        closed_with(&mut first, Duration::from_millis(300)).await,
        None
    );
    assert_eq!(
        closed_with(&mut second, Duration::from_millis(300)).await,
        None
    );

    // Closing one frees its place for the same address.
    first.close(None).await.expect("close first");
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut replacement = open_relay(&mediator).await;
    assert_eq!(
        closed_with(&mut replacement, Duration::from_millis(500)).await,
        None,
        "a freed place is reusable"
    );

    drop((second, replacement));
    mediator.shutdown();
}

#[tokio::test]
async fn frames_over_a_relay_socket_budget_are_nacked_with_429() {
    init_tracing();
    // One frame per second, burst of two.
    let mediator = spawn_relay_mediator(10, 1, 2).await;
    let mut stream = open_relay(&mediator).await;

    let mut codes = Vec::new();
    for i in 0..4 {
        // Not an envelope: within budget it is refused for what it is, over
        // budget it is refused before being looked at.
        let frame = format!("not a DIDComm envelope {i}");
        stream
            .send(WsMessage::Text(frame.clone().into()))
            .await
            .expect("send frame");
        let ack = next_ack(&mut stream).await;
        assert!(ack.answers(&frame_id(frame.as_bytes())));
        assert!(!ack.ok);
        codes.push(ack.code);
    }
    assert_ne!(codes[0], Some(429), "within budget: {codes:?}");
    assert_ne!(codes[1], Some(429), "within budget: {codes:?}");
    assert_eq!(codes[2], Some(429), "over budget: {codes:?}");
    assert_eq!(codes[3], Some(429), "over budget: {codes:?}");

    // The socket stays open: a throttled frame does not end the connection,
    // and the budget refills.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let frame = "not a DIDComm envelope after refill";
    stream
        .send(WsMessage::Text(frame.into()))
        .await
        .expect("send after refill");
    let ack = next_ack(&mut stream).await;
    assert_ne!(ack.code, Some(429), "the budget refills: {ack:?}");

    drop(stream);
    mediator.shutdown();
}
