//! Message rate on authenticated WebSockets (`limits.ws_messages_per_second`,
//! `ws_message_burst`, `ws_message_throttle_close_secs`, and the per-DID
//! limit charged per message).
//!
//! A message over the rate is not dropped: the mediator stops reading the
//! socket until it is due. That is observable from the client as the time a
//! ping takes to be answered, because the mediator only reads (and answers)
//! the ping once it has read every message sent before it. A socket that
//! stays over the rate is closed with 1008.
//!
//! The messages sent here are binary frames that are neither TSP nor UTF-8,
//! which the mediator reads and discards without answering, so the only
//! traffic back is the pong and, at the end, the close.

mod common;

use std::time::{Duration, Instant};

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A message the mediator reads and discards.
fn junk() -> Message {
    Message::Binary(vec![0xFF, 0xFE, 0xFD].into())
}

async fn open_ws(env: &TestEnvironment, did: &str) -> Ws {
    let token = env
        .tdk
        .authentication()
        .authenticate(did.to_string(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate")
        .access_token;
    let uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{token}"));
    let (ws, response) = connect_async(request).await.expect("upgrade");
    assert_eq!(response.status().as_u16(), 101);
    ws
}

/// Send `count` messages back-to-back, then a ping, and return how long the
/// pong took from the first message. Panics if the socket is closed first.
async fn send_then_ping(ws: &mut Ws, count: usize) -> Duration {
    let started = Instant::now();
    for _ in 0..count {
        ws.send(junk()).await.expect("send message");
    }
    let probe = b"rate-probe".to_vec();
    ws.send(Message::Ping(probe.clone().into()))
        .await
        .expect("send ping");
    let deadline = Duration::from_secs(30);
    loop {
        match timeout(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Pong(payload)))) if payload.as_ref() == probe.as_slice() => {
                return started.elapsed();
            }
            Ok(Some(Ok(Message::Close(frame)))) => panic!("socket closed: {frame:?}"),
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => panic!("socket error: {e}"),
            Ok(None) => panic!("socket ended"),
            Err(_) => panic!("no pong within {deadline:?}"),
        }
    }
}

async fn env_with(
    builder: affinidi_messaging_test_mediator::TestMediatorBuilder,
) -> TestEnvironment {
    let mediator = builder.spawn().await.expect("spawn mediator");
    TestEnvironment::new(mediator).await.expect("environment")
}

async fn user(env: &TestEnvironment, name: &str) -> TestUser {
    env.add_user(name).await.expect("add user")
}

#[tokio::test]
async fn steady_traffic_under_the_rate_is_not_slowed() {
    init_tracing();
    let env = env_with(TestMediator::builder().ws_message_rate(20, 5, 1)).await;
    let alice = user(&env, "Alice").await;
    let mut ws = open_ws(&env, &alice.did).await;

    // 10 messages a second against a rate of 20, for two seconds: longer than
    // the close deadline, so a socket wrongly counted as over the rate would
    // be closed.
    for _ in 0..20 {
        ws.send(junk()).await.expect("send");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let took = send_then_ping(&mut ws, 0).await;
    assert!(took < Duration::from_millis(500), "pong took {took:?}");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn a_burst_over_the_rate_is_slowed_not_dropped_or_closed() {
    init_tracing();
    // 10/s with a burst of 5, and plenty of time before a close.
    let env = env_with(TestMediator::builder().ws_message_rate(10, 5, 30)).await;
    let alice = user(&env, "Alice").await;
    let mut ws = open_ws(&env, &alice.did).await;

    // 25 messages at once: 5 in the burst, then 20 at 10/s — about two
    // seconds before the ping behind them is read.
    let took = send_then_ping(&mut ws, 25).await;
    assert!(
        took >= Duration::from_millis(1_500),
        "a burst over the rate must be slowed; pong after {took:?}"
    );
    assert!(took < Duration::from_secs(10), "pong took {took:?}");

    // The socket is still open and answers once the client is within the
    // rate again.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let took = send_then_ping(&mut ws, 1).await;
    assert!(took < Duration::from_millis(500), "pong took {took:?}");

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn a_socket_that_stays_over_the_rate_is_closed_with_1008() {
    init_tracing();
    let env = env_with(TestMediator::builder().ws_message_rate(5, 1, 1)).await;
    let alice = user(&env, "Alice").await;
    let ws = open_ws(&env, &alice.did).await;
    let (mut sink, mut stream) = ws.split();

    // Keep sending far faster than 5/s until the socket goes.
    let sender = tokio::spawn(async move {
        for _ in 0..10_000 {
            if sink.send(junk()).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let started = Instant::now();
    let close = loop {
        match timeout(Duration::from_secs(20), stream.next()).await {
            Ok(Some(Ok(Message::Close(frame)))) => break frame,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => panic!("socket error before a close frame: {e}"),
            Ok(None) => panic!("socket ended without a close frame"),
            Err(_) => panic!("socket over its rate was not closed"),
        }
    };
    sender.abort();
    let frame = close.expect("a close frame with a code");
    assert_eq!(u16::from(frame.code), 1008, "{frame:?}");
    assert_eq!(frame.reason.to_string(), "message rate limit exceeded");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "closed after {:?}, before the 1 s deadline",
        started.elapsed()
    );

    env.shutdown().await.expect("shutdown");
}

/// One DID's sockets share the per-DID budget: messages on a second socket
/// wait for the first socket's spending, though the second socket's own
/// budget is untouched.
#[tokio::test]
async fn one_did_pays_for_its_messages_across_sockets() {
    init_tracing();
    let env = env_with(
        TestMediator::builder()
            .did_rate_limit(2, 2)
            .ws_message_rate(1_000, 1_000, 30),
    )
    .await;
    let alice = user(&env, "Alice").await;
    let mut first = open_ws(&env, &alice.did).await;
    let mut second = open_ws(&env, &alice.did).await;

    // Let the DID's bucket (2 deep, 2/s) refill after the two upgrades.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // The first socket spends the DID's burst.
    send_then_ping(&mut first, 2).await;
    // The second socket's own budget is fresh, but the DID's is empty: two
    // messages at 2/s take about a second.
    let took = send_then_ping(&mut second, 2).await;
    assert!(
        took >= Duration::from_millis(700),
        "the second socket must wait for the DID's budget; pong after {took:?}"
    );

    env.shutdown().await.expect("shutdown");
}

/// The admin DID is not metered, per socket or per DID.
#[tokio::test]
async fn the_admin_did_is_not_metered() {
    init_tracing();
    let admin = TestMediator::random_admin_identity().expect("admin identity");
    let env = env_with(
        TestMediator::builder()
            .did_rate_limit(1, 1)
            .ws_message_rate(1, 1, 1)
            .admin_identity(admin.clone()),
    )
    .await;
    let admin_user = env.add_admin(admin).await.expect("admin");
    let mut ws = open_ws(&env, &admin_user.did).await;

    let took = send_then_ping(&mut ws, 30).await;
    assert!(
        took < Duration::from_millis(1_000),
        "admin messages were slowed; pong after {took:?}"
    );
    // Still open after more than the close deadline's worth of traffic.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    send_then_ping(&mut ws, 30).await;

    env.shutdown().await.expect("shutdown");
}

/// `0` turns the per-socket rate off (the per-DID limit is off by default).
#[tokio::test]
async fn zero_turns_the_socket_rate_off() {
    init_tracing();
    let env = env_with(TestMediator::builder().ws_message_rate(0, 1, 1)).await;
    let alice = user(&env, "Alice").await;
    let mut ws = open_ws(&env, &alice.did).await;

    let took = send_then_ping(&mut ws, 50).await;
    assert!(took < Duration::from_millis(1_000), "pong took {took:?}");

    env.shutdown().await.expect("shutdown");
}
