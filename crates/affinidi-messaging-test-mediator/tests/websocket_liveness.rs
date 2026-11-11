//! WebSocket liveness: the mediator pings every `limits.ws_ping_interval_secs`
//! and closes, with 1001, a socket whose ping has gone unanswered (no frame
//! at all from the peer) for `ws_pong_timeout_secs - ws_ping_interval_secs`.
//! Time the mediator's own loop spends not reading is not held against the
//! peer. The connection's slots are given back when it closes.

mod common;

use std::time::Duration;

use affinidi_messaging_mediator::handlers::websocket::test_hooks::stall_loop_after_ping;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a WebSocket for `user` with a fresh access token.
async fn open_ws(env: &TestEnvironment, user: &TestUser) -> Socket {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate user");
    let ws_uri: Uri = env
        .mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");
    // A benign app subprotocol so the server selects one (tokio-tungstenite's
    // client refuses a handshake where none is selected).
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (stream, response) = connect_async(request).await.expect("upgrade reaches 101");
    assert_eq!(response.status().as_u16(), 101);
    stream
}

/// Read until the server's close, skipping pings, and return its code.
/// Bounded overall: once this reads, the client answers pings, so a socket
/// the server had not closed by now would stay open.
async fn close_code(socket: &mut Socket) -> Option<u16> {
    timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(Some(frame)))) => return Some(u16::from(frame.code)),
                Some(Ok(Message::Close(None))) | None | Some(Err(_)) => return None,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .expect("the server should have closed the socket")
}

#[tokio::test]
async fn a_client_that_never_answers_pings_is_disconnected() {
    init_tracing();

    // Ping every 2 s; 2 s of grace for an unanswered ping. One socket per
    // DID, so a second socket only opens once the first has given its slot
    // back.
    let mediator = TestMediator::builder()
        .websocket_liveness(2, 4, 5)
        .max_websocket_connections_per_did(1)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // Open a socket and read nothing: its pings go unanswered, because a
    // client only answers a ping when it reads it.
    let mut silent = open_ws(&env, &alice).await;
    // The first ping goes out about 2 s after the socket opens and has 2 s of
    // grace; 9 s leaves room for a slow machine.
    tokio::time::sleep(Duration::from_secs(9)).await;

    // Reading now shows the pings that were never answered, then the close.
    assert_eq!(
        close_code(&mut silent).await,
        Some(1001),
        "a socket that answered no ping is closed as unresponsive (1001)"
    );

    // The slot was given back: a new socket for the same DID opens, and one
    // that reads (and so answers each ping) stays open past the deadline.
    let mut reading = open_ws(&env, &alice).await;
    let stayed_open = read_for(&mut reading, Duration::from_secs(10)).await;
    assert!(
        stayed_open.is_err(),
        "a socket that answers pings must stay open, got: {stayed_open:?}"
    );

    drop(reading);
    env.shutdown().await.expect("shutdown");
}

/// Read for `for_how_long`, answering pings (a client answers a ping when it
/// reads it); `Err` if the socket stayed open the whole time.
async fn read_for(socket: &mut Socket, for_how_long: Duration) -> Result<Option<Message>, ()> {
    timeout(for_how_long, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(other)) => return Some(other),
                _ => return None,
            }
        }
    })
    .await
    .map_err(|_| ())
}

#[tokio::test]
async fn a_client_that_answers_pings_survives_a_busy_mediator_loop() {
    init_tracing();

    // Ping every 2 s; 2 s of grace for an unanswered ping.
    let mediator = TestMediator::builder()
        .websocket_liveness(2, 4, 5)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // Right after each of its next three pings, the mediator's loop for this
    // socket spends 4.5 s not reading, as a long flush or a slow message
    // would. The client answers every ping at once, but the mediator only
    // reads the answer after the ping's grace has run out.
    stall_loop_after_ping(&alice.did_hash(), Duration::from_millis(4500), 3);
    let mut socket = open_ws(&env, &alice).await;

    let outcome = read_for(&mut socket, Duration::from_secs(25)).await;
    assert!(
        outcome.is_err(),
        "a client that answers pings must stay open while the mediator is busy, got: {outcome:?}"
    );

    drop(socket);
    env.shutdown().await.expect("shutdown");
}
