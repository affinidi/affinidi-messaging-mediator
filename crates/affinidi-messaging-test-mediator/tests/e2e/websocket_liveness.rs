//! WebSocket liveness: the mediator pings every `limits.ws_ping_interval_secs`
//! and closes, with 1001, a socket whose ping has gone unanswered (no frame
//! at all from the peer) for `ws_pong_timeout_secs - ws_ping_interval_secs`.
//! Time the mediator's own loop spends not reading is not held against the
//! peer. The connection's slots are given back when it closes.

use crate::common;

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

/// The test mediator's liveness settings: ping interval and pong timeout.
const PING_SECS: u64 = 2;
const PONG_SECS: u64 = 4;
/// How many fresh windows the mediator may give one unanswered ping when its
/// loop was busy (`PingWatch::MAX_EXTENSIONS`).
const MAX_EXTENSIONS: u64 = 2;

/// The longest a silent client may take to be closed: the first ping (one
/// interval after the socket opens), its grace, every fresh window a busy
/// loop may add, and a margin for a slow machine.
fn close_bound() -> Duration {
    let grace = PONG_SECS - PING_SECS;
    Duration::from_secs(PING_SECS + grace + MAX_EXTENSIONS * PING_SECS + 5)
}

/// Read the server's frames off the TCP stream *without answering any*, up
/// to the end of the stream, and return the code of the close frame if one
/// came. A WebSocket client library answers each ping as it reads it, and a
/// pong written to a socket the server has already closed draws a TCP reset,
/// which can discard the close frame before it is read; reading the raw
/// bytes keeps the client truly silent until the server is done.
async fn raw_close_code(socket: &mut Socket, within: Duration) -> Option<u16> {
    use tokio::io::AsyncReadExt;
    let MaybeTlsStream::Plain(tcp) = socket.get_mut() else {
        panic!("the test mediator serves plain ws://");
    };
    let mut bytes = Vec::new();
    timeout(within, tcp.read_to_end(&mut bytes))
        .await
        .expect("the server should have closed the socket within the bound")
        .expect("read the server's frames");
    // Server frames are unmasked, and every frame here is a small control
    // frame: FIN|opcode, a 7-bit length, then the payload.
    let mut at = 0;
    while at + 2 <= bytes.len() {
        let opcode = bytes[at] & 0x0f;
        let len = usize::from(bytes[at + 1] & 0x7f);
        let payload = &bytes[at + 2..(at + 2 + len).min(bytes.len())];
        match opcode {
            0x9 => {} // ping
            0x8 if payload.len() >= 2 => return Some(u16::from_be_bytes([payload[0], payload[1]])),
            0x8 => return None,
            other => panic!("unexpected frame opcode {other:#x} on a silent socket"),
        }
        at += 2 + len;
    }
    None
}

#[tokio::test]
async fn a_client_that_never_answers_pings_is_disconnected() {
    init_tracing();

    // Ping every 2 s; 2 s of grace for an unanswered ping. One socket per
    // DID, so a second socket only opens once the first has given its slot
    // back.
    let mediator = TestMediator::builder()
        .websocket_liveness(PING_SECS, PONG_SECS, 5)
        .max_websocket_connections_per_did(1)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // Open a socket and answer nothing. The client reads only raw bytes,
    // so none of the mediator's pings is answered.
    let mut silent = open_ws(&env, &alice).await;
    let started = std::time::Instant::now();
    let code = raw_close_code(&mut silent, close_bound()).await;
    let took = started.elapsed();
    assert_eq!(
        code,
        Some(1001),
        "a socket that answered no ping is closed as unresponsive (1001), with a close frame"
    );
    // Not before the first ping's grace could have run out.
    assert!(
        took >= Duration::from_secs(PONG_SECS - PING_SECS),
        "closed after {took:?}, before an unanswered ping's grace"
    );
    drop(silent);

    // The slot was given back: under a cap of one socket per DID, a new
    // socket for the same DID is admitted (an over-cap one is closed at once
    // with 1008), and one that reads (and so answers each ping) stays open
    // well past the deadline.
    let mut reading = open_ws(&env, &alice).await;
    let stayed_open = read_for(&mut reading, close_bound()).await;
    assert!(
        stayed_open.is_err(),
        "the slot must be released and a socket that answers pings must stay open, \
         got: {stayed_open:?}"
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
        .websocket_liveness(PING_SECS, PONG_SECS, 5)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // Right after each of its next three pings that start a wait, the
    // mediator's loop for this socket spends 4.5 s not reading, as a long
    // flush or a slow message would. The client answers every ping at once,
    // but the mediator only reads the answer after the ping's grace has run
    // out.
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
