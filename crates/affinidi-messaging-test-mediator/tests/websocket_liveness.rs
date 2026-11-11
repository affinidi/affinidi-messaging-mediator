//! WebSocket liveness: the mediator pings every `limits.ws_ping_interval_secs`
//! and closes a socket from which nothing (not even a pong) has arrived within
//! `limits.ws_pong_timeout_secs`, with 1001. The connection's slots are given
//! back when it closes.

mod common;

use std::time::Duration;

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
async fn close_code(socket: &mut Socket) -> Option<u16> {
    loop {
        match timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("the socket should be closed, not left open")
        {
            Some(Ok(Message::Close(Some(frame)))) => return Some(u16::from(frame.code)),
            Some(Ok(Message::Close(None))) | None | Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

#[tokio::test]
async fn a_client_that_never_answers_pings_is_disconnected() {
    init_tracing();

    // Ping every second; close after two seconds of silence. One socket per
    // DID, so a second socket only opens once the first has given its slot
    // back.
    let mediator = TestMediator::builder()
        .websocket_liveness(1, 2, 5)
        .max_websocket_connections_per_did(1)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // Open a socket and read nothing: its pings go unanswered, because a
    // client only answers a ping when it reads it.
    let mut silent = open_ws(&env, &alice).await;
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Reading now shows the pings that were never answered, then the close.
    assert_eq!(
        close_code(&mut silent).await,
        Some(1001),
        "a socket that answered no ping is closed as unresponsive (1001)"
    );

    // The slot was given back: a new socket for the same DID opens, and one
    // that reads (and so answers each ping) stays open past the deadline.
    let mut reading = open_ws(&env, &alice).await;
    let stayed_open = timeout(Duration::from_secs(5), async {
        loop {
            match reading.next().await {
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                other => return other,
            }
        }
    })
    .await;
    assert!(
        stayed_open.is_err(),
        "a socket that answers pings must stay open, got: {stayed_open:?}"
    );

    drop(reading);
    env.shutdown().await.expect("shutdown");
}
