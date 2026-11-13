//! WebSocket admission and frame limits as a client sees them.
//!
//! - `limits.max_websocket_connections = 0` means "unlimited", as documented;
//!   it used to refuse every socket with 1013 (#147).
//! - A frame over `limits.ws_size` closes the socket with 1009 ("message too
//!   big"), so the client knows the message was the problem; it used to end
//!   silently, read as the client leaving (#139).

use crate::common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri, protocol::frame::coding::CloseCode},
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn open_ws(env: &TestEnvironment, user: &TestUser) -> Ws {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (ws, response) = connect_async(request).await.expect("upgrade");
    assert_eq!(response.status().as_u16(), 101);
    ws
}

/// The first close frame the server sends, if any, within `wait`.
async fn close_within(ws: &mut Ws, wait: Duration) -> Option<Option<CloseCode>> {
    timeout(wait, async {
        while let Some(frame) = ws.next().await {
            match frame {
                Ok(Message::Close(close)) => return Some(close.map(|c| c.code)),
                Ok(_) => continue,
                Err(_) => return Some(None),
            }
        }
        Some(None)
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test]
async fn a_connection_limit_of_zero_admits_websockets() {
    init_tracing();
    let mediator = TestMediator::builder()
        .max_websocket_connections(0)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let alice = env.add_user("Alice").await.expect("user");
    let bob = env.add_user("Bob").await.expect("user");

    let mut a = open_ws(&env, &alice).await;
    let mut b = open_ws(&env, &bob).await;
    for ws in [&mut a, &mut b] {
        assert_eq!(
            close_within(ws, Duration::from_secs(1)).await,
            None,
            "0 is no limit: the socket stays open"
        );
    }
}

#[tokio::test]
async fn a_frame_over_the_size_limit_closes_with_1009() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let alice = env.add_user("Alice").await.expect("user");
    let mut ws = open_ws(&env, &alice).await;

    // Over the default `ws_size` (10 MiB).
    let oversized = "x".repeat(11 * 1024 * 1024);
    // The server may close while the frame is still being written.
    let _ = ws.send(Message::Text(oversized.into())).await;
    assert_eq!(
        close_within(&mut ws, Duration::from_secs(10)).await,
        Some(Some(CloseCode::Size)),
        "an oversized frame is refused with 1009"
    );
}
