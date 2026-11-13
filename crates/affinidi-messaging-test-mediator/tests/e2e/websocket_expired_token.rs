//! A WebSocket upgrade with an access token past its `exp`, but still inside
//! the JWT validation leeway, is closed at once — and closing it leaves the
//! DID's existing live socket alone.
//!
//! The upgrade accepts such a token (the leeway), while the socket's lifetime
//! ends at `exp`, so the socket is refused right after the `101`. That refusal
//! must happen before the socket is registered for live delivery: a
//! registration would replace the DID's current socket, which would then be
//! closed for a connection that never ran.

use crate::common;

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_test_mediator::{TestClock, TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

async fn access_token(env: &TestEnvironment, user: &TestUser) -> String {
    env.tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate user")
        .access_token
}

async fn open_ws(
    env: &TestEnvironment,
    access_token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let ws_uri: Uri = env
        .mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");
    // tokio-tungstenite's client refuses a handshake where the server selects
    // no subprotocol, so offer a benign one beside the bearer entry.
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{access_token}"));
    let (stream, response) = connect_async(request)
        .await
        .expect("upgrade must reach 101");
    assert_eq!(response.status().as_u16(), 101, "expected 101 upgrade");
    stream
}

#[tokio::test]
async fn a_token_inside_the_leeway_is_closed_without_displacing_the_live_socket() {
    init_tracing();

    let clock = TestClock::now();
    let access = Duration::from_secs(120);
    let mediator = TestMediator::builder()
        .clock(Arc::new(clock.clone()))
        .jwt_expiry(access, Duration::from_secs(1_800))
        .spawn()
        .await
        .expect("spawn mediator with an injected clock");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire test environment");
    let alice = env.add_user("Alice").await.expect("add Alice");

    // Two sessions for Alice. The SDK caches tokens by wall clock, so the
    // first is dropped from its cache to make it mint a second.
    let stale = access_token(&env, &alice).await;
    env.tdk
        .authentication()
        .invalidate(alice.did.clone(), env.mediator.did().to_string())
        .await;
    let fresh = access_token(&env, &alice).await;
    assert_ne!(
        stale, fresh,
        "the second authentication must mint a new token"
    );

    // The live socket's lifetime was fixed when it opened, so moving the
    // mediator's clock afterwards leaves it running.
    let mut live = open_ws(&env, &fresh).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Past `exp`, inside the 60 s leeway.
    clock.advance_secs(access.as_secs() + 10);

    let mut stale_ws = open_ws(&env, &stale).await;
    let frame = timeout(Duration::from_secs(5), stale_ws.next())
        .await
        .expect("the stale-token socket is closed promptly");
    match frame {
        Some(Ok(Message::Close(Some(cf)))) => {
            assert_eq!(u16::from(cf.code), 1008);
            assert!(
                cf.reason.contains("expired"),
                "close reason should say the token expired, got: {}",
                cf.reason
            );
        }
        other => panic!("expected a 1008 close on the stale-token socket, got: {other:?}"),
    }

    // The live socket keeps its slot: nothing closes it.
    while let Ok(frame) = timeout(Duration::from_secs(1), live.next()).await {
        match frame {
            Some(Ok(Message::Close(cf))) => {
                panic!("the live socket was closed by the stale-token upgrade: {cf:?}")
            }
            None => panic!("the live socket was dropped by the stale-token upgrade"),
            Some(Ok(Message::Text(text))) => {
                panic!("the live socket was sent a frame by the stale-token upgrade: {text}")
            }
            _ => {}
        }
    }

    drop(live);
    env.shutdown().await.expect("shutdown");
}
