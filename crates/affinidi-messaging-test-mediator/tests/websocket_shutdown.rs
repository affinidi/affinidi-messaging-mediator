//! A mediator that shuts down closes its live WebSockets with 1001 ("going
//! away", reason "mediator shutting down"), so their clients reconnect and
//! know why (R6.2). The HTTP server's graceful shutdown does not track
//! upgraded sockets: before this they were closed only once the streaming
//! task had gone, with 1011 "streaming task unavailable".

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::init_tracing;
use futures_util::StreamExt;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri, protocol::frame::coding::CloseCode},
};

#[tokio::test]
async fn shutting_down_closes_live_sockets_with_going_away() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let user = env.add_user("client").await.expect("user");
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
    let (mut ws, _) = connect_async(request).await.expect("upgrade");

    env.mediator.shutdown();
    let close = timeout(Duration::from_secs(10), async {
        while let Some(frame) = ws.next().await {
            match frame {
                Ok(Message::Close(close)) => return close,
                Ok(_) => continue,
                Err(e) => panic!("the socket ended without a close frame: {e}"),
            }
        }
        panic!("the socket ended without a close frame");
    })
    .await
    .expect("closed within 10s of shutdown")
    .expect("a close frame with a code");
    assert_eq!(close.code, CloseCode::Away, "{close:?}");
    assert_eq!(close.reason.as_str(), "mediator shutting down");
}

/// `join` returns only once live sockets have been closed (#131): the close
/// frame has already been written when it does, rather than being cut short
/// by a process that exits as soon as `join` returns.
#[tokio::test]
async fn join_waits_for_live_sockets_to_close() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let user = env.add_user("client").await.expect("user");
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
    let (mut ws, _) = connect_async(request).await.expect("upgrade");

    timeout(Duration::from_secs(20), env.shutdown())
        .await
        .expect("join returns within its bound")
        .expect("clean shutdown");
    // Already written by the time `join` returned.
    let close = timeout(Duration::from_secs(1), async {
        while let Some(frame) = ws.next().await {
            if let Ok(Message::Close(close)) = frame {
                return close;
            }
        }
        None
    })
    .await
    .expect("the close frame was sent before join returned")
    .expect("a close frame with a code");
    assert_eq!(close.code, CloseCode::Away, "{close:?}");
}
