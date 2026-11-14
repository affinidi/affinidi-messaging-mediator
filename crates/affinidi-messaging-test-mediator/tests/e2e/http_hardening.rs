//! HTTP server hardening, end to end through a spawned mediator (#143, #171):
//!
//! - a request whose body never finishes arriving is answered 408 at
//!   `limits.http_request_timeout_secs` instead of being held open;
//! - an unknown OOB invitation id is a real HTTP 404, not a 200 whose body
//!   says 404.

use crate::common;

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use common::init_tracing;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn a_trickled_request_body_is_answered_408() {
    init_tracing();
    let mediator = TestMediator::builder()
        .http_request_timeout_secs(1)
        .spawn()
        .await
        .expect("spawn");

    let path = format!("{}authenticate/challenge", mediator.endpoint().path());
    let mut stream = TcpStream::connect(mediator.bound_addr())
        .await
        .expect("connect");
    // Promise a body and send only part of it.
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: 1000\r\n\r\n{{\"did\":"
    );
    stream.write_all(head.as_bytes()).await.expect("write");

    let mut answer = Vec::new();
    let mut buf = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    answer.extend_from_slice(&buf[..n]);
                    if answer.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(
        read.is_ok(),
        "the mediator answered before the client gave up"
    );
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 408"),
        "expected 408 Request Timeout, got: {answer}"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

#[tokio::test]
async fn an_unknown_oob_invitation_is_a_404() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .get(format!(
            "{}oob?_oobid=no-such-invitation",
            mediator.endpoint()
        ))
        .send()
        .await
        .expect("oob request");
    assert_eq!(resp.status().as_u16(), 404);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["httpCode"], 404);
    assert!(body["data"].is_null());

    mediator.shutdown();
    let _ = mediator.join().await;
}
