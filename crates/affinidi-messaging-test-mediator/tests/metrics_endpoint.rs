//! `/metrics` through the real router: who may read it.
//!
//! The Prometheus recorder is installed once per process, so this binary
//! holds a single test and starts a single mediator.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use common::init_tracing;

#[tokio::test]
async fn metrics_is_served_only_to_allowed_clients_with_the_token() {
    init_tracing();
    // Loopback is the "proxy"; the client it forwards decides access.
    let mediator = TestMediator::builder()
        .trust_xff_cidrs(["127.0.0.0/8"])
        .metrics_access(["127.0.0.1/32", "10.0.0.0/8"], Some("scrape-token"))
        .spawn()
        .await
        .expect("spawn mediator");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let url = format!("{}metrics", mediator.endpoint());

    let status = |request: reqwest::RequestBuilder| async move {
        request
            .send()
            .await
            .expect("metrics request")
            .status()
            .as_u16()
    };

    assert_eq!(status(client.get(&url)).await, 401, "no token");
    assert_eq!(
        status(client.get(&url).bearer_auth("wrong")).await,
        401,
        "wrong token"
    );

    let ok = client
        .get(&url)
        .bearer_auth("scrape-token")
        .send()
        .await
        .expect("metrics request");
    assert_eq!(ok.status().as_u16(), 200, "allowed client with the token");
    assert!(
        ok.headers()[reqwest::header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain"),
        "Prometheus text format"
    );

    assert_eq!(
        status(
            client
                .get(&url)
                .bearer_auth("scrape-token")
                .header("x-forwarded-for", "203.0.113.5")
        )
        .await,
        403,
        "a client outside the allowed ranges is refused even with the token"
    );
    assert_eq!(
        status(
            client
                .get(&url)
                .bearer_auth("scrape-token")
                .header("x-forwarded-for", "10.1.2.3")
        )
        .await,
        200,
        "a forwarded client inside the allowed ranges is served"
    );

    // Other routes are unaffected by the /metrics gate.
    assert_eq!(
        status(client.get(format!("{}livez", mediator.endpoint()))).await,
        200
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}
