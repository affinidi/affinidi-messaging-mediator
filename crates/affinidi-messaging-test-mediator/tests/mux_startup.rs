//! DID multiplexing is opt-in, and a mediator that cannot honour
//! `[limits.mux] enabled = "true"` refuses to start rather than run with a
//! setting that means less than its name (R5.2).

use affinidi_messaging_test_mediator::TestMediator;

#[tokio::test]
async fn mux_is_off_by_default_and_the_mediator_starts() {
    let mediator = TestMediator::spawn().await.expect("default spawn");
    mediator.shutdown();
}

#[tokio::test]
async fn mux_enabled_starts_on_a_backend_that_supports_it() {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .spawn()
        .await
        .expect("mux enabled on the memory backend with streaming");
    mediator.shutdown();
}

#[tokio::test]
async fn mux_without_live_streaming_refuses_to_start() {
    let err = match TestMediator::builder()
        .mux_enabled(true)
        .enable_streaming(false)
        .spawn()
        .await
    {
        Ok(_) => panic!("mux needs live streaming"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("[limits.mux]") && err.contains("streaming"),
        "{err}"
    );
}
