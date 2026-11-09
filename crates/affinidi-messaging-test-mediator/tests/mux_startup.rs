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
async fn enabling_mux_before_it_is_served_refuses_to_start() {
    let err = match TestMediator::builder().mux_enabled(true).spawn().await {
        Ok(_) => panic!("mux enabled must refuse to start until the protocol is served"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("[limits.mux]") && msg.contains("does not yet serve"),
        "refusal should name the setting and the reason, got: {msg}"
    );
}
