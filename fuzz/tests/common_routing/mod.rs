//! Shared fixture for `routing_endpoint_classify_fuzz.rs`.
//!
//! Spawns a real mediator via `affinidi-messaging-test-mediator`'s `pub`
//! `TestMediator`/`TestEnvironment` fixture (external forwarding enabled so
//! next hops are classified, but the forwarding processor off; real
//! `did:peer` DIDs, no network — `did:peer` resolves locally), with one
//! pre-registered authenticated sender wired to the SDK so the test can
//! drive the real `routing/2.0/forward` HTTP flow end-to-end.

#![allow(dead_code)]

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser, acl};

pub struct RoutingFixture {
    /// `env.mediator` is the running `TestMediatorHandle` (store access,
    /// `.did()`, `.endpoint()`); `env.atm` is the SDK client the test
    /// drives `routing().forward_message()` / `send_message()` through.
    pub env: TestEnvironment,
    pub sender: TestUser,
}

impl RoutingFixture {
    pub fn mediator(&self) -> &affinidi_messaging_test_mediator::TestMediatorHandle {
        &self.env.mediator
    }

    pub fn shutdown(&self) {
        self.env.mediator.shutdown();
    }
}

pub async fn spawn() -> RoutingFixture {
    // External forwarding on: `classify_next_hop` classifies a next hop
    // only when it is set, and a Remote verdict lands in FORWARD_Q, which is
    // what the harness observes. The forwarding processor stays off (the
    // mediator starts it only when both flags are set), so nothing drains
    // FORWARD_Q under the harness and nothing relays to the fuzzed endpoints:
    // the test makes no outbound connections.
    let mediator = TestMediator::builder()
        .enable_forwarding(false)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .spawn()
        .await
        .expect("spawn test mediator");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire SDK to mediator");
    let sender = env.add_user("fuzz-sender").await.expect("add sender user");

    RoutingFixture { env, sender }
}
