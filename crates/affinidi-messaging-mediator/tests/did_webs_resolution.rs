//! The mediator resolves did:webs, so a did:webs client can authenticate and a
//! did:webs recipient can be routed to.
//!
//! Resolved the way the mediator's own resolver is built, in-process with the
//! default host policy: a did:webs naming a loopback host is refused by that
//! policy, not reported as an unsupported method.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

#[tokio::test]
async fn a_did_webs_is_resolved_under_the_host_policy() {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("resolver");
    let err = resolver
        .resolve("did:webs:127.0.0.1%3A1:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
        .await
        .expect_err("a loopback did:webs must be refused");
    let message = err.to_string();
    assert!(message.contains("host policy"), "{message}");
}
