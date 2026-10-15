//! This module contains the protocol definitions for the mediator.
//! Each protocol is defined in a separate sub-module.
//!
//! Trust Tasks and the mediator administration they drive run over DIDComm and
//! over TSP, so they build with either. The rest are DIDComm protocols.

#[cfg(feature = "didcomm")]
pub mod discover_features;
pub(crate) mod mediator;
pub(crate) mod mediator_ops;
#[cfg(feature = "didcomm")]
pub mod message_pickup;
#[cfg(feature = "didcomm")]
pub mod ping;
#[cfg(feature = "didcomm")]
pub mod routing;
pub(crate) mod trust_task_sign;
pub(crate) mod trust_task_verify;
pub mod trust_tasks;

/// Whether `from` may relay through this mediator, given the configured relay
/// peer allowlist. Shared by the DIDComm re-wrap peel and the TSP routed relay.
///
/// An empty allowlist accepts any peer (the relay capability is still gated by
/// ACLs); a non-empty list admits only its members, and rejects an anonymous
/// (`None`) peer outright.
pub(crate) fn relay_peer_trusted(allow: &ahash::AHashSet<String>, from: Option<&str>) -> bool {
    allow.is_empty() || matches!(from, Some(did) if allow.contains(did))
}

#[cfg(test)]
mod tests {
    use super::relay_peer_trusted;

    fn allowlist(entries: &[&str]) -> ahash::AHashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn relay_peer_trusted_empty_allowlist_accepts_any() {
        let empty = ahash::AHashSet::new();
        assert!(relay_peer_trusted(&empty, Some("did:peer:anyone")));
        assert!(relay_peer_trusted(&empty, None));
    }

    #[test]
    fn relay_peer_trusted_nonempty_allowlist_is_membership_only() {
        let allow = allowlist(&["did:peer:alice_mediator", "did:peer:bob_mediator"]);
        assert!(relay_peer_trusted(&allow, Some("did:peer:alice_mediator")));
        assert!(!relay_peer_trusted(&allow, Some("did:peer:stranger")));
        // A non-empty allowlist rejects an anonymous relaying peer.
        assert!(!relay_peer_trusted(&allow, None));
    }
}
