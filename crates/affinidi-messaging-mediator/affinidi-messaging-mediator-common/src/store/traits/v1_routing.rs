//! The [`V1RoutingKeyStore`] capability of a storage backend.

use crate::errors::MediatorError;
use async_trait::async_trait;

/// The DIDComm v1 routing-key index (verkey to DID).
#[async_trait]
pub trait V1RoutingKeyStore: Send + Sync + std::fmt::Debug {
    /// Whether this backend implements the DIDComm v1 routing-key index below.
    ///
    /// The mediator checks this at
    /// startup and **refuses to start** with the `didcomm-v1` feature enabled
    /// on a backend that returns `false`, rather than accepting v1 traffic it
    /// would then silently fail to route.
    fn supports_v1_routing_keys(&self) -> bool;

    /// Bind a base58 Ed25519 routing verkey to a local account's DID.
    ///
    /// DIDComm v1 addresses a forward's destination by **verkey**, not DID,
    /// while every routing, ACL, and storage decision in this mediator is
    /// keyed by DID (or its hash). This index is the bridge.
    ///
    /// Takes and returns the **DID**, not its hash: forward ingress hands the
    /// looked-up value straight to the message-store path, which addresses a
    /// recipient by DID and hashes it itself — and a hash cannot be turned back
    /// into a DID. The *reverse* index ([`Self::v1_routing_keys_for`]) is still
    /// keyed by hash, because that is what account removal works from.
    ///
    /// # Security
    ///
    /// A verkey binds to **at most one** DID. An implementation MUST reject a
    /// bind whose verkey is already bound to a *different* DID, because
    /// otherwise any account could claim another account's routing key and
    /// capture its inbound v1 traffic. Re-binding a verkey to the DID that
    /// already holds it is idempotent and succeeds.
    async fn v1_routing_key_bind(&self, verkey: &str, did: &str) -> Result<(), MediatorError>;

    /// The **DID** bound to `verkey`, or `None` when the verkey is unknown.
    async fn v1_routing_key_lookup(&self, verkey: &str) -> Result<Option<String>, MediatorError>;

    /// Drop a binding. Returns whether one was removed.
    async fn v1_routing_key_unbind(&self, verkey: &str) -> Result<bool, MediatorError>;

    /// Drop the binding for `verkey` only if it is bound to `did`, in one
    /// atomic step. Returns whether it was removed.
    ///
    /// Unlike [`Self::v1_routing_key_unbind`] this never removes a binding
    /// that another account holds, even one made between the caller's last
    /// read and this call.
    async fn v1_routing_key_unbind_if_owner(
        &self,
        verkey: &str,
        did: &str,
    ) -> Result<bool, MediatorError>;

    /// Every routing verkey bound to the account with this DID **hash**.
    ///
    /// Used by account removal (so a deleted account's keys stop resolving)
    /// and, once the coordinate-mediation protocol lands, by `keylist-query`.
    async fn v1_routing_keys_for(&self, did_hash: &str) -> Result<Vec<String>, MediatorError>;
}
