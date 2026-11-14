//! The storage capability traits and the [`MediatorStore`] facade over them.
//!
//! A backend implements each capability trait; [`MediatorStore`] is
//! implemented for it automatically once it implements them all, and it is
//! held as `Arc<dyn MediatorStore>`. Algorithms that are the same for every
//! backend (purges, fair pickup, delivery recording) live in
//! [`MediatorStoreExt`], which every `MediatorStore` gets and none overrides.
//!
//! Callers bring the traits into scope with
//! `use affinidi_messaging_mediator_common::store::prelude::*;`.

mod accounts;
mod acls;
mod audit;
mod auxiliary;
mod ext;
mod forward_queue;
mod lifecycle;
mod messages;
mod mux_grants;
mod sessions;
mod stats;
mod streaming;
mod v1_routing;

pub use accounts::AccountStore;
pub use acls::AclStore;
pub use audit::AuditStore;
pub use auxiliary::AuxiliaryStore;
pub use ext::MediatorStoreExt;
pub use forward_queue::ForwardQueueStore;
pub use lifecycle::StoreLifecycle;
pub use messages::MessageStore;
pub use mux_grants::MuxStore;
pub use sessions::SessionStore;
pub use stats::StatsStore;
pub use streaming::StreamingStore;
pub use v1_routing::V1RoutingKeyStore;

/// Semantic storage interface for the Affinidi Messaging Mediator.
///
/// Backends are held as `Arc<dyn MediatorStore>` and shared across all
/// request handlers and background tasks. Every method takes `&self`;
/// backends use interior mutability (connection pools, locks, atomics).
///
/// This trait has no methods of its own: it is the sum of the capability
/// traits, implemented for every type that implements them all. See the
/// [module docs](crate::store) for backend feature flags, multi-process
/// guarantees, atomicity and the error model.
pub trait MediatorStore:
    StoreLifecycle
    + MessageStore
    + SessionStore
    + AccountStore
    + AclStore
    + StatsStore
    + ForwardQueueStore
    + StreamingStore
    + MuxStore
    + V1RoutingKeyStore
    + AuditStore
    + AuxiliaryStore
{
}

impl<T> MediatorStore for T where
    T: StoreLifecycle
        + MessageStore
        + SessionStore
        + AccountStore
        + AclStore
        + StatsStore
        + ForwardQueueStore
        + StreamingStore
        + MuxStore
        + V1RoutingKeyStore
        + AuditStore
        + AuxiliaryStore
        + ?Sized
{
}
