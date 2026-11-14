//! The [`StoreLifecycle`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::StoreHealth;
use async_trait::async_trait;

/// Start-up, health and shutdown of a backend, and what kind of deployment it serves.
#[async_trait]
pub trait StoreLifecycle: Send + Sync + std::fmt::Debug {
    /// One-time backend setup. Called once during mediator startup, after
    /// the store is constructed but before any request handlers spin up.
    /// Backends use this for setup that needs nothing from the mediator's
    /// configuration (Fjall: its schema migrations). The Redis store loads
    /// its stored-function library here; its migrations, which need the
    /// mediator and admin DIDs, run from `RedisStore::initialize_redis`,
    /// which the mediator calls first. Idempotent: safe to call against an
    /// already-initialised backend.
    async fn initialize(&self) -> Result<(), MediatorError>;

    /// Liveness check used by `/readyz`. Should be cheap (single round-trip
    /// or in-memory state read). Returns [`StoreHealth::Unavailable`] when
    /// the backend is short-circuiting requests.
    async fn health(&self) -> StoreHealth;

    /// Cleanup at mediator shutdown. Flush in-flight writes, close
    /// connections, release file handles. Called from the shutdown task
    /// after all request handlers have drained.
    async fn shutdown(&self) -> Result<(), MediatorError>;

    /// Whether several mediator processes may share this store, each with
    /// connections the others cannot see. `false` for an in-process store
    /// (memory, Fjall); the Redis store says `true`. An answer that lists
    /// live state from one process says which it covers on this basis.
    fn spans_processes(&self) -> bool;

    /// The backend's circuit-breaker state, read synchronously for the
    /// admin status and `/readyz` answers: `"closed"` / `"half_open"` /
    /// `"open"`, the names operator dashboards already show. A backend with
    /// no breaker answers `"closed"`.
    fn circuit_breaker_state(&self) -> &'static str;
}
