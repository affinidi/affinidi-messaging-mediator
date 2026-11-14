//! Affinidi Messaging Mediator.
//!
//! A [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
//! [Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/)
//! mediator: it authenticates agents, stores their messages, forwards them to
//! other mediators and delivers them over REST and WebSocket.
//!
//! This crate is both the `mediator` binary and a library. Operators run the
//! binary (see the [README] and the setup wizard in this repository); the
//! library is for running a mediator inside another process.
//!
//! # Embedding
//!
//! [`builder::MediatorBuilder`] starts a mediator from values set in code: no
//! TOML file, no working-directory assumptions, and no global tracing
//! subscriber or signal handlers unless asked for.
//! [`builder::MediatorBuilder::start`] returns a [`builder::MediatorHandle`]
//! carrying the bound URLs, the mediator DID, and `shutdown()` / `join()`.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use affinidi_messaging_mediator::builder::MediatorBuilder;
//! use affinidi_messaging_mediator_common::database::config::DatabaseConfig;
//! use affinidi_secrets_resolver::ThreadedSecretsResolver;
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! affinidi_messaging_mediator::install_jwt_crypto_provider();
//!
//! // The resolver must hold the mediator's signing and key-agreement
//! // secrets (for `mediator_did`) before `start` is called.
//! let (secrets, _resolver_task) = ThreadedSecretsResolver::new(None).await;
//!
//! let database = DatabaseConfig {
//!     database_url: "redis://127.0.0.1/".into(),
//!     ..Default::default()
//! };
//!
//! let handle = MediatorBuilder::new(Arc::new(secrets))
//!     .mediator_did("did:peer:2.Vz6Mk...")
//!     .admin_did("did:key:z6Mk...")
//!     .database(database)
//!     .start(CancellationToken::new())
//!     .await?;
//! println!("mediator {} on {}", handle.mediator_did, handle.http_endpoint);
//!
//! handle.shutdown();
//! handle.join().await?;
//! # Ok(())
//! # }
//! ```
//!
//! With the `memory-backend` or `fjall-backend` feature,
//! `MediatorBuilder::memory_store()` or `MediatorBuilder::fjall_path()`
//! replaces the Redis database. For integration tests,
//! [`affinidi-messaging-test-mediator`](https://docs.rs/affinidi-messaging-test-mediator)
//! does all of this, identities included, in one call.
//!
//! # Features
//!
//! At least one of `didcomm` and `tsp` must be enabled, and one storage
//! backend (`redis-backend`, `fjall-backend` or `memory-backend`). The
//! defaults (`didcomm`, `tsp`, `redis-backend`, `jemalloc`, `vta`) suit the
//! binary; an embedding application usually turns them off and lists what it
//! needs. `jemalloc` affects only the binary: the library never installs an
//! allocator. The [README] lists every feature, including the `secrets-*`
//! backends.
//!
//! # Public API
//!
//! The supported library surface is [`builder`], the configuration types in
//! [`common::config`], the storage backends in [`store`], the generated
//! [`task_specs`], [`error_codes`], [`SharedData`] and
//! [`install_jwt_crypto_provider`]. The other modules are public only so the
//! binary, the test mediator and this crate's integration tests can reach
//! them; they are hidden from these docs and may change in any release.
//!
//! [README]: https://github.com/affinidi/affinidi-messaging-mediator/blob/main/crates/affinidi-messaging-mediator/README.md
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(any(feature = "didcomm", feature = "tsp")))]
compile_error!("At least one of the `didcomm` or `tsp` features must be enabled");

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::store::prelude::*;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::extract::{FromRef, FromRequestParts};
use chrono::{DateTime, Utc};
use common::{config::Config, did_rate_limiter::DidRateLimiter, jwt_auth::AuthError};
use dashmap::DashMap;
use http::request::Parts;
use std::{collections::HashSet, fmt::Debug, sync::Arc, sync::atomic::AtomicUsize};
use tasks::queue_survey::QueueSnapshotCell;
use tasks::supervisor::HealthRegistry;
use tasks::websocket_streaming::StreamingTask;
use tokio_util::sync::CancellationToken;

/// The error code registry (see `ERRORS.md`).
pub use affinidi_messaging_mediator_common::error_codes;

#[doc(hidden)]
pub mod account_stats;
#[doc(hidden)]
pub mod activity;
pub(crate) mod after_write;
pub mod builder;
#[doc(hidden)]
pub mod commands;
pub mod common;
#[cfg(feature = "didcomm")]
#[doc(hidden)]
pub mod didcomm_compat;
#[cfg(feature = "didcomm-v1")]
#[doc(hidden)]
pub mod didcomm_v1_identity;
#[doc(hidden)]
pub mod handlers;
#[doc(hidden)]
pub mod messages;
#[doc(hidden)]
pub mod monitor;
/// DID multiplexing: one connection carrying many DIDs.
#[doc(hidden)]
pub mod mux;
#[doc(hidden)]
pub mod scid_sources;
#[doc(hidden)]
pub mod server;
pub mod store;
/// The Trust Task types this mediator serves, generated at build time from the
/// versions pinned in this crate's `trust-tasks.lock` (see `build.rs`). Module
/// paths match `trust_tasks_rs::specs`, e.g. `task_specs::messaging::ping::v0_2`.
/// A task with two pinned versions is served at both.
pub mod task_specs {
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
}
#[doc(hidden)]
pub mod tasks;
#[cfg(feature = "tsp")]
#[doc(hidden)]
pub mod tsp_identity;
pub mod wake;

/// Install `jsonwebtoken`'s `aws_lc_rs` crypto provider as the process-wide
/// default, idempotently.
///
/// This lives here, rather than in each consumer, because the provider is
/// registered per `jsonwebtoken` *instance*: a consumer that calls
/// `jsonwebtoken::…::install_default()` against its own copy of the crate
/// installs nothing for the copy this mediator verifies tokens with. While the
/// JWT key fields were public that mismatch was at least a compile error;
/// now that `jsonwebtoken` is a private dependency (affinidi-tdk-rs#770) it would be a silent
/// runtime failure instead, so the installation has to be callable from here.
///
/// Errors from an already-installed provider are ignored.
pub fn install_jwt_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

/// Shared application state available to all request handlers via Axum's state extraction.
#[derive(Clone)]
pub struct SharedData {
    /// Mediator configuration loaded at startup.
    pub config: Arc<Config>,
    /// The limits in effect now: `config.limits` with any live `config/patch`
    /// changes. Read the live keys through [`SharedData::limits`]; see
    /// [`common::config::overrides`].
    pub live_limits: common::config::overrides::LiveLimits,
    /// Timestamp when the mediator service was started.
    pub service_start_timestamp: DateTime<Utc>,
    /// Cached DID resolver for resolving DID documents.
    pub did_resolver: DIDCacheClient,
    /// The latest queue survey, published by the statistics task and served by
    /// the `messaging/queue/list` and `messaging/stats/show` Trust Tasks.
    pub queue_snapshot: QueueSnapshotCell,
    /// The live traffic monitor: the event bus the data plane emits onto and
    /// the `messaging/monitor/*` subscriptions reading it.
    pub monitor: monitor::TrafficMonitor,
    /// Records each account's last received message and last authentication,
    /// served by `messaging/account/get` and `messaging/account/list`.
    pub activity: activity::ActivityRecorder,
    /// Storage backend for sessions, messages, accounts, and live
    /// streaming. Polymorphic so the mediator can run against Redis,
    /// Fjall, or memory without changing handler code.
    pub database: Arc<dyn MediatorStore>,
    /// Optional background task handle for WebSocket streaming.
    pub streaming_task: Option<StreamingTask>,
    /// Live DID-multiplexing connections on this instance (empty unless
    /// `limits.mux.enabled`).
    pub mux: Arc<mux::registry::MuxRegistry>,
    /// DIDComm Discover Features protocol handler.
    #[cfg(feature = "didcomm")]
    pub discover_features: Arc<DiscoverFeatures>,
    /// Counter for active WebSocket connections (used for connection limiting).
    pub active_websocket_count: Arc<AtomicUsize>,
    /// Live WebSocket connection count per DID hash, enforcing
    /// `limits.max_websocket_connections_per_did` so a single DID can't
    /// exhaust the global connection budget. Entries are removed when a DID's
    /// count returns to zero.
    pub ws_connections_per_did: Arc<DashMap<String, u32>>,
    /// Live anonymous relay WebSocket count per client address, enforcing
    /// `limits.relay_connections_per_ip` inside the shared relay bucket.
    /// Entries are removed when an address's count returns to zero.
    pub relay_connections_per_ip: Arc<DashMap<String, u32>>,
    /// Resolves the key a relay WebSocket is counted under: its client
    /// address as the per-IP rate limiter resolves it (honouring
    /// `server.trust_xff_cidrs`), with IPv6 masked to its /64.
    pub relay_client_ip: affinidi_rate_limit::ClientIpExtractor,
    /// The cached backend half of `/readyz`.
    pub readiness: Arc<handlers::readiness::ReadinessCache>,
    /// Per-DID rate limiter for authenticated endpoints.
    pub did_rate_limiter: DidRateLimiter,
    /// Cancellation token for coordinated graceful shutdown of all background tasks.
    pub shutdown_token: CancellationToken,
    /// Pre-computed `(host, port)` set used by the routing 2.0 forward
    /// handler to short-circuit when a next-hop's DIDComm service URI
    /// resolves back to this mediator. Populated from
    /// `config.listen_address` plus any operator-declared
    /// `config.local_endpoints` aliases.
    pub self_authorities: Arc<HashSet<(String, u16)>>,
    /// Trust Task signing key and proof verifier, cached across requests.
    pub(crate) trust_task_keys: Arc<messages::protocols::trust_task_sign::TrustTaskKeys>,
    /// Live health of supervised background tasks, published by the
    /// [`TaskSupervisor`](tasks::supervisor::TaskSupervisor). The readiness
    /// handler reads this to fail `/readyz` when a load-bearing component is
    /// down and to report `degraded` for non-load-bearing ones.
    pub component_health: HealthRegistry,
    /// Source of the current time for all expiry / TTL / session-cleanup
    /// decisions on the request path. Production wires a
    /// [`SystemClock`](affinidi_messaging_mediator_common::types::clock::SystemClock);
    /// tests can inject a `TestClock` (via `TestMediatorBuilder::clock`) and
    /// advance it to exercise expiry instantly.
    pub clock: Arc<dyn affinidi_messaging_mediator_common::types::clock::Clock>,
    /// The mediator's own TSP identity (Ed25519 signing + X25519 decryption keys),
    /// derived lazily on first use from the configured DID + operating secrets.
    /// Only needed when the mediator acts as a routed TSP relay hop; Direct
    /// delivery is a blind store-and-forward and never touches it.
    #[cfg(feature = "tsp")]
    pub tsp_identity: Arc<tokio::sync::OnceCell<tsp_identity::MediatorTspIdentity>>,
    /// The mediator's own DIDComm v1 identity, derived lazily on first use from
    /// the same Ed25519 authentication key its v2 identity uses. Needed to open
    /// the anoncrypt `routing/1.0/forward` a v1 client addresses to the
    /// mediator's routing verkey.
    #[cfg(feature = "didcomm-v1")]
    pub didcomm_v1_identity:
        Arc<tokio::sync::OnceCell<didcomm_v1_identity::MediatorDidCommV1Identity>>,
    /// This instance's `messaging/wake/*` state: rate limits, armed requests
    /// and rings awaiting a gateway's answer (see [`wake`]).
    pub wake: Arc<wake::WakeService>,
}

impl SharedData {
    /// The limits in effect now, including live `config/patch` changes.
    pub fn limits(&self) -> Arc<common::config::limits::LimitsConfig> {
        self.live_limits.get()
    }

    /// The mediator's TSP identity, derived (and cached) on first use from its
    /// configured DID document and operating secrets.
    #[cfg(feature = "tsp")]
    pub async fn tsp_identity(
        &self,
    ) -> Result<
        &tsp_identity::MediatorTspIdentity,
        affinidi_messaging_mediator_common::errors::MediatorError,
    > {
        self.tsp_identity
            .get_or_try_init(|| {
                tsp_identity::MediatorTspIdentity::derive(
                    &self.config.mediator_did,
                    &self.did_resolver,
                    &*self.config.security.mediator_secrets,
                )
            })
            .await
    }
    /// The mediator's DIDComm v1 identity, derived (and cached) on first use
    /// from its configured DID document and operating secrets.
    #[cfg(feature = "didcomm-v1")]
    pub async fn didcomm_v1_identity(
        &self,
    ) -> Result<
        &didcomm_v1_identity::MediatorDidCommV1Identity,
        affinidi_messaging_mediator_common::errors::MediatorError,
    > {
        self.didcomm_v1_identity
            .get_or_try_init(|| {
                didcomm_v1_identity::MediatorDidCommV1Identity::derive(
                    &self.config.mediator_did,
                    &self.did_resolver,
                    &*self.config.security.mediator_secrets,
                )
            })
            .await
    }

    /// Bound for request-path storage calls made during admission/validation
    /// (see [`common::storage_timeout`]). Sourced from the existing
    /// `[database] database_timeout` (the same knob that caps Redis
    /// commands), so it is operator-configurable and backend-agnostic.
    pub fn storage_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.database.database_timeout as u64)
    }
}

impl Debug for SharedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .field("service_start_timestamp", &self.service_start_timestamp)
            .finish()
    }
}

impl<S> FromRequestParts<S> for SharedData
where
    Self: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = AuthError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}
