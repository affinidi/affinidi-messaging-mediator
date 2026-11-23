//! Mediator-wide building blocks.
//!
//! Only the `config` submodule is part of the supported library API: the typed
//! configuration an embedder builds or loads and hands to
//! [`MediatorBuilder`](crate::builder::MediatorBuilder). Every other module here
//! is internal: public only so the binary, the test mediator, the setup tool
//! and this crate's tests can reach it, hidden from the docs, and not covered
//! by semver. It may change in any release.

#[doc(hidden)]
pub mod authz;
#[doc(hidden)]
pub mod circuit_breaker;
/// The mediator's typed configuration: [`config::Config`] and its sections,
/// read from `mediator.toml` or built in code.
pub mod config;
#[doc(hidden)]
pub mod did_rate_limiter;
#[doc(hidden)]
pub mod error_codes;
#[doc(hidden)]
pub mod http_server;
#[doc(hidden)]
pub mod jwt_auth;
/// Startup check that the Redis stored-function library matches this build.
#[cfg(feature = "redis-backend")]
#[doc(hidden)]
pub mod lua_integrity;
#[doc(hidden)]
pub mod metrics;
#[doc(hidden)]
pub mod relay_target;
#[doc(hidden)]
pub mod request_id;
#[doc(hidden)]
pub mod request_metrics;
pub(crate) mod roles;
#[doc(hidden)]
pub mod session;
pub(crate) mod standing;
#[doc(hidden)]
pub mod storage_timeout;
#[doc(hidden)]
pub mod time;
#[doc(hidden)]
pub mod ws_budget;
