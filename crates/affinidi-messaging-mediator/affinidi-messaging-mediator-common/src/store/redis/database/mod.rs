//! Redis-specific implementation modules for [`crate::store::redis::RedisStore`].
//!
//! Each submodule houses one topic's worth of Redis operations
//! (accounts, ACLs, sessions, streaming, etc.) implemented as inherent
//! methods on [`crate::store::redis::RedisStore`]. The
//! [`MediatorStore`](crate::store::MediatorStore)
//! trait impl in [`crate::store::redis::store`] delegates to these
//! methods. Splitting by topic keeps each file under ~500 lines.

pub mod accounts;
pub(crate) mod acls;
pub mod admin_accounts;
pub(crate) mod audit;
pub(crate) mod cluster_scripts;
/// Pickup: fetching a batch of an inbox's or outbox's messages.
pub mod fetch;
pub mod forwarding;
/// Reading one message by id, checked against the requester's DID hash.
pub mod get;
/// Loading the stored-function library (`atm-functions.lua`) and
/// checking its `LIBRARY_VERSION`.
pub mod handlers;
pub(crate) mod initialization;
/// Listing the entries of a `RECEIVE_Q` / `SEND_Q` stream.
pub mod list;
pub(crate) mod messages;
pub(crate) mod migrations;
pub mod session;
/// Global counters (`GLOBAL`) and the forward-queue length.
pub mod stats;
/// Storing a message and reading its metadata.
pub mod store;
/// Live-streaming ownership (`GLOBAL_STREAMING` and friends) and the
/// pub/sub channel live deliveries are published on.
pub mod streaming;
pub(crate) mod v1_routing_keys;

/// Compatibility alias preserved during the Database → RedisStore fold.
/// External callers that still hold `&Database` references see
/// the same type. New code should use `RedisStore` directly.
pub use crate::store::redis::RedisStore as Database;
