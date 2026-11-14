//! The [`StatsStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::{MetadataStats, StatCounter};
use async_trait::async_trait;

/// The mediator-wide counters.
#[async_trait]
pub trait StatsStore: Send + Sync + std::fmt::Debug {
    /// Snapshot the global counters for the stats thread, the admin status
    /// endpoint, and `/readyz`.
    async fn get_global_stats(&self) -> Result<MetadataStats, MediatorError>;

    /// Increment a global counter by `by` (typically `1`, but bytes
    /// counters use the message size). Backends apply this atomically.
    async fn stats_increment(&self, counter: StatCounter, by: i64) -> Result<(), MediatorError>;
}
