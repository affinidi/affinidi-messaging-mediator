//! The [`AuditStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::types::audit::{AuditLogEntry, MediatorAuditLogList};
use async_trait::async_trait;

/// The privileged-change audit log.
#[async_trait]
pub trait AuditStore: Send + Sync + std::fmt::Debug {
    /// Append a privileged-change record to the audit log.
    ///
    /// The log is a bounded ring of [`AUDIT_LOG_MAX_ENTRIES`](crate::types::audit::AUDIT_LOG_MAX_ENTRIES):
    /// once full, recording drops the oldest entry. The entry arrives fully
    /// formed (the caller stamps `timestamp` and the actor/target), so backends
    /// only persist + trim; ordering is the backend's insertion order.
    ///
    /// Recording is best-effort at the call sites (a failure here must not abort
    /// the privileged change that already succeeded), so callers log and
    /// continue rather than propagate.
    async fn audit_log_record(&self, entry: &AuditLogEntry) -> Result<(), MediatorError>;

    /// Page through the audit log, newest-first. Pass `0` to start; feed the
    /// returned `cursor` back in for the next page. A returned `cursor` of `0`
    /// means the listing is exhausted (same convention as `account_list`).
    async fn audit_log_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAuditLogList, MediatorError>;
}
