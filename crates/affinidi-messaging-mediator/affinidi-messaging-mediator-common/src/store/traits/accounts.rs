//! The [`AccountStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::Session;
use crate::types::accounts::{
    Account, AccountActivity, AccountStats, AccountStatsDelta, AccountType, ActivityKind,
    MediatorAccountList,
};
use crate::types::acls::MediatorACLSet;
use async_trait::async_trait;

/// Accounts: their records, roles, queue limits, admin membership, activity and per-account counters.
#[async_trait]
pub trait AccountStore: Send + Sync + std::fmt::Debug {
    /// Whether a DID has a local account record on this mediator.
    async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError>;

    /// Retrieve an account by DID hash. Returns `None` when the account
    /// doesn't exist.
    async fn account_get(&self, did_hash: &str) -> Result<Option<Account>, MediatorError>;

    /// Create an account with the given ACLs and optional queue limit, but
    /// only when the DID has none. Returns the created account, or `None` —
    /// having written nothing — when an account already exists.
    ///
    /// The existence check and the write are one atomic step, so an existing
    /// account's role, ACLs, limits, counters and activity are never reset,
    /// however callers interleave.
    async fn account_create(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Option<Account>, MediatorError>;

    /// Remove an account from the mediator.
    ///
    /// This is a composite operation: it blocks the account, drops the
    /// outbox stream key (without purging downstream copies that have
    /// already been delivered), purges the inbox, strips admin
    /// privileges, and removes the DID record. Mediator and root-admin
    /// accounts cannot be removed. Forwarded messages already queued on
    /// the FORWARD_Q are intentionally left alone — letting them flush
    /// is preferable to a queue scan, and the protocol exposes no
    /// option to override.
    async fn account_remove(
        &self,
        session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError>;

    /// List up to 100 accounts using a server-side cursor.
    async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError>;

    /// Change an account's role type. When promoting to `Admin` /
    /// `RootAdmin` / `Mediator` the backend also adds the DID to the
    /// admin set; when demoting back to `Standard` it removes from the
    /// admin set. Atomic with respect to the role + admin-set update.
    async fn account_set_role(
        &self,
        did_hash: &str,
        account_type: &AccountType,
    ) -> Result<(), MediatorError>;

    /// Change an account's queue limits.
    ///
    /// Limit values: `None` = no change; `Some(-1)` = unlimited;
    /// `Some(-2)` = reset to default; `Some(n)` = explicit cap.
    async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError>;

    /// Ensure an admin account exists with the given role and ACLs.
    /// Creates the account if missing, updates the role + admin-set
    /// membership otherwise. Idempotent; safe to call on every startup.
    ///
    /// For batch promote/demote, callers loop over `account_set_role`
    /// directly — a "promote 100 DIDs" primitive doesn't earn its keep
    /// at the storage layer.
    async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError>;

    /// Whether the given DID is an Admin or RootAdmin account.
    async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError>;

    /// Record that the account `did_hash` did `kind` at `at` (Unix epoch
    /// seconds), replacing the time recorded before. Nothing is recorded for
    /// an account that does not exist.
    ///
    /// Adding an account clears whatever was recorded for that hash, so an
    /// account never starts life holding a predecessor's times — including a
    /// record written by a message that was in flight while the predecessor
    /// was being removed, which the existence check cannot rule out on a
    /// store without a transaction across both.
    ///
    /// Activity is observability, not state anything depends on, so the
    /// default keeps nothing and succeeds; [`account_activity`] then reports
    /// nothing recorded. Every built-in backend overrides both. Removing the
    /// account removes its activity.
    ///
    /// [`account_activity`]: Self::account_activity
    async fn account_activity_record(
        &self,
        did_hash: &str,
        kind: ActivityKind,
        at: u64,
    ) -> Result<(), MediatorError> {
        let _ = (did_hash, kind, at);
        Ok(())
    }

    /// The recorded activity of each account in `did_hashes`, in the same
    /// order. An account with nothing recorded, or none at all, gets
    /// [`AccountActivity::default`].
    async fn account_activity(
        &self,
        did_hashes: &[String],
    ) -> Result<Vec<AccountActivity>, MediatorError> {
        Ok(vec![AccountActivity::default(); did_hashes.len()])
    }

    /// Count one message against the account `did_hash`.
    ///
    /// Counters are cumulative, survive restarts, and are discarded with the
    /// account. Nothing is counted for an account that does not exist, and
    /// adding an account clears whatever was counted for that hash — so a new
    /// account never inherits its predecessor's totals.
    ///
    /// This is on the message path, so a backend should make it **one write**.
    ///
    /// The default keeps nothing and succeeds; [`account_stats`] then reports
    /// zeroes. Every built-in backend overrides both.
    ///
    /// [`account_stats`]: Self::account_stats
    async fn account_stats_bump(
        &self,
        did_hash: &str,
        delta: AccountStatsDelta,
    ) -> Result<(), MediatorError> {
        let _ = (did_hash, delta);
        Ok(())
    }

    /// The counters of each account in `did_hashes`, in the same order. An
    /// account with nothing counted, or none at all, gets
    /// [`AccountStats::default`].
    async fn account_stats(
        &self,
        did_hashes: &[String],
    ) -> Result<Vec<AccountStats>, MediatorError> {
        Ok(vec![AccountStats::default(); did_hashes.len()])
    }
}
