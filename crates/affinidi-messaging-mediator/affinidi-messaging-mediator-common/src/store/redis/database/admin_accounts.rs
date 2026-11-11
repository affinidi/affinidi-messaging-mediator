//! Database routines to add/remove/list admin accounts
use crate::errors::{MediatorError, is_storage_full};
use crate::types::{accounts::AccountType, acls::MediatorACLSet};
use tracing::{Instrument, Level, debug, info, span, warn};

use super::Database;

// Redis-backend implementation behind `RedisStore`.
impl Database {
    /// Ensures that the mediator admin account is correctly configured and set up.
    /// It does not do any cleanup or maintenance of other admin accounts.
    /// Updates both the DID role type and the global ADMIN Set in Redis.
    pub(crate) async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        // `account_exists` is false for a `DID:<hash>` record holding only
        // queue counters, so such a record is completed before the role is
        // set: an admin is never left without `ACLS`. The read comes first
        // because this runs on every start, and a full database refuses the
        // create script even when it would change nothing.
        if !self.account_exists(admin_did_hash).await?
            && self
                .account_create(admin_did_hash, acls, None)
                .await?
                .is_some()
        {
            debug!("Admin account didn't exist, created: {}", admin_did_hash);
        }
        let mut con = self.get_connection().await?;

        debug!(
            "Admin DID ({}) == hash ({})",
            admin_did_hash, admin_did_hash
        );

        // ROLE_TYPE alone grants admin rights (sessions read it), so it is
        // written last: a failure between the steps leaves no admin.
        let mut listed = redis::pipe();
        listed.cmd("SADD").arg("ADMINS").arg(admin_did_hash);
        let mut role = redis::pipe();
        role.cmd("HSET")
            .arg(self.keys().did(admin_did_hash))
            .arg("ROLE_TYPE")
            .arg::<String>(admin_type.into());
        match self.exec_steps(&mut con, vec![listed, role]).await {
            Ok(()) => {}
            // A full database refuses even a write that changes nothing, and
            // this runs on every start. Carry on when the account is already
            // set up as asked, so a mediator can restart while full (and then
            // free space); otherwise fail as before.
            Err(err)
                if is_storage_full(&err.to_string())
                    && self
                        .admin_account_in_place(&mut con, admin_did_hash, admin_type)
                        .await =>
            {
                warn!(
                    "Database is full; admin account {admin_did_hash} already set up, not rewritten"
                );
            }
            Err(err) => {
                return Err(MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to set up admin account for ({admin_did_hash}). Reason: {err}"),
                ));
            }
        }

        info!("Admin account successfully setup: {}", admin_did_hash);
        Ok(())
    }

    /// Whether `did_hash` is already in the ADMINS set with role `admin_type`.
    async fn admin_account_in_place(
        &self,
        con: &mut crate::database::RedisConnection,
        did_hash: &str,
        admin_type: AccountType,
    ) -> bool {
        let mut listed = redis::cmd("SISMEMBER");
        listed.arg("ADMINS").arg(did_hash);
        let mut role = redis::cmd("HGET");
        role.arg(self.keys().did(did_hash)).arg("ROLE_TYPE");
        let expected: String = admin_type.into();
        matches!(
            self.query_pair::<bool, Option<String>>(con, listed, role).await,
            Ok((true, Some(current))) if current == expected
        )
    }

    /// Checks if the provided DID is an admin level account
    /// Returns true if the DID is an admin account, false otherwise
    pub(crate) async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_connection().await?;

        let mut listed = redis::cmd("SISMEMBER");
        listed.arg("ADMINS").arg(did_hash);
        let mut role = redis::cmd("HGET");
        role.arg(self.keys().did(did_hash)).arg("ROLE_TYPE");
        let (exists, role_type): (u32, u32) = self
            .query_pair(&mut con, listed, role)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "NA".to_string(),
                    format!("Failed to check admin account for ({did_hash}). Reason: {err}"),
                )
            })?;

        if exists == 1 {
            match role_type.into() {
                AccountType::RootAdmin => Ok(true),
                AccountType::Admin => Ok(true),
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Adds up to 100 admin accounts to the mediator
    /// - `accounts` - The list of accounts to add
    ///
    /// Superseded by [`MediatorStore::add_admin_accounts`] (default
    /// impl loops over [`setup_admin_account`]); kept as a Redis-
    /// specific helper for operator tooling that may want a single
    /// pipelined batch.
    ///
    /// [`MediatorStore::add_admin_accounts`]: crate::store::MediatorStore::add_admin_accounts
    /// [`setup_admin_account`]: crate::store::MediatorStore::setup_admin_account
    #[allow(dead_code)]
    pub(crate) async fn add_admin_accounts(
        &self,
        accounts: Vec<String>,
        acls: &MediatorACLSet,
    ) -> Result<usize, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "add_admin_accounts",
            "#_accounts" = accounts.len(),
        );

        async move {
            debug!("Adding Admin accounts to the mediator");
            if accounts.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    15,
                    "NA".to_string(),
                    "Number of admin accounts being added exceeds 100".to_string(),
                ));
            }

            for account in &accounts {
                debug!("Adding Admin account: {}", account);
                self.setup_admin_account(account, AccountType::Admin, acls)
                    .await?;
            }

            Ok(accounts.len())
        }
        .instrument(_span)
        .await
    }

    /// Strips up to 100 admin accounts from the mediator
    /// - `accounts` - The list of DID hashes to strip admin rights from
    pub(crate) async fn strip_admin_accounts(
        &self,
        accounts: Vec<String>,
    ) -> Result<i32, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "remove_admin_accounts",
            "#_accounts" = accounts.len(),
        );

        async move {
            debug!("Removing Admin accounts from the mediator");
            if accounts.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    16,
                    "NA".to_string(),
                    "Number of admin accounts being removed exceeds 100".to_string(),
                ));
            }

            let mut con = self.get_connection().await?;

            // ROLE_TYPE alone grants admin rights (sessions read it), so each
            // account's role is reset before the ADMINS set is touched.
            let mut roles = redis::pipe();
            for account in &accounts {
                roles
                    .cmd("HSET")
                    .arg(self.keys().did(account))
                    .arg("ROLE_TYPE")
                    .arg::<String>(AccountType::Standard.into());
            }
            let mut unlisted = redis::pipe();
            unlisted.cmd("SREM").arg("ADMINS");
            for account in &accounts {
                debug!("Removing Admin account: {}", account);
                unlisted.arg(account);
            }

            let result = self
                .query_fanout_then(&mut con, roles, unlisted)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        "NA".to_string(),
                        format!("Failed to remove admin account. Reason: {err}"),
                    )
                })?;
            debug!("Admin accounts removed successfully: {:?}", result);

            // The SREM reply, last: how many were in the ADMINS set.
            Ok(result
                .last()
                .and_then(|removed| redis::from_redis_value::<i32>(removed.clone()).ok())
                .unwrap_or(0))
        }
        .instrument(_span)
        .await
    }
}
