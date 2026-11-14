//! The [`AclStore`] capability of a storage backend.

use crate::errors::MediatorError;
use crate::store::DeliveryDecision;
use crate::types::acls::{AccessListModeType, MediatorACLSet};
use crate::types::acls_handler::{
    MediatorACLGetResponse, MediatorAccessListAddResponse, MediatorAccessListGetResponse,
    MediatorAccessListListResponse,
};
use async_trait::async_trait;

/// ACL bitmasks and per-account access lists, and the recipient-side delivery decision built from them.
#[async_trait]
pub trait AclStore: Send + Sync + std::fmt::Debug {
    /// Replace the ACL bitmask for a DID. Caller is responsible for
    /// permission checks (e.g., admin-only ACL changes).
    async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError>;

    /// Read the ACL bitmask for a DID. Returns `None` when the account
    /// has no ACL record.
    async fn get_did_acl(&self, did_hash: &str) -> Result<Option<MediatorACLSet>, MediatorError>;

    /// Read ACL bitmasks for up to 100 DIDs in one call.
    async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError>;

    /// Decide whether `from_hash` is allowed to send to `to_hash` under
    /// `to_hash`'s configured access-list mode (ExplicitAllow vs
    /// ExplicitDeny). For anonymous senders (`from_hash = None`),
    /// consults `to_hash`'s `anon_receive` ACL bit.
    async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool;

    /// Everything the recipient-side delivery gate needs about `to_hash`, in
    /// as few round trips as the backend can manage. Returns `None` when the
    /// account does not exist.
    ///
    /// The direct-delivery path needs three facts about one recipient — does
    /// the account exist, does it grant `RECEIVE_MESSAGES`, and does its
    /// access list admit this sender — which are all derivable from the same
    /// stored record. Fetching them via `account_exists` + `get_did_acl` +
    /// `access_list_allowed` costs three reads of that record; this method
    /// exists so a backend can serve all three from one.
    ///
    /// `RedisStore` pipelines the membership probe and the ACL read into a
    /// single round trip, and the in-process backends read one record.
    async fn delivery_decision(
        &self,
        to_hash: &str,
        from_hash: Option<&str>,
    ) -> Result<Option<DeliveryDecision>, MediatorError>;

    /// Page through a DID's access list using a server-side cursor. Pass `0` to
    /// start; feed the returned `cursor` back in for the next page.
    ///
    /// **Terminal-cursor convention differs by backend.** The in-process
    /// backends (memory, fjall) return `cursor: None` when the listing is
    /// exhausted; the Redis backend pages via `SSCAN`, whose end-of-iteration
    /// cursor is `0`, so it returns `cursor: Some(0)`. Callers MUST treat both
    /// `None` and `Some(0)` as "no more pages" — a loop that stops only on
    /// `None` runs forever against Redis. (The conformance suite's
    /// `access_list_len` helper documents and exercises this.)
    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError>;

    /// Add `hashes` to a DID's access list. Truncates if the addition
    /// would exceed `access_list_limit`; the response signals truncation
    /// and reports which hashes were actually inserted.
    async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<MediatorAccessListAddResponse, MediatorError>;

    /// Remove `hashes` from a DID's access list. Returns the number of
    /// entries actually removed.
    async fn access_list_remove(
        &self,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<usize, MediatorError>;

    /// Drop the entire access list for a DID.
    async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError>;

    /// Filter `hashes` to those present in the given DID's access list.
    async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<MediatorAccessListGetResponse, MediatorError>;
}
