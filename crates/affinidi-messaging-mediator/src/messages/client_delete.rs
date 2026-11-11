//! A client's delete of one message id, on the REST paths that may also
//! withdraw what the client sent (`DELETE /delete`, `/outbound` with delete).
//!
//! # Why this is not a plain `delete_message`
//!
//! The same bytes may be stored for several recipients, one record each, and
//! a client names a message by id alone. Most deletes are acknowledgements —
//! the client took the message and releases it — and an acknowledgement must
//! only ever remove the client's own copy: a copy it sent to someone else is
//! that recipient's, still undelivered. But the REST delete is also how a
//! sender withdraws what it queued (VTA flushes its outbox this way), so a
//! delete that finds no copy of the client's own still has to withdraw.
//!
//! The two are told apart like this, for the session's owners (its own DID
//! and, on a mux connection, the members it may delete for):
//!
//! 1. each owner's own inbox copy, if one holds one — an acknowledgement;
//! 2. otherwise, if an owner already removed its own copy of this id (its
//!    sender holds a receipt for that recipient), the delete is a repeated
//!    acknowledgement — a redelivered message deleted twice — and answers
//!    not found: the copy it was for is gone, and withdrawing would remove
//!    another recipient's;
//! 3. otherwise the copies an owner sent are withdrawn.
//!
//! The receipt check in (2) only reaches back [`OUTBOX_RECEIPT_TTL`]; a
//! repeated acknowledgement later than that is treated as a withdrawal.
//!
//! [`OUTBOX_RECEIPT_TTL`]: affinidi_messaging_mediator_common::store::OUTBOX_RECEIPT_TTL

use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{DeletionAuthority, MediatorStore, MessageScope, RemovedCopy, ops},
};
use std::collections::HashSet;

/// What a client's delete removed, and as which owner.
pub(crate) struct ClientDelete {
    /// The owner the delete was made as.
    pub owner: String,
    /// Every copy removed: one for an acknowledgement, each copy withdrawn
    /// for a sender.
    pub copies: Vec<RemovedCopy>,
}

/// Delete `msg_id` for a client whose session may delete as `owners` (its own
/// DID first). See the module docs for the order; with `withdraw` false only
/// step 1 runs (an acknowledgement, as `messaging/mux/ack` sends). `not_found`
/// when nothing in those owners' queues is removed.
pub(crate) async fn delete_for_client(
    store: &dyn MediatorStore,
    owners: &[String],
    msg_id: &str,
    withdraw: bool,
) -> Result<ClientDelete, MediatorError> {
    let owner_of = |did: &str| DeletionAuthority::Owner {
        did_hash: did.to_string(),
    };

    // 1. An acknowledgement: an owner's own copy.
    for owner in owners {
        match store
            .delete_message_in(msg_id, MessageScope::Recipient(owner), owner_of(owner))
            .await
        {
            Ok(copies) => {
                return Ok(ClientDelete {
                    owner: owner.clone(),
                    copies,
                });
            }
            Err(e) if ops::is_delete_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }

    if !withdraw {
        return Err(ops::delete_not_found(msg_id, None));
    }

    // 2. A repeated acknowledgement: an owner's own copy was removed already.
    let owner_set: HashSet<&str> = owners.iter().map(String::as_str).collect();
    for sender in owners {
        let receipts = store.outbox_receipts(sender, msg_id).await?;
        if receipts
            .iter()
            .any(|(to, _)| owner_set.contains(to.as_str()))
        {
            return Err(ops::delete_not_found(msg_id, None));
        }
    }

    // 3. A withdrawal: the copies an owner sent.
    for owner in owners {
        match store
            .delete_message_in(msg_id, MessageScope::Party(owner), owner_of(owner))
            .await
        {
            Ok(copies) => {
                return Ok(ClientDelete {
                    owner: owner.clone(),
                    copies,
                });
            }
            Err(e) if ops::is_delete_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Err(ops::delete_not_found(msg_id, None))
}
