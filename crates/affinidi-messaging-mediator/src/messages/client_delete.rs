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
//! 1. an owner's own inbox copy, if one holds one — an acknowledgement. When
//!    several owners hold a copy (a mux principal and a member that both
//!    received the same bytes), the one whose copy was handed over first is
//!    acknowledged first, then session order ([`ack_order`]);
//! 2. otherwise, if an owner already acknowledged its own copy of this id
//!    ([`MediatorStore::acknowledged`], kept until that copy would have
//!    expired), the delete is a repeated acknowledgement — a redelivered
//!    message deleted twice — and answers not found: the copy it was for is
//!    gone, and withdrawing would remove another recipient's;
//! 3. otherwise the copies an owner sent are withdrawn.
//!
//! One case cannot be told apart: a DID that sent the same bytes to itself
//! and to someone else, acknowledged its own copy, and then wants to
//! withdraw the other copy sends exactly the request a repeated
//! acknowledgement sends. It is answered as the repeated acknowledgement
//! (nothing removed), which loses nothing; `messaging/message/delete` or an
//! outbox purge withdraws it explicitly. A copy removed by expiry or by an
//! administrator is not an acknowledgement and does not block a withdrawal.

use affinidi_messaging_mediator_common::store::MessageRef;
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{DeletionAuthority, MessageScope, RemovedCopy, ops, prelude::*},
};

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

    // 1. An acknowledgement: an owner's own copy, the delivered one first.
    for owner in &ack_order(store, owners, msg_id).await {
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

    // 2. A repeated acknowledgement: an owner acknowledged its copy already.
    for owner in owners {
        if store.acknowledged(owner, msg_id).await? {
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

/// `owners` in the order an acknowledgement of `msg_id` should try them: those
/// whose own copy has been handed over first, then the rest, each group in
/// session order. A mux session acknowledging a member's delivered copy
/// must not remove the principal's own copy of the same bytes that it has not
/// been given yet. A state read that fails leaves session order.
pub(crate) async fn ack_order(
    store: &dyn MediatorStore,
    owners: &[String],
    msg_id: &str,
) -> Vec<String> {
    if owners.len() < 2 {
        return owners.to_vec();
    }
    let records: Vec<MessageRef> = owners
        .iter()
        .map(|owner| MessageRef::new(owner.clone(), msg_id))
        .collect();
    let states = store.delivery_states(&records).await.unwrap_or_default();
    let delivered = |i: usize| {
        states
            .get(i)
            .and_then(|s| s.as_ref())
            .is_some_and(|s| s.first_delivered_at_ms.is_some())
    };
    let (mut first, rest): (Vec<_>, Vec<_>) = owners
        .iter()
        .cloned()
        .enumerate()
        .partition(|(i, _)| delivered(*i));
    first.extend(rest);
    first.into_iter().map(|(_, owner)| owner).collect()
}
