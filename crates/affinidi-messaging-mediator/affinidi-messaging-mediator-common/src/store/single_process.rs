//! What a store used by one mediator process answers for the parts of the
//! [`StreamingStore`] contract that only matter across processes.
//!
//! The in-process backends (memory, Fjall) call these from their own impls,
//! so each opts out of cross-process coordination explicitly rather than by
//! inheriting a default it might not have meant to.

use crate::errors::MediatorError;
use crate::store::{StreamingClaim, StreamingClientState, StreamingStore};

/// [`StreamingStore::streaming_claim`] for one process: the streaming task
/// already orders its own entries, so set the state and hold the DID.
pub async fn streaming_claim<S: StreamingStore + ?Sized>(
    store: &S,
    did_hash: &str,
    mediator_uuid: &str,
    live: bool,
) -> Result<StreamingClaim, MediatorError> {
    let state = if live {
        StreamingClientState::Live
    } else {
        StreamingClientState::Registered
    };
    store
        .streaming_set_state(did_hash, mediator_uuid, state)
        .await?;
    Ok(StreamingClaim {
        held_here: true,
        displaced_mux: None,
    })
}

/// [`StreamingStore::streaming_release`] for one process: deregister; no
/// other instance can be waiting for the DID.
pub async fn streaming_release<S: StreamingStore + ?Sized>(
    store: &S,
    did_hash: &str,
    mediator_uuid: &str,
) -> Result<bool, MediatorError> {
    store
        .streaming_set_state(did_hash, mediator_uuid, StreamingClientState::Deregistered)
        .await?;
    Ok(false)
}
