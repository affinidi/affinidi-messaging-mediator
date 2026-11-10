//! DID multiplexing (design: `design-docs/mediator-did-multiplexing-design.md`).
//!
//! Grant storage and its rules live in
//! `affinidi_messaging_mediator_common::store::mux`; this module holds the
//! mediator-side pieces: verifying the signed statements members issue
//! (`proof`) and the grant operations the protocol handlers call (`grants`).

pub mod connection;
pub mod grants;
pub mod notice;
pub mod proof;
pub mod registry;
pub mod session;
pub mod sync;
pub mod tasks;
