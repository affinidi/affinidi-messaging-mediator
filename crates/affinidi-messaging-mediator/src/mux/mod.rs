//! DID multiplexing. What it does for clients and operators is described in
//! `docs/multiplexing.md` (in this crate's directory). Comments here that cite
//! "design §N" refer to the internal design note the feature was built from,
//! which is not published; the code and that page are the public reference.
//!
//! Grant storage and its rules live in
//! `affinidi_messaging_mediator_common::store::mux`; this module holds the
//! mediator-side pieces: verifying the signed statements members issue
//! (`proof`) and the grant operations the protocol handlers call (`grants`).

pub mod admin;
pub mod admin_grants;
pub mod audit;
pub mod connection;
pub mod fair_queue;
pub mod grants;
pub mod notice;
pub mod proof;
pub mod registry;
pub mod session;
pub mod sync;
pub mod tasks;
