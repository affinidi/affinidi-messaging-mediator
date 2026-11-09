//! DID multiplexing (design: `design-docs/mediator-did-multiplexing-design.md`).
//!
//! Grant storage and its rules live in
//! `affinidi_messaging_mediator_common::store::mux`; this module holds the
//! mediator-side pieces: verifying the signed statements members issue.

pub mod proof;
