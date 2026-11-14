//! Wizard-side VTA integration: TUI state machine + thin adapters over
//! the SDK's [`vta_sdk::provision_client`] surface.
//!
//! The SDK owns the wire protocol (resolve → enumerate → dispatch →
//! sealed-bundle open) and ships its own diagnostics + event channel
//! shapes. This module re-exports the SDK types the wizard consumes,
//! plus the wizard-only state-machine types ([`VtaConnectState`],
//! [`ConnectPhase`], [`VtaSession`], the 3-variant [`VtaIntent`] /
//! [`VtaReply`] enums that span the online + offline sealed-handoff
//! sub-flows).
//!
//! Phase machine:
//!   `EnterDid` → `EnterContext` → (FullSetup) `EnterMediatorUrl` →
//!   `AwaitingAcl` → `Testing` → either `Connected`, the
//!   `TransportFallbackPrompt` (interactive \[F\]/\[R\]/\[O\]/\[B\] choice
//!   when the alternate transport is still viable), or the
//!   `RecoveryPrompt` (post-auth failure, exhausted attempts, or
//!   no advertised transport).
//!
//! `[O] Offline` from either prompt drops the operator into the
//! sealed-handoff sub-flow with `vta_did` / `context_id` /
//! `mediator_url` carried over.

// Without the `vta` feature only the SDK-free intent types are built: the
// wizard keeps its VTA step (showing VTA as unavailable) and needs the
// intent enum for that. Everything that speaks to a VTA is gated.
#[cfg(feature = "vta")]
pub mod cli;
pub mod intent;
#[cfg(feature = "vta")]
pub mod runner;
#[cfg(feature = "vta")]
pub mod session;
#[cfg(feature = "vta")]
pub mod state;

// ── Local TUI-state types ────────────────────────────────────────────
#[cfg(feature = "vta")]
pub use intent::VtaReply;
pub use intent::{VtaIntent, VtaTransport};
#[cfg(feature = "vta")]
pub use runner::run_connection_test;
#[cfg(feature = "vta")]
pub use session::VtaSession;
#[cfg(feature = "vta")]
pub use state::{ConnectPhase, FallbackOptions, OfflineReason, RecoveryOptions, VtaConnectState};

// ── SDK re-exports — use these via `crate::vta::*` so consumers
// stay decoupled from the upstream module path. Only the items the
// wizard actually consumes are surfaced here; the rest stay reachable
// via the canonical `vta_sdk::provision_client::*` path for the few
// call sites that need them. ──────────────────────────────────────────
#[cfg(feature = "vta")]
pub use vta_sdk::provision_client::{
    AttemptResult, AttemptResultKind, DiagCheck, DiagEntry, DiagStatus, EphemeralSetupKey,
    Protocol, ProvisionResultV2, ResolvedVta, VtaEvent, pending_list,
};

/// Stand-in for the VTA session in a build without the `vta` feature.
///
/// It has no values, so `Option<&VtaSession>` is always `None`: the
/// provisioning and summary code keep their signatures, and every branch that
/// would read a session is statically dead. Step 3 of the release order
/// (vta-sdk back in the graph) makes the real `session::VtaSession` the
/// only one again.
#[cfg(not(feature = "vta"))]
#[derive(Clone, Debug)]
pub enum VtaSession {}

#[cfg(not(feature = "vta"))]
impl VtaSession {
    /// See the `vta` build's `VtaSession::admin_did`.
    pub fn admin_did(&self) -> &str {
        match *self {}
    }

    /// See the `vta` build's `VtaSession::admin_private_key_mb`.
    pub fn admin_private_key_mb(&self) -> &str {
        match *self {}
    }
}

/// Why a VTA option is refused in a build without the `vta` feature. Shown by
/// the wizard's VTA step and returned by every headless VTA entry point.
#[cfg(not(feature = "vta"))]
pub const VTA_UNAVAILABLE: &str = "VTA integration is unavailable in this release: \
    vta-sdk is not built in until it is released on affinidi-messaging-sdk 0.47 / \
    affinidi-tdk 0.45. Configure the mediator without a VTA (No VTA), or use a \
    release that includes VTA integration.";
