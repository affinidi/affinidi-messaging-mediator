//! The Security step's sub-phases: JWT mode, network mode and CORS.

use crate::consts::*;

use super::{InputMode, SecurityPhase, WizardApp, WizardStep};

impl WizardApp {
    /// Enter the JWT-mode sub-phase of the Security step. Called once SSL
    /// has been settled (either selection-only path or after the cert/key
    /// inputs). Pre-selects the operator's last choice so re-entry is
    /// idempotent; defaults to "generate" on a fresh run.
    pub(super) fn enter_jwt_mode_phase(&mut self) {
        self.security_phase = Some(SecurityPhase::JwtMode);
        self.mode = InputMode::Selecting;
        self.selection_index = if self.config.jwt_mode == JWT_MODE_PROVIDE {
            1
        } else {
            0
        };
    }

    /// Enter the network-mode sub-phase. Runs after JWT mode has been
    /// settled. Pre-selects the operator's last choice so re-entry is
    /// idempotent; defaults to Open (index 0) on a fresh run because
    /// that's the wizard's default network posture.
    pub(super) fn enter_network_mode_phase(&mut self) {
        self.security_phase = Some(SecurityPhase::NetworkMode);
        self.mode = InputMode::Selecting;
        self.selection_index = if self.config.network_mode == crate::consts::NETWORK_MODE_CLOSED {
            1
        } else {
            0
        };
    }

    /// Enter the CORS-policy sub-phase. Runs after network mode has been
    /// settled and is the final Security sub-phase before the step
    /// advances. Pre-selects the operator's last choice so re-entry is
    /// idempotent; defaults to None (index 0) on a fresh run — the
    /// mediator's default-closed cross-origin posture.
    pub(super) fn enter_cors_policy_phase(&mut self) {
        self.security_phase = Some(SecurityPhase::CorsPolicy);
        self.mode = InputMode::Selecting;
        self.cors_validation_error = None;
        self.selection_index = match self.config.cors_mode.as_str() {
            crate::consts::CORS_MODE_ANY => 1,
            crate::consts::CORS_MODE_LIST => 2,
            _ => 0,
        };
    }
}

impl WizardApp {
    /// Defensive helper kept symmetric with [`Self::in_key_storage_subflow`].
    /// Currently unused at call sites — the renderer reads
    /// `security_phase` directly — but exposed so future help-bar /
    /// back-nav code can branch on the same predicate.
    #[allow(dead_code)]
    pub fn in_security_subflow(&self) -> bool {
        self.current_step == WizardStep::Security && self.security_phase.is_some()
    }
}
