//! Moving through the wizard: focus, the progress panel, advancing and
//! going back, list movement, text input and paste.

use tui_input::{Input, InputRequest};

use crate::app::{DidMethod, VtaMode};
use crate::vta::VtaIntent;

use super::{
    DEPLOYMENT_CHOICES, DatabasePhase, DidPhase, FocusPanel, InputMode, KEY_STORAGE_CHOICES,
    SSL_CHOICES, SslField, VTA_INTENT_CHOICES, VtaStepPhase, WizardApp, WizardStep, index_of,
};

impl WizardApp {
    /// Switch focus to the progress panel (left)
    pub fn focus_progress(&mut self) {
        if self.mode == InputMode::TextInput {
            return; // Don't switch away from text input
        }
        self.focus = FocusPanel::Progress;
        self.progress_index = self.current_step.index();
    }

    /// Switch focus to the content panel (right)
    pub fn focus_content(&mut self) {
        self.focus = FocusPanel::Content;
    }

    /// Move progress highlight up
    pub fn progress_up(&mut self) {
        if self.progress_index > 0 {
            self.progress_index -= 1;
        }
    }

    /// Move progress highlight down
    pub fn progress_down(&mut self) {
        let max = WizardStep::all().len().saturating_sub(1);
        if self.progress_index < max {
            self.progress_index += 1;
        }
    }

    /// Jump to the step highlighted in the progress panel.
    /// All state is preserved — we just change the current step.
    pub fn jump_to_progress_step(&mut self) {
        let steps = WizardStep::all();
        if let Some(&step) = steps.get(self.progress_index) {
            // Can only jump to completed steps or the current step
            if self.completed.contains(&step) || step == self.current_step {
                self.current_step = step;
                self.on_enter_step();
                self.selection_index = self.default_selection_index();
                // Database now always starts on the backend picker;
                // previously it jumped directly to the URL text input,
                // which is no longer valid since the backend choice
                // hasn't been made yet on a fresh jump-back.
                self.mode = InputMode::Selecting;
                self.focus = FocusPanel::Content;
            }
        }
    }

    pub fn completed_steps(&self) -> Vec<WizardStep> {
        self.completed.clone()
    }
}

impl WizardApp {
    /// Per-step entry reset. Called from every point that mutates
    /// `current_step` so that landing on a step (forward or backward)
    /// always starts from a clean sub-phase. Keeping this in one place
    /// avoids the "which sub-phase leaked from the last visit" class
    /// of bug.
    pub(super) fn on_enter_step(&mut self) {
        if self.current_step == WizardStep::Vta {
            self.vta_step_phase = VtaStepPhase::SelectIntent;
            self.vta_intent_choice = None;
            self.vta_stub_notice = None;
            // Re-entering the VTA step starts the VTA choice over: a
            // session from the previous pass must not leak into a
            // different choice (with a warning that the VTA-side state
            // remains).
            self.discard_vta_session();
        }
        self.input_error = None;
        if self.current_step == WizardStep::Database {
            // Always start the Database step on the backend picker.
            // Re-entry via `go_back` from a later step lands here too,
            // and the caller can then move forward into the URL/path
            // text-input phase.
            self.database_phase = Some(DatabasePhase::SelectBackend);
            self.database_validation_error = None;
        }
    }

    pub(super) fn advance(&mut self) {
        // Step through the wizard, auto-skipping any step whose inputs
        // have already been settled upstream (see
        // `should_auto_skip_step`). The loop lets us chain skips —
        // e.g. a future step that's also FullSetup-noop — without
        // reworking callers. Bounded by `WizardStep::total()` to
        // guarantee termination even if the predicate pathologically
        // fires on every remaining step.
        // Leaving KeyStorage: check the chosen backend first (reachable,
        // and not already holding a mediator) on a spawned task; its
        // result calls `advance` again. Re-checked only when the choice
        // changed.
        if self.current_step == WizardStep::KeyStorage && self.live_backend {
            let url = crate::config_writer::build_backend_url(&self.config);
            if self.backend_checked_url.as_deref() != Some(url.as_str()) {
                self.start_backend_check();
                return;
            }
        }
        let mut guard = WizardStep::total();
        loop {
            self.completed.push(self.current_step);
            let Some(next) = self.current_step.next() else {
                return;
            };
            self.current_step = next;
            self.on_enter_step();
            self.selection_index = self.default_selection_index();
            // Output opens in text-input mode; Summary goes straight
            // to the confirmation screen; Database opens on its
            // backend-picker selection list (the URL/path text input
            // is reached after the picker is confirmed). Everything
            // else uses the selection-list default.
            if self.current_step == WizardStep::Database {
                self.mode = InputMode::Selecting;
                // Pre-select the operator's last-chosen backend so
                // re-entry is idempotent.
                self.selection_index =
                    if self.config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
                        1
                    } else {
                        0
                    };
            } else if self.current_step == WizardStep::Output {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.config_path.clone());
            } else if self.current_step == WizardStep::Summary {
                self.mode = InputMode::Confirming;
            } else {
                self.mode = InputMode::Selecting;
            }
            if !self.should_auto_skip_step() {
                return;
            }
            guard = guard.saturating_sub(1);
            if guard == 0 {
                return;
            }
        }
    }

    /// Per-step predicate: true when the step has no operator-actionable
    /// decision left because upstream work already settled it. The
    /// wizard's `advance` / `go_back` loops consult this to jump over
    /// such steps silently rather than presenting a single-option
    /// confirmation screen.
    ///
    /// Today only the `Did` step qualifies, and only under online
    /// FullSetup / OfflineExport: the VTA either minted the integration
    /// DID during provision-integration (FullSetup — TemplateBootstrap
    /// reply) or exported a pre-provisioned one via `vta contexts
    /// reprovision` (OfflineExport — ContextProvision reply). Either
    /// way `apply_vta_defaults` already pinned `did_method = DidMethod::Vta`
    /// and the mediator DID + doc + keys + did.jsonl ride on
    /// `vta_session`. Operators can still reach this step via the
    /// progress-panel jump if they want to inspect it.
    pub(super) fn should_auto_skip_step(&self) -> bool {
        match self.current_step {
            // No VTA session, so no VTA-minted DID, without the `vta` feature.
            #[cfg(feature = "vta")]
            WizardStep::Did => {
                self.config.use_vta
                    && self.config.did_method == Some(DidMethod::Vta)
                    && self.vta_session.as_ref().is_some_and(|s| {
                        // Either provisioning shape carries a minted
                        // integration DID. AdminOnly has neither
                        // accessor populated — the mediator brought
                        // its own DID, so the Did step still runs.
                        s.as_full_provision().is_some() || s.as_context_export().is_some()
                    })
            }
            _ => false,
        }
    }

    pub fn go_back(&mut self) {
        if self.backend_check_running() {
            return;
        }
        if self.in_key_storage_subflow() {
            self.key_storage_back();
            return;
        }
        if self.in_vta_subflow() {
            self.vta_subflow_back();
            return;
        }
        if self.in_sealed_handoff_subflow() {
            self.sealed_handoff_back();
            return;
        }
        // Top-level Vta picker: Esc from SelectTransport rewinds to
        // SelectIntent rather than leaving the step entirely. The
        // intent choice is cleared so SelectIntent's selection_index
        // can be re-defaulted without a stale pick.
        if self.current_step == WizardStep::Vta
            && self.vta_step_phase == VtaStepPhase::SelectTransport
            && !self.in_vta_subflow()
            && !self.in_sealed_handoff_subflow()
        {
            self.vta_step_phase = VtaStepPhase::SelectIntent;
            self.vta_intent_choice = None;
            self.vta_stub_notice = None;
            self.selection_index = 0;
            self.mode = InputMode::Selecting;
            return;
        }
        // Database step: `Esc` from the text-input phase rewinds to
        // the backend picker rather than leaving the step. Mirrors the
        // Vta `SelectTransport → SelectIntent` rewind pattern above.
        if self.current_step == WizardStep::Database
            && self.database_phase.is_none()
            && self.mode == InputMode::TextInput
        {
            self.database_phase = Some(DatabasePhase::SelectBackend);
            self.mode = InputMode::Selecting;
            self.selection_index =
                if self.config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
                    1
                } else {
                    0
                };
            self.database_validation_error = None;
            return;
        }
        // ConfirmCreateFjallDir: Esc cancels the create-now prompt and
        // sends the operator back to text input so they can retype the
        // path. Same effect as picking "No" from the selection list.
        if self.current_step == WizardStep::Database
            && self.database_phase == Some(DatabasePhase::ConfirmCreateFjallDir)
        {
            self.database_phase = None;
            self.mode = InputMode::TextInput;
            self.text_input = Input::new(self.config.fjall_data_dir.clone());
            return;
        }
        if self.in_did_subflow() {
            // EnterCustomUrl and EnterMnemonic → back to SelectWebvhHost.
            // SelectWebvhHost → exit the sub-flow entirely and fall
            // back to the mediator URL prompt.
            match self.did_phase {
                Some(DidPhase::EnterCustomUrl) => {
                    self.did_phase = Some(DidPhase::SelectWebvhHost);
                    self.mode = InputMode::Selecting;
                    self.selection_index = 0;
                }
                Some(DidPhase::SelectWebvhHost) => {
                    self.did_phase = None;
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.public_url.clone());
                }
                Some(DidPhase::SaveDidWebChoice)
                    if self.config.did_method == Some(DidMethod::Webvh) =>
                {
                    // Back from the did:web pick → the identity-form pick.
                    self.enter_identity_form_choice();
                }
                Some(DidPhase::SaveDidWebChoice) | Some(DidPhase::IdentityFormChoice) => {
                    // Back → re-edit the mediator URL.
                    self.did_phase = None;
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.public_url.clone());
                }
                None => {}
            }
            return;
        }
        self.input_error = None;
        match self.mode {
            InputMode::TextInput => {
                // SSL paths: back from the key path is the certificate path.
                if self.current_step == WizardStep::Security
                    && self.ssl_field == Some(SslField::Key)
                {
                    self.ssl_field = Some(SslField::Cert);
                    self.text_input = Input::new(self.config.ssl_cert_path.clone());
                    return;
                }
                self.ssl_field = None;
                self.mode = InputMode::Selecting;
            }
            InputMode::Confirming => {
                // On Summary, Esc goes back to the previous step
                if self.current_step == WizardStep::Summary {
                    self.step_back_auto_skipping();
                    self.mode = InputMode::Selecting;
                    self.refresh_text_input_mode();
                } else {
                    self.mode = InputMode::Selecting;
                }
            }
            InputMode::Selecting => {
                if !self.step_back_auto_skipping() {
                    // Already at the first step — Esc quits the wizard
                    // (after a confirmation when a VTA session exists).
                    self.request_quit();
                    return;
                }
                self.refresh_text_input_mode();
            }
        }
    }

    /// Walk `current_step` backwards one step, skipping any step that
    /// [`Self::should_auto_skip_step`] reports as non-actionable. The
    /// forward path uses the same predicate inside `advance`, so
    /// back-nav lands on the same step the operator saw on the way in.
    /// Returns `true` when a previous step was found (current_step
    /// mutated), `false` when we're already at the first step.
    pub(super) fn step_back_auto_skipping(&mut self) -> bool {
        let mut guard = WizardStep::total();
        loop {
            let Some(prev) = self.current_step.prev() else {
                return false;
            };
            self.completed.retain(|s| *s != prev);
            self.current_step = prev;
            self.on_enter_step();
            self.selection_index = self.default_selection_index();
            if !self.should_auto_skip_step() {
                return true;
            }
            guard = guard.saturating_sub(1);
            if guard == 0 {
                return true;
            }
        }
    }

    /// Shared helper for `go_back`: when landing on a text-input step
    /// (Database, Output) re-seed the input widget with the current
    /// config value so the operator can edit rather than retype.
    pub(super) fn refresh_text_input_mode(&mut self) {
        match self.current_step {
            WizardStep::Database => {
                // Database is now two-phase. Landing back here from
                // a later step always returns to the backend picker
                // (the URL/path field is reachable by confirming the
                // picker again). `on_enter_step` already reset
                // `database_phase` to `SelectBackend`, so leave the
                // mode as `Selecting`.
                self.mode = InputMode::Selecting;
            }
            WizardStep::Output => {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.config_path.clone());
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        let opts = self.current_options();
        let mut i = self.selection_index;
        while i > 0 {
            i -= 1;
            // The `enabled` flag is only false on the recovery
            // prompt's dimmed retry rows today; every other phase's
            // options are uniformly enabled, so the skip behaves
            // exactly like the old "decrement once" for them.
            if opts.get(i).map(|o| o.enabled).unwrap_or(true) {
                self.selection_index = i;
                return;
            }
        }
    }

    pub fn move_down(&mut self) {
        let opts = self.current_options();
        let max = opts.len().saturating_sub(1);
        let mut i = self.selection_index;
        while i < max {
            i += 1;
            if opts.get(i).map(|o| o.enabled).unwrap_or(true) {
                self.selection_index = i;
                return;
            }
        }
    }

    pub fn handle_text_input(&mut self, req: InputRequest) {
        self.text_input.handle(req);
    }

    /// Toggle the currently highlighted option on a multi-select step.
    /// No-op on single-select steps. Enforces "at least one selection"
    /// invariants where the step has them (e.g. Protocol needs at least one
    /// protocol enabled).
    pub fn toggle_current_multi_select(&mut self) {
        if !self.current_step.is_multi_select() {
            return;
        }
        if self.current_step == WizardStep::Protocol {
            let was_didcomm = self.config.didcomm_enabled;
            let was_tsp = self.config.tsp_enabled;
            match self.selection_index {
                0 => self.config.didcomm_enabled = !self.config.didcomm_enabled,
                1 => self.config.tsp_enabled = !self.config.tsp_enabled,
                _ => {}
            }
            // Never let the operator deselect everything — revert the
            // toggle if the result would leave zero protocols enabled.
            if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                self.config.didcomm_enabled = was_didcomm;
                self.config.tsp_enabled = was_tsp;
            }
        }
    }

    /// Splice a pasted string into the current text input at the cursor
    /// position. No-op outside of `InputMode::TextInput`. Newlines and other
    /// control characters are dropped so a multi-line paste collapses to a
    /// single line (our fields — DID, context id, URLs — are single-line by
    /// design).
    ///
    /// **Exception**: the sealed-handoff `AwaitingBundle` phase accepts
    /// armored bytes whose format is fundamentally multi-line (`-----BEGIN
    /// VTA SEALED BUNDLE-----` / `-----END ...-----` with newlines between
    /// them). We preserve `\n` and `\r` on that phase so a genuine
    /// bracketed-paste of the armor content survives through to
    /// `armor::decode`. In practice most terminals still collapse large
    /// pastes, which is why the confirm handler also accepts a file path —
    /// see `sealed_handoff_confirm_text::AwaitingBundle`.
    pub fn paste_text(&mut self, raw: &str) {
        if self.mode != InputMode::TextInput {
            return;
        }
        #[cfg(feature = "vta")]
        let preserve_newlines = matches!(
            self.sealed_handoff.as_ref().map(|s| s.phase),
            Some(crate::sealed_handoff::SealedPhase::AwaitingBundle)
        );
        #[cfg(not(feature = "vta"))]
        let preserve_newlines = false;
        let cleaned: String = raw
            .chars()
            .filter(|c| {
                if preserve_newlines && (*c == '\n' || *c == '\r') {
                    return true;
                }
                !c.is_control() && *c != '\n' && *c != '\r' && *c != '\t'
            })
            .collect();
        if cleaned.is_empty() {
            return;
        }
        let current = self.text_input.value();
        let cursor = self.text_input.cursor();
        let mut chars = current.chars();
        let mut new_value = String::with_capacity(current.len() + cleaned.len());
        for _ in 0..cursor {
            if let Some(c) = chars.next() {
                new_value.push(c);
            }
        }
        new_value.push_str(&cleaned);
        for c in chars {
            new_value.push(c);
        }
        let new_cursor = cursor + cleaned.chars().count();
        self.text_input = Input::new(new_value).with_cursor(new_cursor);
    }

    /// Get the default selection index based on deployment defaults.
    pub(super) fn default_selection_index(&self) -> usize {
        match self.current_step {
            WizardStep::Vta => {
                let intent = if !self.config.use_vta {
                    None
                } else if self.config.vta_mode == Some(VtaMode::SealedExport) {
                    Some(VtaIntent::OfflineExport)
                } else if self.config.did_method.is_some_and(|m| m != DidMethod::Vta) {
                    Some(VtaIntent::AdminOnly)
                } else {
                    Some(VtaIntent::FullSetup)
                };
                index_of(&VTA_INTENT_CHOICES, intent).unwrap_or(0)
            }
            WizardStep::Protocol => 0, // Start at DIDComm toggle
            WizardStep::Did => self
                .config
                .did_method
                .and_then(|v| index_of(&self.did_choices(), v))
                .unwrap_or(0),
            WizardStep::KeyStorage => self
                .config
                .secret_storage
                .and_then(|v| index_of(&KEY_STORAGE_CHOICES, v))
                .unwrap_or(0),
            WizardStep::Security => self
                .config
                .ssl_mode
                .and_then(|v| index_of(&SSL_CHOICES, v))
                .unwrap_or(0),
            WizardStep::Deployment => self
                .config
                .deployment_type
                .and_then(|v| index_of(&DEPLOYMENT_CHOICES, v))
                .unwrap_or(0),
            WizardStep::Admin => {
                // An `AdminMode::Vta` stored for a flow that no longer offers it
                // (e.g. OfflineExport) falls back to generating a did:key.
                self.config
                    .admin_did_mode
                    .and_then(|v| index_of(&self.admin_choices(), v))
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }
}
