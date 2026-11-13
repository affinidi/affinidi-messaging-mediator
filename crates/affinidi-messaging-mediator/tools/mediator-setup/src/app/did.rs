//! The DID step's sub-phases: webvh hosting, identity form and the
//! did:web copy.

use tui_input::Input;

use super::{DidPhase, InputMode, WizardApp, WizardStep};

impl WizardApp {
    /// Strip any URL path so the stripped `<scheme>://<host>[:port]`
    /// lands on the VTA's `CreateDidWebvhRequest.url`. webvh resolves
    /// to `<url>/.well-known/did.jsonl`, so a trailing `/mediator/v1`
    /// on the operator-typed URL would point the resolver somewhere
    /// that doesn't serve the DID document.
    pub(super) fn strip_url_path(raw: &str) -> String {
        match url::Url::parse(raw) {
            Ok(mut u) => {
                u.set_path("");
                u.to_string().trim_end_matches('/').to_string()
            }
            Err(_) => raw.to_string(),
        }
    }

    /// Number of entries in the webvh-host selection list — kept as
    /// a helper for future navigation code (e.g. up/down clamping)
    /// though the renderer derives the count from `current_options()`
    /// today.
    #[allow(dead_code)]
    pub(super) fn webvh_host_option_count(&self) -> usize {
        // Pre provision-integration there was a list of VTA-registered
        // webvh servers here. That list is gone — the VTA's template
        // decides publishing — so only the two static self-host options
        // remain.
        2
    }

    pub fn in_did_subflow(&self) -> bool {
        self.current_step == WizardStep::Did && self.did_phase.is_some()
    }

    /// Enter the did:web export Yes/No prompt (a sub-phase of the Did
    /// step). Index 0 = "No (recommended)", index 1 = "Yes" — pre-selects
    /// the operator's current choice, defaulting to the recommended "No"
    /// so the export stays opt-in.
    pub(super) fn enter_identity_form_choice(&mut self) {
        self.did_phase = Some(DidPhase::IdentityFormChoice);
        self.mode = InputMode::Selecting;
        self.selection_index = usize::from(self.config.present_as_scid);
    }

    pub(super) fn enter_save_did_web_choice(&mut self) {
        self.did_phase = Some(DidPhase::SaveDidWebChoice);
        self.mode = InputMode::Selecting;
        self.selection_index = usize::from(self.config.save_did_web);
    }

    /// Confirm the SelectWebvhHost selection. `selection_index` maps
    /// to 0 = self-host at mediator URL, 1..=servers.len() = VTA-hosted
    /// server, servers.len()+1 = self-host elsewhere.
    pub(super) fn confirm_webvh_host_choice(&mut self) {
        // Only two static options remain after provision-integration:
        // idx 0 = self-host at mediator URL, idx 1 = self-host elsewhere.
        // The VTA-registered server list is gone; the VTA's template
        // handles publishing for use_vta flows.
        match self.selection_index {
            0 => {
                self.config.vta_webvh_server_id = None;
                self.config.vta_webvh_path = None;
                self.did_phase = None;
                self.advance();
            }
            _ => {
                self.did_phase = Some(DidPhase::EnterCustomUrl);
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.vta_webvh_self_host_url.clone());
            }
        }
    }
}
