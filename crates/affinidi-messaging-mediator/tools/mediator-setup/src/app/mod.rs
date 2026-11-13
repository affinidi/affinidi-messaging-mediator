//! The interactive wizard: its state ([`WizardApp`]), what it collects
//! ([`WizardConfig`]) and how key presses move it.
//!
//! - [`step`]: the steps, input modes and per-step sub-phases.
//! - [`choices`]: the option tables behind each selection list.
//! - [`copy`]: titles, options and info text for the screen on show.
//! - [`input`]: Enter on a list or a text input, per step.
//! - [`navigation`]: advancing, going back, focus and list movement.
//! - [`key_storage`], [`vta_flow`], [`did`], [`security`], [`discovery`]:
//!   the sub-flows of individual steps.
//! - [`background`]: side effects (background tasks, clipboard, quit).
//! - [`config`] and [`validate`]: the collected configuration and the
//!   input checks it must pass.

mod background;
mod choices;
mod config;
mod copy;
mod did;
mod discovery;
mod input;
mod key_storage;
mod navigation;
mod security;
mod step;
mod validate;
mod vta_flow;

pub use choices::{
    Choice, DEPLOYMENT_CHOICES, KEY_STORAGE_CHOICES, SSL_CHOICES, VTA_INTENT_CHOICES, index_of,
    index_of_str,
};
pub use config::WizardConfig;
pub use step::{
    DatabasePhase, DidPhase, FILE_GATE_PHRASE, FocusPanel, InputMode, KeyStoragePhase,
    SecurityPhase, StepData, VtaStepPhase, WizardStep,
};
pub use validate::validate_cors_domains;
pub(crate) use validate::validate_fjall_data_dir;

use tokio::sync::mpsc::UnboundedReceiver;
use tui_input::Input;

use crate::discovery::{DiscoveryEvent, DiscoveryState};
use crate::sealed_handoff::SealedHandoffState;
use crate::vta::{VtaConnectState, VtaIntent, VtaSession};

/// The main wizard application state.
pub struct WizardApp {
    pub current_step: WizardStep,
    pub config: WizardConfig,
    pub selection_index: usize,
    pub text_input: Input,
    pub mode: InputMode,
    pub focus: FocusPanel,
    /// Index of highlighted step in the progress panel (left panel)
    pub progress_index: usize,
    pub should_quit: bool,
    pub write_config: bool,
    completed: Vec<WizardStep>,
    /// Which field within the chosen secret backend we're currently
    /// collecting. `None` means we're still on the scheme-selection list
    /// (the default KeyStorage view). Transient — not persisted.
    pub key_storage_phase: Option<KeyStoragePhase>,
    /// Sub-phase tracker for the `Security` step. `None` means the SSL
    /// portion is still active (selection list or cert/key text inputs);
    /// `Some(JwtMode)` means the JWT-mode selection is on screen.
    pub security_phase: Option<SecurityPhase>,
    /// Sub-phase tracker for the `Database` step. `Some(SelectBackend)`
    /// means the backend-picker list is on screen; `None` means the
    /// operator has picked a backend and we're collecting the
    /// backend-specific URL/path via the text-input widget.
    pub database_phase: Option<DatabasePhase>,
    /// Sub-phase tracker for the `Did` step. Only ever populated when
    /// the operator picked `DID_VTA` and we have an online VTA
    /// session — the wizard then walks the webvh-host selection
    /// screens before advancing to Security.
    pub did_phase: Option<DidPhase>,
    /// Ephemeral state for the online-VTA connection sub-flow. Present only
    /// while the operator is stepping through the sub-phases of the Vta step.
    pub vta_connect: Option<VtaConnectState>,
    /// Optional CLI-provided VTA DID that pre-fills the first sub-flow
    /// text field. Kept on the app (not on `VtaConnectState`) so repeated
    /// enter/exit cycles within the same wizard session all see the prefill.
    pub vta_did_prefill: Option<String>,
    /// Optional CLI-provided context id override for the sub-flow.
    pub vta_context_prefill: Option<String>,
    /// Captured VTA session — set when the Connected phase advances, read
    /// by the config-writing step to provision the mediator's DID.
    pub vta_session: Option<VtaSession>,
    /// Ephemeral state for the air-gapped sealed-handoff sub-flow.
    /// Present only while the operator is on that sub-flow's screens;
    /// extracted into `vta_session` and dropped on completion.
    pub sealed_handoff: Option<SealedHandoffState>,
    /// Snapshot of on-disk artefact paths captured at the moment the
    /// sealed-handoff sub-flow transitions out of `Complete`. Used
    /// post-setup to clean up the ephemeral seed + request file
    /// after the mediator has written its config — same cleanup the
    /// non-interactive `--from` path does via
    /// [`crate::bootstrap_headless::cleanup_artifacts`]. `None`
    /// when the setup didn't go through the sealed-handoff flow.
    pub tui_bootstrap_artifacts: Option<crate::bootstrap_headless::BootstrapArtifacts>,
    /// Which of the two top-level picker questions is on screen. Reset
    /// to [`VtaStepPhase::SelectIntent`] whenever the operator enters
    /// or re-enters the Vta step.
    pub vta_step_phase: VtaStepPhase,
    /// Intent the operator picked on the first question. `None` until
    /// they pick, then `Some(FullSetup)` or `Some(AdminOnly)` while
    /// they answer the second question. Cleared when the Vta step is
    /// left (advance or go-back).
    pub vta_intent_choice: Option<VtaIntent>,
    /// Transient notice shown under the transport picker when the
    /// operator selects a (intent, transport) combination whose
    /// adapter isn't implemented yet. Cleared on the next
    /// transition.
    pub vta_stub_notice: Option<String>,
    /// Active discovery overlay — `Some` while the operator triggered F5
    /// on a cloud-backend namespace screen and either the background
    /// `list_namespace` task is in flight (`Loading`), the result is
    /// being browsed (`Loaded`), or the failure is being read (`Failed`).
    /// Cleared on Enter (apply pick) or Esc (dismiss).
    pub discovery: Option<DiscoveryState>,
    /// Receiver side of the discovery channel. Set when a discovery is
    /// kicked off; drained on each tick by [`Self::drain_discovery_events`]
    /// and dropped when the result lands or the operator dismisses.
    pub discovery_rx: Option<UnboundedReceiver<DiscoveryEvent>>,
    /// Last clipboard outcome rendered on the Summary panel —
    /// "Copied {label} via {method}" on success or
    /// "Clipboard unavailable: …" on failure. Phase-scoped state
    /// for the `[c]` / `[b]` Summary hotkeys; the sub-flow phases
    /// (vta_connect / sealed_handoff) carry their own equivalent
    /// fields. Reset on phase transitions away from Summary.
    pub clipboard_status: Option<String>,
    /// Inline validation error surfaced in the Database step's info
    /// box when the operator confirms a Fjall data-directory path
    /// whose parent is missing or whose target is not a directory.
    /// Cleared on a successful confirm or when the operator backs
    /// out of the step.
    pub database_validation_error: Option<String>,
    /// Inline validation error surfaced on the Security step's CORS
    /// "Specific domains" text-input screen when an entered origin isn't
    /// a valid scheme-qualified origin or `*.subdomain` wildcard. Cleared
    /// on a successful confirm or when re-entering the CORS phase.
    pub cors_validation_error: Option<String>,
    /// First passphrase typed on the [`KeyStoragePhase::FilePassphrase`]
    /// screen. Held just long enough for the operator to retype it on
    /// the [`KeyStoragePhase::FilePassphraseConfirm`] screen — cleared
    /// on a successful match (after the env var is written) or on
    /// mismatch (so the next attempt starts fresh). `Zeroizing<String>`
    /// scrubs the heap allocation when the option is dropped.
    pub pending_passphrase: Option<zeroize::Zeroizing<String>>,
    /// Inline validation error surfaced under the file-backend
    /// passphrase prompt when the confirm-typed value didn't match the
    /// first entry. Cleared on the next successful match or when the
    /// operator backs out of the sub-flow.
    pub passphrase_validation_error: Option<String>,
    /// `--force-reprovision`: the operator accepts writing over a backend
    /// that already holds a provisioned mediator. Set by `main` before the
    /// TUI starts; read by the KeyStorage backend check.
    pub force_reprovision: bool,
    /// Talk to the real secret backend from inside the TUI: probe it when
    /// the KeyStorage step completes and persist a VTA session as soon as
    /// it exists. Set by `main`; off in unit tests, which drive the state
    /// machine without a runtime or a backend.
    pub live_backend: bool,
    /// The KeyStorage backend check, while it runs or after it failed.
    pub backend_check: Option<BackendCheck>,
    /// The backend URL the last successful check covered. Leaving
    /// KeyStorage re-checks only when the choice changed.
    backend_checked_url: Option<String>,
    /// Result channel of a background task (backend check or session
    /// persistence).
    background_rx: Option<UnboundedReceiver<BackgroundEvent>>,
    /// Outcome of persisting the VTA session into the secret backend,
    /// shown to the operator.
    pub session_persist_status: Option<String>,
    /// The spawned provision flight, so Esc can stop it rather than just
    /// stop listening to it.
    vta_task: Option<tokio::task::JoinHandle<()>>,
    /// Ctrl+C / F10 / Esc-on-first-step was pressed while a VTA session
    /// exists: a y/n confirmation is on screen.
    quit_confirm: bool,
    /// Inline error for the text input on screen (a required field left
    /// empty, a wrong confirmation phrase, a malformed DID). Cleared on
    /// the next successful confirm or step change.
    pub input_error: Option<String>,
    /// Which SSL path the "Provide existing certificates" text input is
    /// collecting.
    pub ssl_field: Option<SslField>,
    /// Advances on every tick; drives the spinner of background checks.
    pub tick: usize,
}

/// The two text inputs of the "Provide existing certificates" choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslField {
    Cert,
    Key,
}

/// State of the KeyStorage backend check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCheck {
    /// Probing `url` (shown redacted).
    Running(String),
    /// The probe failed, or the backend already holds a mediator.
    Failed(String),
}

/// Results of the TUI's background tasks.
#[derive(Debug)]
pub enum BackgroundEvent {
    /// The backend check finished: `Ok` with the URL it covered.
    BackendChecked(Result<String, String>),
    /// Persisting the VTA session finished.
    SessionPersisted(Result<String, String>),
}

impl WizardApp {
    pub fn new(config_path: String) -> Self {
        let config = WizardConfig {
            config_path,
            ..WizardConfig::default()
        };
        Self {
            current_step: WizardStep::Deployment,
            config,
            selection_index: 0,
            text_input: Input::default(),
            mode: InputMode::Selecting,
            focus: FocusPanel::Content,
            progress_index: 0,
            should_quit: false,
            write_config: false,
            completed: Vec::new(),
            key_storage_phase: None,
            security_phase: None,
            database_phase: Some(DatabasePhase::SelectBackend),
            did_phase: None,
            vta_connect: None,
            vta_did_prefill: None,
            vta_context_prefill: None,
            vta_session: None,
            sealed_handoff: None,
            tui_bootstrap_artifacts: None,
            vta_step_phase: VtaStepPhase::SelectIntent,
            vta_intent_choice: None,
            vta_stub_notice: None,
            discovery: None,
            discovery_rx: None,
            clipboard_status: None,
            database_validation_error: None,
            cors_validation_error: None,
            pending_passphrase: None,
            passphrase_validation_error: None,
            force_reprovision: false,
            live_backend: false,
            backend_check: None,
            backend_checked_url: None,
            background_rx: None,
            session_persist_status: None,
            vta_task: None,
            quit_confirm: false,
            input_error: None,
            ssl_field: None,
            tick: 0,
        }
    }

    /// Lift the online sub-flow's connection onto `vta_session`.
    fn capture_connected_session(&mut self) {
        if let Some(state) = self.vta_connect.as_ref()
            && let Some(conn) = state.connection.as_ref()
        {
            self.vta_session = Some(VtaSession {
                context_id: state.context_id.clone(),
                vta_did: state.vta_did.clone(),
                rest_url: conn.rest_url.clone(),
                mediator_did: conn.mediator_did.clone(),
                // Lift the SDK's online 2-variant reply into the local
                // 3-variant `VtaReply` (offline-only `ContextExport` is
                // built directly by `crate::sealed_handoff`).
                reply: conn.reply.clone().into(),
            });
        }
    }
}

#[cfg(test)]
// The `unsafe` here is only `std::env::remove_var` (unsafe since the 2024
// edition) on the passphrase variable the wizard exports.
// SAFETY: the tests that touch it are `#[serial_test::serial(passphrase_env)]`,
// so no two of them read or write it concurrently.
#[allow(unsafe_code)]
mod tests;
