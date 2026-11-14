//! Side effects of the wizard: the quit confirmation, background tasks
//! (backend check, VTA-session persistence) and clipboard copies.

use tokio::sync::mpsc::unbounded_channel;

#[cfg(feature = "vta")]
use crate::vta::ConnectPhase;

use super::{BackendCheck, BackgroundEvent, InputMode, WizardApp, WizardStep};

impl WizardApp {
    // ── Quit confirmation ────────────────────────────────────────────

    /// Ctrl+C / F10 / Esc on the first step. Quits at once unless a VTA
    /// session exists — the VTA has then minted keys or used the setup ACL
    /// for this run — in which case a y/n confirmation comes first.
    pub fn request_quit(&mut self) {
        if self.vta_session.is_some() && !self.quit_confirm {
            self.quit_confirm = true;
        } else {
            self.should_quit = true;
        }
    }

    /// The KeyStorage backend check is in flight; input waits for it.
    pub fn backend_check_running(&self) -> bool {
        matches!(self.backend_check, Some(BackendCheck::Running(_)))
    }

    pub fn quit_confirm_pending(&self) -> bool {
        self.quit_confirm
    }

    /// A key while the quit confirmation is on screen: `y` quits, anything
    /// else stays.
    pub fn answer_quit_confirm(&mut self, yes: bool) {
        self.quit_confirm = false;
        if yes {
            self.should_quit = true;
        }
    }

    // ── Background work (backend check, session persistence) ─────────

    /// A provision flight is running on a spawned task.
    pub fn provision_in_flight(&self) -> bool {
        #[cfg(feature = "vta")]
        return self
            .vta_connect
            .as_ref()
            .is_some_and(|s| s.phase == ConnectPhase::Testing && s.event_rx.is_some());
        // No provision flight exists without the `vta` feature.
        #[cfg(not(feature = "vta"))]
        false
    }

    /// Stop the spawned provision flight, if any.
    #[cfg(feature = "vta")]
    pub(super) fn abort_vta_task(&mut self) {
        if let Some(task) = self.vta_task.take() {
            task.abort();
        }
    }

    pub(super) fn background_channel(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedSender<BackgroundEvent> {
        let (tx, rx) = unbounded_channel();
        self.background_rx = Some(rx);
        tx
    }

    /// Probe the chosen backend and check it holds no provisioned mediator,
    /// on a spawned task. The KeyStorage step advances when it succeeds.
    pub(super) fn start_backend_check(&mut self) {
        let url = crate::config_writer::build_backend_url(&self.config);
        let shown = affinidi_messaging_mediator_common::redact::redact_url(&url);
        let force = self.force_reprovision;
        let passphrase = self.file_passphrase.clone();
        self.backend_check = Some(BackendCheck::Running(shown.clone()));
        let tx = self.background_channel();
        tokio::spawn(async move {
            let result = async {
                let store = crate::secret_backend::open_and_probe_secret_backend(
                    &url,
                    passphrase.as_ref(),
                    crate::secret_backend::ProvisionProbe::ReadWrite,
                )
                .await
                .map_err(|e| format!("{e:#}"))?;
                if !force {
                    let found = crate::secret_backend::provisioned_well_known_keys(&store)
                        .await
                        .map_err(|e| format!("{e:#}"))?;
                    if !found.is_empty() {
                        return Err(format!(
                            "{shown} already holds a provisioned mediator ({}). Pick another \
                             backend, or quit and re-run with --force-reprovision (replaces \
                             those keys) or --uninstall.",
                            found.join(", ")
                        ));
                    }
                }
                Ok(url)
            }
            .await;
            let _ = tx.send(BackgroundEvent::BackendChecked(result));
        });
    }

    /// Store the VTA session's admin credential and key cache in the
    /// secret backend now, so a quit or a later failure does not lose what
    /// the VTA already minted.
    #[cfg(feature = "vta")]
    pub(super) fn persist_session(&mut self) {
        if !self.live_backend {
            return;
        }
        let Some(session) = self.vta_session.clone() else {
            return;
        };
        let url = crate::config_writer::build_backend_url(&self.config);
        let passphrase = self.file_passphrase.clone();
        self.session_persist_status =
            Some("Storing the VTA credential in the secret backend…".into());
        let tx = self.background_channel();
        tokio::spawn(async move {
            let result = async {
                let store = crate::secret_backend::open_secret_backend(&url, passphrase.as_ref())
                    .map_err(|e| format!("{e:#}"))?;
                crate::secret_backend::store_vta_session(&store, &session)
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                Ok(affinidi_messaging_mediator_common::redact::redact_url(&url))
            }
            .await;
            let _ = tx.send(BackgroundEvent::SessionPersisted(result));
        });
    }

    /// Apply finished background work. Called on every tick.
    pub fn drain_background(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        let Some(rx) = self.background_rx.as_mut() else {
            return;
        };
        let event = match rx.try_recv() {
            Ok(event) => event,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.background_rx = None;
                return;
            }
        };
        self.background_rx = None;
        self.apply_background(event);
    }

    pub(super) fn apply_background(&mut self, event: BackgroundEvent) {
        match event {
            BackgroundEvent::BackendChecked(Ok(url)) => {
                self.backend_check = None;
                self.backend_checked_url = Some(url);
                if self.current_step == WizardStep::KeyStorage {
                    self.advance();
                }
            }
            BackgroundEvent::BackendChecked(Err(e)) => {
                self.backend_check = Some(BackendCheck::Failed(e));
                // Back on the scheme list so another backend can be picked.
                self.key_storage_phase = None;
                self.mode = InputMode::Selecting;
                self.selection_index = self.default_selection_index();
            }
            #[cfg(feature = "vta")]
            BackgroundEvent::SessionPersisted(Ok(url)) => {
                self.session_persist_status = Some(format!("VTA credential stored in {url}."));
            }
            #[cfg(feature = "vta")]
            BackgroundEvent::SessionPersisted(Err(e)) => {
                self.session_persist_status = Some(format!(
                    "Could not store the VTA credential yet ({e}); it is written again at \
                     the end of the wizard."
                ));
            }
        }
    }

    /// Forget a VTA session when the operator goes back to the VTA step or
    /// leaves VTA integration: the rest of the setup must not use it. The
    /// VTA-side state stays, and so does a credential already stored.
    pub(super) fn discard_vta_session(&mut self) {
        if self.vta_session.take().is_some() {
            #[cfg(feature = "vta")]
            {
                self.tui_bootstrap_artifacts = None;
            }
            self.vta_stub_notice = Some(
                "The previous VTA session was discarded. What the VTA did for it (a minted \
                 DID, a used setup ACL) remains on the VTA side, and a credential already \
                 stored in the secret backend stays there — finishing with a different \
                 choice needs --force-reprovision."
                    .into(),
            );
        }
    }

    /// Copy the mediator config-file path to the operator's
    /// clipboard. Hotkey `[c]` on the Summary panel.
    pub fn copy_config_path_to_clipboard(&mut self) {
        let path = self.config.config_path.clone();
        if path.is_empty() {
            self.clipboard_status = Some("No config path set yet".into());
            return;
        }
        self.copy_text_to_clipboard(&path, "config path");
    }

    /// Copy the resolved secret-backend URL (the same string the
    /// Summary panel renders next to "Key Storage") to the
    /// clipboard. Hotkey `[b]` on the Summary panel.
    pub fn copy_backend_url_to_clipboard(&mut self) {
        let url = crate::config_writer::build_backend_url(&self.config);
        if url.is_empty() {
            self.clipboard_status = Some("Backend URL not yet resolved".into());
            return;
        }
        self.copy_text_to_clipboard(&url, "backend URL");
    }

    /// Shared clipboard-write helper for the Summary panel. Mirrors
    /// the helpers on `VtaConnectState` / `SealedHandoffState`.
    pub(super) fn copy_text_to_clipboard(&mut self, text: &str, label: &str) {
        self.clipboard_status = Some(crate::clipboard::copy_with_status(text, label));
    }
}
