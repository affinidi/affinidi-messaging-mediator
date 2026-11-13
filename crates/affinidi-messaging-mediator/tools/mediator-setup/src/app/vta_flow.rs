//! The VTA step's sub-flows: the online connection and provisioning, and
//! the air-gapped sealed handoff.

use tui_input::Input;

use crate::vta::{
    ConnectPhase, EphemeralSetupKey, VtaConnectState, VtaIntent, pending_list, run_connection_test,
};

use super::{InputMode, WizardApp, WizardStep};

impl WizardApp {
    /// Enter the sealed-handoff sub-flow. Mints the consumer keypair +
    /// nonce + bootstrap-request JSON immediately so the first
    /// rendered screen has something to display. Errors here mean the
    /// system RNG failed — bubble them up rather than silently using a
    /// degraded value.
    pub(super) fn enter_sealed_handoff_subflow(&mut self, intent: VtaIntent) {
        // The sub-flow opens on `CollectContext` — a text-input prompt
        // for the VTA context slug. Seed the input widget with the
        // state's default so the operator can accept with Enter or
        // edit. Keypair + request JSON are produced later by
        // `SealedHandoffState::finalize_request`.
        //
        // For `FullSetup` we pre-seed the mediator URL from
        // `config.public_url` when it's already been set elsewhere in
        // the wizard — saves the operator from retyping.
        let mut state = crate::sealed_handoff::SealedHandoffState::new(
            intent,
            Some(format!("mediator/{}", self.config.config_path)),
        );
        if intent == VtaIntent::FullSetup && !self.config.public_url.is_empty() {
            state = state.with_mediator_url(self.config.public_url.clone());
        }
        self.text_input = Input::new(state.context_id.clone());
        self.mode = InputMode::TextInput;
        self.sealed_handoff = Some(state);
    }

    /// Predicate used by the renderer/key-handler to keep the sealed
    /// sub-flow's screens in scope while the operator is mid-flow.
    pub fn in_sealed_handoff_subflow(&self) -> bool {
        self.current_step == WizardStep::Vta && self.sealed_handoff.is_some()
    }

    /// Transition out of the online VTA-connect sub-flow and into
    /// the offline sealed-handoff sub-flow. Carries `vta_did`,
    /// `context_id`, and (FullSetup only) `mediator_url` over so
    /// the operator doesn't re-type them on the sealed-handoff
    /// intro. The setup key is regenerated at `finalize_request`
    /// time inside the sealed flow — the online setup key stays
    /// inside `vta_connect`, never leaks into the sealed bundle.
    ///
    /// `reason` becomes the operator-facing banner on the
    /// sealed-handoff intro screen, so the operator sees why the
    /// wizard switched flows.
    pub fn transition_to_sealed_handoff(&mut self, reason: crate::vta::OfflineReason) {
        let Some(vta) = self.vta_connect.as_ref() else {
            return;
        };
        let intent = vta.intent;
        let context_id = vta.context_id.clone();
        let mediator_url = vta.mediator_url.clone();

        let mut state = crate::sealed_handoff::SealedHandoffState::new(
            intent,
            Some(format!("mediator/{}", self.config.config_path)),
        );
        state.context_id = context_id.clone();
        if intent == VtaIntent::FullSetup && !mediator_url.is_empty() {
            state = state.with_mediator_url(mediator_url);
        }
        state.offline_transition_banner = Some(reason.banner().to_string());

        self.text_input = Input::new(context_id);
        self.mode = InputMode::TextInput;
        self.sealed_handoff = Some(state);
        self.vta_connect = None;
        self.selection_index = 0;
    }

    /// Drive the sealed sub-flow forward. The phases are linear and
    /// each "select" advances by one — the actual ingest/open work
    /// happens on the text-input confirmation path.
    pub(super) fn sealed_handoff_select(&mut self) {
        use crate::sealed_handoff::SealedPhase;
        let Some(state) = self.sealed_handoff.as_mut() else {
            return;
        };
        match state.phase {
            SealedPhase::CollectContext
            | SealedPhase::CollectAdminLabel
            | SealedPhase::CollectMediatorUrl
            | SealedPhase::CollectWebvhServer
            | SealedPhase::CollectWebvhPath => {
                // These phases drive text-input; Enter goes through
                // `sealed_handoff_confirm_text`, not here. The renderer
                // only lands in `sealed_handoff_select` for these
                // phases if the mode is out of sync (e.g. the user
                // toggled focus). Safest to no-op.
            }
            SealedPhase::RequestGenerated => {
                // Enter the paste prompt for the armored bundle.
                state.phase = SealedPhase::AwaitingBundle;
                self.text_input = Input::default();
                self.mode = InputMode::TextInput;
            }
            SealedPhase::AwaitingBundle | SealedPhase::DigestVerify => {
                // While in TextInput mode the renderer routes Enter
                // through `confirm_text_input`; this branch only
                // matters if the user is somehow in Selecting mode at
                // this phase (e.g. after an error). Stay put.
            }
            SealedPhase::Complete => {
                // Project the captured session onto the wizard and
                // exit the sub-flow. From here the wizard advances to
                // Protocol like the Online VTA path.
                //
                // Before dropping the sealed_handoff state, snapshot
                // the on-disk artefact paths so main.rs can clean
                // them up after the TUI finishes and writes the
                // mediator config. Matches the non-interactive
                // path's cleanup contract — "only what the mediator
                // needs to start should be kept".
                self.tui_bootstrap_artifacts =
                    Some(crate::bootstrap_headless::BootstrapArtifacts {
                        request_path: state.request_path.take(),
                        seed_bundle_id: None,
                    });
                self.vta_session = state.session.take();
                self.sealed_handoff = None;
                self.mode = InputMode::Selecting;
                // Store the credential now, before leaving the VTA step.
                self.persist_session();
                self.advance();
            }
        }
    }

    /// Handle Enter on a text-input prompt belonging to the sealed
    /// sub-flow. Returns `true` if the input was consumed so the
    /// outer dispatcher knows not to fall through.
    pub(super) fn sealed_handoff_confirm_text(&mut self) -> bool {
        use crate::sealed_handoff::{
            SealedPhase, ingest_armored, ingest_armored_file, open_with_digest,
        };
        let Some(state) = self.sealed_handoff.as_mut() else {
            return false;
        };
        let value = self.text_input.value().to_string();
        match state.phase {
            SealedPhase::CollectContext => {
                // Accept the typed context slug (empty means "use the
                // pre-filled default"). Branch to the next collect
                // phase based on intent: AdminOnly → CollectAdminLabel,
                // FullSetup → CollectMediatorUrl.
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    state.context_id = trimmed.to_string();
                }
                match state.intent {
                    VtaIntent::AdminOnly => {
                        state.phase = SealedPhase::CollectAdminLabel;
                        self.text_input = Input::new(state.admin_label.clone());
                    }
                    VtaIntent::FullSetup => {
                        state.phase = SealedPhase::CollectMediatorUrl;
                        self.text_input = Input::new(state.mediator_url.clone());
                    }
                    VtaIntent::OfflineExport => {
                        // No further inputs — context_id alone drives
                        // `vta contexts reprovision`. Finalise the
                        // request right here so the operator lands on
                        // RequestGenerated in one keystroke.
                        if let Err(e) = state.finalize_request() {
                            state.last_error = Some(e.to_string());
                        } else {
                            self.text_input = Input::default();
                            self.mode = InputMode::Selecting;
                        }
                    }
                }
                true
            }
            SealedPhase::CollectMediatorUrl => {
                // Required field for FullSetup — an empty value keeps
                // the operator on this phase with `last_error` set
                // rather than silently finalising a VP the VTA will
                // reject. Advance to the optional webvh-server pick.
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    state.last_error = Some(
                        "Mediator public URL is required for full-setup provisioning \
                         (fed to the VTA's didcomm-mediator template as the `URL` \
                         variable)."
                            .into(),
                    );
                    return true;
                }
                state.mediator_url = trimmed.to_string();
                state.last_error = None;
                state.phase = SealedPhase::CollectWebvhServer;
                self.text_input = Input::new(state.webvh_server.clone());
                true
            }
            SealedPhase::CollectWebvhServer => {
                // Optional — blank means "serverless, self-host at the
                // URL". Non-blank is passed to the VTA as the
                // `WEBVH_SERVER` template var; the VTA validates
                // against its server catalogue (unknown id → NotFound
                // before any minting runs).
                state.webvh_server = value.trim().to_string();
                state.last_error = None;
                if state.webvh_server.is_empty() {
                    // Self-host — no server, no path. Finalise.
                    if let Err(e) = state.finalize_request() {
                        state.last_error = Some(e.to_string());
                    } else {
                        self.text_input = Input::default();
                        self.mode = InputMode::Selecting;
                    }
                } else {
                    // Server picked → ask for the optional DID path /
                    // mnemonic before finalising.
                    state.phase = SealedPhase::CollectWebvhPath;
                    self.text_input = Input::new(state.webvh_path.clone());
                }
                true
            }
            SealedPhase::CollectWebvhPath => {
                // Optional. Empty trims to "let the server auto-assign
                // a mnemonic"; non-empty is forwarded to the VTA as
                // `WEBVH_PATH` and on to the chosen webvh server's
                // `request_uri` call.
                state.webvh_path = value.trim().to_string();
                state.last_error = None;
                if let Err(e) = state.finalize_request() {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::CollectAdminLabel => {
                // Optional field — empty string means "skip the
                // --admin-label flag in the rendered command".
                state.admin_label = value.trim().to_string();
                if let Err(e) = state.finalize_request() {
                    state.last_error = Some(e.to_string());
                    // Stay on CollectAdminLabel so the operator can
                    // retry / back out. `finalize_request` only fails
                    // on unrecoverable RNG / serialisation errors, so
                    // in practice this branch is for dev-time
                    // sanity.
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::AwaitingBundle => {
                // Accept either a file path or an inline armored paste.
                // File-path is the reliable primary route — TUI paste
                // of multi-line armor doesn't survive `tui_input`'s
                // single-line widget on most terminals (newlines get
                // stripped before reaching `ingest_armored`, so the
                // armor decoder can't find its BEGIN/END markers).
                //
                // Detection order:
                // 1. If the input starts with `-----BEGIN ` and has
                //    newlines intact, treat as inline armor. Handles
                //    operators who pipe the contents through a
                //    terminal paste that genuinely preserved newlines.
                // 2. Otherwise trim whitespace and check whether the
                //    input names a path that exists — load the file
                //    and decode.
                // 3. If the path doesn't exist but the input is a
                //    long single-line starting with `-----BEGIN `,
                //    hint that paste likely stripped newlines.
                // 4. Fall through to raw-armor decode which will
                //    error with `"no BEGIN blocks found"` — the
                //    surfaced message lets the operator see the
                //    exact mismatch.
                let trimmed = value.trim();
                let result = if trimmed.starts_with("-----BEGIN ") && value.contains('\n') {
                    ingest_armored(state, &value)
                } else {
                    let path_candidate = trimmed;
                    let path_exists = !path_candidate.is_empty()
                        && std::path::Path::new(path_candidate).is_file();
                    if path_exists {
                        ingest_armored_file(state, path_candidate)
                    } else if trimmed.starts_with("-----BEGIN ") {
                        // Paste looked like armor but has no newlines
                        // — most common failure mode (terminal /
                        // tui_input stripped them). Give a specific
                        // hint instead of a generic armor error.
                        Err(crate::sealed_handoff::SealedHandoffError::ArmorDecode(
                            "paste appears to be armored but contains no line breaks — \
                             terminals often strip newlines on paste. Try entering the \
                             path to `bundle.armor` instead."
                                .into(),
                        ))
                    } else {
                        ingest_armored(state, &value)
                    }
                };
                if let Err(e) = result {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                }
                true
            }
            SealedPhase::DigestVerify => {
                if let Err(e) = open_with_digest(state, value.trim()) {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::RequestGenerated | SealedPhase::Complete => false,
        }
    }

    /// Esc/back from inside the sealed sub-flow. Drops the ephemeral
    /// keypair — `SealedHandoffState`'s `Drop` impl zeroes
    /// `recipient_secret`, `seed_bytes`, and `nonce` automatically, so
    /// the explicit `take()` is enough; no manual `.fill(0)` needed.
    pub(super) fn sealed_handoff_back(&mut self) {
        // Take the state out; the moved-out value drops at end of
        // scope and runs `SealedHandoffState::drop` which zeroes all
        // three secret-bearing fields. Behaviour is now uniform with
        // the success path (which also drops the state) — previously
        // only the back path zeroed `recipient_secret`, and
        // `seed_bytes` was never zeroed at all.
        let _state = self.sealed_handoff.take();
        self.discard_vta_session();
        self.config.use_vta = false;
        self.config.vta_mode = None;
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
    }

    /// True while the operator is inside the online-VTA connection sub-flow.
    pub fn in_vta_subflow(&self) -> bool {
        self.current_step == WizardStep::Vta && self.vta_connect.is_some()
    }

    pub fn vta_phase(&self) -> Option<&ConnectPhase> {
        self.vta_connect.as_ref().map(|s| &s.phase)
    }

    /// Begin the online-VTA sub-flow: initialise ephemeral state and prompt
    /// for the VTA DID.
    pub(super) fn enter_vta_subflow(&mut self, intent: VtaIntent) {
        let mut st = VtaConnectState::new(intent);
        if let Some(did) = self.vta_did_prefill.as_ref() {
            st.vta_did = did.clone();
        }
        if let Some(ctx) = self.vta_context_prefill.as_ref() {
            st.context_id = ctx.clone();
        }
        self.text_input = Input::new(st.vta_did.clone());
        self.mode = InputMode::TextInput;
        self.vta_connect = Some(st);
    }

    /// Exit the sub-flow, discarding ephemeral state. Used when the operator
    /// backs out of the Vta step entirely.
    pub(super) fn exit_vta_subflow(&mut self) {
        self.vta_connect = None;
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
    }

    /// Handle Enter for non-text-input sub-phases.
    pub(super) fn vta_subflow_select(&mut self) {
        let Some(st) = self.vta_connect.as_ref() else {
            return;
        };
        match st.phase {
            ConnectPhase::AwaitingAcl => {
                // Initial attempt — let the orchestrator auto-pick.
                self.start_vta_test(None);
            }
            // Only meaningful after the runner has finished with a failure —
            // let the operator retry. If the runner is still in flight
            // `event_rx` is still `Some` and Enter is ignored.
            ConnectPhase::Testing
                if self
                    .vta_connect
                    .as_ref()
                    .is_some_and(|st| st.event_rx.is_none() && st.last_error.is_some()) =>
            {
                self.start_vta_test(None);
            }
            ConnectPhase::Testing => {}
            ConnectPhase::PickWebvhServer => {
                // Index 0 is "serverless"; indices 1..=N map to
                // `st.webvh_servers[i-1]`. Commit the pick. Serverless
                // jumps straight to the provision flight — there's no
                // server to request a URI from, so no path prompt.
                // Server picks route through `EnterWebvhPath` so the
                // operator can supply an optional path.
                let choice: Option<String> = if self.selection_index == 0 {
                    None
                } else {
                    st.webvh_servers
                        .get(self.selection_index - 1)
                        .map(|s| s.id.clone())
                };
                let rest_url = st.preflight_rest_url.clone();
                let mediator_did = match st.preflight_mediator_did.clone() {
                    Some(m) => m,
                    None => return, // defensive — shouldn't happen after PreflightDone
                };
                // Record the choice on state (read by
                // `start_vta_provision` after the path prompt resolves,
                // and by the UI if the runner later fails). Serverless
                // also wipes any stale `webvh_path` from a back-nav.
                let is_serverless = {
                    let Some(st_mut) = self.vta_connect.as_mut() else {
                        return;
                    };
                    st_mut.webvh_server_choice = choice.clone();
                    if choice.is_none() {
                        st_mut.webvh_path = None;
                        true
                    } else {
                        st_mut.phase = ConnectPhase::EnterWebvhPath;
                        false
                    }
                };
                if is_serverless {
                    self.start_vta_provision(rest_url, mediator_did);
                } else {
                    // Server-hosted — prompt for an optional path.
                    // Pre-fill with any value captured on a prior
                    // attempt (back-nav round-trip) so the operator
                    // can accept with Enter.
                    let prefill = self
                        .vta_connect
                        .as_ref()
                        .and_then(|s| s.webvh_path.clone())
                        .unwrap_or_default();
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(prefill);
                }
            }
            ConnectPhase::Connected => {
                // Persist the authenticated session so later steps can
                // use the credential material. `conn.reply` already
                // carries the right variant — FullSetup → Full,
                // AdminOnly → AdminOnly — we just wrap the transport
                // context around it.
                self.capture_connected_session();
                self.vta_connect = None;
                self.mode = InputMode::Selecting;
                self.advance();
            }
            ConnectPhase::RecoveryPrompt => {
                // Recovery options layout (mirrors current_options):
                //   0 = [R] Retry DIDComm
                //   1 = [E] Retry REST
                //   2 = [O] Offline sealed-handoff
                //   3 = [B] Back to AwaitingAcl
                // Disabled options are silently ignored — the keyboard
                // handler skips them on arrow keys (see move_up /
                // move_down) but a stray Enter on a disabled option is
                // a no-op rather than an error.
                let opts = self.current_options();
                let opt = match opts.get(self.selection_index) {
                    Some(o) if o.enabled => o,
                    _ => return,
                };
                let _ = opt;
                match self.selection_index {
                    0 => {
                        // [R] Retry DIDComm — force the DIDComm path
                        // even on a both-advertised VTA so the
                        // orchestrator doesn't auto-pick BothAvailable
                        // and silently fall through to REST.
                        self.start_vta_test(Some(crate::vta::Protocol::DidComm));
                    }
                    1 => {
                        // [E] Retry REST — force the REST path.
                        self.start_vta_test(Some(crate::vta::Protocol::Rest));
                    }
                    2 => {
                        // [O] Offline sealed-handoff. Reason is
                        // BothFailed when an attempt actually ran;
                        // NoTransportAvailable when the recovery
                        // prompt fired because the VTA advertised
                        // neither transport.
                        let reason = match self.vta_connect.as_ref() {
                            Some(st)
                                if st.attempted.didcomm.is_some()
                                    || st.attempted.rest.is_some() =>
                            {
                                crate::vta::OfflineReason::BothFailed
                            }
                            _ => crate::vta::OfflineReason::NoTransportAvailable,
                        };
                        self.transition_to_sealed_handoff(reason);
                    }
                    3 => {
                        // [B] Back to AwaitingAcl so the operator can
                        // re-run the `pnm acl create` step or change
                        // the setup key.
                        if let Some(st) = self.vta_connect.as_mut() {
                            st.phase = ConnectPhase::AwaitingAcl;
                            st.last_error = None;
                            self.selection_index = 0;
                        }
                    }
                    _ => {}
                }
            }
            ConnectPhase::TransportFallbackPrompt => {
                // Layout: [F] / [R] / [O] / [B]
                let opts = self.current_options();
                let opt = match opts.get(self.selection_index) {
                    Some(o) if o.enabled => o,
                    _ => return,
                };
                let _ = opt;
                match self.selection_index {
                    0 => {
                        // [F] Fall back to REST.
                        self.start_vta_test(Some(crate::vta::Protocol::Rest));
                    }
                    1 => {
                        // [R] Retry DIDComm — useful if the operator
                        // just fixed the underlying issue (ACL row,
                        // network) without giving up on DIDComm.
                        self.start_vta_test(Some(crate::vta::Protocol::DidComm));
                    }
                    2 => {
                        // [O] Offline sealed-handoff with the
                        // BothFailed reason — at least one transport
                        // attempt is recorded by definition (we're
                        // here because of a Failed event).
                        self.transition_to_sealed_handoff(crate::vta::OfflineReason::BothFailed);
                    }
                    3 => {
                        // [B] Back — same as the recovery prompt.
                        if let Some(st) = self.vta_connect.as_mut() {
                            st.phase = ConnectPhase::AwaitingAcl;
                            st.last_error = None;
                            self.selection_index = 0;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Kick off (or re-kick) the diagnostic + auth run. Resets the
    /// checklist, creates a fresh channel, and spawns the runner.
    ///
    /// `force_transport`: `None` lets the orchestrator auto-pick
    /// from advertised endpoints. `Some(Protocol::Rest)` forces the
    /// REST path (used by `[F] Fall back to REST` and `[E] Retry
    /// REST`). `Some(Protocol::DidComm)` forces DIDComm (used by
    /// `[R] Retry DIDComm`).
    pub(super) fn start_vta_test(&mut self, force_transport: Option<crate::vta::Protocol>) {
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        let Some(key) = st.setup_key.as_ref() else {
            st.last_error = Some("setup key missing — regenerate via Esc".into());
            return;
        };
        let intent = st.intent;
        let vta_did = st.vta_did.clone();
        let setup_did = key.did.clone();
        let setup_privkey_mb = key.private_key_multibase().to_string();
        let context_id = st.context_id.clone();
        let mediator_url = st.mediator_url.clone();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        st.diagnostics = pending_list();
        st.event_rx = Some(rx);
        st.last_error = None;
        st.clipboard_status = None;
        st.phase = ConnectPhase::Testing;
        // Clear the prior attempt outcome(s) for the transport(s)
        // about to be retried so the recovery / fallback prompts
        // don't see stale "already attempted" data.
        match force_transport {
            Some(crate::vta::Protocol::Tsp) => st.attempted.tsp = None,
            Some(crate::vta::Protocol::DidComm) => st.attempted.didcomm = None,
            Some(crate::vta::Protocol::Rest) => st.attempted.rest = None,
            None => {
                st.attempted.tsp = None;
                st.attempted.didcomm = None;
                st.attempted.rest = None;
            }
        }
        self.selection_index = 0;

        self.abort_vta_task();
        self.vta_task = Some(tokio::spawn(async move {
            run_connection_test(
                intent,
                vta_did,
                setup_did,
                setup_privkey_mb,
                context_id,
                mediator_url,
                force_transport,
                tx,
            )
            .await;
        }));
    }

    /// Kick off the FullSetup provision flight once the preflight has
    /// delivered a webvh-server choice (auto or operator-picked) and —
    /// for the server-hosted branch — the operator has typed an
    /// optional path via [`ConnectPhase::EnterWebvhPath`]. The
    /// resolved `mediator_did` + `rest_url` captured on preflight
    /// become inputs so we don't re-resolve; the webvh server pick
    /// and path are read from state.
    pub(super) fn start_vta_provision(&mut self, rest_url: Option<String>, mediator_did: String) {
        let tsp_enabled = self.config.tsp_enabled;
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        let Some(key) = st.setup_key.as_ref() else {
            st.last_error = Some("setup key missing — regenerate via Esc".into());
            return;
        };
        let vta_did = st.vta_did.clone();
        let setup_did = key.did.clone();
        let setup_privkey_mb = key.private_key_multibase().to_string();
        let context = st.context_id.clone();
        let mediator_url = st.mediator_url.clone();
        let label = Some(format!("mediator setup — {context}"));
        let webvh_server_id = st.webvh_server_choice.clone();
        let webvh_path = st.webvh_path.clone();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        st.event_rx = Some(rx);
        st.last_error = None;
        st.clipboard_status = None;
        st.phase = ConnectPhase::Testing;
        self.selection_index = 0;
        // Callers reach here from either a selection (PickWebvhServer)
        // or a text-input confirmation (EnterWebvhPath). Force
        // `Selecting` so the renderer drops the prompt widget while
        // the runner works, and so `Connected`'s "Continue" Enter
        // routes to `select_current`, not `confirm_text_input`.
        self.mode = InputMode::Selecting;

        self.abort_vta_task();
        self.vta_task = Some(tokio::spawn(async move {
            crate::vta::runner::run_provision_flight(
                vta_did,
                setup_did,
                setup_privkey_mb,
                mediator_did,
                rest_url,
                context,
                mediator_url,
                label,
                tsp_enabled,
                webvh_server_id,
                webvh_path,
                tx,
            )
            .await;
        }));
    }

    /// Drain any pending events from the runner and apply them to the
    /// sub-flow state. Called from the main event loop on every tick.
    pub fn drain_vta_events(&mut self) {
        // Snapshot phase pre-drain so we can detect transitions
        // (e.g. into RecoveryPrompt) and reset selection_index to
        // a sensible default for the new options layout.
        let pre_phase = self.vta_connect.as_ref().map(|s| s.phase.clone());

        // Drain any pending runner events. Both the early-exit
        // (no sub-flow / no channel) and the normal drain path fall
        // through to the webvh auto-dispatch below, which also runs
        // after a synthesised `PreflightDone` (tests) or after the
        // channel was already closed by a previous drain tick.
        if let Some(st) = self.vta_connect.as_mut() {
            if st.event_rx.is_some() {
                // Collect events first to release the mutable borrow
                // on `event_rx` before calling `apply_event` (which
                // also borrows `st` mutably).
                let mut batch = Vec::new();
                let mut disconnected = false;
                {
                    let rx = st.event_rx.as_mut().unwrap();
                    loop {
                        match rx.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                disconnected = true;
                                break;
                            }
                        }
                    }
                }
                for event in batch {
                    st.apply_event(event);
                }
                if disconnected {
                    st.event_rx = None;
                }
            }
        } else {
            return;
        }

        // If apply_event transitioned us into a recovery / fallback
        // prompt, the previous selection_index almost certainly maps
        // to a disabled row. Snap to the first enabled option so the
        // operator's first Enter doesn't no-op on a dimmed row.
        let post_phase = self.vta_connect.as_ref().map(|s| s.phase.clone());

        // Connected: capture the session and store its credential in the
        // backend right away — the VTA has minted for this run, and a quit
        // or later failure must not lose it.
        if pre_phase != post_phase && post_phase == Some(ConnectPhase::Connected) {
            self.vta_task = None;
            self.capture_connected_session();
            self.persist_session();
        }
        if pre_phase != post_phase
            && matches!(
                post_phase,
                Some(ConnectPhase::RecoveryPrompt) | Some(ConnectPhase::TransportFallbackPrompt)
            )
        {
            let opts = self.current_options();
            if let Some(idx) = opts.iter().position(|o| o.enabled) {
                self.selection_index = idx;
            }
        }

        // Post-drain dispatch: if we just landed on PickWebvhServer
        // with 0 or 1 servers, auto-select and kick the provision
        // flight straight away — no operator interaction needed.
        // Structured as two borrows (read → write → spawn) so the
        // `&mut self` call out to `start_vta_provision` doesn't
        // overlap the `&self` read of `vta_connect`.
        enum AutoPick {
            ServerlessOnly,
            SinglePick(String),
        }
        let auto = self.vta_connect.as_ref().and_then(|s| {
            if s.phase != ConnectPhase::PickWebvhServer || s.event_rx.is_some() {
                return None;
            }
            match s.webvh_servers.len() {
                0 => Some((
                    AutoPick::ServerlessOnly,
                    s.preflight_rest_url.clone(),
                    s.preflight_mediator_did.clone()?,
                )),
                1 => Some((
                    AutoPick::SinglePick(s.webvh_servers[0].id.clone()),
                    s.preflight_rest_url.clone(),
                    s.preflight_mediator_did.clone()?,
                )),
                _ => None,
            }
        });
        if let Some((pick, rest_url, mediator_did)) = auto {
            let choice = match pick {
                AutoPick::ServerlessOnly => None,
                AutoPick::SinglePick(id) => Some(id),
            };
            let is_serverless = {
                let Some(st) = self.vta_connect.as_mut() else {
                    return;
                };
                st.webvh_server_choice = choice.clone();
                if choice.is_none() {
                    st.webvh_path = None;
                    true
                } else {
                    // Auto-picked a server — still prompt for the
                    // optional path so the operator can supply one.
                    st.phase = ConnectPhase::EnterWebvhPath;
                    false
                }
            };
            if is_serverless {
                self.start_vta_provision(rest_url, mediator_did);
            } else {
                let prefill = self
                    .vta_connect
                    .as_ref()
                    .and_then(|s| s.webvh_path.clone())
                    .unwrap_or_default();
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(prefill);
            }
        }
    }

    /// Advance the sub-flow from a text-input phase into the next phase.
    pub(super) fn vta_subflow_confirm_text(&mut self) -> anyhow::Result<()> {
        let Some(st) = self.vta_connect.as_mut() else {
            return Ok(());
        };
        let mut webvh_path_dispatch = false;
        match st.phase {
            ConnectPhase::EnterDid => {
                let val = self.text_input.value().trim().to_string();
                if val.is_empty() {
                    self.input_error = Some("The VTA DID is required.".into());
                    return Ok(());
                }
                st.vta_did = val;
                st.phase = ConnectPhase::EnterContext;
                let ctx = st.context_id.clone();
                self.text_input = Input::new(ctx);
                // Stay in TextInput mode for the next field.
            }
            ConnectPhase::EnterContext => {
                let val = self.text_input.value().trim().to_string();
                if !val.is_empty() {
                    st.context_id = val;
                }
                // FullSetup needs the mediator's public URL (goes into
                // the template's `URL` var); AdminOnly doesn't — skip
                // straight to the ACL instructions screen.
                match st.intent {
                    VtaIntent::FullSetup => {
                        let prefill = if st.mediator_url.is_empty() {
                            self.config.public_url.clone()
                        } else {
                            st.mediator_url.clone()
                        };
                        st.phase = ConnectPhase::EnterMediatorUrl;
                        self.text_input = Input::new(prefill);
                        // Stay in TextInput mode.
                    }
                    VtaIntent::AdminOnly => {
                        st.setup_key = Some(EphemeralSetupKey::generate()?);
                        st.phase = ConnectPhase::AwaitingAcl;
                        self.mode = InputMode::Selecting;
                        self.selection_index = 0;
                        self.text_input = Input::default();
                    }
                    VtaIntent::OfflineExport => {
                        // Online sub-flow is never entered for
                        // OfflineExport — `enter_vta_subflow` rejects
                        // this intent and the transport selector
                        // routes straight to `enter_sealed_handoff_subflow`.
                        // Pattern is exhaustive because the enum
                        // demands it; reaching here would be a wiring
                        // bug: leave the sub-flow rather than panic.
                        self.exit_vta_subflow();
                        return Ok(());
                    }
                }
            }
            ConnectPhase::EnterMediatorUrl => {
                let val = self.text_input.value().trim().to_string();
                if val.is_empty() {
                    // Block advance until the operator provides a URL —
                    // the VTA template requires it.
                    self.input_error = Some("The mediator's public URL is required.".into());
                    return Ok(());
                }
                st.mediator_url = val.clone();
                // Mirror onto WizardConfig so the Did step doesn't
                // prompt again and later generators have the value.
                self.config.public_url = val;
                st.setup_key = Some(EphemeralSetupKey::generate()?);
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
                self.text_input = Input::default();
            }
            ConnectPhase::EnterWebvhPath => {
                // Blank is a valid answer — server auto-assigns the
                // path. Non-blank is forwarded to the VTA as
                // `WEBVH_PATH`. The provision flight itself is
                // dispatched after this match closes so the
                // `&mut VtaConnectState` borrow on `st` is released.
                let val = self.text_input.value().trim().to_string();
                st.webvh_path = if val.is_empty() { None } else { Some(val) };
                self.text_input = Input::default();
                webvh_path_dispatch = true;
            }
            _ => {}
        }
        if webvh_path_dispatch {
            let (rest_url, mediator_did) = {
                let Some(st) = self.vta_connect.as_ref() else {
                    return Ok(());
                };
                match st.preflight_mediator_did.clone() {
                    Some(m) => (st.preflight_rest_url.clone(), m),
                    // Defensive — shouldn't happen past PickWebvhServer.
                    None => return Ok(()),
                }
            };
            self.start_vta_provision(rest_url, mediator_did);
        }
        Ok(())
    }

    /// Handle Esc within the sub-flow — step back one phase, or exit to the
    /// outer Vta selection list.
    pub(super) fn vta_subflow_back(&mut self) {
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        match st.phase {
            ConnectPhase::EnterDid => {
                self.exit_vta_subflow();
            }
            ConnectPhase::EnterContext => {
                st.phase = ConnectPhase::EnterDid;
                let did = st.vta_did.clone();
                self.text_input = Input::new(did);
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::EnterMediatorUrl => {
                st.phase = ConnectPhase::EnterContext;
                let ctx = st.context_id.clone();
                self.text_input = Input::new(ctx);
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::AwaitingAcl => {
                // Step back to the most recent text-input phase —
                // EnterMediatorUrl for FullSetup (which collected
                // that), EnterContext for AdminOnly (which skipped
                // the URL prompt entirely).
                st.setup_key = None;
                match st.intent {
                    VtaIntent::FullSetup => {
                        st.phase = ConnectPhase::EnterMediatorUrl;
                        let url = st.mediator_url.clone();
                        self.text_input = Input::new(url);
                    }
                    VtaIntent::AdminOnly => {
                        st.phase = ConnectPhase::EnterContext;
                        let ctx = st.context_id.clone();
                        self.text_input = Input::new(ctx);
                    }
                    VtaIntent::OfflineExport => {
                        // Online sub-flow is never entered for
                        // OfflineExport. See note in
                        // `vta_subflow_confirm_text` above. Leave rather than panic.
                        self.exit_vta_subflow();
                        return;
                    }
                }
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::PickWebvhServer => {
                // Stepping back from the webvh picker rewinds to
                // `AwaitingAcl` so the operator can re-run
                // `pnm acl create` or re-kick the preflight. The
                // captured server catalogue is cleared so we don't
                // render a stale list on the next attempt.
                st.phase = ConnectPhase::AwaitingAcl;
                st.webvh_servers.clear();
                st.webvh_server_choice = None;
                st.webvh_path = None;
                st.preflight_mediator_did = None;
                st.preflight_rest_url = None;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
            ConnectPhase::EnterWebvhPath => {
                // Back to the server picker — the operator may want a
                // different server or to drop to serverless. The
                // typed path is kept on state so it re-pre-fills if
                // they land here again.
                st.phase = ConnectPhase::PickWebvhServer;
                self.mode = InputMode::Selecting;
                // Seed the picker highlight on the previously-chosen
                // server (offset by 1 for the "serverless" row at 0).
                self.selection_index = st
                    .webvh_server_choice
                    .as_ref()
                    .and_then(|id| {
                        st.webvh_servers
                            .iter()
                            .position(|s| &s.id == id)
                            .map(|idx| idx + 1)
                    })
                    .unwrap_or(0);
            }
            ConnectPhase::Testing | ConnectPhase::Connected => {
                // Stop the runner task itself — dropping the receiver alone
                // left the flight running — and return to the instructions
                // screen so the operator can re-check the ACL and try again.
                if let Some(task) = self.vta_task.take() {
                    task.abort();
                }
                st.event_rx = None;
                st.diagnostics.clear();
                st.last_error = None;
                st.connection = None;
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
            #[allow(unreachable_patterns)]
            _ => {
                // No other transient phases currently exist; guard for
                // future additions.
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
        }
    }
}
