//! Enter on a selection list or a text input: dispatch to the step on
//! screen, and the defaults a deployment or VTA choice implies.

use tui_input::Input;

use crate::app::{AdminMode, DidMethod, SecretScheme, SslMode, VtaMode};
use crate::consts::*;
use crate::vta::{VtaIntent, VtaTransport};

use super::{
    DEPLOYMENT_CHOICES, DatabasePhase, DidPhase, InputMode, KEY_STORAGE_CHOICES, KeyStoragePhase,
    SSL_CHOICES, SecurityPhase, SslField, VTA_INTENT_CHOICES, VtaStepPhase, WizardApp, WizardStep,
    validate_cors_domains, validate_fjall_data_dir,
};

impl WizardApp {
    /// Handle Enter key — select current option and advance.
    pub fn select_current(&mut self) {
        if self.backend_check_running() {
            return;
        }
        match self.current_step {
            WizardStep::Deployment => {
                let Some(choice) = DEPLOYMENT_CHOICES.get(self.selection_index) else {
                    return;
                };
                self.config.deployment_type = Some(choice.value);
                self.apply_deployment_defaults();
                self.advance();
            }
            WizardStep::Vta => {
                if self.in_vta_subflow() {
                    self.vta_subflow_select();
                    return;
                }
                if self.in_sealed_handoff_subflow() {
                    self.sealed_handoff_select();
                    return;
                }
                match self.vta_step_phase {
                    VtaStepPhase::SelectIntent => {
                        let Some(choice) = VTA_INTENT_CHOICES.get(self.selection_index) else {
                            return;
                        };
                        self.vta_stub_notice = None;
                        match choice.value {
                            Some(intent @ (VtaIntent::FullSetup | VtaIntent::AdminOnly)) => {
                                self.vta_intent_choice = Some(intent);
                                self.vta_step_phase = VtaStepPhase::SelectTransport;
                                self.selection_index = 0;
                            }
                            Some(VtaIntent::OfflineExport) => {
                                // Pick up state the VTA already provisioned.
                                // Always offline (the v1 BootstrapRequest has
                                // no online transport), so the transport
                                // question is skipped.
                                self.vta_intent_choice = Some(VtaIntent::OfflineExport);
                                self.config.use_vta = true;
                                self.config.vta_mode = Some(VtaMode::SealedExport);
                                self.apply_vta_defaults();
                                self.enter_sealed_handoff_subflow(VtaIntent::OfflineExport);
                            }
                            None => {
                                self.vta_intent_choice = None;
                                self.discard_vta_session();
                                self.config.use_vta = false;
                                self.config.vta_mode = None;
                                self.apply_vta_defaults();
                                self.advance();
                            }
                        }
                    }
                    VtaStepPhase::SelectTransport => {
                        let Some(intent) = self.vta_intent_choice else {
                            self.vta_step_phase = VtaStepPhase::SelectIntent;
                            return;
                        };
                        let transport = match self.selection_index {
                            0 => VtaTransport::Online,
                            1 => VtaTransport::Offline,
                            _ => return,
                        };
                        self.vta_stub_notice = None;
                        match (intent, transport) {
                            (VtaIntent::FullSetup, VtaTransport::Online) => {
                                // Online DIDComm flow with full
                                // provision-integration — wizard
                                // authenticates then runs the VP
                                // round-trip.
                                self.config.use_vta = true;
                                self.config.vta_mode = Some(VtaMode::Online);
                                self.apply_vta_defaults();
                                self.enter_vta_subflow(VtaIntent::FullSetup);
                            }
                            (VtaIntent::AdminOnly, VtaTransport::Offline) => {
                                // AdminOnly offline: `pnm contexts bootstrap`
                                // produces an `AdminCredential` sealed
                                // bundle; wizard extracts fallback admin
                                // fields.
                                self.config.use_vta = true;
                                self.config.vta_mode = Some(VtaMode::SealedMint);
                                self.apply_vta_defaults();
                                self.enter_sealed_handoff_subflow(VtaIntent::AdminOnly);
                            }
                            (VtaIntent::FullSetup, VtaTransport::Offline) => {
                                // FullSetup offline: wizard emits a VP-framed
                                // BootstrapRequest; VTA admin runs
                                // `vta bootstrap provision-integration` and
                                // returns a TemplateBootstrap sealed bundle
                                // that the wizard projects onto a full
                                // `ProvisionResultV2`.
                                self.config.use_vta = true;
                                self.config.vta_mode = Some(VtaMode::SealedMint);
                                self.apply_vta_defaults();
                                self.enter_sealed_handoff_subflow(VtaIntent::FullSetup);
                            }
                            (VtaIntent::AdminOnly, VtaTransport::Online) => {
                                // Online AdminOnly: wizard generates a
                                // fresh did:key, operator runs `pnm
                                // acl create` out-of-band, wizard
                                // opens an authenticated DIDComm
                                // session to verify enrollment. The
                                // setup did:key becomes the long-term
                                // admin credential (no rotation, no
                                // provision-integration).
                                self.config.use_vta = true;
                                self.config.vta_mode = Some(VtaMode::Online);
                                self.apply_vta_defaults();
                                self.enter_vta_subflow(VtaIntent::AdminOnly);
                            }
                            (VtaIntent::OfflineExport, _) => {
                                // OfflineExport bypasses the
                                // SelectTransport phase entirely (see
                                // SelectIntent index 2 above) — it has
                                // no online transport. Reaching here
                                // means the operator's selection_index
                                // landed on the wrong intent variant;
                                // a wiring bug: route it the only way it goes.
                                self.enter_sealed_handoff_subflow(VtaIntent::OfflineExport);
                            }
                        }
                    }
                }
            }
            WizardStep::Protocol => {
                // Enter always advances on a multi-select step. Toggling is
                // handled by `toggle_current_multi_select` (Space key).
                if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                    return; // Can't continue with no protocol
                }
                self.advance();
            }
            WizardStep::Did => {
                // The did:web export Yes/No pick rides on the same
                // selection-list UI. Record the choice and advance.
                if self.did_phase == Some(DidPhase::IdentityFormChoice) {
                    // Index 0 = did:webvh, index 1 = did:scid (which needs
                    // the alias listed).
                    self.config.present_as_scid = self.selection_index == 1;
                    if self.config.present_as_scid {
                        self.config.scid_also_known_as = true;
                    }
                    self.enter_save_did_web_choice();
                    return;
                }
                if self.did_phase == Some(DidPhase::SaveDidWebChoice) {
                    // Index 0 = "No (recommended)", index 1 = "Yes".
                    self.config.save_did_web = self.selection_index == 1;
                    self.did_phase = None;
                    self.advance();
                    return;
                }
                // The webvh-host selection rides on top of the Did
                // step's selection list UI. Route Enter to the
                // sub-flow handler when that phase is active.
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    self.confirm_webvh_host_choice();
                    return;
                }
                let Some(choice) = self.did_choices().get(self.selection_index).copied() else {
                    return;
                };
                self.config.did_method = Some(choice.value);
                // did:webvh and a VTA-managed DID both need the mediator URL
                // for the DID document's service endpoints. Skip the prompt
                // when a VTA sub-flow already captured it — the mediator DID
                // has been minted from that value.
                let url_already_captured =
                    self.vta_session.is_some() && !self.config.public_url.is_empty();
                if (choice.value == DidMethod::Vta && !url_already_captured)
                    || choice.value == DidMethod::Webvh
                {
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.public_url.clone());
                    return;
                }
                self.advance();
            }
            WizardStep::KeyStorage => {
                // FileEncryptChoice is the only phase that uses
                // selection mode (rather than text input) — handle it
                // here so Enter advances the encrypt/no-encrypt pick.
                if self.key_storage_phase == Some(KeyStoragePhase::FileEncryptChoice) {
                    if self.selection_index == 0 {
                        // Yes, encrypt — collect the passphrase.
                        self.enter_key_storage_phase(KeyStoragePhase::FilePassphrase);
                    } else {
                        // No, plaintext — finish the file:// sub-flow. The
                        // operator typed the gate phrase and chose this:
                        // that is the explicit acceptance a recipe records
                        // as `allow_plaintext_file`.
                        self.config.secret_file_encrypted = false;
                        self.config.allow_plaintext_file = true;
                        self.exit_key_storage_subflow();
                        self.advance();
                    }
                    return;
                }
                // Vault auth-method picker (selection mode). Token
                // finishes the sub-flow; Kubernetes / AppRole branch into
                // their own text prompts.
                if self.key_storage_phase == Some(KeyStoragePhase::VaultAuthMethod) {
                    match self.selection_index {
                        0 => {
                            self.config.secret_vault_auth = "token".into();
                            self.exit_key_storage_subflow();
                            self.advance();
                        }
                        1 => {
                            self.config.secret_vault_auth = "kubernetes".into();
                            self.enter_key_storage_phase(KeyStoragePhase::VaultRole);
                        }
                        2 => {
                            self.config.secret_vault_auth = "approle".into();
                            self.enter_key_storage_phase(KeyStoragePhase::VaultApproleMount);
                        }
                        _ => {}
                    }
                    return;
                }
                // Ignore a stray Enter while a text-input sub-phase is
                // active — `confirm_text_input` drives those.
                if self.key_storage_phase.is_some() {
                    return;
                }
                let Some(choice) = KEY_STORAGE_CHOICES.get(self.selection_index) else {
                    return;
                };
                self.config.secret_storage = Some(choice.value);
                // A new pick clears a failed backend check.
                self.backend_check = None;
                // Every backend has settings to confirm: enter its sub-flow.
                self.enter_key_storage_phase(KeyStoragePhase::first_for(choice.value));
            }
            WizardStep::Security => {
                // Four-phase step: SSL → JWT mode → Network mode → CORS
                // policy. Each sub-phase reuses `selection_index` for its
                // own pick; the last one (CorsPolicy) is what finally
                // advances to `Database`.
                if self.security_phase == Some(SecurityPhase::CorsPolicy) {
                    match self.selection_index {
                        0 => {
                            self.config.cors_mode = crate::consts::CORS_MODE_NONE.into();
                            self.security_phase = None;
                            self.advance();
                        }
                        1 => {
                            self.config.cors_mode = crate::consts::CORS_MODE_ANY.into();
                            self.security_phase = None;
                            self.advance();
                        }
                        2 => {
                            // Specific domains: stay in the CorsPolicy
                            // phase but switch to the text-input widget to
                            // collect the allowlist. `confirm_text_input`
                            // validates and advances.
                            self.config.cors_mode = crate::consts::CORS_MODE_LIST.into();
                            self.cors_validation_error = None;
                            self.mode = InputMode::TextInput;
                            self.text_input = Input::new(self.config.cors_domains.clone());
                        }
                        _ => {}
                    }
                    return;
                }
                if self.security_phase == Some(SecurityPhase::NetworkMode) {
                    self.config.network_mode = match self.selection_index {
                        0 => crate::consts::NETWORK_MODE_OPEN.into(),
                        1 => crate::consts::NETWORK_MODE_CLOSED.into(),
                        _ => return,
                    };
                    self.enter_cors_policy_phase();
                    return;
                }
                if self.security_phase == Some(SecurityPhase::JwtMode) {
                    self.config.jwt_mode = match self.selection_index {
                        0 => JWT_MODE_GENERATE.into(),
                        1 => JWT_MODE_PROVIDE.into(),
                        _ => return,
                    };
                    self.enter_network_mode_phase();
                    return;
                }
                let Some(choice) = SSL_CHOICES.get(self.selection_index) else {
                    return;
                };
                self.config.ssl_mode = Some(choice.value);
                // For existing certs, collect file paths first (certificate,
                // then key); the JWT phase runs once both are saved.
                if choice.value == SslMode::Existing {
                    self.ssl_field = Some(SslField::Cert);
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.ssl_cert_path.clone());
                    return;
                }
                self.enter_jwt_mode_phase();
            }
            WizardStep::Database => {
                // ConfirmCreateFjallDir: Yes (0) runs `create_dir_all`
                // and advances; No (1) sends the operator back to the
                // path-input screen so they can retype. A failure
                // running `create_dir_all` surfaces as
                // `database_validation_error` and re-routes back to
                // text input so the operator sees the OS error.
                if self.database_phase == Some(DatabasePhase::ConfirmCreateFjallDir) {
                    match self.selection_index {
                        0 => match std::fs::create_dir_all(&self.config.fjall_data_dir) {
                            Ok(()) => {
                                self.database_phase = None;
                                self.database_validation_error = None;
                                self.advance();
                            }
                            Err(e) => {
                                self.database_phase = None;
                                self.database_validation_error = Some(format!(
                                    "Couldn't create '{}': {e}",
                                    self.config.fjall_data_dir,
                                ));
                                self.mode = InputMode::TextInput;
                                self.text_input = Input::new(self.config.fjall_data_dir.clone());
                            }
                        },
                        1 => {
                            self.database_phase = None;
                            self.mode = InputMode::TextInput;
                            self.text_input = Input::new(self.config.fjall_data_dir.clone());
                        }
                        _ => {}
                    }
                    return;
                }
                // First phase: backend picker. Confirming this branch
                // sets `storage_backend` and transitions to the
                // backend-specific text-input phase. The text-input
                // confirm path then writes either `database_url` (Redis)
                // or `fjall_data_dir` (Fjall).
                self.config.storage_backend = match self.selection_index {
                    0 => crate::consts::STORAGE_BACKEND_REDIS.into(),
                    1 => crate::consts::STORAGE_BACKEND_FJALL.into(),
                    _ => return,
                };
                self.database_phase = None;
                self.mode = InputMode::TextInput;
                self.text_input =
                    if self.config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
                        Input::new(self.config.fjall_data_dir.clone())
                    } else {
                        Input::new(self.config.database_url.clone())
                    };
            }
            WizardStep::Admin => {
                // Options list is [generate, paste, (vta,) skip] with
                // the `vta` entry at index 2 only when
                // `admin_options_include_vta()` agrees. Use that same
                // predicate to map the selection back to the enum so
                // a layout change doesn't need two-place updates.
                let Some(choice) = self.admin_choices().get(self.selection_index).copied() else {
                    return;
                };
                self.config.admin_did_mode = Some(choice.value);
                if choice.value == AdminMode::Paste {
                    // A real prompt for the DID; `confirm_text_input`
                    // validates it and advances.
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.admin_did.clone());
                    return;
                }
                self.advance();
            }
            WizardStep::Output => {
                // Enter on the Output step is a no-op when the text
                // input is active — `confirm_text_input` handles the
                // actual save. Keep the branch exhaustive.
            }
            WizardStep::Summary => {
                if self.mode == InputMode::Confirming {
                    self.write_config = true;
                    self.should_quit = true;
                } else {
                    self.mode = InputMode::Confirming;
                }
            }
        }
    }
}

impl WizardApp {
    /// Handle text input confirmation (Enter in TextInput mode).
    pub fn confirm_text_input(&mut self) {
        if self.backend_check_running() {
            return;
        }
        // A failed confirm below sets a fresh error.
        self.input_error = None;
        if self.in_key_storage_subflow() {
            self.confirm_key_storage_phase();
            return;
        }
        if self.in_vta_subflow() {
            // Errors here mean the ephemeral key generator failed — surface
            // as a transient error on the sub-flow state, not a panic.
            if let Err(e) = self.vta_subflow_confirm_text()
                && let Some(st) = self.vta_connect.as_mut()
            {
                st.last_error = Some(e.to_string());
            }
            return;
        }
        if self.in_sealed_handoff_subflow() && self.sealed_handoff_confirm_text() {
            return;
        }
        match self.current_step {
            WizardStep::Did => {
                // Handle Did sub-phases (VTA webvh host choice) before
                // the "just saved the mediator URL" fall-through below.
                // Only the `EnterCustomUrl` phase is text-input here;
                // `SelectWebvhHost` is Selecting mode and falls through
                // to the default Did branch below.
                if let Some(DidPhase::EnterCustomUrl) = self.did_phase {
                    let v = self.text_input.value().trim().to_string();
                    if !v.is_empty() {
                        self.config.vta_webvh_self_host_url =
                            crate::config_writer::strip_url_path(&v);
                    }
                    self.config.vta_webvh_server_id = None;
                    self.config.vta_webvh_path = None;
                    self.did_phase = None;
                    self.mode = InputMode::Selecting;
                    self.advance();
                    return;
                }

                self.config.public_url = self.text_input.value().to_string();
                // For the VTA-managed path the mediator DID is already
                // rendered by the VTA's template (provision-integration
                // happened in the Vta step), so we skip the webvh-host
                // picker entirely — there's no choice left for the
                // operator to make. did:webvh / import / sealed-handoff
                // fall through to the straight advance below.
                if self.config.did_method == Some(DidMethod::Vta) && self.vta_session.is_some() {
                    self.mode = InputMode::Selecting;
                    self.advance();
                    return;
                }
                // Locally-generated did:webvh: offer the did:web export
                // before advancing. (VTA-managed webvh DIDs are minted in
                // the Vta sub-flow above and never reach this prompt; pass
                // --save-did-web for those.)
                if self.config.did_method == Some(DidMethod::Webvh) {
                    self.enter_identity_form_choice();
                    return;
                }
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Security => {
                // The CORS "Specific domains" allowlist runs as a
                // text-input sub-phase of CorsPolicy. Validate before
                // accepting; a bad entry surfaces inline and keeps the
                // operator on the input screen.
                if self.security_phase == Some(SecurityPhase::CorsPolicy) {
                    let value = self.text_input.value().trim().to_string();
                    match validate_cors_domains(&value) {
                        Ok(normalised) => {
                            self.config.cors_domains = normalised;
                            self.cors_validation_error = None;
                            self.security_phase = None;
                            self.mode = InputMode::Selecting;
                            self.advance();
                        }
                        Err(err) => {
                            self.cors_validation_error = Some(err);
                        }
                    }
                    return;
                }
                // Certificate path, then key path — tracked explicitly, so
                // re-editing a saved certificate path cannot land in the key
                // field. After the key, the JWT-mode selection.
                let value = self.text_input.value().trim().to_string();
                if value.is_empty() {
                    self.input_error = Some("Enter a file path.".into());
                    return;
                }
                self.input_error = None;
                match self.ssl_field {
                    Some(SslField::Key) => {
                        self.config.ssl_key_path = value;
                        self.ssl_field = None;
                        self.mode = InputMode::Selecting;
                        self.enter_jwt_mode_phase();
                    }
                    _ => {
                        self.config.ssl_cert_path = value;
                        self.ssl_field = Some(SslField::Key);
                        self.text_input = Input::new(self.config.ssl_key_path.clone());
                    }
                }
            }
            WizardStep::Database => {
                // Text-input confirm: save the URL or path against the
                // right field based on the backend the operator picked
                // in the prior phase, then advance. For Fjall, if the
                // path doesn't exist yet we route into a Yes/No
                // confirmation phase asking whether to create it now,
                // rather than silently deferring to the mediator's
                // first-run `create_dir_all`. This surfaces filesystem
                // / permission errors at wizard time and gives the
                // operator a chance to back out and retype.
                let value = self.text_input.value().to_string();
                if self.config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
                    let trimmed = value.trim().to_string();
                    if let Err(err) = validate_fjall_data_dir(&trimmed) {
                        self.database_validation_error = Some(err);
                        return;
                    }
                    self.database_validation_error = None;
                    self.config.fjall_data_dir = trimmed.clone();
                    if !std::path::Path::new(&trimmed).exists() {
                        self.database_phase = Some(DatabasePhase::ConfirmCreateFjallDir);
                        self.mode = InputMode::Selecting;
                        // Default Yes — pressing Enter accepts the
                        // create-directory prompt without re-navigating.
                        self.selection_index = 0;
                        return;
                    }
                } else {
                    self.config.database_url = value;
                }
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Admin => {
                let value = self.text_input.value().trim().to_string();
                if !crate::recipe::looks_like_did(&value) {
                    self.input_error = Some(format!(
                        "'{value}' is not a DID — expected did:<method>:<id>, e.g. \
                         did:key:z6Mk…"
                    ));
                    return;
                }
                self.input_error = None;
                self.config.admin_did = value;
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Output => {
                let value = self.text_input.value().trim().to_string();
                if !value.is_empty() {
                    self.config.config_path = value;
                }
                self.mode = InputMode::Selecting;
                self.advance();
            }
            _ => {
                self.mode = InputMode::Selecting;
                self.advance();
            }
        }
    }

    /// Apply sensible defaults based on deployment type selection.
    pub(super) fn apply_deployment_defaults(&mut self) {
        let Some(deployment) = self.config.deployment_type else {
            return;
        };
        self.config.use_vta = true;
        self.config.vta_mode = Some(VtaMode::Online);
        self.config.didcomm_enabled = true;
        self.config.tsp_enabled = true;
        self.config.did_method = Some(DidMethod::Vta);
        // The unified secret backend is independent of VTA mode —
        // pick a sensible default per platform; the operator
        // refines it on the KeyStorage step.
        self.config.secret_storage = Some(SecretScheme::Keyring);
        self.config.ssl_mode = Some(SslMode::None);
        self.config.database_url = DEFAULT_REDIS_URL.into();
        self.config.admin_did_mode = Some(AdminMode::Generate);
        // A production deployment starts from the template's
        // restrictive posture (explicit ACL grants); local stays open.
        self.config.network_mode = default_network_mode_for(Some(deployment)).into();
    }

    /// Apply or clear VTA-dependent defaults when toggling VTA integration.
    ///
    /// `secret_storage` is deliberately *not* overridden here — the operator
    /// configures it in the earlier `KeyStorage` step and the VTA step
    /// should respect that choice. The Did + Admin defaults still shift
    /// because those steps come after Vta.
    pub(super) fn apply_vta_defaults(&mut self) {
        if self.config.use_vta {
            // Intent decides whether the VTA supplies the mediator
            // DID too, or only the admin credential.
            match self.vta_intent_choice {
                Some(VtaIntent::FullSetup) | None => {
                    // FullSetup deliberately mints a fresh admin DID
                    // as part of `provision_integration`'s admin-DID
                    // rollover — that DID is the intended mediator
                    // admin handoff, so `AdminMode::Vta` is the correct
                    // default.
                    //
                    // `None` shouldn't happen while `use_vta` is
                    // `true` under the two-question picker, but
                    // fall through to the legacy "VTA supplies
                    // everything" defaults for safety.
                    self.config.did_method = Some(DidMethod::Vta);
                    self.config.admin_did_mode = Some(AdminMode::Vta);
                }
                Some(VtaIntent::OfflineExport) => {
                    // OfflineExport mints an admin credential as a
                    // side effect of `vta contexts reprovision` (for
                    // the mediator to authenticate back to the VTA),
                    // NOT as an intentional mediator-admin-API
                    // handoff. Reusing that same DID for both the
                    // mediator→VTA trust boundary and the
                    // clients→mediator-admin trust boundary
                    // overloads one key across two scopes.
                    //
                    // Default the mediator's admin-API identity to
                    // `AdminMode::Generate` (fresh did:key) so the two
                    // roles stay separate by default. Operator can
                    // still override at the Admin step if their
                    // deployment warrants reusing the VTA credential.
                    self.config.did_method = Some(DidMethod::Vta);
                    self.config.admin_did_mode = Some(AdminMode::Generate);
                }
                Some(VtaIntent::AdminOnly) => {
                    // Mediator's integration DID is chosen locally
                    // in the Did step; the VTA only supplies an
                    // admin credential. Drop any stale DidMethod::Vta
                    // carry-over from an earlier FullSetup attempt
                    // so the Did step surfaces the real picker.
                    //
                    // AdminOnly keeps `AdminMode::Vta` because that IS
                    // the point of the intent — the VTA is explicitly
                    // asked to supply the mediator's admin identity.
                    if self.config.did_method == Some(DidMethod::Vta) {
                        self.config.did_method = Some(DidMethod::Peer);
                    }
                    self.config.admin_did_mode = Some(AdminMode::Vta);
                }
            }
        } else {
            if self.config.did_method == Some(DidMethod::Vta) {
                self.config.did_method = Some(DidMethod::Peer);
            }
            if self.config.admin_did_mode == Some(AdminMode::Vta) {
                self.config.admin_did_mode = Some(AdminMode::Generate);
            }
            self.config.vta_mode = None;
        }
    }
}
