//! The Key Storage step's per-backend sub-phases.

use tui_input::Input;

use super::{FILE_GATE_PHRASE, InputMode, KeyStoragePhase, WizardApp, WizardStep};

impl WizardApp {
    /// Enter a specific KeyStorage config sub-phase with the input
    /// pre-filled from the field's current value.
    pub(super) fn enter_key_storage_phase(&mut self, phase: KeyStoragePhase) {
        let value = match phase {
            // FileGate / FilePassphrase / FileEncryptChoice all start
            // with an empty input — the operator must type the
            // dev-only acknowledgement / passphrase from scratch every
            // time, and the encrypt-choice screen uses a selection
            // list rather than text input.
            KeyStoragePhase::FileGate => String::new(),
            KeyStoragePhase::FilePassphrase => String::new(),
            KeyStoragePhase::FilePassphraseConfirm => String::new(),
            KeyStoragePhase::FilePath => self.config.secret_file_path.clone(),
            KeyStoragePhase::KeyringService => self.config.secret_keyring_service.clone(),
            KeyStoragePhase::AwsRegion => self.config.secret_aws_region.clone(),
            KeyStoragePhase::AwsNamespace => self.config.secret_aws_namespace.clone(),
            KeyStoragePhase::GcpProject => self.config.secret_gcp_project.clone(),
            KeyStoragePhase::GcpNamespace => self.config.secret_gcp_namespace.clone(),
            KeyStoragePhase::AzureVault => self.config.secret_azure_vault.clone(),
            KeyStoragePhase::VaultEndpoint => self.config.secret_vault_endpoint.clone(),
            KeyStoragePhase::VaultMount => self.config.secret_vault_mount.clone(),
            KeyStoragePhase::VaultRole => self.config.secret_vault_role.clone(),
            KeyStoragePhase::VaultK8sMount => self.config.secret_vault_k8s_mount.clone(),
            KeyStoragePhase::VaultApproleMount => self.config.secret_vault_approle_mount.clone(),
            KeyStoragePhase::VaultNamespace => self.config.secret_vault_namespace.clone(),
            KeyStoragePhase::K8sNamespace => self.config.secret_k8s_namespace.clone(),
            KeyStoragePhase::K8sSecretName => self.config.secret_k8s_secret_name.clone(),
            // Encrypt choice doesn't take text input — render uses
            // selection mode. Short-circuit before touching the input
            // widget so we don't flip mode unexpectedly.
            KeyStoragePhase::FileEncryptChoice => {
                self.key_storage_phase = Some(phase);
                self.mode = InputMode::Selecting;
                self.selection_index = if self.config.secret_file_encrypted {
                    0
                } else {
                    1
                };
                return;
            }
            // Vault auth-method picker is also selection-mode. Preselect
            // the current method so re-entry doesn't reset the choice.
            KeyStoragePhase::VaultAuthMethod => {
                self.key_storage_phase = Some(phase);
                self.mode = InputMode::Selecting;
                self.selection_index = match self.config.secret_vault_auth.as_str() {
                    "kubernetes" => 1,
                    "approle" => 2,
                    _ => 0,
                };
                return;
            }
        };
        self.key_storage_phase = Some(phase);
        self.text_input = Input::new(value);
        self.mode = InputMode::TextInput;
    }

    /// Confirm the current KeyStorage text-input phase: save the value,
    /// transition to the next phase for this backend, or advance out of
    /// the step if we're on the last field.
    pub(super) fn confirm_key_storage_phase(&mut self) {
        let Some(phase) = self.key_storage_phase else {
            return;
        };
        let value = self.text_input.value().trim().to_string();
        match phase {
            KeyStoragePhase::FileGate => {
                // Case-insensitive match on the literal phrase. Anything
                // else aborts the file:// selection: clear the choice,
                // exit the sub-flow back to the scheme list so the
                // operator can pick a real backend.
                if value.eq_ignore_ascii_case(FILE_GATE_PHRASE) {
                    self.input_error = None;
                    self.enter_key_storage_phase(KeyStoragePhase::FilePath);
                } else {
                    self.config.secret_storage = None;
                    self.exit_key_storage_subflow();
                    self.input_error = Some(format!(
                        "file:// not selected: the confirmation must be \"{FILE_GATE_PHRASE}\"."
                    ));
                }
            }
            KeyStoragePhase::FilePath => {
                if !value.is_empty() {
                    self.config.secret_file_path = value;
                }
                // After the file path lands the encrypt/no-encrypt
                // question. file:// is dev-only; we want the operator
                // to make the security trade-off explicitly rather
                // than silently shipping plaintext.
                self.enter_key_storage_phase(KeyStoragePhase::FileEncryptChoice);
            }
            KeyStoragePhase::FileEncryptChoice => {
                // Driven via select_current; the text-input branch
                // shouldn't be reached. If it is (stray Enter while
                // mode briefly mismatched), treat as no-op.
            }
            KeyStoragePhase::FilePassphrase => {
                if value.is_empty() {
                    // Reject empty — Argon2id with an empty passphrase
                    // is trivially brute-forceable.
                    self.input_error = Some("The passphrase cannot be empty.".into());
                    return;
                }
                // Stash the first entry and ask the operator to retype
                // it on the confirm screen. The actual env-var export
                // (and step advance) happens after the confirm matches —
                // catching typos here is the whole point of having a
                // confirm step at all.
                self.pending_passphrase = Some(zeroize::Zeroizing::new(value));
                // Don't carry a stale "passphrases didn't match" error
                // forward into the confirm screen.
                self.passphrase_validation_error = None;
                self.enter_key_storage_phase(KeyStoragePhase::FilePassphraseConfirm);
            }
            KeyStoragePhase::FilePassphraseConfirm => {
                if value.is_empty() {
                    // Same reasoning as the first prompt — empty input
                    // shouldn't silently match an empty pending entry
                    // (the FilePassphrase arm rejects empties).
                    self.input_error = Some("Type the passphrase again to confirm it.".into());
                    return;
                }
                let matched = self
                    .pending_passphrase
                    .as_ref()
                    .map(|p| p.as_str() == value.as_str())
                    .unwrap_or(false);
                if !matched {
                    // Drop the stash so a future attempt starts clean —
                    // can't leak the first entry into the next try if
                    // the operator backs out and re-enters.
                    self.pending_passphrase = None;
                    self.passphrase_validation_error =
                        Some("Passphrases didn't match — please type the same value twice.".into());
                    self.enter_key_storage_phase(KeyStoragePhase::FilePassphrase);
                    return;
                }
                // Export to the env var the encrypted backend reads.
                // The wizard process is short-lived; the env var dies
                // with it. Operators who want persistence beyond the
                // wizard run set the var themselves before starting
                // the mediator.
                //
                // SAFETY: `set_var` is unsafe because another thread may
                // read the environment at the same time. This runs on the
                // wizard's UI thread in response to a keypress; the reader is
                // the encrypted file backend, which this thread opens later.
                // The residual risk is a library reading some other variable
                // on a worker thread at this instant, accepted for a
                // short-lived interactive tool (the operator is typing).
                #[allow(unsafe_code)]
                unsafe {
                    std::env::set_var(affinidi_messaging_mediator_common::PASSPHRASE_ENV, &value);
                }
                self.pending_passphrase = None;
                self.passphrase_validation_error = None;
                self.config.secret_file_encrypted = true;
                self.config.allow_plaintext_file = false;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::KeyringService => {
                if !value.is_empty() {
                    self.config.secret_keyring_service = value;
                }
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::AwsRegion => {
                if !value.is_empty() {
                    self.config.secret_aws_region = value;
                }
                self.enter_key_storage_phase(KeyStoragePhase::AwsNamespace);
            }
            KeyStoragePhase::AwsNamespace => {
                if !value.is_empty() {
                    self.config.secret_aws_namespace = value;
                }
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::GcpProject => {
                if value.is_empty() {
                    // GCP project IDs aren't optional — there's no
                    // sensible default. Reject and keep the operator on
                    // the prompt rather than write `gcp_secrets:///…`
                    // and explode at backend-open time.
                    self.input_error = Some("A GCP project ID is required.".into());
                    return;
                }
                self.config.secret_gcp_project = value;
                self.enter_key_storage_phase(KeyStoragePhase::GcpNamespace);
            }
            KeyStoragePhase::GcpNamespace => {
                // Empty namespace is allowed — GCP secret names accept
                // the bare well-known keys verbatim.
                self.config.secret_gcp_namespace = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::AzureVault => {
                if value.is_empty() {
                    // No default — sovereign-cloud + commercial-cloud
                    // share no host pattern. Force a typed answer
                    // rather than silently writing `azure_keyvault://`.
                    self.input_error = Some("A vault name or URL is required.".into());
                    return;
                }
                self.config.secret_azure_vault = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::VaultEndpoint => {
                if value.is_empty() {
                    // Vault endpoints are deployment-specific (the
                    // `vault server` listen address is environment-
                    // dependent). No sensible default — force a typed
                    // answer.
                    self.input_error = Some("A Vault endpoint (host[:port]) is required.".into());
                    return;
                }
                self.config.secret_vault_endpoint = value;
                self.enter_key_storage_phase(KeyStoragePhase::VaultMount);
            }
            KeyStoragePhase::VaultMount => {
                if !value.is_empty() {
                    self.config.secret_vault_mount = value;
                }
                // Mount collected — pick the auth method next.
                self.enter_key_storage_phase(KeyStoragePhase::VaultAuthMethod);
            }
            KeyStoragePhase::VaultAuthMethod => {
                // Driven via select_current (selection mode); the
                // text-input branch is unreachable. No-op if hit.
            }
            KeyStoragePhase::VaultRole => {
                if value.is_empty() {
                    // Kubernetes auth needs a role — no sensible default.
                    self.input_error = Some("A Vault role is required for Kubernetes auth.".into());
                    return;
                }
                self.config.secret_vault_role = value;
                self.enter_key_storage_phase(KeyStoragePhase::VaultK8sMount);
            }
            KeyStoragePhase::VaultK8sMount => {
                // Empty keeps the backend default (`kubernetes`); the
                // URL builder omits the param in that case.
                self.config.secret_vault_k8s_mount = value;
                self.enter_key_storage_phase(KeyStoragePhase::VaultNamespace);
            }
            KeyStoragePhase::VaultApproleMount => {
                // Empty keeps the backend default (`approle`).
                self.config.secret_vault_approle_mount = value;
                self.enter_key_storage_phase(KeyStoragePhase::VaultNamespace);
            }
            KeyStoragePhase::VaultNamespace => {
                // Vault Enterprise namespace — optional; empty = none.
                self.config.secret_vault_namespace = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::K8sNamespace => {
                // Empty is allowed — the backend resolves the namespace
                // from the ServiceAccount / kubeconfig at connect time.
                self.config.secret_k8s_namespace = value;
                self.enter_key_storage_phase(KeyStoragePhase::K8sSecretName);
            }
            KeyStoragePhase::K8sSecretName => {
                if value.is_empty() {
                    // The Secret name is required — no default that would
                    // be safe to guess across clusters.
                    self.input_error = Some("A Secret name is required.".into());
                    return;
                }
                self.config.secret_k8s_secret_name = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
        }
    }

    /// Back-nav within the KeyStorage sub-flow. AWS / GCP / Vault each
    /// chain two phases; back from the second returns to the first.
    /// Single-phase backends (keyring, file gate, Azure vault) drop
    /// straight back to the scheme selection list.
    pub(super) fn key_storage_back(&mut self) {
        let Some(phase) = self.key_storage_phase else {
            return;
        };
        match phase {
            KeyStoragePhase::AwsNamespace => {
                self.enter_key_storage_phase(KeyStoragePhase::AwsRegion);
            }
            KeyStoragePhase::GcpNamespace => {
                self.enter_key_storage_phase(KeyStoragePhase::GcpProject);
            }
            KeyStoragePhase::VaultMount => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultEndpoint);
            }
            KeyStoragePhase::VaultAuthMethod => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultMount);
            }
            KeyStoragePhase::VaultRole => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultAuthMethod);
            }
            KeyStoragePhase::VaultK8sMount => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultRole);
            }
            KeyStoragePhase::VaultApproleMount => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultAuthMethod);
            }
            KeyStoragePhase::VaultNamespace => {
                // Return to whichever auth sub-flow led here.
                if self.config.secret_vault_auth == "approle" {
                    self.enter_key_storage_phase(KeyStoragePhase::VaultApproleMount);
                } else {
                    self.enter_key_storage_phase(KeyStoragePhase::VaultK8sMount);
                }
            }
            KeyStoragePhase::K8sSecretName => {
                self.enter_key_storage_phase(KeyStoragePhase::K8sNamespace);
            }
            _ => {
                self.exit_key_storage_subflow();
            }
        }
    }

    pub(super) fn exit_key_storage_subflow(&mut self) {
        self.key_storage_phase = None;
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
        // Drop any partially-collected passphrase + clear stale errors
        // so the operator's next entry into the sub-flow starts clean.
        // `Zeroizing` zeroes the heap allocation when dropped.
        self.pending_passphrase = None;
        self.passphrase_validation_error = None;
    }
}

impl WizardApp {
    pub fn in_key_storage_subflow(&self) -> bool {
        self.current_step == WizardStep::KeyStorage && self.key_storage_phase.is_some()
    }
}
