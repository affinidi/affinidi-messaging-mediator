//! Screens and copy: the title, options and info text for the step and
//! sub-phase on screen.

use crate::app::{Deployment, SecretScheme};
use crate::ui::selection::SelectionOption;
use crate::vta::{ConnectPhase, VtaIntent};

use super::{
    BackendCheck, Choice, DEPLOYMENT_CHOICES, DatabasePhase, DidPhase, KEY_STORAGE_CHOICES,
    KeyStoragePhase, SSL_CHOICES, SecurityPhase, StepData, VTA_INTENT_CHOICES, VtaStepPhase,
    WizardApp, WizardStep,
};

impl WizardApp {
    /// Step title/description to display in the right-panel header.
    /// Overrides the static `WizardStep::step_data` when the wizard is inside
    /// a sub-flow that has its own narrative (e.g. online-VTA).
    pub fn current_step_data(&self) -> StepData {
        let default = self.current_step.step_data();
        if let Some(phase) = self.vta_phase() {
            let num = self.current_step.step_number();
            let total = WizardStep::total();
            let (suffix, desc): (&str, &str) = match phase {
                ConnectPhase::EnterDid => (
                    "Enter VTA DID",
                    "Type the VTA's DID; the wizard resolves its endpoints.",
                ),
                ConnectPhase::EnterContext => (
                    "Enter context id",
                    "VTA context name the mediator will live in (default: mediator).",
                ),
                ConnectPhase::EnterMediatorUrl => (
                    "Enter mediator URL",
                    "Public URL this mediator will serve at — passed to the VTA's DID template.",
                ),
                ConnectPhase::AwaitingAcl => (
                    "Register ACL",
                    "Run the displayed command on the VTA host, then press Enter to provision.",
                ),
                ConnectPhase::Testing => (
                    "Provisioning",
                    "Authenticating over DIDComm and requesting a VTA-minted mediator DID…",
                ),
                ConnectPhase::PickWebvhServer => (
                    "Pick webvh server",
                    "The VTA has more than one registered webvh hosting server — pick one \
                     to host the minted DID's did.jsonl log, or self-host at the URL above.",
                ),
                ConnectPhase::EnterWebvhPath => (
                    "Enter webvh path",
                    "Optional path/mnemonic for the minted DID on the chosen webvh server. \
                     Press Enter with the field blank to let the server auto-assign.",
                ),
                ConnectPhase::Connected => (
                    "Connected",
                    "Mediator DID minted by the VTA — advancing to the next step.",
                ),
                ConnectPhase::RecoveryPrompt => (
                    "Recover",
                    "Online attempts exhausted — retry a transport or switch to offline sealed-handoff.",
                ),
                ConnectPhase::TransportFallbackPrompt => (
                    "Transport fallback",
                    "DIDComm pre-auth failed — fall back to REST, retry DIDComm, or switch to offline.",
                ),
            };
            return StepData {
                title: format!("Step {num}/{total}: VTA Integration — {suffix}"),
                description: desc.into(),
            };
        }
        // Top-level Vta picker — reflect which of the two questions the
        // operator is currently answering so the header stays useful
        // alongside the option list.
        if self.current_step == WizardStep::Vta
            && self.vta_connect.is_none()
            && self.sealed_handoff.is_none()
        {
            let num = self.current_step.step_number();
            let total = WizardStep::total();
            let (suffix, desc): (&str, &str) = match self.vta_step_phase {
                VtaStepPhase::SelectIntent => (
                    "What from VTA?",
                    "Decide whether the VTA should mint your mediator's DID (Full setup), \
                     only provide an admin credential, or stay out of the wizard entirely.",
                ),
                VtaStepPhase::SelectTransport => (
                    "How is the request delivered?",
                    "Pick online for a direct network call or sealed handoff for an \
                     air-gapped armored-bundle exchange.",
                ),
            };
            return StepData {
                title: format!("Step {num}/{total}: VTA Integration — {suffix}"),
                description: desc.into(),
            };
        }
        // Database step: override the generic backend-picker title
        // when the wizard is in the create-directory confirmation
        // sub-phase, so the operator doesn't see "Choose between
        // Redis and Fjall" while the screen is asking a different
        // question entirely. Leading `\u{26A0}` (⚠) signals the
        // warning posture without restyling the whole renderer.
        if self.current_step == WizardStep::Database
            && self.database_phase == Some(DatabasePhase::ConfirmCreateFjallDir)
        {
            let num = self.current_step.step_number();
            let total = WizardStep::total();
            return StepData {
                title: format!(
                    "Step {num}/{total}: Storage Backend — \u{26A0} Fjall directory missing"
                ),
                description: format!(
                    "\u{26A0} The Fjall data directory '{}' does not exist yet. \
                     Create it now or go back and edit the path.",
                    self.config.fjall_data_dir,
                ),
            };
        }
        default
    }

    /// Get the options for the current step.
    pub fn current_options(&self) -> Vec<SelectionOption> {
        match self.current_step {
            WizardStep::Deployment => DEPLOYMENT_CHOICES.iter().map(Choice::option).collect(),
            WizardStep::Vta => {
                if let Some(phase) = self.vta_phase() {
                    let Some(st) = self.vta_connect.as_ref() else {
                        return vec![];
                    };
                    return match phase {
                        ConnectPhase::AwaitingAcl => vec![SelectionOption::new(
                            "Test VTA connection",
                            "Run the `pnm acl create` command below, then press Enter to verify",
                        )],
                        ConnectPhase::Testing => {
                            if st.event_rx.is_some() {
                                // Runner still in flight — no actionable
                                // option yet; the UI renders a spinner.
                                vec![]
                            } else if st.last_error.is_some() {
                                vec![SelectionOption::new(
                                    "Retry",
                                    "Re-run the diagnostic + auth sequence",
                                )]
                            } else {
                                vec![]
                            }
                        }
                        ConnectPhase::Connected => vec![SelectionOption::new(
                            "Continue",
                            "Advance to the next wizard step",
                        )],
                        ConnectPhase::PickWebvhServer => {
                            // First option is always "serverless" (self-host at URL); the
                            // remaining entries mirror `st.webvh_servers` so the
                            // selection index maps to `idx - 1`.
                            let mut opts = Vec::with_capacity(st.webvh_servers.len() + 1);
                            opts.push(SelectionOption::new(
                                "Serverless — self-host at mediator URL",
                                "Don't pin a webvh hosting server; the minted DID resolves \
                                 directly at the mediator's public URL.",
                            ));
                            for srv in &st.webvh_servers {
                                let label = srv.label.as_deref().unwrap_or("(no label)");
                                opts.push(SelectionOption::new(
                                    format!("{} — {}", srv.id, label),
                                    srv.did.clone(),
                                ));
                            }
                            opts
                        }
                        ConnectPhase::TransportFallbackPrompt => {
                            // Slice 3 routes pre-auth failures here
                            // when the alternate transport is
                            // advertised + unattempted.
                            let opts = match st.resolved.as_ref() {
                                Some(resolved) => st.fallback_options(resolved),
                                None => crate::vta::FallbackOptions {
                                    fall_back_to_rest: false,
                                    retry_didcomm: false,
                                    offline_available: true,
                                },
                            };
                            let fall_back = SelectionOption::new(
                                "[F] Fall back to REST",
                                "Re-run the attempt over the REST endpoint the VTA advertises.",
                            );
                            let retry = SelectionOption::new(
                                "[R] Retry DIDComm",
                                "Re-run the DIDComm attempt — useful if the operator just fixed the underlying issue (ACL row, network).",
                            );
                            return vec![
                                if opts.fall_back_to_rest {
                                    fall_back
                                } else {
                                    fall_back.disabled()
                                },
                                if opts.retry_didcomm {
                                    retry
                                } else {
                                    retry.disabled()
                                },
                                SelectionOption::new(
                                    "[O] Offline sealed-handoff",
                                    "Switch to the offline flow: bundle a request file for the VTA admin, decode their reply locally.",
                                ),
                                SelectionOption::new(
                                    "[B] Back",
                                    "Return to the previous step in the wizard.",
                                ),
                            ];
                        }
                        ConnectPhase::RecoveryPrompt => {
                            // Option order is fixed so the keyboard
                            // shortcuts ([R] / [E] / [O] / [B]) and
                            // selection-index handling stay stable
                            // across renders. Disabled options stay
                            // present but render dimmed; Slice 2.3
                            // wires the selection logic to skip
                            // them.
                            let recovery_opts = match st.resolved.as_ref() {
                                Some(resolved) => st.recovery_options(resolved),
                                None => crate::vta::RecoveryOptions {
                                    retry_didcomm: false,
                                    retry_rest: false,
                                    offline_available: true,
                                },
                            };
                            let retry_didcomm = SelectionOption::new(
                                "[R] Retry DIDComm",
                                "Re-run the DIDComm attempt from scratch.",
                            );
                            let retry_rest = SelectionOption::new(
                                "[E] Retry REST",
                                "Re-run the REST attempt from scratch.",
                            );
                            vec![
                                if recovery_opts.retry_didcomm {
                                    retry_didcomm
                                } else {
                                    retry_didcomm.disabled()
                                },
                                if recovery_opts.retry_rest {
                                    retry_rest
                                } else {
                                    retry_rest.disabled()
                                },
                                SelectionOption::new(
                                    "[O] Offline sealed-handoff",
                                    "Switch to the offline flow: bundle a request file for the VTA admin, decode their reply locally.",
                                ),
                                SelectionOption::new(
                                    "[B] Back",
                                    "Return to the previous step in the wizard.",
                                ),
                            ]
                        }
                        _ => vec![],
                    };
                }
                match self.vta_step_phase {
                    VtaStepPhase::SelectIntent => {
                        VTA_INTENT_CHOICES.iter().map(Choice::option).collect()
                    }
                    VtaStepPhase::SelectTransport => {
                        let Some(intent) = self.vta_intent_choice else {
                            return vec![];
                        };
                        let (online_sub, offline_sub) = match intent {
                            VtaIntent::FullSetup => (
                                "Direct DIDComm session to a running VTA. Requires: `pnm acl create` run out-of-band first to enrol the wizard's ephemeral setup DID in the target context.",
                                "No live network from this host. Wizard writes a VP-framed request; VTA admin runs `vta bootstrap provision-integration` on the VTA host and returns an armored bundle.",
                            ),
                            VtaIntent::AdminOnly => (
                                "Direct REST/DIDComm check against the VTA. Requires: `pnm acl create` run out-of-band first to enrol the mediator's own DID as admin of the target context.",
                                "No live network from this host. Wizard writes a request; VTA admin runs `pnm contexts bootstrap --recipient <file>` on their CLI and returns an armored bundle carrying the admin credential.",
                            ),
                            VtaIntent::OfflineExport => {
                                // Defensive: SelectIntent routes
                                // OfflineExport directly to sealed
                                // handoff without ever entering this
                                // phase. If it somehow lands here we
                                // render a single-row stub explaining
                                // the situation rather than panicking
                                // in the renderer (which would tear
                                // the TUI down mid-frame).
                                return vec![SelectionOption::new(
                                    "(no transport choice for OfflineExport)",
                                    "OfflineExport is always offline — sealed handoff via `vta contexts reprovision` is the only producer.",
                                )];
                            }
                        };
                        vec![
                            SelectionOption::new("Online", online_sub),
                            SelectionOption::new("Sealed handoff (air-gapped)", offline_sub),
                        ]
                    }
                }
            }
            WizardStep::Protocol => {
                let didcomm_check = if self.config.didcomm_enabled {
                    "[x]"
                } else {
                    "[ ]"
                };
                let tsp_check = if self.config.tsp_enabled {
                    "[x]"
                } else {
                    "[ ]"
                };
                vec![
                    SelectionOption::new(
                        format!("{didcomm_check} DIDComm v2 (recommended)"),
                        "Industry-standard DID-based messaging",
                    ),
                    SelectionOption::new(
                        format!("{tsp_check} TSP (Trust Spanning Protocol) (recommended)"),
                        "Preferred transport — metadata-private routing",
                    ),
                ]
            }
            WizardStep::Did => {
                if self.did_phase == Some(DidPhase::IdentityFormChoice) {
                    return vec![
                        SelectionOption::new(
                            "did:webvh (recommended)",
                            "The mediator's DID names its host. What every peer expects today.",
                        ),
                        SelectionOption::new(
                            "did:scid",
                            "The same log, presented as a did:scid:vh:1 DID: the identity keeps its name if the log moves to another host. Peers need did:scid support.",
                        ),
                    ];
                }
                // After a local did:webvh URL is captured, offer the
                // did:web export as a Yes/No pick (index 0 = Yes).
                if self.did_phase == Some(DidPhase::SaveDidWebChoice) {
                    return vec![
                        SelectionOption::new(
                            "No (recommended)",
                            "Generate the did:webvh log only. This is all most deployments need.",
                        ),
                        SelectionOption::new(
                            "Yes — also export a did:web copy",
                            "Advanced: only if you specifically need a did:web identifier. Writes did-web.json (id rewritten to did:web:<domain>) for you to host at a web server's /.well-known/did.json.",
                        ),
                    ];
                }
                // When the webvh-host sub-flow is active, render its
                // options (self-host / each server / self-host
                // elsewhere) instead of the DID-method picker.
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    let mut opts = Vec::new();
                    let stripped = if self.config.vta_webvh_self_host_url.is_empty() {
                        crate::config_writer::strip_url_path(&self.config.public_url)
                    } else {
                        self.config.vta_webvh_self_host_url.clone()
                    };
                    opts.push(SelectionOption::new(
                        format!("Self-host at {stripped}"),
                        "Derived from the mediator URL (path stripped — webvh publishes at /.well-known/did.jsonl).",
                    ));
                    // Note: VTA-hosted webvh servers used to appear here
                    // as individual picks, populated from the VTA's
                    // `list_webvh_servers` RPC. With provision-integration
                    // the mediator DID is rendered by a VTA-side template
                    // that decides publishing itself — so the operator
                    // chooses templates (via context overrides on the
                    // VTA), not servers here. Legacy self-host options
                    // remain for non-VTA flows.
                    let _ = self.vta_session.as_ref();
                    opts.push(SelectionOption::new(
                        "Self-host elsewhere",
                        "Type a different base URL (e.g. a webvh server you operate separately).",
                    ));
                    return opts;
                }
                self.did_choices().iter().map(Choice::option).collect()
            }
            WizardStep::KeyStorage => {
                // The file:// encrypt/no-encrypt choice rides on top
                // of the same selection-list UI as the scheme picker.
                // Branch *before* we render the scheme list so the
                // operator sees the right question.
                if self.key_storage_phase == Some(KeyStoragePhase::FileEncryptChoice) {
                    return vec![
                        SelectionOption::new(
                            "Encrypt with a passphrase (recommended)",
                            "Argon2id-derived AES-256-GCM. The wizard prompts for a passphrase you must also provide to the mediator at boot.",
                        ),
                        SelectionOption::new(
                            "No encryption (plaintext on disk)",
                            "Same secrets.json shape as before. Anyone with read access to the file gets the keys.",
                        ),
                    ];
                }
                // The Vault auth-method picker also rides the selection
                // list (like the file encrypt choice above).
                if self.key_storage_phase == Some(KeyStoragePhase::VaultAuthMethod) {
                    return vec![
                        SelectionOption::new(
                            "Token (VAULT_TOKEN env) [default]",
                            "Reads the token from the VAULT_TOKEN environment variable at boot.",
                        ),
                        SelectionOption::new(
                            "Kubernetes (pod ServiceAccount)",
                            "Exchanges the pod's ServiceAccount JWT for a Vault token. Needs a Vault role.",
                        ),
                        SelectionOption::new(
                            "AppRole (VAULT_ROLE_ID / VAULT_SECRET_ID)",
                            "Logs in with an AppRole; role_id/secret_id come from env vars at boot.",
                        ),
                    ];
                }
                // Unified secret-storage backends. `vta://` is not a backend
                // (the VTA is a *source* of keys) and `string://` was removed.
                KEY_STORAGE_CHOICES
                    .iter()
                    .map(|c| {
                        if c.value == SecretScheme::Keyring
                            && self.config.deployment_type == Some(Deployment::Container)
                        {
                            SelectionOption::new(
                                "OS Keyring (keyring://) — not available inside a container",
                                "The container has no OS keyring; the mediator would not find its keys",
                            )
                        } else {
                            c.option()
                        }
                    })
                    .collect()
            }
            WizardStep::Security => {
                if self.security_phase == Some(SecurityPhase::CorsPolicy) {
                    // Order: index 0 = None (the mediator's default-closed
                    // posture), so the first Enter keeps cross-origin
                    // access off unless the operator opts in.
                    vec![
                        SelectionOption::new(
                            "Deny all cross-origin (default)",
                            "No browser may call the REST/WebSocket API cross-origin. Pick this for mediators with no browser-based clients.",
                        ),
                        SelectionOption::new(
                            "Allow any origin (*)",
                            "Any website may call the API. Suggested for public mediators — endpoints gate on a bearer token, not a cookie, so a wildcard is not a CSRF risk.",
                        ),
                        SelectionOption::new(
                            "Specific domains",
                            "Only listed origins are allowed. Next screen collects the allowlist (exact origins and/or *.subdomain wildcards).",
                        ),
                    ]
                } else if self.security_phase == Some(SecurityPhase::NetworkMode) {
                    // Order matches the wizard default — Open is index 0
                    // so the operator's first Enter confirms the recommended
                    // posture without re-selecting.
                    vec![
                        SelectionOption::new(
                            "Open network (default)",
                            "Any DID can message any other DID by default. Override on a per-DID basis via the ACL.",
                        ),
                        SelectionOption::new(
                            "Closed network",
                            "Restricted: explicit ACL grant required before two DIDs can exchange messages.",
                        ),
                    ]
                } else if self.security_phase == Some(SecurityPhase::JwtMode) {
                    vec![
                        SelectionOption::new(
                            "Generate a fresh JWT signing key (recommended)",
                            "Wizard creates an Ed25519 PKCS8 key and stores it under the well-known secret name.",
                        ),
                        SelectionOption::new(
                            "Provide my own JWT secret",
                            "Mediator reads MEDIATOR_JWT_SECRET / --jwt-secret-file at boot. Wizard does not prompt for the key.",
                        ),
                    ]
                } else {
                    SSL_CHOICES.iter().map(Choice::option).collect()
                }
            }
            WizardStep::Database => {
                // The backend-picker phase shows two options; once
                // the operator confirms, the step transitions to a
                // text-input phase (URL or path) and `selection_options`
                // is no longer consulted. ConfirmCreateFjallDir runs
                // a Yes/No selection list when the operator confirmed
                // a Fjall path that doesn't exist on disk yet.
                if self.database_phase == Some(DatabasePhase::SelectBackend) {
                    vec![
                        SelectionOption::new(
                            "Redis",
                            "External Redis instance — required for multi-mediator clusters",
                        ),
                        SelectionOption::new(
                            "Fjall",
                            "Embedded LSM store — single-node, no Redis sidecar",
                        ),
                    ]
                } else if self.database_phase == Some(DatabasePhase::ConfirmCreateFjallDir) {
                    vec![
                        SelectionOption::new(
                            "Yes — create the directory now",
                            "Wizard runs `fs::create_dir_all` so any permission / \
                             filesystem errors surface here, not on first mediator boot.",
                        ),
                        SelectionOption::new(
                            "No — go back and edit the path",
                            "Returns to the path-input screen so you can retype.",
                        ),
                    ]
                } else {
                    vec![]
                }
            }
            WizardStep::Admin => self.admin_choices().iter().map(Choice::option).collect(),
            // Output step is text-input (the renderer branches on
            // `current_step == Output` and draws a compact prompt),
            // so no selection list is needed here.
            WizardStep::Output => vec![],
            WizardStep::Summary => vec![],
        }
    }

    /// Get the info text for the currently highlighted option.
    pub fn current_info_text(&self) -> String {
        match self.current_step {
            WizardStep::Deployment => DEPLOYMENT_CHOICES.get(self.selection_index).map(|c| c.info.to_string()).unwrap_or_default(),
            WizardStep::Vta => {
                if let Some(phase) = self.vta_phase() {
                    return match phase {
                        ConnectPhase::EnterDid => {
                            "Enter the VTA's DID (e.g. did:webvh:vta.example.com). The wizard resolves the DID document to discover its DIDComm service endpoint — you do not need to supply URLs separately.".into()
                        }
                        ConnectPhase::EnterContext => {
                            "The VTA context this mediator will live in. Defaults to 'mediator'; override if you use a different naming convention or run multiple mediators against the same VTA.".into()
                        }
                        ConnectPhase::EnterMediatorUrl => {
                            "Public URL this mediator will serve at (e.g. https://mediator.example.com). Passed to the VTA's DID template as the `URL` variable so the rendered mediator DID advertises the right service endpoints.".into()
                        }
                        ConnectPhase::AwaitingAcl => {
                            "The wizard has generated an ephemeral did:key to authenticate to the VTA. Run the displayed `pnm acl create` command on your VTA admin host, then press Enter to provision the mediator's DID and admin credential in one round-trip.".into()
                        }
                        ConnectPhase::Testing => {
                            "Opening a DIDComm session to the VTA, sending the signed provisioning request, and opening the sealed bundle the VTA returns…".into()
                        }
                        ConnectPhase::PickWebvhServer => {
                            let Some(st) = self.vta_connect.as_ref() else {
                                return String::new();
                            };
                            match self.selection_index {
                                0 => "Self-host the minted DID at the mediator URL (no webvh hosting server). Pick this if the mediator owns the public endpoint for its did.jsonl log.".into(),
                                i => {
                                    // Servers are offset by one (index 0 = serverless).
                                    let idx = i - 1;
                                    match st.webvh_servers.get(idx) {
                                        Some(srv) => {
                                            let label = srv.label.as_deref().unwrap_or("(no label)");
                                            format!("Host the minted DID's did.jsonl on '{}' ({label}). Sent to the VTA as WEBVH_SERVER = {}.", srv.id, srv.id)
                                        }
                                        None => String::new(),
                                    }
                                }
                            }
                        }
                        ConnectPhase::EnterWebvhPath => {
                            "Optional path or mnemonic the webvh server should publish the minted DID under (forwarded to the VTA as the `WEBVH_PATH` template variable, then on to the server's `request_uri` call). Leave blank to let the server auto-assign.".into()
                        }
                        ConnectPhase::Connected => {
                            "VTA-minted mediator DID received. Advancing to the next step.".into()
                        }
                        ConnectPhase::RecoveryPrompt => {
                            "Online attempts have been exhausted. Retry a transport whose last attempt failed pre-auth, or switch to the offline sealed-handoff flow.".into()
                        }
                        ConnectPhase::TransportFallbackPrompt => {
                            "DIDComm failed pre-auth and the VTA also advertises REST. Fall back to REST without restarting, retry DIDComm if you fixed the underlying issue, or switch to offline sealed-handoff.".into()
                        }
                    };
                }
                // A stub notice — surfaced when the operator picked an
                // (intent, transport) leaf that's not yet wired — takes
                // precedence over the per-option hint so the operator
                // sees why nothing moved.
                if let Some(ref notice) = self.vta_stub_notice {
                    return notice.clone();
                }
                match (self.vta_step_phase, self.selection_index) {
                    (VtaStepPhase::SelectIntent, i) => VTA_INTENT_CHOICES
                        .get(i)
                        .map(|c| c.info.to_string())
                        .unwrap_or_default(),
                    (VtaStepPhase::SelectTransport, 0) => "Direct network interaction with a running VTA. Lower friction but requires network reachability and an out-of-band `pnm acl create` step to pre-authorise the wizard against the VTA's ACL.".into(),
                    (VtaStepPhase::SelectTransport, 1) => "Armored sealed-bundle exchange — no network from this host. Suitable for air-gapped or offline deployments, or when the VTA isn't directly reachable.".into(),
                    _ => String::new(),
                }
            }
            WizardStep::Protocol => match self.selection_index {
                0 => "DIDComm v2 is the industry standard for DID-based secure messaging. Recommended for most deployments. [Space] toggles; [Enter] continues.".into(),
                1 => "TSP (Trust Spanning Protocol) is the preferred transport: peers that advertise both pick TSP. Carried alongside DIDComm, and advertised as `#tsp` in the mediator's DID. Keep DIDComm on too — TSP currently authenticates over the DIDComm session. [Space] toggles; [Enter] continues.".into(),
                _ => String::new(),
            },
            WizardStep::Did => {
                if self.did_phase == Some(DidPhase::IdentityFormChoice) {
                    return "Both choices write the same did:webvh log, served at the same URL, and \
                            list both names in it. did:webvh names the host in the DID itself; \
                            did:scid does not, so the log can move without the identity \
                            changing — but a peer must support did:scid to reach this mediator \
                            by it."
                        .into();
                }
                if self.did_phase == Some(DidPhase::SaveDidWebChoice) {
                    return "Most deployments should pick \"No\" — the did:webvh log is \
                            always written and is all you need. Only choose \"Yes\" if you \
                            specifically know you need a did:web identifier as well (e.g. \
                            a verifier or counterparty that resolves did:web but not \
                            did:webvh). did:webvh and did:web are wire-compatible — the \
                            same document resolves under either method once the SCID is \
                            dropped — so \"Yes\" writes an extra did-web.json (id rewritten \
                            to did:web:<domain>) you host at a plain web server's \
                            /.well-known/did.json."
                        .into();
                }
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    return "Pick where the VTA should publish this DID's did.jsonl log. \
                            Self-host = the mediator (or another server you operate) serves \
                            the document at `/.well-known/did.jsonl`. VTA-hosted = the VTA \
                            manages publication for you on a registered webvh server."
                        .into();
                }
                self.did_choices()
                    .get(self.selection_index)
                    .map(|c| c.info.to_string())
                    .unwrap_or_default()
            }
            WizardStep::KeyStorage => {
                // Validation errors take priority — the operator just
                // had a passphrase mismatch and needs to see why their
                // Enter sent them back a screen.
                if matches!(
                    self.key_storage_phase,
                    Some(KeyStoragePhase::FilePassphrase)
                        | Some(KeyStoragePhase::FilePassphraseConfirm)
                ) && let Some(ref err) = self.passphrase_validation_error
                {
                    return err.clone();
                }
                match &self.backend_check {
                    Some(BackendCheck::Running(url)) => {
                        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
                        return format!(
                            "{} Checking the secret backend {url} — reachable, writable, and \
                             not already holding a mediator…",
                            SPINNER[self.tick % SPINNER.len()]
                        );
                    }
                    Some(BackendCheck::Failed(e)) if self.key_storage_phase.is_none() => {
                        return format!("\u{26A0} {e}");
                    }
                    _ => {}
                }
                KEY_STORAGE_CHOICES.get(self.selection_index).map(|c| c.info.to_string()).unwrap_or_default()
            }
            WizardStep::Security => {
                if self.security_phase == Some(SecurityPhase::CorsPolicy) {
                    match self.selection_index {
                        0 => "Leaves `cors_allow_origin` unset. Any client carrying an `Origin` header is refused on both the REST API and the WebSocket upgrade; a client sending no Origin is admitted. Note this is about the header, not about being a browser \u{2014} React Native's WebSocket sends an Origin, so a mobile wallet is refused here too and needs option 2 or 3. This is the mediator's default.".into(),
                        1 => "Emits `cors_allow_origin = \"*\"`. The mediator echoes `Access-Control-Allow-Origin: *` and never sets credentials. Safe here because every endpoint requires a bearer token — a wildcard does not enable CSRF.".into(),
                        2 => "Emits `cors_allow_origin = \"<your list>\"`. The next screen collects a comma-separated allowlist. Each request Origin must match an entry exactly, or fall under a `*.subdomain` wildcard; the matched origin is echoed back.".into(),
                        _ => String::new(),
                    }
                } else if self.security_phase == Some(SecurityPhase::NetworkMode) {
                    match self.selection_index {
                        0 => "Open mode emits `mediator_acl_mode = \"explicit_deny\"`, `global_acl_default = \"ALLOW_ALL\"`, and `local_direct_delivery_allowed = \"true\"`. Any DID may reach any other by default; use the ACL to deny on a per-DID basis.".into(),
                        1 => "Closed mode emits `mediator_acl_mode = \"explicit_allow\"` (only admins may pre-register other DIDs) with a denying default ACL, so a DID that self-registers gets no capabilities until an admin grants them. Note that neither mode blocks authentication itself — the denying default ACL is what makes this closed. Pick this for restricted or invitation-only deployments.".into(),
                        _ => String::new(),
                    }
                } else if self.security_phase == Some(SecurityPhase::JwtMode) {
                    match self.selection_index {
                        0 => "The wizard generates a 32-byte Ed25519 PKCS8 keypair and writes it into the unified secret backend at the well-known key `mediator_jwt_secret`. The mediator picks it up at startup with no further config.".into(),
                        1 => "The wizard records your choice but does NOT generate or prompt for a key. Before starting the mediator, set MEDIATOR_JWT_SECRET (raw PKCS8 bytes, base64-encoded) or pass --jwt-secret-file <path>. Choose this when CI/CD already issues JWT keys or when an HSM holds them.".into(),
                        _ => String::new(),
                    }
                } else {
                    SSL_CHOICES.get(self.selection_index).map(|c| c.info.to_string()).unwrap_or_default()
                }
            }
            WizardStep::Database => {
                if self.database_phase == Some(DatabasePhase::SelectBackend) {
                    match self.selection_index {
                        0 => "Redis: multi-mediator clusters with cross-process pub/sub. Pick this when running more than one mediator instance against shared storage, or when an operator already provisions Redis.".into(),
                        1 => "Fjall: single-node embedded LSM. No Redis sidecar — data lives on disk under data_dir. Recommended for self-hosted deployments and operators who want fewer moving parts.".into(),
                        _ => String::new(),
                    }
                } else if self.database_phase == Some(DatabasePhase::ConfirmCreateFjallDir) {
                    // Validation errors take priority — they're how
                    // we surface a `create_dir_all` failure (permission
                    // denied, etc.) after the operator picked Yes.
                    if let Some(ref err) = self.database_validation_error {
                        return err.clone();
                    }
                    format!(
                        "The path '{}' does not exist yet. \
                         Yes runs `std::fs::create_dir_all` immediately so any \
                         permission / filesystem errors surface here rather than \
                         on first mediator boot. No goes back so you can retype.",
                        self.config.fjall_data_dir,
                    )
                } else if self.config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
                    // Validation errors override the default hint so
                    // the operator sees why Enter didn't advance.
                    if let Some(ref err) = self.database_validation_error {
                        return err.clone();
                    }
                    "Path on disk where Fjall will keep its data directory. Wizard asks before creating if missing. Use a persistent volume (or a host bind-mount) when running in Docker.".into()
                } else {
                    "Redis connection URL. Use database partitions (e.g. redis://127.0.0.1/1) to isolate data when sharing a Redis instance.".into()
                }
            }
            WizardStep::Admin => self
                .admin_choices()
                .get(self.selection_index)
                .map(|c| c.info.to_string())
                .unwrap_or_default(),
            WizardStep::Output => {
                "Defaults to `conf/mediator.toml` (relative to the mediator's working \
                 directory). Sibling files — `secrets.json` when file:// is the chosen \
                 backend, `atm-functions.lua`, `did.jsonl` — land in the same folder."
                    .into()
            }
            WizardStep::Summary => String::new(),
        }
    }
}
