//! The wizard's state machine vocabulary: the steps in order, the input
//! mode and focus, and each step's sub-phases.

use crate::consts::*;

/// All wizard steps in order.
///
/// Ordering note: `KeyStorage` runs before `Vta` deliberately. The secret
/// backend is the foundation everything else writes to — if it's
/// unreachable we want to know *before* spending time on VTA provisioning.
/// The VTA sub-flow also persists the rotated admin credential into this
/// backend on completion, so it needs to exist first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardStep {
    Deployment,
    KeyStorage,
    Vta,
    Protocol,
    Did,
    Security,
    Database,
    Admin,
    /// Where to write `mediator.toml`. Added as its own step so the
    /// question is asked inside the TUI (consistent nav + validation)
    /// rather than via a stdin prompt after the TUI exits.
    Output,
    Summary,
}

impl WizardStep {
    pub fn all() -> Vec<WizardStep> {
        vec![
            Self::Deployment,
            Self::KeyStorage,
            Self::Vta,
            Self::Protocol,
            Self::Did,
            Self::Security,
            Self::Database,
            Self::Admin,
            Self::Output,
            Self::Summary,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Deployment => "Deployment Type",
            Self::Vta => "VTA Integration",
            Self::Protocol => "Protocol",
            Self::Did => "DID Configuration",
            Self::KeyStorage => "Key Storage",
            Self::Security => "Security",
            Self::Database => "Database",
            Self::Admin => "Admin Account",
            Self::Output => "Output Location",
            Self::Summary => "Summary",
        }
    }

    pub fn index(&self) -> usize {
        Self::all().iter().position(|s| s == self).unwrap_or(0)
    }

    pub fn step_number(&self) -> usize {
        self.index() + 1
    }

    pub fn total() -> usize {
        Self::all().len()
    }

    pub fn next(&self) -> Option<WizardStep> {
        let steps = Self::all();
        let idx = self.index();
        steps.get(idx + 1).copied()
    }

    pub fn prev(&self) -> Option<WizardStep> {
        let steps = Self::all();
        let idx = self.index();
        if idx > 0 {
            steps.get(idx - 1).copied()
        } else {
            None
        }
    }

    /// True for steps whose selection list is multi-select (Space toggles,
    /// Enter advances). Exposed so the key handler and the global help bar
    /// can reflect the right key cues. Add any new multi-select step here.
    pub fn is_multi_select(&self) -> bool {
        matches!(self, Self::Protocol)
    }

    pub fn step_data(&self) -> StepData {
        let total = Self::total();
        let num = self.step_number();
        match self {
            Self::Deployment => StepData {
                title: format!("Step {num}/{total}: Deployment Type"),
                description: "What kind of deployment is this?".into(),
            },
            Self::Vta => StepData {
                title: format!("Step {num}/{total}: VTA Integration"),
                description: "Will this mediator use a Verifiable Trust Agent (VTA)?".into(),
            },
            Self::Protocol => StepData {
                title: format!("Step {num}/{total}: Messaging Protocol"),
                description:
                    "[Space] toggles a protocol (at least one required). [Enter] continues, \
                     [Esc] goes back."
                        .into(),
            },
            Self::Did => StepData {
                title: format!("Step {num}/{total}: DID Configuration"),
                description: "How should the mediator's DID be configured?".into(),
            },
            Self::KeyStorage => StepData {
                title: format!("Step {num}/{total}: Key Storage"),
                description: "Where should cryptographic keys be stored?".into(),
            },
            Self::Security => StepData {
                title: format!("Step {num}/{total}: Security"),
                description: "TLS termination, JWT signing, and the mediator's \
                              network access posture (Open vs Closed)."
                    .into(),
            },
            Self::Database => StepData {
                title: format!("Step {num}/{total}: Storage Backend"),
                description: "Choose between Redis (multi-mediator) and Fjall \
                              (embedded single-node)."
                    .into(),
            },
            Self::Admin => StepData {
                title: format!("Step {num}/{total}: Admin Account"),
                description: "Configure the admin DID for mediator management.".into(),
            },
            Self::Output => StepData {
                title: format!("Step {num}/{total}: Output Location"),
                description: "Where should the wizard write mediator.toml? (secrets.json, \
                     atm-functions.lua, did.jsonl all land in the same directory.)"
                    .into(),
            },
            Self::Summary => StepData {
                title: "Summary".into(),
                description: "Review and confirm your configuration.".into(),
            },
        }
    }
}

pub struct StepData {
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Navigating a selection list in the right panel
    Selecting,
    /// Typing into a text field
    TextInput,
    /// Confirming an action (summary write)
    Confirming,
}

/// Which panel has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    /// Right panel — step content (options, text input)
    Content,
    /// Left panel — step progress list (click to jump to a step)
    Progress,
}

/// Sub-phases of the `KeyStorage` step that gather backend-specific config.
///
/// The operator picks a scheme on the selection list (implicit
/// `SelectScheme` phase, represented as `key_storage_phase: None`), and any
/// backend that needs extra info then walks through the relevant phases.
/// The placeholder cloud backends (gcp/azure/vault) have no config to
/// gather yet and skip straight to `advance()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoragePhase {
    /// `file://` — dev-only hard-gate. The operator must type the
    /// literal phrase `I understand` (case-insensitive) before the
    /// wizard advances to [`Self::FilePath`]. Anything else aborts the
    /// selection and rewinds to the scheme list.
    FileGate,
    /// `file://` — prompt for the path to write secrets.json.
    FilePath,
    /// `file://` — ask whether to encrypt with a passphrase
    /// (envelope-encryption via Argon2id + AES-GCM). Selecting "yes"
    /// advances to [`Self::FilePassphrase`]; "no" finishes the
    /// sub-flow with a plaintext file.
    FileEncryptChoice,
    /// `file://` — collect the passphrase via a masked prompt. The
    /// passphrase is exported as `MEDIATOR_FILE_BACKEND_PASSPHRASE`
    /// for the duration of the wizard process so the secret backend
    /// can derive its key when `MediatorSecrets::from_url` is called
    /// in `generate_and_write`.
    FilePassphrase,
    /// `file://` — re-enter the passphrase to guard against typos. The
    /// first input is stashed on `WizardApp::pending_passphrase`; this
    /// phase compares against it and either advances (match) or bounces
    /// back to [`Self::FilePassphrase`] with an inline error (mismatch).
    FilePassphraseConfirm,
    /// `keyring://` — prompt for the OS-keyring service name.
    KeyringService,
    /// `aws_secrets://` — first prompt: AWS region.
    AwsRegion,
    /// `aws_secrets://` — second prompt: secret namespace.
    AwsNamespace,
    /// `gcp_secrets://` — first prompt: GCP project ID.
    GcpProject,
    /// `gcp_secrets://` — second prompt: secret namespace.
    GcpNamespace,
    /// `azure_keyvault://` — vault name (commercial cloud), sovereign-
    /// cloud DNS name, or full URL. Single field — Azure Key Vault
    /// secrets share the vault namespace; the URL parser canonicalises.
    AzureVault,
    /// `vault://` — first prompt: server endpoint (`host[:port]`).
    VaultEndpoint,
    /// `vault://` — second prompt: KV v2 mount + optional per-key
    /// namespace glued (e.g. `secret/mediator`).
    VaultMount,
    /// `vault://` — auth-method picker (Token / Kubernetes / AppRole).
    /// A selection phase (like [`Self::FileEncryptChoice`]), not text.
    VaultAuthMethod,
    /// `vault://` kubernetes auth — Vault role (required).
    VaultRole,
    /// `vault://` kubernetes auth — auth mount (default `kubernetes`).
    VaultK8sMount,
    /// `vault://` approle auth — auth mount (default `approle`).
    VaultApproleMount,
    /// `vault://` — Vault Enterprise namespace (optional). Shared tail of
    /// the kubernetes and approle sub-flows.
    VaultNamespace,
    /// `k8s://` — first prompt: Kubernetes namespace (optional; resolved
    /// from the ServiceAccount / kubeconfig when blank).
    K8sNamespace,
    /// `k8s://` — second prompt: Secret object name (required).
    K8sSecretName,
}

/// Literal phrase the operator must type to clear the `file://` hard-gate.
/// Stored as a constant so tests and the prompt rendering stay in sync.
pub const FILE_GATE_PHRASE: &str = "I understand";

/// Sub-phases of the `Did` step when `DID_VTA` is selected. After the
/// mediator URL is captured, the wizard asks the operator where the
/// VTA should publish the DID — pick a registered webvh hosting
/// service, self-host at the mediator URL, or self-host at a
/// different URL. Mirrors the `KeyStoragePhase` shape.
///
/// Skipped entirely for did:peer / did:webvh / import paths and for
/// sealed-handoff VTA sessions (those bring a fully-provisioned DID
/// already, no hosting choice to make).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidPhase {
    /// Selection list: self-host-at-mediator / each VTA-hosted server
    /// / self-host-elsewhere.
    SelectWebvhHost,
    /// Text input for a different self-host base URL.
    EnterCustomUrl,
    /// Selection: after a local did:webvh URL is captured, choose whether
    /// the mediator presents the log as its did:webvh DID (default) or its
    /// did:scid:vh:1 DID.
    IdentityFormChoice,
    /// Yes/No selection: after a local did:webvh is configured, offer to
    /// also export a did:web (`did-web.json`) copy of the DID document.
    SaveDidWebChoice,
}

/// Sub-phases of the `Security` step. The SSL portion (selection list +
/// optional cert/key text inputs) runs as the implicit `None` phase; once
/// SSL is settled the wizard pivots to a small JWT-mode selection before
/// advancing to `Database`. Mirrors the `KeyStoragePhase` shape so that
/// the renderer can use the same "step has a sub-phase" pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPhase {
    /// Choose between generating a fresh JWT signing key or providing
    /// one out-of-band via env var / `--jwt-secret-file` at boot.
    JwtMode,
    /// Pick the mediator's network posture — Open (any DID can message
    /// any other; per-DID overrides flip individual flags) vs Closed
    /// (every cross-DID exchange needs an explicit ACL grant). Renders
    /// after `JwtMode` and before `CorsPolicy`.
    NetworkMode,
    /// Pick the browser CORS policy for the REST/WebSocket endpoints —
    /// Any (`*`) / None (default, deny all) / Specific domains. The
    /// "Specific" choice drops into a text-input sub-phase (still
    /// `CorsPolicy`, `InputMode::TextInput`) collecting the allowlist.
    /// Renders after `NetworkMode`; confirming it (or the domains input)
    /// is what finally advances the step to `Database`.
    CorsPolicy,
}

/// Sub-phases of the `Database` step. The wizard now asks up to three
/// questions: first which storage backend (Redis vs Fjall), then a
/// backend-specific URL/path, and (Fjall only) — when the path doesn't
/// yet exist on disk — whether to create it now. `None` means the
/// text-input widget is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabasePhase {
    /// Choose between `redis` and `fjall`. After confirm the wizard
    /// transitions to a backend-specific text-input phase
    /// (represented by `database_phase = None` + `InputMode::TextInput`).
    SelectBackend,
    /// Fjall-only: text input was confirmed against a path that doesn't
    /// exist yet. Selection list of "Yes — create now" / "No — edit
    /// path". Yes runs `fs::create_dir_all` and advances; No goes back
    /// to the text-input phase.
    ConfirmCreateFjallDir,
}

/// Sub-phases of the top-level `Vta` step picker (before any of the
/// transport-specific sub-flows take over).
///
/// Splits the single "VTA mode" question into two orthogonal
/// questions — intent (what do you want from the VTA?) and transport
/// (how does the request reach the VTA?). The four intent×transport
/// leaves each route into one of four adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtaStepPhase {
    /// First question — FullSetup / AdminOnly / No VTA.
    SelectIntent,
    /// Second question — Online / Sealed handoff. Only reached after
    /// the operator picked a non-`None` intent on [`Self::SelectIntent`].
    SelectTransport,
}

impl KeyStoragePhase {
    /// First config phase for the given scheme. `None` means the scheme
    /// needs no extra config and can advance immediately.
    pub fn first_for(scheme: &str) -> Option<Self> {
        match scheme {
            // file:// always starts at the hard-gate, never directly at
            // FilePath. This is intentional: skipping the gate means
            // skipping the dev-only acknowledgement.
            STORAGE_FILE => Some(Self::FileGate),
            STORAGE_KEYRING => Some(Self::KeyringService),
            STORAGE_AWS => Some(Self::AwsRegion),
            STORAGE_GCP => Some(Self::GcpProject),
            STORAGE_AZURE => Some(Self::AzureVault),
            STORAGE_VAULT => Some(Self::VaultEndpoint),
            STORAGE_K8S => Some(Self::K8sNamespace),
            _ => None,
        }
    }
}
