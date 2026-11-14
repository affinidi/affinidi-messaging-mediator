//! The option tables behind each selection list: the value a row selects,
//! its label and help line, and the info-box text.

use super::WizardApp;
use crate::app::{AdminMode, Deployment, DidMethod, SecretScheme, SslMode};
use crate::ui::selection::SelectionOption;
use crate::vta::VtaIntent;

/// One entry of a step's option list: the value it selects, the label and
/// one-line help shown in the list, and the longer text for the info box.
///
/// A step's list, its Enter handling and its default highlight are all
/// derived from one table of these, so they cannot drift apart (they did:
/// Enter mapped index 6 to `file://` while the default highlight put
/// `file://` at index 5, which was Kubernetes).
#[derive(Debug, Clone, Copy)]
pub struct Choice<T: Copy + 'static> {
    pub value: T,
    pub label: &'static str,
    pub help: &'static str,
    pub info: &'static str,
}

impl<T: Copy + PartialEq + 'static> Choice<T> {
    pub fn option(&self) -> SelectionOption {
        SelectionOption::new(self.label, self.help)
    }
}

/// Index of the entry holding `value`.
pub fn index_of<T: Copy + PartialEq + 'static>(choices: &[Choice<T>], value: T) -> Option<usize> {
    choices.iter().position(|c| c.value == value)
}

pub const DEPLOYMENT_CHOICES: [Choice<Deployment>; 3] = [
    Choice {
        value: Deployment::Local,
        label: "Local development",
        help: "Desktop, quick start — ideal for testing",
        info: "Starts from: VTA online, OS keyring for secrets, no SSL, local Redis, and an \
               open network (any DID may message any other). Every choice can be changed on \
               the following screens.",
    },
    Choice {
        value: Deployment::Server,
        label: "Headless server",
        help: "Production deployment on cloud or bare metal",
        info: "Starts from: VTA online, OS keyring for secrets, no SSL (TLS proxy), local \
               Redis, and a closed network — DIDs exchange messages only with an explicit ACL \
               grant. Every choice can be changed on the following screens.",
    },
    Choice {
        value: Deployment::Container,
        label: "Container",
        help: "Docker image for container orchestration",
        info: "Same defaults as a server (including the closed network), plus a Dockerfile and docker-compose.yml next to \
               mediator.toml. The image holds only the binary; the config directory and keys \
               are mounted. The OS keyring does not exist inside a container — pick a secret \
               manager or Kubernetes Secrets.",
    },
];

pub const KEY_STORAGE_CHOICES: [Choice<SecretScheme>; 7] = [
    Choice {
        value: SecretScheme::Keyring,
        label: "OS Keyring (keyring://) [recommended for desktop]",
        help: "macOS Keychain, Linux Secret Service, Windows Credential Manager",
        info: "Uses the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential \
               Manager). Good for desktop development and single-host servers.",
    },
    Choice {
        value: SecretScheme::Aws,
        label: "AWS Secrets Manager (aws_secrets://)",
        help: "AWS cloud production",
        info: "Store secrets in AWS Secrets Manager. Requires AWS credentials configured. \
               Suitable for AWS production.",
    },
    Choice {
        value: SecretScheme::Gcp,
        label: "Google Cloud Secret Manager (gcp_secrets://)",
        help: "GCP cloud production",
        info: "Store secrets in Google Cloud Secret Manager. Auth via Application Default \
               Credentials (GOOGLE_APPLICATION_CREDENTIALS / `gcloud auth application-default \
               login` / GKE workload identity).",
    },
    Choice {
        value: SecretScheme::Azure,
        label: "Azure Key Vault (azure_keyvault://)",
        help: "Azure cloud production",
        info: "Store secrets in Azure Key Vault. Auth via Azure CLI / azd developer \
               credentials (`az login`). Sovereign clouds supported via full DNS in the vault \
               field.",
    },
    Choice {
        value: SecretScheme::Vault,
        label: "HashiCorp Vault (vault://)",
        help: "Enterprise / multi-cloud (KV v2 only); token / Kubernetes / AppRole auth",
        info: "Store secrets in HashiCorp Vault (KV v2): token (VAULT_TOKEN), Kubernetes or \
               AppRole auth. The mount point must already exist on the server.",
    },
    Choice {
        value: SecretScheme::K8s,
        label: "Kubernetes Secrets (k8s://)",
        help: "Native Secret object via the K8s API (in-cluster ServiceAccount)",
        info: "Store every key in one Kubernetes Secret, through the API with the pod's \
               ServiceAccount (or kubeconfig). The namespace defaults to the ServiceAccount's.",
    },
    Choice {
        value: SecretScheme::File,
        label: "Local file (file://)",
        help: "Stored in secrets.json — DEV ONLY, requires explicit confirmation",
        info: "Secrets written to a local JSON file, optionally passphrase-encrypted. \
               Unencrypted it is DEV ONLY — anyone with file access can read the private keys. \
               The wizard requires an explicit confirmation before accepting this choice.",
    },
];

/// The VTA step's first question. `None` is "No VTA".
pub const VTA_INTENT_CHOICES: [Choice<Option<VtaIntent>>; 4] = [
    Choice {
        value: Some(VtaIntent::FullSetup),
        label: "Full setup — VTA mints my mediator DID",
        help: "VTA renders a DID template, mints integration + admin keys, issues an \
               authorisation VC. The wizard will skip the DID step when this path is chosen.",
        info: "The mediator's integration DID, admin DID, and VTA trust bundle are all issued \
               by the VTA via a template render. The wizard skips the DID step when this path \
               is chosen.",
    },
    Choice {
        value: Some(VtaIntent::AdminOnly),
        label: "Admin credential only — I'll bring my own DID",
        help: "Mediator keeps the DID from the DID step; the VTA only supplies an admin \
               credential used for VTA admin APIs.",
        info: "The mediator keeps the DID you configure in the next step. The VTA only \
               supplies an admin credential used to authenticate against VTA admin APIs.",
    },
    Choice {
        value: Some(VtaIntent::OfflineExport),
        label: "Pick up pre-provisioned mediator (offline export)",
        help: "VTA already provisioned the context + mediator DID + keys (e.g. during VTA \
               bootstrap). Wizard writes a request; VTA admin runs `vta contexts reprovision \
               --id <ctx> --recipient <file>` and returns the existing material in a \
               ContextProvision bundle. Always offline.",
        info: "The VTA already holds this mediator's DID and keys. The wizard writes a request \
               file; the VTA admin re-exports the existing material sealed to it. Use for \
               migrations and restores.",
    },
    Choice {
        value: None,
        label: "No VTA",
        help: "Manage keys and DIDs independently (local dev, cloud secret stores).",
        info: "Keys and DIDs are generated locally or stored in cloud secret managers. You are \
               responsible for backup and rotation.",
    },
];

pub const SSL_CHOICES: [Choice<SslMode>; 3] = [
    Choice {
        value: SslMode::None,
        label: "No SSL (use TLS-terminating proxy)",
        help: "Recommended: nginx, Caddy, AWS ALB handle TLS",
        info: "Run the mediator behind a reverse proxy (nginx, Caddy, AWS ALB) that terminates \
               TLS. The mediator runs plain HTTP. This is the recommended approach.",
    },
    Choice {
        value: SslMode::Existing,
        label: "Provide existing certificates",
        help: "Use your own SSL certificate and key files",
        info: "Provide paths to existing SSL certificate and key files.",
    },
    Choice {
        value: SslMode::SelfSigned,
        label: "Generate self-signed certificates",
        help: "Local development only — not for production",
        info: "Generate self-signed certificates for local development. Browsers will show \
               security warnings.",
    },
];

const DID_CHOICE_VTA: Choice<DidMethod> = Choice {
    value: DidMethod::Vta,
    label: "Configure via VTA (recommended)",
    help: "Centralized key management — VTA creates and hosts your DID",
    info: "VTA creates and manages the mediator's DID and keys centrally. Uses the built-in \
           `didcomm-mediator` template. To customise: `pnm did-templates init didcomm-mediator \
           > custom.json`, edit, then upload under the same name — context/global scope \
           shadows the built-in automatically.",
};
const DID_CHOICE_WEBVH: Choice<DidMethod> = Choice {
    value: DidMethod::Webvh,
    label: "Generate did:webvh",
    help: "Production — generates keys you manage yourself; you host did.jsonl",
    info: "did:webvh requires a webvh server (or the mediator itself) to host the DID log. \
           Rendered locally from the `didcomm-mediator` template. The log's update and \
           pre-rotation keys are stored in the secret backend so the DID can be updated \
           later.",
};
const DID_CHOICE_PEER: Choice<DidMethod> = Choice {
    value: DidMethod::Peer,
    label: "Generate did:peer",
    help: "Quick start — generates random keys, no hosting required",
    info: "did:peer is self-contained — no hosting required. Generates random keys that you \
           must back up and manage yourself. Best for local dev and testing.",
};

const ADMIN_CHOICE_GENERATE: Choice<AdminMode> = Choice {
    value: AdminMode::Generate,
    label: "Generate a new admin did:key",
    help: "A fresh Ed25519 key, separate from any VTA credential",
    info: "Generates a new Ed25519 did:key for the mediator's admin API. Its key is stored in \
           admin-monitor.json (and, without a VTA, in the secret backend). In a VTA setup it \
           is separate from the VTA credential, which stays the mediator↔VTA identity.",
};
const ADMIN_CHOICE_PASTE: Choice<AdminMode> = Choice {
    value: AdminMode::Paste,
    label: "Use an existing admin DID",
    help: "Paste a DID you control (any method)",
    info: "Paste any DID (did:key, did:peer, did:webvh, …) that will administer the \
           mediator. The wizard holds no key for it.",
};
const ADMIN_CHOICE_VTA: Choice<AdminMode> = Choice {
    value: AdminMode::Vta,
    label: "Use the VTA-issued credential",
    help: "One key for both the VTA credential and the mediator's admin API",
    info: "Reuses the admin DID the VTA issued for this mediator as the admin-API identity. \
           Simpler, but one key then serves two trust scopes (VTA admin and mediator admin).",
};
const ADMIN_CHOICE_SKIP: Choice<AdminMode> = Choice {
    value: AdminMode::Skip,
    label: "Skip for now",
    help: "Configure admin later",
    info: "You can configure the admin DID later by editing mediator.toml or via the admin \
           API.",
};

impl WizardApp {
    /// The DID step's options: "Configure via VTA" only when the operator
    /// picked `FullSetup` on the Vta step (the intent where the VTA mints
    /// the integration DID). Importing an existing DID is not offered — the
    /// wizard cannot provision one.
    pub fn did_choices(&self) -> Vec<Choice<DidMethod>> {
        let mut choices = Vec::with_capacity(3);
        if self.config.use_vta && self.shows_vta_did_option() {
            choices.push(DID_CHOICE_VTA);
        }
        choices.extend([DID_CHOICE_WEBVH, DID_CHOICE_PEER]);
        choices
    }

    /// The Admin step's options, the VTA-credential entry only where the VTA
    /// intends to issue one for the mediator.
    pub fn admin_choices(&self) -> Vec<Choice<AdminMode>> {
        let mut choices = vec![ADMIN_CHOICE_GENERATE, ADMIN_CHOICE_PASTE];
        if self.admin_options_include_vta() {
            choices.push(ADMIN_CHOICE_VTA);
        }
        choices.push(ADMIN_CHOICE_SKIP);
        choices
    }

    /// Whether the Admin step's option list should include the
    /// "Generate admin DID from VTA" entry.
    ///
    /// Returns `true` for deployments where the VTA intentionally mints
    /// an admin DID meant for the mediator (FullSetup's admin-DID
    /// rollover, AdminOnly's whole-flow purpose). Returns `false` for
    /// OfflineExport — the bundle's admin credential there is an
    /// auto-mint for mediator↔VTA authentication, and reusing it as
    /// the mediator's own admin-API identity conflates two trust
    /// scopes behind one key.
    pub(super) fn admin_options_include_vta(&self) -> bool {
        if !self.config.use_vta {
            return false;
        }
        !matches!(self.vta_intent_choice, Some(VtaIntent::OfflineExport))
    }

    /// Whether the Did step should offer the "Configure via VTA"
    /// option. Only meaningful after the Vta step has completed; read
    /// from the persisted `did_method` (set by `apply_vta_defaults`
    /// for FullSetup) plus the session state when present.
    pub(super) fn shows_vta_did_option(&self) -> bool {
        // `did_method == DidMethod::Vta` is the FullSetup signal — AdminOnly
        // clears it in `apply_vta_defaults`. `No VTA` also clears it.
        self.config.did_method == Some(DidMethod::Vta)
    }
}
