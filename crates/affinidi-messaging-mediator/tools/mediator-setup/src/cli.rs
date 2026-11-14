use std::path::PathBuf;

use clap::{Parser, ValueEnum};

// `Default` lets tests construct an `Args` with `..Default::default()` (all
// flags off / `None`) and set only the fields under test — clap always fully
// populates it at runtime, so the derive is test-only ergonomics.
#[derive(Parser, Default)]
#[command(
    name = "mediator-setup",
    about = "Interactive setup wizard for Affinidi Messaging Mediator",
    long_about = "Interactive setup wizard for Affinidi Messaging Mediator.\n\n\
        Run with no arguments on a terminal for the interactive wizard. For \
        scripted setups, describe the mediator in a build recipe and run \
        `mediator-setup --from <recipe.toml>`; `--set section.key=value` \
        overrides any recipe value, and the per-option flags below are \
        shorthands for the matching recipe keys. `--non-interactive` runs the \
        same pipeline from the flags alone.",
    after_help = crate::exit::HELP
)]
pub struct Args {
    /// Path to the mediator configuration file to write [default:
    /// conf/mediator.toml]. Recipe key: `output.config_path`. With
    /// `--uninstall`, the configuration to tear down.
    #[arg(long, short = 'c')]
    pub config: Option<String>,

    /// Deployment type. Recipe key: `deployment.type`.
    #[arg(long, value_enum)]
    pub deployment: Option<DeploymentType>,

    /// Messaging protocol. Recipe key: `deployment.protocols`.
    #[arg(long, value_enum)]
    pub protocol: Option<Protocol>,

    /// DID method for the mediator. Recipe key: `identity.did_method`.
    /// Required with `--non-interactive` (without `--from`).
    #[arg(long, value_enum)]
    pub did_method: Option<DidMethod>,

    /// Public URL for the mediator (required for did:webvh). Recipe key:
    /// `identity.public_url`.
    #[arg(long)]
    pub public_url: Option<String>,

    /// Also write a did:web copy of the generated DID document to
    /// `did-web.json` (next to `did.jsonl`), rewriting the identifier
    /// from `did:webvh:<scid>:<domain>` to `did:web:<domain>`. Only
    /// applies when the mediator DID is a did:webvh (local generator or
    /// VTA-managed webvh log). Recipe key: `identity.save_did_web`.
    #[arg(long)]
    pub save_did_web: bool,

    /// Present a locally generated did:webvh log as its did:scid:vh:1 DID: an
    /// identity that keeps its name when the log moves host. The log, and
    /// what the mediator serves, are the same. Requires
    /// `--did-method webvh` and the did:scid alias. Recipe key:
    /// `identity.present_as = "scid"`.
    #[arg(long, conflicts_with = "no_scid_alias")]
    pub present_as_scid: bool,

    /// Leave the did:scid:vh:1 alias out of a locally generated did:webvh
    /// log's `alsoKnownAs`. It is listed by default, so peers can recognise
    /// the identity under either name. Recipe key:
    /// `identity.scid_also_known_as = false`.
    #[arg(long)]
    pub no_scid_alias: bool,

    /// Extra cryptographic key suite(s) to provision *in addition to* the
    /// mandatory Ed25519 (signing) + X25519 (key-agreement) pair.
    /// Repeatable: `--key-suite p256`. Counterparties that can't speak
    /// Curve25519 (JOSE-first stacks, hardware wallets, ES256 issuers) need
    /// these. Applies to the locally-generated did:peer / did:webvh methods;
    /// VTA-managed DIDs take their key set from the VTA's template. Recipe
    /// key: `identity.extra_key_suites`.
    #[arg(long, value_enum, value_name = "SUITE")]
    pub key_suite: Vec<KeySuite>,

    /// Secret storage backend, with its default settings. Backends that
    /// have no usable default (GCP project, Azure vault, Vault endpoint)
    /// need the full URL instead: `--set secrets.storage=<url>`. Recipe
    /// key: `secrets.storage`.
    #[arg(long, value_enum)]
    pub secret_storage: Option<SecretStorage>,

    /// Accept an unencrypted `file://` secret store outside a local
    /// deployment. Recipe key: `secrets.allow_plaintext_file`.
    #[arg(long)]
    pub allow_plaintext_file: bool,

    /// SSL/TLS mode. Recipe key: `security.ssl`.
    #[arg(long, value_enum)]
    pub ssl: Option<SslMode>,

    /// Redis database URL. Recipe key: `database.url`.
    #[arg(long)]
    pub database_url: Option<String>,

    /// Admin identity for the mediator's admin API. Recipe key:
    /// `security.admin`.
    #[arg(long, value_enum, conflicts_with = "admin_did")]
    pub admin: Option<AdminMode>,

    /// Use this existing DID as the mediator's admin identity (the wizard
    /// holds no key for it). Recipe keys: `security.admin = "import"` and
    /// `security.admin_did`.
    #[arg(long, value_name = "DID")]
    pub admin_did: Option<String>,

    /// Listen address (ip:port). Recipe key: `output.listen_address`.
    #[arg(long)]
    pub listen_address: Option<String>,

    /// Override one recipe value: `--set section.key=value`, e.g.
    /// `--set security.network_mode=closed` or
    /// `--set secrets.storage=vault://vault.example.com:8200/secret/mediator`.
    /// The value is read as TOML (`true`, `42`, `["a", "b"]`) and as a plain
    /// string otherwise. Repeatable; applied after the recipe file and the
    /// shorthand flags. Headless runs only.
    #[arg(long = "set", value_name = "SECTION.KEY=VALUE")]
    pub set: Vec<String>,

    /// Run without the interactive TUI, from the flags (and `--set`)
    /// alone. Needs `--did-method`.
    #[arg(long)]
    pub non_interactive: bool,

    /// Load a build recipe TOML file (non-interactive, fully declarative).
    #[arg(long, value_name = "FILE")]
    pub from: Option<String>,

    /// Phase 2 of a sealed-handoff setup: path to the armored
    /// `bundle.armor` returned by the VTA operator. When present,
    /// `--from` switches from phase 1 (emit request) to phase 2
    /// (open bundle, write mediator config). Requires `--from`.
    #[arg(long, value_name = "PATH", requires = "from")]
    pub bundle: Option<PathBuf>,

    /// Phase 2 only: the SHA-256 digest the VTA admin printed, carried
    /// over a separate channel. Required: the wizard verifies the
    /// bundle's canonical digest before unsealing and refuses on
    /// mismatch. The bundle's encryption does not identify its sender
    /// and the producer's signature is not verified yet, so the digest
    /// is what ties the bundle to the VTA admin.
    #[arg(long, value_name = "HEX", requires = "bundle")]
    pub digest: Option<String>,

    /// Phase 2 only: open the bundle without `--digest`. Nothing then
    /// ties the bundle to the VTA admin — anyone who has seen the
    /// request file could have sealed it. For throwaway dev setups.
    #[arg(long, requires = "bundle", conflicts_with = "digest")]
    pub allow_bundle_without_digest: bool,

    // ── Online-VTA connection flags ────────────────────────────────────
    /// VTA DID (e.g. did:webvh:vta.example.com). Pre-fills the TUI;
    /// required for the `--setup-key-out` / `--setup-key-file` flows.
    #[arg(long, value_name = "DID")]
    pub vta_did: Option<String>,

    /// VTA context id the mediator will live in (default: `mediator`).
    /// Recipe key: `vta.context`.
    #[arg(long, value_name = "ID")]
    pub vta_context: Option<String>,

    /// Public URL the mediator will serve at (e.g.
    /// <https://mediator.example.com>). Required for `--setup-key-file`,
    /// where it also becomes `identity.public_url` unless that is set.
    #[arg(long, value_name = "URL")]
    pub mediator_url: Option<String>,

    /// Two-phase online VTA setup, phase 1: generate an ephemeral did:key,
    /// write it to the given file (0600), print the `pnm contexts create`
    /// command and the phase-2 command, and exit. In this admin-only flow
    /// the setup did:key becomes the mediator's long-term VTA admin
    /// credential.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["setup_key_file", "from", "non_interactive", "bundle", "uninstall"]
    )]
    pub setup_key_out: Option<PathBuf>,

    /// Two-phase online VTA setup, phase 2: authenticate to the VTA with
    /// the did:key from `--setup-key-out`, then provision the mediator —
    /// its own DID from `--did-method` (peer or webvh) plus the VTA admin
    /// credential, stored in the secret backend — and write the config.
    /// The key file is deleted once everything is written. Requires
    /// `--vta-did`, `--mediator-url` and `--did-method`; takes the other
    /// flags and `--set`, or a recipe via `--from`.
    ///
    /// Auto-falls between DIDComm and REST when both transports are
    /// advertised — pre-auth failures on one wire trigger a retry on
    /// the other without prompting. Post-auth failures (VTA accepted
    /// the handshake then rejected the request body) terminate
    /// immediately — a different wire reproduces the rejection.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["bundle", "uninstall"])]
    pub setup_key_file: Option<PathBuf>,

    /// `--setup-key-file` only: retry the authentication loop for up to
    /// this many seconds while waiting for the ACL entry to appear on the
    /// VTA. Useful when ACL provisioning is orchestrated in parallel.
    #[arg(long, value_name = "SECS", requires = "setup_key_file")]
    pub wait_for_acl: Option<u64>,

    // ── Re-run safety ─────────────────────────────────────────────────
    /// Allow the wizard to write into a secret backend that already holds
    /// a provisioned mediator. Without this flag the wizard refuses —
    /// rotating live secrets can lock the mediator out of the VTA, and
    /// previously-issued JWTs would stop verifying.
    #[arg(long)]
    pub force_reprovision: bool,

    /// Print the generated admin private key at the end of the run. Only
    /// honoured when stdout is a terminal; the key is always stored in the
    /// secret backend or `admin-monitor.json`.
    #[arg(long)]
    pub show_admin_key: bool,

    /// Tear down a previous setup: load the configured backend, list the
    /// well-known mediator keys it holds, ask for a typed confirmation,
    /// then delete each entry and remove every file the wizard wrote
    /// (from the setup manifest next to the config).
    #[arg(
        long,
        conflicts_with_all = ["from", "non_interactive", "setup_key_file", "bundle", "set"]
    )]
    pub uninstall: bool,
}

impl Args {
    /// The `--config` path, or the default.
    pub fn config_path(&self) -> String {
        self.config
            .clone()
            .unwrap_or_else(|| crate::consts::DEFAULT_CONFIG_PATH.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeploymentType {
    /// Local development (desktop, quick start)
    Local,
    /// Headless server (production, cloud/bare metal)
    Server,
    /// Container (Docker image)
    Container,
}

impl std::fmt::Display for DeploymentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "Local development"),
            Self::Server => write!(f, "Headless server"),
            Self::Container => write!(f, "Container"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Protocol {
    /// DIDComm v2 only (TSP off)
    Didcomm,
    /// TSP — Trust Spanning Protocol, alongside DIDComm (the default)
    Tsp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Didcomm => write!(f, "DIDComm v2"),
            Self::Tsp => write!(f, "TSP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DidMethod {
    /// Generate a did:peer (simplest, no hosting)
    Peer,
    /// Generate a did:webvh (production, requires webvh server)
    Webvh,
    /// Configure via VTA
    Vta,
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Peer => write!(f, "did:peer"),
            Self::Webvh => write!(f, "did:webvh"),
            Self::Vta => write!(f, "VTA managed"),
        }
    }
}

/// Optional extra key suites layered on top of the always-present Ed25519 +
/// X25519 mediator identity keys. Each suite contributes a signing key plus a
/// key-agreement key so the mediator can both authenticate and receive
/// authcrypt traffic on that curve family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeySuite {
    /// NIST P-256 — ES256 signing + ECDH-ES (P-256) key agreement.
    P256,
    /// secp256k1 — ES256K signing + ECDH-ES (secp256k1) key agreement.
    Secp256k1,
}

impl std::fmt::Display for KeySuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256 => write!(f, "p256"),
            Self::Secp256k1 => write!(f, "secp256k1"),
        }
    }
}

/// Secret-store backends accepted on the CLI. `string://` (inline) was
/// removed in the unified-secrets refactor — inline private keys in TOML
/// are unsafe even for CI. `vta://` was never a backend (the VTA is a
/// *source* of keys); pick whichever real store will hold them.
///
/// The flag picks the backend *kind* with its default settings. Any other
/// setting — a custom AWS region, an Azure vault, a Vault endpoint — goes
/// in the full URL: `--set secrets.storage=<url>` or a recipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SecretStorage {
    /// Local file (file://) — dev only. Unencrypted outside a local
    /// deployment needs --allow-plaintext-file.
    File,
    /// OS Keyring (keyring://), service `affinidi-mediator`.
    Keyring,
    /// AWS Secrets Manager (aws_secrets://), us-east-1, namespace `mediator/`.
    Aws,
    /// GCP Secret Manager (gcp_secrets://). Has no default project: pass
    /// `--set secrets.storage=gcp_secrets://<project>/<namespace>`.
    Gcp,
    /// Azure Key Vault (azure_keyvault://). Has no default vault: pass
    /// `--set secrets.storage=azure_keyvault://<vault>`.
    Azure,
    /// HashiCorp Vault KV v2 (vault://). Has no default endpoint: pass
    /// `--set secrets.storage=vault://<host:port>/<mount>`.
    Vault,
    /// Kubernetes Secret (k8s://), Secret `mediator-secrets` in the
    /// ServiceAccount's namespace.
    K8s,
}

impl std::fmt::Display for SecretStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file://"),
            Self::Keyring => write!(f, "keyring://"),
            Self::Aws => write!(f, "aws_secrets://"),
            Self::Gcp => write!(f, "gcp_secrets://"),
            Self::Azure => write!(f, "azure_keyvault://"),
            Self::Vault => write!(f, "vault://"),
            Self::K8s => write!(f, "k8s://"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SslMode {
    /// No SSL — use a TLS-terminating proxy
    None,
    /// Generate self-signed certificates (local dev only)
    SelfSigned,
}

impl std::fmt::Display for SslMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "No SSL (TLS proxy)"),
            Self::SelfSigned => write!(f, "Self-signed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdminMode {
    /// Generate a new admin did:key — separate from any VTA credential
    Generate,
    /// Reuse the VTA-issued credential as the admin identity (VTA flows)
    Vta,
    /// Skip admin DID configuration
    Skip,
}

impl AdminMode {
    /// The recipe's `security.admin` value.
    pub fn recipe_value(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Vta => "vta",
            Self::Skip => "skip",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_storage_renders_url_prefix_for_each_variant() {
        // The flag value becomes the recipe's `secrets.storage` scheme via
        // this Display impl. Each variant must render exactly the URL
        // prefix the recipe parser and the config writer match on.
        assert_eq!(SecretStorage::File.to_string(), "file://");
        assert_eq!(SecretStorage::Keyring.to_string(), "keyring://");
        assert_eq!(SecretStorage::Aws.to_string(), "aws_secrets://");
        assert_eq!(SecretStorage::Gcp.to_string(), "gcp_secrets://");
        assert_eq!(SecretStorage::Azure.to_string(), "azure_keyvault://");
        assert_eq!(SecretStorage::Vault.to_string(), "vault://");
        assert_eq!(SecretStorage::K8s.to_string(), "k8s://");
    }

    #[test]
    fn secret_storage_clap_value_enum_accepts_every_kebab_name() {
        // Regression: clap derives kebab-case names from the variants. If
        // anyone renames them the CLI flag would silently change, breaking
        // CI scripts. Locking the names in.
        use clap::ValueEnum;
        let variants: Vec<_> = SecretStorage::value_variants()
            .iter()
            .map(|v| v.to_possible_value().unwrap().get_name().to_string())
            .collect();
        assert_eq!(
            variants,
            vec!["file", "keyring", "aws", "gcp", "azure", "vault", "k8s"]
        );
    }

    #[test]
    fn clap_definition_is_consistent() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("mediator-setup").chain(args.iter().copied()))
    }

    #[test]
    fn conflicting_and_dangling_flags_are_rejected() {
        // Each of these used to be accepted and silently ignored.
        for bad in [
            &["--digest", "abc"][..],
            &["--bundle", "b.armor"],
            &["--uninstall", "--from", "r.toml"],
            &["--setup-key-out", "k", "--setup-key-file", "k"],
            &["--wait-for-acl", "5"],
            &["--admin", "skip", "--admin-did", "did:key:z6Mk"],
            &["--present-as-scid", "--no-scid-alias"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(parse(&["--from", "r.toml", "--bundle", "b", "--digest", "ab"]).is_ok());
    }

    #[test]
    fn help_documents_exit_codes_without_rustdoc_links() {
        use clap::CommandFactory;
        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("Exit codes:"));
        assert!(!help.contains("[`"), "raw rustdoc link in --help");
        assert!(!help.contains("(planned)"));
    }
}
