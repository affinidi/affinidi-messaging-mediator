//! Build recipe — a declarative TOML file that drives the setup wizard
//! non-interactively. See `examples/mediator-build.toml` for an annotated
//! example and `docs/setup-guide.md` for the full schema.
//!
//! The recipe is the headless interface: `--from <recipe>` loads one,
//! `--set section.key=value` overrides any value, and the per-option CLI
//! flags (`--did-method`, `--secret-storage`, …) are shorthands for recipe
//! keys (see `crate::headless`).
//!
//! **Security:** build recipes never contain secrets. Credentials embedded
//! in URLs (e.g. Redis passwords) are stripped when saving; supply them at
//! runtime through the `DATABASE_URL` environment variable. A recipe does
//! name the secret backend (region, vault, endpoint), so treat it as
//! internal rather than public.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::app::WizardConfig;
use crate::app::{AdminMode, Deployment, DidMethod, SecretScheme, SslMode, VtaMode};
use crate::consts::*;
use crate::ui::labels::label_of;

/// Top-level build recipe.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipe {
    pub deployment: DeploymentSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub secrets: SecretsSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub database: DatabaseSection,
    /// Optional storage backend selector. When `[storage].backend =
    /// "fjall"`, the mediator opens an embedded Fjall database at
    /// `data_dir`; the `[database]` section is ignored. Defaults to
    /// `"redis"`, so existing recipes without `[storage]` continue
    /// to use the legacy Redis path.
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub output: OutputSection,
    #[serde(default)]
    pub install: InstallSection,
    /// VTA-specific inputs previously collected interactively on the
    /// Vta step. Only meaningful when `deployment.use_vta = true`;
    /// individual fields are mode-gated at validation time (e.g.
    /// `context` is required for every sealed mode, `webvh_server`
    /// only for `sealed-mint`).
    #[serde(default, skip_serializing_if = "VtaSection::is_empty")]
    pub vta: VtaSection,
}

/// `[vta]` section — operator inputs for the VTA integration. Split out
/// of `DeploymentSection` because a growing recipe with VTA-specific
/// fields reads more naturally as its own table than a widening
/// `[deployment]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VtaSection {
    /// VTA context ID this mediator lives in. Defaults to `"mediator"`
    /// when absent; operators with multiple mediators against one VTA
    /// should set this explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Optional webvh server id the VTA should pin the minted DID's
    /// `did.jsonl` log to. Only honoured for `vta_mode =
    /// "sealed-mint"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
    /// Optional webvh path / mnemonic the VTA forwards to the chosen
    /// webvh server's `request_uri` call. Pairs with `webvh_server`;
    /// both are sealed-mint-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_path: Option<String>,
}

impl VtaSection {
    fn is_empty(&self) -> bool {
        self.context.is_none() && self.webvh_server.is_none() && self.webvh_path.is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSection {
    /// `local`, `server`, or `container`
    #[serde(rename = "type")]
    pub deployment_type: String,
    /// Any of `"didcomm"`, `"tsp"`, `"didcomm-v1"`. Default
    /// `["didcomm", "tsp"]`.
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
    /// Whether VTA integration is enabled
    #[serde(default)]
    pub use_vta: bool,
    /// VTA connectivity mode:
    ///
    /// - `"sealed-mint"` — air-gapped sealed handoff where the VTA
    ///   mints a *fresh* mediator DID + keys and returns a
    ///   `TemplateBootstrap` bundle. Use for greenfield deployments.
    /// - `"sealed-export"` — air-gapped export of state the VTA has
    ///   already provisioned. Use for migrations and restores.
    /// - `"online"` — live round-trip to a running VTA. Interactive TUI
    ///   only (or the `--setup-key-out` / `--setup-key-file` pair for an
    ///   admin-only credential); `--from` rejects it.
    /// - `"sealed"` — **deprecated** alias for `"sealed-mint"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_mode: Option<String>,
    /// With `"didcomm-v1"` in `protocols`: accept DIDComm v1 forwards
    /// without an authenticated session (stock Credo wallets need it).
    #[serde(default, skip_serializing_if = "is_false")]
    pub didcomm_v1_allow_unauthenticated_forwards: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_protocols() -> Vec<String> {
    // TSP is the preferred transport and rides alongside DIDComm, which it
    // still authenticates over. `protocols = ["didcomm"]` opts out.
    vec!["didcomm".into(), "tsp".into()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// `vta`, `did:peer`, or `did:webvh`. (`import` is rejected: importing
    /// an existing mediator DID is not supported.)
    #[serde(default = "default_did_method")]
    pub did_method: String,
    /// Required when `did_method = "did:webvh"` or `vta_mode =
    /// "sealed-mint"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// Also write a did:web copy of the generated DID document to
    /// `did-web.json`. Only meaningful for did:webvh / VTA-managed webvh
    /// DIDs; ignored otherwise.
    #[serde(default, skip_serializing_if = "is_false")]
    pub save_did_web: bool,
    /// The identity a locally generated did:webvh log is presented as:
    /// `webvh` (default) or `scid`, its did:scid:vh:1 DID. Only meaningful
    /// for `did_method = "did:webvh"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_as: Option<String>,
    /// List the did:scid alias in the generated log's `alsoKnownAs`. Default
    /// `true`; `false` is refused with `present_as = "scid"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scid_also_known_as: Option<bool>,
    /// Extra key suites to mint alongside the mandatory Ed25519 + X25519
    /// pair, e.g. `["p256"]`. Empty by default (Curve25519 only). Applies
    /// to the local `did:peer` / `did:webvh` generators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_key_suites: Vec<String>,
}

fn default_did_method() -> String {
    "vta".into()
}

/// Map recipe `extra_key_suites` strings (e.g. `["p256"]`) to typed
/// [`crate::cli::KeySuite`] values, mirroring the `--key-suite` CLI flag.
/// Case-insensitive; unknown suites are a hard error so a typo in a recipe
/// fails fast instead of silently provisioning Curve25519-only keys.
fn parse_extra_key_suites(raw: &[String]) -> anyhow::Result<Vec<crate::cli::KeySuite>> {
    raw.iter()
        .map(|s| match s.trim().to_ascii_lowercase().as_str() {
            "p256" | "p-256" | "es256" => Ok(crate::cli::KeySuite::P256),
            "secp256k1" | "k256" | "es256k" => Ok(crate::cli::KeySuite::Secp256k1),
            other => anyhow::bail!(
                "Invalid identity.extra_key_suites entry '{other}': supported suites are 'p256', 'secp256k1'"
            ),
        })
        .collect()
}

impl Default for IdentitySection {
    fn default() -> Self {
        Self {
            did_method: default_did_method(),
            public_url: None,
            save_did_web: false,
            present_as: None,
            scid_also_known_as: None,
            extra_key_suites: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsSection {
    /// One of: `file://`, `keyring://`, `aws_secrets://`,
    /// `gcp_secrets://`, `azure_keyvault://`, `vault://`, `k8s://` — a bare
    /// scheme takes that backend's defaults, a full URL sets them. Note:
    /// `string://` (inline) and `vta://` are not accepted — `vta://` was
    /// never a backend (the VTA is a key *source*) and `string://` is
    /// unsafe even for CI.
    #[serde(default = "default_storage")]
    pub storage: String,
    /// Accept an unencrypted `file://` store outside a `local`
    /// deployment. Without it such a recipe is refused: the keys would sit
    /// in plaintext on a server.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_plaintext_file: bool,
}

fn default_storage() -> String {
    "keyring://".into()
}

impl Default for SecretsSection {
    fn default() -> Self {
        Self {
            storage: default_storage(),
            allow_plaintext_file: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySection {
    /// `none`, `self-signed`, or `existing`
    #[serde(default = "default_ssl")]
    pub ssl: String,
    /// Path to existing SSL certificate (when `ssl = "existing"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssl_cert: Option<String>,
    /// Path to existing SSL key (when `ssl = "existing"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssl_key: Option<String>,
    /// The mediator's admin-API identity:
    /// - `generate` (default) — a fresh did:key, separate from any VTA
    ///   credential (the VTA credential stays the mediator↔VTA identity);
    /// - `vta` — reuse the VTA-issued credential's DID (VTA flows only);
    /// - `import` — an existing DID you hold the key for (`admin_did`);
    /// - `skip` — configure later.
    #[serde(default = "default_admin")]
    pub admin: String,
    /// The existing admin DID when `admin = "import"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_did: Option<String>,
    /// JWT signing-secret provisioning mode: `generate` (default) or
    /// `provide`. With `provide`, the wizard records the choice but does
    /// not mint or prompt for a key — the mediator reads it from
    /// `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at startup.
    #[serde(default = "default_jwt_mode")]
    pub jwt_mode: String,
    /// Network posture: `open` or `closed`. Defaults to `open` for a
    /// `local` deployment and `closed` (the shipped template's restrictive
    /// posture) for `server` and `container`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
    /// Browser CORS policy: `none` (default — deny all cross-origin),
    /// `any` (`*`), or `list` (allow [`Self::cors_domains`]).
    #[serde(default = "default_cors")]
    pub cors: String,
    /// Comma-separated CORS origin allowlist, required when `cors =
    /// "list"`. Entries are exact, scheme-qualified origins
    /// (`https://app.affinidi.com`) or leftmost-label sub-domain
    /// wildcards (`https://*.affinidi.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors_domains: Option<String>,
}

fn default_ssl() -> String {
    "none".into()
}

fn default_admin() -> String {
    "generate".into()
}

fn default_jwt_mode() -> String {
    "generate".into()
}

fn default_cors() -> String {
    crate::consts::DEFAULT_CORS_MODE.into()
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            ssl: default_ssl(),
            ssl_cert: None,
            ssl_key: None,
            admin: default_admin(),
            admin_did: None,
            jwt_mode: default_jwt_mode(),
            network_mode: None,
            cors: default_cors(),
            cors_domains: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSection {
    #[serde(default = "default_database_url")]
    pub url: String,
}

fn default_database_url() -> String {
    "redis://127.0.0.1/".into()
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            url: default_database_url(),
        }
    }
}

/// Optional `[storage]` section in the recipe — selects the mediator's
/// storage backend. When omitted, falls back to the legacy `[database]`
/// section (Redis).
///
/// Memory backend is intentionally absent — it's a tests-only backend
/// and shouldn't appear in operator-facing config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    /// `"redis"` or `"fjall"`. Defaults to `"redis"` so existing
    /// recipes without a `[storage]` section continue to work.
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    /// On-disk path for the Fjall data directory. Used only when
    /// `backend = "fjall"`. The mediator creates this directory if it
    /// doesn't exist.
    #[serde(default = "default_fjall_data_dir")]
    pub data_dir: String,
}

fn default_storage_backend() -> String {
    crate::consts::DEFAULT_STORAGE_BACKEND.into()
}

fn default_fjall_data_dir() -> String {
    crate::consts::DEFAULT_FJALL_DATA_DIR.into()
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            data_dir: default_fjall_data_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    /// Path for the generated mediator.toml
    #[serde(default = "default_config_path")]
    pub config_path: String,
    /// Listen address for the mediator (ip:port)
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    /// HTTP prefix all mediator routes nest under (`/mediator/v1/` by
    /// default). Combined with `identity.public_url` when rendering the
    /// did:webvh service endpoints. Empty / `/` means "serve at host
    /// root" — useful when fronting the mediator with a path-rewriting
    /// reverse proxy.
    #[serde(default = "default_api_prefix")]
    pub api_prefix: String,
    /// Reverse-proxy / load-balancer CIDR ranges whose `X-Forwarded-For` the
    /// mediator trusts for per-IP rate limiting (`[server] trust_xff_cidrs`).
    /// Empty (default) = header ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_xff_cidrs: Vec<String>,
    /// Optional target to publish the minted public DID string to after
    /// provisioning (`aws_parameter_store://<name>[?region=<region>]` or
    /// `file://<path>`). `None` (default) = don't publish.
    ///
    /// Only the `aws_parameter_store://` form round-trips: it is exactly what
    /// `mediator.toml`'s `mediator_did` accepts, so the published target can be
    /// pasted across verbatim. The runtime cannot read `mediator_did` from a
    /// file, so a `file://` target serves out-of-band consumers (a relying
    /// party, a CI step, an operator) — to use its contents in `mediator.toml`,
    /// paste the DID itself as `did://<did>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_target: Option<String>,
    /// Optional target to publish the minted did:webvh log document
    /// (`did.jsonl` content) to after provisioning
    /// (`s3://<bucket>/<key>[?region=<region>]`,
    /// `aws_parameter_store://<name>[?region=<region>]`, or `file://<path>`).
    /// `None` (default) = don't publish.
    ///
    /// All three forms round-trip into the runtime's `did_web_self_hosted`,
    /// which reads a DID *document* (`read_document`) — and when the
    /// deployment self-hosts its log, the generated mediator.toml points
    /// `did_web_self_hosted` at this same target automatically, so the
    /// runtime reads the published copy rather than the local `did.jsonl`
    /// that dies with a one-shot setup task. `s3://` is the intended target
    /// for a self-hosted mediator on ephemeral compute: the log grows with
    /// each key rotation (did:webvh v1.0 embeds the full document per entry
    /// — no JSON Patch), so it can outgrow Parameter Store's value-size
    /// limit; S3 has no such ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log_target: Option<String>,
}

fn default_config_path() -> String {
    "conf/mediator.toml".into()
}

fn default_listen_address() -> String {
    "0.0.0.0:7037".into()
}

fn default_api_prefix() -> String {
    crate::consts::DEFAULT_API_PREFIX.into()
}

impl Default for OutputSection {
    fn default() -> Self {
        Self {
            config_path: default_config_path(),
            listen_address: default_listen_address(),
            api_prefix: default_api_prefix(),
            trust_xff_cidrs: Vec::new(),
            did_target: None,
            did_log_target: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InstallSection {
    /// Whether to run `cargo install` after generating config
    #[serde(default)]
    pub enabled: bool,
    /// Custom install root (passed as `cargo install --root <path>`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Normalise a raw `vta_mode` string from a recipe into the canonical
/// values the wizard code uses ([`VTA_MODE_ONLINE`] /
/// [`VTA_MODE_SEALED_MINT`] / [`VTA_MODE_SEALED_EXPORT`]).
///
/// `None` and empty strings return `None` — `to_wizard_config` then runs
/// its legacy auto-detect path (did_method=vta → ONLINE). A deprecated
/// `"sealed"` is silently rewritten to `sealed-mint` because every
/// pre-split recipe used the single value for the mint case.
fn normalise_vta_mode(raw: Option<&str>) -> anyhow::Result<Option<VtaMode>> {
    let trimmed = raw.unwrap_or("").trim();
    Ok(match trimmed {
        "" => None,
        VTA_MODE_ONLINE => Some(VtaMode::Online),
        VTA_MODE_SEALED_MINT => Some(VtaMode::SealedMint),
        VTA_MODE_SEALED_EXPORT => Some(VtaMode::SealedExport),
        // Backward compat: pre-split recipes wrote `"sealed"` to
        // mean what's now `"sealed-mint"`. Accept silently —
        // nobody's written `"sealed"` to mean anything else.
        VTA_MODE_SEALED_LEGACY => Some(VtaMode::SealedMint),
        other => anyhow::bail!(
            "Invalid deployment.vta_mode '{other}': expected one of '{VTA_MODE_ONLINE}', '{VTA_MODE_SEALED_MINT}', '{VTA_MODE_SEALED_EXPORT}' \
             (or legacy '{VTA_MODE_SEALED_LEGACY}' which maps to '{VTA_MODE_SEALED_MINT}')",
        ),
    })
}

/// Load a build recipe from a TOML file.
#[cfg(test)]
pub fn load(path: &str) -> anyhow::Result<BuildRecipe> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read build recipe '{path}': {e}"))?;
    let recipe: BuildRecipe = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Invalid build recipe '{path}': {e}"))?;
    Ok(recipe)
}

/// Whether `did` has the `did:<method>:<id>` shape.
pub fn looks_like_did(did: &str) -> bool {
    let mut parts = did.splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("did"), Some(method), Some(id))
            if !method.is_empty()
                && method.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && !id.is_empty()
                && !id.chars().any(char::is_whitespace)
    )
}

/// Convert a build recipe into a WizardConfig.
pub fn to_wizard_config(recipe: &BuildRecipe) -> anyhow::Result<WizardConfig> {
    // Initialise `deployment_type` via struct-update so the function
    // does not trip `clippy::field_reassign_with_default` on the very
    // first assignment.
    let deployment_type = match recipe.deployment.deployment_type.as_str() {
        "local" => Some(Deployment::Local),
        "server" => Some(Deployment::Server),
        "container" => Some(Deployment::Container),
        other => anyhow::bail!(
            "Invalid deployment.type '{other}': expected 'local', 'server', or 'container'"
        ),
    };
    let mut config = WizardConfig {
        deployment_type,
        ..WizardConfig::default()
    };

    // VTA integration
    config.use_vta = recipe.deployment.use_vta;
    config.vta_mode = normalise_vta_mode(recipe.deployment.vta_mode.as_deref())?;

    // Auto-detect: if recipe uses VTA-managed DID but use_vta is missing
    // (backward compat). Note: `secrets.storage = "vta://"` is no longer
    // recognised — VTA is a *source* of keys, not a storage backend.
    if !config.use_vta && recipe.identity.did_method == "vta" {
        config.use_vta = true;
        if config.vta_mode.is_none() {
            config.vta_mode = Some(VtaMode::Online);
        }
    }

    // [vta] section — `context` defaults to `DEFAULT_VTA_CONTEXT`
    // (`"mediator"`) when absent; webvh_server / webvh_path stay `None`.
    config.vta_context = recipe
        .vta
        .context
        .clone()
        .unwrap_or_else(|| DEFAULT_VTA_CONTEXT.into());
    config.vta_webvh_server_id = recipe.vta.webvh_server.clone();
    config.vta_webvh_path = recipe.vta.webvh_path.clone();

    // Mode-specific validation: `sealed-mint` mints a new DID on the
    // VTA whose template requires a `URL` — identity.public_url must
    // therefore be present.
    if config.use_vta
        && config.vta_mode == Some(VtaMode::SealedMint)
        && recipe
            .identity
            .public_url
            .as_deref()
            .is_none_or(str::is_empty)
    {
        anyhow::bail!(
            "vta_mode = \"sealed-mint\" requires identity.public_url — \
             the VTA's didcomm-mediator template renders the mediator DID \
             using this URL."
        );
    }

    // Protocols
    config.didcomm_enabled = false;
    config.tsp_enabled = false;
    config.didcomm_v1_enabled = false;
    for proto in &recipe.deployment.protocols {
        match proto.as_str() {
            "didcomm" => config.didcomm_enabled = true,
            "tsp" => config.tsp_enabled = true,
            // Additive over v2.1 and dependent on it: the mediator's
            // `didcomm-v1` Cargo feature implies `didcomm`, and the v1 routing
            // identity is derived from the same Ed25519 authentication key.
            "didcomm-v1" => {
                config.didcomm_v1_enabled = true;
                config.didcomm_enabled = true;
            }
            other => anyhow::bail!(
                "Invalid protocol '{other}': expected 'didcomm', 'didcomm-v1' or 'tsp'"
            ),
        }
    }
    if !config.didcomm_enabled && !config.tsp_enabled {
        anyhow::bail!("At least one protocol must be enabled (didcomm or tsp)");
    }
    if recipe.deployment.didcomm_v1_allow_unauthenticated_forwards && !config.didcomm_v1_enabled {
        anyhow::bail!(
            "deployment.didcomm_v1_allow_unauthenticated_forwards needs \"didcomm-v1\" in \
             deployment.protocols"
        );
    }
    config.didcomm_v1_allow_unauthenticated_forwards =
        recipe.deployment.didcomm_v1_allow_unauthenticated_forwards;

    // DID method
    config.did_method = match recipe.identity.did_method.as_str() {
        "vta" => Some(DidMethod::Vta),
        "did:peer" | "peer" => Some(DidMethod::Peer),
        "did:webvh" | "webvh" => Some(DidMethod::Webvh),
        "import" => {
            return Err(crate::exit::error(
                crate::exit::IMPORT_WITHOUT_DATA,
                "identity.did_method = \"import\" is not supported: the wizard cannot import \
                 an existing mediator DID and its keys. Use \"did:peer\", \"did:webvh\", or \
                 \"vta\" (with a sealed-export recipe to pick up a DID the VTA already holds).",
            ));
        }
        other => anyhow::bail!(
            "Invalid identity.did_method '{other}': expected 'vta', 'did:peer', or 'did:webvh'"
        ),
    };

    if config.did_method == Some(DidMethod::Webvh) {
        config.public_url = recipe
            .identity
            .public_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("identity.public_url is required when did_method = 'did:webvh'")
            })?;
    } else if let Some(ref url) = recipe.identity.public_url {
        config.public_url = url.clone();
    }
    config.save_did_web = recipe.identity.save_did_web;
    config.present_as_scid = match recipe.identity.present_as.as_deref() {
        None | Some("webvh") | Some("did:webvh") => false,
        Some("scid") | Some("did:scid") => true,
        Some(other) => {
            anyhow::bail!("Invalid identity.present_as '{other}': expected 'webvh' or 'scid'")
        }
    };
    config.scid_also_known_as = recipe.identity.scid_also_known_as.unwrap_or(true);
    if config.present_as_scid && config.did_method != Some(DidMethod::Webvh) {
        anyhow::bail!(
            "identity.present_as = 'scid' applies to did_method = 'did:webvh' (a locally \
             generated log)"
        );
    }
    if config.present_as_scid && !config.scid_also_known_as {
        anyhow::bail!(
            "identity.present_as = 'scid' needs the did:scid alias: \
             scid_also_known_as cannot be false"
        );
    }
    config.key_suite = parse_extra_key_suites(&recipe.identity.extra_key_suites)?;

    // Secrets — accept either the bare scheme or a fully-formed URL. A full
    // URL gets parsed into per-backend fields so re-running the wizard from
    // a recipe restores region / project / vault / endpoint.
    apply_secrets_storage(&recipe.secrets.storage, &mut config)?;
    check_backend_settings(&config)?;
    config.allow_plaintext_file = recipe.secrets.allow_plaintext_file;
    check_plaintext_file(&config)?;

    // Security
    config.ssl_mode = match recipe.security.ssl.as_str() {
        "none" => Some(SslMode::None),
        "self-signed" | "self_signed" => Some(SslMode::SelfSigned),
        "existing" => {
            config.ssl_cert_path = recipe.security.ssl_cert.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_cert is required when ssl = 'existing'")
            })?;
            config.ssl_key_path = recipe.security.ssl_key.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_key is required when ssl = 'existing'")
            })?;
            Some(SslMode::Existing)
        }
        other => anyhow::bail!(
            "Invalid security.ssl '{other}': expected 'none', 'self-signed', or 'existing'"
        ),
    };

    config.admin_did_mode = match recipe.security.admin.as_str() {
        "generate" => Some(AdminMode::Generate),
        "skip" => Some(AdminMode::Skip),
        "vta" => {
            if !config.use_vta {
                anyhow::bail!(
                    "security.admin = \"vta\" reuses the VTA-issued credential, so it needs a \
                     VTA deployment (deployment.use_vta = true)"
                );
            }
            Some(AdminMode::Vta)
        }
        "import" => {
            let did = recipe
                .security
                .admin_did
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .ok_or_else(|| {
                    crate::exit::error(
                        crate::exit::IMPORT_WITHOUT_DATA,
                        "security.admin = \"import\" needs security.admin_did — the DID that \
                         will administer the mediator (--admin-did on the command line)",
                    )
                })?;
            if !looks_like_did(did) {
                anyhow::bail!(
                    "security.admin_did '{did}' is not a DID (expected did:<method>:<id>)"
                );
            }
            config.admin_did = did.to_string();
            Some(AdminMode::Paste)
        }
        other => anyhow::bail!(
            "Invalid security.admin '{other}': expected 'generate', 'vta', 'import', or 'skip'"
        ),
    };
    if config.admin_did_mode != Some(AdminMode::Paste) && recipe.security.admin_did.is_some() {
        anyhow::bail!(
            "security.admin_did is only read with security.admin = \"import\" (admin is \"{}\")",
            recipe.security.admin
        );
    }

    config.jwt_mode = match recipe.security.jwt_mode.as_str() {
        "generate" | "" => JWT_MODE_GENERATE.into(),
        "provide" => JWT_MODE_PROVIDE.into(),
        other => {
            anyhow::bail!("Invalid security.jwt_mode '{other}': expected 'generate' or 'provide'")
        }
    };

    config.network_mode = match recipe.security.network_mode.as_deref() {
        None | Some("") => default_network_mode_for(config.deployment_type).into(),
        Some(NETWORK_MODE_OPEN) => NETWORK_MODE_OPEN.into(),
        Some(NETWORK_MODE_CLOSED) => NETWORK_MODE_CLOSED.into(),
        Some(other) => {
            anyhow::bail!("Invalid security.network_mode '{other}': expected 'open' or 'closed'")
        }
    };

    config.cors_mode = match recipe.security.cors.as_str() {
        CORS_MODE_NONE | "" => CORS_MODE_NONE.into(),
        CORS_MODE_ANY => CORS_MODE_ANY.into(),
        CORS_MODE_LIST => {
            // `list` is only meaningful with an allowlist — validate it
            // here (same syntax the TUI enforces) so a bad recipe fails
            // fast rather than emitting a config the mediator rejects.
            let domains = recipe.security.cors_domains.clone().ok_or_else(|| {
                anyhow::anyhow!("security.cors_domains is required when cors = 'list'")
            })?;
            config.cors_domains = crate::app::validate_cors_domains(&domains)
                .map_err(|e| anyhow::anyhow!("Invalid security.cors_domains: {e}"))?;
            CORS_MODE_LIST.into()
        }
        other => {
            anyhow::bail!("Invalid security.cors '{other}': expected 'none', 'any', or 'list'")
        }
    };

    // Database
    config.database_url = recipe.database.url.clone();

    // Storage backend selector. Validate the choice up-front so a
    // typo in the recipe surfaces here rather than at mediator
    // startup. `memory` is intentionally rejected — it's a tests-
    // only backend.
    match recipe.storage.backend.as_str() {
        STORAGE_BACKEND_REDIS => config.storage_backend = STORAGE_BACKEND_REDIS.into(),
        STORAGE_BACKEND_FJALL => {
            config.storage_backend = STORAGE_BACKEND_FJALL.into();
            config.fjall_data_dir = recipe.storage.data_dir.clone();
        }
        other => {
            return Err(anyhow::anyhow!(
                "Invalid storage.backend '{other}': expected 'redis' or 'fjall'"
            ));
        }
    }

    // Output
    config.config_path = recipe.output.config_path.clone();
    config.listen_address = recipe.output.listen_address.clone();
    config.api_prefix = recipe.output.api_prefix.clone();
    let trust_xff_cidrs = recipe
        .output
        .trust_xff_cidrs
        .iter()
        .map(|cidr| {
            cidr.parse::<ipnet::IpNet>().map_err(|e| {
                anyhow::anyhow!("invalid [output].trust_xff_cidrs entry '{cidr}': {e}")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    affinidi_messaging_mediator_config::validate::check_trust_xff_cidrs(&trust_xff_cidrs)
        .map_err(|e| anyhow::anyhow!("[output].trust_xff_cidrs: {e}"))?;
    config.trust_xff_cidrs = recipe.output.trust_xff_cidrs.clone();
    config.did_target = recipe.output.did_target.clone();
    config.did_log_target = recipe.output.did_log_target.clone();

    // Validate the publish targets' schemes now, at recipe load, so a bad
    // target fails before anything is minted, provisioned, or written.
    if let Some(target) = &config.did_target {
        crate::publish::validate_target(target)
            .map_err(|e| anyhow::anyhow!("invalid [output].did_target: {e}"))?;
    }
    if let Some(target) = &config.did_log_target {
        crate::publish::validate_target(target)
            .map_err(|e| anyhow::anyhow!("invalid [output].did_log_target: {e}"))?;
    }

    Ok(config)
}

/// Refuse backend URLs whose required setting is still empty — the bare
/// `gcp_secrets://`, `azure_keyvault://` and `vault://` schemes have no
/// usable default and would otherwise produce `gcp_secrets:///mediator-`
/// and friends.
pub(crate) fn check_backend_settings(config: &WizardConfig) -> anyhow::Result<()> {
    let missing = match config.secret_storage {
        Some(SecretScheme::Gcp) if config.secret_gcp_project.trim().is_empty() => {
            Some(("a GCP project", "gcp_secrets://<project>/mediator-"))
        }
        Some(SecretScheme::Azure) if config.secret_azure_vault.trim().is_empty() => {
            Some(("an Azure Key Vault name", "azure_keyvault://<vault-name>"))
        }
        Some(SecretScheme::Vault) if config.secret_vault_endpoint.trim().is_empty() => {
            Some(("a Vault endpoint", "vault://<host:port>/secret/mediator"))
        }
        _ => None,
    };
    if let Some((what, example)) = missing {
        anyhow::bail!(
            "secrets.storage = \"{}\" needs {what}, which has no default. Give the full URL: \
             `--set secrets.storage={example}` or `storage = \"{example}\"` in the recipe.",
            label_of(config.secret_storage, SecretScheme::prefix)
        );
    }
    Ok(())
}

/// The TUI makes an operator type a confirmation phrase before keys go into
/// a plaintext `file://` store; a headless run needs the same explicit
/// opt-in outside a local deployment.
pub(crate) fn check_plaintext_file(config: &WizardConfig) -> anyhow::Result<()> {
    if config.secret_storage == Some(SecretScheme::File)
        && !config.secret_file_encrypted
        && config.deployment_type != Some(Deployment::Local)
        && !config.allow_plaintext_file
    {
        anyhow::bail!(
            "secrets.storage = \"file://…\" without ?encrypt=1 keeps every mediator key in \
             plaintext on disk, and this is a {} deployment. Use an encrypted store \
             (file://…?encrypt=1 with MEDIATOR_FILE_BACKEND_PASSPHRASE, or a secret manager), \
             or accept it explicitly: `allow_plaintext_file = true` under [secrets] \
             (--allow-plaintext-file).",
            label_of(config.deployment_type, Deployment::label).to_lowercase()
        );
    }
    Ok(())
}

/// Strip credentials from a URL, replacing them with a placeholder.
/// Returns the redacted URL and whether any credentials were found.
///
/// Examples:
///   `redis://:password@host/` → `redis://host/` (credentials stripped)
///   `redis://user:pass@host/` → `redis://host/` (credentials stripped)
///   `redis://127.0.0.1/`      → `redis://127.0.0.1/` (unchanged)
fn redact_url(raw: &str) -> (String, bool) {
    match Url::parse(raw) {
        Ok(mut url) => {
            let had_credentials = !url.username().is_empty() || url.password().is_some();
            if had_credentials {
                let _ = url.set_username("");
                let _ = url.set_password(None);
            }
            (url.to_string(), had_credentials)
        }
        Err(_) => (raw.to_string(), false),
    }
}

/// Check if a database URL needs credentials to be supplied at runtime.
/// Returns true if the URL has a placeholder or if the recipe was saved
/// with credentials stripped.
pub fn needs_database_credentials(url: &str) -> bool {
    url.contains("<") || url.contains("${") || url.contains("$DATABASE")
}

/// The recipe's `secrets.storage` value for `config`. The same URL the
/// mediator gets, except that a `file://` path is kept as the operator gave
/// it (usually relative) rather than resolved against this host's working
/// directory, so the recipe reproduces the setup elsewhere.
fn recipe_storage_url(config: &WizardConfig) -> String {
    if config.secret_storage == Some(SecretScheme::File) {
        let path = config.secret_file_path.trim();
        let path = path.strip_prefix("file://").unwrap_or(path);
        if config.secret_file_encrypted {
            format!("file://{path}?encrypt=1")
        } else {
            format!("file://{path}")
        }
    } else {
        crate::config_writer::build_backend_url(config)
    }
}

/// Project a wizard configuration onto the recipe schema — the inverse of
/// [`to_wizard_config`] for every value a recipe can carry.
pub fn to_recipe(config: &WizardConfig) -> BuildRecipe {
    let deployment_type = config
        .deployment_type
        .map_or("local", Deployment::recipe_value);
    let mut protocols = Vec::new();
    if config.didcomm_enabled {
        protocols.push("didcomm".to_string());
    }
    if config.tsp_enabled {
        protocols.push("tsp".to_string());
    }
    if config.didcomm_v1_enabled {
        protocols.push("didcomm-v1".to_string());
    }

    let vta = if config.use_vta {
        VtaSection {
            context: (!config.vta_context.is_empty() && config.vta_context != DEFAULT_VTA_CONTEXT)
                .then(|| config.vta_context.clone()),
            webvh_server: config.vta_webvh_server_id.clone(),
            webvh_path: config.vta_webvh_path.clone(),
        }
    } else {
        VtaSection::default()
    };

    let did_method = config.did_method.map_or("vta", DidMethod::recipe_value);
    let ssl = config.ssl_mode.map_or("none", SslMode::recipe_value);
    let admin = config
        .admin_did_mode
        .map_or("generate", AdminMode::recipe_value);
    let cors = match config.cors_mode.as_str() {
        CORS_MODE_ANY => CORS_MODE_ANY,
        CORS_MODE_LIST => CORS_MODE_LIST,
        _ => CORS_MODE_NONE,
    };
    let network_mode = match config.network_mode.as_str() {
        NETWORK_MODE_CLOSED => NETWORK_MODE_CLOSED,
        _ => NETWORK_MODE_OPEN,
    };

    BuildRecipe {
        deployment: DeploymentSection {
            deployment_type: deployment_type.into(),
            protocols,
            use_vta: config.use_vta,
            vta_mode: config
                .vta_mode
                .filter(|_| config.use_vta)
                .map(|mode| mode.as_str().to_string()),
            didcomm_v1_allow_unauthenticated_forwards: config.didcomm_v1_enabled
                && config.didcomm_v1_allow_unauthenticated_forwards,
        },
        identity: IdentitySection {
            did_method: did_method.into(),
            public_url: (!config.public_url.is_empty()).then(|| config.public_url.clone()),
            save_did_web: config.save_did_web,
            present_as: config.present_as_scid.then(|| "scid".to_string()),
            scid_also_known_as: (!config.scid_also_known_as).then_some(false),
            extra_key_suites: config.key_suite.iter().map(|s| s.to_string()).collect(),
        },
        secrets: SecretsSection {
            storage: recipe_storage_url(config),
            allow_plaintext_file: config.secret_storage == Some(SecretScheme::File)
                && !config.secret_file_encrypted
                && config.allow_plaintext_file,
        },
        security: SecuritySection {
            ssl: ssl.into(),
            ssl_cert: (ssl == "existing").then(|| config.ssl_cert_path.clone()),
            ssl_key: (ssl == "existing").then(|| config.ssl_key_path.clone()),
            admin: admin.into(),
            admin_did: (admin == "import").then(|| config.admin_did.clone()),
            jwt_mode: if config.jwt_mode == JWT_MODE_PROVIDE {
                "provide".into()
            } else {
                "generate".into()
            },
            network_mode: Some(network_mode.into()),
            cors: cors.into(),
            cors_domains: (cors == CORS_MODE_LIST).then(|| config.cors_domains.clone()),
        },
        database: DatabaseSection {
            url: redact_url(&config.database_url).0,
        },
        storage: StorageSection {
            backend: if config.storage_backend == STORAGE_BACKEND_FJALL {
                STORAGE_BACKEND_FJALL.into()
            } else {
                STORAGE_BACKEND_REDIS.into()
            },
            data_dir: config.fjall_data_dir.clone(),
        },
        output: OutputSection {
            config_path: config.config_path.clone(),
            listen_address: config.listen_address.clone(),
            api_prefix: config.api_prefix.clone(),
            trust_xff_cidrs: config.trust_xff_cidrs.clone(),
            did_target: config.did_target.clone(),
            did_log_target: config.did_log_target.clone(),
        },
        install: InstallSection::default(),
        vta,
    }
}

/// Generate a build recipe TOML string from the wizard config, so
/// `mediator-setup --from <file>` reproduces the same setup.
///
/// Serialised from the same [`BuildRecipe`] structs `--from` parses, so a
/// saved recipe always loads, and values are TOML-escaped. Credentials are
/// stripped from URLs.
pub fn from_wizard_config(config: &WizardConfig) -> String {
    let mut out = String::new();
    out.push_str("# Mediator Build Recipe\n");
    out.push_str("# Generated by mediator-setup — rerun with: mediator-setup --from <this-file>\n");
    out.push_str("#\n");
    out.push_str("# No secrets, passwords, or private keys are stored here. It does name the\n");
    out.push_str("# secret backend (region / vault / endpoint), so keep it internal.\n");
    if redact_url(&config.database_url).1 {
        out.push_str("#\n");
        out.push_str("# NOTE: Credentials were stripped from [database].url for security.\n");
        out.push_str("# Set the DATABASE_URL env var or update that value before running.\n");
    }
    out.push('\n');
    match toml::to_string(&to_recipe(config)) {
        Ok(body) => out.push_str(&body),
        // The recipe types are plain strings, bools and lists; serialising
        // them cannot fail. Keep the header rather than panic if it ever does.
        Err(e) => out.push_str(&format!("# could not serialise the recipe: {e}\n")),
    }
    out
}

/// Apply a recipe's `secrets.storage` value to a [`WizardConfig`].
///
/// Accepts both the bare scheme (backward compat with pre-cloud-config
/// recipes — e.g. `aws_secrets://` with no body) and a fully-formed URL
/// (`aws_secrets://us-east-1/mediator/`). Full URLs are parsed via
/// `mediator-common`'s [`affinidi_messaging_mediator_common::parse_url`](affinidi_messaging_mediator_common::secrets::parse_url)
/// and the per-backend fields (region / project / vault / endpoint /
/// mount) are populated so a recipe replay restores the operator's full
/// choice without re-prompting.
///
/// Deprecated schemes (`string://`, `vta://`) error with a pointer to
/// the supported alternative.
pub(crate) fn apply_secrets_storage(raw: &str, config: &mut WizardConfig) -> anyhow::Result<()> {
    // Bare scheme (no body) — preserve the pre-cloud-config behaviour:
    // set `secret_storage` to the scheme, leave per-backend fields at
    // their wizard defaults. Operators upgrading from older recipes
    // see no surprise change.
    let bare_schemes = [
        SecretScheme::File,
        SecretScheme::Keyring,
        SecretScheme::Aws,
        SecretScheme::Gcp,
        SecretScheme::Azure,
        SecretScheme::Vault,
        SecretScheme::K8s,
    ];
    if let Some(&scheme) = bare_schemes.iter().find(|s| raw == s.prefix()) {
        config.secret_storage = Some(scheme);
        return Ok(());
    }

    // A relative `file://` path (`file://conf/secrets.json`) — what a saved
    // recipe holds, so it reproduces on another host. The shared URL parser
    // only takes absolute paths (it would read `conf` as a host); the
    // wizard resolves a relative path against its working directory.
    if let Some(rest) = raw.strip_prefix(STORAGE_FILE)
        && !rest.is_empty()
        && !rest.starts_with('/')
    {
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut encrypted = false;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some(("encrypt", v)) => encrypted = matches!(v, "1" | "true" | "yes" | "on"),
                _ => anyhow::bail!(
                    "Invalid secrets.storage '{raw}': unknown query parameter '{pair}' on file:// \
                     (only ?encrypt=1)"
                ),
            }
        }
        config.secret_storage = Some(SecretScheme::File);
        config.secret_file_path = path.to_string();
        config.secret_file_encrypted = encrypted;
        return Ok(());
    }

    // Deprecated schemes — match before parse_url so the operator-facing
    // message points at the right replacement rather than a generic
    // parse error.
    if raw.starts_with(STORAGE_STRING) {
        anyhow::bail!(
            "secrets.storage '{raw}' is no longer supported — use '{STORAGE_FILE}' (with optional encryption) instead"
        );
    }
    if raw.starts_with(STORAGE_VTA) {
        anyhow::bail!(
            "secrets.storage '{raw}' is no longer supported — VTA is a key source, not a backend; choose a real store ({STORAGE_KEYRING}, {STORAGE_AWS}, …)"
        );
    }

    // Full URL — let the shared parser handle each scheme's body and
    // surface its diagnostics verbatim. Splitting per-backend fields
    // here mirrors the wizard's own `enter_key_storage_phase` chain.
    use affinidi_messaging_mediator_common::secrets::{BackendUrl, VaultAuth, parse_url};
    let parsed = parse_url(raw).map_err(|e| {
        anyhow::anyhow!(
            "Invalid secrets.storage '{raw}': {e} (expected one of {STORAGE_FILE}, {STORAGE_KEYRING}, {STORAGE_AWS}, {STORAGE_GCP}, {STORAGE_AZURE}, {STORAGE_VAULT}, {STORAGE_K8S})",
        )
    })?;
    match parsed {
        BackendUrl::File { path, encrypted } => {
            config.secret_storage = Some(SecretScheme::File);
            config.secret_file_path = path;
            config.secret_file_encrypted = encrypted;
        }
        BackendUrl::Keyring { service } => {
            config.secret_storage = Some(SecretScheme::Keyring);
            config.secret_keyring_service = service;
        }
        BackendUrl::Aws { region, namespace } => {
            config.secret_storage = Some(SecretScheme::Aws);
            config.secret_aws_region = region;
            config.secret_aws_namespace = namespace;
        }
        BackendUrl::Gcp { project, namespace } => {
            config.secret_storage = Some(SecretScheme::Gcp);
            config.secret_gcp_project = project;
            config.secret_gcp_namespace = namespace;
        }
        BackendUrl::Azure { vault } => {
            config.secret_storage = Some(SecretScheme::Azure);
            // The mediator-common parser canonicalises bare names to
            // `https://<name>.vault.azure.net`. Round-tripping the full
            // URL is fine — it stays canonical when re-parsed.
            config.secret_azure_vault = vault;
        }
        BackendUrl::Vault {
            endpoint,
            path,
            auth,
            enterprise_namespace,
            insecure,
            ca_cert,
        } => {
            config.secret_storage = Some(SecretScheme::Vault);
            config.secret_vault_endpoint = endpoint;
            config.secret_vault_mount = path;
            match auth {
                VaultAuth::Token => config.secret_vault_auth = "token".into(),
                VaultAuth::Kubernetes {
                    role,
                    mount,
                    jwt_path,
                } => {
                    config.secret_vault_auth = "kubernetes".into();
                    config.secret_vault_role = role;
                    config.secret_vault_k8s_mount = mount;
                    config.secret_vault_jwt_path = jwt_path;
                }
                VaultAuth::AppRole { mount } => {
                    config.secret_vault_auth = "approle".into();
                    config.secret_vault_approle_mount = mount;
                }
            }
            config.secret_vault_namespace = enterprise_namespace.unwrap_or_default();
            config.secret_vault_insecure = insecure;
            config.secret_vault_ca_cert = ca_cert.unwrap_or_default();
        }
        BackendUrl::Kubernetes {
            namespace,
            secret_name,
        } => {
            config.secret_storage = Some(SecretScheme::K8s);
            config.secret_k8s_namespace = namespace.unwrap_or_default();
            config.secret_k8s_secret_name = secret_name;
        }
        // `BackendUrl` is `#[non_exhaustive]`; a variant with no wizard
        // mapping yet falls through here.
        _ => {
            anyhow::bail!(
                "Invalid secrets.storage '{raw}': backend not yet supported in recipe config"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_url_no_credentials() {
        let (url, had) = redact_url("redis://127.0.0.1/");
        assert_eq!(url, "redis://127.0.0.1/");
        assert!(!had);
    }

    #[test]
    fn test_redact_url_password_only() {
        let (url, had) = redact_url("redis://:secret@host:6379/");
        assert!(!url.contains("secret"));
        assert!(url.contains("host:6379"));
        assert!(had);
    }

    #[test]
    fn test_redact_url_user_and_password() {
        let (url, had) = redact_url("redis://admin:s3cret@db.example.com:6379/2");
        assert!(!url.contains("admin"));
        assert!(!url.contains("s3cret"));
        assert!(url.contains("db.example.com"));
        assert!(url.contains("/2"));
        assert!(had);
    }

    #[test]
    fn test_recipe_strips_credentials() {
        let config = WizardConfig {
            database_url: "redis://user:p4ssw0rd@prod-redis.example.com:6379/1".into(),
            ..WizardConfig::default()
        };
        let recipe = from_wizard_config(&config);
        assert!(!recipe.contains("p4ssw0rd"), "password leaked into recipe");
        assert!(!recipe.contains("user:"), "username leaked into recipe");
        assert!(recipe.contains("prod-redis.example.com"));
        assert!(recipe.contains("Credentials were stripped"));
    }

    // ── needs_database_credentials ─────────────────────────────────────

    #[test]
    fn test_needs_credentials_placeholders() {
        assert!(needs_database_credentials("redis://<host>:6379/"));
        assert!(needs_database_credentials("redis://${DB_HOST}/"));
        assert!(needs_database_credentials("$DATABASE_URL"));
    }

    #[test]
    fn test_needs_credentials_normal_url() {
        assert!(!needs_database_credentials("redis://127.0.0.1/"));
        assert!(!needs_database_credentials("redis://prod-host:6379/2"));
    }

    // ── to_wizard_config validation ────────────────────────────────────

    fn minimal_recipe() -> BuildRecipe {
        BuildRecipe {
            deployment: DeploymentSection {
                deployment_type: "local".into(),
                protocols: vec!["didcomm".into()],
                use_vta: false,
                vta_mode: None,
                didcomm_v1_allow_unauthenticated_forwards: false,
            },
            identity: IdentitySection::default(),
            secrets: SecretsSection::default(),
            security: SecuritySection::default(),
            database: DatabaseSection::default(),
            storage: StorageSection::default(),
            output: OutputSection::default(),
            install: InstallSection::default(),
            vta: VtaSection::default(),
        }
    }

    #[test]
    fn test_valid_recipe_converts() {
        let config = to_wizard_config(&minimal_recipe()).unwrap();
        assert_eq!(config.deployment_type, Some(Deployment::Local));
        assert!(config.didcomm_enabled);
        assert!(!config.tsp_enabled);
        assert_eq!(config.did_method, Some(DidMethod::Vta));
        // Default backend is now keyring:// (vta:// rejected as a store).
        assert_eq!(config.secret_storage, Some(SecretScheme::Keyring));
    }

    #[test]
    fn test_all_deployment_types() {
        for (input, expected) in [
            ("local", Some(Deployment::Local)),
            ("server", Some(Deployment::Server)),
            ("container", Some(Deployment::Container)),
        ] {
            let mut recipe = minimal_recipe();
            recipe.deployment.deployment_type = input.into();
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.deployment_type, expected);
        }
    }

    #[test]
    fn test_trust_xff_cidrs_are_validated() {
        let mut recipe = minimal_recipe();
        recipe.output.trust_xff_cidrs = vec!["10.0.0.0/8".into(), "::1/128".into()];
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.trust_xff_cidrs, ["10.0.0.0/8", "::1/128"]);

        recipe.output.trust_xff_cidrs = vec!["10.0.0.0/8".into(), "nope".into()];
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");

        recipe.output.trust_xff_cidrs = vec!["0.0.0.0/0".into()];
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(err.contains("0.0.0.0/0"), "{err}");
    }

    #[test]
    fn test_invalid_deployment_type_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.deployment_type = "cloud".into();
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn network_mode_default_follows_the_deployment_type() {
        // An unset network_mode is open for local development and the
        // template's restrictive (closed) posture for production types.
        for (ty, expected) in [
            ("local", crate::consts::NETWORK_MODE_OPEN),
            ("server", crate::consts::NETWORK_MODE_CLOSED),
            ("container", crate::consts::NETWORK_MODE_CLOSED),
        ] {
            let recipe_toml = format!(
                "[deployment]\ntype = \"{ty}\"\nprotocols = [\"didcomm\"]\n\n\
                 [identity]\ndid_method = \"did:peer\"\n"
            );
            let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
            assert_eq!(parsed.security.network_mode, None);
            let config = to_wizard_config(&parsed).unwrap();
            assert_eq!(config.network_mode, expected, "{ty}");
        }
    }

    #[test]
    fn network_mode_closed_round_trips() {
        let mut recipe = minimal_recipe();
        recipe.security.network_mode = Some(crate::consts::NETWORK_MODE_CLOSED.into());
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.network_mode, crate::consts::NETWORK_MODE_CLOSED);

        // Auto-recipe writer must emit it back so a re-run preserves
        // the operator's chosen posture.
        let toml = from_wizard_config(&config);
        assert!(toml.contains("network_mode = \"closed\""));
    }

    #[test]
    fn cors_defaults_to_none_when_unspecified() {
        let recipe = minimal_recipe();
        assert_eq!(recipe.security.cors, crate::consts::CORS_MODE_NONE);
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.cors_mode, crate::consts::CORS_MODE_NONE);
    }

    #[test]
    fn cors_any_round_trips() {
        let mut recipe = minimal_recipe();
        recipe.security.cors = crate::consts::CORS_MODE_ANY.into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.cors_mode, crate::consts::CORS_MODE_ANY);

        let toml = from_wizard_config(&config);
        assert!(toml.contains("cors = \"any\""));
    }

    #[test]
    fn cors_list_round_trips_with_domains() {
        let mut recipe = minimal_recipe();
        recipe.security.cors = crate::consts::CORS_MODE_LIST.into();
        recipe.security.cors_domains =
            Some("https://app.affinidi.com,https://*.affinidi.com".into());
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.cors_mode, crate::consts::CORS_MODE_LIST);
        assert_eq!(
            config.cors_domains,
            "https://app.affinidi.com,https://*.affinidi.com"
        );

        let toml = from_wizard_config(&config);
        assert!(toml.contains("cors = \"list\""));
        assert!(
            toml.contains("cors_domains = \"https://app.affinidi.com,https://*.affinidi.com\"")
        );
    }

    #[test]
    fn cors_list_without_domains_errors() {
        let mut recipe = minimal_recipe();
        recipe.security.cors = crate::consts::CORS_MODE_LIST.into();
        recipe.security.cors_domains = None;
        let err = to_wizard_config(&recipe).unwrap_err();
        assert!(err.to_string().contains("cors_domains"));
    }

    #[test]
    fn cors_list_with_invalid_domain_errors() {
        let mut recipe = minimal_recipe();
        recipe.security.cors = crate::consts::CORS_MODE_LIST.into();
        // Missing scheme — rejected by the shared validator.
        recipe.security.cors_domains = Some("app.affinidi.com".into());
        let err = to_wizard_config(&recipe).unwrap_err();
        assert!(err.to_string().contains("cors_domains"));
    }

    #[test]
    fn cors_invalid_mode_errors() {
        let mut recipe = minimal_recipe();
        recipe.security.cors = "everyone".into();
        let err = to_wizard_config(&recipe).unwrap_err();
        assert!(err.to_string().contains("cors"));
    }

    #[test]
    fn deny_unknown_fields_rejects_typo_in_security_section() {
        // Regression: a typo in a security-relevant key would silently
        // default to the new wizard default (`network_mode = "open"`,
        // `jwt_mode = "generate"`, `ssl = "none"`). With
        // `deny_unknown_fields`, the typo errors at parse time so the
        // operator sees the misconfiguration immediately.
        let recipe_toml = r#"
[deployment]
type = "server"
protocols = ["didcomm"]
use_vta = false

[identity]
did_method = "did:peer"

[security]
# Deliberate typo — kebab-case version of the legal field name.
network-mode = "closed"
"#;
        let err = toml::from_str::<BuildRecipe>(recipe_toml).unwrap_err();
        assert!(
            err.to_string().contains("network-mode"),
            "deny_unknown_fields should name the offending field: {err}"
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_top_level_typo() {
        // Same guard at the top-level — section names also have to be
        // recognised, not silently dropped.
        let recipe_toml = r#"
[deployment]
type = "server"
protocols = ["didcomm"]
use_vta = false

[secuirty]
ssl = "none"
"#;
        let err = toml::from_str::<BuildRecipe>(recipe_toml).unwrap_err();
        assert!(
            err.to_string().contains("secuirty"),
            "deny_unknown_fields should name the offending section: {err}"
        );
    }

    #[test]
    fn network_mode_invalid_value_errors() {
        let mut recipe = minimal_recipe();
        recipe.security.network_mode = Some("invitation-only".into());
        let err = to_wizard_config(&recipe).unwrap_err();
        assert!(err.to_string().contains("network_mode"));
    }

    #[test]
    fn test_both_protocols() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["didcomm".into(), "tsp".into()];
        let config = to_wizard_config(&recipe).unwrap();
        assert!(config.didcomm_enabled);
        assert!(config.tsp_enabled);
    }

    #[test]
    fn test_no_protocols_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec![];
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_invalid_protocol_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["grpc".into()];
        assert!(to_wizard_config(&recipe).is_err());
    }

    fn webvh_recipe() -> BuildRecipe {
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "did:webvh".into();
        recipe.identity.public_url = Some("https://example.com".into());
        recipe
    }

    #[test]
    fn present_as_defaults_to_webvh_with_the_scid_alias() {
        let config = to_wizard_config(&webvh_recipe()).unwrap();
        assert!(!config.present_as_scid);
        assert!(config.scid_also_known_as);
    }

    #[test]
    fn present_as_scid_is_read() {
        for value in ["scid", "did:scid"] {
            let mut recipe = webvh_recipe();
            recipe.identity.present_as = Some(value.into());
            let config = to_wizard_config(&recipe).unwrap();
            assert!(config.present_as_scid, "{value}");
            assert!(config.scid_also_known_as);
        }
    }

    #[test]
    fn scid_alias_can_be_turned_off_for_webvh() {
        let mut recipe = webvh_recipe();
        recipe.identity.scid_also_known_as = Some(false);
        assert!(!to_wizard_config(&recipe).unwrap().scid_also_known_as);
    }

    #[test]
    fn present_as_scid_and_alias_round_trip() {
        let mut recipe = webvh_recipe();
        recipe.identity.present_as = Some("scid".into());
        let toml = from_wizard_config(&to_wizard_config(&recipe).unwrap());
        assert!(toml.contains("present_as = \"scid\""));
        let replayed = to_wizard_config(&toml::from_str::<BuildRecipe>(&toml).unwrap()).unwrap();
        assert!(replayed.present_as_scid);

        let mut recipe = webvh_recipe();
        recipe.identity.scid_also_known_as = Some(false);
        let toml = from_wizard_config(&to_wizard_config(&recipe).unwrap());
        assert!(toml.contains("scid_also_known_as = false"));

        // Defaults write nothing new.
        let toml = from_wizard_config(&to_wizard_config(&webvh_recipe()).unwrap());
        assert!(!toml.contains("present_as") && !toml.contains("scid_also_known_as"));
    }

    #[test]
    fn present_as_scid_is_refused_without_the_alias_or_off_webvh() {
        let mut recipe = webvh_recipe();
        recipe.identity.present_as = Some("scid".into());
        recipe.identity.scid_also_known_as = Some(false);
        assert!(to_wizard_config(&recipe).is_err());

        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "did:peer".into();
        recipe.identity.present_as = Some("scid".into());
        assert!(to_wizard_config(&recipe).is_err());

        let mut recipe = webvh_recipe();
        recipe.identity.present_as = Some("web".into());
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_all_did_methods() {
        for (input, expected) in [
            ("vta", Some(DidMethod::Vta)),
            ("did:peer", Some(DidMethod::Peer)),
            ("peer", Some(DidMethod::Peer)),
            ("did:webvh", Some(DidMethod::Webvh)),
            ("webvh", Some(DidMethod::Webvh)),
        ] {
            let mut recipe = minimal_recipe();
            recipe.identity.did_method = input.into();
            if expected == Some(DidMethod::Webvh) {
                recipe.identity.public_url = Some("https://example.com".into());
            }
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.did_method, expected, "input: {input}");
        }
    }

    #[test]
    fn did_import_is_rejected_with_its_exit_code() {
        // #173: `import` used to write a placeholder DID and exit 0.
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "import".into();
        let err = to_wizard_config(&recipe).unwrap_err();
        assert_eq!(crate::exit::code_of(&err), crate::exit::IMPORT_WITHOUT_DATA);
    }

    #[test]
    fn test_webvh_requires_public_url() {
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "did:webvh".into();
        recipe.identity.public_url = None;
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_all_secret_storage_schemes() {
        // Accepted schemes only — `string://` and `vta://` are rejected
        // by the recipe loader (covered separately in
        // `test_legacy_secret_storage_schemes_rejected`).
        for scheme in [
            SecretScheme::File,
            SecretScheme::Keyring,
            SecretScheme::Aws,
            SecretScheme::K8s,
        ] {
            let mut recipe = minimal_recipe();
            recipe.secrets.storage = scheme.prefix().into();
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.secret_storage, Some(scheme));
        }
        // #193: these have no usable default and used to produce
        // `gcp_secrets:///mediator-`, `azure_keyvault://`, `vault:///secret/…`.
        for scheme in [STORAGE_GCP, STORAGE_AZURE, STORAGE_VAULT] {
            let mut recipe = minimal_recipe();
            recipe.secrets.storage = scheme.into();
            let err = to_wizard_config(&recipe).unwrap_err().to_string();
            assert!(err.contains("--set secrets.storage="), "{scheme}: {err}");
        }
    }

    #[test]
    fn test_legacy_secret_storage_schemes_rejected() {
        for scheme in [STORAGE_STRING, STORAGE_VTA] {
            let mut recipe = minimal_recipe();
            recipe.secrets.storage = scheme.into();
            let err = to_wizard_config(&recipe)
                .err()
                .unwrap_or_else(|| panic!("scheme {scheme} should have been rejected"))
                .to_string();
            assert!(
                err.contains("no longer supported"),
                "expected rejection for {scheme}, got: {err}"
            );
        }
    }

    #[test]
    fn test_invalid_secret_storage_errors() {
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = "dropbox://".into();
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_full_url_round_trip_for_each_cloud_backend() {
        // A full URL in `secrets.storage` populates the per-backend
        // fields so a recipe replay restores region / project / vault /
        // endpoint without re-prompting the operator. Mirrors the
        // wizard's own `enter_key_storage_phase` chain.
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = "aws_secrets://eu-west-2/prod/mediator/".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, Some(SecretScheme::Aws));
        assert_eq!(config.secret_aws_region, "eu-west-2");
        assert_eq!(config.secret_aws_namespace, "prod/mediator/");

        recipe.secrets.storage = "gcp_secrets://my-prod-proj/svc-".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, Some(SecretScheme::Gcp));
        assert_eq!(config.secret_gcp_project, "my-prod-proj");
        assert_eq!(config.secret_gcp_namespace, "svc-");

        recipe.secrets.storage = "azure_keyvault://my-prod-vault".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, Some(SecretScheme::Azure));
        // Bare names canonicalise to the full URL via mediator-common's
        // parser — round-tripping through the recipe preserves the
        // canonical form.
        assert_eq!(
            config.secret_azure_vault,
            "https://my-prod-vault.vault.azure.net"
        );

        recipe.secrets.storage = "vault://vault.internal:8200/secret/prod-mediator".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, Some(SecretScheme::Vault));
        assert_eq!(config.secret_vault_endpoint, "vault.internal:8200");
        assert_eq!(config.secret_vault_mount, "secret/prod-mediator");
    }

    #[test]
    fn test_bare_scheme_keeps_defaults_for_backward_compat() {
        // Pre-cloud-config recipes wrote just the bare scheme. Loading
        // those still works for backends with usable defaults — the
        // per-backend fields keep their wizard defaults.
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = STORAGE_AWS.into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, Some(SecretScheme::Aws));
        assert_eq!(config.secret_aws_region, DEFAULT_AWS_REGION);
        assert_eq!(config.secret_aws_namespace, DEFAULT_AWS_SECRET_NAMESPACE);
    }

    #[test]
    fn test_ssl_existing_requires_paths() {
        let mut recipe = minimal_recipe();
        recipe.security.ssl = "existing".into();
        recipe.security.ssl_cert = None;
        recipe.security.ssl_key = None;
        assert!(to_wizard_config(&recipe).is_err());

        recipe.security.ssl_cert = Some("/path/cert.pem".into());
        assert!(to_wizard_config(&recipe).is_err()); // still missing key

        recipe.security.ssl_key = Some("/path/key.pem".into());
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.ssl_cert_path, "/path/cert.pem");
        assert_eq!(config.ssl_key_path, "/path/key.pem");
    }

    /// `didcomm-v1` is additive over v2.1 and depends on it, so selecting it
    /// alone must still turn v2.1 on — a recipe listing only `didcomm-v1`
    /// otherwise produces a build whose Cargo features imply `didcomm` while
    /// the wizard believes it is off.
    #[test]
    fn didcomm_v1_protocol_implies_didcomm() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["didcomm-v1".into()];

        let config = to_wizard_config(&recipe).unwrap();
        assert!(config.didcomm_v1_enabled);
        assert!(
            config.didcomm_enabled,
            "didcomm-v1 must imply didcomm, matching the mediator's Cargo feature"
        );
        assert!(config.cargo_features().contains(&"didcomm-v1"));
        assert!(config.cargo_features().contains(&"didcomm"));
    }

    #[test]
    fn didcomm_v1_is_off_unless_requested() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["didcomm".into()];

        let config = to_wizard_config(&recipe).unwrap();
        assert!(!config.didcomm_v1_enabled);
        assert!(!config.cargo_features().contains(&"didcomm-v1"));
    }

    #[test]
    fn unknown_protocol_names_didcomm_v1_in_its_error() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["didcommv1".into()];

        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(
            err.contains("didcomm-v1"),
            "the error should list the accepted spellings, got: {err}"
        );
    }

    // ── from_wizard_config round-trip ──────────────────────────────────

    #[test]
    fn test_recipe_round_trip() {
        let original = WizardConfig {
            config_path: "conf/mediator.toml".into(),
            deployment_type: Some(Deployment::Server),
            use_vta: false,
            vta_mode: None,
            didcomm_enabled: true,
            tsp_enabled: true,
            did_method: Some(DidMethod::Peer),
            public_url: String::new(),
            secret_storage: Some(SecretScheme::Keyring),
            ssl_mode: Some(SslMode::None),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://127.0.0.1/3".into(),
            admin_did_mode: Some(AdminMode::Skip),
            listen_address: "0.0.0.0:8080".into(),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();

        assert_eq!(restored.deployment_type, original.deployment_type);
        assert_eq!(restored.didcomm_enabled, original.didcomm_enabled);
        assert_eq!(restored.tsp_enabled, original.tsp_enabled);
        assert_eq!(restored.did_method, original.did_method);
        assert_eq!(restored.secret_storage, original.secret_storage);
        assert_eq!(restored.ssl_mode, original.ssl_mode);
        assert_eq!(restored.database_url, original.database_url);
        assert_eq!(restored.config_path, original.config_path);
        assert_eq!(restored.listen_address, original.listen_address);
        assert_eq!(restored.use_vta, original.use_vta);
    }

    #[test]
    fn test_vta_mode_values_and_legacy_alias() {
        // Canonical split: `sealed-mint` / `sealed-export` / `online`.
        // Legacy `"sealed"` (pre-split) normalises silently to
        // `sealed-mint` because that was the only interpretation
        // before the split landed.
        let mut recipe = minimal_recipe();
        recipe.deployment.use_vta = true;
        recipe.identity.public_url = Some("https://mediator.example.com".into());

        for mode in [VtaMode::SealedMint, VtaMode::SealedExport, VtaMode::Online] {
            recipe.deployment.vta_mode = Some(mode.as_str().into());
            let cfg = to_wizard_config(&recipe).unwrap();
            assert_eq!(cfg.vta_mode, Some(mode));
        }

        recipe.deployment.vta_mode = Some("sealed".into());
        let cfg = to_wizard_config(&recipe).unwrap();
        assert_eq!(
            cfg.vta_mode,
            Some(VtaMode::SealedMint),
            "legacy `sealed` normalises to `sealed-mint`"
        );

        recipe.deployment.vta_mode = Some("cold-start".into());
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(
            err.contains("Invalid deployment.vta_mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_sealed_mint_requires_public_url() {
        let mut recipe = minimal_recipe();
        recipe.deployment.use_vta = true;
        recipe.deployment.vta_mode = Some(VTA_MODE_SEALED_MINT.into());
        // public_url omitted → rejected
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(
            err.contains("requires identity.public_url"),
            "unexpected error: {err}"
        );
        // public_url present → accepted
        recipe.identity.public_url = Some("https://mediator.example.com".into());
        let cfg = to_wizard_config(&recipe).unwrap();
        assert_eq!(cfg.vta_mode, Some(VtaMode::SealedMint));
    }

    #[test]
    fn test_vta_section_round_trips_through_recipe() {
        // Non-default context + webvh fields must be written to the
        // recipe text AND parsed back into the matching wizard
        // config fields. Defaults are elided so the recipe text
        // stays lean.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: Some(VtaMode::SealedMint),
            vta_context: "prod-mediator".into(),
            did_method: Some(DidMethod::Vta),
            public_url: "https://mediator.example.com".into(),
            secret_storage: Some(SecretScheme::Keyring),
            admin_did_mode: Some(AdminMode::Vta),
            vta_webvh_server_id: Some("prod-1".into()),
            vta_webvh_path: Some("mediator/v1".into()),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        assert!(recipe_toml.contains("[vta]"));
        assert!(recipe_toml.contains("context = \"prod-mediator\""));
        assert!(recipe_toml.contains("webvh_server = \"prod-1\""));
        assert!(recipe_toml.contains("webvh_path = \"mediator/v1\""));

        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();
        assert_eq!(restored.vta_context, "prod-mediator");
        assert_eq!(restored.vta_webvh_server_id.as_deref(), Some("prod-1"));
        assert_eq!(restored.vta_webvh_path.as_deref(), Some("mediator/v1"));
    }

    #[test]
    fn test_vta_section_omitted_on_defaults() {
        // Default context + no webvh pins → no `[vta]` in recipe
        // output, keeping the TOML small for the common case.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: Some(VtaMode::Online),
            did_method: Some(DidMethod::Vta),
            ..WizardConfig::default()
        };
        let recipe_toml = from_wizard_config(&original);
        assert!(!recipe_toml.contains("[vta]"));
    }

    #[test]
    fn test_recipe_round_trip_with_vta() {
        // VTA-managed DID with a real secret backend (keyring) — vta:// is
        // no longer a valid storage scheme, so the round-trip exercises
        // the new shape: VTA for *identity*, unified backend for *keys*.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: Some(VtaMode::Online),
            did_method: Some(DidMethod::Vta),
            secret_storage: Some(SecretScheme::Keyring),
            admin_did_mode: Some(AdminMode::Vta),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        assert!(recipe_toml.contains("use_vta = true"));
        assert!(recipe_toml.contains("vta_mode = \"online\""));

        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();

        assert!(restored.use_vta);
        assert_eq!(restored.vta_mode, Some(VtaMode::Online));
        assert_eq!(restored.did_method, Some(DidMethod::Vta));
        assert_eq!(restored.secret_storage, Some(SecretScheme::Keyring));
    }

    #[test]
    fn test_backward_compat_infers_vta() {
        // Old recipe without use_vta but with VTA-managed DID — the
        // loader still infers `use_vta = true`. (The old `secrets.storage
        // = "vta://"` trigger is gone — that scheme is now rejected.)
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "vta".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert!(config.use_vta, "should auto-detect VTA from did_method");
        assert_eq!(config.vta_mode, Some(VtaMode::Online));
    }

    // ── #191: the saved recipe reproduces the run ──────────────────────

    fn round_trip(config: &WizardConfig) -> WizardConfig {
        let text = from_wizard_config(config);
        let parsed: BuildRecipe = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("saved recipe must parse: {e}\n{text}"));
        to_wizard_config(&parsed).unwrap_or_else(|e| panic!("saved recipe must load: {e}\n{text}"))
    }

    /// A configuration exercising every value a recipe can carry,
    /// canonicalised by loading it once.
    fn rich_configs() -> Vec<WizardConfig> {
        let recipes = [
            r#"
[deployment]
type = "server"
protocols = ["didcomm", "tsp", "didcomm-v1"]
didcomm_v1_allow_unauthenticated_forwards = true

[identity]
did_method = "did:webvh"
public_url = "https://mediator.example.com/a \"quoted\" \\ path"
save_did_web = true
present_as = "scid"
extra_key_suites = ["p256", "secp256k1"]

[secrets]
storage = "file://conf/secrets.json"
allow_plaintext_file = true

[security]
ssl = "existing"
ssl_cert = "/etc/tls/cert.pem"
ssl_key = "/etc/tls/key.pem"
admin = "import"
admin_did = "did:key:z6MkAdminImported"
jwt_mode = "provide"
network_mode = "open"
cors = "list"
cors_domains = "https://app.example.com,https://*.example.com"

[storage]
backend = "fjall"
data_dir = "/var/lib/mediator"

[output]
config_path = "deploy/mediator.toml"
listen_address = "127.0.0.1:9000"
api_prefix = "/m/"
trust_xff_cidrs = ["10.0.0.0/8"]
did_target = "aws_parameter_store:///mediator/did?region=eu-west-1"
did_log_target = "s3://bucket/mediator/did.jsonl?region=eu-west-1"
"#,
            r#"
[deployment]
type = "container"
use_vta = true
vta_mode = "sealed-mint"

[vta]
context = "prod-mediator"
webvh_server = "prod-1"
webvh_path = "mediator/v1"

[identity]
did_method = "vta"
public_url = "https://mediator.example.com"

[secrets]
storage = "vault://vault.internal:8200/secret/mediator"

[security]
admin = "vta"
network_mode = "closed"
cors = "any"
"#,
            r#"
[deployment]
type = "local"
protocols = ["tsp"]

[identity]
did_method = "did:peer"
scid_also_known_as = false

[secrets]
storage = "file://conf/secrets.json?encrypt=1"

[security]
admin = "skip"
ssl = "self-signed"
"#,
        ];
        recipes
            .iter()
            .map(|text| to_wizard_config(&toml::from_str(text).unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn saved_recipe_round_trips_every_value() {
        for config in rich_configs() {
            assert_eq!(round_trip(&config), config);
        }
    }

    #[test]
    fn saved_recipe_keeps_a_relative_file_backend_path() {
        // The header says the recipe reproduces the setup elsewhere; an
        // absolute host path would not.
        let config = &rich_configs()[0];
        let text = from_wizard_config(config);
        let parsed: BuildRecipe = toml::from_str(&text).unwrap();
        assert_eq!(parsed.secrets.storage, "file://conf/secrets.json", "{text}");
    }

    #[test]
    fn saved_recipe_escapes_toml_specials() {
        let text = from_wizard_config(&rich_configs()[0]);
        // A quote in a value must not end the TOML string early.
        assert!(toml::from_str::<BuildRecipe>(&text).is_ok());
    }

    #[test]
    fn tui_admin_vta_is_not_saved_as_generate() {
        // `AdminMode::Vta` used to fall through to "generate" in the saved
        // recipe, so the replay minted a different admin.
        let config = WizardConfig {
            deployment_type: Some(Deployment::Local),
            use_vta: true,
            vta_mode: Some(VtaMode::SealedExport),
            did_method: Some(DidMethod::Vta),
            secret_storage: Some(SecretScheme::Keyring),
            admin_did_mode: Some(AdminMode::Vta),
            ..WizardConfig::default()
        };
        assert_eq!(round_trip(&config).admin_did_mode, Some(AdminMode::Vta));
    }

    fn manifest_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn shipped_example_recipes_load() {
        let mut files: Vec<_> = std::fs::read_dir(manifest_dir().join("examples"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        // The test stack's recipe is a shipped recipe too.
        files.push(manifest_dir().join("../../../../docker/test/mediator-build.toml"));
        assert!(files.len() >= 2);
        for path in files {
            let recipe =
                load(path.to_str().unwrap()).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            to_wizard_config(&recipe).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }

    #[test]
    fn every_recipe_in_the_setup_guide_loads() {
        let guide =
            std::fs::read_to_string(manifest_dir().join("../../docs/setup-guide.md")).unwrap();
        let mut blocks = Vec::new();
        let mut current: Option<String> = None;
        for line in guide.lines() {
            match (&mut current, line.trim_start()) {
                (None, l) if l.starts_with("```toml") => current = Some(String::new()),
                (Some(_), l) if l.starts_with("```") => blocks.push(current.take().unwrap()),
                (Some(block), _) => {
                    block.push_str(line);
                    block.push('\n');
                }
                _ => {}
            }
        }
        // Recipe blocks are the ones with a `[deployment]` table; the guide
        // also shows mediator.toml excerpts.
        let recipes: Vec<_> = blocks
            .iter()
            .filter(|b| b.contains("[deployment]"))
            .collect();
        assert!(!recipes.is_empty(), "no recipe blocks found in the guide");
        for block in recipes {
            let recipe: BuildRecipe =
                toml::from_str(block).unwrap_or_else(|e| panic!("guide recipe: {e}\n{block}"));
            to_wizard_config(&recipe).unwrap_or_else(|e| panic!("guide recipe: {e}\n{block}"));
        }
    }

    // ── #173: admin identity ───────────────────────────────────────────

    #[test]
    fn admin_import_needs_a_did_and_has_its_exit_code() {
        let mut recipe = minimal_recipe();
        recipe.security.admin = "import".into();
        let err = to_wizard_config(&recipe).unwrap_err();
        assert_eq!(crate::exit::code_of(&err), crate::exit::IMPORT_WITHOUT_DATA);

        recipe.security.admin_did = Some("not a did".into());
        assert!(to_wizard_config(&recipe).is_err());

        recipe.security.admin_did = Some("did:web:admin.example.com".into());
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.admin_did_mode, Some(AdminMode::Paste));
        assert_eq!(config.admin_did, "did:web:admin.example.com");
    }

    #[test]
    fn admin_did_without_import_is_refused() {
        let mut recipe = minimal_recipe();
        recipe.security.admin_did = Some("did:web:admin.example.com".into());
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn admin_vta_needs_a_vta_deployment() {
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "did:peer".into();
        recipe.security.admin = "vta".into();
        assert!(to_wizard_config(&recipe).is_err());
    }

    // ── #193: plaintext file:// needs an explicit opt-in ──────────────

    #[test]
    fn plaintext_file_backend_needs_opt_in_outside_local() {
        let mut recipe = minimal_recipe();
        recipe.deployment.deployment_type = "server".into();
        recipe.identity.did_method = "did:peer".into();
        recipe.secrets.storage = "file://conf/secrets.json".into();
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(err.contains("allow_plaintext_file"), "{err}");

        // Encrypted is fine.
        recipe.secrets.storage = "file://conf/secrets.json?encrypt=1".into();
        assert!(to_wizard_config(&recipe).is_ok());

        // So is an explicit opt-in.
        recipe.secrets.storage = "file://conf/secrets.json".into();
        recipe.secrets.allow_plaintext_file = true;
        assert!(to_wizard_config(&recipe).is_ok());

        // And a local deployment needs none.
        recipe.secrets.allow_plaintext_file = false;
        recipe.deployment.deployment_type = "local".into();
        assert!(to_wizard_config(&recipe).is_ok());
    }

    #[test]
    fn looks_like_did_accepts_dids_only() {
        assert!(looks_like_did("did:key:z6Mk123"));
        assert!(looks_like_did("did:webvh:scid:example.com"));
        for bad in [
            "",
            "did:",
            "did:key",
            "did::x",
            "did:Key:x",
            "notdid:key:x",
            "did:key:a b",
        ] {
            assert!(!looks_like_did(bad), "{bad}");
        }
    }
}
