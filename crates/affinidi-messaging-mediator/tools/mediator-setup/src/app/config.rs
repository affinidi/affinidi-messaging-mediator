//! [`WizardConfig`]: everything the wizard collected, and what it implies
//! for the mediator build.

use crate::consts::*;

/// Accumulated configuration choices from the wizard.
#[derive(Debug, Clone, PartialEq)]
pub struct WizardConfig {
    pub config_path: String,
    pub deployment_type: String,
    /// Whether VTA integration is enabled
    pub use_vta: bool,
    /// VTA connectivity mode: `"online"`, `"sealed-mint"`, or
    /// `"sealed-export"`. See `consts::VTA_MODE_*`.
    pub vta_mode: String,
    /// VTA context id this mediator lives in. Populated from the
    /// recipe's `[vta] context` field or the TUI's sealed-handoff
    /// CollectContext phase. Defaults to
    /// [`crate::consts::DEFAULT_VTA_CONTEXT`] when unset.
    pub vta_context: String,
    /// DIDComm v2 protocol enabled (default: true)
    pub didcomm_enabled: bool,
    /// TSP protocol enabled (default: true — the preferred transport, carried
    /// alongside DIDComm, and advertised as `#tsp` in the mediator's DID)
    pub tsp_enabled: bool,
    /// DIDComm v1 (Aries RFC 0019) enabled (default: false). Additive
    /// alongside DIDComm v2.1, and dependent on it.
    pub didcomm_v1_enabled: bool,
    /// Accept DIDComm v1 forwards without an authenticated session
    /// (default: false). Required for stock Credo wallets, which cannot
    /// complete this mediator's v2 challenge; see the `[didcomm_v1]` docs.
    pub didcomm_v1_allow_unauthenticated_forwards: bool,
    pub did_method: String,
    pub public_url: String,
    /// When `did_method` produces a did:webvh, also export a did:web copy
    /// of the DID document to `did-web.json`. Collected via the
    /// `DidPhase::SaveDidWebChoice` prompt or the `--save-did-web` flag.
    pub save_did_web: bool,
    /// Present a locally generated did:webvh log as its `did:scid:vh:1` DID
    /// (VTI-KEY-165). Collected via `DidPhase::IdentityFormChoice`,
    /// `--present-as-scid`, or the recipe's `[identity] present_as = "scid"`.
    pub present_as_scid: bool,
    /// List the did:scid alias in a locally generated did:webvh log's
    /// `alsoKnownAs` (VTI-KEY-166). On by default; `--no-scid-alias` or the
    /// recipe's `scid_also_known_as = false` turns it off. Required when
    /// `present_as_scid`.
    pub scid_also_known_as: bool,
    /// Extra key suites (beyond the mandatory Ed25519 + X25519 pair) to mint
    /// for the mediator identity. Empty by default. Only consulted by the
    /// local generators (`did:peer`, `did:webvh`); VTA-managed DIDs derive
    /// their key set from the VTA template. Populated from the `--key-suite`
    /// flag or the recipe's `[identity] extra_key_suites`.
    pub key_suite: Vec<crate::cli::KeySuite>,
    pub secret_storage: String,
    // Per-backend config fields. Only the set relevant to `secret_storage`
    // is meaningful; others stay at defaults. Storing them as flat strings
    // keeps `WizardConfig` serialisable into the build-recipe TOML.
    pub secret_file_path: String,
    pub secret_keyring_service: String,
    pub secret_aws_region: String,
    pub secret_aws_namespace: String,
    /// GCP project ID hosting the mediator's secrets. Used together
    /// with [`Self::secret_gcp_namespace`] to build `gcp_secrets://`.
    pub secret_gcp_project: String,
    /// Per-secret namespace on GCP. Empty is allowed — GCP secret
    /// names accept the bare well-known keys verbatim.
    pub secret_gcp_namespace: String,
    /// Bare vault name (`my-vault`), sovereign-cloud DNS name
    /// (`my-vault.vault.usgovcloudapi.net`), or full URL — the URL
    /// parser canonicalises all three shapes.
    pub secret_azure_vault: String,
    /// Vault server endpoint (`host[:port]`). May omit the scheme;
    /// the backend defaults to `https://` when none is given.
    pub secret_vault_endpoint: String,
    /// KV v2 mount + optional per-key namespace glued together
    /// (`secret/mediator`). The backend splits the first segment off
    /// as the mount and uses the rest as the namespace.
    pub secret_vault_mount: String,
    /// Vault auth method: `token` (default), `kubernetes`, or `approle`.
    /// Empty is treated as `token`.
    pub secret_vault_auth: String,
    /// Vault role for `kubernetes` auth (required for that method).
    pub secret_vault_role: String,
    /// Vault Kubernetes auth mount. Empty → backend default (`kubernetes`).
    pub secret_vault_k8s_mount: String,
    /// ServiceAccount JWT path for `kubernetes` auth. Empty → backend
    /// default (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
    pub secret_vault_jwt_path: String,
    /// Vault AppRole auth mount. Empty → backend default (`approle`).
    pub secret_vault_approle_mount: String,
    /// Vault Enterprise namespace (`X-Vault-Namespace`). Empty → none.
    pub secret_vault_namespace: String,
    /// Skip TLS verification for `vault://` (dev/test only).
    pub secret_vault_insecure: bool,
    /// PEM CA bundle to trust for `vault://` (`?ca_cert=`). Empty → none.
    pub secret_vault_ca_cert: String,
    /// Kubernetes namespace for the `k8s://` backend. Empty → resolved
    /// from the in-pod ServiceAccount / kubeconfig at connect time.
    pub secret_k8s_namespace: String,
    /// Name of the `Secret` object for the `k8s://` backend.
    pub secret_k8s_secret_name: String,
    /// `true` when the operator chose `file://?encrypt=1`. Influences
    /// the backend URL written to `mediator.toml` and whether the
    /// wizard prompts for a passphrase.
    pub secret_file_encrypted: bool,
    pub ssl_mode: String,
    pub ssl_cert_path: String,
    pub ssl_key_path: String,
    /// When VTA-managed and a hosted server was picked, the server id.
    /// `None` means self-host. Set on the Did step's SelectWebvhHost
    /// phase; read by `generate_and_write` when it calls the VTA's
    /// `create_did_webvh`.
    pub vta_webvh_server_id: Option<String>,
    /// Optional DID path / mnemonic (URL path segment) when using a
    /// hosted server. `None` = VTA auto-assigns. Mirrors the recipe's
    /// `[vta].webvh_path` and `SealedHandoffState::webvh_path`; was
    /// previously named `vta_webvh_path` (one of three names for
    /// the same concept) — the consistent name is `path`.
    pub vta_webvh_path: Option<String>,
    /// Self-host base URL — defaults to the stripped mediator URL.
    /// Only meaningful when `vta_webvh_server_id` is `None`.
    pub vta_webvh_self_host_url: String,
    /// `generate` (default) or `provide`. See [`crate::consts::JWT_MODE_GENERATE`].
    pub jwt_mode: String,
    /// Network posture written to `[security]`: `"open"` (default —
    /// any DID can message any other; per-DID overrides flip
    /// individual flags) or `"closed"` (every cross-DID exchange needs
    /// an explicit ACL grant). Drives the trio of `mediator_acl_mode`,
    /// `global_acl_default`, and `local_direct_delivery_allowed` that
    /// `config_writer::write_config` emits.
    pub network_mode: String,
    /// Browser CORS policy mode written to `[security].cors_allow_origin`:
    /// `"none"` (default — key unset, deny all cross-origin), `"any"`
    /// (`*`), or `"list"` (the [`Self::cors_domains`] allowlist). See
    /// [`crate::consts::CORS_MODE_NONE`] / `_ANY` / `_LIST`.
    pub cors_mode: String,
    /// Comma-separated CORS origin allowlist, meaningful only when
    /// `cors_mode == "list"`. Each entry is an exact, scheme-qualified
    /// origin (`https://app.affinidi.com`) or a leftmost-label sub-domain
    /// wildcard (`https://*.affinidi.com`). Validated by
    /// [`validate_cors_domains`] before the wizard accepts it.
    pub cors_domains: String,
    pub database_url: String,
    /// Storage backend the generated `mediator.toml` selects:
    /// `"redis"` (default) or `"fjall"`. Mirrors `[storage].backend`
    /// in the recipe shape and the rendered config.
    pub storage_backend: String,
    /// On-disk path for the Fjall data directory. Only meaningful
    /// when `storage_backend == crate::consts::STORAGE_BACKEND_FJALL`.
    pub fjall_data_dir: String,
    pub admin_did_mode: String,
    /// The operator's own admin DID when `admin_did_mode == ADMIN_PASTE`
    /// (TUI paste prompt, recipe `[security] admin = "import"` +
    /// `admin_did`). Written to `[server].admin_did`; the wizard holds no
    /// key for it. Empty otherwise.
    pub admin_did: String,
    /// The operator explicitly accepted an unencrypted `file://` secret
    /// store (TUI: typing the file-gate phrase and choosing "No
    /// encryption"; recipe `[secrets] allow_plaintext_file = true`; or
    /// `--allow-plaintext-file`). Required outside local deployments.
    pub allow_plaintext_file: bool,
    pub listen_address: String,
    /// HTTP prefix all mediator routes nest under (e.g. `/mediator/v1/`).
    /// Written verbatim to `[server] api_prefix` and combined with
    /// `public_url` when rendering the did:webvh service endpoints so
    /// the DID document points at the same URLs the mediator actually
    /// serves. Empty / `/` means "serve at host root".
    pub api_prefix: String,
    /// Written to `[server] trust_xff_cidrs`; empty = `X-Forwarded-For` ignored.
    pub trust_xff_cidrs: Vec<String>,
    /// Publish target for the minted DID string (recipe `[output].did_target`;
    /// never prompted). `None` = don't publish.
    pub did_target: Option<String>,
    /// Publish target for the minted did:webvh log document (recipe
    /// `[output].did_log_target`; never prompted). `None` = don't publish.
    /// When set (and the deployment self-hosts its log), the generated
    /// mediator.toml points `did_web_self_hosted` at this same target, so a
    /// mediator on ephemeral compute can serve `/.well-known/did.jsonl`
    /// after the one-shot setup task exits.
    pub did_log_target: Option<String>,
}

impl WizardConfig {
    /// Return a display string for the selected protocols.
    pub fn protocol_display(&self) -> String {
        match (self.didcomm_enabled, self.tsp_enabled) {
            (true, true) => "DIDComm v2 + TSP".into(),
            (true, false) => "DIDComm v2".into(),
            (false, true) => "TSP".into(),
            (false, false) => "None (invalid)".into(),
        }
    }

    /// Compute the Cargo `--features` list for the mediator binary
    /// implied by this wizard configuration. Used by every
    /// build/install/run-command emitter (Dockerfile, `cargo install`,
    /// `cargo build`, `cargo run`) so all paths stay in lockstep.
    ///
    /// Always emits exactly one storage backend feature
    /// (`redis-backend` or `fjall-backend`), the protocols chosen, and the
    /// mediator's other defaults (`jemalloc`, `vta`), which the wizard never
    /// turns off. Callers pair it with `--no-default-features` whenever it
    /// differs from [`MEDIATOR_DEFAULT_FEATURES`], so it has to be complete:
    /// a feature missing here is missing from the binary. That is how
    /// wizard-built mediators lost `vta` — and with it the VTA integration a
    /// VTA-linked config needs, which a build without it skips silently.
    pub fn cargo_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();

        if self.didcomm_enabled {
            features.push("didcomm");
        }
        if self.tsp_enabled {
            features.push("tsp");
        }
        // `didcomm-v1` implies `didcomm` in the mediator's Cargo features, but
        // list it explicitly so the rendered build command reads as what the
        // operator chose rather than relying on the implication.
        if self.didcomm_v1_enabled {
            features.push("didcomm-v1");
        }

        features.push(match self.storage_backend.as_str() {
            crate::consts::STORAGE_BACKEND_FJALL => "fjall-backend",
            // Anything else (incl. blank legacy recipes) → redis. The
            // recipe parser also defaults to redis, so this branch
            // primarily covers WizardConfig::default() before the
            // Database step has run.
            _ => "redis-backend",
        });

        // Defaults no wizard choice removes. `vta` is needed by every
        // VTA-linked deployment, and costs a non-VTA one nothing but a
        // dependency; `jemalloc` is the allocator the mediator ships with.
        features.push("jemalloc");
        features.push("vta");

        // Route through the canonical `STORAGE_*` constants rather
        // than re-typing the URL prefixes — keeps this in lockstep
        // with `consts.rs` if a scheme prefix ever changes.
        match self.secret_storage.as_str() {
            STORAGE_KEYRING => features.push("secrets-keyring"),
            STORAGE_AWS => features.push("secrets-aws"),
            STORAGE_GCP => features.push("secrets-gcp"),
            STORAGE_AZURE => features.push("secrets-azure"),
            STORAGE_VAULT => features.push("secrets-vault"),
            STORAGE_K8S => features.push("secrets-k8s"),
            // `file://` needs no feature: the file backend is always built.
            _ => {}
        }

        features
    }

    /// Whether [`Self::cargo_features`] differs from the mediator's own
    /// default features ([`MEDIATOR_DEFAULT_FEATURES`]), as a set. Callers
    /// use this to decide whether to pass `--no-default-features` — when it
    /// returns `false`, plain `cargo build -p affinidi-messaging-mediator` is
    /// sufficient.
    pub fn needs_explicit_features(&self) -> bool {
        let mut features = self.cargo_features();
        let mut defaults = MEDIATOR_DEFAULT_FEATURES.to_vec();
        features.sort_unstable();
        defaults.sort_unstable();
        features != defaults
    }
}

/// The mediator crate's `default` features, which
/// [`WizardConfig::needs_explicit_features`] compares against. Must match
/// `affinidi-messaging-mediator/Cargo.toml`; a test reads that file to hold it.
pub const MEDIATOR_DEFAULT_FEATURES: [&str; 5] =
    ["didcomm", "tsp", "redis-backend", "jemalloc", "vta"];

impl Default for WizardConfig {
    fn default() -> Self {
        Self {
            config_path: DEFAULT_CONFIG_PATH.into(),
            deployment_type: String::new(),
            use_vta: false,
            vta_mode: String::new(),
            vta_context: DEFAULT_VTA_CONTEXT.into(),
            didcomm_enabled: true,
            tsp_enabled: true,
            didcomm_v1_enabled: false,
            didcomm_v1_allow_unauthenticated_forwards: false,
            did_method: String::new(),
            public_url: String::new(),
            save_did_web: false,
            present_as_scid: false,
            scid_also_known_as: true,
            key_suite: Vec::new(),
            secret_storage: String::new(),
            secret_file_path: DEFAULT_SECRET_FILE_PATH.into(),
            secret_keyring_service: DEFAULT_KEYRING_SERVICE.into(),
            secret_aws_region: DEFAULT_AWS_REGION.into(),
            secret_aws_namespace: DEFAULT_AWS_SECRET_NAMESPACE.into(),
            secret_gcp_project: DEFAULT_GCP_PROJECT.into(),
            secret_gcp_namespace: DEFAULT_GCP_SECRET_NAMESPACE.into(),
            secret_azure_vault: DEFAULT_AZURE_VAULT.into(),
            secret_vault_endpoint: DEFAULT_VAULT_ENDPOINT.into(),
            secret_vault_mount: DEFAULT_VAULT_MOUNT.into(),
            secret_vault_auth: String::new(),
            secret_vault_role: String::new(),
            secret_vault_k8s_mount: String::new(),
            secret_vault_jwt_path: String::new(),
            secret_vault_approle_mount: String::new(),
            secret_vault_namespace: String::new(),
            secret_vault_insecure: false,
            secret_vault_ca_cert: String::new(),
            secret_k8s_namespace: String::new(),
            secret_k8s_secret_name: DEFAULT_K8S_SECRET_NAME.into(),
            secret_file_encrypted: false,
            ssl_mode: String::new(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            vta_webvh_server_id: None,
            vta_webvh_path: None,
            vta_webvh_self_host_url: String::new(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            network_mode: crate::consts::DEFAULT_NETWORK_MODE.into(),
            cors_mode: crate::consts::DEFAULT_CORS_MODE.into(),
            cors_domains: String::new(),
            database_url: DEFAULT_REDIS_URL.into(),
            storage_backend: crate::consts::DEFAULT_STORAGE_BACKEND.into(),
            fjall_data_dir: crate::consts::DEFAULT_FJALL_DATA_DIR.into(),
            admin_did_mode: String::new(),
            admin_did: String::new(),
            allow_plaintext_file: false,
            listen_address: DEFAULT_LISTEN_ADDR.into(),
            api_prefix: DEFAULT_API_PREFIX.into(),
            trust_xff_cidrs: Vec::new(),
            did_target: None,
            did_log_target: None,
        }
    }
}
