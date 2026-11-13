pub mod helpers;
pub mod limits;
pub mod overrides;
pub mod processors;
pub mod security;
pub mod validate;
#[cfg(feature = "vta")]
pub(crate) mod vta_bootstrap;
#[cfg(feature = "vta")]
pub mod vta_cache;

pub use limits::*;
pub use processors::*;
pub use security::*;

// The raw TOML schema types now live in the dependency-light
// `affinidi-messaging-mediator-config` crate. Re-exported here so existing
// `crate::common::config::*` paths (and external consumers like
// `affinidi-messaging-test-mediator`) keep resolving. Only the *types* are
// re-exported — the crate's `env` / `validate` modules are used fully-qualified
// (a bare `env` would shadow `std::env`). The resolved runtime `Config` and
// every `ConfigRaw → Config` conversion stay in this module.
pub use affinidi_messaging_mediator_config::{
    ConfigRaw, DIDResolverConfig, ForwardingConfigRaw, LimitsConfigRaw,
    MessageExpiryCleanupConfigRaw, ProcessorsConfigRaw, RedactedString, SecretsConfigRaw,
    SecurityConfigRaw, ServerConfig, SessionExpiryCleanupConfigRaw, StorageConfig, StreamingConfig,
};

use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient,
    config::{DIDCacheConfig, DIDCacheConfigBuilder},
};
use affinidi_messaging_mediator_common::{
    MediatorSecrets,
    database::config::DatabaseConfig,
    did_web::rewrite_did_document_to_web,
    errors::MediatorError,
    secrets::{open_store_async, parse_url},
};
use affinidi_messaging_mediator_config::{ConfigError, values};
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use async_convert::{TryFrom, async_trait};
#[cfg(feature = "aws")]
use aws_config::{self, BehaviorVersion, Region};
use didwebvh_rs::log_entry::LogEntry;
#[cfg(feature = "vta")]
use vta_sdk::credentials::CredentialBundle;

/// AWS SDK configuration type — conditionally compiled.
/// When the `aws` feature is enabled, this is `aws_config::SdkConfig`.
/// When disabled, this is `()` (zero-size placeholder).
#[cfg(feature = "aws")]
pub(crate) type AwsConfig = aws_config::SdkConfig;
#[cfg(not(feature = "aws"))]
pub(crate) type AwsConfig = ();
use serde::Serialize;
use std::{collections::HashMap, env, fmt, path::Path, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};
#[cfg(feature = "vta")]
use vta_sdk::integration::{
    self, SecretSource, TransportPreference, VtaIntegrationError, VtaServiceConfig,
};

use helpers::{
    assert_operating_secrets_cover_key_agreement, get_hostname, load_forwarding_protection_blocks,
    preload_self_did, read_did_config, read_document,
};

/// A [`ConfigError`] from the config crate as the mediator's error.
pub(crate) fn config_error(err: ConfigError) -> MediatorError {
    config_error_msg(err.to_string())
}

/// A configuration error with `msg` as its reason.
pub(crate) fn config_error_msg(msg: String) -> MediatorError {
    MediatorError::ConfigError(crate::common::error_codes::CONFIG_ERROR, "NA".into(), msg)
}

/// The DID resolver's network timeout when none is configured, in
/// **milliseconds** (the SDK's unit).
const DEFAULT_RESOLVER_NETWORK_TIMEOUT_MS: u32 = 5_000;

/// Build the runtime [`DIDCacheConfig`] from the raw [`DIDResolverConfig`]
/// schema. Was `DIDResolverConfig::convert`; became a free function when the
/// raw type relocated to `affinidi-messaging-mediator-config` (inherent impls
/// must live in the type's crate, and this conversion pulls the DID-resolver
/// SDK, which the schema crate avoids).
///
/// Every number is read strictly. `network_timeout` is in milliseconds; an
/// unreadable value used to fall back to `5` — five milliseconds, not the
/// 5000 the template ships.
fn did_resolver_cache_config(raw: &DIDResolverConfig) -> Result<DIDCacheConfig, MediatorError> {
    let num = |key: &str, value: &str| -> Result<u32, MediatorError> {
        values::number(&format!("did_resolver.{key}"), value).map_err(config_error)
    };
    let mut config = DIDCacheConfigBuilder::default()
        .with_cache_capacity(num("cache_capacity", &raw.cache_capacity)?)
        .with_cache_ttl(num("cache_ttl", &raw.cache_ttl)?)
        .with_network_timeout(
            values::number_at_least("did_resolver.network_timeout", &raw.network_timeout, 1)
                .map_err(config_error)?,
        )
        .with_network_cache_limit_count(num("network_limit", &raw.network_limit)?);

    if let Some(address) = &raw.address {
        config = config.with_network_mode(address);
    }

    Ok(config.build())
}

/// Build the runtime [`DatabaseConfig`] from the raw `[database]` schema.
/// `DatabaseConfigRaw` lives in the config crate and `DatabaseConfig` in
/// mediator-common, so this is a free function (the orphan rule forbids a
/// `TryFrom` impl here). `database_timeout` (whole seconds, at least 1),
/// `cluster_mode` (`true`/`false`, absent is `false`) and the circuit-breaker
/// tuning (`circuit_breaker_threshold`, at least 1, absent is 5;
/// `circuit_breaker_recovery_secs`, absent is 10) are read strictly. An empty
/// `functions_file` means the built-in stored-function library.
fn database_config_from_raw(
    raw: &affinidi_messaging_mediator_config::DatabaseConfigRaw,
) -> Result<DatabaseConfig, MediatorError> {
    let functions_file = raw.functions_file.trim();
    let circuit_breaker_threshold = if raw.circuit_breaker_threshold.trim().is_empty() {
        5
    } else {
        values::number_at_least(
            "database.circuit_breaker_threshold",
            &raw.circuit_breaker_threshold,
            1,
        )
        .map_err(config_error)?
    };
    Ok(DatabaseConfig {
        functions_file: (!functions_file.is_empty()).then(|| functions_file.to_string()),
        database_url: raw.database_url.clone(),
        database_timeout: values::number_at_least(
            "database.database_timeout",
            &raw.database_timeout,
            1,
        )
        .map_err(config_error)?,
        cluster_mode: values::boolean_or("database.cluster_mode", &raw.cluster_mode, false)
            .map_err(config_error)?,
        circuit_breaker_threshold,
        circuit_breaker_recovery_secs: values::number_or(
            "database.circuit_breaker_recovery_secs",
            &raw.circuit_breaker_recovery_secs,
            10,
        )
        .map_err(config_error)?,
    })
}

/// The legal `log_level` values.
const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// `log_level`, read strictly: an unknown level used to become INFO.
fn log_level_from(raw: &str) -> Result<LevelFilter, MediatorError> {
    Ok(
        match values::one_of("log_level", raw, LOG_LEVELS).map_err(config_error)? {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "warn" => LevelFilter::WARN,
            "error" => LevelFilter::ERROR,
            _ => LevelFilter::INFO,
        },
    )
}

/// `streaming.uuid` must be `hostname://` or `string://<id>`.
fn check_streaming_uuid(raw: &str) -> Result<(), MediatorError> {
    if raw.starts_with("hostname://") || raw.starts_with("string://") {
        Ok(())
    } else {
        Err(config_error(ConfigError::invalid(
            "streaming.uuid",
            raw,
            "\"hostname://\" or \"string://<id>\"",
        )))
    }
}

/// Check every setting in `raw` that can be checked from the file alone —
/// no secret backend, no network — exactly as the conversion to [`Config`]
/// reads it, and return the `[limits]` it gives.
///
/// Run first thing at startup, so a bad value stops the mediator before it
/// opens a secret backend or contacts a VTA, and by `config/reload`, so a
/// reload that would not survive a restart fails and changes nothing (#112).
pub(crate) fn validate_raw(raw: &ConfigRaw) -> Result<LimitsConfig, MediatorError> {
    use security::SecurityConfigRawExt;

    affinidi_messaging_mediator_config::validate::check_secrets_backend(&raw.secrets.backend)
        .map_err(config_error_msg)?;
    secrets_cache_ttl(raw.secrets.cache_ttl.as_deref())?;
    log_level_from(&raw.log_level)?;
    values::boolean("log_json", &raw.log_json).map_err(config_error)?;
    let streaming =
        values::boolean("streaming.enabled", &raw.streaming.enabled).map_err(config_error)?;
    if streaming {
        check_streaming_uuid(&raw.streaming.uuid)?;
    }
    did_resolver_cache_config(&raw.did_resolver)?;
    database_config_from_raw(&raw.database)?;
    raw.security.values()?;
    processors::forwarding_config_from_raw(raw.processors.forwarding.clone())?;
    helpers::parse_blocked_forwarding_dids(&raw.processors.forwarding.blocked_forwarding_dids)?;
    MessageExpiryCleanupConfig::try_from(raw.processors.message_expiry_cleanup.clone())?;
    SessionExpiryCleanupConfig::try_from(raw.processors.session_expiry_cleanup.clone())?;
    if let Some(storage) = &raw.storage {
        check_storage(storage)?;
    }
    LimitsConfig::try_from(raw.limits.clone())
}

/// `[secrets] cache_ttl` in seconds: `None` when unset (the caller's
/// default), `Some(0)` for "never expires", otherwise a humantime duration
/// such as `"30d"` or `"12h"`. An unreadable value used to fall back to the
/// default with a warning.
fn secrets_cache_ttl(raw: Option<&str>) -> Result<Option<u64>, MediatorError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(0)),
        Some(ttl) => humantime::parse_duration(ttl)
            .map(|d| Some(d.as_secs()))
            .map_err(|e| {
                config_error(ConfigError::invalid(
                    "secrets.cache_ttl",
                    ttl,
                    format!("a duration such as \"30d\" or \"12h\", or \"0\" for never ({e})"),
                ))
            }),
    }
}

/// `[storage]`: a backend this mediator knows, and readable Fjall tuning.
fn check_storage(storage: &StorageConfig) -> Result<(), MediatorError> {
    let backend = values::one_of("storage.backend", &storage.backend, &["redis", "fjall"])
        .map_err(config_error)?;
    if backend == "fjall"
        && storage
            .data_dir
            .as_deref()
            .is_none_or(|d| d.trim().is_empty())
    {
        return Err(config_error_msg(
            "storage.data_dir (env STORAGE_DATA_DIR) is required when storage.backend is \
             \"fjall\""
                .into(),
        ));
    }
    if let Some(fjall) = &storage.fjall {
        for (key, value) in [
            ("storage.fjall.block_cache", &fjall.block_cache),
            ("storage.fjall.write_buffer", &fjall.write_buffer),
            ("storage.fjall.max_journal", &fjall.max_journal),
        ] {
            values::number::<u64>(key, value).map_err(config_error)?;
        }
        values::one_of(
            "storage.fjall.durability",
            &fjall.durability,
            &["buffered", "sync"],
        )
        .map_err(config_error)?;
    }
    Ok(())
}

/// Default VTA cache TTL when `[secrets].cache_ttl` is not set.
#[cfg(feature = "vta")]
const DEFAULT_CACHE_TTL_SECS: u64 = 30 * 86_400; // 30 days

/// Typed `[didcomm_v1]` settings. See
/// [`DidCommV1ConfigRaw`](affinidi_messaging_mediator_config::DidCommV1ConfigRaw)
/// for what each knob means and why `allow_unauthenticated_forwards` exists.
#[derive(Clone, Debug, Serialize)]
pub struct DidCommV1Config {
    pub enabled: bool,
    pub allow_unauthenticated_forwards: bool,
    /// `keylist-update` may register a key other than the request's own
    /// authenticated verkey.
    pub allow_unproven_routing_keys: bool,
    /// Most routing keys one account may hold.
    pub max_routing_keys_per_account: u32,
}

impl Default for DidCommV1Config {
    fn default() -> Self {
        affinidi_messaging_mediator_config::DidCommV1ConfigRaw::default().into()
    }
}

impl From<affinidi_messaging_mediator_config::DidCommV1ConfigRaw> for DidCommV1Config {
    fn from(raw: affinidi_messaging_mediator_config::DidCommV1ConfigRaw) -> Self {
        Self {
            enabled: raw.enabled,
            allow_unauthenticated_forwards: raw.allow_unauthenticated_forwards,
            allow_unproven_routing_keys: raw.allow_unproven_routing_keys,
            max_routing_keys_per_account: raw.max_routing_keys_per_account,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Config {
    #[serde(skip_serializing)]
    pub log_level: LevelFilter,
    #[serde(skip_serializing)]
    pub log_json: bool,
    pub listen_address: String,
    pub mediator_did: String,
    pub mediator_did_hash: String,
    /// Extracted DID document JSON served at `/.well-known/did.json`
    /// when self-hosting. Populated whether the on-disk source was a
    /// raw DID Document (did:web shape) or a webvh log entry — the
    /// loader extracts `state` from the latter so both routes serve
    /// canonical-shape content.
    pub mediator_did_doc: Option<String>,
    /// Typed copy of the mediator's own DID document, parsed once during
    /// config load (`from_raw`). Carried so the request-time server
    /// resolver can preload it via `preload_self_did` without
    /// re-deserialising `mediator_did_doc`. `Some` whenever this mediator
    /// self-hosts a document; `None` for builder-constructed configs,
    /// which set only the string form (the server then parses that as a
    /// fallback).
    #[serde(skip)]
    pub mediator_did_document: Option<Document>,
    /// Raw webvh log entry stream served at `/.well-known/did.jsonl`.
    /// `Some` only when the on-disk source parsed as a `LogEntry`
    /// (did:webvh self-host); `None` for the did:web shape, where the
    /// jsonl route is not registered.
    pub mediator_did_log: Option<String>,
    pub admin_did: String,
    pub api_prefix: String,
    /// Operator-declared URL aliases the mediator considers local. See
    /// [`ServerConfig::local_endpoints`]. Used by the routing 2.0
    /// forward handler to short-circuit when a next-hop's DIDComm
    /// service URI points back at this mediator under a different
    /// hostname (e.g., LB-fronted deployments).
    #[serde(default)]
    pub local_endpoints: Vec<String>,
    /// Trusted reverse-proxy CIDRs used for `X-Forwarded-For` rate-limit attribution.
    pub trust_xff_cidrs: Vec<affinidi_rate_limit::IpNet>,
    /// Client ranges allowed to read `/metrics` (see
    /// [`ServerConfig::metrics_allow_cidrs`]). Defaults to
    /// [`default_metrics_allow_cidrs`].
    pub metrics_allow_cidrs: Vec<affinidi_rate_limit::IpNet>,
    /// When set, `/metrics` also requires this bearer token.
    #[serde(skip_serializing)]
    pub metrics_bearer_token: Option<affinidi_messaging_mediator_config::RedactedString>,
    pub streaming_enabled: bool,
    pub streaming_uuid: String,
    /// Heartbeat and ownership-recheck timing of the streaming task. Not in
    /// the config file: the defaults suit production, and
    /// `MediatorBuilder::streaming_liveness` sets others.
    #[serde(skip)]
    pub streaming_liveness: crate::tasks::websocket_streaming::StreamingLiveness,
    /// Trust Task request type URIs refused as unsupported, as a mediator
    /// that predates them would refuse them. Not in the config file: it
    /// exists so a client's fallback can be tested against a real mediator
    /// (`MediatorBuilder::withhold_task_types`). Empty — everything served —
    /// by default.
    #[serde(skip)]
    pub withheld_task_types: Vec<String>,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    #[serde(skip_serializing)]
    pub did_resolver_config: DIDCacheConfig,
    pub processors: ProcessorsConfig,
    pub limits: LimitsConfig,
    pub tags: HashMap<String, String>,
    /// URL of the unified secret backend (`[secrets].backend` from
    /// the config file). Used by the secret-backend probe and surfaced
    /// in startup logs so operators can confirm the mediator is talking
    /// to the backend they expect. Intentionally NOT echoed in `/readyz`, which is
    /// unauthenticated and must not leak backend identity.
    #[serde(skip_serializing)]
    pub secrets_backend_url: String,
    /// Open handle to the unified secret backend. Cloned cheaply (it
    /// wraps an `Arc<dyn SecretStore>`) so the readiness handler can
    /// re-probe live without coordinating with the rest of the
    /// startup code path.
    #[serde(skip_serializing)]
    pub secrets_backend: MediatorSecrets,
    /// `true` when self-hosted operating keys were loaded from the
    /// backend at startup OR when VTA-managed operating keys came back
    /// from the VTA. `false` only in the (rare) configuration where
    /// neither source produced keys — typically a misconfiguration the
    /// operator wants to see surfaced on /readyz.
    #[serde(skip_serializing)]
    pub operating_keys_loaded: bool,
    /// Resolved storage backend selector. `None` → use the legacy
    /// `[database]` Redis path. `Some(StorageConfig)` → honour the
    /// `[storage]` section the wizard wrote.
    #[serde(default)]
    pub storage: Option<StorageConfig>,
    /// DIDComm v1 (Aries RFC 0019) settings, from `[didcomm_v1]`.
    ///
    /// Defaults to disabled. A mediator built without the `didcomm-v1` feature
    /// carries the parsed value but never acts on it — [`validate`] warns so an
    /// operator who enabled it in TOML is told the binary cannot honour it,
    /// rather than silently dropping every v1 message.
    #[serde(default)]
    pub didcomm_v1: DidCommV1Config,
    /// Inputs for the periodic VTA refresh task. `Some` only in
    /// VTA-linked deployments. The task itself is spawned by
    /// [`crate::server::serve_internal`] alongside the other
    /// background workers, gated on this field being `Some`.
    #[cfg(feature = "vta")]
    #[serde(skip)]
    pub vta_refresher: Option<crate::tasks::vta_refresh::VtaRefresher>,
}

/// Who may read `/metrics` when `[server] metrics_allow_cidrs` is absent:
/// loopback plus the private (RFC 1918), shared (RFC 6598, used by some
/// cluster networks), link-local and IPv6 unique-local ranges. A scraper in the
/// same cluster, VPC or host keeps working; a client on the public internet is
/// refused.
pub fn default_metrics_allow_cidrs() -> Vec<affinidi_rate_limit::IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .map(|cidr| cidr.parse().expect("built-in CIDR parses"))
    .collect()
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("log_json", &self.log_json)
            .field("listen_address", &self.listen_address)
            .field("mediator_did", &self.mediator_did)
            .field("mediator_did_hash", &self.mediator_did_hash)
            .field("admin_did", &self.admin_did)
            .field("mediator_did_doc", &"Hidden")
            .field("database", &self.database)
            .field("streaming_enabled?", &self.streaming_enabled)
            .field("streaming_uuid", &self.streaming_uuid)
            .field("streaming_liveness", &self.streaming_liveness)
            .field("DID Resolver config", &self.did_resolver_config)
            .field("api_prefix", &self.api_prefix)
            .field("security", &self.security)
            .field("processors", &self.processors)
            .field("Limits", &self.limits)
            .field("tags", &self.tags)
            .finish()
    }
}

impl Config {
    /// Construct a [`Config`] with placeholder identity fields and
    /// stubbed secret/JWT material. Embedding callers (and the
    /// `MediatorBuilder` it backs) start here and overwrite the
    /// fields that matter for their deployment.
    ///
    /// Not suitable for direct use — `mediator_did`, `admin_did`,
    /// `secrets_backend`, the database config, and the JWT keys must
    /// all be set before passing the result to the server.
    pub fn headless(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        Self::default(secrets_resolver)
    }

    fn default(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        let did_resolver_config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(1000)
            .with_cache_ttl(300)
            .with_network_timeout(DEFAULT_RESOLVER_NETWORK_TIMEOUT_MS)
            .with_network_cache_limit_count(100)
            .build();

        Config {
            log_level: LevelFilter::INFO,
            log_json: true,
            listen_address: "".into(),
            mediator_did: "".into(),
            mediator_did_hash: "".into(),
            mediator_did_doc: None,
            mediator_did_document: None,
            mediator_did_log: None,
            admin_did: "".into(),
            local_endpoints: Vec::new(),
            trust_xff_cidrs: Vec::new(),
            metrics_allow_cidrs: default_metrics_allow_cidrs(),
            metrics_bearer_token: None,
            database: DatabaseConfig::default(),
            streaming_enabled: true,
            streaming_uuid: "".into(),
            streaming_liveness: Default::default(),
            withheld_task_types: Vec::new(),
            did_resolver_config,
            api_prefix: "/mediator/v1".into(),
            // The default config is only used inside the early-startup
            // path before we've parsed `[secrets].backend`. Stub with
            // an empty URL + an in-memory store so the field is always
            // populated; production code overwrites it from the parsed
            // raw config below.
            secrets_backend_url: String::new(),
            secrets_backend: MediatorSecrets::new(std::sync::Arc::new(
                affinidi_messaging_mediator_common::secrets::backends::MemoryStore::new("memory"),
            )),
            operating_keys_loaded: false,
            storage: None,
            didcomm_v1: DidCommV1Config::default(),
            #[cfg(feature = "vta")]
            vta_refresher: None,
            security: SecurityConfig::default(secrets_resolver),
            processors: ProcessorsConfig {
                forwarding: ForwardingConfig::default(),
                message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
                session_expiry_cleanup: SessionExpiryCleanupConfig::default(),
            },
            limits: LimitsConfig::default(),
            tags: HashMap::from([("app".to_string(), "mediator".to_string())]),
        }
    }
}

/// Render a `VtaIntegrationError` from `integration::startup()` into a
/// `MediatorError::ConfigError` whose message names *both* what went
/// wrong and what the operator can do about it. Also emits a structured
/// `error!` log before returning so the failure cause is captured
/// independently of however the calling panic / process exit is
/// surfaced upstream.
///
/// `NoCachedSecrets` is the most operator-hostile path — the mediator
/// has never successfully contacted the VTA *and* the wizard didn't
/// seed the cache (or the cache was wiped). Spell out both remediation
/// paths so the operator doesn't have to read the SDK source to figure
/// out which one applies.
#[cfg(feature = "vta")]
fn vta_startup_error(context: &str, err: VtaIntegrationError) -> MediatorError {
    let detail = match &err {
        VtaIntegrationError::NoCachedSecrets => format!(
            "VTA is unreachable (or rejected the request) and no cached secrets \
             exist for context '{context}'. Either (a) restore VTA connectivity \
             and restart, or (b) re-run the setup wizard so it can seed the \
             last-known-bundle cache with the mediator's provisioned keys."
        ),
        VtaIntegrationError::EmptySecretsBundle(ctx) => format!(
            "VTA context '{ctx}' returned an empty secrets bundle. The context \
             must have at least one key provisioned — check the wizard's Vta \
             step completed, or inspect the context on the VTA admin side."
        ),
        VtaIntegrationError::CacheError(inner) => format!(
            "Local secret-cache backend failed for context '{context}': {inner}. \
             Check that the configured secret store (keyring / file / AWS / ...) \
             is reachable and that the mediator process has permission to read \
             from it."
        ),
        VtaIntegrationError::Vta(e) => format!(
            "VTA call failed for context '{context}' and no usable cache fallback \
             was available: {e}. If the VTA is reachable, look at the SDK warning \
             above for the specific error — a `validation error` typically means \
             the VTA-side context or DID is misconfigured rather than a network \
             problem."
        ),
        // `VtaIntegrationError` is `#[non_exhaustive]` (vta-sdk 0.77+).
        other => format!("VTA integration failed for context '{context}': {other}"),
    };
    error!(
        context = context,
        error = %err,
        "VTA startup failed terminally — mediator cannot boot"
    );
    if matches!(
        err,
        VtaIntegrationError::NoCachedSecrets | VtaIntegrationError::Vta(_)
    ) {
        print_vta_recovery_playbook(context);
    }
    MediatorError::ConfigError(12, "NA".into(), detail)
}

/// Print an operator-facing recovery playbook to stderr when the
/// mediator can't boot because the cached VTA bundle is gone (or stale)
/// AND the VTA is unreachable.
///
/// The block is intentionally formatted for `journalctl` / `docker logs`
/// readability: a banner that's easy to spot in a wall of structured
/// log output, followed by numbered steps with concrete commands. We
/// write to stderr (not via `tracing`) so the message survives any
/// `RUST_LOG` filter — the operator needs this regardless of log
/// configuration when the process is about to exit.
#[cfg(feature = "vta")]
fn print_vta_recovery_playbook(context: &str) {
    eprintln!(
        "
================================================================================
  MEDIATOR CANNOT START — VTA UNREACHABLE AND NO USABLE CACHE
================================================================================

  Context: {context}

  The mediator could not contact the VTA AND has no fresh cached secret
  bundle to fall back on. To recover, request fresh credentials from the
  VTA admin / Personal Network Manager (PNM) and re-seed this mediator's
  cache. Pick whichever path matches your situation:

  ──────────────────────────────────────────────────────────────────────
  OPTION A — Restore VTA connectivity (fastest)
  ──────────────────────────────────────────────────────────────────────

    If the VTA outage is transient (network blip, VTA host restarting,
    DNS hiccup, etc.) the simplest fix is to restore connectivity and
    restart the mediator. The next successful VTA call will re-seed the
    cache automatically.

      1. Confirm reachability from this host:
           curl -fsS <vta-url>/healthz
      2. Restart the mediator once the VTA is responding.

  ──────────────────────────────────────────────────────────────────────
  OPTION B — Re-provision credentials (sealed-export mode)
  ──────────────────────────────────────────────────────────────────────

    Use this when the existing context on the VTA is intact but this
    mediator's local cache and/or secrets are gone (e.g. lost host,
    wiped disk, expired keyring). Sealed-export reissues the bundle
    without minting a new DID — your mediator's identity stays the
    same.

    You'll need the original setup recipe (`recipe.toml`) used to
    deploy this mediator, with `vta_mode = \"sealed-export\"`. If it's
    been lost, see Option C.

      1. On the mediator host, regenerate a request:
           mediator-setup --from <recipe.toml> --force-reprovision

      2. Hand the resulting request file to your VTA admin. On the VTA
         host, they run:
           vta contexts reprovision --id {context} \\
             --recipient <request.json> \\
             --output <bundle.armor>

      3. Copy `bundle.armor` back to the mediator host and finalise:
           mediator-setup --from <recipe.toml> --bundle <bundle.armor>

      4. Restart the mediator.

  ──────────────────────────────────────────────────────────────────────
  OPTION C — Greenfield re-setup
  ──────────────────────────────────────────────────────────────────────

    Use this only when the context itself is gone on the VTA side, or
    you want to start over with a new mediator DID. This MINTS A NEW
    IDENTITY — clients will need to re-authenticate against the new
    DID.

      mediator-setup

    Pick `Full setup — VTA mints my mediator DID` and follow the
    prompts. See docs/setup-guide.md for the full walkthrough.

  ──────────────────────────────────────────────────────────────────────
  More: docs/setup-guide.md (sections 'Online' and 'Sealed-export')
================================================================================
"
    );
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        // Every value the file alone decides, checked before anything is
        // opened or contacted. The conversions below read the same values the
        // same way; this only moves the failure ahead of the side effects.
        validate_raw(&raw)?;

        // Lazy AWS initialization — only load AWS SDK config when an AWS scheme
        // is actually used in the configuration. This avoids the 3+ second IMDS
        // timeout on non-AWS machines.
        let needs_aws = helpers::config_needs_aws(&raw);

        #[cfg(feature = "aws")]
        let aws_config: Option<AwsConfig> = if needs_aws {
            info!("AWS scheme detected in config — initializing AWS SDK");
            let mut builder = aws_config::defaults(BehaviorVersion::latest());
            if let Ok(region) = env::var("AWS_REGION") {
                builder = builder.region(Region::new(region));
            }
            Some(builder.load().await)
        } else {
            None
        };

        #[cfg(not(feature = "aws"))]
        let aws_config: Option<AwsConfig> = {
            if needs_aws {
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "Configuration uses aws_secrets://, aws_parameter_store://, or s3:// but the \
                     'aws' feature is not enabled. Rebuild with: cargo build --features aws"
                        .into(),
                ));
            }
            None
        };

        let mut tags = HashMap::from([("app".to_string(), "mediator".to_string())]);
        for (key, value) in env::vars() {
            if key.get(..13) == Some("MEDIATOR_TAG_")
                && let Some(tag_key) = key.get(13..)
            {
                tags.insert(tag_key.to_lowercase(), value);
            }
        }

        let secrets_resolver = Arc::new(ThreadedSecretsResolver::new(None).await.0);

        // ── Secret backend ──────────────────────────────────────────────
        // Open the unified secret store and probe end-to-end. Failing here
        // with a clear error beats discovering the backend is unreachable
        // on the first request. Opened on the blocking pool: the encrypted
        // `file://` backend runs Argon2id and reads its file there.
        let store = open_store_async(&raw.secrets.backend).await.map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Could not open secret backend '{}': {e}",
                    raw.secrets.backend
                ),
            )
        })?;
        let mediator_secrets = MediatorSecrets::new(store);
        // Read-only probe: verify reachability without needing write perms.
        mediator_secrets.probe_readonly().await.map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Secret backend '{}' failed probe: {e}", raw.secrets.backend),
            )
        })?;
        // Move a per-key deployment into the single-secret layout before
        // anything reads from it. A failure stops the mediator here, with
        // the cause and the fix, and leaves the store as it was.
        mediator_secrets.ensure_migrated().await.map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Secret backend '{}' could not be moved to the single-secret layout: {e}",
                    raw.secrets.backend
                ),
            )
        })?;
        if parse_url(&raw.secrets.backend).is_ok_and(|url| url.is_plaintext_file()) {
            warn!(
                "Secret backend is file:// — secrets are plaintext on disk. \
                 Only use this for local dev/test."
            );
        }
        if let Some(warning) = keyring_backend_warning(&raw.secrets.backend) {
            warn!("{warning}");
        }

        // ── VTA integration ────────────────────────────────────────────
        // If the backend has an admin credential, we're in VTA mode:
        // authenticate, fetch fresh operating keys, cache them, fall back
        // to the cached copy if the VTA is unreachable.
        //
        // Not read at all without the `vta` feature — and not loaded either,
        // rather than loaded and discarded: the credential is the input to
        // the branch below, so a build that cannot take that branch has no
        // reason to touch the backend for it.
        #[cfg(feature = "vta")]
        let admin_cred = mediator_secrets
            .load_admin_credential()
            .await
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Could not load admin credential: {e}"),
                )
            })?;

        // Only the VTA-linked shape drives the VTA startup branch.
        // Self-hosted admin credentials (stored so subsequent wizard
        // runs can recover the private key) have `vta_did` / `vta_url`
        // unset; the mediator skips VTA integration for those.
        #[cfg(feature = "vta")]
        let vta_startup = if let Some(admin) = admin_cred.as_ref().filter(|a| a.is_vta_linked()) {
            let credential = CredentialBundle {
                did: admin.did.clone(),
                private_key_multibase: admin.private_key_multibase.clone(),
                vta_did: admin
                    .vta_did
                    .clone()
                    .expect("is_vta_linked() guarantees vta_did is Some"),
                vta_url: admin.vta_url.clone(),
            };
            // vta-sdk 0.6.x split `VtaServiceConfig` into an
            // `auth` block (credential + URL + timeout) and a
            // `context` block (id + transport preferences + DID
            // resolver). Construct explicitly rather than using
            // `VtaServiceConfig::new` because we want to express
            // each transport default in a comment, not hide them
            // behind the convenience constructor.
            let service_config = VtaServiceConfig {
                auth: integration::VtaAuthConfig {
                    credential,
                    url_override: admin.vta_url.clone().filter(|u| !u.is_empty()),
                    timeout: None,
                },
                context: integration::VtaContextConfig {
                    id: admin.context.clone(),
                    // DIDComm-first with REST fallback: the mediator
                    // already speaks DIDComm for its primary workload,
                    // and the VTA exposes its `DIDCommMessaging`
                    // service endpoint in its DID doc. Auto-preference
                    // lets the SDK try DIDComm when `mediator_did` is
                    // resolvable and fall through to REST otherwise —
                    // no circular-dependency hazard because
                    // `integration::startup` resolves the VTA's
                    // mediator from the VTA's DID doc, not from our
                    // own config.
                    mediator_did: None,
                    transport_preference: TransportPreference::Auto,
                    // `None` → SDK builds a one-shot resolver on
                    // demand. Mediator boot is a one-shot flow so we
                    // don't share our own `did_resolver` here; it
                    // isn't constructed until later in this TryFrom.
                    // Sharing it would require reordering the config
                    // build, which is a bigger change than this
                    // wire-up warrants.
                    did_resolver: None,
                },
            };

            // Cache TTL — 30 days when unset, `0` means no expiry.
            let ttl_secs = secrets_cache_ttl(raw.secrets.cache_ttl.as_deref())?
                .unwrap_or(DEFAULT_CACHE_TTL_SECS);
            let cache = vta_cache::MediatorSecretCache::new(mediator_secrets.clone(), ttl_secs);

            // Two-line bootstrap narrative: what we're *attempting* first,
            // what we actually *got* second (see the post-startup match
            // below). Operators reading `journalctl` / container logs
            // need both — "did it try?" + "did it succeed, and from
            // where?" — without chasing the SDK's internal log lines.
            info!(
                context = %service_config.context.id,
                vta_url = %service_config.auth.url_override.as_deref().unwrap_or("(from DID doc)"),
                "Starting VTA integration — attempting live fetch with cache fallback"
            );
            let result = vta_bootstrap::bootstrap_vta(&service_config, &cache, &mediator_secrets)
                .await
                .map_err(|e| vta_startup_error(&service_config.context.id, e))?;
            match result.source {
                SecretSource::Vta => info!(
                    context = %service_config.context.id,
                    did = %result.did,
                    secrets = result.bundle.secrets.len(),
                    "VTA integration OK — loaded fresh secrets from VTA"
                ),
                SecretSource::Cache => warn!(
                    context = %service_config.context.id,
                    did = %result.did,
                    secrets = result.bundle.secrets.len(),
                    "VTA integration DEGRADED — booted from LAST-KNOWN CACHED secrets. \
                     Mediator will continue to run with keys as of the last successful VTA \
                     contact; the runtime will refresh the cache on the next successful call. \
                     Investigate the preceding SDK warning for the root cause."
                ),
            }

            if let Some(client) = &result.client {
                match client.health().await {
                    Ok(health) => {
                        if health.mediator_did.as_deref() == Some(&result.did) {
                            warn!(
                                "CIRCULAR DEPENDENCY: This mediator's DID ({}) matches the VTA's \
                                 configured mediator DID. REST bootstrapping prevents startup deadlock, \
                                 but both services are interdependent.",
                                result.did
                            );
                        } else if let Some(vta_med_url) = &health.mediator_url
                            && health.mediator_did.is_some()
                        {
                            info!(
                                "VTA reports mediator dependency — mediator_did: {:?}, mediator_url: {:?}",
                                health.mediator_did.as_deref().unwrap_or("none"),
                                vta_med_url,
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Could not check VTA health for circular dependency detection (non-fatal): {e}"
                        );
                    }
                }
            }

            // Build the refresher alongside the startup result so the
            // outer scope can stash it on Config without re-deriving
            // service_config / ttl_secs.
            let refresher = crate::tasks::vta_refresh::VtaRefresher::new(
                service_config.clone(),
                mediator_secrets.clone(),
                ttl_secs,
                secrets_resolver.clone(),
            )
            // Our own DID, so each refresh tick can tell whether the VTA routes
            // back through us and pick REST if it does.
            .with_mediator_did(result.did.clone());

            Some((result, refresher))
        } else {
            None
        };

        // ── Project the startup result into mediator-local values ────────
        //
        // Everything below this point reads these two rather than the SDK's
        // `StartupResult`, so it compiles identically with or without the
        // `vta` feature and needs no `cfg` of its own. Without the feature
        // there is no key authority, and every consumer takes the
        // self-hosted branch it already had.
        #[cfg(feature = "vta")]
        let authority_did: Option<String> = vta_startup.as_ref().map(|(r, _)| r.did.clone());
        #[cfg(not(feature = "vta"))]
        let authority_did: Option<String> = None;

        #[cfg(feature = "vta")]
        let operating_secrets: Option<Vec<OperatingSecret>> = vta_startup.as_ref().map(|(r, _)| {
            r.bundle
                .secrets
                .iter()
                .map(|entry| OperatingSecret {
                    key_id: entry.key_id.clone(),
                    private_key_multibase: entry.private_key_multibase.clone(),
                })
                .collect()
        });
        #[cfg(not(feature = "vta"))]
        let operating_secrets: Option<Vec<OperatingSecret>> = None;

        // Resolve mediator DID — from VTA startup result (if VTA mode)
        // or the mediator.toml `mediator_did` field (self-hosted mode).
        let mediator_did = if let Some(did) = &authority_did {
            did.clone()
        } else {
            read_did_config(&raw.mediator_did, &aws_config, "mediator_did").await?
        };

        let mut config = Config {
            log_level: log_level_from(&raw.log_level)?,
            log_json: values::boolean("log_json", &raw.log_json).map_err(config_error)?,
            listen_address: raw.server.listen_address,
            mediator_did,
            admin_did: read_did_config(&raw.server.admin_did, &aws_config, "admin_did").await?,
            local_endpoints: raw.server.local_endpoints,
            trust_xff_cidrs: raw.server.trust_xff_cidrs,
            metrics_allow_cidrs: raw
                .server
                .metrics_allow_cidrs
                .unwrap_or_else(default_metrics_allow_cidrs),
            metrics_bearer_token: raw
                .server
                .metrics_bearer_token
                .filter(|token| !token.0.is_empty()),
            database: database_config_from_raw(&raw.database)?,
            streaming_enabled: values::boolean("streaming.enabled", &raw.streaming.enabled)
                .map_err(config_error)?,
            did_resolver_config: did_resolver_cache_config(&raw.did_resolver)?,
            api_prefix: {
                let normalized = helpers::normalize_api_prefix(&raw.server.api_prefix);
                if normalized != raw.server.api_prefix {
                    info!(
                        original = %raw.server.api_prefix,
                        normalized = %normalized,
                        "api_prefix normalized — empty/`/` means mount at root, otherwise canonical form is `/<segment>` with no trailing slash"
                    );
                }
                normalized
            },
            security: raw
                .security
                .convert(
                    secrets_resolver.clone(),
                    &mediator_secrets,
                    operating_secrets.as_deref(),
                )
                .await?,
            processors: ProcessorsConfig {
                forwarding: processors::forwarding_config_from_raw(
                    raw.processors.forwarding.clone(),
                )?,
                message_expiry_cleanup: raw.processors.message_expiry_cleanup.clone().try_into()?,
                session_expiry_cleanup: raw.processors.session_expiry_cleanup.clone().try_into()?,
            },
            limits: raw.limits.try_into()?,
            tags,
            secrets_backend_url: raw.secrets.backend.clone(),
            secrets_backend: mediator_secrets.clone(),
            // Pass the optional `[storage]` section through unchanged.
            // server::serve_internal inspects it to decide between the
            // legacy Redis path and the embedded Fjall path.
            storage: raw.storage.clone(),
            didcomm_v1: raw
                .didcomm_v1
                .clone()
                .map(DidCommV1Config::from)
                .unwrap_or_default(),
            // Operating keys come either from the VTA (when integration
            // is active) or from the unified backend's well-known
            // `mediator_operating_secrets` entry (self-hosted). The
            // security converter has just done both lookups by the time
            // we get here, so we can ask the backend directly: if the
            // entry is present we loaded it; otherwise the VTA bundle
            // (when present) supplied them.
            operating_keys_loaded: authority_did.is_some()
                || mediator_secrets
                    .load_entry::<Vec<affinidi_secrets_resolver::secrets::Secret>>(
                        affinidi_messaging_mediator_common::OPERATING_SECRETS,
                        "operating-secrets",
                    )
                    .await
                    .ok()
                    .flatten()
                    .is_some(),
            // VTA-linked deployments get a periodic refresh task; built
            // alongside the StartupResult above so the service config
            // and TTL parsing aren't re-derived here.
            #[cfg(feature = "vta")]
            vta_refresher: vta_startup.as_ref().map(|(_, refresher)| refresher.clone()),
            ..Config::default(secrets_resolver)
        };

        config.mediator_did_hash =
            affinidi_messaging_mediator_common::did_identity::did_hash(&config.mediator_did);

        // Initialise a mutable did document for later use on validation and resolver loading
        let mut did_document: Option<Document> = None;

        // Are we self-hosting our own did:web Document?
        if let Some(path) = raw.server.did_web_self_hosted {
            let document_json = read_document(&path, &aws_config).await?;

            let (did_json, did_jsonl, parsed_document) =
                split_self_hosted_did_source(document_json, &config.mediator_did)?;
            config.mediator_did_doc = Some(did_json);
            config.mediator_did_log = did_jsonl;

            // Store the parsed Document for later use
            did_document = Some(parsed_document);
        }

        // Cross-field config invariants (incl. JWT access < refresh) are
        // validated as one pass once `config` is fully populated — see the
        // `validate::validate_config` call before `Ok(config)` below.

        // Get Subscriber unique hostname
        if config.streaming_enabled {
            config.streaming_uuid = get_hostname(&raw.streaming.uuid)?;
        }

        // Fill out the forwarding protection for DIDs and associated service endpoints
        // This protects against the mediator forwarding messages to itself.
        let mut did_resolver = DIDCacheClient::new(config.did_resolver_config.clone())
            .await
            .map_err(|err| {
                MediatorError::DIDError(
                    12,
                    "NA".into(),
                    "NA".into(),
                    format!("Couldn't start DID Resolver: {err}"),
                )
            })?;

        // Load the Local DID Document if self hosted. Preload it into this
        // (config-validation) resolver so forwarding-loop detection can
        // resolve our own DID, and stash the typed document on the config so
        // the request-time server resolver can preload the same document
        // without parsing it a second time.
        if let Some(mediator_doc) = did_document {
            preload_self_did(&mut did_resolver, &config.mediator_did, &mediator_doc).await;
            config.mediator_did_document = Some(mediator_doc);
        }

        // ── Guard: operating secrets must be able to decrypt our own traffic ──
        //
        // See `assert_operating_secrets_cover_key_agreement`. For a self-hosted
        // DID we check against the local document we just loaded. For a
        // VTA-managed / network-published DID (no `did_web_self_hosted`) we
        // resolve our *own* published DID and check against that — that path was
        // previously unguarded, so a VTA key-label/kid mismatch booted clean and
        // failed every request at runtime. A resolver failure is logged and
        // skipped (a transient DID-host blip must not block boot); only a
        // *confirmed* coverage gap aborts startup.
        match &config.mediator_did_document {
            Some(doc) => {
                assert_operating_secrets_cover_key_agreement(
                    doc,
                    config.security.mediator_secrets.as_ref(),
                )
                .await?;
            }
            None => match did_resolver.resolve(&config.mediator_did).await {
                Ok(resolved) => {
                    assert_operating_secrets_cover_key_agreement(
                        &resolved.doc,
                        config.security.mediator_secrets.as_ref(),
                    )
                    .await?;
                }
                Err(err) => {
                    warn!(
                        mediator_did = %config.mediator_did,
                        error = %err,
                        "Could not resolve our own published DID document at boot; skipping the \
                         operating-secret coverage guard. Inbound DIDComm decryption is unverified \
                         — a key/kid mismatch would surface at runtime as \"No local secret matches \
                         any JWE recipient\"."
                    );
                }
            },
        }

        // A DID that does not resolve now is blocked by its DID at once and
        // its endpoints are added when it does: a third party's DID host being
        // down must not stop this mediator starting (#146).
        load_forwarding_protection_blocks(
            &did_resolver,
            &mut config.processors.forwarding,
            &config.mediator_did,
            &raw.processors.forwarding.blocked_forwarding_dids,
        )
        .await?;

        // Boot-time invariant validation: hard conflicts abort startup with
        // an actionable message; suspicious-but-legal combinations warn.
        validate::validate_config(&config)?;

        Ok(config)
    }
}

/// Split a self-hosted DID source into the bodies served at the well-known
/// routes, returning `(did.json body, did.jsonl body, typed Document)`.
///
/// The source is either a DID document (did:web) — one JSON object — or a
/// did:webvh log: JSON Lines, one log entry per line, as many entries as the
/// DID has versions. A log is parsed entry by entry and its chain verified
/// (each entry's proof, version and parameters against its predecessor; see
/// [`verify_webvh_log`]); `did.json` serves the **last** entry's document and
/// `did.jsonl` the source exactly as read. The whole log used to be parsed as
/// one JSON value, so a log with a second entry — after the first key
/// rotation — stopped the mediator starting (#120).
///
/// We split the canonical DID Document (served at `did.json`) from the raw
/// log (served at `did.jsonl`) so each well-known route returns the correct
/// shape.
///
/// For did:webvh sources the `did.json` body's identifier is additionally
/// rewritten from `did:webvh:{scid}:{domain}` to `did:web:{domain}` (id,
/// controller, key and service self-references). `did.json` is the did:web
/// resolution surface; without the rewrite a `did:web:{domain}` resolver
/// receives a document whose id and `#key-…` references all live under
/// `did:webvh:`, so they can't be dereferenced. The `did.jsonl` body
/// (`Some` only for did:webvh sources) and the typed Document both stay
/// verbatim (real did:webvh) for did:webvh resolvers and the mediator's own
/// DID.
///
/// When the mediator presents its identity as a `did:scid:vh:1` DID
/// (`mediator_did`), the log is still served verbatim at `did.jsonl` (it *is*
/// the did:scid's verification metadata) and `did.json` still bridges to
/// did:web, but the typed Document is the did:scid's own: `id` the bare
/// did:scid DID and every self-reference under it, so the resolver preload
/// answers for the identity the mediator packs and unpacks as.
fn split_self_hosted_did_source(
    source: String,
    mediator_did: &str,
) -> Result<(String, Option<String>, Document), MediatorError> {
    let source_err = |msg: String| {
        error!("server.did_web_self_hosted: {msg}");
        config_error_msg(format!("server.did_web_self_hosted: {msg}"))
    };

    // One JSON value that is not a log entry: a did:web document.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&source)
        && !is_webvh_log_entry(&value)
    {
        let typed = serde_json::from_value::<Document>(value).map_err(|err| {
            source_err(format!(
                "the content is neither a DID document nor a did:webvh log: {err}"
            ))
        })?;
        return Ok((source, None, typed));
    }

    // A did:webvh log.
    let did_doc_value = verify_webvh_log(&source).map_err(source_err)?;

    // The extracted state's `id` is the did:webvh DID; rewrite it (and every
    // self-reference) to the did:web form for the `did.json` handler. The
    // typed `Document` below is parsed from the original `did:webvh` value so
    // the resolver preload keeps the mediator's real DID.
    let webvh_did = did_doc_value
        .get("id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| source_err("the log's last DID document has no `id`".into()))?
        .to_string();

    let (_web_did, web_doc_value) = rewrite_did_document_to_web(&did_doc_value, &webvh_did)
        .map_err(|err| {
            source_err(format!(
                "couldn't rewrite did:webvh document to did:web: {err}"
            ))
        })?;

    // Serialise the rewritten did:web document for the did.json handler. The
    // resolver receives the typed `Document` below (parsed from the original
    // did:webvh value) so we don't pay double parse costs at request time.
    let did_json = serde_json::to_string(&web_doc_value)
        .map_err(|err| source_err(format!("couldn't serialise the DID document: {err}")))?;

    let did_doc_value = if mediator_did.starts_with("did:scid:") {
        scid_document(&did_doc_value, mediator_did)?
    } else {
        did_doc_value
    };

    let typed = serde_json::from_value(did_doc_value)
        .map_err(|err| source_err(format!("the log's DID document is not valid: {err}")))?;

    Ok((did_json, Some(source), typed))
}

/// Whether `value` looks like a did:webvh log entry rather than a DID
/// document.
fn is_webvh_log_entry(value: &serde_json::Value) -> bool {
    value.get("versionId").is_some() && value.get("state").is_some()
}

/// Parse a did:webvh log (JSON Lines, one entry per non-empty line), verify
/// its chain with didwebvh-rs — each entry's proof, `versionId` and parameter
/// transition against the entry before it — and return the last entry's DID
/// document.
///
/// Witness proofs are not checked: the mediator does not serve
/// `did-witness.json`, so a resolver that requires witnesses checks them
/// against wherever that file is published. A log whose last valid entry
/// deactivates the DID is refused: a mediator cannot run as a deactivated DID.
fn verify_webvh_log(source: &str) -> Result<serde_json::Value, String> {
    let mut entries = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, None).map_err(|err| {
            format!(
                "line {} is not a did:webvh log entry (and the content is not a DID \
                 document): {err}",
                index + 1
            )
        })?;
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("the did:webvh log is empty".into());
    }

    let mut state = didwebvh_rs::DIDWebVHState::from_log_entries(entries);
    let log = state.log_entries_mut();
    for at in 0..log.len() {
        let (verified, rest) = log.split_at_mut(at);
        let entry = &mut rest[0];
        entry.verify_log_entry(verified.last()).map_err(|err| {
            format!(
                "did:webvh log entry {} ({}) does not verify: {err}",
                at + 1,
                entry.get_version_id()
            )
        })?;
        if entry.validated_parameters.deactivated == Some(true) {
            return Err(format!(
                "did:webvh log entry {} ({}) deactivates the DID",
                at + 1,
                entry.get_version_id()
            ));
        }
    }
    let last = log.last().ok_or("the did:webvh log is empty")?;
    last.get_did_document()
        .map_err(|err| format!("couldn't extract the DID document from the log: {err}"))
}

/// The did:scid's own document for a self-hosted did:webvh log, refusing a log
/// whose SCID is not the one `mediator_did` names.
fn scid_document(
    webvh_document: &serde_json::Value,
    mediator_did: &str,
) -> Result<serde_json::Value, MediatorError> {
    let document = didwebvh_rs::did_web::to_scid_did_document(webvh_document).map_err(|err| {
        error!("Couldn't express the did:webvh log as did:scid {mediator_did}. Reason: {err}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Couldn't express the did:webvh log as did:scid {mediator_did}. Reason: {err}"),
        )
    })?;
    let identity = affinidi_messaging_mediator_common::did_identity::account_did(mediator_did);
    if document.get("id").and_then(serde_json::Value::as_str) != Some(identity.as_ref()) {
        error!("The self-hosted did:webvh log is not the log of {mediator_did}");
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "mediator_did is {mediator_did}, but the self-hosted log is {}",
                document
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing an id")
            ),
        ));
    }
    Ok(document)
}

/// Ensure the mediator's DID document advertises a `TSPTransport` service so peers can
/// discover its TSP endpoint (remote routed/nested forwarding resolves it from the DID
/// document). For **did:web** the service is added automatically, mirroring the
/// `DIDCommMessaging` endpoint (TSP and DIDComm share `/inbound`); **did:peer** and
/// **did:webvh** bind the document to the DID, so their service must be baked in at DID
/// generation — there we only warn. A no-op unless the `tsp` feature is on.
///
/// Called once at startup ([`crate::server::serve_internal`]) so it covers both the
/// config-file path (typed `mediator_did_document`) and the builder path (served JSON
/// only).
#[cfg(feature = "tsp")]
pub(crate) fn apply_tsp_did_advertisement(config: &mut Config) {
    // Work from the typed document if we have it (config-file path), else parse the
    // served JSON (builder path). No self-hosted document (e.g. a network-published
    // did:peer) → nothing to advertise here.
    let mut doc = match config.mediator_did_document.clone() {
        Some(doc) => doc,
        None => match config
            .mediator_did_doc
            .as_ref()
            .and_then(|json| serde_json::from_str::<Document>(json).ok())
        {
            Some(doc) => doc,
            None => return,
        },
    };

    // did:web (no webvh log) is the only form we may safely mutate in place.
    if config.mediator_did_log.is_none()
        && let Some(augmented) =
            augment_did_web_doc_with_tsp_service(&mut doc, &config.mediator_did)
    {
        config.mediator_did_doc = Some(augmented);
        config.mediator_did_document = Some(doc.clone());
    }

    if !doc
        .service
        .iter()
        .any(|s| s.type_.iter().any(|t| t == affinidi_tsp::TSP_SERVICE_TYPE))
    {
        warn!(
            "TSP is enabled but the mediator DID document advertises no '{}' service; \
             other mediators cannot discover this mediator's TSP endpoint for routed/nested \
             forwarding. For did:web it is added automatically from the DIDCommMessaging \
             endpoint (is one present?); for did:peer / did:webvh add the service at DID \
             generation.",
            affinidi_tsp::TSP_SERVICE_TYPE
        );
    }
}

/// Ensure a self-hosted **did:web** document advertises a `TSPTransport` service,
/// mirroring the `DIDCommMessaging` endpoint (TSP and DIDComm share the mediator's
/// `/inbound`). Returns the re-serialised document JSON when a service was added, or
/// `None` if the document already advertises TSP or has no DIDComm endpoint to mirror.
///
/// Only safe for did:web, where the served document is authoritative — did:peer and
/// did:webvh bind the document to the DID, so their service must be set at generation.
#[cfg(feature = "tsp")]
fn augment_did_web_doc_with_tsp_service(doc: &mut Document, did: &str) -> Option<String> {
    use affinidi_did_common::ServiceBuilder;
    use affinidi_did_common::service::Endpoint;

    let tsp_type = affinidi_tsp::TSP_SERVICE_TYPE;

    // Already advertised — nothing to do.
    if doc
        .service
        .iter()
        .any(|s| s.type_.iter().any(|t| t == tsp_type))
    {
        return None;
    }

    // Mirror the first DIDCommMessaging endpoint URI — TSP lands on the same `/inbound`.
    let uri = doc
        .service
        .iter()
        .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .and_then(|s| s.service_endpoint.get_uri())?;
    let endpoint = url::Url::parse(&uri).ok()?;

    let service = ServiceBuilder::new(tsp_type, Endpoint::Url(endpoint))
        .id(&format!("{did}#tsp"))
        .ok()?
        .build();
    doc.service.push(service);

    serde_json::to_string(doc).ok()
}

/// Warn when the mediator's DID document advertises a `TSPTransport` service but
/// the binary was built **without** the `tsp` feature. Some DID templates (e.g.
/// the VTA / self-hosted webvh `didcomm-mediator` template) may carry a `#tsp`
/// service unconditionally; if TSP was not compiled in, the mediator cannot
/// actually sniff or handle TSP at ingress, so remote peers that resolve the
/// service and route TSP here will have their messages misclassified as DIDComm
/// and rejected. This is the inverse of [`apply_tsp_did_advertisement`]'s
/// "TSP on but nothing advertised" warning; it runs only on non-TSP builds.
///
/// The `TSPTransport` type is spelled out here rather than referenced via
/// `affinidi_tsp::TSP_SERVICE_TYPE` because that crate is not a dependency when
/// the `tsp` feature is off; the two must stay in sync (both are `"TSPTransport"`).
#[cfg(not(feature = "tsp"))]
pub(crate) fn warn_if_tsp_advertised_without_feature(config: &Config) {
    const TSP_SERVICE_TYPE: &str = "TSPTransport";

    let advertises_tsp = config
        .mediator_did_document
        .as_ref()
        .map(|doc| {
            doc.service
                .iter()
                .any(|s| s.type_.iter().any(|t| t == TSP_SERVICE_TYPE))
        })
        .or_else(|| {
            config
                .mediator_did_doc
                .as_ref()
                .and_then(|json| serde_json::from_str::<Document>(json).ok())
                .map(|doc| {
                    doc.service
                        .iter()
                        .any(|s| s.type_.iter().any(|t| t == TSP_SERVICE_TYPE))
                })
        })
        .unwrap_or(false);

    if advertises_tsp {
        warn!(
            "The mediator DID document advertises a '{TSP_SERVICE_TYPE}' service, but this \
             binary was built without the `tsp` feature. Remote mediators will attempt to \
             route TSP here and their messages will be rejected. Either rebuild with \
             `--features didcomm,tsp` or remove the '{TSP_SERVICE_TYPE}' service from the \
             DID document (for VTA-managed DIDs, disable TSP in the DID template)."
        );
    }
}

/// The startup warning for a `keyring://` secret backend on Linux, where the
/// keyring backend is the kernel keyring (keyutils): its keys do not survive a
/// reboot, so the JWT key, admin credential and operating keys are lost and the
/// mediator then refuses to start (#126).
fn keyring_backend_warning(backend: &str) -> Option<String> {
    (cfg!(target_os = "linux") && backend.trim_start().starts_with("keyring://")).then(|| {
        "Secret backend is keyring:// on Linux, which is the kernel keyring (keyutils): \
         its keys are lost on reboot, and the mediator will then refuse to start without \
         its JWT key, admin credential and operating keys. Use it for desktop development \
         only; choose a persistent backend (aws_secrets://, vault://, k8s://, \
         file://…?encrypt=1, …) for anything else. See docs/secrets-backend.md."
            .to_string()
    })
}

/// Resolve every filesystem path written in the configuration file against
/// that file's directory (Keyring VTI-07); see
/// [`affinidi_messaging_mediator_common::config_path`] for the rule and its
/// legacy fallback.
///
/// A path set by **environment variable** is left exactly as given. It was not
/// written in the config file, so "relative to the config file" is not what it
/// means — relative to where the process started is — and resolving it here
/// would also report it as deprecated, which it is not.
fn resolve_configured_paths(config: &mut ConfigRaw, config_file: &Path) {
    use affinidi_messaging_mediator_common::config_path::{PathSource, resolve_config_relative};

    let resolve = |label: &str, env_var: &str, raw: &str| -> String {
        if env::var_os(env_var).is_some() {
            return raw.to_string();
        }
        let resolved = resolve_config_relative(config_file, raw);
        if resolved.source == PathSource::WorkingDir {
            warn!(
                setting = label,
                path = raw,
                config_file = %config_file.display(),
                "resolved `{label}` against the working directory because it is not \
                 beside the config file; this fallback is deprecated. Move the file \
                 next to the config, or write the path relative to the config file."
            );
        }
        resolved.path.to_string_lossy().into_owned()
    };

    config.database.functions_file = resolve(
        "functions_file",
        "DATABASE_FUNCTIONS_FILE",
        &config.database.functions_file,
    );
    if let Some(cert) = config.security.ssl_certificate_file.as_deref() {
        config.security.ssl_certificate_file = Some(resolve(
            "ssl_certificate_file",
            "SSL_CERTIFICATE_FILE",
            cert,
        ));
    }
    if let Some(key) = config.security.ssl_key_file.as_deref() {
        config.security.ssl_key_file = Some(resolve("ssl_key_file", "SSL_KEY_FILE", key));
    }
    // `did_web_self_hosted = "file://<path>"`: the path, not the URL.
    if let Some(path) = config
        .server
        .did_web_self_hosted
        .as_deref()
        .and_then(|target| target.strip_prefix("file://"))
    {
        let resolved = resolve("did_web_self_hosted", "DID_WEB_SELF_HOSTED", path);
        config.server.did_web_self_hosted = Some(format!("file://{resolved}"));
    }
}

pub async fn init(config_file: &str, with_ansi: bool) -> Result<Config, MediatorError> {
    // Read configuration file parameters. `read_config_file` lives in the config
    // crate now (returns its lean `ConfigError`); map it back to MediatorError.
    // Unknown keys are held until the tracing subscriber below exists — a
    // warning logged now would be dropped (Keyring VTI-06).
    let (config, unknown_keys) =
        affinidi_messaging_mediator_config::env::read_config_file_with_unknown_keys(config_file)
            .map_err(|e| {
                MediatorError::ConfigError(
                    crate::common::error_codes::CONFIG_ERROR,
                    "NA".into(),
                    e.to_string(),
                )
            })?;

    // The two settings logging itself is built from, checked before it is:
    // an unknown level used to become INFO, and an unreadable `log_json`
    // was reported only on stderr.
    let log_level =
        values::one_of("log_level", &config.log_level, LOG_LEVELS).map_err(config_error)?;
    let log_json = values::boolean("log_json", &config.log_json).map_err(config_error)?;

    // setup logging/tracing framework
    let filter = if env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(log_level)
    };

    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        // Display the thread ID an event was recorded on
        .with_thread_ids(false)
        // Don't display the event's target (module path)
        .with_target(true)
        .with_ansi(with_ansi)
        .with_env_filter(filter);

    println!("Switching to tracing subscriber for all logging...");
    if log_json {
        let subscriber = subscriber
            .json()
            // Build the subscriber
            .finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError(12, "NA".into(), format!("Couldn't setup logging: {e}"))
        })?;
    } else {
        let subscriber = subscriber.finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError(12, "NA".into(), format!("Couldn't setup logging: {e}"))
        })?;
    }

    // A key the schema does not recognise — typo'd, removed, or filed under the
    // wrong `[table]` — silently took no effect; say so now that it is heard.
    affinidi_messaging_mediator_config::env::warn_unknown_keys(config_file, &unknown_keys);
    affinidi_messaging_mediator_config::env::warn_ignored_env(&config);

    // Here and nowhere earlier: the subscriber above now exists, so the
    // deprecation warning is seen rather than dropped, and the conversion
    // below — which is where TLS paths are checked — sees resolved paths.
    let mut config = config;
    resolve_configured_paths(&mut config, Path::new(config_file));

    match <Config as async_convert::TryFrom<ConfigRaw>>::try_from(config).await {
        Ok(config) => {
            info!("Configuration settings parsed successfully.\n{:#?}", config);
            Ok(config)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod configured_path_tests {
    use super::*;
    use std::fs;

    /// Stage the shipped `conf/` as an operator would deploy it: somewhere
    /// that is not the working directory the tests run in.
    fn deploy_shipped_conf() -> (tempfile::TempDir, std::path::PathBuf) {
        let conf = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf");
        let dir = tempfile::tempdir().unwrap();
        for f in ["mediator.toml", "atm-functions.lua"] {
            fs::copy(conf.join(f), dir.path().join(f)).unwrap();
        }
        let config_file = dir.path().join("mediator.toml");
        (dir, config_file)
    }

    /// Keyring VTI-07: a config file outside the working directory finds the
    /// Lua functions that ship beside it. Before, this resolved to
    /// `./conf/atm-functions.lua` relative to wherever the process started.
    #[test]
    fn the_shipped_default_finds_its_functions_file_beside_itself() {
        let (dir, config_file) = deploy_shipped_conf();
        let mut config = affinidi_messaging_mediator_config::env::read_config_file(
            config_file.to_str().unwrap(),
        )
        .unwrap();

        resolve_configured_paths(&mut config, &config_file);

        let resolved = Path::new(&config.database.functions_file);
        assert!(
            resolved.starts_with(dir.path()),
            "resolved beside the config, not against the working directory: {}",
            resolved.display()
        );
        assert!(resolved.exists(), "{}", resolved.display());
    }

    /// And it does so by the intended rule, not the deprecated fallback — so a
    /// default start is silent. A default that leaned on the fallback would
    /// warn on every start, and a warning that always fires is one people
    /// learn to ignore.
    #[test]
    fn the_shipped_default_does_not_lean_on_the_legacy_fallback() {
        use affinidi_messaging_mediator_common::config_path::{
            PathSource, resolve_config_relative,
        };
        let (_dir, config_file) = deploy_shipped_conf();
        let config = affinidi_messaging_mediator_config::env::read_config_file(
            config_file.to_str().unwrap(),
        )
        .unwrap();

        let r = resolve_config_relative(&config_file, &config.database.functions_file);
        assert_eq!(
            r.source,
            PathSource::ConfigDir,
            "the shipped `functions_file` must be written relative to the config file"
        );
    }

    /// `did_web_self_hosted = "file://did.jsonl"` is relative to the config
    /// file, like the other paths in it (part of #176).
    #[test]
    fn a_self_hosted_did_file_resolves_beside_the_config() {
        let (dir, config_file) = deploy_shipped_conf();
        fs::write(dir.path().join("did.jsonl"), "{}").unwrap();
        let mut config = affinidi_messaging_mediator_config::env::read_config_file(
            config_file.to_str().unwrap(),
        )
        .unwrap();
        config.server.did_web_self_hosted = Some("file://did.jsonl".into());

        resolve_configured_paths(&mut config, &config_file);

        assert_eq!(
            config.server.did_web_self_hosted,
            Some(format!("file://{}", dir.path().join("did.jsonl").display()))
        );

        // Other sources are left alone.
        config.server.did_web_self_hosted = Some("s3://bucket/did.jsonl".into());
        resolve_configured_paths(&mut config, &config_file);
        assert_eq!(
            config.server.did_web_self_hosted.as_deref(),
            Some("s3://bucket/did.jsonl")
        );
    }
}

#[cfg(test)]
mod validate_raw_tests {
    use super::*;

    fn parse(path: &Path) -> ConfigRaw {
        let toml = std::fs::read_to_string(path).unwrap();
        affinidi_messaging_mediator_config::env::parse_config(&toml)
            .unwrap()
            .0
    }

    /// Every value the shipped template holds passes the strict checks; the
    /// only thing it leaves for the operator is the secrets backend, and the
    /// error for that lists the choices.
    #[test]
    fn the_shipped_template_is_valid_once_a_backend_is_chosen() {
        let mut raw = parse(&Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/mediator.toml"));
        let err = validate_raw(&raw).unwrap_err().to_string();
        assert!(err.contains("no secrets backend is configured"), "{err}");
        assert!(err.contains("aws_secrets://"), "{err}");

        raw.secrets.backend = "file:///var/lib/mediator/secrets.json".into();
        validate_raw(&raw).expect("the template's values are valid");
    }

    /// The container configs pass the same checks (the published image's
    /// config and the test deployment's).
    #[test]
    fn the_container_configs_are_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for rel in [
            "docker/conf/mediator.toml",
            "docker/test/conf/mediator.toml",
        ] {
            let path = root.join(rel);
            if !path.exists() {
                eprintln!("skipping: {} not present", path.display());
                continue;
            }
            validate_raw(&parse(&path)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        }
    }

    /// Issue #112: values outside `[limits]` are strict too.
    #[test]
    fn an_unreadable_value_anywhere_is_refused_naming_its_key() {
        let base = || {
            let mut raw = parse(&Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/mediator.toml"));
            raw.secrets.backend = "file:///var/lib/mediator/secrets.json".into();
            raw
        };
        type Set = fn(&mut ConfigRaw);
        let cases: [(&str, Set); 11] = [
            ("log_level", |r| r.log_level = "verbose".into()),
            ("log_json", |r| r.log_json = "yes".into()),
            ("streaming.enabled", |r| r.streaming.enabled = "on".into()),
            ("streaming.uuid", |r| r.streaming.uuid = "myhost".into()),
            ("did_resolver.cache_capacity", |r| {
                r.did_resolver.cache_capacity = "1k".into()
            }),
            ("did_resolver.network_timeout", |r| {
                r.did_resolver.network_timeout = "5s".into()
            }),
            ("database.database_timeout", |r| {
                r.database.database_timeout = "2s".into()
            }),
            ("security.mediator_acl_mode", |r| {
                r.security.mediator_acl_mode = "explicit-allow".into()
            }),
            ("processors.message_expiry_cleanup.enabled", |r| {
                r.processors.message_expiry_cleanup.enabled = "1".into()
            }),
            ("processors.forwarding.blocked_forwarding_dids", |r| {
                r.processors.forwarding.blocked_forwarding_dids = "did:example:a".into()
            }),
            ("limits.listed_messages", |r| {
                r.limits.listed_messages = "5O".into()
            }),
        ];
        assert!(validate_raw(&base()).is_ok());
        for (key, set) in cases {
            let mut raw = base();
            set(&mut raw);
            let err = validate_raw(&raw).expect_err(key).to_string();
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    #[test]
    fn the_secrets_cache_ttl_is_read_strictly() {
        assert_eq!(secrets_cache_ttl(None).unwrap(), None);
        assert_eq!(secrets_cache_ttl(Some("")).unwrap(), None);
        assert_eq!(secrets_cache_ttl(Some("0")).unwrap(), Some(0));
        assert_eq!(secrets_cache_ttl(Some("12h")).unwrap(), Some(43_200));
        let err = secrets_cache_ttl(Some("30 days please"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("secrets.cache_ttl"), "{err}");
    }

    #[test]
    fn a_storage_section_is_checked() {
        let mut raw = parse(&Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/mediator.toml"));
        raw.secrets.backend = "file:///var/lib/mediator/secrets.json".into();
        raw.storage = Some(StorageConfig {
            backend: "Fjall".into(),
            data_dir: Some("/var/lib/mediator/data".into()),
            fjall: Some(affinidi_messaging_mediator_config::FjallConfig::default()),
        });
        validate_raw(&raw).expect("fjall, case-insensitive");
        for (backend, data_dir, durability, expect) in [
            ("postgres", Some("/d"), "sync", "storage.backend"),
            ("fjall", None, "sync", "storage.data_dir"),
            ("fjall", Some("/d"), "fsync", "storage.fjall.durability"),
        ] {
            let fjall = affinidi_messaging_mediator_config::FjallConfig {
                durability: durability.into(),
                ..Default::default()
            };
            raw.storage = Some(StorageConfig {
                backend: backend.into(),
                data_dir: data_dir.map(str::to_string),
                fjall: Some(fjall),
            });
            let err = validate_raw(&raw).unwrap_err().to_string();
            assert!(err.contains(expect), "{expect}: {err}");
        }
    }

    /// The resolver's network timeout is in milliseconds; the built-in default
    /// is 5000 ms, not 5.
    #[test]
    fn the_default_resolver_timeout_is_in_milliseconds() {
        assert_eq!(DEFAULT_RESOLVER_NETWORK_TIMEOUT_MS, 5_000);
    }

    #[test]
    fn the_keyring_warning_is_for_linux_only() {
        let warning = keyring_backend_warning("keyring://affinidi-mediator");
        assert_eq!(warning.is_some(), cfg!(target_os = "linux"));
        if let Some(w) = warning {
            assert!(w.contains("lost on reboot"), "{w}");
        }
        assert!(keyring_backend_warning("aws_secrets://us-east-1/x/").is_none());
    }
}

#[cfg(test)]
mod self_hosted_did_tests {
    use super::*;

    /// A did:webvh log for `https://example.com/`, built and signed with
    /// didwebvh-rs: the genesis entry plus `updates` more (each adds a
    /// service); with `deactivate` the last one deactivates the DID. Returns
    /// the log as stored (JSON Lines, one entry per line) and the did:webvh
    /// DID.
    async fn webvh_log(updates: usize, deactivate: bool) -> (String, String) {
        use didwebvh_rs::{did_key::generate_did_key, prelude::*};
        use serde_json::json;

        // Entries a day apart: each versionTime must be later than the last.
        let at = |day: usize| {
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap()
                + chrono::Duration::days(day as i64)
        };
        let (_did, key) = generate_did_key(KeyType::Ed25519).unwrap();
        let pk = key.get_public_keymultibase().unwrap();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
            ..Default::default()
        };
        let created = create_did(
            CreateDIDConfig::builder()
                .address("https://example.com/")
                .version_time(at(0))
                .authorization_key(key.clone())
                .did_document(json!({
                    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
                    "id": "{DID}",
                    "controller": "{DID}",
                    "verificationMethod": [{
                        "id": "{DID}#key-0",
                        "type": "Multikey",
                        "controller": "{DID}",
                        "publicKeyMultibase": pk,
                    }],
                    "authentication": ["{DID}#key-0"],
                    "assertionMethod": ["{DID}#key-0"],
                }))
                .parameters(params.clone())
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

        let did = created.did().to_string();
        let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
        state.validate().unwrap().assert_complete().unwrap();
        for n in 0..updates {
            let mut doc = state.log_entries().last().unwrap().get_state().clone();
            doc["service"] = json!([{
                "id": format!("{did}#service-{n}"),
                "type": "LinkedDomains",
                "serviceEndpoint": format!("https://example.com/{n}"),
            }]);
            let mut builder = UpdateDIDConfig::builder()
                .state(state)
                .signing_key(key.clone())
                .document(doc)
                .version_time(at(n + 1));
            if deactivate && n + 1 == updates {
                builder = builder.deactivate(true);
            }
            state = update_did(builder.build().unwrap())
                .await
                .unwrap()
                .into_state();
        }

        let mut log = String::new();
        for entry in state.log_entries() {
            log.push_str(&serde_json::to_string(&entry.log_entry).unwrap());
            log.push('\n');
        }
        (log, did)
    }

    /// `did:scid:vh:1:{scid}` for a `did:webvh:{scid}:{host}` DID.
    fn scid_of(webvh_did: &str) -> String {
        let scid = webvh_did.split(':').nth(2).unwrap();
        format!("did:scid:vh:1:{scid}")
    }

    // A plain did:web DID document (no webvh log envelope).
    const WEB_DOC: &str = r#"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:web:example.com","controller":"did:web:example.com","verificationMethod":[{"type":"Multikey","controller":"did:web:example.com","publicKeyMultibase":"z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG","id":"did:web:example.com#P5RDjVJG"}],"authentication":["did:web:example.com#P5RDjVJG"]}"#;

    /// did:webvh source: the did.json body must have its id (and every
    /// self-reference) rewritten to did:web, while the did.jsonl body stays
    /// the verbatim webvh log and the typed Document keeps the real did:webvh
    /// id.
    #[tokio::test]
    async fn webvh_source_rewrites_did_json_only() {
        let (log, webvh_did) = webvh_log(0, false).await;
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(log.clone(), &webvh_did).unwrap();

        // did.json: rewritten to did:web, no webvh traces anywhere.
        let doc: serde_json::Value = serde_json::from_str(&did_json).unwrap();
        assert_eq!(doc["id"], "did:web:example.com");
        assert_eq!(doc["controller"], "did:web:example.com");
        assert!(!did_json.contains("did:webvh:"));
        for vm in doc["verificationMethod"].as_array().unwrap() {
            assert!(
                vm["id"]
                    .as_str()
                    .unwrap()
                    .starts_with("did:web:example.com#")
            );
        }

        // did.jsonl: verbatim webvh log, unchanged.
        assert_eq!(did_jsonl.as_deref(), Some(log.as_str()));

        // typed Document: the mediator's real did:webvh identity.
        assert_eq!(typed.id.as_str(), webvh_did);
    }

    /// A mediator presenting its log as did:scid: did.jsonl and did.json are
    /// served exactly as for did:webvh, and the typed Document — what the
    /// resolver is preloaded with — is the did:scid's own.
    #[tokio::test]
    async fn scid_identity_gets_its_own_document() {
        let (log, webvh_did) = webvh_log(0, false).await;
        let scid_did = scid_of(&webvh_did);
        for mediator_did in [scid_did.clone(), format!("{scid_did}?src=example.com")] {
            let (did_json, did_jsonl, typed) =
                split_self_hosted_did_source(log.clone(), &mediator_did).unwrap();

            assert_eq!(did_jsonl.as_deref(), Some(log.as_str()));
            let web: serde_json::Value = serde_json::from_str(&did_json).unwrap();
            assert_eq!(web["id"], "did:web:example.com");

            assert_eq!(typed.id.as_str(), scid_did);
            let typed = serde_json::to_value(&typed).unwrap();
            assert_eq!(
                typed["verificationMethod"][0]["id"],
                format!("{scid_did}#key-0")
            );
            assert_eq!(typed["authentication"][0], format!("{scid_did}#key-0"));
            let aliases = typed["alsoKnownAs"].as_array().unwrap();
            assert!(aliases.contains(&serde_json::json!(format!("{scid_did}?src=example.com"))));
            assert!(aliases.contains(&serde_json::json!(webvh_did)));
        }
    }

    /// A did:scid naming another SCID than the log's is a misconfiguration.
    #[tokio::test]
    async fn scid_identity_must_match_the_log() {
        let (log, _) = webvh_log(0, false).await;
        assert!(
            split_self_hosted_did_source(log, "did:scid:vh:1:QmSomeOtherScid?src=example.com")
                .is_err()
        );
    }

    /// Issue #120: a log of two entries (after the first key rotation or
    /// service change) used to stop the mediator starting. The chain is now
    /// verified entry by entry, did.json serves the LAST entry's document,
    /// and did.jsonl serves the log exactly as read, line breaks included.
    #[tokio::test]
    async fn a_two_entry_webvh_log_serves_its_last_state() {
        let (log, webvh_did) = webvh_log(1, false).await;
        assert_eq!(log.lines().count(), 2, "fixture has two entries");
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(log.clone(), &webvh_did).unwrap();

        assert_eq!(did_jsonl.as_deref(), Some(log.as_str()));
        let doc: serde_json::Value = serde_json::from_str(&did_json).unwrap();
        assert_eq!(doc["id"], "did:web:example.com");
        // Only the second entry carries the service: this is the last state.
        assert_eq!(
            doc["service"][0]["serviceEndpoint"], "https://example.com/0",
            "{did_json}"
        );
        assert_eq!(typed.id.as_str(), webvh_did);
        assert!(
            typed
                .service
                .iter()
                .any(|s| s.service_endpoint.get_uri().as_deref() == Some("https://example.com/0"))
        );

        // Three entries, and blank lines (a trailing newline, a blank line
        // between entries) are not entries.
        let (log, webvh_did) = webvh_log(2, false).await;
        let spaced = log.replacen('\n', "\n\n", 1);
        let (did_json, did_jsonl, _) =
            split_self_hosted_did_source(spaced.clone(), &webvh_did).unwrap();
        assert_eq!(did_jsonl.as_deref(), Some(spaced.as_str()));
        assert!(did_json.contains("https://example.com/1"), "{did_json}");
    }

    /// An entry that does not verify against its predecessor is refused,
    /// naming the setting and the entry.
    #[tokio::test]
    async fn a_tampered_webvh_log_is_refused() {
        let (log, webvh_did) = webvh_log(1, false).await;
        let tampered = log.replacen("https://example.com/0", "https://evil.example/0", 1);
        assert_ne!(tampered, log, "fixture must actually change");
        let err = split_self_hosted_did_source(tampered, &webvh_did)
            .unwrap_err()
            .to_string();
        assert!(err.contains("server.did_web_self_hosted"), "{err}");
        assert!(err.contains("entry 2"), "{err}");

        // Entries out of order.
        let mut lines: Vec<&str> = log.lines().collect();
        lines.swap(0, 1);
        assert!(split_self_hosted_did_source(lines.join("\n"), &webvh_did).is_err());

        // A line that is not an entry at all.
        let garbage = format!("{}\nnot json\n", log.lines().next().unwrap());
        let err = split_self_hosted_did_source(garbage, &webvh_did)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2"), "{err}");
    }

    /// A mediator cannot run as a deactivated DID.
    #[tokio::test]
    async fn a_deactivated_webvh_log_is_refused() {
        let (log, webvh_did) = webvh_log(1, true).await;
        let err = split_self_hosted_did_source(log, &webvh_did)
            .unwrap_err()
            .to_string();
        assert!(err.contains("deactivates"), "{err}");
    }

    /// A did:web document written over several lines (pretty-printed) is
    /// still one document, not a log.
    #[test]
    fn a_pretty_printed_web_document_is_one_document() {
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(WEB_DOC).unwrap(),
        )
        .unwrap();
        assert!(pretty.lines().count() > 1);
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(pretty.clone(), "did:web:example.com").unwrap();
        assert_eq!(did_json, pretty);
        assert!(did_jsonl.is_none());
        assert_eq!(typed.id.as_str(), "did:web:example.com");
    }

    /// did:web source: served verbatim at did.json, no did.jsonl log.
    #[test]
    fn web_source_served_verbatim_without_log() {
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(WEB_DOC.to_string(), "did:web:example.com").unwrap();

        assert_eq!(did_json, WEB_DOC);
        assert!(did_jsonl.is_none());
        assert_eq!(typed.id.as_str(), "did:web:example.com");
    }
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_advertise_tests {
    use super::*;

    fn did_doc(services: &str) -> Document {
        let json =
            format!(r#"{{ "id": "did:web:mediator.example.com", "service": [{services}] }}"#);
        serde_json::from_str(&json).expect("valid DID document")
    }

    const DIDCOMM: &str = r#"{
        "id": "did:web:mediator.example.com#didcomm",
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://mediator.example.com/inbound"
    }"#;

    #[test]
    fn adds_tsp_service_mirroring_the_didcomm_endpoint() {
        let mut doc = did_doc(DIDCOMM);
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(
            out.is_some(),
            "a TSPTransport service should have been added"
        );

        let tsp: Vec<_> = doc
            .service
            .iter()
            .filter(|s| s.type_.iter().any(|t| t == affinidi_tsp::TSP_SERVICE_TYPE))
            .collect();
        assert_eq!(tsp.len(), 1, "exactly one TSPTransport service");
        assert_eq!(
            tsp[0].service_endpoint.get_uri().as_deref(),
            Some("https://mediator.example.com/inbound"),
            "the TSP endpoint mirrors the DIDCommMessaging endpoint"
        );
        // The re-serialised JSON carries the new service.
        assert!(out.unwrap().contains(affinidi_tsp::TSP_SERVICE_TYPE));
    }

    #[test]
    fn no_change_when_tsp_already_advertised() {
        let tsp = r#"{
            "id": "did:web:mediator.example.com#tsp",
            "type": "TSPTransport",
            "serviceEndpoint": "https://mediator.example.com/inbound"
        }"#;
        let mut doc = did_doc(&format!("{DIDCOMM},{tsp}"));
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(out.is_none(), "already advertised — no mutation");
        assert_eq!(doc.service.len(), 2, "no extra service appended");
    }

    #[test]
    fn no_change_without_a_didcomm_endpoint_to_mirror() {
        let other = r#"{
            "id": "did:web:mediator.example.com#other",
            "type": "SomeOtherService",
            "serviceEndpoint": "https://mediator.example.com/other"
        }"#;
        let mut doc = did_doc(other);
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(out.is_none(), "no DIDComm endpoint to mirror — no mutation");
    }
}

#[cfg(test)]
mod database_config_tests {
    use super::*;

    fn raw(cluster_mode: &str) -> affinidi_messaging_mediator_config::DatabaseConfigRaw {
        affinidi_messaging_mediator_config::DatabaseConfigRaw {
            functions_file: "./atm-functions.lua".into(),
            database_url: "redis://127.0.0.1/".into(),
            database_timeout: "2".into(),
            scripts_path: None,
            cluster_mode: cluster_mode.into(),
            circuit_breaker_threshold: String::new(),
            circuit_breaker_recovery_secs: String::new(),
        }
    }

    #[test]
    fn circuit_breaker_tuning_defaults_and_parses() {
        let config = database_config_from_raw(&raw("")).unwrap();
        assert_eq!(config.circuit_breaker_threshold, 5);
        assert_eq!(config.circuit_breaker_recovery_secs, 10);

        let mut tuned = raw("");
        tuned.circuit_breaker_threshold = " 3 ".into();
        tuned.circuit_breaker_recovery_secs = "30".into();
        let config = database_config_from_raw(&tuned).unwrap();
        assert_eq!(config.circuit_breaker_threshold, 3);
        assert_eq!(config.circuit_breaker_recovery_secs, 30);
    }

    /// An unreadable circuit-breaker value is refused, naming the key, rather
    /// than falling back to the default with a warning (#112).
    #[test]
    fn an_unreadable_circuit_breaker_value_is_refused() {
        for bad in ["0", "-1", "five", "3s"] {
            let mut raw = raw("");
            raw.circuit_breaker_threshold = bad.into();
            let err = database_config_from_raw(&raw).unwrap_err().to_string();
            assert!(
                err.contains("database.circuit_breaker_threshold"),
                "{bad:?}: {err}"
            );
        }
        for bad in ["soon", "-1", "10s"] {
            let mut raw = raw("");
            raw.circuit_breaker_recovery_secs = bad.into();
            let err = database_config_from_raw(&raw).unwrap_err().to_string();
            assert!(
                err.contains("database.circuit_breaker_recovery_secs"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn an_empty_functions_file_means_the_built_in_library() {
        let mut unset = raw("");
        unset.functions_file = " ".into();
        assert_eq!(
            database_config_from_raw(&unset).unwrap().functions_file,
            None
        );
        assert_eq!(
            database_config_from_raw(&raw(""))
                .unwrap()
                .functions_file
                .as_deref(),
            Some("./atm-functions.lua")
        );
    }

    #[test]
    fn cluster_mode_is_off_when_absent() {
        assert!(!database_config_from_raw(&raw("")).unwrap().cluster_mode);
    }

    #[test]
    fn cluster_mode_is_on_only_when_true() {
        assert!(database_config_from_raw(&raw("true")).unwrap().cluster_mode);
        assert!(
            database_config_from_raw(&raw(" TRUE"))
                .unwrap()
                .cluster_mode
        );
        assert!(
            !database_config_from_raw(&raw("false"))
                .unwrap()
                .cluster_mode
        );
    }

    /// A typo is refused rather than read as off: running a cluster-mode
    /// server in single-node mode is the misconfiguration the setting exists
    /// to rule out.
    #[test]
    fn a_cluster_mode_typo_is_refused() {
        let err = database_config_from_raw(&raw("ture"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("database.cluster_mode"), "{err}");
    }

    #[test]
    fn an_unreadable_database_timeout_is_refused() {
        for bad in ["2s", "", "0", "-1"] {
            let mut raw = raw("");
            raw.database_timeout = bad.into();
            let err = database_config_from_raw(&raw).unwrap_err().to_string();
            assert!(err.contains("database.database_timeout"), "{bad:?}: {err}");
        }
    }

    /// The startup log prints the whole `Config` with `{:#?}`.
    #[tokio::test]
    async fn config_debug_hides_database_url_credentials() {
        for url in ["redis://:pw@h/", "redis://user:pw@h/"] {
            let (secrets, _h) = ThreadedSecretsResolver::new(None).await;
            let mut config = Config::headless(Arc::new(secrets));
            config.database.database_url = url.into();
            let text = format!("{config:#?}");
            assert!(!text.contains("pw"), "{text}");
            assert!(text.contains("redis://***@h/"), "{text}");

            let mut raw = raw("");
            raw.database_url = url.into();
            let text = format!("{raw:#?}");
            assert!(!text.contains("pw"), "{text}");
        }
    }
}
