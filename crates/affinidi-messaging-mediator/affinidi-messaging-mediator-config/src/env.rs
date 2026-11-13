//! Config file reading + environment-variable overrides.
//!
//! `read_config_file` reads `mediator.toml`, deserializes it into
//! [`ConfigRaw`], and applies env-var overrides (env wins
//! over the file). Runtime resolution (secrets, DID resolver, VTA) happens
//! later, in the mediator binary.

use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

use tracing::{error, info, warn};

use crate::ConfigRaw;
use crate::error::ConfigError;

macro_rules! env_override {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = val;
        }
    };
}

macro_rules! env_override_opt {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = Some(val);
        }
    };
}

/// Override a `Vec<String>` field from a comma-separated environment variable.
macro_rules! env_override_list {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = split_list(&val);
        }
    };
}

/// Split a comma-separated environment value into list entries.
///
/// Entries are trimmed and empties dropped, so `""` clears the list and
/// `"a, b"` is the same as `"a,b"`. TOML gives these fields a real array, so
/// the comma form exists only for the environment.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

/// Apply environment variable overrides to the raw config. Env vars take
/// priority over values in the TOML file.
pub fn apply_env_overrides(config: &mut ConfigRaw) {
    env_override!(config.log_level, "LOG_LEVEL");
    env_override!(config.log_json, "LOG_JSON");
    env_override!(config.mediator_did, "MEDIATOR_DID");

    env_override!(config.server.listen_address, "LISTEN_ADDRESS");
    env_override!(config.server.api_prefix, "API_PREFIX");
    env_override!(config.server.admin_did, "ADMIN_DID");
    env_override_opt!(config.server.did_web_self_hosted, "DID_WEB_SELF_HOSTED");
    env_override_list!(config.server.local_endpoints, "LOCAL_ENDPOINTS");
    env_override!(config.database.functions_file, "DATABASE_FUNCTIONS_FILE");
    env_override!(config.database.database_url, "DATABASE_URL");
    // DATABASE_POOL_SIZE removed — the mediator uses a multiplexed
    // connection, there is no pool to size. Pre-0.14 deployments that
    // set it can drop the env var with no behaviour change.
    env_override!(config.database.database_timeout, "DATABASE_TIMEOUT");
    env_override!(config.database.cluster_mode, "DATABASE_CLUSTER_MODE");
    env_override!(
        config.database.circuit_breaker_threshold,
        "DATABASE_CIRCUIT_BREAKER_THRESHOLD"
    );
    env_override!(
        config.database.circuit_breaker_recovery_secs,
        "DATABASE_CIRCUIT_BREAKER_RECOVERY_SECS"
    );

    env_override!(config.security.mediator_acl_mode, "MEDIATOR_ACL_MODE");
    env_override!(config.security.global_acl_default, "GLOBAL_DEFAULT_ACL");
    env_override!(
        config.security.local_direct_delivery_allowed,
        "LOCAL_DIRECT_DELIVERY_ALLOWED"
    );
    env_override!(
        config.security.local_direct_delivery_allow_anon,
        "LOCAL_DIRECT_DELIVERY_ALLOW_ANON"
    );
    env_override!(config.security.use_ssl, "USE_SSL");
    env_override_opt!(config.security.ssl_certificate_file, "SSL_CERTIFICATE_FILE");
    env_override_opt!(config.security.ssl_key_file, "SSL_KEY_FILE");
    env_override!(config.security.jwt_access_expiry, "JWT_ACCESS_EXPIRY");
    env_override!(config.security.jwt_refresh_expiry, "JWT_REFRESH_EXPIRY");
    env_override_opt!(config.security.cors_allow_origin, "CORS_ALLOW_ORIGIN");
    env_override!(
        config.security.block_anonymous_outer_envelope,
        "BLOCK_ANONYMOUS_OUTER_ENVELOPE"
    );
    env_override!(
        config.security.force_session_did_match,
        "FORCE_SESSION_DID_MATCH"
    );
    env_override!(
        config.security.block_remote_admin_msgs,
        "BLOCK_REMOTE_ADMIN_MSGS"
    );
    env_override!(
        config.security.enable_inter_mediator_relay,
        "ENABLE_INTER_MEDIATOR_RELAY"
    );
    env_override!(
        config.security.trust_task_verification,
        "TRUST_TASK_VERIFICATION"
    );
    env_override!(
        config.security.tsp_auth_accept_unbound_until,
        "TSP_AUTH_ACCEPT_UNBOUND_UNTIL"
    );

    env_override!(config.streaming.enabled, "STREAMING_ENABLED");
    env_override!(config.streaming.uuid, "STREAMING_UUID");

    env_override_opt!(config.did_resolver.address, "DID_RESOLVER_ADDRESS");
    env_override!(
        config.did_resolver.cache_capacity,
        "DID_RESOLVER_CACHE_CAPACITY"
    );
    env_override!(config.did_resolver.cache_ttl, "DID_RESOLVER_CACHE_TTL");
    env_override!(
        config.did_resolver.network_timeout,
        "DID_RESOLVER_NETWORK_TIMEOUT"
    );
    env_override!(
        config.did_resolver.network_limit,
        "DID_RESOLVER_NETWORK_LIMIT"
    );

    env_override!(
        config.limits.attachments_max_count,
        "LIMIT_ATTACHMENTS_MAX_COUNT"
    );
    env_override!(
        config.limits.crypto_operations_per_message,
        "LIMIT_CRYPTO_OPERATIONS_PER_MESSAGE"
    );
    env_override!(config.limits.deleted_messages, "LIMIT_DELETED_MESSAGES");
    env_override!(config.limits.forward_task_queue, "LIMIT_FORWARD_TASK_QUEUE");
    env_override!(config.limits.http_size, "LIMIT_HTTP_SIZE");
    env_override!(config.limits.listed_messages, "LIMIT_LISTED_MESSAGES");
    env_override!(config.limits.local_max_acl, "LIMIT_LOCAL_MAX_ACL");
    env_override!(
        config.limits.delivered_expiry_seconds,
        "LIMIT_DELIVERED_EXPIRY_SECONDS"
    );
    env_override!(config.limits.pickup_round_robin, "LIMIT_PICKUP_ROUND_ROBIN");
    env_override!(
        config.limits.message_expiry_seconds,
        "LIMIT_MESSAGE_EXPIRY_SECONDS"
    );
    env_override!(config.limits.message_size, "LIMIT_MESSAGE_SIZE");
    env_override!(
        config.limits.queued_send_messages_per_peer,
        "LIMIT_QUEUED_SEND_MESSAGES_PER_PEER"
    );
    env_override!(
        config.limits.queued_send_messages_soft,
        "LIMIT_QUEUED_SEND_MESSAGES_SOFT"
    );
    env_override!(
        config.limits.queued_send_messages_hard,
        "LIMIT_QUEUED_SEND_MESSAGES_HARD"
    );
    env_override!(
        config.limits.queued_receive_messages_soft,
        "LIMIT_QUEUED_RECEIVE_MESSAGES_SOFT"
    );
    env_override!(
        config.limits.queued_receive_messages_hard,
        "LIMIT_QUEUED_RECEIVE_MESSAGES_HARD"
    );
    env_override!(config.limits.to_keys_per_recipient, "LIMIT_TO_KEYS_PER_DID");
    env_override!(config.limits.to_recipients, "LIMIT_TO_RECIPIENTS");
    env_override!(config.limits.ws_size, "LIMIT_WS_SIZE");
    env_override!(config.limits.access_list_limit, "ACCESS_LIST_LIMIT");
    env_override!(config.limits.oob_invite_ttl, "OOB_INVITE_TTL");
    env_override!(config.limits.rate_limit_per_ip, "LIMIT_RATE_LIMIT_PER_IP");
    env_override!(config.limits.rate_limit_burst, "LIMIT_RATE_LIMIT_BURST");
    env_override!(
        config.limits.max_websocket_connections,
        "LIMIT_MAX_WEBSOCKET_CONNECTIONS"
    );
    env_override!(
        config.limits.max_websocket_connections_per_did,
        "LIMIT_MAX_WEBSOCKET_CONNECTIONS_PER_DID"
    );
    env_override!(
        config.limits.did_rate_limit_per_second,
        "LIMIT_DID_RATE_LIMIT_PER_SECOND"
    );
    env_override!(
        config.limits.did_rate_limit_burst,
        "LIMIT_DID_RATE_LIMIT_BURST"
    );
    env_override!(config.limits.ws_send_buffer, "LIMIT_WS_SEND_BUFFER");
    env_override!(config.limits.pubsub_buffer, "LIMIT_PUBSUB_BUFFER");
    env_override!(
        config.limits.relay_connections_per_ip,
        "LIMIT_RELAY_CONNECTIONS_PER_IP"
    );
    env_override!(
        config.limits.relay_frames_per_second,
        "LIMIT_RELAY_FRAMES_PER_SECOND"
    );
    env_override!(config.limits.relay_frame_burst, "LIMIT_RELAY_FRAME_BURST");
    env_override!(
        config.limits.relay_bytes_per_second,
        "LIMIT_RELAY_BYTES_PER_SECOND"
    );
    env_override!(
        config.limits.ws_messages_per_second,
        "LIMIT_WS_MESSAGES_PER_SECOND"
    );
    env_override!(config.limits.ws_message_burst, "LIMIT_WS_MESSAGE_BURST");
    env_override!(
        config.limits.ws_message_throttle_close_secs,
        "LIMIT_WS_MESSAGE_THROTTLE_CLOSE_SECS"
    );
    env_override!(
        config.limits.metrics_requests_per_second,
        "LIMIT_METRICS_REQUESTS_PER_SECOND"
    );
    env_override!(
        config.limits.ws_ping_interval_secs,
        "LIMIT_WS_PING_INTERVAL_SECS"
    );
    env_override!(
        config.limits.ws_pong_timeout_secs,
        "LIMIT_WS_PONG_TIMEOUT_SECS"
    );
    env_override!(
        config.limits.ws_write_timeout_secs,
        "LIMIT_WS_WRITE_TIMEOUT_SECS"
    );
    env_override!(config.limits.mux.enabled, "LIMIT_MUX_ENABLED");
    env_override!(
        config.limits.mux.max_dids_per_connection,
        "LIMIT_MUX_MAX_DIDS_PER_CONNECTION"
    );
    env_override!(
        config.limits.mux.max_grants_per_principal,
        "LIMIT_MUX_MAX_GRANTS_PER_PRINCIPAL"
    );
    env_override!(
        config.limits.mux.max_grants_per_did,
        "LIMIT_MUX_MAX_GRANTS_PER_DID"
    );
    env_override!(
        config.limits.mux.max_grant_lifetime_secs,
        "LIMIT_MUX_MAX_GRANT_LIFETIME_SECS"
    );

    // `[storage]` is optional, and `[storage.fjall]` is optional within it, so
    // these only override a section that already exists. An env var alone does
    // not conjure a storage backend into being — selecting the backend is a
    // deliberate choice that belongs in the file.
    if let Some(storage) = config.storage.as_mut() {
        env_override!(storage.backend, "STORAGE_BACKEND");
        env_override_opt!(storage.data_dir, "STORAGE_DATA_DIR");
        if storage.fjall.is_none()
            && (std::env::var("STORAGE_FJALL_BLOCK_CACHE").is_ok()
                || std::env::var("STORAGE_FJALL_WRITE_BUFFER").is_ok()
                || std::env::var("STORAGE_FJALL_MAX_JOURNAL").is_ok()
                || std::env::var("STORAGE_FJALL_DURABILITY").is_ok())
        {
            // Any one of the knobs being set means the operator wants to tune;
            // materialise the section at its defaults so the override lands.
            storage.fjall = Some(crate::FjallConfig::default());
        }
        if let Some(fjall) = storage.fjall.as_mut() {
            env_override!(fjall.block_cache, "STORAGE_FJALL_BLOCK_CACHE");
            env_override!(fjall.write_buffer, "STORAGE_FJALL_WRITE_BUFFER");
            env_override!(fjall.max_journal, "STORAGE_FJALL_MAX_JOURNAL");
            env_override!(fjall.durability, "STORAGE_FJALL_DURABILITY");
        }
    }

    env_override!(
        config.processors.forwarding.enabled,
        "PROCESSOR_FORWARDING_ENABLED"
    );
    env_override!(
        config.processors.forwarding.future_time_limit,
        "PROCESSOR_FORWARDING_FUTURE_TIME_LIMIT"
    );
    env_override!(
        config.processors.forwarding.external_forwarding,
        "PROCESSOR_FORWARDING_EXTERNAL"
    );
    env_override!(
        config.processors.forwarding.report_errors,
        "PROCESSOR_FORWARDING_REPORT_ERRORS"
    );
    env_override!(
        config.processors.forwarding.blocked_forwarding_dids,
        "PROCESSOR_FORWARDING_BLOCKED_DIDS"
    );
    env_override!(
        config.processors.forwarding.rate_window_seconds,
        "PROCESSOR_FORWARDING_RATE_WINDOW"
    );
    env_override!(
        config.processors.forwarding.ws_threshold_msgs_per_10s,
        "PROCESSOR_FORWARDING_WS_THRESHOLD"
    );
    env_override!(
        config.processors.forwarding.ws_idle_timeout_seconds,
        "PROCESSOR_FORWARDING_WS_IDLE_TIMEOUT"
    );
    env_override!(
        config.processors.forwarding.batch_size,
        "PROCESSOR_FORWARDING_BATCH_SIZE"
    );
    env_override!(
        config.processors.forwarding.max_retries,
        "PROCESSOR_FORWARDING_MAX_RETRIES"
    );
    env_override!(
        config.processors.forwarding.initial_backoff_ms,
        "PROCESSOR_FORWARDING_INITIAL_BACKOFF_MS"
    );
    env_override!(
        config.processors.forwarding.max_backoff_ms,
        "PROCESSOR_FORWARDING_MAX_BACKOFF_MS"
    );
    env_override!(
        config.processors.forwarding.max_concurrent_endpoints,
        "PROCESSOR_FORWARDING_MAX_CONCURRENT_ENDPOINTS"
    );
    env_override!(
        config.processors.forwarding.delivery_timeout_seconds,
        "PROCESSOR_FORWARDING_DELIVERY_TIMEOUT_SECONDS"
    );
    env_override!(
        config.processors.forwarding.reclaim_idle_seconds,
        "PROCESSOR_FORWARDING_RECLAIM_IDLE_SECONDS"
    );
    env_override!(
        config.processors.forwarding.consumer_group,
        "PROCESSOR_FORWARDING_CONSUMER_GROUP"
    );
    env_override!(
        config.processors.forwarding.max_hops,
        "PROCESSOR_FORWARDING_MAX_HOPS"
    );
    env_override!(
        config.processors.forwarding.relay_mode,
        "PROCESSOR_FORWARDING_RELAY_MODE"
    );
    env_override!(
        config.processors.forwarding.relay_trusted_mediators,
        "PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS"
    );

    env_override!(
        config.processors.message_expiry_cleanup.enabled,
        "PROCESSOR_MESSAGE_EXPIRY_CLEANUP_ENABLED"
    );

    env_override!(
        config.processors.session_expiry_cleanup.enabled,
        "PROCESSOR_SESSION_EXPIRY_CLEANUP_ENABLED"
    );

    env_override!(config.secrets.backend, "MEDIATOR_SECRETS_BACKEND");
    env_override_opt!(config.secrets.cache_ttl, "MEDIATOR_SECRETS_CACHE_TTL");
}

/// Parse a comma-separated list of CIDR ranges from environment variable
/// `var`.
///
/// Unlike the plain string lists this one is parsed, and a bad entry is an
/// error: silently dropping a typo would change who the range admits with no
/// sign why. `""` is the empty list.
fn parse_cidr_list(var: &str, value: &str) -> Result<Vec<ipnet::IpNet>, ConfigError> {
    split_list(value)
        .iter()
        .map(|entry| {
            entry.parse().map_err(|err| {
                ConfigError::Parse(format!("{var} entry '{entry}' is not a CIDR range: {err}"))
            })
        })
        .collect()
}

/// Override `[server] trust_xff_cidrs` from a comma-separated `TRUST_XFF_CIDRS`
/// value. `""` clears the list.
fn apply_trust_xff_cidrs_override(
    config: &mut ConfigRaw,
    value: Option<String>,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };
    config.server.trust_xff_cidrs = parse_cidr_list("TRUST_XFF_CIDRS", &value)?;
    Ok(())
}

/// Override `[server] metrics_allow_cidrs` from a comma-separated
/// `METRICS_ALLOW_CIDRS` value. `""` is an empty list, which refuses every
/// caller; leave the variable unset to keep the file's value (or the default).
fn apply_metrics_allow_cidrs_override(
    config: &mut ConfigRaw,
    value: Option<String>,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };
    config.server.metrics_allow_cidrs = Some(parse_cidr_list("METRICS_ALLOW_CIDRS", &value)?);
    Ok(())
}

/// Override `[server] metrics_bearer_token` from `METRICS_BEARER_TOKEN`.
///
/// An empty (or all-whitespace) value is refused, as is an empty token in the
/// file: either would leave `/metrics` without the token the operator meant to
/// require, usually because a secret reference rendered as `""`. Leave the
/// variable unset to keep the file's token; remove the key from the file to
/// require none.
fn apply_metrics_bearer_token_override(
    config: &mut ConfigRaw,
    value: Option<String>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(ConfigError::Parse(
                "METRICS_BEARER_TOKEN is set but empty. Unset it to keep [server] \
                 metrics_bearer_token from the configuration file, or set a token"
                    .into(),
            ));
        }
        config.server.metrics_bearer_token = Some(crate::RedactedString(value));
    }
    if config
        .server
        .metrics_bearer_token
        .as_ref()
        .is_some_and(|token| token.0.trim().is_empty())
    {
        return Err(ConfigError::Parse(
            "[server] metrics_bearer_token is empty. Set a token, or remove the key to \
             require none"
                .into(),
        ));
    }
    Ok(())
}

/// Read the primary configuration file for the mediator.
/// Returns a [`ConfigRaw`] with env var overrides applied.
///
/// Keys the schema does not recognise are logged as warnings (see
/// [`warn_unknown_keys`]). That only reaches an operator once a tracing
/// subscriber is installed; a caller that reads the file *before* installing
/// one — the mediator's own startup — should use
/// [`read_config_file_with_unknown_keys`] and warn once logging is up.
pub fn read_config_file(file_name: &str) -> Result<ConfigRaw, ConfigError> {
    let (config, unknown_keys) = read_config_file_with_unknown_keys(file_name)?;
    warn_unknown_keys(file_name, &unknown_keys);
    Ok(config)
}

/// [`read_config_file`], also returning the dotted path of every key in the
/// file that the schema does not recognise, instead of logging them.
///
/// Unknown keys are reported, never rejected: a config that boots today must
/// keep booting. The usual cause is not a typo but TOML's table scoping — a
/// key appended at the end of the file lands in whichever `[table]` header
/// precedes it, so `cors_allow_origin` written below
/// `[processors.session_expiry_cleanup]` is
/// `processors.session_expiry_cleanup.cors_allow_origin`, which nothing reads.
pub fn read_config_file_with_unknown_keys(
    file_name: &str,
) -> Result<(ConfigRaw, Vec<String>), ConfigError> {
    info!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let (mut config, unknown_keys) = parse_config(&raw_config.join("\n")).map_err(|err| {
        error!("Could not parse configuration settings. {err}");
        err
    })?;

    apply_env_overrides(&mut config);
    apply_trust_xff_cidrs_override(&mut config, std::env::var("TRUST_XFF_CIDRS").ok())?;
    apply_metrics_allow_cidrs_override(&mut config, std::env::var("METRICS_ALLOW_CIDRS").ok())?;
    apply_metrics_bearer_token_override(&mut config, std::env::var("METRICS_BEARER_TOKEN").ok())?;

    Ok((config, unknown_keys))
}

/// Deserialize `mediator.toml` contents into a [`ConfigRaw`] (no env
/// overrides), collecting the dotted path of every key the schema ignored.
pub fn parse_config(contents: &str) -> Result<(ConfigRaw, Vec<String>), ConfigError> {
    // `Display`, not `Debug`: toml's rendering names the line, the key and the
    // expected type — e.g. an array given for the comma-separated
    // `cors_allow_origin` reads "invalid type: sequence, expected a string".
    let parse_err = |err: toml::de::Error| ConfigError::Parse(err.to_string());
    let de = toml::Deserializer::parse(contents).map_err(parse_err)?;
    let mut unknown_keys = Vec::new();
    let config = serde_ignored::deserialize(de, |path| unknown_keys.push(path.to_string()))
        .map_err(parse_err)?;
    Ok((config, unknown_keys))
}

/// Settings the mediator used to read and no longer does, with why.
///
/// A retired key is reported like any other unknown key — a config that boots
/// today keeps booting — but the warning names it as retired rather than
/// suggesting a typo or a misplaced table.
const RETIRED_KEYS: &[(&str, &str)] = &[
    (
        "security.legacy_admin_protocols",
        "the legacy admin surface it switched (the DIDComm mediator/1.0 \
         admin-management, account-management and acl-management protocols, and \
         REST GET /admin/status, DELETE /purge and GET /queue/status) has been \
         removed; the mediator is administered over the messaging/* Trust Tasks",
    ),
    (
        "security.admin_messages_expiry",
        "it bounded replay of the removed legacy admin protocols; a Trust Task's \
         freshness is checked from its issuedAt under trust_task_verification",
    ),
];

/// The operator-facing warning for one unrecognised key.
pub fn unknown_key_message(file_name: &str, key: &str) -> String {
    if let Some((_, why)) = RETIRED_KEYS.iter().find(|(retired, _)| *retired == key) {
        return format!(
            "configuration key `{key}` in {file_name} is retired and ignored: {why}. \
             Remove it."
        );
    }
    match key.rsplit_once('.') {
        Some((table, leaf)) => format!(
            "unknown configuration key `{key}` in {file_name} — ignored. The mediator \
             has no `{leaf}` setting in [{table}]. Check for a typo or a removed \
             setting; if `{leaf}` belongs to another section, note that a key \
             placed after a [table] header belongs to that table, so a key \
             appended at the end of the file lands in its last section. Move it \
             under its own section header."
        ),
        None => format!(
            "unknown configuration key `{key}` in {file_name} — ignored. Check for a \
             typo or a removed/renamed setting."
        ),
    }
}

/// Log one warning per unrecognised key, naming its full dotted path.
pub fn warn_unknown_keys(file_name: &str, unknown_keys: &[String]) {
    for key in unknown_keys {
        warn!("{}", unknown_key_message(file_name, key));
    }
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// Lines starting with `#` (comments) are blanked rather than dropped, so a
/// parse error's line number still points at the line in the file.
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, ConfigError>
where
    P: AsRef<Path>,
{
    let path = file_name.as_ref();
    let file = File::open(path).map_err(|err| {
        error!("Could not open file({}). {}", path.display(), err);
        ConfigError::FileRead {
            path: path.display().to_string(),
            source: err,
        }
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if line.starts_with('#') {
            lines.push(String::new());
        } else {
            lines.push(line);
        }
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::{
        apply_metrics_allow_cidrs_override, apply_metrics_bearer_token_override,
        apply_trust_xff_cidrs_override, parse_config, split_list, unknown_key_message,
    };

    const SHIPPED: &str = include_str!("../../conf/mediator.toml");

    /// A valid config reports nothing — a warning that always fires is one
    /// operators learn to ignore.
    #[test]
    fn the_shipped_config_has_no_unknown_keys() {
        let (_, unknown) = parse_config(SHIPPED).expect("shipped config parses");
        assert!(unknown.is_empty(), "unexpected unknown keys: {unknown:?}");
    }

    /// The template's header promises every setting can be overridden by the
    /// environment variable named in its `### Env:` label. A label with no
    /// override behind it is silently ignored at runtime
    /// (`LIMIT_QUEUED_SEND_MESSAGES_PER_PEER` was, until 0.49).
    #[test]
    fn every_env_label_in_the_shipped_config_is_read() {
        let source = include_str!("env.rs");
        let missing: Vec<&str> = SHIPPED
            .lines()
            .filter_map(|l| l.strip_prefix("### Env: "))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|var| !source.contains(&format!("\"{var}\"")))
            .collect();
        assert!(
            missing.is_empty(),
            "template names env vars env.rs never reads: {missing:?}"
        );
    }

    /// Keyring VTI-06: a key appended below the last table header is filed
    /// under that table. It used to vanish without a word; now it is reported
    /// with the path it actually landed at.
    #[test]
    fn a_key_appended_after_the_last_table_is_reported_with_its_dotted_path() {
        let toml = format!("{SHIPPED}\ncors_allow_origin = \"*\"\n");
        let (config, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(
            unknown,
            vec!["processors.session_expiry_cleanup.cors_allow_origin".to_string()]
        );
        // And it did not take effect — which is exactly why it is reported.
        assert!(config.security.cors_allow_origin.is_none());

        let msg = unknown_key_message("mediator.toml", &unknown[0]);
        assert!(msg.contains("`processors.session_expiry_cleanup.cors_allow_origin`"));
        assert!(msg.contains("a key placed after a [table] header belongs to that table"));
    }

    /// The same key appended as an array (the shape the Keyring report used)
    /// is still just an unknown key when misplaced — its type is never checked
    /// because nothing reads it.
    #[test]
    fn a_misplaced_array_is_reported_not_rejected() {
        let toml = format!("{SHIPPED}\ncors_allow_origin = [\"*\"]\n");
        let (_, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(
            unknown,
            vec!["processors.session_expiry_cleanup.cors_allow_origin".to_string()]
        );
    }

    /// In the right section, an array is the wrong type for the
    /// comma-separated `cors_allow_origin`, and the error says so by name.
    #[test]
    fn an_array_cors_allow_origin_in_security_is_a_clear_error() {
        let toml = SHIPPED.replacen(
            "\n[security]\n",
            "\n[security]\ncors_allow_origin = [\"*\"]\n",
            1,
        );
        assert_ne!(toml, SHIPPED, "fixture must actually inject the key");
        let err = parse_config(&toml)
            .expect_err("an array is not a string")
            .to_string();
        assert!(err.contains("cors_allow_origin"), "{err}");
        assert!(err.contains("expected a string"), "{err}");
    }

    /// A top-level typo has no table to blame; the message does not invent one.
    /// A config written for an earlier release still boots, and each retired
    /// key is reported as retired rather than as a typo.
    #[test]
    fn a_retired_key_is_reported_as_retired() {
        let toml = SHIPPED.replacen(
            "\n[security]\n",
            "\n[security]\nlegacy_admin_protocols = \"warn\"\nadmin_messages_expiry = \"3\"\n",
            1,
        );
        assert_ne!(toml, SHIPPED, "fixture must actually inject the keys");
        let (_, mut unknown) = parse_config(&toml).expect("still parses");
        unknown.sort();
        assert_eq!(
            unknown,
            vec![
                "security.admin_messages_expiry".to_string(),
                "security.legacy_admin_protocols".to_string(),
            ]
        );
        for key in &unknown {
            let msg = unknown_key_message("mediator.toml", key);
            assert!(msg.contains("is retired and ignored"), "{msg}");
            assert!(!msg.contains("typo"), "{msg}");
        }
        assert!(
            unknown_key_message("mediator.toml", "security.legacy_admin_protocols")
                .contains("messaging/* Trust Tasks")
        );
    }

    #[test]
    fn a_top_level_unknown_key_is_reported_plainly() {
        let toml = format!("log_levle = \"debug\"\n{SHIPPED}");
        let (_, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(unknown, vec!["log_levle".to_string()]);
        assert!(!unknown_key_message("m.toml", "log_levle").contains("[table]"));
    }

    #[test]
    fn split_list_trims_entries_and_drops_empties() {
        assert_eq!(
            split_list("https://a.example.com, https://b.example.com:7037"),
            vec![
                "https://a.example.com".to_string(),
                "https://b.example.com:7037".to_string(),
            ]
        );
        assert_eq!(split_list("did:example:one"), vec!["did:example:one"]);
        // A trailing separator is a typo, not an empty entry.
        assert_eq!(split_list("did:example:one,"), vec!["did:example:one"]);
    }

    /// An empty value clears the list rather than producing one empty entry —
    /// this is how an operator turns off a TOML-configured allowlist from the
    /// environment.
    #[test]
    fn split_list_empty_value_clears_the_list() {
        assert!(split_list("").is_empty());
        assert!(split_list("  ").is_empty());
        assert!(split_list(",,").is_empty());
    }

    #[test]
    fn test_trust_xff_cidrs_env_overrides_the_file() {
        let (mut config, _) = parse_config(SHIPPED).expect("shipped config parses");
        apply_trust_xff_cidrs_override(&mut config, Some("10.0.0.0/8, 2001:db8::/32".into()))
            .expect("valid list");
        assert_eq!(config.server.trust_xff_cidrs.len(), 2);

        apply_trust_xff_cidrs_override(&mut config, Some(String::new())).expect("empty clears");
        assert!(config.server.trust_xff_cidrs.is_empty());
    }

    #[test]
    fn test_trust_xff_cidrs_env_absent_keeps_the_file_value() {
        let (mut config, _) = parse_config(SHIPPED).expect("shipped config parses");
        config.server.trust_xff_cidrs = vec!["10.0.0.0/8".parse().expect("cidr")];
        apply_trust_xff_cidrs_override(&mut config, None).expect("no-op");
        assert_eq!(config.server.trust_xff_cidrs.len(), 1);
    }

    #[test]
    fn test_trust_xff_cidrs_env_rejects_a_bad_entry() {
        let (mut config, _) = parse_config(SHIPPED).expect("shipped config parses");
        let result = apply_trust_xff_cidrs_override(&mut config, Some("10.0.0.0/8,nope".into()));
        match result {
            Err(crate::error::ConfigError::Parse(msg)) => assert!(msg.contains("nope")),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_metrics_bearer_token_is_refused_not_cleared() {
        let token = |config: &crate::ConfigRaw| {
            config
                .server
                .metrics_bearer_token
                .as_ref()
                .map(|t| t.0.clone())
        };
        let (mut config, _) = parse_config(SHIPPED).expect("shipped config parses");
        config.server.metrics_bearer_token = Some(crate::RedactedString("from-file".into()));

        // Unset keeps the file's token; a value replaces it.
        apply_metrics_bearer_token_override(&mut config, None).expect("unset");
        assert_eq!(token(&config).as_deref(), Some("from-file"));
        apply_metrics_bearer_token_override(&mut config, Some("from-env".into())).expect("set");
        assert_eq!(token(&config).as_deref(), Some("from-env"));

        // An empty or blank value is refused and leaves the token in place.
        for empty in ["", "   "] {
            let err = apply_metrics_bearer_token_override(&mut config, Some(empty.into()))
                .expect_err("an empty METRICS_BEARER_TOKEN is refused");
            assert!(err.to_string().contains("METRICS_BEARER_TOKEN"), "{err}");
            assert_eq!(token(&config).as_deref(), Some("from-env"));
        }

        // An empty token in the file is refused too.
        config.server.metrics_bearer_token = Some(crate::RedactedString(String::new()));
        assert!(apply_metrics_bearer_token_override(&mut config, None).is_err());

        // No token anywhere is allowed: the allow-list alone applies.
        config.server.metrics_bearer_token = None;
        apply_metrics_bearer_token_override(&mut config, None).expect("no token");
        assert_eq!(token(&config), None);
    }

    #[test]
    fn metrics_allow_cidrs_env_sets_clears_or_keeps_the_list() {
        let (mut config, _) = parse_config(SHIPPED).expect("shipped config parses");
        apply_metrics_allow_cidrs_override(&mut config, None).expect("no-op");
        assert_eq!(
            config.server.metrics_allow_cidrs, None,
            "absent keeps default"
        );
        apply_metrics_allow_cidrs_override(&mut config, Some("10.1.0.0/16, ::1/128".into()))
            .expect("valid list");
        assert_eq!(
            config.server.metrics_allow_cidrs.as_ref().map(Vec::len),
            Some(2)
        );
        apply_metrics_allow_cidrs_override(&mut config, Some(String::new())).expect("empty");
        assert_eq!(config.server.metrics_allow_cidrs, Some(Vec::new()));
        let err = apply_metrics_allow_cidrs_override(&mut config, Some("nope".into()));
        assert!(
            matches!(err, Err(crate::error::ConfigError::Parse(m)) if m.contains("METRICS_ALLOW_CIDRS"))
        );
    }

    #[test]
    fn the_metrics_token_is_not_printed_by_debug() {
        let token = crate::RedactedString("s3cret-value".into());
        assert!(!format!("{token:?}").contains("s3cret"));
    }
}
