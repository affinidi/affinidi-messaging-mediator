//! Typed reads of the settings whose runtime form needs nothing beyond this
//! crate: the top-level `log_level`/`log_json`, `[streaming]`,
//! `[did_resolver]`, `[secrets] cache_ttl` and `[storage]`.
//!
//! Each is the one place its setting is read. They are pure — no secret
//! backend, no network — so the mediator runs them before anything is opened
//! (and again on `config/reload`), and any other consumer of `mediator.toml`
//! can run the same checks. Every value is read through [`values`]: an
//! unreadable or out-of-range one is a [`ConfigError`] naming its key, never a
//! default.

use tracing::level_filters::LevelFilter;

use crate::{ConfigError, DIDResolverConfig, StorageConfig, StreamingConfig, defaults, values};

/// The legal `log_level` values.
pub const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// `log_level`, read strictly: an unknown level is refused, not read as INFO.
pub fn log_level(raw: &str) -> Result<LevelFilter, ConfigError> {
    Ok(match values::one_of("log_level", raw, LOG_LEVELS)? {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    })
}

/// `log_json`: `true` or `false`.
pub fn log_json(raw: &str) -> Result<bool, ConfigError> {
    values::boolean("log_json", raw)
}

/// `[streaming] enabled`, and when it is on, that `uuid` is `hostname://` or
/// `string://<id>`. Returns whether streaming is enabled.
pub fn streaming(raw: &StreamingConfig) -> Result<bool, ConfigError> {
    let enabled = values::boolean("streaming.enabled", &raw.enabled)?;
    if enabled && !(raw.uuid.starts_with("hostname://") || raw.uuid.starts_with("string://")) {
        return Err(ConfigError::invalid(
            "streaming.uuid",
            raw.uuid.as_str(),
            "\"hostname://\" or \"string://<id>\"",
        ));
    }
    Ok(enabled)
}

/// The typed `[did_resolver]` section. The mediator turns it into the
/// resolver SDK's cache config; this crate stays free of that SDK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidResolverSettings {
    /// A remote resolver to use instead of resolving locally.
    pub address: Option<String>,
    pub cache_capacity: u32,
    /// Seconds.
    pub cache_ttl: u32,
    /// **Milliseconds** (the resolver SDK's unit). At least 1.
    pub network_timeout_ms: u32,
    pub network_limit: u32,
}

impl Default for DidResolverSettings {
    fn default() -> Self {
        did_resolver(&DIDResolverConfig::default())
            .expect("the built-in resolver defaults are valid")
    }
}

/// `[did_resolver]`, every number read strictly. `network_timeout` is in
/// milliseconds; an unreadable value used to fall back to `5` — five
/// milliseconds, not the 5000 the template ships.
pub fn did_resolver(raw: &DIDResolverConfig) -> Result<DidResolverSettings, ConfigError> {
    let num = |key: &str, value: &str| -> Result<u32, ConfigError> {
        values::number(&format!("did_resolver.{key}"), value)
    };
    Ok(DidResolverSettings {
        address: raw.address.clone(),
        cache_capacity: num("cache_capacity", &raw.cache_capacity)?,
        cache_ttl: num("cache_ttl", &raw.cache_ttl)?,
        network_timeout_ms: values::number_at_least(
            "did_resolver.network_timeout",
            &raw.network_timeout,
            1,
        )?,
        network_limit: num("network_limit", &raw.network_limit)?,
    })
}

/// `[secrets] cache_ttl` in seconds: `None` when unset (the caller then uses
/// [`defaults::secrets::CACHE_TTL_SECS`]), `Some(0)` for "never expires",
/// otherwise a humantime duration such as `"30d"` or `"12h"`.
pub fn secrets_cache_ttl(raw: Option<&str>) -> Result<Option<u64>, ConfigError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(0)),
        Some(ttl) => humantime::parse_duration(ttl)
            .map(|d| Some(d.as_secs()))
            .map_err(|e| {
                ConfigError::invalid(
                    "secrets.cache_ttl",
                    ttl,
                    format!("a duration such as \"30d\" or \"12h\", or \"0\" for never ({e})"),
                )
            }),
    }
}

/// [`secrets_cache_ttl`] with the default applied.
pub fn secrets_cache_ttl_or_default(raw: Option<&str>) -> Result<u64, ConfigError> {
    Ok(secrets_cache_ttl(raw)?.unwrap_or(defaults::secrets::CACHE_TTL_SECS))
}

/// `[storage]`: a backend this mediator knows, a data directory for Fjall, and
/// readable Fjall tuning.
pub fn storage(storage: &StorageConfig) -> Result<(), ConfigError> {
    let backend = values::one_of("storage.backend", &storage.backend, &["redis", "fjall"])?;
    if backend == "fjall"
        && storage
            .data_dir
            .as_deref()
            .is_none_or(|d| d.trim().is_empty())
    {
        return Err(ConfigError::Inconsistent(
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
            values::number::<u64>(key, value)?;
        }
        values::one_of(
            "storage.fjall.durability",
            &fjall.durability,
            &["buffered", "sync"],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_resolver_timeout_is_in_milliseconds() {
        let settings = DidResolverSettings::default();
        assert_eq!(settings.network_timeout_ms, 5_000);
        assert_eq!(settings.cache_capacity, 1_000);
        assert_eq!(settings.cache_ttl, 300);
        assert_eq!(settings.network_limit, 100);
    }

    #[test]
    fn an_unreadable_resolver_value_names_its_key() {
        let raw = DIDResolverConfig {
            network_timeout: "5s".into(),
            ..DIDResolverConfig::default()
        };
        let err = did_resolver(&raw).unwrap_err().to_string();
        assert!(err.contains("did_resolver.network_timeout"), "{err}");
        let raw = DIDResolverConfig {
            network_timeout: "0".into(),
            ..DIDResolverConfig::default()
        };
        assert!(did_resolver(&raw).is_err());
    }

    #[test]
    fn log_level_is_strict() {
        assert_eq!(log_level(" Debug ").unwrap(), LevelFilter::DEBUG);
        assert!(log_level("verbose").is_err());
    }

    #[test]
    fn a_streaming_uuid_is_checked_only_when_streaming_is_on() {
        let mut raw = StreamingConfig {
            enabled: "true".into(),
            uuid: "nonsense".into(),
        };
        let err = streaming(&raw).unwrap_err().to_string();
        assert!(err.contains("streaming.uuid"), "{err}");
        raw.enabled = "false".into();
        assert!(!streaming(&raw).unwrap());
    }

    #[test]
    fn the_secrets_cache_ttl_defaults_to_thirty_days() {
        assert_eq!(secrets_cache_ttl_or_default(None).unwrap(), 30 * 86_400);
        assert_eq!(
            secrets_cache_ttl_or_default(Some(" ")).unwrap(),
            30 * 86_400
        );
        assert_eq!(secrets_cache_ttl_or_default(Some("0")).unwrap(), 0);
        assert_eq!(secrets_cache_ttl_or_default(Some("12h")).unwrap(), 43_200);
        assert!(secrets_cache_ttl(Some("forever")).is_err());
    }
}
