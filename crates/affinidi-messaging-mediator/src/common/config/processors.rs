use affinidi_messaging_mediator_common::errors::MediatorError;
pub use affinidi_messaging_mediator_common::tasks::forwarding::ForwardingConfig;
use affinidi_messaging_mediator_common::tasks::forwarding::RelayMode;
// Raw TOML schema lives in the config crate; the typed configs + conversions
// stay here. `ForwardingConfig` is a mediator-common type, so its conversion is
// a free fn (`forwarding_config_from_raw`) rather than a `TryFrom` (orphan rule).
use affinidi_messaging_mediator_config::{
    ForwardingConfigRaw, MessageExpiryCleanupConfigRaw, SessionExpiryCleanupConfigRaw, values,
};
use ahash::AHashSet as HashSet;
use serde::{Deserialize, Serialize};

use super::config_error;

/// Processor configuration for the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorsConfig {
    pub forwarding: ForwardingConfig,
    pub message_expiry_cleanup: MessageExpiryCleanupConfig,
    pub session_expiry_cleanup: SessionExpiryCleanupConfig,
}

/// The config crate's defaults, read through the same conversions a file goes
/// through.
impl Default for ProcessorsConfig {
    fn default() -> Self {
        Self {
            forwarding: forwarding_config_from_raw(ForwardingConfigRaw::default())
                .expect("the built-in forwarding defaults are valid"),
            message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
            session_expiry_cleanup: SessionExpiryCleanupConfig::default(),
        }
    }
}

/// Configuration for the in-process message expiry sweep. The standalone
/// `message_expiry_cleanup` binary in `affinidi-messaging-mediator-processors`
/// has its own config — they're intentionally not shared because the
/// standalone binary is Redis-only by design and runs in a separate process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfig {
    pub enabled: bool,
}

impl Default for MessageExpiryCleanupConfig {
    fn default() -> Self {
        Self::try_from(MessageExpiryCleanupConfigRaw::default())
            .expect("the built-in cleanup default is valid")
    }
}

impl std::convert::TryFrom<MessageExpiryCleanupConfigRaw> for MessageExpiryCleanupConfig {
    type Error = MediatorError;

    fn try_from(raw: MessageExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(MessageExpiryCleanupConfig {
            enabled: values::boolean("processors.message_expiry_cleanup.enabled", &raw.enabled)
                .map_err(config_error)?,
        })
    }
}

/// Configuration for the in-process session expiry sweep. Only does work
/// on backends without native TTL (Fjall, memory); on Redis the sweep is
/// a no-op, so leaving it enabled there is harmless.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionExpiryCleanupConfig {
    pub enabled: bool,
}

impl Default for SessionExpiryCleanupConfig {
    fn default() -> Self {
        Self::try_from(SessionExpiryCleanupConfigRaw::default())
            .expect("the built-in cleanup default is valid")
    }
}

impl std::convert::TryFrom<SessionExpiryCleanupConfigRaw> for SessionExpiryCleanupConfig {
    type Error = MediatorError;

    fn try_from(raw: SessionExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(SessionExpiryCleanupConfig {
            enabled: values::boolean("processors.session_expiry_cleanup.enabled", &raw.enabled)
                .map_err(config_error)?,
        })
    }
}

/// Build the typed [`ForwardingConfig`] (a mediator-common type) from the raw
/// [`ForwardingConfigRaw`] schema. A free function rather than a `TryFrom` impl
/// because both types are now foreign to this crate (the raw type moved to
/// `affinidi-messaging-mediator-config`), which the orphan rule forbids.
///
/// Every value is read strictly: one that does not read is an error naming
/// `processors.forwarding.<key>`, never a default.
pub(crate) fn forwarding_config_from_raw(
    raw: ForwardingConfigRaw,
) -> Result<ForwardingConfig, MediatorError> {
    fn key(field: &str) -> String {
        format!("processors.forwarding.{field}")
    }
    fn num<T: std::str::FromStr>(field: &str, value: &str) -> Result<T, MediatorError> {
        values::number(&key(field), value).map_err(config_error)
    }
    fn at_least_one<T>(field: &str, value: &str) -> Result<T, MediatorError>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy + From<u8>,
    {
        values::number_at_least(&key(field), value, T::from(1)).map_err(config_error)
    }
    fn flag(field: &str, value: &str) -> Result<bool, MediatorError> {
        values::boolean(&key(field), value).map_err(config_error)
    }

    Ok(ForwardingConfig {
        enabled: flag("enabled", &raw.enabled)?,
        future_time_limit: num("future_time_limit", &raw.future_time_limit)?,
        external_forwarding: flag("external_forwarding", &raw.external_forwarding)?,
        report_errors: flag("report_errors", &raw.report_errors)?,
        blocked_forwarding: HashSet::new(),
        blocked_forwarding_late: Default::default(),
        rate_window_seconds: num("rate_window_seconds", &raw.rate_window_seconds)?,
        ws_threshold_msgs_per_10s: num(
            "ws_threshold_msgs_per_10s",
            &raw.ws_threshold_msgs_per_10s,
        )?,
        ws_idle_timeout_seconds: num("ws_idle_timeout_seconds", &raw.ws_idle_timeout_seconds)?,
        batch_size: num("batch_size", &raw.batch_size)?,
        max_retries: num("max_retries", &raw.max_retries)?,
        initial_backoff_ms: num("initial_backoff_ms", &raw.initial_backoff_ms)?,
        max_backoff_ms: num("max_backoff_ms", &raw.max_backoff_ms)?,
        // Zero would stall or disable delivery, so it is refused.
        max_concurrent_endpoints: at_least_one(
            "max_concurrent_endpoints",
            &raw.max_concurrent_endpoints,
        )?,
        delivery_timeout_seconds: at_least_one(
            "delivery_timeout_seconds",
            &raw.delivery_timeout_seconds,
        )?,
        reclaim_idle_seconds: at_least_one("reclaim_idle_seconds", &raw.reclaim_idle_seconds)?,
        consumer_group: raw.consumer_group,
        accept_invalid_certs: flag("accept_invalid_certs", &raw.accept_invalid_certs)?,
        max_hops: num("max_hops", &raw.max_hops)?,
        relay_mode: match values::one_of(
            &key("relay_mode"),
            &raw.relay_mode,
            &["", "blind", "rewrap"],
        )
        .map_err(config_error)?
        {
            "rewrap" => RelayMode::Rewrap,
            _ => RelayMode::Blind,
        },
        relay_trusted_mediators: raw
            .relay_trusted_mediators
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarding_config_default() {
        let config = ForwardingConfig::default();
        assert!(config.enabled);
        assert!(config.external_forwarding);
        assert!(config.report_errors);
        assert_eq!(config.future_time_limit, 86400);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert_eq!(config.max_concurrent_endpoints, 32);
        assert_eq!(config.delivery_timeout_seconds, 90);
        assert_eq!(config.reclaim_idle_seconds, 180);
        assert_eq!(config.consumer_group, "forwarding");
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 10);
        assert!(config.blocked_forwarding.is_empty());
    }

    /// mediator-common's `ForwardingConfig::default()` (and its serde
    /// defaults, which the standalone forwarding processor reads its own
    /// typed config with) cannot see the config crate's defaults table — the
    /// dependency runs the other way. This holds the two to the same values,
    /// so the table stays the one place a forwarding default is decided.
    #[test]
    fn the_common_forwarding_default_is_the_config_table() {
        let from_table = ProcessorsConfig::default().forwarding;
        assert_eq!(
            serde_json::to_value(&from_table).unwrap(),
            serde_json::to_value(ForwardingConfig::default()).unwrap()
        );
        assert!(MessageExpiryCleanupConfig::default().enabled);
        assert!(SessionExpiryCleanupConfig::default().enabled);
    }

    #[test]
    fn test_forwarding_config_try_from() {
        let raw = ForwardingConfigRaw {
            enabled: "true".to_string(),
            external_forwarding: "true".to_string(),
            future_time_limit: "3600".to_string(),
            report_errors: "true".to_string(),
            blocked_forwarding_dids: "did:example:blocked1,did:example:blocked2".to_string(),
            rate_window_seconds: "300".to_string(),
            ws_threshold_msgs_per_10s: "1".to_string(),
            ws_idle_timeout_seconds: "60".to_string(),
            batch_size: "50".to_string(),
            max_retries: "5".to_string(),
            initial_backoff_ms: "1000".to_string(),
            max_backoff_ms: "60000".to_string(),

            max_concurrent_endpoints: "32".to_string(),
            delivery_timeout_seconds: "90".to_string(),
            reclaim_idle_seconds: "180".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "10".to_string(),
            relay_mode: "blind".to_string(),
            relay_trusted_mediators: String::new(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
        assert!(config.enabled);
        assert!(config.external_forwarding);
        assert!(config.report_errors);
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 10);
        assert_eq!(config.future_time_limit, 3600);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert_eq!(config.consumer_group, "forwarding");
        // Note: TryFrom currently ignores blocked_forwarding_dids and always sets empty HashSet
        assert!(config.blocked_forwarding.is_empty());
    }

    #[test]
    fn test_forwarding_config_try_from_disabled() {
        let raw = ForwardingConfigRaw {
            enabled: "false".to_string(),
            external_forwarding: "false".to_string(),
            future_time_limit: "7200".to_string(),
            report_errors: "false".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "600".to_string(),
            ws_threshold_msgs_per_10s: "10".to_string(),
            ws_idle_timeout_seconds: "120".to_string(),
            batch_size: "100".to_string(),
            max_retries: "3".to_string(),
            initial_backoff_ms: "2000".to_string(),
            max_backoff_ms: "120000".to_string(),

            max_concurrent_endpoints: "8".to_string(),
            delivery_timeout_seconds: "15".to_string(),
            reclaim_idle_seconds: "20".to_string(),
            consumer_group: "custom_group".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "5".to_string(),
            relay_mode: "rewrap".to_string(),
            relay_trusted_mediators: "did:peer:alice , did:peer:bob".to_string(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
        assert!(!config.enabled);
        assert!(!config.external_forwarding);
        assert!(!config.report_errors);
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 5);
        assert_eq!(config.future_time_limit, 7200);
        assert_eq!(config.rate_window_seconds, 600);
        assert_eq!(config.ws_threshold_msgs_per_10s, 10);
        assert_eq!(config.ws_idle_timeout_seconds, 120);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 2000);
        assert_eq!(config.max_backoff_ms, 120000);
        assert_eq!(config.max_concurrent_endpoints, 8);
        assert_eq!(config.delivery_timeout_seconds, 15);
        assert_eq!(config.reclaim_idle_seconds, 20);
        assert_eq!(config.consumer_group, "custom_group");
        // relay_mode parses case-insensitively; the trusted-mediator list is
        // comma-split with surrounding whitespace trimmed and blanks dropped.
        assert_eq!(config.relay_mode, RelayMode::Rewrap);
        assert!(config.relay_trusted_mediators.contains("did:peer:alice"));
        assert!(config.relay_trusted_mediators.contains("did:peer:bob"));
        assert_eq!(config.relay_trusted_mediators.len(), 2);
    }

    #[test]
    fn relay_mode_defaults_to_blind_with_empty_allowlist() {
        // The first try_from fixture leaves relay_mode = "blind" and an empty
        // trusted list — the historical, no-regression default.
        let config = ForwardingConfig::default();
        assert_eq!(config.relay_mode, RelayMode::Blind);
        assert!(config.relay_trusted_mediators.is_empty());
    }

    #[test]
    fn unrecognised_relay_mode_is_refused() {
        let raw = ForwardingConfigRaw {
            enabled: "true".to_string(),
            external_forwarding: "true".to_string(),
            future_time_limit: "3600".to_string(),
            report_errors: "true".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "300".to_string(),
            ws_threshold_msgs_per_10s: "1".to_string(),
            ws_idle_timeout_seconds: "60".to_string(),
            batch_size: "50".to_string(),
            max_retries: "5".to_string(),
            initial_backoff_ms: "1000".to_string(),
            max_backoff_ms: "60000".to_string(),

            max_concurrent_endpoints: "32".to_string(),
            delivery_timeout_seconds: "90".to_string(),
            reclaim_idle_seconds: "180".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "10".to_string(),
            relay_mode: "bogus".to_string(),
            relay_trusted_mediators: String::new(),
        };
        let err = forwarding_config_from_raw(raw).unwrap_err().to_string();
        assert!(err.contains("processors.forwarding.relay_mode"), "{err}");
        assert!(err.contains("\"blind\", \"rewrap\""), "{err}");
    }

    #[test]
    fn test_forwarding_config_try_from_invalid_values_are_refused() {
        let raw = ForwardingConfigRaw {
            enabled: "not_bool".to_string(),
            external_forwarding: "not_bool".to_string(),
            future_time_limit: "not_a_number".to_string(),
            report_errors: "not_bool".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "bad".to_string(),
            ws_threshold_msgs_per_10s: "bad".to_string(),
            ws_idle_timeout_seconds: "bad".to_string(),
            batch_size: "bad".to_string(),
            max_retries: "bad".to_string(),
            initial_backoff_ms: "bad".to_string(),
            max_backoff_ms: "bad".to_string(),

            max_concurrent_endpoints: "bad".to_string(),
            delivery_timeout_seconds: "0".to_string(),
            reclaim_idle_seconds: "bad".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "bad".to_string(),
            max_hops: "bad".to_string(),
            relay_mode: "bad".to_string(),
            relay_trusted_mediators: String::new(),
        };
        // Each unreadable value is refused on its own, naming its key.
        let good = || ForwardingConfigRaw {
            enabled: "true".to_string(),
            external_forwarding: "true".to_string(),
            future_time_limit: "3600".to_string(),
            report_errors: "true".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "300".to_string(),
            ws_threshold_msgs_per_10s: "1".to_string(),
            ws_idle_timeout_seconds: "60".to_string(),
            batch_size: "50".to_string(),
            max_retries: "5".to_string(),
            initial_backoff_ms: "1000".to_string(),
            max_backoff_ms: "60000".to_string(),
            max_concurrent_endpoints: "32".to_string(),
            delivery_timeout_seconds: "90".to_string(),
            reclaim_idle_seconds: "180".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "10".to_string(),
            relay_mode: "blind".to_string(),
            relay_trusted_mediators: String::new(),
        };
        assert!(forwarding_config_from_raw(good()).is_ok());
        assert!(forwarding_config_from_raw(raw).is_err());
        type Set = fn(&mut ForwardingConfigRaw);
        let cases: [(&str, Set); 6] = [
            ("enabled", |r| r.enabled = "not_bool".into()),
            ("future_time_limit", |r| r.future_time_limit = "1d".into()),
            ("max_concurrent_endpoints", |r| {
                r.max_concurrent_endpoints = "0".into()
            }),
            ("delivery_timeout_seconds", |r| {
                r.delivery_timeout_seconds = "0".into()
            }),
            ("accept_invalid_certs", |r| {
                r.accept_invalid_certs = "bad".into()
            }),
            ("max_hops", |r| r.max_hops = "-1".into()),
        ];
        for (field, set) in cases {
            let mut raw = good();
            set(&mut raw);
            let err = forwarding_config_from_raw(raw).unwrap_err().to_string();
            assert!(
                err.contains(&format!("processors.forwarding.{field}")),
                "{field}: {err}"
            );
        }
        // Booleans are case-insensitive and trimmed.
        let mut upper = good();
        upper.enabled = " FALSE ".into();
        assert!(!forwarding_config_from_raw(upper).unwrap().enabled);
    }

    #[test]
    fn an_unreadable_expiry_cleanup_flag_is_refused() {
        let err = MessageExpiryCleanupConfig::try_from(MessageExpiryCleanupConfigRaw {
            enabled: "yes".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("processors.message_expiry_cleanup.enabled"),
            "{err}"
        );
        let err = SessionExpiryCleanupConfig::try_from(SessionExpiryCleanupConfigRaw {
            enabled: "1".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("processors.session_expiry_cleanup.enabled"),
            "{err}"
        );
    }
}
