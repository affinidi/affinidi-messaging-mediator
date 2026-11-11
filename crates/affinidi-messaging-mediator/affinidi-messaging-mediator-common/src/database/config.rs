use serde::{Deserialize, Serialize};

use std::fmt;

use crate::errors::MediatorError;
use crate::redact::redact_url;

/// Database Struct contains database and storage of messages related configuration details
///
/// `database_pool_size` was removed in favour of the multiplexed
/// connection; `#[serde(default, skip_serializing)]` on an ignored
/// field silently drops pre-0.14 config files that still set it
/// rather than hard-failing on an unknown key.
#[derive(Serialize, Deserialize)]
pub struct DatabaseConfigRaw {
    pub functions_file: String,
    pub database_url: String,
    pub database_timeout: String,
    pub scripts_path: Option<String>,
    /// `"true"` to talk to a cluster-mode server. Absent means `"false"`.
    #[serde(default)]
    pub cluster_mode: String,
    /// Silently absorbed — pre-0.14 config files set this; the
    /// multiplexed Redis connection doesn't use a pool. The field
    /// stays in the raw struct so deserialisation doesn't error on
    /// unknown keys; it's not round-tripped on serialise.
    #[serde(default, skip_serializing, rename = "database_pool_size")]
    _ignored_pool_size: Option<serde_json::Value>,
}

/// `Debug` is written by hand so `database_url` prints with its credentials
/// replaced (see [`redact_url`]): the startup log prints the whole config.
#[derive(Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub functions_file: Option<String>,
    pub database_url: String,
    pub database_timeout: u32,
    /// Use a cluster client. Startup refuses a server whose cluster mode
    /// differs (ElastiCache Serverless is always cluster mode). Accepts a
    /// bool or the string form `mediator.toml` documents (`"true"`), so the
    /// standalone processors read the same value.
    #[serde(default, deserialize_with = "bool_or_string")]
    pub cluster_mode: bool,
    /// Number of consecutive failures before the circuit breaker opens
    pub circuit_breaker_threshold: u32,
    /// Seconds to wait before probing Redis after circuit opens
    pub circuit_breaker_recovery_secs: u64,
}

impl fmt::Debug for DatabaseConfigRaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfigRaw")
            .field("functions_file", &self.functions_file)
            .field("database_url", &redact_url(&self.database_url))
            .field("database_timeout", &self.database_timeout)
            .field("scripts_path", &self.scripts_path)
            .field("cluster_mode", &self.cluster_mode)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("functions_file", &self.functions_file)
            .field("database_url", &redact_url(&self.database_url))
            .field("database_timeout", &self.database_timeout)
            .field("cluster_mode", &self.cluster_mode)
            .field("circuit_breaker_threshold", &self.circuit_breaker_threshold)
            .field(
                "circuit_breaker_recovery_secs",
                &self.circuit_breaker_recovery_secs,
            )
            .finish()
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            functions_file: Some("./atm-functions.lua".into()),
            database_url: "redis://127.0.0.1/".into(),
            database_timeout: 2,
            cluster_mode: false,
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 10,
        }
    }
}

/// Reads `cluster_mode` written either as `true` or as `"true"`.
fn bool_or_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Text(String),
    }
    Ok(match Flag::deserialize(deserializer)? {
        Flag::Bool(value) => value,
        Flag::Text(text) => parse_cluster_mode(&text),
    })
}

/// Parses `[database] cluster_mode`, ignoring case and surrounding space:
/// `true`/`false`, `1`/`0`, `yes`/`no` or `on`/`off`. Absent (empty) is
/// `false`; any other value is warned about and taken as `false`, and the
/// startup check then refuses a cluster-mode server, so a typo can't go
/// unnoticed.
pub fn parse_cluster_mode(raw: &str) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "false" | "0" | "no" | "off" => false,
        "true" | "1" | "yes" | "on" => true,
        _ => {
            tracing::warn!(
                "Could not parse database.cluster_mode value '{raw}', using default: false"
            );
            false
        }
    }
}

impl std::convert::TryFrom<DatabaseConfigRaw> for DatabaseConfig {
    type Error = MediatorError;

    fn try_from(raw: DatabaseConfigRaw) -> Result<Self, Self::Error> {
        Ok(DatabaseConfig {
            functions_file: Some(raw.functions_file),
            database_url: raw.database_url,
            database_timeout: raw.database_timeout.parse().unwrap_or(2),
            cluster_mode: parse_cluster_mode(&raw.cluster_mode),
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 10,
        })
    }
}

#[cfg(test)]
mod debug_tests {
    use super::{DatabaseConfig, DatabaseConfigRaw};

    #[test]
    fn debug_hides_database_url_credentials() {
        for url in ["redis://:pw@h/", "redis://user:pw@h/"] {
            let config = DatabaseConfig {
                database_url: url.into(),
                ..Default::default()
            };
            for text in [format!("{config:?}"), format!("{config:#?}")] {
                assert!(!text.contains("pw"), "{text}");
                assert!(text.contains("redis://***@h/"), "{text}");
            }

            let raw: DatabaseConfigRaw = serde_json::from_value(serde_json::json!({
                "functions_file": "f",
                "database_url": url,
                "database_timeout": "2",
                "scripts_path": null,
            }))
            .unwrap();
            let text = format!("{raw:#?}");
            assert!(!text.contains("pw"), "{text}");
        }
    }
}

#[cfg(test)]
mod cluster_mode_tests {
    use super::DatabaseConfig;

    fn parse(field: &str) -> bool {
        let text = format!(
            r#"{{"functions_file":"f","database_url":"redis://x/","database_timeout":2,
               "circuit_breaker_threshold":5,"circuit_breaker_recovery_secs":10{field}}}"#
        );
        serde_json::from_str::<DatabaseConfig>(&text)
            .unwrap()
            .cluster_mode
    }

    #[test]
    fn cluster_mode_accepts_bool_and_string() {
        assert!(parse(r#","cluster_mode":true"#));
        assert!(parse(r#","cluster_mode":"true""#));
        assert!(!parse(r#","cluster_mode":"false""#));
        assert!(!parse(r#","cluster_mode":false"#));
        assert!(!parse(""));
    }

    #[test]
    fn cluster_mode_ignores_case_and_accepts_common_spellings() {
        for on in ["True", "TRUE", " true ", "1", "yes", "On"] {
            assert!(super::parse_cluster_mode(on), "{on:?} is on");
        }
        for off in ["False", "0", "no", "OFF", "", "maybe"] {
            assert!(!super::parse_cluster_mode(off), "{off:?} is off");
        }
    }
}
