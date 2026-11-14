//! The typed `[database]` settings the Redis handler runs with.
//!
//! The mediator reads `mediator.toml`'s all-strings `[database]` section with
//! the raw schema in `affinidi-messaging-mediator-config` (its
//! `DatabaseConfigRaw`) and converts it to this type. The standalone processors
//! deserialize this type directly from their own TOML. Either way a value is
//! read strictly: one that does not read is an error, never a default.
//!
//! The defaults here must equal the config crate's `defaults::database` table
//! (this crate cannot depend on it — the dependency runs the other way); the
//! mediator's tests hold the two together.

use serde::{Deserialize, Serialize};

use std::fmt;

use crate::redact::redact_url;

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
///
/// The string form is read as `mediator.toml`'s `[database] cluster_mode` is:
/// `true` or `false`, ignoring case and surrounding space, and empty means
/// `false`. Anything else is refused, not guessed at — a typo must not pick a
/// client that does not match the server.
fn bool_or_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Text(String),
    }
    match Flag::deserialize(deserializer)? {
        Flag::Bool(value) => Ok(value),
        Flag::Text(text) => match text.trim().to_ascii_lowercase().as_str() {
            "" | "false" => Ok(false),
            "true" => Ok(true),
            _ => Err(serde::de::Error::custom(format!(
                "database.cluster_mode = {:?} is not valid: expected \"true\" or \"false\"",
                text.trim()
            ))),
        },
    }
}

#[cfg(test)]
mod debug_tests {
    use super::DatabaseConfig;

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
        }
    }
}

#[cfg(test)]
mod cluster_mode_tests {
    use super::DatabaseConfig;

    fn parse(field: &str) -> Result<bool, serde_json::Error> {
        let text = format!(
            r#"{{"functions_file":"f","database_url":"redis://x/","database_timeout":2,
               "circuit_breaker_threshold":5,"circuit_breaker_recovery_secs":10{field}}}"#
        );
        serde_json::from_str::<DatabaseConfig>(&text).map(|c| c.cluster_mode)
    }

    #[test]
    fn cluster_mode_accepts_bool_and_string() {
        assert!(parse(r#","cluster_mode":true"#).unwrap());
        assert!(parse(r#","cluster_mode":"true""#).unwrap());
        assert!(!parse(r#","cluster_mode":"false""#).unwrap());
        assert!(!parse(r#","cluster_mode":false"#).unwrap());
        assert!(!parse("").unwrap());
        assert!(!parse(r#","cluster_mode":"""#).unwrap());
    }

    #[test]
    fn cluster_mode_ignores_case_and_space() {
        for on in ["True", "TRUE", " true "] {
            assert!(
                parse(&format!(r#","cluster_mode":"{on}""#)).unwrap(),
                "{on:?}"
            );
        }
        for off in ["False", " FALSE "] {
            assert!(
                !parse(&format!(r#","cluster_mode":"{off}""#)).unwrap(),
                "{off:?}"
            );
        }
    }

    /// Read as `mediator.toml` reads it: anything but `true`/`false` is
    /// refused, where it used to be guessed at (`yes` on, `maybe` off).
    #[test]
    fn an_unreadable_cluster_mode_is_refused() {
        for bad in ["yes", "1", "on", "maybe", "ture"] {
            let err = parse(&format!(r#","cluster_mode":"{bad}""#)).unwrap_err();
            assert!(
                err.to_string().contains("database.cluster_mode"),
                "{bad}: {err}"
            );
        }
    }
}
