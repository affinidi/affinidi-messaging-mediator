//! Error type for config loading.
//!
//! The schema crate can't use the mediator's server-tier `MediatorError`, so
//! file-reading / parsing functions return this lean error instead. The
//! mediator maps it back to `MediatorError::ConfigError` at the call site.

/// Failure while reading or parsing a `mediator.toml`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The config file could not be opened/read.
    #[error("could not open config file ({path}): {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },
    /// The TOML did not deserialize into [`ConfigRaw`](crate::ConfigRaw).
    #[error("could not parse configuration settings: {0}")]
    Parse(String),
    /// A setting's value could not be read as what the setting takes, or is
    /// outside the range it allows. Never replaced with a default: a typo must
    /// not quietly pick another value.
    #[error("{key} = {value:?} is not valid: expected {expected}")]
    Invalid {
        /// `section.key`, e.g. `limits.message_size`.
        key: String,
        /// The value as written (after trimming).
        value: String,
        /// What the setting accepts, e.g. `a whole number of 0 or more`.
        expected: String,
    },
}

impl ConfigError {
    /// A [`ConfigError::Invalid`].
    pub fn invalid(
        key: impl Into<String>,
        value: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self::Invalid {
            key: key.into(),
            value: value.into(),
            expected: expected.into(),
        }
    }
}
