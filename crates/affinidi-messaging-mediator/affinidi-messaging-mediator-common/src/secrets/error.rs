//! Errors produced by the [`SecretStore`](crate::secrets::SecretStore) trait and its
//! backends.

use thiserror::Error;

/// A `Result` whose error is a [`SecretStoreError`].
pub type Result<T> = std::result::Result<T, SecretStoreError>;

/// Why a secret-store operation failed.
///
/// `backend` members carry the backend's short label (`aws`, `keyring`,
/// `file`, …); `key` members the secret name as the caller passed it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    /// The `[secrets]` backend URL could not be parsed.
    ///
    /// The error is logged and shown, so `url` never carries credentials: any
    /// `user:password@` becomes `***@` (see
    /// [`redact_url`](crate::redact::redact_url)), and the body of a
    /// `string://` URL, an unknown scheme or a value with no scheme is not
    /// shown at all.
    #[error("invalid backend URL '{url}': {reason}")]
    InvalidUrl {
        /// The URL as configured, with any credentials hidden (see above).
        url: String,
        /// What is wrong with it.
        reason: String,
    },

    /// The backend cannot do this here: it was compiled out (its
    /// `secrets-*` cargo feature is off), its platform service is missing,
    /// or it does not support the operation (enumeration, for one).
    #[error("backend '{backend}' is not available: {reason}")]
    BackendUnavailable {
        /// The backend's label.
        backend: &'static str,
        /// Why it is unavailable, naming the feature to enable where that is the cause.
        reason: String,
    },

    /// The backend exists but could not be reached (network, credentials,
    /// service error). Usually worth retrying.
    #[error("backend '{backend}' unreachable: {reason}")]
    Unreachable {
        /// The backend's label.
        backend: &'static str,
        /// The underlying failure.
        reason: String,
    },

    /// No secret is stored under `key`.
    #[error("secret '{key}' not found")]
    NotFound {
        /// The secret name looked up.
        key: String,
    },

    /// The backend refused access to `key`.
    #[error("permission denied on '{key}': {reason}")]
    PermissionDenied {
        /// The secret name.
        key: String,
        /// The backend's explanation.
        reason: String,
    },

    /// The write–read–delete health check
    /// ([`SecretStore::probe`](crate::secrets::SecretStore::probe)) failed.
    #[error("probe failed on backend '{backend}': {reason}")]
    ProbeFailed {
        /// The backend's label.
        backend: &'static str,
        /// Which step failed and how.
        reason: String,
    },

    /// The stored bytes are not a readable
    /// [`Envelope`](crate::secrets::envelope::Envelope).
    #[error("stored envelope for '{key}' could not be decoded: {reason}")]
    EnvelopeDecode {
        /// The secret name.
        key: String,
        /// The decode failure.
        reason: String,
    },

    /// The envelope decoded but holds a different kind of secret than the
    /// caller asked for.
    #[error("stored envelope for '{key}' has unexpected kind '{actual}' (wanted '{expected}')")]
    EnvelopeKindMismatch {
        /// The secret name.
        key: String,
        /// The kind the caller expected.
        expected: &'static str,
        /// The kind the envelope carries.
        actual: String,
    },

    /// The envelope's schema version is newer than this build reads
    /// (see [`ENVELOPE_VERSION`](crate::secrets::envelope::ENVELOPE_VERSION)).
    #[error("stored envelope for '{key}' has unsupported version {version}")]
    EnvelopeUnsupportedVersion {
        /// The secret name.
        key: String,
        /// The version found.
        version: u32,
    },

    /// The envelope's payload decoded but fails validation (a key of the
    /// wrong length or type, say).
    #[error("stored secret '{key}' failed shape validation: {reason}")]
    InvalidShape {
        /// The secret name.
        key: String,
        /// What is wrong with the payload.
        reason: String,
    },

    /// A file-system error in a file-backed backend.
    #[error("I/O error on backend '{backend}': {source}")]
    Io {
        /// The backend's label.
        backend: &'static str,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },

    /// JSON (de)serialisation of a secret or envelope failed.
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Moving a per-key deployment into the single
    /// [`SECRETS_BUNDLE`](crate::secrets::SECRETS_BUNDLE) secret failed.
    /// `reason` says what happened and whether anything was left behind;
    /// `action` what the operator must do before starting again.
    #[error("{reason}. To fix: {action}, then start again")]
    MigrationFailed {
        /// What went wrong, and what (if anything) was left behind.
        reason: String,
        /// What the operator must do before restarting.
        action: String,
    },

    /// A conditional write lost: `key` changed on the backend since this
    /// process last read it (another writer, or a read served by a
    /// replica that was behind). Nothing was written; read again and
    /// retry.
    #[error("backend '{backend}' refused the write to '{key}': it changed since it was read")]
    Conflict {
        /// The backend's label.
        backend: &'static str,
        /// The secret whose write was refused.
        key: String,
    },

    /// Any other failure, as a message.
    #[error("{0}")]
    Other(String),
}

impl SecretStoreError {
    /// Builds an [`Unreachable`](Self::Unreachable) error for `backend`.
    pub fn unreachable<S: Into<String>>(backend: &'static str, reason: S) -> Self {
        Self::Unreachable {
            backend,
            reason: reason.into(),
        }
    }

    /// Builds an [`Other`](Self::Other) error.
    pub fn other<S: Into<String>>(reason: S) -> Self {
        Self::Other(reason.into())
    }
}
