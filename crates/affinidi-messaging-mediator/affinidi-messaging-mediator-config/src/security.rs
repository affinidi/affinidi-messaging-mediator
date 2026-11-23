//! Raw `[security]` config schema.
//!
//! The resolved `SecurityConfig` (parsed ACL set, JWT keys, CORS layer) and the
//! `SecurityConfigRaw → SecurityConfig` conversion stay in the mediator — they
//! load secrets and build runtime objects this crate intentionally avoids.

use serde::{Deserialize, Serialize};

/// Raw `[security]` section, read into the mediator's `SecurityConfig`.
/// Boolean keys are `"true"`/`"false"` strings.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigRaw {
    /// `explicit_deny` (open: unknown DIDs self-register) or `explicit_allow`
    /// (closed: only pre-registered DIDs authenticate). Case-insensitive; anything
    /// else refuses to start.
    pub mediator_acl_mode: String,
    /// ACL applied to a DID with no account yet: `ALLOW_ALL` or `DENY_ALL`
    /// first, then comma-separated flags (`LOCAL`, `SEND_MESSAGES`, …).
    pub global_acl_default: String,
    /// Whether a message addressed directly to a local DID is delivered.
    pub local_direct_delivery_allowed: String,
    /// Whether an anonymous message may be delivered directly to a local DID.
    pub local_direct_delivery_allow_anon: String,
    /// Whether the mediator terminates TLS itself. `"false"` only behind a
    /// TLS-terminating proxy.
    pub use_ssl: String,
    /// Certificate file for TLS, used when `use_ssl` is on. A relative path is
    /// relative to the config file's directory.
    pub ssl_certificate_file: Option<String>,
    /// Private key file for the TLS certificate.
    pub ssl_key_file: Option<String>,
    /// Access-token lifetime in seconds. At least 10, and less than
    /// `jwt_refresh_expiry`.
    pub jwt_access_expiry: String,
    /// Refresh-token lifetime in seconds, counting the access-token lifetime: a
    /// refresh token is valid for `jwt_refresh_expiry - jwt_access_expiry`.
    pub jwt_refresh_expiry: String,
    /// Origins allowed cross-origin access to the REST endpoints: a
    /// comma-separated list of exact origins or `https://*.domain` wildcards, or
    /// `*`. Absent: no cross-origin access. Also checked against `Origin` on the
    /// WebSocket upgrade.
    pub cors_allow_origin: Option<String>,
    /// Whether every message sent to the mediator must be signed.
    pub block_anonymous_outer_envelope: String,
    /// Whether admin messages must arrive directly rather than through another
    /// mediator.
    pub block_remote_admin_msgs: String,
    /// Whether the outer envelope's signer must be the session's DID. Must be
    /// off when `block_anonymous_outer_envelope` is off.
    pub force_session_did_match: String,
    /// Explicit inter-mediator relay switch. `#[serde(default)]` so configs
    /// that predate the flag deserialize without it (empty → `false`).
    #[serde(default)]
    pub enable_inter_mediator_relay: String,
    /// `warn` or `enforce` — whether a Trust Task that fails its acceptance
    /// checks (proof, `issuedAt`, issuer binding) is refused or only logged.
    /// `#[serde(default)]` so configs that predate the setting deserialize
    /// without it (empty → `warn`).
    #[serde(default)]
    pub trust_task_verification: String,
    /// RFC 3339 time until which `POST /tsp/authenticate` also accepts the
    /// older request that signs only the challenge string. Empty (the default)
    /// accepts only the signed statement that names this mediator.
    /// `#[serde(default)]` so configs that predate the setting deserialize
    /// without it.
    #[serde(default)]
    pub tsp_auth_accept_unbound_until: String,
}
