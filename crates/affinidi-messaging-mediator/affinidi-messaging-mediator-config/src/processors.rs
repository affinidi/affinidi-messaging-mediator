//! Raw `[processors]` config schema (forwarding + expiry sweeps).
//!
//! Every default is a [`defaults::forwarding`](crate::defaults::forwarding) or
//! [`defaults::cleanup`](crate::defaults::cleanup) value. The resolved
//! `ProcessorsConfig` / `ForwardingConfig` and all conversions stay in the
//! mediator (`ForwardingConfig` lives in mediator-common alongside the
//! forwarding processor).

use serde::{Deserialize, Serialize};

use crate::defaults::{cleanup, forwarding as fwd};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessorsConfigRaw {
    pub forwarding: ForwardingConfigRaw,
    pub message_expiry_cleanup: MessageExpiryCleanupConfigRaw,
    // Added after the first release of this struct; default so configs
    // written before the session sweeper existed still parse.
    #[serde(default)]
    pub session_expiry_cleanup: SessionExpiryCleanupConfigRaw,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfigRaw {
    pub enabled: String,
}

impl Default for MessageExpiryCleanupConfigRaw {
    fn default() -> Self {
        Self {
            enabled: cleanup::MESSAGE_EXPIRY_ENABLED.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionExpiryCleanupConfigRaw {
    #[serde(default = "default_session_expiry_enabled")]
    pub enabled: String,
}

impl Default for SessionExpiryCleanupConfigRaw {
    fn default() -> Self {
        SessionExpiryCleanupConfigRaw {
            enabled: default_session_expiry_enabled(),
        }
    }
}

fn default_session_expiry_enabled() -> String {
    cleanup::SESSION_EXPIRY_ENABLED.to_string()
}

// `ForwardingConfig` (the typed shape) lives in `mediator-common`
// alongside `ForwardingProcessor` so the standalone forwarding binary
// can construct it. `ForwardingConfigRaw` (this struct) is the wizard's
// all-strings TOML format and stays here, in the schema crate.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingConfigRaw {
    pub enabled: String,
    pub future_time_limit: String,
    pub external_forwarding: String,
    pub report_errors: String,
    pub blocked_forwarding_dids: String,
    #[serde(default = "default_rate_window_seconds")]
    pub rate_window_seconds: String,
    #[serde(default = "default_ws_threshold_msgs_per_10s")]
    pub ws_threshold_msgs_per_10s: String,
    #[serde(default = "default_ws_idle_timeout_seconds")]
    pub ws_idle_timeout_seconds: String,
    #[serde(default = "default_batch_size")]
    pub batch_size: String,
    #[serde(default = "default_max_retries")]
    pub max_retries: String,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: String,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: String,
    #[serde(default = "default_max_concurrent_endpoints")]
    pub max_concurrent_endpoints: String,
    #[serde(default = "default_delivery_timeout_seconds")]
    pub delivery_timeout_seconds: String,
    #[serde(default = "default_reclaim_idle_seconds")]
    pub reclaim_idle_seconds: String,
    #[serde(default = "default_consumer_group")]
    pub consumer_group: String,
    #[serde(default = "default_accept_invalid_certs")]
    pub accept_invalid_certs: String,
    #[serde(default = "default_max_hops")]
    pub max_hops: String,
    /// Relay mode for remote next-hop forwards: "blind" (default) or "rewrap".
    #[serde(default = "default_relay_mode")]
    pub relay_mode: String,
    /// Comma-separated allowlist of trusted peer-mediator DIDs (rewrap mode).
    #[serde(default)]
    pub relay_trusted_mediators: String,
}

/// Every key at its [`defaults::forwarding`](crate::defaults::forwarding)
/// value, including the keys a file must state. No DID is blocked and no peer
/// mediator is listed.
impl Default for ForwardingConfigRaw {
    fn default() -> Self {
        Self {
            enabled: fwd::ENABLED.to_string(),
            future_time_limit: fwd::FUTURE_TIME_LIMIT.to_string(),
            external_forwarding: fwd::EXTERNAL_FORWARDING.to_string(),
            report_errors: fwd::REPORT_ERRORS.to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: default_rate_window_seconds(),
            ws_threshold_msgs_per_10s: default_ws_threshold_msgs_per_10s(),
            ws_idle_timeout_seconds: default_ws_idle_timeout_seconds(),
            batch_size: default_batch_size(),
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            max_concurrent_endpoints: default_max_concurrent_endpoints(),
            delivery_timeout_seconds: default_delivery_timeout_seconds(),
            reclaim_idle_seconds: default_reclaim_idle_seconds(),
            consumer_group: default_consumer_group(),
            accept_invalid_certs: default_accept_invalid_certs(),
            max_hops: default_max_hops(),
            relay_mode: default_relay_mode(),
            relay_trusted_mediators: String::new(),
        }
    }
}

/// Serde defaults for the optional `[processors.forwarding]` keys: each the
/// [`defaults::forwarding`](crate::defaults::forwarding) value as the string
/// the file holds.
macro_rules! string_defaults {
    ($($fn_name:ident => $value:ident),* $(,)?) => {
        $(
            fn $fn_name() -> String {
                fwd::$value.to_string()
            }
        )*
    };
}

string_defaults! {
    default_rate_window_seconds => RATE_WINDOW_SECONDS,
    default_ws_threshold_msgs_per_10s => WS_THRESHOLD_MSGS_PER_10S,
    default_ws_idle_timeout_seconds => WS_IDLE_TIMEOUT_SECONDS,
    default_batch_size => BATCH_SIZE,
    default_max_retries => MAX_RETRIES,
    default_initial_backoff_ms => INITIAL_BACKOFF_MS,
    default_max_backoff_ms => MAX_BACKOFF_MS,
    default_max_concurrent_endpoints => MAX_CONCURRENT_ENDPOINTS,
    default_delivery_timeout_seconds => DELIVERY_TIMEOUT_SECONDS,
    default_reclaim_idle_seconds => RECLAIM_IDLE_SECONDS,
    default_consumer_group => CONSUMER_GROUP,
    default_accept_invalid_certs => ACCEPT_INVALID_CERTS,
    default_max_hops => MAX_HOPS,
    default_relay_mode => RELAY_MODE,
}
