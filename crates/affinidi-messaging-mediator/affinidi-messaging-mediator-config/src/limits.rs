//! Raw `[limits]` config schema.
//!
//! The resolved `LimitsConfig` (typed numbers) and the
//! `LimitsConfigRaw → LimitsConfig` conversion stay in the mediator.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub deleted_messages: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub listed_messages: String,
    pub local_max_acl: String,
    pub message_expiry_seconds: String,
    /// How long a message is kept after it has first been handed to its
    /// recipient. `"0"` (the default) means "no different from any other
    /// message" — the historical behaviour.
    #[serde(default = "default_delivered_expiry_seconds")]
    pub delivered_expiry_seconds: String,
    /// Give each sender a turn on pickup instead of serving the inbox strictly
    /// head-first. `"true"` by default.
    #[serde(default = "default_pickup_round_robin")]
    pub pickup_round_robin: String,
    pub message_size: String,
    #[serde(default = "default_queued_send_messages_per_peer")]
    pub queued_send_messages_per_peer: String,
    pub queued_send_messages_soft: String,
    pub queued_send_messages_hard: String,
    pub queued_receive_messages_soft: String,
    pub queued_receive_messages_hard: String,
    pub to_keys_per_recipient: String,
    pub to_recipients: String,
    pub ws_size: String,
    pub access_list_limit: String,
    pub oob_invite_ttl: String,
    #[serde(default = "default_rate_limit_per_ip")]
    pub rate_limit_per_ip: String,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: String,
    #[serde(default = "default_max_websocket_connections")]
    pub max_websocket_connections: String,
    #[serde(default = "default_max_websocket_connections_per_did")]
    pub max_websocket_connections_per_did: String,
    #[serde(default = "default_did_rate_limit_per_second")]
    pub did_rate_limit_per_second: String,
    #[serde(default = "default_did_rate_limit_burst")]
    pub did_rate_limit_burst: String,
    #[serde(default = "default_ws_send_buffer")]
    pub ws_send_buffer: String,
    #[serde(default = "default_pubsub_buffer")]
    pub pubsub_buffer: String,
    /// Concurrent anonymous inter-mediator relay WebSockets one source address
    /// may hold. Defaulted so an existing `mediator.toml` keeps loading.
    #[serde(default = "default_relay_connections_per_ip")]
    pub relay_connections_per_ip: String,
    /// Sustained frames per second accepted on one relay WebSocket.
    #[serde(default = "default_relay_frames_per_second")]
    pub relay_frames_per_second: String,
    /// Frames a relay WebSocket may send back-to-back above the sustained rate.
    #[serde(default = "default_relay_frame_burst")]
    pub relay_frame_burst: String,
    /// Sustained bytes per second accepted on one relay WebSocket.
    #[serde(default = "default_relay_bytes_per_second")]
    pub relay_bytes_per_second: String,
    /// Sustained messages per second read from one authenticated WebSocket.
    /// `"0"` means unlimited. Empty (the default) inherits `rate_limit_per_ip`,
    /// so WebSocket messages are held to the same rate as HTTP requests.
    #[serde(default)]
    pub ws_messages_per_second: String,
    /// Messages an authenticated WebSocket may send back-to-back above the
    /// sustained rate. Empty (the default) inherits `rate_limit_burst`.
    #[serde(default)]
    pub ws_message_burst: String,
    /// Seconds an authenticated WebSocket may stay over its message rate
    /// before the mediator closes it with 1008. `"0"` means never close (the
    /// socket is only slowed).
    #[serde(default = "default_ws_message_throttle_close_secs")]
    pub ws_message_throttle_close_secs: String,
    /// Requests per second the `/metrics` endpoint answers, across all callers.
    #[serde(default = "default_metrics_requests_per_second")]
    pub metrics_requests_per_second: String,
    /// Seconds between the pings the mediator sends on each WebSocket.
    #[serde(default = "default_ws_ping_interval_secs")]
    pub ws_ping_interval_secs: String,
    /// How long a WebSocket peer may stay silent: once a ping goes
    /// unanswered, the peer has this minus the ping interval to send any
    /// frame (a pong counts) before the mediator closes it.
    #[serde(default = "default_ws_pong_timeout_secs")]
    pub ws_pong_timeout_secs: String,
    /// Seconds one write to a WebSocket may take before the mediator closes it.
    #[serde(default = "default_ws_write_timeout_secs")]
    pub ws_write_timeout_secs: String,
    /// `[limits.mux]` — DID multiplexing. Absent means disabled.
    #[serde(default)]
    pub mux: MuxConfigRaw,
}

/// Raw `[limits.mux]` schema: DID multiplexing (one connection carrying many
/// DIDs). Every field is optional; an absent table leaves mux **off** (R5.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MuxConfigRaw {
    /// `"true"` to enable. Anything else, including absence, is off.
    pub enabled: String,
    pub max_dids_per_connection: String,
    pub max_grants_per_principal: String,
    pub max_grants_per_did: String,
    pub max_grant_lifetime_secs: String,
    pub max_attach_lifetime_secs: String,
    pub revalidate_interval_secs: String,
    pub max_channel_slots: String,
    pub dead_retention_secs: String,
}

impl Default for MuxConfigRaw {
    fn default() -> Self {
        Self {
            enabled: "false".into(),
            max_dids_per_connection: "1000".into(),
            max_grants_per_principal: "5000".into(),
            max_grants_per_did: "16".into(),
            max_grant_lifetime_secs: "2592000".into(),
            max_attach_lifetime_secs: "86400".into(),
            revalidate_interval_secs: "900".into(),
            max_channel_slots: "512".into(),
            dead_retention_secs: "604800".into(),
        }
    }
}

/// Off. Enabling this shortens how long a delivered-but-unacknowledged message
/// survives, which is a reduction in durability, so it is never turned on by an
/// upgrade — only by an operator who has read what it does.
fn default_delivered_expiry_seconds() -> String {
    "0".to_string()
}

/// On. Unlike the delivered-expiry shortening, this destroys nothing and
/// changes only the interleaving between senders — order within a sender is
/// preserved, and a recipient talking to one peer sees no change at all.
fn default_pickup_round_robin() -> String {
    "true".to_string()
}

/// 50 — the per-relationship outbound cap. A sender may hold this many
/// messages for any one recipient; beyond that it is flooding that peer, not
/// serving it. Defaulted (rather than required) so an existing `mediator.toml`
/// keeps loading without an edit.
fn default_queued_send_messages_per_peer() -> String {
    "50".to_string()
}

fn default_rate_limit_per_ip() -> String {
    "100".to_string()
}

/// 32 MiB — aggregate ceiling across every live WebSocket send queue.
fn default_ws_send_buffer() -> String {
    "33554432".to_string()
}

/// 16 MiB — the live-delivery pub/sub ring. Divided by `message_size` to get
/// the ring's slot count, so this is a true byte ceiling.
fn default_pubsub_buffer() -> String {
    "16777216".to_string()
}
/// 10 — a relaying mediator pools one socket per endpoint, so ten covers a
/// handful of peers sharing one egress address.
fn default_relay_connections_per_ip() -> String {
    "10".to_string()
}
fn default_relay_frames_per_second() -> String {
    "50".to_string()
}
fn default_relay_frame_burst() -> String {
    "100".to_string()
}
/// 4 MiB/s. A single frame larger than this is still admitted (the byte bucket
/// is always at least `ws_size` deep), it just uses up the allowance.
fn default_relay_bytes_per_second() -> String {
    "4194304".to_string()
}
/// 10 s over the rate before the socket is closed.
fn default_ws_message_throttle_close_secs() -> String {
    "10".to_string()
}
/// 5 — a Prometheus scrape is one request every 10-60 s per scraper.
fn default_metrics_requests_per_second() -> String {
    "5".to_string()
}

/// 30 s between pings.
fn default_ws_ping_interval_secs() -> String {
    "30".to_string()
}

/// 90 s — three ping intervals of silence before a socket is treated as gone.
fn default_ws_pong_timeout_secs() -> String {
    "90".to_string()
}

/// 30 s for one write to complete.
fn default_ws_write_timeout_secs() -> String {
    "30".to_string()
}

fn default_rate_limit_burst() -> String {
    "50".to_string()
}
fn default_max_websocket_connections() -> String {
    "10000".to_string()
}
fn default_max_websocket_connections_per_did() -> String {
    "100".to_string()
}
fn default_did_rate_limit_per_second() -> String {
    "0".to_string()
}
fn default_did_rate_limit_burst() -> String {
    "10".to_string()
}
