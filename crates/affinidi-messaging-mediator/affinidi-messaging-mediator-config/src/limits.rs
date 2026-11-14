//! Raw `[limits]` config schema.
//!
//! Every default is a [`defaults::limits`](crate::defaults::limits) value.
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
    /// Seconds an HTTP/1 client has to send a request's headers, counted from
    /// when the connection is ready for its next request, so it also bounds
    /// how long an idle keep-alive connection is held open.
    #[serde(default = "default_http_header_read_timeout_secs")]
    pub http_header_read_timeout_secs: String,
    /// Seconds one HTTP request (other than a WebSocket upgrade's socket) may
    /// take, body upload included, before the mediator answers 408.
    #[serde(default = "default_http_request_timeout_secs")]
    pub http_request_timeout_secs: String,
    /// Concurrent TCP connections the HTTP listener holds, WebSockets
    /// included. `"0"` means unlimited.
    #[serde(default = "default_max_http_connections")]
    pub max_http_connections: String,
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
        use crate::defaults::mux as d;
        Self {
            enabled: d::ENABLED.to_string(),
            max_dids_per_connection: d::MAX_DIDS_PER_CONNECTION.to_string(),
            max_grants_per_principal: d::MAX_GRANTS_PER_PRINCIPAL.to_string(),
            max_grants_per_did: d::MAX_GRANTS_PER_DID.to_string(),
            max_grant_lifetime_secs: d::MAX_GRANT_LIFETIME_SECS.to_string(),
            max_attach_lifetime_secs: d::MAX_ATTACH_LIFETIME_SECS.to_string(),
            revalidate_interval_secs: d::REVALIDATE_INTERVAL_SECS.to_string(),
            max_channel_slots: d::MAX_CHANNEL_SLOTS.to_string(),
            dead_retention_secs: d::DEAD_RETENTION_SECS.to_string(),
        }
    }
}

/// Every key at its [`defaults::limits`](crate::defaults::limits) value,
/// including the keys a file must state. `ws_messages_per_second` and
/// `ws_message_burst` are left empty, as an absent key leaves them: empty
/// inherits the per-IP rate.
impl Default for LimitsConfigRaw {
    fn default() -> Self {
        use crate::defaults::limits as d;
        Self {
            attachments_max_count: d::ATTACHMENTS_MAX_COUNT.to_string(),
            crypto_operations_per_message: d::CRYPTO_OPERATIONS_PER_MESSAGE.to_string(),
            deleted_messages: d::DELETED_MESSAGES.to_string(),
            forward_task_queue: d::FORWARD_TASK_QUEUE.to_string(),
            http_size: d::HTTP_SIZE.to_string(),
            listed_messages: d::LISTED_MESSAGES.to_string(),
            local_max_acl: d::LOCAL_MAX_ACL.to_string(),
            message_expiry_seconds: d::MESSAGE_EXPIRY_SECONDS.to_string(),
            delivered_expiry_seconds: default_delivered_expiry_seconds(),
            pickup_round_robin: default_pickup_round_robin(),
            message_size: d::MESSAGE_SIZE.to_string(),
            queued_send_messages_per_peer: default_queued_send_messages_per_peer(),
            queued_send_messages_soft: d::QUEUED_SEND_MESSAGES_SOFT.to_string(),
            queued_send_messages_hard: d::QUEUED_SEND_MESSAGES_HARD.to_string(),
            queued_receive_messages_soft: d::QUEUED_RECEIVE_MESSAGES_SOFT.to_string(),
            queued_receive_messages_hard: d::QUEUED_RECEIVE_MESSAGES_HARD.to_string(),
            to_keys_per_recipient: d::TO_KEYS_PER_RECIPIENT.to_string(),
            to_recipients: d::TO_RECIPIENTS.to_string(),
            ws_size: d::WS_SIZE.to_string(),
            access_list_limit: d::ACCESS_LIST_LIMIT.to_string(),
            oob_invite_ttl: d::OOB_INVITE_TTL.to_string(),
            rate_limit_per_ip: default_rate_limit_per_ip(),
            rate_limit_burst: default_rate_limit_burst(),
            max_websocket_connections: default_max_websocket_connections(),
            max_websocket_connections_per_did: default_max_websocket_connections_per_did(),
            did_rate_limit_per_second: default_did_rate_limit_per_second(),
            did_rate_limit_burst: default_did_rate_limit_burst(),
            ws_send_buffer: default_ws_send_buffer(),
            pubsub_buffer: default_pubsub_buffer(),
            relay_connections_per_ip: default_relay_connections_per_ip(),
            relay_frames_per_second: default_relay_frames_per_second(),
            relay_frame_burst: default_relay_frame_burst(),
            relay_bytes_per_second: default_relay_bytes_per_second(),
            ws_messages_per_second: String::new(),
            ws_message_burst: String::new(),
            ws_message_throttle_close_secs: default_ws_message_throttle_close_secs(),
            metrics_requests_per_second: default_metrics_requests_per_second(),
            ws_ping_interval_secs: default_ws_ping_interval_secs(),
            ws_pong_timeout_secs: default_ws_pong_timeout_secs(),
            ws_write_timeout_secs: default_ws_write_timeout_secs(),
            http_header_read_timeout_secs: default_http_header_read_timeout_secs(),
            http_request_timeout_secs: default_http_request_timeout_secs(),
            max_http_connections: default_max_http_connections(),
            mux: MuxConfigRaw::default(),
        }
    }
}

/// Serde defaults for the optional `[limits]` keys: each the
/// [`defaults::limits`](crate::defaults::limits) value as the string the file
/// holds.
macro_rules! string_defaults {
    ($($fn_name:ident => $value:ident),* $(,)?) => {
        $(
            fn $fn_name() -> String {
                crate::defaults::limits::$value.to_string()
            }
        )*
    };
}

string_defaults! {
    default_delivered_expiry_seconds => DELIVERED_EXPIRY_SECONDS,
    default_pickup_round_robin => PICKUP_ROUND_ROBIN,
    default_queued_send_messages_per_peer => QUEUED_SEND_MESSAGES_PER_PEER,
    default_rate_limit_per_ip => RATE_LIMIT_PER_IP,
    default_rate_limit_burst => RATE_LIMIT_BURST,
    default_max_websocket_connections => MAX_WEBSOCKET_CONNECTIONS,
    default_max_websocket_connections_per_did => MAX_WEBSOCKET_CONNECTIONS_PER_DID,
    default_did_rate_limit_per_second => DID_RATE_LIMIT_PER_SECOND,
    default_did_rate_limit_burst => DID_RATE_LIMIT_BURST,
    default_ws_send_buffer => WS_SEND_BUFFER,
    default_pubsub_buffer => PUBSUB_BUFFER,
    default_relay_connections_per_ip => RELAY_CONNECTIONS_PER_IP,
    default_relay_frames_per_second => RELAY_FRAMES_PER_SECOND,
    default_relay_frame_burst => RELAY_FRAME_BURST,
    default_relay_bytes_per_second => RELAY_BYTES_PER_SECOND,
    default_ws_message_throttle_close_secs => WS_MESSAGE_THROTTLE_CLOSE_SECS,
    default_metrics_requests_per_second => METRICS_REQUESTS_PER_SECOND,
    default_ws_ping_interval_secs => WS_PING_INTERVAL_SECS,
    default_ws_pong_timeout_secs => WS_PONG_TIMEOUT_SECS,
    default_ws_write_timeout_secs => WS_WRITE_TIMEOUT_SECS,
    default_http_header_read_timeout_secs => HTTP_HEADER_READ_TIMEOUT_SECS,
    default_http_request_timeout_secs => HTTP_REQUEST_TIMEOUT_SECS,
    default_max_http_connections => MAX_HTTP_CONNECTIONS,
}
