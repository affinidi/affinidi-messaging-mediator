//! The one table of built-in defaults for `mediator.toml`.
//!
//! Every setting that has a default has it here, once, as the typed value the
//! mediator runs with. Everything else derives from this table:
//!
//! - the serde defaults of the raw schema (a key that may be left out of the
//!   file), which are these values written as the strings the file holds;
//! - the `Default` impls of the raw sections ([`LimitsConfigRaw`],
//!   [`MuxConfigRaw`], [`ForwardingConfigRaw`], [`DIDResolverConfig`], …),
//!   which also fill the keys the file must state;
//! - the typed runtime defaults in the mediator (`LimitsConfig::default()`,
//!   `MuxConfig::default()`, the headless `Config`), which are the raw defaults
//!   read through the same strict conversion a file goes through.
//!
//! A key the file **must** state (no serde default) still has a value here: it
//! is what a `Config` built in code starts from, not what an absent key means.
//! An absent required key stays a parse error.
//!
//! Absence is the most restrictive reading wherever a setting gates something
//! (R5.1): mux is off, DIDComm v1 is off, unauthenticated v1 forwards and
//! unproven routing keys are refused, invalid TLS certificates are refused.
//!
//! [`LimitsConfigRaw`]: crate::LimitsConfigRaw
//! [`MuxConfigRaw`]: crate::MuxConfigRaw
//! [`ForwardingConfigRaw`]: crate::ForwardingConfigRaw
//! [`DIDResolverConfig`]: crate::DIDResolverConfig

/// `[limits]`.
pub mod limits {
    pub const ATTACHMENTS_MAX_COUNT: usize = 20;
    pub const CRYPTO_OPERATIONS_PER_MESSAGE: usize = 1_000;
    pub const DELETED_MESSAGES: usize = 100;
    pub const FORWARD_TASK_QUEUE: usize = 50_000;
    /// 10 MiB.
    pub const HTTP_SIZE: usize = 10_485_760;
    pub const LISTED_MESSAGES: usize = 100;
    pub const LOCAL_MAX_ACL: usize = 1_000;
    /// 7 days.
    pub const MESSAGE_EXPIRY_SECONDS: u64 = 604_800;
    /// Off. Enabling this shortens how long a delivered-but-unacknowledged
    /// message survives, which is a reduction in durability, so it is never
    /// turned on by an upgrade — only by an operator who has read what it does.
    pub const DELIVERED_EXPIRY_SECONDS: u64 = 0;
    /// On. Unlike the delivered-expiry shortening, this destroys nothing and
    /// changes only the interleaving between senders — order within a sender
    /// is preserved, and a recipient talking to one peer sees no change.
    pub const PICKUP_ROUND_ROBIN: bool = true;
    /// 1 MiB.
    pub const MESSAGE_SIZE: usize = 1_048_576;
    /// The per-relationship outbound cap. A sender may hold this many messages
    /// for any one recipient; beyond that it is flooding that peer, not
    /// serving it.
    pub const QUEUED_SEND_MESSAGES_PER_PEER: i32 = 50;
    pub const QUEUED_SEND_MESSAGES_SOFT: i32 = 2_000;
    pub const QUEUED_SEND_MESSAGES_HARD: i32 = 10_000;
    pub const QUEUED_RECEIVE_MESSAGES_SOFT: i32 = 200;
    pub const QUEUED_RECEIVE_MESSAGES_HARD: i32 = 1_000;
    pub const TO_KEYS_PER_RECIPIENT: usize = 100;
    pub const TO_RECIPIENTS: usize = 100;
    /// 10 MiB.
    pub const WS_SIZE: usize = 10_485_760;
    pub const ACCESS_LIST_LIMIT: usize = 1_000;
    /// 1 day.
    pub const OOB_INVITE_TTL: usize = 86_400;
    pub const RATE_LIMIT_PER_IP: u32 = 100;
    pub const RATE_LIMIT_BURST: u32 = 50;
    pub const MAX_WEBSOCKET_CONNECTIONS: usize = 10_000;
    pub const MAX_WEBSOCKET_CONNECTIONS_PER_DID: usize = 100;
    /// 0 = per-DID rate limiting off.
    pub const DID_RATE_LIMIT_PER_SECOND: u32 = 0;
    pub const DID_RATE_LIMIT_BURST: u32 = 10;
    /// 32 MiB — aggregate ceiling across every live WebSocket send queue.
    pub const WS_SEND_BUFFER: usize = 33_554_432;
    /// 16 MiB — the live-delivery pub/sub ring. Divided by `message_size` to
    /// get the ring's slot count, so this is a true byte ceiling.
    pub const PUBSUB_BUFFER: usize = 16_777_216;
    /// A relaying mediator pools one socket per endpoint, so ten covers a
    /// handful of peers sharing one egress address.
    pub const RELAY_CONNECTIONS_PER_IP: usize = 10;
    pub const RELAY_FRAMES_PER_SECOND: u32 = 50;
    pub const RELAY_FRAME_BURST: u32 = 100;
    /// 4 MiB/s. A single frame larger than this is still admitted (the byte
    /// bucket is always at least `ws_size` deep); it just uses up the allowance.
    pub const RELAY_BYTES_PER_SECOND: u32 = 4_194_304;
    /// The WebSocket message rate when it is left unset and there is no
    /// per-IP rate to inherit (`rate_limit_per_ip = 0`). Unset in the file
    /// means "inherit `rate_limit_per_ip`", so this is never an absent key's
    /// string default.
    pub const WS_MESSAGES_PER_SECOND: u32 = RATE_LIMIT_PER_IP;
    /// As [`WS_MESSAGES_PER_SECOND`], for the burst (`rate_limit_burst`).
    pub const WS_MESSAGE_BURST: u32 = RATE_LIMIT_BURST;
    /// 10 s over the rate before the socket is closed.
    pub const WS_MESSAGE_THROTTLE_CLOSE_SECS: u64 = 10;
    /// A Prometheus scrape is one request every 10-60 s per scraper.
    pub const METRICS_REQUESTS_PER_SECOND: u32 = 5;
    pub const WS_PING_INTERVAL_SECS: u64 = 30;
    /// Three ping intervals of silence before a socket is treated as gone.
    pub const WS_PONG_TIMEOUT_SECS: u64 = 90;
    pub const WS_WRITE_TIMEOUT_SECS: u64 = 30;
    /// Also the most an idle HTTP/1 keep-alive connection is held.
    pub const HTTP_HEADER_READ_TIMEOUT_SECS: u64 = 30;
    pub const HTTP_REQUEST_TIMEOUT_SECS: u64 = 60;
    /// Twice the default WebSocket cap, so HTTP requests still get connections
    /// while every WebSocket slot is taken.
    pub const MAX_HTTP_CONNECTIONS: usize = 20_000;
}

/// `[limits.mux]` — DID multiplexing. Off unless an operator enables it.
pub mod mux {
    pub const ENABLED: bool = false;
    pub const MAX_DIDS_PER_CONNECTION: usize = 1_000;
    pub const MAX_GRANTS_PER_PRINCIPAL: usize = 5_000;
    pub const MAX_GRANTS_PER_DID: usize = 16;
    /// 30 days.
    pub const MAX_GRANT_LIFETIME_SECS: u64 = 2_592_000;
    /// 1 day.
    pub const MAX_ATTACH_LIFETIME_SECS: u64 = 86_400;
    /// 15 minutes.
    pub const REVALIDATE_INTERVAL_SECS: u64 = 900;
    pub const MAX_CHANNEL_SLOTS: usize = 512;
    /// 7 days.
    pub const DEAD_RETENTION_SECS: u64 = 604_800;
}

/// `[processors.forwarding]`.
pub mod forwarding {
    pub const ENABLED: bool = true;
    /// 1 day.
    pub const FUTURE_TIME_LIMIT: u64 = 86_400;
    pub const EXTERNAL_FORWARDING: bool = true;
    pub const REPORT_ERRORS: bool = true;
    pub const RATE_WINDOW_SECONDS: u64 = 300;
    pub const WS_THRESHOLD_MSGS_PER_10S: u64 = 1;
    pub const WS_IDLE_TIMEOUT_SECONDS: u64 = 60;
    pub const BATCH_SIZE: usize = 50;
    pub const MAX_RETRIES: u32 = 5;
    pub const INITIAL_BACKOFF_MS: u64 = 1_000;
    pub const MAX_BACKOFF_MS: u64 = 60_000;
    pub const MAX_CONCURRENT_ENDPOINTS: usize = 32;
    pub const DELIVERY_TIMEOUT_SECONDS: u64 = 90;
    pub const RECLAIM_IDLE_SECONDS: u64 = 180;
    pub const CONSUMER_GROUP: &str = "forwarding";
    /// Refused: only a development setup turns this on.
    pub const ACCEPT_INVALID_CERTS: bool = false;
    pub const MAX_HOPS: u32 = 10;
    /// `"blind"` or `"rewrap"`.
    pub const RELAY_MODE: &str = "blind";
}

/// `[processors.*_cleanup]`.
pub mod cleanup {
    pub const MESSAGE_EXPIRY_ENABLED: bool = true;
    pub const SESSION_EXPIRY_ENABLED: bool = true;
}

/// `[database]`.
pub mod database {
    pub const DATABASE_URL: &str = "redis://127.0.0.1/";
    /// Seconds.
    pub const DATABASE_TIMEOUT: u32 = 2;
    pub const CLUSTER_MODE: bool = false;
    /// Consecutive failed commands that open the circuit breaker.
    pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
    /// Seconds an open breaker waits before letting a probe through.
    pub const CIRCUIT_BREAKER_RECOVERY_SECS: u64 = 10;
}

/// `[did_resolver]`.
pub mod did_resolver {
    pub const CACHE_CAPACITY: u32 = 1_000;
    /// Seconds.
    pub const CACHE_TTL: u32 = 300;
    /// **Milliseconds** (the resolver SDK's unit).
    pub const NETWORK_TIMEOUT_MS: u32 = 5_000;
    pub const NETWORK_LIMIT: u32 = 100;
}

/// `[storage.fjall]`.
pub mod fjall {
    /// 16 MiB (Fjall's own default is 32 MiB).
    pub const BLOCK_CACHE: u64 = 16_777_216;
    /// 32 MiB, split across keyspaces by write weight.
    pub const WRITE_BUFFER: u64 = 33_554_432;
    /// 128 MiB (Fjall's own default is 512 MiB).
    pub const MAX_JOURNAL: u64 = 134_217_728;
    /// `"buffered"` or `"sync"`.
    pub const DURABILITY: &str = "buffered";
}

/// `[secrets]`.
pub mod secrets {
    /// The cached VTA bundle's maximum age when `cache_ttl` is unset: 30 days.
    pub const CACHE_TTL_SECS: u64 = 30 * 86_400;
}

/// `[didcomm_v1]`. Off, and every loosening off (R5.1).
pub mod didcomm_v1 {
    pub const ENABLED: bool = false;
    pub const ALLOW_UNAUTHENTICATED_FORWARDS: bool = false;
    pub const ALLOW_UNPROVEN_ROUTING_KEYS: bool = false;
    /// Room for a wallet with a few hundred connections; `keylist-query`
    /// returns the whole list in one reply, so this also bounds that reply.
    pub const MAX_ROUTING_KEYS_PER_ACCOUNT: u32 = 256;
}

/// `[streaming]`.
pub mod streaming {
    pub const ENABLED: bool = true;
}

/// `[security]`. The file must state each of these keys (except
/// `enable_inter_mediator_relay`, absent = off); the values here are what a
/// `Config` built in code (`SecurityConfig::headless`, the `MediatorBuilder`)
/// starts from. Every gate is closed (R5.1).
pub mod security {
    /// 15 minutes.
    pub const JWT_ACCESS_EXPIRY: u64 = 900;
    /// 1 day.
    pub const JWT_REFRESH_EXPIRY: u64 = 86_400;
    pub const USE_SSL: bool = true;
    pub const LOCAL_DIRECT_DELIVERY_ALLOWED: bool = false;
    pub const LOCAL_DIRECT_DELIVERY_ALLOW_ANON: bool = false;
    pub const BLOCK_ANONYMOUS_OUTER_ENVELOPE: bool = true;
    pub const FORCE_SESSION_DID_MATCH: bool = true;
    pub const BLOCK_REMOTE_ADMIN_MSGS: bool = true;
    pub const ENABLE_INTER_MEDIATOR_RELAY: bool = false;
}

#[cfg(test)]
mod tests {
    use crate::{ForwardingConfigRaw, LimitsConfigRaw, MuxConfigRaw};

    /// A section holding only the keys the file must state reads back as the
    /// section's `Default`: an absent optional key's serde default and the
    /// `Default` impl are the same table value.
    fn only_required<T>(full: &T, required: &[&str]) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let toml::Value::Table(mut table) = toml::Value::try_from(full).unwrap() else {
            panic!("a section serializes to a table");
        };
        table.retain(|key, _| required.iter().any(|r| *key == **r));
        toml::Value::Table(table).try_into().unwrap()
    }

    fn as_toml<T: serde::Serialize>(value: &T) -> toml::Value {
        toml::Value::try_from(value).unwrap()
    }

    #[test]
    fn absent_limits_keys_take_the_table_value() {
        let full = LimitsConfigRaw::default();
        let required = [
            "attachments_max_count",
            "crypto_operations_per_message",
            "deleted_messages",
            "forward_task_queue",
            "http_size",
            "listed_messages",
            "local_max_acl",
            "message_expiry_seconds",
            "message_size",
            "queued_send_messages_soft",
            "queued_send_messages_hard",
            "queued_receive_messages_soft",
            "queued_receive_messages_hard",
            "to_keys_per_recipient",
            "to_recipients",
            "ws_size",
            "access_list_limit",
            "oob_invite_ttl",
        ];
        assert_eq!(as_toml(&only_required(&full, &required)), as_toml(&full));
    }

    #[test]
    fn absent_mux_keys_take_the_table_value() {
        let full = MuxConfigRaw::default();
        assert_eq!(as_toml(&only_required(&full, &[])), as_toml(&full));
    }

    #[test]
    fn absent_forwarding_keys_take_the_table_value() {
        let full = ForwardingConfigRaw::default();
        let required = [
            "enabled",
            "future_time_limit",
            "external_forwarding",
            "report_errors",
            "blocked_forwarding_dids",
        ];
        assert_eq!(as_toml(&only_required(&full, &required)), as_toml(&full));
    }
}
