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
    /// `attachments_max_count`: attachments accepted on one message.
    pub const ATTACHMENTS_MAX_COUNT: usize = 20;
    /// `crypto_operations_per_message`: the per-message CPU guard, capping
    /// recipients × keys worked through while unpacking.
    pub const CRYPTO_OPERATIONS_PER_MESSAGE: usize = 1_000;
    /// `deleted_messages`: message ids one delete call may name.
    pub const DELETED_MESSAGES: usize = 100;
    /// `forward_task_queue`: forward tasks the forwarding queue may hold.
    pub const FORWARD_TASK_QUEUE: usize = 50_000;
    /// 10 MiB.
    pub const HTTP_SIZE: usize = 10_485_760;
    /// `listed_messages`: messages one list call returns.
    pub const LISTED_MESSAGES: usize = 100;
    /// `local_max_acl`: ACL entries one DID may hold.
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
    /// `queued_send_messages_soft`: the outbound queue limit an account starts
    /// on, summed across all its recipients.
    pub const QUEUED_SEND_MESSAGES_SOFT: i32 = 2_000;
    /// `queued_send_messages_hard`: the highest outbound queue limit a non-admin
    /// account may set for itself. At least the soft limit.
    pub const QUEUED_SEND_MESSAGES_HARD: i32 = 10_000;
    /// `queued_receive_messages_soft`: the inbound queue limit an account starts
    /// on.
    pub const QUEUED_RECEIVE_MESSAGES_SOFT: i32 = 200;
    /// `queued_receive_messages_hard`: the highest inbound queue limit a
    /// non-admin account may set for itself. At least the soft limit.
    pub const QUEUED_RECEIVE_MESSAGES_HARD: i32 = 1_000;
    /// `to_keys_per_recipient`: key-agreement keys considered per recipient DID.
    pub const TO_KEYS_PER_RECIPIENT: usize = 100;
    /// `to_recipients`: recipients one message may address.
    pub const TO_RECIPIENTS: usize = 100;
    /// 10 MiB.
    pub const WS_SIZE: usize = 10_485_760;
    /// `access_list_limit`: access-list entries one DID may hold.
    pub const ACCESS_LIST_LIMIT: usize = 1_000;
    /// 1 day.
    pub const OOB_INVITE_TTL: usize = 86_400;
    /// `rate_limit_per_ip`: HTTP requests per second per client address
    /// (0 = off).
    pub const RATE_LIMIT_PER_IP: u32 = 100;
    /// `rate_limit_burst`: token-bucket depth above the per-IP rate.
    pub const RATE_LIMIT_BURST: u32 = 50;
    /// `max_websocket_connections`: concurrent WebSockets across the instance
    /// (0 = unlimited).
    pub const MAX_WEBSOCKET_CONNECTIONS: usize = 10_000;
    /// `max_websocket_connections_per_did`: concurrent WebSockets one DID may
    /// hold (0 = unlimited).
    pub const MAX_WEBSOCKET_CONNECTIONS_PER_DID: usize = 100;
    /// 0 = per-DID rate limiting off.
    pub const DID_RATE_LIMIT_PER_SECOND: u32 = 0;
    /// `did_rate_limit_burst`: token-bucket depth above the per-DID rate.
    pub const DID_RATE_LIMIT_BURST: u32 = 10;
    /// 32 MiB — aggregate ceiling across every live WebSocket send queue.
    pub const WS_SEND_BUFFER: usize = 33_554_432;
    /// 16 MiB — the live-delivery pub/sub ring. Divided by `message_size` to
    /// get the ring's slot count, so this is a true byte ceiling.
    pub const PUBSUB_BUFFER: usize = 16_777_216;
    /// A relaying mediator pools one socket per endpoint, so ten covers a
    /// handful of peers sharing one egress address.
    pub const RELAY_CONNECTIONS_PER_IP: usize = 10;
    /// `relay_frames_per_second`: sustained frames per second accepted on one
    /// inter-mediator relay WebSocket.
    pub const RELAY_FRAMES_PER_SECOND: u32 = 50;
    /// `relay_frame_burst`: frames a relay WebSocket may send back-to-back above
    /// the sustained rate.
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
    /// `ws_ping_interval_secs`: seconds between the pings sent on every
    /// WebSocket.
    pub const WS_PING_INTERVAL_SECS: u64 = 30;
    /// Three ping intervals of silence before a socket is treated as gone.
    pub const WS_PONG_TIMEOUT_SECS: u64 = 90;
    /// `ws_write_timeout_secs`: seconds one WebSocket write may take before the
    /// socket is closed.
    pub const WS_WRITE_TIMEOUT_SECS: u64 = 30;
    /// Also the most an idle HTTP/1 keep-alive connection is held.
    pub const HTTP_HEADER_READ_TIMEOUT_SECS: u64 = 30;
    /// `http_request_timeout_secs`: seconds one HTTP request may take, body
    /// included, before the mediator answers 408.
    pub const HTTP_REQUEST_TIMEOUT_SECS: u64 = 60;
    /// Twice the default WebSocket cap, so HTTP requests still get connections
    /// while every WebSocket slot is taken.
    pub const MAX_HTTP_CONNECTIONS: usize = 20_000;
}

/// `[limits.mux]` — DID multiplexing. Off unless an operator enables it.
pub mod mux {
    /// Mux is off unless an operator turns it on (R5.1).
    pub const ENABLED: bool = false;
    /// Member DIDs one mux connection may carry at once.
    pub const MAX_DIDS_PER_CONNECTION: usize = 1_000;
    /// Stored grants one principal may hold.
    pub const MAX_GRANTS_PER_PRINCIPAL: usize = 5_000;
    /// Active grants one member DID may have issued.
    pub const MAX_GRANTS_PER_DID: usize = 16;
    /// 30 days.
    pub const MAX_GRANT_LIFETIME_SECS: u64 = 2_592_000;
    /// 1 day.
    pub const MAX_ATTACH_LIFETIME_SECS: u64 = 86_400;
    /// 15 minutes.
    pub const REVALIDATE_INTERVAL_SECS: u64 = 900;
    /// Send-queue depth of one mux connection across all its DIDs (each DID
    /// holds at most 8 of them).
    pub const MAX_CHANNEL_SLOTS: usize = 512;
    /// 7 days.
    pub const DEAD_RETENTION_SECS: u64 = 604_800;
}

/// `[processors.forwarding]`.
pub mod forwarding {
    /// The in-process forwarding processor runs.
    pub const ENABLED: bool = true;
    /// 1 day.
    pub const FUTURE_TIME_LIMIT: u64 = 86_400;
    /// Forwards whose next hop is another mediator or endpoint are relayed
    /// (off: every forward is delivered locally).
    pub const EXTERNAL_FORWARDING: bool = true;
    /// A failed forward produces a problem report to its sender.
    pub const REPORT_ERRORS: bool = true;
    /// Seconds of the sliding window used to track each endpoint's message rate.
    pub const RATE_WINDOW_SECONDS: u64 = 300;
    /// Messages per 10 s to one endpoint above which it is sent to over a
    /// WebSocket rather than REST.
    pub const WS_THRESHOLD_MSGS_PER_10S: u64 = 1;
    /// Seconds an outbound WebSocket to a remote endpoint may sit idle before it
    /// is closed.
    pub const WS_IDLE_TIMEOUT_SECONDS: u64 = 60;
    /// Entries read from the forwarding queue per batch.
    pub const BATCH_SIZE: usize = 50;
    /// Delivery attempts for one forward before it is abandoned.
    pub const MAX_RETRIES: u32 = 5;
    /// Backoff after an endpoint's first failure, in milliseconds; it doubles
    /// per consecutive failure.
    pub const INITIAL_BACKOFF_MS: u64 = 1_000;
    /// Ceiling on the per-endpoint backoff, in milliseconds.
    pub const MAX_BACKOFF_MS: u64 = 60_000;
    /// Next-hop endpoints delivered to in parallel.
    pub const MAX_CONCURRENT_ENDPOINTS: usize = 32;
    /// Seconds one delivery attempt (connect, send, the peer's answer, a REST
    /// fallback included) may take.
    pub const DELIVERY_TIMEOUT_SECONDS: u64 = 90;
    /// Seconds a claimed queue entry may sit untouched before another processor
    /// in the group takes it over. Keep it at least twice
    /// [`DELIVERY_TIMEOUT_SECONDS`].
    pub const RECLAIM_IDLE_SECONDS: u64 = 180;
    /// Name of the forwarding queue's consumer group.
    pub const CONSUMER_GROUP: &str = "forwarding";
    /// Refused: only a development setup turns this on.
    pub const ACCEPT_INVALID_CERTS: bool = false;
    /// Relay hops before a forward is refused as a loop; also the depth limit
    /// when peeling re-wrap layers.
    pub const MAX_HOPS: u32 = 10;
    /// `"blind"` or `"rewrap"`.
    pub const RELAY_MODE: &str = "blind";
}

/// `[processors.wake]`: the limits `messaging/wake/request/0.1` Consumer
/// rule 7 recommends. Waking is on by default: nothing rings unless an
/// account sets a handle and the handle's gateway allowlist names this
/// mediator.
pub mod wake {
    /// Waking is on; nothing rings until an account sets a handle.
    pub const ENABLED: bool = true;
    /// Rings one requester may cause for one addressee per minute.
    pub const PAIR_PER_MINUTE: u32 = 1;
    /// Rings one requester may cause for one addressee per day.
    pub const PAIR_PER_DAY: u32 = 10;
    /// Seconds.
    pub const ADDRESSEE_COALESCE_SECONDS: u64 = 15;
    /// Rings one addressee may receive per hour, whoever asks.
    pub const ADDRESSEE_PER_HOUR: u32 = 30;
}

/// `[processors.*_cleanup]`.
pub mod cleanup {
    /// The message expiry cleanup processor runs.
    pub const MESSAGE_EXPIRY_ENABLED: bool = true;
    /// The session expiry cleanup processor runs (a no-op on Redis, which
    /// expires sessions itself).
    pub const SESSION_EXPIRY_ENABLED: bool = true;
}

/// `[database]`.
pub mod database {
    /// A local Redis with no authentication: development only.
    pub const DATABASE_URL: &str = "redis://127.0.0.1/";
    /// Seconds.
    pub const DATABASE_TIMEOUT: u32 = 2;
    /// The database is a standalone server, not a cluster.
    pub const CLUSTER_MODE: bool = false;
    /// Consecutive failed commands that open the circuit breaker.
    pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
    /// Seconds an open breaker waits before letting a probe through.
    pub const CIRCUIT_BREAKER_RECOVERY_SECS: u64 = 10;
}

/// `[did_resolver]`.
pub mod did_resolver {
    /// DID documents held in the resolver's in-memory cache.
    pub const CACHE_CAPACITY: u32 = 1_000;
    /// Seconds.
    pub const CACHE_TTL: u32 = 300;
    /// **Milliseconds** (the resolver SDK's unit).
    pub const NETWORK_TIMEOUT_MS: u32 = 5_000;
    /// Concurrent DID resolution requests.
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
    /// DIDComm v1 (Aries RFC 0019) is not served.
    pub const ENABLED: bool = false;
    /// A v1 forward must come from an authenticated sender.
    pub const ALLOW_UNAUTHENTICATED_FORWARDS: bool = false;
    /// A v1 routing key must be proven by its owner before it is registered.
    pub const ALLOW_UNPROVEN_ROUTING_KEYS: bool = false;
    /// Room for a wallet with a few hundred connections; `keylist-query`
    /// returns the whole list in one reply, so this also bounds that reply.
    pub const MAX_ROUTING_KEYS_PER_ACCOUNT: u32 = 256;
}

/// `[streaming]`.
pub mod streaming {
    /// Live streaming over WebSockets is on.
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
    /// TLS is terminated by the mediator itself.
    pub const USE_SSL: bool = true;
    /// A message addressed directly to a local DID (not wrapped in a forward)
    /// is not delivered.
    pub const LOCAL_DIRECT_DELIVERY_ALLOWED: bool = false;
    /// An anonymous message is never delivered directly to a local DID.
    pub const LOCAL_DIRECT_DELIVERY_ALLOW_ANON: bool = false;
    /// Every message sent to the mediator must be signed.
    pub const BLOCK_ANONYMOUS_OUTER_ENVELOPE: bool = true;
    /// The outer envelope's signer must be the session's DID.
    pub const FORCE_SESSION_DID_MATCH: bool = true;
    /// Admin messages must arrive directly, not through another mediator.
    pub const BLOCK_REMOTE_ADMIN_MSGS: bool = true;
    /// The mediator does not act as an inter-mediator relay.
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
