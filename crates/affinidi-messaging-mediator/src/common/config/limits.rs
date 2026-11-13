use affinidi_messaging_mediator_common::errors::MediatorError;
// `LimitsConfigRaw` (the raw TOML schema) lives in the config crate; the
// conversion to the typed `LimitsConfig` (a mediator-local type) stays here.
use affinidi_messaging_mediator_common::store::mux::MuxLimits;
use affinidi_messaging_mediator_config::{LimitsConfigRaw, MuxConfigRaw, values};
use serde::{Deserialize, Serialize};

use super::{config_error, config_error_msg};

/// Resource limits configuration for the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub attachments_max_count: usize,
    pub crypto_operations_per_message: usize,
    pub deleted_messages: usize,
    pub forward_task_queue: usize,
    pub http_size: usize,
    pub listed_messages: usize,
    pub local_max_acl: usize,
    pub message_expiry_seconds: u64,
    /// How long a message is kept after it has **first been handed to its
    /// recipient**, in seconds. `0` disables the shortening entirely, which is
    /// the default and the historical behaviour.
    ///
    /// A message the recipient has collected but not acknowledged is held for
    /// the full [`message_expiry_seconds`](Self::message_expiry_seconds) — and
    /// held **against its sender**, counting toward that sender's queue-depth
    /// limits the whole time. For a recipient that collected it and simply did
    /// not acknowledge, that is a week of a sender's allowance spent on work
    /// that is already done.
    ///
    /// It is off by default because shortening it is a real reduction in
    /// durability, not a free win: a message can be marked delivered and still
    /// not have reached an application — the delivery layer deliberately does
    /// not acknowledge a message that reached no consumer, so that the mediator
    /// redelivers it. Setting this shorter than a client's worst restart
    /// window will destroy exactly those messages.
    pub delivered_expiry_seconds: u64,
    /// Give each sender a turn on pickup instead of serving the inbox strictly
    /// head-first. On by default.
    ///
    /// A sender that queued fifty messages ahead of another's is otherwise
    /// fifty messages a recipient must collect before it sees the second — and
    /// if it cannot process them and does not delete them, it never does.
    ///
    /// On by default because, unlike
    /// [`delivered_expiry_seconds`](Self::delivered_expiry_seconds), this
    /// destroys nothing: order **within** a sender is preserved exactly, only
    /// the interleaving between senders changes, and no ordering guarantee
    /// covers that. A recipient with one peer sees byte-identical results.
    ///
    /// Turn it off if a client genuinely depends on cross-sender arrival order
    /// — which is depending on a coincidence, but is a real thing to have to
    /// live with.
    pub pickup_round_robin: bool,
    pub message_size: usize,
    /// Per-relationship outbound cap: how many messages one sender may have
    /// queued for one *specific* recipient. This is the gate that catches
    /// flooding; `queued_send_messages_soft` below is a coarse ceiling that
    /// cannot tell flooding from fan-out. `-1` disables it.
    pub queued_send_messages_per_peer: i32,
    pub queued_send_messages_soft: i32,
    pub queued_send_messages_hard: i32,
    pub queued_receive_messages_soft: i32,
    pub queued_receive_messages_hard: i32,
    pub to_keys_per_recipient: usize,
    pub to_recipients: usize,
    pub ws_size: usize,
    pub access_list_limit: usize,
    pub oob_invite_ttl: usize,
    /// Maximum requests per second per IP address. 0 = unlimited.
    pub rate_limit_per_ip: u32,
    /// Burst size for rate limiting (additional requests allowed in a burst)
    pub rate_limit_burst: u32,
    /// Maximum number of concurrent WebSocket connections. 0 = unlimited.
    pub max_websocket_connections: usize,
    /// Maximum concurrent WebSocket connections for a single DID, so one DID
    /// can't exhaust the global `max_websocket_connections` budget.
    /// 0 = unlimited (only the global cap applies).
    pub max_websocket_connections_per_did: usize,
    /// Maximum requests per second per authenticated DID. 0 = unlimited (disabled).
    pub did_rate_limit_per_second: u32,
    /// Burst size for per-DID rate limiting (additional requests allowed in a burst).
    pub did_rate_limit_burst: u32,
    /// Aggregate byte ceiling across every live WebSocket send queue.
    /// Collapses `slots x message_size x connections` into one real number.
    pub ws_send_buffer: usize,
    /// Byte ceiling for the live-delivery pub/sub ring. The ring's slot count is
    /// derived from this — see [`LimitsConfig::pubsub_capacity`].
    pub pubsub_buffer: usize,
    /// Concurrent anonymous inter-mediator relay WebSockets one client address
    /// may hold, so one source cannot take every relay slot. Must be > 0.
    #[serde(default = "defaults::relay_connections_per_ip")]
    pub relay_connections_per_ip: usize,
    /// Sustained frames per second read from one relay WebSocket. Must be > 0.
    #[serde(default = "defaults::relay_frames_per_second")]
    pub relay_frames_per_second: u32,
    /// Frames a relay WebSocket may send back-to-back above the sustained
    /// rate. Must be > 0.
    #[serde(default = "defaults::relay_frame_burst")]
    pub relay_frame_burst: u32,
    /// Sustained bytes per second read from one relay WebSocket. The bucket is
    /// at least `ws_size` deep, so a frame of any admitted size can pass.
    /// Must be > 0.
    #[serde(default = "defaults::relay_bytes_per_second")]
    pub relay_bytes_per_second: u32,
    /// Sustained messages per second read from one authenticated WebSocket.
    /// Every inbound text or binary frame after the upgrade is one message;
    /// control frames are not counted. A socket over its rate is read more
    /// slowly (the mediator stops reading until the next message is due).
    /// Only an explicit 0 turns it off. When the configuration leaves it unset
    /// it inherits [`rate_limit_per_ip`](Self::rate_limit_per_ip), so
    /// WebSocket messages are held to the same rate as HTTP requests — unless
    /// that is 0 (per-IP limiting off, as is usual behind a load balancer),
    /// when the built-in 100 applies instead: switching per-IP limiting off
    /// never switches this off with it. An unreadable value refuses to start.
    #[serde(default = "defaults::ws_messages_per_second")]
    pub ws_messages_per_second: u32,
    /// Messages an authenticated WebSocket may send back-to-back above
    /// [`ws_messages_per_second`](Self::ws_messages_per_second). 0 is read as 1.
    /// When the configuration leaves it unset it inherits
    /// [`rate_limit_burst`](Self::rate_limit_burst) if that is above 0, and is
    /// otherwise the built-in 50. An unreadable value refuses to start.
    #[serde(default = "defaults::ws_message_burst")]
    pub ws_message_burst: u32,
    /// Seconds an authenticated WebSocket may stay continuously over its
    /// message rate (including the per-DID rate, when enabled) before the
    /// mediator closes it with 1008. 0 = never close; the socket is only
    /// slowed. An unreadable value refuses to start.
    #[serde(default = "defaults::ws_message_throttle_close_secs")]
    pub ws_message_throttle_close_secs: u64,
    /// Requests per second `/metrics` answers, across all callers. Must be > 0.
    #[serde(default = "defaults::metrics_requests_per_second")]
    pub metrics_requests_per_second: u32,
    /// Seconds between the pings the mediator sends on each WebSocket.
    /// At least 1.
    #[serde(default = "default_ws_ping_interval_secs")]
    pub ws_ping_interval_secs: u64,
    /// How long a WebSocket peer may stay silent. Once a ping goes
    /// unanswered, the peer has `ws_pong_timeout_secs - ws_ping_interval_secs`
    /// to send any complete frame (a pong, a ping, a message) or the mediator
    /// closes the socket with 1001; time the mediator spends not reading does
    /// not count. At least twice
    /// [`ws_ping_interval_secs`](Self::ws_ping_interval_secs), so a peer that
    /// answers every ping is never closed. Must also cover the slowest single
    /// inbound frame upload, since a frame only counts once complete.
    #[serde(default = "default_ws_pong_timeout_secs")]
    pub ws_pong_timeout_secs: u64,
    /// Seconds one write to a WebSocket may take. A peer that stops reading
    /// leaves a write waiting once its TCP window closes; past this the
    /// mediator closes the connection with 1001. At least 1.
    #[serde(default = "default_ws_write_timeout_secs")]
    pub ws_write_timeout_secs: u64,
    /// `[limits.mux]` — DID multiplexing. Off unless an operator enables it.
    #[serde(default)]
    pub mux: MuxConfig,
}

/// Defaults for the endpoint and relay limits, shared by [`LimitsConfig`]'s
/// `Default`, its serde defaults and the raw-config parse.
mod defaults {
    pub(super) fn relay_connections_per_ip() -> usize {
        10
    }
    pub(super) fn relay_frames_per_second() -> u32 {
        50
    }
    pub(super) fn relay_frame_burst() -> u32 {
        100
    }
    pub(super) fn relay_bytes_per_second() -> u32 {
        4_194_304
    }
    pub(super) fn metrics_requests_per_second() -> u32 {
        5
    }
    /// The per-IP request rate's default (`rate_limit_per_ip`).
    pub(super) fn ws_messages_per_second() -> u32 {
        100
    }
    /// The per-IP burst's default (`rate_limit_burst`).
    pub(super) fn ws_message_burst() -> u32 {
        50
    }
    pub(super) fn ws_message_throttle_close_secs() -> u64 {
        10
    }
}

/// DID multiplexing: one authenticated connection carrying live delivery and
/// pickup for many DIDs. See `design-docs/mediator-did-multiplexing-design.md`.
///
/// **Off by default, and never turned on by an upgrade.** Everything about mux
/// is opt-in (design §5.8): an absent table or an absent or empty `enabled`
/// means off, and only `true` turns it on. Any other `enabled` is refused
/// rather than read as either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuxConfig {
    pub enabled: bool,
    /// Member DIDs one connection may carry at once.
    pub max_dids_per_connection: usize,
    /// Stored grants one principal may hold (a resource bound; see
    /// `store::mux`).
    pub max_grants_per_principal: usize,
    /// Active grants one member DID may have issued.
    pub max_grants_per_did: usize,
    /// Longest lifetime (`exp - iat`) a grant may ask for.
    pub max_grant_lifetime_secs: u64,
    /// Longest a session attach proof may be valid for.
    pub max_attach_lifetime_secs: u64,
    /// How often an attached member's signing key is re-checked against its
    /// current DID document while connected.
    pub revalidate_interval_secs: u64,
    /// Ceiling on a mux connection's send-queue depth, across all its DIDs.
    /// Each DID on the connection may hold up to 8 of these (fair queuing,
    /// design §7.2), so a connection queues at most
    /// `min(8 × DIDs, max_channel_slots)` frames. Clamped to `[8, 65536]`.
    pub max_channel_slots: usize,
    /// How long a dead grant stays listable after its expiry.
    pub dead_retention_secs: u64,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self::try_from(MuxConfigRaw::default()).expect("the built-in mux defaults are valid")
    }
}

impl MuxConfig {
    /// The subset of these limits the grant rules in `store::mux` enforce.
    #[must_use]
    pub fn store_limits(&self) -> MuxLimits {
        MuxLimits {
            max_grants_per_did: self.max_grants_per_did,
            max_grants_per_principal: self.max_grants_per_principal,
            max_grant_lifetime_secs: self.max_grant_lifetime_secs,
            dead_retention_secs: self.dead_retention_secs,
        }
    }
}

/// Largest `limits.mux.max_channel_slots` honoured. Frames are bounded in
/// bytes by `ws_send_buffer` anyway; this keeps one connection's depth sane.
pub const MUX_MAX_CHANNEL_SLOTS_CEILING: usize = 65_536;

/// `limits.mux.max_channel_slots` must be in `[8, 65536]`: below one member's
/// share (8) a member could not use its own slots, and the channel must have a
/// finite capacity.
fn channel_slots(value: &str) -> Result<usize, MediatorError> {
    let key = "limits.mux.max_channel_slots";
    let floor = crate::mux::fair_queue::MEMBER_SLOTS;
    let slots: usize = values::number(key, value).map_err(config_error)?;
    if !(floor..=MUX_MAX_CHANNEL_SLOTS_CEILING).contains(&slots) {
        return Err(config_error(
            affinidi_messaging_mediator_config::ConfigError::invalid(
                key,
                value.trim(),
                format!("a whole number from {floor} to {MUX_MAX_CHANNEL_SLOTS_CEILING}"),
            ),
        ));
    }
    Ok(slots)
}

/// A whole-number setting `limits.<field>`, read strictly.
fn limit<T: std::str::FromStr>(field: &str, value: &str) -> Result<T, MediatorError> {
    values::number(&format!("limits.{field}"), value).map_err(config_error)
}

impl std::convert::TryFrom<MuxConfigRaw> for MuxConfig {
    type Error = MediatorError;

    fn try_from(raw: MuxConfigRaw) -> Result<Self, Self::Error> {
        let num = |field: &str, value: &str| -> Result<u64, MediatorError> {
            limit(&format!("mux.{field}"), value)
        };
        let count = |field: &str, value: &str| -> Result<usize, MediatorError> {
            limit(&format!("mux.{field}"), value)
        };
        Ok(Self {
            enabled: values::boolean_or("limits.mux.enabled", &raw.enabled, false)
                .map_err(config_error)?,
            max_dids_per_connection: count(
                "max_dids_per_connection",
                &raw.max_dids_per_connection,
            )?,
            max_grants_per_principal: count(
                "max_grants_per_principal",
                &raw.max_grants_per_principal,
            )?,
            max_grants_per_did: count("max_grants_per_did", &raw.max_grants_per_did)?,
            max_grant_lifetime_secs: num("max_grant_lifetime_secs", &raw.max_grant_lifetime_secs)?,
            max_attach_lifetime_secs: num(
                "max_attach_lifetime_secs",
                &raw.max_attach_lifetime_secs,
            )?,
            revalidate_interval_secs: num(
                "revalidate_interval_secs",
                &raw.revalidate_interval_secs,
            )?,
            max_channel_slots: channel_slots(&raw.max_channel_slots)?,
            dead_retention_secs: num("dead_retention_secs", &raw.dead_retention_secs)?,
        })
    }
}

impl LimitsConfig {
    /// Stream `MAXLEN` for the per-DID inbox and outbox streams.
    ///
    /// One value bounds **both** streams — the `store_message` Lua applies the
    /// single `queue_maxlen` argument to `RECEIVE_Q` and `SEND_Q` alike — so it
    /// has to sit above the larger of the two hard limits, not one of them.
    ///
    /// It previously *was* one of them: the receive hard limit was passed
    /// directly, so the send stream was trimmed at the receive bound. That was
    /// latent while the send soft limit (200) sat far below it, and became
    /// reachable when 0.28.0 raised the send limits past it. A trim removes the
    /// stream entry and nothing decrements `SEND_QUEUE_COUNT` or `PEER_Q` —
    /// only `delete_message` does — so past the trim a sender is refused by
    /// counters for messages it can no longer list or purge, and recovers only
    /// when the message TTL expires.
    ///
    /// Hence `+ 1`, not `max(..)`: strictly above every limit an account can be
    /// *clamped* to, so trimming cannot fire for an account that is being held
    /// to a limit. Trimming is a backstop against state the gates should have
    /// prevented, never a bound on traffic they allow.
    ///
    /// **Residual, stated rather than hidden:** an admin may set an account's
    /// limit to `-1` (unlimited), which `account_update` stores *without*
    /// clamping to the hard limit. No finite bound can sit above that, so for
    /// such an account the stream is still bounded while its counters are not.
    /// Those accounts have deliberately opted out of limits; the divergence is
    /// a property of that choice, not of this value. A standard account cannot
    /// reach it: `gate_self_managed_limit` refuses `-1` even from an account
    /// that self-manages the limit. (`-2` is not a third limit value but a
    /// request to drop the account's override and fall back to the mediator
    /// default, so it never diverges from the hard limit.)
    ///
    /// A global hard limit of `-1` disables trimming outright (`0` = no
    /// `MAXLEN`), which also avoids handing Redis the result of casting `-1`
    /// to `usize`.
    #[must_use]
    pub fn queue_stream_maxlen(&self) -> usize {
        if self.queued_send_messages_hard < 0 || self.queued_receive_messages_hard < 0 {
            return 0;
        }
        let larger = self
            .queued_send_messages_hard
            .max(self.queued_receive_messages_hard);
        larger as usize + 1
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            attachments_max_count: 20,
            crypto_operations_per_message: 1000,
            deleted_messages: 100,
            forward_task_queue: 50_000,
            http_size: 10_485_760,
            listed_messages: 100,
            local_max_acl: 1_000,
            message_expiry_seconds: 604_800,
            delivered_expiry_seconds: 0,
            pickup_round_robin: true,
            message_size: 1_048_576,
            queued_send_messages_per_peer: 50,
            queued_send_messages_soft: 2_000,
            queued_send_messages_hard: 10_000,
            queued_receive_messages_soft: 200,
            queued_receive_messages_hard: 1_000,
            to_keys_per_recipient: 100,
            to_recipients: 100,
            ws_size: 10_485_760,
            access_list_limit: 1_000,
            oob_invite_ttl: 86_400,
            rate_limit_per_ip: 100,
            rate_limit_burst: 50,
            max_websocket_connections: 10000,
            max_websocket_connections_per_did: 100,
            did_rate_limit_per_second: 0,
            did_rate_limit_burst: 10,
            ws_send_buffer: 33_554_432,
            pubsub_buffer: 16_777_216,
            relay_connections_per_ip: defaults::relay_connections_per_ip(),
            relay_frames_per_second: defaults::relay_frames_per_second(),
            relay_frame_burst: defaults::relay_frame_burst(),
            relay_bytes_per_second: defaults::relay_bytes_per_second(),
            metrics_requests_per_second: defaults::metrics_requests_per_second(),
            ws_messages_per_second: defaults::ws_messages_per_second(),
            ws_message_burst: defaults::ws_message_burst(),
            ws_message_throttle_close_secs: defaults::ws_message_throttle_close_secs(),
            ws_ping_interval_secs: DEFAULT_WS_PING_INTERVAL_SECS,
            ws_pong_timeout_secs: DEFAULT_WS_PONG_TIMEOUT_SECS,
            ws_write_timeout_secs: DEFAULT_WS_WRITE_TIMEOUT_SECS,
            mux: MuxConfig::default(),
        }
    }
}

impl LimitsConfig {
    /// Slot count for the live-delivery pub/sub ring, derived from the byte
    /// budget: `pubsub_buffer / message_size`.
    ///
    /// A `tokio::sync::broadcast` ring holds all of its `capacity` slots for the
    /// life of the channel — a slot is freed only when it is overwritten
    /// `capacity` sends later, not when a subscriber reads it. So the ring costs
    /// `capacity x message_size` bytes as a *standing reservation*, and picking a
    /// capacity by feel (it was 1024) silently reserves that much memory. Deriving
    /// it from a byte budget makes the ceiling explicit and honest.
    ///
    /// Floored at 8 so a small `pubsub_buffer` cannot collapse the ring to a
    /// single slot, which would make even a momentary hiccup lag the subscriber.
    /// Lag is not message loss (the message is durable in the recipient's inbox
    /// and arrives on the next poll), but it does cost a live push.
    pub fn pubsub_capacity(&self) -> usize {
        let per_slot = self.message_size.max(1);
        (self.pubsub_buffer / per_slot).max(8)
    }
}

/// Parse a limit that has no "unlimited" setting: an unreadable value or `0` is
/// refused, because these bound traffic that nothing else bounds.
fn positive<T>(field: &str, value: &str) -> Result<T, MediatorError>
where
    T: std::str::FromStr + Default + PartialEq + std::fmt::Display + Copy,
{
    let parsed: T = limit(field, value)?;
    if parsed == T::default() {
        return Err(config_error_msg(format!(
            "limits.{field} must be greater than 0"
        )));
    }
    Ok(parsed)
}

/// The WebSocket message rate: `(ws_messages_per_second, ws_message_burst,
/// ws_message_throttle_close_secs)`.
///
/// This limit is never switched off implicitly. An unset rate or burst
/// inherits the per-IP HTTP value (`rate_limit_per_ip` / `rate_limit_burst`)
/// only when that is above 0, and otherwise takes the built-in default; only
/// an explicit `0` turns the rate off. A value that cannot be read refuses to
/// start rather than being guessed at, since a guess could turn the limit off
/// or make it far looser than intended.
fn ws_message_limits(raw: &LimitsConfigRaw) -> Result<(u32, u32, u64), MediatorError> {
    fn explicit<T: std::str::FromStr>(
        field: &str,
        value: &str,
    ) -> Result<Option<T>, MediatorError> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        limit(field, value).map(Some)
    }
    let inherited = |value: &str, default: u32| -> u32 {
        match value.trim().parse::<u32>() {
            Ok(n) if n > 0 => n,
            _ => default,
        }
    };
    let rate = match explicit("ws_messages_per_second", &raw.ws_messages_per_second)? {
        Some(rate) => rate,
        None => inherited(&raw.rate_limit_per_ip, defaults::ws_messages_per_second()),
    };
    let burst = match explicit("ws_message_burst", &raw.ws_message_burst)? {
        Some(burst) => burst,
        None => inherited(&raw.rate_limit_burst, defaults::ws_message_burst()),
    };
    let close_secs = explicit(
        "ws_message_throttle_close_secs",
        &raw.ws_message_throttle_close_secs,
    )?
    .unwrap_or_else(defaults::ws_message_throttle_close_secs);
    Ok((rate, burst, close_secs))
}

const DEFAULT_WS_PING_INTERVAL_SECS: u64 = 30;
const DEFAULT_WS_PONG_TIMEOUT_SECS: u64 = 90;
const DEFAULT_WS_WRITE_TIMEOUT_SECS: u64 = 30;

fn default_ws_ping_interval_secs() -> u64 {
    DEFAULT_WS_PING_INTERVAL_SECS
}
fn default_ws_pong_timeout_secs() -> u64 {
    DEFAULT_WS_PONG_TIMEOUT_SECS
}
fn default_ws_write_timeout_secs() -> u64 {
    DEFAULT_WS_WRITE_TIMEOUT_SECS
}

/// The WebSocket liveness settings, held to values that work together:
/// every interval at least 1 s, and the silence allowed at least two ping
/// intervals, so a peer that answers each ping is never closed for silence.
/// Returns `(ping_interval, pong_timeout, write_timeout)` in seconds, and a
/// note for each value that had to be raised.
pub(crate) fn websocket_liveness(
    ping: u64,
    pong: u64,
    write: u64,
) -> ((u64, u64, u64), Vec<String>) {
    let mut notes = Vec::new();
    let ping_interval = if ping == 0 {
        notes.push("limits.ws_ping_interval_secs must be at least 1; using 1".to_string());
        1
    } else {
        ping
    };
    let least_pong = ping_interval.saturating_mul(2);
    let pong_timeout = if pong < least_pong {
        notes.push(format!(
            "limits.ws_pong_timeout_secs ({pong}) must be at least twice \
             limits.ws_ping_interval_secs ({ping_interval}); using {least_pong}"
        ));
        least_pong
    } else {
        pong
    };
    let write_timeout = if write == 0 {
        notes.push("limits.ws_write_timeout_secs must be at least 1; using 1".to_string());
        1
    } else {
        write
    };
    ((ping_interval, pong_timeout, write_timeout), notes)
}

/// Refuse a queue limit below `-1`. `-1` means unlimited and `0` and more is a
/// limit; any other negative value has no meaning, and the gates would
/// otherwise have to guess one for it.
fn check_queue_limits(limits: &LimitsConfig) -> Result<(), MediatorError> {
    for (field, value) in [
        (
            "queued_send_messages_per_peer",
            limits.queued_send_messages_per_peer,
        ),
        (
            "queued_send_messages_soft",
            limits.queued_send_messages_soft,
        ),
        (
            "queued_send_messages_hard",
            limits.queued_send_messages_hard,
        ),
        (
            "queued_receive_messages_soft",
            limits.queued_receive_messages_soft,
        ),
        (
            "queued_receive_messages_hard",
            limits.queued_receive_messages_hard,
        ),
    ] {
        if value < -1 {
            return Err(MediatorError::ConfigError(
                crate::common::error_codes::CONFIG_ERROR,
                "NA".into(),
                format!("limits.{field} must be -1 (unlimited) or 0 and more; got {value}"),
            ));
        }
    }
    Ok(())
}

impl std::convert::TryFrom<LimitsConfigRaw> for LimitsConfig {
    type Error = MediatorError;

    /// Every value is read strictly (an unreadable one is an error naming
    /// `limits.<field>`, never a default), and the result must satisfy
    /// [`LimitsConfig::check_invariants`].
    fn try_from(raw: LimitsConfigRaw) -> Result<Self, Self::Error> {
        let queue = |field: &str, value: &str| -> Result<i32, MediatorError> {
            values::queue_limit(&format!("limits.{field}"), value).map_err(config_error)
        };

        // The WebSocket message rate: see `ws_message_limits`.
        let (ws_messages_per_second, ws_message_burst, ws_message_throttle_close_secs) =
            ws_message_limits(&raw)?;

        // WebSocket liveness: every interval at least 1 s, and the silence
        // allowed at least two ping intervals (see `websocket_liveness`). A
        // value outside that is refused here; a `LimitsConfig` built in code
        // is raised to it instead.
        let ws_ping_interval_secs: u64 = values::number_at_least(
            "limits.ws_ping_interval_secs",
            &raw.ws_ping_interval_secs,
            1,
        )
        .map_err(config_error)?;
        let ws_pong_timeout_secs: u64 = limit("ws_pong_timeout_secs", &raw.ws_pong_timeout_secs)?;
        if ws_pong_timeout_secs < ws_ping_interval_secs.saturating_mul(2) {
            return Err(config_error_msg(format!(
                "limits.ws_pong_timeout_secs ({ws_pong_timeout_secs}) must be at least twice \
                 limits.ws_ping_interval_secs ({ws_ping_interval_secs})"
            )));
        }
        let ws_write_timeout_secs: u64 = values::number_at_least(
            "limits.ws_write_timeout_secs",
            &raw.ws_write_timeout_secs,
            1,
        )
        .map_err(config_error)?;

        let limits = LimitsConfig {
            attachments_max_count: limit("attachments_max_count", &raw.attachments_max_count)?,
            crypto_operations_per_message: limit(
                "crypto_operations_per_message",
                &raw.crypto_operations_per_message,
            )?,
            deleted_messages: limit("deleted_messages", &raw.deleted_messages)?,
            forward_task_queue: limit("forward_task_queue", &raw.forward_task_queue)?,
            http_size: limit("http_size", &raw.http_size)?,
            listed_messages: limit("listed_messages", &raw.listed_messages)?,
            local_max_acl: limit("local_max_acl", &raw.local_max_acl)?,
            pickup_round_robin: values::boolean(
                "limits.pickup_round_robin",
                &raw.pickup_round_robin,
            )
            .map_err(config_error)?,
            delivered_expiry_seconds: limit(
                "delivered_expiry_seconds",
                &raw.delivered_expiry_seconds,
            )?,
            message_expiry_seconds: limit("message_expiry_seconds", &raw.message_expiry_seconds)?,
            message_size: limit("message_size", &raw.message_size)?,
            queued_send_messages_per_peer: queue(
                "queued_send_messages_per_peer",
                &raw.queued_send_messages_per_peer,
            )?,
            queued_send_messages_soft: queue(
                "queued_send_messages_soft",
                &raw.queued_send_messages_soft,
            )?,
            queued_send_messages_hard: queue(
                "queued_send_messages_hard",
                &raw.queued_send_messages_hard,
            )?,
            queued_receive_messages_soft: queue(
                "queued_receive_messages_soft",
                &raw.queued_receive_messages_soft,
            )?,
            queued_receive_messages_hard: queue(
                "queued_receive_messages_hard",
                &raw.queued_receive_messages_hard,
            )?,
            to_keys_per_recipient: limit("to_keys_per_recipient", &raw.to_keys_per_recipient)?,
            to_recipients: limit("to_recipients", &raw.to_recipients)?,
            ws_size: limit("ws_size", &raw.ws_size)?,
            access_list_limit: limit("access_list_limit", &raw.access_list_limit)?,
            oob_invite_ttl: limit("oob_invite_ttl", &raw.oob_invite_ttl)?,
            rate_limit_per_ip: limit("rate_limit_per_ip", &raw.rate_limit_per_ip)?,
            rate_limit_burst: limit("rate_limit_burst", &raw.rate_limit_burst)?,
            max_websocket_connections: limit(
                "max_websocket_connections",
                &raw.max_websocket_connections,
            )?,
            max_websocket_connections_per_did: limit(
                "max_websocket_connections_per_did",
                &raw.max_websocket_connections_per_did,
            )?,
            did_rate_limit_per_second: limit(
                "did_rate_limit_per_second",
                &raw.did_rate_limit_per_second,
            )?,
            did_rate_limit_burst: limit("did_rate_limit_burst", &raw.did_rate_limit_burst)?,
            ws_send_buffer: limit("ws_send_buffer", &raw.ws_send_buffer)?,
            pubsub_buffer: limit("pubsub_buffer", &raw.pubsub_buffer)?,
            relay_connections_per_ip: positive(
                "relay_connections_per_ip",
                &raw.relay_connections_per_ip,
            )?,
            relay_frames_per_second: positive(
                "relay_frames_per_second",
                &raw.relay_frames_per_second,
            )?,
            relay_frame_burst: positive("relay_frame_burst", &raw.relay_frame_burst)?,
            relay_bytes_per_second: positive(
                "relay_bytes_per_second",
                &raw.relay_bytes_per_second,
            )?,
            metrics_requests_per_second: positive(
                "metrics_requests_per_second",
                &raw.metrics_requests_per_second,
            )?,
            ws_messages_per_second,
            ws_message_burst,
            ws_message_throttle_close_secs,
            ws_ping_interval_secs,
            ws_pong_timeout_secs,
            ws_write_timeout_secs,
            mux: MuxConfig::try_from(raw.mux)?,
        };
        limits.check_invariants().map_err(config_error_msg)?;
        Ok(limits)
    }
}

impl LimitsConfig {
    /// The rules a configured set of limits must keep, which the shipped
    /// template documents: the same soft ≤ hard coherence `config/patch` holds
    /// a patch to, a message that fits the HTTP and WebSocket bodies that carry
    /// it, and no `0` where `0` would make the mediator refuse everything
    /// rather than mean "unlimited". The error names the setting.
    pub fn check_invariants(&self) -> Result<(), String> {
        super::overrides::check_coherent(self)?;
        for (field, value) in [
            ("message_size", self.message_size),
            ("http_size", self.http_size),
            ("ws_size", self.ws_size),
            ("listed_messages", self.listed_messages),
            ("deleted_messages", self.deleted_messages),
            ("to_recipients", self.to_recipients),
            ("to_keys_per_recipient", self.to_keys_per_recipient),
            (
                "crypto_operations_per_message",
                self.crypto_operations_per_message,
            ),
            ("forward_task_queue", self.forward_task_queue),
            ("oob_invite_ttl", self.oob_invite_ttl),
            ("ws_send_buffer", self.ws_send_buffer),
            ("pubsub_buffer", self.pubsub_buffer),
        ] {
            if value == 0 {
                return Err(format!("limits.{field} must be greater than 0"));
            }
        }
        if self.message_expiry_seconds == 0 {
            return Err("limits.message_expiry_seconds must be greater than 0".into());
        }
        for (field, carrier) in [("http_size", self.http_size), ("ws_size", self.ws_size)] {
            if carrier < self.message_size {
                return Err(format!(
                    "limits.{field} ({carrier}) must be at least limits.message_size ({}): a \
                     message that size could never be sent",
                    self.message_size
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_is_off_unless_explicitly_enabled() {
        assert!(!LimitsConfig::default().mux.enabled);
        let mut raw = MuxConfigRaw::default();
        assert!(!MuxConfig::try_from(raw.clone()).unwrap().enabled);
        for v in ["", "  ", "false", "FALSE"] {
            raw.enabled = v.into();
            assert!(
                !MuxConfig::try_from(raw.clone()).unwrap().enabled,
                "{v:?} must not enable mux"
            );
        }
        // Anything that is not true or false is refused, not read as either.
        for v in ["yes", "1", "on", "ture"] {
            raw.enabled = v.into();
            let err = MuxConfig::try_from(raw.clone()).unwrap_err().to_string();
            assert!(err.contains("limits.mux.enabled"), "{v:?}: {err}");
        }
        for v in ["true", " TRUE "] {
            raw.enabled = v.into();
            assert!(MuxConfig::try_from(raw.clone()).unwrap().enabled, "{v:?}");
        }
    }

    #[test]
    fn an_absent_mux_table_parses_as_off() {
        let raw: MuxConfigRaw = toml::from_str("").unwrap();
        let mux = MuxConfig::try_from(raw).unwrap();
        assert_eq!(mux, MuxConfig::default());
        assert!(!mux.enabled);
        assert_eq!(mux.store_limits(), MuxLimits::default());
    }

    #[test]
    fn mux_channel_slots_are_bounded() {
        let mut raw = MuxConfigRaw::default();
        assert_eq!(
            MuxConfig::try_from(raw.clone()).unwrap().max_channel_slots,
            512
        );
        for (given, used) in [
            ("8", 8),
            ("1000", 1000),
            ("65536", MUX_MAX_CHANNEL_SLOTS_CEILING),
        ] {
            raw.max_channel_slots = given.into();
            assert_eq!(
                MuxConfig::try_from(raw.clone()).unwrap().max_channel_slots,
                used,
                "{given}"
            );
        }
        // Out of range or unreadable: refused, naming the key.
        for given in ["0", "3", "65537", "10000000", "nonsense"] {
            raw.max_channel_slots = given.into();
            let err = MuxConfig::try_from(raw.clone()).unwrap_err().to_string();
            assert!(
                err.contains("limits.mux.max_channel_slots"),
                "{given}: {err}"
            );
        }
    }

    /// Every mux number is read strictly, naming its key.
    #[test]
    fn an_unreadable_mux_number_is_refused() {
        let raw = MuxConfigRaw {
            revalidate_interval_secs: "15m".into(),
            ..MuxConfigRaw::default()
        };
        let err = MuxConfig::try_from(raw).unwrap_err().to_string();
        assert!(err.contains("limits.mux.revalidate_interval_secs"), "{err}");
    }

    #[test]
    fn test_limits_default() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.attachments_max_count, 20);
        assert_eq!(limits.crypto_operations_per_message, 1000);
        assert_eq!(limits.deleted_messages, 100);
        assert_eq!(limits.forward_task_queue, 50_000);
        assert_eq!(limits.http_size, 10_485_760);
        assert_eq!(limits.listed_messages, 100);
        assert_eq!(limits.local_max_acl, 1_000);
        assert_eq!(limits.message_expiry_seconds, 604_800);
        assert_eq!(limits.message_size, 1_048_576);
        assert_eq!(limits.queued_send_messages_per_peer, 50);
        // Strictly above BOTH hard limits — one value bounds both streams.
        assert!(limits.queue_stream_maxlen() > limits.queued_send_messages_hard as usize);
        assert!(limits.queue_stream_maxlen() > limits.queued_receive_messages_hard as usize);
        // The send total is a coarse ceiling, not the flooding gate — see
        // `validate_peer_queue_limit`. It sits well above realistic fan-out so
        // that a sender is not silenced because its recipients went offline.
        assert_eq!(limits.queued_send_messages_soft, 2_000);
        // `hard` is the maximum an account may set for itself, so it must stay
        // at or above `soft`, which is the default every account starts on.
        assert_eq!(limits.queued_send_messages_hard, 10_000);
        assert!(limits.queued_send_messages_hard >= limits.queued_send_messages_soft);
        assert_eq!(limits.queued_receive_messages_soft, 200);
        assert_eq!(limits.queued_receive_messages_hard, 1_000);
        assert_eq!(limits.to_keys_per_recipient, 100);
        assert_eq!(limits.to_recipients, 100);
        assert_eq!(limits.ws_size, 10_485_760);
        assert_eq!(limits.access_list_limit, 1_000);
        assert_eq!(limits.oob_invite_ttl, 86_400);
        assert_eq!(limits.rate_limit_per_ip, 100);
        assert_eq!(limits.rate_limit_burst, 50);
        assert_eq!(limits.max_websocket_connections, 10000);
        assert_eq!(limits.did_rate_limit_per_second, 0);
        assert_eq!(limits.did_rate_limit_burst, 10);
        assert_eq!(limits.relay_connections_per_ip, 10);
        assert_eq!(limits.relay_frames_per_second, 50);
        assert_eq!(limits.relay_frame_burst, 100);
        assert_eq!(limits.relay_bytes_per_second, 4_194_304);
        assert_eq!(limits.metrics_requests_per_second, 5);
        assert_eq!(limits.ws_messages_per_second, 100);
        assert_eq!(limits.ws_message_burst, 50);
        assert_eq!(limits.ws_message_throttle_close_secs, 10);
    }

    #[test]
    fn test_limits_try_from_valid() {
        let raw = LimitsConfigRaw {
            attachments_max_count: "5".to_string(),
            crypto_operations_per_message: "500".to_string(),
            deleted_messages: "75".to_string(),
            forward_task_queue: "2000".to_string(),
            http_size: "8192".to_string(),
            listed_messages: "50".to_string(),
            local_max_acl: "500".to_string(),
            delivered_expiry_seconds: "0".to_string(),
            pickup_round_robin: "true".to_string(),
            message_expiry_seconds: "3600".to_string(),
            message_size: "2048".to_string(),
            queued_send_messages_per_peer: "50".to_string(),
            queued_send_messages_soft: "150".to_string(),
            queued_send_messages_hard: "800".to_string(),
            queued_receive_messages_soft: "150".to_string(),
            queued_receive_messages_hard: "800".to_string(),
            to_keys_per_recipient: "50".to_string(),
            to_recipients: "50".to_string(),
            ws_size: "8192".to_string(),
            access_list_limit: "500".to_string(),
            oob_invite_ttl: "7200".to_string(),
            rate_limit_per_ip: "200".to_string(),
            rate_limit_burst: "100".to_string(),
            max_websocket_connections: "5000".to_string(),
            max_websocket_connections_per_did: "250".to_string(),
            did_rate_limit_per_second: "50".to_string(),
            did_rate_limit_burst: "20".to_string(),
            ws_send_buffer: "8388608".to_string(),
            pubsub_buffer: "4194304".to_string(),
            relay_connections_per_ip: "4".to_string(),
            relay_frames_per_second: "7".to_string(),
            relay_frame_burst: "9".to_string(),
            relay_bytes_per_second: "65536".to_string(),
            metrics_requests_per_second: "2".to_string(),
            ws_messages_per_second: "25".to_string(),
            ws_message_burst: "40".to_string(),
            ws_message_throttle_close_secs: "0".to_string(),
            ws_ping_interval_secs: "20".to_string(),
            ws_pong_timeout_secs: "50".to_string(),
            ws_write_timeout_secs: "15".to_string(),
            mux: MuxConfigRaw::default(),
        };
        // No "unlimited" setting for the relay and metrics bounds: 0 is refused.
        for field in [
            "relay_connections_per_ip",
            "relay_frames_per_second",
            "relay_frame_burst",
            "relay_bytes_per_second",
            "metrics_requests_per_second",
        ] {
            let mut zeroed = raw.clone();
            let slot = match field {
                "relay_connections_per_ip" => &mut zeroed.relay_connections_per_ip,
                "relay_frames_per_second" => &mut zeroed.relay_frames_per_second,
                "relay_frame_burst" => &mut zeroed.relay_frame_burst,
                "relay_bytes_per_second" => &mut zeroed.relay_bytes_per_second,
                _ => &mut zeroed.metrics_requests_per_second,
            };
            *slot = "0".to_string();
            let err = LimitsConfig::try_from(zeroed).expect_err(field);
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
        // Unset, the WebSocket message rate inherits the per-IP HTTP rate
        // and burst (200 / 100 here); "0" turns it off without touching them.
        let mut inherited = raw.clone();
        inherited.ws_messages_per_second = String::new();
        inherited.ws_message_burst = " ".to_string();
        let inherited = LimitsConfig::try_from(inherited).unwrap();
        assert_eq!(inherited.ws_messages_per_second, 200);
        assert_eq!(inherited.ws_message_burst, 100);
        let mut off = raw.clone();
        off.ws_messages_per_second = "0".to_string();
        let off = LimitsConfig::try_from(off).unwrap();
        assert_eq!(off.ws_messages_per_second, 0);
        assert_eq!(off.rate_limit_per_ip, 200);
        let limits = LimitsConfig::try_from(raw).unwrap();
        assert_eq!(limits.relay_connections_per_ip, 4);
        assert_eq!(limits.relay_frames_per_second, 7);
        assert_eq!(limits.relay_frame_burst, 9);
        assert_eq!(limits.relay_bytes_per_second, 65_536);
        assert_eq!(limits.metrics_requests_per_second, 2);
        assert_eq!(limits.ws_messages_per_second, 25);
        assert_eq!(limits.ws_message_burst, 40);
        assert_eq!(limits.ws_message_throttle_close_secs, 0);
        assert_eq!(limits.ws_send_buffer, 8_388_608);
        assert_eq!(limits.pubsub_buffer, 4_194_304);
        assert_eq!(limits.ws_ping_interval_secs, 20);
        assert_eq!(limits.ws_pong_timeout_secs, 50);
        assert_eq!(limits.ws_write_timeout_secs, 15);
        assert_eq!(limits.attachments_max_count, 5);
        assert_eq!(limits.crypto_operations_per_message, 500);
        assert_eq!(limits.deleted_messages, 75);
        assert_eq!(limits.forward_task_queue, 2000);
        assert_eq!(limits.http_size, 8192);
        assert_eq!(limits.listed_messages, 50);
        assert_eq!(limits.local_max_acl, 500);
        assert_eq!(limits.message_expiry_seconds, 3600);
        assert_eq!(limits.message_size, 2048);
        assert_eq!(limits.queued_send_messages_soft, 150);
        assert_eq!(limits.queued_send_messages_hard, 800);
        assert_eq!(limits.queued_receive_messages_soft, 150);
        assert_eq!(limits.queued_receive_messages_hard, 800);
        assert_eq!(limits.to_keys_per_recipient, 50);
        assert_eq!(limits.to_recipients, 50);
        assert_eq!(limits.ws_size, 8192);
        assert_eq!(limits.access_list_limit, 500);
        assert_eq!(limits.oob_invite_ttl, 7200);
        assert_eq!(limits.rate_limit_per_ip, 200);
        assert_eq!(limits.rate_limit_burst, 100);
        assert_eq!(limits.max_websocket_connections, 5000);
        assert_eq!(limits.did_rate_limit_per_second, 50);
        assert_eq!(limits.did_rate_limit_burst, 20);
    }

    /// The raw form of the defaults, for tests that change one value.
    fn default_raw() -> LimitsConfigRaw {
        toml::from_str(
            r#"
            attachments_max_count = "20"
            crypto_operations_per_message = "1000"
            deleted_messages = "100"
            forward_task_queue = "50000"
            http_size = "10485760"
            listed_messages = "100"
            local_max_acl = "1000"
            message_expiry_seconds = "604800"
            message_size = "1048576"
            queued_send_messages_soft = "2000"
            queued_send_messages_hard = "10000"
            queued_receive_messages_soft = "200"
            queued_receive_messages_hard = "1000"
            to_keys_per_recipient = "100"
            to_recipients = "100"
            ws_size = "10485760"
            access_list_limit = "1000"
            oob_invite_ttl = "86400"
            "#,
        )
        .unwrap()
    }

    /// Set `field` of `raw` to `value`, through its TOML form.
    fn with(raw: &LimitsConfigRaw, field: &str, value: &str) -> LimitsConfigRaw {
        let mut table = toml::Table::try_from(raw).unwrap();
        assert!(table.contains_key(field), "{field} is a [limits] key");
        table.insert(field.into(), toml::Value::String(value.into()));
        table.try_into().unwrap()
    }

    /// Issue #112: an unreadable value used to fall back to the built-in
    /// default, which can be looser than what the operator wrote. Every one is
    /// now refused, naming the key and the value.
    #[test]
    fn an_unreadable_limit_is_refused_not_defaulted() {
        let base = default_raw();
        assert!(LimitsConfig::try_from(base.clone()).is_ok());
        for (field, bad) in [
            ("listed_messages", "5O"),
            ("rate_limit_per_ip", "10/s"),
            ("message_size", "1MB"),
            ("attachments_max_count", "not_a_number"),
            ("crypto_operations_per_message", ""),
            ("relay_connections_per_ip", "x"),
            ("pickup_round_robin", "yes"),
            ("delivered_expiry_seconds", "1d"),
            ("ws_ping_interval_secs", "soon"),
            ("ws_write_timeout_secs", "-1"),
            ("max_websocket_connections", "many"),
        ] {
            let err = LimitsConfig::try_from(with(&base, field, bad))
                .expect_err(field)
                .to_string();
            assert!(err.contains(&format!("limits.{field}")), "{field}: {err}");
            assert!(err.contains(&format!("{bad:?}")), "{field}: {err}");
        }
    }

    /// A queue limit takes -1 (no limit) and no other negative number.
    #[test]
    fn a_negative_queue_limit_other_than_minus_one_is_refused() {
        let base = default_raw();
        for field in [
            "queued_send_messages_per_peer",
            "queued_send_messages_soft",
            "queued_send_messages_hard",
            "queued_receive_messages_soft",
            "queued_receive_messages_hard",
        ] {
            assert!(
                LimitsConfig::try_from(with(&base, field, "-1")).is_ok(),
                "{field}"
            );
            let err = LimitsConfig::try_from(with(&base, field, "-2"))
                .expect_err(field)
                .to_string();
            assert!(err.contains(&format!("limits.{field}")), "{field}: {err}");
        }
    }

    /// The template's documented invariants are enforced on the file baseline,
    /// with the same soft <= hard rule `config/patch` holds a patch to.
    #[test]
    fn the_documented_invariants_are_enforced() {
        let base = default_raw();
        for (field, value, expect) in [
            ("queued_send_messages_soft", "20000", "would exceed"),
            ("queued_receive_messages_hard", "100", "would exceed"),
            ("message_size", "0", "limits.message_size"),
            ("http_size", "1000", "limits.http_size"),
            ("ws_size", "1000", "limits.ws_size"),
            ("listed_messages", "0", "limits.listed_messages"),
            (
                "message_expiry_seconds",
                "0",
                "limits.message_expiry_seconds",
            ),
            ("ws_pong_timeout_secs", "45", "at least twice"),
            ("ws_ping_interval_secs", "0", "limits.ws_ping_interval_secs"),
            ("ws_write_timeout_secs", "0", "limits.ws_write_timeout_secs"),
        ] {
            let err = LimitsConfig::try_from(with(&base, field, value))
                .expect_err(field)
                .to_string();
            assert!(err.contains(expect), "{field}={value}: {err}");
        }
        // Unlimited on either side is exempt from soft <= hard.
        let unlimited_hard = with(&base, "queued_send_messages_hard", "-1");
        assert!(LimitsConfig::try_from(unlimited_hard).is_ok());
        // Equal is coherent.
        let equal = with(&base, "queued_receive_messages_hard", "200");
        assert!(LimitsConfig::try_from(equal).is_ok());
    }

    /// Turning per-IP limiting off (common behind a load balancer) does not
    /// turn the WebSocket message rate off with it; only an explicit 0 does.
    #[test]
    fn the_websocket_message_rate_is_never_switched_off_implicitly() {
        let raw: LimitsConfigRaw = toml::from_str(
            r#"
            attachments_max_count = "20"
            crypto_operations_per_message = "1000"
            deleted_messages = "100"
            forward_task_queue = "50000"
            http_size = "10485760"
            listed_messages = "100"
            local_max_acl = "1000"
            message_expiry_seconds = "604800"
            message_size = "1048576"
            queued_send_messages_soft = "2000"
            queued_send_messages_hard = "10000"
            queued_receive_messages_soft = "200"
            queued_receive_messages_hard = "1000"
            to_keys_per_recipient = "100"
            to_recipients = "100"
            ws_size = "10485760"
            access_list_limit = "1000"
            oob_invite_ttl = "86400"
            rate_limit_per_ip = "0"
            rate_limit_burst = "0"
            "#,
        )
        .unwrap();

        // Per-IP off, WebSocket keys unset: the built-in defaults apply.
        let limits = LimitsConfig::try_from(raw.clone()).unwrap();
        assert_eq!(limits.rate_limit_per_ip, 0);
        assert_eq!(limits.ws_messages_per_second, 100);
        assert_eq!(limits.ws_message_burst, 50);
        assert_eq!(limits.ws_message_throttle_close_secs, 10);

        // An unreadable per-IP value is refused outright (it used to be
        // skipped, leaving the WebSocket rate on its default).
        let mut unreadable = raw.clone();
        unreadable.rate_limit_per_ip = "lots".to_string();
        assert!(LimitsConfig::try_from(unreadable).is_err());

        // Only an explicit 0 turns the WebSocket rate off.
        let mut off = raw.clone();
        off.ws_messages_per_second = "0".to_string();
        assert_eq!(
            LimitsConfig::try_from(off).unwrap().ws_messages_per_second,
            0
        );
    }

    /// An unreadable WebSocket message limit refuses to start, naming the key,
    /// rather than being guessed at.
    #[test]
    fn an_unreadable_websocket_message_limit_refuses_to_start() {
        let base = LimitsConfigRaw {
            ws_messages_per_second: String::new(),
            ws_message_burst: String::new(),
            ws_message_throttle_close_secs: "10".to_string(),
            ..toml::from_str::<LimitsConfigRaw>(
                r#"
                attachments_max_count = "20"
                crypto_operations_per_message = "1000"
                deleted_messages = "100"
                forward_task_queue = "50000"
                http_size = "10485760"
                listed_messages = "100"
                local_max_acl = "1000"
                message_expiry_seconds = "604800"
                message_size = "1048576"
                queued_send_messages_soft = "2000"
                queued_send_messages_hard = "10000"
                queued_receive_messages_soft = "200"
                queued_receive_messages_hard = "1000"
                to_keys_per_recipient = "100"
                to_recipients = "100"
                ws_size = "10485760"
                access_list_limit = "1000"
                oob_invite_ttl = "86400"
                "#,
            )
            .unwrap()
        };
        assert!(LimitsConfig::try_from(base.clone()).is_ok());
        for (field, bad) in [
            ("ws_messages_per_second", "fast"),
            ("ws_messages_per_second", "-1"),
            ("ws_message_burst", "1.5"),
            ("ws_message_throttle_close_secs", "later"),
        ] {
            let mut raw = base.clone();
            match field {
                "ws_messages_per_second" => raw.ws_messages_per_second = bad.to_string(),
                "ws_message_burst" => raw.ws_message_burst = bad.to_string(),
                _ => raw.ws_message_throttle_close_secs = bad.to_string(),
            }
            let err = LimitsConfig::try_from(raw).expect_err(field).to_string();
            assert!(err.contains(field), "{field}={bad}: {err}");
        }
    }

    /// A queue limit below -1 means nothing, so it refuses to start rather
    /// than the gates guessing (it used to cast to about four billion).
    #[test]
    fn a_queue_limit_below_minus_one_refuses_to_start() {
        let base: LimitsConfigRaw = toml::from_str(
            r#"
            attachments_max_count = "20"
            crypto_operations_per_message = "1000"
            deleted_messages = "100"
            forward_task_queue = "50000"
            http_size = "10485760"
            listed_messages = "100"
            local_max_acl = "1000"
            message_expiry_seconds = "604800"
            message_size = "1048576"
            queued_send_messages_per_peer = "50"
            queued_send_messages_soft = "2000"
            queued_send_messages_hard = "10000"
            queued_receive_messages_soft = "200"
            queued_receive_messages_hard = "1000"
            to_keys_per_recipient = "100"
            to_recipients = "100"
            ws_size = "10485760"
            access_list_limit = "1000"
            oob_invite_ttl = "86400"
            "#,
        )
        .unwrap();
        assert!(LimitsConfig::try_from(base.clone()).is_ok());
        let mut unlimited = base.clone();
        unlimited.queued_send_messages_per_peer = "-1".to_string();
        assert!(LimitsConfig::try_from(unlimited).is_ok(), "-1 is unlimited");
        for field in [
            "queued_send_messages_per_peer",
            "queued_send_messages_soft",
            "queued_send_messages_hard",
            "queued_receive_messages_soft",
            "queued_receive_messages_hard",
        ] {
            let mut raw = base.clone();
            let bad = "-2".to_string();
            match field {
                "queued_send_messages_per_peer" => raw.queued_send_messages_per_peer = bad,
                "queued_send_messages_soft" => raw.queued_send_messages_soft = bad,
                "queued_send_messages_hard" => raw.queued_send_messages_hard = bad,
                "queued_receive_messages_soft" => raw.queued_receive_messages_soft = bad,
                _ => raw.queued_receive_messages_hard = bad,
            }
            let err = LimitsConfig::try_from(raw).expect_err(field).to_string();
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn websocket_liveness_defaults() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.ws_ping_interval_secs, 30);
        assert_eq!(limits.ws_pong_timeout_secs, 90);
        assert_eq!(limits.ws_write_timeout_secs, 30);
        // A `[limits]` table written before these keys existed still loads,
        // with the defaults.
        let raw: LimitsConfigRaw = toml::from_str(
            r#"
            attachments_max_count = "20"
            crypto_operations_per_message = "1000"
            deleted_messages = "100"
            forward_task_queue = "50000"
            http_size = "10485760"
            listed_messages = "100"
            local_max_acl = "1000"
            message_expiry_seconds = "604800"
            message_size = "1048576"
            queued_send_messages_soft = "2000"
            queued_send_messages_hard = "10000"
            queued_receive_messages_soft = "200"
            queued_receive_messages_hard = "1000"
            to_keys_per_recipient = "100"
            to_recipients = "100"
            ws_size = "10485760"
            access_list_limit = "1000"
            oob_invite_ttl = "86400"
            "#,
        )
        .expect("a limits table without the WebSocket liveness keys parses");
        let limits = LimitsConfig::try_from(raw).unwrap();
        assert_eq!(limits.ws_ping_interval_secs, 30);
        assert_eq!(limits.ws_pong_timeout_secs, 90);
        assert_eq!(limits.ws_write_timeout_secs, 30);
        // So does the WebSocket message rate: on, inheriting the per-IP rate.
        assert_eq!(limits.ws_messages_per_second, 100);
        assert_eq!(limits.ws_message_burst, 50);
        assert_eq!(limits.ws_message_throttle_close_secs, 10);
    }

    #[test]
    fn websocket_liveness_values_are_held_to_ones_that_work_together() {
        // Already coherent: unchanged, nothing to report.
        let (values, notes) = websocket_liveness(30, 90, 30);
        assert_eq!(values, (30, 90, 30));
        assert!(notes.is_empty());
        // Exactly two intervals is enough.
        assert_eq!(websocket_liveness(10, 20, 5).0, (10, 20, 5));
        // Silence allowed shorter than two intervals would close a peer that
        // answers every ping: raised.
        let (values, notes) = websocket_liveness(30, 45, 30);
        assert_eq!(values, (30, 60, 30));
        assert_eq!(notes.len(), 1);
        // Zero is not "off": each is raised to its least value.
        let (values, notes) = websocket_liveness(0, 0, 0);
        assert_eq!(values, (1, 2, 1));
        assert_eq!(notes.len(), 3);
    }
}

#[cfg(test)]
mod queue_stream_maxlen_tests {
    use super::LimitsConfig;

    /// The regression 0.28.0 introduced: the send stream was trimmed at the
    /// *receive* hard limit, so raising the send limits past it made trimming
    /// reachable in ordinary use — and a trim removes the stream entry while
    /// `SEND_QUEUE_COUNT` and `PEER_Q` keep counting it.
    #[test]
    fn maxlen_sits_above_the_larger_hard_limit_not_the_receive_one() {
        let limits = LimitsConfig {
            queued_send_messages_hard: 10_000,
            queued_receive_messages_hard: 1_000,
            ..LimitsConfig::default()
        };
        // The bug was `1_000` here, which is below the send limit it also bounds.
        assert_eq!(limits.queue_stream_maxlen(), 10_001);
    }

    /// Symmetric: whichever side is larger is the one that has to fit.
    #[test]
    fn maxlen_follows_whichever_hard_limit_is_larger() {
        let limits = LimitsConfig {
            queued_send_messages_hard: 500,
            queued_receive_messages_hard: 9_000,
            ..LimitsConfig::default()
        };
        assert_eq!(limits.queue_stream_maxlen(), 9_001);
    }

    /// An unlimited hard limit disables trimming rather than casting `-1` to
    /// `usize` and handing Redis 18446744073709551615 as a `MAXLEN`.
    #[test]
    fn an_unlimited_hard_limit_disables_trimming() {
        let send_unlimited = LimitsConfig {
            queued_send_messages_hard: -1,
            ..LimitsConfig::default()
        };
        assert_eq!(send_unlimited.queue_stream_maxlen(), 0);

        let receive_unlimited = LimitsConfig {
            queued_receive_messages_hard: -1,
            ..LimitsConfig::default()
        };
        assert_eq!(receive_unlimited.queue_stream_maxlen(), 0);
    }

    /// The property the value exists for, over the whole settable range: a
    /// stream is never trimmed at or below a limit an account can be clamped
    /// to, because that is what makes counters and stream diverge.
    #[test]
    fn maxlen_is_never_at_or_below_a_clampable_limit() {
        for (send, receive) in [
            (1, 1),
            (200, 200),
            (1_000, 10_000),
            (10_000, 1_000),
            (i32::MAX, 5),
        ] {
            let limits = LimitsConfig {
                queued_send_messages_hard: send,
                queued_receive_messages_hard: receive,
                ..LimitsConfig::default()
            };
            let maxlen = limits.queue_stream_maxlen();
            assert!(
                maxlen > send as usize,
                "send {send} not below maxlen {maxlen}"
            );
            assert!(
                maxlen > receive as usize,
                "receive {receive} not below maxlen {maxlen}"
            );
        }
    }
}
