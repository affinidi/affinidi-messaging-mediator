//! Admission and frame budgets for anonymous inter-mediator relay sockets.

use super::*;

/// How long an anonymous inter-mediator relay socket may stay open.
///
/// A relay hop presents no JWT, so there is no token expiry to inherit and
/// nothing would otherwise bound the connection. An hour keeps the peer's
/// pooled socket useful while still forcing it to be re-admitted periodically
/// — re-running the relay-enabled check against current configuration, which
/// is what makes turning relay *off* take effect without a restart.
pub(super) const RELAY_SOCKET_LIFETIME_SECS: u64 = 3600;

/// The error code and reason to hand back in a negative [`RelayAck`].
///
/// A mediator problem report already carries both, and they are what the
/// relaying peer logs (and, once the message is abandoned, what reaches the
/// original sender). Anything without a problem report is an internal failure
/// the peer cannot act on beyond retrying, so it becomes a bare 500.
pub(super) fn relay_refusal(error: &MediatorError) -> (u16, String) {
    match error {
        MediatorError::MediatorError(code, _, _, _, _, log_message) => (*code, log_message.clone()),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            other.to_string(),
        ),
    }
}

/// Take one place in `registry` under `key`, returning the count including it.
/// The caller hands a [`PerDidConnectionGuard`] for the same key to its
/// [`ConnectionSlot`], which gives the place back.
pub(super) fn reserve(registry: &DashMap<String, u32>, key: &str) -> u32 {
    let mut entry = registry.entry(key.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

/// The key a relay socket is counted under: its client address, resolved as
/// the per-IP rate limiter resolves it (through `server.trust_xff_cidrs`).
/// `None` when there is no peer address or a trusted proxy sent an unreadable
/// `X-Forwarded-For` chain.
pub(super) fn relay_source_key(
    state: &SharedData,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    headers: &HeaderMap,
) -> Option<String> {
    let Extension(ConnectInfo(peer)) = connect_info?;
    state
        .relay_client_ip
        .client_key(peer.ip(), headers)
        .ok()
        .map(|ip| ip.to_string())
}

/// Inbound budget for one anonymous relay socket: frames per second and bytes
/// per second, each a token bucket.
///
/// An authenticated socket is bounded by its DID's queue limits; a relay
/// socket has no DID, and each frame costs an unpack and DID resolutions, so
/// without this one socket could push frames as fast as it can write them.
pub(super) struct RelayMeter {
    pub(super) frames: governor::DefaultDirectRateLimiter,
    pub(super) bytes: governor::DefaultDirectRateLimiter,
    pub(super) refused: u64,
}

impl RelayMeter {
    pub(super) fn new(limits: &crate::common::config::limits::LimitsConfig) -> Self {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;
        let nz = |n: u32| NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN);
        let bytes_per_second = nz(limits.relay_bytes_per_second);
        // Deep enough for the largest frame the socket admits at all.
        let byte_burst = nz(limits
            .relay_bytes_per_second
            .max(u32::try_from(limits.ws_size).unwrap_or(u32::MAX)));
        Self {
            frames: RateLimiter::direct(
                Quota::per_second(nz(limits.relay_frames_per_second))
                    .allow_burst(nz(limits.relay_frame_burst)),
            ),
            bytes: RateLimiter::direct(Quota::per_second(bytes_per_second).allow_burst(byte_burst)),
            refused: 0,
        }
    }

    /// Charge one frame of `len` bytes. `Err` names the budget it exceeded.
    pub(super) fn admit(&mut self, len: usize) -> Result<(), &'static str> {
        let refused = if self.frames.check().is_err() {
            Some("frames")
        } else {
            let n = std::num::NonZeroU32::new(u32::try_from(len.max(1)).unwrap_or(u32::MAX))
                .unwrap_or(std::num::NonZeroU32::MIN);
            match self.bytes.check_n(n) {
                Ok(Ok(())) => None,
                _ => Some("bytes"),
            }
        };
        match refused {
            Some(limit) => {
                self.refused += 1;
                Err(limit)
            }
            None => Ok(()),
        }
    }

    /// Whether the refusal just counted was this socket's first.
    pub(super) fn first_refusal(&self) -> bool {
        self.refused == 1
    }
}
