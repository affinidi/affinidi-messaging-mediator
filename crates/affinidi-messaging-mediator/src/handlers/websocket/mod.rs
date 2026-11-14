use crate::common::metrics::names::{
    ACTIVE_WEBSOCKET_CONNECTIONS, MUX_LIVE_FRAMES_WITHHELD_TOTAL, RELAY_CONNECTIONS_REFUSED_TOTAL,
    RELAY_FRAMES_THROTTLED_TOTAL, WS_LIVE_RESYNC_SENT, WS_LIVE_RESYNC_SUPPRESSED,
    WS_PONG_TIMEOUTS_TOTAL, WS_WRITE_TIMEOUTS_TOTAL,
};
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
use crate::error_codes;
#[cfg(feature = "tsp")]
use crate::messages::inbound::handle_inbound_tsp;
use crate::monitor::{Channel, Protocol};
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::config::{CorsOriginPolicy, origin_matches},
    common::jwt_auth::{AuthError, anonymous_relay_session, authenticate_token},
    common::session::Session,
    messages::inbound::handle_inbound,
    tasks::websocket_streaming::{
        CloseReason, EntryKind, QueuedCommand, StreamingUpdate, StreamingUpdateState,
        WS_CHANNEL_SLOTS, WebSocketCommands,
    },
};
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
#[cfg(feature = "tsp")]
use affinidi_messaging_mediator_common::store::{DeletionAuthority, MessageScope};
use affinidi_messaging_mediator_common::store::{StatCounter, prelude::*};
use affinidi_messaging_mediator_common::tasks::forwarding::relay_ack::{
    RELAY_ACK_SUBPROTOCOL, RelayAck, frame_id,
};
#[cfg(feature = "tsp")]
use affinidi_messaging_mediator_common::types::messages::FetchOptions;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::problem_report::ProblemReport;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::{
    Extension,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
#[cfg(feature = "tsp")]
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header::ORIGIN, header::SEC_WEBSOCKET_PROTOCOL};
#[cfg(feature = "didcomm")]
use serde_json::json;
#[cfg(feature = "tsp")]
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{Instrument, debug, info, span, warn};
#[cfg(feature = "didcomm")]
use uuid::Uuid;

// The upgrade handler and its subprotocol negotiation live here; the
// connection itself is split by concern:
// - `connection` — admission, streaming registration and the socket loop;
// - `slot` — the connection-state guard released on every exit path;
// - `liveness` — write deadlines and ping liveness;
// - `close` / `reports` — how a socket's end and refusals are told;
// - `relay` — anonymous inter-mediator relay sockets;
// - `tsp_drain` — raw-TSP inbox delivery.
mod close;
mod connection;
mod liveness;
mod relay;
mod reports;
mod slot;
#[cfg(feature = "tsp")]
mod tsp_drain;

use close::*;
use connection::*;
use liveness::*;
use relay::*;
use reports::*;
use slot::*;
#[cfg(feature = "tsp")]
use tsp_drain::*;

/// Subprotocol prefix used to carry the bearer JWT through the
/// `Sec-WebSocket-Protocol` request header.
///
/// Browsers cannot set an `Authorization` header on `new WebSocket(url,
/// protocols)`, but they *can* offer subprotocols. By convention the
/// browser offers a single entry of the form `bearer.<jwt>` (optionally
/// alongside genuine application subprotocols). The server detects the
/// entry carrying this prefix, strips the literal 7-character `bearer.`
/// prefix, and treats the remainder as the raw JWT — identical to the
/// token a native client would send in the `Authorization` header.
///
/// A *prefix strip* (not a `.`-split) is deliberate: a JWT is three
/// base64url segments joined by `.`, so splitting on `.` would be
/// ambiguous. Every JWT character (`[A-Za-z0-9-_]` plus `.`) is a valid
/// RFC 6455 subprotocol token char, so no extra encoding is needed.
///
/// Browser client usage:
/// ```js
/// new WebSocket("wss://…/mediator/v1/ws", ["bearer." + accessToken]);
/// ```
const WS_BEARER_SUBPROTOCOL_PREFIX: &str = "bearer.";

/// Extract the raw JWT from a `bearer.<jwt>` entry in the client's
/// requested WebSocket subprotocols, returning the first match.
///
/// Returns `None` when no entry carries the `bearer.` prefix or the
/// remainder is empty. Uses [`str::strip_prefix`] (not `split`) so the
/// `.` separators inside the JWT are preserved verbatim.
fn extract_bearer_subprotocol<'a, I>(protocols: I) -> Option<String>
where
    I: IntoIterator<Item = &'a HeaderValue>,
{
    protocols.into_iter().find_map(|p| {
        p.to_str().ok().and_then(|header_val| {
            // RFC 6455: subprotocols may be comma-separated in a single header value
            header_val.split(',').find_map(|s| {
                s.trim()
                    .strip_prefix(WS_BEARER_SUBPROTOCOL_PREFIX)
                    .filter(|token| !token.is_empty())
                    .map(str::to_string)
            })
        })
    })
}

/// The subprotocols the server may safely echo back in the 101
/// response: every requested entry that is **not** a bearer token.
///
/// Reflecting a `bearer.<jwt>` entry would leak the secret token in the
/// `Sec-WebSocket-Protocol` response header, so those entries are
/// filtered out here and never offered to [`WebSocketUpgrade::protocols`].
fn app_subprotocols<'a, I>(protocols: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a HeaderValue>,
{
    // RFC 6455: subprotocols may be comma-separated in a single header value
    protocols
        .into_iter()
        .filter_map(|p| p.to_str().ok())
        .flat_map(|header_val| header_val.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with(WS_BEARER_SUBPROTOCOL_PREFIX))
        .map(str::to_string)
        .collect()
}

/// Shortest gap between two resync `status` messages on one socket.
///
/// Sending one is not free — it costs an inbox read, a DID resolution and a
/// `pack_encrypted` — and the party that decides how often it happens is the
/// congested client, by choosing how slowly to read. Without a floor, a client
/// that alternates between stalling and briefly draining makes the mediator pay
/// that cost at a cadence it picks, on a task pool shared with every other
/// connection.
///
/// It is also the right behaviour with no attacker involved, and for the reason
/// the drops already coalesce: the client's answer to any number of dropped
/// notifications is one drain, so a second `status` before it has acted on the
/// first tells it nothing it does not already know, on the one socket already
/// known to be congested.
///
/// Well under the default 30s ping interval, so a deferred signal is never waiting long
/// for a wake-up to carry it.
const MIN_RESYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Whether a raised resync flag may be acted on yet.
///
/// Separated out so the rule is testable: the socket loop it lives in cannot be
/// driven from a unit test, and "is the flag set" and "has the floor elapsed"
/// are exactly the pair that is easy to get wrong together.
fn resync_due(raised: bool, since_last: Duration) -> bool {
    raised && since_last >= MIN_RESYNC_INTERVAL
}

/// Whether a WebSocket upgrade carrying this `Origin` header is allowed
/// by the configured CORS policy.
///
/// WebSocket upgrades aren't subject to CORS preflight, but browsers
/// still send an `Origin` header on them. This mirrors the REST CORS
/// allowlist ([`CorsOriginPolicy`]) as defence-in-depth: a browser from
/// a non-allowlisted origin is refused even if it somehow holds a valid
/// token. Native clients send no `Origin` header and are always allowed
/// — for them the JWT is the only (and sufficient) gate.
fn ws_origin_allowed(policy: &CorsOriginPolicy, origin: Option<&HeaderValue>) -> bool {
    match origin {
        // No Origin ⇒ not a browser cross-origin context (native client).
        None => true,
        Some(origin) => match policy {
            CorsOriginPolicy::Any => true,
            // Reuse the *same* matcher the REST CORS layer uses so the
            // two enforcement points (incl. `*.suffix` wildcards) can't
            // drift apart.
            CorsOriginPolicy::List(matchers) => origin_matches(matchers, origin),
            // No cross-origin browser access configured ⇒ refuse any
            // request that announces an Origin.
            CorsOriginPolicy::None => false,
        },
    }
}

/// Handles the switching of the protocol to a websocket connection.
///
/// ACL_MODE: Requires LOCAL access.
///
/// Authentication accepts the JWT from either channel, in priority
/// order:
/// 1. `Authorization: Bearer <jwt>` request header — the existing path
///    used by native clients (e.g. the Rust SDK). Unchanged.
/// 2. The `bearer.<jwt>` entry of the `Sec-WebSocket-Protocol` request
///    header — the browser-friendly path (browsers can't set request
///    headers on a WebSocket upgrade). See
///    `WS_BEARER_SUBPROTOCOL_PREFIX`.
///
/// Both channels validate the token identically via
/// `authenticate_token`; the resulting [`Session`] (and therefore the
/// per-connection JWT-expiry timeout enforced in `handle_socket`) is
/// the same regardless of how the token arrived. If neither channel
/// yields a valid token the upgrade is rejected, exactly as before.
pub async fn websocket_handler(
    State(state): State<SharedData>,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // 0. Defence-in-depth Origin check. WebSocket upgrades aren't
    //    subject to CORS, but a client that announces an `Origin` is
    //    refused unless the policy admits it.
    //
    //    This used to say "native clients send no Origin and pass
    //    straight through", which is true of the Rust SDK and false of
    //    the case that matters: **React Native's WebSocket sends an
    //    `Origin` derived from the URL**, so a mobile wallet is refused
    //    under the default (`CorsOriginPolicy::None`) exactly as a
    //    browser would be. "Native" is not the distinction — sending an
    //    Origin header is.
    let origin = headers.get(ORIGIN);
    if !ws_origin_allowed(&state.config.security.cors_origins, origin) {
        warn!(
            ?origin,
            policy = ?state.config.security.cors_origins,
            "WebSocket upgrade rejected: Origin not permitted by CORS policy. \
             A client sending no Origin is admitted; one sending an unlisted \
             Origin is not, and React Native's WebSocket does send one. To \
             admit it, add the origin to `[security] cors_allow_origin` — see \
             docs/cors-and-origin.md."
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    // 1. Resolve the JWT: Authorization header first (native clients),
    //    then the Sec-WebSocket-Protocol subprotocol (browsers).
    let token = if let Some(TypedHeader(Authorization(bearer))) = &auth_header {
        Some(bearer.token().to_string())
    } else {
        extract_bearer_subprotocol(headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter())
    };

    // 1a. No token: the one case that may still be admitted is an
    //     inter-mediator relay hop, which is anonymous by construction — the
    //     relaying mediator holds no session here, exactly as on `/inbound`.
    //     It has to *say* that it is one by offering the `relay-ack`
    //     subprotocol, which is also its promise to consume the per-frame
    //     acknowledgements that give this transport the REST path's delivery
    //     semantics. Everything else is refused as before.
    let offered = app_subprotocols(headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter());
    let wants_relay = offered.iter().any(|p| p == RELAY_ACK_SUBPROTOCOL);

    let (session, relay_source) = match token {
        Some(token) => {
            // 2. Validate the token → Session (identical checks for both paths).
            match authenticate_token(&state, &token).await {
                Ok(session) => (session, None),
                Err(e) => return e.into_response(),
            }
        }
        None if wants_relay => {
            let security = &state.config.security;
            match anonymous_relay_session(
                security.enable_inter_mediator_relay,
                &security.global_acl_default,
            ) {
                Some(mut session) => {
                    // Relay sockets are counted per client address, so the
                    // address has to be known; one that cannot be attributed
                    // is refused rather than counted against nobody.
                    let Some(source) = relay_source_key(&state, connect_info, &headers) else {
                        metrics::counter!(RELAY_CONNECTIONS_REFUSED_TOTAL, "reason" => "no_client_ip")
                            .increment(1);
                        warn!(
                            "Relay WebSocket upgrade refused: client address could not be determined"
                        );
                        return (
                            StatusCode::FORBIDDEN,
                            "client address could not be determined",
                        )
                            .into_response();
                    };
                    // No JWT means no expiry to inherit, and an anonymous
                    // socket that never ends is a resource a peer can hold
                    // open indefinitely. Give it a bounded lifetime instead;
                    // the relaying peer's pool reconnects transparently.
                    session.expires_at = state.clock.unix_secs() + RELAY_SOCKET_LIFETIME_SECS;
                    (session, Some(source))
                }
                None => {
                    warn!(
                        "WebSocket upgrade rejected: `{}` offered but this mediator is not \
                         configured as an inter-mediator relay",
                        RELAY_ACK_SUBPROTOCOL
                    );
                    return AuthError::MissingCredentials.into_response();
                }
            }
        }
        None => {
            warn!(
                "WebSocket upgrade rejected: no bearer token in Authorization header or Sec-WebSocket-Protocol"
            );
            return AuthError::MissingCredentials.into_response();
        }
    };

    let is_relay = relay_source.is_some();

    let _span = span!(
        tracing::Level::INFO,
        "websocket_handler",
        session = session.session_id
    );

    // 3. ACL Check. A relay socket has no account here and never touches one:
    //    it may only push frames, so it is gated on `SEND_MESSAGES` — the same
    //    capability `message_inbound_handler` requires of the REST relay
    //    session — instead of `LOCAL`, which exists to gate access to an
    //    inbox this session does not have.
    let required = if is_relay {
        Capability::SendMessages
    } else {
        Capability::Local
    };
    if authz::require_capability(&session.acls, required).is_err() {
        let error: AppError = MediatorError::problem(
            error_codes::AUTH_NOT_LOCAL,
            session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.local",
            "DID isn't local to the mediator",
            vec![],
            StatusCode::FORBIDDEN,
        )
        .into();

        return error.into_response();
    }

    // 4. Echo back only genuine application subprotocols (if any) — and
    //    NEVER the `bearer.<jwt>` entry, which would leak the token in
    //    the 101 response header. When the client offered only the
    //    bearer entry, no subprotocol is selected and the response
    //    carries no `Sec-WebSocket-Protocol` header (RFC 6455 permits
    //    this; browsers accept it).
    let app_protocols = offered;

    // A client opts into raw-TSP WebSocket delivery by offering a `tsp`
    // subprotocol alongside `bearer.<jwt>`. The `tsp` marker is echoed back to
    // the client via the `app_protocols` path below (it's a genuine app
    // subprotocol, not the bearer entry), so the client learns the mode was
    // accepted from the 101 response's `Sec-WebSocket-Protocol` header.
    //
    // Never on a relay socket: raw-TSP mode is a *delivery* mode — it registers
    // the socket as a live client and flushes an inbox — and a relay session
    // has no DID and no inbox to flush. (It also cannot arise in practice: the
    // relaying mediator offers `relay-ack` alone, and TSP forwards go over
    // REST. Enforced rather than assumed, because the cost of being wrong is an
    // anonymous socket registered as a live streaming client under the empty
    // DID hash.)
    #[cfg(feature = "tsp")]
    let tsp_mode = !is_relay && app_protocols.iter().any(|p| p == "tsp" || p == "tsp-ack");

    // `tsp-ack` opts into DELETE-TO-ACK delivery. Plain `tsp` keeps the
    // original delete-on-send contract, which is at-most-once past the socket
    // write: the frame is deleted as soon as it has been handed to the local
    // sink, so a connection that dies before the peer reads it loses the
    // message with nothing left to redeliver. That is fine for a liveness probe
    // and wrong for anything that matters.
    //
    // In `tsp-ack` mode the mediator sends and keeps. The client acknowledges
    // by deleting the message through the ordinary authenticated delete path
    // once it has taken the frame — the id is `sha256` of the stored body,
    // which is exactly the bytes on the wire, so the client can derive it
    // without the mediator sending ids and without any change to the frame
    // format. An un-acked message is simply still there on the next connect.
    //
    // Opt-in on purpose: flipping every client at once would trade silent loss
    // for silent duplication, since a client that never acks would be
    // redelivered its whole inbox on every reconnect.
    //
    // `tsp-mux` (spec `messaging/mux/event`, "Raw-TSP sockets") makes the
    // raw-TSP socket a mux connection, and implies `tsp-ack`: delete-on-send is
    // at-most-once, and across N member DIDs one socket drop would lose N
    // inboxes' worth of in-flight frames. Selected only when this build can
    // multiplex — mux enabled and a streaming task to register members with —
    // so a mediator that will not multiplex never claims it will. Same
    // ordering trick as `tsp-ack` below: the client offers `tsp`, `tsp-ack`,
    // `tsp-mux` in that order, so an older mediator reflects the list and
    // selects `tsp`.
    #[cfg(feature = "tsp")]
    let tsp_mux_mode = tsp_mode
        && state.config.limits.mux.enabled
        && state.streaming_task.is_some()
        && app_protocols
            .iter()
            .any(|p| p == crate::mux::connection::TSP_MUX_SUBPROTOCOL);
    #[cfg(feature = "tsp")]
    let tsp_ack_mode = !is_relay && (tsp_mux_mode || app_protocols.iter().any(|p| p == "tsp-ack"));

    // The echo has to be a HONEST capability signal, and by default it isn't:
    // the offered list is just the client's own list reflected back, so a
    // mediator that has never heard of a subprotocol still echoes it. A client
    // asking for `tsp-ack` against an older mediator would therefore be told
    // "yes" and silently get delete-on-send — the exact silent downgrade
    // delete-to-ack exists to prevent.
    //
    // Fixed by ordering. Clients offer `tsp` BEFORE `tsp-ack`, and axum selects
    // the first client-requested protocol that the server also lists:
    //   * older mediator — reflects the client's list, so it selects the
    //     client's first entry, `tsp`. The client sees no ack support. Correct.
    //   * this mediator — narrows the offer to `tsp-ack` alone, so that is what
    //     gets selected despite being second. The client sees ack support, and
    //     only a mediator that implements it can produce that answer.
    // DID multiplexing (design §7). Only an authenticated DIDComm socket can
    // become a mux connection, and only when the operator enabled mux. The
    // marker is echoed only then: a client offering it to a mediator that will
    // not multiplex must not be told it will.
    #[cfg(feature = "tsp")]
    let tsp_any = tsp_mode;
    #[cfg(not(feature = "tsp"))]
    let tsp_any = false;
    let mux_selected = if !is_relay && !tsp_any && state.config.limits.mux.enabled {
        crate::mux::connection::mux_subprotocol(&app_protocols)
    } else {
        None
    };
    let mux_mode = mux_selected.is_some();
    let app_protocols: Vec<String> = match mux_selected {
        Some(p) => vec![p.to_string()],
        None => app_protocols
            .into_iter()
            .filter(|p| {
                p != crate::mux::connection::MUX_SUBPROTOCOL
                    && p != crate::mux::connection::LEGACY_MUX_SUBPROTOCOL
                    && p != crate::mux::connection::TSP_MUX_SUBPROTOCOL
            })
            .collect(),
    };

    #[cfg(feature = "tsp")]
    let app_protocols = if tsp_mux_mode {
        vec![crate::mux::connection::TSP_MUX_SUBPROTOCOL.to_string()]
    } else if tsp_ack_mode {
        vec!["tsp-ack".to_string()]
    } else {
        app_protocols
    };
    // From here on `mux_mode` means "this socket is a mux connection", on
    // either wire; `tsp_mode` says which.
    #[cfg(feature = "tsp")]
    let mux_mode = mux_mode || tsp_mux_mode;

    // Same honesty requirement as `tsp-ack` above, and here it is load-bearing:
    // the relaying peer treats the echoed `relay-ack` as proof that its frames
    // will be acknowledged, and refuses to relay over the socket without it. A
    // reflected-by-accident echo would be a mediator promising acks it does not
    // send — so narrow the offer to exactly what this mediator implements.
    let app_protocols = if is_relay {
        vec![RELAY_ACK_SUBPROTOCOL.to_string()]
    } else {
        // And the converse: an authenticated client that offers `relay-ack`
        // is not a relay (a relay hop presents no credential), so it must not
        // be told it will get acks it is never going to receive. Drop the
        // entry rather than reflect it.
        app_protocols
            .into_iter()
            .filter(|p| p != RELAY_ACK_SUBPROTOCOL)
            .collect()
    };

    let ws = if app_protocols.is_empty() {
        ws
    } else {
        ws.protocols(app_protocols)
    };

    // 5. Enforce the configured `ws_size` cap at the tungstenite layer so
    //    oversized frames are rejected during framing instead of being
    //    buffered in full and only checked after `socket.recv()` returns.
    let ws_size = state.config.limits.ws_size;
    let ws = ws.max_message_size(ws_size).max_frame_size(ws_size);

    // From here the socket's mode is one value, not a set of flags whose
    // combinations the loop would have to keep consistent.
    let mode = match relay_source {
        Some(source) => ConnectionMode::Relay { source },
        #[cfg(feature = "tsp")]
        None if tsp_mode => ConnectionMode::Tsp {
            ack: tsp_ack_mode,
            mux: mux_mode,
        },
        None => ConnectionMode::DidComm { mux: mux_mode },
    };

    async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session, mode)) }
        .instrument(_span)
        .await
}

/// Test-only pause points for the connection loop.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::Duration;

    static STALL_AFTER_PING: LazyLock<Mutex<HashMap<String, (Duration, u32)>>> =
        LazyLock::new(Default::default);

    /// Make the connection loop of `did_hash`'s sockets sleep for `stall`
    /// right after each of its next `times` pings that start a wait (no
    /// earlier ping outstanding), as a long-running pass would, so it reads
    /// nothing in that time. One stall per ping: a ping missed across
    /// several consecutive busy passes is closed once its fresh windows run
    /// out, by design.
    pub fn stall_loop_after_ping(did_hash: &str, stall: Duration, times: u32) {
        STALL_AFTER_PING
            .lock()
            .expect("hook map")
            .insert(did_hash.to_string(), (stall, times));
    }

    pub(super) fn stall_after_ping(did_hash: &str) -> Option<Duration> {
        let mut map = STALL_AFTER_PING.lock().expect("hook map");
        let (stall, left) = map.get_mut(did_hash)?;
        let stall = *stall;
        *left -= 1;
        if *left == 0 {
            map.remove(did_hash);
        }
        Some(stall)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedSocket, CorsOriginPolicy, Liveness, MIN_RESYNC_INTERVAL, PingWatch, RelayMeter,
        app_subprotocols, bounded_write, extract_bearer_subprotocol, resync_due, ws_origin_allowed,
    };
    use crate::common::config::OriginMatcher;
    use http::HeaderValue;
    use std::time::Duration;

    #[test]
    fn a_relay_meter_refuses_frames_past_its_burst() {
        let limits = crate::common::config::limits::LimitsConfig {
            relay_frames_per_second: 1,
            relay_frame_burst: 3,
            ..Default::default()
        };
        let mut meter = RelayMeter::new(&limits);
        for _ in 0..3 {
            assert_eq!(meter.admit(10), Ok(()));
        }
        assert_eq!(meter.admit(10), Err("frames"));
        assert!(meter.first_refusal());
        assert_eq!(meter.admit(10), Err("frames"));
        assert!(
            !meter.first_refusal(),
            "only the first refusal is the first"
        );
    }

    #[test]
    fn a_relay_meter_refuses_bytes_past_its_budget() {
        let limits = crate::common::config::limits::LimitsConfig {
            relay_bytes_per_second: 1_000,
            ws_size: 1_000,
            ..Default::default()
        };
        let mut meter = RelayMeter::new(&limits);
        assert_eq!(meter.admit(600), Ok(()));
        assert_eq!(meter.admit(600), Err("bytes"));
        // A frame of the full admitted size passes on a fresh budget: the
        // bucket is never shallower than `ws_size`.
        let mut fresh = RelayMeter::new(&limits);
        assert_eq!(fresh.admit(1_000), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_past_its_deadline_fails_and_marks_the_socket_stalled() {
        let mut stalled = false;
        let never = std::future::pending::<Result<(), axum::Error>>();
        assert!(
            bounded_write(&mut stalled, Duration::from_secs(30), never)
                .await
                .is_err()
        );
        assert!(stalled);

        // Later writes fail without being attempted.
        let attempted = std::cell::Cell::new(false);
        let write = async {
            attempted.set(true);
            Ok(())
        };
        assert!(
            bounded_write(&mut stalled, Duration::from_secs(30), write)
                .await
                .is_err()
        );
        assert!(!attempted.get());
    }

    /// A real WebSocket pair over loopback: the mediator's end, and a client
    /// end the test controls (and may never read from).
    async fn socket_pair() -> (
        axum::extract::ws::WebSocket,
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) {
        use axum::{Router, extract::ws::WebSocketUpgrade, routing::get};
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
        let app = Router::new().route(
            "/",
            get(move |ws: WebSocketUpgrade| {
                let tx = tx.clone();
                async move {
                    ws.on_upgrade(move |socket| async move {
                        if let Some(tx) = tx.lock().expect("lock").take() {
                            let _ = tx.send(socket);
                        }
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let (client, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .expect("client handshake");
        let server = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("server side upgraded in time")
            .expect("server socket handed over");
        (server, client)
    }

    /// A peer that never reads: once its TCP window and the kernel buffers
    /// fill, the next write waits for room that never comes. It must fail
    /// within the write timeout, and the socket must refuse further writes.
    #[tokio::test]
    async fn a_write_to_a_peer_that_never_reads_times_out() {
        let (server, client) = socket_pair().await;
        let mut socket = BoundedSocket::new(server, Duration::from_millis(300));
        let frame = vec![0u8; 256 * 1024];
        let mut written = 0usize;
        let failed = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match socket
                    .send(axum::extract::ws::Message::Binary(frame.clone().into()))
                    .await
                {
                    Ok(()) => {
                        written += 1;
                        // 1 GiB is far beyond any loopback buffering.
                        assert!(written < 4096, "writes kept succeeding with nobody reading");
                    }
                    Err(e) => break e,
                }
            }
        })
        .await
        .expect("a write to a peer that never reads must time out, not hang");
        assert!(
            failed.to_string().contains("did not complete"),
            "expected the write timeout, got: {failed}"
        );
        assert!(socket.stalled(), "a timed-out socket is marked stalled");
        assert!(
            socket
                .send(axum::extract::ws::Message::Ping(Vec::new().into()))
                .await
                .is_err(),
            "a stalled socket accepts no further writes"
        );
        drop(client);
    }

    /// A pong answers the outstanding ping on a real socket.
    #[tokio::test]
    async fn a_pong_answers_the_outstanding_ping() {
        use futures_util::SinkExt;
        let (server, mut client) = socket_pair().await;
        let mut socket = BoundedSocket::new(server, Duration::from_secs(5));
        assert_eq!(socket.pings.deadline(), None, "no ping, nothing waiting");
        socket
            .ping(Duration::from_secs(60))
            .await
            .expect("ping written");
        assert!(socket.pings.deadline().is_some(), "a ping is waiting");

        client
            .send(tokio_tungstenite::tungstenite::Message::Pong(
                Vec::new().into(),
            ))
            .await
            .expect("client sends a pong");
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.recv())
            .await
            .expect("pong arrives");
        assert!(matches!(
            frame,
            Some(Ok(axum::extract::ws::Message::Pong(_)))
        ));
        assert_eq!(socket.pings.deadline(), None, "the pong answered it");
    }

    #[tokio::test(start_paused = true)]
    async fn the_ping_clock_starts_at_the_first_unanswered_ping() {
        let grace = Duration::from_secs(60);
        let mut watch = PingWatch::default();
        // Time without a ping out never counts, however long.
        tokio::time::advance(Duration::from_secs(3600)).await;
        watch.after_pass(tokio::time::Instant::now(), Duration::from_secs(30));
        assert_eq!(watch.deadline(), None);

        let first = tokio::time::Instant::now();
        watch.ping_sent(grace);
        assert_eq!(watch.deadline(), Some(first + grace));
        // A second ping while the first waits keeps the earlier deadline.
        tokio::time::advance(Duration::from_secs(30)).await;
        watch.ping_sent(grace);
        assert_eq!(watch.deadline(), Some(first + grace));

        watch.answered();
        assert_eq!(watch.deadline(), None);
    }

    /// A deadline that passed while the loop was not reading is moved to a
    /// fresh window from now; one still ahead, or one already due when the
    /// loop stopped waiting, is left alone.
    #[tokio::test(start_paused = true)]
    async fn a_deadline_missed_while_busy_gets_a_fresh_window() {
        let grace = Duration::from_secs(60);
        let window = Duration::from_secs(30);
        let mut watch = PingWatch::default();
        let sent = tokio::time::Instant::now();
        watch.ping_sent(grace);

        tokio::time::advance(Duration::from_secs(10)).await;
        watch.after_pass(tokio::time::Instant::now(), window);
        assert_eq!(
            watch.deadline(),
            Some(sent + grace),
            "still ahead: unchanged"
        );

        // The loop stopped waiting at 20 s, then ran for 200 s without reading.
        tokio::time::advance(Duration::from_secs(10)).await;
        let woke = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(200)).await;
        watch.after_pass(woke, window);
        assert_eq!(
            watch.deadline(),
            Some(tokio::time::Instant::now() + window),
            "missed while busy: a fresh window"
        );
    }

    /// One unanswered ping gets a bounded number of fresh windows, however
    /// many busy passes it misses; an answer resets the allowance.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_ping_gets_a_bounded_number_of_windows() {
        let grace = Duration::from_secs(60);
        let window = Duration::from_secs(30);
        let mut watch = PingWatch::default();
        watch.ping_sent(grace);

        // A busy pass that runs past the deadline.
        async fn busy_pass(watch: &mut PingWatch, window: Duration) -> tokio::time::Instant {
            let woke = tokio::time::Instant::now();
            let deadline = watch.deadline().expect("a ping is waiting");
            tokio::time::advance(deadline - woke + Duration::from_secs(1)).await;
            watch.after_pass(woke, window);
            watch.deadline().expect("still waiting")
        }
        for _ in 0..PingWatch::MAX_EXTENSIONS {
            let deadline = busy_pass(&mut watch, window).await;
            assert_eq!(deadline, tokio::time::Instant::now() + window, "extended");
        }
        let deadline = busy_pass(&mut watch, window).await;
        assert!(
            deadline <= tokio::time::Instant::now(),
            "past the allowance the deadline stays due"
        );

        // An answer resets it: the next ping may be extended again.
        watch.answered();
        watch.ping_sent(grace);
        let deadline = busy_pass(&mut watch, window).await;
        assert_eq!(deadline, tokio::time::Instant::now() + window);
    }

    /// The deadline fell due together with another branch (a ping tick), and
    /// that branch won: the loop was waiting, not busy, so no extension.
    #[tokio::test(start_paused = true)]
    async fn a_deadline_due_when_the_wait_ended_is_not_extended() {
        let grace = Duration::from_secs(60);
        let mut watch = PingWatch::default();
        let sent = tokio::time::Instant::now();
        watch.ping_sent(grace);
        tokio::time::advance(grace).await;
        let woke = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(5)).await;
        watch.after_pass(woke, Duration::from_secs(30));
        assert_eq!(watch.deadline(), Some(sent + grace));
    }

    #[test]
    fn liveness_holds_pong_to_two_ping_intervals_whatever_the_source() {
        let limits = crate::common::config::LimitsConfig {
            ws_ping_interval_secs: 30,
            ws_pong_timeout_secs: 10,
            ws_write_timeout_secs: 0,
            ..Default::default()
        };
        let liveness = Liveness::from_limits(&limits);
        assert_eq!(liveness.ping_interval, Duration::from_secs(30));
        assert_eq!(liveness.grace, Duration::from_secs(30), "pong raised to 60");
        assert_eq!(liveness.write_timeout, Duration::from_secs(1));

        let defaults = Liveness::from_limits(&crate::common::config::LimitsConfig::default());
        assert_eq!(defaults.grace, Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_within_its_deadline_succeeds() {
        let mut stalled = false;
        let write = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        };
        assert!(
            bounded_write(&mut stalled, Duration::from_secs(30), write)
                .await
                .is_ok()
        );
        assert!(!stalled);
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("valid header value")
    }

    fn exact(s: &str) -> OriginMatcher {
        OriginMatcher::Exact(hv(s))
    }

    #[test]
    fn extract_strips_prefix_and_preserves_jwt_dots() {
        // A JWT is three base64url segments joined by '.'. The bearer
        // entry must be prefix-stripped, not split, so the inner dots
        // survive intact.
        let protos = [hv("bearer.aaa.bbb.ccc")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("aaa.bbb.ccc".to_string())
        );
    }

    #[test]
    fn extract_finds_bearer_among_app_subprotocols() {
        // The browser may offer a genuine app subprotocol alongside the
        // bearer entry; the token must still be found regardless of order.
        let protos = [hv("didcomm/v2"), hv("bearer.tok.en.value")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("tok.en.value".to_string())
        );
    }

    #[test]
    fn extract_returns_none_without_bearer_entry() {
        let protos = [hv("didcomm/v2"), hv("soap")];
        assert_eq!(extract_bearer_subprotocol(protos.iter()), None);
    }

    #[test]
    fn extract_returns_none_for_empty_token() {
        // "bearer." with nothing after it is not a usable token.
        let protos = [hv("bearer.")];
        assert_eq!(extract_bearer_subprotocol(protos.iter()), None);
    }

    #[test]
    fn app_subprotocols_drops_bearer_entries() {
        // Guards the "never echo the token" requirement: the bearer
        // entry must be excluded from anything the server may reflect.
        let protos = [hv("didcomm/v2"), hv("bearer.secret.jwt.here")];
        assert_eq!(app_subprotocols(protos.iter()), vec!["didcomm/v2"]);
    }

    #[test]
    fn app_subprotocols_empty_when_only_bearer() {
        // Bearer-only offer ⇒ nothing safe to echo ⇒ no subprotocol
        // selected in the 101 response.
        let protos = [hv("bearer.secret.jwt.here")];
        assert!(app_subprotocols(protos.iter()).is_empty());
    }

    #[test]
    fn extract_bearer_from_comma_separated_header() {
        // RFC 6455: clients MAY send subprotocols as comma-separated in
        // a single Sec-WebSocket-Protocol header value.
        let protos = [hv("didcomm/v2, bearer.tok.en.value")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("tok.en.value".to_string())
        );
    }

    #[test]
    fn app_subprotocols_from_comma_separated_header() {
        // Comma-separated bearer entry must be excluded, app protocols kept.
        let protos = [hv("didcomm/v2, bearer.secret.jwt.here")];
        assert_eq!(app_subprotocols(protos.iter()), vec!["didcomm/v2"]);
    }

    /// The resync floor, which exists because sending the signal is not free:
    /// an inbox read, a DID resolution and a `pack_encrypted` per send, at a
    /// cadence the congested client chooses by how slowly it reads.
    #[test]
    fn resync_is_due_only_when_raised_and_past_the_floor() {
        use std::time::Duration;

        // Not raised: never due, however long it has been.
        assert!(!resync_due(false, Duration::from_secs(3600)));
        // Raised but inside the floor: held back, not sent.
        assert!(!resync_due(true, Duration::ZERO));
        assert!(!resync_due(
            true,
            MIN_RESYNC_INTERVAL - Duration::from_millis(1)
        ));
        // Raised and at or past the floor: due.
        assert!(resync_due(true, MIN_RESYNC_INTERVAL));
        assert!(resync_due(true, MIN_RESYNC_INTERVAL * 2));
    }

    #[test]
    fn origin_check_admits_a_request_with_no_origin_header() {
        // Sending no Origin is the thing that passes, under every policy —
        // for such a client the JWT is the gate.
        //
        // Named for the header rather than for "native clients", which is what
        // this test used to say. The rename is the point: the old name, and the
        // identical wording in the reference config and the setup wizard, let a
        // reader conclude that a non-browser client could not be refused. See
        // `origin_check_refuses_a_react_native_client_under_the_default`.
        assert!(ws_origin_allowed(&CorsOriginPolicy::None, None));
        assert!(ws_origin_allowed(&CorsOriginPolicy::Any, None));
        assert!(ws_origin_allowed(
            &CorsOriginPolicy::List(vec![exact("https://app.example")]),
            None
        ));
    }

    #[test]
    fn origin_check_none_policy_refuses_any_origin_header() {
        let origin = hv("https://evil.example");
        assert!(!ws_origin_allowed(&CorsOriginPolicy::None, Some(&origin)));
    }

    /// The KR-05 / VTI-05 regression, named so it cannot be mistaken for a
    /// browser-only concern.
    ///
    /// React Native's WebSocket sends an `Origin` derived from the connection
    /// URL, so a mobile wallet is refused by the default policy exactly as a
    /// browser is. Nothing about the check distinguishes the two, and the
    /// documentation claiming otherwise is what cost an integrator a day.
    #[test]
    fn origin_check_refuses_a_react_native_client_under_the_default() {
        // What a React Native dev bundle typically presents.
        let rn_origin = hv("http://localhost:8081");
        assert!(
            !ws_origin_allowed(&CorsOriginPolicy::None, Some(&rn_origin)),
            "a client sending an Origin is refused under the default, \
             whether or not it is a browser"
        );
        // ...and is admitted once the operator allowlists it.
        assert!(ws_origin_allowed(
            &CorsOriginPolicy::List(vec![exact("http://localhost:8081")]),
            Some(&rn_origin)
        ));
    }

    #[test]
    fn origin_check_any_policy_admits_any_origin_header() {
        let origin = hv("https://anything.example");
        assert!(ws_origin_allowed(&CorsOriginPolicy::Any, Some(&origin)));
    }

    #[test]
    fn origin_check_list_policy_matches_allowlist() {
        let policy = CorsOriginPolicy::List(vec![exact("https://app.example")]);
        let allowed = hv("https://app.example");
        let denied = hv("https://other.example");
        assert!(ws_origin_allowed(&policy, Some(&allowed)));
        assert!(!ws_origin_allowed(&policy, Some(&denied)));
    }

    #[test]
    fn origin_check_list_policy_honours_wildcards() {
        // Parity with the REST CORS layer: the WS check must accept the
        // same `*.suffix` wildcards (and reject the apex / look-alikes).
        let policy = CorsOriginPolicy::List(vec![OriginMatcher::WildcardSubdomain {
            scheme: "https".into(),
            suffix: "affinidi.com".into(),
            port: None,
        }]);
        assert!(ws_origin_allowed(
            &policy,
            Some(&hv("https://app.affinidi.com"))
        ));
        assert!(!ws_origin_allowed(
            &policy,
            Some(&hv("https://affinidi.com"))
        ));
        assert!(!ws_origin_allowed(
            &policy,
            Some(&hv("https://evilaffinidi.com"))
        ));
    }
}
