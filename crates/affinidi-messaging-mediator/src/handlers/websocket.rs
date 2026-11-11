use crate::common::metrics::names::{
    ACTIVE_WEBSOCKET_CONNECTIONS, MUX_LIVE_FRAMES_WITHHELD_TOTAL, RELAY_CONNECTIONS_REFUSED_TOTAL,
    RELAY_FRAMES_THROTTLED_TOTAL, WS_LIVE_RESYNC_SENT, WS_LIVE_RESYNC_SUPPRESSED,
    WS_WRITE_TIMEOUTS_TOTAL,
};
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
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
use affinidi_messaging_mediator_common::store::DeletionAuthority;
use affinidi_messaging_mediator_common::store::{MediatorStore, StatCounter};
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

/// Whether a WebSocket upgrade carrying this `Origin` header is allowed
/// by the configured CORS policy.
///
/// WebSocket upgrades aren't subject to CORS preflight, but browsers
/// still send an `Origin` header on them. This mirrors the REST CORS
/// allowlist ([`CorsOriginPolicy`]) as defence-in-depth: a browser from
/// a non-allowlisted origin is refused even if it somehow holds a valid
/// token. Native clients send no `Origin` header and are always allowed
/// — for them the JWT is the only (and sufficient) gate.
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
/// Well under the 30s ping interval, so a deferred signal is never waiting long
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
            40,
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

    #[cfg(feature = "tsp")]
    {
        async move {
            ws.on_upgrade(move |socket| {
                handle_socket(
                    socket,
                    state,
                    session,
                    relay_source,
                    mux_mode,
                    tsp_mode,
                    tsp_ack_mode,
                )
            })
        }
        .instrument(_span)
        .await
    }
    #[cfg(not(feature = "tsp"))]
    {
        async move {
            ws.on_upgrade(move |socket| {
                handle_socket(socket, state, session, relay_source, mux_mode)
            })
        }
        .instrument(_span)
        .await
    }
}

/// Releases a DID's reserved per-DID WebSocket slot on drop, so the count is
/// decremented on *every* `handle_socket` return path (including the early
/// returns before the main loop). The entry is removed once it reaches zero
/// so the registry doesn't accumulate idle DIDs.
struct PerDidConnectionGuard {
    registry: Arc<DashMap<String, u32>>,
    did_hash: String,
}

impl Drop for PerDidConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.registry.get_mut(&self.did_hash) {
            *count = count.saturating_sub(1);
        }
        self.registry
            .remove_if(&self.did_hash, |_, &count| count == 0);
    }
}

/// One WebSocket's share of the mediator-wide connection state: its slot in
/// the global count, its per-DID slot, its place on the
/// `ACTIVE_WEBSOCKET_CONNECTIONS` gauge, its streaming registration and its
/// close stat.
///
/// Each part is taken on as the connection reaches it and given back by this
/// one value, so no exit path from `handle_socket` skips or repeats one of
/// these releases. [`ConnectionSlot::release`] gives everything back in order
/// and awaits it; dropping the slot without it (an early return, a panic, the
/// task being cancelled) releases the same parts, sending what needs a task
/// in the background.
///
/// A mux connection's members are not held here: they are closed by
/// `mux::connection::close` on the handler's own exit paths, so a panic or a
/// cancelled task leaves them to the registry's sweep.
struct ConnectionSlot {
    count: Arc<AtomicUsize>,
    /// Counted on the gauge.
    on_gauge: bool,
    /// Counted as opened, so a close stat is owed.
    close_stat: Option<Arc<dyn MediatorStore>>,
    /// Registered with the streaming task, so a deregistration is owed.
    registration: Option<(Sender<StreamingUpdate>, StreamingUpdate)>,
    /// The DID's per-DID slot, released with the global one.
    per_did: Option<PerDidConnectionGuard>,
    /// A relay socket's per-address slot, released with the global one.
    per_source: Option<PerDidConnectionGuard>,
}

impl ConnectionSlot {
    /// Reserve a place in the global count. `Err` carries the count already
    /// in use when it is at `max`; the reservation is backed out by then.
    fn acquire(count: &Arc<AtomicUsize>, max: usize) -> Result<Self, usize> {
        let current = count.fetch_add(1, Ordering::Relaxed);
        let slot = Self {
            count: count.clone(),
            on_gauge: false,
            close_stat: None,
            registration: None,
            per_did: None,
            per_source: None,
        };
        if current >= max {
            Err(current)
        } else {
            Ok(slot)
        }
    }

    /// The connection is admitted: count it on the gauge and in the open
    /// stat, which this slot then owes a matching close for.
    async fn open(&mut self, database: &Arc<dyn MediatorStore>) {
        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).increment(1.0);
        self.on_gauge = true;
        let _ = database
            .stats_increment(StatCounter::WebsocketOpen, 1)
            .await;
        self.close_stat = Some(database.clone());
    }

    /// Hold the DID's per-DID slot until this slot is released.
    fn hold_per_did(&mut self, guard: PerDidConnectionGuard) {
        self.per_did = Some(guard);
    }

    /// Hold a relay socket's per-address slot until this slot is released.
    fn hold_per_source(&mut self, guard: PerDidConnectionGuard) {
        self.per_source = Some(guard);
    }

    /// The streaming task holds a registration for this socket, made with
    /// the send queue `client`. The deregistration names that queue, so it
    /// can only ever remove this socket's entry: another socket for the same
    /// DID may share the session id.
    fn registered(
        &mut self,
        channel: Sender<StreamingUpdate>,
        did_hash: &str,
        session_id: &str,
        client: &Sender<QueuedCommand>,
    ) {
        self.registration = Some((
            channel,
            StreamingUpdate {
                did_hash: did_hash.to_string(),
                state: StreamingUpdateState::Deregister {
                    session_id: session_id.to_string(),
                    channel: client.downgrade(),
                },
            },
        ));
    }

    /// The streaming task closed this socket and has already let its
    /// registration go. Deregistering now could remove the newer socket
    /// that took the slot.
    fn deregistered_by_streaming(&mut self) {
        self.registration = None;
    }

    /// Give everything back now, awaiting the parts that go to other tasks.
    async fn release(mut self) {
        if let Some((channel, stop)) = self.registration.take() {
            let _ = channel.send(stop).await;
        }
        if let Some(database) = self.close_stat.take() {
            let _ = database
                .stats_increment(StatCounter::WebsocketClose, 1)
                .await;
        }
        // The count, the per-DID slot and the gauge go in `drop`.
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
        if self.on_gauge {
            metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).decrement(1.0);
        }
        let registration = self.registration.take();
        let close_stat = self.close_stat.take();
        if registration.is_none() && close_stat.is_none() {
            return;
        }
        // Dropped without `release`. The deregistration is tried without
        // waiting first; only a full control channel needs a task.
        let registration = registration.and_then(|(channel, stop)| match channel.try_send(stop) {
            Err(mpsc::error::TrySendError::Full(stop)) => Some((channel, stop)),
            _ => None,
        });
        if registration.is_none() && close_stat.is_none() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Some((channel, stop)) = registration {
                        let _ = channel.send(stop).await;
                    }
                    if let Some(database) = close_stat {
                        let _ = database
                            .stats_increment(StatCounter::WebsocketClose, 1)
                            .await;
                    }
                });
            }
            Err(_) => warn!(
                "WebSocket connection released outside a runtime; streaming deregistration and close stat not sent"
            ),
        }
    }
}

/// How long one write to a WebSocket may take before the peer is treated as
/// gone. A peer that stops reading leaves a write parked once its TCP window
/// closes; without a bound the connection never notices, and holds its
/// slots and queued frames until the kernel gives up on it.
const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A [`WebSocket`] whose writes are bounded by [`WS_WRITE_TIMEOUT`].
///
/// A write that runs out of time may have left part of a frame on the wire,
/// so the socket is unusable after it: every later write fails at once, and
/// the connection loop closes on [`BoundedSocket::stalled`].
struct BoundedSocket {
    inner: WebSocket,
    write_timeout: Duration,
    stalled: bool,
}

impl BoundedSocket {
    fn new(inner: WebSocket) -> Self {
        Self {
            inner,
            write_timeout: WS_WRITE_TIMEOUT,
            stalled: false,
        }
    }

    async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        let write = self.inner.send(msg);
        bounded_write(&mut self.stalled, self.write_timeout, write).await
    }

    async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        self.inner.recv().await
    }

    /// A write timed out; the connection should close.
    fn stalled(&self) -> bool {
        self.stalled
    }
}

/// Run `write` within `limit`. A timeout marks the socket `stalled`, and a
/// stalled socket's writes fail without being attempted. Either way the
/// caller sees an error, so nothing is reported as written that wasn't.
async fn bounded_write<F>(stalled: &mut bool, limit: Duration, write: F) -> Result<(), axum::Error>
where
    F: std::future::Future<Output = Result<(), axum::Error>>,
{
    if *stalled {
        return Err(axum::Error::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "an earlier WebSocket write timed out",
        )));
    }
    match tokio::time::timeout(limit, write).await {
        Ok(result) => result,
        Err(_) => {
            *stalled = true;
            metrics::counter!(WS_WRITE_TIMEOUTS_TOTAL).increment(1);
            Err(axum::Error::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "WebSocket write did not complete within {}s",
                    limit.as_secs()
                ),
            )))
        }
    }
}

/// RFC 6455 close codes the mediator uses, so clients learn *why* a socket was
/// closed instead of seeing a bare close.
mod close_code {
    /// Normal closure (graceful end / client-initiated).
    pub const NORMAL: u16 = 1000;
    /// Endpoint going away — peer unresponsive or the stream ended.
    pub const GOING_AWAY: u16 = 1001;
    /// Policy violation — auth expired, per-DID cap, duplicate displacement.
    pub const POLICY: u16 = 1008;
    /// A message larger than the mediator accepts.
    #[cfg(feature = "tsp")]
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    /// Unexpected server-side condition.
    pub const SERVER_ERROR: u16 = 1011;
    /// Transient capacity limit — try again later.
    pub const TRY_AGAIN_LATER: u16 = 1013;
}

/// The close a raw-TSP socket sends when the mediator refuses a message on it.
///
/// The code is the client's cue: 1009 (too big) and 1008 (refused) mean
/// resending the same message will not help; 1013 means it may. Every
/// server-side failure is the same 1013, so the close tells a client whether to
/// retry and nothing about the state of the mediator behind it.
#[cfg(feature = "tsp")]
fn tsp_refusal_close(error: &MediatorError) -> (u16, &'static str) {
    let status = match error {
        MediatorError::MediatorError(_, _, _, _, status, _) => *status,
        _ => 500,
    };
    match status {
        413 => (
            close_code::MESSAGE_TOO_BIG,
            "TSP message exceeds the mediator's message size limit",
        ),
        500..=599 => (
            close_code::TRY_AGAIN_LATER,
            "TSP message not accepted now; try again later",
        ),
        _ => (close_code::POLICY, "TSP message refused"),
    }
}

/// How long an anonymous inter-mediator relay socket may stay open.
///
/// A relay hop presents no JWT, so there is no token expiry to inherit and
/// nothing would otherwise bound the connection. An hour keeps the peer's
/// pooled socket useful while still forcing it to be re-admitted periodically
/// — re-running the relay-enabled check against current configuration, which
/// is what makes turning relay *off* take effect without a restart.
const RELAY_SOCKET_LIFETIME_SECS: u64 = 3600;

/// The error code and reason to hand back in a negative [`RelayAck`].
///
/// A mediator problem report already carries both, and they are what the
/// relaying peer logs (and, once the message is abandoned, what reaches the
/// original sender). Anything without a problem report is an internal failure
/// the peer cannot act on beyond retrying, so it becomes a bare 500.
fn relay_refusal(error: &MediatorError) -> (u16, String) {
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
fn reserve(registry: &DashMap<String, u32>, key: &str) -> u32 {
    let mut entry = registry.entry(key.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

/// The key a relay socket is counted under: its client address, resolved as
/// the per-IP rate limiter resolves it (through `server.trust_xff_cidrs`).
/// `None` when there is no peer address or a trusted proxy sent an unreadable
/// `X-Forwarded-For` chain.
fn relay_source_key(
    state: &SharedData,
    connect_info: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    headers: &HeaderMap,
) -> Option<String> {
    let Extension(ConnectInfo(peer)) = connect_info?;
    state
        .client_ip
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
struct RelayMeter {
    frames: governor::DefaultDirectRateLimiter,
    bytes: governor::DefaultDirectRateLimiter,
    refused: u64,
}

impl RelayMeter {
    fn new(limits: &crate::common::config::limits::LimitsConfig) -> Self {
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
    fn admit(&mut self, len: usize) -> Result<(), &'static str> {
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
    fn first_refusal(&self) -> bool {
        self.refused == 1
    }
}

/// Build a close message carrying an RFC 6455 code + human-readable reason.
fn close_with(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// WebSocket state machine. This is spawned per connection.
async fn handle_socket(
    socket: WebSocket,
    state: SharedData,
    mut session: Session,
    // `Some(client address)` for an anonymous inter-mediator relay socket: it
    // may push frames and receives nothing but the `RelayAck` answers to them.
    relay_source: Option<String>,
    // A DID-multiplexing connection (design §7): carries member DIDs too.
    mux_mode: bool,
    #[cfg(feature = "tsp")] tsp_mode: bool,
    #[cfg(feature = "tsp")] tsp_ack_mode: bool,
) {
    let _span = span!(
        tracing::Level::INFO,
        "handle_socket",
        session = session.session_id
    );
    let is_relay = relay_source.is_some();
    async move {
        let mut socket = BoundedSocket::new(socket);

        // A token past its `exp` is still accepted by the upgrade within the
        // JWT leeway, but the socket lives only until `exp`. Refuse it here,
        // before anything is reserved or registered, rather than reserving a
        // connection that would have no lifetime left.
        let epoch = state.clock.unix_secs();
        if session.expires_at <= epoch {
            warn!("JWT access token has expired. Closing Session");
            let _ = socket
                .send(close_with(
                    close_code::POLICY,
                    "authentication token expired",
                ))
                .await;
            return;
        }

        // Enforce the global connection limit. From here the slot gives back
        // everything it holds on every return path.
        let mut slot = match ConnectionSlot::acquire(
            &state.active_websocket_count,
            state.config.limits.max_websocket_connections,
        ) {
            Ok(slot) => slot,
            Err(current) => {
                warn!("WebSocket connection limit reached ({}/{})", current, state.config.limits.max_websocket_connections);
                let _ = socket
                    .send(close_with(
                        close_code::TRY_AGAIN_LATER,
                        "server connection limit reached",
                    ))
                    .await;
                return;
            }
        };

        // Relay sockets share one bucket (below), so each client address may
        // hold only `relay_connections_per_ip` of them: one source cannot take
        // every relay slot from the other peers.
        if let Some(source) = &relay_source {
            let held = reserve(&state.relay_connections_per_ip, source);
            slot.hold_per_source(PerDidConnectionGuard {
                registry: state.relay_connections_per_ip.clone(),
                did_hash: source.clone(),
            });
            let cap = state.config.limits.relay_connections_per_ip;
            if held as usize > cap {
                metrics::counter!(RELAY_CONNECTIONS_REFUSED_TOTAL, "reason" => "per_ip").increment(1);
                warn!(source = %source, held, cap, "Relay WebSocket refused: per-address relay connection limit reached");
                drop(slot);
                let _ = socket
                    .send(close_with(
                        close_code::TRY_AGAIN_LATER,
                        "relay connection limit reached for this address",
                    ))
                    .await;
                return;
            }
        }

        // Enforce the per-DID connection cap (0 = unlimited). Reserve the slot
        // immediately and hand its guard to the connection slot, so it's
        // released with the global one on every return path; then reject if
        // this DID is over its cap.
        let per_did_count = reserve(&state.ws_connections_per_did, &session.did_hash);
        // Note for relay sockets: they carry no DID, so they all share the
        // empty-hash bucket and `max_websocket_connections_per_did` (default
        // 100) becomes the ceiling on *concurrent relay sockets across all
        // peers*, with `relay_connections_per_ip` above bounding each source's
        // share of it. The empty string cannot collide with a real DID's
        // bucket, which is a sha256 hash.
        slot.hold_per_did(PerDidConnectionGuard {
            registry: state.ws_connections_per_did.clone(),
            did_hash: session.did_hash.clone(),
        });
        let per_did_cap = state.config.limits.max_websocket_connections_per_did;
        if per_did_cap != 0 && per_did_count as usize > per_did_cap {
            warn!(
                "Per-DID WebSocket connection limit reached for {} ({}/{})",
                session.did_hash, per_did_count, per_did_cap
            );
            // Released before the close is written, which may take a while.
            drop(slot);
            let _ = socket
                .send(close_with(
                    close_code::POLICY,
                    "per-DID connection limit reached",
                ))
                .await;
            return;
        }

        slot.open(&state.database).await;

        // A mux connection shares its queue among many DIDs, so each gets a
        // fair share of it (design §7.2): per-DID slots on the way in, and a
        // round-robin writer on the way out. A direct socket keeps the plain
        // bounded channel.
        let mux_slots = mux_mode.then(|| {
            crate::mux::fair_queue::MuxSlots::new(state.config.limits.mux.max_channel_slots)
        });
        let mut fair = mux_slots
            .as_ref()
            .map(|_| crate::mux::fair_queue::FairOrder::<QueuedCommand>::default());

        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, mut rx): (Sender<QueuedCommand>, Receiver<QueuedCommand>) = mpsc::channel(
            mux_slots
                .as_ref()
                .map_or(WS_CHANNEL_SLOTS, |s| s.channel_capacity()),
        );

        // Raised by the streaming task when a live notification for this DID
        // had to be dropped (send queue full, or the global byte budget
        // exhausted). Nothing durable is lost — the message stays in the inbox
        // — but a client that only listens would never learn it is there.
        //
        // A flag rather than another queued frame, because the drop happens
        // exactly when there is no room to queue one. It is read below, after
        // every wake-up, so the signal goes out as soon as the socket is
        // moving again.
        let live_resync = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Starts in the past so the first drop is signalled immediately; the
        // floor exists to bound a *repeating* cost, not to delay the first one.
        let mut last_resync_sent = Instant::now() - MIN_RESYNC_INTERVAL;

        // A relay socket is push-only and must never be registered with the
        // streaming task. It has no DID, so it would register under the empty
        // did_hash — claiming that stream for an anonymous peer and pointing
        // live delivery at a socket that belongs to no account. Skipping the
        // registration is what makes "relays can only send" structural rather
        // than a matter of which messages we happen to handle: `rx` below can
        // never yield.
        if let Some(streaming) = &state.streaming_task
            && !is_relay
        {

            let start = StreamingUpdate {
                did_hash: session.did_hash.clone(),
                state: StreamingUpdateState::Register {
                    channel: tx.clone(),
                    session_id: session.session_id.clone(),
                    did: session.did.clone(),
                    resync: live_resync.clone(),
                    kind: EntryKind::Direct,
                    slots: mux_slots.clone(),
                },
            };
            match streaming.channel.send(start).await {
                Ok(_) => {
                    debug!("Sent start message to streaming task");
                    slot.registered(
                        streaming.channel.clone(),
                        &session.did_hash,
                        &session.session_id,
                        &tx,
                    );
                }
                Err(e) => {
                    warn!("Error sending start message to streaming task: {:?}", e);
                    return;
                }
            }

            // Raw-TSP mode is live by construction — enable it here.
            //
            // `Register` alone leaves the client in `StreamingClientState::
            // Registered` ("has a socket but has not enabled live delivery"),
            // and only `Start` promotes it to `Live`. The DIDComm client gets
            // there by sending `messagepickup/3.0/live-delivery-change`; a
            // raw-TSP socket has no such message — it carries binary TSP frames
            // and nothing else — so it stayed `Registered` forever. With the
            // client not live, `store_message` skips the streaming publish
            // entirely, so the `rx.recv()` re-drain arm below never fired and
            // the ONLY delivery this socket ever got was flush-on-connect.
            // Every frame that arrived after the socket came up was stored and
            // left sitting in the inbox: the sender saw a successful send and
            // the recipient heard nothing.
            //
            // Push delivery isn't an opt-in here the way it is for DIDComm —
            // it is the raw-TSP contract (flush-on-connect + delete-on-send),
            // so the socket declares itself live the moment it registers.
            #[cfg(feature = "tsp")]
            if tsp_mode {
                let live = StreamingUpdate {
                    did_hash: session.did_hash.clone(),
                    state: StreamingUpdateState::Start {
                        session_id: session.session_id.clone(),
                    },
                };
                match streaming.channel.send(live).await {
                    Ok(_) => {
                        debug!("Raw-TSP socket: enabled live delivery");
                    }
                    Err(e) => {
                        warn!("Error enabling live delivery for raw-TSP socket: {:?}", e);
                        return;
                    }
                }
            }
        }

        info!("Websocket connection established");

        // A mux connection admits its stored grants and tells the client its
        // nonce and members before anything else is written.
        #[cfg(feature = "tsp")]
        let mux_wire = if tsp_mode {
            crate::mux::connection::MuxWire::Tsp
        } else {
            crate::mux::connection::MuxWire::DidComm
        };
        #[cfg(not(feature = "tsp"))]
        let mux_wire = crate::mux::connection::MuxWire::DidComm;
        let mux_conn = if let Some(slots) = &mux_slots {
            let (conn, frames) = crate::mux::connection::open(
                &state,
                &session,
                tx.clone(),
                live_resync.clone(),
                slots.clone(),
                mux_wire,
            )
            .await;
            // A `tsp-mux` client has no other way to learn its nonce and
            // members, and must not be left inferring them (R6.2): with no
            // `ready` to send, the connection is not opened.
            let no_ready = frames.is_empty() && mux_wire == crate::mux::connection::MuxWire::Tsp;
            for frame in frames {
                if let Err(e) = socket.send(frame.into()).await {
                    warn!("Failed to send mux event to WebSocket client: {e}");
                }
            }
            if no_ready {
                warn!("tsp-mux connection not opened: its `ready` event could not be sealed");
                crate::mux::connection::close(&state, &session, &conn).await;
                slot.release().await;
                let _ = socket
                    .send(close_with(
                        close_code::SERVER_ERROR,
                        "mux connection could not be established",
                    ))
                    .await;
                return;
            }
            Some(conn)
        } else {
            None
        };
        // As before mux: a registered socket's channel is held open only by
        // the streaming task (and, for mux, the registry), so the socket
        // notices when they let go. An unregistered socket (relay, or no
        // streaming task) keeps its own sender so `rx` simply never yields.
        let _unregistered_tx = (is_relay || state.streaming_task.is_none()).then_some(tx);
        let mut mux_sweep = tokio::time::interval(Duration::from_secs(30));
        mux_sweep.reset();
        let mut mux_revalidate = tokio::time::interval(Duration::from_secs(
            state.config.limits.mux.revalidate_interval_secs.max(30),
        ));
        mux_revalidate.reset();
        // Members' account standing, re-checked in a task of its own so the
        // store reads never hold this loop up.
        #[allow(unused_mut)]
        let mut standing_every = Duration::from_secs(crate::mux::connection::STANDING_PASS_SECS);
        #[cfg(feature = "test-hooks")]
        if let Some(every) = crate::mux::connection::test_hooks::standing_pass_interval(&session.did_hash) {
            standing_every = every;
        }
        let mut mux_standing = tokio::time::interval(standing_every);
        mux_standing.reset();

        // The socket lives until the JWT Auth token expires. `expires_at` was
        // checked to be in the future on entry; the setup since may have
        // taken that time, which leaves a zero-length lifetime.
        let epoch = state.clock.unix_secs();
        let auth_timeout = tokio::time::sleep(Duration::from_secs(session.expires_at.saturating_sub(epoch)));
        tokio::pin!(auth_timeout);
        debug!(expires_in_secs = session.expires_at.saturating_sub(epoch), "WebSocket auth timeout set");

        // Periodic ping to detect dead connections
        let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
        ping_interval.reset(); // Skip the immediate first tick

        // Sent-but-not-yet-acked message ids, for `tsp-ack` mode only.
        //
        // In ack mode the mediator no longer deletes on send, so every drain
        // re-fetches the same un-acked messages and would re-send them on each
        // live-delivery wake-up — turning "may see a duplicate after a
        // reconnect" into "sees duplicates constantly". This set is what makes
        // redelivery a *recovery* mechanism rather than the steady state:
        // within one connection a frame is sent once, and the set dies with the
        // connection, so a reconnect legitimately re-sends whatever was never
        // acked.
        //
        // Bounded implicitly: it only ever holds ids the inbox still contains,
        // and it is pruned against each completed drain, so client acks remove
        // entries. The inbox itself is capped by
        // `queued_receive_messages_hard` and message expiry.
        #[cfg(feature = "tsp")]
        let mut tsp_inflight: std::collections::HashSet<String> = std::collections::HashSet::new();
        // On a `tsp-mux` socket the drain covers the members too.
        #[cfg(feature = "tsp")]
        let tsp_mux_conn = if tsp_mode { mux_conn.clone() } else { None };
        #[cfg(feature = "tsp")]
        let mut member_inflight = MemberInflight::new();
        // Principal wake-ups waiting for one drain (raw TSP). An inbox
        // redelivery queues one per message, and each drain walks the whole
        // inbox, so they are answered together once the queue is empty, or
        // after `TSP_DRAIN_COALESCE` of them under a steady stream.
        #[cfg(feature = "tsp")]
        let mut tsp_drain_owed: usize = 0;

        // Flush-on-connect for raw-TSP delivery: drain whatever is already queued
        // for this DID straight onto the socket before entering the live-delivery
        // loop. If the socket is already gone, exit cleanly.
        #[cfg(feature = "tsp")]
        if tsp_mode && drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, tsp_mux_conn.as_deref().map(|c| (c, &mut member_inflight, None)))
            .await
            .is_break() {
            if let Some(conn) = &mux_conn {
                crate::mux::connection::close(&state, &session, conn).await;
            }
            slot.release().await;
            info!("Websocket connection closed during TSP flush-on-connect");
            return;
        }

        // Inbound frame budget for a relay socket (see `RelayMeter`).
        let mut relay_meter = is_relay.then(|| RelayMeter::new(&state.config.limits));

        // Why this socket ends up closing — surfaced in the final close frame.
        let mut close_reason: (u16, &'static str) = (close_code::NORMAL, "normal closure");
        loop {
            // Checked at the top so it holds however the last pass ended,
            // including the arms that `continue`.
            if socket.stalled() {
                warn!("WebSocket write timed out; closing");
                close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                break;
            }
            select! {
                _ = &mut auth_timeout => {
                    debug!("Socket lifetime reached");
                    close_reason = if is_relay {
                        // No token was ever presented — this is the relay
                        // socket's bounded lifetime, and the peer should
                        // reconnect rather than go looking for a credential
                        // problem it doesn't have.
                        (close_code::POLICY, "relay socket lifetime reached")
                    } else {
                        (close_code::POLICY, "authentication token expired")
                    };
                    break;
                }
                value = socket.recv() => {
                    match value { Some(msg) => {
                        if let Ok(msg) = msg {
                            match msg {
                                Message::Text(msg) => {
                                    // A `tsp-mux` socket carries binary TSP frames
                                    // only; anything else is a protocol violation
                                    // by the principal, which closes the socket.
                                    #[cfg(feature = "tsp")]
                                    if tsp_mux_conn.is_some() {
                                        warn!("Text frame on a tsp-mux socket; closing");
                                        close_reason = (close_code::POLICY, "tsp-mux sockets carry TSP frames only");
                                        break;
                                    }
                                    if msg.len() > state.config.limits.ws_size {
                                        warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.limits.ws_size, msg.len());
                                        continue;
                                    }

                                    // A relay frame over the socket's budget is
                                    // refused with a negative ack, which sends the
                                    // relaying mediator to its REST fallback (where
                                    // the per-IP limiter applies) for that message.
                                    if let Some(meter) = relay_meter.as_mut()
                                        && let Err(limit) = meter.admit(msg.len())
                                    {
                                        metrics::counter!(RELAY_FRAMES_THROTTLED_TOTAL, "limit" => limit).increment(1);
                                        if meter.first_refusal() {
                                            warn!(limit, "Relay frame refused: socket over its frame budget; further refusals on this socket are logged at debug");
                                        } else {
                                            debug!(limit, "Relay frame refused: socket over its frame budget");
                                        }
                                        let ack = RelayAck::rejected(
                                            frame_id(msg.as_bytes()),
                                            StatusCode::TOO_MANY_REQUESTS.as_u16(),
                                            "relay frame rate exceeded; send again later",
                                        );
                                        match serde_json::to_string(&ack) {
                                            Ok(body) => {
                                                if let Err(e) = socket.send(Message::Text(body.into())).await {
                                                    warn!("Failed to send relay-ack: {e}");
                                                    close_reason = (close_code::GOING_AWAY, "peer disconnected");
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Couldn't serialise relay-ack: {e}");
                                                close_reason = (close_code::SERVER_ERROR, "could not acknowledge");
                                                break;
                                            }
                                        }
                                        continue;
                                    }

                                    if !is_relay {
                                        refresh_standing(&state, &mut session).await;
                                    }
                                    // Process the message, which also takes care of any storing and live-streaming of the message
                                    state.monitor.received(&session.did_hash, Channel::Websocket, Protocol::DidComm, msg.as_bytes());
                                    let outcome = crate::monitor::with_channel(Channel::Websocket, handle_inbound(&state, &session, &msg)).await;
                                    if let Err(e) = &outcome {
                                        state.monitor.refused(&session.did_hash, Channel::Websocket, Protocol::DidComm, msg.as_bytes(), e);
                                    }

                                    // A relay socket gets a `relay-ack` per frame instead of a
                                    // problem report. Two reasons it cannot have the latter: a
                                    // problem report is packed *to* `session.did`, which a relay
                                    // session does not have; and the relaying peer is a mediator
                                    // waiting on a transport answer, not a client reading its
                                    // inbox. The ack is what stops a refused frame from being
                                    // reported as delivered — see `relay_ack`.
                                    if is_relay {
                                        let ack = match &outcome {
                                            Ok(_) => RelayAck::accepted(frame_id(msg.as_bytes())),
                                            Err(e) => {
                                                warn!("Relay frame refused: {}", e);
                                                let (code, reason) = relay_refusal(e);
                                                RelayAck::rejected(frame_id(msg.as_bytes()), code, reason)
                                            }
                                        };
                                        match serde_json::to_string(&ack) {
                                            Ok(body) => {
                                                if let Err(e) = socket.send(Message::Text(body.into())).await {
                                                    warn!("Failed to send relay-ack: {e}");
                                                    close_reason = (close_code::GOING_AWAY, "peer disconnected");
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                // Unreachable for this type, and if it ever
                                                // happened the peer must not read silence as
                                                // success: drop the socket so it retries.
                                                warn!("Couldn't serialise relay-ack: {e}");
                                                close_reason = (close_code::SERVER_ERROR, "could not acknowledge");
                                                break;
                                            }
                                        }
                                        continue;
                                    }

                                    match outcome {
                                        Ok(_) => {}
                                        Err(e) => {
                                            warn!("WebSocket inbound error: {}", e);

                                            // Send a problem report to the sender
                                            #[cfg(feature = "didcomm")]
                                            match e {
                                                MediatorError::MediatorError(_, _, msg_id, problem_report, _, log_message) => {
                                                    match  _package_problem_report(&state, &session, msg_id, *problem_report).await {
                                                        Ok(msg) => {
                                                            warn!(log_message);
                                                            if let Err(e) = socket.send(Message::Text(msg.into())).await {
                                                                warn!("Failed to send message to WebSocket client: {e}");
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Error packaging problem report: {:?}", e);
                                                        }
                                                    }
                                                },
                                                other => {
                                                    // This is a generic error, we don't need to send a problem report
                                                    warn!("Error processing message: {:?}", other);
                                                }
                                            }
                                            #[cfg(not(feature = "didcomm"))]
                                            warn!("Error processing message: {:?}", e);

                                            continue;
                                        }
                                    };
                                }
                                Message::Ping(_) => {
                                    // Don't need to do anything, the library will automatically respond with a pong
                                }
                                Message::Pong(_) => {
                                    // Don't need to do anything
                                }
                                Message::Binary(msg) => {
                                    // The relay contract is Text frames answered by acks.
                                    // A binary frame on a relay socket is either a
                                    // confused peer or something that is not a peer at
                                    // all; either way it cannot be acknowledged, and
                                    // staying open would leave the sender waiting out the
                                    // ack timeout for every frame. Close instead, so it
                                    // falls back to REST immediately.
                                    if is_relay {
                                        warn!("Binary frame on a relay socket; closing");
                                        close_reason = (close_code::POLICY, "relay sockets carry text frames only");
                                        break;
                                    }
                                    if msg.len() > state.config.limits.ws_size {
                                        warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.limits.ws_size, msg.len());
                                        continue;
                                    }

                                    // A binary frame leading with the TSP magic byte (0xF8) is a
                                    // TSP message; route it to the TSP handler. Other binary frames
                                    // are UTF-8-decoded and handled as DIDComm exactly as before.
                                    if !is_relay {
                                        refresh_standing(&state, &mut session).await;
                                    }
                                    #[cfg(feature = "tsp")]
                                    if affinidi_tsp::is_tsp(&msg) {
                                        state.monitor.received(&session.did_hash, Channel::Websocket, Protocol::Tsp, &msg);
                                        if let Err(e) = crate::monitor::with_channel(Channel::Websocket, handle_inbound_tsp(&state, &session, &msg)).await {
                                            state.monitor.refused(&session.did_hash, Channel::Websocket, Protocol::Tsp, &msg, &e);
                                            warn!("WebSocket TSP inbound error: {}", e);
                                            // The sender's write already succeeded, so a refusal that is
                                            // only logged leaves it believing the message went (R1.1).
                                            // A raw-TSP socket has no in-band error frame: the one thing
                                            // it can say is why it is closing.
                                            //
                                            // A `tsp-mux` socket does have one: the
                                            // `refused` event, so one member's bad
                                            // frame does not take every member
                                            // offline. It closes only for a failure
                                            // of the principal itself (here, its
                                            // account blocked), or when the event
                                            // cannot be sealed — then closing is the
                                            // only report left.
                                            if let Some(conn) = &tsp_mux_conn
                                                && !session.acls.get_blocked()
                                                && let Some(frame) = crate::mux::connection::refused_event(&state, conn, &msg, &e).await
                                            {
                                                if let Err(e) = socket.send(frame.into()).await {
                                                    warn!("Failed to send mux refused event: {e}");
                                                    close_reason = (close_code::GOING_AWAY, "client disconnected");
                                                    break;
                                                }
                                                continue;
                                            }
                                            if tsp_mode {
                                                close_reason = tsp_refusal_close(&e);
                                                break;
                                            }
                                            // A DIDComm socket can carry the problem report itself.
                                            #[cfg(feature = "didcomm")]
                                            if let MediatorError::MediatorError(_, _, msg_id, problem_report, _, _) = e
                                                && let Ok(report) = _package_problem_report(&state, &session, msg_id, *problem_report).await
                                                && let Err(e) = socket.send(Message::Text(report.into())).await
                                            {
                                                warn!("Failed to send problem report to WebSocket client: {e}");
                                            }
                                        }
                                        continue;
                                    }

                                    // Same classification without the feature, for the
                                    // same reason as `message_inbound`: a TSP frame here
                                    // would otherwise fail `String::from_utf8` below and
                                    // be logged as an unprocessable binary frame, which
                                    // says nothing about TSP and nothing about why. The
                                    // frame is still dropped — decoding it genuinely
                                    // needs the feature — but it is now dropped by name.
                                    #[cfg(feature = "tsp")]
                                    if tsp_mux_conn.is_some() {
                                        warn!("Non-TSP binary frame on a tsp-mux socket; closing");
                                        close_reason = (close_code::POLICY, "tsp-mux sockets carry TSP frames only");
                                        break;
                                    }

                                    #[cfg(not(feature = "tsp"))]
                                    if crate::handlers::message_inbound::looks_like_tsp_bytes(&msg) {
                                        warn!(
                                            "Dropping a TSP frame from {}: this mediator was built without \
                                             TSP support (cargo feature `tsp`). Rebuild with \
                                             `--features didcomm,tsp` to accept TSP traffic.",
                                            session.did_hash
                                        );
                                        continue;
                                    }

                                    let msg = match String::from_utf8(msg.into()) {
                                        Ok(msg) => msg,
                                        Err(e) => {
                                            warn!("Error processing binary message: {:?}", e);
                                            continue;
                                        }
                                    };

                                    state.monitor.received(&session.did_hash, Channel::Websocket, Protocol::DidComm, msg.as_bytes());
                                    match crate::monitor::with_channel(Channel::Websocket, handle_inbound(&state, &session, &msg)).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            state.monitor.refused(&session.did_hash, Channel::Websocket, Protocol::DidComm, msg.as_bytes(), &e);
                                            warn!("WebSocket inbound error: {}", e);
                                            continue;
                                        }
                                    };
                                }
                                Message::Close(_) => {
                                    debug!("Received close message, closing connection");
                                    break;
                                }
                            }
                        }
                    } _ => {
                        debug!("Received None, closing connection");
                        close_reason = (close_code::GOING_AWAY, "client disconnected");
                        break;
                    }}
                }
                _ = async { match &mux_conn { Some(c) => c.notify.notified().await, None => std::future::pending().await } } => {
                    if let Some(conn) = &mux_conn {
                        for frame in crate::mux::connection::drain_changes(&state, conn, mux_wire).await {
                            if let Err(e) = socket.send(frame.into()).await {
                                warn!("Failed to send mux event to WebSocket client: {e}");
                            }
                        }
                    }
                }
                _ = mux_sweep.tick(), if mux_conn.is_some() => {
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::sweep(&state, conn, false).await;
                    }
                }
                _ = mux_revalidate.tick(), if mux_conn.is_some() => {
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::sweep(&state, conn, true).await;
                    }
                }
                _ = mux_standing.tick(), if mux_conn.is_some() => {
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::spawn_standing_pass(&state, conn);
                    }
                }
                // A resync held back by the floor is sent when it falls due,
                // not whenever something else next wakes this loop (a ping,
                // up to a minute later). The body is empty: the resync check
                // after this select acts on it.
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(last_resync_sent + MIN_RESYNC_INTERVAL)),
                    if live_resync.load(std::sync::atomic::Ordering::Relaxed) => {}
                _ = ping_interval.tick() => {
                    if let Err(e) = socket.send(Message::Ping(vec![].into())).await {
                        debug!("Failed to send WebSocket ping: {e}");
                        close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                        break;
                    }
                }
                value = next_queued(&mut rx, fair.as_mut()) => {
                    if let Some(queued) = value {
                        // On a mux connection a member's frame is written only
                        // while the member holds `receive`, checked now rather
                        // than when it was queued: after a detach (revoke,
                        // expiry, key change) or a narrowing that dropped
                        // `receive`, nothing more is pushed for that DID. A
                        // member holding only `pickup` is told its mail waits
                        // instead. Either way the message stays in the
                        // member's inbox (§7.3, R1.1).
                        // A nudge must not `continue`: the resync it raises is
                        // acted on below, after this select, in this pass.
                        let mut write = true;
                        if let (Some(conn), Some(for_did)) = (&mux_conn, queued.did_hash.as_deref()) {
                            use crate::mux::registry::LiveFrame;
                            match conn.live_frame(for_did, state.clock.unix_secs()).await {
                                LiveFrame::Write => {}
                                LiveFrame::Nudge => {
                                    metrics::counter!(MUX_LIVE_FRAMES_WITHHELD_TOTAL, "outcome" => "nudge").increment(1);
                                    debug!(did_hash = %for_did, "pickup-only mux member has mail; resync raised");
                                    conn.nudge(for_did);
                                    write = false;
                                }
                                LiveFrame::Drop => {
                                    metrics::counter!(MUX_LIVE_FRAMES_WITHHELD_TOTAL, "outcome" => "drop").increment(1);
                                    debug!(did_hash = %for_did, "dropping a queued frame for a mux member without receive");
                                    continue;
                                }
                            }
                        }
                        // A stored message's delivery, reported only once its
                        // frame is written (R1.1).
                        let report = queued.report;
                        // Destructuring drops `_permit` at the end of this arm,
                        // returning the message's bytes to the global send pool
                        // once it has been written to the socket.
                        if write { match queued.cmd {
                            WebSocketCommands::Message(msg) => {
                                debug!("ws: Received message from streaming task");
                                // On a `tsp-mux` socket a member's notification
                                // is that member's live frame, written as it is:
                                // its stored inbox is walked only by a drain, and
                                // only with `pickup`.
                                #[cfg(feature = "tsp")]
                                if let Some(conn) = &tsp_mux_conn
                                    && let Some(for_did) = queued.did_hash.as_deref()
                                    && for_did != session.did_hash
                                {
                                    match send_tsp_member_live(conn, for_did, state.clock.unix_secs(), &mut socket, &msg, &mut member_inflight).await {
                                        ControlFlow::Break(()) => {
                                            close_reason = (close_code::GOING_AWAY, "client disconnected");
                                            break;
                                        }
                                        ControlFlow::Continue(true) => {
                                            if let Some(r) = report {
                                                r.written(&state).await;
                                            }
                                        }
                                        ControlFlow::Continue(false) => {}
                                    }
                                    continue;
                                }
                                // In raw-TSP mode the notification body carries no id we can
                                // delete by, so it's just a wake-up: re-drain the inbox (which
                                // re-fetches with ids, sends Binary, and deletes-on-send). The
                                // DIDComm path is unchanged — send the body as Text.
                                #[cfg(feature = "tsp")]
                                let raw_tsp = tsp_mode;
                                #[cfg(not(feature = "tsp"))]
                                let raw_tsp = false;
                                if raw_tsp {
                                    // The body is ignored: the drain re-fetches
                                    // with ids and reports what it writes, so
                                    // this notification is not itself a
                                    // delivery. Answered after this select,
                                    // together with any queued behind it.
                                    drop(report);
                                    #[cfg(feature = "tsp")]
                                    {
                                        tsp_drain_owed += 1;
                                    }
                                } else {
                                    match socket.send(Message::Text(msg.into())).await {
                                        Ok(()) => {
                                            if let Some(r) = report {
                                                r.written(&state).await;
                                            }
                                        }
                                        Err(e) => warn!("Failed to send message to WebSocket client: {e}"),
                                    }
                                }
                            },
                            WebSocketCommands::Verbatim(body) => {
                                // The body IS the frame: a monitor batch,
                                // pushed and stored nowhere, so there is no
                                // inbox to drain for it. A raw-TSP socket gets
                                // it as the Binary qb2 its client expects,
                                // decoded from the base64url the live channel
                                // carries; every other socket gets it as Text,
                                // the same shape an ordinary push has.
                                #[cfg(feature = "tsp")]
                                if tsp_mode {
                                    match BASE64_URL_SAFE_NO_PAD.decode(&body) {
                                        Ok(qb2) => {
                                            match socket.send(Message::Binary(qb2.into())).await {
                                                Ok(()) => {
                                                    if let Some(r) = report {
                                                        r.emit(&state.monitor);
                                                    }
                                                }
                                                Err(e) => warn!("Failed to send frame to WebSocket client: {e}"),
                                            }
                                        }
                                        Err(e) => warn!(
                                            did_hash = %session.did_hash,
                                            "dropping a verbatim frame that isn't base64url: {e}"
                                        ),
                                    }
                                    continue;
                                }
                                match socket.send(Message::Text(body.into())).await {
                                    Ok(()) => {
                                        if let Some(r) = report {
                                            r.emit(&state.monitor);
                                        }
                                    }
                                    Err(e) => warn!("Failed to send frame to WebSocket client: {e}"),
                                }
                            },
                            WebSocketCommands::MemberChange(change) => {
                                if let Some(conn) = &mux_conn
                                    && let Some(frame) = crate::mux::connection::on_member_change(&state, conn, change, mux_wire).await
                                    && let Err(e) = socket.send(frame.into()).await
                                {
                                    warn!("Failed to send mux event to WebSocket client: {e}");
                                }
                            }
                            WebSocketCommands::Close(why) => {
                                // A raw-TSP socket carries TSP frames only, so
                                // it gets no DIDComm problem report: the close
                                // frame's code and reason say why.
                                #[cfg(feature = "tsp")]
                                let raw_tsp = tsp_mode;
                                #[cfg(not(feature = "tsp"))]
                                let raw_tsp = false;
                                #[cfg(feature = "didcomm")]
                                if !raw_tsp
                                    && let Ok(msg) =  _package_problem_report(&state, &session, None, _close_problem_report(why)).await
                                    && let Err(e) = socket.send(Message::Text(msg.into())).await
                                {
                                    warn!("Failed to send message to WebSocket client: {e}");
                                }
                                #[cfg(not(feature = "didcomm"))]
                                let _ = raw_tsp;
                                debug!(reason = ?why, "Streaming task requested close");
                                // The streaming task has dropped this socket's
                                // registration (e.g. a newer socket replaced it);
                                // deregistering now would remove the successor.
                                slot.deregistered_by_streaming();
                                close_reason = _close_frame_reason(why);
                                break;
                            }
                        } }
                    } else {
                        debug!("Received None from streaming task, closing connection");
                        close_reason = (close_code::SERVER_ERROR, "streaming task unavailable");
                        break;
                    }
                }
            }

            // Principal wake-ups, answered by one drain once nothing more is
            // queued behind them (raw TSP).
            #[cfg(feature = "tsp")]
            if tsp_drain_owed > 0 && (rx.is_empty() || tsp_drain_owed >= TSP_DRAIN_COALESCE) {
                tsp_drain_owed = 0;
                if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, None)
                    .await
                    .is_break()
                {
                    close_reason = (close_code::GOING_AWAY, "client disconnected");
                    break;
                }
            }

            // A live notification was dropped while this socket was congested.
            // `swap` rather than load-then-clear: many drops collapse into one
            // signal, and clearing before the send means a drop landing during
            // it raises the flag again rather than being folded into a signal
            // already on its way out.
            //
            // The flag is *read*, not swapped, until the floor has elapsed:
            // clearing it early is how a deferred signal gets lost, so it stays
            // raised and the next wake-up past the floor carries it. That is
            // also why the suppressed count is a separate metric — under
            // sustained congestion a flat resync count is correct, not a fault.
            let raised = live_resync.load(std::sync::atomic::Ordering::Relaxed);
            if raised && !resync_due(raised, last_resync_sent.elapsed()) {
                metrics::counter!(WS_LIVE_RESYNC_SUPPRESSED).increment(1);
            }
            if resync_due(raised, last_resync_sent.elapsed()) {
                // Cleared before the send, so a drop landing during it raises
                // the flag again rather than being folded into a signal already
                // on its way out.
                live_resync.store(false, std::sync::atomic::Ordering::Relaxed);
                last_resync_sent = Instant::now();
                metrics::counter!(WS_LIVE_RESYNC_SENT).increment(1);
                #[cfg(feature = "tsp")]
                if tsp_mode {
                    // A TSP notification is only ever a wake-up, so the resync
                    // *is* the drain — there is no separate signal to send.
                    //
                    // On `tsp-mux` the resync is owed per DID, as on a DIDComm
                    // mux connection: the members whose pushes were dropped
                    // are drained (those with `pickup`; a `receive`-only
                    // member's frames stay stored for its next connection).
                    // The principal's own inbox is always drained, which is
                    // cheap and safe under ack mode.
                    let owed: Option<std::collections::HashSet<String>> = mux_slots
                        .as_ref()
                        .filter(|_| tsp_mux_conn.is_some())
                        .map(|slots| slots.take_resync().into_iter().collect());
                    if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, tsp_mux_conn.as_deref().map(|c| (c, &mut member_inflight, owed.as_ref())))
                        .await
                        .is_break()
                    {
                        close_reason = (close_code::GOING_AWAY, "client disconnected");
                        break;
                    }
                    continue;
                }
                // Whose inbox each status reports. A direct socket carries one
                // DID. A mux connection's resync is owed per DID, to the ones
                // whose pushes were dropped, and never to a member that has
                // left since (R7.2); the statuses all go to the principal.
                // A status is message pickup for that inbox, so a member is
                // reported only while its scope includes `pickup`; a
                // `receive`-only member's dropped frame stays in its inbox,
                // where the principal could not collect it anyway.
                #[cfg(feature = "didcomm")]
                let owed: Vec<(String, String)> = match (&mux_conn, &mux_slots) {
                    (Some(conn), Some(slots)) => {
                        let hashes = slots.take_resync();
                        let now = state.clock.unix_secs();
                        let s = conn.session.lock().await;
                        hashes
                            .into_iter()
                            .filter_map(|h| {
                                if h == session.did_hash {
                                    Some((session.did.clone(), h))
                                } else if s.allows(
                                    &h,
                                    affinidi_messaging_mediator_common::store::mux::MuxCapability::Pickup,
                                    now,
                                ) {
                                    s.get(&h).map(|m| (m.did.clone(), h))
                                } else {
                                    None
                                }
                            })
                            .collect()
                    }
                    _ => vec![(session.did.clone(), session.did_hash.clone())],
                };
                #[cfg(feature = "didcomm")]
                for (did, did_hash) in owed {
                    match _package_status_for(&state, &session, &did, &did_hash).await {
                        Ok(packed) => {
                            if let Err(e) = socket.send(Message::Text(packed.into())).await {
                                warn!("Failed to send resync status to WebSocket client: {e}");
                            } else {
                                debug!(
                                    did_hash = %did_hash,
                                    "sent message-pickup status after a dropped live notification"
                                );
                            }
                        }
                        Err(e) => {
                            // Leave the flag down: a failure to *build* the status
                            // will fail identically next time, and re-raising it
                            // would spin. The client still recovers on its next
                            // poll; this is the enhancement failing, not delivery.
                            warn!("Couldn't build resync status for {did_hash}: {e}");
                        }
                    }
                }
            }
        }

        if let Some(conn) = &mux_conn {
            crate::mux::connection::close(&state, &session, conn).await;
        }

        // Deregister from the streaming task (unless it closed this socket
        // itself; a relay socket was never registered), release the
        // connection count and gauge, and record the close.
        slot.release().await;

        // We're done, close the connection with the reason that ended the loop.
        if let Err(e) = socket
            .send(close_with(close_reason.0, close_reason.1))
            .await
        {
            debug!("Failed to send WebSocket close frame: {e}");
        }

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
}

/// The next command for the socket loop. A direct socket reads its channel in
/// order, as it always has; a mux connection reads it through its fair order
/// (design §7.2). Cancel-safe either way.
async fn next_queued(
    rx: &mut Receiver<QueuedCommand>,
    fair: Option<&mut crate::mux::fair_queue::FairOrder<QueuedCommand>>,
) -> Option<QueuedCommand> {
    match fair {
        None => rx.recv().await,
        Some(fair) => fair.next(rx).await,
    }
}

/// The most principal wake-ups one TSP drain answers while more keep
/// arriving; past this it drains anyway, so a steady stream is still
/// delivered.
#[cfg(feature = "tsp")]
const TSP_DRAIN_COALESCE: usize = 64;

/// Page size for the TSP inbox drain — reuses the same shape as
/// [`crate::tasks::websocket_streaming`]'s redelivery drain.
#[cfg(feature = "tsp")]
const TSP_DRAIN_PAGE: usize = 50;

/// Safety bound on how many messages a single TSP drain will push, so a
/// pathologically large inbox can't pin the socket loop. If hit, the
/// remainder is left for the next drain (the next live-delivery wake-up
/// re-fetches from the head of the inbox).
#[cfg(feature = "tsp")]
const TSP_DRAIN_MAX: usize = 1000;

/// Drain the recipient's undelivered inbox to a **raw TSP** WebSocket,
/// inline on the connection. Each stored message is decoded to its raw qb2
/// bytes and sent as a `Binary` frame; what happens next depends on the mode
/// the client negotiated at the upgrade.
///
/// ## `ack_mode = false` (subprotocol `tsp`) — delete-on-send, at-most-once
///
/// The socket write itself is treated as the ack: the message is deleted the
/// moment `send` returns. A successful `send` means the frame was accepted by
/// the local sink, **not** that the peer received it, so a connection that
/// drops between the write and the peer reading it loses the message with
/// nothing left to redeliver — the mediator has already forgotten it. This is
/// the historical behaviour and is kept for compatibility. It is appropriate
/// for a liveness probe and not for anything that matters.
///
/// (If the *send* fails, the socket is gone and the message and the rest of
/// the inbox are left intact for the next connection.)
///
/// ## `ack_mode = true` (subprotocol `tsp-ack`) — delete-to-ack, at-least-once
///
/// The mediator sends and keeps. The client acknowledges out of band, by
/// deleting the message through the ordinary authenticated delete path once it
/// has actually taken the frame; the id is `sha256` of the stored body, which
/// is exactly the bytes on the wire, so the client derives it without the
/// mediator sending ids and without any change to the frame format. A message
/// the client never acks is simply still in the inbox on the next connect and
/// is redelivered — so a consumer may see a duplicate, and must be idempotent,
/// which is the standard trade for not losing messages.
///
/// Un-acked messages are bounded by the same limits as any other queued
/// message (`queued_receive_messages_hard`, message expiry); nothing new can
/// grow without limit here.
///
/// ## On a `tsp-mux` socket (`members` is the connection)
///
/// When `members` is given, the principal's inbox is drained first and then
/// each attached member's whose scope includes `pickup` (all of them, or only
/// those named by the third element: the DIDs owed a resync), round-robin, one page
/// of [`TSP_MUX_MEMBER_PAGE`] per member per round, so one deep inbox cannot
/// hold the rest back. The socket loop asks for that on connect and on a
/// resync; the principal's own notifications drain the principal only, so a
/// busy principal does not re-walk every member's inbox per message. The mode
/// is always ack mode (`tsp-mux` implies `tsp-ack`), so nothing is deleted on
/// send: a member's frames go only when the client acks them, and the ack is
/// authorised against that member's `delete` scope by the delete path. A
/// member without `delete` therefore keeps its frames in its inbox.
/// Membership and scope are re-read before every page, so a member detached
/// mid-drain gets nothing more. Each member has its own in-flight set,
/// pruned only by a complete walk of that member's inbox.
///
/// Returns:
/// - [`ControlFlow::Break`] when the socket send failed (caller should
///   tear the connection down).
/// - [`ControlFlow::Continue`] when the inbox is drained (or the safety
///   cap was hit) and the connection should keep running.
#[cfg(feature = "tsp")]
async fn drain_tsp_inbox(
    state: &SharedData,
    session: &Session,
    socket: &mut BoundedSocket,
    ack_mode: bool,
    inflight: &mut std::collections::HashSet<String>,
    members: Option<(
        &crate::mux::registry::MuxConn,
        &mut MemberInflight,
        Option<&std::collections::HashSet<String>>,
    )>,
) -> ControlFlow<(), ()> {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    // Delete-on-send is never used for a member: `tsp-mux` forces ack mode.
    debug_assert!(ack_mode || members.is_none());
    let mut walk = TspDrainWalk {
        budget: TSP_DRAIN_MAX,
        total: 0,
    };

    // The principal's own inbox, to the end. Every id walked past (ack mode
    // only) is kept, to prune `inflight` against once the walk completes, so
    // ids the client has since acked stop occupying the set.
    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    loop {
        match drain_tsp_page(
            state,
            session,
            &session.did_hash,
            socket,
            ack_mode,
            inflight,
            &mut seen,
            &mut walk,
            &mut cursor,
            TSP_DRAIN_PAGE,
        )
        .await
        {
            TspPage::SocketGone => return ControlFlow::Break(()),
            // Returns WITHOUT pruning `inflight`, deliberately: only a
            // complete walk proves an absent id was acked, and pruning against
            // a walk cut short by the cap (or a failed fetch) would resurrect
            // still-in-flight messages as duplicates.
            TspPage::Stopped => return ControlFlow::Continue(()),
            TspPage::More => continue,
            TspPage::Exhausted => break,
        }
    }
    if ack_mode {
        // Anything no longer in the inbox has been acked (or expired): drop it
        // so the set tracks only what is genuinely outstanding.
        inflight.retain(|id| seen.contains(id));
    }

    // Then each member with `pickup`, a page at a time, round-robin.
    if let Some((conn, member_inflight, only)) = members {
        let now = state.clock.unix_secs();
        let candidates: Vec<crate::mux::session::MuxMember> = {
            let s = conn.session.lock().await;
            // A member no longer attached has nothing in flight here.
            member_inflight.retain(|did_hash, _| s.get(did_hash).is_some());
            s.members()
                .filter(|m| only.is_none_or(|o| o.contains(&m.did_hash)))
                .filter(|m| s.allows(&m.did_hash, MuxCapability::Pickup, now))
                .cloned()
                .collect()
        };
        // Each member's account must still stand before its inbox is walked;
        // one whose standing has lapsed is detached, with its event.
        let mut order: Vec<String> = Vec::with_capacity(candidates.len());
        for m in candidates {
            if crate::mux::connection::member_stands(state, conn, &m).await {
                order.push(m.did_hash);
            }
        }
        order.sort();
        let mut walks: std::collections::HashMap<
            String,
            (Option<String>, std::collections::HashSet<String>),
        > = std::collections::HashMap::new();
        while !order.is_empty() {
            let mut still: Vec<String> = Vec::with_capacity(order.len());
            for member in order {
                // Still attached, still with `pickup`? Re-read per page: a
                // detach between pages must stop this member's frames (§7.3).
                let allowed = conn.session.lock().await.allows(
                    &member,
                    MuxCapability::Pickup,
                    state.clock.unix_secs(),
                );
                if !allowed {
                    continue;
                }
                let (cursor, seen) = walks.entry(member.clone()).or_default();
                let inflight = member_inflight.entry(member.clone()).or_default();
                match drain_tsp_page(
                    state,
                    session,
                    &member,
                    socket,
                    ack_mode,
                    inflight,
                    seen,
                    &mut walk,
                    cursor,
                    TSP_MUX_MEMBER_PAGE,
                )
                .await
                {
                    TspPage::SocketGone => return ControlFlow::Break(()),
                    TspPage::Stopped => return ControlFlow::Continue(()),
                    TspPage::More => still.push(member),
                    // This member's walk is complete: prune its set.
                    TspPage::Exhausted => inflight.retain(|id| seen.contains(id)),
                }
            }
            order = still;
        }
    }

    if walk.total > 0 {
        debug!(
            did_hash = %session.did_hash,
            total = walk.total,
            awaiting_ack = inflight.len(),
            "TSP inbox drain complete"
        );
    }
    ControlFlow::Continue(())
}

/// Members' pages are smaller than the principal's, so a round over many
/// members stays short.
#[cfg(feature = "tsp")]
const TSP_MUX_MEMBER_PAGE: usize = 20;

/// The most ids one member's in-flight set holds. A set is pruned by a
/// complete drain of the member's inbox, which happens on connect and resync
/// only, and a member without `pickup` is never drained, so live frames
/// alone would grow it for the life of the connection. Past this the set is
/// cleared; the cost is a possible duplicate, which an at-least-once client
/// already handles.
#[cfg(feature = "tsp")]
const TSP_MUX_MEMBER_INFLIGHT_MAX: usize = 1024;

/// In-flight ids per member DID hash, on a `tsp-mux` socket.
#[cfg(feature = "tsp")]
type MemberInflight = std::collections::HashMap<String, std::collections::HashSet<String>>;

/// The budget shared by every page of one drain.
#[cfg(feature = "tsp")]
struct TspDrainWalk {
    /// Frames this drain may still send ([`TSP_DRAIN_MAX`] in all).
    budget: usize,
    total: usize,
}

/// How one page of a drain ended.
#[cfg(feature = "tsp")]
enum TspPage {
    /// The socket is gone; nothing more was written or deleted.
    SocketGone,
    /// The fetch failed or the drain's cap was reached: stop this drain
    /// without pruning `inflight`.
    Stopped,
    /// The page was full; the inbox may hold more.
    More,
    /// The inbox has nothing after the cursor.
    Exhausted,
}

/// Write one page of `did_hash`'s inbox after `cursor` to the socket.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "tsp")]
async fn drain_tsp_page(
    state: &SharedData,
    session: &Session,
    did_hash: &str,
    socket: &mut BoundedSocket,
    ack_mode: bool,
    inflight: &mut std::collections::HashSet<String>,
    seen: &mut std::collections::HashSet<String>,
    walk: &mut TspDrainWalk,
    cursor: &mut Option<String>,
    limit: usize,
) -> TspPage {
    let options = FetchOptions {
        limit,
        start_id: cursor.clone(),
        ..Default::default() // delete_policy defaults to DoNotDelete; we delete explicitly.
    };
    // Fetched without stamping: a message is recorded as delivered only once
    // its frame is written (R1.1), so one this drain skips (not a TSP frame:
    // a DIDComm message for this DID) keeps its expiry. Paging needs stream
    // order, so round-robin applies to a first page only, as in
    // `fetch_messages_delivering`.
    let fetched = if state.config.limits.pickup_round_robin && options.start_id.is_none() {
        state
            .database
            .fetch_messages_fair(&session.session_id, did_hash, &options)
            .await
    } else {
        state
            .database
            .fetch_messages(&session.session_id, did_hash, &options)
            .await
    };
    let page = match fetched {
        Ok(page) => page,
        Err(err) => {
            warn!(
                %did_hash,
                "TSP inbox drain fetch failed, aborting drain: {err}"
            );
            return TspPage::Stopped;
        }
    };
    if page.success.is_empty() {
        return TspPage::Exhausted;
    }

    let mut written: Vec<String> = Vec::new();
    let outcome = drain_tsp_elements(
        state,
        session,
        did_hash,
        socket,
        ack_mode,
        inflight,
        seen,
        walk,
        cursor,
        page.success,
        &mut written,
    )
    .await;
    if let Err(err) = state
        .database
        .record_delivered(
            &written,
            state.clock.unix_millis() as u64,
            state.config.limits.delivered_expiry_seconds,
        )
        .await
    {
        warn!(%did_hash, "couldn't record {} TSP frames as delivered: {err}", written.len());
    }
    outcome
}

/// Write `elements` (one fetched page) to the socket, adding each written
/// message's id to `written`.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "tsp")]
async fn drain_tsp_elements(
    state: &SharedData,
    session: &Session,
    did_hash: &str,
    socket: &mut BoundedSocket,
    ack_mode: bool,
    inflight: &mut std::collections::HashSet<String>,
    seen: &mut std::collections::HashSet<String>,
    walk: &mut TspDrainWalk,
    cursor: &mut Option<String>,
    elements: Vec<affinidi_messaging_sdk::messages::MessageListElement>,
    written: &mut Vec<String>,
) -> TspPage {
    for element in elements {
        // Advance the cursor regardless of body presence so a missing body
        // can't pin the drain on the same page forever. `receive_id` is the
        // inbox stream id, used as the exclusive fetch cursor.
        *cursor = element.receive_id.clone();

        let parties = (element.from_address.clone(), element.to_address.clone());
        let size = element.size;
        let Some(body) = element.msg else { continue };
        // Deletion keys on `msg_id` (the message hash) — the same key the
        // optimistic-delete fetch path uses; `receive_id` is only the stream
        // cursor, not a valid delete key.
        let id = element.msg_id;
        if ack_mode {
            seen.insert(id.clone());
            // Already on the wire for this connection and not yet acked —
            // sending it again would duplicate within a single session.
            if inflight.contains(&id) {
                continue;
            }
        }

        // Stored body is base64url(qb2). Decode back to raw qb2 bytes for
        // the wire. Anything else (a DIDComm message for this DID, or a
        // malformed entry) is skipped, not deleted: a raw-TSP socket carries
        // TSP frames only, and the message stays for a client that can read
        // it.
        let qb2 = match BASE64_URL_SAFE_NO_PAD.decode(&body) {
            Ok(bytes) if affinidi_tsp::is_tsp(&bytes) => bytes,
            Ok(_) => {
                debug!(%did_hash, message_id = %id, "not a TSP frame; left for another client");
                continue;
            }
            Err(_) => {
                debug!(%did_hash, message_id = %id, "not a TSP frame (not base64url); left for another client");
                continue;
            }
        };

        if let Err(e) = socket.send(Message::Binary(qb2.into())).await {
            // The socket is gone — leave this message and the rest of the
            // inbox in place for the next connection (do NOT delete).
            warn!("Failed to send TSP message to WebSocket client: {e}");
            return TspPage::SocketGone;
        }
        // Only once it is on the wire.
        written.push(id.clone());
        state.monitor.delivered(
            &id,
            parties.0.as_deref(),
            parties.1.as_deref(),
            size,
            Channel::Websocket,
            Some(&body),
        );

        if ack_mode {
            // Delete-to-ack: the write is not the acknowledgement, so keep
            // the message. The client deletes it once it has taken the
            // frame; until then it stays recoverable across a reconnect.
            inflight.insert(id.clone());
            debug!(
                %did_hash,
                message_id = %id,
                "Sent TSP message, awaiting client ack (tsp-ack mode)"
            );
        } else {
            // Delete-on-send: delivered as far as this mode is concerned. A
            // delete error is logged but not fatal — the frame is already
            // on the wire, so we continue.
            match state
                .database
                .delete_message(
                    &id,
                    DeletionAuthority::Owner {
                        did_hash: did_hash.to_string(),
                    },
                )
                .await
            {
                Ok(()) => state.monitor.deleted(
                    &id,
                    did_hash,
                    parties.0.as_deref(),
                    parties.1.as_deref(),
                    Channel::Websocket,
                    // The frame this drain just sent: a TSP body, stored
                    // base64url, which is what `detect` reads.
                    Some(body.as_str()),
                ),
                Err(err) => warn!(
                    %did_hash,
                    message_id = %id,
                    "Failed to delete delivered TSP message: {err}"
                ),
            }
        }

        walk.total += 1;
        walk.budget = walk.budget.saturating_sub(1);
        if walk.budget == 0 {
            warn!(
                did_hash = %session.did_hash,
                max = TSP_DRAIN_MAX,
                "TSP inbox drain hit its safety cap; remaining messages left for the next drain"
            );
            return TspPage::Stopped;
        }
    }
    TspPage::More
}

/// Write a mux member's live notification to a `tsp-mux` socket. Returns
/// `Continue(true)` once the frame is written.
///
/// The notification body is the stored message (base64url of the qb2), so it
/// is the frame itself. Writing it, rather than answering with a drain of the
/// member's inbox as the principal's notifications are answered, keeps a
/// `receive` wake-up from becoming a `pickup` drain: a member's stored inbox
/// is walked only for a member with `pickup` ([`drain_tsp_inbox`]). Ack mode
/// applies: the frame stays stored until the client acks it, and its
/// id joins `inflight` so a later drain does not send it again. A body that
/// is not a TSP message is not written; it stays in the member's inbox.
#[cfg(feature = "tsp")]
async fn send_tsp_member_live(
    conn: &crate::mux::registry::MuxConn,
    did_hash: &str,
    now: u64,
    socket: &mut BoundedSocket,
    body: &str,
    inflight: &mut MemberInflight,
) -> ControlFlow<(), bool> {
    // Checked by the caller already; re-checked here because this write is
    // the one that must not happen for a member without `receive` (§7.3, R1.1).
    if conn.live_frame(did_hash, now).await != crate::mux::registry::LiveFrame::Write {
        return ControlFlow::Continue(false);
    }
    let id = sha256::digest(body);
    let inflight = inflight.entry(did_hash.to_string()).or_default();
    if inflight.contains(&id) {
        return ControlFlow::Continue(false);
    }
    if inflight.len() >= TSP_MUX_MEMBER_INFLIGHT_MAX {
        inflight.clear();
    }
    let qb2 = match BASE64_URL_SAFE_NO_PAD.decode(body) {
        Ok(b) if affinidi_tsp::is_tsp(&b) => b,
        _ => {
            debug!(%did_hash, "not writing a non-TSP live frame to a tsp-mux socket; it stays stored");
            return ControlFlow::Continue(false);
        }
    };
    if let Err(e) = socket.send(Message::Binary(qb2.into())).await {
        warn!("Failed to send TSP message to WebSocket client: {e}");
        return ControlFlow::Break(());
    }
    inflight.insert(id);
    ControlFlow::Continue(true)
}

/// The problem report for a socket the streaming task is closing.
///
/// One report per [`CloseReason`], because the three are not the same event and
/// a client can only act on the difference. Until #1028 every one of them sent
/// `duplicate-channel` / "a new duplicate connection has caused this websocket
/// to terminate" — true of [`CloseReason::Replaced`], and the exact inverse of
/// what happened on the other two.
///
/// `duplicate-channel` is preserved verbatim for `Replaced`: it is the code
/// existing clients already match on, and the socket it goes to is the one whose
/// meaning never changed.
#[cfg(feature = "didcomm")]
fn _close_problem_report(why: CloseReason) -> ProblemReport {
    let (code, message) = match why {
        CloseReason::Replaced => (
            "duplicate-channel",
            "A new duplicate websocket connection for this DID has caused this websocket to \
             terminate"
                .to_string(),
        ),
        CloseReason::Refused => (
            "duplicate-channel-refused",
            "This DID already has a live websocket connection, which has been kept. This \
             connection was refused and nothing was displaced — something is running a second \
             live session for this DID."
                .to_string(),
        ),
        CloseReason::Unauthenticated => (
            "unauthenticated-session",
            "This session reached streaming registration without an authenticated DID, so it \
             cannot be routed to."
                .to_string(),
        ),
    };
    ProblemReport::new(
        ProblemReportSorter::Warning,
        ProblemReportScope::Other("websocket".to_string()),
        code.to_string(),
        message,
        vec![],
        None,
    )
}

/// The websocket close frame for a [`CloseReason`].
///
/// A client that never unpacks the problem report — one on the TSP-only build,
/// where the report is `didcomm`-gated and never sent at all — still has this to
/// go on, so the two must not disagree.
fn _close_frame_reason(why: CloseReason) -> (u16, &'static str) {
    match why {
        CloseReason::Replaced => (close_code::POLICY, "replaced by a newer connection"),
        CloseReason::Refused => (close_code::POLICY, "this DID already has a live connection"),
        CloseReason::Unauthenticated => (close_code::POLICY, "session has no authenticated DID"),
    }
}

/// Re-read the account's role and ACLs before a frame is handled.
///
/// A socket's `Session` is built once, at upgrade, and lives until its access
/// token expires (`jwt_access_expiry`, 15 minutes by default). Authorisation
/// reads `session.account_type` and `session.acls`, so without this a change to
/// the account reached a REST request at once — `get_session` re-joins the
/// account on every call — and a live socket not at all: an account promoted
/// to admin was refused on the socket it already had, and, the case that
/// matters, one **demoted or blocked** kept its old authority for the rest of
/// the token's life. This is the same join `get_session` does, applied per
/// frame. A store failure keeps what the session had, as that join does.
async fn refresh_standing(state: &SharedData, session: &mut Session) {
    match state.database.account_get(&session.did_hash).await {
        Ok(Some(account)) => {
            session.account_type = account._type;
            session.acls =
                affinidi_messaging_mediator_common::types::acls::MediatorACLSet::from_u64(
                    account.acls,
                );
        }
        Ok(None) => {}
        Err(e) => warn!(
            "couldn't refresh the account behind session {}: {e}",
            session.session_id
        ),
    }
}

/// Takes a problem report and packages it for sending to the recipient
#[cfg(feature = "didcomm")]
async fn _package_problem_report(
    state: &SharedData,
    session: &Session,
    msg_id: Option<String>,
    problem_report: ProblemReport,
) -> Result<String, MediatorError> {
    let mut pr_msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
        json!(problem_report),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(state.clock.unix_secs());

    if let Some(msg_id) = msg_id {
        pr_msg = pr_msg.pthid(msg_id);
    }

    let (packed, _) = didcomm_compat::pack_encrypted(
        &pr_msg.finalize(),
        &session.did,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|err| {
        MediatorError::MessagePackError(
            47,
            session.session_id.clone(),
            format!("Couldn't pack DIDComm message. Reason: {err}"),
        )
    })?;

    Ok(packed)
}

/// Build a packed message-pickup 3.0 `status` for this session's client.
///
/// Sent after a dropped live notification: `message_count` is read live from
/// the recipient's inbox, so the client is told what is actually waiting rather
/// than that *something* was missed. A client already understands this message
/// — it is the same one it gets for a `status-request` — so the resync needs no
/// new protocol on the client side.
///
/// It reports the inbox of `did`: the session's own DID, or a member of its
/// mux connection. Either way it is packed to the session's DID: on a mux
/// connection the principal is the party the control plane addresses
/// (design §7.5), and `recipient_did` says whose inbox it is.
#[cfg(feature = "didcomm")]
async fn _package_status_for(
    state: &SharedData,
    session: &Session,
    did: &str,
    did_hash: &str,
) -> Result<String, MediatorError> {
    let status = state.database.inbox_status(did_hash).await?;

    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/messagepickup/3.0/status".to_string(),
        json!({
            "recipient_did": did,
            "message_count": status.message_count,
            "live_delivery": true,
        }),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(state.clock.unix_secs())
    .finalize();

    let (packed, _) = didcomm_compat::pack_encrypted(
        &msg,
        &session.did,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|err| {
        MediatorError::MessagePackError(
            47,
            session.session_id.clone(),
            format!("Couldn't pack resync status. Reason: {err}"),
        )
    })?;

    Ok(packed)
}

#[cfg(test)]
mod close_reason_tests {
    use super::_close_frame_reason;
    use crate::tasks::websocket_streaming::CloseReason;

    /// A refused newcomer must not be told it was replaced.
    ///
    /// This is the whole defect. Before #1028 the refusal path reused the
    /// eviction path's close frame, so a client that had been kept *out* was
    /// told its connection had been taken *over* — and, having nothing truthful
    /// to render, showed a transport error. OpenVTC reported it as a network
    /// fault; it was two instances of the app.
    #[test]
    fn refusal_does_not_claim_the_socket_was_replaced() {
        let (_, refused) = _close_frame_reason(CloseReason::Refused);
        assert!(
            !refused.contains("replaced"),
            "the refused socket was not replaced — nothing of its own was \
             displaced — but it is told: {refused:?}"
        );
        assert!(
            refused.contains("already has a live connection"),
            "a refused client can only say \"you have this open twice\" if it is \
             told that; got: {refused:?}"
        );
    }

    /// Each reason is distinguishable, which is the property a client keys on.
    ///
    /// Asserted as a set rather than three equality checks: the failure being
    /// guarded against is two reasons collapsing onto one string, and equality
    /// checks pass happily while that happens elsewhere in the match.
    #[test]
    fn every_close_reason_is_distinct() {
        let all = [
            CloseReason::Replaced,
            CloseReason::Refused,
            CloseReason::Unauthenticated,
        ];
        let mut seen: Vec<&str> = all.iter().map(|r| _close_frame_reason(*r).1).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "two close reasons render the same text, so a client cannot tell them \
             apart: {seen:?}"
        );
    }

    /// The wording that existing clients already match on is unchanged.
    ///
    /// `Replaced` is the one situation the old shared message described
    /// correctly, so it keeps its exact text: this change is meant to give the
    /// other two a truthful signal, not to move the ground under anything
    /// already parsing this one.
    #[test]
    fn the_replaced_wording_is_preserved_verbatim() {
        assert_eq!(
            _close_frame_reason(CloseReason::Replaced).1,
            "replaced by a newer connection"
        );
    }
}

#[cfg(all(test, feature = "didcomm"))]
mod close_report_tests {
    use super::_close_problem_report;
    use crate::tasks::websocket_streaming::CloseReason;

    /// `duplicate-channel` is a wire code clients match on; only the socket
    /// whose meaning did not change may keep it.
    ///
    /// Asserted in the qualified form `ProblemReport::new` actually emits
    /// (`<sorter>.<scope>.<code>`) rather than the bare code passed in — that
    /// string is what reaches a client, and it is the thing a client matches.
    #[test]
    fn only_replacement_keeps_the_duplicate_channel_code() {
        assert_eq!(
            _close_problem_report(CloseReason::Replaced).code,
            "w.websocket.duplicate-channel",
            "existing clients match this; the replaced socket is the one case \
             the old wording described correctly, so it must not move"
        );
        assert_eq!(
            _close_problem_report(CloseReason::Refused).code,
            "w.websocket.duplicate-channel-refused",
            "a refused connection reported as `duplicate-channel` is \
             indistinguishable from having been evicted — which is what sent a \
             real investigation to the network layer"
        );
        assert_eq!(
            _close_problem_report(CloseReason::Unauthenticated).code,
            "w.websocket.unauthenticated-session",
            "an unauthenticated session is not a duplicate at all"
        );
    }

    /// The close frame and the problem report must agree.
    ///
    /// They travel independently — the report is `didcomm`-gated and the frame
    /// is not — so a client may see either one. Two sources of truth that can
    /// disagree is how the original bug read as a network fault in the first
    /// place.
    #[test]
    fn the_report_and_the_frame_tell_the_same_story() {
        for why in [
            CloseReason::Replaced,
            CloseReason::Refused,
            CloseReason::Unauthenticated,
        ] {
            let report = _close_problem_report(why);
            let (_, frame) = super::_close_frame_reason(why);
            let describes_replacement = |s: &str| {
                s.contains("replaced") || s.contains("caused this websocket to terminate")
            };
            assert_eq!(
                describes_replacement(&report.comment),
                describes_replacement(frame),
                "report and close frame disagree for {why:?}: {:?} vs {frame:?}",
                report.comment
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CorsOriginPolicy, MIN_RESYNC_INTERVAL, RelayMeter, app_subprotocols, bounded_write,
        extract_bearer_subprotocol, resync_due, ws_origin_allowed,
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

#[cfg(all(test, feature = "memory-backend"))]
mod connection_slot_tests {
    use super::ConnectionSlot;
    use super::PerDidConnectionGuard;
    use crate::store::memory_store::MemoryStore;
    use crate::tasks::websocket_streaming::{QueuedCommand, StreamingUpdate, StreamingUpdateState};
    use affinidi_messaging_mediator_common::store::MediatorStore;
    use dashmap::DashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    async fn closes(database: &Arc<dyn MediatorStore>) -> (i64, i64) {
        let stats = database.get_global_stats().await.expect("stats");
        (stats.websocket_open, stats.websocket_close)
    }

    /// Wait for the background release a dropped slot spawns.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_slot_over_the_limit_gives_its_count_back() {
        let count = Arc::new(AtomicUsize::new(2));
        assert_eq!(ConnectionSlot::acquire(&count, 2).err(), Some(2));
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_dropped_slot_releases_everything_it_took() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        // An early return: the slot is dropped, never released by hand.
        drop(slot);
        settle().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        match rx.try_recv().expect("a deregistration is sent") {
            StreamingUpdate {
                did_hash,
                state: StreamingUpdateState::Deregister { session_id, .. },
            } => {
                assert_eq!(did_hash, "did-hash");
                assert_eq!(session_id, "session-1");
            }
            _ => panic!("expected a Deregister"),
        }
        assert!(rx.try_recv().is_err(), "deregistered exactly once");
        assert_eq!(closes(&database).await, (1, 1));
    }

    #[tokio::test]
    async fn a_released_slot_releases_once() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        slot.release().await;
        settle().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "deregistered exactly once");
        assert_eq!(closes(&database).await, (1, 1));
    }

    /// A socket the streaming task closed has no registration of its own left;
    /// deregistering it could remove the socket that replaced it.
    #[tokio::test]
    async fn a_slot_closed_by_the_streaming_task_does_not_deregister() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<StreamingUpdate>(4);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.open(&database).await;
        let (client, _client_rx) = mpsc::channel::<QueuedCommand>(1);
        slot.registered(tx, "did-hash", "session-1", &client);
        slot.deregistered_by_streaming();
        slot.release().await;

        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err());
        assert_eq!(closes(&database).await, (1, 1));
    }

    /// The per-DID slot goes back with the global one, when the connection
    /// is released rather than when the handler finally returns.
    #[tokio::test]
    async fn a_released_slot_gives_back_the_per_did_slot() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        let registry: Arc<DashMap<String, u32>> = Arc::new(DashMap::new());
        registry.insert("did-hash".to_string(), 1);

        let mut slot = ConnectionSlot::acquire(&count, 10).expect("under the limit");
        slot.hold_per_did(PerDidConnectionGuard {
            registry: registry.clone(),
            did_hash: "did-hash".to_string(),
        });
        slot.open(&database).await;
        slot.release().await;

        assert!(registry.get("did-hash").is_none());
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    /// A slot that was never admitted owes no close stat.
    #[tokio::test]
    async fn an_unopened_slot_records_no_close() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let count = Arc::new(AtomicUsize::new(0));
        drop(ConnectionSlot::acquire(&count, 10).expect("under the limit"));
        settle().await;
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert_eq!(closes(&database).await, (0, 0));
    }
}
