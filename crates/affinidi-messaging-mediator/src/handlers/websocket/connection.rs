//! The per-connection state machine: admission, registration, and the loop
//! that reads frames and writes queued deliveries.

use super::*;

/// What the read side of the connection loop produced.
pub(super) enum Inbound {
    /// A frame from the peer (or the end of the stream), as
    /// [`BoundedSocket::recv`] returns it.
    Frame(Option<Result<Message, axum::Error>>),
    /// The socket has stayed over its message rate for too long.
    RateLimited,
}

/// The next frame from the peer, read no faster than `meter` allows.
///
/// A text or binary message over the rate is kept in `held` and the socket is
/// not read again until it is due, so the peer's further frames wait in its
/// own send buffer: one message is held, never more. Control frames are read
/// and returned as they come while nothing is held.
///
/// Cancel-safe, as the connection loop's `select!` needs: the only await
/// after a message is taken off the socket is the pause, and the message is
/// in `held` for it, so a dropped future loses nothing and the message is
/// charged again (each budget once) on the next call.
pub(super) async fn next_inbound(
    socket: &mut BoundedSocket,
    held: &mut Option<Message>,
    mut meter: Option<&mut crate::handlers::ws_message_meter::WsMessageMeter>,
) -> Inbound {
    use crate::handlers::ws_message_meter::Verdict;
    loop {
        let (message, was_held) = match held.take() {
            Some(message) => (message, true),
            None => match socket.recv().await {
                Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) if meter.is_some() => {
                    (message, false)
                }
                other => return Inbound::Frame(other),
            },
        };
        let Some(meter) = meter.as_deref_mut() else {
            return Inbound::Frame(Some(Ok(message)));
        };
        match meter.charge(Instant::now()) {
            Verdict::Admit => {
                if was_held {
                    // The mediator chose not to read while it waited, so a
                    // ping that went unanswered meanwhile is not held against
                    // the peer, which was sending all along.
                    socket.pings.answered();
                }
                return Inbound::Frame(Some(Ok(message)));
            }
            Verdict::Close => return Inbound::RateLimited,
            Verdict::Wait(pause) => {
                *held = Some(message);
                tokio::time::sleep(pause).await;
            }
        }
    }
}

/// Build a close message carrying an RFC 6455 code + human-readable reason.
pub(super) fn close_with(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// WebSocket state machine. This is spawned per connection.
pub(super) async fn handle_socket(
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
        let liveness = Liveness::from_limits(&state.config.limits);
        let mut socket = BoundedSocket::new(socket, liveness.write_timeout);

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
                    // A raw-TSP socket answers any notification for its own
                    // DID by draining its inbox (below), so a redelivery to it
                    // is one wake-up.
                    #[cfg(feature = "tsp")]
                    wake_only: tsp_mode,
                    #[cfg(not(feature = "tsp"))]
                    wake_only: false,
                    live: false,
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
        // The socket's last read of its own account (`refresh_standing`).
        let mut standing_read: Option<crate::common::standing::StandingRead> = None;
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

        // Periodic ping to detect dead connections: a peer that is still
        // there answers with a pong, which (like any frame from it) clears the
        // ping deadline below.
        let mut ping_interval = tokio::time::interval(liveness.ping_interval);
        // After a long pass, one ping rather than a burst of the missed ones.
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
        // What a drain on a `tsp-mux` socket left undone because live frames
        // were waiting (see [`drain_tsp_inbox`]). Resumed whenever the queue
        // is empty, not on the resync flag, so the resync floor does not hold
        // it back.
        #[cfg(feature = "tsp")]
        let mut tsp_drain_rest: Option<TspDrainRest> = None;

        // Flush-on-connect for raw-TSP delivery: drain whatever is already queued
        // for this DID straight onto the socket before entering the live-delivery
        // loop. If the socket is already gone, exit cleanly.
        #[cfg(feature = "tsp")]
        if tsp_mode && drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, true, tsp_mux_conn.as_deref().map(|c| (c, &mut member_inflight, None)), tsp_mux_conn.as_ref().map(|_| (&rx, fair.as_ref())))
            .await
            .map_continue(|rest| TspDrainRest::merge(&mut tsp_drain_rest, rest))
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
        // Inbound message rate for an authenticated socket (see
        // `ws_message_meter`): read with the live limits, so a `config/patch`
        // applies to every socket opened after it. `None` for a relay socket
        // and for the exempt DIDs.
        let mut message_meter = if is_relay {
            None
        } else {
            crate::handlers::ws_message_meter::WsMessageMeter::new(
                &state.limits(),
                &state.did_rate_limiter,
                &session.did_hash,
            )
        };
        // A message read but held back until it is due (see `next_inbound`).
        let mut held: Option<Message> = None;

        // Why this socket ends up closing — surfaced in the final close frame.
        let mut close_reason: (u16, &'static str) = (close_code::NORMAL, "normal closure");
        // When the last select returned: from then until the next one the
        // loop was not reading. Every arm that loops again sets it first.
        let mut woke = tokio::time::Instant::now();
        loop {
            // Checked at the top so it holds however the last pass ended,
            // including the arms that `continue`.
            if socket.stalled() {
                warn!("WebSocket write timed out; closing");
                close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                break;
            }
            // A ping deadline that passed while the last pass was busy (not
            // reading) gets a fresh window now that the loop reads again.
            socket.pings.after_pass(woke, liveness.ping_interval);
            let ping_deadline = socket.pings.deadline();
            // A drain left undone for live frames, with nothing queued ahead
            // of it.
            #[cfg(feature = "tsp")]
            let drain_pending = tsp_drain_rest.is_some() && queue_idle(&rx, fair.as_ref());
            #[cfg(not(feature = "tsp"))]
            let drain_pending = false;
            // While a message is held the loop is deliberately not reading,
            // so an unanswered ping is not the peer's silence.
            let reading = held.is_none();
            select! {
                // The mediator is stopping. The HTTP server's graceful
                // shutdown does not track upgraded sockets; before this they
                // were closed only once the streaming task had gone, with
                // 1011 "streaming task unavailable", which reads as a server
                // fault. Close with 1001 "going away": clients reconnect, and
                // the reason says why (R6.2).
                _ = state.shutdown_token.cancelled() => {
                    debug!("Mediator shutting down; closing the socket");
                    close_reason = (close_code::GOING_AWAY, "mediator shutting down");
                    break;
                }
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
                inbound = next_inbound(&mut socket, &mut held, message_meter.as_mut()) => {
                    woke = tokio::time::Instant::now();
                    let value = match inbound {
                        Inbound::Frame(value) => value,
                        Inbound::RateLimited => {
                            warn!("WebSocket stayed over its message rate; closing");
                            close_reason = (close_code::POLICY, crate::handlers::ws_message_meter::CLOSE_REASON);
                            break;
                        }
                    };
                    match value { Some(msg) => {
                        let msg = match msg {
                            Ok(msg) => msg,
                            Err(e) => {
                                // A frame the socket could not read: over
                                // `ws_size` (1009, so the client knows to
                                // send less), or malformed. Either way the
                                // socket cannot go on, and the reason is
                                // logged and told rather than read as the
                                // client leaving.
                                close_reason = read_error_close(&e);
                                warn!(code = close_reason.0, "WebSocket read failed; closing: {e}");
                                break;
                            }
                        };
                        {
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
                                        refresh_standing(&state, &mut session, &mut standing_read).await;
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

                                    if let Err(e) = outcome {
                                        report_refusal(&state, &session, &mut socket, e).await;
                                        continue;
                                    }
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
                                    // A binary frame leading with the TSP magic byte (0xF8) is a
                                    // TSP message; route it to the TSP handler. Other binary frames
                                    // are UTF-8-decoded and handled as DIDComm exactly as before.
                                    if !is_relay {
                                        refresh_standing(&state, &mut session, &mut standing_read).await;
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
                                            report_refusal(&state, &session, &mut socket, e).await;
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
                                    if let Err(e) = crate::monitor::with_channel(Channel::Websocket, handle_inbound(&state, &session, &msg)).await {
                                        state.monitor.refused(&session.did_hash, Channel::Websocket, Protocol::DidComm, msg.as_bytes(), &e);
                                        // Told as a Text frame refusal is: a
                                        // client that frames DIDComm as Binary
                                        // must not take a refused message for
                                        // a sent one (R1.1).
                                        report_refusal(&state, &session, &mut socket, e).await;
                                        continue;
                                    }
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
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &mux_conn {
                        for frame in crate::mux::connection::drain_changes(&state, conn, mux_wire).await {
                            if let Err(e) = socket.send(frame.into()).await {
                                warn!("Failed to send mux event to WebSocket client: {e}");
                            }
                        }
                    }
                }
                // A member's live delivery moved (or came back): recorded on
                // the connection's slots by the streaming task, so it is never
                // lost to a full queue, and reported here in order.
                _ = async { match &mux_slots { Some(s) => s.member_changed.notified().await, None => std::future::pending().await } }, if mux_conn.is_some() => {
                    woke = tokio::time::Instant::now();
                    if let (Some(conn), Some(slots)) = (&mux_conn, &mux_slots) {
                        for change in slots.take_member_changes() {
                            if let Some(frame) = crate::mux::connection::on_member_change(&state, conn, change, mux_wire).await
                                && let Err(e) = socket.send(frame.into()).await
                            {
                                warn!("Failed to send mux event to WebSocket client: {e}");
                            }
                        }
                    }
                }
                _ = mux_sweep.tick(), if mux_conn.is_some() => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::spawn_sweep(&state, conn, false);
                    }
                }
                // A drain left undone for live frames resumes after the select
                // once the queue is empty; this wakes the loop for it when
                // nothing else would.
                _ = std::future::ready(()), if drain_pending => {
                    woke = tokio::time::Instant::now();
                }
                _ = mux_revalidate.tick(), if mux_conn.is_some() => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::spawn_sweep(&state, conn, true);
                    }
                }
                _ = mux_standing.tick(), if mux_conn.is_some() => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &mux_conn {
                        crate::mux::connection::spawn_standing_pass(&state, conn);
                    }
                }
                // A resync held back by the floor is sent when it falls due,
                // not whenever something else next wakes this loop (a ping,
                // up to a minute later). The body is empty: the resync check
                // after this select acts on it.
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(last_resync_sent + MIN_RESYNC_INTERVAL)),
                    if live_resync.load(std::sync::atomic::Ordering::Relaxed) => {
                    woke = tokio::time::Instant::now();
                }
                // A ping has gone unanswered for the whole grace, and nothing
                // else has arrived from the peer either: it has gone without
                // closing.
                _ = tokio::time::sleep_until(ping_deadline.unwrap_or_else(|| tokio::time::Instant::now() + liveness.ping_interval)),
                    if ping_deadline.is_some() && reading => {
                    warn!(
                        grace_secs = liveness.grace.as_secs(),
                        "WebSocket ping unanswered, and no frame from the peer; closing"
                    );
                    metrics::counter!(WS_PONG_TIMEOUTS_TOTAL).increment(1);
                    close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                    break;
                }
                _ = ping_interval.tick() => {
                    woke = tokio::time::Instant::now();
                    #[cfg(feature = "test-hooks")]
                    let starts_wait = socket.pings.deadline().is_none();
                    if let Err(e) = socket.ping(liveness.grace).await {
                        debug!("Failed to send WebSocket ping: {e}");
                        close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                        break;
                    }
                    #[cfg(feature = "test-hooks")]
                    if starts_wait
                        && let Some(stall) = test_hooks::stall_after_ping(&session.did_hash)
                    {
                        tokio::time::sleep(stall).await;
                    }
                }
                value = next_queued(&mut rx, fair.as_mut()) => {
                    woke = tokio::time::Instant::now();
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
                if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, true, None, tsp_mux_conn.as_ref().map(|_| (&rx, fair.as_ref())))
                    .await
                    .map_continue(|rest| TspDrainRest::merge(&mut tsp_drain_rest, rest))
                    .is_break()
                {
                    close_reason = (close_code::GOING_AWAY, "client disconnected");
                    break;
                }
            }

            // A drain cut short so live frames could go first, resumed once
            // they have (`tsp-mux` fairness: one member's backlog must not
            // hold another's live frame behind it).
            #[cfg(feature = "tsp")]
            if queue_idle(&rx, fair.as_ref())
                && let Some(rest) = tsp_drain_rest.take()
            {
                let only = rest.only;
                if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, rest.principal, tsp_mux_conn.as_deref().filter(|_| rest.members).map(|c| (c, &mut member_inflight, only.as_ref())), Some((&rx, fair.as_ref())))
                    .await
                    .map_continue(|rest| TspDrainRest::merge(&mut tsp_drain_rest, rest))
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
                    if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight, true, tsp_mux_conn.as_deref().map(|c| (c, &mut member_inflight, owed.as_ref())), tsp_mux_conn.as_ref().map(|_| (&rx, fair.as_ref())))
                        .await
                        .map_continue(|rest| TspDrainRest::merge(&mut tsp_drain_rest, rest))
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
pub(super) async fn next_queued(
    rx: &mut Receiver<QueuedCommand>,
    fair: Option<&mut crate::mux::fair_queue::FairOrder<QueuedCommand>>,
) -> Option<QueuedCommand> {
    match fair {
        None => rx.recv().await,
        Some(fair) => fair.next(rx).await,
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
///
/// Not a store read on *every* frame: `last` is the socket's previous read,
/// and it stands while no account change has been seen and it is younger
/// than [`STANDING_FRESH`](crate::common::standing::STANDING_FRESH) (#159;
/// see `common::standing`). A failed read is not remembered, so the next
/// frame tries again.
pub(super) async fn refresh_standing(
    state: &SharedData,
    session: &mut Session,
    last: &mut Option<crate::common::standing::StandingRead>,
) {
    use crate::common::standing::{StandingRead, epoch};
    if !StandingRead::is_stale(last.as_ref()) {
        return;
    }
    let seen = epoch();
    match state.database.account_get(&session.did_hash).await {
        Ok(Some(account)) => {
            session.account_type = account._type;
            session.acls =
                affinidi_messaging_mediator_common::types::acls::MediatorACLSet::from_u64(
                    account.acls,
                );
            *last = Some(StandingRead::taken(seen));
        }
        Ok(None) => {
            *last = Some(StandingRead::taken(seen));
        }
        Err(e) => warn!(
            "couldn't refresh the account behind session {}: {e}",
            session.session_id
        ),
    }
}
