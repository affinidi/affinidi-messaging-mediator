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

/// What a socket carries, decided at upgrade from its credential and the
/// subprotocols it negotiated. The modes are exclusive: a relay socket is never
/// a delivery socket, and a raw-TSP socket never carries DIDComm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ConnectionMode {
    /// An anonymous inter-mediator relay socket from `source` (its client
    /// address): it may push frames and receives nothing but the `RelayAck`
    /// answers to them.
    Relay { source: String },
    /// An authenticated DIDComm socket; `mux` when it is a DID-multiplexing
    /// connection (`didcomm-mux`, design §7) carrying member DIDs too.
    DidComm { mux: bool },
    /// An authenticated raw-TSP socket. `ack` is delete-to-ack delivery
    /// (`tsp-ack`); `mux` is a `tsp-mux` connection, which implies `ack`.
    #[cfg(feature = "tsp")]
    Tsp { ack: bool, mux: bool },
}

impl ConnectionMode {
    /// The client address of a relay socket.
    pub(super) fn relay_source(&self) -> Option<&str> {
        match self {
            ConnectionMode::Relay { source } => Some(source),
            _ => None,
        }
    }

    pub(super) fn is_relay(&self) -> bool {
        matches!(self, ConnectionMode::Relay { .. })
    }

    /// A mux connection, on either wire.
    pub(super) fn is_mux(&self) -> bool {
        match self {
            ConnectionMode::DidComm { mux } => *mux,
            #[cfg(feature = "tsp")]
            ConnectionMode::Tsp { mux, .. } => *mux,
            ConnectionMode::Relay { .. } => false,
        }
    }

    /// A raw-TSP socket: binary TSP frames only, inbox delivery by drain.
    pub(super) fn is_tsp(&self) -> bool {
        #[cfg(feature = "tsp")]
        if let ConnectionMode::Tsp { .. } = self {
            return true;
        }
        false
    }

    /// Delete-to-ack delivery on a raw-TSP socket.
    #[cfg(feature = "tsp")]
    pub(super) fn tsp_ack(&self) -> bool {
        matches!(self, ConnectionMode::Tsp { ack: true, .. })
    }

    /// The wire a mux connection's events travel on.
    fn mux_wire(&self) -> crate::mux::connection::MuxWire {
        if self.is_tsp() {
            crate::mux::connection::MuxWire::Tsp
        } else {
            crate::mux::connection::MuxWire::DidComm
        }
    }
}

/// A close frame's code and reason.
pub(super) type CloseFrameReason = (u16, &'static str);

/// What handling one wake-up of the connection loop decided.
pub(super) enum Step {
    /// Go on to the checks that follow every wake-up (drains, resync).
    Proceed,
    /// Wait for the next wake-up straight away.
    Skip,
    /// End the connection with this close frame.
    Close(CloseFrameReason),
}

/// Admit a connection: refuse an expired token, then take its places in the
/// global count, a relay socket's per-address count and the per-DID count. A
/// refusal is written as the close frame and `None` returned. `Some` is the
/// opened slot, which gives everything back on every exit path from here.
async fn admit(
    state: &SharedData,
    session: &Session,
    mode: &ConnectionMode,
    socket: &mut BoundedSocket,
) -> Option<ConnectionSlot> {
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
        return None;
    }

    // Enforce the global connection limit. From here the slot gives back
    // everything it holds on every return path.
    let mut slot = match ConnectionSlot::acquire(
        &state.active_websocket_count,
        state.config.limits.max_websocket_connections,
    ) {
        Ok(slot) => slot,
        Err(current) => {
            warn!(
                "WebSocket connection limit reached ({}/{})",
                current, state.config.limits.max_websocket_connections
            );
            let _ = socket
                .send(close_with(
                    close_code::TRY_AGAIN_LATER,
                    "server connection limit reached",
                ))
                .await;
            return None;
        }
    };

    // Relay sockets share one bucket (below), so each client address may
    // hold only `relay_connections_per_ip` of them: one source cannot take
    // every relay slot from the other peers.
    if let Some(source) = mode.relay_source() {
        let held = reserve(&state.relay_connections_per_ip, source);
        slot.hold_per_source(PerDidConnectionGuard {
            registry: state.relay_connections_per_ip.clone(),
            did_hash: source.to_string(),
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
            return None;
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
        return None;
    }

    slot.open(&state.database).await;
    Some(slot)
}

/// Register the socket with the streaming task, which then queues its live
/// deliveries on `tx`. `false` when the streaming task could not be told; the
/// connection is then not opened.
///
/// A relay socket is push-only and must never be registered. It has no DID,
/// so it would register under the empty did_hash — claiming that stream for an
/// anonymous peer and pointing live delivery at a socket that belongs to no
/// account. Skipping the registration is what makes "relays can only send"
/// structural rather than a matter of which messages we happen to handle: its
/// queue can never yield.
async fn register_streaming(
    state: &SharedData,
    session: &Session,
    mode: &ConnectionMode,
    slot: &mut ConnectionSlot,
    tx: &Sender<QueuedCommand>,
    live_resync: &Arc<std::sync::atomic::AtomicBool>,
    mux_slots: &Option<Arc<crate::mux::fair_queue::MuxSlots>>,
) -> bool {
    let Some(streaming) = &state.streaming_task else {
        return true;
    };
    if mode.is_relay() {
        return true;
    }

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
            // DID by draining its inbox, so a redelivery to it is one
            // wake-up.
            wake_only: mode.is_tsp(),
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
                tx,
            );
        }
        Err(e) => {
            warn!("Error sending start message to streaming task: {:?}", e);
            return false;
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
    // entirely, so the queue's re-drain wake-up never fired and the ONLY
    // delivery this socket ever got was flush-on-connect. Every frame that
    // arrived after the socket came up was stored and left sitting in the
    // inbox: the sender saw a successful send and the recipient heard
    // nothing.
    //
    // Push delivery isn't an opt-in here the way it is for DIDComm —
    // it is the raw-TSP contract (flush-on-connect + delete-on-send),
    // so the socket declares itself live the moment it registers.
    if mode.is_tsp() {
        let live = StreamingUpdate {
            did_hash: session.did_hash.clone(),
            state: StreamingUpdateState::Start {
                session_id: session.session_id.clone(),
            },
        };
        match streaming.channel.send(live).await {
            Ok(_) => debug!("Raw-TSP socket: enabled live delivery"),
            Err(e) => {
                warn!("Error enabling live delivery for raw-TSP socket: {:?}", e);
                return false;
            }
        }
    }
    true
}

/// WebSocket state machine. This is spawned per connection.
pub(super) async fn handle_socket(
    socket: WebSocket,
    state: SharedData,
    session: Session,
    mode: ConnectionMode,
) {
    let _span = span!(
        tracing::Level::INFO,
        "handle_socket",
        session = session.session_id
    );
    async move {
        let liveness = Liveness::from_limits(&state.config.limits);
        let mut socket = BoundedSocket::new(socket, liveness.write_timeout);

        let Some(mut slot) = admit(&state, &session, &mode, &mut socket).await else {
            return;
        };

        // A mux connection shares its queue among many DIDs, so each gets a
        // fair share of it (design §7.2): per-DID slots on the way in, and a
        // round-robin writer on the way out. A direct socket keeps the plain
        // bounded channel.
        let mux_slots = mode.is_mux().then(|| {
            crate::mux::fair_queue::MuxSlots::new(state.config.limits.mux.max_channel_slots)
        });
        let fair = mux_slots
            .as_ref()
            .map(|_| crate::mux::fair_queue::FairOrder::<QueuedCommand>::default());

        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, rx): (Sender<QueuedCommand>, Receiver<QueuedCommand>) = mpsc::channel(
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
        // exactly when there is no room to queue one. It is read after every
        // wake-up, so the signal goes out as soon as the socket is moving
        // again.
        let live_resync = Arc::new(std::sync::atomic::AtomicBool::new(false));

        if !register_streaming(
            &state,
            &session,
            &mode,
            &mut slot,
            &tx,
            &live_resync,
            &mux_slots,
        )
        .await
        {
            return;
        }

        info!("Websocket connection established");

        // A mux connection admits its stored grants and tells the client its
        // nonce and members before anything else is written.
        let mux_wire = mode.mux_wire();
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
        let unregistered_tx = (mode.is_relay() || state.streaming_task.is_none()).then_some(tx);

        let is_relay = mode.is_relay();
        // Inbound frame budget for a relay socket (see `RelayMeter`).
        let relay_meter = is_relay.then(|| RelayMeter::new(&state.config.limits));
        // Inbound message rate for an authenticated socket (see
        // `ws_message_meter`): read with the live limits, so a `config/patch`
        // applies to every socket opened after it. `None` for a relay socket
        // and for the exempt DIDs.
        let message_meter = if is_relay {
            None
        } else {
            crate::handlers::ws_message_meter::WsMessageMeter::new(
                &state.limits(),
                &state.did_rate_limiter,
                &session.did_hash,
            )
        };

        #[cfg(feature = "tsp")]
        let tsp_mux_conn = if mode.is_tsp() {
            mux_conn.clone()
        } else {
            None
        };
        let mut connection = Connection {
            state,
            session,
            mode,
            liveness,
            socket,
            slot,
            rx,
            fair,
            mux_slots,
            mux_conn,
            mux_wire,
            live_resync,
            // Starts in the past so the first drop is signalled immediately;
            // the floor exists to bound a *repeating* cost, not to delay the
            // first one.
            last_resync_sent: Instant::now() - MIN_RESYNC_INTERVAL,
            _unregistered_tx: unregistered_tx,
            standing_read: None,
            relay_meter,
            message_meter,
            held: None,
            #[cfg(feature = "tsp")]
            tsp_inflight: std::collections::HashSet::new(),
            #[cfg(feature = "tsp")]
            tsp_mux_conn,
            #[cfg(feature = "tsp")]
            member_inflight: MemberInflight::new(),
            #[cfg(feature = "tsp")]
            tsp_drain_owed: 0,
            #[cfg(feature = "tsp")]
            tsp_drain_rest: None,
        };

        // Flush-on-connect for raw-TSP delivery: drain whatever is already queued
        // for this DID straight onto the socket before entering the live-delivery
        // loop. If the socket is already gone, exit cleanly.
        #[cfg(feature = "tsp")]
        if connection.mode.is_tsp() && connection.drain(true, Some(None), false).await {
            if let Some(conn) = &connection.mux_conn {
                crate::mux::connection::close(&connection.state, &connection.session, conn).await;
            }
            connection.slot.release().await;
            info!("Websocket connection closed during TSP flush-on-connect");
            return;
        }

        let close_reason = connection.run().await;
        connection.finish(close_reason).await;
    }
    .instrument(_span)
    .await
}

/// One connection's state, from the moment it is admitted and registered
/// until it closes. [`Connection::run`] is the loop; each kind of wake-up has
/// its own handler, and every way out of the loop is a close reason that
/// [`Connection::finish`] writes after giving the connection's slots back.
pub(super) struct Connection {
    state: SharedData,
    session: Session,
    mode: ConnectionMode,
    liveness: Liveness,
    socket: BoundedSocket,
    slot: ConnectionSlot,
    /// Live deliveries queued by the streaming task (and, on a mux
    /// connection, the registry).
    rx: Receiver<QueuedCommand>,
    /// A mux connection's fair order over `rx` (design §7.2).
    fair: Option<crate::mux::fair_queue::FairOrder<QueuedCommand>>,
    mux_slots: Option<Arc<crate::mux::fair_queue::MuxSlots>>,
    mux_conn: Option<Arc<crate::mux::registry::MuxConn>>,
    mux_wire: crate::mux::connection::MuxWire,
    /// Raised by the streaming task when a live notification was dropped.
    live_resync: Arc<std::sync::atomic::AtomicBool>,
    last_resync_sent: Instant,
    /// Holds the queue open for a socket nothing else feeds.
    _unregistered_tx: Option<Sender<QueuedCommand>>,
    /// The socket's last read of its own account (`refresh_standing`).
    standing_read: Option<crate::common::standing::StandingRead>,
    relay_meter: Option<RelayMeter>,
    message_meter: Option<crate::handlers::ws_message_meter::WsMessageMeter>,
    /// A message read but held back until it is due (see `next_inbound`).
    held: Option<Message>,
    /// Sent-but-not-yet-acked message ids, for `tsp-ack` mode only.
    ///
    /// In ack mode the mediator no longer deletes on send, so every drain
    /// re-fetches the same un-acked messages and would re-send them on each
    /// live-delivery wake-up — turning "may see a duplicate after a
    /// reconnect" into "sees duplicates constantly". This set is what makes
    /// redelivery a *recovery* mechanism rather than the steady state:
    /// within one connection a frame is sent once, and the set dies with the
    /// connection, so a reconnect legitimately re-sends whatever was never
    /// acked.
    ///
    /// Bounded implicitly: it only ever holds ids the inbox still contains,
    /// and it is pruned against each completed drain, so client acks remove
    /// entries. The inbox itself is capped by
    /// `queued_receive_messages_hard` and message expiry.
    #[cfg(feature = "tsp")]
    tsp_inflight: std::collections::HashSet<String>,
    /// On a `tsp-mux` socket the drain covers the members too.
    #[cfg(feature = "tsp")]
    tsp_mux_conn: Option<Arc<crate::mux::registry::MuxConn>>,
    #[cfg(feature = "tsp")]
    member_inflight: MemberInflight,
    /// Principal wake-ups waiting for one drain (raw TSP). An inbox
    /// redelivery queues one per message, and each drain walks the whole
    /// inbox, so they are answered together once the queue is empty, or
    /// after `TSP_DRAIN_COALESCE` of them under a steady stream.
    #[cfg(feature = "tsp")]
    tsp_drain_owed: usize,
    /// What a drain on a `tsp-mux` socket left undone because live frames
    /// were waiting (see [`drain_tsp_inbox`]). Resumed whenever the queue
    /// is empty, not on the resync flag, so the resync floor does not hold
    /// it back.
    #[cfg(feature = "tsp")]
    tsp_drain_rest: Option<TspDrainRest>,
}

impl Connection {
    /// The connection loop. Returns why the connection is closing.
    async fn run(&mut self) -> CloseFrameReason {
        let mut mux_sweep = tokio::time::interval(Duration::from_secs(30));
        mux_sweep.reset();
        let mut mux_revalidate = tokio::time::interval(Duration::from_secs(
            self.state
                .config
                .limits
                .mux
                .revalidate_interval_secs
                .max(30),
        ));
        mux_revalidate.reset();
        // Members' account standing, re-checked in a task of its own so the
        // store reads never hold this loop up.
        #[allow(unused_mut)]
        let mut standing_every = Duration::from_secs(crate::mux::connection::STANDING_PASS_SECS);
        #[cfg(feature = "test-hooks")]
        if let Some(every) =
            crate::mux::connection::test_hooks::standing_pass_interval(&self.session.did_hash)
        {
            standing_every = every;
        }
        let mut mux_standing = tokio::time::interval(standing_every);
        mux_standing.reset();

        // The socket lives until the JWT Auth token expires. `expires_at` was
        // checked to be in the future on entry; the setup since may have
        // taken that time, which leaves a zero-length lifetime.
        let epoch = self.state.clock.unix_secs();
        let auth_timeout = tokio::time::sleep(Duration::from_secs(
            self.session.expires_at.saturating_sub(epoch),
        ));
        tokio::pin!(auth_timeout);
        debug!(
            expires_in_secs = self.session.expires_at.saturating_sub(epoch),
            "WebSocket auth timeout set"
        );

        // Periodic ping to detect dead connections: a peer that is still
        // there answers with a pong, which (like any frame from it) clears the
        // ping deadline below.
        let mut ping_interval = tokio::time::interval(self.liveness.ping_interval);
        // After a long pass, one ping rather than a burst of the missed ones.
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping_interval.reset(); // Skip the immediate first tick

        let is_mux = self.mux_conn.is_some();
        // When the last select returned: from then until the next one the
        // loop was not reading. Every arm that loops again sets it first.
        let mut woke = tokio::time::Instant::now();
        loop {
            // Checked at the top so it holds however the last pass ended,
            // including the arms that skip the after-pass checks.
            if self.socket.stalled() {
                warn!("WebSocket write timed out; closing");
                return (close_code::GOING_AWAY, "connection unresponsive");
            }
            // A ping deadline that passed while the last pass was busy (not
            // reading) gets a fresh window now that the loop reads again.
            self.socket
                .pings
                .after_pass(woke, self.liveness.ping_interval);
            let ping_deadline = self.socket.pings.deadline();
            // A drain left undone for live frames, with nothing queued ahead
            // of it.
            #[cfg(feature = "tsp")]
            let drain_pending =
                self.tsp_drain_rest.is_some() && queue_idle(&self.rx, self.fair.as_ref());
            #[cfg(not(feature = "tsp"))]
            let drain_pending = false;
            // While a message is held the loop is deliberately not reading,
            // so an unanswered ping is not the peer's silence.
            let reading = self.held.is_none();
            let resync_raised = self.live_resync.load(std::sync::atomic::Ordering::Relaxed);
            let step = select! {
                // The mediator is stopping. The HTTP server's graceful
                // shutdown does not track upgraded sockets; before this they
                // were closed only once the streaming task had gone, with
                // 1011 "streaming task unavailable", which reads as a server
                // fault. Close with 1001 "going away": clients reconnect, and
                // the reason says why (R6.2).
                _ = self.state.shutdown_token.cancelled() => {
                    debug!("Mediator shutting down; closing the socket");
                    Step::Close((close_code::GOING_AWAY, "mediator shutting down"))
                }
                _ = &mut auth_timeout => {
                    debug!("Socket lifetime reached");
                    Step::Close(if self.mode.is_relay() {
                        // No token was ever presented — this is the relay
                        // socket's bounded lifetime, and the peer should
                        // reconnect rather than go looking for a credential
                        // problem it doesn't have.
                        (close_code::POLICY, "relay socket lifetime reached")
                    } else {
                        (close_code::POLICY, "authentication token expired")
                    })
                }
                inbound = next_inbound(&mut self.socket, &mut self.held, self.message_meter.as_mut()) => {
                    woke = tokio::time::Instant::now();
                    match inbound {
                        Inbound::Frame(frame) => self.on_frame(frame).await,
                        Inbound::RateLimited => {
                            warn!("WebSocket stayed over its message rate; closing");
                            Step::Close((close_code::POLICY, crate::handlers::ws_message_meter::CLOSE_REASON))
                        }
                    }
                }
                _ = async { match &self.mux_conn { Some(c) => c.notify.notified().await, None => std::future::pending().await } } => {
                    woke = tokio::time::Instant::now();
                    self.on_mux_changes().await;
                    Step::Proceed
                }
                // A member's live delivery moved (or came back): recorded on
                // the connection's slots by the streaming task, so it is never
                // lost to a full queue, and reported here in order.
                _ = async { match &self.mux_slots { Some(s) => s.member_changed.notified().await, None => std::future::pending().await } }, if is_mux => {
                    woke = tokio::time::Instant::now();
                    self.on_member_changes().await;
                    Step::Proceed
                }
                _ = mux_sweep.tick(), if is_mux => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &self.mux_conn {
                        crate::mux::connection::spawn_sweep(&self.state, conn, false);
                    }
                    Step::Proceed
                }
                // A drain left undone for live frames resumes after the select
                // once the queue is empty; this wakes the loop for it when
                // nothing else would.
                _ = std::future::ready(()), if drain_pending => {
                    woke = tokio::time::Instant::now();
                    Step::Proceed
                }
                _ = mux_revalidate.tick(), if is_mux => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &self.mux_conn {
                        crate::mux::connection::spawn_sweep(&self.state, conn, true);
                    }
                    Step::Proceed
                }
                _ = mux_standing.tick(), if is_mux => {
                    woke = tokio::time::Instant::now();
                    if let Some(conn) = &self.mux_conn {
                        crate::mux::connection::spawn_standing_pass(&self.state, conn);
                    }
                    Step::Proceed
                }
                // A resync held back by the floor is sent when it falls due,
                // not whenever something else next wakes this loop (a ping,
                // up to a minute later). The body is empty: the resync check
                // after this select acts on it.
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.last_resync_sent + MIN_RESYNC_INTERVAL)),
                    if resync_raised => {
                    woke = tokio::time::Instant::now();
                    Step::Proceed
                }
                // A ping has gone unanswered for the whole grace, and nothing
                // else has arrived from the peer either: it has gone without
                // closing.
                _ = tokio::time::sleep_until(ping_deadline.unwrap_or_else(|| tokio::time::Instant::now() + self.liveness.ping_interval)),
                    if ping_deadline.is_some() && reading => {
                    warn!(
                        grace_secs = self.liveness.grace.as_secs(),
                        "WebSocket ping unanswered, and no frame from the peer; closing"
                    );
                    metrics::counter!(WS_PONG_TIMEOUTS_TOTAL).increment(1);
                    Step::Close((close_code::GOING_AWAY, "connection unresponsive"))
                }
                _ = ping_interval.tick() => {
                    woke = tokio::time::Instant::now();
                    self.on_ping_tick().await
                }
                queued = next_queued(&mut self.rx, self.fair.as_mut()) => {
                    woke = tokio::time::Instant::now();
                    match queued {
                        Some(queued) => self.on_queued(queued).await,
                        None => {
                            debug!("Received None from streaming task, closing connection");
                            Step::Close((close_code::SERVER_ERROR, "streaming task unavailable"))
                        }
                    }
                }
            };
            match step {
                Step::Close(reason) => return reason,
                Step::Skip => continue,
                Step::Proceed => {}
            }
            if let Some(reason) = self.after_pass().await {
                return reason;
            }
        }
    }

    /// Close the connection: release its mux members and its slots, then
    /// write the close frame with the reason that ended the loop.
    async fn finish(self, close_reason: CloseFrameReason) {
        if let Some(conn) = &self.mux_conn {
            crate::mux::connection::close(&self.state, &self.session, conn).await;
        }

        // Deregister from the streaming task (unless it closed this socket
        // itself; a relay socket was never registered), release the
        // connection count and gauge, and record the close.
        self.slot.release().await;

        let mut socket = self.socket;
        if let Err(e) = socket
            .send(close_with(close_reason.0, close_reason.1))
            .await
        {
            debug!("Failed to send WebSocket close frame: {e}");
        }

        info!("Websocket connection closed");
    }

    /// A frame from the peer (or the end of the stream).
    async fn on_frame(&mut self, frame: Option<Result<Message, axum::Error>>) -> Step {
        let msg = match frame {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                // A frame the socket could not read: over `ws_size` (1009, so
                // the client knows to send less), or malformed. Either way the
                // socket cannot go on, and the reason is logged and told
                // rather than read as the client leaving.
                let reason = read_error_close(&e);
                warn!(code = reason.0, "WebSocket read failed; closing: {e}");
                return Step::Close(reason);
            }
            None => {
                debug!("Received None, closing connection");
                return Step::Close((close_code::GOING_AWAY, "client disconnected"));
            }
        };
        match msg {
            Message::Text(msg) => self.on_text(msg.as_str()).await,
            // Nothing to do: the library answers a ping with a pong, and a
            // pong (like any frame) has already cleared the ping deadline.
            Message::Ping(_) | Message::Pong(_) => Step::Proceed,
            Message::Binary(msg) => self.on_binary(msg.into()).await,
            Message::Close(_) => {
                debug!("Received close message, closing connection");
                Step::Close((close_code::NORMAL, "normal closure"))
            }
        }
    }

    /// Send a relay socket's answer to one frame. A failure to send it closes
    /// the socket, so the peer never reads silence as success.
    async fn send_relay_ack(&mut self, ack: RelayAck) -> Step {
        match serde_json::to_string(&ack) {
            Ok(body) => {
                if let Err(e) = self.socket.send(Message::Text(body.into())).await {
                    warn!("Failed to send relay-ack: {e}");
                    return Step::Close((close_code::GOING_AWAY, "peer disconnected"));
                }
                Step::Skip
            }
            Err(e) => {
                // Unreachable for this type, and if it ever happened the peer
                // must not read silence as success: drop the socket so it
                // retries.
                warn!("Couldn't serialise relay-ack: {e}");
                Step::Close((close_code::SERVER_ERROR, "could not acknowledge"))
            }
        }
    }

    /// A Text frame: a DIDComm message, or a relayed frame on a relay socket.
    async fn on_text(&mut self, msg: &str) -> Step {
        // A `tsp-mux` socket carries binary TSP frames only; anything else is
        // a protocol violation by the principal, which closes the socket.
        #[cfg(feature = "tsp")]
        if self.tsp_mux_conn.is_some() {
            warn!("Text frame on a tsp-mux socket; closing");
            return Step::Close((close_code::POLICY, "tsp-mux sockets carry TSP frames only"));
        }
        // A relay frame over the socket's budget is refused with a negative
        // ack, which sends the relaying mediator to its REST fallback (where
        // the per-IP limiter applies) for that message.
        if let Some(meter) = self.relay_meter.as_mut()
            && let Err(limit) = meter.admit(msg.len())
        {
            metrics::counter!(RELAY_FRAMES_THROTTLED_TOTAL, "limit" => limit).increment(1);
            if meter.first_refusal() {
                warn!(
                    limit,
                    "Relay frame refused: socket over its frame budget; further refusals on this socket are logged at debug"
                );
            } else {
                debug!(limit, "Relay frame refused: socket over its frame budget");
            }
            let ack = RelayAck::rejected(
                frame_id(msg.as_bytes()),
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                "relay frame rate exceeded; send again later",
            );
            return self.send_relay_ack(ack).await;
        }

        let is_relay = self.mode.is_relay();
        if !is_relay {
            refresh_standing(&self.state, &mut self.session, &mut self.standing_read).await;
        }
        // Process the message, which also takes care of any storing and
        // live-streaming of the message.
        let (state, session) = (&self.state, &self.session);
        state.monitor.received(
            &session.did_hash,
            Channel::Websocket,
            Protocol::DidComm,
            msg.as_bytes(),
        );
        let outcome =
            crate::monitor::with_channel(Channel::Websocket, handle_inbound(state, session, msg))
                .await;
        if let Err(e) = &outcome {
            state.monitor.refused(
                &session.did_hash,
                Channel::Websocket,
                Protocol::DidComm,
                msg.as_bytes(),
                e,
            );
        }

        // A relay socket gets a `relay-ack` per frame instead of a problem
        // report. Two reasons it cannot have the latter: a problem report is
        // packed *to* `session.did`, which a relay session does not have; and
        // the relaying peer is a mediator waiting on a transport answer, not a
        // client reading its inbox. The ack is what stops a refused frame from
        // being reported as delivered — see `relay_ack`.
        if is_relay {
            let ack = match &outcome {
                Ok(_) => RelayAck::accepted(frame_id(msg.as_bytes())),
                Err(e) => {
                    warn!("Relay frame refused: {}", e);
                    let (code, reason) = relay_refusal(e);
                    RelayAck::rejected(frame_id(msg.as_bytes()), code, reason)
                }
            };
            return self.send_relay_ack(ack).await;
        }

        if let Err(e) = outcome {
            report_refusal(&self.state, &self.session, &mut self.socket, e).await;
            return Step::Skip;
        }
        Step::Proceed
    }

    /// A Binary frame: a TSP message, or DIDComm framed as Binary.
    async fn on_binary(&mut self, msg: Vec<u8>) -> Step {
        // The relay contract is Text frames answered by acks. A binary frame
        // on a relay socket is either a confused peer or something that is
        // not a peer at all; either way it cannot be acknowledged, and staying
        // open would leave the sender waiting out the ack timeout for every
        // frame. Close instead, so it falls back to REST immediately.
        if self.mode.is_relay() {
            warn!("Binary frame on a relay socket; closing");
            return Step::Close((close_code::POLICY, "relay sockets carry text frames only"));
        }
        refresh_standing(&self.state, &mut self.session, &mut self.standing_read).await;

        // A binary frame leading with the TSP magic byte (0xF8) is a TSP
        // message; route it to the TSP handler. Other binary frames are
        // UTF-8-decoded and handled as DIDComm exactly as before.
        #[cfg(feature = "tsp")]
        if affinidi_tsp::is_tsp(&msg) {
            return self.on_tsp(&msg).await;
        }

        // Same classification without the feature, for the same reason as
        // `message_inbound`: a TSP frame here would otherwise fail
        // `String::from_utf8` below and be logged as an unprocessable binary
        // frame, which says nothing about TSP and nothing about why. The frame
        // is still dropped — decoding it genuinely needs the feature — but it
        // is now dropped by name.
        #[cfg(feature = "tsp")]
        if self.tsp_mux_conn.is_some() {
            warn!("Non-TSP binary frame on a tsp-mux socket; closing");
            return Step::Close((close_code::POLICY, "tsp-mux sockets carry TSP frames only"));
        }

        #[cfg(not(feature = "tsp"))]
        if crate::handlers::message_inbound::looks_like_tsp_bytes(&msg) {
            warn!(
                "Dropping a TSP frame from {}: this mediator was built without \
                 TSP support (cargo feature `tsp`). Rebuild with \
                 `--features didcomm,tsp` to accept TSP traffic.",
                self.session.did_hash
            );
            return Step::Skip;
        }

        let msg = match String::from_utf8(msg) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Error processing binary message: {:?}", e);
                return Step::Skip;
            }
        };

        let (state, session) = (&self.state, &self.session);
        state.monitor.received(
            &session.did_hash,
            Channel::Websocket,
            Protocol::DidComm,
            msg.as_bytes(),
        );
        if let Err(e) =
            crate::monitor::with_channel(Channel::Websocket, handle_inbound(state, session, &msg))
                .await
        {
            state.monitor.refused(
                &session.did_hash,
                Channel::Websocket,
                Protocol::DidComm,
                msg.as_bytes(),
                &e,
            );
            // Told as a Text frame refusal is: a client that frames DIDComm
            // as Binary must not take a refused message for a sent one (R1.1).
            report_refusal(&self.state, &self.session, &mut self.socket, e).await;
            return Step::Skip;
        }
        Step::Proceed
    }

    /// A TSP frame.
    #[cfg(feature = "tsp")]
    async fn on_tsp(&mut self, msg: &[u8]) -> Step {
        let (state, session) = (&self.state, &self.session);
        state
            .monitor
            .received(&session.did_hash, Channel::Websocket, Protocol::Tsp, msg);
        let Err(e) = crate::monitor::with_channel(
            Channel::Websocket,
            handle_inbound_tsp(state, session, msg),
        )
        .await
        else {
            return Step::Skip;
        };
        state.monitor.refused(
            &session.did_hash,
            Channel::Websocket,
            Protocol::Tsp,
            msg,
            &e,
        );
        warn!("WebSocket TSP inbound error: {}", e);
        // The sender's write already succeeded, so a refusal that is only
        // logged leaves it believing the message went (R1.1). A raw-TSP socket
        // has no in-band error frame: the one thing it can say is why it is
        // closing.
        //
        // A `tsp-mux` socket does have one: the `refused` event, so one
        // member's bad frame does not take every member offline. It closes
        // only for a failure of the principal itself (here, its account
        // blocked), or when the event cannot be sealed — then closing is the
        // only report left.
        if let Some(conn) = &self.tsp_mux_conn
            && !self.session.acls.get_blocked()
            && let Some(frame) =
                crate::mux::connection::refused_event(&self.state, conn, msg, &e).await
        {
            if let Err(e) = self.socket.send(frame.into()).await {
                warn!("Failed to send mux refused event: {e}");
                return Step::Close((close_code::GOING_AWAY, "client disconnected"));
            }
            return Step::Skip;
        }
        if self.mode.is_tsp() {
            return Step::Close(tsp_refusal_close(&e));
        }
        // A DIDComm socket can carry the problem report itself.
        report_refusal(&self.state, &self.session, &mut self.socket, e).await;
        Step::Skip
    }

    /// The mux connection changed (members attached, detached, narrowed):
    /// tell the client.
    async fn on_mux_changes(&mut self) {
        if let Some(conn) = &self.mux_conn {
            for frame in
                crate::mux::connection::drain_changes(&self.state, conn, self.mux_wire).await
            {
                if let Err(e) = self.socket.send(frame.into()).await {
                    warn!("Failed to send mux event to WebSocket client: {e}");
                }
            }
        }
    }

    /// Members' live delivery moved or came back.
    async fn on_member_changes(&mut self) {
        if let (Some(conn), Some(slots)) = (&self.mux_conn, &self.mux_slots) {
            for change in slots.take_member_changes() {
                if let Some(frame) = crate::mux::connection::on_member_change(
                    &self.state,
                    conn,
                    change,
                    self.mux_wire,
                )
                .await
                    && let Err(e) = self.socket.send(frame.into()).await
                {
                    warn!("Failed to send mux event to WebSocket client: {e}");
                }
            }
        }
    }

    async fn on_ping_tick(&mut self) -> Step {
        #[cfg(feature = "test-hooks")]
        let starts_wait = self.socket.pings.deadline().is_none();
        if let Err(e) = self.socket.ping(self.liveness.grace).await {
            debug!("Failed to send WebSocket ping: {e}");
            return Step::Close((close_code::GOING_AWAY, "connection unresponsive"));
        }
        #[cfg(feature = "test-hooks")]
        if starts_wait && let Some(stall) = test_hooks::stall_after_ping(&self.session.did_hash) {
            tokio::time::sleep(stall).await;
        }
        Step::Proceed
    }

    /// A command the streaming task (or the mux registry) queued for this
    /// socket.
    async fn on_queued(&mut self, queued: QueuedCommand) -> Step {
        // On a mux connection a member's frame is written only while the
        // member holds `receive`, checked now rather than when it was queued:
        // after a detach (revoke, expiry, key change) or a narrowing that
        // dropped `receive`, nothing more is pushed for that DID. A member
        // holding only `pickup` is told its mail waits instead. Either way the
        // message stays in the member's inbox (§7.3, R1.1).
        // A nudge must not skip the after-pass checks: the resync it raises
        // is acted on there, in this pass.
        if let (Some(conn), Some(for_did)) = (&self.mux_conn, queued.did_hash.as_deref()) {
            use crate::mux::registry::LiveFrame;
            match conn.live_frame(for_did, self.state.clock.unix_secs()).await {
                LiveFrame::Write => {}
                LiveFrame::Nudge => {
                    metrics::counter!(MUX_LIVE_FRAMES_WITHHELD_TOTAL, "outcome" => "nudge")
                        .increment(1);
                    debug!(did_hash = %for_did, "pickup-only mux member has mail; resync raised");
                    conn.nudge(for_did);
                    return Step::Proceed;
                }
                LiveFrame::Drop => {
                    metrics::counter!(MUX_LIVE_FRAMES_WITHHELD_TOTAL, "outcome" => "drop")
                        .increment(1);
                    debug!(did_hash = %for_did, "dropping a queued frame for a mux member without receive");
                    return Step::Skip;
                }
            }
        }
        // A stored message's delivery, reported only once its frame is
        // written (R1.1). `queued` (and with it the message's share of the
        // global send pool) is released when this returns, after the write.
        let report = queued.report;
        match queued.cmd {
            WebSocketCommands::Message(msg) => {
                debug!("ws: Received message from streaming task");
                // On a `tsp-mux` socket a member's notification is that
                // member's live frame, written as it is: its stored inbox is
                // walked only by a drain, and only with `pickup`.
                #[cfg(feature = "tsp")]
                if let Some(conn) = &self.tsp_mux_conn
                    && let Some(for_did) = queued.did_hash.as_deref()
                    && for_did != self.session.did_hash
                {
                    match send_tsp_member_live(
                        conn,
                        for_did,
                        self.state.clock.unix_secs(),
                        &mut self.socket,
                        &msg,
                        &mut self.member_inflight,
                    )
                    .await
                    {
                        ControlFlow::Break(()) => {
                            return Step::Close((close_code::GOING_AWAY, "client disconnected"));
                        }
                        ControlFlow::Continue(true) => {
                            if let Some(r) = report {
                                r.written(&self.state).await;
                            }
                        }
                        ControlFlow::Continue(false) => {}
                    }
                    return Step::Skip;
                }
                // In raw-TSP mode the notification body carries no id we can
                // delete by, so it's just a wake-up: re-drain the inbox (which
                // re-fetches with ids, sends Binary, and deletes-on-send). The
                // DIDComm path sends the body as Text.
                if self.mode.is_tsp() {
                    // The body is ignored: the drain re-fetches with ids and
                    // reports what it writes, so this notification is not
                    // itself a delivery. Answered after this pass, together
                    // with any queued behind it.
                    drop(report);
                    #[cfg(feature = "tsp")]
                    {
                        self.tsp_drain_owed += 1;
                    }
                } else {
                    match self.socket.send(Message::Text(msg.into())).await {
                        Ok(()) => {
                            if let Some(r) = report {
                                r.written(&self.state).await;
                            }
                        }
                        Err(e) => warn!("Failed to send message to WebSocket client: {e}"),
                    }
                }
            }
            WebSocketCommands::Verbatim(body) => {
                // The body IS the frame: a monitor batch, pushed and stored
                // nowhere, so there is no inbox to drain for it. A raw-TSP
                // socket gets it as the Binary qb2 its client expects, decoded
                // from the base64url the live channel carries; every other
                // socket gets it as Text, the same shape an ordinary push has.
                #[cfg(feature = "tsp")]
                if self.mode.is_tsp() {
                    match BASE64_URL_SAFE_NO_PAD.decode(&body) {
                        Ok(qb2) => match self.socket.send(Message::Binary(qb2.into())).await {
                            Ok(()) => {
                                if let Some(r) = report {
                                    r.emit(&self.state.monitor);
                                }
                            }
                            Err(e) => warn!("Failed to send frame to WebSocket client: {e}"),
                        },
                        Err(e) => warn!(
                            did_hash = %self.session.did_hash,
                            "dropping a verbatim frame that isn't base64url: {e}"
                        ),
                    }
                    return Step::Skip;
                }
                match self.socket.send(Message::Text(body.into())).await {
                    Ok(()) => {
                        if let Some(r) = report {
                            r.emit(&self.state.monitor);
                        }
                    }
                    Err(e) => warn!("Failed to send frame to WebSocket client: {e}"),
                }
            }
            WebSocketCommands::MemberChange(change) => {
                if let Some(conn) = &self.mux_conn
                    && let Some(frame) = crate::mux::connection::on_member_change(
                        &self.state,
                        conn,
                        change,
                        self.mux_wire,
                    )
                    .await
                    && let Err(e) = self.socket.send(frame.into()).await
                {
                    warn!("Failed to send mux event to WebSocket client: {e}");
                }
            }
            WebSocketCommands::Close(why) => {
                // A raw-TSP socket carries TSP frames only, so it gets no
                // DIDComm problem report: the close frame's code and reason
                // say why.
                #[cfg(feature = "didcomm")]
                if !self.mode.is_tsp()
                    && let Ok(msg) = _package_problem_report(
                        &self.state,
                        &self.session,
                        None,
                        _close_problem_report(why),
                    )
                    .await
                    && let Err(e) = self.socket.send(Message::Text(msg.into())).await
                {
                    warn!("Failed to send message to WebSocket client: {e}");
                }
                debug!(reason = ?why, "Streaming task requested close");
                // The streaming task has dropped this socket's registration
                // (e.g. a newer socket replaced it); deregistering now would
                // remove the successor.
                self.slot.deregistered_by_streaming();
                return Step::Close(_close_frame_reason(why));
            }
        }
        Step::Proceed
    }

    /// Drain the raw-TSP inbox onto the socket: the principal's when
    /// `principal`, the members' when `members` is `Some` (and this is a
    /// `tsp-mux` socket), each limited to `only` when it names DIDs. On a
    /// `tsp-mux` socket — or always, with `always_yield` — the drain stops for
    /// live frames waiting in the queue and leaves the rest for later. `true`
    /// when the socket has gone.
    #[cfg(feature = "tsp")]
    async fn drain(
        &mut self,
        principal: bool,
        members: Option<Option<&std::collections::HashSet<String>>>,
        always_yield: bool,
    ) -> bool {
        let conn = self.tsp_mux_conn.clone();
        let members = match (conn.as_deref(), members) {
            (Some(conn), Some(only)) => Some((conn, &mut self.member_inflight, only)),
            _ => None,
        };
        let yield_to = (always_yield || conn.is_some()).then_some((&self.rx, self.fair.as_ref()));
        drain_tsp_inbox(
            &self.state,
            &self.session,
            &mut self.socket,
            self.mode.tsp_ack(),
            &mut self.tsp_inflight,
            principal,
            members,
            yield_to,
        )
        .await
        .map_continue(|rest| TspDrainRest::merge(&mut self.tsp_drain_rest, rest))
        .is_break()
    }

    /// The checks after every wake-up that did not skip them: owed and
    /// resumed raw-TSP drains, and a resync for a dropped live notification.
    /// `Some` closes the connection.
    async fn after_pass(&mut self) -> Option<CloseFrameReason> {
        // Principal wake-ups, answered by one drain once nothing more is
        // queued behind them (raw TSP).
        #[cfg(feature = "tsp")]
        if self.tsp_drain_owed > 0
            && (self.rx.is_empty() || self.tsp_drain_owed >= TSP_DRAIN_COALESCE)
        {
            self.tsp_drain_owed = 0;
            if self.drain(true, None, false).await {
                return Some((close_code::GOING_AWAY, "client disconnected"));
            }
        }

        // A drain cut short so live frames could go first, resumed once they
        // have (`tsp-mux` fairness: one member's backlog must not hold
        // another's live frame behind it).
        #[cfg(feature = "tsp")]
        if queue_idle(&self.rx, self.fair.as_ref())
            && let Some(rest) = self.tsp_drain_rest.take()
        {
            let members = rest.members.then_some(rest.only.as_ref());
            if self.drain(rest.principal, members, true).await {
                return Some((close_code::GOING_AWAY, "client disconnected"));
            }
        }

        self.resync().await
    }

    /// A live notification was dropped while this socket was congested: tell
    /// the client its inbox holds more, no more often than the floor allows.
    async fn resync(&mut self) -> Option<CloseFrameReason> {
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
        let raised = self.live_resync.load(std::sync::atomic::Ordering::Relaxed);
        if raised && !resync_due(raised, self.last_resync_sent.elapsed()) {
            metrics::counter!(WS_LIVE_RESYNC_SUPPRESSED).increment(1);
        }
        if !resync_due(raised, self.last_resync_sent.elapsed()) {
            return None;
        }
        // Cleared before the send, so a drop landing during it raises the
        // flag again rather than being folded into a signal already on its
        // way out.
        self.live_resync
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.last_resync_sent = Instant::now();
        metrics::counter!(WS_LIVE_RESYNC_SENT).increment(1);
        #[cfg(feature = "tsp")]
        if self.mode.is_tsp() {
            // A TSP notification is only ever a wake-up, so the resync *is*
            // the drain — there is no separate signal to send.
            //
            // On `tsp-mux` the resync is owed per DID, as on a DIDComm mux
            // connection: the members whose pushes were dropped are drained
            // (those with `pickup`; a `receive`-only member's frames stay
            // stored for its next connection). The principal's own inbox is
            // always drained, which is cheap and safe under ack mode.
            let owed: Option<std::collections::HashSet<String>> = self
                .mux_slots
                .as_ref()
                .filter(|_| self.tsp_mux_conn.is_some())
                .map(|slots| slots.take_resync().into_iter().collect());
            if self.drain(true, Some(owed.as_ref()), false).await {
                return Some((close_code::GOING_AWAY, "client disconnected"));
            }
            return None;
        }
        // Whose inbox each status reports. A direct socket carries one DID. A
        // mux connection's resync is owed per DID, to the ones whose pushes
        // were dropped, and never to a member that has left since (R7.2); the
        // statuses all go to the principal. A status is message pickup for
        // that inbox, so a member is reported only while its scope includes
        // `pickup`; a `receive`-only member's dropped frame stays in its
        // inbox, where the principal could not collect it anyway.
        #[cfg(feature = "didcomm")]
        {
            let owed: Vec<(String, String)> = match (&self.mux_conn, &self.mux_slots) {
                (Some(conn), Some(slots)) => {
                    let hashes = slots.take_resync();
                    let now = self.state.clock.unix_secs();
                    let s = conn.session.lock().await;
                    hashes
                        .into_iter()
                        .filter_map(|h| {
                            if h == self.session.did_hash {
                                Some((self.session.did.clone(), h))
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
                _ => vec![(self.session.did.clone(), self.session.did_hash.clone())],
            };
            for (did, did_hash) in owed {
                match _package_status_for(&self.state, &self.session, &did, &did_hash).await {
                    Ok(packed) => {
                        if let Err(e) = self.socket.send(Message::Text(packed.into())).await {
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
        None
    }
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
