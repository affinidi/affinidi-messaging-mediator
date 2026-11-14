//! Raw-TSP inbox delivery: draining stored messages onto the socket, for the
//! principal and, on a `tsp-mux` socket, its members.

use super::*;

/// The most principal wake-ups one TSP drain answers while more keep
/// arriving; past this it drains anyway, so a steady stream is still
/// delivered.
#[cfg(feature = "tsp")]
pub(super) const TSP_DRAIN_COALESCE: usize = 64;

/// Page size for the TSP inbox drain — reuses the same shape as
/// [`crate::tasks::websocket_streaming`]'s redelivery drain.
#[cfg(feature = "tsp")]
pub(super) const TSP_DRAIN_PAGE: usize = 50;

/// Safety bound on how many messages a single TSP drain will push, so a
/// pathologically large inbox can't pin the socket loop. If hit, the
/// remainder is left for the next drain (the next live-delivery wake-up
/// re-fetches from the head of the inbox).
#[cfg(feature = "tsp")]
pub(super) const TSP_DRAIN_MAX: usize = 1000;

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
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_tsp_inbox(
    state: &SharedData,
    session: &Session,
    socket: &mut BoundedSocket,
    ack_mode: bool,
    inflight: &mut std::collections::HashSet<String>,
    principal: bool,
    members: Option<(
        &crate::mux::registry::MuxConn,
        &mut MemberInflight,
        Option<&std::collections::HashSet<String>>,
    )>,
    yield_to: Option<(
        &Receiver<QueuedCommand>,
        Option<&crate::mux::fair_queue::FairOrder<QueuedCommand>>,
    )>,
) -> ControlFlow<(), Option<TspDrainRest>> {
    use affinidi_messaging_mediator_common::store::mux::MuxCapability;
    // Delete-on-send is never used for a member: `tsp-mux` forces ack mode.
    debug_assert!(ack_mode || members.is_none());
    let mut walk = TspDrainWalk {
        budget: TSP_DRAIN_MAX,
        total: 0,
    };

    // Live frames are waiting: stop between pages and say what is left.
    let live_waiting = || yield_to.is_some_and(|(rx, fair)| !queue_idle(rx, fair));
    let members_owed = members.as_ref().map(|(_, _, only)| only.cloned());

    // The principal's own inbox, to the end. Every id walked past (ack mode
    // only) is kept, to prune `inflight` against once the walk completes, so
    // ids the client has since acked stop occupying the set.
    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    loop {
        // Resuming a drain whose principal part was done already.
        if !principal {
            break;
        }
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
            TspPage::Stopped => return ControlFlow::Continue(None),
            TspPage::More if live_waiting() => {
                return ControlFlow::Continue(Some(TspDrainRest {
                    principal: true,
                    members: members_owed.is_some(),
                    only: members_owed.flatten(),
                }));
            }
            TspPage::More => continue,
            TspPage::Exhausted => break,
        }
    }
    if principal && ack_mode {
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
            let mut round = order.into_iter();
            while let Some(member) = round.next() {
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
                    TspPage::Stopped => return ControlFlow::Continue(None),
                    TspPage::More => still.push(member),
                    // This member's walk is complete: prune its set.
                    TspPage::Exhausted => inflight.retain(|id| seen.contains(id)),
                }
                // Another member's live frame is waiting: let it go first.
                // The members not done are drained again from the head of
                // their inbox, skipping what is already in flight.
                if live_waiting() {
                    let left: std::collections::HashSet<String> =
                        still.drain(..).chain(round.by_ref()).collect();
                    if left.is_empty() {
                        break;
                    }
                    return ControlFlow::Continue(Some(TspDrainRest {
                        principal: false,
                        members: true,
                        only: Some(left),
                    }));
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
    ControlFlow::Continue(None)
}

/// Nothing waits to be written: the channel is empty, and so are the fair
/// queue's lanes it was moved into.
#[cfg(feature = "tsp")]
pub(super) fn queue_idle(
    rx: &Receiver<QueuedCommand>,
    fair: Option<&crate::mux::fair_queue::FairOrder<QueuedCommand>>,
) -> bool {
    rx.is_empty() && fair.is_none_or(|f| f.is_empty())
}

/// What a [`drain_tsp_inbox`] on a `tsp-mux` socket left undone when live
/// frames were waiting: the principal's inbox, and the members (`only` =
/// those named, or every member with `pickup` when `None`).
#[cfg(feature = "tsp")]
#[derive(Debug)]
pub(super) struct TspDrainRest {
    pub(super) principal: bool,
    pub(super) members: bool,
    pub(super) only: Option<std::collections::HashSet<String>>,
}

#[cfg(feature = "tsp")]
impl TspDrainRest {
    /// Fold `more` into what is already pending.
    pub(super) fn merge(pending: &mut Option<TspDrainRest>, more: Option<TspDrainRest>) {
        let Some(more) = more else { return };
        *pending = Some(match pending.take() {
            None => more,
            Some(had) => {
                // Every member owed on either side means every member.
                let only = if (had.members && had.only.is_none())
                    || (more.members && more.only.is_none())
                {
                    None
                } else {
                    Some(had.only.into_iter().chain(more.only).flatten().collect())
                };
                TspDrainRest {
                    principal: had.principal || more.principal,
                    members: had.members || more.members,
                    only,
                }
            }
        });
    }
}

/// Members' pages are smaller than the principal's, so a round over many
/// members stays short.
#[cfg(feature = "tsp")]
pub(super) const TSP_MUX_MEMBER_PAGE: usize = 20;

/// The most ids one member's in-flight set holds. A set is pruned by a
/// complete drain of the member's inbox, which happens on connect and resync
/// only, and a member without `pickup` is never drained, so live frames
/// alone would grow it for the life of the connection. Past this the set is
/// cleared; the cost is a possible duplicate, which an at-least-once client
/// already handles.
#[cfg(feature = "tsp")]
pub(super) const TSP_MUX_MEMBER_INFLIGHT_MAX: usize = 1024;

/// In-flight ids per member DID hash, on a `tsp-mux` socket.
#[cfg(feature = "tsp")]
pub(super) type MemberInflight =
    std::collections::HashMap<String, std::collections::HashSet<String>>;

/// The budget shared by every page of one drain.
#[cfg(feature = "tsp")]
pub(super) struct TspDrainWalk {
    /// Frames this drain may still send ([`TSP_DRAIN_MAX`] in all).
    pub(super) budget: usize,
    pub(super) total: usize,
}

/// How one page of a drain ended.
#[cfg(feature = "tsp")]
pub(super) enum TspPage {
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
pub(super) async fn drain_tsp_page(
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
            did_hash,
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
pub(super) async fn drain_tsp_elements(
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
                // The copy just delivered to this DID, never one it sent.
                .delete_message_in(
                    &id,
                    MessageScope::Recipient(did_hash),
                    DeletionAuthority::Owner {
                        did_hash: did_hash.to_string(),
                    },
                )
                .await
            {
                Ok(_) => state.monitor.deleted(
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
pub(super) async fn send_tsp_member_live(
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
