//! Write deadlines and ping liveness for one socket.

use super::*;

/// How long the connection loop waits on the peer.
///
/// `ws_write_timeout_secs` bounds one write: a peer that stops reading leaves
/// a write parked once its TCP window closes, and without a bound the
/// connection would hold its slots and queued frames until the kernel gives
/// up on it.
///
/// `ws_pong_timeout_secs` bounds silence: a peer that has gone away without
/// closing (a dropped network, a suspended device) answers no ping. The clock
/// starts at a ping that is still unanswered, and the peer gets
/// `pong_timeout - ping_interval` (the "grace") from then to send any frame;
/// so a silent peer is closed within `pong_timeout` of its last frame. Only
/// time the loop spends able to read counts: see [`PingWatch::after_pass`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Liveness {
    pub(super) ping_interval: Duration,
    pub(super) write_timeout: Duration,
    /// How long an unanswered ping waits for any frame from the peer.
    pub(super) grace: Duration,
}

impl Liveness {
    pub(super) fn from_limits(limits: &crate::common::config::LimitsConfig) -> Self {
        // The same rules the file configuration gets, so a `LimitsConfig`
        // built in code (tests, embedders) cannot skip them.
        let ((ping, pong, write), notes) = crate::common::config::limits::websocket_liveness(
            limits.ws_ping_interval_secs,
            limits.ws_pong_timeout_secs,
            limits.ws_write_timeout_secs,
        );
        for note in notes {
            warn!("{note}");
        }
        Self {
            ping_interval: Duration::from_secs(ping),
            write_timeout: Duration::from_secs(write),
            grace: Duration::from_secs(pong - ping),
        }
    }
}

/// Whether a ping is waiting for the peer, and until when.
///
/// Anchored to an unanswered ping rather than to the last frame read, so time
/// the connection loop spends not reading (a long flush-on-connect, a slow
/// inbound message) is never held against the peer: the loop sends no pings
/// while it is busy, and [`after_pass`](Self::after_pass) gives an
/// outstanding ping a fresh window if its deadline passed meanwhile.
#[derive(Debug, Default)]
pub(super) struct PingWatch {
    pub(super) deadline: Option<tokio::time::Instant>,
    /// Fresh windows given to the ping now waiting; see
    /// [`MAX_EXTENSIONS`](Self::MAX_EXTENSIONS).
    pub(super) extensions: u8,
}

impl PingWatch {
    /// At most this many fresh windows for one unanswered ping. A loop kept
    /// busy by other traffic must not keep a peer that has gone away open
    /// window after window; a peer that is there answers within the first.
    pub(super) const MAX_EXTENSIONS: u8 = 2;

    /// A ping went out. Starts the clock unless an earlier ping is already
    /// waiting, which keeps its own (earlier) deadline.
    pub(super) fn ping_sent(&mut self, grace: Duration) {
        if self.deadline.is_none() {
            self.deadline = Some(tokio::time::Instant::now() + grace);
            self.extensions = 0;
        }
    }

    /// A frame arrived: the peer is there, nothing is waiting.
    pub(super) fn answered(&mut self) {
        self.deadline = None;
        self.extensions = 0;
    }

    /// Called before the loop waits again; `woke` is when the last wait
    /// ended. If the deadline passed after that, while the loop was busy
    /// elsewhere, the peer's answer may be sitting unread, so the ping gets
    /// `window` more, in which the loop *is* reading, up to
    /// [`MAX_EXTENSIONS`](Self::MAX_EXTENSIONS) times. A deadline already due
    /// when the wait ended (another branch won the tie) is left as it is.
    pub(super) fn after_pass(&mut self, woke: tokio::time::Instant, window: Duration) {
        let now = tokio::time::Instant::now();
        if let Some(deadline) = self.deadline
            && deadline > woke
            && deadline <= now
            && self.extensions < Self::MAX_EXTENSIONS
        {
            self.deadline = Some(now + window);
            self.extensions += 1;
        }
    }

    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

/// A [`WebSocket`] whose writes are bounded by a deadline, and which tracks
/// whether its last ping has been answered.
///
/// A write that runs out of time may have left part of a frame on the wire,
/// so the socket is unusable after it: every later write fails at once, and
/// the connection loop closes on [`BoundedSocket::stalled`].
pub(super) struct BoundedSocket {
    pub(super) inner: WebSocket,
    pub(super) write_timeout: Duration,
    pub(super) stalled: bool,
    pub(super) pings: PingWatch,
}

impl BoundedSocket {
    pub(super) fn new(inner: WebSocket, write_timeout: Duration) -> Self {
        Self {
            inner,
            write_timeout,
            stalled: false,
            pings: PingWatch::default(),
        }
    }

    pub(super) async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        let write = self.inner.send(msg);
        bounded_write(&mut self.stalled, self.write_timeout, write).await
    }

    /// Send a ping and, once it is written, start waiting for an answer.
    pub(super) async fn ping(&mut self, grace: Duration) -> Result<(), axum::Error> {
        self.send(Message::Ping(Vec::new().into())).await?;
        self.pings.ping_sent(grace);
        Ok(())
    }

    /// The next frame from the peer. Any complete frame, a pong included,
    /// answers an outstanding ping.
    pub(super) async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        let frame = self.inner.recv().await;
        if matches!(frame, Some(Ok(_))) {
            self.pings.answered();
        }
        frame
    }

    /// A write timed out; the connection should close.
    pub(super) fn stalled(&self) -> bool {
        self.stalled
    }
}

/// Run `write` within `limit`. A timeout marks the socket `stalled`, and a
/// stalled socket's writes fail without being attempted. Either way the
/// caller sees an error, so nothing is reported as written that wasn't.
pub(super) async fn bounded_write<F>(
    stalled: &mut bool,
    limit: Duration,
    write: F,
) -> Result<(), axum::Error>
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
                    "WebSocket write did not complete within {}ms",
                    limit.as_millis()
                ),
            )))
        }
    }
}
