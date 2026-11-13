//! Connection-level hardening for the HTTP listener (#143).
//!
//! The per-IP rate limiter only sees complete requests, so without these a
//! client could hold a file descriptor and a task for as long as it liked by
//! sending headers slowly, by never sending anything, or by leaving a
//! keep-alive connection idle. Here:
//!
//! - [`configure`] gives hyper a timer, without which its HTTP/1
//!   `header_read_timeout` does nothing. That timeout runs whenever the
//!   connection waits for a request's headers, so it bounds slow headers and
//!   idle keep-alive connections alike. HTTP/2 connections are pinged, and
//!   closed when a ping goes unanswered.
//! - [`ConnectionLimit`] wraps the listener's acceptor: it caps the
//!   connections open at once (`limits.max_http_connections`), closing one
//!   over the cap as soon as it is accepted, and gives each connection a
//!   deadline for its first bytes. hyper's protocol detection (HTTP/1 or
//!   HTTP/2) waits for those bytes with no timeout of its own.
//!
//! The per-request timeout (`limits.http_request_timeout_secs`) is a
//! `TimeoutLayer` on the routes; see `handlers::application_routes`.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum_server::accept::Accept;
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Sleep,
};
use tracing::warn;

use super::{config::limits::LimitsConfig, metrics::names};

/// How often an idle HTTP/2 connection is pinged.
pub const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// How long an HTTP/2 ping may go unanswered before the connection is closed.
pub const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Apply the connection timeouts in `limits` to the server's protocol builder.
pub fn configure(builder: &mut Builder<TokioExecutor>, limits: &LimitsConfig) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(limits.http_header_read_timeout_secs));
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
}

/// An acceptor that caps the connections open at once and gives each one a
/// deadline for its first bytes, around an inner acceptor (plain TCP, or TLS).
///
/// The cap is taken before the inner acceptor runs, so a connection over it
/// is closed before any TLS handshake is spent on it.
#[derive(Clone)]
pub struct ConnectionLimit<A> {
    inner: A,
    /// `None` = unlimited.
    permits: Option<Arc<Semaphore>>,
    first_bytes_within: Duration,
}

impl<A> ConnectionLimit<A> {
    /// `max_connections` of 0 means unlimited.
    pub fn new(inner: A, max_connections: usize, first_bytes_within: Duration) -> Self {
        Self {
            inner,
            permits: (max_connections > 0)
                .then(|| Arc::new(Semaphore::new(max_connections.min(Semaphore::MAX_PERMITS)))),
            first_bytes_within,
        }
    }

    /// Take a slot for a new connection, or `None` when the cap is reached.
    fn admit(&self) -> Option<ConnectionSlot> {
        let permit = match &self.permits {
            None => None,
            Some(permits) => Some(permits.clone().try_acquire_owned().ok()?),
        };
        metrics::gauge!(names::HTTP_CONNECTIONS_OPEN).increment(1.0);
        Some(ConnectionSlot { _permit: permit })
    }
}

/// When the last "connection cap reached" warning was logged (UNIX seconds),
/// so a flood logs once a minute rather than once per connection.
static LAST_CAP_WARNING: AtomicU64 = AtomicU64::new(0);

fn note_refused() {
    metrics::counter!(names::HTTP_CONNECTIONS_REFUSED_TOTAL).increment(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let last = LAST_CAP_WARNING.load(Ordering::Relaxed);
    if now >= last + 60
        && LAST_CAP_WARNING
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!(
            "HTTP connection cap (limits.max_http_connections) reached: closing new connections \
             until some close. Counted in http_connections_refused_total"
        );
    }
}

type AcceptFuture<S, M> = Pin<Box<dyn Future<Output = io::Result<(S, M)>> + Send>>;

impl<A, I, S> Accept<I, S> for ConnectionLimit<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
    I: Send + 'static,
{
    type Stream = LimitedStream<A::Stream>;
    type Service = A::Service;
    type Future = AcceptFuture<Self::Stream, Self::Service>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let Some(slot) = self.admit() else {
            note_refused();
            // Dropping the stream closes the connection now.
            drop(stream);
            return Box::pin(std::future::ready(Err(io::Error::other(
                "HTTP connection cap reached",
            ))));
        };
        let inner = self.inner.accept(stream, service);
        let first_bytes_within = self.first_bytes_within;
        // A failed TLS handshake drops `slot`, giving the connection back.
        Box::pin(async move {
            let (stream, service) = inner.await?;
            Ok((
                LimitedStream::new(stream, slot, first_bytes_within),
                service,
            ))
        })
    }
}

/// One connection's share of the cap, held for as long as the connection is
/// open (an upgraded WebSocket included).
struct ConnectionSlot {
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        metrics::gauge!(names::HTTP_CONNECTIONS_OPEN).decrement(1.0);
    }
}

/// A connection's stream, holding its slot under the cap and failing a read
/// with `TimedOut` if no bytes at all arrive before the first-bytes deadline.
pub struct LimitedStream<S> {
    inner: S,
    _slot: ConnectionSlot,
    /// Until the first bytes arrive.
    first_bytes: Option<Pin<Box<Sleep>>>,
}

impl<S> LimitedStream<S> {
    fn new(inner: S, slot: ConnectionSlot, first_bytes_within: Duration) -> Self {
        Self {
            inner,
            _slot: slot,
            first_bytes: Some(Box::pin(tokio::time::sleep(first_bytes_within))),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if buf.filled().len() > before {
                    this.first_bytes = None;
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let expired = this
                    .first_bytes
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready());
                if expired {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no request on a new connection before the deadline",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Serve a one-route app on an ephemeral port with these limits, the way
    /// `serve_internal` does, and return its address.
    async fn serve(limits: LimitsConfig) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut server = axum_server::from_tcp(listener).unwrap().map(|inner| {
            ConnectionLimit::new(
                inner,
                limits.max_http_connections,
                Duration::from_secs(limits.http_header_read_timeout_secs),
            )
        });
        configure(server.http_builder(), &limits);
        let app = Router::new().route("/", get(|| async { "ok" }));
        tokio::spawn(server.serve(app.into_make_service()));
        addr
    }

    /// Read until the peer closes or `within` passes; `true` if it closed.
    async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
        let mut buf = [0u8; 1024];
        tokio::time::timeout(within, async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        })
        .await
        .is_ok()
    }

    fn limits(header_secs: u64, max_connections: usize) -> LimitsConfig {
        LimitsConfig {
            http_header_read_timeout_secs: header_secs,
            max_http_connections: max_connections,
            ..LimitsConfig::default()
        }
    }

    /// A client that sends half a request's headers and then stalls is cut
    /// off at the header-read timeout. Without a timer hyper never enforced
    /// it, so the connection was held for as long as the client liked.
    #[tokio::test]
    async fn slow_headers_are_cut_off() {
        let addr = serve(limits(1, 0)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        assert!(closed_within(&mut stream, Duration::from_secs(5)).await);
    }

    /// A connection that never sends anything is closed at the deadline too:
    /// protocol detection would otherwise wait for its first bytes forever.
    #[tokio::test]
    async fn a_silent_connection_is_closed() {
        let addr = serve(limits(1, 0)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert!(closed_within(&mut stream, Duration::from_secs(5)).await);
    }

    /// An idle keep-alive connection is closed after the header-read timeout.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed() {
        let addr = serve(limits(1, 0)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        assert!(closed_within(&mut stream, Duration::from_secs(5)).await);
    }

    /// Past the cap a new connection is closed at once; once a connection
    /// closes, its slot is free again.
    #[tokio::test]
    async fn connections_over_the_cap_are_closed() {
        let addr = serve(limits(30, 1)).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = first.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

        let mut second = TcpStream::connect(addr).await.unwrap();
        assert!(closed_within(&mut second, Duration::from_secs(5)).await);

        drop(first);
        // The server notices the close and gives the slot back.
        let mut answered = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut third = TcpStream::connect(addr).await.unwrap();
            if third
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .is_err()
            {
                continue;
            }
            if let Ok(n) = third.read(&mut buf).await
                && String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200")
            {
                answered = true;
                break;
            }
        }
        assert!(answered, "a freed slot admits a new connection");
    }
}
