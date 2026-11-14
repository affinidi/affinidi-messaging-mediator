//! Work that may only happen once a reply has been handed to its transport.
//!
//! R1.1: "acks, `delivered` monitor events and queue deletions must follow the
//! actual write". A handler that hands stored messages to a client — a REST
//! fetch, a Message Pickup `delivery` — builds its reply long before anything
//! is written, and the reply can still fail after it returns: packing fails,
//! the client disconnects, the body is never fully sent. Reporting the
//! messages delivered (or deleting them) from inside the handler claims a
//! delivery that may not happen.
//!
//! So such a handler does not act; it hands the action here as a
//! [`Completion`], and the transport runs it once the reply is out:
//!
//! - **REST** runs the handler inside [`collect`], then wraps the response
//!   body with [`on_body_written`]. The completions run once the whole body
//!   has been handed to the HTTP connection; a body that is dropped before
//!   then (the client went away, the write failed) runs nothing, so nothing
//!   is deleted or reported.
//! - **A live stream** (a WebSocket pickup, whose reply is pushed through the
//!   streaming task) runs them as soon as the push is accepted — see
//!   [`defer_or_run`].
//!
//! Outside both (no REST scope, nothing pushed) a completion is dropped: the
//! reply reached no transport, so nothing it describes happened.

use affinidi_messaging_mediator_common::store::MediatorStoreExt;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use axum::body::{Body, Bytes, HttpBody};

/// One deferred action.
pub(crate) type Completion = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// The completions a request's handler deferred.
#[derive(Clone, Default)]
pub(crate) struct AfterWrite(Arc<Mutex<Vec<Completion>>>);

impl AfterWrite {
    /// Add a completion to run after the write, after those already added.
    pub(crate) fn push_completion(&self, completion: Completion) {
        self.push(completion);
    }

    fn push(&self, completion: Completion) {
        if let Ok(mut pending) = self.0.lock() {
            pending.push(completion);
        }
    }

    fn take(&self) -> Vec<Completion> {
        self.0
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default()
    }

    /// Whether nothing was deferred.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().map(|p| p.is_empty()).unwrap_or(true)
    }

    /// Run every deferred completion, in the order they were deferred.
    #[cfg(test)]
    pub(crate) async fn run(self) {
        for completion in self.take() {
            completion.await;
        }
    }

    /// Run them on a task of their own: for a caller (a body's `Drop`) that
    /// cannot wait. Needs a Tokio runtime; without one nothing runs, which is
    /// the conservative outcome.
    fn spawn(self) {
        let pending = self.take();
        if pending.is_empty() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    for completion in pending {
                        completion.await;
                    }
                });
            }
            Err(_) => tracing::warn!(
                "a reply was written outside a Tokio runtime; its deliveries are not recorded"
            ),
        }
    }
}

tokio::task_local! {
    static AFTER_WRITE: AfterWrite;
}

/// Run `f` with a fresh scope for deferred completions, returning its output
/// and what it deferred. The caller decides when (and whether) to run them.
pub(crate) async fn collect<F: Future>(f: F) -> (F::Output, AfterWrite) {
    let after = AfterWrite::default();
    // Boxed: `f` is a whole inbound handler, and a scope around it inline
    // would double its size on the caller's stack.
    let output = AFTER_WRITE.scope(after.clone(), Box::pin(f)).await;
    (output, after)
}

/// Whether the current task runs inside [`collect`].
#[cfg(test)]
pub(crate) fn in_scope() -> bool {
    AFTER_WRITE.try_with(|_| ()).is_ok()
}

/// Defer `completion` to the enclosing [`collect`] scope. Returns it back when
/// there is no scope, so the caller can decide what an unscoped write means.
#[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
pub(crate) fn defer(completion: Completion) -> Result<(), Completion> {
    match AFTER_WRITE.try_with(|after| after.clone()) {
        Ok(after) => {
            after.push(completion);
            Ok(())
        }
        Err(_) => Err(completion),
    }
}

/// For a reply that may travel two ways: deferred to the REST body when the
/// request came in over REST (the body is the reply the client reads), else
/// run now when `pushed` — the reply was accepted by a live stream — and
/// otherwise dropped, because no transport took the reply.
#[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
pub(crate) async fn defer_or_run(completion: Completion, pushed: bool) {
    match defer(completion) {
        Ok(()) => {}
        Err(completion) if pushed => completion.await,
        Err(_) => {
            tracing::debug!("reply reached no transport; its deliveries are not recorded");
        }
    }
}

/// Wrap `body` so that `after` runs once the whole body has been handed to the
/// HTTP connection, and never if it is dropped part-way (or before the first
/// byte). Size hints are passed through, so the response keeps its
/// `Content-Length`.
pub(crate) fn on_body_written(body: Body, after: AfterWrite) -> Body {
    if after.is_empty() {
        return body;
    }
    Body::new(CompletionBody {
        inner: body,
        after: Some(after),
        finished: false,
    })
}

/// [`on_body_written`] for a whole response.
pub(crate) fn respond_then(
    response: axum::response::Response,
    after: AfterWrite,
) -> axum::response::Response {
    let (parts, body) = response.into_parts();
    axum::response::Response::from_parts(parts, on_body_written(body, after))
}

struct CompletionBody {
    inner: Body,
    after: Option<AfterWrite>,
    /// Every frame has been handed out.
    finished: bool,
}

impl CompletionBody {
    fn complete(&mut self) {
        if let Some(after) = self.after.take() {
            after.spawn();
        }
    }
}

impl HttpBody for CompletionBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(None) => {
                self.finished = true;
                self.complete();
            }
            // A body of known length is not polled again once its last byte
            // is out: hyper stops at `Content-Length`. That frame is the end,
            // and the completion runs when the connection drops the body
            // (below), after it took the frame.
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => self.finished = true,
            // A failed body was not written.
            Poll::Ready(Some(Err(_))) => self.after = None,
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CompletionBody {
    fn drop(&mut self) {
        if self.finished {
            self.complete();
        }
    }
}

/// One stored message a reply hands over.
#[derive(Clone, Debug)]
pub(crate) struct HandedOverMessage {
    pub msg_id: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub size: u64,
    pub protocol: crate::monitor::Protocol,
}

impl HandedOverMessage {
    pub(crate) fn of(
        element: &affinidi_messaging_mediator_common::types::messages::MessageListElement,
    ) -> Self {
        Self {
            msg_id: element.msg_id.clone(),
            from: element.from_address.clone(),
            to: element.to_address.clone(),
            size: element.size,
            protocol: element.msg.as_deref().map_or(
                crate::monitor::Protocol::Other,
                crate::monitor::Protocol::detect,
            ),
        }
    }
}

/// The stored messages one reply hands to `recipient_did_hash`: what is
/// stamped delivered and reported `delivered` once the reply is written, and
/// only then. Built from the messages actually placed in the reply, never from
/// what was fetched.
#[derive(Clone, Debug, Default)]
pub(crate) struct HandedOver {
    pub recipient_did_hash: String,
    pub messages: Vec<HandedOverMessage>,
}

impl HandedOver {
    pub(crate) fn new(recipient_did_hash: &str) -> Self {
        Self {
            recipient_did_hash: recipient_did_hash.to_string(),
            messages: Vec::new(),
        }
    }

    /// The completion that records the handover: stamps each message
    /// delivered (the recipient's copy only) and emits one `delivered`
    /// monitor event per message on `channel`.
    pub(crate) fn completion(
        self,
        state: &crate::SharedData,
        channel: crate::monitor::Channel,
    ) -> Completion {
        let state = state.clone();
        Box::pin(async move {
            if self.messages.is_empty() {
                return;
            }
            let ids: Vec<String> = self.messages.iter().map(|m| m.msg_id.clone()).collect();
            if let Err(e) = state
                .database
                .record_delivered(
                    &self.recipient_did_hash,
                    &ids,
                    state.clock.unix_millis() as u64,
                    state.config.limits.delivered_expiry_seconds,
                )
                .await
            {
                tracing::warn!(
                    recipient = %self.recipient_did_hash,
                    "couldn't stamp {} written message(s) as delivered: {e}",
                    ids.len()
                );
            }
            for m in &self.messages {
                state.monitor.delivered_as(
                    &m.msg_id,
                    m.from.as_deref(),
                    m.to.as_deref(),
                    m.size,
                    channel,
                    m.protocol,
                );
            }
        })
    }
}

/// Fetch messages to hand over, without recording anything: the same selection
/// [`MediatorStore::fetch_messages_delivering`] makes (fair round-robin for a
/// fresh pickup when configured, stream order when paging), but neither
/// stamping nor deleting — the caller records the handover with
/// [`HandedOver::completion`] once the reply is written.
///
/// `options.delete_policy` is ignored: a delete is the caller's to make after
/// the write.
///
/// [`MediatorStore::fetch_messages_delivering`]: affinidi_messaging_mediator_common::store::MediatorStore::fetch_messages_delivering
pub(crate) async fn fetch_for_handover(
    state: &crate::SharedData,
    session_id: &str,
    did_hash: &str,
    options: &affinidi_messaging_sdk::messages::fetch::FetchOptions,
) -> Result<
    affinidi_messaging_sdk::messages::GetMessagesResponse,
    affinidi_messaging_mediator_common::errors::MediatorError,
> {
    use affinidi_messaging_sdk::messages::{FetchDeletePolicy, fetch::FetchOptions};
    let options = FetchOptions {
        limit: options.limit,
        start_id: options.start_id.clone(),
        delete_policy: FetchDeletePolicy::DoNotDelete,
    };
    if state.config.limits.pickup_round_robin && options.start_id.is_none() {
        state
            .database
            .fetch_messages_fair(session_id, did_hash, &options)
            .await
    } else {
        state
            .database
            .fetch_messages(session_id, did_hash, &options)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting(counter: &Arc<AtomicUsize>) -> Completion {
        let counter = counter.clone();
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        })
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_completion_outside_a_scope_is_handed_back() {
        let counter = Arc::new(AtomicUsize::new(0));
        assert!(!in_scope());
        assert!(defer(counting(&counter)).is_err());
        defer_or_run(counting(&counter), false).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0, "nothing pushed: not run");
        defer_or_run(counting(&counter), true).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "pushed: run now");
    }

    #[tokio::test]
    async fn a_scoped_completion_waits_for_the_caller() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let ((), after) = collect(async move {
            assert!(in_scope());
            defer_or_run(counting(&c), true).await;
        })
        .await;
        assert_eq!(counter.load(Ordering::SeqCst), 0, "deferred, not run");
        after.run().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// The body is read to its end: the completion runs.
    #[tokio::test]
    async fn a_fully_written_body_runs_its_completions() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ((), after) = collect(async {
            defer(counting(&counter)).ok().unwrap();
        })
        .await;
        let body = on_body_written(Body::from("hello"), after);
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"hello");
        settle().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// The connection went away before the body was sent: nothing runs.
    #[tokio::test]
    async fn a_body_dropped_unwritten_runs_nothing() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ((), after) = collect(async {
            defer(counting(&counter)).ok().unwrap();
        })
        .await;
        let body = on_body_written(Body::from("hello"), after);
        drop(body);
        settle().await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    /// A known-length body whose last frame was taken, then dropped without
    /// being polled to `None` (what hyper does at `Content-Length`): runs.
    #[tokio::test]
    async fn a_body_dropped_after_its_last_frame_runs() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ((), after) = collect(async {
            defer(counting(&counter)).ok().unwrap();
        })
        .await;
        let mut body = on_body_written(Body::from("hello"), after);
        assert_eq!(body.size_hint().exact(), Some(5), "Content-Length is kept");
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.into_data().unwrap(), "hello");
        drop(body);
        settle().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
