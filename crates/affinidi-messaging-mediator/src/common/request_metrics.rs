//! Per-request metrics + structured access-logging middleware.
//!
//! A single `axum::middleware::from_fn` layer that, for every routed request:
//! - tracks in-flight requests (gauge), total requests (counter), and request
//!   duration (histogram) — the `http_requests_*` metrics defined in
//!   [`super::metrics`];
//! - emits one structured `tracing` event (target `http_access`) with the
//!   request id, method, matched route, status, and latency. This is the
//!   mediator's only access log: the `TraceLayer` in `server.rs` opens a span
//!   for each request but logs no request or response events of its own.
//!
//! **Cancellation:** a request whose client goes away before the response is
//! ready has its future dropped mid-flight. The accounting lives in a drop
//! guard (`InFlight`), so the in-flight gauge is always given back, and the
//! request is still counted and logged, with the outcome `cancelled` in place
//! of a status code.
//!
//! **Cardinality and privacy:** the metric `route` label and the logged route
//! are the axum [`MatchedPath`] (the route *template*, e.g. `/inbound`), never
//! the raw URI — so path parameters can't blow up the Prometheus series count,
//! and a query string (`/oob?_oobid=…`, whose id is all it takes to fetch an
//! invitation) never reaches the log. Requests that don't match a route (404s)
//! are bucketed under a single `unmatched` label.
//!
//! Wired as the innermost layer in `server.rs`, so it runs after the request-id
//! layer has stamped the id and inside the router where `MatchedPath` is set.

use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::info;

use super::metrics::names;
use super::request_id::RequestId;

/// Label value used when a request matches no route (e.g. a 404).
const UNMATCHED_ROUTE: &str = "unmatched";

/// The `status` label (and logged outcome) of a request whose future was
/// dropped before it produced a response — normally a client that
/// disconnected.
pub(crate) const CANCELLED_OUTCOME: &str = "cancelled";

/// Middleware: record HTTP request metrics and emit a structured access log.
pub async fn track_request(req: Request, next: Next) -> Response {
    // Route *template* (bounded cardinality), not the raw path.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_owned());
    // Stamped by the outer `RequestIdLayer`; absent only if that layer is gone.
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let guard = InFlight::start(req.method().as_str().to_owned(), route, request_id);
    let response = next.run(req).await;
    guard.finish(&response.status().as_u16().to_string());
    response
}

/// One request in flight. Created when the request enters, it holds one unit
/// of the in-flight gauge until it is finished or dropped, and records the
/// request exactly once either way.
pub(crate) struct InFlight {
    start: Instant,
    method: String,
    route: String,
    request_id: String,
    done: bool,
}

impl InFlight {
    pub(crate) fn start(method: String, route: String, request_id: String) -> Self {
        metrics::gauge!(names::HTTP_REQUESTS_IN_FLIGHT).increment(1.0);
        Self {
            start: Instant::now(),
            method,
            route,
            request_id,
            done: false,
        }
    }

    /// The request produced a response with this status.
    pub(crate) fn finish(mut self, status: &str) {
        self.record(status);
    }

    fn record(&mut self, outcome: &str) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        metrics::gauge!(names::HTTP_REQUESTS_IN_FLIGHT).decrement(1.0);
        let latency = self.start.elapsed();
        metrics::counter!(
            names::HTTP_REQUESTS_TOTAL,
            "method" => self.method.clone(),
            "route" => self.route.clone(),
            "status" => outcome.to_owned(),
        )
        .increment(1);
        metrics::histogram!(
            names::HTTP_REQUEST_DURATION_SECONDS,
            "method" => self.method.clone(),
            "route" => self.route.clone(),
        )
        .record(latency.as_secs_f64());

        if outcome == CANCELLED_OUTCOME {
            info!(
                target: "http_access",
                request_id = %self.request_id,
                method = %self.method,
                route = %self.route,
                outcome = CANCELLED_OUTCOME,
                latency_ms = latency.as_millis() as u64,
                "http request cancelled before a response"
            );
        } else {
            info!(
                target: "http_access",
                request_id = %self.request_id,
                method = %self.method,
                route = %self.route,
                status = %outcome,
                latency_ms = latency.as_millis() as u64,
                "http request completed"
            );
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        // Finished requests have already been recorded; anything else was
        // dropped mid-flight.
        self.record(CANCELLED_OUTCOME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    /// What was recorded since the last look. The debugging recorder resets
    /// each counter and gauge as it is read, so these are changes.
    #[derive(Debug, Default, PartialEq)]
    struct Recorded {
        in_flight: f64,
        cancelled: u64,
        ok: u64,
    }

    fn recorded(snapshotter: &Snapshotter) -> Recorded {
        let mut seen = Recorded::default();
        for (key, _, _, value) in snapshotter.snapshot().into_vec() {
            let status = key
                .key()
                .labels()
                .find(|l| l.key() == "status")
                .map(|l| l.value().to_string());
            match (key.key().name(), value) {
                (names::HTTP_REQUESTS_IN_FLIGHT, DebugValue::Gauge(g)) => {
                    seen.in_flight += g.into_inner()
                }
                (names::HTTP_REQUESTS_TOTAL, DebugValue::Counter(c)) => match status.as_deref() {
                    Some(CANCELLED_OUTCOME) => seen.cancelled += c,
                    Some("200") => seen.ok += c,
                    _ => {}
                },
                _ => {}
            }
        }
        seen
    }

    fn change(in_flight: f64, cancelled: u64, ok: u64) -> Recorded {
        Recorded {
            in_flight,
            cancelled,
            ok,
        }
    }

    /// A request dropped mid-flight (its client went away) gives its unit of
    /// the in-flight gauge back and is counted as `cancelled`; it used to
    /// leave the gauge one higher for good and record nothing.
    #[test]
    fn a_dropped_request_is_given_back_and_counted_as_cancelled() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let dropped = InFlight::start("GET".into(), "/fetch".into(), "id".into());
            assert_eq!(recorded(&snapshotter), change(1.0, 0, 0));
            drop(dropped);
            assert_eq!(recorded(&snapshotter), change(-1.0, 1, 0));

            InFlight::start("GET".into(), "/fetch".into(), "id".into()).finish("200");
            assert_eq!(recorded(&snapshotter), change(0.0, 0, 1));
        });
    }

    /// Dropping the future that runs the middleware, as hyper does when a
    /// client disconnects, records the request as cancelled.
    #[tokio::test]
    async fn a_cancelled_request_future_is_recorded() {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let app = Router::new()
            .route("/slow", get(std::future::pending::<&'static str>))
            .layer(axum::middleware::from_fn(track_request));
        let request = Request::builder().uri("/slow").body(Body::empty()).unwrap();
        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(50), app.oneshot(request)).await;
        assert!(outcome.is_err(), "the handler never answers");
        assert_eq!(recorded(&snapshotter), change(0.0, 1, 0));
    }
}
