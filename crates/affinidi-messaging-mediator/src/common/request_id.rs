//! Request ID middleware.
//!
//! Assigns a unique UUID v4 to each incoming request. If the request already
//! carries an `x-request-id` header that is a plausible id (see
//! [`acceptable_request_id`]), that value is reused, so a caller's id follows
//! the request through the mediator's logs; anything else is replaced with a
//! fresh UUID. The ID is inserted as a request extension (accessible to
//! handlers) and echoed back as the `x-request-id` response header.

use axum::{body::Body, response::Response};
use http::{HeaderValue, Request};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Longest inbound request id reused. A UUID is 36 characters; this leaves
/// room for other id schemes without letting a caller write kilobytes into
/// every log line.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Whether a client-supplied `x-request-id` is reused as is: 1 to
/// [`MAX_REQUEST_ID_LEN`] characters, each an ASCII letter, digit, `-`, `_`,
/// `.` or `:`. The value is written to the access log and echoed back, so
/// anything that could break a log line (spaces, quotes, control characters,
/// non-ASCII) is refused rather than escaped.
pub fn acceptable_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_REQUEST_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// A new-type so handlers can extract the request ID from extensions.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Tower Layer that injects a request ID.
#[derive(Clone, Default)]
pub struct RequestIdLayer;

impl RequestIdLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// Tower Service that generates / propagates a request ID.
#[derive(Clone)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for RequestIdService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Reuse an acceptable header value or generate a new UUID v4.
        let id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| acceptable_request_id(v))
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Make the ID available to downstream handlers via request extensions.
        req.extensions_mut().insert(RequestId(id.clone()));

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut response = inner.call(req).await?;
            if let Ok(value) = HeaderValue::from_str(&id) {
                response.headers_mut().insert(REQUEST_ID_HEADER, value);
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    /// The id the layer assigns to a request carrying `header` (if any).
    async fn assigned(header: Option<&str>) -> String {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RequestIdLayer::new());
        let mut request = Request::builder().uri("/");
        if let Some(header) = header {
            request = request.header(REQUEST_ID_HEADER, header);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.headers()[REQUEST_ID_HEADER]
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn a_plausible_inbound_id_is_reused() {
        assert_eq!(assigned(Some("req-42_a.b:c")).await, "req-42_a.b:c");
        let uuid = Uuid::new_v4().to_string();
        assert_eq!(assigned(Some(&uuid)).await, uuid);
    }

    /// An over-long id, or one with characters that could break a log line,
    /// is replaced with a fresh UUID instead of being written to the log.
    #[tokio::test]
    async fn an_unbounded_or_unsafe_inbound_id_is_replaced() {
        let long = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        for bad in [long.as_str(), "has space", "quote\"d", "tab\there", ""] {
            let id = assigned(Some(bad)).await;
            assert_ne!(id, bad);
            assert!(Uuid::parse_str(&id).is_ok(), "{id} is a fresh UUID");
        }
        assert!(acceptable_request_id(&"a".repeat(MAX_REQUEST_ID_LEN)));
        assert!(Uuid::parse_str(&assigned(None).await).is_ok());
    }
}
