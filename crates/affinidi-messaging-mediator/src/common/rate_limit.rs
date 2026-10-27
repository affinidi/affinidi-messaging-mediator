//! Trusted reverse-proxy client attribution for the mediator rate limiter.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context, Poll},
};

use affinidi_rate_limit::{RateLimiterState, Refusal};
use axum::{
    body::Body,
    extract::ConnectInfo,
    response::{IntoResponse, Response},
};
use http::{HeaderName, HeaderValue, Request, StatusCode, header};
use ipnetwork::IpNetwork;
use tower::{Layer, Service};
use tracing::warn;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const MAX_FORWARDED_ENTRIES: usize = 64;

/// Extracts a client address from `X-Forwarded-For` only for trusted peers.
#[derive(Clone, Debug)]
pub struct TrustedProxyKeyExtractor {
    trusted_cidrs: Vec<IpNetwork>,
}

impl TrustedProxyKeyExtractor {
    /// Create an extractor using the operator-declared trusted proxy CIDRs.
    pub fn new(trusted_cidrs: Vec<IpNetwork>) -> Self {
        Self { trusted_cidrs }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    fn client_from_chain(&self, headers: &http::HeaderMap) -> Option<IpAddr> {
        let mut entries = Vec::new();
        for value in headers.get_all(X_FORWARDED_FOR) {
            let value = value.to_str().ok()?;
            for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                if entries.len() == MAX_FORWARDED_ENTRIES {
                    return None;
                }
                entries.push(entry);
            }
        }

        for entry in entries.iter().rev() {
            let ip = parse_forwarded_ip(entry)?;
            if !self.is_trusted(ip) {
                return Some(ip);
            }
        }
        None
    }

    /// Return the address to charge for a request, or `None` when no peer is
    /// available to provide an unspoofable attribution anchor.
    pub fn extract<T>(&self, request: &Request<T>) -> Option<IpAddr> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| canonical(info.0.ip()))?;
        if !self.is_trusted(peer) {
            return Some(peer);
        }
        Some(self.client_from_chain(request.headers()).unwrap_or(peer))
    }
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(canonical(address.ip()));
    }
    value
        .strip_prefix('[')?
        .strip_suffix(']')?
        .parse::<IpAddr>()
        .ok()
        .map(canonical)
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

/// Tower layer equivalent to the mediator limiter, with trusted proxy
/// attribution.
type RefusalCallback = Arc<dyn Fn(&Refusal) + Send + Sync>;

#[derive(Clone)]
pub struct TrustedProxyRateLimitLayer {
    state: RateLimiterState,
    extractor: TrustedProxyKeyExtractor,
    on_refused: Option<RefusalCallback>,
}

impl TrustedProxyRateLimitLayer {
    /// Build a rate-limit layer using the supplied limiter and trusted CIDRs.
    pub fn new(state: RateLimiterState, trusted_cidrs: Vec<IpNetwork>) -> Self {
        Self {
            state,
            extractor: TrustedProxyKeyExtractor::new(trusted_cidrs),
            on_refused: None,
        }
    }

    /// Observe refusals for service metrics.
    pub fn on_refused(mut self, callback: impl Fn(&Refusal) + Send + Sync + 'static) -> Self {
        self.on_refused = Some(Arc::new(callback));
        self
    }
}

impl<S> Layer<S> for TrustedProxyRateLimitLayer {
    type Service = TrustedProxyRateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TrustedProxyRateLimitService {
            inner,
            state: self.state.clone(),
            extractor: self.extractor.clone(),
            on_refused: self.on_refused.clone(),
        }
    }
}

#[derive(Clone)]
pub struct TrustedProxyRateLimitService<S> {
    inner: S,
    state: RateLimiterState,
    extractor: TrustedProxyKeyExtractor,
    on_refused: Option<RefusalCallback>,
}

impl<S> Service<Request<Body>> for TrustedProxyRateLimitService<S>
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

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if !self.state.is_enabled() {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(request).await });
        }

        let Some(ip) = self.extractor.extract(&request) else {
            warn!("No client IP available; rejecting request");
            if let Some(callback) = &self.on_refused {
                callback(&Refusal::NoClientIp);
            }
            let response = refusal_response(&Refusal::NoClientIp);
            return Box::pin(async move { Ok(response) });
        };
        if let Err(refusal) = self.state.check(ip) {
            warn!(%ip, "Rate limit exceeded");
            if let Some(callback) = &self.on_refused {
                callback(&refusal);
            }
            let response = refusal_response(&refusal);
            return Box::pin(async move { Ok(response) });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(request).await })
    }
}

fn refusal_response(refusal: &Refusal) -> Response {
    match refusal {
        Refusal::RateLimited { retry_after_secs } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": "rate_limited",
                    "limiter": "mediator",
                    "message": "Rate limit exceeded. Please try again later.",
                    "retryAfterSecs": retry_after_secs,
                })),
            )
                .into_response();
            response.headers_mut().insert(
                HeaderName::from_static(affinidi_rate_limit::SOURCE_HEADER),
                HeaderValue::from_static("mediator"),
            );
            if let Ok(value) = HeaderValue::try_from(retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Refusal::NoClientIp => (
            StatusCode::FORBIDDEN,
            "Rate limiting requires client IP; request rejected.",
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rate limiting refused the request.",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request(peer: [u8; 4], forwarded: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 443))));
        if let Some(forwarded) = forwarded {
            request.headers_mut().insert(
                X_FORWARDED_FOR,
                HeaderValue::from_str(forwarded).expect("header"),
            );
        }
        request
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        let extractor = TrustedProxyKeyExtractor::new(vec!["10.0.0.0/8".parse().expect("cidr")]);
        assert_eq!(
            extractor.extract(&request([192, 0, 2, 1], Some("198.51.100.1"))),
            Some("192.0.2.1".parse().expect("ip"))
        );
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_forwarded_address() {
        let extractor = TrustedProxyKeyExtractor::new(vec!["10.0.0.0/8".parse().expect("cidr")]);
        assert_eq!(
            extractor.extract(&request([10, 0, 0, 1], Some("203.0.113.1, 10.0.0.2"))),
            Some("203.0.113.1".parse().expect("ip"))
        );
    }
}
