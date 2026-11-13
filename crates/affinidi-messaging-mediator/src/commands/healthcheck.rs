//! `mediator healthcheck`: probe a running mediator's liveness route.
//!
//! Exists so a container can be health-checked without shipping curl or wget
//! in the runtime image: `HEALTHCHECK CMD ["/usr/local/bin/mediator",
//! "healthcheck"]`. It reads the same config file the server reads (with the
//! same environment overrides), works out where `livez` is served, GETs it and
//! exits 0 on a 2xx and 1 on anything else.
//!
//! Liveness only: `livez` answers whenever the HTTP server is up. Readiness
//! (`readyz`, which also covers the storage backend) is for an orchestrator
//! deciding whether to route traffic, and failing a Docker healthcheck on a
//! Redis blip would restart a mediator that is fine.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crate::common::config::helpers::{join_api_path, normalize_api_prefix};

/// How long the probe waits for an answer before calling the mediator dead.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The `livez` URL for a mediator listening on `listen_address` under
/// `api_prefix`.
///
/// A wildcard bind (`0.0.0.0`, `::`) is probed on the matching loopback
/// address, since the probe runs beside the server (in the same container).
pub fn livez_url(listen_address: &str, api_prefix: &str, use_ssl: bool) -> Result<String, String> {
    let addr: SocketAddr = listen_address
        .trim()
        .parse()
        .map_err(|e| format!("listen_address {listen_address:?} is not host:port ({e})"))?;
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    let scheme = if use_ssl { "https" } else { "http" };
    let path = join_api_path(&normalize_api_prefix(api_prefix), "livez");
    Ok(format!(
        "{scheme}://{}{path}",
        SocketAddr::new(ip, addr.port())
    ))
}

/// Resolve the `livez` URL from the mediator config file at `config_path`.
pub fn livez_url_from_config(config_path: &str) -> Result<String, String> {
    let raw = affinidi_messaging_mediator_config::env::read_config_file(config_path)
        .map_err(|e| format!("could not read {config_path}: {e}"))?;
    let use_ssl = raw.security.use_ssl.trim().eq_ignore_ascii_case("true");
    livez_url(&raw.server.listen_address, &raw.server.api_prefix, use_ssl)
}

/// GET `url` and succeed on a 2xx.
pub async fn probe(url: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        // The probe talks to this host's own listener. With in-process TLS the
        // certificate names the public host, not the loopback address, so
        // verifying it here would fail every probe; liveness is the question,
        // not the certificate.
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("could not build HTTP client: {e}"))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("GET {url} answered {status}"))
    }
}

/// The subcommand: probe `url`, or the URL the config at `config_path` names.
pub async fn run(config_path: &str, url: Option<&str>) -> Result<(), String> {
    let url = match url {
        Some(url) => url.to_string(),
        None => livez_url_from_config(config_path)?,
    };
    probe(&url, DEFAULT_TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_v4_bind_probes_loopback_under_the_prefix() {
        assert_eq!(
            livez_url("0.0.0.0:7037", "/mediator/v1/", false).unwrap(),
            "http://127.0.0.1:7037/mediator/v1/livez"
        );
    }

    #[test]
    fn wildcard_v6_bind_probes_v6_loopback() {
        assert_eq!(
            livez_url("[::]:7037", "", true).unwrap(),
            "https://[::1]:7037/livez"
        );
    }

    #[test]
    fn specific_bind_address_is_kept() {
        assert_eq!(
            livez_url("10.0.0.5:8080", "api", false).unwrap(),
            "http://10.0.0.5:8080/api/livez"
        );
    }

    #[test]
    fn unparseable_listen_address_is_an_error() {
        assert!(livez_url("localhost", "/", false).is_err());
    }

    #[tokio::test]
    async fn probe_fails_when_nothing_listens() {
        // Bind then drop, so the port is very likely closed.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("http://127.0.0.1:{port}/livez");
        assert!(probe(&url, Duration::from_secs(2)).await.is_err());
    }
}
