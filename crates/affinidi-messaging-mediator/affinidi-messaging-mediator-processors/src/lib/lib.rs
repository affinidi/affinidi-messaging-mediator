//! Standalone background processors for the Affinidi Messaging Mediator.
//!
//! These processors run as separate processes from the mediator binary,
//! intended for horizontal scaling: drop more processor instances onto
//! additional hosts and they coordinate through Redis to share work.
//!
//! ## Redis-only by design
//!
//! Multi-process coordination relies on Redis primitives:
//! - **Forwarding processor**: Redis Streams consumer groups
//!   (`XREADGROUP` / `XACK` / `XAUTOCLAIM`) for at-least-once delivery
//!   across competing consumers.
//! - **Message expiry cleanup**: atomic `SPOP` on expiry-timeslot sets
//!   so multiple processors can drain the same timeslot without
//!   duplicating work.
//!
//! Memory and Fjall backends are single-process by definition and have
//! no equivalent multi-host coordination, so the standalone binaries
//! are not portable to those backends. The mediator's in-process tasks
//! cover the same workloads on every backend via the
//! `MediatorStore` trait — operators only need this crate when they want
//! to scale a Redis deployment horizontally.
//!
//! ## Implementation
//!
//! Both binaries reuse the trait-based code path lifted into
//! `mediator-common`:
//!
//! - `forwarding_processor` constructs an `Arc<dyn MediatorStore>`
//!   over a `RedisStore` and feeds it to
//!   `mediator_common::tasks::forwarding::ForwardingProcessor`. Same
//!   processor type the mediator binary spawns in-process.
//! - `message_expiry_cleanup` opens the same `RedisStore` and calls
//!   `MessageStore::sweep_expired_messages` on a one-second tick,
//!   matching the mediator's in-process expiry sweep.
//!
//! No duplicated implementation lives in this crate — both binaries
//! are thin shells that wire config to mediator-common. The helpers below
//! are what the two shells share: reading their config without panicking,
//! the forwarder's startup check, and stopping on a signal.

use affinidi_messaging_mediator_common::tasks::forwarding::ForwardingConfig;
use serde::de::DeserializeOwned;

/// Read and parse a TOML config file. A file that can't be read or parsed
/// is an error naming the file and the reason, not a panic.
pub fn load_toml<T: DeserializeOwned>(file: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("couldn't read config file {file}: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("couldn't parse config file {file}: {e}"))
}

/// Refuse a forwarding configuration the standalone processor can't honour.
///
/// `report_errors = true` promises each sender a problem report when its
/// forward is refused or abandoned. Writing one needs the mediator's own keys
/// to pack it, which this process doesn't hold, so it would silently report
/// nothing. Run with `report_errors = false` here, or forward in-process in
/// the mediator, which can report.
pub fn check_standalone_forwarding(config: &ForwardingConfig) -> Result<(), String> {
    if config.report_errors {
        return Err(
            "processors.forwarding.report_errors = true needs the mediator's keys to \
                    pack the failure reports, which the standalone forwarding processor does \
                    not have. Set report_errors = false, or run forwarding in-process in the \
                    mediator"
                .to_string(),
        );
    }
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or, on Unix, SIGTERM. A handler that can't be
/// installed is left pending, so the other still works.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_standalone_forwarder_refuses_report_errors() {
        let mut config = ForwardingConfig {
            report_errors: true,
            ..ForwardingConfig::default()
        };
        let err = check_standalone_forwarding(&config).expect_err("refused");
        assert!(err.contains("report_errors"), "{err}");
        config.report_errors = false;
        assert!(check_standalone_forwarding(&config).is_ok());
    }

    #[test]
    fn an_unreadable_config_is_an_error_not_a_panic() {
        let missing = load_toml::<toml::Table>("/nonexistent/forwarding.toml")
            .expect_err("a missing file is an error");
        assert!(
            missing.contains("/nonexistent/forwarding.toml"),
            "{missing}"
        );

        let dir = std::env::temp_dir().join(format!("processors-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "this is = = not toml").unwrap();
        let err = load_toml::<toml::Table>(bad.to_str().unwrap()).expect_err("bad toml");
        assert!(err.contains("couldn't parse"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The shipped `conf/forwarding.toml` passes the startup check, so the
    /// binary starts with the configuration it is shipped with.
    #[test]
    fn the_shipped_forwarding_config_starts() {
        #[derive(serde::Deserialize)]
        struct Shipped {
            processors: Processors,
        }
        #[derive(serde::Deserialize)]
        struct Processors {
            forwarding: ForwardingConfig,
        }
        let shipped: Shipped =
            load_toml(concat!(env!("CARGO_MANIFEST_DIR"), "/conf/forwarding.toml")).unwrap();
        assert!(check_standalone_forwarding(&shipped.processors.forwarding).is_ok());
    }
}
