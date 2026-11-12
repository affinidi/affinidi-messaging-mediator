//! The mux metrics on `/metrics` (design §7.8): `mux_connections` and
//! `mux_members` rise as a connection opens and members join, come back down
//! as members are revoked and the connection closes, and each detach is
//! counted under its reason in `mux_detach_total`.
//!
//! The Prometheus recorder is installed once per process, so this binary
//! holds a single test and starts a single mediator.

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::protocols::mux::{MuxCapability, MuxMembers, sign_attach, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::init_tracing;
use tokio::time::timeout;

const CONNECTIONS: &str = "mux_connections{wire=\"didcomm\"}";
const BY_GRANT: &str = "mux_members{source=\"grant\"}";
const BY_ATTACH: &str = "mux_members{source=\"attach\"}";
const REVOKED: &str = "mux_detach_total{reason=\"revokedByPrincipal\"}";
const DETACH_REQUESTED: &str = "mux_detach_total{reason=\"detachRequested\"}";

/// One scrape of `/metrics`.
async fn scrape(env: &TestEnvironment) -> String {
    reqwest::Client::new()
        .get(format!("{}metrics", env.mediator.endpoint()))
        .send()
        .await
        .expect("metrics request")
        .error_for_status()
        .expect("metrics served")
        .text()
        .await
        .expect("metrics body")
}

/// The value of `series` in `body`, or 0 when it is absent.
fn value(body: &str, series: &str) -> f64 {
    body.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
        .unwrap_or(0.0)
}

/// Scrape until every `(series, value)` in `want` holds, or fail naming
/// what the last scrape showed.
async fn metrics_until(env: &TestEnvironment, what: &str, want: &[(&str, f64)]) {
    let mut last = String::new();
    let reached = timeout(Duration::from_secs(5), async {
        loop {
            last = scrape(env).await;
            if want.iter().all(|(s, v)| value(&last, s) == *v) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if reached.is_err() {
        let mux: Vec<&str> = last.lines().filter(|l| l.starts_with("mux_")).collect();
        panic!("{what}: wanted {want:?}, last scrape:\n{}", mux.join("\n"));
    }
}

async fn members_until(
    rx: &mut tokio::sync::watch::Receiver<MuxMembers>,
    what: &str,
    done: impl Fn(&MuxMembers) -> bool,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            if done(&rx.borrow_and_update()) {
                return;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("member set: {what}: {:?}", rx.borrow()))
}

#[tokio::test]
async fn mux_gauges_rise_and_fall_and_detaches_are_counted_by_reason() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .metrics_access(["127.0.0.1/32"], None)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    metrics_until(
        &env,
        "nothing before the connection",
        &[(CONNECTIONS, 0.0), (BY_GRANT, 0.0), (BY_ATTACH, 0.0)],
    )
    .await;

    // Open the mux connection.
    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let mut ready_rx = device.profile.mux_ready().await.unwrap();
    let ready = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("ready");
    metrics_until(&env, "connection open", &[(CONNECTIONS, 1.0)]).await;

    // One member by grant, one by session attach.
    let (g, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g])
        .await
        .expect("grant");
    let a = sign_attach(
        &env.atm,
        &temp.did,
        &device.did,
        &mediator_did,
        &ready.session_id,
        &ready.mux_nonce,
        &[MuxCapability::Receive],
        600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_attach(&device.profile, vec![a])
        .await
        .expect("attach");
    let mut members_rx = device.profile.mux_members().await.unwrap();
    members_until(&mut members_rx, "two members", |m| m.len() == 2).await;
    metrics_until(
        &env,
        "two members",
        &[(CONNECTIONS, 1.0), (BY_GRANT, 1.0), (BY_ATTACH, 1.0)],
    )
    .await;

    // The device revokes its grant from `work`: one detach, by the principal.
    env.atm
        .trust_tasks()
        .mux_revoke(&device.profile, false, vec![], vec![work.did.clone()])
        .await
        .expect("revoke");
    members_until(&mut members_rx, "work detached", |m| {
        m.get(&work.did).is_none()
    })
    .await;
    metrics_until(
        &env,
        "grant revoked",
        &[(BY_GRANT, 0.0), (BY_ATTACH, 1.0), (REVOKED, 1.0)],
    )
    .await;

    // The socket closes with `temp` still attached: the gauges come back to
    // zero, and the close is not counted as a detach.
    device
        .profile
        .stop_websocket()
        .await
        .expect("stop websocket");
    metrics_until(
        &env,
        "connection closed",
        &[
            (CONNECTIONS, 0.0),
            (BY_GRANT, 0.0),
            (BY_ATTACH, 0.0),
            (REVOKED, 1.0),
            (DETACH_REQUESTED, 0.0),
        ],
    )
    .await;

    env.mediator.shutdown();
}
