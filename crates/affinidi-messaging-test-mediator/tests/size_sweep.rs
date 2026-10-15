//! Message-size sweep across protocols, delivery paths and storage backends.
//!
//! Every message is packed before it is sent, so its exact wire size is known
//! and the expected outcome follows from `limits.message_size`:
//!
//! - **at or under the limit** it must reach the recipient byte for byte, on
//!   every path;
//! - **over the limit** it must be refused, and never delivered.
//!
//! A path whose wire size isn't known up front (cross-mediator forwards wrap
//! the message again) is held to the invariant that matters most: a send that
//! reported success is delivered.
//!
//! Slow — it spawns a few hundred mediators — so it is opt-in:
//!
//! ```sh
//! cargo test -p affinidi-messaging-test-mediator --features tsp,fjall-backend \
//!     --test size_sweep -- --ignored --nocapture
//! # Redis as well: a server with at least 8 databases, and
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features tsp,fjall-backend,redis-backend --test size_sweep -- --ignored --nocapture
//! ```

mod common;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{
    TestEnvironment, TestMediator, TestMediatorBuilder, TestTopology, TestUser,
};
use common::init_tracing;
use serde_json::json;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

/// The production default `limits.message_size`.
const DEFAULT_LIMIT: usize = 1_048_576;
/// Payload sizes swept at the default limit: small, mid, the reported ~600 KiB,
/// and either side of the limit once encoding overhead is added.
const SIZES: &[usize] = &[
    1_000, 64_000, 256_000, 614_400, 760_000, 1_040_000, 1_100_000,
];
/// A raised limit, and a payload that only fits under it — beyond axum's own
/// 2 MiB default request-body limit.
const RAISED_LIMIT: usize = 8 * 1_048_576;
const RAISED_SIZES: &[usize] = &[3_000_000];
/// How long a delivery may take before it counts as lost.
const DELIVERY_WAIT: Duration = Duration::from_secs(6);

// ─── Backends ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Backend {
    Memory,
    #[cfg(feature = "fjall-backend")]
    Fjall,
    #[cfg(feature = "redis-backend")]
    Redis,
}

/// Redis keys are per logical DB and the sweeps run concurrently, so each sweep
/// owns a block of DBs: `[base, base + 1]` (two for the two-mediator paths).
#[derive(Clone, Copy)]
struct Sweep {
    backend: Backend,
    #[cfg_attr(not(feature = "redis-backend"), allow(dead_code))]
    redis_db_base: u8,
}

#[cfg(feature = "redis-backend")]
async fn redis_store(
    db: u8,
) -> std::sync::Arc<dyn affinidi_messaging_mediator_common::store::MediatorStore> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = std::env::var("REDIS_URL").expect("REDIS_URL");
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../affinidi-messaging-mediator/conf/atm-functions.lua"
            )
            .to_string(),
        ),
        database_url: format!("{}/{db}", base.trim_end_matches('/')),
        database_timeout: 2,
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };
    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL");
    let store = RedisStore::new(handler, 5, 10, config.functions_file.clone());
    let mut conn = store.get_connection().await.expect("redis connection");
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .expect("FLUSHDB");
    std::sync::Arc::new(store)
}

/// The store a node of `sweep` runs on: `None` for the builder's default
/// (memory) or one the builder opens itself (Fjall). Redis is opened here,
/// because the builder hooks that take it are synchronous.
type Store = Option<std::sync::Arc<dyn affinidi_messaging_mediator_common::store::MediatorStore>>;

async fn open_store(sweep: Sweep, node: u8) -> Store {
    let _ = node;
    match sweep.backend {
        #[cfg(feature = "redis-backend")]
        Backend::Redis => Some(redis_store(sweep.redis_db_base + node).await),
        _ => None,
    }
}

/// Apply `sweep`'s backend to a mediator builder.
fn with_backend(builder: TestMediatorBuilder, sweep: Sweep, store: Store) -> TestMediatorBuilder {
    if let Some(store) = store {
        return builder.store(store);
    }
    match sweep.backend {
        #[cfg(feature = "fjall-backend")]
        Backend::Fjall => builder.fjall_backend().expect("fjall store"),
        _ => builder,
    }
}

async fn environment(sweep: Sweep, limit: usize) -> TestEnvironment {
    let builder = TestMediator::builder()
        .local_direct_delivery(true, false)
        .message_size(limit);
    let mediator = with_backend(builder, sweep, open_store(sweep, 0).await)
        .spawn()
        .await
        .expect("spawn mediator");
    TestEnvironment::new(mediator).await.expect("environment")
}

async fn topology(sweep: Sweep, limit: usize) -> TestTopology {
    let stores = std::sync::Mutex::new(
        vec![open_store(sweep, 0).await, open_store(sweep, 1).await].into_iter(),
    );
    TestTopology::builder()
        .mediators(2)
        // Keep the topology's own per-node settings; add the backend and limit.
        .configure_each(move |builder| {
            let store = stores
                .lock()
                .expect("stores")
                .next()
                .expect("one store per node");
            with_backend(builder, sweep, store).message_size(limit)
        })
        .spawn()
        .await
        .expect("spawn topology")
}

// ─── Outcomes ─────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Outcome {
    Delivered,
    /// The send itself failed, so the sender knows.
    Refused(String),
    /// The send returned before the mediator judged the message (a websocket
    /// write), and the refusal reached the sender afterwards.
    RefusedLater(String),
    /// Nothing arrived and the sender was never told.
    Lost,
    /// Something arrived that isn't what was sent.
    Corrupted(String),
}

struct Row {
    backend: Backend,
    path: &'static str,
    size: usize,
    /// The packed size, when the path sends it unwrapped.
    wire: Option<usize>,
    limit: usize,
    outcome: Outcome,
}

impl Row {
    /// Why this row is wrong, if it is.
    fn violation(&self) -> Option<String> {
        let fits = self.wire.map(|w| w <= self.limit);
        match (&self.outcome, fits) {
            (Outcome::Delivered, Some(false)) => Some("delivered over the limit".into()),
            (Outcome::Delivered, _) => None,
            (Outcome::Corrupted(why), _) => Some(format!("corrupted: {why}")),
            (_, Some(true)) => Some("fits the limit but was not delivered".into()),
            (Outcome::Lost, _) => Some("not delivered, and the sender was never told".into()),
            _ => None,
        }
    }
}

impl fmt::Display for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire.map_or("?".to_string(), |w| w.to_string());
        let outcome = match &self.outcome {
            Outcome::Refused(why) => {
                format!("refused: {}", why.chars().take(90).collect::<String>())
            }
            Outcome::RefusedLater(why) => {
                format!(
                    "refused later: {}",
                    why.chars().take(84).collect::<String>()
                )
            }
            other => format!("{other:?}"),
        };
        write!(
            f,
            "{:<7} {:<26} payload={:>9} wire={:>9} limit={:>8}  {outcome}",
            format!("{:?}", self.backend),
            self.path,
            self.size,
            wire,
            self.limit
        )
    }
}

fn report(rows: &[Row]) {
    for row in rows {
        let flag = if row.violation().is_some() {
            "FAIL"
        } else {
            "ok  "
        };
        println!("{flag} {row}");
    }
    let failures: Vec<String> = rows
        .iter()
        .filter_map(|r| r.violation().map(|v| format!("{r}\n      -> {v}")))
        .collect();
    assert!(
        failures.is_empty(),
        "{} violation(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ─── Payloads ─────────────────────────────────────────────────────────────

#[cfg(feature = "tsp")]
fn payload_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn payload_text(size: usize) -> String {
    (0..size)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A basic message from `from` to `to` carrying `text`, authcrypted for `to`.
async fn didcomm_packed(
    env: &TestEnvironment,
    from: &TestUser,
    to: &TestUser,
    text: &str,
) -> (String, String) {
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(now())
    .expires_time(now() + 600)
    .finalize();
    let id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .expect("pack");
    (packed, id)
}

fn check_text(msg: &Message, text: &str) -> Outcome {
    match msg.body.get("content").and_then(|c| c.as_str()) {
        Some(got) if got == text => Outcome::Delivered,
        Some(got) => Outcome::Corrupted(format!("content length {} != {}", got.len(), text.len())),
        None => Outcome::Corrupted(format!("no content in {}", msg.typ)),
    }
}

#[cfg(feature = "tsp")]
fn check_bytes(got: &[u8], sent: &[u8]) -> Outcome {
    if got == sent {
        Outcome::Delivered
    } else {
        Outcome::Corrupted(format!("payload length {} != {}", got.len(), sent.len()))
    }
}

/// Poll `user`'s inbox until a message lands or the wait runs out.
async fn poll_inbox(env: &TestEnvironment, user: &TestUser) -> Option<String> {
    let deadline = tokio::time::Instant::now() + DELIVERY_WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Ok(fetched) = env
            .atm
            .fetch_messages(&user.profile, &FetchOptions::default())
            .await
            && let Some(body) = fetched.success.first().and_then(|e| e.msg.clone())
        {
            return Some(body);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    None
}

/// A problem report waiting on `user`'s live stream: how a refusal of a
/// websocket-sent DIDComm message reaches its sender.
async fn didcomm_refusal(env: &TestEnvironment, user: &TestUser) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some((msg, _))) = env
            .atm
            .message_pickup()
            .live_stream_next(&user.profile, Some(Duration::from_millis(250)), false)
            .await
            && msg.typ.contains("problem-report")
        {
            return Some(
                msg.body
                    .get("code")
                    .map_or_else(|| msg.typ.clone(), |c| c.to_string()),
            );
        }
    }
    None
}

// ─── DIDComm paths ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum DidcommPath {
    RestToFetch,
    RestToLiveWebsocket,
    WebsocketToFetch,
    CrossMediatorForward,
}

impl DidcommPath {
    const ALL: [Self; 4] = [
        Self::RestToFetch,
        Self::RestToLiveWebsocket,
        Self::WebsocketToFetch,
        Self::CrossMediatorForward,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::RestToFetch => "didcomm rest->fetch",
            Self::RestToLiveWebsocket => "didcomm rest->live ws",
            Self::WebsocketToFetch => "didcomm ws->fetch",
            Self::CrossMediatorForward => "didcomm cross-mediator",
        }
    }
}

async fn didcomm_case(sweep: Sweep, path: DidcommPath, size: usize, limit: usize) -> Row {
    let text = payload_text(size);
    let mut row = Row {
        backend: sweep.backend,
        path: path.name(),
        size,
        wire: None,
        limit,
        outcome: Outcome::Lost,
    };

    if let DidcommPath::CrossMediatorForward = path {
        let topology = topology(sweep, limit).await;
        let alice = topology.add_user(0, "alice").await.expect("alice");
        let bob = topology.add_user(1, "bob").await.expect("bob");
        row.outcome = match topology
            .forward(0, &alice, 1, &bob, &text, DELIVERY_WAIT)
            .await
        {
            Ok(Some(got)) if got == text => Outcome::Delivered,
            Ok(Some(got)) => {
                Outcome::Corrupted(format!("content length {} != {}", got.len(), text.len()))
            }
            Ok(None) => match didcomm_refusal(topology.node(0).expect("A"), &alice).await {
                Some(code) => Outcome::RefusedLater(code),
                None => Outcome::Lost,
            },
            Err(e) => Outcome::Refused(e.to_string()),
        };
        topology.shutdown().await.ok();
        return row;
    }

    let env = environment(sweep, limit).await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    if let DidcommPath::RestToLiveWebsocket = path {
        env.atm
            .profile_enable_websocket(&bob.profile)
            .await
            .expect("bob websocket");
    }
    if let DidcommPath::WebsocketToFetch = path {
        env.atm
            .profile_enable_websocket(&alice.profile)
            .await
            .expect("alice websocket");
    }

    let (packed, id) = didcomm_packed(&env, &alice, &bob, &text).await;
    row.wire = Some(packed.len());
    if let Err(e) = env
        .atm
        .send_message(&alice.profile, &packed, &id, false, false)
        .await
    {
        row.outcome = Outcome::Refused(e.to_string());
        env.shutdown().await.ok();
        return row;
    }

    row.outcome = match path {
        DidcommPath::RestToLiveWebsocket => {
            let deadline = tokio::time::Instant::now() + DELIVERY_WAIT;
            let mut outcome = Outcome::Lost;
            while tokio::time::Instant::now() < deadline {
                match env
                    .atm
                    .message_pickup()
                    .live_stream_next(&bob.profile, Some(Duration::from_millis(500)), false)
                    .await
                {
                    // Pickup status messages share the stream.
                    Ok(Some((msg, _))) if msg.typ.contains("basicmessage") => {
                        outcome = check_text(&msg, &text);
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        outcome = Outcome::Corrupted(format!("live stream error: {e}"));
                        break;
                    }
                }
            }
            outcome
        }
        _ => match poll_inbox(&env, &bob).await {
            None => match didcomm_refusal(&env, &alice).await {
                Some(code) => Outcome::RefusedLater(code),
                None => Outcome::Lost,
            },
            Some(body) => match env.atm.unpack(&body).await {
                Ok((msg, _)) => check_text(&msg, &text),
                Err(e) => Outcome::Corrupted(format!("unpack: {e}")),
            },
        },
    };
    env.shutdown().await.ok();
    row
}

// ─── TSP paths ────────────────────────────────────────────────────────────

#[cfg(feature = "tsp")]
#[derive(Clone, Copy)]
enum TspPath {
    RestToFetch,
    RestToRawSocket,
    RestToSdkWebsocket,
    RawSocketToFetch,
    CrossMediatorRouted,
}

#[cfg(feature = "tsp")]
impl TspPath {
    const ALL: [Self; 5] = [
        Self::RestToFetch,
        Self::RestToRawSocket,
        Self::RestToSdkWebsocket,
        Self::RawSocketToFetch,
        Self::CrossMediatorRouted,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::RestToFetch => "tsp rest->fetch",
            Self::RestToRawSocket => "tsp rest->raw socket",
            Self::RestToSdkWebsocket => "tsp rest->sdk ws",
            Self::RawSocketToFetch => "tsp raw socket->fetch",
            Self::CrossMediatorRouted => "tsp cross-mediator",
        }
    }
}

#[cfg(feature = "tsp")]
async fn tsp_case(sweep: Sweep, path: TspPath, size: usize, limit: usize) -> Row {
    use affinidi_messaging_sdk::protocols::message_pickup::InboundFrame;

    let payload = payload_bytes(size);
    let mut row = Row {
        backend: sweep.backend,
        path: path.name(),
        size,
        wire: None,
        limit,
        outcome: Outcome::Lost,
    };

    if let TspPath::CrossMediatorRouted = path {
        let topology = topology(sweep, limit).await;
        let route = vec![
            topology.mediator_did(0).expect("A").to_string(),
            topology.mediator_did(1).expect("B").to_string(),
        ];
        let alice = topology.add_user(0, "alice").await.expect("alice");
        let bob = topology.add_user(1, "bob").await.expect("bob");
        topology
            .relate_directly(&alice, &bob)
            .await
            .expect("relate");
        let a = topology.node(0).expect("A");
        let b = topology.node(1).expect("B");
        let mut full_route = route.clone();
        full_route.push(bob.did.clone());
        row.outcome = match a
            .atm
            .tsp()
            .send_routed(&alice.profile, &full_route, &payload)
            .await
        {
            Err(e) => Outcome::Refused(e.to_string()),
            Ok(()) => match poll_inbox(b, &bob).await {
                None => Outcome::Lost,
                Some(stored) => match b.atm.tsp().unpack(&bob.profile, &stored).await {
                    Ok((got, _)) => check_bytes(&got, &payload),
                    Err(e) => Outcome::Corrupted(format!("unpack: {e}")),
                },
            },
        };
        topology.shutdown().await.ok();
        return row;
    }

    let env = environment(sweep, limit).await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.relate_directly(&alice, &bob).await.expect("relate");

    let mut bob_socket = match path {
        TspPath::RestToRawSocket => Some(
            env.atm
                .tsp()
                .connect_websocket(&bob.profile)
                .await
                .expect("bob socket"),
        ),
        _ => None,
    };
    if let TspPath::RestToSdkWebsocket = path {
        env.atm
            .profile_enable_websocket(&bob.profile)
            .await
            .expect("bob websocket");
    }

    let bytes = env
        .atm
        .tsp()
        .pack(&alice.profile, &bob.did, &payload)
        .await
        .expect("pack");
    row.wire = Some(bytes.len());

    let mut alice_socket = None;
    let sent = if let TspPath::RawSocketToFetch = path {
        let mut socket = env
            .atm
            .tsp()
            .connect_websocket(&alice.profile)
            .await
            .expect("alice socket");
        let sent = socket.send(&bytes).await;
        alice_socket = Some(socket);
        sent
    } else {
        env.atm.tsp().send_raw(&alice.profile, &bytes).await
    };
    if let Err(e) = sent {
        row.outcome = Outcome::Refused(e.to_string());
        env.shutdown().await.ok();
        return row;
    }

    row.outcome = match path {
        TspPath::RestToRawSocket => {
            let socket = bob_socket.as_mut().expect("bob socket");
            match tokio::time::timeout(DELIVERY_WAIT, socket.recv()).await {
                Ok(Ok(Some(frame))) => match env.atm.tsp().unpack_bytes(&bob.profile, &frame).await
                {
                    Ok((got, _)) => check_bytes(&got, &payload),
                    Err(e) => Outcome::Corrupted(format!("unpack: {e}")),
                },
                Ok(Ok(None)) | Err(_) => Outcome::Lost,
                Ok(Err(e)) => Outcome::Corrupted(format!("socket: {e}")),
            }
        }
        TspPath::RestToSdkWebsocket => {
            let deadline = tokio::time::Instant::now() + DELIVERY_WAIT;
            let mut outcome = Outcome::Lost;
            while tokio::time::Instant::now() < deadline {
                match env
                    .atm
                    .message_pickup()
                    .live_stream_next_frame(&bob.profile, Some(Duration::from_millis(500)), false)
                    .await
                {
                    Ok(Some(InboundFrame::Tsp(stored))) => {
                        outcome = match env.atm.tsp().unpack(&bob.profile, &stored).await {
                            Ok((got, _)) => check_bytes(&got, &payload),
                            Err(e) => Outcome::Corrupted(format!("unpack: {e}")),
                        };
                        break;
                    }
                    // Pickup status messages share the stream.
                    Ok(_) => {}
                    Err(e) => {
                        outcome = Outcome::Corrupted(format!("live stream error: {e}"));
                        break;
                    }
                }
            }
            outcome
        }
        _ => match poll_inbox(&env, &bob).await {
            // A raw-TSP socket carries no problem reports: a refusal can only
            // come back as the mediator closing the sender's socket.
            None => match alice_socket.as_mut() {
                Some(socket) => {
                    match tokio::time::timeout(Duration::from_secs(1), socket.recv()).await {
                        Ok(Err(e)) => Outcome::RefusedLater(e.to_string()),
                        _ => Outcome::Lost,
                    }
                }
                None => Outcome::Lost,
            },
            Some(stored) => match env.atm.tsp().unpack(&bob.profile, &stored).await {
                Ok((got, _)) => check_bytes(&got, &payload),
                Err(e) => Outcome::Corrupted(format!("unpack: {e}")),
            },
        },
    };
    if let Some(socket) = alice_socket {
        socket.close().await.ok();
    }
    if let Some(socket) = bob_socket {
        socket.close().await.ok();
    }
    env.shutdown().await.ok();
    row
}

// ─── Sweeps ───────────────────────────────────────────────────────────────

async fn sweep_didcomm(sweep: Sweep) {
    init_tracing();
    let mut rows = Vec::new();
    for path in DidcommPath::ALL {
        for &size in SIZES {
            rows.push(didcomm_case(sweep, path, size, DEFAULT_LIMIT).await);
        }
        for &size in RAISED_SIZES {
            rows.push(didcomm_case(sweep, path, size, RAISED_LIMIT).await);
        }
    }
    report(&rows);
}

#[cfg(feature = "tsp")]
async fn sweep_tsp(sweep: Sweep) {
    init_tracing();
    let mut rows = Vec::new();
    for path in TspPath::ALL {
        for &size in SIZES {
            rows.push(tsp_case(sweep, path, size, DEFAULT_LIMIT).await);
        }
        for &size in RAISED_SIZES {
            rows.push(tsp_case(sweep, path, size, RAISED_LIMIT).await);
        }
    }
    report(&rows);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_memory_didcomm() {
    sweep_didcomm(Sweep {
        backend: Backend::Memory,
        redis_db_base: 0,
    })
    .await;
}

#[cfg(feature = "tsp")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_memory_tsp() {
    sweep_tsp(Sweep {
        backend: Backend::Memory,
        redis_db_base: 0,
    })
    .await;
}

#[cfg(feature = "fjall-backend")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_fjall_didcomm() {
    sweep_didcomm(Sweep {
        backend: Backend::Fjall,
        redis_db_base: 0,
    })
    .await;
}

#[cfg(all(feature = "fjall-backend", feature = "tsp"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_fjall_tsp() {
    sweep_tsp(Sweep {
        backend: Backend::Fjall,
        redis_db_base: 0,
    })
    .await;
}

#[cfg(feature = "redis-backend")]
fn redis_available() -> bool {
    let set = std::env::var("REDIS_URL").is_ok_and(|u| !u.trim().is_empty());
    if !set {
        eprintln!("SKIP redis size sweep: REDIS_URL not set");
    }
    set
}

#[cfg(feature = "redis-backend")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_redis_didcomm() {
    if redis_available() {
        sweep_didcomm(Sweep {
            backend: Backend::Redis,
            redis_db_base: 1,
        })
        .await;
    }
}

#[cfg(all(feature = "redis-backend", feature = "tsp"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow size sweep; run with --ignored"]
async fn size_sweep_redis_tsp() {
    if redis_available() {
        sweep_tsp(Sweep {
            backend: Backend::Redis,
            redis_db_base: 3,
        })
        .await;
    }
}
