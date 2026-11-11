//! Two instances of one mediator in two operating-system processes, sharing
//! one Redis database, one DID and one session-token key.
//!
//! `mux_two_instances.rs` runs both instances in one process. This test runs
//! instance B as a child process (this test binary, started again with
//! [`IDENTITY_ENV`] set), so the instances share nothing but Redis, and B can
//! die without running any clean-up, as a crashed or killed replica does:
//!
//! 1. a principal's mux socket on B receives, live, a member's message stored
//!    through A (A's publish crosses into the other process);
//! 2. B is killed (`SIGKILL`). The principal's socket closes; the principal
//!    reconnects to A, and the member's mail is pushed there (the message B
//!    pushed but nobody acknowledged first), although B never released the
//!    member's streaming entry.
//! 3. B is started again, and `work`'s own socket opens there, which outranks
//!    the device's mux entry on A: A's entry stands by. B is killed. Its
//!    heartbeat expires, A takes the DID over from the dead instance's
//!    entry, and `work` is active and pushed on A again, though `work`
//!    never reconnects.
//!
//! Needs a Redis server:
//! ```text
//! REDIS_URL=redis://127.0.0.1:6379 cargo test -p affinidi-messaging-test-mediator \
//!     --features redis-backend --test mux_two_processes
//! ```
//! Skips (passes) when `REDIS_URL` is unset.

#![cfg(feature = "redis-backend")]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message as DidcommMessage;
use affinidi_messaging_mediator::tasks::websocket_streaming::StreamingLiveness;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_test_mediator::{ReplicaIdentity, TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use uuid::Uuid;

/// A logical DB no other test-mediator test uses.
const DB: u8 = 11;

/// Set on the child process: the file holding the identity it runs as.
const IDENTITY_ENV: &str = "MUX_TWO_PROCESSES_IDENTITY";

/// What the child prints once it serves, followed by its websocket URL.
const READY: &str = "REPLICA_READY ";

const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";
const BASIC: &str = "https://didcomm.org/basicmessage/2.0/message";

/// Both instances beat often, and take a dead one's DIDs over within a
/// couple of seconds, so scenario 3 doesn't wait out the production timing.
fn fast_liveness() -> StreamingLiveness {
    StreamingLiveness {
        heartbeat_every: Duration::from_millis(250),
        heartbeat_lifetime: Duration::from_millis(1500),
        ownership_recheck: Duration::from_secs(1),
    }
}

/// One instance's own connection to the shared database.
async fn redis_store(flush: bool) -> Option<Arc<dyn MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP mux_two_processes: REDIS_URL not set");
            return None;
        }
    };
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../affinidi-messaging-mediator/conf/atm-functions.lua"
            )
            .to_string(),
        ),
        database_url: format!("{}/{DB}", base.trim_end_matches('/')),
        database_timeout: 2,
        cluster_mode: std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true"),
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };
    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL");
    let store = RedisStore::new(handler, 5, 10, config.functions_file.clone());
    if flush {
        let mut conn = store.get_connection().await.expect("redis connection");
        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .expect("FLUSHDB");
    }
    Some(Arc::new(store))
}

/// Instance B, in the child process: serve as a replica of the identity in
/// [`IDENTITY_ENV`] until stdin closes. A no-op in an ordinary test run.
#[tokio::test]
async fn replica_process() {
    let Ok(path) = std::env::var(IDENTITY_ENV) else {
        return;
    };
    init_tracing();
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("identity file"))
        .expect("identity JSON");
    let identity = ReplicaIdentity {
        did: raw["did"].as_str().expect("did").to_string(),
        secrets: serde_json::from_value(raw["secrets"].clone()).expect("secrets"),
        jwt_pkcs8: serde_json::from_value(raw["jwt"].clone()).expect("jwt key"),
    };
    let store = redis_store(false).await.expect("REDIS_URL");
    let b = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store)
        .streaming_liveness(fast_liveness())
        .replica_of(identity)
        .spawn()
        .await
        .expect("instance B");
    println!("{READY}{}", b.ws_endpoint());
    // Serve until the parent closes stdin, or kills this process.
    tokio::task::spawn_blocking(|| {
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    })
    .await
    .expect("stdin reader");
    b.shutdown();
}

/// The child process running instance B. Killed when dropped, so a failing
/// test leaves nothing running.
struct ReplicaProcess {
    child: Child,
    _identity: TempFile,
}

impl ReplicaProcess {
    /// Start instance B as a replica of `identity`; returns once it serves,
    /// with its websocket URL. B's start-up may call instance A, so the wait
    /// runs off this runtime.
    async fn start(identity: &ReplicaIdentity) -> (Self, Uri) {
        let file = TempFile::new(
            json!({
                "did": identity.did,
                "secrets": identity.secrets,
                "jwt": identity.jwt_pkcs8,
            })
            .to_string(),
        );
        let mut child = Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "replica_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(IDENTITY_ENV, &file.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start instance B");
        let stdout = child.stdout.take().expect("child stdout");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let mut ready_tx = Some(ready_tx);
            // Past the ready line, keep draining so B never blocks on a full
            // pipe; B's output goes to this test's stderr.
            for line in lines.by_ref().map_while(Result::ok) {
                eprintln!("[B] {line}");
                if let Some(url) = line.strip_prefix(READY)
                    && let Some(tx) = ready_tx.take()
                {
                    let _ = tx.send(url.to_string());
                }
            }
        });
        let ws = match timeout(Duration::from_secs(60), ready_rx).await {
            Ok(Ok(url)) => url.parse().expect("B's websocket URL"),
            _ => {
                let _ = child.kill();
                panic!("instance B did not serve");
            }
        };
        (
            Self {
                child,
                _identity: file,
            },
            ws,
        )
    }

    /// Kill instance B at once, as a crash would: nothing is cleaned up.
    fn kill(&mut self) {
        self.child.kill().expect("kill instance B");
        let _ = self.child.wait();
    }
}

impl Drop for ReplicaProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A file removed when dropped. It holds key material, readable by its owner
/// only.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(contents: String) -> Self {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("mux-two-processes-{}.json", Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).expect("identity file");
        file.write_all(contents.as_bytes()).expect("write identity");
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// What arrived on the principal's socket, unpacked.
enum Frame {
    /// A `messaging/mux/event` payload.
    Event(Value),
    /// Anything else, with the DID it was encrypted to.
    Message(Box<DidcommMessage>, Option<String>),
    /// The socket closed.
    Closed,
}

async fn next_frame<S>(env: &TestEnvironment, ws: &mut S, within: Duration) -> Option<Frame>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let frame = match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => return Some(Frame::Closed),
            Ok(Some(Ok(frame))) => frame,
        };
        let Message::Text(t) = frame else { continue };
        let (msg, meta) = env.atm.unpack(t.as_str()).await.expect("unpack");
        if msg.body["type"] == EVENT_TYPE {
            return Some(Frame::Event(msg.body["payload"].clone()));
        }
        let to = affinidi_messaging_sdk::protocols::mux::mux_recipient(&meta);
        return Some(Frame::Message(Box::new(msg), to));
    }
}

/// Wait for the `attached` event that makes `member` active on the socket.
async fn active<S>(env: &TestEnvironment, ws: &mut S, member: &TestUser) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let within = Duration::from_secs(10);
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match next_frame(env, ws, left).await {
            Some(Frame::Event(e))
                if e["event"] == "attached"
                    && e["dids"][0]["did"] == member.did.as_str()
                    && e["dids"][0]["deliveryActive"] == true =>
            {
                return e["dids"][0].clone();
            }
            Some(Frame::Event(_) | Frame::Message(..)) => continue,
            Some(Frame::Closed) => panic!("the socket closed"),
            None => panic!("{} not active within {within:?}", member.did),
        }
    }
}

/// The next message pushed on the socket, with the DID it was encrypted to.
async fn pushed<S>(env: &TestEnvironment, ws: &mut S) -> (Box<DidcommMessage>, Option<String>)
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let within = Duration::from_secs(5);
    timeout(within, async {
        loop {
            match next_frame(env, ws, within).await {
                Some(Frame::Message(m, to)) if m.typ == BASIC => return (m, to),
                Some(Frame::Closed) => panic!("the socket closed"),
                None => panic!("nothing pushed"),
                Some(_) => continue,
            }
        }
    })
    .await
    .expect("a push")
}

/// Open `principal`'s mux socket on `ws_url` and wait for `ready`.
async fn open_mux(
    env: &TestEnvironment,
    principal: &TestUser,
    ws_url: Uri,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate through A");
    let request = ClientRequestBuilder::new(ws_url)
        .with_sub_protocol("didcomm-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("mux socket");
    match next_frame(env, &mut ws, Duration::from_secs(5)).await {
        Some(Frame::Event(e)) if e["event"] == "ready" => {}
        _ => panic!("no ready event"),
    }
    ws
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        BASIC.to_string(),
        json!({ "content": text }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .unwrap();
    env.atm
        .send_message(&from.profile, &packed, &msg.id, false, false)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replica_in_another_process_delivers_and_can_die() {
    if std::env::var(IDENTITY_ENV).is_ok() {
        return; // The child runs `replica_process` only.
    }
    init_tracing();
    let Some(store_a) = redis_store(true).await else {
        return;
    };
    let a = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .store(store_a)
        .streaming_liveness(fast_liveness())
        .spawn()
        .await
        .expect("instance A");
    let identity = a.replica_identity();
    let (mut b, b_ws) = ReplicaProcess::start(&identity).await;
    let a_ws: Uri = a.ws_endpoint().as_str().parse().unwrap();

    let env = TestEnvironment::new(a).await.expect("env");
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    // `work` grants the device, through A from its own socket there, and
    // goes offline, so the device's connection on B carries it.
    let mut ws = open_mux(&env, &device, b_ws).await;
    let (grant, grant_id) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        &mediator_did,
        &[MuxCapability::Receive, MuxCapability::Delete],
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .profile_add(&work.profile, true)
        .await
        .expect("work's own websocket on A");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&work.profile, vec![grant])
        .await
        .expect("mux_grant");
    assert_eq!(
        serde_json::to_value(&r).unwrap()["results"][0]["status"],
        "stored"
    );
    work.profile
        .stop_websocket()
        .await
        .expect("stop work's websocket");
    assert_eq!(
        active(&env, &mut ws, &work).await["grantId"],
        grant_id.as_str()
    );

    // 1. Stored through A, pushed by B, in the other process.
    send(&env, &sender, &work, "via A, to B").await;
    let (m, to) = pushed(&env, &mut ws).await;
    assert_eq!(m.body["content"], "via A, to B");
    assert_eq!(to.as_deref(), Some(work.did.as_str()));

    // 2. B dies without cleaning up: its streaming entries stay in Redis.
    b.kill();
    let closed = timeout(Duration::from_secs(10), async {
        loop {
            match next_frame(&env, &mut ws, Duration::from_secs(10)).await {
                Some(Frame::Closed) | None => return,
                Some(_) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the socket on the dead instance closes");

    // The device reconnects to A. Its connection takes `work` from the dead
    // instance's entry, and `work`'s mail is pushed there: first the message
    // B pushed, which the device never acknowledged and so is still stored
    // (R1.7), then a new one.
    let mut ws = open_mux(&env, &device, a_ws).await;
    active(&env, &mut ws, &work).await;
    let (m, to) = pushed(&env, &mut ws).await;
    assert_eq!(
        m.body["content"], "via A, to B",
        "the unacknowledged message is redelivered"
    );
    assert_eq!(to.as_deref(), Some(work.did.as_str()));
    send(&env, &sender, &work, "via A, after B died").await;
    let (m, to) = pushed(&env, &mut ws).await;
    assert_eq!(m.body["content"], "via A, after B died");
    assert_eq!(to.as_deref(), Some(work.did.as_str()));

    // 3. B comes back, and `work`'s own socket opens there. A direct socket
    //    outranks the device's mux entry on A, which stands by: the device
    //    is told the member is detached, `superseded`.
    let (mut b, b_ws) = ReplicaProcess::start(&identity).await;
    let tokens = env
        .tdk
        .authentication()
        .authenticate(work.did.clone(), mediator_did.clone(), 3, None)
        .await
        .expect("authenticate work through A");
    let request = ClientRequestBuilder::new(b_ws)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (_work_on_b, _) = connect_async(request)
        .await
        .expect("work's own socket on B");
    member_event(&env, &mut ws, "detached", &work, |e| {
        e["reason"] == "superseded"
    })
    .await;

    // B dies with `work`'s socket on it. Its heartbeat expires, and A takes
    // `work` over from the dead instance's entry without `work` doing
    // anything.
    b.kill();
    let back = member_event(&env, &mut ws, "attached", &work, |e| {
        e["reason"] == "reactivated"
    })
    .await;
    assert_eq!(back["deliveryActive"], true);
    // Taking the DID back redelivers `work`'s inbox: the two messages the
    // device never acknowledged come first, then the new one.
    send(&env, &sender, &work, "via A, after B died again").await;
    let mut seen = Vec::new();
    loop {
        let (m, to) = pushed(&env, &mut ws).await;
        assert_eq!(to.as_deref(), Some(work.did.as_str()));
        let content = m.body["content"].as_str().unwrap_or_default().to_string();
        if content == "via A, after B died again" {
            break;
        }
        assert!(
            ["via A, to B", "via A, after B died"].contains(&content.as_str()),
            "only unacknowledged messages are redelivered: {content}"
        );
        seen.push(content);
    }
    assert!(seen.len() <= 2, "each redelivered once: {seen:?}");
}

/// Wait for an `event` for `member` whose entry `matches`.
async fn member_event<S>(
    env: &TestEnvironment,
    ws: &mut S,
    event: &str,
    member: &TestUser,
    matches: impl Fn(&Value) -> bool,
) -> Value
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let within = Duration::from_secs(15);
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match next_frame(env, ws, left).await {
            Some(Frame::Event(e))
                if e["event"] == event
                    && e["dids"][0]["did"] == member.did.as_str()
                    && matches(&e["dids"][0]) =>
            {
                return e["dids"][0].clone();
            }
            Some(Frame::Event(_) | Frame::Message(..)) => continue,
            Some(Frame::Closed) => panic!("the socket closed"),
            None => panic!("no matching {event} for {} within {within:?}", member.did),
        }
    }
}
