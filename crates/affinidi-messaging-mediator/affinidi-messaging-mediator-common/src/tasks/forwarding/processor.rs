//! Forwarding Processor
//!
//! Reads messages from the FORWARD_Q Redis stream and delivers them to remote mediators.
//! Uses Redis consumer groups for multi-processor coordination:
//! - XREADGROUP BLOCK 0 for event-driven wake-up (no polling)
//! - XACK on successful delivery
//! - XAUTOCLAIM for recovering stale messages from crashed processors
//!
//! Transport selection:
//! - Tracks message rate per endpoint over a sliding window
//! - If rate exceeds threshold: use WebSocket (kept alive with idle timeout)
//! - Otherwise: use REST POST
//!
//! Scheduling:
//! - Endpoints are delivered to concurrently, up to `max_concurrent_endpoints`;
//!   messages for one endpoint go out in order, one at a time
//! - Each attempt is bounded by `delivery_timeout_seconds`
//!
//! Error handling:
//! - Connection failures: the endpoint backs off exponentially, and the
//!   message is queued again with a not-before at the end of the backoff
//! - Refusal from remote mediator (a 4xx other than 408/425/429): drop the
//!   message at once and send the sender a problem report; it is not retried
//! - An endpoint URL that does not parse, or that the egress policy does not
//!   admit: likewise dropped at once with a problem report of its own

use crate::store::{MediatorStore, types::ForwardQueueEntry};
use crate::tasks::forwarding::config::ForwardingConfig;
use crate::tasks::forwarding::observer::{ForwardOutcome, ForwardTransport, ForwardingObserver};
use crate::tasks::forwarding::packer::SystemMessagePacker;
use crate::time::{unix_timestamp_millis, unix_timestamp_secs};
use affinidi_net_guard::{EgressPolicy, guarded_dns_resolver};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::relay_ack::{RELAY_ACK_SUBPROTOCOL, RelayAck, frame_id};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Tracks message rate to a specific endpoint using time-bucketed counters.
///
/// Uses 1-second resolution buckets in a ring buffer instead of per-message
/// timestamps. All operations are O(1) regardless of message throughput.
struct EndpointRateTracker {
    /// Ring buffer of per-second message counts.
    /// Index = unix_seconds % bucket_count.
    buckets: Vec<(u64, u32)>, // (second_timestamp, count)
    /// Number of buckets (= window size in seconds)
    bucket_count: usize,
    /// Total count across all active buckets (cached for O(1) rate queries)
    total: u32,
    /// Window duration in seconds
    window_secs: u64,
}

impl EndpointRateTracker {
    fn new(window_seconds: u64) -> Self {
        let bucket_count = window_seconds.max(1) as usize;
        Self {
            buckets: vec![(0, 0); bucket_count],
            bucket_count,
            total: 0,
            window_secs: window_seconds,
        }
    }

    /// Record N message sends and return current rate per 10 seconds.
    fn record_and_rate(&mut self, count: u32) -> f64 {
        let now_secs = now_epoch_secs();
        self.expire_stale(now_secs);

        let idx = (now_secs as usize) % self.bucket_count;
        let bucket = &mut self.buckets[idx];
        if bucket.0 == now_secs {
            bucket.1 += count;
        } else {
            // New second — reset this bucket
            if bucket.0 > 0 {
                self.total = self.total.saturating_sub(bucket.1);
            }
            *bucket = (now_secs, count);
        }
        self.total += count;

        self.rate_per_10s()
    }

    /// Get current rate per 10 seconds without recording.
    fn current_rate(&mut self) -> f64 {
        self.expire_stale(now_epoch_secs());
        self.rate_per_10s()
    }

    fn rate_per_10s(&self) -> f64 {
        if self.window_secs > 0 {
            (self.total as f64 / self.window_secs as f64) * 10.0
        } else {
            0.0
        }
    }

    /// Expire buckets that are outside the window.
    fn expire_stale(&mut self, now_secs: u64) {
        let cutoff = now_secs.saturating_sub(self.window_secs);
        for bucket in &mut self.buckets {
            if bucket.0 > 0 && bucket.0 <= cutoff {
                self.total = self.total.saturating_sub(bucket.1);
                *bucket = (0, 0);
            }
        }
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A forward whose `message` is a TSP message decodes back to raw qb2 bytes for
/// the wire; a DIDComm message does not (and is sent as text, unchanged).
///
/// TSP forwards are queued as `base64url(qb2)` — the CESR qb64 text form of the
/// envelope's count code. A DIDComm JWE/JWS is not valid base64url of such
/// bytes, so this returns `None` and the message is sent verbatim.
///
/// Both framings are accepted. A short `-E##` frame reads `-E` in text and
/// leads with `0xF8`; a long `--E#####` frame reads `--E` and leads with
/// `0xFB`. Spec Rev 3 widened the `-E` count to cover the ciphertext, which
/// makes the long form reachable for any message over roughly 12 KB — and a
/// forwarding path that recognises only the short one drops exactly the large
/// messages it exists to carry.
fn decode_tsp_forward(message: &str) -> Option<Vec<u8>> {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    if !(message.starts_with("-E") || message.starts_with("--E")) {
        return None;
    }
    BASE64_URL_SAFE_NO_PAD
        .decode(message)
        .ok()
        .filter(|bytes| matches!(bytes.first(), Some(0xF8) | Some(0xFB)))
}

/// How long an endpoint may sit idle before its cached state is reaped.
///
/// Must stay comfortably above both the rate tracker's window (10s) and the
/// retry backoff ceiling (`max_backoff_ms`, 60s by default), so that state
/// still in active use is never dropped out from under a retry.
const ENDPOINT_IDLE_TTL: Duration = Duration::from_secs(300);

/// How long an endpoint is left on REST after a WebSocket attempt failed.
///
/// Long enough that a peer which cannot accept our WebSocket costs one failed
/// connect per window instead of one per message; short enough that a peer
/// which gains the capability (or recovers) is picked up without a restart.
const WS_SUPPRESSION_WINDOW: Duration = Duration::from_secs(300);

/// State for a connection to a remote mediator endpoint
struct EndpointState {
    rate_tracker: EndpointRateTracker,
    last_activity: Instant,
    /// Consecutive failure count for backoff calculation
    consecutive_failures: u32,
    /// Unix ms until which this endpoint is backing off after a failed
    /// attempt; `0` when it is not. While it is, its messages are queued
    /// again for after the window instead of being sent.
    retry_after_ms: u128,
    /// Set when a WebSocket attempt to this endpoint failed; until it elapses,
    /// delivery goes straight to REST.
    ///
    /// An inter-mediator hop is posted anonymously — the relaying mediator
    /// holds no session on the peer — and this mediator's own WebSocket route
    /// requires a bearer token, so a peer running this implementation refuses
    /// the upgrade every time. Without this, crossing the rate threshold buys
    /// a failed connect on *every* message before the REST fallback that was
    /// always going to carry it.
    ws_suppressed_until: Option<Instant>,
}

impl EndpointState {
    fn new(rate_window_seconds: u64) -> Self {
        EndpointState {
            rate_tracker: EndpointRateTracker::new(rate_window_seconds),
            last_activity: Instant::now(),
            consecutive_failures: 0,
            retry_after_ms: 0,
            ws_suppressed_until: None,
        }
    }

    /// Whether a WebSocket attempt is currently suppressed for this endpoint.
    fn ws_suppressed(&self, now: Instant) -> bool {
        self.ws_suppressed_until.is_some_and(|until| now < until)
    }
}

/// Shared HTTP client to avoid creating one per request.
///
/// The client is built on the [`affinidi_net_guard`] egress guard: names are
/// resolved through a fail-closed guarded resolver (any answer that is not
/// globally routable fails the whole name, closing DNS-rebinding) and redirects
/// are refused (a 3xx must not pivot the resolver onto an internal address).
/// The `policy` is retained so each delivery can additionally *vet* the target
/// URL up front — that is the half of the guard that sees IP literals, which
/// reqwest's custom resolver never gets to see (it is bypassed for literal
/// hosts). Together they stop an attacker-advertised service endpoint
/// (`169.254.169.254`, RFC1918, loopback, link-local, or plaintext http/ws)
/// from turning the mediator's forwarding client into an SSRF / open relay.
struct HttpClientPool {
    client: reqwest::Client,
    policy: EgressPolicy,
}

impl HttpClientPool {
    fn new(accept_invalid_certs: bool) -> Result<Self, String> {
        // `danger_accept_invalid_certs` is honoured ONLY in dev/test builds
        // (`test-clock`, where a local peer may present a self-signed cert). A
        // production mediator always validates TLS on the forwarding client —
        // disabling it would let a MITM on a public forwarding hop intercept
        // relayed traffic even behind the egress guard. So the config flag is
        // forced to `false` in a release build.
        #[cfg(not(feature = "test-clock"))]
        let accept_invalid_certs = {
            if accept_invalid_certs {
                warn!(
                    "ignoring danger_accept_invalid_certs: TLS validation is enforced on the \
                     forwarding client in non-test builds"
                );
            }
            false
        };
        if accept_invalid_certs {
            warn!(
                "forwarding HTTP client accepts invalid TLS certificates (test-clock build — NOT for production)"
            );
        }
        // Public-internet posture: https/wss only, globally-routable addresses
        // only, no special-use names. Deployments running an internal mediator
        // mesh (private-range peers) need an operator-configured allow-list —
        // tracked as a follow-up; the secure default is fail-closed.
        #[allow(unused_mut)]
        let mut policy = EgressPolicy::public_internet();
        // Integration-test builds only (`test-clock`, the fixture-mode marker —
        // never a default and never a production build): admit loopback +
        // plaintext http/ws so the test harness can forward between mediators on
        // 127.0.0.1. A release mediator keeps the fail-closed policy above.
        #[cfg(feature = "test-clock")]
        {
            policy = policy.with_dev_loopback(
                affinidi_net_guard::DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback(
                ),
            );
            warn!(
                "forwarding egress guard: loopback/plaintext next hops permitted (test-clock build — NOT for production)"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(accept_invalid_certs)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            // Following a redirect lets the remote host pivot the resolver onto
            // an arbitrary internal address (SSRF), so refuse.
            .redirect(reqwest::redirect::Policy::none())
            // Never honour ambient proxy env — it would route around the guard.
            .no_proxy()
            // Fail-closed DNS: refuse any name that resolves to a non-routable
            // address, and connect only to the vetted addresses (no rebind).
            .dns_resolver(guarded_dns_resolver(policy.clone()))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;
        Ok(Self { client, policy })
    }
}

/// A pooled WebSocket connection to a remote mediator
struct PooledWebSocket {
    /// The relay socket, unsplit: every relayed frame is answered by a
    /// [`RelayAck`] on the same connection, so this side both writes and reads
    /// and there is no concurrent use to split for.
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    /// When this connection was last used
    last_used: Instant,
}

/// Why a relayed frame did not come back acknowledged.
///
/// The distinction decides what happens to the *connection*: a rejection is the
/// peer answering about one message and leaves the socket usable, while a
/// transport failure means the socket itself is no longer trustworthy. Both
/// fail the message, which is what keeps WebSocket relay as safe as REST.
enum AckFailure {
    /// The peer answered with a negative [`RelayAck`] — the analogue of a
    /// non-2xx REST response.
    Rejected(String),
    /// The frame, or its answer, never made it: send error, closed socket,
    /// or no ack inside the timeout.
    Transport(String),
}

/// Why one relay attempt failed, which decides whether it is worth retrying.
#[derive(Debug)]
enum RelayFailure {
    /// The peer answered and refused the message: a 4xx other than 408, 425
    /// or 429. Sending it again gets the same answer, and a refusal must not
    /// turn into a delivery just because the recipient's policy changed
    /// while we were retrying, so it is dropped at once.
    Refused { status: u16, reason: String },
    /// The peer was unreachable, overloaded or failed: worth another try.
    Retryable(String),
    /// The endpoint URL does not parse, or the egress policy does not admit
    /// it. No request was made, and none ever will be, so it is final.
    NotPermitted(String),
}

impl RelayFailure {
    /// Classify a non-2xx answer from the peer.
    fn from_status(status: u16, reason: String) -> Self {
        let transient = matches!(status, 408 | 425 | 429) || !(400..500).contains(&status);
        if transient {
            RelayFailure::Retryable(reason)
        } else {
            RelayFailure::Refused { status, reason }
        }
    }
}

impl std::fmt::Display for RelayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayFailure::Refused { reason, .. }
            | RelayFailure::Retryable(reason)
            | RelayFailure::NotPermitted(reason) => f.write_str(reason),
        }
    }
}

/// Abandonment reports whose live notification could not be published. The
/// report itself is stored, so this counts delayed notices, not lost ones.
const METRIC_FORWARD_REPORT_LIVE_PUBLISH_FAILED_TOTAL: &str =
    "forward_problem_report_live_publish_failed_total";

/// Why a forward was dropped undelivered, which picks the sender's report.
#[derive(Clone, Copy, Debug)]
enum ReportReason {
    /// Its retries ran out.
    Abandoned,
    /// The peer refused it with this HTTP status.
    Refused(u16),
    /// The next-hop endpoint is not one this mediator sends to.
    NotPermitted,
}

/// When an entry may first be attempted (unix ms): after the delay its sender
/// asked for, and after the not-before of a retry.
fn due_at_ms(entry: &ForwardQueueEntry) -> u128 {
    let requested = if entry.delay_milli > 0 {
        entry.received_at_ms + entry.delay_milli as u128
    } else {
        0
    };
    requested.max(entry.not_before_ms)
}

/// The processor's claimed-but-unfinished entries, and which endpoint is
/// delivered to next.
///
/// Each held entry is in exactly one of `parked`, `queued`, or a running
/// delivery task (its endpoint is then in `busy`), and its stream id is in
/// `held` until that task finishes. An endpoint is in `waiting` exactly when
/// it has queued entries and no running task.
struct Scheduler {
    max_concurrent: usize,
    batch_size: usize,
    /// Stop reading once this many entries are held.
    max_held: usize,
    /// The longest an entry is parked for. Retries never ask for more than
    /// `max_backoff_ms`; a sender-requested delay beyond it is left claimed
    /// in the store, as before.
    park_horizon_ms: u128,
    held: HashSet<String>,
    /// Entries not yet due, by (due unix ms, arrival order).
    parked: BTreeMap<(u128, u64), ForwardQueueEntry>,
    arrivals: u64,
    queued: HashMap<String, VecDeque<ForwardQueueEntry>>,
    waiting: VecDeque<String>,
    busy: HashSet<String>,
}

impl Scheduler {
    fn new(config: &ForwardingConfig) -> Self {
        let max_concurrent = config.max_concurrent_endpoints.max(1);
        let batch_size = config.batch_size.max(1);
        Scheduler {
            max_concurrent,
            batch_size,
            max_held: batch_size.saturating_mul(max_concurrent),
            park_horizon_ms: config.max_backoff_ms.max(config.initial_backoff_ms) as u128,
            held: HashSet::new(),
            parked: BTreeMap::new(),
            arrivals: 0,
            queued: HashMap::new(),
            waiting: VecDeque::new(),
            busy: HashSet::new(),
        }
    }

    fn has_room(&self) -> bool {
        self.held.len() < self.max_held
    }

    /// Take newly read entries: due ones are queued for their endpoint, the
    /// rest parked until due.
    fn accept(&mut self, entries: Vec<ForwardQueueEntry>, now_ms: u128) {
        for entry in entries {
            if !self.held.insert(entry.stream_id.clone()) {
                debug!(
                    "FORWARD_Q entry {} is already held; ignoring the repeat",
                    entry.stream_id
                );
                continue;
            }
            let due = due_at_ms(&entry);
            if due <= now_ms {
                self.enqueue(entry);
            } else if entry.not_before_ms == 0 && due - now_ms > self.park_horizon_ms {
                debug!(
                    "Forward {} is delayed {}ms, beyond the {}ms park horizon; leaving it claimed",
                    entry.stream_id,
                    due - now_ms,
                    self.park_horizon_ms
                );
                self.held.remove(&entry.stream_id);
            } else {
                // A retry's not-before is at most `max_backoff_ms` ahead when
                // written; the clamp only bites on clock skew between
                // processors, where an early attempt beats holding it forever.
                let until = due.min(now_ms + self.park_horizon_ms);
                self.arrivals += 1;
                self.parked.insert((until, self.arrivals), entry);
            }
        }
    }

    /// Move parked entries that are now due onto their endpoint's queue.
    fn release_due(&mut self, now_ms: u128) {
        while let Some(first) = self.parked.first_entry() {
            if first.key().0 > now_ms {
                break;
            }
            let entry = first.remove();
            self.enqueue(entry);
        }
    }

    fn enqueue(&mut self, entry: ForwardQueueEntry) {
        let endpoint_url = entry.endpoint_url.clone();
        let queue = self.queued.entry(endpoint_url.clone()).or_default();
        let was_empty = queue.is_empty();
        queue.push_back(entry);
        if was_empty && !self.busy.contains(&endpoint_url) {
            self.waiting.push_back(endpoint_url);
        }
    }

    /// The next endpoint to deliver to and up to `batch_size` of its entries,
    /// marking it busy. Endpoints take turns in the order they became ready.
    fn next_batch(&mut self) -> Option<(String, Vec<ForwardQueueEntry>)> {
        while let Some(endpoint_url) = self.waiting.pop_front() {
            let Some(queue) = self.queued.get_mut(&endpoint_url) else {
                continue;
            };
            let take = queue.len().min(self.batch_size);
            let batch: Vec<_> = queue.drain(..take).collect();
            if queue.is_empty() {
                self.queued.remove(&endpoint_url);
            }
            if batch.is_empty() {
                continue;
            }
            self.busy.insert(endpoint_url.clone());
            return Some((endpoint_url, batch));
        }
        None
    }

    /// A delivery task for `endpoint_url` has finished with `stream_ids`.
    fn finished(&mut self, endpoint_url: &str, stream_ids: &[String]) {
        for id in stream_ids {
            self.held.remove(id);
        }
        self.busy.remove(endpoint_url);
        if self.queued.get(endpoint_url).is_some_and(|q| !q.is_empty()) {
            self.waiting.push_back(endpoint_url.to_string());
        }
    }

    fn next_due_ms(&self) -> Option<u128> {
        self.parked.keys().next().map(|(due, _)| *due)
    }
}

/// The forwarding processor that reads from FORWARD_Q and delivers to remote mediators
#[derive(Clone)]
pub struct ForwardingProcessor {
    config: ForwardingConfig,
    database: Arc<dyn MediatorStore>,
    consumer_name: String,
    endpoints: Arc<RwLock<HashMap<String, EndpointState>>>,
    http_pool: Arc<HttpClientPool>,
    /// WebSocket connection pool keyed by endpoint URL
    ws_pool: Arc<Mutex<HashMap<String, PooledWebSocket>>>,
    /// How mediator-authored messages (the forwarding-failure problem report)
    /// are encrypted for their recipient. `None` when the host has no mediator
    /// identity to pack with — see [`SystemMessagePacker`].
    packer: Option<Arc<dyn SystemMessagePacker>>,
    /// Told the fate of every relay attempt — see [`ForwardingObserver`].
    observer: Option<Arc<dyn ForwardingObserver>>,
}

impl ForwardingProcessor {
    pub fn new(
        config: ForwardingConfig,
        database: Arc<dyn MediatorStore>,
    ) -> Result<Self, crate::errors::MediatorError> {
        let consumer_name = format!("processor_{}", Uuid::new_v4());
        info!(
            "ForwardingProcessor created: consumer={}, group={}",
            consumer_name, config.consumer_group
        );
        let http_pool = Arc::new(HttpClientPool::new(config.accept_invalid_certs).map_err(
            |e| {
                crate::errors::MediatorError::InternalError(
                    17,
                    "forwarding".into(),
                    format!("Failed to create HTTP client pool: {e}"),
                )
            },
        )?);
        Ok(Self {
            config,
            database,
            consumer_name,
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            http_pool,
            ws_pool: Arc::new(Mutex::new(HashMap::new())),
            packer: None,
            observer: None,
        })
    }

    /// Supply the mediator identity that mediator-authored messages are packed
    /// under. Without it the processor can still forward — only the
    /// forwarding-failure problem report needs to be encrypted — so this is a
    /// post-construction opt-in rather than a `new` argument, keeping the
    /// standalone `forwarding_processor` binary (which has no mediator DID or
    /// secrets in its config) compiling and running unchanged.
    pub fn with_system_packer(mut self, packer: Arc<dyn SystemMessagePacker>) -> Self {
        self.packer = Some(packer);
        self
    }

    /// Report each relay attempt's outcome to `observer` (the mediator's traffic
    /// monitor). Optional for the same reason as
    /// [`with_system_packer`](Self::with_system_packer).
    pub fn with_observer(mut self, observer: Arc<dyn ForwardingObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn observe(&self, entry: &ForwardQueueEntry, outcome: ForwardOutcome) {
        if let Some(observer) = &self.observer {
            observer.observe(entry, outcome);
        }
    }

    /// Start the forwarding processor. This runs indefinitely.
    ///
    /// Reading and delivering are decoupled. A reader task claims batches from
    /// the queue; this loop sorts each entry into "ready now" or "parked until
    /// its not-before", and hands ready entries to one delivery task per
    /// endpoint, at most `max_concurrent_endpoints` at a time. A slow or
    /// failing endpoint therefore occupies one slot, and its backoff is a
    /// not-before on its own entries rather than a pause of the whole loop.
    ///
    /// Every claimed entry is held in exactly one place — parked, queued for
    /// its endpoint, or inside that endpoint's delivery task — and only the
    /// delivery task acks or deletes it, once. An endpoint never has two
    /// delivery tasks at a time, which keeps its messages in order and its
    /// pooled WebSocket single-user.
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // The consumer group is created lazily on the first
        // `forward_queue_read` call; no explicit ensure step needed.
        info!(
            "ForwardingProcessor started: consumer={}, group={}, batch_size={}, max_concurrent_endpoints={}, delivery_timeout={}s, ws_threshold={} msgs/10s, ws_idle_timeout={}s",
            self.consumer_name,
            self.config.consumer_group,
            self.config.batch_size,
            self.config.max_concurrent_endpoints,
            self.config.delivery_timeout_seconds,
            self.config.ws_threshold_msgs_per_10s,
            self.config.ws_idle_timeout_seconds
        );

        // `report_errors` promises the sender an explanation when we give up on
        // their forward, and we can only keep that promise if we can encrypt it
        // as ourselves. Say so at startup rather than at the first abandonment,
        // which may be weeks later and buried in a batch of delivery failures.
        if self.config.report_errors && self.packer.is_none() {
            warn!(
                "report_errors is enabled but no system message packer is configured — \
                 abandoned forwards will be logged here and NOT reported to their senders"
            );
        }

        // Spawn a background task to periodically reclaim stale messages.
        //
        // The reclaimed entries are not delivered from here. If that changes,
        // it must skip entries this processor already holds (see `held` in
        // the loop below): a parked retry sits claimed but idle for up to
        // `max_backoff_ms`, which can exceed the 60 s idle threshold.
        let db_clone = self.database.clone();
        let group = self.config.consumer_group.clone();
        let consumer = self.consumer_name.clone();
        let batch_size = self.config.batch_size;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                match db_clone
                    .forward_queue_autoclaim(&group, &consumer, Duration::from_secs(60), batch_size)
                    .await
                {
                    Ok(entries) if !entries.is_empty() => {
                        info!("Autoclaimed {} stale forwarding messages", entries.len());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Autoclaim error: {}", e);
                    }
                }
            }
        });

        // Spawn a background task to clean up idle WebSocket connections and
        // idle per-endpoint state.
        let ws_pool = self.ws_pool.clone();
        let endpoints = self.endpoints.clone();
        let idle_timeout = Duration::from_secs(self.config.ws_idle_timeout_seconds);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let mut pool = ws_pool.lock().await;
                let now = Instant::now();
                let before = pool.len();
                pool.retain(|endpoint, ws| {
                    if now.duration_since(ws.last_used) > idle_timeout {
                        info!(
                            "Closing idle WebSocket to {} (idle {}s)",
                            endpoint,
                            now.duration_since(ws.last_used).as_secs()
                        );
                        // Dropping the writer closes the connection
                        false
                    } else {
                        true
                    }
                });
                let closed = before - pool.len();
                if closed > 0 {
                    debug!(
                        "Closed {} idle WebSocket connections ({} remaining)",
                        closed,
                        pool.len()
                    );
                }
                drop(pool);

                // `endpoints` is keyed by the service endpoint URL out of a
                // peer's DID Doc, so its key space is remote-controlled and it
                // would otherwise grow for the process lifetime. Entries only
                // cache a rate window and a failure count, both of which are
                // meaningless once an endpoint has been silent this long, so
                // dropping them just means the next forward starts fresh.
                let mut endpoints = endpoints.write().await;
                let before = endpoints.len();
                endpoints.retain(|_, state| {
                    now.duration_since(state.last_activity) <= ENDPOINT_IDLE_TTL
                });
                let reaped = before - endpoints.len();
                if reaped > 0 {
                    debug!(
                        "Reaped {} idle forwarding endpoint(s) ({} remaining)",
                        reaped,
                        endpoints.len()
                    );
                }
            }
        });

        // The read runs in its own task because it is not cancel-safe: a
        // Redis XREADGROUP abandoned mid-flight still claims what it read.
        // The channel holds one batch, so the reader stays at most one batch
        // ahead of what this loop has accepted.
        let (batch_tx, mut batch_rx) = mpsc::channel::<Vec<ForwardQueueEntry>>(1);
        let mut reader = JoinSet::new();
        {
            let database = self.database.clone();
            let group = self.config.consumer_group.clone();
            let consumer = self.consumer_name.clone();
            let batch_size = self.config.batch_size;
            reader.spawn(async move {
                loop {
                    match database
                        .forward_queue_read(&group, &consumer, batch_size, Duration::from_secs(5))
                        .await
                    {
                        Ok(entries) if entries.is_empty() => {}
                        Ok(entries) => {
                            if batch_tx.send(entries).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            error!("Error reading from FORWARD_Q: {}. Retrying in 1s...", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }

        let this = Arc::new(self.clone());
        let mut scheduler = Scheduler::new(&self.config);
        let mut deliveries: JoinSet<()> = JoinSet::new();
        // Which endpoint, and which entries, each delivery task holds.
        let mut running: HashMap<tokio::task::Id, (String, Vec<String>)> = HashMap::new();

        loop {
            let now_ms = unix_timestamp_millis();
            scheduler.release_due(now_ms);

            while deliveries.len() < scheduler.max_concurrent {
                let Some((endpoint_url, batch)) = scheduler.next_batch() else {
                    break;
                };
                let ids = batch.iter().map(|m| m.stream_id.clone()).collect();
                let processor = this.clone();
                let task_endpoint = endpoint_url.clone();
                let handle = deliveries.spawn(async move {
                    processor
                        .process_endpoint_batch(&task_endpoint, batch)
                        .await;
                });
                running.insert(handle.id(), (endpoint_url, ids));
            }

            let wake_in = scheduler
                .next_due_ms()
                .map(|due| Duration::from_millis(due.saturating_sub(now_ms) as u64))
                .unwrap_or(Duration::from_secs(3600));
            let can_read = scheduler.has_room();

            tokio::select! {
                Some(done) = deliveries.join_next_with_id(), if !deliveries.is_empty() => {
                    let id = match done {
                        Ok((id, ())) => id,
                        Err(e) => {
                            // The entries stay claimed in the store, as they
                            // would after a crash; nothing here acks them.
                            error!("Forwarding delivery task failed: {e}");
                            e.id()
                        }
                    };
                    if let Some((endpoint_url, ids)) = running.remove(&id) {
                        scheduler.finished(&endpoint_url, &ids);
                    }
                }
                batch = batch_rx.recv(), if can_read => {
                    let Some(entries) = batch else {
                        return Err("forwarding queue reader stopped".into());
                    };
                    debug!("Read {} entries from FORWARD_Q", entries.len());
                    scheduler.accept(entries, unix_timestamp_millis());
                }
                _ = tokio::time::sleep(wake_in) => {}
            }
        }
    }

    /// Deliver a batch of entries, all due now, for one endpoint.
    ///
    /// Messages go out one at a time, in order. Each ends in exactly one
    /// queue update: acked and deleted (delivered, refused, not permitted,
    /// expired or abandoned), or replaced by a retry entry carrying a
    /// not-before and then deleted. Once one attempt fails, the endpoint backs
    /// off and the rest of the batch are retried after the backoff without
    /// being sent now; so a failing endpoint costs one attempt per backoff
    /// window, not one per message.
    async fn process_endpoint_batch(&self, endpoint_url: &str, messages: Vec<ForwardQueueEntry>) {
        let msg_count = messages.len();
        debug!(
            "Processing {} messages for endpoint: {}",
            msg_count, endpoint_url
        );

        // Check if any messages have expired
        let now_secs = unix_timestamp_secs();

        let (ready, expired): (Vec<_>, Vec<_>) =
            messages.into_iter().partition(|m| m.expires_at > now_secs);

        // ACK and delete expired messages
        if !expired.is_empty() {
            let expired_ids: Vec<&str> = expired.iter().map(|m| m.stream_id.as_str()).collect();
            warn!(
                "Dropping {} expired forwarding messages for endpoint {}",
                expired.len(),
                endpoint_url
            );
            for msg in &expired {
                info!(
                    "FORWARD_EXPIRED: to_did_hash={} from_did_hash={} endpoint={}",
                    msg.to_did_hash, msg.from_did_hash, endpoint_url
                );
                self.observe(msg, ForwardOutcome::Expired);
            }
            if let Err(e) = self
                .database
                .forward_queue_ack_and_delete(&self.config.consumer_group, &expired_ids)
                .await
            {
                warn!(
                    "Failed to ACK and delete {} expired entries: {}",
                    expired_ids.len(),
                    e
                );
            }
        }

        if ready.is_empty() {
            return;
        }

        // Update rate tracker and decide transport
        let use_websocket = {
            let mut endpoints = self.endpoints.write().await;
            let state = endpoints
                .entry(endpoint_url.to_string())
                .or_insert_with(|| EndpointState::new(self.config.rate_window_seconds));

            let now = Instant::now();
            state.rate_tracker.record_and_rate(ready.len() as u32);
            state.last_activity = now;

            let rate = state.rate_tracker.current_rate();
            let suppressed = state.ws_suppressed(now);
            debug!(
                "Endpoint {} rate: {:.2} msgs/10s (threshold: {}, ws_suppressed: {})",
                endpoint_url, rate, self.config.ws_threshold_msgs_per_10s, suppressed
            );
            rate >= self.config.ws_threshold_msgs_per_10s as f64 && !suppressed
        };

        // Deliver messages
        let transport = if use_websocket { "WebSocket" } else { "REST" };
        let relayed = ForwardOutcome::Relayed {
            transport: if use_websocket {
                ForwardTransport::Websocket
            } else {
                ForwardTransport::Rest
            },
        };
        debug!(
            "Delivering {} messages to {} via {}",
            ready.len(),
            endpoint_url,
            transport
        );

        let delivery_timeout = Duration::from_secs(self.config.delivery_timeout_seconds.max(1));
        let mut succeeded = Vec::new();

        for msg in &ready {
            // Checked per message, not once per batch: the attempt before this
            // one may just have failed and opened the backoff window.
            if let Some(retry_after_ms) = self.endpoint_backing_off(endpoint_url).await {
                debug!(
                    "Endpoint {} is backing off; deferring message (retry_count={})",
                    endpoint_url, msg.retry_count
                );
                self.retry_or_abandon(msg, endpoint_url, retry_after_ms)
                    .await;
                continue;
            }

            let attempt = tokio::time::timeout(
                delivery_timeout,
                self.deliver_message(endpoint_url, msg, use_websocket),
            )
            .await
            .unwrap_or_else(|_| {
                Err(RelayFailure::Retryable(format!(
                    "no answer from {endpoint_url} within {}s",
                    delivery_timeout.as_secs()
                )))
            });

            match attempt {
                Ok(()) => {
                    let forward_time_ms =
                        unix_timestamp_millis().saturating_sub(msg.received_at_ms);
                    let delay_info = if msg.delay_milli > 0 {
                        format!(", delay_requested={}ms", msg.delay_milli)
                    } else {
                        String::new()
                    };

                    info!(
                        "FORWARD_DELIVERED: to_did_hash={} from_did_hash={} endpoint={} transport={} forward_time={}ms{}",
                        msg.to_did_hash,
                        msg.from_did_hash,
                        endpoint_url,
                        transport,
                        forward_time_ms,
                        delay_info,
                    );
                    self.observe(msg, relayed);
                    succeeded.push(msg.stream_id.as_str());
                    self.record_endpoint_success(endpoint_url).await;
                }
                // A refusal is final: drop it now and tell the sender. The peer
                // answered, so it says nothing about the endpoint's health and
                // does not count towards backoff.
                Err(RelayFailure::Refused { status, reason }) => {
                    warn!(
                        "FORWARD_REFUSED: to_did_hash={} from_did_hash={} endpoint={} status={} error={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, status, reason
                    );
                    self.drop_final(msg, endpoint_url, ForwardOutcome::Refused { status })
                        .await;
                }
                // So is an endpoint we will not send to: no retry changes the
                // URL or the policy, and nothing was sent.
                Err(RelayFailure::NotPermitted(reason)) => {
                    warn!(
                        "FORWARD_NOT_PERMITTED: to_did_hash={} from_did_hash={} endpoint={} error={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, reason
                    );
                    self.drop_final(msg, endpoint_url, ForwardOutcome::NotPermitted)
                        .await;
                }
                Err(e @ RelayFailure::Retryable(_)) => {
                    warn!(
                        "FORWARD_FAILED: to_did_hash={} from_did_hash={} endpoint={} error={} retry_count={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, e, msg.retry_count
                    );
                    let retry_after_ms = self.record_endpoint_failure(endpoint_url).await;

                    // Remove broken WebSocket connection on failure
                    if use_websocket {
                        let mut pool = self.ws_pool.lock().await;
                        if pool.remove(endpoint_url).is_some() {
                            debug!("Removed failed WebSocket connection for {}", endpoint_url);
                        }
                    }

                    self.retry_or_abandon(msg, endpoint_url, retry_after_ms)
                        .await;
                }
            }
        }

        // ACK and delete succeeded messages
        if !succeeded.is_empty() {
            let count = succeeded.len();
            if let Err(e) = self
                .database
                .forward_queue_ack_and_delete(&self.config.consumer_group, &succeeded)
                .await
            {
                warn!(
                    "Failed to ACK and delete {} succeeded entries: {}",
                    count, e
                );
            }
            debug!("ACKed {} forwarded messages for {}", count, endpoint_url);
        }
    }

    /// When the endpoint's backoff ends (unix ms), if it is backing off now.
    async fn endpoint_backing_off(&self, endpoint_url: &str) -> Option<u128> {
        let endpoints = self.endpoints.read().await;
        let retry_after_ms = endpoints.get(endpoint_url)?.retry_after_ms;
        (retry_after_ms > unix_timestamp_millis()).then_some(retry_after_ms)
    }

    async fn record_endpoint_success(&self, endpoint_url: &str) {
        let mut endpoints = self.endpoints.write().await;
        if let Some(state) = endpoints.get_mut(endpoint_url) {
            state.consecutive_failures = 0;
            state.retry_after_ms = 0;
        }
    }

    /// Count a failed attempt against the endpoint and open its backoff
    /// window. Returns when the window ends (unix ms).
    async fn record_endpoint_failure(&self, endpoint_url: &str) -> u128 {
        let mut endpoints = self.endpoints.write().await;
        let state = endpoints
            .entry(endpoint_url.to_string())
            .or_insert_with(|| EndpointState::new(self.config.rate_window_seconds));
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let backoff = self.calculate_backoff(state.consecutive_failures);
        state.retry_after_ms = unix_timestamp_millis() + backoff.as_millis();
        debug!(
            "Endpoint {} backing off {}ms (failures: {})",
            endpoint_url,
            backoff.as_millis(),
            state.consecutive_failures
        );
        state.retry_after_ms
    }

    /// Drop an entry that no retry can deliver, and tell its sender.
    async fn drop_final(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        outcome: ForwardOutcome,
    ) {
        let ids = [msg.stream_id.as_str()];
        if let Err(e) = self
            .database
            .forward_queue_ack_and_delete(&self.config.consumer_group, &ids)
            .await
        {
            warn!("Failed to ACK and delete undeliverable entry: {e}");
        }
        self.observe(msg, outcome);
        if self.config.report_errors && !msg.from_did.is_empty() {
            let reason = match outcome {
                ForwardOutcome::Refused { status } => ReportReason::Refused(status),
                ForwardOutcome::NotPermitted => ReportReason::NotPermitted,
                _ => ReportReason::Abandoned,
            };
            self.send_forwarding_failure_report(msg, endpoint_url, reason)
                .await;
        }
    }

    /// Queue `msg` again for an attempt no earlier than `not_before_ms`, or
    /// abandon it if its retries are spent.
    async fn retry_or_abandon(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        not_before_ms: u128,
    ) {
        if msg.retry_count >= self.config.max_retries {
            // Max retries exceeded — ACK and drop, send problem report to sender
            warn!(
                "FORWARD_ABANDONED: to_did_hash={} from_did_hash={} endpoint={} retries={}",
                msg.to_did_hash, msg.from_did_hash, endpoint_url, msg.retry_count
            );
            let ids = [msg.stream_id.as_str()];
            if let Err(e) = self
                .database
                .forward_queue_ack_and_delete(&self.config.consumer_group, &ids)
                .await
            {
                warn!("Failed to ACK and delete abandoned entry: {e}");
            }
            self.observe(
                msg,
                ForwardOutcome::Abandoned {
                    attempts: msg.retry_count + 1,
                },
            );

            // Send problem report to the original sender if we know their DID
            if self.config.report_errors && !msg.from_did.is_empty() {
                self.send_forwarding_failure_report(msg, endpoint_url, ReportReason::Abandoned)
                    .await;
            }
            return;
        }

        // Re-enqueue with incremented retry count. The not-before travels with
        // the entry, so whichever processor reads it next waits out the
        // backoff too.
        let mut retry_entry = msg.clone();
        retry_entry.retry_count += 1;
        retry_entry.not_before_ms = not_before_ms;

        // Enqueue the retry before releasing the old entry. In the other
        // order a crash between the two loses the message; in this one it
        // leaves the old entry claimed, so autoclaim redelivers it (at least
        // once, never zero).
        //
        // `max_len = 0` keeps the legacy unbounded behaviour for retries; the
        // inbound enqueue path applies the queue limit instead.
        match self.database.forward_queue_enqueue(&retry_entry, 0).await {
            Ok(_) => {
                self.observe(
                    msg,
                    ForwardOutcome::Retrying {
                        attempt: msg.retry_count + 1,
                        max_retries: self.config.max_retries,
                    },
                );
                let ids = [msg.stream_id.as_str()];
                if let Err(e) = self
                    .database
                    .forward_queue_ack_and_delete(&self.config.consumer_group, &ids)
                    .await
                {
                    warn!("Failed to ACK and delete retried entry: {e}");
                }
            }
            Err(e) => {
                // The old entry stays claimed, so autoclaim picks it up again
                // once it has been idle long enough.
                error!("Failed to re-enqueue retry entry; leaving it claimed for autoclaim: {e}");
            }
        }
    }

    /// How long a forwarding-failure problem report stays in the sender's
    /// inbox before the expiry sweep reclaims it.
    const PROBLEM_REPORT_TTL_SECS: u64 = 300;

    /// Build the DIDComm **plaintext** of the abandonment problem report.
    ///
    /// `from` is the mediator's own DID and is not optional: the report is
    /// packed authcrypt, and the recipient's addressing-consistency check binds
    /// the authcrypt sender to this field. A report with no `from` decrypts and
    /// is then rejected — which is indistinguishable, from the sender's side,
    /// from the bug this replaces.
    /// How to name a forward's destination in diagnostics.
    ///
    /// Usually the VID. For a relayed endpoint-to-endpoint message it is the
    /// hash, because Rev 3 §5.3.3 forbids an intermediary from keeping the VID
    /// and the queue entry therefore does not carry one. The hash still lets an
    /// operator correlate a report with the log lines for the same forward,
    /// which is what these strings are for.
    fn destination_label(msg: &ForwardQueueEntry) -> &str {
        if msg.to_did.is_empty() {
            &msg.to_did_hash
        } else {
            &msg.to_did
        }
    }

    fn build_problem_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.abandoned",
            "comment": format!(
                "Message forwarding to {} failed after {} retries. Destination endpoint: {}",
                destination, msg.retry_count, endpoint_url
            ),
            "args": [destination, msg.retry_count.to_string(), endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    /// The DIDComm plaintext of the report sent when the peer mediator
    /// refused the relay outright (see [`RelayFailure::Refused`]). The peer's
    /// own reason stays in the log: it may describe the recipient's policy,
    /// which the sender is not told.
    fn build_refusal_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        status: u16,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.refused",
            "comment": format!(
                "The mediator for {} refused the forwarded message (HTTP {}). Destination endpoint: {}",
                destination, status, endpoint_url
            ),
            "args": [destination, status.to_string(), endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    /// The DIDComm plaintext of the report sent when the next hop is not an
    /// endpoint this mediator forwards to (see [`RelayFailure::NotPermitted`]).
    /// Which policy rule matched stays in the log.
    fn build_not_permitted_report(
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        let destination = Self::destination_label(msg);
        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.endpoint-not-permitted",
            "comment": format!(
                "The forwarded message for {} was not sent: this mediator does not forward to the destination endpoint {}",
                destination, endpoint_url
            ),
            "args": [destination, endpoint_url],
        });
        Self::problem_report_envelope(msg, problem_body, from, now)
    }

    fn problem_report_envelope(
        msg: &ForwardQueueEntry,
        problem_body: serde_json::Value,
        from: &str,
        now: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "https://didcomm.org/report-problem/2.0/problem-report",
            "id": Uuid::new_v4().to_string(),
            "body": problem_body,
            "from": from,
            "to": [msg.from_did],
            "created_time": now,
            "expires_time": now + Self::PROBLEM_REPORT_TTL_SECS,
        })
    }

    /// Send a problem report to the original sender when forwarding has been
    /// abandoned.
    ///
    /// The report is authcrypted from the mediator to the sender, like every
    /// other message the mediator puts in an inbox. It used to be stored as the
    /// raw plaintext JSON, which every SDK client on the default receive policy
    /// discards with `envelope wrapping Plaintext is not in the accepted set` —
    /// so from the sender's point of view a forward that the mediator gave up on
    /// simply vanished.
    ///
    /// When the report cannot be packed it is **not** stored. An envelope the
    /// recipient's policy refuses is the defect being fixed, and storing one
    /// merely moves the failure to their client (where it re-fails on every
    /// fetch until it expires) instead of putting it where an operator can act
    /// on it. Anoncrypt is no fallback either — bare anoncrypt is outside the
    /// default accepted set too. So the abandonment surfaces as an operator-side
    /// `ERROR` naming the sender, the destination and the reason.
    ///
    /// `reason` says whether the retries ran out, the peer refused the relay
    /// outright, or the endpoint was not one this mediator sends to.
    async fn send_forwarding_failure_report(
        &self,
        msg: &ForwardQueueEntry,
        endpoint_url: &str,
        reason: ReportReason,
    ) {
        let now = unix_timestamp_secs();

        let Some(packer) = self.packer.as_ref() else {
            error!(
                "FORWARD_PROBLEM_REPORT_UNSENT: no system message packer configured, so the \
                 abandoned forward to {} (sender {}, endpoint {}) cannot be reported to its sender",
                Self::destination_label(msg),
                msg.from_did_hash,
                endpoint_url
            );
            return;
        };

        let report = match reason {
            ReportReason::Refused(status) => {
                Self::build_refusal_report(msg, endpoint_url, status, packer.mediator_did(), now)
            }
            ReportReason::NotPermitted => {
                Self::build_not_permitted_report(msg, endpoint_url, packer.mediator_did(), now)
            }
            ReportReason::Abandoned => {
                Self::build_problem_report(msg, endpoint_url, packer.mediator_did(), now)
            }
        };

        let packed = match packer.pack(&report, &msg.from_did).await {
            Ok(packed) => packed,
            Err(e) => {
                error!(
                    "FORWARD_PROBLEM_REPORT_UNSENT: couldn't pack the abandonment report for \
                     sender {} (abandoned forward to {}, endpoint {}): {}",
                    msg.from_did_hash,
                    Self::destination_label(msg),
                    endpoint_url,
                    e
                );
                return;
            }
        };

        match self
            .database
            .store_message(
                "forwarding-processor",
                &packed,
                &msg.from_did_hash,
                // The mediator authored this one, so it is the sender of
                // record — the same `from` hash its protocol replies carry.
                // (This slot used to hold the literal string "SYSTEM", which
                // is not a DID hash and gave the report an outbox of its own.)
                Some(&crate::did_identity::did_hash(packer.mediator_did())),
                now + Self::PROBLEM_REPORT_TTL_SECS,
                0, // No MAXLEN for system-generated problem reports
            )
            .await
        {
            Ok(hash) => {
                info!(
                    "FORWARD_PROBLEM_REPORT: stored problem report {} for sender {}",
                    hash, msg.from_did_hash
                );
                // Notify after the store, as every other inbox write does: a
                // live socket only learns of the report from this, and a
                // raw-TSP socket answers it by draining the inbox.
                if let Some(stream_uuid) = self
                    .database
                    .streaming_is_client_live(&msg.from_did_hash, false)
                    .await
                    && let Err(e) = self
                        .database
                        .streaming_publish_message(&msg.from_did_hash, &stream_uuid, &packed, false)
                        .await
                {
                    // Counted as well as logged, so a streaming outage shows
                    // as a rate rather than scattered warnings (R6).
                    metrics::counter!(METRIC_FORWARD_REPORT_LIVE_PUBLISH_FAILED_TOTAL).increment(1);
                    warn!(
                        "FORWARD_PROBLEM_REPORT: live notification for sender {} not published \
                         (the report waits in the inbox): {}",
                        msg.from_did_hash, e
                    );
                }
            }
            Err(e) => {
                error!(
                    "Failed to store forwarding problem report for {}: {}",
                    msg.from_did_hash, e
                );
            }
        }
    }

    /// Deliver a single message to a remote mediator endpoint
    async fn deliver_message(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
        use_websocket: bool,
    ) -> Result<(), RelayFailure> {
        // TSP forwards go over REST: they carry raw qb2 binary which the remote
        // mediator's ingress sniffs by its magic byte, whereas the WebSocket relay
        // path is DIDComm-text oriented.
        let use_websocket = use_websocket && decode_tsp_forward(&msg.message).is_none();
        if use_websocket {
            match self.deliver_via_websocket(endpoint_url, msg).await {
                Ok(()) => {
                    self.set_ws_suppression(endpoint_url, None).await;
                    Ok(())
                }
                Err(ws_err) => {
                    // WebSocket failed — fall back to REST for this message,
                    // and stop attempting it for this endpoint for a while
                    // (see `EndpointState::ws_suppressed_until`). A relay-ack
                    // refusal carries a mediator error code, not an HTTP
                    // status, so the REST answer is what classifies it as
                    // final or retryable.
                    let until = Instant::now() + WS_SUPPRESSION_WINDOW;
                    let first = self.set_ws_suppression(endpoint_url, Some(until)).await;
                    if first {
                        warn!(
                            "WebSocket delivery to {} failed ({}). Falling back to REST and \
                             suppressing WebSocket for {}s.",
                            endpoint_url,
                            ws_err,
                            WS_SUPPRESSION_WINDOW.as_secs()
                        );
                    } else {
                        debug!(
                            "WebSocket delivery failed for {}, falling back to REST: {}",
                            endpoint_url, ws_err
                        );
                    }
                    self.deliver_via_rest(endpoint_url, msg).await
                }
            }
        } else {
            self.deliver_via_rest(endpoint_url, msg).await
        }
    }

    /// Set (or clear) the WebSocket suppression window for an endpoint.
    ///
    /// Returns true when this call started a new suppression window, so the
    /// caller can log the transition once rather than per message.
    async fn set_ws_suppression(&self, endpoint_url: &str, until: Option<Instant>) -> bool {
        let mut endpoints = self.endpoints.write().await;
        let Some(state) = endpoints.get_mut(endpoint_url) else {
            // Reaped between the transport decision and here; the next batch
            // re-creates it unsuppressed, which is the safe direction.
            return false;
        };
        let was_suppressed = state.ws_suppressed(Instant::now());
        state.ws_suppressed_until = until;
        until.is_some() && !was_suppressed
    }

    /// Deliver a message via REST POST to the remote mediator's inbound endpoint
    async fn deliver_via_rest(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), RelayFailure> {
        let inbound_url = if endpoint_url.ends_with('/') {
            format!("{endpoint_url}inbound")
        } else {
            format!("{endpoint_url}/inbound")
        };

        // Egress guard (literal + scheme half): refuse a next-hop endpoint that
        // is not a public, globally-routable https target before issuing the
        // request. This is the check that sees IP literals (metadata/RFC1918/
        // loopback/link-local), which the client's DNS resolver never sees.
        //
        // Every vet error is final: a refusal by address class or scheme, or a
        // URL that does not parse. Retrying would only spend the retry budget
        // and the backoff on an answer that cannot change.
        self.http_pool.policy.vet(&inbound_url).map_err(|e| {
            RelayFailure::NotPermitted(format!(
                "Refusing to forward to {inbound_url}: blocked by egress policy: {e}"
            ))
        })?;

        // A TSP forward is queued as base64url(qb2) text; send the decoded raw qb2
        // so the remote mediator's ingress recognises the TSP magic byte. A DIDComm
        // message is sent as-is. (DIDComm forwarding is unchanged.)
        let (content_type, body): (&str, Vec<u8>) = match decode_tsp_forward(&msg.message) {
            Some(qb2) => ("application/tsp", qb2),
            None => (
                "application/didcomm-encrypted+json",
                msg.message.clone().into_bytes(),
            ),
        };

        let response = self
            .http_pool
            .client
            .post(&inbound_url)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                RelayFailure::Retryable(format!("Connection error to {inbound_url}: {e}"))
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(RelayFailure::from_status(
                status.as_u16(),
                format!("Remote mediator {inbound_url} returned HTTP {status}: {body}"),
            ))
        }
    }

    /// How long to wait for a peer's [`RelayAck`] before giving up on the frame.
    ///
    /// Matches the REST client's request timeout, so a stalled peer costs the
    /// same on either transport.
    const RELAY_ACK_TIMEOUT: Duration = Duration::from_secs(30);

    /// Deliver a message via WebSocket to the remote mediator, and wait for the
    /// peer's acknowledgement.
    ///
    /// Connections are pooled per endpoint URL and kept alive for the configured
    /// idle timeout. When the rate drops below the threshold, the idle cleanup
    /// task closes the connection.
    ///
    /// **Delivery semantics are the REST path's.** A frame is only reported
    /// delivered once the peer answers with a positive [`RelayAck`]; a negative
    /// ack, a missing one, or a socket error is an `Err`, which the caller
    /// retries and eventually abandons with a problem report to the sender —
    /// exactly what a non-2xx does on `deliver_via_rest`. Without this a
    /// WebSocket write would report success for a message the peer refused.
    ///
    /// A peer that does not negotiate the `relay-ack` subprotocol gets no
    /// frames over the socket at all: the connection is closed and the error
    /// sends this endpoint back to REST (and, via the suppression window, keeps
    /// it there for a while).
    async fn deliver_via_websocket(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), String> {
        let ws_url = Self::http_to_ws_url(endpoint_url);

        // Egress guard (literal + scheme half): refuse a next-hop that is not a
        // public, globally-routable wss target before dialing — same guarantee
        // the REST path gets, so the WebSocket transport cannot be used to reach
        // a metadata/RFC1918/loopback/link-local literal or a plaintext ws host.
        let vetted = self.http_pool.policy.vet(&ws_url).map_err(|e| {
            format!("Refusing to relay via WebSocket to {ws_url}: blocked by egress policy: {e}")
        })?;

        let frame = msg.message.clone();
        let id = frame_id(frame.as_bytes());

        // Take the pooled connection out for the duration of the exchange, so
        // the pool lock is never held across network I/O: deliveries to other
        // endpoints run concurrently and need the pool too. Only one delivery
        // task runs per endpoint, so nothing else wants this connection.
        let pooled = self.ws_pool.lock().await.remove(endpoint_url);

        // Try the pooled connection first.
        if let Some(mut ws) = pooled {
            match Self::send_and_await_ack(&mut ws.stream, &frame, &id).await {
                Ok(()) => {
                    ws.last_used = Instant::now();
                    self.ws_pool
                        .lock()
                        .await
                        .insert(endpoint_url.to_string(), ws);
                    debug!("Relayed via pooled WebSocket to {} (acked)", endpoint_url);
                    return Ok(());
                }
                Err(AckFailure::Rejected(reason)) => {
                    // The peer answered, and refused. The connection is fine;
                    // the message is not. Keep the socket, fail the message —
                    // retry/abandonment is the caller's job, as on REST.
                    ws.last_used = Instant::now();
                    self.ws_pool
                        .lock()
                        .await
                        .insert(endpoint_url.to_string(), ws);
                    return Err(reason);
                }
                Err(AckFailure::Transport(e)) => {
                    warn!(
                        "Pooled WebSocket relay to {} failed: {}. Reconnecting...",
                        endpoint_url, e
                    );
                }
            }
        }

        // No usable connection — establish one, negotiating `relay-ack`.

        // DNS-rebinding guard for the WS path: the URL vet above blocks
        // IP-literal internal targets, but `tokio_tungstenite` resolves the
        // *name* itself at connect, so a name pointing at an internal address
        // would still be dialed. Resolve it here first and refuse if it maps to
        // a non-routable address. (A narrow resolve-then-connect TOCTOU race
        // remains — far harder to win than a static internal-resolving name —
        // and the REST path closes it fully via the guarded resolver.)
        Self::refuse_ws_if_resolves_nonpublic(&vetted).await?;

        let mut request = ws_url
            .as_str()
            .into_client_request()
            .map_err(|e| format!("WebSocket request for {ws_url} is not valid: {e}"))?;
        request.headers_mut().insert(
            tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
            tungstenite::http::HeaderValue::from_static(RELAY_ACK_SUBPROTOCOL),
        );

        let (mut stream, response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| format!("WebSocket connect to {ws_url} failed: {e}"))?;

        // The subprotocol IS the negotiation: a peer that doesn't echo it
        // cannot acknowledge frames, so it must not be relayed to over this
        // socket. (An anonymous relay upgrade is also only admitted by a peer
        // that offers it, so in practice a non-echoing peer has refused the
        // upgrade outright and we never reach here.)
        let negotiated = response
            .headers()
            .get(tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if negotiated != RELAY_ACK_SUBPROTOCOL {
            let _ = stream.close(None).await;
            return Err(format!(
                "peer at {ws_url} did not negotiate the `{RELAY_ACK_SUBPROTOCOL}` subprotocol \
                 (got {negotiated:?}); relaying over REST instead"
            ));
        }

        info!("WebSocket connected to {} (relay-ack, pool)", endpoint_url);

        let outcome = Self::send_and_await_ack(&mut stream, &frame, &id).await;

        // A transport failure means the socket is not worth keeping; a
        // rejection is about the message and leaves the connection usable.
        match outcome {
            Ok(()) | Err(AckFailure::Rejected(_)) => {
                let mut pool = self.ws_pool.lock().await;
                pool.insert(
                    endpoint_url.to_string(),
                    PooledWebSocket {
                        stream,
                        last_used: Instant::now(),
                    },
                );
            }
            Err(AckFailure::Transport(_)) => {
                let _ = stream.close(None).await;
            }
        }

        match outcome {
            Ok(()) => Ok(()),
            Err(AckFailure::Rejected(reason)) => Err(reason),
            Err(AckFailure::Transport(e)) => Err(e),
        }
    }

    /// Write one relayed frame and wait for the peer's [`RelayAck`] for it.
    ///
    /// Frames that are not this frame's ack — a ping, a stray text frame, an
    /// ack for something else — are skipped rather than mistaken for the
    /// answer, until the ack arrives or [`RELAY_ACK_TIMEOUT`] elapses.
    async fn send_and_await_ack(
        stream: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        frame: &str,
        id: &str,
    ) -> Result<(), AckFailure> {
        stream
            .send(tungstenite::Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| AckFailure::Transport(format!("WebSocket send failed: {e}")))?;

        let deadline = tokio::time::sleep(Self::RELAY_ACK_TIMEOUT);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    return Err(AckFailure::Transport(format!(
                        "no relay-ack within {}s",
                        Self::RELAY_ACK_TIMEOUT.as_secs()
                    )));
                }
                incoming = stream.next() => {
                    match incoming {
                        Some(Ok(tungstenite::Message::Text(text))) => {
                            let Ok(ack) = serde_json::from_str::<RelayAck>(&text) else {
                                debug!("Ignoring a non-ack text frame on the relay socket");
                                continue;
                            };
                            if !ack.answers(id) {
                                debug!("Ignoring a relay-ack for another frame ({})", ack.id);
                                continue;
                            }
                            return if ack.ok {
                                Ok(())
                            } else {
                                Err(AckFailure::Rejected(format!(
                                    "peer refused the relayed message: {} (code {})",
                                    ack.reason.as_deref().unwrap_or("no reason given"),
                                    ack.code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                                )))
                            };
                        }
                        Some(Ok(tungstenite::Message::Close(frame))) => {
                            return Err(AckFailure::Transport(format!(
                                "peer closed the relay socket before acknowledging ({frame:?})"
                            )));
                        }
                        // Ping/Pong/Binary on a relay socket are not ours to
                        // interpret; tungstenite answers pings itself.
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => {
                            return Err(AckFailure::Transport(format!(
                                "WebSocket error awaiting relay-ack: {e}"
                            )));
                        }
                        None => {
                            return Err(AckFailure::Transport(
                                "relay socket ended before acknowledging".to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Refuse a WebSocket dial whose host is a DNS name that resolves to a
    /// non-globally-routable address — the DNS-rebinding guard for the WS path.
    /// IP-literal hosts are already address-class-checked by `policy.vet()`, so
    /// only names are resolved here.
    async fn refuse_ws_if_resolves_nonpublic(
        vetted: &affinidi_net_guard::VettedUrl,
    ) -> Result<(), String> {
        let url = vetted.as_url();
        let name = match url.host() {
            Some(url::Host::Domain(name)) => name.to_string(),
            // An IP-literal host already passed the address-class vet.
            _ => return Ok(()),
        };
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((name.as_str(), port))
            .await
            .map_err(|e| format!("WebSocket host {name} did not resolve: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("WebSocket host {name} resolved to no addresses"));
        }
        for addr in &addrs {
            if !affinidi_net_guard::is_globally_routable(addr.ip()) {
                return Err(format!(
                    "Refusing WebSocket relay to {name}: it resolves to a non-routable address ({})",
                    addr.ip()
                ));
            }
        }
        Ok(())
    }

    /// Convert an HTTP(S) endpoint URL to a WebSocket URL
    fn http_to_ws_url(endpoint_url: &str) -> String {
        let ws_base = endpoint_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        if ws_base.ends_with('/') {
            format!("{ws_base}ws")
        } else {
            format!("{ws_base}/ws")
        }
    }

    /// Calculate exponential backoff duration
    fn calculate_backoff(&self, consecutive_failures: u32) -> Duration {
        let base = self.config.initial_backoff_ms;
        let max = self.config.max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_problem_report tests ---

    /// Rev 3 §5.3.3: an entry whose destination was withheld still produces a
    /// usable report, and does not invent a destination it was not given.
    ///
    /// The withholding happens where the queue entry is built — the mediator
    /// leaves `to_did` empty when relaying an endpoint-to-endpoint message —
    /// so what is checked here is the other half: that the reporting path
    /// degrades to the hash rather than emitting an empty string into a message
    /// sent to the sender, and that nothing reintroduces the VID.
    #[test]
    fn a_withheld_destination_reports_as_its_hash() {
        let mut entry = abandoned_entry();
        entry.to_did = String::new();

        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://example/inbound",
            "did:med",
            0,
        );
        let body = &report["body"];

        let comment = body["comment"].as_str().expect("a comment");
        assert!(
            comment.contains("to-hash"),
            "the hash stands in for the VID: {comment}"
        );
        assert!(
            !comment.contains("forwarding to  failed"),
            "and does not leave a hole where the destination should be: {comment}"
        );
        assert_eq!(body["args"][0], "to-hash");
    }

    /// An ordinary forward is unaffected: a routing-layer VID is the
    /// intermediary's own business and is still named in full.
    #[test]
    fn an_ordinary_destination_is_still_named() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://example/inbound",
            "did:med",
            0,
        );
        assert_eq!(report["body"]["args"][0], "did:example:recipient");
        assert!(
            report["body"]["comment"]
                .as_str()
                .expect("a comment")
                .contains("did:example:recipient")
        );
    }

    fn abandoned_entry() -> ForwardQueueEntry {
        ForwardQueueEntry {
            stream_id: "1-0".into(),
            message: "encrypted-forward".into(),
            to_did_hash: "to-hash".into(),
            from_did_hash: "from-hash".into(),
            from_did: "did:example:sender".into(),
            to_did: "did:example:recipient".into(),
            endpoint_url: "https://remote.example.com".into(),
            received_at_ms: 0,
            delay_milli: 0,
            expires_at: 0,
            retry_count: 5,
            hop_count: 1,
            not_before_ms: 0,
        }
    }

    /// The report is addressed *from* the mediator. This is the field the
    /// recipient's addressing-consistency check binds the authcrypt sender to;
    /// without it the report decrypts and is then thrown away, which is the
    /// same silent outcome as never sending one.
    #[test]
    fn problem_report_names_the_mediator_as_sender() {
        let report = ForwardingProcessor::build_problem_report(
            &abandoned_entry(),
            "https://remote.example.com",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    /// The wire contract clients match on: the report-problem 2.0 type, the
    /// `e.p.me.res.forwarding.abandoned` code, and the `[to_did, retries,
    /// endpoint]` args a client needs to identify which forward was dropped.
    #[test]
    fn problem_report_carries_the_abandonment_code_and_args() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_problem_report(
            &entry,
            "https://remote.example.com",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(
            report["type"],
            "https://didcomm.org/report-problem/2.0/problem-report"
        );
        assert_eq!(report["body"]["code"], "e.p.me.res.forwarding.abandoned");
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "5", "https://remote.example.com"])
        );
        assert_eq!(report["created_time"], 1_000);
        assert_eq!(
            report["expires_time"],
            1_000 + ForwardingProcessor::PROBLEM_REPORT_TTL_SECS
        );
        assert!(
            report["id"].as_str().is_some_and(|id| !id.is_empty()),
            "every report needs its own message id"
        );
    }

    /// A peer's refusal is final; a timeout, rate limit or server error is not.
    #[test]
    fn a_client_error_is_a_refusal_and_the_rest_are_retried() {
        for status in [400, 401, 403, 404, 413, 422] {
            assert!(
                matches!(
                    RelayFailure::from_status(status, String::new()),
                    RelayFailure::Refused { status: s, .. } if s == status
                ),
                "{status} is final"
            );
        }
        for status in [408, 425, 429, 500, 502, 503, 504, 302] {
            assert!(
                matches!(
                    RelayFailure::from_status(status, String::new()),
                    RelayFailure::Retryable(_)
                ),
                "{status} is retried"
            );
        }
    }

    /// The refusal report has its own code, and carries the peer's HTTP
    /// status rather than a retry count it never accumulated.
    #[test]
    fn refusal_report_carries_the_refused_code_and_status() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_refusal_report(
            &entry,
            "https://remote.example.com",
            403,
            "did:example:mediator",
            1_000,
        );

        assert_eq!(report["body"]["code"], "e.p.me.res.forwarding.refused");
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "403", "https://remote.example.com"])
        );
        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    /// The report for an endpoint this mediator will not send to has its own
    /// code, distinct from a peer's refusal and from running out of retries.
    #[test]
    fn not_permitted_report_carries_its_own_code() {
        let entry = abandoned_entry();
        let report = ForwardingProcessor::build_not_permitted_report(
            &entry,
            "https://169.254.169.254",
            "did:example:mediator",
            1_000,
        );

        assert_eq!(
            report["body"]["code"],
            "e.p.me.res.forwarding.endpoint-not-permitted"
        );
        assert_eq!(
            report["body"]["args"],
            serde_json::json!(["did:example:recipient", "https://169.254.169.254"])
        );
        assert_eq!(report["from"], "did:example:mediator");
        assert_eq!(report["to"], serde_json::json!(["did:example:sender"]));
    }

    // --- Scheduler tests ---

    fn scheduler(batch_size: usize, max_concurrent_endpoints: usize) -> Scheduler {
        Scheduler::new(&ForwardingConfig {
            batch_size,
            max_concurrent_endpoints,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            ..Default::default()
        })
    }

    fn queued(id: &str, endpoint_url: &str) -> ForwardQueueEntry {
        ForwardQueueEntry {
            stream_id: id.into(),
            endpoint_url: endpoint_url.into(),
            received_at_ms: 1_000,
            retry_count: 0,
            ..abandoned_entry()
        }
    }

    /// While one endpoint's delivery is still running, another endpoint's
    /// entries are handed out regardless.
    #[test]
    fn a_busy_endpoint_does_not_hold_up_another() {
        let mut s = scheduler(10, 4);
        s.accept(
            vec![queued("1-0", "https://slow"), queued("2-0", "https://fast")],
            5_000,
        );

        let (first, _) = s.next_batch().expect("a batch for the first endpoint");
        assert_eq!(first, "https://slow");
        // More for the busy endpoint arrives; it waits for that task to end.
        s.accept(vec![queued("3-0", "https://slow")], 5_000);

        let (second, batch) = s.next_batch().expect("a batch for the other endpoint");
        assert_eq!(second, "https://fast");
        assert_eq!(batch.len(), 1);
        assert!(
            s.next_batch().is_none(),
            "the busy endpoint gets no second task"
        );

        s.finished("https://slow", &["1-0".to_string()]);
        let (again, batch) = s.next_batch().expect("its queued entry, once it is free");
        assert_eq!(again, "https://slow");
        assert_eq!(batch[0].stream_id, "3-0");
    }

    /// A retry is held back until its not-before, then released.
    #[test]
    fn a_retry_waits_for_its_not_before() {
        let mut s = scheduler(10, 4);
        let mut retry = queued("1-0", "https://peer");
        retry.not_before_ms = 9_000;
        s.accept(vec![retry], 5_000);

        assert!(s.next_batch().is_none(), "not due yet");
        assert_eq!(s.next_due_ms(), Some(9_000));

        s.release_due(8_999);
        assert!(s.next_batch().is_none(), "still not due");

        s.release_due(9_000);
        let (_, batch) = s.next_batch().expect("due now");
        assert_eq!(batch[0].stream_id, "1-0");
    }

    /// An entry read twice is held once, so it cannot be delivered (or
    /// deleted) twice by this processor.
    #[test]
    fn a_repeated_read_is_held_once() {
        let mut s = scheduler(10, 4);
        s.accept(vec![queued("1-0", "https://peer")], 5_000);
        s.accept(vec![queued("1-0", "https://peer")], 5_000);

        let (_, batch) = s.next_batch().expect("a batch");
        assert_eq!(batch.len(), 1);
        assert!(s.next_batch().is_none());
    }

    /// Reading stops once the held entries reach the limit, and resumes as
    /// deliveries finish.
    #[test]
    fn reading_pauses_while_the_hold_is_full() {
        let mut s = scheduler(1, 2);
        s.accept(
            vec![queued("1-0", "https://a"), queued("2-0", "https://b")],
            5_000,
        );
        assert!(!s.has_room());

        let (endpoint, batch) = s.next_batch().expect("a batch");
        let ids: Vec<String> = batch.iter().map(|m| m.stream_id.clone()).collect();
        s.finished(&endpoint, &ids);
        assert!(s.has_room());
    }

    /// A delay the sender asked for that is beyond what the processor parks
    /// is left claimed in the store, as before; it is not held in memory.
    #[test]
    fn a_long_requested_delay_is_not_parked() {
        let mut s = scheduler(10, 4);
        let mut delayed = queued("1-0", "https://peer");
        delayed.delay_milli = 3_600_000;
        s.accept(vec![delayed], 5_000);

        assert!(s.next_due_ms().is_none());
        assert!(s.next_batch().is_none());
        assert!(s.held.is_empty());
    }

    #[test]
    fn due_time_honours_both_requested_delay_and_retry_not_before() {
        let mut entry = queued("1-0", "https://peer");
        assert_eq!(due_at_ms(&entry), 0);
        entry.delay_milli = 500;
        assert_eq!(due_at_ms(&entry), 1_500);
        entry.not_before_ms = 2_000;
        assert_eq!(due_at_ms(&entry), 2_000);
    }

    // --- decode_tsp_forward tests ---

    #[test]
    fn decode_tsp_forward_recovers_qb2_and_passes_didcomm_through() {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

        // A TSP message (leads with the 0xF8 -E count-code magic byte) queued as base64url(qb2).
        let qb2 = [0xF8u8, 0x40, 0x13, 1, 2, 3, 4];
        let queued = BASE64_URL_SAFE_NO_PAD.encode(qb2);
        assert!(queued.starts_with("-E"), "qb64 envelope-code prefix");
        assert_eq!(
            decode_tsp_forward(&queued).as_deref(),
            Some(&qb2[..]),
            "a TSP forward decodes back to the exact qb2 bytes"
        );

        // DIDComm messages (JSON or compact) are not TSP — sent verbatim.
        assert!(decode_tsp_forward("{\"protected\":\"...\"}").is_none());
        assert!(decode_tsp_forward("eyJhbGciOiJ...").is_none());
        assert!(decode_tsp_forward("").is_none());
    }

    // --- http_to_ws_url tests ---

    #[test]
    fn test_http_to_ws_url_https() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/path"),
            "wss://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_http() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://example.com/path"),
            "ws://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_trailing_slash() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/"),
            "wss://example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_plain_domain() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://mediator.example.com"),
            "wss://mediator.example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_port() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://localhost:8080/didcomm"),
            "ws://localhost:8080/didcomm/ws"
        );
    }

    // --- EndpointRateTracker tests ---

    #[test]
    fn test_rate_tracker_new_has_zero_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        assert_eq!(tracker.current_rate(), 0.0);
    }

    #[test]
    fn test_rate_tracker_record_increases_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        let rate = tracker.record_and_rate(1);
        // 1 message in 60 seconds = 1/60 * 10 = 0.1667 msgs/10s
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_batch_record() {
        let mut tracker = EndpointRateTracker::new(60);
        let rate = tracker.record_and_rate(10);
        // 10 messages in 60 second window = 10/60 * 10 = ~1.667 msgs/10s
        assert!(rate > 1.0, "rate should be > 1.0, got {rate}");
        assert!(rate < 2.0, "rate should be < 2.0, got {rate}");
    }

    #[test]
    fn test_rate_tracker_multiple_records() {
        let mut tracker = EndpointRateTracker::new(60);
        tracker.record_and_rate(5);
        tracker.record_and_rate(5);
        let rate = tracker.current_rate();
        // 10 messages in 60 second window
        assert!(rate > 1.0, "rate should be > 1.0, got {rate}");
        assert!(rate < 2.0, "rate should be < 2.0, got {rate}");
    }

    #[test]
    fn test_rate_tracker_zero_window_returns_zero() {
        let mut tracker = EndpointRateTracker::new(0);
        let rate = tracker.record_and_rate(1);
        assert_eq!(rate, 0.0);
    }

    // --- calculate_backoff tests ---

    /// Helper to test calculate_backoff without needing a full ForwardingProcessor.
    /// Replicates the same formula: base * 2^min(failures, 10), capped at max.
    fn compute_backoff(
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        consecutive_failures: u32,
    ) -> Duration {
        let base = initial_backoff_ms;
        let max = max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }

    #[test]
    fn test_backoff_zero_failures() {
        // 2^0 = 1, so backoff = initial_backoff_ms * 1 = 1000ms
        let backoff = compute_backoff(1000, 60000, 0);
        assert_eq!(backoff, Duration::from_millis(1000));
    }

    #[test]
    fn test_backoff_one_failure() {
        // 2^1 = 2, so backoff = 1000 * 2 = 2000ms
        let backoff = compute_backoff(1000, 60000, 1);
        assert_eq!(backoff, Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_three_failures() {
        // 2^3 = 8, so backoff = 1000 * 8 = 8000ms
        let backoff = compute_backoff(1000, 60000, 3);
        assert_eq!(backoff, Duration::from_millis(8000));
    }

    #[test]
    fn test_backoff_capped_at_max() {
        // 2^6 = 64, so 1000 * 64 = 64000ms, but max is 60000ms
        let backoff = compute_backoff(1000, 60000, 6);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_high_failures_capped_exponent_at_10() {
        // Failures > 10 should be clamped to 10: 2^10 = 1024
        // 1000 * 1024 = 1024000, but max is 60000
        let backoff = compute_backoff(1000, 60000, 20);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_custom_initial_and_max() {
        // initial=500, max=5000, failures=2 => 500 * 4 = 2000
        let backoff = compute_backoff(500, 5000, 2);
        assert_eq!(backoff, Duration::from_millis(2000));

        // failures=4 => 500 * 16 = 8000, capped at 5000
        let backoff = compute_backoff(500, 5000, 4);
        assert_eq!(backoff, Duration::from_millis(5000));
    }

    #[test]
    fn test_backoff_saturating_prevents_overflow() {
        // Very large initial_backoff_ms should not panic
        let backoff = compute_backoff(u64::MAX / 2, 60000, 5);
        // Should be capped at max_backoff_ms
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    // --- WebSocket suppression tests ---

    fn endpoint_state(ws_suppressed_until: Option<Instant>) -> EndpointState {
        EndpointState {
            rate_tracker: EndpointRateTracker::new(300),
            last_activity: Instant::now(),
            consecutive_failures: 0,
            retry_after_ms: 0,
            ws_suppressed_until,
        }
    }

    #[test]
    fn ws_is_not_suppressed_by_default() {
        assert!(!endpoint_state(None).ws_suppressed(Instant::now()));
    }

    #[test]
    fn ws_is_suppressed_inside_the_window_and_free_after_it() {
        let now = Instant::now();
        let state = endpoint_state(Some(now + WS_SUPPRESSION_WINDOW));

        assert!(state.ws_suppressed(now));
        assert!(state.ws_suppressed(now + WS_SUPPRESSION_WINDOW - Duration::from_secs(1)));
        // The window is half-open: at the deadline the endpoint is re-probed.
        assert!(!state.ws_suppressed(now + WS_SUPPRESSION_WINDOW));
        assert!(!state.ws_suppressed(now + WS_SUPPRESSION_WINDOW + Duration::from_secs(1)));
    }

    /// The suppression window must outlast the rate tracker's 10s window,
    /// which is what put the endpoint on WebSocket in the first place —
    /// otherwise a busy peer is re-probed on every batch and the suppression
    /// buys nothing. (An endpoint quiet for `ENDPOINT_IDLE_TTL` is reaped
    /// along with its suppression, which is the intended reset: the next
    /// forward to a long-silent peer probes afresh.)
    #[test]
    fn ws_suppression_window_outlasts_the_rate_window() {
        assert!(WS_SUPPRESSION_WINDOW > Duration::from_secs(10));
    }
}
