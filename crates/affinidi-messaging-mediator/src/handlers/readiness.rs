//! `/readyz`: deep readiness, with the backend checks cached.
//!
//! The probe is unauthenticated and unthrottled (an orchestrator must never be
//! refused), and its backend checks are not free: two storage calls, a
//! secret-backend read — a billed API call on the cloud stores — and the VTA
//! cache read. So those checks run at most once per [`REFRESH_INTERVAL`],
//! whatever the request rate, and every request in between is answered from
//! the last result. Cheap in-process state (shutdown, the circuit breaker,
//! supervised-task health) is still read on every request, so a drain or a
//! failed component shows at once.

use crate::{SharedData, common::storage_timeout::with_storage_timeout};
use axum::{Json, extract::State, response::IntoResponse};
use http::StatusCode;
use std::{
    future::Future,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tracing::warn;

use crate::tasks::supervisor::ComponentState;

/// How long a backend readiness result is reused. Orchestrators probe every
/// few seconds, so this costs at most one interval of staleness.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// How long a request with no usable result waits for a running refresh
/// before answering `not_ready`.
const RESULT_WAIT: Duration = Duration::from_secs(2);

/// Bound on each secret-backend read made for readiness, so a slow provider
/// fails the check promptly instead of holding the refresh open.
const SECRETS_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// A value recomputed at most once per interval, however many callers ask.
///
/// A caller that finds the value expired starts one refresh (if none is
/// running) in its own task, so the refresh finishes and is stored even when
/// that caller gives up — a probe with a short timeout must not leave the
/// value unrefreshed. Meanwhile callers are answered from the previous value
/// while it is younger than `max_age`; past that, or before any value exists,
/// they wait a bounded time for the refresh and otherwise get `None`, so a
/// refresh that never completes cannot keep an old answer alive. No lock is
/// held while refreshing.
pub struct RefreshCache<T> {
    inner: Arc<Inner<T>>,
}

struct Inner<T> {
    interval: Duration,
    latest: Mutex<Option<(Instant, Arc<T>)>>,
    refreshing: AtomicBool,
    refreshed: Notify,
}

impl<T: Send + Sync + 'static> RefreshCache<T> {
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                interval,
                latest: Mutex::new(None),
                refreshing: AtomicBool::new(false),
                refreshed: Notify::new(),
            }),
        }
    }

    /// The current value: fresh (younger than the interval) or, while a
    /// refresh runs, one younger than `max_age`. Waits up to `wait` for a
    /// refresh when there is nothing usable, then gives `None`.
    pub async fn get<F, Fut>(&self, max_age: Duration, wait: Duration, refresh: F) -> Option<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + wait;
        let mut refresh = Some(refresh);
        loop {
            // Registered before the value is read, so a refresh that
            // finishes in between still wakes this caller.
            let notified = self.inner.refreshed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let current = self
                .inner
                .latest
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some((at, value)) = &current
                && at.elapsed() < self.inner.interval
            {
                return Some(value.clone());
            }
            if let Some(refresh) = refresh.take()
                && self
                    .inner
                    .refreshing
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let inner = self.inner.clone();
                let work = refresh();
                tokio::spawn(async move {
                    let done = RefreshDone(&inner);
                    let value = Arc::new(work.await);
                    *inner.latest.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some((Instant::now(), value));
                    drop(done);
                });
            }
            if let Some((at, value)) = current
                && at.elapsed() < max_age
            {
                return Some(value);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }
}

/// Ends a refresh, completed or not (a panic in the refresh drops this too):
/// frees the refresher slot and wakes the callers waiting for a value.
struct RefreshDone<'a, T>(&'a Inner<T>);

impl<T> Drop for RefreshDone<'_, T> {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Ordering::Release);
        self.0.refreshed.notify_waiters();
    }
}

/// The cached part of `/readyz`: storage, forwarding queue, secret backend and
/// VTA cache.
#[derive(Debug)]
pub struct BackendReadiness {
    checks: Vec<serde_json::Value>,
    ok: bool,
    secrets_backend_reachable: bool,
    /// When the VTA bundle in the cache was fetched (unix seconds), so its age
    /// is computed per response rather than frozen at refresh time.
    vta_cache_fetched_at: Option<u64>,
}

pub type ReadinessCache = RefreshCache<BackendReadiness>;

/// Run the backend checks once. Detail goes to the operator log only — the
/// probe is unauthenticated, so the body carries static messages.
async fn check_backends(state: SharedData) -> BackendReadiness {
    let mut checks = Vec::new();
    let mut ok = true;

    // Bounded so a wedged backend fails the probe promptly.
    match with_storage_timeout(
        state.storage_timeout(),
        "get_global_stats",
        "NA",
        state.database.get_global_stats(),
    )
    .await
    {
        Ok(_) => checks.push(serde_json::json!({ "name": "redis", "status": "pass" })),
        Err(e) => {
            ok = false;
            warn!(error = %e, "Redis readiness check failed");
            checks.push(serde_json::json!({
                "name": "redis",
                "status": "fail",
                "message": "Redis check failed"
            }));
        }
    }

    match with_storage_timeout(
        state.storage_timeout(),
        "forward_queue_len",
        "NA",
        state.database.forward_queue_len(),
    )
    .await
    {
        Ok(len) => {
            let limit = state.limits().forward_task_queue;
            let queue_status = if len >= limit {
                ok = false;
                "warn"
            } else {
                "pass"
            };
            checks.push(serde_json::json!({
                "name": "forward_queue",
                "status": queue_status,
                "length": len,
                "limit": limit
            }));
        }
        Err(e) => {
            ok = false;
            warn!(error = %e, "Forward-queue readiness check failed");
            checks.push(serde_json::json!({
                "name": "forward_queue",
                "status": "fail",
                "message": "Queue check failed"
            }));
        }
    }

    // Read-only probe, so polling never writes a sentinel. The backend URL and
    // the error stay out of the body (they can name hosts, ARNs or paths).
    let probe = tokio::time::timeout(
        SECRETS_CHECK_TIMEOUT,
        state.config.secrets_backend.probe_readonly(),
    )
    .await;
    let secrets_backend_reachable = match probe {
        Ok(Ok(())) => {
            checks.push(serde_json::json!({ "name": "secrets_backend", "status": "pass" }));
            true
        }
        failed => {
            ok = false;
            match failed {
                Ok(Err(e)) => warn!(error = %e, "Secret backend probe failed"),
                _ => warn!(
                    timeout_secs = SECRETS_CHECK_TIMEOUT.as_secs(),
                    "Secret backend probe timed out"
                ),
            }
            checks.push(serde_json::json!({
                "name": "secrets_backend",
                "status": "fail",
                "message": "Secret backend probe failed",
            }));
            false
        }
    };

    // VTA cache: `None` means no cache, which is normal when self-hosting; a
    // present one is within its TTL (`load_vta_cached_bundle` enforces it).
    let vta = tokio::time::timeout(
        SECRETS_CHECK_TIMEOUT,
        state.config.secrets_backend.load_vta_cached_bundle(),
    )
    .await;
    let vta_cache_fetched_at = match vta {
        Ok(Ok(cached)) => cached.map(|c| c.fetched_at),
        failed => {
            // Not fatal: the mediator serves from in-memory keys. Usually an
            // HMAC mismatch (admin key rotated externally) or a corrupt entry.
            match failed {
                Ok(Err(e)) => {
                    warn!(error = %e, "Could not read VTA cache during readiness probe")
                }
                _ => warn!(
                    timeout_secs = SECRETS_CHECK_TIMEOUT.as_secs(),
                    "VTA cache read timed out during readiness probe"
                ),
            }
            checks.push(serde_json::json!({
                "name": "vta_cache",
                "status": "warn",
                "message": "Could not read VTA cache",
            }));
            None
        }
    };

    // Component errors are logged here, once per refresh, rather than on
    // every probe.
    for entry in state.component_health.iter() {
        let h = entry.value();
        if let Some(err) = h.last_error.as_deref() {
            warn!(component = %h.name, error = %err, "Supervised component reported an error");
        }
    }

    BackendReadiness {
        checks,
        ok,
        secrets_backend_reachable,
        vta_cache_fetched_at,
    }
}

/// Deep readiness check that verifies the mediator can serve traffic.
/// Checks shutdown state, the storage circuit breaker and supervised
/// background tasks on every request, and storage, queue, secret backend and
/// VTA cache at most once per [`REFRESH_INTERVAL`].
///
/// Returns 503 `not_ready` when a hard dependency or a **load-bearing**
/// background task is down; 200 `degraded` when only non-load-bearing
/// components are unhealthy; 200 `ready` otherwise.
pub async fn readiness_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;
    // Non-fatal degradation (non-load-bearing components down). Keeps the
    // instance in rotation (200) but flags the condition for dashboards.
    let mut degraded = false;

    if state.shutdown_token.is_cancelled() {
        all_ok = false;
        checks.push(serde_json::json!({
            "name": "shutdown",
            "status": "fail",
            "message": "Shutdown in progress"
        }));
    } else {
        checks.push(serde_json::json!({ "name": "shutdown", "status": "pass" }));
    }

    let cb_state = state.database.circuit_breaker_state();
    if cb_state != "closed" {
        all_ok = false;
        checks.push(serde_json::json!({
            "name": "redis_circuit_breaker",
            "status": "fail",
            "state": cb_state,
            "message": "Redis circuit breaker is not closed"
        }));
    } else {
        checks.push(serde_json::json!({
            "name": "redis_circuit_breaker",
            "status": "pass",
            "state": cb_state
        }));
    }

    // The oldest result still worth serving: two intervals plus the longest a
    // refresh can take. Older means the refresh is not completing, and the
    // probe fails rather than repeat an answer nobody has checked.
    let max_age = 2 * REFRESH_INTERVAL + 2 * state.storage_timeout() + 2 * SECRETS_CHECK_TIMEOUT;
    let backends = state
        .readiness
        .get(max_age, RESULT_WAIT, {
            let state = state.clone();
            move || check_backends(state)
        })
        .await;
    let (secrets_backend_reachable, vta_cache_age_secs) = match &backends {
        Some(backends) => {
            all_ok &= backends.ok;
            checks.extend(backends.checks.iter().cloned());
            let age = backends.vta_cache_fetched_at.map(|fetched_at| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(fetched_at);
                now.saturating_sub(fetched_at)
            });
            (backends.secrets_backend_reachable, age)
        }
        None => {
            all_ok = false;
            warn!("Readiness backend checks have not completed recently; reporting not ready");
            checks.push(serde_json::json!({
                "name": "backend_checks",
                "status": "fail",
                "message": "Backend checks have not completed recently",
            }));
            (false, None)
        }
    };

    // A load-bearing component that isn't `Running` fails readiness (503); a
    // non-load-bearing one only marks the instance `degraded`. Only a boolean
    // for an error goes in the body; the detail is logged by the refresh.
    let mut components: Vec<serde_json::Value> = Vec::new();
    for entry in state.component_health.iter() {
        let h = entry.value();
        if h.state != ComponentState::Running {
            if h.load_bearing {
                all_ok = false;
            } else {
                degraded = true;
            }
        }
        components.push(serde_json::json!({
            "name": h.name,
            "state": h.state,
            "load_bearing": h.load_bearing,
            "restarts": h.restarts,
            "has_error": h.last_error.is_some(),
        }));
    }
    // Stable order so dashboards diffing the payload don't see churn.
    components.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let status_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status = if !all_ok {
        "not_ready"
    } else if degraded {
        "degraded"
    } else {
        "ready"
    };

    let response = serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": (chrono::Utc::now() - state.service_start_timestamp).num_seconds(),
        "checks": checks,
        "components": components,
        // Top-level fields so dashboards need not parse `checks`. The secret
        // backend's URL is deliberately absent: the probe is unauthenticated.
        "secrets_backend_reachable": secrets_backend_reachable,
        "vta_cache_age_secs": vta_cache_age_secs,
        "operating_keys_loaded": state.config.operating_keys_loaded,
    });

    (status_code, Json(response))
}

#[cfg(test)]
mod tests {
    use super::RefreshCache;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    const LONG: Duration = Duration::from_secs(60);
    const WAIT: Duration = Duration::from_secs(2);

    fn counting(
        runs: &Arc<AtomicUsize>,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send>> {
        let runs = runs.clone();
        move || Box::pin(async move { runs.fetch_add(1, Ordering::SeqCst) + 1 })
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_refresh() {
        let cache = Arc::new(RefreshCache::<usize>::new(LONG));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let cache = cache.clone();
            let runs = runs.clone();
            tasks.push(tokio::spawn(async move {
                *cache
                    .get(LONG, WAIT, move || async move {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        runs.fetch_add(1, Ordering::SeqCst) + 1
                    })
                    .await
                    .expect("a value")
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), 1, "every caller sees the one result");
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // Within the interval, nothing is recomputed.
        for _ in 0..100 {
            cache.get(LONG, WAIT, counting(&runs)).await;
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_value_is_refreshed_once() {
        let cache = RefreshCache::<usize>::new(Duration::from_millis(30));
        let runs = Arc::new(AtomicUsize::new(0));
        assert_eq!(*cache.get(LONG, WAIT, counting(&runs)).await.unwrap(), 1);
        assert_eq!(*cache.get(LONG, WAIT, counting(&runs)).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
        // The expired value starts a refresh; the caller may see the old
        // value while it runs, and the new one after.
        cache.get(LONG, WAIT, counting(&runs)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(*cache.get(LONG, WAIT, counting(&runs)).await.unwrap(), 2);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn callers_are_answered_from_the_old_value_while_one_refreshes() {
        let cache = Arc::new(RefreshCache::<usize>::new(Duration::from_millis(10)));
        assert_eq!(*cache.get(LONG, WAIT, || async { 1 }).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(20)).await;

        let release = Arc::new(tokio::sync::Notify::new());
        let gate = release.clone();
        // Starts the refresh, which parks; this caller is answered at once.
        let first = cache
            .get(LONG, WAIT, move || async move {
                gate.notified().await;
                2
            })
            .await
            .unwrap();
        assert_eq!(*first, 1);
        let quick = tokio::time::timeout(
            Duration::from_millis(100),
            cache.get(LONG, WAIT, || async { panic!("only one refresh may run") }),
        )
        .await
        .expect("answered without waiting")
        .unwrap();
        assert_eq!(*quick, 1);
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(*cache.get(LONG, WAIT, || async { 3 }).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_refresh_completes_and_is_stored_after_its_caller_gives_up() {
        let cache = Arc::new(RefreshCache::<usize>::new(LONG));
        let caller = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get(LONG, WAIT, || async {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        7
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        caller.abort();
        let _ = caller.await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let value = cache
            .get(LONG, WAIT, || async {
                panic!("the abandoned refresh was stored")
            })
            .await
            .unwrap();
        assert_eq!(*value, 7);
    }

    #[tokio::test]
    async fn a_value_past_its_max_age_is_not_served_while_a_refresh_hangs() {
        let interval = Duration::from_millis(10);
        let max_age = Duration::from_millis(60);
        let wait = Duration::from_millis(50);
        let cache = Arc::new(RefreshCache::<usize>::new(interval));
        assert_eq!(*cache.get(max_age, wait, || async { 1 }).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(20)).await;

        // A refresher whose backend never answers, and whose caller (a probe
        // with a short timeout) gives up.
        let refresher = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get(max_age, wait, || async {
                        std::future::pending::<()>().await;
                        0
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        refresher.abort();
        let _ = refresher.await;

        // Within max_age, other callers still get the last value.
        let stale = cache
            .get(max_age, wait, || async {
                panic!("refresh already running")
            })
            .await;
        assert_eq!(stale.as_deref(), Some(&1));

        // Past max_age, they get nothing rather than the old answer.
        tokio::time::sleep(max_age).await;
        let overdue = cache
            .get(max_age, wait, || async {
                panic!("refresh already running")
            })
            .await;
        assert!(overdue.is_none(), "an overdue value must not be served");
    }
}
