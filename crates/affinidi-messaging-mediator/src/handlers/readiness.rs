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

/// Bound on each secret-backend read made for readiness, so a slow provider
/// fails the check promptly instead of holding the refresh open.
const SECRETS_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// A value recomputed at most once per interval, however many callers ask.
///
/// One caller refreshes an expired value while the others are answered from
/// the previous one; only a caller that arrives before any value exists waits
/// for the first refresh. No lock is held while refreshing: a flag picks the
/// refresher, and a refresher that is cancelled clears it on drop, so the next
/// caller takes over.
pub struct RefreshCache<T> {
    interval: Duration,
    latest: Mutex<Option<(Instant, Arc<T>)>>,
    refreshing: AtomicBool,
    refreshed: Notify,
}

impl<T> RefreshCache<T> {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            latest: Mutex::new(None),
            refreshing: AtomicBool::new(false),
            refreshed: Notify::new(),
        }
    }

    /// The current value, running `refresh` first when it is older than the
    /// interval and no other caller is already refreshing it.
    pub async fn get<F, Fut>(&self, refresh: F) -> Arc<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = T>,
    {
        loop {
            // Registered before the flag is read, so a refresh that finishes
            // in between still wakes this caller.
            let notified = self.refreshed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let current = self
                .latest
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some((at, value)) = &current
                && at.elapsed() < self.interval
            {
                return value.clone();
            }
            if self
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _done = RefreshDone(self);
                let value = Arc::new(refresh().await);
                *self.latest.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some((Instant::now(), value.clone()));
                return value;
            }
            if let Some((_, value)) = current {
                return value;
            }
            notified.await;
        }
    }
}

/// Ends a refresh, completed or cancelled: frees the refresher slot and wakes
/// the callers waiting for a first value.
struct RefreshDone<'a, T>(&'a RefreshCache<T>);

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
async fn check_backends(state: &SharedData) -> BackendReadiness {
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

    let backends = state.readiness.get(|| check_backends(&state)).await;
    all_ok &= backends.ok;
    checks.extend(backends.checks.iter().cloned());
    let vta_cache_age_secs = backends.vta_cache_fetched_at.map(|fetched_at| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(fetched_at);
        now.saturating_sub(fetched_at)
    });

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
        "secrets_backend_reachable": backends.secrets_backend_reachable,
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

    #[tokio::test]
    async fn concurrent_callers_share_one_refresh() {
        let cache = Arc::new(RefreshCache::<usize>::new(Duration::from_secs(60)));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let cache = cache.clone();
            let runs = runs.clone();
            tasks.push(tokio::spawn(async move {
                *cache
                    .get(|| async {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        runs.fetch_add(1, Ordering::SeqCst) + 1
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), 1, "every caller sees the one result");
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // Within the interval, nothing is recomputed.
        for _ in 0..100 {
            cache
                .get(|| async { runs.fetch_add(1, Ordering::SeqCst) + 1 })
                .await;
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_value_is_refreshed_once() {
        let cache = RefreshCache::<usize>::new(Duration::from_millis(30));
        let runs = AtomicUsize::new(0);
        let refresh = || async { runs.fetch_add(1, Ordering::SeqCst) + 1 };
        assert_eq!(*cache.get(refresh).await, 1);
        assert_eq!(*cache.get(refresh).await, 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(*cache.get(refresh).await, 2);
        assert_eq!(*cache.get(refresh).await, 2);
    }

    #[tokio::test]
    async fn callers_are_answered_from_the_old_value_while_one_refreshes() {
        let cache = Arc::new(RefreshCache::<usize>::new(Duration::from_millis(10)));
        assert_eq!(*cache.get(|| async { 1 }).await, 1);
        tokio::time::sleep(Duration::from_millis(20)).await;

        let release = Arc::new(tokio::sync::Notify::new());
        let slow = {
            let cache = cache.clone();
            let release = release.clone();
            tokio::spawn(async move {
                *cache
                    .get(|| {
                        let release = release.clone();
                        async move {
                            release.notified().await;
                            2
                        }
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        // The refresh is parked; another caller does not wait for it.
        let quick = tokio::time::timeout(
            Duration::from_millis(100),
            cache.get(|| async { panic!("only one refresh may run") }),
        )
        .await
        .expect("answered without waiting");
        assert_eq!(*quick, 1);
        release.notify_one();
        assert_eq!(slow.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_cancelled_refresh_lets_the_next_caller_refresh() {
        let cache = Arc::new(RefreshCache::<usize>::new(Duration::from_secs(60)));
        let parked = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get(|| async {
                        std::future::pending::<()>().await;
                        0
                    })
                    .await;
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        parked.abort();
        let _ = parked.await;
        let value = tokio::time::timeout(Duration::from_secs(1), cache.get(|| async { 7 }))
            .await
            .expect("not stuck behind the cancelled refresh");
        assert_eq!(*value, 7);
    }
}
