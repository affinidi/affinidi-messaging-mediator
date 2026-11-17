//! Target: `trust_task_verify.rs`'s freshness/retention date arithmetic —
//! `freshness_for`, `retention_end`, `claim`, and the `trust-tasks-rs` public
//! API they wrap (`FreshnessPolicy::{default,consequential,record_expiry}`,
//! `TrustTask::{validate_freshness,validate_basic}`,
//! `DEFAULT_MAX_AGE`/`DEFAULT_EXPIRY_HORIZON`/`DEFAULT_SKEW`).
//!
//! Recon tag: T9 (P0) — new in this diff (commit `521618c`, "replay record to
//! record_expiry"), on the exact attack-surface shape that produced the
//! predecessor repo's WebSocket session-expiry integer-underflow bug: an
//! inbound document's attacker-controlled `issuedAt`/`expiresAt` timestamps
//! flow into `DateTime<Utc>` arithmetic. Reachable, authenticated-remote, via
//! `crate::messages::protocols::trust_tasks::process` -> `::consume` ->
//! `trust_task_verify::accept` -> `::check` (freshness) -> `::claim`
//! (`retention_end`) for any served task other than `ping`; `validate_basic`
//! (expiresAt-vs-now, pre-existing, unrelated to this diff) runs later, per
//! task, inside each handler after `accept()` has already returned `Ok`.
//!
//! `freshness_for`/`retention_end`/`claim`/`check`/`accept` in the mediator
//! crate are `pub(crate)` or module-private — this engagement's rules forbid
//! a `pub(crate)` reach-around, so they are never called directly. Instead
//! this harness calls the `pub` `trust-tasks-rs` functions they wrap, with
//! the IDENTICAL policy construction `freshness_for` uses (confirmed by
//! reading `trust_task_verify.rs` lines 249-255 and 308-315 at the pinned
//! HEAD, `137e192f789c21789b4a24ae25c64a7ba4722976`):
//!
//! ```ignore
//! fn freshness_for(policy: SpecPolicy) -> FreshnessPolicy {
//!     if is_consequential(policy) { FreshnessPolicy::consequential() }
//!     else { FreshnessPolicy::default() }
//! }
//! fn retention_end(doc, policy, now) -> DateTime<Utc> {
//!     freshness_for(policy).record_expiry(doc, now).unwrap_or_else(|| {
//!         doc.issued_at.unwrap_or(now) + DEFAULT_MAX_AGE + freshness.skew
//!     })
//! }
//! ```
//!
//! Technique: proptest (property-based, boundary-value-injected timestamps)
//! over the real `TrustTask<Value>` document type and the real
//! `FreshnessPolicy`/`validate_freshness`/`record_expiry` API, plus
//! deterministic boundary-matrix and minimal-repro tests. Oracles:
//!   Tier 1 — no panic, on the realistic (guard-first) call order, for any
//!     `issued_at` a real wall clock could ever present as "not future-dated".
//!   Tier 2 — positive invariants on any `Ok` verdict (`expiresAt > issuedAt`,
//!     `issuedAt <= now + skew`).
//!   Tier 5 — differential: `record_expiry`'s three documented branches
//!     (expiry-within-horizon, expiry-clamped-to-horizon,
//!     no-expiry/max-age fallback) reproduced independently with checked
//!     arithmetic and compared against the live call, including where the
//!     live call overflows and the checked reference does not — which is
//!     itself how Finding T9-01 (below) was characterized.
//!
//! A second, clearly-separated family of tests (`shield_probe_*`) calls the
//! same `pub` functions OUTSIDE the realistic guard order on purpose, to
//! characterize what the pinned dependency (`trust-tasks-rs = "=0.37.0"`)
//! does in isolation — this is Step 8's "prove reachability or demote to
//! comment" exercise, not a claim that HEAD is vulnerable end-to-end.

use chrono::{DateTime, TimeDelta, Utc};
use proptest::prelude::*;
use serde_json::json;
use trust_tasks_rs::{
    DEFAULT_EXPIRY_HORIZON, DEFAULT_MAX_AGE, DEFAULT_SKEW, FreshnessPolicy, TrustTask, TypeUri,
};

/// chrono's own representable-range endpoints, as `i64` Unix seconds — used
/// to keep the property-test generators inside constructible territory
/// (constructing a `DateTime<Utc>` outside this range is covered separately,
/// deterministically, by [`boundary_timestamps`]).
const MIN_TS: i64 = -8_334_601_228_800; // DateTime::<Utc>::MIN_UTC
const MAX_TS: i64 = 8_210_266_876_799; // DateTime::<Utc>::MAX_UTC

/// Build a `TrustTask<Value>` the same shape `trust_tasks::consume` hands to
/// `trust_task_verify::accept` after `serde_json::from_value` — same public
/// struct, same pub fields (`document.rs`'s `TrustTask<P>` derives
/// `Deserialize`, and `issued_at`/`expires_at` are plain pub
/// `Option<DateTime<Utc>>`), just constructed directly rather than via a JSON
/// string so the test can reach genuinely extreme `DateTime<Utc>` values that
/// RFC3339 string parsing (4-digit year) could not spell.
fn doc(
    issued_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
) -> TrustTask<serde_json::Value> {
    let mut d = TrustTask::new(
        "urn:uuid:00000000-0000-4000-8000-000000000000",
        TypeUri::canonical("messaging/account/update", 0, 1).expect("canonical type uri"),
        json!({"did": "did:example:abc", "accountType": "standard"}),
    );
    d.issued_at = issued_at;
    d.expires_at = expires_at;
    d
}

/// The two policies `freshness_for` ever produces — verbatim constructors,
/// not reimplementations.
fn consequential() -> FreshnessPolicy {
    FreshnessPolicy::consequential()
}
fn default_policy() -> FreshnessPolicy {
    FreshnessPolicy::default()
}

/// Boundary-value-injected candidate timestamps (skill Step 6, adapted to
/// `DateTime<Utc>`): the representable-range extremes and points near them,
/// the Unix epoch, and points near "now".
fn boundary_timestamps(now: DateTime<Utc>) -> Vec<DateTime<Utc>> {
    let mut v = vec![
        DateTime::<Utc>::MIN_UTC,
        DateTime::<Utc>::MIN_UTC + TimeDelta::seconds(1),
        DateTime::<Utc>::MAX_UTC,
        DateTime::<Utc>::MAX_UTC - TimeDelta::seconds(1),
        DateTime::<Utc>::MAX_UTC - TimeDelta::days(30),
        DateTime::<Utc>::MAX_UTC - TimeDelta::days(30) - TimeDelta::seconds(61),
        DateTime::<Utc>::MAX_UTC - TimeDelta::days(30) - TimeDelta::seconds(59),
        DateTime::<Utc>::UNIX_EPOCH,
        DateTime::<Utc>::UNIX_EPOCH - TimeDelta::seconds(1),
        now,
        now - TimeDelta::seconds(1),
        now + TimeDelta::seconds(1),
        now - DEFAULT_MAX_AGE,
        now - DEFAULT_MAX_AGE - TimeDelta::seconds(1),
        now - DEFAULT_MAX_AGE + TimeDelta::seconds(1),
        now - DEFAULT_EXPIRY_HORIZON,
        now + DEFAULT_EXPIRY_HORIZON,
        now + DEFAULT_SKEW,
        now + DEFAULT_SKEW + TimeDelta::seconds(1),
    ];
    v.dedup();
    v
}

/// `true` for an `issued_at` a real wall clock running at `now` could ever
/// present to `validate_freshness` as "not future-dated" — i.e. the
/// precondition the realistic (HTTP-reachable) call order always guarantees
/// by the time `claim()`/`retention_end()`/`record_expiry()` run, because
/// `check()` calls `validate_freshness` first and `?`-short-circuits on
/// `Err`. Mirrors check (A) in `trust-tasks-rs`'s `validate_freshness`.
fn realistically_reachable(issued_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match issued_at {
        Some(i) => i <= now + DEFAULT_SKEW,
        None => true,
    }
}

// ============================================================================
// Part 1 — realistic (guard-first) call order: this IS the HTTP-reachable
// shape. Oracle: no panic, ever; Tier-2 invariants on `Ok`.
// ============================================================================

#[test]
fn realistic_boundary_matrix_through_the_guarded_order_never_panics() {
    let now = Utc::now();
    let stamps = boundary_timestamps(now);
    let policies = [
        ("default", default_policy()),
        ("consequential", consequential()),
    ];
    let mut ran = 0usize;
    let mut accepted = 0usize;
    let mut panics = Vec::new();
    for (name, policy) in &policies {
        for issued in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
            if !realistically_reachable(issued, now) {
                continue; // validate_freshness would have already refused this upstream of claim().
            }
            for expires in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
                ran += 1;
                let d = doc(issued, expires);
                let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    d.validate_freshness(now, policy)
                }));
                let verdict = match verdict {
                    Ok(v) => v,
                    Err(e) => {
                        panics.push(format!(
                            "validate_freshness panicked (policy={name}, issued_at={issued:?}, expires_at={expires:?}): {e:?}"
                        ));
                        continue;
                    }
                };
                if let Ok(()) = verdict {
                    accepted += 1;
                    if let (Some(i), Some(e)) = (issued, expires) {
                        assert!(e > i, "accepted expiresAt <= issuedAt: issued={i} expires={e}");
                    }
                    if let Some(i) = issued {
                        assert!(
                            i <= now + policy.skew,
                            "accepted a future-dated issuedAt beyond skew: {i} vs now={now}"
                        );
                    }
                    let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        policy.record_expiry(&d, now)
                    }));
                    match end {
                        Ok(_) => {}
                        Err(e) => panics.push(format!(
                            "record_expiry panicked after a successful validate_freshness on the \
                             guard-first order (policy={name}, issued_at={issued:?}, expires_at={expires:?}): {e:?}"
                        )),
                    }
                }
            }
        }
    }
    assert!(
        panics.is_empty(),
        "{} panic(s) on the realistic guard-first call order:\n{}",
        panics.len(),
        panics.join("\n")
    );
    eprintln!(
        "realistic_boundary_matrix: {ran} reachable combinations run, {accepted} accepted, 0 panics"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Property fuzz over randomized (bounded-to-constructible,
    /// boundary-biased) timestamps, both policies, real `now`, restricted to
    /// `issued_at` values `validate_freshness`'s own future-dating guard
    /// would actually let through in production — i.e. the realistic,
    /// HTTP-reachable input space. `expires_at` is NOT restricted: it is
    /// compared, never added to, inside `validate_freshness`, and is the
    /// field the task brief calls out as attacker-controlled with no
    /// upstream bound.
    #[test]
    fn realistic_freshness_and_retention_never_panic(
        issued_present in any::<bool>(),
        issued_offset_secs in prop_oneof![
            1 => Just(-(MAX_TS - MIN_TS)), // effectively "as old as representable" once clamped below
            1 => Just(0i64),
            1 => Just(-1i64),
            1 => Just(-300i64),            // DEFAULT_MAX_AGE
            1 => Just(-301i64),
            1 => Just(-2_592_000i64),      // DEFAULT_EXPIRY_HORIZON (30d)
            10 => -400_000_000_000i64..=60i64, // random past, up to +60s (skew) future
        ],
        expires_present in any::<bool>(),
        expires_secs in prop_oneof![
            1 => Just(MIN_TS),
            1 => Just(MIN_TS + 1),
            1 => Just(MAX_TS),
            1 => Just(MAX_TS - 1),
            1 => Just(0i64),
            10 => MIN_TS..=MAX_TS,
        ],
        use_consequential in any::<bool>(),
    ) {
        let now = Utc::now();
        let policy = if use_consequential { consequential() } else { default_policy() };

        let issued = if issued_present {
            // Clamp into chrono's representable range rather than reject —
            // keeps every generated case usable instead of burning the
            // proptest global-reject budget on out-of-range raw seconds.
            let secs = (now.timestamp() + issued_offset_secs).clamp(MIN_TS, MAX_TS);
            DateTime::<Utc>::from_timestamp(secs, 0)
        } else {
            None
        };
        let expires = if expires_present {
            DateTime::<Utc>::from_timestamp(expires_secs.clamp(MIN_TS, MAX_TS), 0)
        } else {
            None
        };

        prop_assume!(realistically_reachable(issued, now));

        let d = doc(issued, expires);

        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            d.validate_freshness(now, &policy)
        }));
        let verdict = match verdict {
            Ok(v) => v,
            Err(e) => panic!(
                "validate_freshness panicked on the realistic guard-first order: issued={issued:?} expires={expires:?} consequential={use_consequential}: {e:?}"
            ),
        };

        if let Ok(()) = verdict {
            if let (Some(i), Some(e)) = (issued, expires) {
                prop_assert!(e > i, "accepted an expiresAt <= issuedAt");
            }
            if let Some(i) = issued {
                prop_assert!(i <= now + policy.skew, "accepted a too-far-future issuedAt");
            }

            // record_expiry is only ever reached in production once
            // validate_freshness has already said Ok — test it in exactly
            // that position, not before.
            let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                policy.record_expiry(&d, now)
            }));
            match end {
                Ok(_) => {}
                Err(e) => panic!(
                    "record_expiry panicked after a successful validate_freshness: issued={issued:?} expires={expires:?} consequential={use_consequential}: {e:?}"
                ),
            }
        }
    }
}

// ============================================================================
// Part 2 — differential oracle on record_expiry's documented formula.
// ============================================================================

/// Independent reference, using ONLY `checked_*` arithmetic, of
/// `FreshnessPolicy::record_expiry`'s documented three-branch behaviour
/// (trust-tasks-rs `freshness.rs` doc comment on `record_expiry`). This
/// reference can never itself panic or silently wrap, which is what lets it
/// serve as the oracle for whether the live implementation diverges —
/// including by panicking where this does not.
fn reference_record_expiry(
    policy: &FreshnessPolicy,
    issued_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if let Some(expires_at) = expires_at {
        let horizon_end = policy
            .expiry_horizon
            .zip(issued_at)
            .and_then(|(h, i)| i.checked_add_signed(h));
        return Some(match horizon_end {
            Some(he) if expires_at > he => return he.checked_add_signed(policy.skew),
            _ => expires_at,
        });
    }
    let max_age = policy.max_age?;
    issued_at.unwrap_or(now).checked_add_signed(max_age)?.checked_add_signed(policy.skew)
}

#[test]
fn record_expiry_matches_its_documented_formula_or_the_live_call_overflows() {
    let now = Utc::now();
    let stamps = boundary_timestamps(now);
    let mut matched = 0usize;
    let mut unexpected_divergence = Vec::new();
    let mut live_panics = Vec::new();
    for policy in [default_policy(), consequential()] {
        for issued in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
            for expires in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
                if let (Some(i), Some(e)) = (issued, expires) {
                    if e <= i {
                        continue; // not a validly-ordered pair; not what record_expiry documents.
                    }
                }
                let d = doc(issued, expires);
                let expected = reference_record_expiry(&policy, issued, expires, now);
                let actual = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    policy.record_expiry(&d, now)
                }));
                match actual {
                    Ok(actual) => {
                        if actual == expected {
                            matched += 1;
                        } else {
                            unexpected_divergence.push(format!(
                                "issued={issued:?} expires={expires:?} skew={:?} expected={expected:?} actual={actual:?}",
                                policy.skew
                            ));
                        }
                    }
                    Err(_) => {
                        // Finding T9-01: the live, unchecked-arithmetic
                        // implementation panics on genuine `DateTime<Utc>`
                        // overflow instead of returning `None` the way its
                        // `Option<DateTime<Utc>>` signature otherwise uses
                        // `None` for ("no policy bound configured") — here
                        // it means "no representable answer", which the
                        // all-`checked_*` reference confirms by itself
                        // computing `None` for the same input.
                        live_panics.push(format!(
                            "issued={issued:?} expires={expires:?} skew={:?} reference_result={expected:?}",
                            policy.skew
                        ));
                    }
                }
            }
        }
    }
    eprintln!(
        "record_expiry differential: {matched} matched exactly, {} divergent-but-non-panicking, \
         {} live-overflow panics (Finding T9-01)",
        unexpected_divergence.len(),
        live_panics.len()
    );
    assert!(
        unexpected_divergence.is_empty(),
        "record_expiry diverged from its documented formula without panicking:\n{}",
        unexpected_divergence.join("\n")
    );
    assert!(
        !live_panics.is_empty(),
        "expected at least the known near-MAX_UTC overflow case to reproduce \
         (Finding T9-01) — if this now passes empty, the dependency may have \
         fixed it; update the technique report.\nAll live_panics: {live_panics:?}"
    );
    for p in &live_panics {
        eprintln!("  T9-01 overflow case: {p}");
    }
}

// ============================================================================
// Part 3 — shield probes (Step 8): characterize what the pinned dependency
// does OUTSIDE the realistic guard order. Not a claim HEAD is vulnerable.
// ============================================================================

/// The `retention_end` fallback formula in `trust_task_verify.rs` line 313 —
/// `doc.issued_at.unwrap_or(now) + DEFAULT_MAX_AGE + freshness.skew` —
/// reproduced VERBATIM with the same public constants, fed an UNVALIDATED,
/// attacker-shaped `issued_at` (bypassing `validate_freshness` on purpose).
/// In the real pipeline this fallback is additionally dead code for
/// `consequential()` specifically (see
/// `consequential_record_expiry_never_returns_none`, below) — two
/// independent reasons it cannot fire on HEAD today, both pinned here as
/// executable facts.
#[test]
fn shield_probe_retention_end_fallback_overflows_without_the_upfront_guard() {
    let skew = DEFAULT_SKEW; // == FreshnessPolicy::{default,consequential}().skew
    let near_max_but_overflows = DateTime::<Utc>::MAX_UTC - TimeDelta::seconds(30);
    let result = std::panic::catch_unwind(|| near_max_but_overflows + DEFAULT_MAX_AGE + skew);
    assert!(
        result.is_err(),
        "expected the unguarded fallback formula to panic on an issuedAt within \
         {:?} of DateTime::<Utc>::MAX_UTC — got {result:?} instead",
        DEFAULT_MAX_AGE + skew
    );

    // And confirm the guard that actually runs first in production (`now` is
    // the real wall clock, nowhere near MAX_UTC) rejects this same document
    // as future-dated before any retention arithmetic runs — i.e. the shield
    // is a structural fact of the call order, not a timing coincidence.
    let now = Utc::now();
    let d = doc(Some(near_max_but_overflows), None);
    let verdict = d.validate_freshness(now, &consequential());
    assert!(
        verdict.is_err(),
        "a document stamped near DateTime::<Utc>::MAX_UTC must be rejected as \
         future-dated by the real wall clock before any retention arithmetic runs"
    );
}

/// Pins the SECOND, independent reason the fallback formula above is dead
/// code on HEAD: `record_expiry` never returns `None` for `consequential()`,
/// because `consequential()` always sets `max_age`. Exhaustive over the
/// boundary matrix, standing in for the infinite-domain claim ("for every
/// `doc`") the way Wave 2's ACL exhaustiveness argument did.
#[test]
fn consequential_record_expiry_never_returns_none() {
    let now = Utc::now();
    let stamps = boundary_timestamps(now);
    let policy = consequential();
    for issued in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
        for expires in stamps.iter().copied().map(Some).chain(std::iter::once(None)) {
            let d = doc(issued, expires);
            if let Ok(end) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                policy.record_expiry(&d, now)
            })) {
                assert!(
                    end.is_some(),
                    "record_expiry returned None for consequential() — the max_age \
                     invariant that keeps retention_end's fallback formula dead \
                     code just broke (issued={issued:?}, expires={expires:?})"
                );
            }
            // A panic here is the known T9-01 overflow, already characterized
            // above — not re-asserted against in this invariant-only test.
        }
    }
}

/// Minimal, literal reproducer for the behavioural finding T9-02: a document
/// whose own `expiresAt` already lies in the past relative to the real clock
/// is nonetheless accepted as "fresh" by `validate_freshness` under
/// `consequential()` — because the only staleness check run when `expiresAt`
/// is present compares it against the `issuedAt + expiry_horizon` HORIZON,
/// never against `now` — so `trust_task_verify::claim()` burns the
/// duplicate-execution id for a document that `validate_basic` (run later,
/// per-task, after `accept()` has already returned `Ok`) will then refuse as
/// `Expired`. No panic; a behavioural/ordering quirk, not a bypass — see the
/// technique report's Finding T9-02 for full analysis and severity.
#[test]
fn t9_02_minimal_repro_already_expired_document_passes_validate_freshness() {
    let now = Utc::now();
    let issued_at = now - TimeDelta::minutes(20);
    let expires_at = now - TimeDelta::minutes(10); // already expired by 10 minutes
    let d = doc(Some(issued_at), Some(expires_at));

    // 1. accept()'s freshness check (the new diff) says this document is
    //    fine — not stale, not malformed.
    assert!(
        d.validate_freshness(now, &consequential()).is_ok(),
        "expected validate_freshness to accept an issuedAt/expiresAt pair whose \
         expiresAt already passed, as long as it is within the horizon"
    );

    // 2. claim()/record_expiry would bound the replay-guard record to
    //    exactly that already-past expiresAt.
    let retain_until = consequential().record_expiry(&d, now).expect("Some for consequential()");
    assert_eq!(retain_until, expires_at);
    assert!(
        retain_until < now,
        "the duplicate-execution record is bounded to an instant already in \
         the past at the moment it is created: retain_until={retain_until} now={now}"
    );

    // 3. validate_basic (pre-existing, unrelated to this diff; runs LATER,
    //    per-task, in trust_tasks.rs — not reachable from this crate without
    //    a `pub(crate)` reach-around) is what would actually catch this as
    //    Expired. We cannot call it from here, but its documented rule
    //    (`expires_at <= now` => Expired) is exactly `expires_at <= now`,
    //    which this constructed document satisfies by 10 minutes — i.e. the
    //    task WILL be refused, just one step later than the id was burned.
    assert!(expires_at <= now, "document is expired per validate_basic's own rule");
}
