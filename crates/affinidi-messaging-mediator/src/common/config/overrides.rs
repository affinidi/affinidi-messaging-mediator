//! Runtime configuration overrides — what `config/patch` changes.
//!
//! An override is a `limits.<field>` key and a new value. Overrides are kept in
//! the store ([`MediatorStore::config_overrides_get`]) and layered over the
//! file/env configuration at every start, so a patch survives a restart. A
//! **live** key also takes effect at once: the request path reads it through
//! [`LiveLimits`] rather than the startup [`Config`](super::Config). A
//! **restart** key is read by something built once at startup (a rate
//! limiter, a body-size layer, the streaming task), so its override is stored
//! and applies from the next start — `config/patch` reports it as
//! `pendingRestart`, never as applied.
//!
//! Anything not listed in [`PATCHABLE`] is refused: keys the store itself is
//! sized from before it opens (`message_size`, `pubsub_buffer`), keys whose
//! tightening loses data (`delivered_expiry_seconds`), and anything outside
//! `limits`.
//!
//! # A patch can tighten, never loosen
//!
//! The file/env configuration is the operator's policy, and it bounds what an
//! account can do: `account/update`, for one, clamps a per-account queue limit
//! to the hard limit. A runtime patch must not be a way round that. So every
//! patched value is held between a floor and a ceiling ([`Patchable`]):
//!
//! - the **floor** keeps a protection on: `0` and `-1`, which mean "unlimited"
//!   or "disabled" for some limits, are below it;
//! - the **ceiling** is the operator's configured value, or an absolute cap
//!   where that value is itself unlimited.
//!
//! Every limit here is stricter the lower it is, so a patch can make the
//! mediator stricter than configured, or restore it, but never looser.
//! Raising a limit is the operator's call: change the configuration and
//! restart. The same bounds apply to stored overrides at startup, so if the
//! operator lowers the configured value, it wins.
//!
//! [`MediatorStore::config_overrides_get`]: affinidi_messaging_mediator_common::store::MediatorStore::config_overrides_get

use std::sync::{Arc, OnceLock, RwLock};

use serde_json::{Map, Value};

use super::limits::LimitsConfig;

/// When a patched key takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// Now: the request path reads it through [`LiveLimits`].
    Live,
    /// At the next start: something built once at startup reads it.
    Restart,
}

/// One key `config/patch` accepts.
#[derive(Clone, Copy, Debug)]
pub struct Patchable {
    /// `limits.<field>`.
    pub key: &'static str,
    pub class: KeyClass,
    /// The lowest value accepted: above any "unlimited" or "disabled" value.
    pub floor: i64,
    /// The highest value accepted when the configured value is itself
    /// unlimited. Otherwise the configured value is the ceiling.
    pub cap: i64,
}

const fn key(key: &'static str, class: KeyClass, floor: i64, cap: i64) -> Patchable {
    Patchable {
        key,
        class,
        floor,
        cap,
    }
}

const HOUR: i64 = 3_600;
const YEAR: i64 = 365 * 24 * HOUR;
const MIB: i64 = 1_048_576;

/// The keys `config/patch` accepts, with when each takes effect and its bounds.
pub const PATCHABLE: &[Patchable] = &[
    key(
        "limits.queued_send_messages_soft",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_send_messages_hard",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_send_messages_per_peer",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_receive_messages_soft",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_receive_messages_hard",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    // A shorter expiry discards queued mail sooner; an hour is the least a
    // patch may leave a client to collect it.
    key("limits.message_expiry_seconds", KeyClass::Live, HOUR, YEAR),
    key("limits.listed_messages", KeyClass::Live, 1, 10_000),
    key("limits.deleted_messages", KeyClass::Live, 1, 10_000),
    key("limits.to_recipients", KeyClass::Live, 1, 10_000),
    key("limits.to_keys_per_recipient", KeyClass::Live, 1, 10_000),
    key("limits.attachments_max_count", KeyClass::Live, 1, 1_000),
    key("limits.access_list_limit", KeyClass::Live, 1, 1_000_000),
    key("limits.oob_invite_ttl", KeyClass::Live, 60, YEAR),
    key("limits.forward_task_queue", KeyClass::Live, 1, 10_000_000),
    // The WebSocket message rate is read when a socket opens, so a patch
    // applies to every connection opened after it; an open socket keeps the
    // rate it started with. 0 (unlimited / never close) is below the floor.
    key("limits.ws_messages_per_second", KeyClass::Live, 1, 100_000),
    key("limits.ws_message_burst", KeyClass::Live, 1, 100_000),
    key(
        "limits.ws_message_throttle_close_secs",
        KeyClass::Live,
        1,
        HOUR,
    ),
    // Connection and rate limiting, and the HTTP/WS body-size layers, are
    // built once at startup. For these, 0 means unlimited.
    key(
        "limits.max_websocket_connections",
        KeyClass::Restart,
        1,
        1_000_000,
    ),
    key(
        "limits.max_websocket_connections_per_did",
        KeyClass::Restart,
        1,
        10_000,
    ),
    key("limits.ws_send_buffer", KeyClass::Restart, MIB, 1_024 * MIB),
    key("limits.rate_limit_per_ip", KeyClass::Restart, 1, 100_000),
    key("limits.rate_limit_burst", KeyClass::Restart, 1, 100_000),
    key(
        "limits.did_rate_limit_per_second",
        KeyClass::Restart,
        1,
        100_000,
    ),
    key("limits.did_rate_limit_burst", KeyClass::Restart, 1, 100_000),
    key("limits.http_size", KeyClass::Restart, 64 * 1_024, 256 * MIB),
    key("limits.ws_size", KeyClass::Restart, 64 * 1_024, 256 * MIB),
];

fn patchable(key: &str) -> Option<&'static Patchable> {
    PATCHABLE.iter().find(|p| p.key == key)
}

/// When `key` takes effect, or `None` when it cannot be patched.
pub fn class_of(key: &str) -> Option<KeyClass> {
    patchable(key).map(|p| p.class)
}

/// The value of `key`'s field in `limits`, as a number.
fn field_value(limits: &LimitsConfig, key: &str) -> Option<i64> {
    let field = key.strip_prefix("limits.")?;
    serde_json::to_value(limits).ok()?.get(field)?.as_i64()
}

/// Keys whose configured `0` means "unlimited" or "off" rather than a limit
/// of zero. For these, and for any key configured at `-1`, the ceiling of a
/// patch is the key's absolute cap. Any other configured value is the ceiling
/// as written, even when it is below the key's floor: a patch must never be
/// able to raise a limit the operator set low.
const ZERO_IS_UNLIMITED: &[&str] = &[
    "limits.ws_messages_per_second",
    "limits.ws_message_throttle_close_secs",
    "limits.max_websocket_connections",
    "limits.max_websocket_connections_per_did",
    "limits.rate_limit_per_ip",
    "limits.rate_limit_burst",
    "limits.did_rate_limit_per_second",
    "limits.did_rate_limit_burst",
];

/// Check `value` against `key`'s floor and ceiling, where the ceiling is the
/// operator's configured value in `baseline` unless that is unlimited (see
/// [`ZERO_IS_UNLIMITED`]), when it is the key's absolute cap.
fn check_bounds(p: &Patchable, value: &Value, baseline: &LimitsConfig) -> Result<(), String> {
    let n = value
        .as_i64()
        .ok_or_else(|| "invalid value: expected a whole number".to_string())?;
    let configured = field_value(baseline, p.key).unwrap_or(p.cap);
    let unlimited = configured < 0 || (configured == 0 && ZERO_IS_UNLIMITED.contains(&p.key));
    let ceiling = if unlimited {
        p.cap
    } else {
        configured.min(p.cap)
    };
    if n < p.floor {
        return Err(format!(
            "{n} is below the least allowed ({}): a patch cannot switch this limit off",
            p.floor
        ));
    }
    if n > ceiling {
        return Err(if ceiling == configured {
            format!(
                "{n} is above the configured value ({configured}): a patch can tighten a \
                 limit but not raise it; change the configuration to raise it"
            )
        } else {
            format!("{n} is above the most allowed ({ceiling})")
        });
    }
    Ok(())
}

/// `limits` with `key` set to `value`, checked on its own: a [`PATCHABLE`]
/// key, a whole number within the key's bounds against `baseline`, and of the
/// field's type. Coherence with other keys is not checked here.
fn set_checked(
    limits: &LimitsConfig,
    baseline: &LimitsConfig,
    key: &str,
    value: &Value,
) -> Result<LimitsConfig, String> {
    let Some(p) = patchable(key) else {
        return Err("not a patchable configuration key".into());
    };
    check_bounds(p, value, baseline)?;
    let field = key.strip_prefix("limits.").unwrap_or(key);
    let mut object = serde_json::to_value(limits).map_err(|e| e.to_string())?;
    object[field] = value.clone();
    serde_json::from_value(object).map_err(|e| format!("invalid value: {e}"))
}

/// `limits` with `key` (a [`PATCHABLE`] key) set to `value`, checked: the
/// value must be a whole number within the key's bounds against `baseline` (the
/// operator's configuration, see the module docs), have the field's type, and
/// keep the queue limits coherent (a soft limit no higher than its hard limit).
/// The error is the reason to report.
pub fn with_override(
    limits: &LimitsConfig,
    baseline: &LimitsConfig,
    key: &str,
    value: &Value,
) -> Result<LimitsConfig, String> {
    let candidate = set_checked(limits, baseline, key, value)?;
    check_coherent(&candidate)?;
    Ok(candidate)
}

/// The soft/hard pairs a configuration must keep ordered.
const COHERENT_PAIRS: [(&str, &str); 2] = [
    (
        "limits.queued_send_messages_soft",
        "limits.queued_send_messages_hard",
    ),
    (
        "limits.queued_receive_messages_soft",
        "limits.queued_receive_messages_hard",
    ),
];

/// The first soft/hard pair `limits` has out of order, with the reason.
fn incoherent_pair(limits: &LimitsConfig) -> Option<((&'static str, &'static str), String)> {
    COHERENT_PAIRS.into_iter().find_map(|(soft_key, hard_key)| {
        let soft = field_value(limits, soft_key)?;
        let hard = field_value(limits, hard_key)?;
        (soft >= 0 && hard >= 0 && soft > hard).then(|| {
            (
                (soft_key, hard_key),
                format!(
                    "{} ({soft}) would exceed {} ({hard})",
                    soft_key.trim_start_matches("limits."),
                    hard_key.trim_start_matches("limits."),
                ),
            )
        })
    })
}

/// The cross-field rules a configuration must not break: a soft queue limit no
/// higher than its hard limit. A negative queue limit means "unlimited", so it
/// is exempt. Checked on the file baseline at load
/// ([`LimitsConfig::check_invariants`]), on every patch, and once over the
/// result of laying the stored overrides over the baseline ([`overlay`]).
pub(crate) fn check_coherent(limits: &LimitsConfig) -> Result<(), String> {
    match incoherent_pair(limits) {
        Some((_, reason)) => Err(reason),
        None => Ok(()),
    }
}

/// Apply stored `overrides` onto `limits` (the baseline) at startup or reload.
///
/// Each override is checked on its own against the baseline (a patchable key,
/// within its bounds, of the field's type) and laid onto one candidate; the
/// soft ≤ hard rule is checked **once**, over the result. Checking it after
/// each key instead made the outcome depend on the keys' (alphabetical)
/// order: with both keys of a pair lowered, `…_hard` was laid first against
/// the baseline `…_soft`, failed, and was skipped — silently reverting a
/// tightened hard limit (#107).
///
/// An override that no longer applies (an unknown key, a bad value, or a pair
/// that is out of order once everything is laid) is skipped and returned with
/// its reason so the caller can log it: a stale override must not stop the
/// mediator starting. A pair out of order is returned to its baseline values,
/// which are coherent.
pub fn overlay(limits: &mut LimitsConfig, overrides: &Map<String, Value>) -> Vec<(String, String)> {
    // Bounded by the configuration the overrides are layered over.
    let baseline = limits.clone();
    let mut skipped = Vec::new();
    let mut applied: Vec<String> = Vec::new();
    for (key, value) in overrides {
        match set_checked(limits, &baseline, key, value) {
            Ok(next) => {
                *limits = next;
                applied.push(key.clone());
            }
            Err(reason) => skipped.push((key.clone(), reason)),
        }
    }
    while let Some(((soft_key, hard_key), reason)) = incoherent_pair(limits) {
        let reverted: Vec<String> = applied
            .iter()
            .filter(|key| key.as_str() == soft_key || key.as_str() == hard_key)
            .cloned()
            .collect();
        if reverted.is_empty() {
            // The baseline itself is out of order; it is checked at load, so
            // this is a `LimitsConfig` built in code. Nothing here to undo.
            break;
        }
        *limits = with_fields_from(limits, &baseline, &reverted);
        applied.retain(|key| !reverted.contains(key));
        skipped.extend(reverted.into_iter().map(|key| (key, reason.clone())));
    }
    skipped
}

/// What a `config/patch` does, worked out without side effects.
pub struct PatchPlan {
    /// The limits the baseline and the new stored overrides give.
    pub desired: LimitsConfig,
    /// The stored overrides to write back.
    pub stored: Map<String, Value>,
    /// The patch's keys that were taken, with when each applies and its value
    /// (`null` for a reset).
    pub accepted: Vec<(String, KeyClass, Value)>,
    /// The patch's keys that were refused, with why.
    pub rejected: Vec<(String, String)>,
}

/// Plan a `config/patch` of `patch` over the `stored` overrides and the
/// file/env `baseline`.
///
/// Each key is checked on its own (bounds and type), then the whole patch is
/// laid over the stored overrides and coherence is checked over the result,
/// as at startup ([`overlay`]) — so lowering both keys of a soft/hard pair in
/// one patch works whatever order they come in. A patch key that leaves a pair
/// out of order is refused and its previous stored value kept; so is a reset
/// (`null`) that would leave a stored partner out of order, which would
/// otherwise drop that partner's override and loosen the limit.
pub fn plan_patch<'a>(
    baseline: &LimitsConfig,
    stored: &Map<String, Value>,
    patch: impl IntoIterator<Item = (&'a String, &'a Value)>,
) -> PatchPlan {
    let original = stored.clone();
    let not_applying = |stored: &Map<String, Value>| -> Vec<(String, String)> {
        let mut desired = baseline.clone();
        overlay(&mut desired, stored)
    };
    let skipped_before: Vec<String> = not_applying(&original)
        .into_iter()
        .map(|(key, _)| key)
        .collect();

    let mut stored = original.clone();
    let mut accepted: Vec<(String, KeyClass, Value)> = Vec::new();
    let mut rejected: Vec<(String, String)> = Vec::new();
    for (key, value) in patch {
        let Some(class) = class_of(key) else {
            rejected.push((key.clone(), "not a patchable configuration key".into()));
            continue;
        };
        if value.is_null() {
            stored.remove(key);
            accepted.push((key.clone(), class, Value::Null));
            continue;
        }
        if let Err(reason) = set_checked(baseline, baseline, key, value) {
            rejected.push((key.clone(), reason));
            continue;
        }
        stored.insert(key.clone(), value.clone());
        accepted.push((key.clone(), class, value.clone()));
    }

    loop {
        let newly_skipped: Vec<(String, String)> = not_applying(&stored)
            .into_iter()
            .filter(|(key, _)| !skipped_before.contains(key))
            .collect();
        // The patch keys responsible: a newly skipped key the patch set, or
        // the patch keys in the same pair as a newly skipped stored key.
        let mut refuse: Vec<(String, String)> = Vec::new();
        for (key, reason) in &newly_skipped {
            let pair = COHERENT_PAIRS
                .iter()
                .find(|(soft, hard)| key == soft || key == hard);
            for (patched, ..) in &accepted {
                let same_pair = pair.is_some_and(|(soft, hard)| patched == soft || patched == hard);
                if (patched == key || same_pair) && !refuse.iter().any(|(k, _)| k == patched) {
                    refuse.push((patched.clone(), reason.clone()));
                }
            }
        }
        if refuse.is_empty() {
            break;
        }
        for (key, reason) in refuse {
            match original.get(&key) {
                Some(previous) => stored.insert(key.clone(), previous.clone()),
                None => stored.remove(&key),
            };
            accepted.retain(|(k, ..)| *k != key);
            rejected.push((key, reason));
        }
    }

    let mut desired = baseline.clone();
    overlay(&mut desired, &stored);
    PatchPlan {
        desired,
        stored,
        accepted,
        rejected,
    }
}

/// Parse the stored overrides document; an absent or malformed one is empty.
pub fn parse_stored(stored: Option<&str>) -> Map<String, Value> {
    stored
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// The limits the request path reads, swapped whole by `config/patch`. Cheap
/// to clone; a read is a lock and an `Arc` clone, never a copy of the limits.
///
/// It also keeps the **baseline**: the file/env limits before any override,
/// which is what a key returns to when its override is removed.
#[derive(Clone, Debug)]
pub struct LiveLimits {
    baseline: Arc<RwLock<Arc<LimitsConfig>>>,
    current: Arc<RwLock<Arc<LimitsConfig>>>,
    /// Held across a patch's read-modify-write of the stored overrides.
    patch: Arc<tokio::sync::Mutex<()>>,
}

impl LiveLimits {
    /// `baseline` is the configuration before overrides; `effective` is what
    /// is in force (the baseline with the stored overrides layered over it).
    pub fn new(baseline: LimitsConfig, effective: LimitsConfig) -> Self {
        Self {
            baseline: Arc::new(RwLock::new(Arc::new(baseline))),
            current: Arc::new(RwLock::new(Arc::new(effective))),
            patch: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Exclusive right to change the configuration: hold it across reading
    /// the stored overrides, writing them back and putting the result into
    /// effect. Every writer of the stored overrides takes it, so two changes
    /// can't interleave and lose one another's keys.
    pub async fn lock_for_patch(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.patch.lock().await
    }

    /// The file/env limits, before any override.
    pub fn baseline(&self) -> Arc<LimitsConfig> {
        self.baseline
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Replace the file/env limits (`config/reload`).
    pub fn set_baseline(&self, limits: LimitsConfig) {
        let next = Arc::new(limits);
        match self.baseline.write() {
            Ok(mut g) => *g = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }

    /// The limits now in effect.
    pub fn get(&self) -> Arc<LimitsConfig> {
        self.current
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Put `limits` into effect.
    pub fn set(&self, limits: LimitsConfig) {
        let next = Arc::new(limits);
        match self.current.write() {
            Ok(mut g) => *g = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }
}

/// The configuration file this mediator was started from, recorded by
/// [`server::start`](crate::server::start). An embedded mediator (a test
/// harness, or an application passing its own `Config`) has none, and so has
/// nothing to reload.
static CONFIG_PATH: OnceLock<String> = OnceLock::new();

/// Record the configuration file the mediator was started from.
pub fn record_config_path(path: &str) {
    let _ = CONFIG_PATH.set(path.to_string());
}

/// The configuration file the mediator was started from, if any.
pub fn config_path() -> Option<&'static str> {
    CONFIG_PATH.get().map(String::as_str)
}

/// What a `config/reload` does, worked out without side effects: the new
/// file/env limits `baseline`, with the stored `overrides` laid over them (and
/// held to the same bounds), give the limits the mediator should run with.
/// Only live keys change a running mediator, so the plan applies those to
/// `live` and lists the ones whose value moved; restart-gated keys are left to
/// the next start.
pub struct ReloadPlan {
    /// The limits to put into effect.
    pub live: LimitsConfig,
    /// Live keys whose value changed.
    pub reloaded: Vec<String>,
    /// Restart-gated keys whose value in the file changed; they apply at the
    /// next start.
    pub pending_restart: Vec<String>,
    /// Stored overrides that no longer apply over the new baseline.
    pub skipped: Vec<(String, String)>,
}

pub fn reload_plan(
    live: &LimitsConfig,
    baseline: &LimitsConfig,
    overrides: &Map<String, Value>,
) -> ReloadPlan {
    let mut desired = baseline.clone();
    let skipped = overlay(&mut desired, overrides);
    let mut reloaded = Vec::new();
    let mut pending_restart = Vec::new();
    for p in PATCHABLE {
        if field_value(live, p.key) != field_value(&desired, p.key) {
            match p.class {
                KeyClass::Live => reloaded.push(p.key.to_string()),
                KeyClass::Restart => pending_restart.push(p.key.to_string()),
            }
        }
    }
    ReloadPlan {
        live: with_fields_from(live, &desired, &reloaded),
        reloaded,
        pending_restart,
        skipped,
    }
}

/// `target` with each of `keys` (a `limits.<field>` key) copied from `from`.
pub fn with_fields_from(
    target: &LimitsConfig,
    from: &LimitsConfig,
    keys: &[String],
) -> LimitsConfig {
    let (Ok(mut t), Ok(f)) = (serde_json::to_value(target), serde_json::to_value(from)) else {
        return target.clone();
    };
    for key in keys {
        let field = key.strip_prefix("limits.").unwrap_or(key);
        if let Some(v) = f.get(field) {
            t[field] = v.clone();
        }
    }
    serde_json::from_value(t).unwrap_or_else(|_| target.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_patchable_key_is_applied_with_its_type_and_an_unknown_one_is_not() {
        let base = LimitsConfig::default();
        let next = with_override(
            &base,
            &base,
            "limits.queued_send_messages_hard",
            &json!(5000),
        )
        .unwrap();
        assert_eq!(next.queued_send_messages_hard, 5000);

        assert!(with_override(&base, &base, "limits.message_size", &json!(1)).is_err());
        assert!(with_override(&base, &base, "security.use_ssl", &json!(false)).is_err());
        assert!(
            with_override(&base, &base, "limits.listed_messages", &json!("many"))
                .unwrap_err()
                .starts_with("invalid value")
        );
        assert!(
            with_override(&base, &base, "limits.delivered_expiry_seconds", &json!(10)).is_err(),
            "tightening delivered expiry loses data, so it is not patchable"
        );
    }

    #[test]
    fn a_patch_can_tighten_a_limit_but_not_loosen_it_or_switch_it_off() {
        let base = LimitsConfig::default(); // listed 100, send hard 10000
        assert!(with_override(&base, &base, "limits.listed_messages", &json!(10)).is_ok());
        let err = with_override(&base, &base, "limits.listed_messages", &json!(101)).unwrap_err();
        assert!(err.contains("above the configured value"), "{err}");
        // The disabled / unlimited values are below every floor.
        for (key, off) in [
            ("limits.queued_send_messages_hard", -1),
            ("limits.rate_limit_per_ip", 0),
            ("limits.max_websocket_connections", 0),
        ] {
            let err = with_override(&base, &base, key, &json!(off)).unwrap_err();
            assert!(err.contains("switch this limit off"), "{key}: {err}");
        }
        let err =
            with_override(&base, &base, "limits.message_expiry_seconds", &json!(60)).unwrap_err();
        assert!(err.contains("below the least"), "{err}");
    }

    #[test]
    fn an_unlimited_configured_value_is_bounded_by_the_absolute_cap() {
        // did_rate_limit_per_second defaults to 0: unlimited. Enabling it is
        // tightening, up to the cap.
        let base = LimitsConfig::default();
        assert_eq!(base.did_rate_limit_per_second, 0);
        assert!(
            with_override(&base, &base, "limits.did_rate_limit_per_second", &json!(50)).is_ok()
        );
        let err = with_override(
            &base,
            &base,
            "limits.did_rate_limit_per_second",
            &json!(100_001),
        )
        .unwrap_err();
        assert!(err.contains("above the most allowed"), "{err}");
    }

    #[test]
    fn the_websocket_message_rate_can_be_tightened_but_not_switched_off() {
        let base = LimitsConfig::default(); // 100/s, burst 50, close after 10 s
        for key in [
            "limits.ws_messages_per_second",
            "limits.ws_message_burst",
            "limits.ws_message_throttle_close_secs",
        ] {
            assert_eq!(class_of(key), Some(KeyClass::Live), "{key}");
            let err = with_override(&base, &base, key, &json!(0)).unwrap_err();
            assert!(err.contains("switch this limit off"), "{key}: {err}");
        }
        let next =
            with_override(&base, &base, "limits.ws_messages_per_second", &json!(10)).unwrap();
        assert_eq!(next.ws_messages_per_second, 10);
        let err =
            with_override(&base, &base, "limits.ws_messages_per_second", &json!(101)).unwrap_err();
        assert!(err.contains("above the configured value"), "{err}");
        let next = with_override(
            &base,
            &base,
            "limits.ws_message_throttle_close_secs",
            &json!(3),
        )
        .unwrap();
        assert_eq!(next.ws_message_throttle_close_secs, 3);

        // An operator who configured the rate off can still turn it on by
        // patch, up to the absolute cap.
        let unlimited = LimitsConfig {
            ws_messages_per_second: 0,
            ..LimitsConfig::default()
        };
        assert!(
            with_override(
                &unlimited,
                &unlimited,
                "limits.ws_messages_per_second",
                &json!(200)
            )
            .is_ok()
        );
    }

    #[test]
    fn a_soft_limit_may_not_exceed_its_hard_limit() {
        let base = LimitsConfig::default(); // send soft 2000, hard 10000
        let err = with_override(
            &base,
            &base,
            "limits.queued_send_messages_hard",
            &json!(100),
        )
        .unwrap_err();
        assert!(err.contains("would exceed"), "{err}");
    }

    /// Issue #107: both keys of a pair lowered below the baseline soft. Laid
    /// one at a time in (alphabetical) key order, `…_hard` came first, failed
    /// against the baseline `…_soft`, and was skipped — the tightened hard
    /// limit silently reverted on the next start.
    #[test]
    fn both_keys_of_a_pair_lowered_survive_a_restart() {
        let baseline = LimitsConfig::default(); // send 2000/10000, receive 200/1000
        let stored = parse_stored(Some(
            r#"{"limits.queued_send_messages_soft": 500,
                "limits.queued_send_messages_hard": 1000,
                "limits.queued_receive_messages_soft": 50,
                "limits.queued_receive_messages_hard": 100}"#,
        ));
        let mut limits = baseline.clone();
        let skipped = overlay(&mut limits, &stored);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(limits.queued_send_messages_soft, 500);
        assert_eq!(limits.queued_send_messages_hard, 1000);
        assert_eq!(limits.queued_receive_messages_soft, 50);
        assert_eq!(limits.queued_receive_messages_hard, 100);

        // The same through a reload.
        let plan = reload_plan(&baseline, &baseline, &stored);
        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        assert_eq!(plan.live.queued_send_messages_hard, 1000);
        assert_eq!(plan.live.queued_receive_messages_hard, 100);
    }

    /// A pair that is out of order once every override is laid goes back to
    /// its baseline values (which are coherent), and both keys are reported.
    #[test]
    fn an_incoherent_stored_pair_returns_to_the_baseline() {
        let baseline = LimitsConfig::default();
        // hard 100 is below the baseline soft 2000, and nothing lowers soft.
        let stored = parse_stored(Some(r#"{"limits.queued_send_messages_hard": 100}"#));
        let mut limits = baseline.clone();
        let skipped = overlay(&mut limits, &stored);
        assert_eq!(limits.queued_send_messages_hard, 10_000);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].1.contains("would exceed"), "{skipped:?}");
    }

    /// The same in one `config/patch`: both keys of a pair lowered together are
    /// both taken, whatever order they arrive in.
    #[test]
    fn a_patch_lowering_both_keys_of_a_pair_is_taken() {
        let baseline = LimitsConfig::default();
        let patch = parse_stored(Some(
            r#"{"limits.queued_send_messages_hard": 1000, "limits.queued_send_messages_soft": 500}"#,
        ));
        let plan = plan_patch(&baseline, &Map::new(), &patch);
        assert!(plan.rejected.is_empty(), "{:?}", plan.rejected);
        assert_eq!(plan.accepted.len(), 2);
        assert_eq!(plan.desired.queued_send_messages_soft, 500);
        assert_eq!(plan.desired.queued_send_messages_hard, 1000);
        assert_eq!(plan.stored.len(), 2);
    }

    /// A patch key that leaves its pair out of order is refused and the
    /// previously stored value kept; the rest of the patch still applies.
    #[test]
    fn a_patch_key_that_breaks_its_pair_is_refused_and_the_old_value_kept() {
        let baseline = LimitsConfig::default();
        let stored = parse_stored(Some(r#"{"limits.queued_send_messages_hard": 5000}"#));
        let patch = parse_stored(Some(
            r#"{"limits.queued_send_messages_hard": 100, "limits.listed_messages": 10}"#,
        ));
        let plan = plan_patch(&baseline, &stored, &patch);
        assert_eq!(plan.rejected.len(), 1, "{:?}", plan.rejected);
        assert_eq!(plan.rejected[0].0, "limits.queued_send_messages_hard");
        assert!(plan.rejected[0].1.contains("would exceed"));
        assert_eq!(plan.desired.queued_send_messages_hard, 5000);
        assert_eq!(
            plan.stored.get("limits.queued_send_messages_hard"),
            Some(&serde_json::json!(5000))
        );
        assert_eq!(plan.desired.listed_messages, 10);
        assert_eq!(plan.accepted.len(), 1);
    }

    /// Resetting the soft override of a lowered pair would leave the stored
    /// hard below the baseline soft and drop it — loosening the hard limit. The
    /// reset is refused instead.
    #[test]
    fn a_reset_that_would_drop_a_stored_partner_is_refused() {
        let baseline = LimitsConfig::default();
        let stored = parse_stored(Some(
            r#"{"limits.queued_send_messages_soft": 500, "limits.queued_send_messages_hard": 1000}"#,
        ));
        let patch = parse_stored(Some(r#"{"limits.queued_send_messages_soft": null}"#));
        let plan = plan_patch(&baseline, &stored, &patch);
        assert_eq!(plan.rejected.len(), 1, "{:?}", plan.rejected);
        assert_eq!(plan.desired.queued_send_messages_hard, 1000);
        assert_eq!(plan.desired.queued_send_messages_soft, 500);
        assert_eq!(plan.stored, stored);
    }

    /// A configured value below a key's floor is still its ceiling: a patch
    /// can never raise a limit the operator set low.
    #[test]
    fn a_low_configured_value_is_not_read_as_unlimited() {
        let base = LimitsConfig {
            message_expiry_seconds: 60, // below the one-hour floor
            ..LimitsConfig::default()
        };
        assert!(
            with_override(&base, &base, "limits.message_expiry_seconds", &json!(YEAR)).is_err()
        );
    }

    #[test]
    fn a_stale_stored_override_is_skipped_not_fatal() {
        let mut limits = LimitsConfig::default();
        // An operator who lowers the configured value below a stored override
        // wins: the override is now above the configuration and is skipped.
        let stored = parse_stored(Some(
            r#"{"limits.listed_messages": 7, "limits.gone_away": 1, "limits.to_recipients": "x", "limits.deleted_messages": 500}"#,
        ));
        let skipped = overlay(&mut limits, &stored);
        assert_eq!(limits.listed_messages, 7);
        assert_eq!(limits.deleted_messages, 100, "the configured value stands");
        let keys: Vec<&str> = skipped.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), 3, "{skipped:?}");
        assert!(keys.contains(&"limits.gone_away") && keys.contains(&"limits.to_recipients"));
        assert!(keys.contains(&"limits.deleted_messages"));
        assert!(parse_stored(Some("not json")).is_empty());
        assert!(parse_stored(None).is_empty());
    }

    #[test]
    fn fields_are_copied_by_key_and_others_left_alone() {
        let target = LimitsConfig::default();
        let from = LimitsConfig {
            listed_messages: 9,
            to_recipients: 9,
            ..Default::default()
        };
        let out = with_fields_from(&target, &from, &["limits.listed_messages".into()]);
        assert_eq!(out.listed_messages, 9);
        assert_eq!(out.to_recipients, target.to_recipients);
    }

    #[test]
    fn a_reload_applies_changed_live_keys_and_keeps_overrides_on_top() {
        let running = LimitsConfig::default(); // listed 100, deleted 100
        let file = LimitsConfig {
            listed_messages: 80,   // changed in the file
            deleted_messages: 90,  // changed, but overridden below
            rate_limit_per_ip: 50, // restart-gated
            ..LimitsConfig::default()
        };
        let stored = parse_stored(Some(r#"{"limits.deleted_messages": 60}"#));
        let plan = reload_plan(&running, &file, &stored);

        assert_eq!(plan.live.listed_messages, 80);
        assert_eq!(plan.live.deleted_messages, 60, "the override still wins");
        assert!(
            plan.reloaded
                .contains(&"limits.listed_messages".to_string())
        );
        assert!(
            plan.reloaded
                .contains(&"limits.deleted_messages".to_string())
        );
        assert_eq!(
            plan.pending_restart,
            vec!["limits.rate_limit_per_ip".to_string()]
        );
        assert_eq!(
            plan.live.rate_limit_per_ip, running.rate_limit_per_ip,
            "a restart-gated key is not changed on a running mediator"
        );
        assert!(plan.skipped.is_empty());

        // Nothing changed: an empty reload.
        let plan = reload_plan(&running, &running, &Map::new());
        assert!(plan.reloaded.is_empty() && plan.pending_restart.is_empty());
    }

    #[test]
    fn an_override_looser_than_the_reloaded_file_is_skipped() {
        let running = LimitsConfig::default();
        let file = LimitsConfig {
            listed_messages: 10,
            ..LimitsConfig::default()
        };
        let stored = parse_stored(Some(r#"{"limits.listed_messages": 50}"#));
        let plan = reload_plan(&running, &file, &stored);
        assert_eq!(
            plan.live.listed_messages, 10,
            "the operator's lower value wins"
        );
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn live_limits_swap_whole() {
        let live = LiveLimits::new(LimitsConfig::default(), LimitsConfig::default());
        let before = live.get();
        let mut next = (*before).clone();
        next.listed_messages = 3;
        live.set(next);
        assert_eq!(live.get().listed_messages, 3);
        assert_eq!(before.listed_messages, 100, "a reader's snapshot is stable");
    }

    #[test]
    fn every_patchable_key_names_a_real_field() {
        let fields = serde_json::to_value(LimitsConfig::default()).unwrap();
        for p in PATCHABLE {
            let field = p.key.strip_prefix("limits.").unwrap();
            assert!(
                fields.get(field).is_some(),
                "{} is not a LimitsConfig field",
                p.key
            );
            assert!(p.floor >= 1 && p.floor <= p.cap, "{}", p.key);
        }
    }
}
