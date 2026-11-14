//! `audit/list` and `config/show`: the mediator-wide administration tasks.

#![allow(deprecated)]

use super::*;

/// Handle the generic `audit/list`: admin-only. Pages the mediator's
/// privileged-change log, newest first, as `AuditEnvelope`s — the messaging
/// profile of the generic task that replaces the retired
/// `messaging/admin/audit-log` (request `limit` → `pageSize`; response
/// `nextCursor` → `cursor` + `truncated`).
///
/// Filter support is per page: `action` / `actor` / `from` / `to` are applied to
/// the fetched page (the cursor still advances page-by-page). The mediator's log
/// tracks neither `outcome` nor `contextId`, so a filter on those matches
/// nothing.
pub(super) async fn consume_audit_list(
    typed: TrustTask<audit::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use audit::list::v0_1::Response;
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "audit/list")?;

    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed
        .payload
        .page_size
        .map(|n| n.get() as u32)
        .unwrap_or(100);

    let page = state.database.audit_log_list(cursor, limit).await?;
    let entries = page
        .entries
        .iter()
        .filter(|e| audit_filters_match(&typed.payload, e))
        .map(map_audit_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = page.cursor != 0;

    let response: Response = build(
        Response::builder()
            .cursor(truncated.then(|| page.cursor.to_string()))
            .entries(entries)
            .truncated(truncated),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Apply the generic `audit/list` filters to one internal log entry.
pub(super) fn audit_filters_match(payload: &audit::list::v0_1::Payload, e: &AuditLogEntry) -> bool {
    // The mediator's log tracks neither outcome nor context: a filter on them
    // matches nothing (honest emptiness rather than a silently ignored filter).
    if payload.outcome.is_some() || payload.context_id.is_some() {
        return false;
    }
    if let Some(action) = &payload.action
        && **action != audit_action_name(e.action)
    {
        return false;
    }
    if let Some(actor) = &payload.actor
        && **actor != e.actor_did_hash
    {
        return false;
    }
    let recorded = e.timestamp as i64;
    if let Some(from) = &payload.from
        && recorded < from.timestamp()
    {
        return false;
    }
    if let Some(to) = &payload.to
        && recorded >= to.timestamp()
    {
        return false;
    }
    true
}

/// Map one internal audit record onto the generic `AuditEnvelope` profile:
/// `timestamp` → `recordedAt`, `actor`/`target` hashes → `actor`/`target`,
/// the action's shared-schema name → `action`, and the free-text detail →
/// `detail.detail`. The mediator's log has no native event id, so a stable one
/// is minted as the digest of the entry's content.
pub(super) fn map_audit_envelope(
    e: &AuditLogEntry,
) -> Result<audit::list::v0_1::AuditEnvelope, MediatorError> {
    use audit::list::v0_1::{AuditEnvelope, AuditEnvelopeAction, AuditEnvelopeEventId};

    let action = audit_action_name(e.action);
    let event_id = digest(format!(
        "{}:{}:{}:{}:{}",
        e.timestamp, e.actor_did_hash, e.target_did_hash, action, e.detail
    ));
    let mut detail = serde_json::Map::new();
    detail.insert("detail".to_string(), Value::String(e.detail.clone()));

    // `contextId`, `entryHash`, `outcome`, `prevHash` and `schemaVersion` are
    // left unset: this mediator's audit rows carry no equivalent.
    build(
        AuditEnvelope::builder()
            .action(
                AuditEnvelopeAction::from_str(action)
                    .map_err(|err| serialize_err_msg(format!("audit action: {err}")))?,
            )
            .actor(Some(e.actor_did_hash.clone()))
            .detail(detail)
            .event_id(
                AuditEnvelopeEventId::from_str(&event_id)
                    .map_err(|err| serialize_err_msg(format!("audit event id: {err}")))?,
            )
            .recorded_at(
                chrono::DateTime::from_timestamp(e.timestamp as i64, 0)
                    .unwrap_or_else(chrono::Utc::now),
            )
            .target(Some(e.target_did_hash.clone())),
    )
}

/// The shared-schema (`messaging.schema.json#/$defs/AuditAction`) name of an
/// internal audit action — the maintainer-defined action vocabulary this
/// mediator reports through the generic `audit/list`.
pub(super) fn audit_action_name(a: AuditAction) -> &'static str {
    match a {
        AuditAction::SetAcl => "setAcl",
        AuditAction::AccessListAdd => "accessListAdd",
        AuditAction::AccessListRemove => "accessListRemove",
        AuditAction::AccessListClear => "accessListClear",
        AuditAction::AccountAdd => "accountAdd",
        AuditAction::AccountRemove => "accountRemove",
        AuditAction::AccountChangeType => "accountChangeType",
        AuditAction::AccountChangeQueueLimits => "accountChangeQueueLimits",
        AuditAction::AdminAdd => "adminAdd",
        AuditAction::AdminStrip => "adminStrip",
        AuditAction::MessageRead => "messageRead",
        AuditAction::MessageDelete => "messageDelete",
        AuditAction::QueuePurge => "queuePurge",
        AuditAction::MonitorSubscribe => "monitorSubscribe",
        AuditAction::MonitorUnsubscribe => "monitorUnsubscribe",
        AuditAction::ConfigPatch => "configPatch",
        AuditAction::ConfigReload => "configReload",
        // A kind added to the common crate before this mapping learns it.
        _ => "other",
    }
}

/// Handle the generic `config/show`: admin-only. Returns the mediator's
/// configuration as per-key `ConfigField`s — the messaging profile of the
/// generic task that replaces the retired `messaging/admin/config` (each
/// top-level member of the old opaque `config` blob becomes a field; the old
/// `version` member is the `mediator.version` key). The mediator loads its
/// configuration at startup, so every key reports `requiresRestart: true` with
/// source `mediator`.
pub(super) async fn consume_config_show(
    typed: TrustTask<config::show::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::common::config::overrides::{KeyClass, class_of, parse_stored};
    use config::show::v0_1::{ConfigField, ConfigFieldKey, ConfigFieldSource, Response};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "config/show")?;

    // The configuration as dotted scalar keys (`limits.listed_messages`,
    // `database.database_url`), with the limits as they are in effect now
    // rather than as they were at startup.
    let mut config_object = serde_json::to_value(&state.config).map_err(serialize_err)?;
    config_object["limits"] = serde_json::to_value(&*state.limits()).map_err(serialize_err)?;
    let mut flat = Vec::new();
    flatten_config("", &config_object, &mut flat);

    // Which keys a `config/patch` override supplies.
    let overridden = parse_stored(
        state
            .database
            .config_overrides_get()
            .await
            .ok()
            .flatten()
            .as_deref(),
    );

    // Optional `keys` filter: return only the requested keys.
    let wanted: Option<HashSet<String>> = typed
        .payload
        .keys
        .as_ref()
        .map(|ks| ks.iter().map(|k| (**k).clone()).collect());

    let mut fields = Vec::new();
    let mut push_field = |key: String, value: Value| -> Result<(), MediatorError> {
        if wanted.as_ref().is_some_and(|w| !w.contains(&key)) {
            return Ok(());
        }
        let requires_restart = class_of(&key) != Some(KeyClass::Live);
        let source = if overridden.contains_key(&key) {
            "override"
        } else {
            "mediator"
        };
        fields.push(build(
            ConfigField::builder()
                .key(
                    ConfigFieldKey::from_str(&key)
                        .map_err(|e| serialize_err_msg(format!("config key: {e}")))?,
                )
                .requires_restart(requires_restart)
                .source(
                    ConfigFieldSource::from_str(source)
                        .map_err(|e| serialize_err_msg(format!("config source: {e}")))?,
                )
                .value(value),
        )?);
        Ok(())
    };
    push_field(
        "mediator.version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    )?;
    for (key, value) in flat {
        push_field(key, value)?;
    }

    let response: Response = build(Response::builder().fields(fields))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Flatten `value` into `prefix.key` → scalar pairs. Arrays, which the spec's
/// scalar `value` cannot hold, become their JSON text. Credentials embedded in
/// a URL are redacted: the spec requires it of any secret-bearing value, and a
/// store URL such as `redis://:password@host` is one.
pub(super) fn flatten_config(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_config(&key, v, out);
            }
        }
        Value::Array(_) => out.push((
            prefix.to_string(),
            Value::String(redact_strings(value).to_string()),
        )),
        Value::String(s) => out.push((prefix.to_string(), Value::String(redact_url(s)))),
        scalar => out.push((prefix.to_string(), scalar.clone())),
    }
}

/// `value` with every string in it, at any depth, passed through [`redact_url`].
pub(super) fn redact_strings(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_url(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_strings(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}
