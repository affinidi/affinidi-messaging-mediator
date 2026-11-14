//! `messaging/mux/*` and `messaging/mux/admin-*`: DID multiplexing grants,
//! attachments, acknowledgements and their administration.

#![allow(deprecated)]

use super::*;

/// Reject a non-admin caller of an admin-only task.
/// `messaging/mux/connections`: this instance's live mux connections, for an
/// administrator. See [`crate::mux::admin`].
pub(super) async fn consume_mux_connections(
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::admin;
    use crate::task_specs::messaging::mux::connections::v0_1 as connections;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;
    require_admin(session, "messaging/mux/connections")?;

    let query = admin::Query::from_payload(&doc.payload);
    let mut views = Vec::new();
    for conn in state.mux.all() {
        views.push(admin::view(&conn).await);
    }
    let binding = admin::Binding {
        requester: &session.did_hash,
        instance: &state.config.streaming_uuid,
        now: now.timestamp().max(0) as u64,
    };
    let page = admin::page(views, &query, &binding, !state.database.spans_processes()).map_err(
        |admin::PageError::CursorInvalid| {
            tt_problem(
                session,
                admin::CURSOR_INVALID,
                "the cursor was not issued by this instance for this request, or has expired; \
                 start again without one"
                    .into(),
                StatusCode::BAD_REQUEST,
            )
        },
    )?;
    let response: connections::Response = super::mediator_ops::from_json(page)?;
    let typed: TrustTask<connections::Payload> = downcast(doc, session)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// A mux task's request-level refusal as a problem report. An
/// `epochMismatch` carries the epoch in force as its first argument, which a
/// `trust-task-error` turns into `details.currentEpoch`
/// ([`trust_task_error`](crate::messages::protocols::trust_task_error)); the comment says it too, for older clients.
pub(super) fn task_refusal(session: &Session, e: crate::mux::tasks::TaskError) -> MediatorError {
    let args = e
        .current_epoch
        .map(|c| vec![c.to_string()])
        .unwrap_or_default();
    tt_problem_with_args(
        session,
        &e.code,
        e.message,
        args,
        if e.retryable {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_REQUEST
        },
    )
}

/// Serve a connection-independent `messaging/mux/*` task (design §4).
///
/// Off unless `limits.mux.enabled`, in which case the type is unsupported, as
/// the specs require. The response payload is built as JSON and checked
/// against the generated `Response` type before it is wrapped, so a shape the
/// schema does not allow fails here rather than on the client.
pub(super) async fn consume_mux(
    task: ServedTask,
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    sender_did: &str,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::{grants::Ctx, proof::StatementVerifier, tasks};
    use crate::task_specs::messaging::mux;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;

    let verifier = StatementVerifier::new(state.did_resolver.clone());
    let ctx = Ctx {
        store: &*state.database,
        verifier: &verifier,
        mediator_did,
        limits: state.config.limits.mux.store_limits(),
        default_acl: &state.config.security.global_acl_default,
        now: now.timestamp().max(0) as u64,
    };
    let payload = &doc.payload;
    let refused = |e: tasks::TaskError| task_refusal(session, e);

    // attach / detach act on the connection the request arrived on.
    let conn = || {
        state.mux.get(&session.session_id).ok_or_else(|| {
            tt_problem(
                session,
                "messaging/mux:notMuxConnection",
                "this request must be sent on a mux connection".to_string(),
                StatusCode::BAD_REQUEST,
            )
        })
    };
    let streaming = state.streaming_task.as_ref();

    let (mut response, changed) = match task {
        ServedTask::MuxAttach => {
            tasks::attach(
                &ctx,
                &*conn()?,
                streaming,
                state.config.limits.mux.max_attach_lifetime_secs,
                payload,
            )
            .await
        }
        ServedTask::MuxDetach => (
            tasks::detach(&*conn()?, streaming, payload).await,
            tasks::Changed::default(),
        ),
        ServedTask::MuxAck => {
            conn()?;
            (
                tasks::ack(state, session, payload).await.map_err(refused)?,
                tasks::Changed::default(),
            )
        }
        ServedTask::MuxGrant => tasks::grant(&ctx, sender_did, payload).await,
        ServedTask::MuxList => (
            tasks::list(&ctx, sender_did, payload)
                .await
                .map_err(refused)?,
            tasks::Changed::default(),
        ),
        ServedTask::MuxUpdate => tasks::update(&ctx, sender_did, payload)
            .await
            .map_err(refused)?,
        ServedTask::MuxRevoke => tasks::revoke(&ctx, sender_did, payload)
            .await
            .map_err(refused)?,
        ServedTask::MuxRevokeAll => tasks::revoke_all(&ctx, payload).await.map_err(refused)?,
        _ => unreachable!("consume_mux is only called for mux tasks"),
    };

    let carried = apply_mux_change(state, &ctx, &changed).await;
    // `attachedNow` on each stored grant: whether a connection on this
    // instance took the member. Another instance's connection takes it
    // moments later and is not counted.
    if !changed.stored.is_empty()
        && let Some(results) = response.get_mut("results").and_then(Value::as_array_mut)
    {
        for r in results {
            if r.get("status").and_then(Value::as_str) == Some("stored") {
                let id = r.get("grantId").and_then(Value::as_str).unwrap_or_default();
                r["attachedNow"] = Value::Bool(carried.contains(id));
            }
        }
    }
    // Audit records the specs require: revocations, an advanced epoch, and
    // grants the unknown-key rule suspended.
    match task {
        ServedTask::MuxRevoke => {
            crate::mux::audit::revoked(state, &session.did_hash, &changed).await
        }
        ServedTask::MuxRevokeAll => {
            crate::mux::audit::revoked_all(state, &session.did_hash, &response).await
        }
        _ => {}
    }
    crate::mux::audit::suspended(
        state,
        &changed.suspended,
        crate::mux::audit::SuspendedBy::Statement,
    )
    .await;

    fn respond<P, R>(
        doc: &TrustTask<Value>,
        session: &Session,
        response: Value,
    ) -> Result<Value, MediatorError>
    where
        P: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned + serde::Serialize,
    {
        let typed: TrustTask<P> = downcast(doc, session)?;
        let response: R = serde_json::from_value(response).map_err(|e| {
            serialize_err_msg(format!("mux response does not match its schema: {e}"))
        })?;
        serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err)
    }
    match task {
        ServedTask::MuxAttach => {
            respond::<mux::attach::v0_1::Payload, mux::attach::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxDetach => {
            respond::<mux::detach::v0_1::Payload, mux::detach::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxAck => {
            respond::<mux::ack::v0_1::Payload, mux::ack::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxGrant => {
            respond::<mux::grant::v0_1::Payload, mux::grant::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxList => {
            respond::<mux::list::v0_1::Payload, mux::list::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxUpdate => {
            respond::<mux::update::v0_1::Payload, mux::update::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxRevoke => {
            respond::<mux::revoke::v0_1::Payload, mux::revoke::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxRevokeAll => respond::<
            mux::revoke_all::v0_1::Payload,
            mux::revoke_all::v0_1::Response,
        >(doc, session, response),
        _ => unreachable!("consume_mux is only called for mux tasks"),
    }
}

/// Carry a committed mux change to every live connection, then tell the
/// other instances and the affected principals. Every `messaging/mux/*` task
/// that changes grants comes through here — a party's own `revoke` or
/// `revoke-all`, and an administrator's `admin-revoke` or `admin-revoke-all`
/// — so they detach, publish and notify identically; only the reason in
/// `changed` differs. Returns the ids of stored grants a connection on this
/// instance took.
pub(super) async fn apply_mux_change(
    state: &SharedData,
    ctx: &crate::mux::grants::Ctx<'_>,
    changed: &crate::mux::tasks::Changed,
) -> std::collections::HashSet<String> {
    use crate::mux::session::LeaveReason;
    let streaming = state.streaming_task.as_ref();
    // Drop the members whose grants this task removed, voided or suspended,
    // and re-scope narrowed ones, on every live connection that carries them
    // — *before* answering, so no frame for them leaves after the response
    // says they are gone (§7.3, R1.1/R7.2).
    if !changed.removed.is_empty() {
        state
            .mux
            .detach_grants(
                streaming,
                &changed.removed,
                changed.reason.unwrap_or(LeaveReason::RevokedByMember),
            )
            .await;
    }
    if !changed.suspended.is_empty() {
        state
            .mux
            .detach_grants(
                streaming,
                &changed.suspended,
                LeaveReason::SuspendedUnknownKey,
            )
            .await;
    }
    if !changed.narrowed.is_empty() {
        state
            .mux
            .narrow(state.streaming_task.as_ref(), &changed.narrowed)
            .await;
    }
    // An epoch advance ends the member's session attaches as well as its
    // grants, on every connection here, before answering (design §5.2).
    let attaches_reason = changed.reason.unwrap_or(LeaveReason::EpochBumped);
    if let Some(member) = &changed.attaches_ended {
        state
            .mux
            .detach_attaches(streaming, member, ctx.now, attaches_reason)
            .await;
    }
    let carried = if changed.stored.is_empty() {
        Default::default()
    } else {
        state
            .mux
            .admit_grants(streaming, ctx.store, &ctx.limits, ctx.now, &changed.stored)
            .await
    };
    // The same principals' connections on other instances sharing the store
    // follow within one pub/sub hop (§7.4); this answer does not wait for them.
    crate::mux::sync::publish(state, &crate::mux::sync::changes_of(changed)).await;
    if let Some(member) = &changed.attaches_ended {
        crate::mux::sync::publish_members(
            state,
            &[
                affinidi_messaging_mediator_common::store::mux::MemberHint::AttachesEnded {
                    did_hash: member.clone(),
                    at: ctx.now,
                    // Only a reason other than the member's own is sent, so
                    // an instance that predates the field reads the same.
                    reason: (attaches_reason != LeaveReason::EpochBumped)
                        .then(|| attaches_reason.wire().to_string()),
                },
            ],
        )
        .await;
    }
    // Durable notices for what this task suspended or revoked: only now,
    // once the change is committed and its members detached (spec rule 2).
    crate::mux::notice::after_change(state, changed).await;
    carried
}

/// Serve an administrator's stored-grant task: `messaging/mux/admin-list`,
/// `admin-revoke` or `admin-revoke-all` (see [`crate::mux::admin_grants`]).
///
/// Authorised as `messaging/mux/connections` is — the §7.2 checks have run
/// (proof, `issuedAt`, freshness) and the requester's stored role decides —
/// with the read open to the mediator's own account and the two destructive
/// tasks to `admin` and `rootAdmin` only. A revocation is applied through
/// [`apply_mux_change`], as a party's own `revoke` is, before the answer.
pub(super) async fn consume_mux_admin(
    task: ServedTask,
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::{admin_grants, grants::Ctx, proof::StatementVerifier, tasks};
    use crate::task_specs::messaging::mux;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;
    match task {
        // The read: administrators and the mediator's own account.
        ServedTask::MuxAdminList => {
            if !roles::is_privileged(session.account_type) {
                return Err(tt_problem(
                    session,
                    "permissionDenied",
                    "messaging/mux/admin-list requires an administrator account".into(),
                    StatusCode::FORBIDDEN,
                ));
            }
        }
        // Destructive: an operator decides, never the service.
        ServedTask::MuxAdminRevoke => require_admin(session, "messaging/mux/admin-revoke")?,
        ServedTask::MuxAdminRevokeAll => require_admin(session, "messaging/mux/admin-revoke-all")?,
        _ => unreachable!("consume_mux_admin is only called for mux admin tasks"),
    }

    let verifier = StatementVerifier::new(state.did_resolver.clone());
    let ctx = Ctx {
        store: &*state.database,
        verifier: &verifier,
        mediator_did,
        limits: state.config.limits.mux.store_limits(),
        default_acl: &state.config.security.global_acl_default,
        now: now.timestamp().max(0) as u64,
    };
    let root_admin_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(&state.config.admin_did);
    let requester = admin_grants::Requester {
        root: roles::is_root(session.account_type),
        root_admin_hash: &root_admin_hash,
    };
    let refused = |e: tasks::TaskError| task_refusal(session, e);

    fn respond<P, R>(
        doc: &TrustTask<Value>,
        session: &Session,
        response: Value,
    ) -> Result<Value, MediatorError>
    where
        P: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned + serde::Serialize,
    {
        let typed: TrustTask<P> = downcast(doc, session)?;
        let response: R = serde_json::from_value(response).map_err(|e| {
            serialize_err_msg(format!("mux response does not match its schema: {e}"))
        })?;
        serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err)
    }

    match task {
        ServedTask::MuxAdminList => {
            let key = admin_list_cursor_key(state).await;
            let binding = admin_grants::CursorBinding {
                requester: &session.did_hash,
                now: ctx.now,
                key: &key,
            };
            let page = admin_grants::admin_list(&ctx, &doc.payload, &binding)
                .await
                .map_err(refused)?;
            respond::<mux::admin_list::v0_1::Payload, mux::admin_list::v0_1::Response>(
                doc, session, page,
            )
        }
        ServedTask::MuxAdminRevoke => {
            let (result, changed) =
                admin_grants::admin_revoke(&ctx, &requester, &doc.payload).await;
            // Whatever was revoked is detached, published and notified, even
            // when a later member's record refused the write (spec rule 10).
            if !changed.removed.is_empty() {
                apply_mux_change(state, &ctx, &changed).await;
                let selection = admin_selection(&doc.payload);
                crate::mux::audit::admin_revoked(
                    state,
                    &session.did_hash,
                    &selection,
                    &changed.removed,
                )
                .await;
            }
            respond::<mux::admin_revoke::v0_1::Payload, mux::admin_revoke::v0_1::Response>(
                doc,
                session,
                result.map_err(refused)?,
            )
        }
        ServedTask::MuxAdminRevokeAll => {
            let (response, changed, voided_epoch) =
                admin_grants::admin_revoke_all(&ctx, &requester, &doc.payload)
                    .await
                    .map_err(refused)?;
            apply_mux_change(state, &ctx, &changed).await;
            if let (Some(before), Some(member)) = (voided_epoch, &changed.attaches_ended) {
                crate::mux::audit::admin_revoked_all(
                    state,
                    &session.did_hash,
                    member,
                    before,
                    before + 1,
                    changed.removed.len(),
                )
                .await;
            }
            respond::<mux::admin_revoke_all::v0_1::Payload, mux::admin_revoke_all::v0_1::Response>(
                doc, session, response,
            )
        }
        _ => unreachable!("consume_mux_admin is only called for mux admin tasks"),
    }
}

/// An `admin-revoke` selection for the audit record, as DID hashes.
pub(super) fn admin_selection(payload: &Value) -> String {
    use affinidi_messaging_mediator_common::did_identity::did_hash;
    let mut parts = Vec::new();
    if let Some(p) = payload.get("principal").and_then(Value::as_str) {
        parts.push(format!("principal {}", did_hash(p)));
    }
    if let Some(m) = payload.get("member").and_then(Value::as_str) {
        parts.push(format!("member {}", did_hash(m)));
    }
    if let Some(ids) = payload.get("grantIds").and_then(Value::as_array) {
        parts.push(format!("{} named grant ids", ids.len()));
    }
    parts.join(", ")
}

/// The key `messaging/mux/admin-list` cursors are tagged with. Derived from
/// the mediator's own signing key, so every instance of one mediator holds
/// the same key and a listing paged on one continues on another; a mediator
/// without a signing key falls back to a key that lives only in this
/// process, and its cursors then continue only here.
pub(super) async fn admin_list_cursor_key(state: &SharedData) -> Vec<u8> {
    static PROCESS_KEY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        k[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        k
    });
    match super::trust_task_sign::signing_secret(state).await {
        Some(secret) => ring::digest::digest(
            &ring::digest::SHA256,
            &[
                b"affinidi-mediator/mux/admin-list/cursor\n".as_slice(),
                secret.get_private_bytes(),
            ]
            .concat(),
        )
        .as_ref()
        .to_vec(),
        None => PROCESS_KEY.to_vec(),
    }
}
