//! `messaging/account/*`: get, list, update, remove and add, with the
//! queue-limit rules `account/update` applies.

#![allow(deprecated)]

use super::*;

/// Handle `messaging/account/get`: read-only, self-or-admin. Returns the
/// mediator's view of the named account as a `TrustTask<Response>` JSON value.
pub(super) async fn consume_account_get(
    typed: TrustTask<account::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    // Framework basics: addressed to this mediator and not expired.
    validate_tt_basic(&typed, session, mediator_did, now)?;

    // Authz: the caller must be the target account itself, or an admin.
    let target_hash = typed.payload.did.to_string();
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to read account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    let account = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/get:unknownAccount",
                format!("account {target_hash} not found"),
                StatusCode::NOT_FOUND,
            )
        })?;

    let mut wire = map_account_get(&account);
    if typed.payload.include_stats.unwrap_or(false) {
        let stats = state
            .database
            .account_stats(std::slice::from_ref(&target_hash))
            .await?;
        if let Some(stats) = stats.first() {
            wire.stats = Some(to_wire_stats(stats));
        }
    }
    if typed.payload.include_activity.unwrap_or(false) {
        let activity = state
            .database
            .account_activity(std::slice::from_ref(&target_hash))
            .await?;
        if let Some(activity) = activity.first() {
            wire.last_received_at = activity.last_received;
            wire.last_authenticated_at = activity.last_authenticated;
        }
    }
    let response: account::get::v0_1::Response =
        build(account::get::v0_1::Response::builder().account(wire))?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/list`: admin-only, read-only. Returns one page of the
/// mediator's accounts (with an opaque continuation cursor) as a `TrustTask<Response>`.
/// An `accountType` filter restricts the page to one role — filtering on `admin` /
/// `rootAdmin` enumerates the administrators (this subsumes the retired
/// `messaging/admin/list`). The filter applies per page, so a filtered page may
/// hold fewer than `limit` entries while `nextCursor` still advances.
pub(super) async fn consume_account_list(
    typed: TrustTask<account::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    // Authz: admin-only (listing every account is an administrative action).
    require_admin(session, "account/list")?;

    // The wire cursor is an opaque string over the store's numeric cursor.
    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed.payload.limit.map(|n| n.get() as u32).unwrap_or(100);

    // Optional role filter (subsumes the retired `messaging/admin/list`).
    let type_filter = typed.payload.account_type.as_ref().map(|t| {
        use account::list::v0_1::AccountType as WireType;
        match t {
            WireType::Standard => AccountType::Standard,
            WireType::Admin => AccountType::Admin,
            WireType::RootAdmin => AccountType::RootAdmin,
            WireType::Mediator => AccountType::Mediator,
            // No wildcard: the wire enum is generated in this crate from the
            // pinned bundle, so a role added to the spec only arrives with a
            // pin move, and then this match fails to compile until it is
            // mapped. (A role this build does not know cannot be decoded.)
        }
    });

    let page = state.database.account_list(cursor, limit).await?;
    // Annotated: the element type used to be pinned by the response struct
    // literal below, and the builder's `TryInto` setter no longer pins it.
    let mut accounts: Vec<account::list::v0_1::Account> = page
        .accounts
        .iter()
        .filter(|a| type_filter.as_ref().is_none_or(|t| a._type == *t))
        .map(to_wire_account::<account::list::v0_1::Account>)
        .collect();
    // The times are read for the page as it is returned, in one call, so a
    // filtered-out account costs nothing.
    if typed.payload.include_stats.unwrap_or(false) {
        let hashes: Vec<String> = accounts.iter().map(|a| a.did.to_string()).collect();
        for (account, stats) in accounts
            .iter_mut()
            .zip(state.database.account_stats(&hashes).await?)
        {
            account.stats = Some(to_wire_stats_as(&stats));
        }
    }
    if typed.payload.include_activity.unwrap_or(false) {
        let hashes: Vec<String> = accounts.iter().map(|a| a.did.to_string()).collect();
        for (account, activity) in accounts
            .iter_mut()
            .zip(state.database.account_activity(&hashes).await?)
        {
            account.last_received_at = activity.last_received;
            account.last_authenticated_at = activity.last_authenticated;
        }
    }
    // The store returns cursor 0 when the listing is exhausted.
    let next_cursor = (page.cursor != 0)
        .then(|| account::list::v0_1::ResponseNextCursor::from_str(&page.cursor.to_string()))
        .transpose()
        .map_err(|e| {
            tt_problem(
                session,
                "internalError",
                format!("couldn't encode the continuation cursor: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let response: account::list::v0_1::Response = build(
        account::list::v0_1::Response::builder()
            .accounts(accounts)
            .next_cursor(next_cursor),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/update`: one partial update of a served account's
/// role, capabilities, and queue limits — the merge of the retired
/// `change-type` / `change-queue-limits` / `acl/set` handlers, with their guards
/// applied per member:
///
/// - `accountType` — admin only; only a root admin may grant a privileged role
///   (admin, root admin, mediator) or change the role of an account holding one.
///
/// An account that holds a privileged role is changed only by itself or by a
/// root admin, whichever members the update carries (see `common::roles`).
/// - `acl` — self-or-admin; a non-admin may only change flags it self-manages.
/// - `queueLimits` — self-or-admin; a standard account may only change limits it
///   self-manages, capped at the mediator's hard maximum.
///
/// Guards run before anything is applied so a refused member refuses the whole
/// update. Returns the account's realized view after the change.
pub(super) async fn consume_account_update(
    typed: TrustTask<account::update::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::update::v0_1::AccountType as WireType;

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    let is_admin = roles::can_administer(session.account_type);
    let denied = |reason: &str| {
        tt_problem(
            session,
            "permissionDenied",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // The task updates; it does not create.
    let current = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/update:unknownAccount",
                format!("account {target_hash} not found"),
                StatusCode::NOT_FOUND,
            )
        })?;

    // ---- Guards first, so a refused member refuses the whole update. ----

    // An account holding a privileged role (admin, root admin, the mediator's
    // own) is changed only by itself or by a root admin.
    if !roles::may_modify_account(
        session.account_type,
        &session.did_hash,
        current._type,
        &target_hash,
    ) {
        return Err(tt_problem(
            session,
            "messaging/account/update:rootAdminRequired",
            "root-admin access is required to modify a privileged account".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // This one *writes* the role, so it must never store something the caller
    // did not ask for. No wildcard: the wire enum is generated in this crate
    // from the pinned bundle, so a role added to the spec only arrives with a
    // pin move, and then this match fails to compile until it is mapped. A
    // role this build does not know cannot be decoded at all.
    let new_type = typed.payload.account_type.as_ref().map(|t| match t {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
    });
    if let Some(new_type) = new_type {
        // Must be an admin to change roles at all.
        if !roles::can_administer(session.account_type) {
            return Err(denied("admin access is required to change account types"));
        }
        // The mediator's own account and the configured root admin keep the
        // roles configuration gave them.
        if is_configured_account(state, &target_hash) {
            return Err(tt_problem(
                session,
                "permissionDenied",
                "the roles of the mediator and root-admin accounts cannot be changed".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }
        // Granting a privileged role, or changing the role of an account that
        // holds one, is for a root admin.
        if !roles::can_assign_role(session.account_type, Some(current._type), new_type) {
            return Err(tt_problem(
                session,
                "messaging/account/update:rootAdminRequired",
                "root-admin access is required to grant or change a privileged role".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }
    }

    // Capabilities and queue limits are self-or-admin.
    let acl_value = match &typed.payload.acl {
        Some(acl) => Some(serde_json::to_value(acl).map_err(serialize_err)?),
        None => None,
    };
    if (acl_value.is_some() || typed.payload.queue_limits.is_some())
        && !check_permissions(
            session,
            std::slice::from_ref(&target_hash),
            state.config.security.block_remote_admin_msgs,
            sender_kid,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to update account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }
    if let Some(acl_value) = &acl_value {
        // A non-admin may only change flags it is permitted to self-manage.
        if !is_admin {
            ensure_self_manageable(acl_value, &MediatorACLSet::from_u64(current.acls), session)?;
        }
    }

    // Queue limits are resolved here rather than at the write below, because a
    // refusal must refuse the *whole* update: by the time the write runs, the ACL
    // member has already been stored and audited. The wire carries i64 and the
    // store works in i32; a member omitted is left unchanged.
    let queue_limits = typed
        .payload
        .queue_limits
        .as_ref()
        .map(|limits| {
            resolve_queue_limits(
                session,
                is_admin,
                (
                    wire_queue_limit(limits.send_queue_limit, "send_queue_limit", session)?,
                    wire_queue_limit(limits.receive_queue_limit, "receive_queue_limit", session)?,
                ),
                (
                    state.limits().queued_send_messages_hard,
                    state.limits().queued_receive_messages_hard,
                ),
            )
        })
        .transpose()?;

    // ---- Apply: every member in one atomic store write. ----
    //
    // Every refusal was decided above, and the store applies the ACL, the
    // queue limits and the role together, so a failure leaves the account as
    // it was rather than part-updated.
    let acls = match acl_value {
        Some(acl_value) => {
            let base = state
                .database
                .get_did_acl(&target_hash)
                .await?
                .unwrap_or_default();
            Some(merge_wire_acl(acl_value, base)?)
        }
        None => None,
    };
    let role = new_type.filter(|new_type| *new_type != current._type);
    let update = AccountUpdate {
        acls,
        send_queue_limit: queue_limits.and_then(|(send, _)| send),
        receive_queue_limit: queue_limits.and_then(|(_, receive)| receive),
        role,
    };
    if !state.database.account_update(&target_hash, &update).await? {
        // Removed between the read above and the write: nothing was applied.
        return Err(tt_problem(
            session,
            "messaging/account/update:unknownAccount",
            format!("account {target_hash} not found"),
            StatusCode::NOT_FOUND,
        ));
    }

    if let Some(stored) = &update.acls {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::SetAcl,
            format!("acl -> {:#018x}", stored.to_u64()),
        )
        .await;
    }
    if let Some((send_queue_limit, receive_queue_limit)) = queue_limits {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccountChangeQueueLimits,
            format!("send={send_queue_limit:?} receive={receive_queue_limit:?}"),
        )
        .await;
    }
    if let Some(new_type) = update.role {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccountChangeType,
            format!("type -> {new_type}"),
        )
        .await;
    }
    if update.acls.is_some() || update.role.is_some() {
        // A live mux connection carrying the account as a member drops it now
        // if the new ACLs no longer cover its scope, before this answers; open
        // sockets here and on every instance sharing the store re-read their
        // account on their next frame (`common::standing`).
        crate::mux::connection::account_changed(state, &target_hash).await;
    }

    let account = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/update:unknownAccount",
                format!("account {target_hash} not found after update"),
                StatusCode::NOT_FOUND,
            )
        })?;
    let response: account::update::v0_1::Response = build(
        account::update::v0_1::Response::builder()
            .account(to_wire_account::<account::update::v0_1::Account>(&account)),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// The stored `(send, receive)` queue limits for a `(requested send, requested
/// receive)` pair. An admin's request stands as sent; anyone else's goes through
/// [`gate_self_managed_limit`]. `None` in either position leaves that limit
/// unchanged. `hard` is `(send, receive)` from the mediator's limits.
///
/// `is_admin` is the caller's own admin test, so that the two self-or-admin members
/// of one `account/update` — the ACL and these limits — cannot disagree about who
/// an admin is. It had tested `account_type != Standard` here while the ACL member
/// tested `Admin | RootAdmin`, which let an account whose type did not decode
/// (`Unknown`) past this gate but not that one.
pub(super) fn resolve_queue_limits(
    session: &Session,
    is_admin: bool,
    requested: (Option<i32>, Option<i32>),
    hard: (i32, i32),
) -> Result<(Option<i32>, Option<i32>), MediatorError> {
    if is_admin {
        return Ok(requested);
    }
    Ok((
        gate_self_managed_limit(
            requested.0,
            session.acls.get_self_manage_send_queue_limit(),
            hard.0,
            "send_queue_limit",
            session,
        )?,
        gate_self_managed_limit(
            requested.1,
            session.acls.get_self_manage_receive_queue_limit(),
            hard.1,
            "receive_queue_limit",
            session,
        )?,
    ))
}

/// A standard account may change a queue limit only if it self-manages that limit,
/// and may not switch it off. Permission to adjust a limit is not permission to
/// remove it, so `-1` (unlimited) and anything past `-2` are refused: being below
/// every maximum they would slip past the clamp and be stored verbatim. `-2` resets
/// to the mediator default and passes through; a value above `hard` is clamped; a
/// negative `hard` is unbounded, so there is no ceiling to clamp against. Not
/// self-managed → refused, as `ensure_self_manageable` refuses a capability the
/// account may not change. Admins do not come here.
pub(super) fn gate_self_managed_limit(
    requested: Option<i32>,
    self_managed: bool,
    hard: i32,
    limit_name: &str,
    session: &Session,
) -> Result<Option<i32>, MediatorError> {
    // Both limits are gated on every request, so an omitted member is nothing to
    // gate — it must be answered before the permission test, or an account that
    // self-manages one limit and not the other could never set the one it does.
    let Some(requested) = requested else {
        return Ok(None);
    };
    if !self_managed {
        // A member the account may not touch is refused, not quietly dropped: the
        // response echoes the stored account, so a silent no-op reaches the caller
        // as a success carrying the old value, which reads as "applied".
        return Err(tt_problem(
            session,
            "messaging/account/update:selfChangeDenied",
            format!("this account may not self-manage its `{limit_name}`"),
            StatusCode::FORBIDDEN,
        ));
    }
    match requested {
        RESET_QUEUE_LIMIT_TO_DEFAULT => Ok(Some(RESET_QUEUE_LIMIT_TO_DEFAULT)),
        limit if limit < 0 => Err(tt_problem(
            session,
            "permissionDenied",
            format!(
                "admin access is required to set an unlimited `{limit_name}` ({limit}); \
                 this account may set a limit of 0 or more, or \
                 {RESET_QUEUE_LIMIT_TO_DEFAULT} to reset it to the mediator default"
            ),
            StatusCode::FORBIDDEN,
        )),
        limit if hard >= 0 && limit > hard => Ok(Some(hard)),
        limit => Ok(Some(limit)),
    }
}

/// A queue limit from the wire (i64) as the store holds it (i32): `-1`
/// (unlimited), `-2` (reset to the default) or `0` and more. A value outside
/// that — any other negative, or one past `i32` — is refused rather than
/// wrapped or stored with no meaning, whoever asks.
pub(super) fn wire_queue_limit(
    requested: Option<i64>,
    limit_name: &str,
    session: &Session,
) -> Result<Option<i32>, MediatorError> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    match i32::try_from(requested) {
        Ok(limit) if limit >= RESET_QUEUE_LIMIT_TO_DEFAULT => Ok(Some(limit)),
        _ => Err(tt_problem(
            session,
            "malformedRequest",
            format!(
                "`{limit_name}` must be -1 (unlimited), {RESET_QUEUE_LIMIT_TO_DEFAULT} (reset to \
                 the default) or a limit from 0 to {}; got {requested}",
                i32::MAX
            ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// The queue-limit sentinel meaning "drop this account's override and fall back to
/// the mediator default" — `_change_queue_limit` in the store turns it into an
/// `HDEL`. It is not a limit value, so it is never clamped.
pub(super) const RESET_QUEUE_LIMIT_TO_DEFAULT: i32 = -2;

/// Handle `messaging/account/remove`: self-or-admin. Refuses to remove the
/// mediator's own account or the root admin (both compared in constant time).
/// Returns the target id and whether a record was removed.
pub(super) async fn consume_account_remove(
    typed: TrustTask<account::remove::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to remove account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    // Never remove the mediator's own account or the root admin.
    if is_configured_account(state, &target_hash) {
        return Err(tt_problem(
            session,
            "messaging/account/remove:protectedAccount",
            "the mediator and root-admin accounts cannot be removed".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    // Another privileged account is removed only by a root admin.
    if let Some(target) = state.database.account_get(&target_hash).await?
        && !roles::may_modify_account(
            session.account_type,
            &session.did_hash,
            target._type,
            &target_hash,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "root-admin access is required to remove a privileged account".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    let removed = state
        .database
        .account_remove(&session.to_store_session(), &target_hash)
        .await?;
    // Mux grants on either side of the removed account go too, whether or not
    // mux is enabled now: grants left from when it was would otherwise come
    // back to life if the DID re-registered. Done after the account removal,
    // so a failure here cannot leave a half-removed account; it is logged
    // loudly because the grants then outlive the account (R6.3).
    if removed && state.database.supports_mux() {
        let limits = state.config.limits.mux.store_limits();
        match affinidi_messaging_mediator_common::store::mux::remove_account(
            &*state.database,
            &target_hash,
            &limits,
            state.clock.unix_secs(),
        )
        .await
        {
            // Principals carrying the removed DID drop it now and are told.
            Ok(as_member) if !as_member.is_empty() => {
                use crate::mux::session::LeaveReason;
                state
                    .mux
                    .detach_grants(
                        state.streaming_task.as_ref(),
                        &as_member,
                        LeaveReason::AccountRemoved,
                    )
                    .await;
                let changes: Vec<_> = as_member
                    .iter()
                    .map(|g| {
                        affinidi_messaging_mediator_common::store::mux::MuxChange::of(g, false)
                    })
                    .collect();
                crate::mux::sync::publish(state, &changes).await;
                let changed = crate::mux::tasks::Changed {
                    removed: as_member,
                    reason: Some(LeaveReason::AccountRemoved),
                    ..Default::default()
                };
                crate::mux::notice::after_change(state, &changed).await;
            }
            Ok(_) => {}
            Err(e) => tracing::error!(
                did_hash = %target_hash,
                "account removed, but its DID multiplexing grants could not be: {e}"
            ),
        }
    }
    // Members admitted by a session attach hold no stored grant, so the
    // detach above does not reach them; the account is gone, so its standing
    // check detaches them (`accountRemoved`) on every connection here.
    if removed {
        crate::mux::connection::account_changed(state, &target_hash).await;
    }
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountRemove,
        "account removed".to_string(),
    )
    .await;

    let response: account::remove::v0_1::Response = build(
        account::remove::v0_1::Response::builder()
            .did(typed.payload.did.clone())
            .removed(removed),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Whether `target_hash` is the mediator's own account or the configured root
/// admin (`admin_did`), compared in constant time. Neither is removed, and
/// neither has its role changed, through a Trust Task: both are set up from
/// configuration at startup.
pub(super) fn is_configured_account(state: &SharedData, target_hash: &str) -> bool {
    state
        .config
        .mediator_did_hash
        .as_bytes()
        .ct_eq(target_hash.as_bytes())
        .unwrap_u8()
        == 1
        || affinidi_messaging_mediator_common::did_identity::did_hash(&state.config.admin_did)
            .as_bytes()
            .ct_eq(target_hash.as_bytes())
            .unwrap_u8()
            == 1
}

/// Handle `messaging/account/add`. Only an admin may add accounts, in either
/// `mediator_acl_mode`: an account for the caller itself already exists (it is
/// created when the DID first authenticates), so the only accounts this task
/// can create belong to other DIDs, which is account administration. The admin
/// may supply the new account's ACL (applied onto the mediator default).
/// Creating an account with a privileged role (admin, root admin, mediator)
/// requires a root admin.
///
/// An account that already exists is refused with `alreadyExists` and left
/// exactly as it was; `messaging/account/update` changes an existing account.
/// Returns the created account's realized view.
pub(super) async fn consume_account_add(
    typed: TrustTask<account::add::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::add::v0_1::AccountType as WireType;

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    let new_type = match typed.payload.account_type {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
        // No wildcard: a role added to the spec only arrives with a pin move,
        // and then this match fails to compile until the role is mapped. A
        // role this build does not know cannot be decoded, so it is never
        // stored as a privilege level the mediator cannot reason about.
    };
    let denied = |reason: &str| {
        tt_problem(
            session,
            "permissionDenied",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // The role was read from the store for this request (see `principal`), so
    // a role removed since the session was issued no longer grants this.
    if !roles::can_administer(session.account_type) {
        return Err(denied("admin access is required to add accounts"));
    }
    // Creating a privileged account is for a root admin.
    if !roles::can_assign_role(session.account_type, None, new_type) {
        return Err(denied(
            "root-admin access is required to create a privileged account",
        ));
    }

    // ACLs: the admin may supply them (applied onto the mediator default).
    let acls = match &typed.payload.acl {
        Some(acl) => merge_wire_acl(
            serde_json::to_value(acl).map_err(serialize_err)?,
            state.config.security.global_acl_default.clone(),
        )?,
        None => state.config.security.global_acl_default.clone(),
    };

    let account = state
        .database
        .account_create(&target_hash, &acls, None)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/add:alreadyExists",
                format!("account {target_hash} already exists"),
                StatusCode::CONFLICT,
            )
        })?;
    // Apply a non-standard role if requested (the guards above already authorized it).
    let account = if new_type != AccountType::Standard {
        state
            .database
            .account_set_role(&target_hash, &new_type)
            .await?;
        state
            .database
            .account_get(&target_hash)
            .await?
            .unwrap_or(account)
    } else {
        account
    };

    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountAdd,
        "account created".to_string(),
    )
    .await;

    let response: account::add::v0_1::Response = build(
        account::add::v0_1::Response::builder()
            .account(to_wire_account::<account::add::v0_1::Account>(&account)),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}
