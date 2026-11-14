//! `messaging/acl/get` and `messaging/access-list/*`: who may read and
//! change an account's ACL and access list.

#![allow(deprecated)]

use super::*;

/// Most DIDs one `messaging/acl/get` may name: the store's batch read limit.
pub(super) const ACL_GET_MAX_DIDS: usize = 100;

/// Handle `messaging/acl/get`: self-or-admin, read-only, batched. Returns one entry
/// per known DID and lists any unknown DIDs separately.
pub(super) async fn consume_acl_get(
    typed: TrustTask<acl::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use acl::get::v0_1::{Entry, Response, Vid};

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let dids: Vec<String> = typed.payload.dids.iter().map(|v| v.to_string()).collect();
    // Bounded here because the pinned schema does not bound it (no
    // `maxItems` on `dids`): every DID is a store read.
    if dids.len() > ACL_GET_MAX_DIDS {
        return Err(tt_problem(
            session,
            "malformedRequest",
            format!(
                "`dids` may name at most {ACL_GET_MAX_DIDS} accounts; this request names {}",
                dids.len()
            ),
            StatusCode::BAD_REQUEST,
        ));
    }
    if !check_permissions(
        session,
        &dids,
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "not permitted to read one or more of the requested ACLs".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // One batched read for every requested DID, not one round trip each.
    let found: std::collections::HashMap<String, MediatorACLSet> = state
        .database
        .get_did_acls(&dids, state.config.security.mediator_acl_mode.clone())
        .await?
        .acl_response
        .into_iter()
        .map(|entry| (entry.did_hash, entry.acls))
        .collect();
    let mut entries = Vec::new();
    let mut unknown = Vec::new();
    for did in &dids {
        let vid = Vid::from_str(did).expect("a requested DID is a valid Vid");
        match found.get(did) {
            Some(aclset) => entries.push(build(
                Entry::builder()
                    .acl(to_wire_acl::<acl::get::v0_1::MediatorAcl>(aclset))
                    .did(vid),
            )?),
            None => unknown.push(vid),
        }
    }

    let response: Response = build(Response::builder().entries(entries).unknown(unknown))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Access-list authz: self-or-admin for the target, plus the `self_manage_list`
/// capability for a standard account performing a write.
pub(super) async fn authorize_access_list(
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    target_hash: &str,
    write: bool,
) -> Result<(), MediatorError> {
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash.to_string()),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to access the access list for {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }
    if write && !roles::can_administer(session.account_type) && !session.acls.get_self_manage_list()
    {
        return Err(tt_problem(
            session,
            "messaging/access-list/update:selfChangeDenied",
            "this account may not self-manage its access list".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    // Another privileged account's list is changed only by a root admin.
    if write
        && let Some(target) = state.database.account_get(target_hash).await?
        && !roles::may_modify_account(
            session.account_type,
            &session.did_hash,
            target._type,
            target_hash,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "root-admin access is required to change a privileged account's access list"
                .to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// The current size of a DID's access list (0 if the account is unknown).
pub(super) async fn access_list_count(state: &SharedData, target_hash: &str) -> u64 {
    state
        .database
        .account_get(target_hash)
        .await
        .ok()
        .flatten()
        .map(|a| a.access_list_count as u64)
        .unwrap_or(0)
}

/// Gate a non-admin `acl/set`: a standard account may change a capability only when
/// its per-capability self-change bit is set, and may never touch the admin-only flags
/// (`blocked`, `local`, the `selfManage*` bits). A flag whose requested value equals
/// the current value is not a change. Faithful to the legacy `acls_set` self-service
/// rules.
pub(super) fn ensure_self_manageable(
    acl_value: &Value,
    base: &MediatorACLSet,
    session: &Session,
) -> Result<(), MediatorError> {
    let req: account::get::v0_1::MediatorAcl = serde_json::from_value(acl_value.clone())
        .map_err(|e| malformed_acl(format!("invalid ACL payload: {e}")))?;
    let cur = decode_acl_canonical(base);
    let deny = |flag: &str| -> Result<(), MediatorError> {
        Err(tt_problem(
            session,
            "messaging/account/update:selfChangeDenied",
            format!("this account may not change `{flag}`"),
            StatusCode::FORBIDDEN,
        ))
    };

    // Capabilities self-manageable when the account's self-change bit is set.
    if req.access_list_mode.is_some()
        && req.access_list_mode != cur.access_list_mode
        && !base.get_access_list_mode().1
    {
        return deny("accessListMode");
    }
    if req.send_messages.is_some()
        && req.send_messages != cur.send_messages
        && !base.get_send_messages().1
    {
        return deny("sendMessages");
    }
    if req.receive_messages.is_some()
        && req.receive_messages != cur.receive_messages
        && !base.get_receive_messages().1
    {
        return deny("receiveMessages");
    }
    if req.send_forwarded.is_some()
        && req.send_forwarded != cur.send_forwarded
        && !base.get_send_forwarded().1
    {
        return deny("sendForwarded");
    }
    if req.receive_forwarded.is_some()
        && req.receive_forwarded != cur.receive_forwarded
        && !base.get_receive_forwarded().1
    {
        return deny("receiveForwarded");
    }
    if req.create_invites.is_some()
        && req.create_invites != cur.create_invites
        && !base.get_create_invites().1
    {
        return deny("createInvites");
    }
    if req.anon_receive.is_some()
        && req.anon_receive != cur.anon_receive
        && !base.get_anon_receive().1
    {
        return deny("anonReceive");
    }

    // Admin-only flags: a non-admin may never change these.
    if req.blocked.is_some() && req.blocked != cur.blocked {
        return deny("blocked");
    }
    if req.local.is_some() && req.local != cur.local {
        return deny("local");
    }
    if req.self_manage_list.is_some() && req.self_manage_list != cur.self_manage_list {
        return deny("selfManageList");
    }
    if req.self_manage_send_queue_limit.is_some()
        && req.self_manage_send_queue_limit != cur.self_manage_send_queue_limit
    {
        return deny("selfManageSendQueueLimit");
    }
    if req.self_manage_receive_queue_limit.is_some()
        && req.self_manage_receive_queue_limit != cur.self_manage_receive_queue_limit
    {
        return deny("selfManageReceiveQueueLimit");
    }

    Ok(())
}

/// Handle `messaging/access-list/update`: self-or-admin (+ `self_manage_list` for
/// a standard account). One write task for the whole access list — the merge of
/// the retired `access-list/add` / `remove` / `clear` handlers. Members apply in
/// the spec's fixed order **`clear`, `add`, `remove`**, so `clear + add` replaces
/// the list wholesale. Reports the entries actually added and removed plus the
/// resulting count.
pub(super) async fn consume_access_list_update(
    typed: TrustTask<access_list::update::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::update::v0_1::{Response, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, true).await?;

    // One atomic store write: `clear`, `add` and `remove` land together, so
    // no reader sees the list cleared and not yet refilled, and a failure
    // leaves it as it was.
    let update = AccessListUpdate {
        clear: typed.payload.clear == Some(true),
        add: typed.payload.add.iter().map(|v| v.to_string()).collect(),
        remove: typed.payload.remove.iter().map(|v| v.to_string()).collect(),
    };
    let outcome = state
        .database
        .access_list_update(state.limits().access_list_limit, &target_hash, &update)
        .await?;

    if update.clear {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListClear,
            "access list cleared".to_string(),
        )
        .await;
    }
    if !update.add.is_empty() {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListAdd,
            format!("added {} entries", outcome.added.len()),
        )
        .await;
    }
    if !update.remove.is_empty() {
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListRemove,
            format!("removed {} entries", outcome.removed.len()),
        )
        .await;
    }
    let vids = |hashes: &[String]| -> Vec<Vid> {
        hashes
            .iter()
            .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
            .collect()
    };
    let added = vids(&outcome.added);
    let removed = vids(&outcome.removed);

    let response: Response = build(
        Response::builder()
            .access_list_count(outcome.count as u64)
            .added(added)
            .did(typed.payload.did.clone())
            .removed(removed),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/access-list/list`: self-or-admin, read-only, cursor-paged.
/// An `entries` filter turns the enumeration into a membership check (subsuming
/// the retired `messaging/access-list/get`): only the supplied DIDs present in
/// the list are returned, unpaged, with `accessListCount` still the whole-list
/// total.
pub(super) async fn consume_access_list_list(
    typed: TrustTask<access_list::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::list::v0_1::{Response, ResponseNextCursor, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, false).await?;

    // Membership check (subsumes the retired `messaging/access-list/get`): return
    // exactly the supplied entries that are present; a supplied DID absent from
    // the response is not a member.
    if !typed.payload.entries.is_empty() {
        let hashes: Vec<String> = typed
            .payload
            .entries
            .iter()
            .map(|v| v.to_string())
            .collect();
        let present: HashSet<String> = state
            .database
            .access_list_get(&target_hash, &hashes)
            .await?
            .did_hashes
            .into_iter()
            .collect();
        let entries: Vec<Vid> = typed
            .payload
            .entries
            .iter()
            .filter(|v| present.contains(v.as_str()))
            .cloned()
            .collect();

        // `next_cursor` stays unset: a membership check answers in one page.
        let response: Response = build(
            Response::builder()
                .access_list_count(access_list_count(state, &target_hash).await)
                .did(typed.payload.did.clone())
                .entries(entries),
        )?;
        return serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err);
    }

    let cursor: u64 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let page = state
        .database
        .access_list_list(&target_hash, cursor)
        .await?;
    let entries: Vec<Vid> = page
        .did_hashes
        .iter()
        .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
        .collect();
    // Both `None` and `Some(0)` mean the listing is exhausted.
    let next_cursor = match page.cursor {
        None | Some(0) => None,
        Some(c) => Some(
            ResponseNextCursor::from_str(&c.to_string())
                .map_err(|e| serialize_err_msg(format!("cursor: {e}")))?,
        ),
    };

    let response: Response = build(
        Response::builder()
            .access_list_count(access_list_count(state, &target_hash).await)
            .did(typed.payload.did.clone())
            .entries(entries)
            .next_cursor(next_cursor),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}
