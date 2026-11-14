//! Mapping between the store's account and ACL types and the Trust Task wire
//! documents.

#![allow(deprecated)]

use super::*;

/// Map the mediator's internal [`Account`] to the wire `account/get` shape.
///
/// The DID is carried as the mediator's account hash — a valid `Vid` per the
/// messaging spec's privacy note (the mediator never holds the full DID). The
/// `u64` ACL bitfield is decoded into the spec's named booleans; `didcommEnabled`
/// / `tspEnabled` have no bitfield slot and are reported as `None`.
pub(super) fn map_account_get(acc: &Account) -> account::get::v0_1::Account {
    use account::get::v0_1::{Account as WireAccount, AccountType as WireType, QueueLimits, Vid};

    let queue_limits: QueueLimits = QueueLimits::builder()
        .send_queue_limit(acc.queue_send_limit.map(|v| v as i64))
        .receive_queue_limit(acc.queue_receive_limit.map(|v| v as i64))
        .try_into()
        .expect("QueueLimits has no required member");

    WireAccount::builder()
        .did(Vid::from_str(&acc.did_hash).expect("an account hash is a non-empty Vid string"))
        .account_type(match acc._type {
            AccountType::Standard => WireType::Standard,
            AccountType::Admin => WireType::Admin,
            AccountType::RootAdmin => WireType::RootAdmin,
            AccountType::Mediator => WireType::Mediator,
            AccountType::Unknown => WireType::Standard,
        })
        .acl(decode_acl_canonical(&MediatorACLSet::from_u64(acc.acls)))
        .access_list_count(Some(acc.access_list_count as u64))
        .queue_limits(Some(queue_limits))
        .send_queue_count(Some(acc.send_queue_count as u64))
        .send_queue_bytes(Some(acc.send_queue_bytes))
        .receive_queue_count(Some(acc.receive_queue_count as u64))
        .receive_queue_bytes(Some(acc.receive_queue_bytes))
        .try_into()
        .expect("every required member of the wire Account is set above")
}

/// Map the mediator's [`AccountStats`] onto the wire shape. Every counter is
/// reported: this mediator keeps all of them, so an absent member on the wire
/// would say "not kept" of something it has.
pub(super) fn to_wire_stats(
    stats: &affinidi_messaging_mediator_common::types::accounts::AccountStats,
) -> account::get::v0_1::AccountStats {
    use account::get::v0_1::{AccountStats as WireStats, ProtocolCounts};
    use affinidi_messaging_mediator_common::types::accounts::ProtocolCounts as Counts;

    let counts = |c: &Counts| -> ProtocolCounts {
        ProtocolCounts::builder()
            .didcomm(Some(c.didcomm))
            .didcomm_v1(Some(c.didcomm_v1))
            .tsp(Some(c.tsp))
            .other(Some(c.other))
            .try_into()
            .expect("ProtocolCounts has no required member")
    };
    WireStats::builder()
        .messages_received(Some(stats.messages_received))
        .messages_sent(Some(stats.messages_sent))
        .bytes_received(Some(stats.bytes_received))
        .bytes_sent(Some(stats.bytes_sent))
        .received_by_protocol(Some(counts(&stats.received_by_protocol)))
        .sent_by_protocol(Some(counts(&stats.sent_by_protocol)))
        .try_into()
        .expect("AccountStats has no required member")
}

/// [`to_wire_stats`] into another `messaging/*` module's copy of the shared
/// `AccountStats` type, the same JSON round-trip [`to_wire_account`] uses and
/// for the same reason: typify generates one copy per spec module.
pub(super) fn to_wire_stats_as<T: serde::de::DeserializeOwned>(
    stats: &affinidi_messaging_mediator_common::types::accounts::AccountStats,
) -> T {
    serde_json::from_value(
        serde_json::to_value(to_wire_stats(stats)).expect("get AccountStats serialises"),
    )
    .expect("messaging AccountStats types share the one shared schema")
}

/// Re-shape [`map_account_get`]'s output into another `messaging/*` module's copy of
/// the shared `Account` type. typify generates a structurally-identical `Account`
/// per spec module; they all derive from the one shared schema, so a JSON round-trip
/// converts between them without re-implementing the bitfield decode.
pub(super) fn decode_acl_canonical(acl: &MediatorACLSet) -> account::get::v0_1::MediatorAcl {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    // `didcommEnabled` / `tspEnabled` are left unset: they have no bitfield
    // slot, so there is nothing to decode into them.
    MediatorAcl::builder()
        .access_list_mode(Some(match acl.get_access_list_mode().0 {
            AccessListModeType::ExplicitAllow => MediatorAclAccessListMode::ExplicitAllow,
            AccessListModeType::ExplicitDeny => MediatorAclAccessListMode::ExplicitDeny,
        }))
        .blocked(Some(acl.get_blocked()))
        .local(Some(acl.get_local()))
        .send_messages(Some(acl.get_send_messages().0))
        .receive_messages(Some(acl.get_receive_messages().0))
        .send_forwarded(Some(acl.get_send_forwarded().0))
        .receive_forwarded(Some(acl.get_receive_forwarded().0))
        .create_invites(Some(acl.get_create_invites().0))
        .anon_receive(Some(acl.get_anon_receive().0))
        .self_manage_list(Some(acl.get_self_manage_list()))
        .self_manage_send_queue_limit(Some(acl.get_self_manage_send_queue_limit()))
        .self_manage_receive_queue_limit(Some(acl.get_self_manage_receive_queue_limit()))
        .try_into()
        .expect("MediatorAcl has no required member")
}

/// Decode an ACL set into any `messaging/*` module's copy of `MediatorAcl`.
pub(super) fn to_wire_acl<T: serde::de::DeserializeOwned>(acl: &MediatorACLSet) -> T {
    serde_json::from_value(serde_json::to_value(decode_acl_canonical(acl)).expect("acl serialises"))
        .expect("messaging MediatorAcl types share the one shared schema")
}

/// Apply a wire `MediatorAcl` (from any module, passed as JSON) onto a base ACL set
/// as a **partial update**: each present value flag is set; absent flags and the
/// per-capability "self-change" bits — which the wire form does not carry — are left
/// as they are in `base`. `didcommEnabled`/`tspEnabled` have no bitfield slot and are
/// ignored. This is the reverse of [`decode_acl_canonical`].
pub(super) fn merge_wire_acl(
    acl_value: Value,
    mut base: MediatorACLSet,
) -> Result<MediatorACLSet, MediatorError> {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    let acl: MediatorAcl = serde_json::from_value(acl_value)
        .map_err(|e| malformed_acl(format!("invalid ACL payload: {e}")))?;
    let acl_err = |e: ACLError| malformed_acl(format!("ACL update rejected: {e}"));

    if let Some(mode) = acl.access_list_mode {
        let mode = match mode {
            MediatorAclAccessListMode::ExplicitAllow => AccessListModeType::ExplicitAllow,
            MediatorAclAccessListMode::ExplicitDeny => AccessListModeType::ExplicitDeny,
            // No wildcard: the mode decides whether the list allows or denies,
            // and a mode this build does not know cannot be decoded, so it is
            // never guessed. A new mode arrives only with a pin move, and then
            // this match fails to compile until it is mapped.
        };
        let self_change = base.get_access_list_mode().1;
        base.set_access_list_mode(mode, self_change, true)
            .map_err(acl_err)?;
    }
    if let Some(v) = acl.blocked {
        base.set_blocked(v);
    }
    if let Some(v) = acl.local {
        base.set_local(v);
    }
    if let Some(v) = acl.send_messages {
        let sc = base.get_send_messages().1;
        base.set_send_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_messages {
        let sc = base.get_receive_messages().1;
        base.set_receive_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.send_forwarded {
        let sc = base.get_send_forwarded().1;
        base.set_send_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_forwarded {
        let sc = base.get_receive_forwarded().1;
        base.set_receive_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.create_invites {
        let sc = base.get_create_invites().1;
        base.set_create_invites(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.anon_receive {
        let sc = base.get_anon_receive().1;
        base.set_anon_receive(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.self_manage_list {
        base.set_self_manage_list(v);
    }
    if let Some(v) = acl.self_manage_send_queue_limit {
        base.set_self_manage_send_queue_limit(v);
    }
    if let Some(v) = acl.self_manage_receive_queue_limit {
        base.set_self_manage_receive_queue_limit(v);
    }
    Ok(base)
}

pub(super) fn to_wire_account<T: serde::de::DeserializeOwned>(acc: &Account) -> T {
    serde_json::from_value(
        serde_json::to_value(map_account_get(acc)).expect("get Account serialises"),
    )
    .expect("messaging Account types share the one shared schema")
}
