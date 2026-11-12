//! Account roles: the one place that says what each role may do.
//!
//! Handlers used to answer "is this caller an administrator?" in different
//! ways — `AccountType::is_admin()` (which counts the mediator's own account),
//! `Admin | RootAdmin`, a store lookup, or `!= Standard` — so a role's reach
//! depended on which handler asked. Every role decision now goes through the
//! predicates here.
//!
//! The rules:
//!
//! - **Administration** (acting on accounts other than one's own) belongs to
//!   `Admin` and `RootAdmin` only. `Mediator` is the mediator's own account,
//!   not an operator, and administers nothing.
//! - **`Unknown`** — a stored role this build could not decode — is the least
//!   privilege: it is gated exactly like `Standard` everywhere.
//! - **Privileged roles** are `Admin`, `RootAdmin` and `Mediator`. Granting one,
//!   or changing or removing an account that holds one (other than one's own),
//!   is reserved to `RootAdmin`.
//!
//! The caller's role is read from the store once per request ([`principal`]),
//! not taken from the session token.

use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    types::{accounts::AccountType, acls::MediatorACLSet},
};

use crate::{SharedData, common::session::Session};

/// The role a stored account is treated as holding.
///
/// `listed_admin` is the store's own admin check (`check_admin_account`): an
/// `Admin` / `RootAdmin` role that the store does not also list as an admin is
/// not honoured. `Unknown` is treated as `Standard`.
pub(crate) fn effective_role(stored: AccountType, listed_admin: bool) -> AccountType {
    match stored {
        AccountType::Admin | AccountType::RootAdmin if !listed_admin => AccountType::Standard,
        AccountType::Unknown => AccountType::Standard,
        role => role,
    }
}

/// The session a request is authorised as: `session` with its role and ACLs
/// read from the store for this request.
///
/// Every handler then decides from the same, current answer. The role is the
/// stored one, honoured as an administrator only when the store also lists the
/// account as one (`check_admin_account`), and an `Unknown` role is read as
/// `Standard` (see [`effective_role`]). An account the
/// store no longer has is treated as `Standard` with the session's ACLs.
pub(crate) async fn principal(
    state: &SharedData,
    session: &Session,
) -> Result<Session, MediatorError> {
    let mut principal = session.clone();
    match state.database.account_get(&session.did_hash).await? {
        Some(account) => {
            let listed_admin = can_administer(account._type)
                && state
                    .database
                    .check_admin_account(&session.did_hash)
                    .await?;
            principal.account_type = effective_role(account._type, listed_admin);
            principal.acls = MediatorACLSet::from_u64(account.acls);
        }
        None => principal.account_type = AccountType::Standard,
    }
    Ok(principal)
}

/// Whether `role` may act on accounts other than its own.
pub(crate) fn can_administer(role: AccountType) -> bool {
    matches!(role, AccountType::Admin | AccountType::RootAdmin)
}

/// Whether `role` is the root administrator.
pub(crate) fn is_root(role: AccountType) -> bool {
    role == AccountType::RootAdmin
}

/// Whether `role` carries authority beyond a standard account.
pub(crate) fn is_privileged(role: AccountType) -> bool {
    matches!(
        role,
        AccountType::Admin | AccountType::RootAdmin | AccountType::Mediator
    )
}

/// Whether an existing account holding `role` is protected from other
/// administrators: a privileged role, or `Unknown`. A stored role this build
/// cannot decode might be a privileged one, so changing such an account is
/// left to a root admin.
pub(crate) fn is_protected_account(role: AccountType) -> bool {
    is_privileged(role) || role == AccountType::Unknown
}

/// Whether `actor` may give an account the role `target`. `current` is the
/// account's role now, or `None` when the account is being created.
///
/// Any administrator may assign `Standard` to a standard account. Assigning a
/// privileged role, or changing the role of an account that holds one (or
/// whose role is `Unknown`), needs `RootAdmin`.
pub(crate) fn can_assign_role(
    actor: AccountType,
    current: Option<AccountType>,
    target: AccountType,
) -> bool {
    if !can_administer(actor) {
        return false;
    }
    let touches_privileged = is_privileged(target) || current.is_some_and(is_protected_account);
    !touches_privileged || is_root(actor)
}

/// Whether an actor may change or remove the account `target_hash`, which
/// holds `target_role`, as far as the target's role is concerned.
///
/// An account holding a privileged role, or whose role is `Unknown`, can be
/// changed by itself or by a `RootAdmin`, and by nobody else. Other accounts
/// are not restricted here; the caller's own self-or-admin check still
/// applies.
pub(crate) fn may_modify_account(
    actor_role: AccountType,
    actor_hash: &str,
    target_role: AccountType,
    target_hash: &str,
) -> bool {
    !is_protected_account(target_role) || target_hash == actor_hash || is_root(actor_role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use AccountType::*;

    const ALL: [AccountType; 5] = [Standard, Admin, RootAdmin, Mediator, Unknown];

    #[test]
    fn only_admin_and_root_administer() {
        for role in ALL {
            assert_eq!(
                can_administer(role),
                matches!(role, Admin | RootAdmin),
                "{role:?}"
            );
        }
    }

    #[test]
    fn the_mediator_account_administers_nothing() {
        assert!(!can_administer(Mediator));
        for target in ALL {
            assert!(!can_assign_role(Mediator, None, target), "{target:?}");
        }
    }

    #[test]
    fn unknown_is_the_least_privilege() {
        assert_eq!(effective_role(Unknown, true), Standard);
        assert_eq!(effective_role(Unknown, false), Standard);
        assert!(!can_administer(Unknown));
        for target in ALL {
            assert!(!can_assign_role(Unknown, None, target), "{target:?}");
        }
        assert!(!may_modify_account(Unknown, "a", Admin, "b"));
    }

    #[test]
    fn an_admin_role_the_store_does_not_list_is_not_honoured() {
        assert_eq!(effective_role(Admin, false), Standard);
        assert_eq!(effective_role(RootAdmin, false), Standard);
        assert_eq!(effective_role(Admin, true), Admin);
        assert_eq!(effective_role(RootAdmin, true), RootAdmin);
        assert_eq!(effective_role(Mediator, false), Mediator);
        assert_eq!(effective_role(Standard, false), Standard);
    }

    #[test]
    fn only_root_grants_or_changes_a_privileged_role() {
        for target in [Admin, RootAdmin, Mediator] {
            assert!(!can_assign_role(Admin, None, target), "create {target:?}");
            assert!(
                !can_assign_role(Admin, Some(Standard), target),
                "promote to {target:?}"
            );
            assert!(
                can_assign_role(RootAdmin, None, target),
                "create {target:?}"
            );
            assert!(can_assign_role(RootAdmin, Some(Standard), target));
        }
        for current in [Admin, RootAdmin, Mediator] {
            assert!(
                !can_assign_role(Admin, Some(current), Standard),
                "demote {current:?}"
            );
            assert!(can_assign_role(RootAdmin, Some(current), Standard));
        }
    }

    #[test]
    fn an_admin_may_assign_the_standard_role() {
        assert!(can_assign_role(Admin, None, Standard));
        assert!(can_assign_role(Admin, Some(Standard), Standard));
        assert!(!can_assign_role(Admin, Some(Unknown), Standard));
        assert!(can_assign_role(RootAdmin, Some(Unknown), Standard));
        assert!(!can_assign_role(Standard, None, Standard));
    }

    #[test]
    fn a_privileged_account_is_changed_only_by_itself_or_root() {
        for target in [Admin, RootAdmin, Mediator] {
            assert!(!may_modify_account(Admin, "a", target, "b"), "{target:?}");
            assert!(
                may_modify_account(Admin, "b", target, "b"),
                "self {target:?}"
            );
            assert!(may_modify_account(RootAdmin, "a", target, "b"));
        }
        assert!(may_modify_account(Admin, "a", Standard, "b"));
        assert!(!may_modify_account(Admin, "a", Unknown, "b"));
        assert!(may_modify_account(RootAdmin, "a", Unknown, "b"));
        assert!(may_modify_account(Unknown, "b", Unknown, "b"));
    }
}
