//! Editing one account's settings: its role, ACL flags, access-list mode and
//! queue limits, as `messaging/account/update` changes them.
//!
//! [`AccountEdit`] starts from the account as `account/get` reported it, lets
//! the user change rows, and yields only what changed, as the typed
//! `account/update` members — `account/update` is a partial update, so an
//! untouched setting is never sent. The mediator decides who may change what
//! (granting or changing a privileged role — admin, rootAdmin — needs a
//! rootAdmin; an account may manage only the flags its own ACL lets it) and
//! refuses the rest.

use affinidi_messaging_mediator_admin::specs::account::{get::v0_2 as get, update::v0_2 as update};

/// The role an editor sets: `account/update`'s.
pub type Role = update::AccountType;
/// The access-list mode an editor sets.
pub type AccessListMode = update::MediatorAclAccessListMode;

/// The roles an editor can cycle through. `mediator` is not assignable.
const ROLES: [Role; 3] = [Role::Standard, Role::Admin, Role::RootAdmin];
const MODES: [AccessListMode; 2] = [AccessListMode::ExplicitDeny, AccessListMode::ExplicitAllow];

/// Which queue limit a [`Setting::Limit`] row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    Send,
    Receive,
}

impl LimitKind {
    /// Its wire name.
    pub fn name(self) -> &'static str {
        match self {
            LimitKind::Send => "sendQueueLimit",
            LimitKind::Receive => "receiveQueueLimit",
        }
    }
}

/// One editable setting.
#[derive(Clone, Debug, PartialEq)]
pub enum Setting {
    Role(Role),
    /// An ACL flag, by its wire name (one of [`ACL_FLAGS`]).
    Flag(&'static str, bool),
    AccessListMode(AccessListMode),
    /// A queue limit; `-1` is unlimited, `None` is not set on the account
    /// (the mediator default).
    Limit(LimitKind, Option<i64>),
}

impl Setting {
    /// What the row is called.
    pub fn name(&self) -> String {
        match self {
            Setting::Role(_) => "role".into(),
            Setting::Flag(k, _) => (*k).into(),
            Setting::AccessListMode(_) => "accessListMode".into(),
            Setting::Limit(k, _) => k.name().into(),
        }
    }

    /// Its value as shown.
    pub fn shown(&self) -> String {
        match self {
            Setting::Role(r) => r.to_string(),
            Setting::AccessListMode(m) => m.to_string(),
            Setting::Flag(_, on) => if *on { "✓ on" } else { "✗ off" }.into(),
            Setting::Limit(_, Some(-1)) => "unlimited".into(),
            Setting::Limit(_, Some(n)) => n.to_string(),
            Setting::Limit(_, None) => "default".into(),
        }
    }
}

/// The ACL's boolean flags, by wire name, in the order they are shown.
pub const ACL_FLAGS: [&str; 13] = [
    "anonReceive",
    "blocked",
    "createInvites",
    "didcommEnabled",
    "local",
    "receiveForwarded",
    "receiveMessages",
    "selfManageList",
    "selfManageReceiveQueueLimit",
    "selfManageSendQueueLimit",
    "sendForwarded",
    "sendMessages",
    "tspEnabled",
];

/// Each ACL flag of `acl` by wire name ([`ACL_FLAGS`] order); `None` when
/// the mediator did not report it.
pub fn acl_flags(acl: &get::MediatorAcl) -> [(&'static str, Option<bool>); 13] {
    [
        ("anonReceive", acl.anon_receive),
        ("blocked", acl.blocked),
        ("createInvites", acl.create_invites),
        ("didcommEnabled", acl.didcomm_enabled),
        ("local", acl.local),
        ("receiveForwarded", acl.receive_forwarded),
        ("receiveMessages", acl.receive_messages),
        ("selfManageList", acl.self_manage_list),
        (
            "selfManageReceiveQueueLimit",
            acl.self_manage_receive_queue_limit,
        ),
        ("selfManageSendQueueLimit", acl.self_manage_send_queue_limit),
        ("sendForwarded", acl.send_forwarded),
        ("sendMessages", acl.send_messages),
        ("tspEnabled", acl.tsp_enabled),
    ]
}

/// Set flag `name` (one of [`ACL_FLAGS`]) on `acl`.
fn set_flag(acl: &mut update::MediatorAcl, name: &str, on: bool) {
    let slot = match name {
        "anonReceive" => &mut acl.anon_receive,
        "blocked" => &mut acl.blocked,
        "createInvites" => &mut acl.create_invites,
        "didcommEnabled" => &mut acl.didcomm_enabled,
        "local" => &mut acl.local,
        "receiveForwarded" => &mut acl.receive_forwarded,
        "receiveMessages" => &mut acl.receive_messages,
        "selfManageList" => &mut acl.self_manage_list,
        "selfManageReceiveQueueLimit" => &mut acl.self_manage_receive_queue_limit,
        "selfManageSendQueueLimit" => &mut acl.self_manage_send_queue_limit,
        "sendForwarded" => &mut acl.send_forwarded,
        "sendMessages" => &mut acl.send_messages,
        "tspEnabled" => &mut acl.tsp_enabled,
        _ => return,
    };
    *slot = Some(on);
}

/// `account/get`'s role as `account/update` names it; `None` for one an
/// editor cannot assign (`mediator`, or a role this console doesn't know).
fn role_of(role: get::AccountType) -> Option<Role> {
    match role {
        get::AccountType::Standard => Some(Role::Standard),
        get::AccountType::Admin => Some(Role::Admin),
        get::AccountType::RootAdmin => Some(Role::RootAdmin),
        _ => None,
    }
}

fn mode_of(mode: get::MediatorAclAccessListMode) -> Option<AccessListMode> {
    match mode {
        get::MediatorAclAccessListMode::ExplicitAllow => Some(AccessListMode::ExplicitAllow),
        get::MediatorAclAccessListMode::ExplicitDeny => Some(AccessListMode::ExplicitDeny),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// What an edit changes, as `account/update`'s members: each `None` when
/// nothing in it changed.
#[derive(Clone, Debug, Default)]
pub struct AccountChanges {
    pub role: Option<Role>,
    pub acl: Option<update::MediatorAcl>,
    pub limits: Option<update::QueueLimits>,
}

/// An account being edited.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountEdit {
    /// The account hash.
    pub target: String,
    pub rows: Vec<Setting>,
    original: Vec<Setting>,
    pub selected: usize,
    /// Digits typed into the selected limit, not yet applied.
    pub typing: Option<String>,
}

impl AccountEdit {
    /// Rows for `account` (an `account/get` answer). `with_role` offers the
    /// role row, for a rootAdmin: only a rootAdmin may grant or change a
    /// privileged role.
    pub fn new(target: String, account: &get::Account, with_role: bool) -> Self {
        let mut rows = Vec::new();
        if with_role && let Some(role) = role_of(account.account_type) {
            rows.push(Setting::Role(role));
        }
        rows.extend(
            acl_flags(&account.acl)
                .into_iter()
                .filter_map(|(k, on)| on.map(|on| Setting::Flag(k, on))),
        );
        if let Some(mode) = account.acl.access_list_mode.and_then(mode_of) {
            rows.push(Setting::AccessListMode(mode));
        }
        let limits = account.queue_limits.as_ref();
        rows.push(Setting::Limit(
            LimitKind::Send,
            limits.and_then(|l| l.send_queue_limit),
        ));
        rows.push(Setting::Limit(
            LimitKind::Receive,
            limits.and_then(|l| l.receive_queue_limit),
        ));
        Self {
            target,
            original: rows.clone(),
            rows,
            selected: 0,
            typing: None,
        }
    }

    pub fn up(&mut self) {
        self.commit_typing();
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn down(&mut self) {
        self.commit_typing();
        self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
    }

    /// Toggle a flag, or step a role or access-list mode to its next value.
    pub fn toggle(&mut self) {
        fn next<T: Copy + PartialEq>(all: &[T], cur: T) -> T {
            let i = all.iter().position(|v| *v == cur).map_or(0, |i| i + 1);
            all[i % all.len()]
        }
        match self.rows.get_mut(self.selected) {
            Some(Setting::Flag(_, on)) => *on = !*on,
            Some(Setting::Role(r)) => *r = next(&ROLES, *r),
            Some(Setting::AccessListMode(m)) => *m = next(&MODES, *m),
            _ => {}
        }
    }

    /// A character typed on a limit row: digits, or `-` for `-1` (unlimited).
    pub fn type_char(&mut self, c: char) {
        if matches!(self.rows.get(self.selected), Some(Setting::Limit(..)))
            && (c.is_ascii_digit() || c == '-')
        {
            self.typing.get_or_insert_with(String::new).push(c);
        }
    }

    pub fn backspace(&mut self) {
        if let Some(t) = &mut self.typing {
            t.pop();
        }
    }

    /// Apply digits typed into a limit row.
    fn commit_typing(&mut self) {
        let Some(typed) = self.typing.take() else {
            return;
        };
        if let (Some(Setting::Limit(_, value)), Ok(n)) =
            (self.rows.get_mut(self.selected), typed.parse::<i64>())
            && n >= -1
        {
            *value = Some(n);
        }
    }

    /// Whether anything differs from the account as loaded.
    pub fn changed(&mut self) -> bool {
        self.commit_typing();
        self.rows != self.original
    }

    /// What changes, row by row: `(setting, was, now)`, to show before it is
    /// sent.
    pub fn diff(&mut self) -> Vec<(String, String, String)> {
        self.commit_typing();
        self.rows
            .iter()
            .zip(&self.original)
            .filter(|(now, was)| now != was)
            .map(|(now, was)| (now.name(), was.shown(), now.shown()))
            .collect()
    }

    /// What in the changes can cut the account off: a lower role, or
    /// `blocked` turned on. `None` when nothing does. Worth a warning when
    /// the account is the one the console is signed in as.
    pub fn risks_lockout(&self) -> Option<String> {
        let rank = |r: &Role| ROLES.iter().position(|x| x == r);
        let mut risks = Vec::new();
        for (now, was) in self.rows.iter().zip(&self.original) {
            match (was, now) {
                (Setting::Role(from), Setting::Role(to)) if rank(to) < rank(from) => {
                    risks.push(format!("Lowering the role {from} → {to}"));
                }
                (Setting::Flag("blocked", false), Setting::Flag(_, true)) => {
                    risks.push("Blocking it".to_string());
                }
                _ => {}
            }
        }
        (!risks.is_empty()).then(|| risks.join(" and "))
    }

    /// The `account/update` members that changed.
    pub fn changes(&mut self) -> AccountChanges {
        self.commit_typing();
        let mut role = None;
        let mut acl: Option<update::MediatorAcl> = None;
        let mut limits: Option<update::QueueLimits> = None;
        for (now, was) in self.rows.iter().zip(&self.original) {
            if now == was {
                continue;
            }
            match now {
                Setting::Role(r) => role = Some(*r),
                Setting::Flag(k, on) => set_flag(acl.get_or_insert_with(Default::default), k, *on),
                Setting::AccessListMode(m) => {
                    acl.get_or_insert_with(Default::default).access_list_mode = Some(*m);
                }
                Setting::Limit(kind, Some(n)) => {
                    let l = limits.get_or_insert_with(Default::default);
                    match kind {
                        LimitKind::Send => l.send_queue_limit = Some(*n),
                        LimitKind::Receive => l.receive_queue_limit = Some(*n),
                    }
                }
                Setting::Limit(_, None) => {}
            }
        }
        AccountChanges { role, acl, limits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account(role: &str) -> get::Account {
        serde_json::from_value(json!({
            "did": "abc",
            "accountType": role,
            "acl": {
                "sendMessages": true,
                "receiveMessages": true,
                "blocked": false,
                "accessListMode": "explicitDeny",
            },
            "queueLimits": { "sendQueueLimit": 100 },
        }))
        .expect("an account")
    }

    fn wire<T: serde::Serialize>(v: &Option<T>) -> serde_json::Value {
        serde_json::to_value(v).unwrap()
    }

    #[test]
    fn only_what_changed_is_sent() {
        let mut e = AccountEdit::new("abc".into(), &account("standard"), true);
        assert!(!e.changed());
        let none = e.changes();
        assert!(none.role.is_none() && none.acl.is_none() && none.limits.is_none());

        // Rows: role, blocked, receiveMessages, sendMessages, accessListMode,
        // sendQueueLimit, receiveQueueLimit.
        e.selected = 1;
        e.toggle(); // blocked on
        e.selected = 5;
        for c in "250".chars() {
            e.type_char(c);
        }
        let changes = e.changes();
        assert_eq!(changes.role, None);
        assert_eq!(wire(&changes.acl), json!({ "blocked": true }));
        assert_eq!(wire(&changes.limits), json!({ "sendQueueLimit": 250 }));
    }

    #[test]
    fn a_role_and_a_mode_cycle_and_minus_one_is_unlimited() {
        let mut e = AccountEdit::new("abc".into(), &account("standard"), true);
        e.toggle(); // role: standard -> admin
        e.selected = 4;
        e.toggle(); // mode: explicitDeny -> explicitAllow
        e.selected = 6;
        e.type_char('-');
        e.type_char('1');
        let changes = e.changes();
        assert_eq!(changes.role, Some(Role::Admin));
        assert_eq!(
            wire(&changes.acl),
            json!({ "accessListMode": "explicitAllow" })
        );
        assert_eq!(wire(&changes.limits), json!({ "receiveQueueLimit": -1 }));
        assert_eq!(e.rows[6].shown(), "unlimited");
    }

    #[test]
    fn the_changes_are_listed_before_they_are_sent() {
        let mut e = AccountEdit::new("abc".into(), &account("standard"), true);
        assert!(e.diff().is_empty());
        e.toggle(); // role: standard -> admin
        e.selected = 1;
        e.toggle(); // blocked on
        assert_eq!(
            e.diff(),
            [
                ("role".into(), "standard".into(), "admin".into()),
                ("blocked".into(), "✗ off".into(), "✓ on".into()),
            ]
        );
    }

    #[test]
    fn lowering_a_role_or_blocking_is_a_lockout_risk_and_raising_is_not() {
        let mut e = AccountEdit::new("abc".into(), &account("rootAdmin"), true);
        assert_eq!(e.risks_lockout(), None);
        e.toggle(); // rootAdmin -> standard (wraps)
        assert_eq!(
            e.risks_lockout().as_deref(),
            Some("Lowering the role rootAdmin → standard")
        );
        e.selected = 1;
        e.toggle(); // blocked on
        assert!(e.risks_lockout().unwrap().ends_with("and Blocking it"));

        let mut raise = AccountEdit::new("abc".into(), &account("standard"), true);
        raise.toggle(); // standard -> admin
        assert_eq!(raise.risks_lockout(), None);
    }

    #[test]
    fn without_the_role_row_the_role_cannot_change() {
        let e = AccountEdit::new("abc".into(), &account("standard"), false);
        assert!(!e.rows.iter().any(|r| matches!(r, Setting::Role(_))));
        // The mediator's own role is not one an editor assigns.
        let m = AccountEdit::new("abc".into(), &account("mediator"), true);
        assert!(!m.rows.iter().any(|r| matches!(r, Setting::Role(_))));
    }

    #[test]
    fn every_flag_name_round_trips_through_the_typed_acl() {
        for name in ACL_FLAGS {
            let mut acl = update::MediatorAcl::default();
            set_flag(&mut acl, name, true);
            let wire = serde_json::to_value(&acl).unwrap();
            assert_eq!(wire, json!({ name: true }), "{name}");
            let read: get::MediatorAcl = serde_json::from_value(wire).unwrap();
            let flags = acl_flags(&read);
            assert!(
                flags.iter().any(|(k, on)| *k == name && *on == Some(true)),
                "{name}"
            );
        }
    }
}
