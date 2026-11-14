//! What the console shows: the mediator's answers, kept as the typed Trust
//! Task structs they arrived as, and where the user is in them.
//!
//! [`State`] is the whole model. The screens render from it and nothing
//! else, so a screen can be drawn from fixtures without a mediator; the
//! only thing rendering writes back is each table's scroll position.

use std::collections::BTreeSet;
use std::time::Instant;

use affinidi_messaging_mediator_admin::{
    AddressBook, BulkRevokeOutcome, ConnState, GrantKey, GrantRevokeResult, MediatorConsole, Mode,
    audit_specs, config_specs, specs,
};
use chrono::{DateTime, Utc};
use ratatui::widgets::TableState;

use super::Tab;
use super::monitor::MonitorPane;
use super::popup::Popup;
use crate::logs::LogCapture;
use crate::quota::ColorDepth;

/// `messaging/stats/show`.
pub type StatsReport = specs::stats::show::v0_1::Response;
/// One account in the queue ranking (`messaging/queue/list`).
pub type QueueRow = specs::queue::list::v0_1::QueueSummary;
/// Both queues of one account (`messaging/queue/status`).
pub type QueueStatus = specs::queue::status::v0_1::Response;
/// One stored message's metadata (`messaging/message/list`).
pub type MessageRow = specs::message::list::v0_1::MessageMeta;
/// One audit-log entry (`audit/list`).
pub type AuditRow = audit_specs::list::v0_2::AuditEnvelope;
/// One account in the account list (`messaging/account/list`).
pub type AccountRow = specs::account::list::v0_2::Account;
/// One account's settings (`messaging/account/get`).
pub type AccountInfo = specs::account::get::v0_2::Account;
/// One configuration key (`config/show`).
pub type ConfigRow = config_specs::show::v0_1::ConfigField;
/// A page of live mux connections (`messaging/mux/connections`).
pub type MuxPage = specs::mux::connections::v0_1::Response;
/// One stored mux grant (`messaging/mux/admin-list`).
pub type GrantRow = specs::mux::admin_list::v0_1::AdminGrantView;

/// What the console knows of its own session, read once from the
/// [`MediatorConsole`] so the screens need no connection to draw.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    pub mode: Mode,
    pub did_hash: String,
    pub mediator_did: String,
    pub mediator_version: Option<String>,
    pub serves_operations: bool,
    pub can_patch_config: bool,
}

impl Session {
    pub fn of(console: &MediatorConsole) -> Self {
        Self {
            mode: console.mode(),
            did_hash: console.did_hash().to_string(),
            mediator_did: console.mediator_did().to_string(),
            mediator_version: console.mediator_version().map(str::to_string),
            serves_operations: console.serves_operations(),
            can_patch_config: console.can_patch_config(),
        }
    }

    pub fn admin(&self) -> bool {
        matches!(self.mode, Mode::Admin { .. })
    }

    pub fn root(&self) -> bool {
        matches!(self.mode, Mode::Admin { root: true })
    }
}

/// A row that keeps its identity across pages and refreshes, so the
/// selection can follow it.
pub(crate) trait Keyed {
    fn key(&self) -> &str;
}

impl Keyed for QueueRow {
    fn key(&self) -> &str {
        &self.did
    }
}
impl Keyed for MessageRow {
    fn key(&self) -> &str {
        &self.msg_id
    }
}
impl Keyed for AuditRow {
    fn key(&self) -> &str {
        &self.event_id
    }
}
impl Keyed for AccountRow {
    fn key(&self) -> &str {
        &self.did
    }
}
impl Keyed for ConfigRow {
    fn key(&self) -> &str {
        &self.key
    }
}

/// The rows of a list loaded so far, where its next page starts, and the
/// table showing it.
pub(crate) struct Paged<T> {
    pub rows: Vec<T>,
    pub next: Option<String>,
    pub pages: usize,
    pub table: TableState,
}

impl<T> Default for Paged<T> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            next: None,
            pages: 0,
            table: TableState::default().with_selected(Some(0)),
        }
    }
}

impl<T: Keyed> Paged<T> {
    /// Take in a page: the first (replacing the rows) or, with `more`, the
    /// next one. `order` sorts the rows; the selection stays on the same
    /// row (by its key) wherever that moved it.
    pub fn take(
        &mut self,
        rows: Vec<T>,
        next: Option<String>,
        more: bool,
        order: impl FnOnce(&mut Vec<T>),
    ) {
        let keep = self.selected().map(|r| r.key().to_string());
        if more {
            self.rows.extend(rows);
            self.pages += 1;
        } else {
            self.rows = rows;
            self.pages = 1;
        }
        self.next = next;
        order(&mut self.rows);
        reselect(&mut self.table, &self.rows, keep);
    }

    pub fn selected(&self) -> Option<&T> {
        self.rows.get(self.table.selected()?)
    }
}

impl<T> Paged<T> {
    /// Paged past its first page: a refresh would drop the rest, so it waits
    /// for `r`.
    pub fn paged(&self) -> bool {
        self.pages > 1
    }

    pub fn clear(&mut self) {
        self.rows.clear();
        self.next = None;
        self.pages = 0;
        self.table.select(Some(0));
    }
}

/// Select the row keyed `id` (the row selected before a refresh); when it
/// is gone, keep the position, within the rows there are.
pub(crate) fn reselect<T: Keyed>(state: &mut TableState, rows: &[T], id: Option<String>) {
    let found = id.and_then(|id| rows.iter().position(|r| r.key() == id));
    let i = found.unwrap_or_else(|| {
        state
            .selected()
            .unwrap_or(0)
            .min(rows.len().saturating_sub(1))
    });
    state.select(Some(i));
}

/// Which stored grants the Grants tab lists: a principal DID's, a member
/// DID's, or those between the two.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct GrantQuery {
    pub principal: Option<String>,
    pub member: Option<String>,
}

impl GrantQuery {
    pub fn is_empty(&self) -> bool {
        self.principal.is_none() && self.member.is_none()
    }

    /// The query the find popup's fields name: blank is none.
    pub fn from_fields(principal: &str, member: &str) -> Self {
        let did = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        GrantQuery {
            principal: did(principal),
            member: did(member),
        }
    }
}

/// A listed grant as a bulk revocation names it: its member DID and id.
pub(crate) fn grant_key(g: &GrantRow) -> GrantKey {
    GrantKey::new(g.did.as_str(), g.grant_id.as_str())
}

/// The grants marked on the Grants tab for a bulk revocation.
#[derive(Default, Debug)]
pub(crate) struct GrantMarks(BTreeSet<GrantKey>);

impl GrantMarks {
    /// Mark `key`, or unmark it when marked.
    pub fn toggle(&mut self, key: GrantKey) {
        if !self.0.remove(&key) {
            self.0.insert(key);
        }
    }

    /// Mark every grant in `listed`.
    pub fn mark_all(&mut self, listed: &[GrantRow]) {
        self.0.extend(listed.iter().map(grant_key));
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn contains(&self, key: &GrantKey) -> bool {
        self.0.contains(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Keep only the marks of grants in `listed`.
    pub fn retain_listed(&mut self, listed: &[GrantRow]) {
        let listed: BTreeSet<GrantKey> = listed.iter().map(grant_key).collect();
        self.0.retain(|k| listed.contains(k));
    }

    /// The marked grants, in the order `listed` shows them.
    pub fn in_listed_order(&self, listed: &[GrantRow]) -> Vec<GrantKey> {
        listed
            .iter()
            .map(grant_key)
            .filter(|k| self.0.contains(k))
            .collect()
    }

    /// After a bulk revocation: unmark what is gone — revoked, or no longer
    /// stored — and keep the rest marked, to try again.
    pub fn settle(&mut self, outcome: &BulkRevokeOutcome) {
        for (key, result) in &outcome.results {
            if matches!(
                result,
                GrantRevokeResult::Revoked | GrantRevokeResult::NotStored
            ) {
                self.0.remove(key);
            }
        }
    }
}

/// The Grants tab: what it lists, and what it has loaded of it.
#[derive(Default)]
pub(crate) struct Grants {
    pub query: GrantQuery,
    pub rows: Vec<GrantRow>,
    pub table: TableState,
    /// The listed member's current epoch, when the query names a member.
    pub epoch: Option<u64>,
    /// The cursor for the next page, when there is one.
    pub next: Option<String>,
    /// Grants marked for a bulk revocation.
    pub marks: GrantMarks,
}

impl Grants {
    pub fn selected(&self) -> Option<&GrantRow> {
        self.rows.get(self.table.selected()?)
    }
}

/// The queue ranking's sort keys: what the request names, what the title
/// says.
pub(crate) const SORTS: [(&str, &str); 4] = [
    ("count", "depth"),
    ("bytes", "bytes"),
    ("oldest", "oldest"),
    ("saturation", "saturation"),
];

/// Everything the screens draw.
pub(crate) struct State {
    pub session: Session,
    pub depth: ColorDepth,
    pub tab: Tab,

    pub stats: Option<StatsReport>,
    pub queues: Paged<QueueRow>,
    /// When the ranking shown was surveyed.
    pub queues_snapshot: Option<DateTime<Utc>>,
    pub queue_send: bool,
    /// Index into [`SORTS`].
    pub sort: usize,

    /// The account the Account tab shows: `None` is the console's own.
    pub target: Option<String>,
    pub status: Option<QueueStatus>,
    pub messages: Paged<MessageRow>,
    pub message_send: bool,
    /// The Account tab's account: role, ACL, limits.
    pub account_info: Option<AccountInfo>,

    pub audit: Paged<AuditRow>,
    pub accounts: Paged<AccountRow>,
    pub accounts_loaded: Option<Instant>,
    pub config: Paged<ConfigRow>,
    /// The last `messaging/mux/connections` page.
    pub mux: Option<MuxPage>,
    pub mux_table: TableState,
    pub grants: Grants,

    pub monitor: MonitorPane,
    pub popup: Option<Popup>,
    pub notice: Option<(String, bool)>,
    /// When `notice` was set; it gives way to the key hints after a while.
    pub notice_at: Option<Instant>,
    pub updated: Option<Instant>,

    /// Nicknames for account hashes.
    pub book: AddressBook,
    /// The host's log output, kept off the terminal while the console runs.
    pub logs: Option<LogCapture>,
    /// The connection's state (`None`: unknown, no websocket), and since when.
    pub link: Option<ConnState>,
    pub link_since: Instant,
    /// Table rows the screen showed last frame: a page, for PgUp / PgDn.
    pub page_rows: usize,
}

impl State {
    pub fn new(session: Session, tab: Tab, link: Option<ConnState>) -> Self {
        Self {
            session,
            depth: ColorDepth::detect(),
            tab,
            stats: None,
            queues: Paged::default(),
            queues_snapshot: None,
            queue_send: false,
            sort: 0,
            target: None,
            status: None,
            messages: Paged::default(),
            message_send: false,
            account_info: None,
            audit: Paged::default(),
            accounts: Paged::default(),
            accounts_loaded: None,
            config: Paged::default(),
            mux: None,
            mux_table: TableState::default().with_selected(Some(0)),
            grants: Grants {
                table: TableState::default().with_selected(Some(0)),
                ..Grants::default()
            },
            monitor: MonitorPane::new(),
            popup: None,
            notice: None,
            notice_at: None,
            updated: None,
            book: AddressBook::new(),
            logs: None,
            link,
            link_since: Instant::now(),
            page_rows: 10,
        }
    }

    /// Show `notice` in the footer for a while.
    pub fn set_notice(&mut self, text: impl Into<String>, bad: bool) {
        self.notice = Some((text.into(), bad));
        self.notice_at = Some(Instant::now());
    }

    /// The screens this session has.
    pub fn tabs(&self) -> Vec<Tab> {
        if self.session.admin() {
            vec![
                Tab::Dashboard,
                Tab::Queues,
                Tab::Account,
                Tab::Audit,
                Tab::Accounts,
                Tab::Config,
                // Last, so the other tabs keep their number keys.
                Tab::Mux,
                Tab::Grants,
            ]
        } else {
            vec![Tab::Account]
        }
    }

    /// The Account tab's account hash: the target, or the console's own.
    pub fn account_hash(&self) -> &str {
        self.target.as_deref().unwrap_or(&self.session.did_hash)
    }

    /// The Account tab's account as the user knows it.
    pub fn account_label(&self) -> String {
        match &self.target {
            Some(t) => super::format::label(&self.book, t),
            None => format!(
                "{} (you)",
                super::format::label(&self.book, &self.session.did_hash)
            ),
        }
    }

    /// The selected message's counterparty in the queue shown: its sender
    /// in the receive queue, its recipient in the send queue.
    pub fn selected_peer(&self) -> Option<String> {
        let m = self.messages.selected()?;
        let peer = if self.message_send { &m.to } else { &m.from };
        peer.as_ref().map(|p| p.to_string())
    }

    /// The selected live mux connection's principal DID.
    pub fn selected_principal(&self) -> Option<String> {
        let i = self.mux_table.selected()?;
        let c = self.mux.as_ref()?.connections.get(i)?;
        Some(c.principal.to_string())
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Typed rows for tests, from the JSON the mediator sends.
    use super::*;

    pub fn grant(member: &str, id: &str) -> GrantRow {
        serde_json::from_value(serde_json::json!({
            "did": member, "grantId": id, "principal": "did:example:p",
            "epoch": 0, "expiresAt": "2030-01-01T00:00:00Z",
            "signedAt": "2026-01-01T00:00:00Z", "scope": ["receive"], "state": "active",
        }))
        .expect("a grant row")
    }

    pub fn message(id: &str) -> MessageRow {
        serde_json::from_value(serde_json::json!({
            "msgId": id, "queue": "receive", "receivedAt": "2026-09-21T10:00:00Z", "size": 10,
        }))
        .expect("a message row")
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{grant, message};
    use super::*;

    #[test]
    fn the_find_popup_s_blank_fields_name_nothing() {
        let q = GrantQuery::from_fields("  did:example:p ", "");
        assert_eq!(q.principal.as_deref(), Some("did:example:p"));
        assert_eq!(q.member, None);
        assert!(GrantQuery::from_fields(" ", "").is_empty());
    }

    #[test]
    fn grants_are_marked_one_at_a_time_all_at_once_and_cleared() {
        let rows = [
            grant("did:ex:m1", "g1"),
            grant("did:ex:m1", "g2"),
            grant("did:ex:m2", "g1"),
        ];
        let mut marks = GrantMarks::default();
        assert!(marks.is_empty());

        // The same grant id under another member is another grant.
        marks.toggle(GrantKey::new("did:ex:m1", "g1"));
        assert!(marks.contains(&GrantKey::new("did:ex:m1", "g1")));
        assert!(!marks.contains(&GrantKey::new("did:ex:m2", "g1")));
        // Toggling again unmarks.
        marks.toggle(GrantKey::new("did:ex:m1", "g1"));
        assert!(marks.is_empty());

        marks.mark_all(&rows);
        assert_eq!(marks.len(), 3);
        // Marking all again marks nothing twice.
        marks.mark_all(&rows);
        assert_eq!(marks.len(), 3);
        marks.clear();
        assert!(marks.is_empty());
    }

    #[test]
    fn marks_follow_the_listing_and_are_revoked_in_its_order() {
        let rows = [
            grant("did:ex:m2", "g9"),
            grant("did:ex:m1", "g1"),
            grant("did:ex:m1", "g2"),
        ];
        let mut marks = GrantMarks::default();
        marks.toggle(GrantKey::new("did:ex:m1", "g2"));
        marks.toggle(GrantKey::new("did:ex:m2", "g9"));
        assert_eq!(
            marks.in_listed_order(&rows),
            [
                GrantKey::new("did:ex:m2", "g9"),
                GrantKey::new("did:ex:m1", "g2")
            ]
        );
        // A refresh that no longer lists a grant drops its mark.
        marks.retain_listed(&[grant("did:ex:m1", "g1"), grant("did:ex:m1", "g2")]);
        assert_eq!(marks.len(), 1);
        assert!(marks.contains(&GrantKey::new("did:ex:m1", "g2")));
    }

    #[test]
    fn after_a_bulk_revocation_only_the_grants_not_revoked_stay_marked() {
        use affinidi_messaging_mediator_admin::ConsoleError;
        let rows = [
            grant("did:ex:m", "revoked"),
            grant("did:ex:m", "gone"),
            grant("did:ex:root", "protected"),
            grant("did:ex:m", "lost"),
            grant("did:ex:m", "unsent"),
        ];
        let mut marks = GrantMarks::default();
        marks.mark_all(&rows);
        let key = |id: &str| {
            GrantKey::new(
                if id == "protected" {
                    "did:ex:root"
                } else {
                    "did:ex:m"
                },
                id,
            )
        };
        let outcome = BulkRevokeOutcome {
            results: vec![
                (key("revoked"), GrantRevokeResult::Revoked),
                (key("gone"), GrantRevokeResult::NotStored),
                (
                    key("protected"),
                    GrantRevokeResult::Refused(ConsoleError::Refused {
                        code: "e.p.messaging/mux/admin-revoke:protectedAccount".into(),
                        comment: "rootAdmin".into(),
                        current_epoch: None,
                    }),
                ),
                (
                    key("lost"),
                    GrantRevokeResult::Unconfirmed(ConsoleError::connect("sending", "closed")),
                ),
                (key("unsent"), GrantRevokeResult::NotAttempted),
            ],
        };
        marks.settle(&outcome);
        assert_eq!(
            marks.in_listed_order(&rows),
            [key("protected"), key("lost"), key("unsent")]
        );
    }

    #[test]
    fn a_refresh_keeps_the_selection_on_the_same_row() {
        let mut list: Paged<MessageRow> = Paged::default();
        list.take(
            vec![message("a"), message("b"), message("c")],
            None,
            false,
            |_| {},
        );
        list.table.select(Some(1));
        // "a" was delivered and a new one arrived: "b" moved up a row.
        list.take(
            vec![message("b"), message("c"), message("d")],
            None,
            false,
            |_| {},
        );
        assert_eq!(list.table.selected(), Some(0));
        // The selected row went: the position holds, within the rows left.
        list.table.select(Some(2));
        list.take(vec![message("x"), message("y")], None, false, |_| {});
        assert_eq!(list.table.selected(), Some(1));
    }

    #[test]
    fn a_page_replaces_or_adds_and_says_whether_more_wait() {
        let mut paged: Paged<MessageRow> = Paged::default();
        paged.take(vec![message("1")], Some("c1".into()), false, |_| {});
        assert!(!paged.paged());
        assert_eq!(paged.next.as_deref(), Some("c1"));
        paged.take(vec![message("2")], None, true, |_| {});
        assert!(paged.paged());
        assert_eq!(paged.rows.len(), 2);
        assert_eq!(paged.next, None);
    }
}
