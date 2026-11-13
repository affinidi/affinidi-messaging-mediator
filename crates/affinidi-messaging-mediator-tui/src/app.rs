//! The console application: state, keys, rendering and background work.
//!
//! [`App`] is a component, not a program. A host owns the terminal and the
//! event loop and calls [`App::handle_key`], [`App::apply`] and
//! [`App::render`]; [`App::run`] is that loop for hosts that want it done for
//! them (the `mediator-console` binary does). Work against the mediator runs
//! on background tasks and comes back as [`Update`]s, so rendering never
//! waits on the network.

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{
    AddressBook, BulkRevokeOutcome, ConnState, ConsoleError, GrantKey, GrantSelection,
    InspectedMessage, MediatorConsole, MembershipFilter, Mode, MonitorFilter, MonitorUpdate,
    MuxConnectionsQuery, PurgePlan, PurgeRequest, account_hash, revoke_summary, specs,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::account_edit::{AccountEdit, Setting};
use crate::keymap;
use crate::logs::{CaptureGuard, LogCapture, LogLevel};
use crate::quota::{ColorDepth, QuotaBar, quota_line};
use crate::requests::{InFlight, Job, Ticket};
use crate::tally::TrafficTally;

/// How often the current view refreshes on its own.
const REFRESH: Duration = Duration::from_secs(5);
/// The Accounts list is loaded once, then again this often (or on `r`): on a
/// large mediator it is many signed round trips.
const ACCOUNTS_EVERY: Duration = Duration::from_secs(300);
/// How often the mediator surveys its queues for the ranking (`queue/list`
/// answers from that survey, so asking more often only repeats it).
const SURVEY_EVERY: Duration = Duration::from_secs(60);
/// Rows asked for per page of a list.
const PAGE_ROWS: u32 = 200;
/// Accounts asked for per page.
const ACCOUNT_PAGE: u32 = 500;
/// The fastest the screen is redrawn for monitor traffic alone (~10 fps).
const FRAME: Duration = Duration::from_millis(100);
/// How long a notice stays in the footer before the key hints come back.
const NOTICE_FOR: Duration = Duration::from_secs(12);

/// A feed this long without even a heartbeat (the mediator sends one every
/// 30 s) is taken as gone, the way a mediator restart leaves it, and replaced.
const MONITOR_SILENCE: Duration = Duration::from_secs(90);
/// First wait before resubscribing the monitor; it doubles up to the cap.
const RESUBSCRIBE: Duration = Duration::from_secs(2);
const RESUBSCRIBE_MAX: Duration = Duration::from_secs(30);

/// Monitor lines kept for scrolling back; older ones are dropped.
const MONITOR_LINES: usize = 2000;

/// The console's screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tab {
    Dashboard,
    Queues,
    Account,
    Audit,
    /// Every account on the mediator (administrators).
    Accounts,
    /// The mediator's configuration; a rootAdmin can change its limits.
    Config,
    /// Live mux connections and the member DIDs each carries
    /// (administrators).
    Mux,
    /// Stored mux grants of a principal or member DID: list, revoke, advance
    /// a member's epoch (administrators).
    Grants,
}

impl Tab {
    pub(crate) fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Queues => "Queues",
            Tab::Account => "Account",
            Tab::Audit => "Audit",
            Tab::Accounts => "Accounts",
            Tab::Config => "Config",
            Tab::Mux => "Mux",
            Tab::Grants => "Grants",
        }
    }
}

/// Which stored grants the Grants tab lists: a principal DID's, a member
/// DID's, or those between the two.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GrantQuery {
    principal: Option<String>,
    member: Option<String>,
}

impl GrantQuery {
    fn is_empty(&self) -> bool {
        self.principal.is_none() && self.member.is_none()
    }
}

/// Grants asked for per page; a refresh asks for what is shown, up to the
/// mediator's 500.
const GRANT_PAGE: u64 = 100;

/// A list the console pages through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum List {
    /// The queue ranking (Dashboard, Queues).
    Queues,
    /// One queue's messages (Account).
    Messages,
    /// The audit log, newest first.
    Audit,
    /// Every account on the mediator.
    Accounts,
}

impl List {
    /// The member of a page that holds its rows.
    fn rows_key(self) -> &'static str {
        match self {
            List::Queues => "queues",
            List::Messages => "messages",
            List::Audit => "entries",
            List::Accounts => "accounts",
        }
    }

    /// The member of a row that identifies it across pages and refreshes.
    fn id_key(self) -> &'static str {
        match self {
            List::Queues | List::Accounts => "did",
            List::Messages => "msgId",
            List::Audit => "eventId",
        }
    }
}

/// The rows of a list loaded so far, and where its next page starts.
#[derive(Default)]
struct Paged {
    rows: Vec<Value>,
    next: Option<String>,
    pages: usize,
}

impl Paged {
    /// Take in a page: the first (replacing the rows) or the next one.
    fn take(&mut self, list: List, page: &Value, more: bool) {
        let rows = page[list.rows_key()]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if more {
            self.rows.extend(rows);
            self.pages += 1;
        } else {
            self.rows = rows;
            self.pages = 1;
        }
        self.next = page["nextCursor"].as_str().map(str::to_string);
    }

    /// Paged past its first page: a refresh would drop the rest, so it waits
    /// for `r`.
    fn paged(&self) -> bool {
        self.pages > 1
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// A result of background work, applied with [`App::apply`].
#[non_exhaustive]
pub enum Update {
    Stats(Result<Value, ConsoleError>),
    Status(Result<Value, ConsoleError>),
    /// A page of a list: the first (replacing what is shown) or, with
    /// `more`, the next one.
    Page {
        list: List,
        more: bool,
        result: Result<Value, ConsoleError>,
    },
    /// The console's connection to the mediator changed state.
    Connection(ConnState),
    /// The answer to a tagged request: applied only while the screen still
    /// wants it (the same account, queue or listing it was asked for).
    Tagged(Ticket, Box<Update>),
    /// The mediator's configuration fields.
    Config(Result<Value, ConsoleError>),
    /// A page of live mux connections.
    Mux(Result<Value, ConsoleError>),
    /// A page of stored mux grants for the Grants tab's query: the first
    /// page (replacing what is shown) or, with `more`, the next one.
    Grants {
        result: Result<Value, ConsoleError>,
        more: bool,
    },
    /// The marked grants' revocation, grant by grant.
    RevokedMarked(Result<BulkRevokeOutcome, ConsoleError>),
    /// A member DID's current mux epoch, read to confirm advancing it.
    Epoch {
        did: String,
        result: Result<u64, ConsoleError>,
    },
    /// The account on the Account tab, as `account/get` reports it.
    AccountInfo(Result<Value, ConsoleError>),
    /// The mediator's answer to a configuration change.
    Patched(Result<Value, ConsoleError>),
    Inspected(Box<Result<InspectedMessage, ConsoleError>>),
    PurgePreview(Result<PurgePlan, ConsoleError>),
    /// A finished action: what to tell the user.
    Done(Result<String, ConsoleError>),
    Monitor(MonitorUpdate),
    /// The monitor could not start, or was refused: it stays stopped.
    MonitorFailed(ConsoleError),
    /// The monitor's feed ended or went silent; it resubscribes `after` this.
    MonitorRetrying {
        reason: String,
        after: Duration,
    },
}

/// What the host should do after a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    Quit,
}

enum Popup {
    Text {
        title: String,
        body: String,
    },
    /// A message, scrolled `scroll` lines down; `y` copies it, `w` writes it
    /// to a file.
    Inspect {
        id: String,
        body: String,
        scroll: u16,
    },
    /// Every key that works here, scrolled `scroll` lines down.
    Help {
        scroll: u16,
    },
    ConfirmDelete {
        target: Option<String>,
        ids: Vec<String>,
        /// Whose message, from which queue, which one, from and to whom.
        about: Vec<String>,
    },
    ConfirmPurge(PurgePlan),
    /// Apply an account edit: what changes, and a warning when it can lock
    /// the console out of its own account.
    ConfirmAccount {
        edit: AccountEdit,
        who: String,
        changes: Vec<String>,
        warning: Option<String>,
    },
    /// Set a configuration key (`to` is `null` to reset its override).
    ConfirmPatch {
        key: String,
        from: String,
        to: Value,
        /// What was typed, to go back to editing.
        typed: Option<String>,
    },
    /// Name an account: `hash` is the selected account, if any; the user
    /// fills in its DID (optional when `hash` is known) and a nickname.
    Name {
        hash: Option<String>,
        did: String,
        name: String,
        /// Which field typing goes to: the name (true) or the DID.
        on_name: bool,
    },
    /// The address book, with the selected entry.
    Book {
        selected: usize,
    },
    /// Change one configuration key.
    EditConfig {
        key: String,
        value: String,
    },
    /// Change an account's role, ACL and queue limits.
    EditAccount(AccountEdit),
    /// The captured log, `back` rows up from its newest.
    Logs {
        back: usize,
    },
    /// Look up stored grants by principal and/or member DID.
    FindGrants {
        principal: String,
        member: String,
        /// Which field typing goes to: the member (true) or the principal.
        on_member: bool,
    },
    /// Revoke the grants a selection names.
    ConfirmRevoke(GrantSelection),
    /// Revoke the marked grants, each on its own.
    ConfirmRevokeMarked(Vec<GrantKey>),
    /// Advance member `did`'s epoch, voiding `epoch`.
    ConfirmBumpEpoch {
        did: String,
        epoch: u64,
    },
}

/// One line of the monitor pane. Events are kept raw and drawn on each frame,
/// so naming an account renames it in the lines already shown.
enum MonitorLine {
    Event(Value),
    /// A mux member attached to or detached from a principal's connection.
    Membership(Value),
    Note(Line<'static>),
    /// The feed was interrupted; one line however many attempts it takes.
    Retry {
        reason: String,
        attempts: u32,
    },
}

struct MonitorPane {
    visible: bool,
    failures_only: bool,
    lines: VecDeque<MonitorLine>,
    dropped: u64,
    gaps: u64,
    last_seen: Option<Instant>,
    watching: String,
    task: Option<JoinHandle<()>>,
    /// Totals since the monitor (re)started.
    tally: TrafficTally,
    /// Show the per-account totals instead of the live lines.
    show_totals: bool,
    /// Lines scrolled back from the newest; 0 follows new traffic.
    back: usize,
    /// Rows the pane showed last frame: a page, for scrolling.
    page: usize,
    /// When the monitor resubscribes, while it's between feeds.
    retry_at: Option<Instant>,
    /// The feed reported the connection down, and not yet back.
    link_down: bool,
}

/// The console application.
pub struct App {
    console: Arc<MediatorConsole>,
    depth: ColorDepth,
    tab: Tab,
    tx: mpsc::UnboundedSender<Update>,
    rx: mpsc::UnboundedReceiver<Update>,

    stats: Option<Value>,
    queues: Paged,
    /// When the ranking shown was surveyed, and for which ranking it is.
    queues_snapshot: Option<chrono::DateTime<chrono::Utc>>,
    queues_view: Option<String>,
    queues_fetched: Option<Instant>,
    queue_state: TableState,
    queue_send: bool,
    sort: usize,

    /// The account the Account tab shows: `None` is the console's own.
    target: Option<String>,
    status: Option<Value>,
    messages: Paged,
    message_state: TableState,
    message_send: bool,

    audit: Paged,
    audit_state: TableState,
    /// The last `messaging/mux/connections` page.
    mux: Value,
    mux_state: TableState,
    /// What the Grants tab lists, and what it has loaded of it.
    grant_query: GrantQuery,
    grants: Vec<Value>,
    grants_state: TableState,
    /// The listed member's current epoch, when the query names a member.
    grants_epoch: Option<u64>,
    /// The cursor for the next page, when there is one.
    grants_next: Option<String>,
    /// Grants marked for a bulk revocation.
    grant_marks: GrantMarks,
    accounts: Paged,
    accounts_loaded: Option<Instant>,
    accounts_state: TableState,
    config: Vec<Value>,
    config_state: TableState,
    /// The Account tab's account: role, ACL, limits.
    account_info: Option<Value>,
    monitor: MonitorPane,
    popup: Option<Popup>,
    notice: Option<(String, bool)>,
    /// When `notice` was set; it gives way to the key hints after [`NOTICE_FOR`].
    notice_at: Option<Instant>,
    updated: Option<Instant>,

    /// Nicknames for account hashes; saved to `book_path` when it is set.
    book: AddressBook,
    book_path: Option<PathBuf>,

    /// The host's log output, kept off the terminal while the console runs.
    logs: Option<(LogCapture, CaptureGuard)>,

    /// Background requests in flight, so late answers are dropped.
    inflight: InFlight,
    /// The mediator's account hash, to recognise the console's own traffic.
    mediator_hash: String,
    /// The connection's state (`None`: unknown, no websocket), and since when.
    link: Option<ConnState>,
    link_since: Instant,
    /// Table rows the screen showed last frame: a page, for PgUp / PgDn.
    page_rows: usize,
    /// Set while refreshing after a change: requests go out even when one
    /// is pending, since that one may predate the change.
    forcing: bool,
}

const SORTS: [(&str, &str); 4] = [
    ("count", "depth"),
    ("bytes", "bytes"),
    ("oldest", "oldest"),
    ("saturation", "saturation"),
];

impl App {
    /// A console application over a connected session.
    pub fn new(console: MediatorConsole) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let admin = matches!(console.mode(), Mode::Admin { .. });
        // A mediator too old for the operations tasks still serves the audit
        // log, so an administrator starts there rather than on a dashboard
        // that cannot fill.
        let tab = match (admin, console.serves_operations()) {
            (true, true) => Tab::Dashboard,
            (true, false) => Tab::Audit,
            (false, _) => Tab::Account,
        };
        // Every drop and reconnect, as the SDK reports it (R6.2).
        let link = console.connection_state();
        if let Some(mut state) = link.clone() {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(Update::Connection(*state.borrow_and_update()));
                while state.changed().await.is_ok() {
                    let now = *state.borrow_and_update();
                    if tx.send(Update::Connection(now)).is_err() {
                        return;
                    }
                }
            });
        }
        let mediator_hash = sha256_hex(console.mediator_did());
        let mut app = Self {
            console: Arc::new(console),
            depth: ColorDepth::detect(),
            tab,
            tx,
            rx,
            stats: None,
            queues: Paged::default(),
            queues_snapshot: None,
            queues_view: None,
            queues_fetched: None,
            queue_state: TableState::default().with_selected(Some(0)),
            queue_send: false,
            sort: 0,
            target: None,
            status: None,
            messages: Paged::default(),
            message_state: TableState::default().with_selected(Some(0)),
            message_send: false,
            audit: Paged::default(),
            audit_state: TableState::default().with_selected(Some(0)),
            mux: Value::Null,
            mux_state: TableState::default().with_selected(Some(0)),
            grant_query: GrantQuery::default(),
            grants: Vec::new(),
            grants_state: TableState::default().with_selected(Some(0)),
            grants_epoch: None,
            grants_next: None,
            grant_marks: GrantMarks::default(),
            accounts: Paged::default(),
            accounts_loaded: None,
            accounts_state: TableState::default().with_selected(Some(0)),
            config: Vec::new(),
            config_state: TableState::default().with_selected(Some(0)),
            account_info: None,
            monitor: MonitorPane {
                visible: false,
                failures_only: false,
                lines: VecDeque::new(),
                dropped: 0,
                gaps: 0,
                last_seen: None,
                watching: String::new(),
                task: None,
                tally: TrafficTally::new(Instant::now()),
                show_totals: false,
                back: 0,
                page: 0,
                retry_at: None,
                link_down: false,
            },
            popup: None,
            notice: None,
            notice_at: None,
            updated: None,
            book: AddressBook::new(),
            book_path: None,
            logs: None,
            inflight: InFlight::default(),
            mediator_hash,
            link: link.map(|s| *s.borrow()),
            link_since: Instant::now(),
            page_rows: 10,
            forcing: false,
        };
        app.know_self();
        app.refresh();
        app
    }

    /// Keep the host's log output off the screen while the console runs, and
    /// show it on request (`l`) instead. Give the same capture to the host's
    /// `tracing` subscriber as its writer; see [`LogCapture`].
    pub fn with_logs(mut self, logs: LogCapture) -> Self {
        let guard = logs.hold();
        self.logs = Some((logs, guard));
        self
    }

    /// Resolves when a log line was captured, so a host running its own loop
    /// knows to redraw. Never resolves without [`App::with_logs`].
    pub async fn log_changed(&self) {
        match &self.logs {
            Some((logs, _)) => logs.changed().await,
            None => std::future::pending().await,
        }
    }

    /// Show `notice` in the footer for a while.
    fn set_notice(&mut self, notice: (String, bool)) {
        self.notice = Some(notice);
        self.notice_at = Some(Instant::now());
    }

    /// Use `book` for account nicknames, saving changes to `path` when given.
    /// The console's own account and the mediator are named automatically
    /// unless the book names them.
    pub fn with_address_book(mut self, book: AddressBook, path: Option<PathBuf>) -> Self {
        self.book = book;
        self.book_path = path;
        self.know_self();
        self
    }

    fn know_self(&mut self) {
        let own = self.console.did().to_string();
        self.book.know(&own, "you");
        let mediator = self.console.mediator_did().to_string();
        self.book.know(&mediator, "mediator");
    }

    /// Text pasted into the console (bracketed paste): goes to the field being
    /// edited, if any. Control characters (line breaks) are dropped.
    pub fn handle_paste(&mut self, text: &str) {
        let clean = |t: &str| -> String { t.trim().chars().filter(|c| !c.is_control()).collect() };
        if let Some(Popup::EditConfig { value, .. }) = &mut self.popup {
            value.push_str(&clean(text));
            return;
        }
        if let Some(Popup::FindGrants {
            principal,
            member,
            on_member,
        }) = &mut self.popup
        {
            let field = if *on_member { member } else { principal };
            field.push_str(&clean(text));
            return;
        }
        if let Some(Popup::Name {
            did, name, on_name, ..
        }) = &mut self.popup
        {
            let clean: String = text.chars().filter(|c| !c.is_control()).collect();
            if *on_name {
                name.push_str(&clean);
            } else {
                did.push_str(clean.trim());
            }
        }
    }

    /// The account the user is looking at, to name with `n`.
    fn account_in_view(&self) -> Option<String> {
        match self.tab {
            Tab::Queues | Tab::Dashboard => self.selected_queue_did(),
            Tab::Accounts => self.selected_account_did(),
            Tab::Account => self
                .selected_message_field(if self.message_send { "to" } else { "from" })
                .or_else(|| self.target.clone())
                .or_else(|| Some(self.console.did_hash().to_string())),
            Tab::Grants => self.selected_grant_field("did").map(|d| account_hash(&d)),
            Tab::Audit | Tab::Config | Tab::Mux => None,
        }
    }

    fn name_popup(&self, hash: Option<String>) -> Popup {
        let entry = hash.as_deref().and_then(|h| self.book.lookup(h));
        Popup::Name {
            did: entry
                .filter(|e| !e.is_bare_hash())
                .map(|e| e.did.clone())
                .unwrap_or_default(),
            name: entry.map(|e| e.name.clone()).unwrap_or_default(),
            on_name: hash.is_some(),
            hash,
        }
    }

    /// Save a Name popup. Returns the popup to keep open when the input needs
    /// correcting.
    fn save_name(&mut self, hash: Option<String>, did: String, name: String) -> Option<Popup> {
        let (did, name) = (did.trim().to_string(), name.trim().to_string());
        let key = match (&hash, did.is_empty()) {
            (_, false) => {
                if let Some(h) = &hash
                    && account_hash(&did) != *h
                {
                    self.set_notice((
                        format!(
                            "that DID is account {}, not {}",
                            short(&account_hash(&did)),
                            short(h)
                        ),
                        true,
                    ));
                    return Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: false,
                    });
                }
                did
            }
            (Some(h), true) => h.clone(),
            (None, true) => {
                self.set_notice(("paste a DID (or an account hash) to name".into(), true));
                return Some(Popup::Name {
                    hash,
                    did,
                    name,
                    on_name: false,
                });
            }
        };
        let hash = account_hash(&key);
        if name.is_empty() {
            self.book.remove(&hash);
            self.set_notice((format!("{} unnamed", short(&hash)), false));
        } else {
            self.book.insert(&key, &name);
            self.set_notice((format!("{} is now {name}", short(&hash)), false));
        }
        self.save_book();
        None
    }

    fn save_book(&mut self) {
        if let Some(path) = &self.book_path
            && let Err(e) = self.book.save(path)
        {
            self.set_notice((format!("address book not saved: {e}"), true));
        }
    }

    /// Show one account on the Account tab — `None` is the console's own.
    pub fn open_account(&mut self, did_hash: Option<String>) {
        self.tab = Tab::Account;
        self.set_target(did_hash);
    }

    /// Point the Account tab at another account (or queue): nothing of the
    /// last one stays on screen, and answers still on their way for it are
    /// dropped when they arrive.
    fn set_target(&mut self, did_hash: Option<String>) {
        // The console's own account is `None`, however it was named.
        let did_hash = did_hash.filter(|h| h != self.console.did_hash());
        if did_hash != self.target {
            self.status = None;
            self.account_info = None;
        }
        self.target = did_hash;
        self.messages.clear();
        self.message_state.select(Some(0));
        self.refresh();
    }

    /// The view a job's answer belongs to, as it stands now: an answer asked
    /// for another one is dropped.
    fn view_of(&self, job: Job) -> String {
        let account = self.target.clone().unwrap_or_default();
        let queue = if self.message_send { "send" } else { "receive" };
        match job {
            Job::Status | Job::AccountInfo => account,
            Job::Messages | Job::More(List::Messages) => format!("{account}/{queue}"),
            // A popup for an account the user has left would be about the
            // wrong one.
            Job::Inspect | Job::PurgePreview if self.tab == Tab::Account => {
                format!("{account}/{queue}")
            }
            Job::Inspect | Job::PurgePreview => "elsewhere".into(),
            Job::Queues | Job::More(List::Queues) => self.queue_view(),
            Job::Grants => format!("{:?}", self.grant_query),
            _ => String::new(),
        }
    }

    /// Which ranking the queue list shows.
    fn queue_view(&self) -> String {
        format!("{}/{}", self.queue_send, self.sort)
    }

    /// Run `work` in the background for `job`, tagged so its answer is
    /// applied only while the screen still wants it. `force` sends it even
    /// while the same request is pending (a user's action); otherwise a
    /// pending one is waited for.
    fn request<F, Fut>(&mut self, job: Job, force: bool, work: F)
    where
        F: FnOnce(Arc<MediatorConsole>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Update> + Send + 'static,
    {
        let view = self.view_of(job);
        let now = Instant::now();
        let ticket = if force || self.forcing {
            self.inflight.force(job, view, now)
        } else {
            match self.inflight.begin(job, view, now) {
                Some(ticket) => ticket,
                None => return,
            }
        };
        self.spawn(move |c| async move { Update::Tagged(ticket, Box::new(work(c).await)) });
    }

    /// Show the stored mux grants of a `principal` DID, a `member` DID, or
    /// those between the two on the Grants tab. Naming neither shows how to
    /// look some up.
    pub fn open_grants_of(&mut self, principal: Option<String>, member: Option<String>) {
        self.open_grants(GrantQuery { principal, member });
    }

    /// Force a colour depth (the default is detected from the environment).
    pub fn with_color_depth(mut self, depth: ColorDepth) -> Self {
        self.depth = depth;
        self
    }

    fn admin(&self) -> bool {
        matches!(self.console.mode(), Mode::Admin { .. })
    }

    fn tabs(&self) -> Vec<Tab> {
        if self.admin() {
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

    /// Run `work` in the background and deliver its result as an update.
    fn spawn<F, Fut>(&self, work: F)
    where
        F: FnOnce(Arc<MediatorConsole>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Update> + Send + 'static,
    {
        let (console, tx) = (self.console.clone(), self.tx.clone());
        tokio::spawn(async move {
            let _ = tx.send(work(console).await);
        });
    }

    /// Reload what the current screen shows.
    pub fn refresh(&mut self) {
        // On a mediator too old to serve them, these screens explain that
        // instead of asking (see `render_unsupported`).
        if !self.console.serves_operations()
            && !matches!(self.tab, Tab::Audit | Tab::Accounts | Tab::Config)
        {
            self.updated = Some(Instant::now());
            return;
        }
        match self.tab {
            Tab::Dashboard => {
                self.request(Job::Stats, false, |c| async move {
                    Update::Stats(to_value(c.stats().await))
                });
                self.load_queues(false);
            }
            Tab::Queues => self.load_queues(false),
            Tab::Account => {
                let target = self.target.clone();
                let t = target.clone();
                self.request(Job::Status, false, move |c| async move {
                    Update::Status(to_value(c.queue_status(t, Some(10)).await))
                });
                let t = target.clone();
                self.request(Job::AccountInfo, false, move |c| async move {
                    Update::AccountInfo(to_value(c.account_of(t).await))
                });
                // Paged past the first page, the list stays as loaded until
                // `r`: a refresh would drop what was paged in.
                if !self.messages.paged() {
                    self.load_messages(None);
                }
            }
            Tab::Audit if !self.audit.paged() => self.load_audit(None),
            Tab::Audit => {}
            Tab::Accounts => {
                let due = self
                    .accounts_loaded
                    .is_none_or(|at| at.elapsed() >= ACCOUNTS_EVERY && !self.accounts.paged());
                if due {
                    self.load_accounts(None);
                }
            }
            Tab::Mux => self.request(Job::Mux, false, |c| async move {
                // One page: up to 100 connections and 1000 members. The
                // screen says when there are more.
                let query = MuxConnectionsQuery::all().limit(100);
                Update::Mux(to_value(c.mux_connections(query).await))
            }),
            // Again from the first page, as many as are shown.
            Tab::Grants => {
                let limit = (self.grants.len() as u64).clamp(GRANT_PAGE, 500);
                self.load_grants(None, limit);
            }
            Tab::Config => self.request(Job::Config, false, |c| async move {
                Update::Config(to_value(c.config().await))
            }),
        }
    }

    /// Reload after something changed (a delete, a purge, a patch, a
    /// reconnect): from the first page, without waiting on requests sent
    /// before the change.
    fn refresh_after_change(&mut self) {
        self.forcing = true;
        self.reload();
        self.forcing = false;
    }

    /// Reload the current screen from scratch (`r`): lists go back to their
    /// first page, and nothing waits for a schedule.
    pub fn reload(&mut self) {
        match self.tab {
            Tab::Dashboard | Tab::Queues => self.queues_fetched = None,
            Tab::Account => self.messages.pages = 0,
            Tab::Audit => self.audit.pages = 0,
            Tab::Accounts => self.accounts_loaded = None,
            _ => {}
        }
        self.refresh();
    }

    /// Whether the queue ranking is worth asking for again: it is another
    /// ranking, or the mediator has surveyed its queues since (it does so
    /// about once a minute; asking in between gets the same answer).
    fn queues_due(&self) -> bool {
        if self.queues_view.as_deref() != Some(self.queue_view().as_str()) {
            return true;
        }
        let Some(fetched) = self.queues_fetched else {
            return true;
        };
        if self.queues.paged() {
            return false;
        }
        match self.queues_snapshot {
            Some(at) => survey_due(at, chrono::Utc::now(), fetched.elapsed()),
            None => fetched.elapsed() >= REFRESH,
        }
    }

    /// The queue ranking: its first page when `force`d or due, else nothing.
    fn load_queues(&mut self, force: bool) {
        if !force && !self.queues_due() {
            return;
        }
        self.queues_fetched = Some(Instant::now());
        self.queues_view = Some(self.queue_view());
        self.queue_page(None);
    }

    fn queue_page(&mut self, cursor: Option<String>) {
        let send = self.queue_send;
        let sort = self.sort;
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Queues)
        } else {
            Job::Queues
        };
        self.request(job, more, move |c| async move {
            use specs::queue::list::v0_1::{PayloadSort, Queue};
            let queue = if send { Queue::Send } else { Queue::Receive };
            let sort = match sort {
                1 => PayloadSort::Bytes,
                2 => PayloadSort::Oldest,
                3 => PayloadSort::Saturation,
                _ => PayloadSort::Count,
            };
            let result = to_value(
                c.queues(Some(queue), Some(sort), cursor, Some(PAGE_ROWS))
                    .await,
            );
            Update::Page {
                list: List::Queues,
                more,
                result,
            }
        });
    }

    /// A page of the Account tab's queue: the first, or the one at `cursor`.
    fn load_messages(&mut self, cursor: Option<String>) {
        let target = self.target.clone();
        let send = self.message_send;
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Messages)
        } else {
            Job::Messages
        };
        self.request(job, more, move |c| async move {
            let queue = if send {
                specs::message::list::v0_1::Queue::Send
            } else {
                specs::message::list::v0_1::Queue::Receive
            };
            let result = to_value(
                c.messages(target, queue, None, cursor, Some(PAGE_ROWS))
                    .await,
            );
            Update::Page {
                list: List::Messages,
                more,
                result,
            }
        });
    }

    /// A page of the audit log: the newest, or the one at `cursor`.
    fn load_audit(&mut self, cursor: Option<String>) {
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Audit)
        } else {
            Job::Audit
        };
        self.request(job, more, move |c| async move {
            let result = to_value(c.audit(cursor, Some(PAGE_ROWS)).await);
            Update::Page {
                list: List::Audit,
                more,
                result,
            }
        });
    }

    /// A page of the account list: the first, or the one at `cursor`.
    fn load_accounts(&mut self, cursor: Option<String>) {
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Accounts)
        } else {
            self.accounts_loaded = Some(Instant::now());
            Job::Accounts
        };
        self.request(job, more, move |c| async move {
            let page = c.accounts(cursor, Some(ACCOUNT_PAGE)).await;
            Update::Page {
                list: List::Accounts,
                more,
                result: to_value(page),
            }
        });
    }

    /// The next page of the list on screen, when it has one (`]`, or reaching
    /// its last row).
    fn load_more(&mut self) {
        let list = match self.tab {
            Tab::Dashboard | Tab::Queues => List::Queues,
            Tab::Account => List::Messages,
            Tab::Audit => List::Audit,
            Tab::Accounts => List::Accounts,
            Tab::Grants => {
                match self.grants_next.clone() {
                    Some(cursor) => self.load_grants(Some(cursor), GRANT_PAGE),
                    None => self.set_notice(("no more grants".into(), false)),
                }
                return;
            }
            _ => return,
        };
        if self.inflight.is_pending(Job::More(list)) {
            return;
        }
        let next = self.paged(list).next.clone();
        match (list, next) {
            (_, None) => self.set_notice(("that's all of them".into(), false)),
            (List::Queues, Some(c)) => self.queue_page(Some(c)),
            (List::Messages, Some(c)) => self.load_messages(Some(c)),
            (List::Audit, Some(c)) => self.load_audit(Some(c)),
            (List::Accounts, Some(c)) => self.load_accounts(Some(c)),
        }
    }

    fn paged(&self, list: List) -> &Paged {
        match list {
            List::Queues => &self.queues,
            List::Messages => &self.messages,
            List::Audit => &self.audit,
            List::Accounts => &self.accounts,
        }
    }

    /// A page of the Grants tab's query: from its start, or from `cursor`
    /// (then added to what is shown). Nothing while there is no query.
    fn load_grants(&mut self, cursor: Option<String>, limit: u64) {
        if self.grant_query.is_empty() {
            return;
        }
        let GrantQuery { principal, member } = self.grant_query.clone();
        let more = cursor.is_some();
        let work = move |c: Arc<MediatorConsole>| async move {
            let page = c
                .mux_grants(principal.as_deref(), member.as_deref(), cursor, Some(limit))
                .await;
            Update::Grants {
                result: to_value(page),
                more,
            }
        };
        if more {
            // Added to what is shown, so not tied to a refresh.
            self.spawn(work);
        } else {
            self.request(Job::Grants, false, work);
        }
    }

    /// Show the Grants tab for `query`, from its first page.
    fn open_grants(&mut self, query: GrantQuery) {
        self.grant_query = query;
        self.grants.clear();
        self.grants_epoch = None;
        self.grants_next = None;
        self.grant_marks.clear();
        self.grants_state.select(Some(0));
        self.tab = Tab::Grants;
        self.refresh();
    }

    /// The grant under the cursor, as a bulk revocation names it.
    fn selected_grant_key(&self) -> Option<GrantKey> {
        let i = self.grants_state.selected()?;
        grant_key(self.grants.get(i)?)
    }

    fn selected_grant_field(&self, field: &str) -> Option<String> {
        let i = self.grants_state.selected()?;
        self.grants.get(i)?[field].as_str().map(str::to_string)
    }

    /// Read member `did`'s current epoch, to confirm advancing it.
    fn ask_bump_epoch(&self, did: String) {
        self.spawn(move |c| async move {
            let result = c.mux_epoch(&did).await;
            Update::Epoch { did, result }
        });
    }

    /// Apply the result of background work.
    pub fn apply(&mut self, update: Update) {
        let ok = |this: &mut Self| this.updated = Some(Instant::now());
        match update {
            Update::Tagged(ticket, inner) => {
                let latest = self.inflight.finish(&ticket);
                if latest && ticket.view == self.view_of(ticket.job) {
                    self.apply(*inner);
                } else if latest && matches!(ticket.job, Job::PurgePreview | Job::Inspect) {
                    // The user moved on before it came: a popup now would be
                    // about something no longer on screen.
                    self.set_notice((
                        "that answer was for another account or queue; ask again here".into(),
                        true,
                    ));
                }
            }
            Update::Connection(state) => self.link_changed(state),
            Update::Stats(r) => match r {
                Ok(v) => {
                    self.stats = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Page { list, more, result } => match result {
                Ok(v) => {
                    self.take_page(list, &v, more);
                    ok(self)
                }
                Err(e) => {
                    // Not loaded after all: try again on the next refresh
                    // rather than in five minutes.
                    if list == List::Accounts && !more {
                        self.accounts_loaded = None;
                    }
                    self.error(e)
                }
            },
            Update::Status(r) => match r {
                Ok(v) => {
                    self.status = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Mux(r) => match r {
                Ok(v) => {
                    self.mux = v;
                    let len = self.mux["connections"].as_array().map_or(0, Vec::len);
                    if self.mux_state.selected().is_none_or(|i| i >= len) {
                        self.mux_state.select(Some(0));
                    }
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Grants { result, more } => match result {
                Ok(v) => {
                    let page = v["grants"].as_array().cloned().unwrap_or_default();
                    if more {
                        self.grants.extend(page);
                    } else {
                        self.grants = page;
                        // A grant no longer listed can't be seen, so it
                        // can't stay marked.
                        self.grant_marks.retain_listed(&self.grants);
                    }
                    self.grants_epoch = v["epoch"].as_u64();
                    self.grants_next = v["nextCursor"].as_str().map(str::to_string);
                    let len = self.grants.len();
                    if self.grants_state.selected().is_none_or(|i| i >= len) {
                        self.grants_state.select(Some(0));
                    }
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::RevokedMarked(r) => {
                match r {
                    Ok(outcome) => self.revoked_marked(outcome),
                    Err(e) => self.error(e),
                }
                self.refresh_after_change();
            }
            Update::Epoch { did, result } => match result {
                Ok(epoch) => self.popup = Some(Popup::ConfirmBumpEpoch { did, epoch }),
                Err(e) => self.error(e),
            },
            Update::AccountInfo(r) => match r {
                Ok(v) => {
                    self.account_info = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Config(r) => match r {
                Ok(v) => {
                    let mut fields = v["fields"].as_array().cloned().unwrap_or_default();
                    // Limits first (they are what can be changed), then the rest.
                    fields.sort_by_key(|f| {
                        let key = f["key"].as_str().unwrap_or("").to_string();
                        (!key.starts_with("limits."), key)
                    });
                    let keep = selected_id(&self.config, &self.config_state, "key");
                    self.config = fields;
                    reselect(&mut self.config_state, &self.config, "key", keep);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Patched(r) => {
                match r {
                    Ok(v) => self.set_notice(patch_summary(&v)),
                    Err(e) => self.error(e),
                }
                self.refresh_after_change();
            }
            Update::Inspected(r) => match *r {
                // Over whatever else is open: the user asked for it just now.
                Ok(m) => self.popup = Some(inspect_popup(&m)),
                Err(e) => self.error(e),
            },
            Update::PurgePreview(r) => match r {
                Ok(plan) if plan.matched == 0 => {
                    self.set_notice(("nothing to purge".into(), false))
                }
                Ok(plan) => self.popup = Some(Popup::ConfirmPurge(plan)),
                Err(e) => self.error(e),
            },
            Update::Done(r) => {
                match r {
                    Ok(msg) => self.set_notice((msg, false)),
                    Err(e) => self.error(e),
                }
                self.refresh_after_change();
            }
            Update::Monitor(u) => self.monitor_update(u),
            Update::MonitorFailed(e) => {
                self.monitor.task = None;
                self.monitor.retry_at = None;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── monitor stopped: {e} ──"),
                    Style::default().fg(Color::Red),
                )));
                self.error(e);
            }
            Update::MonitorRetrying { reason, after } => {
                self.monitor.retry_at = Some(Instant::now() + after);
                let attempts = match self.monitor.lines.back() {
                    Some(MonitorLine::Retry { attempts, .. }) => {
                        let n = *attempts;
                        self.monitor.lines.pop_back();
                        n + 1
                    }
                    _ => 1,
                };
                self.monitor
                    .lines
                    .push_back(MonitorLine::Retry { reason, attempts });
            }
        }
    }

    /// Take in a page of `list`, keeping the selection on the same row (by
    /// its id) wherever the refresh moved it.
    fn take_page(&mut self, list: List, page: &Value, more: bool) {
        let key = list.id_key();
        let (paged, state) = match list {
            List::Queues => (&mut self.queues, &mut self.queue_state),
            List::Messages => (&mut self.messages, &mut self.message_state),
            List::Audit => (&mut self.audit, &mut self.audit_state),
            List::Accounts => (&mut self.accounts, &mut self.accounts_state),
        };
        let keep = selected_id(&paged.rows, state, key);
        paged.take(list, page, more);
        match list {
            List::Queues if !more => {
                self.queues_snapshot = page["snapshotAt"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc));
            }
            List::Accounts => {
                let book = &self.book;
                self.accounts
                    .rows
                    .sort_by_cached_key(|a| account_order(a, book));
            }
            _ => {}
        }
        let (paged, state) = match list {
            List::Queues => (&self.queues, &mut self.queue_state),
            List::Messages => (&self.messages, &mut self.message_state),
            List::Audit => (&self.audit, &mut self.audit_state),
            List::Accounts => (&self.accounts, &mut self.accounts_state),
        };
        reselect(state, &paged.rows, key, keep);
    }

    /// The connection went down or came back: say so in the header, the
    /// monitor and the footer, and reload once it is back.
    fn link_changed(&mut self, state: ConnState) {
        let was = self.link.replace(state);
        if was == Some(state) {
            return;
        }
        let down_for = self.link_since.elapsed();
        self.link_since = Instant::now();
        match state {
            ConnState::Disconnected => {
                self.monitor_note(
                    "── connection to the mediator lost — reconnecting ──".into(),
                    Color::Red,
                );
                self.set_notice(("connection to the mediator lost; reconnecting".into(), true));
            }
            ConnState::Connected if was == Some(ConnState::Disconnected) => {
                self.monitor_note(
                    format!(
                        "── reconnected to the mediator after {} ──",
                        human_secs(Some(down_for.as_secs()))
                    ),
                    Color::Green,
                );
                self.set_notice(("reconnected to the mediator".into(), false));
                self.refresh_after_change();
            }
            _ => {}
        }
    }

    /// A note line in the monitor pane (kept even while it is hidden).
    fn monitor_note(&mut self, text: String, color: Color) {
        let before = self.monitor.lines.len();
        self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
            text,
            Style::default().fg(color),
        )));
        self.monitor_lines_added(before);
    }

    /// Bookkeeping after lines were added to the monitor: a view scrolled
    /// back stays on what it shows, and the oldest lines go past the limit.
    fn monitor_lines_added(&mut self, before: usize) {
        if self.monitor.back > 0 {
            self.monitor.back += self.monitor.lines.len() - before;
        }
        while self.monitor.lines.len() > MONITOR_LINES {
            self.monitor.lines.pop_front();
        }
        self.scroll_monitor(0);
    }

    /// Wait for the next result of background work — for a host running its
    /// own loop. Apply it with [`App::apply`].
    pub async fn next_update(&mut self) -> Option<Update> {
        self.rx.recv().await
    }

    /// Report a bulk revocation: a summary, and every grant that was not
    /// revoked with why. Those stay marked, to try again; the rest are gone.
    fn revoked_marked(&mut self, outcome: BulkRevokeOutcome) {
        let summary = outcome.summary();
        self.grant_marks.settle(&outcome);
        if outcome.all_revoked() {
            self.set_notice((summary, false));
            return;
        }
        // Each grant not revoked, by its short id and its parties' names.
        let failures: Vec<String> = outcome
            .results
            .iter()
            .filter(|(_, r)| !r.is_revoked())
            .map(|(key, result)| {
                let principal = self
                    .grants
                    .iter()
                    .find(|g| grant_key(g).as_ref() == Some(key))
                    .and_then(|g| g["principal"].as_str())
                    .map(|p| format!(" → {}", did_label(&self.book, p)))
                    .unwrap_or_default();
                format!(
                    "• grant {} ({}{principal}): {}",
                    short(&key.grant_id),
                    did_label(&self.book, &key.member),
                    result.describe()
                )
            })
            .collect();
        self.set_notice((summary.clone(), true));
        self.popup = Some(Popup::Text {
            title: " Not every grant was revoked ".into(),
            body: format!(
                "{summary}.\n\n{}\n\nThose not revoked stay marked.",
                failures.join("\n")
            ),
        });
    }

    fn error(&mut self, e: ConsoleError) {
        // In plain words where the refusal has them (epoch mismatches,
        // protected accounts, permissions); otherwise as it reads.
        self.set_notice((e.explain(), true));
    }

    // ─── Keys ────────────────────────────────────────────────────────────

    /// Handle a key press.
    pub fn handle_key(&mut self, key: KeyEvent) -> Control {
        if key.kind != KeyEventKind::Press {
            return Control::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Control::Quit;
        }
        if let Some(popup) = self.popup.take() {
            self.popup_key(popup, key.code);
            return Control::Continue;
        }
        match key.code {
            // Only `q` (and Ctrl-C) quit: Esc closes popups, and one Esc too
            // many must not end the session.
            KeyCode::Char('q') => return Control::Quit,
            KeyCode::Esc => {}
            KeyCode::Char('?') => self.popup = Some(Popup::Help { scroll: 0 }),
            KeyCode::Char('y') => self.copy_selected(),
            KeyCode::Char(']') => self.load_more(),
            KeyCode::Char(c @ '1'..='8') => {
                if let Some(tab) = self.tabs().get((c as u8 - b'1') as usize) {
                    self.tab = *tab;
                    self.refresh();
                }
            }
            KeyCode::Tab => {
                let tabs = self.tabs();
                let i = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = tabs[(i + 1) % tabs.len()];
                self.refresh();
            }
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('n') => self.popup = Some(self.name_popup(self.account_in_view())),
            KeyCode::Char('b') => self.popup = Some(Popup::Book { selected: 0 }),
            KeyCode::Char('m') => self.toggle_monitor(),
            KeyCode::Char('l') => match &self.logs {
                Some((logs, _)) => {
                    logs.mark_seen();
                    self.popup = Some(Popup::Logs { back: 0 });
                }
                None => self.set_notice(("this console isn't keeping a log".into(), true)),
            },
            KeyCode::PageUp if self.monitor.visible => {
                self.scroll_monitor(self.monitor.page as i64)
            }
            KeyCode::PageDown if self.monitor.visible => {
                self.scroll_monitor(-(self.monitor.page as i64))
            }
            KeyCode::Up if self.monitor.visible && key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_monitor(1)
            }
            KeyCode::Down
                if self.monitor.visible && key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.scroll_monitor(-1)
            }
            KeyCode::Home if self.monitor.visible => self.scroll_monitor(i64::MAX),
            KeyCode::End if self.monitor.visible => self.monitor.back = 0,
            KeyCode::Char('t') if self.monitor.visible => {
                self.monitor.show_totals = !self.monitor.show_totals;
            }
            KeyCode::Char('f') => {
                self.monitor.failures_only = !self.monitor.failures_only;
                if self.monitor.visible {
                    self.start_monitor();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_rows.max(1) as i32),
            KeyCode::PageUp => self.move_selection(-(self.page_rows.max(1) as i32)),
            _ => self.tab_key(key.code),
        }
        Control::Continue
    }

    fn tab_key(&mut self, code: KeyCode) {
        match (self.tab, code) {
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('s')) => {
                self.sort = (self.sort + 1) % SORTS.len();
                self.queues.clear();
                self.load_queues(true);
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('x')) => {
                self.queue_send = !self.queue_send;
                self.queues.clear();
                self.load_queues(true);
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Enter) => {
                if let Some(did) = self.selected_queue_did() {
                    self.open_account(Some(did));
                }
            }
            (Tab::Config, KeyCode::Enter) if self.console.can_patch_config() => {
                if let Some(field) = self.selected_config() {
                    let key = field["key"].as_str().unwrap_or("").to_string();
                    if key.starts_with("limits.") {
                        let value = field["value"].to_string();
                        self.popup = Some(Popup::EditConfig { key, value });
                    } else {
                        self.set_notice(("only limits can be changed at runtime".into(), true));
                    }
                }
            }
            // The same key toggles a queue on other screens, so this one asks
            // before it changes anything.
            (Tab::Config, KeyCode::Char('x')) if self.console.can_patch_config() => {
                match self.selected_config() {
                    Some(field) if field["source"] == "override" => {
                        self.popup = Some(Popup::ConfirmPatch {
                            key: field["key"].as_str().unwrap_or("").to_string(),
                            from: config_value(&field["value"]),
                            to: Value::Null,
                            typed: None,
                        });
                    }
                    Some(_) => self.set_notice(("that key has no override to reset".into(), false)),
                    None => {}
                }
            }
            (Tab::Accounts, KeyCode::Enter) => {
                if let Some(did) = self.selected_account_did() {
                    self.open_account(Some(did));
                }
            }
            (Tab::Mux, KeyCode::Char('g')) => {
                let principal = self
                    .mux_state
                    .selected()
                    .and_then(|i| self.mux["connections"].get(i))
                    .and_then(|c| c["principal"].as_str())
                    .map(str::to_string);
                if let Some(principal) = principal {
                    self.open_grants(GrantQuery {
                        principal: Some(principal),
                        member: None,
                    });
                }
            }
            (Tab::Grants, KeyCode::Char('/')) => {
                self.popup = Some(Popup::FindGrants {
                    principal: self.grant_query.principal.clone().unwrap_or_default(),
                    member: self.grant_query.member.clone().unwrap_or_default(),
                    on_member: false,
                });
            }
            (Tab::Grants, KeyCode::Char('p')) => {
                if let Some(principal) = self.selected_grant_field("principal") {
                    self.open_grants(GrantQuery {
                        principal: Some(principal),
                        member: None,
                    });
                }
            }
            (Tab::Grants, KeyCode::Char('g')) => {
                if let Some(member) = self.selected_grant_field("did") {
                    self.open_grants(GrantQuery {
                        principal: None,
                        member: Some(member),
                    });
                }
            }
            (Tab::Grants, KeyCode::Char(' ')) => {
                if let Some(key) = self.selected_grant_key() {
                    self.grant_marks.toggle(key);
                    self.move_selection(1);
                }
            }
            (Tab::Grants, KeyCode::Char('a')) => {
                self.grant_marks.mark_all(&self.grants);
            }
            (Tab::Grants, KeyCode::Char('c')) => self.grant_marks.clear(),
            (Tab::Grants, KeyCode::Char('d')) if !self.grant_marks.is_empty() => {
                self.popup = Some(Popup::ConfirmRevokeMarked(
                    self.grant_marks.in_listed_order(&self.grants),
                ));
            }
            (Tab::Grants, KeyCode::Char('E')) if !self.grant_marks.is_empty() => {
                self.set_notice((
                    "E advances one member's epoch, not the marked grants: c clears the marks"
                        .into(),
                    true,
                ));
            }
            (Tab::Grants, KeyCode::Char('d')) => {
                if let (Some(member), Some(id)) = (
                    self.selected_grant_field("did"),
                    self.selected_grant_field("grantId"),
                ) {
                    self.popup = Some(Popup::ConfirmRevoke(GrantSelection::grants(
                        member,
                        vec![id],
                    )));
                }
            }
            (Tab::Grants, KeyCode::Char('D')) if !self.grant_query.is_empty() => {
                self.popup = Some(Popup::ConfirmRevoke(GrantSelection {
                    principal: self.grant_query.principal.clone(),
                    member: self.grant_query.member.clone(),
                    grant_ids: Vec::new(),
                }));
            }
            (Tab::Grants, KeyCode::Char('E')) => {
                match self
                    .grant_query
                    .member
                    .clone()
                    .or_else(|| self.selected_grant_field("did"))
                {
                    Some(did) => self.ask_bump_epoch(did),
                    None => self.set_notice(("select a grant, or list a member's".into(), true)),
                }
            }
            (Tab::Account, KeyCode::Char('x')) => {
                self.message_send = !self.message_send;
                self.set_target(self.target.clone());
            }
            (Tab::Account, KeyCode::Char('e')) => {
                if let Some(info) = &self.account_info {
                    // The account on screen: `account_info` is only ever the
                    // answer for it (a late one for another is dropped).
                    let hash = self
                        .target
                        .clone()
                        .unwrap_or_else(|| self.console.did_hash().to_string());
                    // Only a rootAdmin may change roles: every role an admin
                    // could set other than `standard` is privileged, so the
                    // row is offered to a rootAdmin alone.
                    self.popup = Some(Popup::EditAccount(AccountEdit::new(
                        hash,
                        info,
                        matches!(self.console.mode(), Mode::Admin { root: true }),
                    )));
                } else {
                    self.set_notice(("the account's settings are still loading".into(), true));
                }
            }
            (Tab::Account, KeyCode::Char('o')) => self.set_target(None),
            (Tab::Account, KeyCode::Char('i')) => {
                if let Some(id) = self.selected_message_field("msgId") {
                    let target = self.target.clone();
                    self.request(Job::Inspect, true, move |c| async move {
                        Update::Inspected(Box::new(c.inspect(target, &id).await))
                    });
                }
            }
            (Tab::Account, KeyCode::Char('d')) => {
                let selected = self
                    .message_state
                    .selected()
                    .and_then(|i| self.messages.rows.get(i));
                if let Some(m) = selected
                    && let Some(id) = m["msgId"].as_str()
                {
                    let about =
                        delete_summary(&self.book, &self.account_label(), self.message_send, m);
                    self.popup = Some(Popup::ConfirmDelete {
                        target: self.target.clone(),
                        ids: vec![id.to_string()],
                        about,
                    });
                }
            }
            (Tab::Account, KeyCode::Char('p') | KeyCode::Char('P')) => {
                let peer = if code == KeyCode::Char('P') {
                    self.selected_message_field(if self.message_send { "to" } else { "from" })
                } else {
                    None
                };
                let request = PurgeRequest {
                    target: self.target.clone(),
                    queue: if self.message_send {
                        specs::queue::purge::v0_1::Queue::Send
                    } else {
                        specs::queue::purge::v0_1::Queue::Receive
                    },
                    peer,
                    older_than_seconds: None,
                };
                self.request(Job::PurgePreview, true, move |c| async move {
                    Update::PurgePreview(c.purge_preview(request).await)
                });
            }
            _ => {}
        }
    }

    /// The Account tab's account as the user knows it.
    fn account_label(&self) -> String {
        match &self.target {
            Some(t) => label(&self.book, t),
            None => format!("{} (you)", label(&self.book, self.console.did_hash())),
        }
    }

    /// Copy the full identifier behind the selected row — an account hash, a
    /// DID, a message id — to the terminal's clipboard (`y`).
    fn copy_selected(&mut self) {
        let row = |rows: &[Value], state: &TableState, field: &str| {
            state
                .selected()
                .and_then(|i| rows.get(i))
                .and_then(|r| r[field].as_str())
                .map(str::to_string)
        };
        let picked: Option<(&str, String)> = match self.tab {
            Tab::Dashboard | Tab::Queues => {
                row(&self.queues.rows, &self.queue_state, "did").map(|v| ("account hash", v))
            }
            Tab::Accounts => {
                row(&self.accounts.rows, &self.accounts_state, "did").map(|v| ("account hash", v))
            }
            Tab::Account => row(&self.messages.rows, &self.message_state, "msgId")
                .map(|v| ("message id", v))
                .or_else(|| {
                    Some((
                        "account hash",
                        self.target
                            .clone()
                            .unwrap_or_else(|| self.console.did_hash().to_string()),
                    ))
                }),
            Tab::Audit => row(&self.audit.rows, &self.audit_state, "target")
                .or_else(|| row(&self.audit.rows, &self.audit_state, "actor"))
                .map(|v| ("DID", v)),
            Tab::Config => self
                .selected_config()
                .map(|f| ("value", config_value(&f["value"]))),
            Tab::Mux => self
                .mux_state
                .selected()
                .and_then(|i| self.mux["connections"].get(i))
                .and_then(|c| c["principal"].as_str())
                .map(|v| ("principal DID", v.to_string())),
            Tab::Grants => self.selected_grant_field("did").map(|v| ("member DID", v)),
        };
        match picked {
            Some((what, text)) => self.copy_out(what, &text),
            None => self.set_notice(("nothing selected to copy".into(), true)),
        }
    }

    /// Send `text` to the terminal's clipboard and say so.
    fn copy_out(&mut self, what: &str, text: &str) {
        match crate::clipboard::copy(text) {
            Ok(()) => self.set_notice((
                format!(
                    "copied {what} {} (if the terminal allows OSC 52)",
                    short(text)
                ),
                false,
            )),
            Err(e) => self.set_notice((format!("copy failed: {e}"), true)),
        }
    }

    fn popup_key(&mut self, popup: Popup, code: KeyCode) {
        let yes = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'));
        match popup {
            Popup::Logs { back } => {
                const PAGE: usize = 10;
                let back = match code {
                    KeyCode::Up | KeyCode::Char('k') => back.saturating_add(1),
                    KeyCode::Down | KeyCode::Char('j') => back.saturating_sub(1),
                    KeyCode::PageUp => back.saturating_add(PAGE),
                    KeyCode::PageDown => back.saturating_sub(PAGE),
                    KeyCode::Home => usize::MAX,
                    KeyCode::End => 0,
                    KeyCode::Char('c') => {
                        if let Some((logs, _)) = &self.logs {
                            logs.clear();
                        }
                        0
                    }
                    // Esc, q, l or anything else closes it.
                    _ => {
                        if let Some((logs, _)) = &self.logs {
                            logs.mark_seen();
                        }
                        return;
                    }
                };
                self.popup = Some(Popup::Logs { back });
            }
            Popup::Name {
                hash,
                mut did,
                mut name,
                on_name,
            } => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Enter => self.popup = self.save_name(hash, did, name),
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    self.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: !on_name,
                    })
                }
                other => {
                    let field = if on_name { &mut name } else { &mut did };
                    match other {
                        KeyCode::Backspace => {
                            field.pop();
                        }
                        KeyCode::Char(c) => field.push(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name,
                    });
                }
            },
            Popup::Book { selected } => {
                let len = self.book.entries().len();
                match code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.popup = Some(Popup::Book {
                            selected: (selected + 1).min(len.saturating_sub(1)),
                        })
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.popup = Some(Popup::Book {
                            selected: selected.saturating_sub(1),
                        })
                    }
                    KeyCode::Char('x') | KeyCode::Delete => {
                        if let Some(entry) = self.book.entries().get(selected).cloned() {
                            self.book.remove(&entry.hash());
                            self.save_book();
                            self.set_notice((format!("{} removed", entry.name), false));
                        }
                        self.popup = Some(Popup::Book {
                            selected: selected.min(len.saturating_sub(2)),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Enter => {
                        let hash = self.book.entries().get(selected).map(|e| e.hash());
                        self.popup = Some(self.name_popup(hash));
                    }
                    KeyCode::Char('a') => self.popup = Some(self.name_popup(None)),
                    _ => {}
                }
            }
            Popup::Inspect {
                id,
                body,
                mut scroll,
            } => {
                let lines = body.lines().count() as u16;
                let page = self.page_rows.max(1) as u16;
                match code {
                    KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(page),
                    KeyCode::PageDown | KeyCode::Char(' ') => scroll = scroll.saturating_add(page),
                    KeyCode::Home => scroll = 0,
                    KeyCode::End => scroll = lines,
                    KeyCode::Char('y') => self.copy_out("message", &body),
                    KeyCode::Char('w') => {
                        let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                        match crate::clipboard::save(&dir, &format!("message-{id}"), &body) {
                            Ok(path) => self.set_notice((
                                format!("message written to {}", path.display()),
                                false,
                            )),
                            Err(e) => self.set_notice((format!("message not written: {e}"), true)),
                        }
                    }
                    // Esc, q or anything else closes it.
                    _ => return,
                }
                self.popup = Some(Popup::Inspect {
                    id,
                    body,
                    scroll: scroll.min(lines.saturating_sub(1)),
                });
            }
            Popup::Help { scroll } => {
                let scroll = match code {
                    KeyCode::Up | KeyCode::Char('k') => scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => scroll.saturating_add(1).min(200),
                    KeyCode::PageUp => scroll.saturating_sub(10),
                    KeyCode::PageDown => scroll.saturating_add(10).min(200),
                    _ => return,
                };
                self.popup = Some(Popup::Help { scroll });
            }
            Popup::ConfirmAccount { edit, .. } if yes => self.save_account(edit),
            // Anything else goes back to the editor, the changes intact.
            Popup::ConfirmAccount { edit, .. } => {
                self.set_notice(("not saved — still editing".into(), false));
                self.popup = Some(Popup::EditAccount(edit));
            }
            Popup::ConfirmPatch { key, to, .. } if yes => self.patch(key, to),
            Popup::ConfirmPatch {
                key,
                typed: Some(value),
                ..
            } => {
                self.set_notice(("not applied — still editing".into(), false));
                self.popup = Some(Popup::EditConfig { key, value });
            }
            Popup::ConfirmPatch { .. } => self.set_notice(("cancelled".into(), false)),
            Popup::EditAccount(mut edit) => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Char('s') => {
                    if edit.changed() {
                        self.popup = Some(self.confirm_account(edit));
                    } else {
                        self.set_notice(("nothing changed".into(), false));
                    }
                }
                other => {
                    match other {
                        KeyCode::Up | KeyCode::Char('k') => edit.up(),
                        KeyCode::Down | KeyCode::Char('j') => edit.down(),
                        KeyCode::Char(' ') | KeyCode::Enter => edit.toggle(),
                        KeyCode::Backspace => edit.backspace(),
                        KeyCode::Char(c) => edit.type_char(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::EditAccount(edit));
                }
            },
            Popup::EditConfig { key, mut value } => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Enter => {
                    // A number when it reads as one; otherwise the text as given.
                    let parsed = serde_json::from_str::<Value>(value.trim())
                        .unwrap_or_else(|_| Value::String(value.trim().to_string()));
                    let from = self
                        .config
                        .iter()
                        .find(|f| f["key"] == key.as_str())
                        .map(|f| config_value(&f["value"]))
                        .unwrap_or_else(|| "?".into());
                    self.popup = Some(Popup::ConfirmPatch {
                        key,
                        from,
                        to: parsed,
                        typed: Some(value),
                    });
                }
                other => {
                    match other {
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Char(c) => value.push(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::EditConfig { key, value });
                }
            },
            Popup::FindGrants {
                mut principal,
                mut member,
                on_member,
            } => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Enter => {
                    let query = grant_query(&principal, &member);
                    if query.is_empty() {
                        self.set_notice((
                            "name a principal DID, a member DID, or both".into(),
                            true,
                        ));
                        self.popup = Some(Popup::FindGrants {
                            principal,
                            member,
                            on_member,
                        });
                    } else {
                        self.open_grants(query);
                    }
                }
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    self.popup = Some(Popup::FindGrants {
                        principal,
                        member,
                        on_member: !on_member,
                    })
                }
                other => {
                    let field = if on_member {
                        &mut member
                    } else {
                        &mut principal
                    };
                    match other {
                        KeyCode::Backspace => {
                            field.pop();
                        }
                        KeyCode::Char(c) => field.push(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::FindGrants {
                        principal,
                        member,
                        on_member,
                    });
                }
            },
            Popup::ConfirmRevoke(selection) if yes => {
                self.spawn(move |c| async move {
                    Update::Done(c.mux_revoke(&selection).await.map(|o| revoke_summary(&o)))
                });
            }
            Popup::ConfirmRevokeMarked(keys) if yes => {
                self.spawn(move |c| async move {
                    Update::RevokedMarked(c.mux_revoke_each(&keys).await)
                });
            }
            Popup::ConfirmBumpEpoch { did, epoch } if yes => {
                let name = did_label(&self.book, &did);
                self.spawn(move |c| async move {
                    Update::Done(c.mux_bump_epoch(&did, epoch).await.map(|r| {
                        bump_summary(&name, epoch, r.epoch, r.epoch_advanced, r.revoked_grants)
                    }))
                });
            }
            Popup::Text { .. } => {}
            Popup::ConfirmDelete { target, ids, .. } if yes => {
                self.spawn(move |c| async move {
                    Update::Done(c.delete(target, &ids).await.map(|r| {
                        let deleted = serde_json::to_value(&r)
                            .ok()
                            .and_then(|v| v["results"].as_array().cloned())
                            .unwrap_or_default()
                            .iter()
                            .filter(|x| x["deleted"] == true)
                            .count();
                        format!("deleted {deleted} message(s)")
                    }))
                });
            }
            Popup::ConfirmPurge(plan) if yes => {
                let matched = plan.matched;
                self.spawn(move |c| async move {
                    Update::Done(
                        c.purge(plan)
                            .await
                            .map(|r| purge_summary(matched, r.purged)),
                    )
                });
            }
            // Anything but "y" cancels a confirmation.
            Popup::ConfirmDelete { .. }
            | Popup::ConfirmPurge(_)
            | Popup::ConfirmRevoke(_)
            | Popup::ConfirmRevokeMarked(_)
            | Popup::ConfirmBumpEpoch { .. } => {
                self.set_notice(("cancelled".into(), false));
            }
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let (state, len, more) = match self.tab {
            Tab::Queues | Tab::Dashboard => (
                &mut self.queue_state,
                self.queues.rows.len(),
                self.queues.next.is_some(),
            ),
            Tab::Account => (
                &mut self.message_state,
                self.messages.rows.len(),
                self.messages.next.is_some(),
            ),
            Tab::Accounts => (
                &mut self.accounts_state,
                self.accounts.rows.len(),
                self.accounts.next.is_some(),
            ),
            Tab::Audit => (
                &mut self.audit_state,
                self.audit.rows.len(),
                self.audit.next.is_some(),
            ),
            Tab::Config => (&mut self.config_state, self.config.len(), false),
            Tab::Mux => (
                &mut self.mux_state,
                self.mux["connections"].as_array().map_or(0, Vec::len),
                false,
            ),
            Tab::Grants => (&mut self.grants_state, self.grants.len(), false),
        };
        if len == 0 {
            return;
        }
        let i = (state.selected().unwrap_or(0) as i32 + delta).clamp(0, len as i32 - 1) as usize;
        state.select(Some(i));
        // At the last row of a list with more behind it: fetch the next page.
        if delta > 0 && i + 1 == len && more {
            self.load_more();
        }
    }

    /// The confirmation an account edit needs before it is sent: what
    /// changes, and a warning when it can lock the console out.
    fn confirm_account(&self, mut edit: AccountEdit) -> Popup {
        let changes = edit
            .diff()
            .into_iter()
            .map(|(name, was, now)| format!("{name}: {was} → {now}"))
            .collect();
        let own = edit.target == self.console.did_hash();
        let warning = edit.risks_lockout().filter(|_| own).map(|what| {
            format!(
                "⚠ This is the account the console is signed in as. {what} can lock \
                 you out of this console, and only another administrator can undo it."
            )
        });
        let who = if own {
            format!("{} (you)", label(&self.book, &edit.target))
        } else {
            label(&self.book, &edit.target)
        };
        Popup::ConfirmAccount {
            edit,
            who,
            changes,
            warning,
        }
    }

    /// Send an account edit's changes with `account/update`.
    fn save_account(&mut self, mut edit: AccountEdit) {
        use specs::account::update::v0_2::{AccountType, MediatorAcl, QueueLimits};
        let (role, acl, limits) = edit.changes();
        let role: Option<AccountType> = match role.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("role: {e}"), true)),
        };
        let acl: Option<MediatorAcl> = match acl.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("acl: {e}"), true)),
        };
        let limits: Option<QueueLimits> = match limits.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("limits: {e}"), true)),
        };
        let target = (edit.target != self.console.did_hash()).then(|| edit.target.clone());
        self.spawn(move |c| async move {
            Update::Done(
                c.update_account(target, role, acl, limits)
                    .await
                    .map(|_| "account updated".to_string()),
            )
        });
    }

    fn selected_config(&self) -> Option<Value> {
        let i = self.config_state.selected()?;
        self.config.get(i).cloned()
    }

    /// Ask the mediator to set `key` to `value` (`null` removes its override).
    fn patch(&self, key: String, value: Value) {
        self.spawn(move |c| async move {
            let mut overrides = serde_json::Map::new();
            overrides.insert(key, value);
            Update::Patched(to_value(c.patch_config(overrides).await))
        });
    }

    fn selected_account_did(&self) -> Option<String> {
        let i = self.accounts_state.selected()?;
        self.accounts.rows.get(i)?["did"]
            .as_str()
            .map(str::to_string)
    }

    fn selected_queue_did(&self) -> Option<String> {
        let i = self.queue_state.selected()?;
        self.queues.rows.get(i)?["did"].as_str().map(str::to_string)
    }

    fn selected_message_field(&self, field: &str) -> Option<String> {
        let i = self.message_state.selected()?;
        self.messages.rows.get(i)?[field]
            .as_str()
            .map(str::to_string)
    }

    // ─── Monitor ─────────────────────────────────────────────────────────

    fn toggle_monitor(&mut self) {
        self.monitor.visible = !self.monitor.visible;
        if self.monitor.visible {
            self.start_monitor();
        } else if let Some(task) = self.monitor.task.take() {
            // Dropping the feed inside the task unsubscribes.
            task.abort();
        }
    }

    fn start_monitor(&mut self) {
        if let Some(task) = self.monitor.task.take() {
            task.abort();
        }
        // New subscription, new totals.
        self.monitor.tally = TrafficTally::new(Instant::now());
        let dids = match (&self.target, self.tab) {
            (Some(t), Tab::Account) => Some(vec![t.clone()]),
            _ => None,
        };
        let everyone = dids.is_none();
        self.monitor.watching = match (&dids, self.admin()) {
            (Some(d), _) => format!("account {}", label(&self.book, &d[0])),
            (None, true) => "all traffic".into(),
            (None, false) => "your traffic".into(),
        };
        let mut filter = serde_json::json!({});
        if let Some(d) = dids {
            filter["dids"] = serde_json::json!(d);
        }
        if self.monitor.failures_only {
            filter["failuresOnly"] = serde_json::json!(true);
        }
        let filter: MonitorFilter = serde_json::from_value(filter).unwrap_or_else(|_| {
            serde_json::from_value(serde_json::json!({})).expect("empty filter")
        });
        // Mux members attaching and detaching too, for an administrator
        // watching everything (they are not failures, nor one account's
        // traffic).
        let membership: Option<MembershipFilter> = (self.admin()
            && everyone
            && !self.monitor.failures_only
            && self.console.serves_mux_admin())
        .then(|| serde_json::from_value(serde_json::json!({})).expect("empty membership filter"));
        let (console, tx) = (self.console.clone(), self.tx.clone());
        self.monitor.retry_at = None;
        self.monitor.task = Some(tokio::spawn(watch(console, filter, membership, tx)));
    }

    /// This console's own requests to the mediator, and the clean-up of their
    /// replies. From mediator 0.28.22 the mediator leaves all of that out
    /// itself. Before that, a `received` event carried no recipient and a
    /// `deleted` event no sender, so the console's own polling showed through;
    /// this filter keeps the pane clean on those mediators.
    fn is_own_console_traffic(&self, e: &Value) -> bool {
        let me = self.console.did_hash();
        let from = e["from"].as_str();
        let to = e["to"].as_str();
        let own_request = from == Some(me) && to.is_none_or(|to| to == self.mediator_hash);
        let own_reply_cleanup = e["stage"] == "deleted" && to == Some(me) && from.is_none();
        own_request || own_reply_cleanup
    }

    /// Scroll the monitor `by` lines towards older traffic (negative: newer).
    fn scroll_monitor(&mut self, by: i64) {
        let oldest = self
            .monitor
            .lines
            .len()
            .saturating_sub(self.monitor.page.max(1));
        let back = (self.monitor.back as i64).saturating_add(by);
        self.monitor.back = back.clamp(0, oldest as i64) as usize;
    }

    fn monitor_update(&mut self, update: MonitorUpdate) {
        // The connection's state comes from this side, not the mediator: it
        // says nothing about whether the tap is alive.
        match update {
            MonitorUpdate::Disconnected => {
                self.monitor.link_down = true;
                return;
            }
            MonitorUpdate::Reconnected => {
                self.monitor.link_down = false;
                return;
            }
            _ => {}
        }
        self.monitor.last_seen = Some(Instant::now());
        self.monitor.retry_at = None;
        let before = self.monitor.lines.len();
        match update {
            MonitorUpdate::Events { events, dropped } => {
                self.monitor.dropped += dropped;
                for e in events {
                    let v = serde_json::to_value(e).unwrap_or(Value::Null);
                    if !self.is_own_console_traffic(&v) {
                        self.monitor.tally.record(&v, Instant::now());
                        self.monitor.lines.push_back(MonitorLine::Event(v));
                    }
                }
            }
            MonitorUpdate::Membership { events, dropped } => {
                self.monitor.dropped += dropped;
                for e in events {
                    let v = serde_json::to_value(e).unwrap_or(Value::Null);
                    self.monitor.lines.push_back(MonitorLine::Membership(v));
                }
            }
            MonitorUpdate::Gap { missing } => {
                self.monitor.gaps += missing;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── {missing} batch(es) lost in transit ──"),
                    Style::default().fg(Color::Yellow),
                )));
            }
            MonitorUpdate::Heartbeat => {}
            MonitorUpdate::Ended(reason) => {
                self.monitor.task = None;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── monitor ended: {reason} ──"),
                    Style::default().fg(Color::Red),
                )));
            }
            _ => {}
        }
        // Scrolled back, the view stays on the lines being read while new
        // ones arrive below.
        self.monitor_lines_added(before);
    }

    // ─── Loop ────────────────────────────────────────────────────────────

    /// Run the console on `terminal` until the user quits.
    pub async fn run<B: ratatui::backend::Backend>(
        mut self,
        terminal: &mut ratatui::Terminal<B>,
    ) -> std::io::Result<()>
    where
        std::io::Error: From<B::Error>,
    {
        let mut events = EventStream::new();
        let mut tick = tokio::time::interval(REFRESH);
        tick.tick().await;
        // The header's clocks ("down for 12s") move once a second.
        let mut clock = tokio::time::interval(Duration::from_secs(1));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let logs = self.logs.as_ref().map(|(logs, _)| logs.clone());
        // Draw at once for the user; monitor traffic alone is batched into at
        // most one frame per `FRAME`, however fast it arrives.
        let mut now_please = true;
        let mut dirty = false;
        let mut last_draw = Instant::now();
        loop {
            if now_please || (dirty && last_draw.elapsed() >= FRAME) {
                terminal.draw(|f| self.render(f, f.area()))?;
                last_draw = Instant::now();
                (now_please, dirty) = (false, false);
            }
            let log_changed = async {
                match &logs {
                    Some(logs) => logs.changed().await,
                    None => std::future::pending().await,
                }
            };
            let frame_due = async {
                if dirty {
                    tokio::time::sleep_until((last_draw + FRAME).into()).await
                } else {
                    std::future::pending().await
                }
            };
            tokio::select! {
                Some(Ok(event)) = events.next() => {
                    now_please = true;
                    match event {
                        // Repaint every cell, whatever wrote over them.
                        Event::Key(key)
                            if key.kind == KeyEventKind::Press
                                && key.modifiers.contains(KeyModifiers::CONTROL)
                                && key.code == KeyCode::Char('l') =>
                        {
                            terminal.clear()?;
                        }
                        Event::Key(key) if self.handle_key(key) == Control::Quit => break,
                        Event::Paste(text) => self.handle_paste(&text),
                        _ => {}
                    }
                }
                Some(update) = self.rx.recv() => {
                    if matches!(update, Update::Monitor(_)) {
                        dirty = true;
                    } else {
                        now_please = true;
                    }
                    self.apply(update);
                }
                _ = log_changed => dirty = true,
                _ = frame_due => {}
                _ = clock.tick() => dirty = true,
                _ = tick.tick() => if self.popup.is_none() { self.refresh() },
            }
        }
        if let Some(task) = self.monitor.task.take() {
            task.abort();
        }
        Ok(())
    }

    // ─── Rendering ───────────────────────────────────────────────────────

    /// Draw the console into `area`.
    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);
        self.render_header(f, rows[0]);
        self.render_tabs(f, rows[1]);

        let body = if self.monitor.visible {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(rows[2]);
            self.render_monitor(f, split[1]);
            split[0]
        } else {
            rows[2]
        };
        // A table's header and borders take three or four rows of the body.
        self.page_rows = body.height.saturating_sub(4) as usize;
        if !self.console.serves_operations()
            && !matches!(self.tab, Tab::Audit | Tab::Accounts | Tab::Config)
        {
            self.render_unsupported(f, body);
        } else {
            self.render_screen(f, body);
        }
        self.render_footer(f, rows[3]);
        match &self.popup {
            Some(Popup::Logs { back }) => {
                // Keep the position in range, so scrolling from the top
                // moves at once.
                let back = self.render_logs(f, area, *back);
                self.popup = Some(Popup::Logs { back });
            }
            Some(Popup::Help { scroll }) => self.render_help(f, area, *scroll),
            Some(popup) => render_popup(f, area, popup, &self.book),
            None => {}
        }
        if self.depth == ColorDepth::Monochrome {
            crate::theme::strip_colors(f.buffer_mut(), area);
        }
    }

    /// Every key that works here, over the screen.
    fn render_help(&self, f: &mut Frame, area: Rect, scroll: u16) {
        let cx = self.key_context();
        let mut text: Vec<Line> = Vec::new();
        for (title, keys) in keymap::help(cx) {
            text.push(Line::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            ));
            for b in keys {
                text.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<16}", b.keys),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(b.does),
                ]));
            }
            text.push(Line::raw(""));
        }
        let w = area.width.saturating_sub(8).min(100);
        let h = area.height.saturating_sub(2);
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        f.render_widget(Clear, rect);
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan))
                        .title(" Keys ")
                        .title_bottom(Line::from(" ↑↓ PgUp PgDn scroll  any other key closes ")),
                ),
            rect,
        );
    }

    fn key_context(&self) -> keymap::Context {
        keymap::Context {
            tab: self.tab,
            monitor: self.monitor.visible,
            can_patch: self.console.can_patch_config(),
        }
    }

    fn render_screen(&mut self, f: &mut Frame, body: Rect) {
        match self.tab {
            Tab::Dashboard => self.render_dashboard(f, body),
            Tab::Queues => self.render_queues(f, body),
            Tab::Account => self.render_account(f, body),
            Tab::Audit => self.render_audit(f, body),
            Tab::Accounts => self.render_accounts(f, body),
            Tab::Config => self.render_config(f, body),
            Tab::Mux => self.render_mux(f, body),
            Tab::Grants => self.render_grants(f, body),
        }
    }

    fn render_grants(&mut self, f: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(grants_title(
            &self.grant_query,
            self.grants_epoch,
            self.grants.len(),
            self.grants_next.is_some(),
            self.grant_marks.len(),
            &self.book,
        ));
        if self.grant_query.is_empty() {
            f.render_widget(
                Paragraph::new(
                    "Stored mux grants: what each member DID delegated to which principal, \
                     in what state, until when.\n\n\
                     Press / to look one up by principal or member DID, or g on a \
                     connection in the Mux tab.\n\n\
                     On a grant: d revokes it, E advances its member's epoch (voiding every \
                     grant the member gave), p and g list its principal's or member's grants. \
                     Space marks grants (a marks every one listed, c clears) and d then \
                     revokes the marked ones, each on its own.",
                )
                .wrap(Wrap { trim: false })
                .block(block),
                area,
            );
            return;
        }
        let rows: Vec<Row> = self
            .grants
            .iter()
            .map(|g| {
                let state = g["state"].as_str().unwrap_or("?").to_string();
                let color = match state.as_str() {
                    "active" => Color::Green,
                    "suspended" | "staleKey" => Color::Yellow,
                    _ => Color::DarkGray,
                };
                let scope = g["scope"]
                    .as_array()
                    .map(|s| {
                        s.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let narrowed = if g["narrowed"] == true { "*" } else { "" };
                let marked = grant_key(g).is_some_and(|k| self.grant_marks.contains(&k));
                Row::new(vec![
                    Cell::from(if marked { "●" } else { " " })
                        .style(Style::default().fg(Color::Magenta)),
                    Cell::from(did_label(&self.book, g["did"].as_str().unwrap_or("?"))),
                    Cell::from(did_label(
                        &self.book,
                        g["principal"].as_str().unwrap_or("?"),
                    )),
                    Cell::from(state).style(Style::default().fg(color)),
                    Cell::from(format!("{scope}{narrowed}")),
                    Cell::from(g["expiresAt"].as_str().unwrap_or("").replace('T', " ")),
                    Cell::from(g["epoch"].as_u64().map_or(String::new(), |e| e.to_string())),
                    Cell::from(short(g["grantId"].as_str().unwrap_or(""))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Fill(2),
                Constraint::Fill(2),
                Constraint::Length(12),
                Constraint::Fill(1),
                Constraint::Length(21),
                Constraint::Length(6),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "",
                "member",
                "principal",
                "state",
                "scope",
                "expires",
                "epoch",
                "grant",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(block);
        f.render_stateful_widget(table, area, &mut self.grants_state);
    }

    /// What a screen shows when the mediator predates the tasks it needs.
    fn render_unsupported(&self, f: &mut Frame, area: Rect) {
        let (major, minor, patch) = affinidi_messaging_mediator_admin::OPERATIONS_SINCE;
        let version = self.console.mediator_version().unwrap_or("unknown");
        let admin = matches!(self.console.mode(), Mode::Admin { .. });
        let mut text = vec![
            Line::styled(
                format!("This mediator is version {version}."),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(format!(
                "Statistics, queues, messages and the traffic monitor need \
                 affinidi-messaging-mediator {major}.{minor}.{patch} or later."
            )),
            Line::raw("Upgrade the mediator to use this screen."),
        ];
        if admin {
            text.push(Line::raw(""));
            text.push(Line::raw(
                "The Audit screen works on this mediator: press 4 or Tab.",
            ));
        }
        f.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(Block::bordered().title(" Not available on this mediator ")),
            area,
        );
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let (badge, color) = match self.console.mode() {
            Mode::Admin { root: true } => (" ROOT ", Color::Red),
            Mode::Admin { root: false } => (" ADMIN ", Color::Yellow),
            Mode::SelfService => (" SELF ", Color::Cyan),
        };
        let age = self
            .updated
            .map(|t| format!("updated {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "loading…".into());
        let (link, link_color) = link_badge(self.link, self.link_since.elapsed());
        let line = Line::from(vec![
            Span::styled(
                " mediator-console ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(badge, Style::default().fg(Color::Black).bg(color)),
            Span::styled(format!(" {link}"), Style::default().fg(link_color)),
            Span::raw(format!(
                "  {} → {}  ",
                label(&self.book, self.console.did_hash()),
                short_did(self.console.mediator_did())
            )),
            Span::styled(age, Style::default().fg(Color::DarkGray)),
        ]);
        let mut line = line;
        match self.console.mediator_version() {
            Some(v) if !self.console.serves_operations() => line.push_span(Span::styled(
                format!("  ⚠ mediator {v} is too old for most screens"),
                Style::default().fg(Color::Yellow),
            )),
            Some(v) => line.push_span(Span::styled(
                format!("  mediator {v}"),
                Style::default().fg(Color::DarkGray),
            )),
            None => {}
        }
        if let Some((logs, _)) = &self.logs {
            let unseen = logs.unseen();
            if unseen > 0 {
                line.push_span(Span::styled(
                    format!("  ⚠ {unseen} log warning(s) — l to read"),
                    Style::default().fg(Color::Yellow),
                ));
            }
        }
        f.render_widget(Paragraph::new(line), area);
    }

    /// The captured log over the screen, newest at the bottom, each line
    /// wrapped to the width so none of it is cut off. Returns `back` within
    /// what there is to scroll.
    fn render_logs(&self, f: &mut Frame, area: Rect, back: usize) -> usize {
        let w = area.width.saturating_sub(4);
        let h = area.height.saturating_sub(2);
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        let inner_w = w.saturating_sub(2).max(1) as usize;
        let inner_h = h.saturating_sub(2) as usize;
        let mut rows: Vec<Line> = Vec::new();
        // Read in place: only the rows that wrap are built, not a copy of
        // every line kept.
        let count = self.logs.as_ref().map_or(0, |(logs, _)| {
            logs.with_lines(|lines| {
                for line in lines {
                    let color = match line.level {
                        Some(LogLevel::Error) => Color::Red,
                        Some(LogLevel::Warn) => Color::Yellow,
                        Some(LogLevel::Info) => Color::Reset,
                        _ => Color::DarkGray,
                    };
                    let chunks = match line.repeats {
                        1 => wrap_hard(&line.text, inner_w),
                        n => wrap_hard(&format!("{}  ×{n}", line.text), inner_w),
                    };
                    for chunk in chunks {
                        rows.push(Line::styled(chunk, Style::default().fg(color)));
                    }
                }
                lines.len()
            })
        });
        let back = back.min(rows.len().saturating_sub(inner_h));
        let skip = rows.len().saturating_sub(inner_h + back);
        let shown: Vec<Line> = rows.into_iter().skip(skip).take(inner_h).collect();
        let position = if back > 0 {
            format!(" {back} row(s) newer below · End ")
        } else {
            String::new()
        };
        f.render_widget(Clear, rect);
        f.render_widget(
            Paragraph::new(shown).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(format!(" Log — {count} line(s) "))
                    .title_bottom(Line::from(format!(
                        "{position} ↑↓ PgUp PgDn Home End scroll  c clear  Esc close "
                    ))),
            ),
            rect,
        );
        back
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = self.tabs();
        let titles: Vec<Line> = tabs
            .iter()
            .enumerate()
            .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
            .collect();
        let selected = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
        f.render_widget(
            Tabs::new(titles).select(selected).highlight_style(
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
            area,
        );
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let fresh = self.notice_at.is_some_and(|t| t.elapsed() < NOTICE_FOR);
        let notice = if fresh { self.notice.as_ref() } else { None };
        let line = match notice {
            Some((text, true)) => {
                Line::styled(format!(" ✗ {text}"), Style::default().fg(Color::Red))
            }
            Some((text, false)) => {
                Line::styled(format!(" ✓ {text}"), Style::default().fg(Color::Green))
            }
            None => Line::styled(
                keymap::footer(self.key_context(), area.width as usize),
                Style::default().fg(Color::DarkGray),
            ),
        };
        f.render_widget(Paragraph::new(line), area);
    }

    fn render_dashboard(&mut self, f: &mut Frame, area: Rect) {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(9), Constraint::Min(4)])
            .split(area);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(parts[0]);

        let s = self.stats.as_ref();
        let get = |p: &str| s.and_then(|s| s.pointer(p)).cloned().unwrap_or(Value::Null);
        let n = |p: &str| get(p).as_u64().map(|v| v.to_string()).unwrap_or("–".into());
        let breaker = get("/forwarding/circuitBreaker");
        let breaker_color = match breaker.as_str() {
            Some("open") => Color::Red,
            Some("halfOpen") => Color::Yellow,
            _ => Color::Green,
        };
        let mut lines = vec![
            Line::from(format!(
                "version {}   up {}",
                get("/version").as_str().unwrap_or("–"),
                human_secs(get("/uptimeSeconds").as_u64())
            )),
            Line::from(format!(
                "websockets {} / {}",
                n("/connections/websocketActive"),
                n("/connections/websocketMax")
            )),
            Line::from(format!(
                "stored {}   delivered {}   deleted {}",
                n("/totals/receivedCount"),
                n("/totals/sentCount"),
                n("/totals/deletedCount")
            )),
            Line::from(format!(
                "sessions {} ({} authenticated)",
                n("/totals/sessionsCreated"),
                n("/totals/sessionsAuthenticated")
            )),
            Line::from(vec![
                Span::raw(format!(
                    "forwarding {} / {}   breaker ",
                    n("/forwarding/queueLength"),
                    n("/forwarding/queueLimit")
                )),
                Span::styled(
                    breaker.as_str().unwrap_or("–").to_string(),
                    Style::default().fg(breaker_color),
                ),
            ]),
        ];
        // DID multiplexing, when the mediator reports it (an extension member
        // of `stats/show`; counts are for the instance answering).
        let mux = get("/ext/com.affinidi.mux");
        if mux.is_object() {
            lines.push(Line::from(mux_summary_line(&mux)));
        }
        f.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Mediator ")),
            top[0],
        );

        // Aggregate queue pressure: the fullest single queue, as a gradient.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Queue pressure ");
        let inner = block.inner(top[1]);
        f.render_widget(block, top[1]);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1); 6])
            .split(inner);
        for (i, (label, side)) in [("receive", "receive"), ("send", "send")]
            .iter()
            .enumerate()
        {
            let depth = get(&format!("/queues/{side}"));
            let sat = depth["saturation"].as_f64();
            f.render_widget(
                Paragraph::new(format!(
                    "{label}: {} msgs, worst queue {}, oldest {}",
                    depth["count"].as_u64().unwrap_or(0),
                    sat.map_or("–".into(), |s| format!("{:.0}%", s * 100.0)),
                    human_secs(depth["oldestAgeSeconds"].as_u64())
                )),
                rows[i * 3],
            );
            f.render_widget(QuotaBar::new(sat, self.depth), rows[i * 3 + 1]);
        }

        self.render_queue_table(f, parts[1], " Busiest queues ");
    }

    fn render_queues(&mut self, f: &mut Frame, area: Rect) {
        self.render_queue_table(f, area, " Queues ");
    }

    fn render_queue_table(&mut self, f: &mut Frame, area: Rect, title: &str) {
        let rows = &self.queues.rows;
        // The account column fits the longest name (within reason) and the two
        // quota bars share whatever width is left, so the table uses the pane.
        let names: Vec<String> = rows
            .iter()
            .map(|q| label(&self.book, q["did"].as_str().unwrap_or("?")))
            .collect();
        let inner = area.width.saturating_sub(2);
        const FIXED: u16 = 9 + 11 + 11 + 8 + 6; // role, two counts, oldest, gaps
        let account_width = fit_width(&names, 15, 40);
        let bar_width = (inner.saturating_sub(account_width + FIXED) / 2).clamp(8, 40);
        let depth = self.depth;
        let table_rows: Vec<Row> = rows
            .iter()
            .map(|q| {
                let side = |s: &str| {
                    let d = &q[s];
                    (
                        d["count"].as_u64().unwrap_or(0),
                        d["limit"].as_i64().unwrap_or(-1),
                        d["saturation"].as_f64(),
                        d["oldestAgeSeconds"].as_u64(),
                    )
                };
                let (rc, rl, rs, ro) = side("receive");
                let (sc, sl, ss, so) = side("send");
                let limit = |l: i64| {
                    if l < 0 {
                        "∞".to_string()
                    } else {
                        l.to_string()
                    }
                };
                Row::new(vec![
                    Cell::from(label(&self.book, q["did"].as_str().unwrap_or("?"))),
                    Cell::from(q["accountType"].as_str().unwrap_or("").to_string()),
                    Cell::from(format!("{rc}/{}", limit(rl))),
                    Cell::from(quota_line(rs, bar_width, depth)),
                    Cell::from(format!("{sc}/{}", limit(sl))),
                    Cell::from(quota_line(ss, bar_width, depth)),
                    Cell::from(human_secs(ro.max(so))),
                ])
            })
            .collect();
        let snapshot = self
            .queues_snapshot
            .map(|s| format!(" survey {} ", s.format("%Y-%m-%d %H:%M:%SZ")))
            .unwrap_or_default();
        let title = format!(
            "{title}— {} by {} of {} queue{snapshot}",
            count_shown(rows.len(), None, self.queues.next.is_some()),
            SORTS[self.sort].1,
            if self.queue_send { "send" } else { "receive" }
        );
        let table = Table::new(
            table_rows,
            [
                Constraint::Length(account_width),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(bar_width),
                Constraint::Length(11),
                Constraint::Length(bar_width),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(vec!["account", "role", "receive", "", "send", "", "oldest"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(title));
        f.render_stateful_widget(table, area, &mut self.queue_state);
    }

    fn render_account(&mut self, f: &mut Frame, area: Rect) {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(4),
            ])
            .split(area);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(parts[0]);
        self.render_account_settings(f, top[1]);
        let who = self.target.as_deref().map_or_else(
            || format!("{} (you)", short(self.console.did_hash())),
            |t| label(&self.book, t),
        );

        // Two gradient bars: how full each queue is against its limit.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Account {who} "));
        let inner = block.inner(top[0]);
        f.render_widget(block, top[0]);
        let lines = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1); 4])
            .split(inner);
        let q = self.status.as_ref().map(|s| &s["queues"]);
        for (i, side) in ["receive", "send"].iter().enumerate() {
            let d = q.map(|q| &q[side]).cloned().unwrap_or(Value::Null);
            let limit = d["limit"].as_i64().unwrap_or(-1);
            let sat = d["saturation"].as_f64();
            f.render_widget(
                Paragraph::new(format!(
                    "{side:>7}: {} / {}  {}  oldest {}",
                    d["count"].as_u64().unwrap_or(0),
                    if limit < 0 {
                        "∞".into()
                    } else {
                        limit.to_string()
                    },
                    sat.map_or(String::new(), |s| format!("{:.0}%", s * 100.0)),
                    human_secs(d["oldestAgeSeconds"].as_u64()),
                )),
                lines[i * 2],
            );
            f.render_widget(QuotaBar::new(sat, self.depth), lines[i * 2 + 1]);
        }

        // Who has not collected: the send queue by recipient.
        let peers = self
            .status
            .as_ref()
            .and_then(|s| s["sendPeers"].as_array().cloned())
            .unwrap_or_default();
        let peer_rows: Vec<Row> = peers
            .iter()
            .map(|p| {
                Row::new(vec![
                    label(&self.book, p["peer"].as_str().unwrap_or("?")),
                    p["count"].as_u64().unwrap_or(0).to_string(),
                    human_bytes(p["bytes"].as_u64()),
                    human_secs(p["oldestAgeSeconds"].as_u64()),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                peer_rows,
                [
                    Constraint::Fill(1),
                    Constraint::Length(7),
                    Constraint::Length(9),
                    Constraint::Length(9),
                ],
            )
            .header(
                Row::new(vec!["recipient", "waiting", "bytes", "oldest"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Send queue by recipient — who hasn't collected "),
            ),
            parts[1],
        );

        let rows: Vec<Row> = self
            .messages
            .rows
            .iter()
            .map(|m| {
                let state = m["deliveryState"].as_str().unwrap_or("");
                let color = if state == "delivered" {
                    Color::Yellow
                } else {
                    Color::Reset
                };
                Row::new(vec![
                    Cell::from(m["receivedAt"].as_str().map(time_of).unwrap_or_default()),
                    Cell::from(
                        m["from"]
                            .as_str()
                            .map_or_else(|| "anon".to_string(), |h| label(&self.book, h)),
                    ),
                    Cell::from(label(&self.book, m["to"].as_str().unwrap_or("?"))),
                    Cell::from(human_bytes(m["size"].as_u64())),
                    Cell::from(Span::styled(state.to_string(), Style::default().fg(color))),
                    Cell::from(short(m["msgId"].as_str().unwrap_or(""))),
                ])
            })
            .collect();
        // How many the queue holds, from its status: the list is a page of it.
        let side = if self.message_send { "send" } else { "receive" };
        let total = self
            .status
            .as_ref()
            .and_then(|s| s["queues"][side]["count"].as_u64());
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Fill(2),
                Constraint::Fill(2),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec!["at", "from", "to", "size", "state", "id"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} queue — {} messages{} ",
            if self.message_send { "Send" } else { "Receive" },
            count_shown(
                self.messages.rows.len(),
                total,
                self.messages.next.is_some()
            ),
            if self.messages.paged() {
                " (paged: r reloads)"
            } else {
                ""
            }
        )));
        f.render_stateful_widget(table, parts[2], &mut self.message_state);
    }

    /// The Account tab's settings panel: role, limits, access list, ACL flags.
    fn render_account_settings(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Settings — e to edit ");
        let Some(a) = &self.account_info else {
            f.render_widget(Paragraph::new("loading…").block(block), area);
            return;
        };
        let limit = |k: &str| match a["queueLimits"][k].as_i64() {
            Some(-1) => "unlimited".to_string(),
            Some(n) => n.to_string(),
            None => "default".to_string(),
        };
        let role = a["accountType"].as_str().unwrap_or("?").to_string();
        let role_style = match role.as_str() {
            "rootAdmin" => Style::default().fg(Color::Red),
            "admin" => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };
        let mut flags: Vec<Span> = Vec::new();
        if let Some(acl) = a["acl"].as_object() {
            let mut entries: Vec<(&String, bool)> = acl
                .iter()
                .filter_map(|(k, v)| v.as_bool().map(|b| (k, b)))
                .collect();
            entries.sort_by(|x, y| x.0.cmp(y.0));
            for (k, on) in entries {
                flags.push(Span::styled(
                    format!("{}{k} ", if on { "✓" } else { "✗" }),
                    Style::default().fg(if on { Color::Green } else { Color::DarkGray }),
                ));
            }
        }
        let text = vec![
            Line::from(vec![Span::raw("role "), Span::styled(role, role_style)]),
            Line::raw(format!(
                "limits  send {}  receive {}",
                limit("sendQueueLimit"),
                limit("receiveQueueLimit")
            )),
            Line::raw(format!(
                "access list  {} ({} entries)",
                a["acl"]["accessListMode"].as_str().unwrap_or("?"),
                a["accessListCount"].as_u64().unwrap_or(0)
            )),
            Line::raw(format!(
                "last message {} ago  last login {} ago",
                ago(a["lastReceivedAt"].as_u64()),
                ago(a["lastAuthenticatedAt"].as_u64())
            )),
            Line::raw(lifetime_totals(&a["stats"])),
            Line::from(flags),
        ];
        f.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(block),
            area,
        );
    }

    fn render_mux(&mut self, f: &mut Frame, area: Rect) {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Min(5)])
            .split(area);
        let connections: Vec<Value> = self.mux["connections"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let rows: Vec<Row> = connections
            .iter()
            .map(|c| {
                let members = c["members"].as_array().cloned().unwrap_or_default();
                let inactive = members
                    .iter()
                    .filter(|m| m["deliveryActive"] == false)
                    .count();
                Row::new(vec![
                    Cell::from(did_label(
                        &self.book,
                        c["principal"].as_str().unwrap_or("?"),
                    )),
                    Cell::from(c["wire"].as_str().unwrap_or("").to_string()),
                    Cell::from(c["openedAt"].as_str().unwrap_or("").replace('T', " ")),
                    Cell::from(c["memberCount"].as_u64().unwrap_or(0).to_string()),
                    Cell::from(if inactive > 0 {
                        inactive.to_string()
                    } else {
                        String::new()
                    })
                    .style(Style::default().fg(Color::Yellow)),
                    Cell::from(short(c["sessionId"].as_str().unwrap_or(""))),
                ])
            })
            .collect();
        let title = mux_title(&self.mux);
        let table = Table::new(
            rows,
            [
                Constraint::Fill(2),
                Constraint::Length(8),
                Constraint::Length(21),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "principal",
                "wire",
                "opened",
                "members",
                "inactive",
                "session",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(title));
        f.render_stateful_widget(table, parts[0], &mut self.mux_state);

        let selected = self
            .mux_state
            .selected()
            .and_then(|i| connections.get(i))
            .cloned()
            .unwrap_or(Value::Null);
        let members = selected["members"].as_array().cloned().unwrap_or_default();
        let member_rows: Vec<Row> = members
            .iter()
            .map(|m| {
                let active = m["deliveryActive"] != false;
                let scope = m["scope"]
                    .as_array()
                    .map(|s| {
                        s.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                Row::new(vec![
                    Cell::from(did_label(&self.book, m["did"].as_str().unwrap_or("?"))),
                    Cell::from(m["source"].as_str().unwrap_or("").to_string()),
                    Cell::from(scope),
                    Cell::from(m["expiresAt"].as_str().unwrap_or("").replace('T', " ")),
                    Cell::from(if active { "live" } else { "inactive" }).style(if active {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::Yellow)
                    }),
                ])
            })
            .collect();
        let shown = members.len() as u64;
        let total = selected["memberCount"].as_u64().unwrap_or(0);
        let members_title = if shown < total {
            format!(" Members ({shown} of {total} shown) ")
        } else {
            format!(" Members ({total}) ")
        };
        f.render_widget(
            Table::new(
                member_rows,
                [
                    Constraint::Fill(2),
                    Constraint::Length(7),
                    Constraint::Fill(1),
                    Constraint::Length(21),
                    Constraint::Length(9),
                ],
            )
            .header(
                Row::new(vec!["member", "source", "scope", "expires", "delivery"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(members_title)),
            parts[1],
        );
    }

    fn render_accounts(&mut self, f: &mut Frame, area: Rect) {
        let names: Vec<String> = self
            .accounts
            .rows
            .iter()
            .map(|a| label(&self.book, a["did"].as_str().unwrap_or("?")))
            .collect();
        let name_width = fit_width(&names, 15, 40);
        let rows: Vec<Row> = self
            .accounts
            .rows
            .iter()
            .zip(&names)
            .map(|(a, name)| {
                let hash = a["did"].as_str().unwrap_or("?");
                let n = |k: &str| a[k].as_u64().map_or("–".into(), |v| v.to_string());
                let bytes = a["receiveQueueBytes"].as_u64().unwrap_or(0)
                    + a["sendQueueBytes"].as_u64().unwrap_or(0);
                let role = a["accountType"].as_str().unwrap_or("").to_string();
                let style = match role.as_str() {
                    "rootAdmin" => Style::default().fg(Color::Red),
                    "admin" => Style::default().fg(Color::Yellow),
                    "mediator" => Style::default().fg(Color::Cyan),
                    _ => Style::default(),
                };
                Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(if self.book.name_of(hash).is_some() {
                        short(hash)
                    } else {
                        String::new()
                    }),
                    Cell::from(role).style(style),
                    Cell::from(n("receiveQueueCount")),
                    Cell::from(n("sendQueueCount")),
                    Cell::from(human_bytes(Some(bytes))),
                    Cell::from(ago(a["lastReceivedAt"].as_u64())),
                    Cell::from(ago(a["lastAuthenticatedAt"].as_u64())),
                    Cell::from(n("accessListCount")),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(name_width),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "account",
                "hash",
                "role",
                "receive",
                "send",
                "queued",
                "msg ago",
                "login ago",
                "access list",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(format!(
                    " Accounts — {}{} ",
                    count_shown(self.accounts.rows.len(), None, self.accounts.next.is_some()),
                    self.accounts_loaded
                        .map(|at| format!(
                            " · loaded {} ago, r reloads",
                            human_secs(Some(at.elapsed().as_secs()))
                        ))
                        .unwrap_or_default()
                )));
        f.render_stateful_widget(table, area, &mut self.accounts_state);
    }

    fn render_config(&mut self, f: &mut Frame, area: Rect) {
        let keys: Vec<String> = self
            .config
            .iter()
            .map(|c| c["key"].as_str().unwrap_or("").to_string())
            .collect();
        let rows: Vec<Row> = self
            .config
            .iter()
            .zip(&keys)
            .map(|(c, key)| {
                let value = match &c["value"] {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let source = c["source"].as_str().unwrap_or("").to_string();
                let applies = if c["requiresRestart"] == false {
                    "live"
                } else {
                    "restart"
                };
                Row::new(vec![
                    Cell::from(key.clone()),
                    Cell::from(value),
                    Cell::from(source.clone()).style(if source == "override" {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    }),
                    Cell::from(applies),
                ])
            })
            .collect();
        let overrides = self
            .config
            .iter()
            .filter(|c| c["source"] == "override")
            .count();
        let table = Table::new(
            rows,
            [
                Constraint::Length(fit_width(&keys, 20, 48)),
                Constraint::Fill(2),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(vec!["key", "value", "from", "applies"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Configuration — {} keys, {overrides} overridden{} ",
            self.config.len(),
            if self.console.can_patch_config() {
                ""
            } else {
                " · read only (changing limits needs a rootAdmin)"
            }
        )));
        f.render_stateful_widget(table, area, &mut self.config_state);
    }

    /// The audit log, newest first, as `audit/list` 0.2 records each entry:
    /// when, who, what, to whom, how it ended, and its detail.
    fn render_audit(&mut self, f: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .audit
            .rows
            .iter()
            .map(|e| {
                let text = |k: &str| e[k].as_str().unwrap_or("").to_string();
                let action = text("action");
                // DID-multiplexing decisions (grants suspended under the
                // unknown-key rule, revoked, an epoch advanced) stand out:
                // each one cut a device off from a DID.
                let style = if is_mux_action(&action) {
                    Style::default().fg(Color::Magenta)
                } else {
                    Style::default()
                };
                let outcome = text("outcome");
                let outcome_color = match outcome.as_str() {
                    "success" => Color::Green,
                    "" => Color::Reset,
                    "denied" | "failure" | "failed" | "error" => Color::Red,
                    _ => Color::Yellow,
                };
                // Actor and target are DIDs (absent once redacted).
                let did = |k: &str| match e[k].as_str() {
                    Some(d) => did_label(&self.book, d),
                    None => "–".into(),
                };
                Row::new(vec![
                    Cell::from(e["recordedAt"].as_str().map(when_of).unwrap_or_default()),
                    Cell::from(did("actor")),
                    Cell::from(action),
                    Cell::from(did("target")),
                    Cell::from(outcome).style(Style::default().fg(outcome_color)),
                    Cell::from(detail_line(&e["detail"])),
                ])
                .style(style)
            })
            .collect();
        let title = format!(
            " Audit log — {} entries, newest first{} ",
            count_shown(self.audit.rows.len(), None, self.audit.next.is_some()),
            if self.audit.paged() {
                " (paged: r reloads)"
            } else {
                ""
            }
        );
        f.render_stateful_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(15),
                    Constraint::Fill(1),
                    Constraint::Length(20),
                    Constraint::Fill(1),
                    Constraint::Length(8),
                    Constraint::Fill(3),
                ],
            )
            .header(
                Row::new(vec![
                    "when", "actor", "action", "target", "outcome", "detail",
                ])
                .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .block(Block::default().borders(Borders::ALL).title(title)),
            area,
            &mut self.audit_state,
        );
    }

    fn render_monitor(&mut self, f: &mut Frame, area: Rect) {
        let alive = match (self.monitor.task.is_some(), self.monitor.last_seen) {
            (false, _) => Span::styled("○ stopped", Style::default().fg(Color::Red)),
            // Said as it happens, not after a silence.
            (true, _) if self.monitor.link_down || self.link == Some(ConnState::Disconnected) => {
                Span::styled("✗ connection down", Style::default().fg(Color::Red))
            }
            (true, _) if let Some(at) = self.monitor.retry_at => Span::styled(
                format!(
                    "↻ resubscribing in {}s",
                    at.saturating_duration_since(Instant::now()).as_secs()
                ),
                Style::default().fg(Color::Yellow),
            ),
            (true, Some(t)) if t.elapsed() < Duration::from_secs(45) => {
                Span::styled("● live", Style::default().fg(Color::Green))
            }
            (true, Some(_)) => Span::styled("● silent", Style::default().fg(Color::Yellow)),
            (true, None) => Span::styled("◌ connecting", Style::default().fg(Color::DarkGray)),
        };
        let now = Instant::now();
        let tally = &self.monitor.tally;
        let title = Line::from(vec![
            Span::raw(format!(" Traffic — {} ", self.monitor.watching)),
            alive,
            Span::styled(
                format!(
                    "  {} msgs · {:.1}/s (now {:.1}/s) · {}",
                    tally.messages,
                    tally.rate(now),
                    tally.rate_now(now),
                    human_secs(Some(now.duration_since(tally.started()).as_secs())),
                ),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                protocol_mix(&tally.protocols),
                Style::default().fg(Color::Blue),
            ),
            Span::raw(format!(
                "  dropped {}  lost {}{} ",
                self.monitor.dropped,
                self.monitor.gaps,
                if self.monitor.failures_only {
                    "  failures only"
                } else {
                    ""
                },
            )),
        ]);
        let mut block = Block::default().borders(Borders::ALL).title(title);
        // On the bottom edge: the title is often wider than the pane.
        if self.monitor.back > 0 && !self.monitor.show_totals {
            block = block.title_bottom(
                Line::styled(
                    format!(" ⏸ {} newer · End to follow ", self.monitor.back),
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                )
                .right_aligned(),
            );
        }
        if self.monitor.show_totals {
            self.render_totals(f, area, block, now);
            return;
        }
        let inner = block.inner(area);
        let height = inner.height as usize;
        self.monitor.page = height;
        // Sender and recipient as aligned columns, sharing what the fixed
        // columns (time, stage, protocol, channel, size) leave.
        const FIXED: u16 = 8 + 3 + 10 + 10 + 10 + 3 + 6;
        let name_w = (inner.width.saturating_sub(FIXED) / 2).clamp(14, 32) as usize; // a short hash is 13
        let back = self
            .monitor
            .back
            .min(self.monitor.lines.len().saturating_sub(height));
        let skip = self.monitor.lines.len().saturating_sub(height + back);
        let lines: Vec<Line> = self
            .monitor
            .lines
            .iter()
            .skip(skip)
            .take(height)
            .map(|l| match l {
                MonitorLine::Event(v) => event_line(v, &self.book, name_w),
                MonitorLine::Membership(v) => membership_line(v, &self.book, name_w),
                MonitorLine::Note(line) => line.clone(),
                // The count ahead of the reason, which is often a long error
                // the pane cuts off.
                MonitorLine::Retry { reason, attempts } => Line::styled(
                    match attempts {
                        1 => format!("── monitor interrupted: {reason} ──"),
                        n => format!("── monitor interrupted ×{n}: {reason} ──"),
                    },
                    Style::default().fg(Color::Yellow),
                ),
            })
            .collect();
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    /// The monitor's per-account totals: the busiest accounts since it started.
    fn render_totals(&self, f: &mut Frame, area: Rect, block: Block, now: Instant) {
        let top = self
            .monitor
            .tally
            .top(area.height.saturating_sub(3) as usize);
        let names: Vec<String> = top.iter().map(|(h, _)| label(&self.book, h)).collect();
        let rows: Vec<Row> = top
            .iter()
            .zip(&names)
            .map(|((_, a), name)| {
                Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(a.sent.to_string()),
                    Cell::from(a.addressed.to_string()),
                    Cell::from(a.delivered.to_string()),
                    Cell::from(a.refused.to_string()).style(if a.refused > 0 {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default()
                    }),
                    Cell::from(human_bytes(Some(a.bytes))),
                    Cell::from(human_secs(a.last.map(|t| now.duration_since(t).as_secs()))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(fit_width(&names, 14, 32)),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Length(8),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "account",
                "sent",
                "to it",
                "delivered",
                "refused",
                "bytes",
                "last",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(block);
        f.render_widget(table, area);
    }
}

/// A one-line account of the mediator's answer to a `config/patch`.
fn patch_summary(v: &Value) -> (String, bool) {
    let list = |k: &str| -> Vec<String> {
        v[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let rejected: Vec<String> = v["rejected"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| {
                    format!(
                        "{}: {}",
                        r["key"].as_str().unwrap_or("?"),
                        r["reason"].as_str().unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if !rejected.is_empty() {
        return (format!("refused — {}", rejected.join("; ")), true);
    }
    let applied = list("applied");
    let pending = list("pendingRestart");
    let mut parts = Vec::new();
    if !applied.is_empty() {
        parts.push(format!("in effect now: {}", applied.join(", ")));
    }
    if !pending.is_empty() {
        parts.push(format!("applies after a restart: {}", pending.join(", ")));
    }
    (parts.join("; "), false)
}

/// The row `state` selects, by its `key` member, to find it again after a
/// refresh.
fn selected_id(rows: &[Value], state: &TableState, key: &str) -> Option<String> {
    let i = state.selected()?;
    rows.get(i)?[key].as_str().map(str::to_string)
}

/// Select the row whose `key` is `id` (the row selected before a refresh);
/// when it is gone, keep the position, within the rows there are.
fn reselect(state: &mut TableState, rows: &[Value], key: &str, id: Option<String>) {
    let found = id.and_then(|id| rows.iter().position(|r| r[key] == id.as_str()));
    let i = found.unwrap_or_else(|| {
        state
            .selected()
            .unwrap_or(0)
            .min(rows.len().saturating_sub(1))
    });
    state.select(Some(i));
}

/// How many rows a list shows: `200`, `200 of 5000` when the total is known,
/// and `+ (] more)` when another page is waiting.
fn count_shown(shown: usize, total: Option<u64>, more: bool) -> String {
    let mut s = shown.to_string();
    match total {
        Some(t) if t > shown as u64 => s.push_str(&format!(" of {t}")),
        _ if more => s.push('+'),
        _ => {}
    }
    if more {
        s.push_str(" (] more)");
    }
    s
}

/// Whether the mediator has probably surveyed its queues again since the
/// one taken `at` (fetched `since` ago): a survey is due a minute after the
/// last. A survey that runs late is not chased every few seconds.
fn survey_due(
    at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    since: Duration,
) -> bool {
    let age = (now - at).to_std().unwrap_or_default();
    if age < SURVEY_EVERY {
        false
    } else if age < SURVEY_EVERY * 2 {
        since >= REFRESH
    } else {
        since >= SURVEY_EVERY / 2
    }
}

/// The header's connection badge: what the SDK says of the connection, and
/// for how long (`since`) when it is down.
fn link_badge(link: Option<ConnState>, since: Duration) -> (String, Color) {
    match link {
        Some(ConnState::Connected) => ("● connected".into(), Color::Green),
        Some(ConnState::Connecting) => ("◌ connecting".into(), Color::DarkGray),
        Some(ConnState::Disconnected) => (
            format!(
                "✗ disconnected {} — reconnecting",
                human_secs(Some(since.as_secs()))
            ),
            Color::Red,
        ),
        // No websocket (or a state this console doesn't know): say so rather
        // than claim a connection.
        _ => ("? connection unknown".into(), Color::Yellow),
    }
}

/// An audit time, local: `MM-DD HH:MM:SS`.
fn when_of(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| ts.to_string())
}

/// An audit entry's `detail` object as `key=value` pairs.
fn detail_line(detail: &Value) -> String {
    match detail {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            })
            .collect::<Vec<_>>()
            .join(" "),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// A configuration value as the console shows it.
fn config_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "–".into(),
        other => other.to_string(),
    }
}

/// What a confirmed purge did, against what was counted.
fn purge_summary(matched: u64, purged: u64) -> String {
    if purged < matched {
        format!(
            "purged {purged} of the {matched} message(s) counted; the rest were delivered or \
             deleted meanwhile"
        )
    } else {
        format!("purged {purged} message(s)")
    }
}

/// The lines a delete confirmation shows: whose message, from which queue,
/// which one, from and to whom.
fn delete_summary(book: &AddressBook, account: &str, send: bool, m: &Value) -> Vec<String> {
    let who = |k: &str| {
        m[k].as_str()
            .map_or_else(|| "anonymous".to_string(), |h| label(book, h))
    };
    vec![
        format!("Account  {account}"),
        format!("Queue    {}", if send { "send" } else { "receive" }),
        format!("Message  {}", m["msgId"].as_str().unwrap_or("?")),
        format!("From     {}", who("from")),
        format!("To       {}", who("to")),
        format!(
            "Received {}  ({})",
            m["receivedAt"].as_str().unwrap_or("?"),
            human_bytes(m["size"].as_u64())
        ),
    ]
}

/// The Accounts list's order: the mediator and administrators first, then
/// accounts you have named (by name), then the rest by hash.
fn account_order(a: &Value, book: &AddressBook) -> (u8, String) {
    let hash = a["did"].as_str().unwrap_or("");
    let rank = match a["accountType"].as_str() {
        Some("mediator") => 0,
        Some("rootAdmin") => 1,
        Some("admin") => 2,
        _ if book.name_of(hash).is_some() => 3,
        _ => 4,
    };
    let key = book
        .name_of(hash)
        .map(str::to_lowercase)
        .unwrap_or_else(|| hash.to_string());
    (rank, key)
}

/// `s` padded or cut (with `…`) to exactly `width` characters.
fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        format!("{s}{}", " ".repeat(width - n))
    } else {
        let cut: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// A column width that fits the longest of `labels` (plus a space), held
/// between `min` and `max`.
fn fit_width(labels: &[String], min: u16, max: u16) -> u16 {
    let longest = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0) as u16;
    (longest + 1).clamp(min, max)
}

/// An account hash as the user knows it: its nickname, else a short hash.
fn label(book: &AddressBook, hash: &str) -> String {
    book.name_of(hash)
        .map(str::to_string)
        .unwrap_or_else(|| short(hash))
}

/// One monitor event as a coloured line.
fn event_line(e: &Value, book: &AddressBook, name_w: usize) -> Line<'static> {
    let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
    let stage = s("stage");
    let color = match stage.as_str() {
        "refused" => Color::Red,
        "delivered" => Color::Green,
        "forwarded" => Color::Cyan,
        "stored" => Color::Blue,
        "deleted" | "purged" | "expired" => Color::Magenta,
        _ => Color::Reset,
    };
    let arrow = match s("direction").as_str() {
        "inbound" => "▶",
        "outbound" => "◀",
        _ => "·",
    };
    let mut spans = vec![
        Span::styled(
            time_of(&s("occurredAt")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {arrow} ")),
        Span::styled(format!("{stage:<9}"), Style::default().fg(color)),
        Span::raw(format!(" {:<9} {:<9} ", s("protocol"), s("channel"))),
        Span::raw(format!(
            "{} → {} ",
            fit(
                &e["from"].as_str().map_or("·".into(), |h| label(book, h)),
                name_w
            ),
            fit(
                &e["to"].as_str().map_or("·".into(), |h| label(book, h)),
                name_w
            )
        )),
        Span::styled(
            human_bytes(e["size"].as_u64()),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if let Some(code) = e["outcome"]["code"].as_str() {
        spans.push(Span::styled(
            format!("  {code}"),
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

fn inspect_popup(m: &InspectedMessage) -> Popup {
    let meta = serde_json::to_string_pretty(&m.meta).unwrap_or_default();
    let body = match &m.opened {
        Some((message, _)) => format!(
            "{meta}\n\n── decrypted ──\n{}",
            serde_json::to_string_pretty(message).unwrap_or_default()
        ),
        // All of it: the popup scrolls, and `y` / `w` take it whole.
        None => format!(
            "{meta}\n\n── encrypted ──\nThis session does not hold the recipient's key.\n\n{}",
            m.envelope
        ),
    };
    Popup::Inspect {
        id: m.meta.msg_id.to_string(),
        body,
        scroll: 0,
    }
}

fn render_popup(f: &mut Frame, area: Rect, popup: &Popup, book: &AddressBook) {
    let mut scroll = 0;
    let mut tall = false;
    let (title, body, danger) = match popup {
        Popup::Inspect {
            body, scroll: down, ..
        } => {
            scroll = *down;
            tall = true;
            (
                " Message — ↑↓ PgUp PgDn scroll  y copy  w write to a file  Esc close ".into(),
                body.clone(),
                false,
            )
        }
        // Drawn by `App::render_help`, which knows the screen.
        Popup::Help { .. } => return,
        Popup::ConfirmAccount {
            who,
            changes,
            warning,
            ..
        } => (
            " Change an account ".into(),
            format!(
                "Account  {who}\n\n{}\n{}\ny applies these changes; any other key goes back to \
                 editing.",
                changes
                    .iter()
                    .map(|c| format!("  {c}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                warning
                    .as_deref()
                    .map(|w| format!("\n{w}\n"))
                    .unwrap_or_default(),
            ),
            true,
        ),
        Popup::ConfirmPatch { key, from, to, .. } => (
            " Change the configuration ".into(),
            match to {
                Value::Null => format!(
                    "Reset the override of\n  {key}\n(now {from}) to the configured value?\n\n\
                     y to confirm, any other key to cancel"
                ),
                to => format!(
                    "{key}\n  {from} → {}\n\ny applies it; any other key goes back to editing.",
                    config_value(to)
                ),
            },
            true,
        ),
        Popup::Name {
            hash,
            did,
            name,
            on_name,
        } => {
            let cursor = |on: bool| if on { "▏" } else { "" };
            let account = match hash {
                Some(h) => format!("Account  {h}\n\n"),
                None => String::new(),
            };
            let check = match (hash, did.trim()) {
                (Some(h), d) if !d.is_empty() => {
                    if account_hash(d) == *h {
                        "      ✓ this is the account\n"
                    } else {
                        "      ✗ a different account\n"
                    }
                }
                _ => "",
            };
            (
                " Name an account ".into(),
                format!(
                    "{account}DID   {did}{}\n{check}Name  {name}{}\n\n\
                     Paste or type. Tab switches field, ⏎ saves, Esc cancels.\n\
                     The DID is optional when an account is selected. An empty name \
                     removes the entry.",
                    cursor(!*on_name),
                    cursor(*on_name),
                ),
                false,
            )
        }
        Popup::Book { selected } => {
            let entries = book.entries();
            let body = if entries.is_empty() {
                "No names yet. Select an account and press n, or press a here to add one.".into()
            } else {
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        format!(
                            "{} {:<24} {}  {}",
                            if i == *selected { "▶" } else { " " },
                            e.name,
                            short(&e.hash()),
                            if e.is_bare_hash() {
                                "(no DID)".to_string()
                            } else {
                                short_did(&e.did)
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            (
                " Address book ".into(),
                format!("{body}\n\n↑↓ select  n rename  a add  x remove  any other key closes"),
                false,
            )
        }
        // Drawn by `App::render_logs`, which has the log.
        Popup::Logs { .. } => return,
        Popup::EditAccount(edit) => {
            let rows = edit
                .rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let here = i == edit.selected;
                    let value = match (&edit.typing, r) {
                        (Some(t), Setting::Limit(..)) if here => format!("{t}▏"),
                        _ => r.shown(),
                    };
                    format!("{} {:<30} {value}", if here { "▶" } else { " " }, r.name())
                })
                .collect::<Vec<_>>()
                .join("\n");
            (
                format!(" Edit account {} ", short(&edit.target)),
                format!(
                    "{rows}\n\n↑↓ select  space toggle / cycle  digits set a limit (-1 = unlimited)\n\
                     s save  Esc cancel. The mediator decides what this session may change."
                ),
                false,
            )
        }
        Popup::EditConfig { key, value } => (
            " Change a limit ".into(),
            format!(
                "{key}\n\nNew value  {value}▏\n\n\
                 ⏎ applies, Esc cancels. A patch can make a limit stricter than the\n\
                 configuration, not looser; the mediator says which keys apply now,\n\
                 which from its next start, and why any are refused."
            ),
            false,
        ),
        Popup::Text { title, body } => (
            title.clone(),
            format!("{body}\n\n(any key to close)"),
            false,
        ),
        Popup::ConfirmDelete { ids, about, .. } => (
            " Delete ".into(),
            format!(
                "Delete {} message(s)? This cannot be undone.\n\n{}\n\ny to confirm, any other key to cancel",
                ids.len(),
                about.join("\n"),
            ),
            true,
        ),
        Popup::FindGrants {
            principal,
            member,
            on_member,
        } => {
            let cursor = |on: bool| if on { "▏" } else { "" };
            (
                " Find stored grants ".into(),
                format!(
                    "Principal DID  {principal}{}\nMember DID     {member}{}\n\n\
                     Paste or type either or both. Tab switches field, ⏎ lists, Esc cancels.\n\
                     A member's listing shows its current epoch.",
                    cursor(!*on_member),
                    cursor(*on_member),
                ),
                false,
            )
        }
        Popup::ConfirmRevoke(selection) => (
            " Revoke grants ".into(),
            format!(
                "Revoke {}?\n\nRevoked grants are deleted and their members detached at once; \
                 the signed statements can never be stored again.\n\n\
                 y to confirm, any other key to cancel",
                selection.describe()
            ),
            true,
        ),
        Popup::ConfirmRevokeMarked(keys) => {
            let members = keys
                .iter()
                .map(|k| &k.member)
                .collect::<BTreeSet<_>>()
                .len();
            (
                " Revoke marked grants ".into(),
                format!(
                    "Revoke {} marked grant(s) of {members} member(s)?\n\n\
                     Each is revoked on its own: one the mediator refuses (a rootAdmin's, \
                     say) leaves the rest to go ahead, and you're told which.\n\n\
                     y to confirm, any other key to cancel",
                    keys.len()
                ),
                true,
            )
        }
        Popup::ConfirmBumpEpoch { did, epoch } => (
            " Advance a member's epoch ".into(),
            format!(
                "Member {did}\nCurrent epoch {epoch} → {}\n\n\
                 Every grant the member gave is voided and its session attaches end, \
                 without its signature. Only epoch {epoch} is named: if it has moved \
                 on since, nothing changes.\n\n\
                 y to confirm, any other key to cancel",
                epoch + 1
            ),
            true,
        ),
        Popup::ConfirmPurge(plan) => (
            " Purge ".into(),
            format!(
                "Account  {}\n\nPurge {} message(s) ({}) from the {} queue{}?\n\
                 Only messages queued before this count can go: one arriving now stays. \
                 Fewer may go, if some are delivered meanwhile.\n\
                 Undelivered messages are gone, not returned to their senders.\n\n\
                 y to confirm, any other key to cancel",
                plan.request
                    .target
                    .as_deref()
                    .map_or_else(|| "your own".to_string(), |t| label(book, t)),
                plan.matched,
                human_bytes(Some(plan.matched_bytes)),
                format!("{:?}", plan.request.queue).to_lowercase(),
                plan.request
                    .peer
                    .as_deref()
                    .map(|p| format!(" exchanged with {}", label(book, p)))
                    .unwrap_or_default(),
            ),
            true,
        ),
    };
    let w = area.width.saturating_sub(8).min(100);
    let h = area
        .height
        .saturating_sub(if tall { 2 } else { 4 })
        .min(match (tall, danger) {
            (true, _) => u16::MAX,
            (false, true) => 18,
            (false, false) => 40,
        });
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    let border = if danger { Color::Red } else { Color::Cyan };
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border))
                    .title(title),
            ),
        rect,
    );
}

/// The monitor's feed, kept up for as long as the pane is open: a feed that
/// ends (its lease renewal failed, say, with the connection down) or goes
/// silent is replaced, after a backoff. Only a refusal stops it, since asking
/// again would get the same answer.
///
/// `membership` adds mux membership events; a mediator that doesn't serve
/// them (one that predates them, its version unknown) gets the traffic feed
/// alone rather than no feed.
async fn watch(
    console: Arc<MediatorConsole>,
    filter: MonitorFilter,
    mut membership: Option<MembershipFilter>,
    tx: mpsc::UnboundedSender<Update>,
) {
    let mut failures = 0;
    loop {
        let opened = console
            .monitor_with(filter.clone(), membership.clone())
            .await;
        let reason = match opened {
            Err(e) if membership.is_some() && is_unsupported(&e) => {
                membership = None;
                continue;
            }
            opened => opened,
        };
        let reason = match reason {
            Ok(mut feed) => loop {
                match tokio::time::timeout(MONITOR_SILENCE, feed.next()).await {
                    Ok(Some(MonitorUpdate::Ended(reason))) => break reason,
                    Ok(Some(update)) => {
                        failures = 0;
                        if tx.send(Update::Monitor(update)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break "the feed closed".to_string(),
                    Err(_) => {
                        break format!(
                            "nothing from the mediator for {}s",
                            MONITOR_SILENCE.as_secs()
                        );
                    }
                }
                // Dropping the feed on the way out unsubscribes it.
            },
            Err(e) if is_refusal(&e) => {
                let _ = tx.send(Update::MonitorFailed(e));
                return;
            }
            Err(e) => e.to_string(),
        };
        let after = resubscribe_after(failures);
        failures += 1;
        if tx.send(Update::MonitorRetrying { reason, after }).is_err() {
            return;
        }
        tokio::time::sleep(after).await;
    }
}

/// The mediator doesn't serve what was asked (its type is unsupported).
fn is_unsupported(e: &ConsoleError) -> bool {
    // `unsupportedType` from a mediator at 0.53 or later; the older
    // mediator's own code before that.
    e.refusal_code().is_some_and(|c| {
        c.ends_with("unsupportedType")
            || c.ends_with("unsupportedVersion")
            || c.ends_with("protocol.trust_task.unsupported")
    })
}

/// A subscribe the mediator (or the console, knowing its answer) turned down.
fn is_refusal(e: &ConsoleError) -> bool {
    matches!(
        e,
        ConsoleError::Refused { .. } | ConsoleError::NotPermitted(_)
    )
}

/// How long to wait before the next subscribe, after `failures` in a row.
fn resubscribe_after(failures: u32) -> Duration {
    RESUBSCRIBE
        .saturating_mul(2u32.saturating_pow(failures.min(8)))
        .min(RESUBSCRIBE_MAX)
}

/// `text` cut into rows of at most `width` characters.
fn wrap_hard(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width.max(1))
        .map(|c| c.iter().collect())
        .collect()
}

fn sha256_hex(s: &str) -> String {
    sha256::digest(s)
}

fn to_value<T: serde::Serialize>(r: Result<T, ConsoleError>) -> Result<Value, ConsoleError> {
    r.map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
}

/// A DID hash shortened for a column.
fn short(s: &str) -> String {
    if s.chars().count() <= 14 {
        s.to_string()
    } else {
        let head: String = s.chars().take(8).collect();
        let tail: String = s
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{head}…{tail}")
    }
}

/// A DID cut to 30 characters (never inside one: DIDs from an address book
/// or a profile need not be ASCII).
fn short_did(s: &str) -> String {
    if s.chars().count() <= 32 {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(30).collect::<String>())
    }
}

fn time_of(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| ts.chars().take(8).collect())
}

fn human_secs(s: Option<u64>) -> String {
    match s {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3_600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3_600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

/// How long ago a Unix-seconds timestamp was, for the activity columns. A
/// mediator that doesn't serve the times, or has none for the account, gives
/// `None` — shown the same as any other unknown ("–").
fn ago(at: Option<u64>) -> String {
    let (Some(at), Ok(now)) = (at, std::time::SystemTime::UNIX_EPOCH.elapsed()) else {
        return "–".into();
    };
    // A time slightly in the future (clock skew between mediator and console)
    // reads as "now" rather than as a wrapped-around age.
    human_secs(Some(now.as_secs().saturating_sub(at)))
}

/// The wire mix of what arrived: TSP's share, and the counts behind it.
/// Empty until something has arrived — a share of nothing is not 0%.
fn protocol_mix(mix: &crate::tally::ProtocolMix) -> String {
    let Some(share) = mix.tsp_share() else {
        return String::new();
    };
    let mut parts = vec![format!("tsp {share:.0}%")];
    for (name, n) in [
        ("tsp", mix.tsp),
        ("didcomm", mix.didcomm),
        ("v1", mix.didcomm_v1),
        ("other", mix.other),
    ] {
        if n > 0 {
            parts.push(format!("{name} {n}"));
        }
    }
    format!("  {} ", parts.join(" · "))
}

/// An account's lifetime totals as the mediator counted them — not the
/// monitor's view, which only covers the current session. Empty against a
/// mediator that doesn't serve them.
fn lifetime_totals(stats: &Value) -> String {
    let Some(stats) = stats.as_object() else {
        return String::new();
    };
    let n = |k: &str| stats.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mix = |k: &str| {
        let counts = &stats[k];
        let at = |p: &str| counts[p].as_u64().unwrap_or(0);
        let (tsp, didcomm) = (at("tsp"), at("didcomm") + at("didcommV1"));
        match tsp + didcomm {
            0 => String::new(),
            total => format!(" ({}% tsp)", tsp * 100 / total),
        }
    };
    format!(
        "lifetime  in {} / {}{}   out {} / {}{}",
        n("messagesReceived"),
        human_bytes(Some(n("bytesReceived"))),
        mix("receivedByProtocol"),
        n("messagesSent"),
        human_bytes(Some(n("bytesSent"))),
        mix("sentByProtocol"),
    )
}

fn human_bytes(b: Option<u64>) -> String {
    match b {
        None => "–".into(),
        Some(b) if b < 1_024 => format!("{b}B"),
        Some(b) if b < 1_048_576 => format!("{:.1}K", b as f64 / 1_024.0),
        Some(b) => format!("{:.1}M", b as f64 / 1_048_576.0),
    }
}

/// A DID as the console shows it: its address-book name when it has one
/// (the book is keyed by DID hash), otherwise the DID shortened.
fn did_label(book: &AddressBook, did: &str) -> String {
    book.name_of(&sha256::digest(did))
        .map(str::to_string)
        .unwrap_or_else(|| short(did))
}

/// The Grants tab's query from the find popup's fields: blank is none.
fn grant_query(principal: &str, member: &str) -> GrantQuery {
    let did = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
    GrantQuery {
        principal: did(principal),
        member: did(member),
    }
}

/// The Grants tab's title: what is listed, the member's epoch, how many.
fn grants_title(
    query: &GrantQuery,
    epoch: Option<u64>,
    shown: usize,
    more: bool,
    marked: usize,
    book: &AddressBook,
) -> String {
    let mut parts = Vec::new();
    if let Some(p) = &query.principal {
        parts.push(format!("principal {}", did_label(book, p)));
    }
    if let Some(m) = &query.member {
        parts.push(format!("member {}", did_label(book, m)));
    }
    if parts.is_empty() {
        return " Stored grants ".into();
    }
    let mut title = format!(" Grants of {}", parts.join(" · "));
    if let Some(e) = epoch {
        title.push_str(&format!(" · member epoch {e}"));
    }
    title.push_str(&format!(
        ": {shown}{} ",
        if more { "+ (] for more)" } else { "" }
    ));
    if marked > 0 {
        title.push_str(&format!("· {marked} marked "));
    }
    title
}

/// A listed grant as a bulk revocation names it: its member DID and id.
fn grant_key(g: &Value) -> Option<GrantKey> {
    Some(GrantKey::new(g["did"].as_str()?, g["grantId"].as_str()?))
}

/// The grants marked on the Grants tab for a bulk revocation.
#[derive(Default, Debug)]
struct GrantMarks(BTreeSet<GrantKey>);

impl GrantMarks {
    /// Mark `key`, or unmark it when marked.
    fn toggle(&mut self, key: GrantKey) {
        if !self.0.remove(&key) {
            self.0.insert(key);
        }
    }

    /// Mark every grant in `listed`.
    fn mark_all(&mut self, listed: &[Value]) {
        self.0.extend(listed.iter().filter_map(grant_key));
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    fn contains(&self, key: &GrantKey) -> bool {
        self.0.contains(key)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Keep only the marks of grants in `listed`.
    fn retain_listed(&mut self, listed: &[Value]) {
        let listed: BTreeSet<GrantKey> = listed.iter().filter_map(grant_key).collect();
        self.0.retain(|k| listed.contains(k));
    }

    /// The marked grants, in the order `listed` shows them.
    fn in_listed_order(&self, listed: &[Value]) -> Vec<GrantKey> {
        listed
            .iter()
            .filter_map(grant_key)
            .filter(|k| self.0.contains(k))
            .collect()
    }

    /// After a bulk revocation: unmark what is gone — revoked, or no longer
    /// stored — and keep the rest marked, to try again.
    fn settle(&mut self, outcome: &BulkRevokeOutcome) {
        use affinidi_messaging_mediator_admin::GrantRevokeResult;
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

/// What advancing member `name`'s epoch did, in a sentence.
fn bump_summary(name: &str, named: u64, epoch: u64, advanced: bool, revoked: u64) -> String {
    if advanced {
        format!("epoch of {name} advanced {named} → {epoch}: {revoked} grant(s) voided")
    } else {
        format!("epoch {named} of {name} was already voided (now {epoch}); nothing changed")
    }
}

/// One mux membership change as a monitor line: who attached to or
/// detached from whose connection, how and why.
fn membership_line(e: &Value, book: &AddressBook, name_w: usize) -> Line<'static> {
    let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
    let change = s("change");
    let (arrow, color) = match change.as_str() {
        "attached" => ("⊕", Color::Green),
        "detached" => ("⊖", Color::Yellow),
        _ => ("·", Color::Reset),
    };
    Line::from(vec![
        Span::styled(
            time_of(&s("occurredAt")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {arrow} ")),
        Span::styled(format!("{change:<9}"), Style::default().fg(color)),
        Span::raw(format!(" {:<9} {:<9} ", "mux", s("wire"))),
        Span::raw(format!(
            "{} ⇢ {} ",
            fit(&label(book, &s("member")), name_w),
            fit(&label(book, &s("principal")), name_w),
        )),
        Span::styled(
            format!("{} {}", s("source"), s("reason")),
            Style::default().fg(Color::Magenta),
        ),
    ])
}

/// The Mux tab's title: how many connections, and whether the page covers
/// every instance of the mediator or only the one that answered.
fn mux_title(page: &Value) -> String {
    let n = page["connections"].as_array().map_or(0, Vec::len);
    let more = if page.get("nextCursor").is_some() {
        "+"
    } else {
        ""
    };
    let coverage = match page["coverage"].as_str() {
        Some("thisInstance") => " (this instance only)",
        _ => "",
    };
    format!(" Mux connections: {n}{more}{coverage} ")
}

/// Whether an audit `action` is a DID-multiplexing one (`mux_grant_suspend`,
/// `mux_grant_revoke`, `mux_revoke_all`, and any later `mux_` action).
fn is_mux_action(action: &str) -> bool {
    action.starts_with("mux_")
}

/// The dashboard line for `stats/show`'s `com.affinidi.mux` extension.
fn mux_summary_line(mux: &Value) -> String {
    let n = |k: &str| mux[k].as_u64().unwrap_or(0);
    let mut line = format!(
        "mux {} connections, {} members ({} grant, {} attach)",
        n("connections"),
        n("members"),
        n("membersByGrant"),
        n("membersByAttach")
    );
    if n("membersInactive") > 0 {
        line.push_str(&format!(", {} inactive", n("membersInactive")));
    }
    line
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_find_popup_s_blank_fields_name_nothing() {
        let q = super::grant_query("  did:example:p ", "");
        assert_eq!(q.principal.as_deref(), Some("did:example:p"));
        assert_eq!(q.member, None);
        assert!(super::grant_query(" ", "").is_empty());
    }

    #[test]
    fn the_grants_title_says_what_is_listed_and_the_member_s_epoch() {
        let book = super::AddressBook::new();
        let none = super::GrantQuery::default();
        assert_eq!(
            super::grants_title(&none, None, 0, false, 0, &book),
            " Stored grants "
        );
        let member = super::GrantQuery {
            principal: None,
            member: Some("did:ex:m".into()),
        };
        assert_eq!(
            super::grants_title(&member, Some(2), 3, true, 0, &book),
            " Grants of member did:ex:m · member epoch 2: 3+ (] for more) "
        );
        let both = super::GrantQuery {
            principal: Some("did:ex:p".into()),
            member: Some("did:ex:m".into()),
        };
        assert_eq!(
            super::grants_title(&both, None, 1, false, 0, &book),
            " Grants of principal did:ex:p · member did:ex:m: 1 "
        );
        assert_eq!(
            super::grants_title(&both, None, 4, false, 2, &book),
            " Grants of principal did:ex:p · member did:ex:m: 4 · 2 marked "
        );
    }

    fn listed(grants: &[(&str, &str)]) -> Vec<serde_json::Value> {
        grants
            .iter()
            .map(|(did, id)| serde_json::json!({ "did": did, "grantId": id, "principal": "did:p" }))
            .collect()
    }

    #[test]
    fn grants_are_marked_one_at_a_time_all_at_once_and_cleared() {
        use affinidi_messaging_mediator_admin::GrantKey;
        let rows = listed(&[("did:m1", "g1"), ("did:m1", "g2"), ("did:m2", "g1")]);
        let mut marks = super::GrantMarks::default();
        assert!(marks.is_empty());

        // The same grant id under another member is another grant.
        marks.toggle(GrantKey::new("did:m1", "g1"));
        assert!(marks.contains(&GrantKey::new("did:m1", "g1")));
        assert!(!marks.contains(&GrantKey::new("did:m2", "g1")));
        // Toggling again unmarks.
        marks.toggle(GrantKey::new("did:m1", "g1"));
        assert!(marks.is_empty());

        marks.mark_all(&rows);
        assert_eq!(marks.len(), 3);
        // Marking all again marks nothing twice.
        marks.mark_all(&rows);
        assert_eq!(marks.len(), 3);
        marks.clear();
        assert!(marks.is_empty());
        // A row without a member or id can't be marked.
        marks.mark_all(&[serde_json::json!({ "did": "did:m3" })]);
        assert!(marks.is_empty());
    }

    #[test]
    fn marks_follow_the_listing_and_are_revoked_in_its_order() {
        use affinidi_messaging_mediator_admin::GrantKey;
        let rows = listed(&[("did:m2", "g9"), ("did:m1", "g1"), ("did:m1", "g2")]);
        let mut marks = super::GrantMarks::default();
        marks.toggle(GrantKey::new("did:m1", "g2"));
        marks.toggle(GrantKey::new("did:m2", "g9"));
        assert_eq!(
            marks.in_listed_order(&rows),
            [GrantKey::new("did:m2", "g9"), GrantKey::new("did:m1", "g2")]
        );
        // A refresh that no longer lists a grant drops its mark.
        marks.retain_listed(&listed(&[("did:m1", "g1"), ("did:m1", "g2")]));
        assert_eq!(marks.len(), 1);
        assert!(marks.contains(&GrantKey::new("did:m1", "g2")));
    }

    #[test]
    fn after_a_bulk_revocation_only_the_grants_not_revoked_stay_marked() {
        use affinidi_messaging_mediator_admin::{
            BulkRevokeOutcome, ConsoleError, GrantKey, GrantRevokeResult,
        };
        let rows = listed(&[
            ("did:m", "revoked"),
            ("did:m", "gone"),
            ("did:root", "protected"),
            ("did:m", "lost"),
            ("did:m", "unsent"),
        ]);
        let mut marks = super::GrantMarks::default();
        marks.mark_all(&rows);
        let key = |id: &str| {
            GrantKey::new(
                if id == "protected" {
                    "did:root"
                } else {
                    "did:m"
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
                    GrantRevokeResult::Unconfirmed(ConsoleError::Connect("closed".into())),
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
    fn an_epoch_bump_says_whether_it_advanced() {
        assert_eq!(
            super::bump_summary("work", 0, 1, true, 2),
            "epoch of work advanced 0 → 1: 2 grant(s) voided"
        );
        assert_eq!(
            super::bump_summary("work", 0, 3, false, 0),
            "epoch 0 of work was already voided (now 3); nothing changed"
        );
    }

    #[test]
    fn a_membership_event_shows_who_joined_whom_and_why() {
        let book = super::AddressBook::new();
        let e = serde_json::json!({
            "occurredAt": "2026-09-21T10:11:12Z", "change": "detached",
            "member": "abcdef0123456789", "principal": "0123456789abcdef",
            "reason": "admin", "source": "grant", "wire": "tsp",
        });
        let text: String = super::membership_line(&e, &book, 14)
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("⊖ detached"), "{text}");
        assert!(text.contains("tsp"), "{text}");
        assert!(text.contains("grant admin"), "{text}");
    }

    #[test]
    fn the_mux_title_says_what_the_page_covers() {
        let page = serde_json::json!({
            "connections": [{}, {}], "coverage": "thisInstance", "nextCursor": "c"
        });
        assert_eq!(
            super::mux_title(&page),
            " Mux connections: 2+ (this instance only) "
        );
        let all = serde_json::json!({ "connections": [], "coverage": "allInstances" });
        assert_eq!(super::mux_title(&all), " Mux connections: 0 ");
    }

    #[test]
    fn mux_audit_actions_are_recognised() {
        for a in ["mux_grant_suspend", "mux_grant_revoke", "mux_revoke_all"] {
            assert!(super::is_mux_action(a), "{a}");
        }
        assert!(!super::is_mux_action("account_remove"));
    }

    #[test]
    fn the_mux_summary_line_reads_the_extension() {
        let mux = serde_json::json!({
            "scope": "instance", "connections": 2, "members": 5,
            "membersByGrant": 4, "membersByAttach": 1, "membersInactive": 1
        });
        assert_eq!(
            super::mux_summary_line(&mux),
            "mux 2 connections, 5 members (4 grant, 1 attach), 1 inactive"
        );
        let quiet = serde_json::json!({ "connections": 0, "members": 0 });
        assert_eq!(
            super::mux_summary_line(&quiet),
            "mux 0 connections, 0 members (0 grant, 0 attach)"
        );
    }

    use super::*;

    #[test]
    fn resubscribing_backs_off_to_a_ceiling() {
        let waits: Vec<u64> = (0..6).map(|n| resubscribe_after(n).as_secs()).collect();
        assert_eq!(waits, [2, 4, 8, 16, 30, 30]);
        assert_eq!(resubscribe_after(u32::MAX), RESUBSCRIBE_MAX);
    }

    #[test]
    fn only_a_refusal_stops_the_monitor() {
        assert!(is_refusal(&ConsoleError::Refused {
            code: "e.p.req.unauthorized".into(),
            comment: "no".into(),
            current_epoch: None,
        }));
        assert!(is_refusal(&ConsoleError::NotPermitted("monitor")));
        assert!(!is_refusal(&ConsoleError::Connect("dns error".into())));
    }

    #[test]
    fn short_did_never_cuts_inside_a_character() {
        let did = format!("did:web:{}", "é".repeat(40));
        let cut = short_did(&did);
        assert_eq!(cut.chars().count(), 31);
        assert!(cut.ends_with('…'));
        assert_eq!(short_did("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn the_connection_badge_is_never_a_stale_connected() {
        let (up, color) = link_badge(Some(ConnState::Connected), Duration::from_secs(90));
        assert_eq!((up.as_str(), color), ("● connected", Color::Green));
        let (down, color) = link_badge(Some(ConnState::Disconnected), Duration::from_secs(12));
        assert_eq!(color, Color::Red);
        assert!(down.contains("disconnected 12s"), "{down}");
        assert!(down.contains("reconnecting"), "{down}");
        // No websocket: unknown, not connected.
        let (unknown, _) = link_badge(None, Duration::ZERO);
        assert!(unknown.contains("unknown"), "{unknown}");
    }

    #[test]
    fn a_refresh_keeps_the_selection_on_the_same_row() {
        let rows = |ids: &[&str]| -> Vec<Value> {
            ids.iter()
                .map(|id| serde_json::json!({ "msgId": id }))
                .collect()
        };
        let mut state = TableState::default().with_selected(Some(1));
        let before = rows(&["a", "b", "c"]);
        let keep = selected_id(&before, &state, "msgId");
        assert_eq!(keep.as_deref(), Some("b"));
        // "a" was delivered and a new one arrived: "b" moved up a row.
        reselect(&mut state, &rows(&["b", "c", "d"]), "msgId", keep);
        assert_eq!(state.selected(), Some(0));
        // The selected row went: the position holds, within the rows left.
        let mut state = TableState::default().with_selected(Some(2));
        reselect(&mut state, &rows(&["x", "y"]), "msgId", Some("gone".into()));
        assert_eq!(state.selected(), Some(1));
    }

    #[test]
    fn a_page_replaces_or_adds_and_says_whether_more_wait() {
        let mut paged = Paged::default();
        paged.take(
            List::Audit,
            &serde_json::json!({ "entries": [{ "eventId": "1" }], "nextCursor": "c1" }),
            false,
        );
        assert!(!paged.paged());
        assert_eq!(paged.next.as_deref(), Some("c1"));
        paged.take(
            List::Audit,
            &serde_json::json!({ "entries": [{ "eventId": "2" }] }),
            true,
        );
        assert!(paged.paged());
        assert_eq!(paged.rows.len(), 2);
        assert_eq!(paged.next, None);
    }

    #[test]
    fn a_list_says_how_much_of_it_is_shown() {
        assert_eq!(count_shown(200, Some(5_000), true), "200 of 5000 (] more)");
        assert_eq!(count_shown(200, None, true), "200+ (] more)");
        assert_eq!(count_shown(3, Some(3), false), "3");
    }

    #[test]
    fn the_queue_ranking_is_asked_for_again_once_resurveyed() {
        let at = chrono::Utc::now();
        let secs = chrono::Duration::seconds;
        // The survey shown is still the latest.
        assert!(!survey_due(at, at + secs(30), Duration::from_secs(30)));
        // A minute on, a new one is due.
        assert!(survey_due(at, at + secs(61), Duration::from_secs(10)));
        // But not asked for again within one refresh.
        assert!(!survey_due(at, at + secs(61), Duration::from_secs(1)));
        // A survey running late is checked on every half minute, not tick.
        assert!(!survey_due(at, at + secs(300), Duration::from_secs(10)));
        assert!(survey_due(at, at + secs(300), Duration::from_secs(30)));
    }

    #[test]
    fn audit_detail_reads_as_key_value_pairs() {
        assert_eq!(
            detail_line(&serde_json::json!({ "queue": "receive", "purged": 3 })),
            "purged=3 queue=receive"
        );
        assert_eq!(detail_line(&Value::Null), "");
    }

    #[test]
    fn a_short_purge_says_what_happened_to_the_rest() {
        assert_eq!(purge_summary(3, 3), "purged 3 message(s)");
        assert!(purge_summary(3, 2).starts_with("purged 2 of the 3"));
    }

    #[test]
    fn a_delete_confirmation_names_its_account_queue_and_message() {
        let mut book = AddressBook::new();
        book.insert("did:example:alice", "alice");
        let m = serde_json::json!({
            "msgId": "m-1", "from": sha256::digest("did:example:alice"),
            "to": "bobhash", "receivedAt": "2026-09-21T10:00:00Z", "size": 10,
        });
        let lines = delete_summary(&book, "bob", false, &m).join("\n");
        for want in [
            "Account  bob",
            "Queue    receive",
            "Message  m-1",
            "From     alice",
            "To       bobhash",
        ] {
            assert!(lines.contains(want), "{want}:\n{lines}");
        }
    }

    #[test]
    fn short_keeps_ends_of_a_hash() {
        assert_eq!(short("abcdefghijklmnopqrstuvwxyz"), "abcdefgh…wxyz");
        assert_eq!(short("short"), "short");
    }

    #[test]
    fn human_units() {
        assert_eq!(human_secs(Some(59)), "59s");
        assert_eq!(human_secs(Some(7_200)), "2h");
        assert_eq!(human_bytes(Some(2_048)), "2.0K");
        assert_eq!(human_bytes(None), "–");
    }

    #[test]
    fn a_named_account_shows_by_its_name_and_others_by_short_hash() {
        let alice = "did:example:alice";
        let mut book = AddressBook::new();
        book.insert(alice, "alice");
        let bob_hash = sha256::digest("did:example:bob");
        let line = event_line(
            &serde_json::json!({
                "occurredAt": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "stored",
                "channel": "rest", "protocol": "didcomm",
                "from": sha256::digest(alice), "to": bob_hash,
            }),
            &book,
            14,
        );
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        // Aligned: the sender is padded to the column width.
        assert!(text.contains("alice          → "), "{text}");
        assert!(text.contains(&short(&bob_hash)), "{text}");
    }

    #[test]
    fn a_patch_answer_is_summarised_in_one_line() {
        let (text, bad) = patch_summary(&serde_json::json!({
            "applied": ["limits.listed_messages"],
            "pendingRestart": ["limits.rate_limit_per_ip"],
            "rejected": [],
        }));
        assert!(!bad);
        assert!(
            text.contains("in effect now: limits.listed_messages"),
            "{text}"
        );
        assert!(
            text.contains("after a restart: limits.rate_limit_per_ip"),
            "{text}"
        );

        let (text, bad) = patch_summary(&serde_json::json!({
            "applied": [], "pendingRestart": [],
            "rejected": [{ "key": "limits.listed_messages", "reason": "above the configured value" }],
        }));
        assert!(bad);
        assert!(text.contains("above the configured value"), "{text}");
    }

    #[test]
    fn text_is_fitted_to_its_column() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abcd", 4), "abcd");
        let names = vec![
            "short".to_string(),
            "a much longer account name".to_string(),
        ];
        assert_eq!(fit_width(&names, 15, 40), 27);
        assert_eq!(fit_width(&names, 15, 20), 20);
        assert_eq!(fit_width(&[], 15, 40), 15);
    }

    #[test]
    fn a_refusal_event_shows_its_code_in_red() {
        let line = event_line(
            &serde_json::json!({
                "occurredAt": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "refused",
                "channel": "rest", "protocol": "tsp", "from": "a", "size": 10,
                "outcome": { "code": "authorization.send" },
            }),
            &AddressBook::new(),
            14,
        );
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("refused") && text.contains("authorization.send"));
        assert!(line.spans.iter().any(|s| s.style.fg == Some(Color::Red)));
    }
}
