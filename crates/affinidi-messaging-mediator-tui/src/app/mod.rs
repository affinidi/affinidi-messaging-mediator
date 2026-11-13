//! The console application: background work against the mediator, and the
//! loop that ties keys, answers and drawing together.
//!
//! [`App`] is a component, not a program. A host owns the terminal and the
//! event loop and calls [`App::handle_key`], [`App::apply`] and
//! [`App::render`]; [`App::run`] is that loop for hosts that want it done for
//! them (the `mediator-console` binary does). Work against the mediator runs
//! on background tasks and comes back as [`Update`]s, so rendering never
//! waits on the network.
//!
//! The pieces:
//!
//! - `state` — the model: every answer as the typed Trust Task struct it
//!   arrived as, and where the user is in it;
//! - `keys` — what each key does;
//! - `monitor` — the live traffic pane and the feed behind it;
//! - `screens` — one pure `render` per screen, from the state;
//! - `popup` — confirmations, editors, help and the log.

mod format;
mod keys;
mod monitor;
mod popup;
mod screens;
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{
    AddressBook, BulkRevokeOutcome, ConnState, ConsoleError, InspectedMessage, MediatorConsole,
    MonitorUpdate, MuxConnectionsQuery, PurgePlan, audit_specs, config_specs, specs,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::logs::{CaptureGuard, LogCapture};
use crate::quota::ColorDepth;
use crate::requests::{InFlight, Job, Ticket};
use format::{did_label, human_secs, short};
use popup::{Popup, inspect_popup};
use state::{GrantQuery, Session, State, grant_key};

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
/// Grants asked for per page; a refresh asks for what is shown, up to the
/// mediator's 500.
const GRANT_PAGE: u64 = 100;

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

/// A result of background work, applied with [`App::apply`]. Each carries
/// the mediator's answer as the typed Trust Task struct it arrived as.
#[non_exhaustive]
pub enum Update {
    Stats(Box<Result<specs::stats::show::v0_1::Response, ConsoleError>>),
    Status(Result<specs::queue::status::v0_1::Response, ConsoleError>),
    /// A page of the queue ranking: the first (replacing what is shown) or,
    /// with `more`, the next one.
    Queues {
        more: bool,
        result: Result<specs::queue::list::v0_1::Response, ConsoleError>,
    },
    /// A page of the Account tab's queue.
    Messages {
        more: bool,
        result: Result<specs::message::list::v0_1::Response, ConsoleError>,
    },
    /// A page of the audit log.
    Audit {
        more: bool,
        result: Result<audit_specs::list::v0_2::Response, ConsoleError>,
    },
    /// A page of the account list.
    Accounts {
        more: bool,
        result: Result<specs::account::list::v0_2::Response, ConsoleError>,
    },
    /// The console's connection to the mediator changed state.
    Connection(ConnState),
    /// The answer to a tagged request: applied only while the screen still
    /// wants it (the same account, queue or listing it was asked for).
    Tagged(Ticket, Box<Update>),
    /// The mediator's configuration fields.
    Config(Result<config_specs::show::v0_1::Response, ConsoleError>),
    /// A page of live mux connections.
    Mux(Result<specs::mux::connections::v0_1::Response, ConsoleError>),
    /// A page of stored mux grants for the Grants tab's query: the first
    /// page (replacing what is shown) or, with `more`, the next one.
    Grants {
        result: Result<specs::mux::admin_list::v0_1::Response, ConsoleError>,
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
    AccountInfo(Box<Result<specs::account::get::v0_2::Account, ConsoleError>>),
    /// The mediator's answer to a configuration change.
    Patched(Result<config_specs::patch::v0_1::Response, ConsoleError>),
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

/// The console application.
pub struct App {
    console: Arc<MediatorConsole>,
    tx: mpsc::UnboundedSender<Update>,
    rx: mpsc::UnboundedReceiver<Update>,
    /// Everything the screens draw.
    s: State,
    /// Where the address book is saved, when it is.
    book_path: Option<PathBuf>,
    /// Keeps the host's log output captured while the console runs.
    log_guard: Option<CaptureGuard>,
    /// Background requests in flight, so late answers are dropped.
    inflight: InFlight,
    /// Set while refreshing after a change: requests go out even when one
    /// is pending, since that one may predate the change.
    forcing: bool,
    /// Which ranking the queue list shows, and when it was asked for.
    queues_view: Option<String>,
    queues_fetched: Option<Instant>,
    /// The mediator's account hash, to recognise the console's own traffic.
    mediator_hash: String,
    /// The monitor's feed, while the pane is open.
    monitor_task: Option<JoinHandle<()>>,
}

impl App {
    /// A console application over a connected session.
    pub fn new(console: MediatorConsole) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let session = Session::of(&console);
        // A mediator too old for the operations tasks still serves the audit
        // log, so an administrator starts there rather than on a dashboard
        // that cannot fill.
        let tab = match (session.admin(), session.serves_operations) {
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
        let mediator_hash = sha256::digest(console.mediator_did());
        let mut app = Self {
            s: State::new(session, tab, link.map(|s| *s.borrow())),
            console: Arc::new(console),
            tx,
            rx,
            book_path: None,
            log_guard: None,
            inflight: InFlight::default(),
            forcing: false,
            queues_view: None,
            queues_fetched: None,
            mediator_hash,
            monitor_task: None,
        };
        app.know_self();
        app.refresh();
        app
    }

    /// Keep the host's log output off the screen while the console runs, and
    /// show it on request (`l`) instead. Give the same capture to the host's
    /// `tracing` subscriber as its writer; see [`LogCapture`].
    pub fn with_logs(mut self, logs: LogCapture) -> Self {
        self.log_guard = Some(logs.hold());
        self.s.logs = Some(logs);
        self
    }

    /// Resolves when a log line was captured, so a host running its own loop
    /// knows to redraw. Never resolves without [`App::with_logs`].
    pub async fn log_changed(&self) {
        match &self.s.logs {
            Some(logs) => logs.changed().await,
            None => std::future::pending().await,
        }
    }

    /// Use `book` for account nicknames, saving changes to `path` when given.
    /// The console's own account and the mediator are named automatically
    /// unless the book names them.
    pub fn with_address_book(mut self, book: AddressBook, path: Option<PathBuf>) -> Self {
        self.s.book = book;
        self.book_path = path;
        self.know_self();
        self
    }

    /// Force a colour depth (the default is detected from the environment).
    pub fn with_color_depth(mut self, depth: ColorDepth) -> Self {
        self.s.depth = depth;
        self
    }

    fn know_self(&mut self) {
        self.s.book.know(self.console.did(), "you");
        self.s.book.know(self.console.mediator_did(), "mediator");
    }

    fn save_book(&mut self) {
        if let Some(path) = &self.book_path
            && let Err(e) = self.s.book.save(path)
        {
            self.s
                .set_notice(format!("address book not saved: {e}"), true);
        }
    }

    /// Show one account on the Account tab — `None` is the console's own.
    pub fn open_account(&mut self, did_hash: Option<String>) {
        self.s.tab = Tab::Account;
        self.set_target(did_hash);
    }

    /// Show the stored mux grants of a `principal` DID, a `member` DID, or
    /// those between the two on the Grants tab. Naming neither shows how to
    /// look some up.
    pub fn open_grants_of(&mut self, principal: Option<String>, member: Option<String>) {
        self.open_grants(GrantQuery { principal, member });
    }

    /// Point the Account tab at another account (or queue): nothing of the
    /// last one stays on screen, and answers still on their way for it are
    /// dropped when they arrive.
    fn set_target(&mut self, did_hash: Option<String>) {
        // The console's own account is `None`, however it was named.
        let did_hash = did_hash.filter(|h| *h != self.s.session.did_hash);
        if did_hash != self.s.target {
            self.s.status = None;
            self.s.account_info = None;
        }
        self.s.target = did_hash;
        self.s.messages.clear();
        self.refresh();
    }

    /// The view a job's answer belongs to, as it stands now: an answer asked
    /// for another one is dropped.
    fn view_of(&self, job: Job) -> String {
        let account = self.s.target.clone().unwrap_or_default();
        let queue = if self.s.message_send {
            "send"
        } else {
            "receive"
        };
        match job {
            Job::Status | Job::AccountInfo => account,
            Job::Messages | Job::More(List::Messages) => format!("{account}/{queue}"),
            // A popup for an account the user has left would be about the
            // wrong one.
            Job::Inspect | Job::PurgePreview if self.s.tab == Tab::Account => {
                format!("{account}/{queue}")
            }
            Job::Inspect | Job::PurgePreview => "elsewhere".into(),
            Job::Queues | Job::More(List::Queues) => self.queue_view(),
            Job::Grants => format!("{:?}", self.s.grants.query),
            _ => String::new(),
        }
    }

    /// Which ranking the queue list shows.
    fn queue_view(&self) -> String {
        format!("{}/{}", self.s.queue_send, self.s.sort)
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
        // instead of asking.
        if !screens::available(&self.s) {
            self.s.updated = Some(Instant::now());
            return;
        }
        match self.s.tab {
            Tab::Dashboard => {
                self.request(Job::Stats, false, |c| async move {
                    Update::Stats(Box::new(c.stats().await))
                });
                self.load_queues(false);
            }
            Tab::Queues => self.load_queues(false),
            Tab::Account => {
                let target = self.s.target.clone();
                let t = target.clone();
                self.request(Job::Status, false, move |c| async move {
                    Update::Status(c.queue_status(t, Some(10)).await)
                });
                self.request(Job::AccountInfo, false, move |c| async move {
                    Update::AccountInfo(Box::new(c.account_of(target).await))
                });
                // Paged past the first page, the list stays as loaded until
                // `r`: a refresh would drop what was paged in.
                if !self.s.messages.paged() {
                    self.load_messages(None);
                }
            }
            Tab::Audit if !self.s.audit.paged() => self.load_audit(None),
            Tab::Audit => {}
            Tab::Accounts => {
                let due = self
                    .s
                    .accounts_loaded
                    .is_none_or(|at| at.elapsed() >= ACCOUNTS_EVERY && !self.s.accounts.paged());
                if due {
                    self.load_accounts(None);
                }
            }
            Tab::Mux => self.request(Job::Mux, false, |c| async move {
                // One page: up to 100 connections and 1000 members. The
                // screen says when there are more.
                let query = MuxConnectionsQuery::all().limit(100);
                Update::Mux(c.mux_connections(query).await)
            }),
            // Again from the first page, as many as are shown.
            Tab::Grants => {
                let limit = (self.s.grants.rows.len() as u64).clamp(GRANT_PAGE, 500);
                self.load_grants(None, limit);
            }
            Tab::Config => self.request(Job::Config, false, |c| async move {
                Update::Config(c.config().await)
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
        match self.s.tab {
            Tab::Dashboard | Tab::Queues => self.queues_fetched = None,
            Tab::Account => self.s.messages.pages = 0,
            Tab::Audit => self.s.audit.pages = 0,
            Tab::Accounts => self.s.accounts_loaded = None,
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
        if self.s.queues.paged() {
            return false;
        }
        match self.s.queues_snapshot {
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
        use specs::queue::list::v0_1::{PayloadSort, Queue};
        let queue = if self.s.queue_send {
            Queue::Send
        } else {
            Queue::Receive
        };
        let sort = match self.s.sort {
            1 => PayloadSort::Bytes,
            2 => PayloadSort::Oldest,
            3 => PayloadSort::Saturation,
            _ => PayloadSort::Count,
        };
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Queues)
        } else {
            Job::Queues
        };
        self.request(job, more, move |c| async move {
            let result = c
                .queues(Some(queue), Some(sort), cursor, Some(PAGE_ROWS))
                .await;
            Update::Queues { more, result }
        });
    }

    /// A page of the Account tab's queue: the first, or the one at `cursor`.
    fn load_messages(&mut self, cursor: Option<String>) {
        use specs::message::list::v0_1::Queue;
        let target = self.s.target.clone();
        let queue = if self.s.message_send {
            Queue::Send
        } else {
            Queue::Receive
        };
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Messages)
        } else {
            Job::Messages
        };
        self.request(job, more, move |c| async move {
            let result = c
                .messages(target, queue, None, cursor, Some(PAGE_ROWS))
                .await;
            Update::Messages { more, result }
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
            let result = c.audit(cursor, Some(PAGE_ROWS)).await;
            Update::Audit { more, result }
        });
    }

    /// A page of the account list: the first, or the one at `cursor`.
    fn load_accounts(&mut self, cursor: Option<String>) {
        let more = cursor.is_some();
        let job = if more {
            Job::More(List::Accounts)
        } else {
            self.s.accounts_loaded = Some(Instant::now());
            Job::Accounts
        };
        self.request(job, more, move |c| async move {
            let result = c.accounts(cursor, Some(ACCOUNT_PAGE)).await;
            Update::Accounts { more, result }
        });
    }

    /// A page of the Grants tab's query: from its start, or from `cursor`
    /// (then added to what is shown). Nothing while there is no query.
    fn load_grants(&mut self, cursor: Option<String>, limit: u64) {
        if self.s.grants.query.is_empty() {
            return;
        }
        let GrantQuery { principal, member } = self.s.grants.query.clone();
        let more = cursor.is_some();
        let work = move |c: Arc<MediatorConsole>| async move {
            let result = c
                .mux_grants(principal.as_deref(), member.as_deref(), cursor, Some(limit))
                .await;
            Update::Grants { result, more }
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
        let g = &mut self.s.grants;
        g.query = query;
        g.rows.clear();
        g.epoch = None;
        g.next = None;
        g.marks.clear();
        g.table.select(Some(0));
        self.s.tab = Tab::Grants;
        self.refresh();
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
        let ok = |s: &mut State| s.updated = Some(Instant::now());
        let s = &mut self.s;
        match update {
            Update::Tagged(ticket, inner) => {
                let latest = self.inflight.finish(&ticket);
                if latest && ticket.view == self.view_of(ticket.job) {
                    self.apply(*inner);
                } else if latest && matches!(ticket.job, Job::PurgePreview | Job::Inspect) {
                    // The user moved on before it came: a popup now would be
                    // about something no longer on screen.
                    self.s.set_notice(
                        "that answer was for another account or queue; ask again here",
                        true,
                    );
                }
            }
            Update::Connection(state) => self.link_changed(state),
            Update::Stats(r) => match *r {
                Ok(v) => {
                    s.stats = Some(v);
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Queues { more, result } => match result {
                Ok(page) => {
                    if !more {
                        s.queues_snapshot = Some(page.snapshot_at);
                    }
                    let next = page.next_cursor.map(String::from);
                    s.queues.take(page.queues, next, more, |_| {});
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Messages { more, result } => match result {
                Ok(page) => {
                    let next = page.next_cursor.map(String::from);
                    s.messages.take(page.messages, next, more, |_| {});
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Audit { more, result } => match result {
                Ok(page) => {
                    s.audit.take(page.entries, page.next_cursor, more, |_| {});
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Accounts { more, result } => match result {
                Ok(page) => {
                    let next = page.next_cursor.map(String::from);
                    let book = &s.book;
                    s.accounts.take(page.accounts, next, more, |rows| {
                        rows.sort_by_cached_key(|a| screens::accounts::account_order(a, book))
                    });
                    ok(s)
                }
                Err(e) => {
                    // Not loaded after all: try again on the next refresh
                    // rather than in five minutes.
                    if !more {
                        s.accounts_loaded = None;
                    }
                    self.error(e)
                }
            },
            Update::Status(r) => match r {
                Ok(v) => {
                    s.status = Some(v);
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Mux(r) => match r {
                Ok(page) => {
                    let len = page.connections.len();
                    s.mux = Some(page);
                    if s.mux_table.selected().is_none_or(|i| i >= len) {
                        s.mux_table.select(Some(0));
                    }
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Grants { result, more } => match result {
                Ok(page) => {
                    let g = &mut s.grants;
                    if more {
                        g.rows.extend(page.grants);
                    } else {
                        g.rows = page.grants;
                        // A grant no longer listed can't be seen, so it
                        // can't stay marked.
                        g.marks.retain_listed(&g.rows);
                    }
                    g.epoch = page.epoch;
                    g.next = page.next_cursor.map(String::from);
                    let len = g.rows.len();
                    if g.table.selected().is_none_or(|i| i >= len) {
                        g.table.select(Some(0));
                    }
                    ok(s)
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
                Ok(epoch) => s.popup = Some(Popup::ConfirmBumpEpoch { did, epoch }),
                Err(e) => self.error(e),
            },
            Update::AccountInfo(r) => match *r {
                Ok(v) => {
                    s.account_info = Some(v);
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Config(r) => match r {
                Ok(v) => {
                    // Limits first (they are what can be changed), then the rest.
                    s.config.take(v.fields, None, false, |rows| {
                        rows.sort_by_key(|f| (!f.key.starts_with("limits."), f.key.to_string()))
                    });
                    ok(s)
                }
                Err(e) => self.error(e),
            },
            Update::Patched(r) => {
                match r {
                    Ok(v) => {
                        let (text, bad) = patch_summary(&v);
                        s.set_notice(text, bad)
                    }
                    Err(e) => self.error(e),
                }
                self.refresh_after_change();
            }
            Update::Inspected(r) => match *r {
                // Over whatever else is open: the user asked for it just now.
                Ok(m) => s.popup = Some(inspect_popup(&m)),
                Err(e) => self.error(e),
            },
            Update::PurgePreview(r) => match r {
                Ok(plan) if plan.matched == 0 => s.set_notice("nothing to purge", false),
                Ok(plan) => s.popup = Some(Popup::ConfirmPurge(plan)),
                Err(e) => self.error(e),
            },
            Update::Done(r) => {
                match r {
                    Ok(msg) => s.set_notice(msg, false),
                    Err(e) => self.error(e),
                }
                self.refresh_after_change();
            }
            Update::Monitor(u) => self.monitor_update(u),
            Update::MonitorFailed(e) => {
                self.monitor_task = None;
                s.monitor.running = false;
                s.monitor.retry_at = None;
                s.monitor
                    .note(format!("── monitor stopped: {e} ──"), Color::Red);
                self.error(e);
            }
            Update::MonitorRetrying { reason, after } => s.monitor.retrying(reason, after),
        }
    }

    /// The connection went down or came back: say so in the header, the
    /// monitor and the footer, and reload once it is back.
    fn link_changed(&mut self, state: ConnState) {
        let s = &mut self.s;
        let was = s.link.replace(state);
        if was == Some(state) {
            return;
        }
        let down_for = s.link_since.elapsed();
        s.link_since = Instant::now();
        match state {
            ConnState::Disconnected => {
                s.monitor.note(
                    "── connection to the mediator lost — reconnecting ──".into(),
                    Color::Red,
                );
                s.set_notice("connection to the mediator lost; reconnecting", true);
            }
            ConnState::Connected if was == Some(ConnState::Disconnected) => {
                s.monitor.note(
                    format!(
                        "── reconnected to the mediator after {} ──",
                        human_secs(Some(down_for.as_secs()))
                    ),
                    Color::Green,
                );
                s.set_notice("reconnected to the mediator", false);
                self.refresh_after_change();
            }
            _ => {}
        }
    }

    /// Wait for the next result of background work — for a host running its
    /// own loop. Apply it with [`App::apply`].
    pub async fn next_update(&mut self) -> Option<Update> {
        self.rx.recv().await
    }

    /// Report a bulk revocation: a summary, and every grant that was not
    /// revoked with why. Those stay marked, to try again; the rest are gone.
    fn revoked_marked(&mut self, outcome: BulkRevokeOutcome) {
        let s = &mut self.s;
        let summary = outcome.summary();
        s.grants.marks.settle(&outcome);
        if outcome.all_revoked() {
            s.set_notice(summary, false);
            return;
        }
        // Each grant not revoked, by its short id and its parties' names.
        let failures: Vec<String> = outcome
            .results
            .iter()
            .filter(|(_, r)| !r.is_revoked())
            .map(|(key, result)| {
                let principal = s
                    .grants
                    .rows
                    .iter()
                    .find(|g| grant_key(g) == *key)
                    .map(|g| format!(" → {}", did_label(&s.book, &g.principal)))
                    .unwrap_or_default();
                format!(
                    "• grant {} ({}{principal}): {}",
                    short(&key.grant_id),
                    did_label(&s.book, &key.member),
                    result.describe()
                )
            })
            .collect();
        s.set_notice(summary.clone(), true);
        s.popup = Some(Popup::Text {
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
        self.s.set_notice(e.explain(), true);
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
        let logs = self.s.logs.clone();
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
                _ = tick.tick() => if self.s.popup.is_none() { self.refresh() },
            }
        }
        self.stop_monitor();
        Ok(())
    }

    /// Draw the console into `area`.
    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        screens::render(f, area, &mut self.s);
    }
}

/// A one-line account of the mediator's answer to a `config/patch`, and
/// whether any of it was refused.
fn patch_summary(v: &config_specs::patch::v0_1::Response) -> (String, bool) {
    if !v.rejected.is_empty() {
        let rejected: Vec<String> = v
            .rejected
            .iter()
            .map(|r| format!("{}: {}", r.key.as_str(), r.reason.as_str()))
            .collect();
        return (format!("refused — {}", rejected.join("; ")), true);
    }
    let names = |keys: Vec<&str>| keys.join(", ");
    let mut parts = Vec::new();
    if !v.applied.is_empty() {
        parts.push(format!(
            "in effect now: {}",
            names(v.applied.iter().map(|k| k.as_str()).collect())
        ));
    }
    if !v.pending_restart.is_empty() {
        parts.push(format!(
            "applies after a restart: {}",
            names(v.pending_restart.iter().map(|k| k.as_str()).collect())
        ));
    }
    (parts.join("; "), false)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_patch_answer_is_summarised_in_one_line() {
        let answer = |v: serde_json::Value| -> config_specs::patch::v0_1::Response {
            serde_json::from_value(v).expect("a patch answer")
        };
        let (text, bad) = patch_summary(&answer(serde_json::json!({
            "applied": ["limits.listed_messages"],
            "pendingRestart": ["limits.rate_limit_per_ip"],
            "rejected": [],
        })));
        assert!(!bad);
        assert!(
            text.contains("in effect now: limits.listed_messages"),
            "{text}"
        );
        assert!(
            text.contains("after a restart: limits.rate_limit_per_ip"),
            "{text}"
        );

        let (text, bad) = patch_summary(&answer(serde_json::json!({
            "applied": [], "pendingRestart": [],
            "rejected": [{ "key": "limits.listed_messages", "reason": "above the configured value" }],
        })));
        assert!(bad);
        assert!(text.contains("above the configured value"), "{text}");
    }
}
