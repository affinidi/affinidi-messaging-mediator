//! A connected console session.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::ConnState;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::protocols::trust_tasks::{MuxAdminRevokeOutcome, MuxConnectionsQuery};
use affinidi_messaging_sdk::tasks::messaging::{
    access_list, account, acl, message, mux, queue, stats,
};
use affinidi_messaging_sdk::tasks::{audit, config};
use affinidi_messaging_sdk::{
    ATM, config::ATMConfig, messages::compat::UnpackMetadata, profiles::ATMProfile,
};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
use serde_json::Value;
use tokio::sync::watch;

use crate::error::{ConsoleError, Result, bounded};
use crate::grants::{BulkRevokeOutcome, GrantKey, GrantRevokeResult, GrantSelection};
use crate::identity::Identity;
use crate::live::{LiveStream, MembershipFilter, MonitorFeed, MonitorFilter};
use crate::purge::{PurgePlan, PurgeRequest, pinned_to_preview, transit_margin_secs};

/// Which account a call acts on: `None` is the console's own.
pub type Target = Option<String>;

/// What the connected account is at the mediator — decided by the mediator's
/// own record of it, never claimed by the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// An administrator: sees and manages every account. `root` adds the
    /// rootAdmin-only operations (reading another account's message bodies,
    /// granting or changing a privileged role — admin, rootAdmin, mediator —
    /// changing, removing or acting on the queues of another privileged
    /// account, and changing or reloading the configuration).
    Admin { root: bool },
    /// Any other account: its own queues, messages, settings and traffic.
    SelfService,
}

/// What this session may do, so a console can grey out what the mediator
/// would refuse. The mediator still enforces every rule; this only saves a
/// round trip and an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Mediator-wide views: stats, the queue ranking, any account's queues and
    /// message metadata, the audit log, configuration, monitoring everyone.
    pub mediator_wide: bool,
    /// Read another account's message body; grant or change a privileged role;
    /// change, remove or act on the queues of another privileged account;
    /// change or reload the configuration.
    pub root: bool,
    /// The account is served locally (has queues here). Needed for self-service
    /// message operations.
    pub local: bool,
    /// May edit its own access list.
    pub self_manage_list: bool,
    /// May change its own send-queue limit.
    pub self_manage_send_limit: bool,
    /// May change its own receive-queue limit.
    pub self_manage_receive_limit: bool,
}

/// A stored message fetched raw, and opened when this session can.
#[derive(Debug)]
pub struct InspectedMessage {
    pub meta: message::get::v0_1::MessageMeta,
    /// The envelope exactly as the mediator stores it.
    pub envelope: String,
    /// The decrypted message, when this session holds the recipient's
    /// key-agreement secret — its own messages, typically. `None` is the normal
    /// answer for someone else's message.
    pub opened: Option<(Message, UnpackMetadata)>,
}

/// How long a console waits: for the whole connection, and for each answer.
///
/// Every request the console sends is bounded (R1.2); a call that runs out
/// of time fails with [`ConsoleError::Timeout`], which
/// [`is_transient`](ConsoleError::is_transient). To bound one call
/// differently, wrap it in [`with_deadline`](crate::with_deadline); to cancel
/// one, drop its future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsoleOptions {
    /// The longest [`MediatorConsole::connect`] takes, all of it: resolving
    /// the DID, authenticating, and reading the account. Default 30 s.
    pub connect_timeout: Duration,
    /// The longest any one call waits for the mediator's answer. Default
    /// 30 s. [`MediatorConsole::mux_revoke`] sends up to
    /// [`MUX_REVOKE_MAX_ROUNDS`] requests and gets that many times this.
    pub request_timeout: Duration,
}

impl Default for ConsoleOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl ConsoleOptions {
    /// Bound the whole connection by `timeout`.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Bound each call by `timeout`.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

/// A live console session with one mediator, as one identity.
pub struct MediatorConsole {
    atm: ATM,
    profile: Arc<ATMProfile>,
    did: String,
    did_hash: String,
    mediator_did: String,
    account: account::get::v0_2::Account,
    mode: Mode,
    capabilities: Capabilities,
    live: LiveStream,
    /// The mediator's release, from its `readyz` probe; `None` when it could
    /// not be read.
    mediator_version: Option<String>,
    /// The connection's state, as the SDK publishes it.
    conn: Option<watch::Receiver<ConnState>>,
    /// How long each call waits for an answer.
    request_timeout: Duration,
}

/// The first mediator release that serves the operations tasks the console is
/// built on: `messaging/stats`, `queue`, `message` and `monitor`.
pub const OPERATIONS_SINCE: (u64, u64, u64) = (0, 28, 20);

/// The first mediator release that serves `config/patch`.
pub const CONFIG_PATCH_SINCE: (u64, u64, u64) = (0, 28, 27);

/// The first mediator release that serves DID multiplexing: the
/// administrator's stored-grant tasks (`messaging/mux/admin-list`,
/// `admin-revoke`, `admin-revoke-all`), an account's own grant tasks
/// (`messaging/mux/grant`, `list`, `revoke`, `revoke-all`) and
/// `messaging/monitor/subscribe` 0.2, with its mux membership events.
pub const MUX_ADMIN_SINCE: (u64, u64, u64) = (0, 52, 0);

/// How many `admin-revoke` requests [`MediatorConsole::mux_revoke`] sends at
/// most, each revoking up to 500 grants.
pub const MUX_REVOKE_MAX_ROUNDS: usize = 20;

/// The first mediator release that serves account activity times
/// (`includeActivity` on `account/get` and `account/list`).
pub const ACTIVITY_SINCE: (u64, u64, u64) = (0, 28, 33);

/// The first mediator release that serves each account's lifetime counters
/// (`includeStats` on `account/get` and `account/list`).
pub const STATS_SINCE: (u64, u64, u64) = (0, 28, 36);

impl MediatorConsole {
    /// Connect as `identity`, with a private SDK instance and the default
    /// [`ConsoleOptions`].
    pub async fn connect(identity: Identity) -> Result<Self> {
        Self::connect_with_options(identity, ConsoleOptions::default()).await
    }

    /// Connect as `identity`, with a private SDK instance, waiting as
    /// `options` says. The whole connection is bounded by
    /// [`ConsoleOptions::connect_timeout`].
    ///
    /// The instance is the console's alone, so the console takes every live
    /// message pushed to `identity`'s DID on it, as
    /// [`connect_exclusive`](Self::connect_exclusive) does.
    pub async fn connect_with_options(identity: Identity, options: ConsoleOptions) -> Result<Self> {
        let connect = async {
            let config = TDKConfig::headless()
                .map_err(|e| ConsoleError::connect("configuring the TDK", e))?;
            let tdk = TDKSharedState::new(config)
                .await
                .map_err(|e| ConsoleError::connect("starting the TDK", e))?;
            // The SDK's own REST calls get the same bound as the console's.
            let atm_config = ATMConfig::builder()
                .with_request_timeout(options.request_timeout)
                .build()
                .map_err(|e| ConsoleError::connect("configuring the SDK", e))?;
            let atm = ATM::new(atm_config, Arc::new(tdk))
                .await
                .map_err(|e| ConsoleError::connect("starting the SDK", e))?;
            Self::connect_inner(atm, identity, None, options.request_timeout).await
        };
        bounded_connect(options.connect_timeout, connect).await
    }

    /// Connect as `identity` through an SDK instance dedicated to the console,
    /// with the default [`ConsoleOptions`] (see
    /// [`connect_exclusive_with_options`](Self::connect_exclusive_with_options)
    /// for others). `identity`'s secrets are added to that instance's
    /// resolver.
    ///
    /// **The console takes every live message pushed to `identity`'s DID on
    /// that instance.** The SDK has no receive filtered by message type, so
    /// the console's reader pops each live message for the profile and keeps
    /// only its own monitor batches; anything else is dropped from the SDK's
    /// live cache (the mediator keeps its stored copy until it is picked up
    /// and deleted). Use this only when nothing else on `atm` reads live
    /// messages for the same DID. An application that shares the instance and
    /// the DID uses [`connect_with_unclaimed`](Self::connect_with_unclaimed),
    /// which hands those messages on instead.
    pub async fn connect_exclusive(atm: ATM, identity: Identity) -> Result<Self> {
        Self::connect_exclusive_with_options(atm, identity, ConsoleOptions::default()).await
    }

    /// [`connect_exclusive`](Self::connect_exclusive), waiting as `options`
    /// says; the same warning applies.
    ///
    /// The SDK instance's own REST timeout is its configuration's, not
    /// `options.request_timeout`; the console still bounds each call by the
    /// latter.
    pub async fn connect_exclusive_with_options(
        atm: ATM,
        identity: Identity,
        options: ConsoleOptions,
    ) -> Result<Self> {
        bounded_connect(
            options.connect_timeout,
            Self::connect_inner(atm, identity, None, options.request_timeout),
        )
        .await
    }

    /// Connect as `identity` through an existing SDK instance, taking every
    /// live message for the DID on it.
    ///
    /// Deprecated because the name does not say that the console drops other
    /// live messages for the DID. Choose explicitly:
    /// [`connect_exclusive`](Self::connect_exclusive) for an instance
    /// dedicated to the console (the same behaviour as this), or
    /// [`connect_with_unclaimed`](Self::connect_with_unclaimed) for one shared
    /// with the application's own live traffic.
    #[deprecated(
        since = "0.52.0",
        note = "drops other live messages for the DID; use connect_exclusive for a dedicated SDK instance or connect_with_unclaimed for a shared one"
    )]
    pub async fn connect_with(atm: ATM, identity: Identity) -> Result<Self> {
        Self::connect_exclusive(atm, identity).await
    }

    /// Connect as `identity` through an existing SDK instance, for an
    /// application that shares the SDK instance **and the DID** with its own
    /// live traffic, with the default [`ConsoleOptions`] (see
    /// [`connect_with_unclaimed_options`](Self::connect_with_unclaimed_options)
    /// for others): every pushed message that is not one of the console's
    /// monitor batches goes to `unclaimed`, with its unpack metadata, rather
    /// than being dropped.
    ///
    /// The console never deletes such a message at the mediator: the
    /// application acknowledges (deletes) it as it would any other. When
    /// `unclaimed` is full the message is not delivered to it (a warning is
    /// logged); it stays stored at the mediator for a later pickup.
    pub async fn connect_with_unclaimed(
        atm: ATM,
        identity: Identity,
        unclaimed: tokio::sync::mpsc::Sender<crate::live::Unclaimed>,
    ) -> Result<Self> {
        Self::connect_with_unclaimed_options(atm, identity, unclaimed, ConsoleOptions::default())
            .await
    }

    /// [`connect_with_unclaimed`](Self::connect_with_unclaimed), waiting as
    /// `options` says.
    ///
    /// The SDK instance's own REST timeout is its configuration's, not
    /// `options.request_timeout`; the console still bounds each call by the
    /// latter.
    pub async fn connect_with_unclaimed_options(
        atm: ATM,
        identity: Identity,
        unclaimed: tokio::sync::mpsc::Sender<crate::live::Unclaimed>,
        options: ConsoleOptions,
    ) -> Result<Self> {
        bounded_connect(
            options.connect_timeout,
            Self::connect_inner(atm, identity, Some(unclaimed), options.request_timeout),
        )
        .await
    }

    async fn connect_inner(
        atm: ATM,
        identity: Identity,
        unclaimed: Option<tokio::sync::mpsc::Sender<crate::live::Unclaimed>>,
        request_timeout: Duration,
    ) -> Result<Self> {
        if identity.secrets.is_empty() {
            return Err(ConsoleError::Identity(format!(
                "{} has no secrets to connect with",
                identity.did
            )));
        }
        atm.get_tdk()
            .secrets_resolver()
            .insert_vec(&identity.secrets)
            .await;

        let mediator_did = match identity.mediator_did.clone() {
            Some(m) => m,
            None => discover_mediator(&atm, &identity.did).await?,
        };

        let profile = ATMProfile::new(
            &atm,
            Some(identity.alias.clone()),
            identity.did.clone(),
            Some(mediator_did.clone()),
        )
        .await
        .map_err(|e| ConsoleError::connect(format!("setting up {}", identity.did), e))?;
        // `ATMProfile::new` drops a mediator it could not set up rather than
        // failing; a profile without one would fail every call later, so say
        // so now.
        profile.dids().map_err(|e| {
            ConsoleError::connect(
                format!(
                    "could not reach mediator {mediator_did} for {}",
                    identity.did
                ),
                e,
            )
        })?;
        let profile = atm
            .profile_add(&profile, true)
            .await
            .map_err(|e| ConsoleError::connect("authenticating to the mediator", e))?;

        let account = bounded(
            "messaging/account/get",
            request_timeout,
            atm.trust_tasks().account_get(&profile, None),
        )
        .await?;
        let (mode, capabilities) = classify(&account);
        let mediator_version = probe_version(&atm, &profile).await;
        let conn = profile.connection_state().await;
        let live = LiveStream::start(atm.clone(), profile.clone(), unclaimed, conn.clone());

        Ok(Self {
            conn,
            did_hash: crate::address_book::account_hash(&identity.did),
            did: identity.did,
            mediator_did,
            atm,
            profile,
            account,
            mode,
            capabilities,
            live,
            mediator_version,
            request_timeout,
        })
    }

    /// The console's connection to the mediator, live: it changes to
    /// [`ConnState::Disconnected`] on every drop and to
    /// [`ConnState::Connected`] on every reconnect, so a caller can show
    /// connectivity rather than infer it (R6.2). Wait on it with
    /// [`watch::Receiver::changed`].
    ///
    /// `None` when the SDK runs no websocket for the session (REST only); its
    /// state is then unknown, and a caller should say so rather than show it
    /// as connected.
    pub fn connection_state(&self) -> Option<watch::Receiver<ConnState>> {
        self.conn.clone()
    }

    /// The mediator's release, when it could be read at connect time.
    pub fn mediator_version(&self) -> Option<&str> {
        self.mediator_version.as_deref()
    }

    /// How long each call waits for the mediator's answer.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Wait `timeout` for each answer from now on. Monitor feeds already
    /// open keep the timeout they were opened with.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Send one request for `operation`, bounded by the request timeout.
    async fn call<T>(
        &self,
        operation: &'static str,
        request: impl Future<Output = std::result::Result<T, affinidi_messaging_sdk::errors::ATMError>>,
    ) -> Result<T> {
        bounded(operation, self.request_timeout, request).await
    }

    /// Whether the mediator serves the operations tasks: statistics, the queue
    /// ranking and queue status, message listing, reading, deleting and
    /// purging, and live traffic. Assumed to when its version is unknown;
    /// the mediator then answers for itself.
    pub fn serves_operations(&self) -> bool {
        self.serves_since(OPERATIONS_SINCE)
    }

    /// Whether the mediator's release is `since` or later; assumed to be
    /// when its version is unknown.
    fn serves_since(&self, since: (u64, u64, u64)) -> bool {
        self.mediator_version
            .as_deref()
            .and_then(parse_version)
            .is_none_or(|v| v >= since)
    }

    /// Refuse locally, with the reason, a task this mediator is too old to
    /// serve. An older mediator doesn't answer such a request at all, so
    /// sending it would only wait out the reply timeout.
    fn require_release(&self, since: (u64, u64, u64), task: &'static str) -> Result<()> {
        if self.serves_since(since) {
            return Ok(());
        }
        let (major, minor, patch) = since;
        Err(ConsoleError::Refused {
            code: "protocol.trust_task.unsupported".into(),
            current_epoch: None,
            comment: format!(
                "this mediator ({}) does not serve {task}: it needs \
                 affinidi-messaging-mediator {major}.{minor}.{patch} or later",
                self.mediator_version
                    .as_deref()
                    .unwrap_or("unknown version")
            ),
        })
    }

    fn require_operations(&self, task: &'static str) -> Result<()> {
        self.require_release(OPERATIONS_SINCE, task)
    }

    pub fn did(&self) -> &str {
        &self.did
    }
    /// The console's own account identifier at the mediator.
    pub fn did_hash(&self) -> &str {
        &self.did_hash
    }
    pub fn mediator_did(&self) -> &str {
        &self.mediator_did
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    /// The account as the mediator reported it at connect time.
    pub fn account(&self) -> &account::get::v0_2::Account {
        &self.account
    }

    /// Re-read the console's own account and recompute mode and capabilities
    /// — after an administrator changed its role or ACL, for example.
    pub async fn refresh(&mut self) -> Result<()> {
        self.account = self
            .call(
                "messaging/account/get",
                self.atm.trust_tasks().account_get(&self.profile, None),
            )
            .await?;
        (self.mode, self.capabilities) = classify(&self.account);
        Ok(())
    }

    fn require_admin(&self, what: &'static str) -> Result<()> {
        if self.capabilities.mediator_wide {
            Ok(())
        } else {
            Err(ConsoleError::NotPermitted(what))
        }
    }

    fn require_root(&self, what: &'static str) -> Result<()> {
        if self.capabilities.root {
            Ok(())
        } else {
            Err(ConsoleError::NotPermitted(what))
        }
    }

    /// Whether `target` names another account than the console's own.
    fn is_other(&self, target: &Target) -> bool {
        target.as_ref().is_some_and(|t| *t != self.did_hash)
    }

    /// A target other than the console's own account needs admin standing.
    fn require_target(&self, target: &Target, what: &'static str) -> Result<()> {
        if self.is_other(target) {
            self.require_admin(what)
        } else {
            Ok(())
        }
    }

    // ─── Mediator-wide (administrators) ─────────────────────────────────

    pub async fn stats(&self) -> Result<stats::show::v0_1::Response> {
        self.require_admin("mediator statistics")?;
        self.require_operations("messaging/stats/show")?;
        self.call(
            "messaging/stats/show",
            self.atm.trust_tasks().stats_show(&self.profile),
        )
        .await
    }

    /// One page of this mediator's live mux connections (DID
    /// multiplexing), as `messaging/mux/connections` reports them. Its
    /// `coverage` says whether the page covers every instance of the
    /// mediator or only the one that answered.
    pub async fn mux_connections(
        &self,
        query: MuxConnectionsQuery,
    ) -> Result<mux::connections::v0_1::Response> {
        self.require_admin("the mux connections")?;
        self.require_operations("messaging/mux/connections")?;
        self.call(
            "messaging/mux/connections",
            self.atm
                .trust_tasks()
                .mux_connections(&self.profile, &query),
        )
        .await
    }

    /// One page of accounts ranked by the given queue and key.
    pub async fn queues(
        &self,
        queue: Option<queue::list::v0_1::Queue>,
        sort: Option<queue::list::v0_1::PayloadSort>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<queue::list::v0_1::Response> {
        self.require_admin("the queue ranking")?;
        self.require_operations("messaging/queue/list")?;
        self.call(
            "messaging/queue/list",
            self.atm
                .trust_tasks()
                .queue_list(&self.profile, queue, sort, None, cursor, limit),
        )
        .await
    }

    /// One page of every account on the mediator, with activity times and
    /// lifetime counters where the mediator serves them.
    pub async fn accounts(
        &self,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<account::list::v0_2::Response> {
        self.require_admin("the account list")?;
        self.call(
            "messaging/account/list",
            self.atm.trust_tasks().account_list_detailed(
                &self.profile,
                cursor,
                limit,
                None,
                self.serves_activity(),
                self.serves_stats(),
            ),
        )
        .await
    }

    /// Whether this mediator serves each account's last-received and
    /// last-authenticated times.
    ///
    /// Unlike the other gates this one is closed when the version can't be
    /// read: `includeActivity` is a *request* member, and a mediator that
    /// predates it refuses the whole request rather than ignoring the member.
    /// Asking blind would cost the account view itself.
    pub fn serves_activity(&self) -> bool {
        self.mediator_version
            .as_deref()
            .and_then(parse_version)
            .is_some_and(|v| v >= ACTIVITY_SINCE)
    }

    /// Whether this mediator serves each account's lifetime counters.
    ///
    /// Closed when the version can't be read, for the same reason as
    /// [`serves_activity`](Self::serves_activity): `includeStats` is a
    /// request member, so asking a mediator that predates it would cost the
    /// account view itself rather than just the counters.
    pub fn serves_stats(&self) -> bool {
        self.mediator_version
            .as_deref()
            .and_then(parse_version)
            .is_some_and(|v| v >= STATS_SINCE)
    }

    /// One page of the audit log, newest first. Pass the previous page's
    /// `next_cursor` to continue.
    ///
    /// The log can be filtered by action, actor, outcome and time on the
    /// wire, but the SDK's `audit_list` does not take those members yet, so
    /// this lists everything.
    pub async fn audit(
        &self,
        cursor: Option<String>,
        page_size: Option<u32>,
    ) -> Result<audit::list::v0_2::Response> {
        self.require_admin("the audit log")?;
        self.call(
            "audit/list",
            self.atm
                .trust_tasks()
                .audit_list(&self.profile, cursor, page_size),
        )
        .await
    }

    /// Whether this session can change the mediator's configuration:
    /// a rootAdmin, on a mediator that serves `config/patch` (or whose version
    /// is unknown, when the mediator answers for itself).
    pub fn can_patch_config(&self) -> bool {
        self.capabilities.root && self.serves_since(CONFIG_PATCH_SINCE)
    }

    /// Change mediator limits at runtime (`config/patch`, rootAdmin). Keys are
    /// like `limits.queued_send_messages_hard`; a `null` value removes the
    /// key's override. The mediator checks each key on its own and answers
    /// which took effect now, which apply from its next start, and which it
    /// refused, with the reason.
    pub async fn patch_config(
        &self,
        overrides: serde_json::Map<String, Value>,
    ) -> Result<config::patch::v0_1::Response> {
        self.require_root("changing the mediator's configuration needs a rootAdmin")?;
        self.require_release(CONFIG_PATCH_SINCE, "config/patch")?;
        self.call(
            "config/patch",
            self.atm
                .trust_tasks()
                .config_patch(&self.profile, overrides),
        )
        .await
    }

    /// Re-read the mediator's limits from its configuration file and
    /// environment, without a restart (`config/reload`, rootAdmin). Answers
    /// which keys' running values changed; keys that apply only at a restart
    /// are never among them.
    pub async fn reload_config(&self) -> Result<config::reload::v0_1::Response> {
        self.require_root("reloading the mediator's configuration needs a rootAdmin")?;
        self.call(
            "config/reload",
            self.atm.trust_tasks().config_reload(&self.profile),
        )
        .await
    }

    /// The mediator's effective configuration, key by key.
    pub async fn config(&self) -> Result<config::show::v0_1::Response> {
        self.require_admin("the mediator configuration")?;
        self.call(
            "config/show",
            self.atm.trust_tasks().config_show(&self.profile, None),
        )
        .await
    }

    // ─── Accounts (administrators) ───────────────────────────────────────

    /// Register account `did_hash` (`messaging/account/add`, administrators)
    /// with `role` and, optionally, an ACL applied over the mediator's
    /// default. Creating an admin or rootAdmin account needs a rootAdmin.
    pub async fn add_account(
        &self,
        did_hash: String,
        role: account::add::v0_2::AccountType,
        acl: Option<account::add::v0_2::MediatorAcl>,
    ) -> Result<account::add::v0_2::Account> {
        use account::add::v0_2::AccountType;
        self.require_admin("adding an account")?;
        if matches!(role, AccountType::Admin | AccountType::RootAdmin) {
            self.require_root("creating a privileged account needs a rootAdmin")?;
        }
        self.call(
            "messaging/account/add",
            self.atm
                .trust_tasks()
                .account_add(&self.profile, did_hash, role, acl),
        )
        .await
    }

    /// Remove an account (`messaging/account/remove`): `None` is the
    /// console's own, which also ends this session's standing at the
    /// mediator. Another account needs an administrator (and a privileged
    /// one a rootAdmin); the mediator's own and rootAdmin accounts cannot be
    /// removed. `true` when a record was removed.
    pub async fn remove_account(&self, target: Target) -> Result<bool> {
        self.require_target(&target, "removing another account")?;
        self.call(
            "messaging/account/remove",
            self.atm.trust_tasks().account_remove(&self.profile, target),
        )
        .await
    }

    // ─── One account (self, or any for an administrator) ────────────────

    pub async fn account_of(&self, target: Target) -> Result<account::get::v0_2::Account> {
        self.require_target(&target, "another account")?;
        self.call(
            "messaging/account/get",
            self.atm.trust_tasks().account_get_detailed(
                &self.profile,
                target,
                self.serves_activity(),
                self.serves_stats(),
            ),
        )
        .await
    }

    /// The ACL of each of `did_hashes` (`messaging/acl/get`), and the ones
    /// the mediator does not know. Any account but the console's own needs
    /// an administrator.
    pub async fn acls(&self, did_hashes: Vec<String>) -> Result<acl::get::v0_1::Response> {
        if did_hashes.iter().any(|h| *h != self.did_hash) {
            self.require_admin("another account's ACL")?;
        }
        if did_hashes.is_empty() {
            return Err(ConsoleError::Invalid("name at least one account".into()));
        }
        self.call(
            "messaging/acl/get",
            self.atm.trust_tasks().acl_get(&self.profile, did_hashes),
        )
        .await
    }

    /// One page of an account's access list (`messaging/access-list/list`).
    /// With `entries`, only those of them on the list come back: a
    /// membership check. Pass the previous page's `next_cursor` to continue.
    pub async fn access_list(
        &self,
        target: Target,
        cursor: Option<String>,
        limit: Option<u32>,
        entries: Option<Vec<String>>,
    ) -> Result<access_list::list::v0_1::Response> {
        self.require_target(&target, "another account's access list")?;
        self.call(
            "messaging/access-list/list",
            self.atm
                .trust_tasks()
                .access_list_list(&self.profile, target, cursor, limit, entries),
        )
        .await
    }

    /// Change an account's access list (`messaging/access-list/update`):
    /// `clear` it, then `add`, then `remove` entries (account hashes), in
    /// that order, so `clear` with `add` replaces it. Answers what was added
    /// and removed, and the new count. The console's own list needs
    /// `selfManageList` (or an administrator); another account's, an
    /// administrator.
    pub async fn update_access_list(
        &self,
        target: Target,
        clear: bool,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Result<access_list::update::v0_1::Response> {
        if self.is_other(&target) {
            self.require_admin("another account's access list")?;
        } else if !self.capabilities.mediator_wide && !self.capabilities.self_manage_list {
            return Err(ConsoleError::NotPermitted(
                "this account may not change its own access list (selfManageList is off)",
            ));
        }
        if !clear && add.is_empty() && remove.is_empty() {
            return Err(ConsoleError::Invalid(
                "nothing to change: clear, add or remove entries".into(),
            ));
        }
        self.call(
            "messaging/access-list/update",
            self.atm
                .trust_tasks()
                .access_list_update(&self.profile, target, clear, add, remove),
        )
        .await
    }

    /// Both queues of an account, live; `peers` adds the top counterparties.
    pub async fn queue_status(
        &self,
        target: Target,
        peers: Option<u32>,
    ) -> Result<queue::status::v0_1::Response> {
        self.require_target(&target, "another account's queues")?;
        self.require_operations("messaging/queue/status")?;
        self.call(
            "messaging/queue/status",
            self.atm
                .trust_tasks()
                .queue_status(&self.profile, target, peers),
        )
        .await
    }

    /// One page of an account's queue: metadata only, oldest first.
    pub async fn messages(
        &self,
        target: Target,
        queue: message::list::v0_1::Queue,
        peer: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<message::list::v0_1::Response> {
        self.require_target(&target, "another account's messages")?;
        self.require_operations("messaging/message/list")?;
        self.call(
            "messaging/message/list",
            self.atm
                .trust_tasks()
                .message_list(&self.profile, target, queue, peer, cursor, limit),
        )
        .await
    }

    /// Fetch one stored message and, if this session can decrypt it, open it.
    /// Opening happens here, locally; the plaintext never goes back to the
    /// mediator.
    pub async fn inspect(&self, target: Target, msg_id: &str) -> Result<InspectedMessage> {
        if self.is_other(&target) && !self.capabilities.root {
            return Err(ConsoleError::NotPermitted(
                "reading another account's message body needs a rootAdmin",
            ));
        }
        self.require_operations("messaging/message/get")?;
        let got = self
            .call(
                "messaging/message/get",
                self.atm
                    .trust_tasks()
                    .message_get(&self.profile, target, msg_id),
            )
            .await?;
        let envelope = got.message.to_string();
        // Unpacking can resolve DIDs; it is bounded like a request.
        let opened = tokio::time::timeout(self.request_timeout, self.atm.unpack(&envelope))
            .await
            .ok()
            .and_then(|r| r.ok());
        Ok(InspectedMessage {
            meta: got.meta,
            envelope,
            opened,
        })
    }

    /// Delete stored messages by id, in one call. Unlike a purge there is no
    /// preview: the ids name exactly what goes. Each id's answer says
    /// whether it was deleted.
    pub async fn delete(
        &self,
        target: Target,
        msg_ids: &[String],
    ) -> Result<message::delete::v0_1::Response> {
        self.require_target(&target, "another account's messages")?;
        self.require_operations("messaging/message/delete")?;
        self.call(
            "messaging/message/delete",
            self.atm
                .trust_tasks()
                .message_delete(&self.profile, target, msg_ids),
        )
        .await
    }

    /// Count what a purge would remove, and return a plan to confirm.
    pub async fn purge_preview(&self, request: PurgeRequest) -> Result<PurgePlan> {
        self.require_target(&request.target, "another account's queue")?;
        // Taken before the request leaves, so the instant is never later than
        // the one the mediator counted at: pinning the purge to it can only
        // leave out, never add, a message.
        let previewed_at = chrono::Utc::now();
        let preview = self.run_purge(&request, true).await?;
        Ok(PurgePlan {
            matched: preview.matched,
            matched_bytes: preview.matched_bytes.unwrap_or(0),
            previewed_at,
            request,
        })
    }

    /// Carry out a previewed purge, pinned to the preview's instant.
    ///
    /// The purge is sent with an age that excludes every message that
    /// arrived after the preview (and, with an age of its own, every message
    /// that had not reached it by then): it removes only messages the
    /// preview could have counted. It can remove **fewer** than
    /// [`PurgePlan::matched`] — some may have been delivered or deleted
    /// since, and the age carries a safety margin
    /// (the time the request may take to execute: the console's request
    /// timeout, and at least
    /// [`PURGE_TRANSIT_MARGIN_SECS`](crate::PURGE_TRANSIT_MARGIN_SECS)) and is rounded up to whole
    /// seconds, so what arrived in that window before the preview is left
    /// out — but never a message newer than the preview, provided the
    /// mediator runs the purge within the margin. `purged` in the answer says
    /// how many went.
    ///
    /// The pin is an age the console computes; the mediator still decides
    /// what matches. The mediator also honours `storedBefore`, the exact
    /// form of this pin, but no published `affinidi-messaging-sdk` can send
    /// it yet (its `queue_purge` has no such parameter), so the console
    /// switches to it once one can (#122).
    pub async fn purge(&self, plan: PurgePlan) -> Result<queue::purge::v0_1::Response> {
        let request = pinned_to_preview(
            &plan,
            chrono::Utc::now(),
            transit_margin_secs(self.request_timeout),
        );
        self.run_purge(&request, false).await
    }

    async fn run_purge(
        &self,
        request: &PurgeRequest,
        dry_run: bool,
    ) -> Result<queue::purge::v0_1::Response> {
        self.require_operations("messaging/queue/purge")?;
        self.call(
            "messaging/queue/purge",
            self.atm.trust_tasks().queue_purge(
                &self.profile,
                request.target.clone(),
                request.queue,
                request.peer.clone(),
                request.older_than_seconds,
                dry_run,
            ),
        )
        .await
    }

    /// Apply a partial account update: role, capability flags, queue limits.
    /// Omitted members are unchanged. A single call, with no preview: show
    /// the user what changes before sending it.
    pub async fn update_account(
        &self,
        target: Target,
        role: Option<account::update::v0_2::AccountType>,
        acl: Option<account::update::v0_2::MediatorAcl>,
        limits: Option<account::update::v0_2::QueueLimits>,
    ) -> Result<account::update::v0_2::Account> {
        self.require_target(&target, "another account")?;
        if let Some(role) = &role {
            self.require_admin("changing a role")?;
            // Granting a privileged role is the mediator's rootAdmin-only rule;
            // checked here so the console can say so before the round trip.
            if *role != account::update::v0_2::AccountType::Standard {
                self.require_root("granting a privileged role needs a rootAdmin")?;
            }
        }
        self.call(
            "messaging/account/update",
            self.atm
                .trust_tasks()
                .account_update(&self.profile, target, role, acl, limits),
        )
        .await
    }

    // ─── Live traffic ────────────────────────────────────────────────────

    /// Open a live traffic monitor. Administrators may watch anything; any
    /// other account only its own traffic. The feed renews its lease itself
    /// and unsubscribes when dropped.
    pub async fn monitor(&self, filter: MonitorFilter) -> Result<MonitorFeed> {
        self.monitor_with(filter, None).await
    }

    /// [`monitor`](Self::monitor), with mux membership events as well when
    /// `membership` is given: each member DID attached to or detached from a
    /// principal's mux connection, as [`MonitorUpdate::Membership`]. An
    /// administrator sees every change; any other account only those it is
    /// party to. The feed's [`membership`](MonitorFeed::membership) is `None`
    /// when the mediator sends none (mux is not enabled there).
    ///
    /// Membership events need `monitor/subscribe` 0.2 ([`MUX_ADMIN_SINCE`]);
    /// a traffic-only feed falls back to 0.1 on an older mediator.
    ///
    /// [`MonitorUpdate::Membership`]: crate::MonitorUpdate::Membership
    pub async fn monitor_with(
        &self,
        filter: MonitorFilter,
        membership: Option<MembershipFilter>,
    ) -> Result<MonitorFeed> {
        self.require_operations("messaging/monitor/subscribe")?;
        if membership.is_some() {
            self.require_release(MUX_ADMIN_SINCE, "mux membership events")?;
        }
        self.live
            .open_feed(
                &self.atm,
                &self.profile,
                filter,
                membership,
                self.serves_mux_admin(),
                self.request_timeout,
            )
            .await
    }

    // ─── An account's own mux grants ─────────────────────────────────────

    /// Store grant statements (`messaging/mux/grant`), signed by the member
    /// with the SDK's `protocols::mux::sign_grant`. Either party may send
    /// them; each is accepted or refused on its own.
    pub async fn mux_grant(&self, statements: Vec<Value>) -> Result<mux::grant::v0_1::Response> {
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/grant")?;
        if statements.is_empty() {
            return Err(ConsoleError::Invalid("no grant statements to store".into()));
        }
        self.call(
            "messaging/mux/grant",
            self.atm.trust_tasks().mux_grant(&self.profile, statements),
        )
        .await
    }

    /// One page of this account's own stored grants (`messaging/mux/list`):
    /// those it holds as a principal, or with `as_member` those it gave, with
    /// its current epoch.
    pub async fn mux_own_grants(
        &self,
        as_member: bool,
        cursor: Option<String>,
        limit: Option<u64>,
    ) -> Result<mux::list::v0_1::Response> {
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/list")?;
        self.call(
            "messaging/mux/list",
            self.atm
                .trust_tasks()
                .mux_list(&self.profile, as_member, cursor, limit),
        )
        .await
    }

    /// Revoke this account's own grants (`messaging/mux/revoke`): as a
    /// principal, `dids` are members to drop; with `as_member`, principals
    /// to leave. `grant_ids` name grants directly either way.
    pub async fn mux_revoke_own(
        &self,
        as_member: bool,
        grant_ids: Vec<String>,
        dids: Vec<String>,
    ) -> Result<mux::revoke::v0_1::Response> {
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/revoke")?;
        if grant_ids.is_empty() && dids.is_empty() {
            return Err(ConsoleError::Invalid(
                "name the grants or DIDs to revoke".into(),
            ));
        }
        self.call(
            "messaging/mux/revoke",
            self.atm
                .trust_tasks()
                .mux_revoke(&self.profile, as_member, grant_ids, dids),
        )
        .await
    }

    /// Void every grant this account gave under an epoch
    /// (`messaging/mux/revoke-all`), with a statement signed by the member
    /// (the SDK's `protocols::mux::sign_revoke_all`). An administrator does
    /// this without the member's signature with
    /// [`mux_bump_epoch`](Self::mux_bump_epoch).
    pub async fn mux_revoke_all_own(
        &self,
        statement: Value,
    ) -> Result<mux::revoke_all::v0_1::Response> {
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/revoke-all")?;
        self.call(
            "messaging/mux/revoke-all",
            self.atm
                .trust_tasks()
                .mux_revoke_all(&self.profile, statement),
        )
        .await
    }

    // ─── Stored mux grants (administrators) ─────────────────────────────

    /// Whether this mediator serves DID multiplexing: the stored-grant tasks
    /// and monitor membership events. Assumed to when its version is
    /// unknown; the mediator then answers for itself.
    pub fn serves_mux_admin(&self) -> bool {
        self.serves_since(MUX_ADMIN_SINCE)
    }

    /// One page of stored mux grants (`messaging/mux/admin-list`): those of
    /// a `principal` DID, of a `member` DID, or between the two — at least
    /// one is required. Each grant's parties, state, effective scope and
    /// expiry, and the epoch it was signed under; never the signed
    /// statement. With `member`, the page's `epoch` is that DID's current
    /// epoch. Pass the previous page's `next_cursor`, with the same DIDs, to
    /// continue; `limit` is 1–500.
    pub async fn mux_grants(
        &self,
        principal: Option<&str>,
        member: Option<&str>,
        cursor: Option<String>,
        limit: Option<u64>,
    ) -> Result<mux::admin_list::v0_1::Response> {
        self.require_admin("the stored mux grants")?;
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/admin-list")?;
        if principal.is_none() && member.is_none() {
            return Err(ConsoleError::Invalid(
                "name a principal DID, a member DID, or both".into(),
            ));
        }
        self.call(
            "messaging/mux/admin-list",
            self.atm
                .trust_tasks()
                .mux_admin_list(&self.profile, principal, member, cursor, limit),
        )
        .await
    }

    /// A member DID's current mux epoch: the one
    /// [`mux_bump_epoch`](Self::mux_bump_epoch) names to void it.
    pub async fn mux_epoch(&self, member: &str) -> Result<u64> {
        let page = self.mux_grants(None, Some(member), None, Some(1)).await?;
        page.epoch.ok_or_else(|| {
            ConsoleError::Unexpected("the mediator listed a member without its epoch".into())
        })
    }

    /// Revoke the stored grants `selection` names
    /// (`messaging/mux/admin-revoke`), sending the request again while grants
    /// still match, at most [`MUX_REVOKE_MAX_ROUNDS`] times. Revoked grants
    /// are deleted and their members detached before each answer; the
    /// statements can never be stored again.
    ///
    /// The outcome says what was revoked, what still matches and why it
    /// stopped; [`revoke_summary`](crate::revoke_summary) puts that in a
    /// sentence. A refusal of the first request, with nothing revoked, is the
    /// error — `…:protectedAccount` when a party is a root administrator and
    /// this session is not one. The rounds together are bounded by
    /// [`MUX_REVOKE_MAX_ROUNDS`] request timeouts.
    pub async fn mux_revoke(&self, selection: &GrantSelection) -> Result<MuxAdminRevokeOutcome> {
        self.require_admin("revoking stored mux grants")?;
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/admin-revoke")?;
        selection.check()?;
        bounded(
            "messaging/mux/admin-revoke",
            self.request_timeout
                .saturating_mul(MUX_REVOKE_MAX_ROUNDS as u32),
            self.atm.trust_tasks().mux_admin_revoke_until_done(
                &self.profile,
                selection.principal.as_deref(),
                selection.member.as_deref(),
                &selection.grant_ids,
                None,
                MUX_REVOKE_MAX_ROUNDS,
            ),
        )
        .await
    }

    /// Revoke each of `grants`, one `admin-revoke` request per grant, and
    /// say what happened to each: revoked, no longer stored, refused (a
    /// rootAdmin party's grant is `…:protectedAccount`), or unconfirmed when
    /// a request was lost in transit or timed out — after which the rest are
    /// not sent.
    ///
    /// One request per grant because the mediator refuses a whole request
    /// when any grant it selects is protected; asked one at a time, every
    /// other grant is still revoked, and each refusal names its grant. A
    /// grant is reported revoked only when the mediator's answer lists it.
    pub async fn mux_revoke_each(&self, grants: &[GrantKey]) -> Result<BulkRevokeOutcome> {
        self.require_admin("revoking stored mux grants")?;
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/admin-revoke")?;
        let mut outcome = BulkRevokeOutcome::default();
        let mut lost = false;
        for key in grants {
            if lost {
                outcome
                    .results
                    .push((key.clone(), GrantRevokeResult::NotAttempted));
                continue;
            }
            let selection = GrantSelection::grants(&key.member, vec![key.grant_id.clone()]);
            let result = match self.mux_revoke(&selection).await {
                Ok(o) => {
                    let revoked: Vec<String> =
                        o.revoked.iter().map(|g| g.grant_id.to_string()).collect();
                    let unmatched: Vec<String> = o
                        .unmatched_grant_ids
                        .iter()
                        .map(|g| g.to_string())
                        .collect();
                    GrantRevokeResult::from_round(&key.grant_id, &revoked, &unmatched, &o.stopped)
                }
                Err(e) => GrantRevokeResult::from_error(e),
            };
            lost = matches!(result, GrantRevokeResult::Unconfirmed(_));
            outcome.results.push((key.clone(), result));
        }
        Ok(outcome)
    }

    /// Advance member `did`'s mux epoch (`messaging/mux/admin-revoke-all`),
    /// voiding every grant on it and ending its session attaches, without the
    /// member's signature. `epoch` is the one being voided — the DID's
    /// current epoch, from [`mux_epoch`](Self::mux_epoch) — so the change is
    /// a compare-and-set: naming an epoch already voided changes nothing
    /// (`epoch_advanced` is false), and naming a later one is refused with
    /// `…:epochMismatch` ([`ConsoleError::current_epoch`] reads the epoch in
    /// force from it).
    pub async fn mux_bump_epoch(
        &self,
        did: &str,
        epoch: u64,
    ) -> Result<mux::admin_revoke_all::v0_1::Response> {
        self.require_admin("advancing a member's mux epoch")?;
        self.require_release(MUX_ADMIN_SINCE, "messaging/mux/admin-revoke-all")?;
        self.call(
            "messaging/mux/admin-revoke-all",
            self.atm
                .trust_tasks()
                .mux_admin_revoke_all(&self.profile, did, epoch),
        )
        .await
    }

    /// The SDK instance, for an embedding application.
    pub fn atm(&self) -> &ATM {
        &self.atm
    }
    /// The console's SDK profile.
    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }
}

impl Drop for MediatorConsole {
    fn drop(&mut self) {
        self.live.stop();
    }
}

/// Run a connection, bounded by `after`.
async fn bounded_connect<T>(
    after: Duration,
    connect: impl Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(after, connect).await {
        Ok(result) => result,
        Err(_) => Err(ConsoleError::Timeout {
            operation: "connecting to the mediator",
            after,
        }),
    }
}

/// Mode and capabilities from the mediator's record of the account.
fn classify(account: &account::get::v0_2::Account) -> (Mode, Capabilities) {
    use account::get::v0_2::AccountType;
    let (admin, root) = match account.account_type {
        AccountType::RootAdmin => (true, true),
        AccountType::Admin => (true, false),
        // `standard`, `mediator`, and any role this console doesn't know:
        // never more than self-service.
        _ => (false, false),
    };
    let mode = if admin {
        Mode::Admin { root }
    } else {
        Mode::SelfService
    };
    let acl = &account.acl;
    let on = |flag: Option<bool>| flag.unwrap_or(false);
    (
        mode,
        Capabilities {
            mediator_wide: admin,
            root,
            local: on(acl.local),
            self_manage_list: on(acl.self_manage_list),
            self_manage_send_limit: on(acl.self_manage_send_queue_limit),
            self_manage_receive_limit: on(acl.self_manage_receive_queue_limit),
        },
    )
}

/// The mediator a DID names in its `DIDCommMessaging` service.
async fn discover_mediator(atm: &ATM, did: &str) -> Result<String> {
    let doc = atm
        .get_tdk()
        .did_resolver()
        .resolve(did)
        .await
        .map_err(|e| ConsoleError::Identity(format!("resolving {did}: {e}")))?
        .doc;
    doc.service
        .iter()
        .filter(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|s| s.service_endpoint.get_uris())
        .find_map(|uri| mediator_did_in(&uri))
        .ok_or_else(|| ConsoleError::NoMediator(did.to_string()))
}

/// The mediator DID a `DIDCommMessaging` endpoint URI names, if it names one
/// (rather than a URL). `affinidi-did-common` before 0.4.3 returns a map-form
/// endpoint's `uri` JSON-quoted, so the quotes are stripped first.
fn mediator_did_in(uri: &str) -> Option<String> {
    let uri = uri.trim_matches('"');
    uri.starts_with("did:").then(|| uri.to_string())
}

/// The mediator's release from its public `readyz` endpoint, best effort: any
/// failure (no REST endpoint, unreachable, an older mediator without a
/// `version` member) is `None`.
async fn probe_version(atm: &ATM, profile: &ATMProfile) -> Option<String> {
    let base = profile.get_mediator_rest_endpoint()?;
    let url = format!("{}/readyz", base.trim_end_matches('/'));
    let probe = async {
        let response = atm.get_tdk().client().get(&url).send().await.ok()?;
        let body: Value = response.json().await.ok()?;
        body["version"].as_str().map(str::to_string)
    };
    // Headers and body together, not just until the headers arrive.
    tokio::time::timeout(Duration::from_secs(5), probe)
        .await
        .ok()
        .flatten()
}

/// `major.minor.patch`, ignoring any pre-release or build suffix.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(role: &str, acl: Value) -> account::get::v0_2::Account {
        serde_json::from_value(serde_json::json!({
            "did": "abc",
            "accountType": role,
            "acl": acl,
        }))
        .unwrap()
    }

    #[test]
    fn versions_parse_and_compare_against_the_operations_floor() {
        assert_eq!(parse_version("0.26.3"), Some((0, 26, 3)));
        assert_eq!(parse_version("0.28.20-rc.1"), Some((0, 28, 20)));
        assert_eq!(parse_version("nonsense"), None);
        assert!(parse_version("0.26.3").unwrap() < OPERATIONS_SINCE);
        assert!(parse_version("0.28.20").unwrap() >= OPERATIONS_SINCE);
        assert!(parse_version("0.29.0").unwrap() >= OPERATIONS_SINCE);
    }

    #[test]
    fn a_mediator_did_is_found_quoted_or_not_and_a_url_is_not_one() {
        let did = "did:webvh:Qm:example.com:mediator";
        assert_eq!(mediator_did_in(did).as_deref(), Some(did));
        assert_eq!(mediator_did_in(&format!("\"{did}\"")).as_deref(), Some(did));
        assert_eq!(mediator_did_in("https://mediator.example.com/"), None);
    }

    #[test]
    fn a_standard_account_is_self_service_with_its_flags() {
        let (mode, caps) = classify(&account(
            "standard",
            serde_json::json!({ "local": true, "selfManageList": true }),
        ));
        assert_eq!(mode, Mode::SelfService);
        assert!(!caps.mediator_wide && !caps.root);
        assert!(caps.local && caps.self_manage_list && !caps.self_manage_send_limit);
    }

    #[test]
    fn admins_and_root_admins_are_told_apart() {
        assert_eq!(
            classify(&account("admin", serde_json::json!({}))).0,
            Mode::Admin { root: false }
        );
        let (mode, caps) = classify(&account("rootAdmin", serde_json::json!({})));
        assert_eq!(mode, Mode::Admin { root: true });
        assert!(caps.mediator_wide && caps.root);
        // The mediator's own account administers nothing through a console.
        assert_eq!(
            classify(&account("mediator", serde_json::json!({}))).0,
            Mode::SelfService
        );
    }

    #[tokio::test]
    async fn a_connection_that_hangs_times_out() {
        let hang = std::future::pending::<Result<()>>();
        let e = bounded_connect(Duration::from_millis(10), hang)
            .await
            .unwrap_err();
        assert!(matches!(e, ConsoleError::Timeout { .. }), "{e:?}");
        assert!(e.is_transient());
        let options = ConsoleOptions::default()
            .with_connect_timeout(Duration::from_secs(3))
            .with_request_timeout(Duration::from_secs(4));
        assert_eq!(options.connect_timeout, Duration::from_secs(3));
        assert_eq!(options.request_timeout, Duration::from_secs(4));
    }

    #[tokio::test]
    async fn a_call_that_hangs_times_out_naming_its_task() {
        let hang = std::future::pending::<
            std::result::Result<(), affinidi_messaging_sdk::errors::ATMError>,
        >();
        let e = bounded("audit/list", Duration::from_millis(10), hang)
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                ConsoleError::Timeout {
                    operation: "audit/list",
                    ..
                }
            ),
            "{e:?}"
        );
        let slow = crate::with_deadline("stats", Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(matches!(
            slow,
            ConsoleError::Timeout {
                operation: "stats",
                ..
            }
        ));
    }
}
