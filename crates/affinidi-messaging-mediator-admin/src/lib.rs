//! Operate an Affinidi messaging mediator — the engine behind the mediator
//! console, usable headless or embedded in another application.
//!
//! Connect as an [`Identity`] from any [`IdentitySource`] and get a
//! [`MediatorConsole`]. What it can do follows from the mediator's own record
//! of the account ([`Mode`], [`Capabilities`]):
//!
//! - an **administrator** sees the whole mediator — statistics, every account's
//!   queues ranked, any account's messages, settings and access list, the
//!   audit log, the configuration, stored mux grants, and live traffic for
//!   everyone; it adds and removes accounts;
//! - **any other account** manages itself — its own queues and messages, the
//!   settings and access list it may self-manage, its own mux grants, and its
//!   own live traffic.
//!
//! Every operation is a signed Trust Task, so the mediator authorises each one
//! independently; the console's capability checks only spare a round trip.
//! Every call is bounded in time ([`ConsoleOptions`], [`with_deadline`]) and
//! its failure says whether trying again can help
//! ([`ConsoleError::is_transient`]). A purge is two-step
//! ([`MediatorConsole::purge_preview`] then [`MediatorConsole::purge`]); the
//! other changes ([`MediatorConsole::delete`],
//! [`MediatorConsole::update_account`], [`MediatorConsole::patch_config`] and
//! the like) are single calls, so a front end shows what changes and asks
//! before sending one. The live [`MonitorFeed`] reports lost batches and
//! dead taps rather than going quiet.

pub mod address_book;
mod console;
mod error;
mod grants;
mod identity;
mod live;
mod purge;

pub use address_book::{AddressBook, AddressEntry, account_hash};
/// The connection signal [`MediatorConsole::connection_state`] reports.
pub use affinidi_messaging_core::ConnState;
pub use console::{
    ACTIVITY_SINCE, CONFIG_PATCH_SINCE, Capabilities, ConsoleOptions, InspectedMessage,
    MUX_ADMIN_SINCE, MUX_REVOKE_MAX_ROUNDS, MediatorConsole, Mode, OPERATIONS_SINCE, STATS_SINCE,
    Target,
};
pub use error::{BoxError, ConsoleError, Result, with_deadline};
pub use grants::{BulkRevokeOutcome, GrantKey, GrantRevokeResult, GrantSelection, revoke_summary};
pub use identity::{Identity, IdentityChoice, IdentitySource, ProfileFileSource, StaticIdentities};
pub use live::{
    MembershipEvent, MembershipFilter, MonitorEvent, MonitorFeed, MonitorFilter, MonitorUpdate,
    Unclaimed,
};
pub use purge::{PURGE_TRANSIT_MARGIN_SECS, PurgePlan, PurgeRequest};

/// What a `messaging/mux/connections` page lists: see
/// [`MediatorConsole::mux_connections`].
pub use affinidi_messaging_sdk::protocols::trust_tasks::MuxConnectionsQuery;
/// What [`MediatorConsole::mux_revoke`] did, and why it stopped.
pub use affinidi_messaging_sdk::protocols::trust_tasks::{
    MuxAdminRevokeOutcome, MuxAdminRevokeStop,
};
/// The generated Trust Task types the console's calls take and return.
pub use affinidi_messaging_sdk::tasks::messaging as specs;
/// The generated `audit/*` and `config/*` Trust Task types
/// ([`MediatorConsole::audit`], [`MediatorConsole::config`],
/// [`MediatorConsole::patch_config`], [`MediatorConsole::reload_config`]).
pub use affinidi_messaging_sdk::tasks::{audit as audit_specs, config as config_specs};
