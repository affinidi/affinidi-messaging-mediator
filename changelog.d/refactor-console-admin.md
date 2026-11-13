### Breaking — mediator-admin: a typed transport error, timeouts, and `ConsoleError` is `#[non_exhaustive]`

- `affinidi-messaging-mediator-admin`: a failure in transit is now
  `ConsoleError::Transport` (the connection dropped, the mediator was
  unreachable, or it answered `408`, `429` or `5xx`), and a call that got no
  answer in time is `ConsoleError::Timeout { operation, after }`. Both used to
  be `ConsoleError::Sdk`, which now holds only failures that recur.
  `ConsoleError::is_transient()` says whether trying again can help,
  `is_refusal()` and `is_unsupported()` what the mediator said.
- `ConsoleError::Connect` keeps its cause: it is now
  `Connect { context, source }` (was `Connect(String)`), with
  `ConsoleError::connect(context, source)` to build one.
- `ConsoleError` is `#[non_exhaustive]`: a `match` on it needs a `_` arm.
- Every call is bounded in time (R1.2). `ConsoleOptions` sets
  `connect_timeout` (the whole of `connect`, which had no deadline) and
  `request_timeout` (each call after, also given to the SDK's REST client);
  both default to 30 s. `MediatorConsole::connect_with_options`,
  `connect_exclusive_with_options`, `connect_with_unclaimed_options`,
  `set_request_timeout` and the free
  function `with_deadline` (one call, its own deadline) are new. Monitor
  subscribes, lease renewals and the closing unsubscribe are bounded too.
- **Behaviour change:** a monitor feed retries a failed lease renewal only
  when the failure is transient (`is_transient()`); before, it retried every
  failure but a refusal. A renewal that fails for a reason that would recur
  now ends the feed (`MonitorUpdate::Ended`) at once.

### Breaking — mediator-tui: the console keeps the typed answers

- `affinidi-messaging-mediator-tui`: `Update` carries each answer as the
  typed Trust Task struct the admin crate returned, not `serde_json::Value`.
  `Update::Page { list, .. }` is replaced by `Update::Queues`,
  `Update::Messages`, `Update::Audit` and `Update::Accounts`; `Stats` and
  `AccountInfo` are boxed.
- `account_edit::AccountEdit::new` takes the typed `account/get` account,
  and `changes()` returns `AccountChanges` with the typed `account/update`
  role, ACL and queue limits. `Setting::Role` holds the role type,
  `Setting::Flag` a `&'static str` flag name (`ACL_FLAGS`), and
  `Setting::Limit` a `LimitKind`.
- `tally::TrafficTally::record` takes a typed `MonitorEvent`.

### Fixed — the console shows fields it used to drop

- The Account screen's "last message" and "last login", and the Accounts
  list's "msg ago" and "login ago", read the mediator's activity times as
  the instants they are; they always showed `–` before.
- Every screen reads the mediator's answers through their generated types,
  so a renamed or retyped member fails to compile rather than showing as
  `–`, `?` or `0`. The audit screen's action, outcome, actor and target, the
  dashboard's counters and the mux tables are read this way too.
- The admin crate tells a session's mode from the generated `AccountType` and
  ACL fields, not from their JSON strings.

### Changed — the console's code is split by concern

- `app.rs` (5,000 lines) is split into `state` (the typed model),
  `keys`, `monitor`, `popup` and one module per screen, each a `render`
  from the state. The screens are now tested from typed fixtures without a
  mediator.

### Added — the admin crate covers the rest of the administration tasks

- `MediatorConsole::add_account`, `remove_account`, `acls`,
  `access_list` (with a membership check), `update_access_list` and
  `reload_config`, each with the same capability pre-checks as the
  others (a privileged role needs a rootAdmin; an account changes its own
  access list only with `selfManageList`).
- An account's own mux grants: `mux_grant`, `mux_own_grants`,
  `mux_revoke_own` and `mux_revoke_all_own` (mediator 0.52.0).
- `ACTIVITY_SINCE` and `STATS_SINCE` are exported, and the generated
  `audit/*` and `config/*` types are re-exported as `audit_specs` and
  `config_specs`.

### Added — `mediator-console` runs one command and exits

- `mediator-console <command>` — `stats`, `queues`, `accounts`, `account`,
  `messages`, `audit`, `config`, `access-list`, `grants` and `purge` —
  prints the answer, as the Trust Task's JSON with `--json`, and exits with
  a code a script can act on: `0` done, `1` failed, `2` invalid arguments,
  `3` refused, `4` unreachable or timed out. `purge` needs `--dry-run` (count
  only) or `--yes` (count, then remove what was counted, sparing what was
  queued within the 30 s transit margin before the count).
- `--timeout` and `--connect-timeout` bound the console's waits, in the
  console and in commands alike.

### Fixed — admin, console and test-mediator docs match the code

- The admin crate's docs no longer say every destructive operation is
  two-step (only a purge is), and say how errors and timeouts work.
- The console README shows all eight tabs and documents the commands and
  exit codes.
- The test-mediator's crate-doc examples are `no_run` and compile-checked;
  its docs no longer mention a loopback Redis default (the default is an
  in-memory store) or removed admin-protocol names, the README's version is
  current, and the standalone example's comment names the right default ACL
  mode.
