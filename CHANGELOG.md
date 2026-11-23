# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## 0.54.0 (2026-11-23)

### Breaking — AWS deployments: grant `secretsmanager:UpdateSecretVersionStage` before upgrading

- Grant `secretsmanager:UpdateSecretVersionStage`, next to `PutSecretValue`,
  to every role that writes (`mediator-setup`, the mediator, and whoever runs
  `mediator rotate-admin`) on `<prefix>mediator_secrets_bundle` and, on a
  deployment not yet cut over to the bundle, on the per-key secret names too:
  until the cutover every write goes to the per-key secret first, and that
  write is conditional as well. Without it the first write of a new secret
  still succeeds, and the next one fails with `AccessDeniedException`, so
  `mediator-setup` or `rotate-admin` stops before it finishes.

### Breaking — a Trust Task that does not ask is refused with a problem report again (R3.6)

- **Wire change (R3.6), only for a request that does not ask.** A refused
  Trust Task is answered with a `trust-task-error` document when the request
  carries `"x-errorFormat": "trust-task-error"`, and with the problem report
  `e.p.<code>` otherwise. 0.52 and 0.53.0 sent the document to every
  request; releases up to 0.51 sent only problem reports, and a client
  written for them (`affinidi-messaging-sdk` before 0.46.2) cannot parse the
  document: every refusal reached it as `response is not a Trust Task
  document: unknown field 'code'`.
- `affinidi-messaging-sdk` asks on every Trust Task from 0.46.2, so a client
  on it sees no change.
- **A raw-TSP socket closes on a refusal that does not ask.** Over a `tsp` or
  `tsp-ack` WebSocket, any refused Trust Task that does not ask (an
  `account/add` the sender may not make, a `messaging/mux/ack` off a mux
  connection, …) closes the socket with 1008 again, as any refused frame on
  such a socket does: a raw-TSP socket has no in-band error frame. 0.52 and
  0.53.0 kept the socket open and sealed the document back instead, so a
  hand-built TSP client written for them that does not ask loses its live
  delivery on a refusal and must reconnect. One that asks still gets the
  sealed `trust-task-error` (`messaging/mux:notMuxConnection` for the mux
  ack). A `tsp-mux` socket is unaffected: it reports the refusal with its
  `refused` event.
- The codes do not change: both forms carry the Trust Task code (`e.p.`
  before it in a problem report). A client that matched the mediator's old
  codes (`account.not_found`, `authorization.*`) must still move to the new
  ones.
- The ask is needed while 0.51 is supported, until 2027-02-07. It is to be
  withdrawn in the first release cut after that date, which answers every
  refusal with a document again.

### Breaking — a few rarely used duration spellings are refused

Duration settings (`[secrets] cache_ttl` / `MEDIATOR_SECRETS_CACHE_TTL`, and the
setup tool's `MEDIATOR_BOOTSTRAP_SEED_TTL`) are now read with jiff's duration
syntax. Every value in the shipped templates and docs (`30d`, `12h`, `6h`, `0`,
…) reads exactly as before, and so does every humantime form except these,
which are now refused with an error naming the accepted syntax:

- `M` for months (`1M`): it reads as minutes. Write `1mo` or `1 month`.
- A fraction on days, weeks, months or years (`1.5d`, `0.5y`). Write `1d 12h`
  or `36h`. Fractions on hours and smaller (`1.5h`) still work.
- A fraction before the last unit (`1.5h 30m`), units out of order or repeated
  (`30m 1h`, `1s 1s`), and digits split by a space (`1 0d`).
- Values over roughly 19,998 years.

A refused `cache_ttl` stops the mediator at startup, as any unreadable value
does. A refused `MEDIATOR_BOOTSTRAP_SEED_TTL` falls back to the 24h default
with a warning, as before. Years and months keep their fixed lengths
(365.25 and 30.44 days) and days are 24 hours. Newly accepted: `mo`/`mos`,
`HH:MM:SS`, comma-separated units and spelled-out sub-second units.

`security.tsp_auth_accept_unbound_until` reads RFC 3339 as before, including a
space in place of `T` and no offset meaning UTC. It now also takes lowercase
`t`/`z`, times without seconds, and offsets other than UTC, which are applied.
Before, a non-UTC offset was refused, or ignored when it followed fractional
seconds. A non-UTC offset now logs a startup warning naming the deadline in
UTC, so a value whose meaning moved on upgrade is visible. More than nine
fractional-second digits are now refused. The boot notice still shows the
deadline as, e.g., `2026-11-19T10:00:00Z`.

### Changed — `affinidi-messaging-mediator`: the `common` helper modules are internal

- Every submodule of `affinidi_messaging_mediator::common` except `config`
  (`authz`, `circuit_breaker`, `did_rate_limiter`, `error_codes`,
  `http_server`, `jwt_auth`, `lua_integrity`, `metrics`, `relay_target`,
  `request_id`, `request_metrics`, `session`, `storage_timeout`, `time`,
  `ws_budget`) is now `#[doc(hidden)]`, as the crate's other internal modules
  (`handlers`, `messages`, `server`, `mux`, `tasks`, `monitor`, …) already
  were. They stay `pub` for the binary, the test mediator, the console, the
  setup tool and the fuzz targets, but they are internal: not covered by
  semver, and they may change in any release. The supported library surface
  is `builder` (`MediatorBuilder`, `MediatorHandle`), `common::config`,
  `store`, `task_specs`, `error_codes`, `SharedData` and
  `install_jwt_crypto_provider`. Nothing was removed and no signature changed.

### Changed — every library crate's public items are documented

- `missing_docs` is now a workspace lint (`warn`, so `-D warnings` in CI makes
  it an error), and every public item of `affinidi-messaging-mediator-common`,
  `-config`, `-processors`, `-admin`, `-tui`, the test mediator and the
  mediator library is documented: units, defaults, the config key or wire
  value each one maps to, and what its errors mean.
- The READMEs of `affinidi-messaging-test-mediator`,
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-mediator-tui`
  are compiled as doctests, so their examples can no longer drift from the
  API. Compiling them caught one stale example: the test mediator's admin
  example imported `trust_tasks_rs::specs::messaging`, which needs a
  `trust-tasks-rs` feature; it now uses
  `affinidi_messaging_sdk::tasks::messaging`.
- The CI `cargo doc` job builds with `--all-features`, so items behind the
  storage, secrets and protocol features are checked as docs.rs shows them.

### Fixed — a `did:webs` with a designated service resolves

`affinidi-did-webs` 0.13.9 (lockfile only). Its check of a published
`did.json` against the services the key event stream authorises compared each
service's `type` as written, so `"TSPTransport"` and `["TSPTransport"]` were
different services. A did:webs host serves the document rendered through
`Document`, which writes every `type` as an array, so any did:webs with a
designated service — such as a VTA's own identity, whose `#tsp` and
`#didcomm` name this mediator — failed to resolve with `DocumentMismatch`, and
the mediator could not authenticate it. Types are now compared as a set. No
configuration or wire change.

### Fixed — jemalloc tuning is applied

- The mediator exported its jemalloc settings (`background_thread:true`,
  5s dirty/muzzy decay) as `malloc_conf`, but `tikv-jemalloc-sys` builds
  jemalloc with the `_rjem_` symbol prefix, so the setting was never read and
  jemalloc ran on its defaults with no background purge thread. The symbol is
  now `_rjem_malloc_conf`: freed pages are returned to the OS while the
  mediator is idle, and after 5s rather than 10s.

### Fixed — AWS secrets: a write no longer drops keys from `mediator_secrets_bundle`

- On AWS Secrets Manager a read can return a version older than the
  process's own last write, and the bundle's read-modify-write then dropped
  every key written since: a fresh mediator could fail to start with "JWT
  signing secret is missing from the backend" after `mediator-setup`
  reported the key written.
- A write of a secret the process has read or written is now conditional,
  as on Vault: it is staged under the mediator's own `MEDIATOR_STAGED` label
  and made `AWSCURRENT` only if the secret is still at the version last seen,
  and the label is then removed. Otherwise the bundle redoes the write from a
  fresh read, as do the read-write probe and the cutover on the first start
  after a migration. A direct write of a per-key secret fails with a conflict
  error instead of overwriting, and keeps failing until the secret is read
  again. `AWSPENDING` is left to Secrets Manager rotation; rotation is still
  not supported on these secrets.
- A read-back right after a write (the migration's checks, the cutover, the
  read-write probe) is read again a few times before the write is called
  lost, so a lagging read no longer rolls back a migration that succeeded.
- A cutover that cannot be confirmed is undone only when that drops nothing:
  an entry another process wrote to the bundle since is kept.
- A migration whose own bundle write is refused as a conflict stops with that
  reason and deletes nothing, rather than asking for IAM access the role
  already has.

### Security — `url` 2.5.9 (RUSTSEC-2026-0592)

- The workspace requires `url` 2.5.9 and the lockfiles move from 2.5.8. In
  2.5.8 `Url::origin()` recursed once per nested `blob:` prefix, so a crafted
  URL could overflow the stack and abort the process (RUSTSEC-2026-0592,
  GHSA-hrj5-67jp-wqp9).

### Security — humantime replaced by jiff (RUSTSEC-2026-0542)

humantime is unmaintained (RUSTSEC-2026-0542, #298) and has left the
dependency graph. Duration and timestamp settings are parsed by one helper,
`affinidi_messaging_mediator_config::time`, built on `jiff` 0.2, which the cloud
SDKs already pulled in. `mediator-common` drops its unused optional humantime
dependency from the `server` feature. The `deny.toml` exception for
RUSTSEC-2026-0542 is removed.

### Security — secrets backend errors and the in-memory store hold no stray credentials

- An invalid secrets backend URL is reported with any `user:password@` in it
  replaced by `***@`, and without the body of a `string://` URL, of an unknown
  scheme, or of a value with no scheme at all (a secret pasted where the URL
  belongs), so a credential mistakenly written into `[secrets].backend` (or
  `MEDIATOR_SECRETS_BACKEND`) never reaches the logs or the startup error.
- The in-memory secret store (tests and the setup wizard's temporary
  sessions; the mediator never uses it) wipes each value from memory when it
  is deleted, overwritten or dropped.

## 0.53.0 (release/0.53)

### Changed — the vta feature is back

- `affinidi-messaging-mediator` depends on `vta-sdk` 0.90 again,
  released on the same line as this workspace (`affinidi-messaging-sdk` 0.47 /
  `affinidi-tdk` 0.45 / `trust-tasks` 0.39 / `affinidi-crypto` 0.3), so every
  `affinidi-*` and `trust-tasks-*` crate still resolves once.
- `vta` (VTA-backed key management: operating secrets fetched from a
  Verifiable Trust Agent at boot, periodic refresh, `mediator rotate-admin`) is
  back in the mediator's `default` features, and enabling it no longer stops
  the build. Library consumers can still turn it off with
  `default-features = false`; self-hosted mediators never used it.
- `mediator-setup`'s `vta` feature is now real and on by default: the VTA step
  offers full setup, admin-only and offline export again, the deployment
  defaults pick a VTA-managed setup again, and `--setup-key-out`,
  `--setup-key-file`, `use_vta = true` recipes (sealed-mint, sealed-export,
  `--bundle`) and `did_method = "vta"` run instead of exiting 5. A self-hosted
  `did:webvh` document is rendered by `vta-sdk`'s `didcomm-mediator` template
  again. A wizard built with `--no-default-features` and without `vta` keeps
  the previous release's behaviour (only "No VTA", VTA paths refused with exit
  5).
- The build commands the wizard renders (Dockerfile, `cargo install`,
  `cargo build`) list the mediator's `vta` feature again.
- The container image includes VTA integration again: the mediator's `default`
  features (with `vta`) and `mediator-setup` with its `vta` flows. A
  VTA-linked deployment that stayed on an earlier image can move to this one.

## 0.52.0 (release/0.52)

### Breaking — a forward is delivered only to a next hop that has an account

- A forward never creates an account. A local next hop with no account on
  this mediator is refused with `73 delivery.refused`; it used to be
  registered with `global_acl_default`, in either `mediator_acl_mode`. A
  recipient gets its account by authenticating (or from an admin) before
  forwards to it are accepted. A sender that forwards to an address before
  that address has first connected (for example a freshly minted DID) is now
  refused and must wait for the recipient's first connection, or retry
  (R3.6).
- A forward from a DID with no account here is still checked against the
  least-privilege relay ACL (`SEND_FORWARDED` only, if `global_acl_default`
  grants it), but that DID is no longer registered. Its queued messages
  are still counted per recipient, so `limits.queue.peer` holds it as it
  holds any sender; `limits.queue.sender` (a per-account total) does not
  apply to it. An abandoned relay has no inbox here to report to (logged as
  `FORWARD_PROBLEM_REPORT_UNSENT`). Recipient-side checks, including access
  lists, see the sender's DID.
- A next hop this mediator cannot route is refused instead of stored where
  nothing would collect it. One whose DID document publishes a DIDComm
  service with no usable endpoint, or names a mediator whose document has
  no endpoint URL, gets `73 delivery.refused`. One that names a mediator
  whose DID cannot be resolved gets `74 did.resolve` with 503, so the sender
  can retry. Previously each was stored locally, logged "Storing locally —
  it will not be delivered", and answered as forwarded.
- A next hop whose own DID cannot be resolved is treated as local: it is
  delivered if it holds an account here, so a resolver outage does not stop
  local delivery, and refused with `73` otherwise.
- A forward is answered as forwarded only once it is stored: a storage
  failure while storing it locally is now returned to the sender instead of
  being logged and answered with success. An `ephemeral` forward is accepted
  only when it is handed to the recipient's live stream; a recipient with no
  live stream gets `73 delivery.refused`, and a failed publish a 503.

**Behaviour change (R3.6):** a deployment that forwards to recipients
before they have ever authenticated must now pre-register them with
`messaging/account/add` (admin). Senders that relied on an unresolvable or
unroutable next hop being accepted, or on `ephemeral` forwards to an
offline recipient succeeding, now get an error.

### Breaking — `affinidi-messaging-mediator-common` API

- `DatabaseHandler::get_async_connection` and `RedisStore::get_connection`
  return `RedisConnection` (one server or a cluster) instead of
  `ConnectionManager`, and `DatabaseConfig` has a new public field,
  `cluster_mode`.
- `mux::MuxChangeRecord` has a new public field, `streaming`
  (`Vec<StreamingHandoff>`), so a struct literal needs it; it is skipped on
  the wire when empty. `MediatorStore` gains `streaming_claim` and
  `streaming_release`, with defaults for single-instance stores. The Redis
  `Database` helpers `streaming_register_client`, `streaming_start_live`,
  `streaming_stop_live` and `streaming_deregister_client` are removed: they
  bypassed the cross-instance ownership rules. Use `streaming_set_state`,
  `streaming_claim` or `streaming_release`.

### Breaking — the console reads typed refusals; `ConsoleError::Refused` gains `current_epoch` (sdk 0.46.3)

- The workspace requires `affinidi-messaging-sdk` 0.46.3 (0.46.2 asks for documents; 0.46.3 also collects a reply sent over REST). Every Trust Task
  it sends now asks to be refused with a `trust-task-error` document. A
  mediator that serves that answers with one; others keep answering with
  problem reports.
- `ConsoleError::Refused` is built from either form, and gains a
  `current_epoch: Option<u64>` field. This is a breaking change for code that
  constructs it or matches it without `..`.
  - `code` is the mediator's own code (`ATMError::mediator_code`), so code
    that matched it keeps working. A problem report's code keeps its `e.p.`
    prefix, as before.
  - `ConsoleError::current_epoch()` reads the field, which comes from the
    document's `details.currentEpoch`, or from an older mediator's comment.
    It no longer parses the comment itself.
- The console's other refusal checks (monitor unsupported-type fallback, a
  failed `admin-revoke` round) read either form.

### Breaking — test mediator keeps private keys on their own side of the boundary

`affinidi-messaging-test-mediator` no longer shares one secrets resolver
between the mediator and the test's client (#149). By default:

- the mediator's private keys stay in the mediator's resolver.
  `TestEnvironment` no longer copies them into the SDK's resolver
  (`env.tdk`), so the SDK cannot decrypt anything addressed to the mediator;
- user keys from `TestMediatorHandle::add_user` / `TestMediator::with_users`
  go into a client-side resolver, and no longer into the mediator's.
  `TestMediatorHandle::secrets_resolver()` now returns that client-side
  resolver, which holds no mediator keys. `TestEnvironment::add_user` follows
  the same rule, so the two `add_user`s now behave alike.

A downstream test that passed only because the keys were shared, such as an
envelope encrypted to the end recipient instead of wrapped in a forward, or
mail unpacked by the wrong party, now fails as it would against a real
mediator. Tests that genuinely act as the mediator (forging what it would
sign) opt in: `TestEnvironment::with_mediator_keys()` copies the mediator's
keys into the SDK's resolver, and `TestMediatorBuilder::share_secrets(true)`
restores the old single shared resolver. `TestMediatorHandle::shares_secrets()`
reports which applies. All users of one `TestEnvironment` still share its SDK
resolver, as before.

### Breaking — dropping a `TestMediatorHandle` stops the mediator

The handle's docs always said it stops on drop, but it did not: a test that
failed or returned early left the server, listener and processors running
until the runtime ended (#153). Dropping the handle (or the
`TestEnvironment` / `TestTopology` that owns it) now cancels the mediator. A
test that let the handle go out of scope while still using the mediator
through its URL must now keep the handle alive. With `fjall-backend` the
store's temp directory is removed only after the server task has ended, not
underneath it. The handle is `#[must_use]`.

### Breaking — purge returns a report; one purge algorithm on every backend

- `MediatorStore::purge_folder` and `purge_folder_by` now return a
  `PurgeReport` (`count`, `bytes`, `scanned`, `failed`) instead of
  `(count, bytes)`, and every backend runs the same purge
  (`store::purge_folder_by_listing`): it pages through the folder, deletes
  each page together (pipelined on Redis rather than four sequential round
  trips per message), treats an already-gone message as removed, counts any
  other refusal in `failed` and carries on, and removes only the stream
  entries of messages it actually removed. Previously Redis aborted at the
  first undeletable message, and Fjall and memory swallowed refusals and
  wiped the stream anyway, leaving messages stored but unlisted. The new
  trait method `delete_folder_entries` removes named entries.
- **Behaviour change (R3.6):** account removal fails, with the account left
  blocked, when its inbox purge could not delete every message (it used to
  stop at the first failure on Redis, and carry on silently on Fjall and
  memory). Running the removal again retries the rest.

### Breaking — a session that no longer exists is answered 401

- **Behaviour change (R3.6):** a valid, unexpired JWT whose session record is
  gone (its 24 h TTL, a store flush, a memory-backed mediator's restart) is
  now refused with HTTP 401 `Invalid token`, so the client authenticates
  again. It was a 500 carrying the storage backend's error text. Every
  backend's `get_session` answers a missing or expired session with the new
  `store::session_not_found` error (`Unauthorized`), and a Redis account
  record without a role or ACLs as `account_gone`. A real storage failure is
  still a 500, now with a fixed message; the cause is logged. A request
  without connection info is an internal error (it was reported as missing
  credentials).

### Breaking — A store failure is an error, never a success carrying it

- **Behaviour change (R1.1, R3.6):** a direct delivery, a TSP or bridged
  message, or a DIDComm v1 envelope that the store fails to keep is now
  answered with the store's error (`me.res.storage.*` 14/503, or the
  `limits.*` refusal) instead of `Stored` with the failure in `errors`.
  A mediator reply addressed to several recipients fails when it was stored
  for none of them; when some were stored it still answers `Stored` with the
  rest in `errors`. Clients that read `errors` out of a success must treat
  the error response as the failure.
- **Behaviour change (R3.6):** an `ephemeral` forward whose recipient has no
  live stream is answered with its own problem report,
  `w.m.delivery.not_live` (99, HTTP 404), instead of the uniform
  `delivery.refused`: the message was not delivered and is not queued.

### Breaking — Deliveries are recorded once the reply is written

- **Behaviour change (R1.1, R3.6):** Message Pickup `delivery` replies
  (DIDComm v2 and v1) no longer stamp messages delivered or emit `delivered`
  monitor events when they are fetched. Both happen once the reply has been
  packed and handed to its transport — the REST response body written, or
  the live stream's push accepted — and only for the messages actually
  attached. A message with no body, or (v1) a body that is not a v1
  envelope, stays queued and unreported.
- **Behaviour change (R1.1, R3.6):** `POST /outbound` with `delete` and
  `POST /fetch` with `FetchDeletePolicy::Optimistic` delete — and emit
  `delivered` — only once the response body has been written. A response
  that is never fully written deletes nothing, so the client can fetch
  again. A delete that fails after the write is logged; `delete_errors` is
  now always empty on both.
- A pickup `delivery` carries at most four `limits.message_size` of stored
  bodies (always at least one message); the rest stay queued for the next
  request.
- Rust API: `handlers::message_outbound_handler` and
  `handlers::inbox_fetch_handler` return `axum::response::Response`.

### Breaking — Trust-ping answers with `ping-response`

- **Wire change (R3.6):** the answer to a DIDComm trust-ping is now
  `https://didcomm.org/trust-ping/2.0/ping-response` (it reused the request
  type, so a conformant peer saw a new ping). Clients that match the answer
  by type should accept both while they may talk to an older mediator.
- Trust-ping and Discover Features requests must be addressed (`to`) to the
  mediator, the same check Message Pickup applies (`message.to`); the reply
  is no longer sent "from" whatever DID the request named.
- A Trust Task `ping` advertises only the protocols the build serves
  (`didcomm`, `tsp`), not both unconditionally.

### Breaking — Forward edge cases are refused, not guessed at

- **Behaviour change (R3.6):** a forward with more than one attachment is
  refused (`protocol.forwarding.attachments.too_many`); only the first used to
  be delivered while the sender was told `Forwarded`.
- **Behaviour change (R3.6):** `delay_milli` must be a whole number from 0 to
  `future_time_limit` × 1000. A negative, fractional or non-numeric value is
  refused (`protocol.forwarding.delay_milli`) instead of being read as 0 or as
  its magnitude.
- A forward's own `hop_count` is no longer read. Only the count an
  authenticated peer mediator carries on a re-wrap layer is used, as a floor,
  and it saturates instead of wrapping.
- **Behaviour change (R3.6):** a queue limit of N now admits N messages (it
  admitted N−1, and a limit of 1 admitted none). A queue limit below −1 in
  `[limits]` refuses to start; one stored on an account admits nothing.
  `account/update` refuses a queue limit below −2 or outside `i32`.

### Breaking — Message Pickup status and live delivery tell the truth

- **Behaviour change (R6.2, R3.6):** turning live delivery on where the
  mediator has no streaming task is refused
  (`protocol.pickup.live_streaming`, 501) instead of answered with a status
  claiming it is on.
- A status for a mux member names the member's DID in `recipient_did` (it
  named the principal's). After a `messages-received` that acknowledged only
  a member's messages, the status returned is the member's.
- `messages-received` names at most 100 ids
  (`protocol.pickup.messages_received.limit`), and no longer reads each
  message before deleting it; its `deleted` monitor events carry no protocol.

### Breaking — configuration values are checked strictly; a config that booted on silent defaults now fails

A configuration that started before may now refuse to start (and `config/reload`
may now fail) with an error naming the setting, the value and what it takes.
Fix the value the error names.

- **No silent defaults.** An unreadable number or boolean anywhere in the file
  (`listed_messages = "5O"`, `rate_limit_per_ip = "10/s"`,
  `message_size = "1MB"`, `use_ssl = "ture"`, a processor `enabled`, the
  resolver cache settings, `database_timeout`, `cluster_mode`,
  `[secrets] cache_ttl`, `[storage.fjall]` values, …) is a startup error
  naming `section.key`, instead of quietly running on a built-in default that
  could be looser than what was written. Values are trimmed, and booleans and
  enum-like values are case-insensitive.
- **`security.mediator_acl_mode`** must be `explicit_allow` or `explicit_deny`
  (any case). An unknown value used to select `explicit_deny` — the OPEN mode.
  `log_level` must be one of `trace debug info warn error` (it used to become
  `info`); `processors.forwarding.relay_mode` must be `blind` or `rewrap`; a
  `[limits.mux] enabled` other than `true`/`false`/empty is refused (it used to
  mean off); `storage.backend` must be `redis` or `fjall`, and
  `storage.fjall.durability` `buffered` or `sync` (it used to become `sync`).
- **Documented invariants are enforced on the file**, not only on
  `config/patch`: each `queued_*_soft` ≤ its `queued_*_hard`; a queue limit is
  `-1` or ≥ 0 (no other negative); `message_size` ≥ 1 and ≤ `http_size` and
  `ws_size`; no `0` for `listed_messages`, `deleted_messages`, `to_recipients`,
  `to_keys_per_recipient`, `crypto_operations_per_message`,
  `forward_task_queue`, `oob_invite_ttl`, `message_expiry_seconds`,
  `ws_send_buffer`, `pubsub_buffer`; `jwt_access_expiry` ≥ 10 s and below
  `jwt_refresh_expiry`; `ws_pong_timeout_secs` ≥ 2 × `ws_ping_interval_secs`
  and both intervals ≥ 1 (these used to be raised silently);
  `limits.mux.max_channel_slots` in 8..65536 (it used to be clamped);
  `database_timeout` and `did_resolver.network_timeout` ≥ 1.
- **CORS entries are checked at startup.** An exact `cors_allow_origin` entry
  must be `scheme://host[:port]` with no path or trailing slash
  (`app.example.com`, `https://app.example.com/` and `null` are refused; they
  could never match). Scheme and host are now compared case-insensitively.
- **`[secrets] backend` has no default.** The shipped `conf/mediator.toml`
  leaves it commented out with the choices listed; startup fails until one is
  set, and the error lists the choices. `mediator-setup` sets it as before.
- **`config/reload`** runs the same checks over the whole file: a value that
  would not survive a restart fails the reload with `config.reload.invalid`
  and changes nothing.

Rust API (affinidi-messaging-mediator): `MuxConfig` is built with `TryFrom`
(was `From`); `LimitsConfig::try_from` now fails on values it used to default;
`relay_target_blocked` takes any `BlockList`. affinidi-messaging-mediator-common:
`ForwardingConfig` gains `blocked_forwarding_late` (construct it with
`..Default::default()`). affinidi-messaging-mediator-config: new
`ConfigError::Invalid`, `values` module, `validate::check_secrets_backend`,
`env::ignored_env_notes` / `warn_ignored_env`; `SecretsConfigRaw::backend` is
`#[serde(default)]`.

### Breaking — `file://` and `vault://` secret-backend URLs are checked strictly

- `file://…?encrypt=` accepts only `1`, `true`, `yes`, `on` or `0`, `false`,
  `no`, `off` (any case). Any other value (`enabled`, `2`, empty) used to
  mean *plaintext*; it now fails at startup. `?encrypt=TRUE` and `=True`,
  which used to write plaintext, now open the encrypted backend.
- A `file://` URL with a host is refused with "use three slashes for an
  absolute path". `file://conf/secrets.json` used to read and write
  `/secrets.json`.
- `vault://…?insecure=1` is refused at startup by a release build unless
  `MEDIATOR_ALLOW_INSECURE_VAULT=1` is set. Debug and test builds still take
  it. Every open and login with it logs a warning. Trust a private CA with
  the new `?ca_cert=<path>` (a PEM bundle) instead. `insecure=` also takes
  only the values above.
- The never-working `vault://http://…` form is gone: the endpoint is always
  HTTPS.
- The "secrets are plaintext on disk" warning is logged only for an
  unencrypted `file://` store.

### Breaking — the encrypted `file://` store writes format version 2

- Version 2 adds a file MAC (HMAC-SHA256 under a key derived from the
  passphrase key) over the KDF header, the verifier and every entry, and
  names the version in each AEAD's associated data. Deleting an entry,
  rolling one back to an older copy, or editing the header now fails the
  open instead of going unnoticed. Replacing the whole file with an older
  copy is still not detectable.
- Version 1 files are read as before and rewritten as version 2 by the next
  write. **A mediator or `mediator-setup` older than this release cannot read
  a version 2 file**, so keep a copy of the file before upgrading if you may
  roll back.
- On-disk Argon2id parameters outside memory 8 MiB–1 GiB, 1–16 iterations
  and 1–16 lanes are refused before the KDF runs.
- Only a missing file starts a new store. An existing empty file (what an
  interrupted write by an older release left) is now an error rather than a
  silent fresh store with a new salt.

### Breaking — mediator-setup: `--non-interactive` needs `--did-method`, and no longer defaults to a VTA DID it cannot mint

- `mediator-setup --non-interactive` without `--from` now fails unless
  `--did-method peer` or `webvh` is given. It used to default to a
  VTA-managed DID with no VTA session, write `did://vta://mediator` (or
  `PLACEHOLDER_DID` for "import") into `mediator.toml`, and exit 0.
- A VTA-managed DID without a VTA session is now a hard error (exit 5);
  `did_method = "import"` and `admin = "import"` without `admin_did` are
  refused (exit 6). Importing an existing mediator DID was never
  implemented and is no longer offered.
- Headless runs never prompt or read stdin. `--non-interactive` used to end
  in an "Install now?" prompt that, without a terminal, started
  `cargo install` on its own.

### Breaking — mediator-setup: a plaintext `file://` secret store outside a local deployment needs an explicit opt-in

A `server` or `container` setup whose `[secrets].storage` is an unencrypted
`file://` URL is refused unless the recipe sets
`allow_plaintext_file = true` under `[secrets]` (or `--allow-plaintext-file`
is passed). Prefer `file://…?encrypt=1` or a secret manager. The bare
`gcp_secrets://`, `azure_keyvault://` and `vault://` schemes, which have no
usable default and produced invalid URLs, are refused with a pointer to the
full URL form.

### Breaking — mediator-setup: production deployments default to a closed network

A recipe without `[security].network_mode` (and the TUI's starting point)
now gets `closed` — explicit ACL grants, the shipped template's posture —
for `server` and `container` deployments. `local` stays `open`. Set
`network_mode = "open"` to keep the previous behaviour. The posture is
printed in the summary before anything is written.

### Breaking — mediator-setup: the admin choice is honoured in VTA flows

With a VTA session, `[server].admin_did` used to be the VTA-issued
credential whatever was chosen. Now `admin = "generate"` (the recipe
default) mints a separate did:key for the mediator's admin API — its key goes
to `admin-monitor.json` — while the VTA credential stays the mediator↔VTA
identity in `mediator_admin_credential`. A sealed-mint or sealed-export
recipe that relied on the default therefore gets a different admin DID; set
`admin = "vta"` to reuse the VTA credential. "Use an existing admin DID" is
now a real prompt (recipe: `admin = "import"` + `admin_did`, or
`--admin-did`).

### Breaking — mediator-setup: re-running into a provisioned backend is refused whatever the config path

The re-run guard now checks the secret backend about to be written, after
its probe, in every flow (TUI, `--from`, `--non-interactive`,
`--setup-key-file`): if it already holds mediator keys the run stops with
exit 4 unless `--force-reprovision` is given. A different `--config`, a
moved `mediator.toml`, or a backend that cannot be read no longer bypass it.
Other exit codes are listed in `--help` and the setup guide (7: setup
complete but publishing the DID failed).

### Breaking — console engine: connection state, monitor feed drops, pinned purges (R3.6)

- `MediatorConsole::connection_state()` returns the SDK's live
  `watch::Receiver<ConnState>` (`ConnState` is re-exported): `Disconnected` on
  every drop, `Connected` on every reconnect, `None` when there is no
  websocket (R6.2). The console logs each drop at `warn` (was `debug`) and
  each recovery at `info`.
- `MonitorUpdate` gains `Disconnected` and `Reconnected`, reported by every
  feed the moment the connection drops and recovers, instead of a reader
  inferring it from silence. `MonitorUpdate` is now `#[non_exhaustive]`: a
  `match` on it needs a wildcard arm.
- `MediatorConsole::purge` no longer recounts and refuses with `PlanStale`. It
  sends the purge pinned to the preview's instant (`olderThanSeconds` = any
  requested age plus the time since the preview, rounded up to whole seconds,
  plus `PURGE_TRANSIT_MARGIN_SECS` (30) for the request's transit and
  queueing before the mediator runs it), so it never removes a message that
  arrived after the preview. It can remove **fewer** than
  `PurgePlan::matched`: messages delivered in between, and messages stored in
  the margin before the preview, are left; report `purged`, not `matched`. The old recount let a message that
  arrived after the check be removed, and let a different set with the same
  count through. `ConsoleError::PlanStale` stays, but `purge` no longer
  returns it. A mediator-side "as of" member for `queue/purge` is a separate
  follow-up.

### Breaking — one error-code scheme: Trust Task refusals carry Trust Task codes, overloaded numbers split

Error codes are part of the client contract, so this is breaking for every
consumer that matches on them (R3.6). Clients on `affinidi-messaging-sdk`
0.46 that read refusals with `ATMError::refusal_code()` see the new codes
directly; code that matched the old mediator codes through
`ATMError::mediator_code()` must match the new ones below.

**Trust Task refusals.**

- Every refused Trust Task is answered with a `trust-task-error` document
  (SPEC §8), over every transport (DIDComm over REST or WebSocket, TSP, mux
  connections). The request no longer has to ask with
  `x-errorFormat: trust-task-error` (still accepted). A problem report is
  sent only where no document can be: the body is not a Trust Task
  document, the sender is unauthenticated or is not the session's own DID,
  or the document could not be signed. It carries the same code, as
  `e.p.<code>`.
- The code is always the framework's standard code (SPEC §8.3) or the
  `<task>:<code>` the task's specification declares. The mediator's own
  spellings are gone, and so is `details.mediatorCode`:

  | Old code | New code |
  | :------- | :------- |
  | `authorization.permission`, `authorization.account.denied`, `authorization.local`, `authorization.admin_required`, `authorization.queue_limit.admin_required`, `authorization.root_admin_required` (config/patch, config/reload), `message.trust_task.unauthenticated`, `account.update.protected` | `permissionDenied` |
  | root-admin refusals in `messaging/account/update` (was `authorization.permission`) | `messaging/account/update:rootAdminRequired` |
  | `authorization.queue_limit.not_self_manageable`, `authorization.acl.not_self_manageable` | `messaging/account/update:selfChangeDenied` |
  | access-list self-management refused (was `authorization.permission`) | `messaging/access-list/update:selfChangeDenied` |
  | `account.not_found` | `<task>:unknownAccount` (`messaging/account/get`, `messaging/account/update`, `messaging/queue/status`, `messaging/message/list`) |
  | `account.remove.protected` | `messaging/account/remove:protectedAccount` |
  | `message.trust_task.malformed`, `message.trust_task.rejected` (policy) | `malformedRequest` |
  | `message.trust_task.rejected` (basic validation) | `expired` or `wrongRecipient` |
  | `protocol.trust_task.unsupported` | `unsupportedType` |
  | `message.trust_task.stale` | `expired` |
  | `message.trust_task.identity_mismatch` | `identityMismatch` |
  | `message.trust_task.proof_required` / `.proof_invalid` | `proofRequired` / `proofInvalid` |
  | `message.trust_task.id_conflict`, `message.trust_task.duplicate` | `idConflict` |
  | `message.trust_task.unavailable`, `config.storage`, `config.reload.unavailable`, storage full/busy | `unavailable` |
  | `config.reload.invalid` | `taskFailed` |
  | `account.list.cursor`, serialisation failures | `internalError` |

- A `messaging/mux/ack` sent on a raw-TSP socket that is not a mux
  connection is answered with a sealed `trust-task-error`
  (`messaging/mux:notMuxConnection`) pushed on that socket; the socket used
  to be closed with 1008.
- A malformed ACL in `messaging/account/update` or `messaging/account/add`
  is a 400 `malformedRequest`; it was a 500 internal error (14).
- Trust Task refusals have their own numbers, 120–139 (one per standard
  code, 139 for a declared code); they were all 37.

**Numbers.** One number means one condition. Moved to new numbers:

| Old | New | Problem code |
| --: | --: | :----------- |
| 37 | 100 | `e.m.message.size.exceeded` |
| 37 | 101 | `e.p.protocol.unsupported`, `e.p.message.tsp.unsupported`, `e.m.message.didcomm_v1.unsupported` |
| 37 | 102 | `e.m.message.didcomm_v1.*` (malformed DIDComm v1 requests) |
| 37 | 47 | `e.p.message.tsp.reseal`, `e.p.message.tsp.trust_task.seal` / `.serialize`, `e.m.message.didcomm_v1.build` / `.pack` |
| 28 | 103 | `e.p.authentication.tsp.resolve`, `.signature.encoding`, `.signature.length` |
| 38 | 104 | `e.p.authentication.session.refresh_token.expired` |
| 38 | 105 | `e.p.authentication.session.refresh_token.reuse` |
| 44 | 106 | `e.p.authorization.authentication_required` |
| 44 | 60 | TSP `e.p.authorization.send_forwarded` (now the same number as DIDComm) |
| 43 | 107 | `e.p.api.message_outbound.limit` |
| 58 | 108 | `e.p.message.tsp.resolve`, `e.p.message.tsp.mediator.unresolvable` |
| 60 | 109 | `e.p.authorization.relay.untrusted_peer` (and its relay-ack) |
| 10 | 110 | `w.m.database.message.delete.not_found` |
| 10 | 111 | `w.m.database.message.delete.permission_denied` |
| 10, 11 | 3 | `e.p.me.res.storage.connection.blocking` |
| 91–98 | 14 | forwarding-queue storage failures (logged; they collided with client codes) |
| 21 | 34 | a session that no longer exists (`store::session_not_found`; 21 is `e.p.database.stats.parse`) |
| 500 | 17 | internal errors in the Fjall store and at shutdown |

- `w.m.message.header.ephemera.invalid` is spelled
  `w.m.message.header.ephemeral.invalid`, as documented.
- An unpack failure and a message with no recipient no longer echo the
  whole envelope in the problem report's arguments; they name its sha256.

**Registry.** The constants live in
`affinidi_messaging_mediator_common::error_codes` (re-exported as
`affinidi_messaging_mediator::error_codes`) and handlers use them instead of
numbers. `ERRORS.md` lists every number, every problem code and every Trust
Task code, and code 96 is described correctly (the DID that authenticated
the message, not the session). A test fails when a constant, a problem code
written in a handler, or a code a served task declares is missing from it.

**Console.** The admin client and TUI recognise `unsupportedType` and
`unsupportedVersion` as well as the old `protocol.trust_task.unsupported`.

### Breaking — mediator-common drops its duplicate `DatabaseConfigRaw` and `parse_cluster_mode`

- `affinidi_messaging_mediator_common::database::config::DatabaseConfigRaw`,
  its `TryFrom<DatabaseConfigRaw> for DatabaseConfig` and `parse_cluster_mode`
  are removed. The raw `[database]` schema is
  `affinidi_messaging_mediator_config::DatabaseConfigRaw`; the mediator
  converts it to `DatabaseConfig` with strict parsing. The removed conversion
  silently fell back to a 2 s timeout and fixed circuit-breaker values.
- `DatabaseConfig`'s `cluster_mode` written as a string is now read as
  `mediator.toml` reads it: `"true"` or `"false"` (any case, empty is
  `false`). Anything else is refused at startup. It used to be warned about
  and read as `false`, and `yes`/`no`, `1`/`0` and `on`/`off` were accepted.
  This affects the standalone processors' TOML (`forwarding.toml`,
  `message_expiry_cleanup.toml`); a native boolean is unaffected.

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

### Breaking — `MediatorStore` is split into capability traits, with no silent defaults

- `affinidi-messaging-mediator-common`: `MediatorStore` is now a facade with
  no methods of its own over twelve capability traits — `StoreLifecycle`,
  `MessageStore`, `SessionStore`, `AccountStore`, `AclStore`, `StatsStore`,
  `ForwardQueueStore`, `StreamingStore`, `MuxStore`, `V1RoutingKeyStore`,
  `AuditStore` and `AuxiliaryStore` — and is implemented for every type that
  implements them all. A storage backend outside this workspace implements
  each trait instead of `MediatorStore`. Code holding `Arc<dyn MediatorStore>`
  keeps calling methods as before.
- The algorithms no backend overrode move to `MediatorStoreExt`, implemented
  for every `MediatorStore` and not overridable: `delete_message`,
  `fetch_messages_fair`, `fetch_messages_delivering`, `record_delivered`,
  `count_sent`, the four purges, `account_add` and the legacy aliases
  (`create_session`, `update_send_stats`, `add_admin_accounts`,
  `strip_admin_accounts`). Calling them needs
  `use affinidi_messaging_mediator_common::store::MediatorStoreExt;` (or
  `store::prelude::*`). A `MediatorStore::method(...)` call in path form names
  the capability trait instead.
- Every method whose default made a backend degrade silently is now required:
  acknowledgements, outbox receipts and sent-message states, delivery marking
  and state, `peer_queue_count`, the expiry and session sweeps, refresh-token
  reads and rotation, `update_session_authenticated` (whose default was not
  atomic), account activity and counters, `delivery_decision`, Trust Task
  claims, did:scid sources, config overrides, mux and DIDComm v1 primitives,
  the tagged and verbatim publishes, the forward queue's ack-and-delete and
  consumer pruning, `circuit_breaker_state`, `spans_processes`, and the
  cross-instance streaming calls. The only defaults left are loops that are
  correct everywhere (`get_messages`, `delivery_states`, `streaming_owners`).
  Single-process backends call `store::single_process` for the streaming
  claim and release.
- New store operations `AccountStore::account_update` and
  `AclStore::access_list_update`, with the `AccountUpdate`,
  `AccessListUpdate` and `AccessListUpdateOutcome` types.
- The Redis database module's own `MessageMetaData` and `MetadataStats` are
  re-exports of the store types, and the Redis store's identity conversions
  between them are gone (they cloned every forward-queue body).
- No wire changes.

### Breaking — a trust-ping asking for no response is a success, not a 500

- A DIDComm trust-ping with `response_requested: false`, and a Trust Task
  over DIDComm that the mediator answers with silence, now succeed with
  nothing in them. Over REST, `/inbound` answers `200` with the usual success
  envelope and `data: "Empty"` (the SDK's `InboundMessageResponse::Empty`,
  "no response expected"), the same status every other accepted message gets.
  Over a WebSocket no frame is sent. Previously both were refused with
  `500 e.p.me.storage.message.error` (code 77), and a WebSocket client was
  sent a problem report, for a message that had been handled.
- Wire change (R3.6): a client that treated that `500` as the expected answer
  to a silent ping must now expect `200` / `data: "Empty"`. Error code 77 is
  no longer returned.

### Breaking — `wake` fields on `ProcessorsConfig`, `ProcessorsConfigRaw` and `SharedData`; two `AuxiliaryStore` methods

- `ProcessorsConfig` and `ProcessorsConfigRaw` gain `wake`, and `SharedData`
  gains `wake`. Code that builds any of them with a struct literal must add
  the field (`WakeConfig::default()`, `WakeConfigRaw::default()`,
  `Default::default()`); code that starts from `Default` is unaffected.
- `AuxiliaryStore` (part of `MediatorStore`) gains the required
  `wake_handle_set` and `wake_handle_get`.

### Breaking — the mediator's `vta` feature is no longer a default, and cannot be enabled in this release (R3.6)

- `affinidi-messaging-mediator`'s `default` features are now `didcomm`, `tsp`,
  `redis-backend` and `jemalloc`. `vta` (VTA-backed key management: operating
  secrets fetched from a Verifiable Trust Agent at boot, periodic refresh,
  `mediator rotate-admin`) is no longer one of them.
- The feature stays defined, but enabling it stops the build with a
  `compile_error!`: `vta-sdk` is out of this workspace's dependency graph.
  Every published `vta-sdk` (up to 0.88.x) pulls `trust-tasks-proof`
  0.36/0.37. Those no longer compile once `affinidi-data-integrity` unifies to
  0.8.7, which `trust-tasks-proof` 0.39 requires, because 0.8.7 moved its
  public `KeyType` from `affinidi-crypto` 0.2 to 0.3.
- A deployment that boots from a VTA (`[vta]` configuration, the
  `mediator_admin_credential` linking the mediator to a VTA) must stay on the
  previous release until `vta` returns. Self-hosted mediators (operating
  secrets from the secret backend's well-known entry) are unaffected: that path
  never used `vta-sdk`.
- Release order across the two repositories:
  1. This release ships without `vta-sdk`, on `affinidi-messaging-sdk` 0.47 /
     `affinidi-tdk` 0.45.
  2. verifiable-trust-infrastructure releases `vta-sdk` on that line (it
     depends on `affinidi-messaging-test-mediator` from step 1).
  3. The next mediator release restores the `vta-sdk` dependency, puts `vta`
     back into `default`, and turns the setup wizard's VTA flows back on.

### Breaking — the setup wizard's VTA flows are unavailable in this release

- `mediator-setup` is built without VTA integration. Its new `vta` feature is
  off by default and, like the mediator's, cannot be enabled until `vta-sdk`
  returns.
- The interactive wizard's VTA step offers only "No VTA", and says why. The
  deployment defaults no longer pick a VTA-managed setup: they start from
  `did:peer`, with no VTA.
- Every VTA path is refused with that reason and exit code 5
  (`NO_VTA_SESSION`):
  - `--setup-key-out` and `--setup-key-file`.
  - A recipe with `use_vta = true`, including the sealed-mint and
    sealed-export modes and `--bundle`.
  - `did_method = "vta"`.
- A self-hosted `did:webvh` is generated as before. Its DID document is the one
  the built-in `didcomm-mediator` template renders, now built locally instead
  of through `vta-sdk`'s template renderer.
- The build commands the wizard renders (Dockerfile, `cargo install`,
  `cargo build`) no longer list the mediator's `vta` feature.

### Breaking — images built from this release have no VTA integration

- The container image builds the mediator's `default` features, which no
  longer include `vta`, and `mediator-setup` without VTA flows. An image from
  this release cannot boot a mediator from a VTA or run the wizard's VTA
  setup. Use an earlier image for a VTA-linked deployment until `vta` returns.

### Breaking — `affinidi-messaging-sdk` 0.47, `affinidi-tdk` 0.45, `trust-tasks-rs` 0.39, `affinidi-crypto` 0.3 (R3.6)

- The workspace moves to the current TDK line:
  - `affinidi-messaging-sdk` 0.47.2, from 0.46.3.
  - `affinidi-tdk` 0.45.0, from 0.43.0 (mediator-setup, test-mediator).
  - `affinidi-messaging-didcomm-service` 0.32.0, from 0.31.0 (test-mediator
    dev-dependency).
  - `trust-tasks-rs` and `trust-tasks-proof` 0.39.0, from 0.38.0. This is the
    version `affinidi-messaging-sdk` 0.47.2 requires, so one copy of each
    crosses the SDK boundary. 0.39 is 0.38 rebuilt on `affinidi-crypto` 0.3.
  - `affinidi-crypto` 0.3, from 0.2.
  - The floors that move with them: `affinidi-data-integrity` 0.8.7,
    `affinidi-did-common` 0.4.7, `affinidi-messaging-didcomm` 0.15.14,
    `affinidi-messaging-didcomm-v1` 0.2.4 (on `affinidi-crypto` 0.3),
    `affinidi-messaging-core` 0.1.12, `affinidi-did-resolver-cache-sdk`
    0.8.53, `affinidi-secrets-resolver` 0.5.18.
- **Library users:** `trust-tasks-rs` and SDK types cross these crates'
  public APIs. Examples are the generated
  `affinidi_messaging_mediator::task_specs` and the SDK's `ATM` /
  `ATMProfile` / `ATMError` taken and returned by
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-test-mediator`.
  A crate that passes such values to or from these crates must itself move
  to `trust-tasks-rs` 0.39, `affinidi-messaging-sdk` 0.47 and
  `affinidi-crypto` 0.3, or it gets mismatched types from two copies.
- No source change was needed in the mediator, the admin client, the console
  or the test mediator. The wire protocol is unchanged, and clients on earlier
  SDKs see no difference.
- Every `affinidi-*` and `trust-tasks-*` crate now resolves once. The four
  duplicates `vta-sdk` 0.77 brought (`affinidi-messaging-sdk` 0.44,
  `affinidi-tdk` 0.36, `trust-tasks-rs` / `trust-tasks-proof` 0.36) left with
  it, and their allow-list entries are gone.

### Changed — manual image runs publish only what their ref allows

- A manual run of `publish-images.yaml` on a release tag publishes only that
  tag's version. On `main` or `release/*` it publishes only a dev version,
  `vX.Y.Z-dev.<hex sha>` (the default); any other branch is refused. A
  version already in GHCR is replaced only with the new `overwrite` input,
  checked before the build and again just before the tag moves; one run at a
  time publishes a given version. Rules in `docker/ci/check-dispatch.sh`,
  self-tested by `docker/ci/test-dispatch-guard.sh` on every image run.
- The jobs that push images (`build`, `publish-ghcr`) now run in the
  `release` environment, like the ECR mirror. Its deployment policy must
  admit `v*` tags (RELEASES.md) or tag runs will wait.
- The README says how to pin the image by digest and verify its provenance.

### Changed — DIDComm v1 `keylist-update` registers only keys the client is known to hold, up to a limit

- **Behaviour change (R3.6):** by default a `keylist-update` add succeeds
  only for the verkey that authenticated the request. Any other key gets
  `client_error`. Coordinate-mediation 1.0 gives the mediator no proof that a
  client holds the other keys it lists. Aries wallets, which register a new
  key per connection, need the new `[didcomm_v1] allow_unproven_routing_keys
  = true` (default `false`).
- **Behaviour change (R3.6):** an account holds at most
  `[didcomm_v1] max_routing_keys_per_account` routing keys (new, default
  256). An add past the limit gets `client_error`, and removing a key frees
  a slot. The account's keys are counted once per request and again after
  its adds. If concurrent requests took the account over the limit, the
  request's newest adds are withdrawn and reported as `client_error`.
- **Behaviour change (R3.6):** an add needs the account to hold
  `RECEIVE_MESSAGES`, the same condition `mediate-request` checks before it
  grants mediation. Otherwise the add gets `client_error`. A remove does not
  need it.
- **Behaviour change (R3.6):** one `keylist-update` may carry at most 100
  entries. A longer one is refused with `400 message.didcomm_v1.keylist`, and
  none of its entries are applied.
- **Behaviour change (R3.6):** a key registered without proof can be taken
  over by its holder. That is the case where another account registered the
  key under `allow_unproven_routing_keys`, and the key's holder then adds it
  in a request that key authenticates. Otherwise a key registered to one
  account is still never moved to another.
- Re-adding a key the account already holds is `no_change` under every
  setting.
- When another account claims a key between the mediator's check and its
  bind, the add gets `client_error`. It used to get `server_error`.
- A remove, or a withdrawn add, deletes the binding only while this account
  still holds it. The deletion is one atomic step in each store. New
  `MediatorStore::v1_routing_key_unbind_if_owner`.
- Every refused add is logged with its reason. The mediator warns at startup
  when `allow_unproven_routing_keys` is on.
- New: `MediatorBuilder::didcomm_v1_routing_keys` and
  `TestMediatorBuilder::didcomm_v1_routing_keys`.

### Changed — live mux members and monitor subscriptions follow account changes
### Changed — live mux members and monitor subscriptions follow account changes; `revoke-all` ends session attaches

- A mux member stays on a connection only while its own account stands: it
  exists, is not blocked, and its ACLs still cover the member's scope. That
  was checked only when the member was admitted. It is now checked again:
  - at once, when `account/update` changes the member's ACLs or
    `account/remove` removes it: on the instance that handled it before it
    answers, and on the other instances sharing a Redis store within one
    pub/sub hop (a new `members` entry on the mux change record; an
    instance that predates it ignores it);
  - when a pickup or delete is made for the member on the connection, or a
    `tsp-mux` drain is about to walk its inbox. A delete checks only the
    member that a message id belongs to, and a good result counts for 10
    seconds, so a burst of requests reads the account once;
  - every 30 seconds, by a standing pass that runs off the socket loop with
    at most 8 store reads in flight. This catches a change made directly in
    the store, or whose pub/sub record was lost.

  A member whose standing has lapsed is detached, with a `detached` event
  naming `accountBlocked` or `accountRemoved`. Members admitted by a session
  attach are covered as well as grant-admitted ones; until now an attach
  outlived its member's removal. ACLs narrowed below the member's scope
  detach the whole member with `accountBlocked`, as admission would have
  refused it; the member is not narrowed to what the ACLs still allow. A
  store failure during a re-check keeps the member, but the request it was
  made for is refused.
- `messaging/mux/revoke-all` now ends the member DID's session attaches as
  well as its grants, on every connection carrying it, before it answers,
  with a `detached` event naming `epochBumped`. Other instances end theirs
  within one pub/sub hop. Only attaches admitted before the `revoke-all` end;
  one made afterwards stays.
- A live frame for a member whose admission has expired is no longer
  written in the moments before the sweep removes the member.
- A `messaging/monitor/subscribe` subscription whose filter reaches beyond
  its owner's own account (one only an administrator may open) now needs its
  owner to still be an administrator (the store's admin check) each time a
  batch is sent. Any subscription also ends when its owner's account is
  removed or blocked. When that happens:
  - pending events are discarded and counted as dropped;
  - the subscription is ended before the subscriber is told, so a renewal
    racing the end also gets `unknownSubscription`;
  - a last batch with no events and `expiresAt` set to now tells the
    subscriber it has ended;
  - if the subscription had administrator reach, its end is written to the
    audit log as `monitorUnsubscribe`.

  A batch whose standing check cannot read the store is withheld and
  counted as dropped; the next batch reports it.

**Behaviour change (R3.6):**
- A principal can lose a member before the grant or attach expires, when an
  administrator blocks or removes the member's account or narrows its ACLs
  below the member's scope. Clients already handle `detached` with these
  reasons, which the event schema defines.
- `revoke-all` ends session attaches. The `messaging/mux/revoke-all` 0.1
  specification said they were unaffected; it is amended to match
  (dtgwg-trust-tasks-tf#1165). A principal relying on an attach
  surviving its member's `revoke-all` must attach again with a new statement.
- An administrator demoted mid-lease stops receiving monitor batches at the
  next batch rather than at the end of the lease. A client that renews only
  shortly before `expiresAt` should treat a batch whose `expiresAt` has
  already passed as the end of the subscription.

### Changed — `account/add` is admin-only and never replaces an existing account

- `messaging/account/add` for a DID that already has an account is refused
  with `messaging/account/add:alreadyExists` (409), and the account is left
  as it was. It used to be written afresh: role back to `standard`, ACLs
  back to `global_acl_default`, queue limits, counters, activity and stats
  cleared. Use `messaging/account/update` to change an existing account.
- `messaging/account/add` now requires an `Admin` or `RootAdmin` account in
  both `mediator_acl_mode`s. In `explicit_deny` any authenticated account
  could call it; its own account always exists by then (authentication
  creates it), so the only accounts it could add were other DIDs'.
- `MediatorStore` gains `account_create`, which creates an account only if
  none exists and returns `None` otherwise, with the check and the write in
  one atomic step (a Lua script on Redis; under the store lock on memory and
  Fjall). `account_add` is now a provided method built on it: it creates
  the account or returns the existing one unchanged, so two first-contact
  requests racing can no longer reset an account's counters. Login
  registration (`/authenticate`, `/tsp/authenticate`) creates the account
  through it in one step, so an account an admin adds or changes while a
  login is in flight is used as it is. A third-party
  `MediatorStore` implements `account_create` in place of `account_add`.
- Storing a message for a party with no account keeps queue counters for
  it, and every backend now agrees that those counters alone are not an
  account: it is not found by `account_exists` / `account_get`, not listed,
  not given ACLs (and so not admitted in `explicit_allow`), and
  `account_create` completes the record, keeping its counters. Memory and
  Fjall used to treat such a record as a deny-all account; Redis's
  `account_exists` counted it too. Fjall marks records with a new
  `is_account` field; records written before it read as accounts.
- Admin set-up at start completes such a record before setting the role,
  so the mediator and root-admin accounts never end up without ACLs.
- `account/add` checks the caller's role in the store, not the role cached
  in its session.

**Behaviour change (R3.6):** a non-admin client calling
`messaging/account/add`, or any caller re-adding an existing account to
reset it, now gets an error.

### Changed — access and refresh tokens are each accepted only where they belong (R3.6)

Auth-semantics change: clients that send the access token as the bearer and
the refresh token to `/authenticate/refresh` (as the SDK does) are
unaffected.

- Session tokens now carry a `token_use` claim, `"access"` or `"refresh"`.
  `aud`, the header and the signing key are unchanged.
- REST routes and `/ws` (both the `Authorization` header and the
  `bearer.<jwt>` subprotocol) accept only access tokens; a refresh token is
  refused with `401`.
- `/authenticate/refresh` exchanges only refresh tokens. An access token is
  refused with `400` (error code 38) before the stored refresh-token hash is
  consulted, so it no longer ends the session.
- Transition for tokens issued by the previous release, which have no
  `token_use`:
  - as a bearer, an unmarked token is accepted only if it has no `jti` and
    expires within one access-token lifetime (`jwt_access_expiry`) plus the
    60 s expiry leeway. Anything longer-lived is a refresh token and is
    refused;
  - at `/authenticate/refresh`, an unmarked token is still accepted; the
    one-time stored-hash check applies as before.
  - All such tokens have expired one `jwt_refresh_expiry` after the upgrade;
    a later release will refuse unmarked tokens outright.
  - An operator who lowered `jwt_access_expiry` in the same upgrade will see
    previously issued access tokens refused early; clients refresh or
    re-authenticate as on expiry.

### Changed — token refresh is bound to the session's DID and is single-use

- `/authenticate/refresh` now requires the authcrypt sender, the inner
  message's `from` and the refresh token's subject to name the DID that owns
  the session. A refresh sent from any other DID is refused with
  `authentication.session.mismatch` (error code 33). The blocked check on
  refresh now reads the session owner's ACLs.
- A session with no recorded refresh-token hash can no longer be refreshed.
- The compare and the rotation of the refresh-token hash are one atomic
  store operation on every backend (a Lua script on Redis, under the
  backend's lock on Fjall and Memory). Of two requests presenting the same
  refresh token, at most one succeeds.
- Presenting a refresh token that was already exchanged, or one the session
  has no record of, ends that session: the request gets `401` and the DID
  must authenticate again from the challenge.
- `MediatorStore` gains `rotate_refresh_token_hash` and the
  `RefreshRotation` outcome. The trait default is not atomic; out-of-tree
  backends should override it.

### Changed — accounts are registered after the challenge is answered

- In `explicit_deny` mode, `/authenticate/challenge` no longer creates an
  account for an unknown DID. The account is created with
  `global_acl_default` once the DID answers the challenge on `/authenticate`
  or `/tsp/authenticate`, before any token is issued. The blocked and
  `explicit_allow` checks at the challenge step are unchanged.
- `/authenticate/challenge` accepts only a `did:<method>:<id>` string of at
  most 2048 bytes with a lowercase-alphanumeric method and DID URL
  characters; anything else gets `400 authentication.challenge.invalid_did`.
- The authentication routes carry their own body limits: 16 KiB for
  `/authenticate/challenge` and `/tsp/authenticate`, 64 KiB for
  `/authenticate` and `/authenticate/refresh` (previously axum's 2 MiB
  default). A larger body gets `413`.
- Both login steps (`/authenticate`, `/tsp/authenticate`) re-check whether
  the DID is blocked when the challenge is answered, so a DID blocked after
  it was issued a challenge gets no tokens. `/tsp/authenticate` previously
  relied on the check made at the challenge step.
- `/authenticate` now requires the answer to carry the challenge string the
  session issued (`authentication.session.invalid`, error code 34).
- A `ChallengeSent` session is readable before its DID has an account, on
  every backend.

### Changed — removing an account ends its sessions on every backend

- `get_session` fails with `Unauthorized` for a session past the challenge
  step whose DID has no account. Redis already refused such sessions (as a
  storage error); Fjall and Memory returned them with the ACLs recorded at
  the challenge, so a removed account kept using and refreshing its session
  until it expired.
- Requests carrying such a session's access token get `401` instead of
  `500`, and `/authenticate/refresh` answers `401
  authentication.session.invalid` instead of `503`, so clients authenticate
  again rather than retry.

**Behaviour change (R3.6):** a client that retries a refresh with a token it
already exchanged (for example after losing the response) has its session
ended and must re-authenticate. Tooling that relied on a DID's account
existing as soon as it requested a challenge will see it only after the
first successful authentication. Challenge requests with non-DID-shaped or
oversized `did` values, and refresh requests sent from a DID other than the
session's, are now refused. Sessions of a removed account stop working at
once on Fjall and Memory, as they already did on Redis.

### Changed — forwarding delivers to endpoints concurrently, with per-endpoint backoff

- The forwarding processor delivers to up to `max_concurrent_endpoints`
  next-hop endpoints at once (default 32). Messages for one endpoint still go
  out one at a time, usually in queue order; a retried message can now go
  after later ones. Before, endpoints were served one after another, so a
  slow peer delayed every other peer's forwards.
- Each delivery attempt is bounded by `delivery_timeout_seconds` (default
  90, env `PROCESSOR_FORWARDING_DELIVERY_TIMEOUT_SECONDS`), covering a
  WebSocket attempt and its REST fallback together.
- Backoff now applies to the failing endpoint only. The processor used to
  pause all forwarding for up to `max_backoff_ms` after a failed batch. Now
  the failed message is queued again with a not-before at the end of that
  endpoint's backoff, and the endpoint's other messages are held until the
  same time instead of being sent into the failure. Those were not sent, so
  they keep their retry budget. Every processor sharing the queue honours
  the not-before, so retries are spaced out on multi-processor deployments
  too.
- A processor holds at most `batch_size` × `max_concurrent_endpoints`
  claimed entries, one endpoint at most half of them, and an endpoint that
  is backing off at most `batch_size`, so backlogs for peers that are slow
  or down do not stop other peers' forwards being read. The rest stay
  claimed in the queue and are picked up again by the reclaim sweep.
- Claimed entries are no longer stranded when a processor stops or
  restarts. A processor refreshes the claims on what it holds, and any
  processor takes over an entry whose claim has been idle for
  `reclaim_idle_seconds` (new, default 180, env
  `PROCESSOR_FORWARDING_RECLAIM_IDLE_SECONDS`). Previously such entries were
  reclaimed but never delivered. The sweep follows its cursor over the whole
  pending list, so idle entries behind a long run of busy ones are reached.
  The same sweep delivers a forward with a requested delay (`delay_milli`)
  once it is due; a delay of up to `max_backoff_ms` is held in memory and
  sent on time.
- A processor only finishes an entry it still holds. Acking a delivered,
  refused, expired or abandoned entry, and replacing a failed one with its
  retry, are each one owner-checked write; an entry another processor has
  taken over is left to it. A processor that cannot confirm its claims for
  half of `reclaim_idle_seconds` (its store calls are failing) stops
  sending — including a REST fallback after a WebSocket attempt — reading
  and reclaiming until it can. A send already under way at that point
  completes, so its message can arrive twice; none is lost. Keep
  `reclaim_idle_seconds` at least twice `delivery_timeout_seconds` so such a
  send ends before another processor can take the entry over; the processor
  warns at start when it is not. A processor holding all it may skips the
  reclaim sweep. Reclaimed entries that cannot be parsed are dropped with a
  warning instead of being reclaimed again and again.
- Each delivered entry is acked as soon as the peer accepts it, rather than
  with the rest of its batch.
- A next hop whose URL does not parse, or that the egress policy does not
  admit, is final: the forward is dropped on the first attempt and the
  sender gets a problem report with the new code
  `e.p.me.res.forwarding.endpoint-not-permitted`. It used to be retried
  `max_retries` times and reported as abandoned.
- `ForwardQueueEntry` has a new `not_before_ms` field (unix ms, `0` = none),
  stored as `NOT_BEFORE_MS` on Redis. Entries written before it read as `0`;
  a processor from an earlier release ignores it and retries at once.
  `ForwardOutcome` has a new `NotPermitted` variant. `MediatorStore` has
  new required methods `forward_queue_refresh_claims` and
  `forward_queue_finish`, and `forward_queue_autoclaim` now takes a cursor
  and returns a `ForwardQueueClaimPage` with the cursor to continue from.

**Behaviour change (R3.6):** retries of a failed forward are spaced by the
endpoint's backoff across all processors; forwards to a non-permitted next hop
produce `e.p.me.res.forwarding.endpoint-not-permitted` instead of
`e.p.me.res.forwarding.abandoned`; messages may be relayed in a different
order than they were queued, across endpoints and, after a retry, within one;
and an entry a stopped processor held is delivered by another after
`reclaim_idle_seconds`, which can repeat a delivery the stopped processor made
but had not yet acked.

### Changed — mux frame decisions are counted; delivery reports hold no body

- A live frame the socket withholds from a mux member, decided against the
  member's scope when it comes up, now counts in
  `mux_live_frames_withheld_total{outcome="nudge"|"drop"}`: `nudge` for a
  `pickup`-only member, whose principal is told mail waits, and `drop` for
  a member that left or holds neither scope. These were visible only in
  debug logs.
- A websocket delivery report, which rides with its queued frame until the
  write, now carries the frame's protocol instead of a copy of its body.
  The monitor only ever used the body to name the protocol and never
  published it, so events are unchanged. Queued frames no longer double
  their memory while a monitor is subscribed. `StreamingTask` no longer
  takes a monitor, and `spawn_supervised_with_monitor` is gone.

### Changed — `pickup`-only mux members are told when mail waits

- A member holding `pickup` but not `receive` is never pushed its messages,
  and until now the principal learned of new ones only by polling (DIDComm)
  or at the next connect (raw TSP, where the drain is the only way to
  collect). New mail for such a member now raises its resync: a pickup
  `status` naming it on DIDComm, a drain of its inbox on `tsp-mux`. Resyncs
  keep their 5 s floor, so this is a batched nudge, not a push.

### Changed — affinidi-messaging-sdk 0.45.5

- The SDK now checks mux events on DIDComm sockets: the mediator must have
  authcrypted them, and they must be addressed to the principal. It also
  keeps each connection's member set (`ATMProfile::mux_members()`,
  `TspMuxWebSocket::members()`). `tests/mux_sdk.rs` checks that set
  against this mediator: grants, an attach, a narrowed grant, a member
  inactive while its own socket is up, and a revoke.

### Changed — affinidi-messaging-sdk 0.45.4

- The SDK now has a `tsp-mux` client (`TspOps::connect_websocket_mux`), and
  parses `connectionFull` events. `tests/tsp_mux.rs` drives a raw-TSP mux
  connection through it end to end, beside the tests that drive the wire
  by hand.

### Changed — DID multiplexing across mediator instances

- **Behaviour change (clusters, R3.6):** with several mediator instances
  sharing one Redis, a grant revoked, voided by `revoke-all`, suspended by the
  unknown-key rule, narrowed by `mux/update`, marked stale by the key
  re-check, removed with its member's account, or newly stored on one
  instance now reaches the principal's live mux connections on the *other*
  instances within one pub/sub hop. Before, the other instances only
  detached, and only at their next 30-second sweep; they never narrowed a
  member or carried a new grant until the principal reconnected. A client
  connected to another instance now sees the `detached` / `attached` event
  moments after the change, with the same reasons the sweep uses (a deleted
  grant reports `revokedByMember` there). The handling instance's answer
  still waits only for its own connections.
- Each instance publishes a `MuxChangeRecord` on the Redis channel
  `MUX_CHANGES` after its local update: its instance id (the streaming UUID)
  and the changed (member DID hash, principal hash) pairs, with a flag on
  pairs whose grant was just stored. Hashes only; no statement, DID or key.
  A new supervised task, `mux_sync`, started when `[limits.mux]` is enabled,
  ignores its own instance's records and re-reads each changed member's
  record before acting, so a late or repeated record is harmless. A grant is
  carried from another instance only when the record says it was just
  stored, so a grant this connection refused on connect is not admitted by an
  unrelated change. Publishing is best effort (logged at `warn`); the
  30-second sweep remains the backstop.
- When the listener lags or loses its subscription it resubscribes (bounded
  backoff, then the supervisor's restart, which marks it degraded) and
  re-checks every member of every local mux connection. A grant stored
  elsewhere while records were missed is carried at the principal's next
  connection.
- `MediatorStore` gains `mux_changes_publish` / `mux_changes_subscribe`,
  defaulted to a no-op and `None` for single-process backends (Memory,
  Fjall); Redis implements them. A third-party backend keeps compiling.
- The mediator gains a `test-hooks` feature (test-only pause points, never
  for deployed builds). The test mediator enables it for its own tests, which
  now cover a suspension landing while a mux connection is opening (#106).

### Changed — DID multiplexing connections (R3.6)

- **Subprotocol `didcomm-mux`.** A DIDComm socket now becomes a mux
  connection by offering `didcomm-mux`, the name `messaging/mux/event/0.1`
  defines (trustoverip/dtgwg-trust-tasks-tf#1078). The provisional
  `affinidi-mux` that SDK 0.45.1 and 0.45.2 offer is still accepted; when a
  client offers both, `didcomm-mux` is selected. SDK 0.45.3 offers the new
  name.
- **`connectionFull`.** A connection already carrying
  `max_dids_per_connection` members now says so instead of leaving the
  client to infer it. On connect, valid grants it has no room for are listed
  in the `detached` event with reason `connectionFull`. A grant stored while
  the principal is connected, which the connection has no room for, gets a
  `detached` / `connectionFull` event too. Previously the first case
  was logged only, with the wrong reason, and the second only logged.
  Grants are now validated before the connection's room is checked, so a
  grant reported `connectionFull` is a valid one.
- **`attachedNow`.** A stored grant's outcome in the `messaging/mux/grant`
  response now carries `attachedNow`, which the schema requires: whether a
  connection on this instance took the member at once.
- **Event entries match the schema.** `detached` entries carry only `did`,
  `reason` and `grantId`. They used to carry `scope`, `expiresAt` and
  (for `superseded`) `deliveryActive`, which the spec allows on `attached`
  entries only. `attached` entries always carry `deliveryActive`. The
  `attached` event that marks a member inactive, because the DID's own
  direct socket keeps its traffic, now gives the reason the member joined by
  (`connect` or `attach`) instead of `superseded`, which is not an attach
  reason.
- **Login check bounded.** The unknown-key check on a direct login now
  reads the DID's grants and resolves its key within 5 s
  (`mux::notice::CHECK_READ_TIMEOUT`). A slow store or resolver refuses the
  login as retryable (`me.res.storage.error`, 503) instead of holding it
  open. The commit and detach that follow are not cut short. Each refusal
  counts in the new `mux_login_check_failures_total` metric.

### Changed — DID multiplexing connections (R3.6)

- **Subprotocol `didcomm-mux`.** A DIDComm socket now becomes a mux
  connection by offering `didcomm-mux`, the name `messaging/mux/event/0.1`
  defines (trustoverip/dtgwg-trust-tasks-tf#1078). The provisional
  `affinidi-mux` that SDK 0.45.1 and 0.45.2 offer is still accepted; when a
  client offers both, `didcomm-mux` is selected. SDK 0.45.3 offers the new
  name.
- **`connectionFull`.** A connection already carrying
  `max_dids_per_connection` members now says so instead of leaving the
  client to infer it. On connect, valid grants it has no room for are listed
  in the `detached` event with reason `connectionFull`. A grant stored while
  the principal is connected, which the connection has no room for, gets a
  `detached` / `connectionFull` event too. Previously the first case
  was logged only, with the wrong reason, and the second only logged.
  Grants are now validated before the connection's room is checked, so a
  grant reported `connectionFull` is a valid one.
- **`attachedNow`.** A stored grant's outcome in the `messaging/mux/grant`
  response now carries `attachedNow`, which the schema requires: whether a
  connection on this instance took the member at once.
- **Event entries match the schema.** `detached` entries carry only `did`,
  `reason` and `grantId`. They used to carry `scope`, `expiresAt` and
  (for `superseded`) `deliveryActive`, which the spec allows on `attached`
  entries only. `attached` entries always carry `deliveryActive`. The
  `attached` event that marks a member inactive, because the DID's own
  direct socket keeps its traffic, now gives the reason the member joined by
  (`connect` or `attach`) instead of `superseded`, which is not an attach
  reason.
- **Login check bounded.** The unknown-key check on a direct login now
  reads the DID's grants and resolves its key within 5 s
  (`mux::notice::CHECK_READ_TIMEOUT`). A slow store or resolver refuses the
  login as retryable (`me.res.storage.error`, 503) instead of holding it
  open. The commit and detach that follow are not cut short. Each refusal
  counts in the new `mux_login_check_failures_total` metric.

### Changed — Redis storage, both modes

- **Startup checks the server's cluster mode.** With `cluster_mode` off it
  reads `cluster_enabled` from `INFO cluster` and refuses only a definite
  cluster, so existing deployments start as before (no new ACL permission).
  With it on it runs `CLUSTER INFO`.
- **The expiry sweeper retries a failed delete** instead of dropping the
  message from the expiry index (both modes). A bucket it can't clear is
  tried again a minute later, behind the buckets that are due, so a message
  whose delete keeps failing can't hold up expiry for the rest.
- **A full or throttled database reaches clients as a named error** in both
  modes: 97 `storage.full` (507) or 98 `storage.busy` (503), also over a
  websocket, which got no reply before. This covers session writes and
  deletes too. 98 carries a `Retry-After` of 5 to 10 s, picked at random so
  the clients refused in one throttle don't all retry at once. The cause is read from the
  Redis error where it is converted (the `OOM` code, also inside an aborted
  transaction; a reply timeout; `STORE_IN_PROGRESS`/`DELETE_IN_PROGRESS`),
  never from its wording, so a reworded server message can't change the
  answer, and an unrelated error that mentions "timed out" isn't reported as
  busy. Handlers that wrap a storage error in their own report (login,
  token refresh, routing, pickup status, creating or deleting an
  out-of-band invitation) pass 97 and 98 through in place of the generic
  `storage.error`. A caller with no session yet (a login challenge or
  response, DIDComm or TSP, and retrieving an out-of-band invitation) gets a
  generic `storage.error` 503
  with no cause, so the endpoints open to anyone don't reveal whether storage
  is full or busy; the cause is logged. A full database
  no longer stops a restart or forwarding (with `cluster_mode` off, a
  restart goes ahead when the loaded Lua library already matches this
  build).
- The server version check accepts a two-part `redis_version`; ElastiCache
  Serverless reports `7.2`.

### Changed — one set of role rules for account administration

- Role decisions go through one set of rules (`common::roles`):
  - Only `admin` and `rootAdmin` administer accounts. The mediator's own
    account (`mediator`) does not, in any handler.
  - An account whose stored role did not decode (`Unknown`) is gated like a
    `standard` account everywhere. It used to skip the `selfManageList`
    check on access-list writes.
  - A Trust Task's caller role and ACLs, and the caller role for deleting
    an OOB invitation, are read from the store once per request. An `admin`
    / `rootAdmin` role the store does not also list as an administrator is
    not honoured.
- Only a `rootAdmin` may:
  - create an account with a privileged role (`admin`, `rootAdmin`,
    `mediator`) through `messaging/account/add`;
  - grant a privileged role, or change the role of an account that holds
    one, through `messaging/account/update`;
  - change (any member of `account/update`), remove (`account/remove`) or
    change the access list (`access-list/update`) of an account holding a
    privileged role, other than its own. The queue tasks already applied
    this rule. An account whose stored role did not decode counts as
    privileged here, so only a `rootAdmin` can change or repair it.
- The roles of the mediator's own account and of the configured
  `admin_did` cannot be changed through `account/update`
  (`account.update.protected`, 403), as neither can be removed.
- The operator console (mediator-admin) refuses a non-root administrator's
  privileged role grant before sending it, and the TUI offers the role row
  to a `rootAdmin` only.
- An `admin` still creates standard accounts, changes standard accounts and
  their roles, and changes its own account's ACL and queue limits.

**Behaviour change (R3.6):** an `admin` that is not the root admin can no
longer create or promote administrators, change the mediator's account, or
change, remove or edit the access list of another administrator; those calls are refused with
`authorization.permission` (403). `pnm messaging grant --role admin` needs to
run as the root admin (its `admin_did`), as its own message already advises.

### Changed — requests to the mediator act for the session's own DID

- Trust ping, discover features, message pickup and every Trust Task
  addressed to the mediator now need an authenticated session whose DID
  authenticated the message (signature or authcrypt). Otherwise they are
  refused before any handler runs:
  - on the anonymous inter-mediator relay session, with
    `44 authorization.authentication_required` (401). That session relays
    forwards only; forwards and blind-relay direct delivery on it are
    unchanged.
  - on an authenticated session, when the message was authenticated as
    another DID, with `52 authorization.did.session_mismatch` (400). An
    anonymous message on an authenticated session is the session's own, as
    before (where `block_anonymous_outer_envelope` lets it through).
- This holds whatever `security.force_session_did_match` says. That switch
  now governs only what a session may send (forwards and direct delivery);
  previously, with it off, a session could carry another DID's requests and
  each handler chose which of the two identities to authorise.
- The same check applies to Trust Tasks over TSP.
- Because the sender is now always the session DID,
  `block_remote_admin_msgs` holds for every administrative task.
- DIDComm v1 coordinate-mediation and pickup are unchanged: the authcrypt
  verkey is the identity there.
- On Redis, a session read back from the store is now marked authenticated
  when its stored state is `Authenticated`, as on Fjall and memory. It never
  was, so on Redis every session was handled as unauthenticated: session /
  sender matching under `force_session_did_match` and the checks TSP applies
  to an authenticated session's routed frames were skipped, and with this
  change every request to the mediator would have been refused.

**Behaviour change (R3.6):** a deployment running with
`force_session_did_match = false` whose clients send requests to the
mediator as a DID other than the one they authenticated as is refused.
SDK clients send as the session DID and need no change. On Redis,
`force_session_did_match` (default on) now applies as documented: a client
that authenticated as one DID and sends forwards or direct deliveries as
another is refused, as it already was on Fjall and memory.

### Changed — embedded mediators get a generated JWT key by default

- `Config::headless`, `SecurityConfig::headless` and `MediatorBuilder` now
  start with an Ed25519 JWT key pair generated for the process, instead of a
  fixed placeholder key. Sessions it signs end when the process restarts and
  are not shared between instances; set a persistent key with
  `SecurityConfig::set_jwt_keys_from_pkcs8`. The shipped binary and the test
  mediator already set their own key and are unaffected.

### Changed — `/readyz` reuses its backend checks; `/metrics` has access control and a request bound

- `/readyz` runs its storage, forwarding-queue, secret-backend and VTA-cache
  checks at most once every 5 s and answers every request in between from
  the last result, so polling it often costs no more backend calls than
  polling it once. The refresh runs in its own task, so it completes and is
  stored even if the request that started it times out. While it runs, other
  requests get the previous result, but only while that result is younger
  than two intervals plus the longest a refresh can take; past that,
  `/readyz` answers 503 with a failing `backend_checks` check rather than
  repeat an old answer. Each secret-backend read is bounded at 5 s. Shutdown, the storage circuit breaker and supervised-task state are
  still read on every request, and component errors are logged once per
  refresh rather than once per request. The response body is unchanged.
- **Behaviour change (R3.6):** `/metrics` is served only to clients in
  `[server] metrics_allow_cidrs` (env `METRICS_ALLOW_CIDRS`). The client
  address is resolved as for per-IP rate limiting, through
  `trust_xff_cidrs`. When the key is absent, loopback and the private
  (10/8, 172.16/12, 192.168/16), shared (100.64/10), link-local and IPv6
  unique-local ranges are allowed, so a Prometheus in the same host,
  cluster or VPC keeps scraping. A client on the public internet now gets
  `403`. `[]` refuses everyone.
  - Optional `[server] metrics_bearer_token` (env `METRICS_BEARER_TOKEN`)
    also requires `Authorization: Bearer <token>`; a missing or wrong token
    is `401`. An empty token, in the file or in the environment, is refused
    at startup rather than taken to mean no token; leave the key out to
    require none.
  - `[limits] metrics_requests_per_second` (default 5, burst twice that)
    bounds the endpoint across all callers; over it is `429` with
    `x-rate-limit-source: mediator`.
  - Refusals are counted in `metrics_requests_refused_total{reason}`.
  - The bearer scheme name is matched case-insensitively.
  - At startup, a warning is logged when `trust_xff_cidrs` is empty and
    `metrics_allow_cidrs` is the default.
  - Behind a load balancer that is not in `trust_xff_cidrs`, requests appear
    to come from the balancer's address. If that address is private,
    requests through it are still admitted; add the balancer to
    `trust_xff_cidrs`, or narrow `metrics_allow_cidrs` to the scraper.
- Requires affinidi-rate-limit 0.1.4 (was 0.1.3) for its client-address
  resolver.

### Changed — anonymous relay WebSockets are limited per address and metered

- **Behaviour change (R3.6):** when `security.enable_inter_mediator_relay`
  is on, one client address may hold at most
  `[limits] relay_connections_per_ip` (default 10) anonymous relay
  WebSockets at once (an IPv6 client is counted by its /64). All relay
  sockets still share the
  `max_websocket_connections_per_did` bucket; this stops one address from
  holding all of it. A socket over the limit is closed with 1013 ("relay
  connection limit reached for this address"). A relay upgrade whose client
  address cannot be determined is refused with `403`. The address is
  resolved as for per-IP rate limiting, so behind a load balancer set
  `trust_xff_cidrs`, or every peer shares the balancer's allowance.
- **Behaviour change (R3.6):** each relay WebSocket has an inbound budget:
  `relay_frames_per_second` / `relay_frame_burst` (50 / 100) and
  `relay_bytes_per_second` (4 MiB/s; the byte budget is never smaller than
  `ws_size`). A frame over budget is not processed. It gets a negative
  `relay-ack` with code 429, so the relaying mediator sends that message
  over REST. The socket stays open, and the relaying mediator does not
  suppress the WebSocket transport for that endpoint over a 429 ack (any
  other failure still suppresses it for five minutes).
- Every refusal is counted: `relay_connections_refused_total{reason}`
  (`per_ip`, `no_client_ip`) and `relay_frames_throttled_total{limit}`
  (`frames`, `bytes`). A refused connection is logged at warn. The first
  throttled frame on a socket is logged at warn, and later ones at debug.
- All five new limits must be greater than 0; startup refuses `0`.
  Authenticated sockets are unchanged.

### Changed — `mediator-setup` requires the digest to open a sealed bundle

- **Behaviour change (R3.6):** phase 2 of a sealed handoff
  (`--from <recipe> --bundle bundle.armor`) now requires `--digest`, and
  the TUI's verify screen no longer accepts a blank digest. The bundle's
  encryption does not identify its sender and the producer's `DidSigned` /
  `Attested` proof is not verified yet, so the out-of-band digest is what
  ties the bundle to the VTA admin. `--allow-bundle-without-digest` opens a
  bundle without one for a throwaway dev setup.
- The TUI refuses a bundle whose id differs from this run's request nonce.
  The headless path is unchanged: it looks up the decryption seed by the
  bundle's id, so a bundle for another request already fails to open there.
- The TUI no longer shows the bundle's computed digest before the operator
  types one, and `[F2]` no longer copies it: copying it back would make the
  check meaningless. A mismatch error still shows both values.
- Backend URLs printed by `mediator-setup` hide any `user:password@`
  credentials.
- `--force-reprovision` on phase 1 now discards an in-flight bootstrap's
  seed and starts a new request, as its error message and the setup guide
  said. A bundle made for the discarded request can no longer be opened.
- The headless modes (`--from`, `--non-interactive`, `--uninstall`,
  `--setup-key-*`) print the tool's warnings to stderr (`RUST_LOG`
  overrides the level). They were previously dropped.
- The `--digest` help and the setup guide's trust-model section now
  describe what the digest protects.

### Changed — the config template names no identity; release builds refuse the committed test identities

- `conf/mediator.toml` now leaves `mediator_did` and `admin_did` empty, like
  the container profile. It used to set both to the same example DID.
  `mediator-setup` fills them in; otherwise set `MEDIATOR_DID` and
  `ADMIN_DID`.
- **Behaviour change (R3.6):** a release build of the mediator refuses to
  start when `mediator_did` or `admin_did` is one of the sample or test DIDs
  committed to this repository (the old template example and the
  `docker/test/conf` identity), when a loaded operating key is one of those
  DIDs' keys (whatever DID it is published under), or when the JWT signing
  key is the one in `docker/test/conf/secrets.json`. Set
  `MEDIATOR_ALLOW_TEST_IDENTITY=true` for a test deployment;
  `docker-compose.test.yml` does. Debug builds only log a warning, so a
  debug build is not a substitute for this check.
- **Behaviour change (R3.6):** the mediator refuses to start, in every
  build, when `admin_did` names the mediator's own DID. The two are compared
  as accounts: a `did://` prefix, a fragment, a query (including a did:scid
  `src` locator) and the case of `did:` and the method do not hide a match.
  One account would otherwise hold the root-admin role, so the mediator's
  operating keys could administer every account. `MediatorBuilder` applies
  the same check, and `mediator-setup` stops before writing such a config.
  Migration: a deployment that set both to one DID (as the earlier template
  did) must give the admin its own DID before upgrading. Run
  `mediator-setup` (Admin step, "Generate did:key"), or create one and set
  `[server] admin_did` / `ADMIN_DID`, and give its keys to whoever
  administers the mediator.

### Changed — live WebSockets close with 1001 "mediator shutting down" on shutdown

When the mediator shuts down, each live WebSocket now closes at once with
1001 (going away) and the reason "mediator shutting down". The HTTP server's
graceful shutdown does not track upgraded sockets, so before this a socket
closed only once the streaming task had stopped, with 1011 "streaming task
unavailable", which reads as a server fault. Clients reconnect as before; the
code and reason now say it was a shutdown.

### Changed — `messaging/mux/ack` removes only a copy held for the connection

- **Behaviour change (R3.6):** with a stored message held per recipient,
  `messaging/mux/ack` is an acknowledgement like message-pickup
  `messages-received`: it removes the copy held for the principal or for a
  member it may delete for (the copy handed over first when several are
  held), never a copy one of them sent to someone else. An id that names
  only such a sent copy is refused as `notFound`. `DELETE /delete` still
  withdraws what the caller sent when it holds no copy of its own.

### Changed — Cross-instance mux detaches keep the reason they were made with

- A mux change record published to the other instances now carries the
  reason the originating instance detached with (`MuxChange::reason`, and
  `reason` on `MemberHint::AttachesEnded`). A receiving instance uses it to
  label a detach the store cannot attribute, so a principal connected to
  another instance sees `admin` or `revokedByPrincipal` rather than
  `revokedByMember` or `epochBumped`. The store still decides whether a
  member leaves. Records without the field read as before, so instances can
  be upgraded one at a time.
- `affinidi-messaging-mediator-common`: `MuxChange` gains a public `reason`
  field and `MemberHint::AttachesEnded` a `reason` field. Code that builds
  either with a struct literal must add them (`None`); `MuxChange::of` is
  unchanged.

### Changed — TSP login signs a statement naming the mediator, the session and an expiry

- **Behaviour change (R3.6):** `POST /tsp/authenticate` now verifies the
  signature over a statement, not over the challenge string alone. The client
  signs the RFC 8785 canonical JSON
  `{"body":{"challenge","session_id"},"created_time","expires_time","from","to","typ"}`
  with `typ` `https://affinidi.com/atm/1.0/tsp/authenticate`, `from` its VID
  and `to` this mediator's DID: the fields of the DIDComm authentication
  message. The request carries `to`, `created_time` and `expires_time` next to
  `vid`, `session_id` and `signature`; the mediator rebuilds the statement
  from the challenge it issued and verifies it. Clients send this from
  `affinidi-messaging-sdk` 0.45.16.
- A statement addressed to another DID is refused with
  `authentication.tsp.statement.audience` (error code 32, `401`); one that has
  expired, was made more than 60 s ahead of the mediator's clock, or is valid
  for longer than 300 s with `authentication.tsp.statement.expired` (31,
  `401`); a request with only some of `to`, `created_time` and `expires_time`
  with `authentication.tsp.statement.incomplete` (28, `400`).
- A request in the older form (no `to`, `created_time` or `expires_time`) is
  refused with `authentication.tsp.statement.required` (32, `401`). Clients on
  `affinidi-messaging-sdk` before 0.45.16 send that form and cannot log in
  over TSP until they upgrade, unless the operator sets the new
  `security.tsp_auth_accept_unbound_until` (env
  `TSP_AUTH_ACCEPT_UNBOUND_UNTIL`) to an RFC 3339 time: until then the older
  form is also accepted, with a warning at boot and on every login that uses
  it. Empty (the default) accepts only the statement; a value that does not
  parse stops the mediator from starting.
- The request body now refuses unknown fields. `TspAuthenticateBody` gains
  the optional `to`, `created_time` and `expires_time` fields, and the
  module exports `signed_statement_bytes` and `TSP_AUTH_TYP`.
- `TestMediatorBuilder::tsp_auth_accept_unbound_until` sets the new setting
  in tests.

### Changed — the console's live monitor subscribes at monitor/subscribe 0.2

- The live monitor now subscribes with `messaging/monitor/subscribe` 0.2 and
  reads `messaging/monitor/event` 0.3. On a mediator that refuses 0.2 as an
  unsupported type, or whose version predates 0.52.0, it subscribes at 0.1, as
  before. The SDK marks the 0.1 types superseded; only this fallback uses
  them.
- `MediatorConsole::monitor_with` adds mux membership events.
  `MonitorUpdate::Membership` carries them, after the same batch's
  `Events`. The TUI's monitor shows members attaching and detaching to an
  administrator watching all traffic.
- Breaking for code that names these types: `MonitorFilter` is now the
  subscribe 0.2 filter, and `MonitorEvent` the event 0.3 traffic event (both
  the same JSON as before). `MonitorUpdate` has a new `Membership` variant, and
  `ConsoleError` new `Invalid` and `Unexpected` variants, so an exhaustive
  `match` on either needs an arm for them.
- Needs `affinidi-messaging-sdk` 0.45.17.

### Changed — membership monitor events cross instances behind a shared Redis

- An opted-in `messaging/monitor/subscribe` 0.2 subscriber now sees the mux
  membership changes of every instance sharing the mediator's Redis, not
  only those of the instance it is connected to. A remote event passes the
  same membership filter, non-administrator narrowing and standing check as
  a local one, and is delivered once: an instance ignores its own events on
  the channel. Traffic events stay per instance.
- Events carry no instance tag: `messaging/monitor/event` 0.3's
  `MonitorMembershipEvent` does not allow one. Telling instances apart needs
  a spec revision.
- Redis traffic only while it is used: an instance with a membership
  subscriber announces it on the mediator's own pub/sub channel
  (`MONITOR_FANOUT:<mediator DID hash>`) when one opens and every 10 s; the
  others publish their membership events for 35 s after each announcement.
  With no membership subscriber anywhere, the channel carries one query per
  instance start.
- Never on the connection path: a membership event is handed to a background
  task through a bounded queue without waiting; a full queue drops the event
  for the other instances only. With Redis down each instance's subscribers
  see that instance's events, a failed publish is logged once per outage, and
  a lost subscription restarts the `monitor_fanout` task under the supervisor
  (readiness shows it degraded meanwhile).
- Subscribers can see what was lost. Events an instance could not hand over
  or publish are reported to the others once publishing works again, and a
  receiver that fell behind on the channel counts what it missed; either
  count is added to `membershipDropped` of every opted-in subscription on the
  receiving instance (an upper bound: the lost events' filters are unknown).
  While the fan-out task is down, each opted-in event 0.3 batch carries
  `ext["com.affinidi.mediator"].membershipCoverage = "thisInstance"`: the
  subscriber is seeing only its own instance's changes.

### Changed — Trust Task refusals change form for a client that asks (R3.6)

- This is a wire change, but only for a client that asks. A request without
  the member is refused exactly as before.
- `affinidi-messaging-sdk` asks on every Trust Task from 0.46.2, and decodes
  the document into `ATMError::TrustTaskError`. A service that matches
  problem-report codes on Trust Task calls (`ATMError::ProblemReport(code, ..)`)
  and moves to that SDK should match on `ATMError::refusal_code()` or
  `ATMError::mediator_code()`, which give the same answer for both forms.
- A refused Trust Task that asked is now answered like a response: stored and
  delivered, or pushed for `messaging/mux/ack`. Over TSP the inbound POST no
  longer fails for it; the refusal arrives sealed in the inbox, threaded to
  the request.

### Changed — `affinidi-messaging-sdk` 0.46 and `trust-tasks-rs` 0.38 (R3.6)

- The workspace moves to `affinidi-messaging-sdk` 0.46.1 and to
  `trust-tasks-rs` / `trust-tasks-proof` 0.38.0, from 0.45.17 and 0.37. The
  TDK crates that move in lockstep with them move too: `affinidi-tdk` 0.43.0
  (mediator-setup, test-mediator) and `affinidi-messaging-didcomm-service`
  0.31.0 (test-mediator dev-dependency).
- **Library users:** `trust-tasks-rs` and SDK types cross these crates'
  public APIs. Examples are the generated
  `affinidi_messaging_mediator::task_specs`, the SDK's `ATM` /
  `ATMProfile` / `ATMError` taken and returned by
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-test-mediator`.
  A crate that passes such values to or from these crates must itself move
  to `trust-tasks-rs` 0.38 and `affinidi-messaging-sdk` 0.46, or it gets
  mismatched types from two copies.
- 0.38 is stricter than 0.37:
  - It refuses out-of-range `issuedAt` / `expiresAt` / proof `created`
    values instead of rolling them over.
  - It refuses a document whose `type` is not the spec it is consumed under.
  - It follows the JCS cryptosuites' `@context` rule in proofs.
  - It bounds DID resolution in the `affinidi` proof backend (10 s, no
    private hosts).
  - Its in-memory replay guard refuses when full.
- Tested against this mediator, clients on `affinidi-messaging-sdk` 0.45.17
  (`trust-tasks-rs` 0.37) and 0.44.0 (0.36) see no change. The tasks tried
  were authentication, ping, account get/update, ACL and access-list
  get/update/list, queue and message status, stats, audit, monitor subscribe,
  mux grant/list/revoke-all/admin-list/admin-revoke-all, and message pickup,
  with proofs enforced.
  - Their timestamps are in range.
  - Their documents carry no `@context`.
  - The mediator keeps its own replay record.
  - The `type` check applies only to `ping`, which both versions pass.
- **DID host policy.** A proof or mux statement whose signing key is on a DID
  naming `localhost` or a loopback, private-network or link-local IP literal
  is now refused before resolution, in both resolver modes. In local mode the
  mediator's resolver already refused those hosts. In network mode
  (`[did_resolver] address` set) this is new: 0.37 passed such DIDs to the
  resolver service. A deployment whose clients sign with DIDs on private
  hosts (e.g. a local-dev VTA at `did:webvh:{SCID}:localhost%3A3000`) behind
  a resolver service is refused; no stack in this repo or VTI does this.
- `vta-sdk` (the `vta` feature) still brings its own `affinidi-messaging-sdk`
  0.44 and `trust-tasks-rs` 0.36, as before. Nothing passes their types
  across.

### Changed — messages on an authenticated WebSocket are rate limited

- Every text or binary message read from an established, authenticated
  WebSocket is now metered per socket, at the same rate as HTTP requests:
  `limits.ws_messages_per_second` and `limits.ws_message_burst` (new) inherit
  `rate_limit_per_ip` / `rate_limit_burst` (100 a second, burst 50, by
  default) when unset; set them to override. If the per-IP value is `0`
  (per-IP limiting off, as is usual behind a load balancer) the built-in
  100 / 50 apply instead, so turning per-IP limiting off never turns this off.
  Only an explicit `ws_messages_per_second = "0"` disables it, and the
  mediator warns at startup when it is off. Ping, pong and close frames are
  not counted.
- The budget is per socket, not per DID: a DID-multiplexing connection has
  one budget shared by every DID it carries, however many there are. Raise
  `ws_messages_per_second` / `ws_message_burst` for busy multiplexing
  clients, and watch `rate_limited_total{scope="ws"}` to see when they are
  being slowed.
- A `ws_messages_per_second`, `ws_message_burst` or
  `ws_message_throttle_close_secs` value that is not a whole number refuses to
  start with a configuration error naming the key, rather than being replaced
  by a guess.
- When the per-DID limit (`limits.did_rate_limit_per_second` /
  `did_rate_limit_burst`, off by default) is enabled, each WebSocket message
  is also charged, exactly as an HTTP request is, to the sender's DID, so a
  DID shares one budget across all of its sockets. Previously only the `/ws`
  upgrade was charged.
- A message over either rate is held, not dropped: the mediator stops reading
  the socket until the message is due, so the client's further messages wait
  in its own send buffer and nothing is buffered for it on the mediator. Live
  delivery to the client continues meanwhile. A socket that stays over the
  rate for `limits.ws_message_throttle_close_secs` (new, default 10; `0` =
  never close) is closed with 1008 "message rate limit exceeded"; the clock
  resets when a message arrives within the rate.
- Messages that had to wait are counted in `rate_limited_total{scope="ws"}`
  (socket rate) and `rate_limited_total{scope="did"}` (DID rate).
- The mediator's own DID and the configured admin DID are not metered;
  anonymous inter-mediator relay sockets keep their own `limits.relay_*`
  budget.
- Env: `LIMIT_WS_MESSAGES_PER_SECOND`, `LIMIT_WS_MESSAGE_BURST`,
  `LIMIT_WS_MESSAGE_THROTTLE_CLOSE_SECS`. All three can be tightened with
  `config/patch`; a patch applies to sockets opened after it.
- `TestMediatorBuilder::ws_message_rate(per_second, burst, close_after_secs)`
  sets them for tests.

**Behaviour change (R3.6):** this is on by default. A client that sends
messages over one WebSocket faster than 100 a second (after a burst of 50;
or the configured `rate_limit_per_ip` / `rate_limit_burst`) is
now slowed to that rate, and one that keeps exceeding it for 10 seconds is
disconnected with close code 1008. Clients that send in bulk over a single
socket — including DID-multiplexing connections, whose members share the
socket's rate — should pace their sends or reconnect with backoff after a
1008, and operators with such clients should set
`limits.ws_messages_per_second` / `ws_message_burst` (or set
`ws_message_throttle_close_secs = 0` to slow without closing) before
upgrading. This includes deployments with `rate_limit_per_ip = 0`: they get
the built-in 100 / 50 unless they set these keys. With `did_rate_limit_per_second`
enabled, WebSocket messages now count against it.

### Changed — test mediator suite is one binary

The fixture's ~80 integration-test files are now modules of one binary,
`tests/e2e/main.rs`, which links the mediator, SDK and TDK once instead of
once per file (#157). Select an area with a name filter, e.g.
`cargo test -p affinidi-messaging-test-mediator --test e2e -- mux_send::`.
Only `metrics_endpoint`, `mux_metrics` and `config_reload` remain separate
binaries, since each needs process-wide state to itself. The copies of the
grant, clock, basic-message, mailbox, websocket-token and Redis-store helpers
are now one each in `tests/common`; fixed sleeps in `receive_leg_probe`
(45 s, now done when the probe is answered, about 20 s), `tsp_transport_adapter`
and `websocket_per_did_cap` wait for the condition instead; the no-op
`skip_if_no_redis` is gone; and the forwarding-processor Redis tests move to
logical DBs 5-7 so they no longer collide with the cross-instance tests in the
same process. CI's Redis and TSP jobs select the same suites by filter.

### Changed — a DIDComm message refused on a Binary WebSocket frame is answered with a problem report; an oversized frame closes with 1009

- A DIDComm message sent as a Binary frame and refused by the mediator is
  now answered with the same problem report a Text frame gets. Before, the
  refusal was only logged, and a client using Binary framing took the
  message as sent (R1.1).
- A frame over `limits.ws_size` now closes the socket with 1009 "message too
  big". Before, the read error was dropped silently and the socket ended as
  if the client had left (1001 "client disconnected"). Other read errors are
  logged and close with 1001 "connection error".

**Behaviour change (R3.6):** a client that frames DIDComm as Binary may now
receive problem-report Text frames it did not get before, and should handle
them as it does on Text framing. A client that sends an oversized frame sees
1009 instead of 1001, and should not resend the same message unchanged.

### Changed — `join` waits for live WebSockets to close and background tasks to stop

`MediatorHandle::join` (and so a mediator process exiting after SIGTERM) now
waits, for up to 10 seconds after the HTTP server has stopped, for every
WebSocket to finish closing (1001 "mediator shutting down", deregistration,
close statistic) and every supervised background task to stop. Before, it
returned as soon as the HTTP server stopped, which does not track upgraded
sockets, so a process could exit before its sockets' close frames were
written. Shutdown can take up to 10 seconds longer when a socket or task is
slow to finish; the mediator logs what it gave up waiting for.

### Changed — the Redis stored-function library is built in and versioned

- The mediator loads the `atm-functions.lua` library compiled into it, and
  `database.functions_file` is now optional: unset (the shipped
  `mediator.toml` no longer sets it), the built-in library is loaded. A file
  that is set but older than the built-in library (by its new
  `LIBRARY_VERSION` line) is refused in favour of the built-in one, with an
  error in the log.
- **Behaviour change (R3.6):** the library is only loaded over an older (or
  unversioned) one. A database already holding a newer library, loaded by a
  newer mediator, keeps it, so an older instance restarting during a rolling
  deploy no longer replaces the functions newer instances run.
- `docker/test/conf/atm-functions.lua`, the second copy of the library, is
  removed; the docker test configuration uses the built-in library.

### Changed — Redis start-up fails rather than waiting forever

- **Behaviour change (R3.6):** start-up fails at once when the database
  refuses the credentials, and after 30 attempts 10 seconds apart when it is
  unreachable; it used to retry forever.
- **Behaviour change (R3.6):** start-up fails when the database records a
  schema migration this build does not know (a newer mediator has migrated
  it). Migrations now run under a lock (`SCHEMA_MIGRATIONS:LOCK`), so
  instances starting together do not run them concurrently.

### Changed — backends agree on observable semantics

- **Behaviour change (R3.6):** the global `SENT_COUNT` / `SENT_BYTES`
  counters move when a handover is recorded (`record_delivered`, or an
  optimistic delivering fetch), on every backend. A read by id
  (`get_message`) no longer counts, and Fjall and memory, which never
  counted, now do.
- **Behaviour change (R3.6):** `live_delivery` in a pickup status reply is
  true only while live mode is on, on every backend; Redis and Fjall
  reported any connected socket.
- `list_messages` accepts `-`, `+`, `<ms>` and `<ms>-<seq>` as range bounds
  and refuses anything else on every backend (Redis passed it to `XRANGE`;
  Fjall and memory read it as unbounded).
- Fjall's paged `fetch_messages` returned one message short.
- An optimistic fetch whose delete fails returns the message, with the
  failure in `delete_errors`, on every backend (Fjall and memory withheld
  the body).
- Redis reports `poison_suspected` redeliveries; `check_admin_account` is
  false, not an error, for a DID with no record on Redis; memory keeps a
  session's expiry when its refresh-token hash is updated.

### Changed — an unresolvable blocked-forwarding DID no longer stops startup

A `processors.forwarding.blocked_forwarding_dids` entry (or the mediator's own
DID) that cannot be resolved at startup is blocked by its DID at once, logged,
and its service endpoints added by a background retry once it resolves. Errors
for a bad `streaming.uuid` or `server.did_web_self_hosted` now name the setting
and the value.

### Changed — secret backend guidance

- `keyring://` on Linux is the kernel keyring, which loses its keys on reboot;
  the mediator now warns at startup when it is used there, and the template
  and `docs/secrets-backend.md` say so.
- `azure_keyvault://` authenticates only with an Azure CLI login and is marked
  wizard / development only (not HA-capable) in the docs.
- The VTA-cache HMAC is documented as detecting corruption or mismatch, not
  tampering by someone who can write the backend.

### Changed — the HTTP server bounds slow, idle and excess connections

- HTTP/1 clients have `limits.http_header_read_timeout_secs` (default 30) to
  send a request's headers. The clock runs whenever a connection waits for its
  next request, so idle keep-alive connections are closed after it too, and a
  new connection that sends nothing is closed at the same deadline. hyper
  never enforced its header timeout before, because the server had no timer.
  HTTP/2 connections are pinged every 20 s and closed when a ping goes
  unanswered for 20 s.
- Each HTTP request other than `/ws` has `limits.http_request_timeout_secs`
  (default 60), body upload included. Past it the mediator answers **408** and
  drops the request's work. A client uploading a message near `http_size` over
  a slow link may need this raised.
- `limits.max_http_connections` (default 20000, 0 = unlimited) caps the TCP
  connections the listener holds, WebSockets included. A connection over the
  cap is closed as soon as it is accepted, before TLS. New metrics:
  `http_connections_open` and `http_connections_refused_total`.
- An unreadable value for any of the three keys refuses to start. All three
  are documented in `conf/mediator.toml`, with `LIMIT_*` environment overrides.

### Changed — OOB invitation lookups answer with real HTTP status codes

- `GET /oob?_oobid=` for an unknown invitation answers HTTP **404**, and a
  `DELETE /oob` by a non-admin for an unknown invitation answers HTTP **404**.
  Both used to answer HTTP 200 with a body whose `httpCode` was 404 or 204.
  The SDK already treated both answers as errors. A client that read only the
  body's `httpCode` must now also accept a non-2xx status (R3.6).

### Changed — `/fetch` takes its limit from `limits.listed_messages`

- `POST /fetch` accepts a `limit` from 1 to `limits.listed_messages` (default
  100). It was hardcoded to 100, so a mediator configured with another value
  refused, or allowed, the wrong amount. A `start_id` must now be a whole
  message id: one with characters before it used to pass.

### Changed — `jwt_refresh_expiry` is documented as what it does

- A refresh token is valid for `jwt_refresh_expiry - jwt_access_expiry`
  seconds from issue (85500 s with the shipped values). `conf/mediator.toml`
  described it as the refresh-token lifetime. The behaviour is unchanged.

### Changed — The mediator image runs as UID:GID 10001:10001

- `USER` is now numeric (`10001:10001`, user and group `mediator`), so
  Kubernetes `runAsNonRoot: true` accepts the image without a `runAsUser`.
  It used to be a system-allocated UID for `lowPrivUser`. **Files you mount
  into the container (config, `file://` secrets, TLS keys) must be readable by
  UID 10001**; a deployment that chowned them to the old UID needs updating.
- The image no longer runs `apt-get upgrade` on its digest-pinned base, so a
  given digest always builds the same runtime layer. Base-image fixes arrive as
  digest bumps.
- Nothing is copied from the template `conf/` directory: the sample
  `mediator_did.json`, `secrets.json-example` and `atm-functions.lua` no longer
  ship in the image. The container profile leaves `database.functions_file`
  unset, so the Redis library built into the binary is loaded.

### Changed — Release profile tuned for throughput

- `[profile.release]` is now `opt-level = 3`, `lto = "thin"`,
  `codegen-units = 1`, `strip = "symbols"` (was `opt-level = "s"`, fat LTO).
  The image and in-repo release builds are faster on the crypto/JSON hot paths
  and the image build needs far less memory. Binaries are stripped of symbols;
  panics still report file and line. Cargo applies this profile only to builds
  of this workspace: `cargo install affinidi-messaging-mediator` users can
  match it with the environment variables in the README's "Release profile"
  section.

### Changed — console keys: `Esc` no longer quits; `?` lists every key

- `Esc` only closes popups. On its own it does nothing, so one `Esc` too many
  no longer ends the session. Quit with `q` or `Ctrl-C`.
- `?` opens a help overlay listing every key for the current screen. The
  overlay and the footer come from one key table. The footer fits the width
  and ends with `… ? for more` when cut.
- `y` copies the selected row's full account hash, DID or message id to the
  clipboard (OSC 52). `]` (or reaching the last row) loads the next page of
  a list. `PgUp` / `PgDn` page through tables while the monitor is closed.
- Role, ACL, limit and configuration changes need a confirmation:
  - `s` in the account editor shows each change (`role: admin → rootAdmin`)
    and waits for `y`. It warns when the console's own account would be
    demoted or blocked.
  - A new `limits.*` value shows `from → to` and waits for `y`.
  - `x` on the Config screen (reset an override) now asks first.
- `r` reloads the screen from its first page.

### Changed — Hot-path store, I/O and parsing costs cut (P12 perf)

- **Queue survey (#144).** `queue_oldest_age_seconds` now ages the deepest
  queues plus a window over every other non-empty queue that rotates each
  cycle, so a shallow queue stuck for days is reached within a bounded number
  of cycles. Alert on `max_over_time(...)` over a window that spans the
  rotation. A survey cut short by the account cap resumes where it stopped on
  the next cycle instead of starting at 0 again, and each probe lists its
  queue once. **The gauge reads `NaN`, not `0`, when messages are queued but
  no probe succeeded**: `0` now means only that the folder is empty.
- **Fjall (#175).** The `fsync` behind `durability = "sync"` runs on the
  blocking pool, not on a runtime worker. Streaming registrations are held in
  memory and no longer take the global write lock or touch disk; an older
  data directory's `streaming_clients` keyspace is dropped at open.
  `inbox_status` reads the two ends of the inbox rather than walking it, v1
  routing keys get an in-memory owner index (no scan on `v1_routing_keys_for`
  or account removal), the session sweep decodes only the expiry, and
  `account_list` no longer re-serves accounts that follow a counter-only record
  on the next page.
- **Live streaming (#128).** A mux member is registered with live delivery in
  one command and one store write (was `Register` + `Start`, two writes). An
  inactive entry corrects the store's live state once, not on every in-flight
  notification. Inbox redeliveries run at most 32 at a time, and the
  streaming control channel holds a mux connection's whole member set.
- **Mux sweeps (#132).** The 30 s grant re-check and the key revalidation run
  as a task beside the socket loop, with store reads and DID resolutions eight
  at a time, so the socket keeps reading, writing and pinging during a sweep.
- **WebSocket and delete paths (#159).** A socket re-reads its account before
  a frame only when an account change has been seen since its last read or
  that read is over 2 s old. A change made through any mediator instance (ACL
  set, role change, account removal; role changes are now published to other
  instances too) still reaches the socket on its next frame; **one made
  directly in the store, behind every instance, can take up to 2 s**.
  `DELETE /delete` reads mux members' copies with one batched read per member
  and works on up to eight ids at once; `POST /outbound` fetches with one
  batched read and deletes after the write eight at a time.
- **Inbound (#198).** The envelope pre-read skips the ciphertext instead of
  copying it into a JSON tree. In Rewrap relay mode the innermost envelope is
  decrypted once, not twice. Forwards borrow their attachment and **read the
  attached envelope only for a local next hop**: one for a remote hop is
  relayed as is and judged by the mediator it goes to. Trust Task requests
  decode only their payload, and the response-signing key (re-resolved every
  5 minutes) and proof verifier are cached.

### Changed — one defaults table and one read per setting for `mediator.toml`

- `affinidi_messaging_mediator_config::defaults` is the single table of
  built-in defaults. The raw schema's serde defaults, the new `Default` impls
  of `LimitsConfigRaw`, `ForwardingConfigRaw`, `ProcessorsConfigRaw`,
  `MessageExpiryCleanupConfigRaw`, `DatabaseConfigRaw` and
  `DIDResolverConfig`, and the mediator's `LimitsConfig::default()`,
  `ProcessorsConfig::default()` and headless `Config` all derive from it.
  `LimitsConfig::default()` is now the table read through the same strict
  conversion as a file, so a default can never be a value the file would
  refuse. The values are unchanged.
- `affinidi_messaging_mediator_config::settings` holds the typed reads of
  `log_level`, `log_json`, `[streaming]`, `[did_resolver]`
  (`DidResolverSettings`), `[secrets] cache_ttl` and `[storage]`, which used
  to be private to the mediator binary. They are pure, so any consumer of
  `mediator.toml` can run the same checks.
- Building the mediator's `Config` is now two steps: a pure
  `ConfigRaw → ValidatedConfig` step that reads every file-only value once
  (run at startup and by `config/reload`), then `resolve()`, which opens the
  secret backend, runs the VTA integration and resolves DIDs using those
  values rather than reading the file a second time.
- `ConfigError` gains an `Inconsistent` variant for settings that each read
  but do not work together (it is `#[non_exhaustive]`).
- Config file format, environment variables and default values are
  unchanged.

### Changed — mediator-common depends on mediator-config, and takes its defaults from the table

- The dependency between the two crates is inverted:
  `affinidi-messaging-mediator-common` now depends on
  `affinidi-messaging-mediator-config`, and the config crate no longer depends
  on mediator-common (it takes `affinidi-messaging-mediator-types` directly for
  the ACL types). The config crate is published first.
- `ForwardingConfig::default()`, `ForwardingConfig`'s serde defaults (which the
  standalone forwarding processor reads its typed TOML with) and
  `DatabaseConfig::default()` now read the `defaults` table instead of
  repeating its values. The values are unchanged; `DatabaseConfig::default()`
  still names `./atm-functions.lua` as its `functions_file`.
- The headless `SecurityConfig` (what `Config::headless` and `MediatorBuilder`
  start from) takes its JWT lifetimes (900 s access, 86400 s refresh) and
  security flags from the new `defaults::security` table. Values unchanged.
- `redact` and `did_identity` move to `affinidi_messaging_mediator_config`
  (its schema and validation use them). mediator-common re-exports both, so
  `affinidi_messaging_mediator_common::redact::*` and
  `affinidi_messaging_mediator_common::did_identity::*` keep working.
- mediator-common's lean tier (`default-features = false`) now also pulls the
  config crate's dependencies: `toml`, `serde_ignored`, `ipnet`, `humantime`
  and `tracing`.

### Changed — mediator-setup: the wizard no longer writes the file-backend passphrase into its own environment

The interactive wizard used to export the `file://?encrypt=1` passphrase
with `std::env::set_var`, which is unsound on its multi-threaded runtime
(a worker thread may read the environment at the same time). It now keeps
the confirmed passphrase in memory and hands it to every open of the
encrypted store. Nothing changes for operators: the mediator still reads
`MEDIATOR_FILE_BACKEND_PASSPHRASE` / `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE`
at boot, and headless runs (`--from`, `--non-interactive`,
`--setup-key-file`) still take the passphrase from those variables.

A recipe the wizard saves after a TUI sealed-mint handoff now records
`vta_mode = "sealed-mint"` instead of the legacy alias `"sealed"`. Both
load the same way.

### Changed — mediator-setup: internal restructuring

`app.rs` and `main.rs` are split into modules (`app/` for the wizard's
steps, choices, screen text and sub-flows; `flows/`, `tui/`, `provision/`
and `install.rs` for the binary), and `WizardConfig` holds enums rather
than the selection-list labels. Screens, prompts, flags, recipes, the
generated files and exit codes are unchanged.

### Changed — the console's code is split by concern

- `app.rs` (5,000 lines) is split into `state` (the typed model),
  `keys`, `monitor`, `popup` and one module per screen, each a `render`
  from the state. The screens are now tested from typed fixtures without a
  mediator.

### Changed — one local-delivery gate for DIDComm, TSP and DIDComm v1 (R3.6)

DIDComm v2 direct delivery, TSP (opaque pass-through and the routed, nested
and to-mediator arms) and the DIDComm v1 forward now pass the same
local-delivery gate (`messages::delivery_gate`). The three copies it replaces
had drifted; where they disagreed the gate keeps the stricter or more correct
answer. These are behaviour changes on the delivery and auth paths, so
consumers that match on them should check:

- **The mediator DID and a claimed sender are compared as accounts**
  (`same_account`, which ignores a did:scid `src` locator) on every path. A
  DIDComm envelope addressed to the mediator under another locator of its
  did:scid DID is now handled as addressed to the mediator rather than as a
  direct delivery, and a DIDComm direct delivery whose `skid` names the session
  DID under another locator is no longer refused with
  `authorization.did.session_mismatch`. TSP already behaved this way.
- **Who a stored message is attributed to** (its queue gates, account stats
  and recorded sender) is the sender verified on the hop, else the
  authenticated session, else the claimed sender. Two cases change: a TSP
  pass-through on an authenticated session with `force_session_did_match`
  off is now charged to the session rather than to the envelope's unchecked
  sender claim; and a DIDComm direct delivery on the anonymous relay session
  (blind relay) is charged to its claimed sender, as TSP already did, rather
  than to the anonymous session.
- **The direct-delivery-disabled refusal** (`direct_delivery.denied`, same
  code) is one problem report on both protocols: sorter `error`, scope
  `message`, and protocol-neutral text. DIDComm sent `warning`; TSP sent scope
  `protocol`.
- **DIDComm direct delivery binds the claimed sender to the session before
  the direct-delivery policy**, as TSP does. A sender that fails both now gets
  `authorization.did.session_mismatch` rather than `direct_delivery.denied`.
- **The relay peer allowlist** (`relay_trusted_mediators`) matches a peer by
  account, so a did:scid peer is recognised under any `src` locator.

### Changed — message processing and connection handling restructured

- No wire or behaviour change beyond the entry above. `messages/inbound.rs`
  is split per protocol (`inbound/{didcomm,tsp,tsp_relay}.rs`),
  `protocols/trust_tasks.rs` by task family, and `handlers/websocket.rs` by
  concern; `serve_internal` is a sequence of named startup phases and the
  WebSocket connection loop is a `ConnectionMode` with one handler per event.
- Message expiry is checked once, before dispatch, for every DIDComm message
  to the mediator. `ProcessMessageResponse` is an enum.

### Changed — each release is supported for 90 days after its GA

- The support policy is now time-based: a release gets security and
  deployment-breaking fixes for 90 days after its GA, and the newest release
  always does. It replaces "the newest two releases", which at the current
  release cadence lasted a few days. `RELEASES.md` lists each release's
  "Supported until" date; `SECURITY.md` and the README say the same.
- Every `0.x` minor is a breaking release under Cargo's rules: track the newest
  one and read its **Breaking** entries before you move.

### Changed — mediator library docs show the supported API

- `affinidi-messaging-mediator`'s crate documentation now describes embedding
  with `MediatorBuilder` (with a compiled example), the features and the
  supported API: `builder`, `common::config`, `store`, `task_specs`,
  `error_codes`, `SharedData` and `install_jwt_crypto_provider`. The other
  public modules (`handlers`, `messages`, `mux`, `server`, `tasks` and so on)
  are hidden from the docs. They are still public, so nothing that compiles
  today stops compiling, but they are internal and may change in any release.
- `builder::StreamingLiveness` re-exports the type
  `MediatorBuilder::streaming_liveness` takes, so it no longer has to be named
  through `tasks::websocket_streaming`.
- docs.rs builds the published crates with their storage and secret-backend
  features on, so those items appear with their feature badges.

### Fixed — WebSocket relay to a next hop is time-bounded and dials the checked address

- Every step of a WebSocket relay attempt to a next-hop mediator now has a
  limit: name resolution, TCP connect, TLS and the upgrade together get 10 s;
  the whole attempt (pooled socket, a reconnect if that failed, the send and
  the peer's `relay-ack`) gets 30 s, or a third of `delivery_timeout_seconds`
  if that is less, so the REST fallback always has time left. The close
  handshake on a discarded socket runs on its own task, bounded at 5 s. A
  next hop that accepts the connection and never completes the handshake used
  to hold the attempt until `delivery_timeout_seconds` ran out, with no REST
  fallback, and the same thing happened on every retry; it now falls back to
  REST after 10 s.
- When a next-hop name resolves to several addresses, each gets a share of
  the connect time (at least 2 s), so one that never answers does not stop
  the others being tried.
- The processor logs a warning at startup when `delivery_timeout_seconds` is
  below 60.
- The socket is dialed at an address that the egress policy admitted. A
  next-hop name is resolved once, through the same guarded resolver the REST
  client uses, and the connection goes to one of those addresses; TLS SNI,
  certificate validation and the `Host` header still use the name. Before,
  the name was checked and then resolved again by the WebSocket client.
- A pooled relay socket is taken out of the pool for the exchange and put
  back after it, so the pool lock is never held during network I/O and no
  two deliveries share a socket.
- **Behaviour change (R3.6):** the 30 s wait for the peer's `relay-ack` now
  starts when the attempt starts, not after the connection is open, so a peer
  that takes longer than 30 s from dial to ack is relayed to over REST
  instead. Resolved addresses are now judged by the forwarding egress
  policy, the same check as on REST; in a release build that policy admits
  only globally routable addresses, as before. Discarded relay sockets are
  logged at `info`.

### Fixed — DIDComm direct delivery answers the same way for every recipient it refuses

- **Behaviour change (R3.6):** with `local_direct_delivery_allowed`, the
  checks about the sender (session binding, `SEND_MESSAGES`,
  `local_direct_delivery_allow_anon`) now run before the recipient is looked
  up. A sender-side refusal (`52`, `44`, `50`) is therefore the same whether
  or not the recipient has an account here. Previously an unknown recipient
  was answered `73 delivery.refused` first, while a known one got the
  sender-side code. Every recipient-side refusal (no account, no
  `RECEIVE_MESSAGES`, access list) is still the single `73
  delivery.refused`. The TSP path already ran its checks in this order.

### Fixed — live delivery across mediator instances (Redis)

Two instances of one mediator share Redis, and each DID's live-streaming
owner is one entry there. Two bugs:

- **An instance leaving a DID stopped another's live delivery.** Clean-up
  deleted the DID's entry whichever instance owned it: a deregistration, a
  socket found dead, and the clean start an instance runs as it boots. When a
  DID had moved to another instance (its client reconnected there, or it
  became a mux member of a connection there), the old instance's clean-up
  removed the new owner's entry, and messages for the DID were stored but no
  longer pushed until it registered again. Clean-up, and every live-delivery
  change, now touches the entry only while that instance owns it. The memory
  and Fjall stores follow the same rule.
- **A mux connection on one instance took a DID's traffic from the DID's
  own socket on another.** Within one instance a DID's own socket outranks a
  mux connection carrying it (design §7.2); across instances the newest
  registration simply won. A member online on instance A and granted to a
  principal connected to instance B lost its own live traffic, Trust Task
  replies included, to the principal's connection. Now:
  - a mux registration does not take a DID that a direct socket on another
    instance holds. The member stays on the connection, reported inactive
    (`attached`, `deliveryActive: false`);
  - when the direct socket leaves, the instance holding the mux entry is told
    over the mux pub/sub channel and takes the DID back (`reactivated`, with
    an inbox redelivery);
  - a direct socket taking a DID from a mux entry on another instance tells
    that instance, which reports the member `superseded`;
  - every 60 s each instance re-reads the owner of each DID it carries as a
    mux member, so a handoff that was lost (an instance dying between its
    store write and its publish, or a dropped pub/sub message) leaves a
    member in the wrong state for a minute at most.

  Which kind of owner holds a DID is kept in a new hash beside the owner
  entry (`STREAMING_KIND`), with `STREAMING_WAITING` for the mux entries
  waiting on a DID. The owner entry's format is unchanged, so instances on
  the previous release keep routing during a rolling upgrade; they don't
  apply the new rules until upgraded, and what they remove is claimed back
  (below).

**Behaviour change (R3.6):** principals on a multi-instance mediator see
members whose own socket is online elsewhere as inactive, and later
`reactivated`, as they already did on a single instance.

### Fixed — a live-delivery entry that goes missing is claimed back (Redis)

Each instance holds a store entry for every DID it streams. When an entry
went missing while its socket stayed open, messages for the DID were stored
but never pushed, until the client reconnected. An entry goes missing when
an instance that doesn't check owners removes it: during a rolling upgrade
an instance on 0.51 or earlier removes entries whichever instance owns them,
and its `FUNCTION LOAD` at startup brings back a clean start that does the
same. It also goes missing when the store loses data (a failover, a flush).

Every minute each instance now reads the owners of all the DIDs it streams,
direct sockets included (one `HMGET` per 500 DIDs). An entry that has gone
is claimed back, and the inbox is redelivered to a socket that wants live
delivery, so nothing that arrived meanwhile stays unseen. An entry another
instance holds is left alone, as before.
`streaming_entries_reclaimed_total{kind=direct|mux,reason=missing}` counts
the claims; it stays at 0 outside an upgrade or a data loss. `MediatorStore`
gains `streaming_owners`, with a default for single-instance stores.

**Rolling upgrade from 0.51:** a DID whose entry an old instance removes
gets live delivery back within a minute, with a redelivery. Until every
instance is upgraded, a client may see a message pushed twice after such a
claim. Upgrading all instances promptly keeps the window short.

### Fixed — mux notices reach a TSP principal, sealed for TSP

Durable `messaging/mux/notice` documents (grants suspended, revoked or
expiring; delegations present) were always packed as DIDComm. A raw-TSP
socket carries TSP frames only, so a principal on `tsp-mux` never received
them, while its `ready.pendingNotices` counted them.

- A notice is sealed for the wire its recipient last used: a TSP Direct
  message from the mediator's VID (stored as TSP messages are), or DIDComm as
  before. That is the wire of its last mux connection, or, for
  `grantsPresent`, of the direct login that prompted it. DIDComm when
  unknown.
- When a principal opens a mux connection on the other wire, its pending
  notices are re-issued in that wire's form and the old copies deleted,
  before `pendingNotices` is counted. The inbox holds one copy of each.
- The mux record gains `wire` and `noticeForms` (the payloads of the last 32
  notices, at most 64 KB, kept so they can be sealed again). Both are
  optional: an instance on the previous release reads the record as before,
  and counts the same notice ids. A notice older than the kept payloads
  stays in the form it was stored in.

### Fixed — raw-TSP sockets record only what they write, and never get a DIDComm frame

- **R1.1:** the raw-TSP inbox drain (`tsp`, `tsp-ack`, `tsp-mux`) recorded
  every message on a page as delivered before writing any of them, including
  ones it then skipped (a DIDComm message for the same DID, such as a mux
  notice). With `limits.delivered_expiry_seconds` set, a skipped message's
  expiry was brought forward although no client had seen it. It now records
  only the frames it writes, and writes only TSP frames.
- **R1.1:** the streaming task's inbox redelivery (after a socket is
  replaced, an entry claimed back, or a mux member reactivated) recorded each
  message as delivered when it queued it. Each is now recorded when the socket
  writes it; a raw-TSP socket answers the redelivery with its own drain, so a
  message it cannot carry is not recorded at all.
- A socket the streaming task closes (replaced by a newer one, or the
  mediator shutting down) got a DIDComm problem report as a Text frame before
  the close frame, raw-TSP sockets included. A raw-TSP socket now gets the
  close frame only, whose code and reason say why.
- A raw-TSP socket answers a burst of wake-ups for its own inbox (an inbox
  redelivery queues one per message) with one drain once the queue is empty,
  or every 64 under a steady stream, instead of one whole-inbox walk each.
- `MediatorStore::record_delivered` stamps messages as handed over and
  publishes the delivery metrics; `fetch_messages_delivering` uses it.

New tests for `tsp-mux`, through the SDK client: `detached` for a member's
revoke and `connectionFull`, `superseded` then `reactivated` with the
member's mail redelivered as TSP frames, a replaced socket closing without a
Text frame, the drain recording only what it writes; and
`tsp_mux_two_instances` (Redis, in both CI Redis jobs) for live delivery,
`superseded` and `reactivated` across two instances.

### Fixed — a killed instance's DIDs are taken over by the instances still running (Redis)

When an instance died without cleaning up (killed, crashed, or cut off from
the store), its streaming entries stayed in Redis. A mux member whose own
socket had been on that instance stayed inactive on every other instance's
mux connections until the member reconnected somewhere: its messages were
stored, but not pushed. (Pickup still worked.)

- Each instance now renews a heartbeat in the store every 10 s
  (`STREAMING_ALIVE:<uuid>`, lasting 45 s) and lists itself in
  `STREAMING_INSTANCES`.
- The minute recheck also asks whether the owners of the DIDs the instance
  carries are alive. A DID whose owner is listed but has let its heartbeat
  expire is taken over: the dead instance's entry is removed in one script
  that checks both again, and the entry here claims the DID, or a mux entry
  standing by for it takes it, with an inbox redelivery. A DID is taken over
  within about 105 s of its instance dying.
- An instance on an older release never heartbeats, so it is never taken
  for dead: rolling upgrades are unaffected.
- A direct socket that finds its DID held by a mux entry on another instance
  takes it back, since a direct socket outranks a mux entry. That repairs an
  instance taken for dead while it was still serving (its store writes
  failing for longer than the heartbeat lifetime): when its heartbeat comes
  back it logs a warning and rechecks at once.
- Dead instances leave the list a day after their last beat.

Metrics: `streaming_entries_reclaimed_total` gains a `reason` label
(`missing`, `dead_owner`, `outranks_mux`); new
`streaming_entries_evicted_total` and `streaming_heartbeat_lapses_total`.
`MediatorStore` gains `streaming_heartbeat`, `streaming_dead_instances`,
`streaming_evict` and `streaming_mux_owned`, with defaults for
single-instance stores. `MediatorBuilder::streaming_liveness` (and
`TestMediatorBuilder::streaming_liveness`) sets the heartbeat and recheck
timing; the defaults are for production.

**Behaviour change (R3.6):** on a multi-instance mediator, principals see
a member whose own socket was on a killed instance come back `reactivated`
on their mux connection without the member reconnecting, and its unacknowledged
messages redelivered.

### Fixed — database URL credentials are hidden in debug output

- The configuration printed at startup showed `database.database_url` in
  full, including any password it carries (`redis://:password@host/`). The
  `Debug` output of `DatabaseConfig` and `DatabaseConfigRaw` now shows
  `redis://***@host/`, as `config/show` already did, and so does the
  "Database URL is invalid" error. The helper is shared as
  `affinidi_messaging_mediator_common::redact::redact_url`.

### Fixed — WebSocket connections release their resources on every exit

- A socket's global and per-DID connection counts,
  `active_websocket_connections` gauge, streaming registration and
  `WEBSOCKET_CLOSE` stat are now held by one guard and released together on
  every return path, before the final close frame is written. Previously a
  few early exits skipped part of the cleanup, so the count and gauge could
  drift from the sockets actually open.
- A socket's streaming deregistration now names the connection it belongs
  to, not only its session. Two sockets opened with the same access token
  share a session id, so a replaced socket winding down could remove the
  live entry of the socket that replaced it, which then closed with
  "streaming task unavailable".
- An expired token is now refused before anything is reserved or
  registered. A token accepted inside the JWT leeway after its `exp` still
  closes at once with 1008 "authentication token expired", as before.
- `WEBSOCKET_OPEN` is now counted when the connection is admitted (past
  the global and per-DID limits), before it registers for live delivery,
  rather than after registration. It and `WEBSOCKET_CLOSE` always come in
  pairs.

### Fixed — a slow client no longer holds up live delivery for others

- Replacing a socket whose send queue was full waited for that socket to
  drain before the streaming task could serve anyone else. The `Close` is
  now queued without waiting; when the queue is full it follows the queued
  frames from a task of its own.
- Every WebSocket write is bounded at 30 s. A peer that stops reading is
  closed with 1001 "connection unresponsive" instead of holding its
  connection, and nothing queued for it is reported delivered. Timeouts
  count in the new `ws_write_timeouts_total`.

**Behaviour change (R3.6):** a client that stops reading its socket long
enough for a mediator write to wait 30 s is disconnected.

### Fixed — narrowing away `receive` stops live pushes

- A live frame for a mux member was written if the DID was still a member,
  whatever its scope. Narrowing a grant to drop `receive` (`mux/update`)
  left its pushes flowing until the next reconnect. Each frame is now
  checked against the member's scope when it is written.

### Fixed — a held-back resync is sent when due

- A resync raised within 5 s of the last one waited for something else to
  wake the socket, as late as the next ping. It is now sent once the floor
  has passed. This also speeds up the resync after a dropped live push.

**Behaviour change (R3.6):** principals may receive pickup `status`
messages (DIDComm) or drained frames (`tsp-mux`) for `pickup`-only members
while connected, and stop receiving pushes for members narrowed to exclude
`receive`.

### Fixed — a redelivery cut short tells the client

- The inbox redelivery a websocket gets on activation or after replacing
  another socket stops early when the socket's send queue or the byte
  budget is full, at its 1000-message cap, or when a fetch fails. It left
  the rest in the inbox for message-pickup without telling the client, so a
  client that only listens never learned it was there. It now raises the
  client's resync, as a dropped live push already did: a pickup `status` on
  DIDComm, a drain on raw TSP. On a mux connection the resync is owed to
  that member only.

### Fixed — `delivered` is reported once the frame is written

- A live push or a reconnect redelivery over a websocket was reported
  `delivered` to the traffic monitor when the streaming task put it in the
  socket's send queue, not when the socket wrote it (R1.1). A queued frame
  that was never written still counted as delivered: one for a mux member
  that left before its turn, one on a socket that closed first, or one
  whose write failed. The report now travels with the queued frame, and the
  socket emits it after a successful write.
- On a raw-TSP socket a live push was reported twice: once when queued,
  and again by the inbox drain that wrote it. Only the drain reports it now.

### Fixed — `attached` events for attaches and narrowed grants

Spec event rule 5 says a mediator emits `attached` whenever a member joins
or its scope or expiry changes. Three gaps:

- A DID admitted by `messaging/mux/attach` got no `attached` event, only the
  task response, so a client keeping its member set from events never saw
  it. It now gets one, with reason `attach`.
- Narrowing a grant (`messaging/mux/update`, here or relayed from another
  instance) changed the member's scope and expiry silently. It is now
  reported in an `attached` event with reason `grant`.
- A member joining while connected was always reported
  `deliveryActive: true`, and was labelled `grant` even when it came by
  attach. `deliveryActive` now says whether the member's live traffic comes
  over this connection: `false` while the DID's own socket, or a newer
  connection, holds it, until an `attached` with reason `reactivated`.

**Behaviour change (R3.6):** principals may now see `attached` events where
there were none, and a `grant` join with `deliveryActive: false`. Clients
built on affinidi-messaging-sdk 0.45.5 fold them into `mux_members()`.

### Fixed — global sent counters on Redis

- On the Redis backend, fetching a message by id never counted it in the
  global `SENT_COUNT`/`SENT_BYTES` stats: the `HINCRBY` for `SENT_COUNT`
  had no key, so Redis refused the whole `MULTI`. Both counters now move,
  and the store conformance suite checks it.

### Fixed — resync status honours the `pickup` scope

- On a DIDComm mux connection, a member whose live pushes dropped was sent
  a pickup `status` for its inbox even when its scope lacked `pickup`,
  telling the principal that inbox's counts. A status is message pickup, so
  it is now sent only for a member holding `pickup`. A `receive`-only
  member's dropped frames stay in its inbox, as before. The `tsp-mux` drain
  already skipped such members.

### Fixed — DID multiplexing

- The `muxNonce` in a mux connection's `ready` event is now 32 random bytes
  as unpadded base64url (43 characters), as `messaging/mux/event/0.1`
  requires. It was 32 alphanumeric characters, which a client parsing the
  event with the generated bindings refused. The end-to-end test now checks
  every mux event against the spec's generated type.
- `DELETE /delete` on a mux connection's session now deletes a member's
  messages when the member's grant or attach includes `delete`, as
  `messages-received` already did. The SDK acknowledges live-stream messages
  this way (`auto_delete`), so before this a principal could receive a
  member's message but never acknowledge it, and it was redelivered.
- A grant stored while its principal is connected is carried on that
  connection at once, with an `attached` event, as the design requires.
  Before, the mediator admitted grants only when the connection opened, so a
  device that granted a new DID had to reconnect before that DID's messages
  arrived. A grant that replaces an earlier one takes over its member, so
  revoking the new grant detaches it.
  The mediator re-reads the member's record before and after it carries a
  grant, without holding the connection's lock across the read, and never
  lets an older grant displace a newer one. So a grant replaced or revoked
  in the meantime, or two grants finishing out of order, cannot leave the
  connection on the wrong scope. A grant the connection has no room for is
  logged at `warn` and carried on the next connection.

### Fixed — `blocked_forwarding_dids` and `limits.to_keys_per_recipient` take effect

- A DIDComm forward or TSP relay whose relay endpoint, relay DID or next hop
  is on `processors.forwarding.blocked_forwarding` is refused instead of
  queued: DIDComm answers `delivery_refused`, TSP error 94. The list holds
  this mediator's own DID and published endpoints, plus each DID in
  `blocked_forwarding_dids` and its endpoints. Both settings were loaded at
  startup but never consulted. Entries and candidates are compared in one
  canonical form, so another spelling of a listed DID or URL is refused too:
  a DID matches with any case of `did:` and its method, and with a query or
  fragment; a URL matches with any case of scheme and host, its default
  port, a trailing dot on the host, a fragment, or an internationalised
  host in either its Unicode or punycode form.
- A reply is not packed for a recipient that publishes more key-agreement
  keys than `limits.to_keys_per_recipient` (default 100); the sender gets
  `message.pack` (47). The recipient lookup this uses replaces one whose
  result was discarded.

**Behaviour change (R3.6):** a forward addressed to this mediator's own
published endpoint, when that endpoint is not covered by `local_endpoints`,
is now refused instead of relayed back to this mediator (where it used to
travel round until `max_hops`). Declare public aliases in `local_endpoints`
to have them delivered locally.

### Fixed — a Redis session read back after login is marked authenticated

- The Redis store's `get_session` set a session's state but never its
  `authenticated` flag, which Fjall and memory store. Every session on
  Redis was therefore handled as unauthenticated: session / sender matching
  under `security.force_session_did_match` was skipped for forwards and
  direct deliveries, and an authenticated session's routed TSP frames went
  through the relay checks meant for the anonymous relay session. The flag
  now follows the stored state (`Authenticated`). The store conformance test
  checks it after login on every backend.

**Behaviour change (R3.6):** on Redis, `force_session_did_match` (default
on) now applies as documented: a client that authenticated as one DID and
sends forwards or direct deliveries as another is refused, as it already
was on Fjall and memory.

### Fixed — a challenge session is promoted once

- On Fjall, memory and the trait default, `update_session_authenticated`
  now fails unless the challenge session exists, has not expired and is
  still waiting for its answer (`ChallengeSent`); it used to promote a fresh
  session in place of a missing one. Of two answers to one challenge, only
  the first is accepted, as on Redis. The memory store promotes under its
  state lock.
- Redis `update_refresh_token_hash` fails for a session that has ended
  instead of recreating it as a hash with no expiry.

### Fixed — the access-list limit holds on Redis

- `access_list_add` on Redis now counts, truncates and adds in one script.
  When a request does not fit, the first `limit - current` hashes are added
  and `truncated` is set, as on Fjall and memory. A list already at its limit
  takes nothing; before, a request made when the list was exactly full was
  added in full, and one made over a lowered limit could fail or add
  everything. An empty request is a no-op instead of a Redis error. A
  request longer than the limit sends only its first `limit` hashes to
  Redis, and is reported truncated.

### Fixed — TSP empty-route delivery uses the hop's verified sender

- When a routed TSP message addressed to the mediator has no hops left, the
  mediator now applies the recipient's access list against the sender that
  `unpack` verified for that hop, as the last-hop and nested arms already do.
  It previously used the sender named in the clear by the inner message's
  envelope. The inner envelope is now read only for its receiver, and an
  inner that does not parse is refused with `message.tsp.malformed`.
  `affinidi-tsp` 0.3 decodes an empty route as `Nested`, so no message takes
  this path today; unit tests pin the decision so that a decoder change does
  not alter it.
- `deliver_tsp_local` takes the sender from its caller instead of reading it
  from the bytes it stores (unchanged for existing callers).

### Fixed — a WebSocket client that has gone away is closed within a set time

- The mediator already pinged every WebSocket every 30 s but ignored the
  answer, so a client that vanished without closing (lost network, suspended
  device) kept its connection, slots and queued frames until TCP gave up,
  which can take many minutes. Now, once a ping goes unanswered, the client
  has `limits.ws_pong_timeout_secs` (new, default 90) minus the ping interval
  to send any frame, a pong included. Otherwise the socket is closed with 1001
  "connection unresponsive", within `ws_pong_timeout_secs` of the client's
  last frame. Time the mediator spends not reading (a large flush on connect,
  a slow message) does not count against the client. Its slots and
  live-delivery registration are released as on any other close. Counted in
  the new `ws_pong_timeouts_total`.
- Only complete frames count, so `ws_pong_timeout_secs -
  ws_ping_interval_secs` must cover the slowest single inbound frame upload.
- The ping interval and the write bound are now settings:
  `limits.ws_ping_interval_secs` (new, default 30) and
  `limits.ws_write_timeout_secs` (new, default 30, the value that was
  fixed). Env: `LIMIT_WS_PING_INTERVAL_SECS`, `LIMIT_WS_PONG_TIMEOUT_SECS`,
  `LIMIT_WS_WRITE_TIMEOUT_SECS`. The pong timeout is raised to at least two
  ping intervals, and each value to at least 1 s, with a warning, whether
  the values come from the file or are set in code.
- `TestMediatorBuilder::websocket_liveness(ping, pong, write)` sets all
  three for tests.
- Documented: on the plain `tsp` subprotocol a message is deleted once its
  frame is written to the connection, so a client that goes away can lose
  frames written shortly before the close. Use `tsp-ack` for at-least-once
  delivery.

**Behaviour change (R3.6):** a client that sends the mediator nothing for
90 s, not even a pong, is disconnected. A client answers pings only while it
reads its socket, so it must keep reading to stay connected. A TSP stream
must be read continuously: the TDK `TspStream` answers pings only while the
application is inside `recv()`. DIDComm clients of the TDK SDK read
continuously and send their own keepalive, so they are not affected.

### Fixed — a session error over HTTP returns a fixed message

- **Behaviour change (R3.6):** an HTTP `SessionError` response (status 406)
  now carries the message "Session could not be established or found"
  instead of the error's own text, which could include a storage backend's
  error message. The status, `errorCode` and `errorCodeStr` are unchanged;
  the full text is logged at WARN.

### Fixed — the answer to `messaging/mux/ack` on a DIDComm mux connection is not stored

On a `didcomm-mux` connection the answer to `messaging/mux/ack` was stored in
the principal's inbox like any other Trust Task reply. A stored answer needs
acknowledging in turn, and so does the answer to that (spec, consumer rule 4).
It now goes to the connection only, as it already did on `tsp-mux`. When the
connection drops before the answer arrives, the client asks again: acking is
idempotent.

Clients: affinidi-messaging-sdk 0.45.13 sends background deletes on a
`didcomm-mux` connection as `messaging/mux/ack` on the socket, and does not
delete the answer. It needs this change.

### Fixed — the same bytes stored for two recipients get a record each

- A stored message is now held per recipient. The same bytes stored for two
  recipients — one multi-recipient message forwarded to two local
  recipients is the usual case — get a record each, with their own sender,
  queue entries, counters and expiry. Previously the second store replaced
  the first recipient's record: its inbox entry was left with nothing
  behind it, its delete was refused, fair pickup skipped it, and once the
  second recipient deleted its copy the first recipient's queue counters
  and the sender's per-peer count never came down. Storing the same bytes
  again for the **same** recipient is still one record, counted once.
- The message id clients see is unchanged: `sha256(body)`. SDKs that derive
  ids from bodies keep working, and nothing on the wire changes.
- How an id is resolved, now that it can name several records:
  - an acknowledgement removes the acknowledging recipient's own copy only,
    never a copy of the same bytes held for someone else: message-pickup
    `messages-received`, TSP delete-on-send over the websocket, DIDComm v1
    `messages-received`, fetch with delete, and live-delivery deletes;
  - when a session holds several copies of an id — a mux principal and a
    member that both received the same bytes — an acknowledgement removes
    the copy that was handed over first, then follows session order;
  - `DELETE /delete` and `/outbound` with delete remove the copy held for
    the session's own DID or, on a mux connection, for a member it may
    delete for. Only when no such copy exists do they withdraw what the
    caller sent (every copy under that id), and not even then when an
    owner on the session already acknowledged its own copy of that id: that
    is a repeated acknowledgement (a redelivered message deleted twice) and
    answers `not_found`. An acknowledgement is remembered per recipient
    until that copy would have expired (7 days for a copy with no recorded
    expiry); a copy removed by expiry, an administrator or its sender is
    not an acknowledgement;
  - `messaging/message/delete` (self or admin) acts on the target account's
    queues: its own copy, else every copy it sent; an admin never removes a
    copy held for another account that the target did not send. Queue
    purge and account removal remove the queue's own copies only;
  - `messaging/message/status` answers for all of the sender's copies (see
    receipts below); `messaging/message/get` and `/outbound` read the
    caller's own copy, else one copy it sent;
  - the expiry sweep, delivery stamps (`mark_delivered`, delivered-TTL) and
    the admin message list act on one recipient's copy.
- Outbox receipts are kept per recipient. Status answers, over every copy:
  `withdrawn`/`discarded` (the latest) when any copy was removed without
  being collected, else `queued` while any copy waits for its first
  handover, else `delivered` (latest first handover) while copies are held,
  else `collected` (latest). It never answers `delivered` or `collected`
  while a copy was discarded or withdrawn.
- A `deleted` monitor event is emitted for each copy a delete removes.
- Anything that is not a message id (64 lowercase hex) names no message and
  is answered as not found, before any storage is addressed.
- The expiry sweep removes a record only when the index entry is at or after
  the record's current expiry. An entry left by an earlier copy of the same
  bytes for the same recipient, or by a deadline that delivered-TTL brought
  forward, is dropped instead of removing a later copy early.
- Redis `purge_folder` no longer stops at an inbox or outbox entry whose
  message is already gone; it drops the entry and carries on.
- Storage layout:
  - Redis: `MSG:<id>:<to>` (body) and `MSG:META:<id>:<to>` (metadata, now
    with `EXPIRES_AT`), plus `MSG:RCPT:<id>`, the set of recipients holding
    a copy. Expiry buckets hold `<id>:<to>`; in cluster mode the queue-id
    hashes are keyed the same way. Every key of one id stays in that id's
    cluster slot. Receipts are a hash per sender and id,
    `RECEIPTS:<from>:<id>` (recipient → receipt); acknowledgements are
    `ACKED:<to>:<id>`, expiring with the copy. `atm-functions.lua`
    changes (`store_message`, `delete_message`, `fetch_messages`); delivery
    stamping moved to a script outside the library, which no longer
    recreates the metadata of a message deleted in between.
  - Fjall: `messages` rows are keyed `{id}:{to}`; expiry entries name the
    row; receipt keys end in `:<to>`; acknowledgements are kept in the
    receipts keyspace under an `ACK` prefix and pruned with the receipts.
  - Memory: records are keyed by `(id, to)`; receipts and acknowledgements
    per recipient.
- Existing data needs no migration. Records stored under the old per-id keys
  (Redis `MSG:<id>` / `MSG:META:<id>`, a Fjall row keyed by the bare id) stay
  readable, deletable, counted and expirable: an operation for a recipient
  falls back to the old record when its `TO` is that recipient, the sweeper
  resolves a bare-id expiry entry through it (every expiry entry of an old
  record is due, as before, since its delivered deadline was never recorded
  on it), and storing the same bytes again for that recipient is still a
  no-op. Old single receipts (Redis `RECEIPT:<from>:<id>`, an unsuffixed
  Fjall receipt key) are still read, for an unknown recipient. Nothing
  writes the old layout any more, so the fallback can be removed once no old
  key remains: after the longest message expiry configured at the upgrade
  (`limits.message_expiry_seconds`, and 24 hours for receipts) has passed,
  and a scan (`SCAN MATCH 'MSG:META:*'` for keys with no `:` after the id;
  Fjall `messages` keys with no `:`) finds none.
- **Behaviour change (R3.6):**
  - A delete by id that finds nothing in the caller's own queues answers
    `database.message.delete.not_found`, also when another account holds a
    copy under the same id, or when the caller is not a party at all. A
    non-party deleting an existing message used to get
    `database.message.delete.permission_denied`. Clients already treat
    `not_found` as "already gone", which is now true from their side.
  - Acknowledgement paths never withdraw: a recipient that also sent the
    same bytes to someone else releases only its own copy.
  - `DELETE /delete` semantics, per id: the session's own copy (or a mux
    member's it may delete for; a delivered copy first) is acknowledged; if
    there is none, a repeat of an earlier acknowledgement by an owner on
    the session answers `not_found`; otherwise every copy the caller sent
    under that id is withdrawn. One request cannot be read both ways: a DID
    that sent the same bytes to itself and to someone else, acknowledged
    its own copy and then deletes the id again is answered as a repeated
    acknowledgement and withdraws nothing. `messaging/message/delete` or
    an outbox purge withdraws it explicitly; `messaging/message/delete`
    withdraws without the repeat check.
  - `messaging/message/status` can answer `withdrawn`/`discarded` for an id
    whose other copies are still held or were collected.
  - Store trait (`affinidi-messaging-mediator-common`):
    `delete_message_in(id, MessageScope, by)` is new, returns the removed
    copies, and is what backends implement; `delete_message(id, by)` is a
    provided method over it, and an owner's id-only delete removes its own
    copy only (withdrawal is `MessageScope::Party`). `mark_delivered`,
    `delivery_state` and `get_message_metadata` take the recipient;
    `delivery_states` takes `MessageRef`s; `outbox_receipts` and
    `acknowledged` are new;
    `ops::sent_message_state` takes every held copy and every receipt.
- **Deploying this release.** Instances of this release and of an earlier
  one must not run against the same database at the same time:
  1. stop **every** mediator instance sharing the database (all replicas, in
     every deployment that points at it);
  2. deploy this release everywhere;
  3. start the new instances. Do not start an instance of an earlier release
     against the database afterwards.

  Why: on single-node Redis the function library is per server and each
  instance loads its own at start, replacing it for every instance. An
  earlier build reads only the old per-id records, so it does not see
  messages a new instance stored, and a new instance running the earlier
  library cannot delete. As a safety net, a new instance that finds the
  earlier library loaded (its `delete_message` refuses the new arguments,
  or `fetch_messages` rows lack the layout marker) logs an error and loads
  its own library again, and the new library answers an earlier build's
  `delete_message` call the way it used to (`OK`): a bare id from the
  earlier build's admin reaches only an old-layout record, and an expiry
  bucket member it passes (`<id>:<to>`) removes that recipient's record
  only once its expiry has passed. A new instance whose `store_message` is
  answered by the earlier library (`OK` rather than `STORED`) keeps the
  message, which that library stored in the old layout this release still
  reads, and loads its own library again. That limits the damage of
  a missed instance; it does not make running both supported, since the two
  keep replacing each other's library. In cluster mode (ElastiCache
  Serverless) there is no shared library — each call carries its script —
  but the two builds still disagree about where a message is stored, so the
  same stop-everything-first order applies. Fjall and the in-memory store
  are single-process.

### Fixed — on a `tsp-mux` socket, one member's backlog no longer holds back another member's live frames

On raw TSP, the resync for a member whose live pushes were dropped is a drain
of that member's inbox. The socket loop ran that drain to completion, up to
1000 frames, while other members' live frames waited behind it. A flood to one
member delayed every other member on the connection, against design §10
("one member floods, others still get live frames within bound").

The drain now stops between pages whenever live frames are waiting, writes
them first, and picks up where it left off (from the head of each member's
inbox, skipping frames already on the wire) as soon as the queue is empty.
Frames are still delivered once each and acknowledged as before. DIDComm mux
connections, where a resync is a pickup `status`, and plain `tsp`/`tsp-ack`
sockets are unchanged.

### Fixed — a renewed monitor subscription keeps its filter

- The console renewed its monitor lease without the filter. A renewal
  re-filters, so after the first renewal (about four minutes in) an
  administrator's narrowed feed widened to all traffic. Renewals now send the
  filters in force.

### Fixed — the crates require the SDK release whose APIs they use

- `affinidi-messaging-mediator`, `-admin`, `-tui` and `-test-mediator` now
  require `affinidi-messaging-sdk` 0.45.17 rather than any 0.45.x. They use
  the mux admin, socket-ack and monitor subscribe 0.2 APIs added in
  0.45.13–0.45.17, so a downstream lockfile still on an older 0.45 patch
  failed to compile inside these crates instead of being upgraded by cargo.

### Fixed — a re-sent notice for a grant an administrator voided says `admin`

- A grant voided by an epoch advance now records who advanced the epoch
  (`voidedBy`: `member` or `admin`) on its stored record. When the
  `grantsRevoked` notice for an `admin-revoke-all` was lost to a crash
  between the commit and the notice, the copy re-sent when the principal
  next connects now carries reason `admin`, as the live one did, instead of
  `epochBumped`. A member's own `revoke-all` is still re-sent as
  `epochBumped`.
- A detach decided from the stored record alone (a resync, the periodic
  re-check, or a change record from an instance without the reason hint)
  also reports `admin` for such a grant.
- The field is optional and omitted when unset: records stored before it, or
  written by an older instance during a rolling deploy, read as the member's
  (`epochBumped`, the previous behaviour), and older instances ignore it. No
  wire type changes.

### Fixed — `limits.max_websocket_connections = 0` means unlimited

A value of `0` is documented as "unlimited", but refused every WebSocket with
1013 "server connection limit reached". It now admits every socket, as the
per-DID cap already did for its `0`. A deployment that set `0` and relied on
it to turn WebSockets off now accepts them.

### Fixed — inbox redelivery is paced to the socket, and raw-TSP sockets get one wake-up

- The redelivery that runs when live delivery turns on, or a socket replaces
  another, now waits for room in the socket's queue (up to 10 seconds per
  frame) instead of stopping at the first full queue. Before, it queued about
  8 messages and then stopped with a resync, so paging and the 1000-message
  cap never took effect. Each message is still recorded as delivered only
  once its frame is written (R1.1).
- A raw-TSP socket, which drains its whole inbox itself on any notification,
  is redelivered to with one wake-up instead of a push per stored message
  (each of which only triggered another drain).
- A repeated live-delivery `Start` for a socket that is already live no
  longer drains the inbox again.

### Fixed — a socket that replaces another gets the redelivery already running for it

The guard that keeps one redelivery per DID skipped the replacing socket's
redelivery while the replaced socket's was still running, so the new socket
got neither the stranded messages nor a resync. A running redelivery now
hands itself over to the newest socket for the DID and starts the inbox again
for it.

### Fixed — a lagged streaming subscription raises every live client's resync

When the streaming task's notification subscription fell behind, the skipped
live notifications were logged and dropped, and no client was told that mail
was waiting (R6.2). Every live client (and each live member of a mux
connection) now has its resync raised, rate-limited by the usual 5-second
floor. New counter `ws_streaming_lagged_total`.

### Fixed — mux member registration is idempotent, and a grant that gains `receive` starts live delivery

- Renewing an attach for a member the connection already carries no longer
  registers it again. Before, the streaming task treated it as a newer
  connection: the client got a spurious `detached: superseded` for a member it
  still carried, `deliveryActive` could read `false` for a live member, an
  extra redelivery ran, and a standby entry was left behind that later
  stopped the real entry from being removed.
- A member carried by a grant without `receive` or `pickup` that is replaced
  by one with either now starts live delivery at once, rather than at the next
  reconnect. A member narrowed to neither has live delivery turned off.

### Fixed — a restart of the streaming task keeps its registered sockets

The registered sockets were held by the streaming task's run, so a
supervised restart forgot every one. A direct socket noticed and reconnected,
but a mux connection stayed up and silently received nothing for its
principal or any member. The registrations now outlive a restart: the
restarted task claims each back and redelivers what arrived while it was
down.

### Fixed — mux member-change events are never dropped

`superseded`, `inactive` and `reactivated` member changes were queued to the
connection without waiting and silently lost when its queue was full (a burst
of members changing at once), leaving `deliveryActive` and the inactive count
wrong. They are now recorded on the connection and the socket woken, so none
is lost and they are reported in order.

### Fixed — the Redis circuit breaker follows real command failures

- The breaker counted handing out a connection, which cannot fail, as a
  success, so it never opened on the request path. Every command sent over
  the store's connection now reports to it: a connection error or timeout as
  a failure, any reply as a success. A half-open probe that never reports
  (its task was cancelled) no longer leaves the breaker refusing every
  request until restart.
- `[database] circuit_breaker_threshold` (default 5) and
  `circuit_breaker_recovery_secs` (default 10) are now settings
  (`DATABASE_CIRCUIT_BREAKER_THRESHOLD`,
  `DATABASE_CIRCUIT_BREAKER_RECOVERY_SECS`); they were hard-coded.

### Fixed — Redis forward queue

- Ack and delete of a finished forward are one `MULTI` on Redis, as on Fjall,
  so a crash between them cannot strand an entry in `FORWARD_Q`.
- Each forwarding consumer keeps one blocking connection, reopened after an
  error, instead of opening a connection per read, and the consumer group is
  created once (again only on `NOGROUP`) rather than before every read.
- The reclaim sweep removes consumers of earlier processor runs once they
  hold nothing and have been idle an hour (`XGROUP DELCONSUMER`; new trait
  method `forward_queue_prune_consumers`). The conformance suite now checks
  that a delayed forward read and left pending by one consumer is reclaimed,
  with its delay, and finished by another.

### Fixed — Redis message storage

- `store_message` adds its queue entries before anything else and lets Redis
  choose the stream id (`*`), so a clock that steps back (a failover to a
  replica that is behind, an NTP step) no longer fails stores, and a refused
  store no longer leaves counters, a body or an expiry entry behind.
- Deleting a removed account's sent messages no longer recreates its
  `DID:` record as a ghost account with negative counters.
- `account_add` with a queue limit sets the send and receive limits on Redis,
  as on Fjall and memory (it wrote a field nothing read).
- A delivered message's expiry entry is moved to its new deadline, not
  duplicated; the sweeper deletes each bucket's messages together and
  unlists a bucket only while it is empty, so a message stored into it
  meanwhile keeps its expiry; and message bodies and metadata carry a
  backstop expiry a day past the message's own.
- `clean_start_streaming` runs until every registration of the previous run
  is cleared, not just the first 500.

### Fixed — TSP Trust Task answers are the mediator's own messages

- A Trust Task answered over TSP is stored as the mediator's message, as the
  DIDComm path stores its replies: no queue or access-list gate after the
  task has run, and not counted against the requester's own queues. The
  requester must still hold an account.
- A relayed TSP message is stored, gated and counted as sent by its verified
  sender (`from_vid`), not by the relaying session.

### Fixed — Bounded work and audited partial outcomes in admin tasks

- `messaging/acl/get` reads all requested ACLs in one batch and refuses more
  than 100 DIDs (the pinned schema has no `maxItems`; the bound is enforced
  in code until the spec adds one).
- `messaging/message/list` scans in fixed chunks of 500 whatever `limit` is,
  and a store error reading delivery state is returned instead of the
  state being silently left out.
- `messaging/message/delete` reports a per-id store failure as
  `deleted: false` (the ids are named under
  `ext["com.affinidi.mediator"].failed`) and carries on, so deletes already
  done are reported and audited; the audit record says `outcome partial`.
- `messaging/queue/purge`, `account/update` and `access-list/update` audit
  an `outcome partial` record when a store failure stops them after part of
  the work was applied.

### Fixed — stored `config/patch` overrides that tighten both keys of a pair no longer revert on restart

Overrides were laid one key at a time in alphabetical order, so with both keys
of a soft/hard pair lowered the `…_hard` key was checked against the baseline
`…_soft`, failed, and was dropped with only a warning — the tightened hard
limit reverted on the next start or reload. All overrides are now laid first
and the soft ≤ hard rule checked once over the result; a pair still out of
order returns to its configured values. A single `config/patch` may lower both
keys together in any order; a patch key (or a reset) that would leave its pair
out of order is refused and the stored value kept. A configured limit below a
key's patch floor is no longer read as unlimited, so a patch cannot raise it.

### Fixed — a self-hosted did:webvh log with more than one entry starts

`server.did_web_self_hosted` read a `file://` log line by line and joined the
lines with nothing between them, so after the DID's first update the mediator
refused to start. The source is now read exactly as stored; a log is parsed
one entry per line and its chain verified with didwebvh-rs (each entry's proof,
`versionId` and parameters against the one before; witness proofs are not
checked), `/.well-known/did.json` serves the last entry's document and
`/.well-known/did.jsonl` the log byte for byte. A log that deactivates the DID
is refused. A relative `file://` path is now resolved against the config
file's directory, like `functions_file` and the TLS paths (part of #176).

### Fixed — `mediator rotate-admin` uses the server's configuration loader

The command read `[secrets] backend` from the TOML by hand and ignored
`MEDIATOR_SECRETS_BACKEND`, so in an env-configured deployment it rotated the
credential in a different store from the one the mediator uses. It now loads
the configuration through the server's loader and environment overlay.
`--dry-run` no longer mints and prints a throwaway DID, and its messages and
the module docs now describe what the command does.

Also fixed: the DID resolver's built-in network timeout is 5000 ms (it was 5,
read as milliseconds).

### Fixed — request metrics and access logs

- A request whose client disconnects mid-flight no longer leaves
  `http_requests_in_flight` one higher for good. It is counted in
  `http_requests_total` with `status="cancelled"` and logged as cancelled.
- Each request is logged once, at INFO, by the `http_access` line. The
  `TraceLayer` still opens a span per request, so handler logs carry the
  method, path and request id, but it no longer logs its own lines.
- Query strings are no longer logged. The request span records the path
  only, so an OOB invitation id (`/oob?_oobid=`) stays out of the logs.
- An inbound `x-request-id` is reused only if it is 1 to 128 characters of
  ASCII letters, digits, `-`, `_`, `.` or `:`. Anything else is replaced with
  a fresh UUID before it is logged or echoed back.
- Client DIDs in the authentication and REST handler logs are logged as
  hashes (`did_hash`), never raw. A message fetched over `/outbound` is no
  longer logged whole at DEBUG; its id and size are.

### Fixed — peer mediator responses are bounded and escaped before logging

- When a next-hop mediator refuses a forward, at most 2 KB of its response
  body is read, and control and bidirectional-formatting characters in it are
  escaped, before it goes into the logged and reported failure reason. A
  relay-ack `reason` gets the same treatment. Before, the whole body was
  buffered and logged verbatim, so a hostile endpoint could fill memory or
  forge log lines.

### Fixed — the standalone processors

- The standalone `forwarding_processor` refuses to start with
  `report_errors = true`: it has no keys to pack the failure reports with, so
  it silently reported nothing. The shipped `conf/forwarding.toml` now sets
  `report_errors = false` and also has the settings it was missing
  (`future_time_limit` and others), without which it did not parse at all.
- Both standalone processors return config file errors instead of panicking,
  and stop cleanly on SIGINT or SIGTERM.
- A live-delivery notification for a DID no socket on this instance holds is
  logged at DEBUG instead of WARN. The stale streaming claim behind it is
  released, so later messages stop being routed to this instance.

### Fixed — `file://` secret stores are never truncated or replaced on a failed read

- Both `file://` backends write a temp file (`0600`), `fsync` it, rename it
  over the store and `fsync` the directory. A crash, `SIGKILL` or `ENOSPC`
  mid-write leaves the previous store, never a truncated one.
- A plaintext store file that exists but can't be read or parsed now fails a
  `put` or `delete`. It used to be replaced by a store holding only the entry
  being written, losing the admin credential, JWT key and operating keys.
- A write that fails leaves the in-memory copy as it was.

### Fixed — secret backends no longer block async workers or rebuild clients

- The encrypted store's Argon2id KDF, all `file://` I/O, the OS keyring calls
  and the Vault Kubernetes-auth JWT read run on tokio's blocking pool. The
  mediator opens its backend with the new `open_store_async` /
  `MediatorSecrets::from_url_async`.
- The AWS Secrets Manager and Kubernetes backends build their client once and
  reuse it, instead of re-running the credential chain (an STS or IMDS round
  trip on IRSA / ECS roles) and opening a new connection pool on every call.

### Fixed — Vault re-logs in only when the token is actually refused

- A `403` re-authenticates (Kubernetes / AppRole) only when
  `auth/token/lookup-self` also refuses the token; a policy denial is
  returned as is. Each write with a policy lacking `update` on the destroy
  path used to cost a re-login (a new token and lease, and an AppRole
  `secret_id` use) and two refused destroys.
- After the first refused destroy of superseded versions, later writes skip
  the destroy until the mediator restarts.

### Fixed — mediator-setup: safer, recoverable provisioning

- The did:webvh update key and pre-rotation key of a locally generated DID
  are stored in the secret backend (`mediator_webvh_update_keys`), and the
  first log entry commits to the *hash* of the next key, so the DID can be
  updated.
- Sealed handoff phase 2 keeps the ephemeral seed until the whole setup is
  written, so a failure can be retried with the same bundle. `did.jsonl` is
  written before `mediator.toml` and its failure is fatal. Every file is
  written to a temporary name, fsynced and renamed; key-bearing files are
  `0600` even when replacing a looser file, symlinked targets are refused,
  and directories the wizard creates are `0700`. The `mediator.toml` being
  replaced is backed up as `mediator.toml.bak.<UTC timestamp>` in every
  flow. Publishing to `did_target` / `did_log_target` runs last.
- `--setup-key-file` now finishes the setup: it builds the admin-only VTA
  session from the phase-1 key, provisions the mediator (`--did-method`,
  other flags, `--set` or `--from`), stores the setup did:key — the
  long-term VTA credential — in the secret backend and deletes the key file.
- The admin private key is no longer printed; `--show-admin-key` prints it
  on a terminal only. `--uninstall` removes every file the setup wrote,
  from a manifest kept next to the config.
- `did_web_self_hosted` names the `did.jsonl` actually written (its
  in-container path for container deployments) instead of
  `file://./conf/did.jsonl`. Kubernetes Secrets setups emit the
  `secrets-k8s` build feature.
- Container output: `Dockerfile`, `Dockerfile.dockerignore` and
  `docker-compose.yml` are written next to `mediator.toml` (never over a
  different existing file, and never the repository's `.dockerignore`); the
  image holds only the binary, and the config directory with the keys is
  mounted rather than copied into a layer.
- The TUI checks the secret backend when the Key Storage step completes,
  stores a VTA session's credential as soon as it connects, asks before
  quitting once a session exists, stops a provision flight on Esc, and
  saves the answers as a resume recipe when the final step fails. Option
  lists, Enter handling and default highlights come from one table per
  step; re-editing an SSL certificate path no longer overwrites the key
  path; going back to the VTA step discards the old session with a warning;
  rejected inputs say why. A panic restores the terminal, small terminals
  get a "too small" screen, `NO_COLOR` and non-terminal output drop the
  colour codes, and the help bar lists the keys that work.

### Fixed — console: background answers land where they were asked for

- Every screen request is tagged with what it was asked for: the account and
  queue, the ranking, the grant query. An answer that arrives after the user
  moved on is dropped, so a slow answer for one account no longer shows on
  another's screen or feeds `e`. A purge count or inspect result for an
  account the user has left is dropped, not shown.
- A screen sends one request per kind at a time, so a slow or unreachable
  mediator no longer gets a new batch every 5 s.
- The selection stays on the same message, account, queue or key across
  refreshes, not on the same row number.
- The delete and purge confirmations name the account and queue. The delete
  confirmation also names the message id, sender and recipient.

### Fixed — console: connection state, audit, paging, colour and copy

- The header shows `● connected`, `◌ connecting` or
  `✗ disconnected Ns — reconnecting` from the SDK's connection signal. The
  monitor writes a line on each drop and recovery, and its title says
  `✗ connection down` at once instead of `● live` for up to 45 s. The screen
  reloads when the connection returns.
- Audit scrolls, pages through `nextCursor` and adds an outcome column. It
  reads the `audit/list` 0.2 fields (`recordedAt`, `actor`, `action`,
  `target`, `outcome`) rather than guessing, and shows `detail` as
  `key=value`.
- The Account, Queues and Accounts lists say how much is shown
  (`200 of 5000 (] more)`) and page on demand, instead of cutting off at 200
  without saying so.
- Accounts loads a page at a time as the list is scrolled, and reloads every
  five minutes or on `r`. Before, it re-read every account every 5 s. The
  queue ranking is asked for again only once a newer survey is due. Monitor
  traffic redraws at most ten times a second.
- `NO_COLOR` now turns colour off on every screen, not just the quota bars.
  Badges and highlights are shown reversed instead.
- The inspect popup scrolls and shows the whole envelope (it was cut at 2,000
  characters). `y` copies the message and `w` writes it to a file.
- A long non-ASCII DID no longer panics the console when shortened.
- Pasted text has control characters removed in every field.
- The `mediator-console` binary turns bracketed paste off when it panics, as
  well as on a normal exit.

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

### Fixed — `account/update` and `access-list/update` apply atomically

- `messaging/account/update` wrote the ACL, the queue limits and the role in
  up to four store calls, and `messaging/access-list/update` cleared, added
  and removed in up to three, so a store failure part-way left a partial
  update in place (audited as `outcome partial`). Each is now one store
  operation on every backend: one Lua script on Redis, one batch on Fjall,
  one locked change in memory. A failure leaves the account or list as it
  was, and no reader sees a list cleared and not yet refilled. With Redis
  cluster mode on, the global `ADMINS` set is a separate step, written before
  a promotion and after a demotion; `ROLE_TYPE`, which alone grants admin
  rights, is always in the atomic step.
- `access-list/update` reports a hash listed twice in `remove` once, and its
  `accessListCount` is the count the update left, not a second read.

### Fixed — the Redis store reports its circuit breaker

- `RedisStore` inherited the trait's `circuit_breaker_state` default, which
  always answered `closed`, so `/readyz` never failed its
  `redis_circuit_breaker` check and the store's `health()` always said
  healthy, even with the breaker open. It now reports the breaker's state.
  **Behaviour change (R6.2):** while the breaker is open, `/readyz` answers
  503 `not_ready` until a request (the readiness probe's storage check is
  one) finds Redis back.
- The in-memory store's forward-queue ack-and-delete is one step under its
  lock instead of an ack followed by a delete.

### Fixed — documentation that contradicted the code

- The mediator README no longer says a TSP-only build has no authentication
  path (it authenticates with `POST /tsp/authenticate`), pins Redis to a
  supported major instead of `redis:latest`, and states the working directory
  the wizard and the mediator need. The root README's embedding snippet no
  longer names an end-of-life version.
- The configuration template's DID multiplexing notes no longer cite an
  unpublished design document, and describe how a revoke reaches other
  instances as the code does it.
- `NOTICE.txt` describes this repository, not crates that live in
  affinidi-tdk-rs; issue references from affinidi-tdk-rs are written
  `affinidi-tdk-rs#NNN`.

### Fixed — the wake rate limiter has a hard size ceiling and sweeps at most once a minute

- The per-(requester, addressee) wake counters are capped at 100,000 entries; past that, the entry whose day window started first is dropped. A pair entry is only made by a ring that passed every earlier rule and spent the addressee's hourly budget, so live entries were already bounded by wake-capable accounts; the cap is a hard ceiling on top. Dropping an entry only resets one requester's budget for one addressee; the addressee's coalescing window and hourly budget still apply.
- Once the counters pass 10,000 entries, closed windows are swept at most once a minute instead of on every wake request, so a map full of live entries is not rescanned per request.

### Added — `messaging/mux/connections` and the console's Mux tab

- The mediator serves `messaging/mux/connections` 0.1
  (dtgwg-trust-tasks-tf#1083) to administrators. It lists this instance's
  live mux connections: each one's principal, wire (`didcomm`/`tsp`),
  opening time and exact member count. Within the page's member budget it
  also lists each connection's members, with source (grant or attach),
  scope, expiry and whether their live delivery is active there.
  - Filters: `principal`, `member`. Paging: `limit` (up to 100 connections)
    and `memberLimit` (up to 1000 member entries; a large connection is
    split across pages).
  - `coverage` is `allInstances` on an in-process store, and `thisInstance`
    on Redis, where other instances' connections are not visible.
  - A cursor is bound to the requester, the filters and the instance that
    issued it, and expires after 10 minutes. Anything else is refused with
    `messaging/mux/connections:cursorInvalid`.
  - Not served when mux is disabled.
- The operator console has a **Mux** tab. It lists the live connections,
  then the members of the selected one, with their delivery state, and its
  title says when the view covers this instance only.
- Needs affinidi-messaging-sdk 0.45.6 (`TrustTasksOps::mux_connections`).

### Added — `messaging/mux/ack`: acknowledge frames on the mux connection

A `tsp-mux` socket is delete-to-ack, and a client acked out of band, with a
REST delete. Only the connection knows its members and their scopes, so on a
multi-instance mediator a delete landing on an instance that does not hold
the connection was refused for every member's frame, and those frames were
redelivered for ever.

- The mediator serves `messaging/mux/ack` 0.1
  (trustoverip/dtgwg-trust-tasks-tf#1174). The principal sends it on its mux
  connection, naming up to 100 message ids. The answer lists `acked` and
  `refused` (`notFound` / `notPermitted`).
- **Authority:** the principal's own frames, and a member's while it holds
  `delete` and its account stands, as for a REST delete on the connection's
  session. Both now go through one function, so they cannot drift.
- **Privacy:** an id held for no one the connection may act for is
  `notFound`, whoever holds it: an id is a hash of the message, and the
  answer does not confirm another DID's mail. `notPermitted` is given only
  for a member whose mail the connection reads (`receive` or `pickup`); a
  member carried with neither (say, only `send`) gets `notFound`, so a
  principal cannot confirm that such a member still holds a message it sent.
- On `tsp-mux` the answer is pushed to the socket and not stored.
  Acknowledging is idempotent, and a stored answer would itself need
  acknowledging.
- A store failure fails the request, retryable, rather than reporting a frame
  as not found. Off a mux connection the request is refused
  (`messaging/mux:notMuxConnection`); a plain `tsp-ack` socket closes on it,
  as it does for any refused frame.
- REST deletes behave as before.

### Added — `TestMediatorBuilder::replica_of`

- A test mediator can run as a second instance of another: the same DID,
  keys and session-token key, on its own port with its own streaming task.
  Paired with a shared Redis store, that gives two instances of one
  mediator, as behind a load balancer. `tests/mux_two_instances.rs` uses
  it: a member grants, sends and revokes through one instance while the
  principal's mux socket is on the other. It found both bugs above, and
  runs in CI against standalone Redis and a Redis cluster.

### Added — DID multiplexing in `stats/show` and the console

- `messaging/stats/show` reports this instance's mux connections and
  members under the extension member `ext["com.affinidi.mux"]`:
  `connections`, `members`, `membersByGrant`, `membersByAttach`,
  `membersInactive`, with `scope: "instance"`, since another instance's
  connections are not counted. It is present only when mux is enabled. The
  spec's `connections` object is closed, so the counts go under `ext`.
- The console's dashboard shows them on one line, and its Audit tab
  highlights mux decisions (`mux_grant_suspend`, `mux_grant_revoke`,
  `mux_revoke_all`), each of which cut a device off from a DID.

### Added — DID multiplexing on raw-TSP sockets (`tsp-mux`)

- A raw-TSP WebSocket can now be a mux connection (spec
  `messaging/mux/event/0.1`, "Raw-TSP sockets"). The client offers `tsp`,
  `tsp-ack`, `tsp-mux` in that order. The mediator selects `tsp-mux` only in
  a TSP build with `limits.mux.enabled` on and a streaming task running.
  Otherwise it selects `tsp-ack` or `tsp` as before, so a mediator that will
  not multiplex never claims it will. A `tsp-mux` offer that is not selected
  is no longer echoed back. `tsp-mux` implies `tsp-ack`.
- On a `tsp-mux` socket the mux events (`ready` first, then `attached` for
  grants carried on connect, then `attached`/`detached` as members change)
  are signed `messaging/mux/event` documents. Each is sent as a TSP Direct
  message from the mediator's VID to the principal's, in a Binary frame. Mux
  Trust Tasks use the existing TSP Trust Task path, and their responses
  arrive through the principal's inbox. If `ready` cannot be sealed, the
  socket closes (1011) instead of running a mux connection the client
  cannot see.
- Members' live frames arrive untagged on the principal's socket. The
  client routes each one by the receiver VID in its envelope. A frame stays
  stored until it is acked.
- **In-band refusals.** On a `tsp-mux` socket a refused inbound frame no
  longer closes the socket. The mediator sends a `refused` event with
  `frameId` (lowercase hex SHA-256 of the frame's exact bytes) and `code`
  (the traffic monitor's refusal code). Where it can read them, it adds
  `sender`, `receiver` and `reason`. The socket still closes when the
  principal's token expires, when the principal's account is blocked, on a
  protocol violation (a Text or non-TSP frame), and when the event cannot
  be sealed. Plain `tsp` and `tsp-ack` still close on a refusal.
- **Inbox drain.** On connect, a `tsp-mux` drain empties the principal's
  inbox first. It then goes round-robin through the attached members with
  `pickup`, one bounded page per member per round. A resync drains the
  principal and only the members owed one (per-member resync, as on a
  DIDComm mux connection). The principal's own live notifications drain
  only the principal. Nothing is
  deleted on send. An ack (a delete by message id) is authorised against
  the owning member's `delete` scope, so a member without `delete` keeps
  its frames in its inbox.
- Membership is re-checked before each drain page and each live write, so
  a member detached part-way through a drain gets nothing more. Closing a
  `tsp-mux` socket tears down its mux connection. That now also happens
  when a mux socket closes during flush-on-connect or because its token had
  already expired.

### Added — DID multiplexing audit records

The `messaging/mux/*` specs require an audit record for each of these, and
the mediator wrote none. Each is now in the audit log (`audit/list`), with
the new actions from affinidi-messaging-mediator-types 0.1.1:

- `mux_grant_revoke`: one entry per grant `messaging/mux/revoke` removed.
  The actor is the party that revoked; the target is the other party.
- `mux_revoke_all`: a `messaging/mux/revoke-all` that advanced the member's
  epoch, with the new epoch and how many grants it voided. The target is the
  member DID.
- `mux_grant_suspend`: one entry per grant the unknown-key rule suspended,
  whether fired by a statement or by a direct login. The actor is the member
  DID whose key fired it; the target is the principal that lost the grant.
  On a direct login it is written before the login answers.

Recording is best-effort, like every audit entry: a failure is logged and
never undoes the change.

### Added — the mux `send` scope on the inbound path

- A mux connection now accepts a frame whose sender is one of its member
  DIDs when that member's grant or attach includes `send`. The frame is
  still signed or authcrypted with the member's own keys. This covers a
  DIDComm `routing/2.0/forward` to the mediator (sender proven by its
  authcrypt or JWS key), a DIDComm direct-delivery envelope (sender as the
  JWE `skid` names it), and raw TSP Direct, Routed and Nested frames on the
  connection.
- An accepted frame is the member's from then on, exactly as if the member
  had sent it on its own connection. It is checked against the member's own
  ACLs: not blocked, `LOCAL` and `SEND_MESSAGES`, read when the frame
  arrives, so a grant cannot outlive a revoked ACL. The forwarding,
  queue-limit and recipient ACL / access-list checks also see the member,
  and the per-account `messages_sent` counters and `stored` monitor events
  name the member, not the principal. Problem reports for the connection
  still go to the principal.
- `send` admits sending only. A member's message to the mediator itself
  (pickup, Trust Tasks, trust ping, mediator administration, a TSP Direct
  or Control message to the mediator) is refused on the principal's
  connection, as before.
- **Behaviour change (R3.6):** with `security.force_session_did_match` on
  (the default), such frames were refused on every socket with
  `authorization.did.session_mismatch`. They are now accepted for `send`
  members only. A frame from a member without `send`, or from a DID that is
  not a member, is still refused with that same problem report and the same
  monitor `refused` code, and the socket stays open. With
  `force_session_did_match` off, nothing changes: any authenticated session
  could already present any sender's frames.
- The rule follows the session, as pickup and delete scopes already do, so
  `POST /inbound` with the token of an open mux connection is covered too.
- Design §7.6 names a `mux.send.not_attached` refusal code. That code is
  not used; refusals keep today's code (see above).

### Added — fair queuing on DID multiplexing connections

- A mux connection's send queue is now shared fairly among its DIDs (design
  §7.2, step 3). Each DID on the connection, the principal included, may
  have at most 8 frames queued (the depth a direct socket has), and the
  connection at most `limits.mux.max_channel_slots` (default 512, now
  enforced and clamped to 8–65536). The socket writes round-robin across
  DIDs with frames waiting, and member/close events before any of them.
  Before, one busy member filled the connection's single 8-slot queue and
  every other member's live pushes were dropped behind it.
- **Behaviour change for mux clients:** when a member's own share is full,
  only that member's push is dropped, and the resync that follows is a
  pickup `status` for *that member's* inbox (`recipient_did` is the member),
  still packed to the principal. Before, any drop on a mux connection sent a
  status for the principal's own inbox. A member that left the connection is
  not sent one.
- New metric `mux_queue_fairness_skips_total`: pushes refused because that
  DID already held its share (also counted in
  `ws_live_delivery_dropped_total`).
- Unchanged: direct sockets (plain 8-slot queue), the global
  `ws_send_buffer` byte pool, when the `delivered` monitor event is emitted
  (when the frame is queued, as before), and dropping queued frames of a
  member detached after they were queued.

### Added — DID multiplexing audit records

The `messaging/mux/*` specs require an audit record for each of these, and
the mediator wrote none. Each is now in the audit log (`audit/list`), with
the new actions from affinidi-messaging-mediator-types 0.1.1:

- `mux_grant_revoke`: one entry per grant `messaging/mux/revoke` removed.
  The actor is the party that revoked; the target is the other party.
- `mux_revoke_all`: a `messaging/mux/revoke-all` that advanced the member's
  epoch, with the new epoch and how many grants it voided. The target is the
  member DID.
- `mux_grant_suspend`: one entry per grant the unknown-key rule suspended,
  whether fired by a statement or by a direct login. The actor is the member
  DID whose key fired it; the target is the principal that lost the grant.
  On a direct login it is written before the login answers.

Recording is best-effort, like every audit entry: a failure is logged and
never undoes the change. Every failed audit write, mux or not, now also
counts in the new `audit_write_failures_total` metric.

### Added — durable DID multiplexing notices

- The mediator now stores signed `messaging/mux/notice/0.1` documents in the
  inbox of the party that must act. They are delivered at least once, and
  the recipient acknowledges one by deleting it:
  - `grantsSuspended` goes to each principal whose grants the unknown-key
    rule suspended. Those grants must be recreated with a fresh member
    signature. A principal that was offline finds the notice when it next
    picks up or connects.
  - `grantsRevoked` goes to each principal whose grant was revoked by its
    member (`revokedByMember`), voided by `revoke-all` (`epochBumped`), or
    removed with the member's account (`accountRemoved`). A principal that
    revoked its own grant is not sent one.
  - `grantsPresent` goes to a member DID: when its new key suspended grants,
    and when it authenticates directly (DIDComm) while grants on it exist
    and it has not been told since they changed. It carries counts only,
    never a principal DID.
- The `ready` event's `pendingNotices` now counts the notices waiting in the
  principal's inbox. It was always 0.
- A notice is stored only after the change it reports is committed and its
  members are detached. A `grantsSuspended` or `epochBumped` notice lost to
  a crash is sent when the principal next opens a mux connection. A
  `revokedByMember` or `accountRemoved` notice is best effort, because those
  grants are deleted; `messaging/mux/list` stays the source of truth.
- Removing a member DID's account now detaches it from its principals' live
  connections at once (`accountRemoved`). Before, they kept carrying it until
  the next 30-second sweep.
- **The unknown-key rule now also runs on direct authentication**, comparing
  the proven key only with keys of the same kind. A grant records the member
  DID's `keyAgreement` keys when it is stored. A DIDComm login fires the rule
  only if its authcrypt sender key is none of those. A TSP login fires it
  only if the VID's signing key signed none of the active grants. A member
  that logs in directly with keys it already had keeps its grants; a key
  added since suspends them, with the same notices as any other suspension.
  A DID that listed no `keyAgreement` keys when it granted has none known,
  so its first one suspends its grants. Spec:
  trustoverip/dtgwg-trust-tasks-tf#1072.
- **Behaviour change (login):** for a DID with active mux grants, the
  unknown-key check runs before the login succeeds, and its suspensions are
  committed and detached before tokens are issued. If the check cannot run,
  because the sender key does not resolve or the store fails, the login is
  refused with `me.res.storage.error` (HTTP 503) and the client retries. A
  DID with no active grant is unaffected and never resolved for this.
- A grant whose member DID cannot be resolved for its `keyAgreement` keys is
  refused with `messaging/mux:didUnresolvable` (retryable). Before, it was
  stored with no keys recorded, which switched the DIDComm unknown-key rule
  off for every grant on that DID.
- A mux connection now re-reads its grants once it is published, so a
  revocation or suspension committed while it was opening detaches the
  member at once rather than at the next sweep.
- `grantsExpiring` is stored once per grant, for active grants past about
  three quarters of their lifetime. It is checked when the principal logs
  in, when it opens a mux connection, and on the key re-check timer while
  connected (`revalidate_interval_secs`). The mediator cannot see a client's
  renewal opt-in, so it sends the notice for every such grant; a client that
  renews discards it. A renewed grant starts a new lifetime.
- Not yet: the audit record for a suspension. Each notice is one more inbox
  message, so a principal that never drains its inbox accumulates them.

### Added — DID multiplexing grant storage (no behaviour change yet)

- Storage for DID multiplexing grants: a member DID's signed permission for a
  *principal* connection to collect its messages (see
  `crates/affinidi-messaging-mediator/docs/multiplexing.md`). Every grant rule (epoch,
  replay floor, quotas, narrow-only updates, unknown-key suspension, expiry)
  lives once, in `affinidi-messaging-mediator-common::store::mux`; the Redis,
  Fjall and memory backends implement only a versioned compare-and-swap of a
  per-DID record, so they cannot drift on a rule. Nothing reads or writes
  grants yet: the protocol and connection handling follow, opt-in, behind
  `limits.mux.enabled` (off by default).
- `MediatorStore` gains `supports_mux`, `mux_record_get`, `mux_record_cas`,
  `mux_principal_dids` and `mux_principal_count`, all defaulted, so a
  third-party backend keeps compiling and reports mux as unsupported.
- `[limits.mux]` config (and `LIMIT_MUX_*` env overrides), **off by default**.
  Only the exact value `"true"` enables it; anything else is off. A mediator
  with `enabled = "true"` refuses to start on a backend without mux support
  or with live streaming disabled. With several instances behind one Redis, a
  revoke handled by one instance reaches another's live connections within
  one 30-second member sweep (it is immediate on the instance that handled
  it).
- Removing an account removes its mux grants on both sides (as a member DID
  and as a principal), whether or not mux is enabled at the time.
- `mux::proof::StatementVerifier`: verifies the `MuxGrant` / `MuxAttach`
  statements a member DID signs to allow a principal to carry its traffic.
  They use W3C Data Integrity proofs (`eddsa-jcs-2022` / `eddsa-rdfc-2022`),
  the same format and verifier as Trust Tasks, and only an `authentication`
  key may sign one. Statements are closed objects (unknown members are
  refused), bound to the mediator (`audience`), the principal and, for an
  attach, the connection. It can also re-check that a stored grant's signing
  key is still the member's current authentication key; a DID that cannot be
  resolved reports "unknown", never "stale" or "fine".
- `mux::grants`: the transport-free grant operations the protocol handlers
  will call: store (verify, then member standing and scope within the
  member's own ACLs, then the unknown-key rule, then the store rules), revoke
  as principal or member, revoke-all, and key re-validation. Each one returns
  exactly which grants it changed, so the connection layer can detach them.
- The live-delivery streaming task can now carry one DID on a mux
  connection as well as on its own socket. A DID's own (direct) socket always
  wins; a mux entry yields to it and waits on standby, is told it is inactive
  or superseded, and is reactivated (with inbox redelivery, as for any
  replacement) when the direct socket goes away. A mux connection is never
  closed for one of its members. Every queued frame now carries the DID it is
  for. Direct-socket behaviour (newest wins, duel damper, redelivery) is
  unchanged and still pinned by the existing tests.
- `mux::session::MuxSession`: one connection's member set. It admits members
  by session attach (bound to the connection's nonce) or by stored grant on
  connect (re-checking each grant's key; a DID that cannot be resolved is not
  carried), enforces `max_dids_per_connection`, expires and detaches members,
  and answers whether the connection may receive, pick up, delete or send for
  a given DID.
- The `messaging/mux/{grant,list,update,revoke,revoke-all}/0.1` Trust Tasks
  are served (over DIDComm and TSP, through the existing Trust Task core) when
  `limits.mux.enabled` is on; otherwise they answer
  `protocol.trust_task.unsupported`. The specs are pinned from trusttasks.org
  (dtgwg-trust-tasks-tf#1068).
- DIDComm mux connections. A client opens one by offering the
  `affinidi-mux` WebSocket subprotocol (provisional name) alongside its
  bearer token; the mediator echoes it only when mux is enabled. On connect
  the mediator admits the principal's stored grants, registers each member
  with live delivery on the one socket, and sends a signed
  `messaging/mux/event` `ready` (with the attach nonce) and `attached`.
  `messaging/mux/attach` and `detach` act on the connection they arrive on.
  Revoke, revoke-all, unknown-key suspension and narrowing reach every live
  connection carrying the affected DIDs **before** the response is sent, and
  a frame queued for a member that has since left is dropped, not written.
  Members expire on their own clocks and grant members' keys are re-checked
  every `revalidate_interval_secs`. Message pickup (`status-request`,
  `delivery-request`) and `messages-received` accept a member's DID when its
  scope includes `pickup` / `delete`.

### Added — Redis cluster mode, for ElastiCache Serverless

- **`[database] cluster_mode` (`DATABASE_CLUSTER_MODE`), off by default.** On,
  the mediator runs on a single-endpoint cluster-mode Valkey such as
  ElastiCache Serverless: hash-tagged keys, a cluster client, single-slot
  scripts instead of `FCALL` (serverless has no `FUNCTION`), and idempotent,
  crash-safe steps where one operation spans slots. Off keeps today's key
  layout and Lua functions. Startup refuses a setting that doesn't match the
  server, a cluster with more than one primary node, an endpoint that reaches
  a replica, and existing data written under the other `cluster_mode` (the
  key names differ, so flipping the setting would orphan every account and
  message; there is no migration). Limits (one slot's throughput for the
  shared keys; TTL keys evicted before error 97) are in `conf/mediator.toml`.
  The standalone processors read the same setting. It takes `true`/`false`,
  `1`/`0`, `yes`/`no` or `on`/`off`, ignoring case, as a boolean or a string.
- **Cluster-mode stores and deletes keep the library's guarantees.** A store
  holds the message until it is fully queued and a delete holds it until it
  is removed, so exactly one of two concurrent deletes succeeds (the other
  gets NOT_FOUND, R1.7), a delete never leaves queue entries or counters for
  a gone message, and a store is never reported for a message that isn't
  queued (R1.1). A store or delete that dies or stalls part-way is taken over
  after 30 seconds. A store that takes over a delete releases the entries the
  delete claimed and queues the message again under new entries, so the
  delete, if it resumes, removes nothing. A store refused at its last step
  releases what it queued. A delete whose release fails gives its hold up at
  once. The expiry index is written before the message, so a failed write
  can't leave a message the sweeper never reaches.

### Added — DID multiplexing metrics on `/metrics`

- `mux_connections{wire}` (gauge, `wire` = `didcomm` | `tsp`): live mux
  connections on this instance. It moves only as connections enter and leave
  the mux registry, so it matches `messaging/stats/show`.
- `mux_members{source}` (gauge, `source` = `grant` | `attach`): member DIDs
  carried by those connections. It moves with each connection's member set,
  so every way a member joins or leaves (attach, grant, detach, revoke,
  expiry, a change from another instance, the connection closing) keeps it
  exact. A member admitted both ways counts once, as `grant`.
- `mux_detach_total{reason}` (counter): members detached, or stored grants
  not carried, by the spec's `DetachReason` (`revokedByMember`, `expired`,
  `superseded`, `connectionFull`, …). A connection closing is not counted as
  a detach.
- `mux_grant_revalidate_failures_total{cause}` (counter, `cause` =
  `resolution` | `store`): signing-key re-validations that could not reach a
  decision (the member's DID did not resolve, or a stale key could not be
  recorded).
- `mux_queue_fairness_skips_total` already existed and is unchanged.
- No label carries a DID.
- No `attached`/`detached` stage was added to the traffic monitor. The pinned
  `messaging/monitor/event/0.2` schema closes its stage set, so that needs a
  spec revision first.

### Added — the traffic monitor can report mux membership changes, on request

- `messaging/monitor/subscribe` 0.2 is served beside 0.1. Its optional
  `membership` filter (by DID, change, wire and source) opts a subscription
  in to mux membership events. Without it there are none. `traffic: false`
  makes a membership-only tap. The response echoes the effective
  `membership` filter, and says `traffic: false` when traffic is off.
- A 0.2 subscription receives `messaging/monitor/event` 0.3 batches. An
  opted-in one gets a `membership` array and a `membershipDropped` count on
  every batch; `dropped` still counts traffic events only. One rate ceiling
  covers both kinds.
- Each event mirrors one member change the mediator reports in an
  `attached` or `detached` `messaging/mux/event`: when, which change, the
  principal and member (as DID hashes, like traffic events), the wire
  (`didcomm` or `tsp`), the source (`grant` or `attach`), the reason, and
  the connection's `sessionId`. Metadata only: no statement, nonce, scope or
  key material.
- An administrator may watch any account's membership. Anyone else sees only
  changes it is party to, as principal or member: an omitted `dids` is
  narrowed to its own account, and naming another account is refused with
  `permissionDenied`. The membership filter counts toward the re-check that
  ends an administrator's wide tap when it stops being one, and it is on the
  audit log.
- Behind a shared Redis, every instance's membership events reach every
  instance's subscribers (see "membership monitor events cross instances").
  A mediator without mux enabled grants no membership filter.
- Unchanged for existing clients: a 0.1 subscription still gets event 0.2
  batches, traffic only. Pins `messaging/monitor/event` 0.3 and
  `messaging/monitor/subscribe` 0.2 beside their older versions, and takes
  the in-place draft update of `messaging/mux/notice` 0.1 (a description
  change only).

### Added — Administrators list and revoke stored mux grants

- The mediator serves three new Trust Tasks (specs 0.1, pinned in
  `trust-tasks.lock`), when `limits.mux.enabled` is on:
  - `messaging/mux/admin-list` lists the stored grants of a principal DID,
    of a member DID, or between the two, a page at a time. Each grant shows
    its parties, state, effective scope and expiry, epoch and signing time,
    never the signed statement. With `member`, the answer carries the
    member's current epoch. Open to `admin`, `rootAdmin` and the mediator's
    own account. Cursors are bound to the requester and the request, and
    continue on any instance of the mediator.
  - `messaging/mux/admin-revoke` revokes grants by principal, by member, by
    both, or by member and grant ids, at most `limit` (500) per request,
    with an exact `remaining` count. Same effect as `messaging/mux/revoke`:
    members are detached on every connection before the answer, the replay
    floor rises, and each principal gets a `detached` event and a durable
    `grantsRevoked` notice, both with reason `admin`.
  - `messaging/mux/admin-revoke-all` advances a member DID's epoch on the
    administrator's standing, compare-and-set on the epoch the request
    names. Same state change as `messaging/mux/revoke-all`, reported with
    reason `admin` instead of `epochBumped`.
- Both revoke tasks are for `admin` and `rootAdmin` only. An `admin` is
  refused (`protectedAccount`) when a selected grant's member or principal
  is a `rootAdmin`, before anything is revoked; a `rootAdmin` may act on any
  grant. Each revocation and epoch advance is written to the audit log.

### Added — the console manages stored mux grants

- `affinidi-messaging-mediator-admin`: an administrator lists stored mux
  grants by principal or member DID, a page at a time
  (`MediatorConsole::mux_grants`), with the member's current epoch. It
  revokes chosen grants, a principal's or a member's (`mux_revoke`, with a
  `GrantSelection`), in bounded rounds, and says what was revoked, what still
  matches and why it stopped (`revoke_summary`). It advances a member's epoch
  (`mux_bump_epoch`), naming the epoch it read (`mux_epoch`), so a change made
  meanwhile is not overwritten.
- `ConsoleError::explain` puts the stored-grant refusals in plain words
  (`epochMismatch`, `protectedAccount`, `unknownAccount`, `contended`,
  administrator required). `ConsoleError::current_epoch` reads the epoch in
  force from an `epochMismatch`.
- `affinidi-messaging-mediator-tui`: a **Grants** tab (`8`) lists a
  principal's or member's grants (`/` to look one up, `g` from a Mux
  connection), revokes the selected grant (`d`) or all listed (`D`), and
  advances the member's epoch (`E`) after showing the current one. Each asks
  for confirmation. Number keys now reach the 7th and 8th tabs.
- These need mediator 0.52.0. The console refuses them locally, with the
  reason, on an older mediator it knows the version of.

### Added — a test mediator can stand in for one that predates a task version

- `MediatorBuilder::withhold_task_types` and
  `TestMediatorBuilder::withhold_task_types` refuse the named Trust Task
  request types as unsupported (`protocol.trust_task.unsupported`), as a
  mediator that predates them does, so a client's fallback to an older
  version can be tested against a real mediator. Nothing is withheld by
  default and the config file cannot set it.
- The console's live monitor is now tested both ways against a live
  mediator: at `monitor/subscribe` 0.2 with traffic and mux membership, and
  falling back to 0.1, traffic only, when 0.2 is withheld — where asking for
  membership is refused rather than quietly dropped.

### Added — the console revokes several marked grants at once, grant by grant

- `affinidi-messaging-mediator-tui`: the **Grants** tab marks grants —
  `space` marks or unmarks the selected one, `a` marks every grant listed,
  `c` clears the marks; the marked rows show `●` and the title their count.
  With grants marked, `d` revokes them after one confirmation naming how
  many. Every grant not revoked is then listed with why — a rootAdmin
  party's grant is refused as protected — and stays marked to try again;
  the rest are revoked regardless. `E` acts on one member and is refused
  while grants are marked. Changing the listing clears the marks.
- `affinidi-messaging-mediator-admin`: `MediatorConsole::mux_revoke_each`
  revokes a list of grants (`GrantKey`: member DID and grant id), one
  `messaging/mux/admin-revoke` request each, since the mediator refuses a
  whole request when any grant in it is protected. `BulkRevokeOutcome` says
  what happened to each grant (`GrantRevokeResult`: revoked, no longer
  stored, refused, not confirmed, not sent), with `summary()` and
  `failures()`. A grant is reported revoked only when the mediator's answer
  lists it; after a request lost in transit, the rest are not sent and are
  reported as such.

### Added — monitor fan-out metrics

- `monitor_fanout_dropped_total` (label `cause`: `overflow`, `publish`,
  `lagged`) counts membership events one instance's subscribers missed from
  another; `monitor_fanout_received_total` counts those received.
- `MediatorStore::monitor_fanout_publish` / `monitor_fanout_subscribe`
  (affinidi-messaging-mediator-common), with no-op defaults for
  single-process stores.

### Added — Trust Task refusals as `trust-task-error` documents, for a request that asks

- A Trust Task request that carries the top-level member
  `"x-errorFormat": "trust-task-error"` is now refused with a
  `trust-task-error` document (Trust Tasks SPEC §8). It replaces the DIDComm
  problem report the mediator sent before, over DIDComm, TSP and the mux
  sockets. The DIDComm binding says a problem report is not an error response
  (`didcomm/0.2` §4.1). The document carries:
  - `code` and `retryable`;
  - `inResponseTo` (the refused request's type and `id`), with `threadId` set
    to the request's;
  - the `details` the code's specification declares.
  It is signed as a success response is, threaded and delivered like one.
- `details` per the pinned bundles' `detailsSchema`:
  - `currentEpoch` for `messaging/mux/revoke-all:epochMismatch` and
    `messaging/mux/admin-revoke-all:epochMismatch`;
  - `size` for `messaging/message/get:messageTooLarge`.
- The problem report for those codes now also carries the value as its first
  `args` entry. The user's `revoke-all` did not carry it before; the
  administrator's already did. The comment text is unchanged.
- Codes a specification declares (`messaging/mux/…:…`) and standard codes are
  sent as they are. The mediator's own codes are not valid `trust-task-error`
  codes (`authorization.admin_required`, `message.trust_task.stale`,
  `protocol.trust_task.unsupported`, …). Each is sent as the standard code
  that says the same thing (`permissionDenied`, `expired`, `unsupportedType`,
  …), with the original in `details.mediatorCode`.
- An internal or storage failure is `internalError` or `unavailable` with a
  generic message. Its text stays in the log, as it does for an HTTP client.
  An `identityMismatch` names neither identity (SPEC §8.1).
- A document goes only to a request whose sender is the session's
  authenticated account, the one case in which it could have been answered.
  A relay-only session, or a TSP frame signed by another DID than the
  session's, is refused with a problem report as before. Nothing is signed
  or stored for it.
- The refusal of `messaging/mux/ack` is pushed to the connection only, never
  stored, like its answer. It says no more than the problem report did, so an
  ack still does not confirm that another DID's message exists.

### Added — `MEDIATOR_`-prefixed environment names and complete `Env:` labels

- `MEDIATOR_DATABASE_URL`, `MEDIATOR_LOG_LEVEL`, `MEDIATOR_USE_SSL` and
  `MEDIATOR_LISTEN_ADDRESS` are accepted and win over the bare names, which can
  collide with other software in a container. Names that did not match their
  setting gain consistent ones (`GLOBAL_ACL_DEFAULT`,
  `LIMIT_TO_KEYS_PER_RECIPIENT`, `LIMIT_ACCESS_LIST_LIMIT`,
  `LIMIT_OOB_INVITE_TTL`); the old names keep working.
- New overrides: `LIMIT_MUX_MAX_ATTACH_LIFETIME_SECS`,
  `LIMIT_MUX_REVALIDATE_INTERVAL_SECS`, `LIMIT_MUX_MAX_CHANNEL_SLOTS`,
  `LIMIT_MUX_DEAD_RETENTION_SECS`, `PROCESSOR_FORWARDING_ACCEPT_INVALID_CERTS`.
- `STORAGE_BACKEND` now creates the `[storage]` section when the file has none
  (the published image's config has none, so it used to be ignored); other
  `STORAGE_*` variables set without a section are reported as ignored.
- Every variable the overlay reads is labelled in the template and every label
  is read, checked by a test in both directions; the drift test now covers
  `docker/test/conf/mediator.toml`, whose send-queue limits move to the
  documented 2000 / 10000.

### Added — mediator-setup: headless runs from one recipe with `--set`

Every headless run builds one recipe: the `--from` file, then the per-option
flags (shorthands for recipe keys), then `--set section.key=value`
overrides. Each override and each unused flag is reported, a mistyped key is
an error, and `DATABASE_URL` overriding the recipe is reported too. Saved
recipes are serialised from the recipe schema (TOML-escaped, with
`[storage]`, `save_did_web`, `extra_key_suites`, the DIDComm v1 forwarding
flag, a relative `file://` path) and load back to the same configuration.
`--key-suite secp256k1` now applies to did:peer too.

### Added — `mediator healthcheck` and an image HEALTHCHECK

- `mediator healthcheck` GETs the `livez` route of the mediator its config
  describes (`--config`, with the usual environment overrides; a wildcard
  `listen_address` is probed on loopback) and exits 0 on a 2xx, 1 otherwise.
  `--url` probes an explicit URL instead.
- The image declares `HEALTHCHECK CMD ["/usr/local/bin/mediator",
  "healthcheck"]`, so Docker, Compose and ECS see container health without
  extra tools in the image.

### Added — `MediatorConsole::connect_with_unclaimed` and `connect_exclusive`; `connect_with` deprecated

- The SDK has no receive filtered by message type, so the console's live
  reader takes every message pushed to its DID on its SDK instance, keeping
  only monitor batches. `connect_with` hid that in its name, so it is
  deprecated; it still behaves as before. Choose explicitly instead:
  `connect_exclusive(atm, identity)` for an SDK instance dedicated to the
  console (what `connect_with` did), or
  `connect_with_unclaimed(atm, identity, tx)` for an application sharing its
  SDK instance and DID with the console. Every other
  message then goes to `tx`, with its unpack metadata. The console never
  deletes such a message at the mediator. If `tx` is full, the message is left
  stored for a later pickup.

### Added — `affinidi-messaging-mediator-common`: open an encrypted file store with an explicit passphrase

`secrets::open_store_with_passphrase`, `open_store_with_passphrase_async`
and `MediatorSecrets::from_url_with_passphrase` take the
`file://?encrypt=1` passphrase from the caller instead of the environment,
trimmed the same way so both give the same key. `None` behaves exactly like
`open_store` / `MediatorSecrets::from_url`. Additive; other backends ignore
the passphrase.

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
  queued within the transit margin before the count: the request timeout,
  at least 30 s).
- `--timeout` and `--connect-timeout` bound the console's waits, in the
  console and in commands alike.

### Added — `messaging/queue/purge` honours `storedBefore`

- The vendored `messaging/queue/purge/0.1` bundle is refreshed to the
  in-place draft revision that adds `storedBefore` (request) and
  `selectedAt` (response) (dtgwg-trust-tasks-tf#1288).
- The mediator selects only messages stored at or before `storedBefore`
  (RFC 3339; floored to the store's millisecond), combined with `peer` and
  `olderThanSeconds`, on every backend. The purge audit entry names it
  (`stored before: …`). A request without it behaves as before.
- A narrowed purge or a dry run is now bounded by the instant its selection
  is taken: a message stored while the walk runs is neither counted nor
  removed.
- `selectedAt` is **not** returned yet. Every published
  `affinidi-messaging-sdk` (0.47.0 and older) parses the purge response with
  unknown members denied, so returning it would make every existing client's
  purge fail. It ships once an SDK that knows the member is released; the
  console then sends the dry run's `selectedAt` as `storedBefore` in place of
  its age-based pin (#122).

### Added — Waking an account's device on a sender's request (`messaging/wake/set`, `messaging/wake/request`)

- `messaging/wake/set/0.1`: an account gives the mediator the opaque wake
  handle its push gateway issued, or clears it. One record per account, in
  every storage backend, removed with the account. Answered `wakeCapable:
  true` only when the mediator holds the handle and can ring its gateway (a
  DID advertising `DIDCommMessaging`).
- `messaging/wake/request/0.1`: a sender that has just queued mail for an
  account asks the mediator to ring the account's device. Accepted from a
  sender with no account here, relayed by its own mediator, for this type
  only; it never creates an account and is charged to the per-DID inbound
  rate limit. Its proof (`proofPurpose: authentication`) is required and
  checked whatever `security.trust_task_verification` says. Every accepted
  request is answered with the same `{}`, before and whatever the mediator
  decides, so it reveals nothing about the addressee.
- The mediator rings — `push/wake/0.2` to the handle's gateway, signed as the
  mediator, over DIDComm — only when the addressee is an offline account with
  a handle, every named message is queued for it, undelivered and stored in
  the last 10 minutes, a stored authcrypt envelope's sender is the requester,
  the addressee's access list does not refuse the requester, no named message
  has rung before, and the `[processors.wake]` limits allow it (defaults: one
  ring a minute and ten a day per requester and addressee; rings for one
  addressee coalesce over 15 s, at most 30 an hour). A request naming mail not
  stored yet is held for up to 120 s. A gateway answer `tokenUnregistered`
  drops the handle; `notAllowed` stops ringing it until the account sets one.
- New metrics `wake_requests_total{outcome}` and `wake_rings_total{outcome}`;
  new config `[processors.wake]` (`enabled`, `pair_per_minute`,
  `pair_per_day`, `addressee_coalesce_seconds`, `addressee_per_hour`, each
  with a `PROCESSOR_WAKE_*` environment override). Absent, waking is on with
  the defaults above.
- `AuxiliaryStore` gains `wake_handle_set` / `wake_handle_get`, implemented
  by the memory, fjall and redis backends. A third-party backend must
  implement them.

### Added — getting started, operations, multiplexing and architecture docs

- The root README's "Getting started" leads from a fresh checkout to a running,
  checked mediator and the console in five steps, and `docker/README.md`
  covers the container quickstart and running the published image.
- New docs in `crates/affinidi-messaging-mediator/docs/`: `multiplexing.md`
  (DID multiplexing), `operations.md` (probe routes, metrics catalogue, logs,
  shutdown) and `architecture.md` (crate and module map, message lifecycle).
  `docs/delivery-rules.md` states the R-numbered rules that code comments and
  changelog entries cite.

### Removed — dead code in the request path

- `handlers::LoadState` and `common::jwt_auth::TokenPayload`, which nothing
  used. `SharedData::config` is now `Arc<Config>`, so the configuration is no
  longer deep-cloned on every request, and the `Session` and `MaybeSession`
  extractors take `SharedData` by reference. Code that built a `SharedData`
  by hand must wrap its `Config` in an `Arc`.

### Deprecated — `messages::WrapperType`

- No longer used by the mediator; removed at the next breaking release.

### Security — the console escapes mediator text before showing it

- A refusal's code and comment, and the text `ConsoleError::explain` returns,
  now have control characters, line and paragraph separators and
  bidirectional formatting marks escaped (`\u{1b}`). A mediator, or anything
  that can shape a refusal's comment, can no longer send ANSI/OSC escape
  sequences or reordering marks that rewrite the operator's terminal or
  disguise a confirmation. Other text, non-ASCII included, is shown as before.

### Security — operator key files are read and written more carefully

- `ProfileFileSource` (the standalone console's `--profile`, such as
  `admin-monitor.json`) refuses on Unix to load a profile that its group or
  other users can access (any of mode `0o077`), naming the `chmod 600` that
  fixes it, as `ssh` does with a private key. `mediator-setup` already writes
  the file at `0600`. The file's bytes are wiped once parsed, and listing
  profiles no longer parses their secrets (#169).
- `AddressBook::save` writes atomically (a temporary file, flushed, then
  renamed over the book), so a crash mid-save leaves the old book whole, and
  creates the file at mode `0600`.
- The test mediator's `standalone` example prints a "TEST FIXTURE — no TLS,
  allow-all ACL" banner when bound to a non-loopback address, and the
  fixture's README says it is test-only.

### Security — secret material is redacted from `Debug` and wiped on drop

- `AdminCredential`, `VtaCachedBundle` and the internal bundle and seed types
  print `<redacted>` (or entry names only) in `Debug`.
- `AdminCredential`'s private key, bundle entries, bootstrap seeds, operating
  keys and the JWT key are zeroised when dropped; the passphrase read from
  the environment or a file is no longer left in an unwiped `String`.
- A cached bundle read is shared rather than copied on every `get`.
- The passphrase env var is left set: removing it is unsound while other
  threads may read the environment. Use
  `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE` to keep it out of the environment.
- **API (affinidi-messaging-mediator-common):** `AdminCredential` implements
  `Drop`, so its fields can't be moved out (struct-update syntax
  `..credential` included); clone them instead. `BackendUrl::Vault` has a new
  `ca_cert` field. New: `open_store_async`, `MediatorSecrets::from_url_async`,
  `BackendUrl::is_plaintext_file`.

## 0.51.0 (release/0.51)

### Added — did:webs

- The mediator resolves `did:webs`, so a did:webs client can authenticate and
  a did:webs recipient can be routed to. A did:webs resolves only when its
  KERI key event log verifies and the published `did.json` matches the
  verified key state, under the same default host policy as did:web and
  did:webvh: public hosts only, no redirects, no proxy. Requires
  `affinidi-did-resolver-cache-sdk` 0.8.47, which does not turn on
  `serde_json`'s `preserve_order` for the whole build. A mediator configured to
  resolve through a DID resolver cache server needs one that resolves did:webs
  (`affinidi-did-resolver-cache-server` 0.9.16).

### Changed — container send-queue limits

- The published container image now ships `queued_send_messages_soft = 2000`
  and `queued_send_messages_hard = 10000`, matching the annotated template and
  the Rust defaults. It shipped 200 and 1000, so every deployment ran a send
  queue ten times tighter than the documented default while a code search
  reported 2000, which is a trap for anyone sizing a deployment or reading a
  `queue_max_saturation_ratio` against the wrong denominator. 200 is also tight
  in practice: a sender whose recipients stop deleting fills it in seconds.
  `queued_receive_messages_soft` and `_hard` are unchanged at 200 and 1000,
  because the receive limits bound total storage and the send limits do not;
  `queued_send_messages_per_peer` is unchanged at 50 and remains the gate that
  catches one sender flooding one recipient.

### Fixed

- **A standard account can no longer switch its own queue limit off.**
  `SELF_MANAGE_SEND_QUEUE_LIMIT` / `SELF_MANAGE_RECEIVE_QUEUE_LIMIT` let an
  account raise its own limit up to the mediator's hard maximum, enforced by
  clamping anything larger. `-1` is not a larger number — it is the sentinel
  for *no limit at all* — so it slid past the clamp and was stored verbatim,
  after which the account's queue gate never refused it again, whatever its
  depth. Any deployment whose default ACL grants those flags — AMA's does,
  through `GLOBAL_DEFAULT_ACL` in `cdk-atlas-lib`; this repo's shipped
  `global_acl_default` does not — made one `messaging/account/update/0.1`
  enough, with no admin and no redeploy. **Behaviour change (R3.6):** a
  standard account requesting `-1` (or any negative other than `-2`) for either
  queue limit now gets an `authorization.queue_limit.admin_required` problem
  report and a 403 instead of a success; a request it is allowed to make is
  unaffected, and values above the hard limit are still clamped rather than
  refused. An admin still sets `-1` deliberately, and `-2` still resets the
  account to the mediator default for standard accounts and admins alike.
  The `queue_stream_maxlen` doc comment in `limits.rs` described `-2` as
  unlimited; it is a reset, and now says so.

- **A self-managed queue limit is no longer clamped against an unbounded hard
  limit.** When the mediator is configured with `queued_send_messages_hard` or
  `queued_receive_messages_hard` of `-1` (not bounded), the clamp compared
  against it as a number: `500 > -1` holds, so a standard account asking to be
  held to 500 was stored as `-1` instead and ended up with no limit at all —
  reaching the state above by asking for something *tighter*. A negative hard
  limit is now read as "no ceiling" and the request stands, as
  `queue_stream_maxlen` already reads one. (`queue_at_capacity` and
  `validate_peer_queue_limit` test for `-1` exactly, and are unbounded on any
  other negative only through the unsigned cast — the accident this change
  closes on the write path, not prior art to copy.) An unbounded mediator
  still does not hand out its own exemption: `-1` from a standard account is
  refused either way.

- **A queue limit the account may not self-manage is now refused, not silently
  dropped.** `account/update` ignored a `send_queue_limit` / `receive_queue_limit`
  from an account without the matching `SELF_MANAGE_*` flag and answered 200 with
  the account echoed, so the caller read the unchanged old value as the value it
  had just set. It now gets an `authorization.queue_limit.not_self_manageable`
  problem report and a 403, as `acl` already did for a capability the account may
  not change.

- **The two self-or-admin members of `account/update` now agree on who an admin
  is.** The `acl` member tested `Admin | RootAdmin`, the queue limits tested
  "anything that is not `Standard`", so an account whose type did not decode
  (`AccountType::Unknown`) was gated on one member and waved through on the other.
  Both now use the handler's own `is_admin`.

- **`account/update` no longer applies part of a refused request.** The handler
  guards every member before applying any of them, so that a member the caller
  may not set refuses the whole update; the queue-limit check above was added
  at the write instead, one step inside the apply phase. A single request
  carrying both an `acl` member and an unlimited queue limit therefore stored
  and audited the ACL change and then returned 403, leaving the account
  half-updated with no response document to say which half landed. The check
  now runs with the other guards, before the first write.

## 0.50.0 (release/0.50)

### Changed — trust-tasks-rs 0.37 (breaking)

- **`trust-tasks-rs` / `trust-tasks-proof` 0.37, `affinidi-messaging-sdk`
  0.45, `affinidi-tdk` 0.37, `affinidi-messaging-didcomm-service` 0.30.**
  0.37 (trustoverip/dtgwg-trust-tasks-tf #1021) makes `validate_freshness`
  honour a stated `expiresAt`. **Behaviour change:** a consequential task
  that states an `expiresAt` is accepted until then, up to 30 days after its
  `issuedAt`, instead of being refused 5 minutes after `issuedAt`. A task
  without an `expiresAt` keeps the 5-minute window.

### Fixed

- **The replay record now lasts as long as the document is acceptable.** It
  was kept until `issuedAt` + 5 minutes + skew, or a sooner `expiresAt`. Under
  0.37 a document with a later `expiresAt` stays acceptable past that, so a
  replay of it after the record was dropped would have executed again.
  `retention_end` is now `FreshnessPolicy::record_expiry`, which the 30-day
  horizon bounds.
- `vta-sdk` still resolves `trust-tasks-rs` 0.36 (with `affinidi-messaging-sdk`
  0.44 and `affinidi-tdk` 0.36) until the VTI moves to 0.37. No types cross
  between the two, and the next `vta-sdk` release removes the second copies.

## 0.49.0 (release/0.49)

### Changed — dependencies to latest (breaking)

- **`vta-sdk` 0.77** (from 0.72; the mediator's default `vta` feature and
  `mediator-setup`). **Breaking for VTA-linked deployments:** from vta-sdk
  0.75 the SDK authenticates with `auth/authenticate/0.3` and pages
  `keys/list/0.2`, and the VTA no longer serves the earlier versions. A
  mediator built with `vta` now needs a VTA from the same release line (vta-sdk
  0.75 or later); conversely, mediator 0.48 and earlier cannot authenticate to
  such a VTA. Upgrade the VTA and the mediator together. Self-hosted mediators
  (operating secrets from the unified secret backend) and builds without `vta`
  are unaffected. vta-sdk 0.77 also made `VtaEvent`, `DiagStatus`,
  `AttemptResultKind` and `VtaIntegrationError` `#[non_exhaustive]`; the
  mediator and wizard handle an unknown variant by skipping it or reporting it
  generically.
- **`kube` 5 / `k8s-openapi` 0.29** (from 4.2 / 0.28; `secrets-k8s`). The
  `latest` API feature now targets Kubernetes 1.37 (was 1.36); the
  backend's calls (core/v1 `Secret` get/create/replace) are unchanged.
- **`aws-config` 1.13**, and the `aws-smithy-types >=1.6.1, <1.7` resolver
  bound is removed. `aws-config` 1.13 is the first release off
  `aws-smithy-json` 0.63, whose break against `aws-smithy-types` 1.7 the bound
  existed to avoid; requiring 1.13 keeps a downstream resolve off the broken
  pair. `aws-sdk-*` move to their current releases.
- Lockfile refreshed to the latest compatible versions throughout, including
  TDK patch releases (`affinidi-did-common` 0.4.5, `affinidi-did-resolver-cache-sdk`
  0.8.44, `affinidi-messaging-didcomm` 0.15.11), `redis` 1.8 and
  `trust-tasks-rs` 0.36.6. The second copies of `affinidi-messaging-sdk`
  (0.37), `affinidi-tdk` (0.27) and `trust-tasks-rs` (0.32) that vta-sdk 0.72
  pulled in are gone.

### Fixed — configuration and documentation

- `LIMIT_QUEUED_SEND_MESSAGES_PER_PEER` now overrides
  `[limits] queued_send_messages_per_peer`, as the shipped template's
  `### Env:` label always said; it was silently ignored. A test now fails if
  any template `### Env:` label has no override behind it.
- Documentation brought in line with the code: the template lists the GCP,
  Azure, Vault and Kubernetes secret backends as available (not "coming soon")
  and names the `secrets-*` feature each needs; the quick start builds with
  the feature for the wizard's default `keyring://` backend; the
  `rate_limit_per_ip` guidance and a new README section point load-balanced
  deployments at `trust_xff_cidrs` (also in the example setup recipe);
  version snippets say 0.49; links into affinidi-tdk-rs that broke when the
  mediator moved out are absolute; stale CI workflow names, feature lists and
  crate docs corrected; the release schedule shows 0.48 GA.

### Changed — trusted-proxy rate-limit attribution

- **`affinidi-rate-limit` 0.1.3.** The per-IP limiter can now charge clients
  behind a reverse proxy to themselves. New `[server] trust_xff_cidrs` (env
  `TRUST_XFF_CIDRS`, comma-separated; default `[]`, which keeps today's
  behaviour of keying on the socket peer). When the socket peer is inside a
  listed range, the limiter walks `X-Forwarded-For` from the right, skips
  listed hops and charges the first address that is not one; a header from any
  other peer is never read. List only proxies that append to
  `X-Forwarded-For` (an ALB does), and make sure the mediator is reachable
  only through them.
- **Behaviour change:** an unreadable `X-Forwarded-For` chain from a listed
  proxy (a hop from the client rightwards that is not an address, a non-ASCII
  header, more than 64 entries) is refused with `400` and `x-rate-limit-source: mediator`, body
  `{"error":"invalid_forwarded_for","limiter":"mediator","message":…}`, rather
  than charging the proxy's shared bucket. Entries left of the client are
  never parsed, so junk a client prepends is ignored (it still counts towards
  the 64-entry cap). Counted in the new
  `rate_limit_attribution_failures_total{reason="invalid_forwarded_for"}`
  (also `reason="no_client_ip"` for the existing `403`).
- **Behaviour change:** per-IP keys are canonical, so a dual-stack listener's
  `::ffff:a.b.c.d` peer shares the IPv4 client's bucket instead of holding a
  second one. The `403` for a request with no client IP now also carries
  `x-rate-limit-source: mediator`.
- A catch-all range (`0.0.0.0/0`, `::/0`) in `trust_xff_cidrs` fails startup
  (and setup-wizard recipe loading): it would let any client choose its own
  rate-limit key. Startup logs which key the limiter uses and the trusted
  ranges, and warns when `trust_xff_cidrs` is set while per-IP limiting is
  disabled (`rate_limit_per_ip = 0`), since it then has no effect.
- `affinidi-messaging-mediator-setup` now depends on
  `affinidi-messaging-mediator-config` (previously a dev-dependency) to apply
  the same checks to recipe values.

## 0.48.0 (release/0.48)

### Changed — trust-tasks-rs 0.36, affinidi-messaging-sdk 0.44, monitor/event 0.2 (breaking)

- `trust-tasks-rs` / `trust-tasks-proof` 0.36, `affinidi-messaging-sdk` 0.44
  (affinidi/affinidi-tdk-rs#978), `affinidi-tdk` 0.36 and (test-mediator's
  dev-dependency) `affinidi-messaging-didcomm-service` 0.29.
- The mediator pushes `messaging/monitor/event` at 0.2: each event's `at` is
  now `occurredAt`. SDK 0.44's `decode_monitor_event` reads both versions; a
  console built on SDK 0.43 or earlier sees no events from this mediator.
  mediator-admin's `MonitorEvent` is the 0.2 type (`occurred_at`), so this is
  breaking for it.
- The seven tasks with a 0.2 (`ping`, `account/{get,list,add,update}`,
  `audit/list`, `message/status`) are still served at 0.1 beside 0.2: every
  SDK before 0.43 speaks only 0.1.

## 0.47.0 (release/0.47)

### Changed — affinidi-messaging-sdk 0.43: the admin console speaks 0.2 (breaking)

- `affinidi-messaging-sdk` 0.43 (affinidi/affinidi-tdk-rs#977), `affinidi-tdk`
  0.35 and (test-mediator's dev-dependency) `affinidi-messaging-didcomm-service`
  0.28. The SDK speaks `ping`, `account/{get,list,add,update}`, `audit/list` and
  `message/status` at 0.2, falling back to 0.1 for a mediator before 0.47.0, and
  returns only the 0.2 types.
- mediator-admin's console and the TUI move to those types: account activity
  times are timestamps rather than Unix seconds, and `audit/list` pages by
  `next_cursor`. mediator-admin exposes them, so this is breaking for it.

### Added — the 0.2 versions are served beside 0.1

- The mediator serves `messaging/ping`, `messaging/account/{get,list,add,update}`,
  `audit/list` and `messaging/message/status` at 0.2 as well as 0.1. A client
  is answered in the version it sent. Each 0.2 request is accepted under its
  own spec's rules, run through the task's one handler, and its reply is
  checked against the 0.2 response schema before it is signed. What differs:
  ping's `serverTime` → `respondedAt`; an account's `lastReceivedAt` /
  `lastAuthenticatedAt` are RFC 3339 strings rather than Unix seconds;
  `audit/list` pages with `limit` / `nextCursor` and drops `truncated`;
  `message/status`'s `at` → `reachedAt`. The TSP arm claims the 0.2 types too.
- `messaging/monitor/event` stays at 0.1: the mediator pushes it on a
  subscription that names no event version.

### Changed — Trust Task types generated at build time (breaking)

- The mediator pins the 31 task versions it serves in `trust-tasks.lock`
  (vendored bundles under `trust-tasks/`, checked by digest) and generates
  their types in `build.rs` with `trust-tasks-build`, as
  `affinidi_messaging_mediator::task_specs`. `trust-tasks-rs` /
  `trust-tasks-proof` 0.35.3 are runtime only (`default-features = false`),
  so the ~900 prebuilt specification modules are no longer compiled.
- mediator-admin and test-mediator take the types they exchange with the SDK
  from `affinidi_messaging_sdk::tasks` (`affinidi-messaging-sdk` 0.42,
  affinidi/affinidi-tdk-rs#976), with `affinidi-tdk` 0.34 and
  `affinidi-messaging-didcomm-service` 0.27. mediator-admin's `specs`
  re-export is now `affinidi_messaging_sdk::tasks::messaging`.
- Wildcard arms over the wire enums (account role, access-list mode) are gone:
  the enums come from a pinned bundle, so a new variant arrives only with a pin
  move, and the match then fails to compile until it is mapped.
- The optional VTA integration still brings `vta-sdk` 0.72, and with it
  `trust-tasks-rs` 0.32 with every family, until it moves to a `vta-sdk` on
  0.35.

### Fixed — a relay leaves a remote recipient's policy to its own mediator

- **Behaviour change (R3.6).** A forward whose next hop is hosted by another
  mediator is no longer checked on the relaying mediator against the next
  hop's `RECEIVE_FORWARDED`, access list, `ANON_RECEIVE` or receive-queue
  limit, and the relay no longer registers an account for it. That account
  was a placeholder made from the relay's `global_acl_default`, so under a
  closed default (`MODE_EXPLICIT_ALLOW`) every cross-mediator forward was
  refused with `73 delivery.refused`, both single (`next` = recipient) and
  double (`next` = recipient's mediator). The recipient's mediator enforces
  all of these, as
  `crates/affinidi-messaging-mediator/docs/multi-mediator.md` §6 lays out. A
  local next hop is checked as before. A relay deployment no longer needs a
  `global_acl_default` that grants `RECEIVE_FORWARDED`.
- An exception: a remote next hop that already holds an account on the relay
  **with access-list entries** still has that list applied. It covers a local
  account wrongly classed as remote, such as a hostname missing from
  `server.local_endpoints`.
- The relay resolves `next` only after its own cheap checks (sender, queue
  limits, attachments, `delay_milli`, forward-queue capacity), so a forward it
  would reject anyway costs no DID resolution. A DID that cannot be resolved
  is treated as local, so it is still checked.
- **Behaviour change (R1.1, R3.6).** When the peer mediator refuses a relayed
  message with a 4xx other than 408, 425 or 429, the forwarding processor
  drops it at once instead of retrying it until `max_retries`. Before, a
  refused message could still be delivered if the recipient changed their
  policy during the retries. The sender gets a problem report with the new
  code `e.p.me.res.forwarding.refused` (args
  `[destination, http_status, endpoint]`), and the monitor reports
  `forwarded` with that outcome. `ForwardOutcome` gains a `Refused { status }`
  variant (the enum is `#[non_exhaustive]`).
- **Fixed: `rewrap` relay of a single forward.** The re-wrap layer was
  encrypted to `next`, which for a single forward is the recipient, not their
  mediator. The receiving mediator therefore could not peel it, and it checked
  the recipient's policy against the relaying mediator's DID. The layer is now
  encrypted to the peer mediator the recipient's DID document names.

## 0.46.0 (release/0.46)

### Changed — trust-tasks-rs 0.35, affinidi-messaging-sdk 0.41 (breaking)

- `trust-tasks-rs` / `trust-tasks-proof` 0.34 → 0.35
  (trustoverip/dtgwg-trust-tasks-tf#910, #912, #917), and with them
  `affinidi-messaging-sdk` 0.41, `affinidi-tdk` 0.33 and (test-mediator's
  dev-dependency) `affinidi-messaging-didcomm-service` 0.26
  (affinidi/affinidi-tdk-rs#975), which require 0.35. mediator-admin and
  test-mediator expose these types, so this is a breaking change for them.
- 0.35 marks superseded spec versions deprecated
  (trustoverip/dtgwg-trust-tasks-tf#921), including the `messaging/*` and
  `audit/list` 0.1 tasks this mediator serves and the admin console calls.
  Nothing changes on the wire: the mediator still serves 0.1, and the modules
  that do so allow the deprecation, with a note. A superseded version is
  withdrawn about 90 days later, so the mediator must serve the 0.2 versions
  beside 0.1 before then (around late January 2027).

## 0.45.0 (release/0.45)

### Changed — trust-tasks-rs 0.34, affinidi-messaging-sdk 0.40 (breaking)

- `trust-tasks-rs` / `trust-tasks-proof` 0.33 → 0.34
  (trustoverip/dtgwg-trust-tasks-tf#884, #901), and with them
  `affinidi-messaging-sdk` 0.40, `affinidi-tdk` 0.32 and (test-mediator's
  dev-dependency) `affinidi-messaging-didcomm-service` 0.25
  (affinidi/affinidi-tdk-rs#972). The SDK requires 0.34, so the two move
  together. None of 0.34 touches anything here; no source change.
- mediator-admin takes an `ATM`, so consumers move to
  `affinidi-messaging-sdk` 0.40 and `trust-tasks-rs` 0.34 with this release.
  The lockfile still holds `affinidi-messaging-sdk` 0.37 / `trust-tasks-rs`
  0.32 beside these through `vta-sdk` 0.72, as before.
- **The mediator (`aws` feature) and mediator-setup no longer enable
  `aws-sdk-s3`'s `sigv4a`.** SigV4a is for S3 Multi-Region Access Points; an
  `s3://` target is a plain bucket and key. It was the only path to `crypto-bigint` 0.5.5
  (RUSTSEC-2026-0387, secret-dependent timing, no 0.5.x fix), which
  `cargo deny` now refuses. Lockfile: `tokio` 1.54.1, `ctutils` 0.4.5 and
  `crypto-bigint` 0.7.6 (RUSTSEC-2026-0386, -0385, -0387).

### Changed — TSP 1.0: affinidi-tsp 0.3, affinidi-messaging-sdk 0.39 (breaking)

- `affinidi-tsp` 0.2 → 0.3, `affinidi-messaging-sdk` 0.39, `affinidi-tdk`
  0.31 and (test-mediator's dev-dependency) `affinidi-messaging-didcomm-service`
  0.24 (affinidi/affinidi-tdk-rs#967). These speak TSP 1.0 (`YTSP-BAA`,
  trustoverip/tswg-tsp-specification#86) in place of Rev 3 (`YTSP-AAC`).
  No source change.
- **Routing reads every TSP version.** Ingress and the monitor address a TSP
  message with `MetaEnvelope::parse`, which in `affinidi-tsp` 0.3 no longer
  gates on MAJOR. A mediator on this release therefore keeps routing Rev 3
  traffic between endpoints that have not upgraded, as well as 1.0 traffic.
  A mediator still on `affinidi-tsp` 0.2 refuses 1.0 messages at ingress, so
  **the mediator upgrades first**, before the VTA and the wallet move to 1.0.
- **A TSP message addressed to the mediator itself must be 1.0.** It is opened
  with `direct::unpack`, which refuses a Rev 3 frame (`RevisionMismatch`) and,
  per 1.0, a confidential payload whose ESSR sender is NULL.
- mediator-admin takes an `ATM`, so consumers move to `affinidi-messaging-sdk`
  0.39 with this release. The lockfile holds `affinidi-messaging-sdk` 0.37 /
  `affinidi-tdk` 0.27 beside these through `vta-sdk` 0.72, as before, without
  the `tsp` feature; no type crosses between `vta-sdk` and the mediator.

### Added — did:scid identities

A `did:scid:vh:1` identity is the DID `did:scid:vh:1:<scid>`; `?src=…` only
says where its did:webvh log is published (VTI-KEY-160 of the VTI
specification). Requires affinidi-did-common 0.4.4 (`scid`),
affinidi-did-resolver-cache-sdk 0.8.43 (native did:scid resolution, durable
version floors) and
didwebvh-rs 0.8.1 (`did_web::to_scid_did_document`,
`DIDWebVHState::convert_scid_id_to_webvh_id`).

- **Behaviour:** accounts, sessions, ACLs, routing, queues and the admin DID are
  keyed by `did_identity::did_hash` (mediator-common), the SHA-256 of the DID
  with a did:scid `src` locator removed, so
  `did:scid:vh:1:<scid>?src=a.example`, `?src=b.example` and the bare DID are
  one account. Every other DID hashes exactly as before: no existing account,
  session or ACL moves. DIDs a party presents are checked against a session,
  the mediator's own DID or a sender with `did_identity::same_account`, which
  ignores the same locator and nothing else.
- **Added (security):** did:scid version floors survive a restart
  (VTI-KEY-162). A moved portable log's former host can serve its pre-move
  log, with keys since rotated away, under the same did:scid; the resolver
  refuses that only after it has verified a newer version. The mediator now
  stores the resolver's source record (sources and latest verified version)
  of every did:scid account, and of its own DID, and seeds them back into the
  resolver at boot. New `MediatorStore::scid_source_put` / `scid_source_list`
  (memory, fjall keyspace `scid_sources`, Redis hash `SCID_SOURCES`); a store
  that does not implement them refuses the write, which is logged.
- **Added:** the mediator's own DID may be a did:scid. With a self-hosted
  did:webvh log (`did_web_self_hosted`) the log is served at `did.jsonl` and
  bridged to did:web at `did.json` exactly as before, and the resolver is
  preloaded with the did:scid's own document (its `id` the bare DID, every
  self-reference under it) and seeded with its source. A log whose SCID is not
  the configured did:scid's is refused at boot.
- **Added (mediator-setup):** `--present-as-scid` / `[identity] present_as =
  "scid"` / a Did-step prompt present a locally generated did:webvh log as its
  did:scid: `mediator_did` is the did:scid DID URL with `src`, and the runtime
  secrets are keyed under the bare did:scid's key ids. The did:webvh default is
  unchanged.
- **Behaviour (mediator-setup):** a locally generated did:webvh log now lists
  its `did:scid:vh:1:<scid>?src=…` alias in `alsoKnownAs` (VTI-KEY-166).
  `--no-scid-alias` / `scid_also_known_as = false` leaves it out. A
  VTA-managed DID is unchanged: vta-sdk 0.72 requests `vta/webvh/dids/create`
  1.1, which carries neither choice.
- **Fixed (mediator-setup):** `did_web_self_hosted` is activated for a did:scid
  mediator DID whose `src` host is the public URL's, as for did:webvh, and
  `--save-did-web` bridges its log.

## 0.44.0 (release/0.44)

### Changed — trust-tasks-rs 0.33, affinidi-messaging-sdk 0.38 (breaking)

- `trust-tasks-rs` / `trust-tasks-proof` 0.32 → 0.33, `affinidi-messaging-sdk`
  0.38, `affinidi-tdk` 0.28 and (test-mediator's dev-dependency)
  `affinidi-messaging-didcomm-service` 0.23. 0.33
  (trustoverip/dtgwg-trust-tasks-tf#858) adds a linking form to
  `persona/contact/put/1.1` and makes `subjectDid` optional in its `get`/`list`
  1.1 responses; none of it touches the mediator. No source change.
  mediator-admin re-exports `trust_tasks_rs::specs::messaging` and takes an
  `ATM`, so consumers move to `trust-tasks-rs` 0.33 and `affinidi-messaging-sdk`
  0.38 with this release. The lockfile holds `affinidi-messaging-sdk` 0.37 /
  `trust-tasks-rs` 0.32 beside these until verifiable-trust-infrastructure
  publishes a `vta-sdk` on 0.38 / 0.33; no type crosses between `vta-sdk` and
  the mediator, so it builds.

### Changed — vta-sdk 0.72

- `vta-sdk` 0.68 → 0.72 (mediator's optional `vta` feature, and mediator-setup).
  0.72 is the release on `trust-tasks-rs` 0.32 / `affinidi-messaging-sdk` 0.37 /
  `affinidi-tdk` 0.27, so the lockfile holds one copy of each again. 0.43.0
  linked a second (0.31 / 0.36 / 0.26) through vta-sdk 0.68; a release
  `rustc` of `trust-tasks-rs` peaks at ~6.7 GB, and two compiling at once ran a
  16 GB runner out of memory. No source change.

## 0.43.0 (release/0.43)

### Changed — trust-tasks-rs 0.32, affinidi-messaging-sdk 0.37 (breaking)

- Moves to `trust-tasks-rs` / `trust-tasks-proof` 0.32,
  `affinidi-messaging-sdk` 0.37, `affinidi-tdk` 0.27 and (test-mediator's
  dev-dependency) `affinidi-messaging-didcomm-service` 0.22. 0.32
  (trustoverip/dtgwg-trust-tasks-tf#818) is breaking: `SealedRecord` gains a
  `version` (#816), the device `Capability` enum gains `sign-document` (#819),
  and rooms `register` 0.2 and `group/remove` 0.3 are new. None of it touches
  the mediator. No source change.
- **API:** the generated Trust Task types are in the public API —
  mediator-admin re-exports `trust_tasks_rs::specs::messaging` as `specs` and
  takes an `ATM` — so consumers must move to `trust-tasks-rs` 0.32 and
  `affinidi-messaging-sdk` 0.37 with this release.
- `vta-sdk` 0.68 (the optional `vta` feature, and mediator-setup) still pulls
  `affinidi-messaging-sdk` 0.36 / `affinidi-tdk` 0.26 / `trust-tasks-rs` 0.31
  beside these until verifiable-trust-infrastructure publishes a `vta-sdk` on
  0.37 / 0.27 / 0.32. No `trust-tasks-rs` type crosses between `vta-sdk` and
  the mediator, so it builds.

### Added — `[storage.fjall] durability`

- `durability = "buffered"` (default, unchanged behaviour) or `"sync"`
  (`STORAGE_FJALL_DURABILITY`). With `"sync"`, a stored message and an
  enqueued forward are synced to disk before the store reports success, so
  an accepted message survives a power loss, not only a process crash. An
  unrecognised value is treated as `"sync"`. Shutdown now always syncs.
- **API:** `FjallTuning` and `FjallConfig` gain a `durability` field, and
  `FjallDurability` is new. Code that builds either struct with a literal
  needs `..Default::default()` or the new field.

### Fixed — Fjall store crash safety and races

- Forwarding: finishing with an entry now acks and deletes it in one write
  (`MediatorStore::forward_queue_ack_and_delete`, a new provided method that
  Fjall overrides with one batch; other backends keep running the two steps
  in turn). A crash between a separate ack and delete used to strand the
  entry, unread, until the queue trim.
- Forwarding retries enqueue the next attempt **before** releasing the old
  entry. In the old order a crash between the two lost the message; now it
  can at worst be delivered twice. If the re-enqueue fails the old entry stays
  claimed for autoclaim instead of being reported abandoned.
- Fjall: autoclaim drops a claim whose queue entry is gone rather than
  re-claiming it forever.
- Fjall: the expiry sweep removes expiry-index keys whose message is gone
  (the delivered-TTL deadline outlived its message and was rescanned on every
  sweep). A store error during the sweep now keeps the key for the next sweep
  instead of being counted as already deleted.
- Fjall: session expiry (the sweep and the lazy check in `get_session`)
  re-reads the session under the write lock, so a session refreshed since the
  scan is not removed.
- Fjall: `account_remove` purges messages stored while it was running; the
  OOB-invite counters, `oob_discovery_delete` and `streaming_set_state` take
  the write lock.

### Fixed — forwarding-abandonment reports reach live senders

- When the forwarding processor gives up on a relay, the problem report it
  stores in the sender's inbox now also gets a live notification. A sender
  with an open websocket used to see nothing until an unrelated message woke
  it. **Behaviour change (R3.6):** live DIDComm clients now receive this
  report as a pushed message rather than only on pickup.

### Fixed — live notification is published after the message is stored

- **Behaviour change in delivery ordering (R3.6).** The mediator now stores a
  message before publishing its live notification, for client deliveries,
  mediator replies and forwarded messages alike. Previously the notification
  went first, so a raw-TSP websocket — which drains its inbox on the
  notification — could drain before the store landed and leave the message
  stranded until an unrelated wake-up (often a ~30 s client timeout).
- Consequences consumers may notice:
  - A live frame now always refers to a stored message, so an `auto_delete`
    of a live-delivered message can no longer race the store and miss.
  - If the store fails, no live frame is sent (previously the recipient could
    receive a frame for a message that was never stored). This includes
    `force_live_delivery` pickup replies. The sender still gets the store
    error.
- The traffic monitor reports a `delivered` event for a stored message only
  when its live notification was actually published; a failed publish now
  shows as stored only (R1.1).
- `MemoryStore::with_store_delay` adds random per-store latency for tests;
  it panics on an inverted range.

### Fixed — monitor reports a live delivery only once it is queued to the socket

- The traffic monitor's `delivered` event for a live-streamed message is now
  emitted by the streaming task when the notification is actually queued to
  the recipient's socket, instead of at store time (R1.1). A push dropped for
  a full send queue or byte budget, or never published, is no longer
  reported as delivered. Behind a shared Redis the event now comes from the
  instance holding the socket.
- **API (mediator-common):** `PubSubRecord` gains `stored:
  Option<StoredMessageRef>` (`#[serde(default)]`, wire-compatible across
  versions in both directions); code building it with a literal needs the
  new field. `MediatorStore::streaming_publish_stored` is a new provided
  method; its default publishes untagged, so a third-party store keeps
  delivering but reports no live `delivered` events until it implements it.
- During a rolling upgrade, live deliveries published by an older instance
  are not reported as `delivered`.

### Fixed — monitor batches no longer lost at a live-stream timeout

- `Cargo.lock` takes `affinidi-messaging-sdk` 0.36.2
  ([affinidi-tdk-rs#954](https://github.com/affinidi/affinidi-tdk-rs/pull/954)).
  A frame arriving just as a `live_stream_next` wait timed out could be
  discarded by the SDK. A monitor batch is never stored, so one lost there
  was gone for good. This made
  `the_monitor_follows_a_message_from_arrival_to_deletion` fail about one run
  in ten (now 0 of 30). The requirement stays `0.36`; only the lockfile, and
  therefore the mediator binary and images, change.

### Fixed — REST messages over 2 MiB, and silent raw-TSP refusals

- **REST `/inbound` refused every body over 2 MiB**, whatever `http_size` and
  `message_size` said. The handler takes the body as axum's `Bytes`, which
  applies axum's own 2 MiB default on top of `RequestBodyLimitLayer`.
  `/inbound` now buffers up to `message_size` when that is larger (other
  routes keep axum's default), so default deployments are unchanged. Only
  deployments that raised `message_size` above 2 MiB were affected.
- **A message refused on a raw-TSP websocket was dropped silently.** The
  sender's write had already succeeded and a raw-TSP socket has no error
  frame, so it was never told (R1.1). The mediator now closes the socket with
  a code saying why: **1009** for a message over `message_size`, **1013** to
  retry later (any server-side failure), **1008** for any other refusal.
  A TSP frame refused on a DIDComm websocket now gets a problem report, as a
  DIDComm message there already did. **Behaviour change (R3.6):** a raw-TSP
  client that sends an unacceptable message now sees its socket closed and
  must reconnect.

### Added — test-mediator size limits, Redis, and a message-size sweep

- `TestMediatorBuilder::message_size`, the in-process equivalent of
  `LIMIT_MESSAGE_SIZE` (raising `http_size`/`ws_size` to match).
- A `redis-backend` feature on `affinidi-messaging-test-mediator`, so a test
  can run the in-process mediator on a `RedisStore`.
- `tests/size_sweep.rs` (opt-in, `--ignored`): DIDComm and TSP at sizes from
  1 KB to past the limit, over REST, websocket, raw-TSP socket, live delivery,
  pickup and cross-mediator paths, on memory, Fjall and (with `REDIS_URL`)
  Redis. Anything within `message_size` must arrive byte for byte; anything
  over must be refused in a way the sender sees.

### Fixed — a TSP-only mediator builds and serves TSP clients

- **`tsp` without `didcomm` did not compile**, although the features were
  documented as independent. Trust Tasks, mediator administration, monitor
  subscriptions and the authentication challenge were gated on `didcomm`
  even where TSP uses them. They now build with either protocol; only the
  DIDComm bindings stay `didcomm`-only. `tsp` now pulls in the Trust Task
  dependencies (`trust-tasks-rs`, `trust-tasks-proof`,
  `affinidi-data-integrity`).
- **A TSP-only mediator now has the routes a pure-TSP client needs.**
  `/inbound` and `/authenticate/challenge` exist whenever either protocol is
  built, and `/tsp/authenticate` whenever `tsp` is (it used to need both).
  `/authenticate`, `/authenticate/refresh` and `/oob` remain DIDComm-only.
  Builds with `didcomm` serve exactly the routes they did before.
- CI gains a `tsp-only` job (clippy over all targets for each backend, and
  the unit tests), since every other job builds with `didcomm` on.

## 0.42.0 (release/0.42)

### Moved — the mediator has its own repository

- The mediator, `affinidi-messaging-mediator-common`, `-config`,
  `-processors`, `mediator-setup`, `affinidi-messaging-test-mediator`,
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-mediator-tui`
  moved out of [affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs)
  with their history, and are released from here on a
  main → nightly → `release/X.Y` flow (see [RELEASES.md](RELEASES.md)).
- **Lockstep versioning from 0.42.0.** Every crate jumps to 0.42.0 and moves
  together from now on. This is a minor bump for every crate, so consumers
  pinned at `0.41`, `0.17`, `0.22` or `0.11` must update their requirement to
  `0.42`. No API changes come with the move itself.
- TDK crates (`affinidi-messaging-sdk`, `affinidi-messaging-didcomm`,
  `affinidi-tsp`, `affinidi-tdk`, …) are now crates.io dependencies. The SDK
  requirement is `0.36.1`, the first release that takes the protocol types
  from `affinidi-messaging-mediator-types` instead of depending on
  mediator-common, so no second mediator-common copy enters the graph.
- `affinidi-messaging-test-mediator` gained the didcomm-service end-to-end
  tests (`soft_restart_websocket`, `tsp_live_stream`, `tsp_transport_adapter`,
  `tsp_invite_then_payload`) and the `docker_smoke` example, which lived in
  affinidi-tdk-rs only because the mediator did.
- Docker images keep the name `ghcr.io/affinidi/messaging-mediator` and are
  now tagged `vX.Y.Z`. Release candidates never move `:latest`.
