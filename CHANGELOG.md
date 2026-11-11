# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## Unreleased

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

### Changed — a forward is delivered only to a next hop that has an account

- A forward never creates an account. A local next hop with no account on
  this mediator is refused with `73 delivery.refused`; it used to be
  registered with `global_acl_default`, in either `mediator_acl_mode`. A
  recipient gets its account by authenticating (or from an admin) before
  forwards to it are accepted.
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

### Added — `TestMediatorBuilder::replica_of`

- A test mediator can run as a second instance of another: the same DID,
  keys and session-token key, on its own port with its own streaming task.
  Paired with a shared Redis store, that gives two instances of one
  mediator, as behind a load balancer. `tests/mux_two_instances.rs` uses
  it: a member grants, sends and revokes through one instance while the
  principal's mux socket is on the other. It found both bugs above, and
  runs in CI against standalone Redis and a Redis cluster.

### Fixed — database URL credentials are hidden in debug output

- The configuration printed at startup showed `database.database_url` in
  full, including any password it carries (`redis://:password@host/`). The
  `Debug` output of `DatabaseConfig` and `DatabaseConfigRaw` now shows
  `redis://***@host/`, as `config/show` already did, and so does the
  "Database URL is invalid" error. The helper is shared as
  `affinidi_messaging_mediator_common::redact::redact_url`.

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

### Changed — affinidi-messaging-sdk 0.45.5

- The SDK now checks mux events on DIDComm sockets: the mediator must have
  authcrypted them, and they must be addressed to the principal. It also
  keeps each connection's member set (`ATMProfile::mux_members()`,
  `TspMuxWebSocket::members()`). `tests/mux_sdk.rs` checks that set
  against this mediator: grants, an attach, a narrowed grant, a member
  inactive while its own socket is up, and a revoke.

### Fixed — global sent counters on Redis

- On the Redis backend, fetching a message by id never counted it in the
  global `SENT_COUNT`/`SENT_BYTES` stats: the `HINCRBY` for `SENT_COUNT`
  had no key, so Redis refused the whole `MULTI`. Both counters now move,
  and the store conformance suite checks it.

### Changed — affinidi-messaging-sdk 0.45.4

- The SDK now has a `tsp-mux` client (`TspOps::connect_websocket_mux`), and
  parses `connectionFull` events. `tests/tsp_mux.rs` drives a raw-TSP mux
  connection through it end to end, beside the tests that drive the wire
  by hand.

### Fixed — resync status honours the `pickup` scope

- On a DIDComm mux connection, a member whose live pushes dropped was sent
  a pickup `status` for its inbox even when its scope lacked `pickup`,
  telling the principal that inbox's counts. A status is message pickup, so
  it is now sent only for a member holding `pickup`. A `receive`-only
  member's dropped frames stay in its inbox, as before. The `tsp-mux` drain
  already skipped such members.

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

### Added — DID multiplexing grant storage (no behaviour change yet)

- Storage for DID multiplexing grants: a member DID's signed permission for a
  *principal* connection to collect its messages (design:
  `design-docs/mediator-did-multiplexing-design.md`). Every grant rule (epoch,
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
