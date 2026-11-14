# DID multiplexing

DID multiplexing ("mux") lets one authenticated WebSocket carry live
delivery, pickup, acknowledgement and sending for many DIDs. A client that
holds many DIDs (one per relationship, say) opens one connection instead of
one per DID.

- The **principal** is the DID that authenticated the connection.
- A **member** is another DID the connection carries. Each member signs a
  statement allowing the principal to do this, within a **scope** it names.
- The member's messages are still its own: they are stored in its inbox,
  encrypted to its keys, and a frame it sends is still signed or authcrypted
  with its keys. The principal only collects and presents them.

Mux is **off by default**. It is served on the Redis, Fjall and in-memory
backends, over DIDComm and raw TSP. The code is in `src/mux/`; grant storage
rules are in `affinidi-messaging-mediator-common/src/store/mux.rs`. The
wire formats are the `messaging/mux/*` Trust Task specifications pinned in
`trust-tasks.lock` (bundles under `trust-tasks/messaging/mux/`).

## Enabling it

```toml
[limits.mux]
enabled = "true"
```

Only `"true"` turns it on; an absent table or empty value leaves it off, and
any value other than `"true"`/`"false"` refuses to start. With it on, the
mediator refuses to start when live streaming (`[streaming]`) is disabled,
because members are carried by live delivery (`start_mux` in `src/server.rs`).

When mux is off, every `messaging/mux/*` task answers `unsupportedType`, the
mux subprotocols are never selected, and `messaging/stats/show` carries no mux
counts.

### `[limits.mux]` settings

Every key has an environment override `LIMIT_MUX_<KEY>`. Defaults are in
`affinidi-messaging-mediator-config/src/defaults.rs`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns mux on. |
| `max_dids_per_connection` | `1000` | Members one connection may carry. Beyond it a member is refused (`memberQuota` on attach, `connectionFull` for a grant). |
| `max_grants_per_principal` | `5000` | Stored grants naming one principal. A resource bound, checked before the store write, so concurrent grants can overshoot it slightly. |
| `max_grants_per_did` | `16` | Stored grants on one member DID. |
| `max_grant_lifetime_secs` | `2592000` (30 days) | Longest `exp - iat` a grant may have. |
| `max_attach_lifetime_secs` | `86400` (1 day) | Longest lifetime of a session attach. |
| `revalidate_interval_secs` | `900` | How often each connection re-checks its grant members' signing keys against their DID documents. |
| `max_channel_slots` | `512` | Send-queue depth of one connection across all its DIDs. Must be 8 to 65536. |
| `dead_retention_secs` | `604800` (7 days) | How long a dead grant (suspended, stale key, expired, epoch-revoked) stays listable before it is pruned. |

## Opening a mux connection

A client asks for a mux connection with a WebSocket subprotocol, alongside its
`bearer.<jwt>` entry. The mediator echoes a mux subprotocol only when it will
actually multiplex the socket, so a client can rely on the echo
(`src/handlers/websocket/mod.rs`).

| Wire | Client offers | Selected when |
|---|---|---|
| DIDComm | `didcomm-mux` (or the provisional `affinidi-mux` that SDK 0.45.1 and 0.45.2 offer; `didcomm-mux` wins when both are offered) | mux is enabled and the socket is not a raw-TSP socket |
| Raw TSP | `tsp`, `tsp-ack`, `tsp-mux`, in that order | a `tsp` build, mux enabled and the streaming task running |

`tsp-mux` implies `tsp-ack` (delete-to-ack) delivery. Because the client lists
`tsp` first, an older mediator that reflects the offer selects plain `tsp`,
and the client learns it is not multiplexed. A mux subprotocol that is not
selected is stripped from the echo.

On a DIDComm mux connection, events are DIDComm messages authcrypted by the
mediator to the principal (Text frames). On `tsp-mux`, events are TSP Direct
messages from the mediator's VID to the principal's (Binary frames). If the
`ready` event cannot be sealed, the socket closes with 1011.

### Events (`messaging/mux/event`)

Live, unstored events from the mediator to the principal:

| Event | When | Carries |
|---|---|---|
| `ready` | First frame on the connection | `sessionId`, `muxNonce` (32 random bytes, base64url), `sessionExpiresAt`, the limits (`maxDidsPerConnection`, `maxGrantLifetimeSeconds`, `maxAttachLifetimeSeconds`), `pendingNotices` |
| `attached` | Members joined: stored grants admitted on connect, a grant stored while connected, an attach, a member reactivated | Per member: `did`, `reason`, `scope`, `expiresAt`, `deliveryActive` |
| `detached` | Members left, or a valid grant was not carried | Per member: `did`, `reason`, `grantId` |
| `refused` | (`tsp-mux` only) an inbound frame was refused; the socket stays open | `frameId` (hex SHA-256 of the frame bytes), `code`, and where readable `sender`, `receiver`, `reason` |

Attach reasons: `connect`, `grant`, `attach`, `reactivated`. Detach reasons:
`revokedByMember`, `revokedByPrincipal`, `epochBumped`, `suspendedUnknownKey`,
`keyRotated`, `expired`, `accountBlocked`, `superseded`, `admin`,
`detachRequested`, `accountRemoved`, `resolutionFailed`, `connectionFull`.

`deliveryActive: false` means the member's own direct socket is online and
keeps its live traffic: a DID's own socket always outranks a mux connection
carrying it. The member stays on the connection, inactive, and is reported
`reactivated` (with an inbox redelivery) when its own socket goes away. A
mux connection is never closed because of one of its members.

## How members join

Every admission is a member-signed **statement**: a closed JSON object whose
`issuer` is the member DID, with an embedded W3C Data Integrity proof
(`eddsa-jcs-2022` or `eddsa-rdfc-2022`) made with one of the member's
`authentication` keys. Statements are bound to this mediator (`audience`) and
to the principal, have `iat` / `exp` (60 s of clock skew allowed) and an
explicit, non-empty scope. Verification is in `src/mux/proof.rs`.

There are two kinds:

- **Session attach** (`messaging/mux/attach`). Bound to one connection by its
  `sessionId` and the `muxNonce` from `ready`, and gone when the connection
  closes. Sent by the principal on the mux connection it applies to.
- **Stored grant** (`messaging/mux/grant`). A standing permission, valid on
  any connection of the principal until it expires or is revoked. It may be
  presented by the member or by the principal it names. Stored grants are
  admitted every time the principal connects, and a grant stored while the
  principal is connected is carried at once (`attachedNow` in the response).

A member is admitted only if its account exists, is not blocked, and its own
ACLs cover the scope: `LOCAL`, plus `RECEIVE_MESSAGES` for `receive`,
`pickup` and `delete`, and `SEND_MESSAGES` for `send`
(`check_scope` in `src/mux/grants.rs`). A scope never exceeds what the member
could do on its own connection.

### Scopes

| Scope | Lets the connection |
|---|---|
| `receive` | Get the member's live messages pushed. |
| `pickup` | Make message-pickup `status` / `delivery` requests naming the member as `recipient_did`, and include the member in a `tsp-mux` inbox drain. |
| `delete` | Delete (acknowledge) the member's stored messages: `messaging/mux/ack`, `messages-received`, `DELETE /delete`. Without it, a member's messages stay in its inbox. |
| `send` | Submit frames whose sender is the member. The frame is checked against the member's own ACLs and limits and is the member's from then on. Messages to the mediator itself (pickup, Trust Tasks, administration) are not accepted for a member. |

A `pickup`-only member is never pushed messages; new mail raises a resync
for it instead (a pickup `status` naming it on DIDComm, a drain of its inbox
on `tsp-mux`), at most every 5 s.

### Grant lifecycle

Each member DID has one record holding its **epoch**, its grants and a replay
floor per principal. All rules (epoch, replay floor, quotas, narrow-only
updates, suspension, expiry) are applied in one place, then written with a
compare-and-swap, so the backends cannot disagree.

| State | Meaning |
|---|---|
| `active` | Valid; admitted whenever the principal connects. |
| `suspended` | The member proved control with a key that signed none of its active grants (the unknown-key rule). Terminal: the member must sign a new grant. |
| `staleKey` | The signing key left the member's `authentication` keys. Terminal. |
| `expired` | Past its expiry; computed on read. |
| `epochRevoked` | The member (or an administrator) advanced its epoch. |

A grant removed with `messaging/mux/revoke` is deleted, and the replay floor
stops the same statement from being stored again. The **unknown-key rule**
also runs on direct authentication: a DIDComm login whose authcrypt key is
not among the `keyAgreement` keys recorded with the member's grants, or a TSP
login whose signing key signed none of them, suspends those grants before the
login answers. If that check cannot run within 5 s, the login is refused as
retryable (503, counted in `mux_login_check_failures_total`).

## Trust Tasks

All are served over DIDComm and TSP through the normal Trust Task path, and
only when mux is enabled.

| Task | Who | What |
|---|---|---|
| `messaging/mux/grant` | member or principal | Store or replace grants. Refusals are per grant. |
| `messaging/mux/list` | principal, or a proven member | List the grants held as principal, or those on a member DID, a page at a time. |
| `messaging/mux/update` | grant party | Narrow a grant (smaller scope, earlier expiry) without a new signature. Widening is refused. |
| `messaging/mux/revoke` | principal or member | Delete named grants. |
| `messaging/mux/revoke-all` | member (signed statement) | Advance the member's epoch: voids every grant on it and ends its session attaches. |
| `messaging/mux/attach` | principal, on the mux connection | Admit members by attach statement. |
| `messaging/mux/detach` | principal, on the mux connection | Remove session attaches. |
| `messaging/mux/ack` | principal, on the mux connection | Acknowledge up to 100 delivered frames by id; answer is `acked` / `refused` (`notFound`, `notPermitted`). Pushed to the socket, never stored. |
| `messaging/mux/event` | mediator to principal | The live events above. |
| `messaging/mux/notice` | mediator to recipient | Durable notices (below). |
| `messaging/mux/connections` | administrator | This instance's live mux connections with their members. |
| `messaging/mux/admin-list` | administrator | Stored grants of a principal, a member, or between the two, without signed statements. |
| `messaging/mux/admin-revoke` | `admin` / `rootAdmin` | Revoke other accounts' grants, at most 500 per request. An `admin` cannot touch a grant involving a `rootAdmin`. |
| `messaging/mux/admin-revoke-all` | `admin` / `rootAdmin` | Advance a member's epoch, compare-and-set on the epoch named. Reported with reason `admin`. |

`attach`, `detach` and `ack` sent off a mux connection are refused with
`messaging/mux:notMuxConnection`. Error codes are listed in
[ERRORS.md](../ERRORS.md#trust-task-errors).

Revocations, epoch advances, suspensions and narrowings detach (or re-scope)
the affected members on every connection on this instance **before** the
response is sent.

## Notices (`messaging/mux/notice`)

Durable, signed notices stored in the inbox of whoever must act, delivered at
least once and acknowledged by deleting them. `ready.pendingNotices` counts
those waiting for the principal. Each is sealed for the wire its recipient
last used (DIDComm or TSP).

| Notice | To | When |
|---|---|---|
| `grantsSuspended` | principal | The unknown-key rule suspended its grants. |
| `grantsRevoked` | principal | A grant was revoked by its member, voided by an epoch advance, removed with the member's account, or revoked by an administrator. Not sent when the principal revoked it itself. |
| `grantsExpiring` | principal | An active grant passed about three quarters of its lifetime. |
| `grantsPresent` | member | Grants exist on the member DID (counts only, no principal DIDs). |

A notice is stored only after the change it reports is committed. `messaging/mux/list`
remains the source of truth.

## Delivery on a mux connection

- **Fair queuing.** Each DID on the connection (principal included) may have
  at most 8 frames queued, and the connection at most `max_channel_slots`.
  The socket writes round-robin across DIDs with frames waiting. When one
  member's share is full only its push is dropped (counted in
  `mux_queue_fairness_skips_total`), and it gets a resync for its own inbox.
- **Scope at write time.** Each live frame is checked against the member's
  scope when it is written, so narrowing away `receive` stops pushes at once.
- **`tsp-mux` drain.** On connect the principal's inbox is drained first,
  then the members holding `pickup`, round-robin, one page per member per
  round. A drain yields to waiting live frames between pages. Nothing is
  deleted on send; frames stay stored until acknowledged.
- **Acknowledgement.** `messaging/mux/ack` (or a REST delete on the
  connection's session) removes the copy held for the principal or for a
  member holding `delete`, never a copy one of them sent to someone else.

## Re-checks

Each connection runs, off its socket loop:

| Pass | Interval | Checks |
|---|---|---|
| Sweep | 30 s | Expires members past their expiry; drops grant members whose stored grant is no longer active. |
| Key re-validation | `revalidate_interval_secs` | Each grant member's signing key is still an `authentication` key (`keyRotated` otherwise; an unresolvable DID is kept until a later check). |
| Standing | 30 s | Each member's account still exists, is not blocked, and its ACLs still cover its scope (`accountRemoved` / `accountBlocked`). |

Account changes made through `account/update` or `account/remove` are applied
at once, and standing is also checked when a request is made for a member.

## Several instances

With several instances sharing one Redis:

- After a local change, the handling instance publishes a change record
  (hashes only) on the store's mux pub/sub channel. The `mux_sync` task on
  every other instance re-reads the affected members' records and applies
  the change to its own connections within one pub/sub hop, with the same
  reason. The 30 s sweep is the backstop if a record is lost.
- A mux connection does not take a DID whose direct socket is on another
  instance; it holds the member inactive and takes it over when that socket
  leaves, or when that instance is found dead (heartbeat expired).
- `messaging/mux/connections` and the `stats/show` mux counts cover only the
  instance answering (`coverage: thisInstance`). Fjall and in-memory stores
  are single-process.

## Observability

Metrics on `/metrics` (no label carries a DID):

| Metric | Type | Labels |
|---|---|---|
| `mux_connections` | gauge | `wire` = `didcomm` / `tsp` |
| `mux_members` | gauge | `source` = `grant` / `attach` |
| `mux_detach_total` | counter | `reason` (detach reasons above) |
| `mux_grant_revalidate_failures_total` | counter | `cause` = `resolution` / `store` |
| `mux_queue_fairness_skips_total` | counter | — |
| `mux_live_frames_withheld_total` | counter | `outcome` = `nudge` / `drop` |
| `mux_login_check_failures_total` | counter | — |
| `streaming_entries_reclaimed_total` | counter | `kind` = `direct` / `mux`, `reason` |
| `monitor_fanout_dropped_total`, `monitor_fanout_received_total` | counter | membership events across instances |

Also:

- `messaging/stats/show` reports this instance's connections and members under
  `ext["com.affinidi.mux"]`.
- The audit log (`audit/list`) records `mux_grant_revoke`, `mux_revoke_all`
  and `mux_grant_suspend`, and the administrator tasks' revocations.
- `messaging/monitor/subscribe` 0.2 with a `membership` filter streams
  member attach/detach events (metadata only).

## Administration

- `mediator-console` has a **Mux** tab (live connections and their members)
  and a **Grants** tab (list a principal's or member's grants, revoke one or
  all, advance a member's epoch), and its monitor shows membership changes.
- `affinidi-messaging-mediator-admin` exposes the same through
  `MediatorConsole::mux_connections`, `mux_grants`, `mux_revoke`, `mux_epoch`
  and `mux_bump_epoch`, plus the self-service `mux_grant`, `mux_own_grants`,
  `mux_revoke_own` and `mux_revoke_all_own`.
- Removing an account removes its grants on both sides, whether or not mux is
  enabled at the time.

## Clients

`affinidi-messaging-sdk` opens mux connections on both wires, signs
statements and keeps each connection's member set
(`ATMProfile::mux_members()`, `TspMuxWebSocket::members()`). The end-to-end
tests in `crates/affinidi-messaging-test-mediator/tests/e2e/mux_*.rs` and
`tsp_mux*.rs` exercise every behaviour described here, including two-instance
runs against Redis.
