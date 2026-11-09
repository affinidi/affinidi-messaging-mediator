# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## Unreleased

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
  Only the exact value `"true"` enables it; anything else is off. This build
  implements the grant storage only, so a mediator with `enabled = "true"`
  **refuses to start** with an error naming the setting, rather than accept a
  setting it cannot honour. It also refuses on a backend without mux support.
- Removing an account removes its mux grants on both sides (as a member DID
  and as a principal), whether or not mux is enabled at the time.

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
