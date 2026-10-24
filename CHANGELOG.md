# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## Unreleased

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
