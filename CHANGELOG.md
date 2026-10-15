# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## Unreleased

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
