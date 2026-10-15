# Changelog

Workspace-wide release notes. Every crate in this repository carries the same
version, so a release has one entry here. The per-crate `CHANGELOG.md` files
hold the history from before the move (up to mediator 0.41.2,
mediator-common 0.17.7, test-mediator 0.22.0, mediator-admin and
mediator-tui 0.11.0); they are no longer updated.

## Unreleased

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
