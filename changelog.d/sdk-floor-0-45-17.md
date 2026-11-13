### Fixed — the crates require the SDK release whose APIs they use

- `affinidi-messaging-mediator`, `-admin`, `-tui` and `-test-mediator` now
  require `affinidi-messaging-sdk` 0.45.17 rather than any 0.45.x. They use
  the mux admin, socket-ack and monitor subscribe 0.2 APIs added in
  0.45.13–0.45.17, so a downstream lockfile still on an older 0.45 patch
  failed to compile inside these crates instead of being upgraded by cargo.
