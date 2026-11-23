### Breaking — Built on the affinidi-tdk 0.49 generation

- The workspace moves to affinidi-tdk 0.49 and the crates released with it:
  affinidi-messaging-sdk 0.50, affinidi-messaging-didcomm 0.16,
  affinidi-messaging-didcomm-v1 0.3, affinidi-data-integrity 0.9,
  affinidi-secrets-resolver 0.6, affinidi-did-common 0.5,
  affinidi-did-resolver-cache-sdk 0.9, affinidi-crypto 0.4,
  affinidi-encoding 0.2, affinidi-tdk-common 0.8 and affinidi-tsp 0.5.
  Trust Tasks move to trust-tasks-rs / trust-tasks-proof 0.40 and
  trust-tasks-build 0.2; didwebvh-rs to 0.8.3. Types from these crates appear
  in this workspace's public API, so a consumer must be on the same
  generation.
- The `vta` feature still uses vta-sdk 0.90, which is on the 0.45 generation,
  until a vta-sdk on 0.49 is published. Operating secrets cross that boundary
  as multibase strings, so the two generations never share a type. The
  lockfile pins `trust-tasks-proof` 0.40 and `didwebvh-rs` to the 0.49
  generation.
- affinidi-messaging-test-mediator: `live_stream_get` now takes
  `Option<Duration>`, following affinidi-messaging-sdk 0.50.

### Removed — `WrapperType`

- The deprecated `messages::WrapperType` enum is gone. Nothing in the mediator
  used it; a handler's outcome is `ProcessMessageResponse`.

### Changed — Rust 1.100.0 toolchain

- `rust-toolchain.toml` pins Rust 1.100.0, matching
  verifiable-trust-infrastructure. The minimum supported Rust stays 1.95.0.
