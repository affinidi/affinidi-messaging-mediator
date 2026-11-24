### Changed — trust-tasks 0.41 and the affinidi-tdk 0.50 generation

- affinidi-messaging-sdk 0.50 -> 0.51 and affinidi-tdk 0.49 -> 0.50. The
  mediator's generated task types come from the SDK, so trust-tasks-rs and
  trust-tasks-proof move with it from 0.40 to 0.41.
- The `vta` feature moves to vta-sdk 0.93, on the same generation. The
  workspace now resolves a single trust-tasks-rs (0.41); the second copy that
  vta-sdk 0.92 brought in is gone.
- trust-tasks-build 0.2.2 for the mediator's build script; the test mediator's
  didcomm-service tests move to affinidi-messaging-didcomm-service 0.39.
- No wire or API change: the Trust Task envelopes the mediator accepts and
  emits are unchanged.
- The vti-specs-* crates move to their trust-tasks-build 0.2.2 patch releases
  (core 0.7.1, rooms 0.11.1, vta 0.12.1, vtc 0.8.1, vtn 0.4.1), so
  trust-tasks-build resolves once too and its allow-list entry is gone.
