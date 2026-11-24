### Changed — vta-sdk 0.92 and jsonwebtoken 12

- The `vta` feature moves from vta-sdk 0.90 (affinidi-tdk 0.45 generation) to
  vta-sdk 0.92, which is on the affinidi-tdk 0.49 generation like the rest of
  the workspace. The second copy of the affinidi stack that vta-sdk 0.90
  brought in is gone. vta-sdk 0.92 uses trust-tasks-rs 0.41; this workspace
  stays on 0.40 until affinidi-messaging-sdk 0.51 (affinidi-tdk-rs#1189) is
  published. No type crosses between the two.
- jsonwebtoken 11 -> 12 for the mediator's session JWTs. The mediator signs
  and verifies them with Ed25519 keys only, so token format and validation are
  unchanged.
