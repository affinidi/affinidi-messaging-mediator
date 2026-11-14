### Breaking — the mediator's `vta` feature is no longer a default, and cannot be enabled in this release (R3.6)

- `affinidi-messaging-mediator`'s `default` features are now `didcomm`, `tsp`,
  `redis-backend` and `jemalloc`. `vta` (VTA-backed key management: operating
  secrets fetched from a Verifiable Trust Agent at boot, periodic refresh,
  `mediator rotate-admin`) is no longer one of them.
- The feature stays defined, but enabling it stops the build with a
  `compile_error!`: `vta-sdk` is out of this workspace's dependency graph.
  Every published `vta-sdk` (up to 0.88.x) pulls `trust-tasks-proof`
  0.36/0.37. Those no longer compile once `affinidi-data-integrity` unifies to
  0.8.7, which `trust-tasks-proof` 0.39 requires, because 0.8.7 moved its
  public `KeyType` from `affinidi-crypto` 0.2 to 0.3.
- A deployment that boots from a VTA (`[vta]` configuration, the
  `mediator_admin_credential` linking the mediator to a VTA) must stay on the
  previous release until `vta` returns. Self-hosted mediators (operating
  secrets from the secret backend's well-known entry) are unaffected: that path
  never used `vta-sdk`.
- Release order across the two repositories:
  1. This release ships without `vta-sdk`, on `affinidi-messaging-sdk` 0.47 /
     `affinidi-tdk` 0.45.
  2. verifiable-trust-infrastructure releases `vta-sdk` on that line (it
     depends on `affinidi-messaging-test-mediator` from step 1).
  3. The next mediator release restores the `vta-sdk` dependency, puts `vta`
     back into `default`, and turns the setup wizard's VTA flows back on.

### Breaking — the setup wizard's VTA flows are unavailable in this release

- `mediator-setup` is built without VTA integration. Its new `vta` feature is
  off by default and, like the mediator's, cannot be enabled until `vta-sdk`
  returns.
- The interactive wizard's VTA step offers only "No VTA", and says why. The
  deployment defaults no longer pick a VTA-managed setup: they start from
  `did:peer`, with no VTA.
- Every VTA path is refused with that reason and exit code 5
  (`NO_VTA_SESSION`):
  - `--setup-key-out` and `--setup-key-file`.
  - A recipe with `use_vta = true`, including the sealed-mint and
    sealed-export modes and `--bundle`.
  - `did_method = "vta"`.
- A self-hosted `did:webvh` is generated as before. Its DID document is the one
  the built-in `didcomm-mediator` template renders, now built locally instead
  of through `vta-sdk`'s template renderer.
- The build commands the wizard renders (Dockerfile, `cargo install`,
  `cargo build`) no longer list the mediator's `vta` feature.

### Breaking — images built from this release have no VTA integration

- The container image builds the mediator's `default` features, which no
  longer include `vta`, and `mediator-setup` without VTA flows. An image from
  this release cannot boot a mediator from a VTA or run the wizard's VTA
  setup. Use an earlier image for a VTA-linked deployment until `vta` returns.

### Breaking — `affinidi-messaging-sdk` 0.47, `affinidi-tdk` 0.45, `trust-tasks-rs` 0.39, `affinidi-crypto` 0.3 (R3.6)

- The workspace moves to the current TDK line:
  - `affinidi-messaging-sdk` 0.47.2, from 0.46.3.
  - `affinidi-tdk` 0.45.0, from 0.43.0 (mediator-setup, test-mediator).
  - `affinidi-messaging-didcomm-service` 0.32.0, from 0.31.0 (test-mediator
    dev-dependency).
  - `trust-tasks-rs` and `trust-tasks-proof` 0.39.0, from 0.38.0. This is the
    version `affinidi-messaging-sdk` 0.47.2 requires, so one copy of each
    crosses the SDK boundary. 0.39 is 0.38 rebuilt on `affinidi-crypto` 0.3.
  - `affinidi-crypto` 0.3, from 0.2.
  - The floors that move with them: `affinidi-data-integrity` 0.8.7,
    `affinidi-did-common` 0.4.7, `affinidi-messaging-didcomm` 0.15.14,
    `affinidi-messaging-didcomm-v1` 0.2.4 (on `affinidi-crypto` 0.3),
    `affinidi-messaging-core` 0.1.12, `affinidi-did-resolver-cache-sdk`
    0.8.53, `affinidi-secrets-resolver` 0.5.18.
- **Library users:** `trust-tasks-rs` and SDK types cross these crates'
  public APIs. Examples are the generated
  `affinidi_messaging_mediator::task_specs` and the SDK's `ATM` /
  `ATMProfile` / `ATMError` taken and returned by
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-test-mediator`.
  A crate that passes such values to or from these crates must itself move
  to `trust-tasks-rs` 0.39, `affinidi-messaging-sdk` 0.47 and
  `affinidi-crypto` 0.3, or it gets mismatched types from two copies.
- No source change was needed in the mediator, the admin client, the console
  or the test mediator. The wire protocol is unchanged, and clients on earlier
  SDKs see no difference.
- Every `affinidi-*` and `trust-tasks-*` crate now resolves once. The four
  duplicates `vta-sdk` 0.77 brought (`affinidi-messaging-sdk` 0.44,
  `affinidi-tdk` 0.36, `trust-tasks-rs` / `trust-tasks-proof` 0.36) left with
  it, and their allow-list entries are gone.
