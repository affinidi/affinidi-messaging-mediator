### Changed — the vta feature is back

- `affinidi-messaging-mediator` depends on `vta-sdk` 0.90 again,
  released on the same line as this workspace (`affinidi-messaging-sdk` 0.47 /
  `affinidi-tdk` 0.45 / `trust-tasks` 0.39 / `affinidi-crypto` 0.3), so every
  `affinidi-*` and `trust-tasks-*` crate still resolves once.
- `vta` (VTA-backed key management: operating secrets fetched from a
  Verifiable Trust Agent at boot, periodic refresh, `mediator rotate-admin`) is
  back in the mediator's `default` features, and enabling it no longer stops
  the build. Library consumers can still turn it off with
  `default-features = false`; self-hosted mediators never used it.
- `mediator-setup`'s `vta` feature is now real and on by default: the VTA step
  offers full setup, admin-only and offline export again, the deployment
  defaults pick a VTA-managed setup again, and `--setup-key-out`,
  `--setup-key-file`, `use_vta = true` recipes (sealed-mint, sealed-export,
  `--bundle`) and `did_method = "vta"` run instead of exiting 5. A self-hosted
  `did:webvh` document is rendered by `vta-sdk`'s `didcomm-mediator` template
  again. A wizard built with `--no-default-features` and without `vta` keeps
  the previous release's behaviour (only "No VTA", VTA paths refused with exit
  5).
- The build commands the wizard renders (Dockerfile, `cargo install`,
  `cargo build`) list the mediator's `vta` feature again.
- The container image includes VTA integration again: the mediator's `default`
  features (with `vta`) and `mediator-setup` with its `vta` flows. A
  VTA-linked deployment that stayed on an earlier image can move to this one.
