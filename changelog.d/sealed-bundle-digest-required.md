### Changed — `mediator-setup` requires the digest to open a sealed bundle

- **Behaviour change (R3.6):** phase 2 of a sealed handoff
  (`--from <recipe> --bundle bundle.armor`) now requires `--digest`, and
  the TUI's verify screen no longer accepts a blank digest. The bundle's
  encryption does not identify its sender and the producer's `DidSigned` /
  `Attested` proof is not verified yet, so the out-of-band digest is what
  ties the bundle to the VTA admin. `--allow-bundle-without-digest` opens a
  bundle without one for a throwaway dev setup.
- The TUI refuses a bundle whose id differs from this run's request nonce.
  The headless path is unchanged: it looks up the decryption seed by the
  bundle's id, so a bundle for another request already fails to open there.
- The TUI no longer shows the bundle's computed digest before the operator
  types one, and `[F2]` no longer copies it: copying it back would make the
  check meaningless. A mismatch error still shows both values.
- Backend URLs printed by `mediator-setup` hide any `user:password@`
  credentials.
- `--force-reprovision` on phase 1 now discards an in-flight bootstrap's
  seed and starts a new request, as its error message and the setup guide
  said. A bundle made for the discarded request can no longer be opened.
- The headless modes (`--from`, `--non-interactive`, `--uninstall`,
  `--setup-key-*`) print the tool's warnings to stderr (`RUST_LOG`
  overrides the level). They were previously dropped.
- The `--digest` help and the setup guide's trust-model section now
  describe what the digest protects.
