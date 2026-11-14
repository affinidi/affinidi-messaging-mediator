### Changed — mediator-setup: the wizard no longer writes the file-backend passphrase into its own environment

The interactive wizard used to export the `file://?encrypt=1` passphrase
with `std::env::set_var`, which is unsound on its multi-threaded runtime
(a worker thread may read the environment at the same time). It now keeps
the confirmed passphrase in memory and hands it to every open of the
encrypted store. Nothing changes for operators: the mediator still reads
`MEDIATOR_FILE_BACKEND_PASSPHRASE` / `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE`
at boot, and headless runs (`--from`, `--non-interactive`,
`--setup-key-file`) still take the passphrase from those variables.

A recipe the wizard saves after a TUI sealed-mint handoff now records
`vta_mode = "sealed-mint"` instead of the legacy alias `"sealed"`. Both
load the same way.

### Changed — mediator-setup: internal restructuring

`app.rs` and `main.rs` are split into modules (`app/` for the wizard's
steps, choices, screen text and sub-flows; `flows/`, `tui/`, `provision/`
and `install.rs` for the binary), and `WizardConfig` holds enums rather
than the selection-list labels. Screens, prompts, flags, recipes, the
generated files and exit codes are unchanged.

### Added — `affinidi-messaging-mediator-common`: open an encrypted file store with an explicit passphrase

`secrets::open_store_with_passphrase`, `open_store_with_passphrase_async`
and `MediatorSecrets::from_url_with_passphrase` take the
`file://?encrypt=1` passphrase from the caller instead of the environment,
trimmed the same way so both give the same key. `None` behaves exactly like
`open_store` / `MediatorSecrets::from_url`. Additive; other backends ignore
the passphrase.
