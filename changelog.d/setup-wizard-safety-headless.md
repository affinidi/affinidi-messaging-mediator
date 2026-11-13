### Breaking — mediator-setup: `--non-interactive` needs `--did-method`, and no longer defaults to a VTA DID it cannot mint

- `mediator-setup --non-interactive` without `--from` now fails unless
  `--did-method peer` or `webvh` is given. It used to default to a
  VTA-managed DID with no VTA session, write `did://vta://mediator` (or
  `PLACEHOLDER_DID` for "import") into `mediator.toml`, and exit 0.
- A VTA-managed DID without a VTA session is now a hard error (exit 5);
  `did_method = "import"` and `admin = "import"` without `admin_did` are
  refused (exit 6). Importing an existing mediator DID was never
  implemented and is no longer offered.
- Headless runs never prompt or read stdin. `--non-interactive` used to end
  in an "Install now?" prompt that, without a terminal, started
  `cargo install` on its own.

### Breaking — mediator-setup: a plaintext `file://` secret store outside a local deployment needs an explicit opt-in

A `server` or `container` setup whose `[secrets].storage` is an unencrypted
`file://` URL is refused unless the recipe sets
`allow_plaintext_file = true` under `[secrets]` (or `--allow-plaintext-file`
is passed). Prefer `file://…?encrypt=1` or a secret manager. The bare
`gcp_secrets://`, `azure_keyvault://` and `vault://` schemes, which have no
usable default and produced invalid URLs, are refused with a pointer to the
full URL form.

### Breaking — mediator-setup: production deployments default to a closed network

A recipe without `[security].network_mode` (and the TUI's starting point)
now gets `closed` — explicit ACL grants, the shipped template's posture —
for `server` and `container` deployments. `local` stays `open`. Set
`network_mode = "open"` to keep the previous behaviour. The posture is
printed in the summary before anything is written.

### Breaking — mediator-setup: the admin choice is honoured in VTA flows

With a VTA session, `[server].admin_did` used to be the VTA-issued
credential whatever was chosen. Now `admin = "generate"` (the recipe
default) mints a separate did:key for the mediator's admin API — its key goes
to `admin-monitor.json` — while the VTA credential stays the mediator↔VTA
identity in `mediator_admin_credential`. A sealed-mint or sealed-export
recipe that relied on the default therefore gets a different admin DID; set
`admin = "vta"` to reuse the VTA credential. "Use an existing admin DID" is
now a real prompt (recipe: `admin = "import"` + `admin_did`, or
`--admin-did`).

### Breaking — mediator-setup: re-running into a provisioned backend is refused whatever the config path

The re-run guard now checks the secret backend about to be written, after
its probe, in every flow (TUI, `--from`, `--non-interactive`,
`--setup-key-file`): if it already holds mediator keys the run stops with
exit 4 unless `--force-reprovision` is given. A different `--config`, a
moved `mediator.toml`, or a backend that cannot be read no longer bypass it.
Other exit codes are listed in `--help` and the setup guide (7: setup
complete but publishing the DID failed).

### Fixed — mediator-setup: safer, recoverable provisioning

- The did:webvh update key and pre-rotation key of a locally generated DID
  are stored in the secret backend (`mediator_webvh_update_keys`), and the
  first log entry commits to the *hash* of the next key, so the DID can be
  updated.
- Sealed handoff phase 2 keeps the ephemeral seed until the whole setup is
  written, so a failure can be retried with the same bundle. `did.jsonl` is
  written before `mediator.toml` and its failure is fatal. Every file is
  written to a temporary name, fsynced and renamed; key-bearing files are
  `0600` even when replacing a looser file, symlinked targets are refused,
  and directories the wizard creates are `0700`. The `mediator.toml` being
  replaced is backed up as `mediator.toml.bak.<UTC timestamp>` in every
  flow. Publishing to `did_target` / `did_log_target` runs last.
- `--setup-key-file` now finishes the setup: it builds the admin-only VTA
  session from the phase-1 key, provisions the mediator (`--did-method`,
  other flags, `--set` or `--from`), stores the setup did:key — the
  long-term VTA credential — in the secret backend and deletes the key file.
- The admin private key is no longer printed; `--show-admin-key` prints it
  on a terminal only. `--uninstall` removes every file the setup wrote,
  from a manifest kept next to the config.
- `did_web_self_hosted` names the `did.jsonl` actually written (its
  in-container path for container deployments) instead of
  `file://./conf/did.jsonl`. Kubernetes Secrets setups emit the
  `secrets-k8s` build feature.
- Container output: `Dockerfile`, `Dockerfile.dockerignore` and
  `docker-compose.yml` are written next to `mediator.toml` (never over a
  different existing file, and never the repository's `.dockerignore`); the
  image holds only the binary, and the config directory with the keys is
  mounted rather than copied into a layer.
- The TUI checks the secret backend when the Key Storage step completes,
  stores a VTA session's credential as soon as it connects, asks before
  quitting once a session exists, stops a provision flight on Esc, and
  saves the answers as a resume recipe when the final step fails. Option
  lists, Enter handling and default highlights come from one table per
  step; re-editing an SSL certificate path no longer overwrites the key
  path; going back to the VTA step discards the old session with a warning;
  rejected inputs say why. A panic restores the terminal, small terminals
  get a "too small" screen, `NO_COLOR` and non-terminal output drop the
  colour codes, and the help bar lists the keys that work.

### Added — mediator-setup: headless runs from one recipe with `--set`

Every headless run builds one recipe: the `--from` file, then the per-option
flags (shorthands for recipe keys), then `--set section.key=value`
overrides. Each override and each unused flag is reported, a mistyped key is
an error, and `DATABASE_URL` overriding the recipe is reported too. Saved
recipes are serialised from the recipe schema (TOML-escaped, with
`[storage]`, `save_did_web`, `extra_key_suites`, the DIDComm v1 forwarding
flag, a relative `file://` path) and load back to the same configuration.
`--key-suite secp256k1` now applies to did:peer too.
