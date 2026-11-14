### Breaking — configuration values are checked strictly; a config that booted on silent defaults now fails

A configuration that started before may now refuse to start (and `config/reload`
may now fail) with an error naming the setting, the value and what it takes.
Fix the value the error names.

- **No silent defaults.** An unreadable number or boolean anywhere in the file
  (`listed_messages = "5O"`, `rate_limit_per_ip = "10/s"`,
  `message_size = "1MB"`, `use_ssl = "ture"`, a processor `enabled`, the
  resolver cache settings, `database_timeout`, `cluster_mode`,
  `[secrets] cache_ttl`, `[storage.fjall]` values, …) is a startup error
  naming `section.key`, instead of quietly running on a built-in default that
  could be looser than what was written. Values are trimmed, and booleans and
  enum-like values are case-insensitive.
- **`security.mediator_acl_mode`** must be `explicit_allow` or `explicit_deny`
  (any case). An unknown value used to select `explicit_deny` — the OPEN mode.
  `log_level` must be one of `trace debug info warn error` (it used to become
  `info`); `processors.forwarding.relay_mode` must be `blind` or `rewrap`; a
  `[limits.mux] enabled` other than `true`/`false`/empty is refused (it used to
  mean off); `storage.backend` must be `redis` or `fjall`, and
  `storage.fjall.durability` `buffered` or `sync` (it used to become `sync`).
- **Documented invariants are enforced on the file**, not only on
  `config/patch`: each `queued_*_soft` ≤ its `queued_*_hard`; a queue limit is
  `-1` or ≥ 0 (no other negative); `message_size` ≥ 1 and ≤ `http_size` and
  `ws_size`; no `0` for `listed_messages`, `deleted_messages`, `to_recipients`,
  `to_keys_per_recipient`, `crypto_operations_per_message`,
  `forward_task_queue`, `oob_invite_ttl`, `message_expiry_seconds`,
  `ws_send_buffer`, `pubsub_buffer`; `jwt_access_expiry` ≥ 10 s and below
  `jwt_refresh_expiry`; `ws_pong_timeout_secs` ≥ 2 × `ws_ping_interval_secs`
  and both intervals ≥ 1 (these used to be raised silently);
  `limits.mux.max_channel_slots` in 8..65536 (it used to be clamped);
  `database_timeout` and `did_resolver.network_timeout` ≥ 1.
- **CORS entries are checked at startup.** An exact `cors_allow_origin` entry
  must be `scheme://host[:port]` with no path or trailing slash
  (`app.example.com`, `https://app.example.com/` and `null` are refused; they
  could never match). Scheme and host are now compared case-insensitively.
- **`[secrets] backend` has no default.** The shipped `conf/mediator.toml`
  leaves it commented out with the choices listed; startup fails until one is
  set, and the error lists the choices. `mediator-setup` sets it as before.
- **`config/reload`** runs the same checks over the whole file: a value that
  would not survive a restart fails the reload with `config.reload.invalid`
  and changes nothing.

Rust API (affinidi-messaging-mediator): `MuxConfig` is built with `TryFrom`
(was `From`); `LimitsConfig::try_from` now fails on values it used to default;
`relay_target_blocked` takes any `BlockList`. affinidi-messaging-mediator-common:
`ForwardingConfig` gains `blocked_forwarding_late` (construct it with
`..Default::default()`). affinidi-messaging-mediator-config: new
`ConfigError::Invalid`, `values` module, `validate::check_secrets_backend`,
`env::ignored_env_notes` / `warn_ignored_env`; `SecretsConfigRaw::backend` is
`#[serde(default)]`.

### Fixed — stored `config/patch` overrides that tighten both keys of a pair no longer revert on restart

Overrides were laid one key at a time in alphabetical order, so with both keys
of a soft/hard pair lowered the `…_hard` key was checked against the baseline
`…_soft`, failed, and was dropped with only a warning — the tightened hard
limit reverted on the next start or reload. All overrides are now laid first
and the soft ≤ hard rule checked once over the result; a pair still out of
order returns to its configured values. A single `config/patch` may lower both
keys together in any order; a patch key (or a reset) that would leave its pair
out of order is refused and the stored value kept. A configured limit below a
key's patch floor is no longer read as unlimited, so a patch cannot raise it.

### Fixed — a self-hosted did:webvh log with more than one entry starts

`server.did_web_self_hosted` read a `file://` log line by line and joined the
lines with nothing between them, so after the DID's first update the mediator
refused to start. The source is now read exactly as stored; a log is parsed
one entry per line and its chain verified with didwebvh-rs (each entry's proof,
`versionId` and parameters against the one before; witness proofs are not
checked), `/.well-known/did.json` serves the last entry's document and
`/.well-known/did.jsonl` the log byte for byte. A log that deactivates the DID
is refused. A relative `file://` path is now resolved against the config
file's directory, like `functions_file` and the TLS paths (part of #176).

### Changed — an unresolvable blocked-forwarding DID no longer stops startup

A `processors.forwarding.blocked_forwarding_dids` entry (or the mediator's own
DID) that cannot be resolved at startup is blocked by its DID at once, logged,
and its service endpoints added by a background retry once it resolves. Errors
for a bad `streaming.uuid` or `server.did_web_self_hosted` now name the setting
and the value.

### Added — `MEDIATOR_`-prefixed environment names and complete `Env:` labels

- `MEDIATOR_DATABASE_URL`, `MEDIATOR_LOG_LEVEL`, `MEDIATOR_USE_SSL` and
  `MEDIATOR_LISTEN_ADDRESS` are accepted and win over the bare names, which can
  collide with other software in a container. Names that did not match their
  setting gain consistent ones (`GLOBAL_ACL_DEFAULT`,
  `LIMIT_TO_KEYS_PER_RECIPIENT`, `LIMIT_ACCESS_LIST_LIMIT`,
  `LIMIT_OOB_INVITE_TTL`); the old names keep working.
- New overrides: `LIMIT_MUX_MAX_ATTACH_LIFETIME_SECS`,
  `LIMIT_MUX_REVALIDATE_INTERVAL_SECS`, `LIMIT_MUX_MAX_CHANNEL_SLOTS`,
  `LIMIT_MUX_DEAD_RETENTION_SECS`, `PROCESSOR_FORWARDING_ACCEPT_INVALID_CERTS`.
- `STORAGE_BACKEND` now creates the `[storage]` section when the file has none
  (the published image's config has none, so it used to be ignored); other
  `STORAGE_*` variables set without a section are reported as ignored.
- Every variable the overlay reads is labelled in the template and every label
  is read, checked by a test in both directions; the drift test now covers
  `docker/test/conf/mediator.toml`, whose send-queue limits move to the
  documented 2000 / 10000.

### Changed — secret backend guidance

- `keyring://` on Linux is the kernel keyring, which loses its keys on reboot;
  the mediator now warns at startup when it is used there, and the template
  and `docs/secrets-backend.md` say so.
- `azure_keyvault://` authenticates only with an Azure CLI login and is marked
  wizard / development only (not HA-capable) in the docs.
- The VTA-cache HMAC is documented as detecting corruption or mismatch, not
  tampering by someone who can write the backend.

### Fixed — `mediator rotate-admin` uses the server's configuration loader

The command read `[secrets] backend` from the TOML by hand and ignored
`MEDIATOR_SECRETS_BACKEND`, so in an env-configured deployment it rotated the
credential in a different store from the one the mediator uses. It now loads
the configuration through the server's loader and environment overlay.
`--dry-run` no longer mints and prints a throwaway DID, and its messages and
the module docs now describe what the command does.

Also fixed: the DID resolver's built-in network timeout is 5000 ms (it was 5,
read as milliseconds).
