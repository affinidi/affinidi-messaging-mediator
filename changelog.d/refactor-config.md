### Breaking — mediator-common drops its duplicate `DatabaseConfigRaw` and `parse_cluster_mode`

- `affinidi_messaging_mediator_common::database::config::DatabaseConfigRaw`,
  its `TryFrom<DatabaseConfigRaw> for DatabaseConfig` and `parse_cluster_mode`
  are removed. The raw `[database]` schema is
  `affinidi_messaging_mediator_config::DatabaseConfigRaw`; the mediator
  converts it to `DatabaseConfig` with strict parsing. The removed conversion
  silently fell back to a 2 s timeout and fixed circuit-breaker values.
- `DatabaseConfig`'s `cluster_mode` written as a string is now read as
  `mediator.toml` reads it: `"true"` or `"false"` (any case, empty is
  `false`). Anything else is refused at startup. It used to be warned about
  and read as `false`, and `yes`/`no`, `1`/`0` and `on`/`off` were accepted.
  This affects the standalone processors' TOML (`forwarding.toml`,
  `message_expiry_cleanup.toml`); a native boolean is unaffected.

### Changed — one defaults table and one read per setting for `mediator.toml`

- `affinidi_messaging_mediator_config::defaults` is the single table of
  built-in defaults. The raw schema's serde defaults, the new `Default` impls
  of `LimitsConfigRaw`, `ForwardingConfigRaw`, `ProcessorsConfigRaw`,
  `MessageExpiryCleanupConfigRaw`, `DatabaseConfigRaw` and
  `DIDResolverConfig`, and the mediator's `LimitsConfig::default()`,
  `ProcessorsConfig::default()` and headless `Config` all derive from it.
  `LimitsConfig::default()` is now the table read through the same strict
  conversion as a file, so a default can never be a value the file would
  refuse. The values are unchanged.
- `affinidi_messaging_mediator_config::settings` holds the typed reads of
  `log_level`, `log_json`, `[streaming]`, `[did_resolver]`
  (`DidResolverSettings`), `[secrets] cache_ttl` and `[storage]`, which used
  to be private to the mediator binary. They are pure, so any consumer of
  `mediator.toml` can run the same checks.
- Building the mediator's `Config` is now two steps: a pure
  `ConfigRaw → ValidatedConfig` step that reads every file-only value once
  (run at startup and by `config/reload`), then `resolve()`, which opens the
  secret backend, runs the VTA integration and resolves DIDs using those
  values rather than reading the file a second time.
- `ConfigError` gains an `Inconsistent` variant for settings that each read
  but do not work together (it is `#[non_exhaustive]`).
- Config file format, environment variables and default values are
  unchanged.

### Changed — mediator-common depends on mediator-config, and takes its defaults from the table

- The dependency between the two crates is inverted:
  `affinidi-messaging-mediator-common` now depends on
  `affinidi-messaging-mediator-config`, and the config crate no longer depends
  on mediator-common (it takes `affinidi-messaging-mediator-types` directly for
  the ACL types). The config crate is published first.
- `ForwardingConfig::default()`, `ForwardingConfig`'s serde defaults (which the
  standalone forwarding processor reads its typed TOML with) and
  `DatabaseConfig::default()` now read the `defaults` table instead of
  repeating its values. The values are unchanged; `DatabaseConfig::default()`
  still names `./atm-functions.lua` as its `functions_file`.
- The headless `SecurityConfig` (what `Config::headless` and `MediatorBuilder`
  start from) takes its JWT lifetimes (900 s access, 86400 s refresh) and
  security flags from the new `defaults::security` table. Values unchanged.
- `redact` and `did_identity` move to `affinidi_messaging_mediator_config`
  (its schema and validation use them). mediator-common re-exports both, so
  `affinidi_messaging_mediator_common::redact::*` and
  `affinidi_messaging_mediator_common::did_identity::*` keep working.
- mediator-common's lean tier (`default-features = false`) now also pulls the
  config crate's dependencies: `toml`, `serde_ignored`, `ipnet`, `humantime`
  and `tracing`.
