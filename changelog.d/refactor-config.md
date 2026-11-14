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
