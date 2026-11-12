### Fixed — database URL credentials are hidden in debug output

- The configuration printed at startup showed `database.database_url` in
  full, including any password it carries (`redis://:password@host/`). The
  `Debug` output of `DatabaseConfig` and `DatabaseConfigRaw` now shows
  `redis://***@host/`, as `config/show` already did, and so does the
  "Database URL is invalid" error. The helper is shared as
  `affinidi_messaging_mediator_common::redact::redact_url`.
