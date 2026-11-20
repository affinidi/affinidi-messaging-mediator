### Changed — `affinidi-messaging-mediator`: the `common` helper modules are internal

- Every submodule of `affinidi_messaging_mediator::common` except `config`
  (`authz`, `circuit_breaker`, `did_rate_limiter`, `error_codes`,
  `http_server`, `jwt_auth`, `lua_integrity`, `metrics`, `relay_target`,
  `request_id`, `request_metrics`, `session`, `storage_timeout`, `time`,
  `ws_budget`) is now `#[doc(hidden)]`, as the crate's other internal modules
  (`handlers`, `messages`, `server`, `mux`, `tasks`, `monitor`, …) already
  were. They stay `pub` for the binary, the test mediator, the console, the
  setup tool and the fuzz targets, but they are internal: not covered by
  semver, and they may change in any release. The supported library surface
  is `builder` (`MediatorBuilder`, `MediatorHandle`), `common::config`,
  `store`, `task_specs`, `error_codes`, `SharedData` and
  `install_jwt_crypto_provider`. Nothing was removed and no signature changed.

### Changed — every library crate's public items are documented

- `missing_docs` is now a workspace lint (`warn`, so `-D warnings` in CI makes
  it an error), and every public item of `affinidi-messaging-mediator-common`,
  `-config`, `-processors`, `-admin`, `-tui`, the test mediator and the
  mediator library is documented: units, defaults, the config key or wire
  value each one maps to, and what its errors mean.
- The READMEs of `affinidi-messaging-test-mediator`,
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-mediator-tui`
  are compiled as doctests, so their examples can no longer drift from the
  API. Compiling them caught one stale example: the test mediator's admin
  example imported `trust_tasks_rs::specs::messaging`, which needs a
  `trust-tasks-rs` feature; it now uses
  `affinidi_messaging_sdk::tasks::messaging`.
- The CI `cargo doc` job builds with `--all-features`, so items behind the
  storage, secrets and protocol features are checked as docs.rs shows them.
