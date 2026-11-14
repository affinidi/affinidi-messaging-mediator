### Changed — each release is supported for 90 days after its GA

- The support policy is now time-based: a release gets security and
  deployment-breaking fixes for 90 days after its GA, and the newest release
  always does. It replaces "the newest two releases", which at the current
  release cadence lasted a few days. `RELEASES.md` lists each release's
  "Supported until" date; `SECURITY.md` and the README say the same.
- Every `0.x` minor is a breaking release under Cargo's rules: track the newest
  one and read its **Breaking** entries before you move.

### Changed — mediator library docs show the supported API

- `affinidi-messaging-mediator`'s crate documentation now describes embedding
  with `MediatorBuilder` (with a compiled example), the features and the
  supported API: `builder`, `common::config`, `store`, `task_specs`,
  `error_codes`, `SharedData` and `install_jwt_crypto_provider`. The other
  public modules (`handlers`, `messages`, `mux`, `server`, `tasks` and so on)
  are hidden from the docs. They are still public, so nothing that compiles
  today stops compiling, but they are internal and may change in any release.
- `builder::StreamingLiveness` re-exports the type
  `MediatorBuilder::streaming_liveness` takes, so it no longer has to be named
  through `tasks::websocket_streaming`.
- docs.rs builds the published crates with their storage and secret-backend
  features on, so those items appear with their feature badges.

### Added — getting started, operations, multiplexing and architecture docs

- The root README's "Getting started" leads from a fresh checkout to a running,
  checked mediator and the console in five steps, and `docker/README.md`
  covers the container quickstart and running the published image.
- New docs in `crates/affinidi-messaging-mediator/docs/`: `multiplexing.md`
  (DID multiplexing), `operations.md` (probe routes, metrics catalogue, logs,
  shutdown) and `architecture.md` (crate and module map, message lifecycle).
  `docs/delivery-rules.md` states the R-numbered rules that code comments and
  changelog entries cite.

### Fixed — documentation that contradicted the code

- The mediator README no longer says a TSP-only build has no authentication
  path (it authenticates with `POST /tsp/authenticate`), pins Redis to a
  supported major instead of `redis:latest`, and states the working directory
  the wizard and the mediator need. The root README's embedding snippet no
  longer names an end-of-life version.
- The configuration template's DID multiplexing notes no longer cite an
  unpublished design document, and describe how a revoke reaches other
  instances as the code does it.
- `NOTICE.txt` describes this repository, not crates that live in
  affinidi-tdk-rs; issue references from affinidi-tdk-rs are written
  `affinidi-tdk-rs#NNN`.
