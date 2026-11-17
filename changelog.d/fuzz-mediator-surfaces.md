### Added — Fuzz targets for the mediator's own envelope, config and Redis wire types

- Four cargo-fuzz targets join the existing edge-parser suite in `fuzz/`:
  `meta_envelope_new` (the mediator's `MetaEnvelope::new` inbound DIDComm
  classifier, on unauthenticated bytes), `config_parse` (operator TOML/env
  parsing — a malformed `--config` is a startup DoS), and `forward_queue_roundtrip`
  / `pubsub_record_roundtrip` (encoder-side round-trip oracles on the Redis
  forward-queue and pub/sub wire types behind past delivery findings). Seed and
  regression corpora are committed; the weekly `Fuzz` workflow runs them too.
  Harnesses only — no mediator runtime behaviour changes. (Refs: SEC-4245)
