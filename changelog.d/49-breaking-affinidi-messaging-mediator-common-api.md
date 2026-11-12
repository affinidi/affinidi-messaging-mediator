### Breaking — `affinidi-messaging-mediator-common` API

- `DatabaseHandler::get_async_connection` and `RedisStore::get_connection`
  return `RedisConnection` (one server or a cluster) instead of
  `ConnectionManager`, and `DatabaseConfig` has a new public field,
  `cluster_mode`.
- `mux::MuxChangeRecord` has a new public field, `streaming`
  (`Vec<StreamingHandoff>`), so a struct literal needs it; it is skipped on
  the wire when empty. `MediatorStore` gains `streaming_claim` and
  `streaming_release`, with defaults for single-instance stores. The Redis
  `Database` helpers `streaming_register_client`, `streaming_start_live`,
  `streaming_stop_live` and `streaming_deregister_client` are removed: they
  bypassed the cross-instance ownership rules. Use `streaming_set_state`,
  `streaming_claim` or `streaming_release`.
