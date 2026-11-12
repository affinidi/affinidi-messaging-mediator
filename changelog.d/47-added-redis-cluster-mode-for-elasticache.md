### Added — Redis cluster mode, for ElastiCache Serverless

- **`[database] cluster_mode` (`DATABASE_CLUSTER_MODE`), off by default.** On,
  the mediator runs on a single-endpoint cluster-mode Valkey such as
  ElastiCache Serverless: hash-tagged keys, a cluster client, single-slot
  scripts instead of `FCALL` (serverless has no `FUNCTION`), and idempotent,
  crash-safe steps where one operation spans slots. Off keeps today's key
  layout and Lua functions. Startup refuses a setting that doesn't match the
  server, a cluster with more than one primary node, an endpoint that reaches
  a replica, and existing data written under the other `cluster_mode` (the
  key names differ, so flipping the setting would orphan every account and
  message; there is no migration). Limits (one slot's throughput for the
  shared keys; TTL keys evicted before error 97) are in `conf/mediator.toml`.
  The standalone processors read the same setting. It takes `true`/`false`,
  `1`/`0`, `yes`/`no` or `on`/`off`, ignoring case, as a boolean or a string.
- **Cluster-mode stores and deletes keep the library's guarantees.** A store
  holds the message until it is fully queued and a delete holds it until it
  is removed, so exactly one of two concurrent deletes succeeds (the other
  gets NOT_FOUND, R1.7), a delete never leaves queue entries or counters for
  a gone message, and a store is never reported for a message that isn't
  queued (R1.1). A store or delete that dies or stalls part-way is taken over
  after 30 seconds. A store that takes over a delete releases the entries the
  delete claimed and queues the message again under new entries, so the
  delete, if it resumes, removes nothing. A store refused at its last step
  releases what it queued. A delete whose release fails gives its hold up at
  once. The expiry index is written before the message, so a failed write
  can't leave a message the sweeper never reaches.
