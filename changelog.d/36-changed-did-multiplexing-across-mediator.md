### Changed — DID multiplexing across mediator instances

- **Behaviour change (clusters, R3.6):** with several mediator instances
  sharing one Redis, a grant revoked, voided by `revoke-all`, suspended by the
  unknown-key rule, narrowed by `mux/update`, marked stale by the key
  re-check, removed with its member's account, or newly stored on one
  instance now reaches the principal's live mux connections on the *other*
  instances within one pub/sub hop. Before, the other instances only
  detached, and only at their next 30-second sweep; they never narrowed a
  member or carried a new grant until the principal reconnected. A client
  connected to another instance now sees the `detached` / `attached` event
  moments after the change, with the same reasons the sweep uses (a deleted
  grant reports `revokedByMember` there). The handling instance's answer
  still waits only for its own connections.
- Each instance publishes a `MuxChangeRecord` on the Redis channel
  `MUX_CHANGES` after its local update: its instance id (the streaming UUID)
  and the changed (member DID hash, principal hash) pairs, with a flag on
  pairs whose grant was just stored. Hashes only; no statement, DID or key.
  A new supervised task, `mux_sync`, started when `[limits.mux]` is enabled,
  ignores its own instance's records and re-reads each changed member's
  record before acting, so a late or repeated record is harmless. A grant is
  carried from another instance only when the record says it was just
  stored, so a grant this connection refused on connect is not admitted by an
  unrelated change. Publishing is best effort (logged at `warn`); the
  30-second sweep remains the backstop.
- When the listener lags or loses its subscription it resubscribes (bounded
  backoff, then the supervisor's restart, which marks it degraded) and
  re-checks every member of every local mux connection. A grant stored
  elsewhere while records were missed is carried at the principal's next
  connection.
- `MediatorStore` gains `mux_changes_publish` / `mux_changes_subscribe`,
  defaulted to a no-op and `None` for single-process backends (Memory,
  Fjall); Redis implements them. A third-party backend keeps compiling.
- The mediator gains a `test-hooks` feature (test-only pause points, never
  for deployed builds). The test mediator enables it for its own tests, which
  now cover a suspension landing while a mux connection is opening (#106).
