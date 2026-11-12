### Changed — Redis storage, both modes

- **Startup checks the server's cluster mode.** With `cluster_mode` off it
  reads `cluster_enabled` from `INFO cluster` and refuses only a definite
  cluster, so existing deployments start as before (no new ACL permission).
  With it on it runs `CLUSTER INFO`.
- **The expiry sweeper retries a failed delete** instead of dropping the
  message from the expiry index (both modes). A bucket it can't clear is
  tried again a minute later, behind the buckets that are due, so a message
  whose delete keeps failing can't hold up expiry for the rest.
- **A full or throttled database reaches clients as a named error** in both
  modes: 97 `storage.full` (507) or 98 `storage.busy` (503), also over a
  websocket, which got no reply before. This covers session writes and
  deletes too. 98 carries a `Retry-After` of 5 to 10 s, picked at random so
  the clients refused in one throttle don't all retry at once. The cause is read from the
  Redis error where it is converted (the `OOM` code, also inside an aborted
  transaction; a reply timeout; `STORE_IN_PROGRESS`/`DELETE_IN_PROGRESS`),
  never from its wording, so a reworded server message can't change the
  answer, and an unrelated error that mentions "timed out" isn't reported as
  busy. Handlers that wrap a storage error in their own report (login,
  token refresh, routing, pickup status, creating or deleting an
  out-of-band invitation) pass 97 and 98 through in place of the generic
  `storage.error`. A caller with no session yet (a login challenge or
  response, DIDComm or TSP, and retrieving an out-of-band invitation) gets a
  generic `storage.error` 503
  with no cause, so the endpoints open to anyone don't reveal whether storage
  is full or busy; the cause is logged. A full database
  no longer stops a restart or forwarding (with `cluster_mode` off, a
  restart goes ahead when the loaded Lua library already matches this
  build).
- The server version check accepts a two-part `redis_version`; ElastiCache
  Serverless reports `7.2`.
