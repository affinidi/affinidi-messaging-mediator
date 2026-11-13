### Breaking — purge returns a report; one purge algorithm on every backend

- `MediatorStore::purge_folder` and `purge_folder_by` now return a
  `PurgeReport` (`count`, `bytes`, `scanned`, `failed`) instead of
  `(count, bytes)`, and every backend runs the same purge
  (`store::purge_folder_by_listing`): it pages through the folder, deletes
  each page together (pipelined on Redis rather than four sequential round
  trips per message), treats an already-gone message as removed, counts any
  other refusal in `failed` and carries on, and removes only the stream
  entries of messages it actually removed. Previously Redis aborted at the
  first undeletable message, and Fjall and memory swallowed refusals and
  wiped the stream anyway, leaving messages stored but unlisted. The new
  trait method `delete_folder_entries` removes named entries.
- **Behaviour change (R3.6):** account removal fails, with the account left
  blocked, when its inbox purge could not delete every message (it used to
  stop at the first failure on Redis, and carry on silently on Fjall and
  memory). Running the removal again retries the rest.

### Breaking — a session that no longer exists is answered 401

- **Behaviour change (R3.6):** a valid, unexpired JWT whose session record is
  gone (its 24 h TTL, a store flush, a memory-backed mediator's restart) is
  now refused with HTTP 401 `Invalid token`, so the client authenticates
  again. It was a 500 carrying the storage backend's error text. Every
  backend's `get_session` answers a missing or expired session with the new
  `store::session_not_found` error (`Unauthorized`), and a Redis account
  record without a role or ACLs as `account_gone`. A real storage failure is
  still a 500, now with a fixed message; the cause is logged. A request
  without connection info is an internal error (it was reported as missing
  credentials).

### Changed — the Redis stored-function library is built in and versioned

- The mediator loads the `atm-functions.lua` library compiled into it, and
  `database.functions_file` is now optional: unset (the shipped
  `mediator.toml` no longer sets it), the built-in library is loaded. A file
  that is set but older than the built-in library (by its new
  `LIBRARY_VERSION` line) is refused in favour of the built-in one, with an
  error in the log.
- **Behaviour change (R3.6):** the library is only loaded over an older (or
  unversioned) one. A database already holding a newer library, loaded by a
  newer mediator, keeps it, so an older instance restarting during a rolling
  deploy no longer replaces the functions newer instances run.
- `docker/test/conf/atm-functions.lua`, the second copy of the library, is
  removed; the docker test configuration uses the built-in library.

### Changed — Redis start-up fails rather than waiting forever

- **Behaviour change (R3.6):** start-up fails at once when the database
  refuses the credentials, and after 30 attempts 10 seconds apart when it is
  unreachable; it used to retry forever.
- **Behaviour change (R3.6):** start-up fails when the database records a
  schema migration this build does not know (a newer mediator has migrated
  it). Migrations now run under a lock (`SCHEMA_MIGRATIONS:LOCK`), so
  instances starting together do not run them concurrently.

### Fixed — the Redis circuit breaker follows real command failures

- The breaker counted handing out a connection, which cannot fail, as a
  success, so it never opened on the request path. Every command sent over
  the store's connection now reports to it: a connection error or timeout as
  a failure, any reply as a success. A half-open probe that never reports
  (its task was cancelled) no longer leaves the breaker refusing every
  request until restart.
- `[database] circuit_breaker_threshold` (default 5) and
  `circuit_breaker_recovery_secs` (default 10) are now settings
  (`DATABASE_CIRCUIT_BREAKER_THRESHOLD`,
  `DATABASE_CIRCUIT_BREAKER_RECOVERY_SECS`); they were hard-coded.

### Fixed — Redis forward queue

- Ack and delete of a finished forward are one `MULTI` on Redis, as on Fjall,
  so a crash between them cannot strand an entry in `FORWARD_Q`.
- Each forwarding consumer keeps one blocking connection, reopened after an
  error, instead of opening a connection per read, and the consumer group is
  created once (again only on `NOGROUP`) rather than before every read.
- The reclaim sweep removes consumers of earlier processor runs once they
  hold nothing and have been idle an hour (`XGROUP DELCONSUMER`; new trait
  method `forward_queue_prune_consumers`). The conformance suite now checks
  that a delayed forward read and left pending by one consumer is reclaimed,
  with its delay, and finished by another.

### Fixed — Redis message storage

- `store_message` adds its queue entries before anything else and lets Redis
  choose the stream id (`*`), so a clock that steps back (a failover to a
  replica that is behind, an NTP step) no longer fails stores, and a refused
  store no longer leaves counters, a body or an expiry entry behind.
- Deleting a removed account's sent messages no longer recreates its
  `DID:` record as a ghost account with negative counters.
- `account_add` with a queue limit sets the send and receive limits on Redis,
  as on Fjall and memory (it wrote a field nothing read).
- A delivered message's expiry entry is moved to its new deadline, not
  duplicated; the sweeper deletes each bucket's messages together and
  unlists a bucket only while it is empty, so a message stored into it
  meanwhile keeps its expiry; and message bodies and metadata carry a
  backstop expiry a day past the message's own.
- `clean_start_streaming` runs until every registration of the previous run
  is cleared, not just the first 500.

### Changed — backends agree on observable semantics

- **Behaviour change (R3.6):** the global `SENT_COUNT` / `SENT_BYTES`
  counters move when a handover is recorded (`record_delivered`, or an
  optimistic delivering fetch), on every backend. A read by id
  (`get_message`) no longer counts, and Fjall and memory, which never
  counted, now do.
- **Behaviour change (R3.6):** `live_delivery` in a pickup status reply is
  true only while live mode is on, on every backend; Redis and Fjall
  reported any connected socket.
- `list_messages` accepts `-`, `+`, `<ms>` and `<ms>-<seq>` as range bounds
  and refuses anything else on every backend (Redis passed it to `XRANGE`;
  Fjall and memory read it as unbounded).
- Fjall's paged `fetch_messages` returned one message short.
- An optimistic fetch whose delete fails returns the message, with the
  failure in `delete_errors`, on every backend (Fjall and memory withheld
  the body).
- Redis reports `poison_suspected` redeliveries; `check_admin_account` is
  false, not an error, for a DID with no record on Redis; memory keeps a
  session's expiry when its refresh-token hash is updated.
