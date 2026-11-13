### Changed — Hot-path store, I/O and parsing costs cut (P12 perf)

- **Queue survey (#144).** `queue_oldest_age_seconds` now ages the deepest
  queues plus a window over every other non-empty queue that rotates each
  cycle, so a shallow queue stuck for days is reached within a bounded number
  of cycles. Alert on `max_over_time(...)` over a window that spans the
  rotation. A survey cut short by the account cap resumes where it stopped on
  the next cycle instead of starting at 0 again, and each probe lists its
  queue once. **The gauge reads `NaN`, not `0`, when messages are queued but
  no probe succeeded**: `0` now means only that the folder is empty.
- **Fjall (#175).** The `fsync` behind `durability = "sync"` runs on the
  blocking pool, not on a runtime worker. Streaming registrations are held in
  memory and no longer take the global write lock or touch disk; an older
  data directory's `streaming_clients` keyspace is dropped at open.
  `inbox_status` reads the two ends of the inbox rather than walking it, v1
  routing keys get an in-memory owner index (no scan on `v1_routing_keys_for`
  or account removal), the session sweep decodes only the expiry, and
  `account_list` no longer re-serves accounts that follow a counter-only record
  on the next page.
- **Live streaming (#128).** A mux member is registered with live delivery in
  one command and one store write (was `Register` + `Start`, two writes). An
  inactive entry corrects the store's live state once, not on every in-flight
  notification. Inbox redeliveries run at most 32 at a time, and the
  streaming control channel holds a mux connection's whole member set.
- **Mux sweeps (#132).** The 30 s grant re-check and the key revalidation run
  as a task beside the socket loop, with store reads and DID resolutions eight
  at a time, so the socket keeps reading, writing and pinging during a sweep.
- **WebSocket and delete paths (#159).** A socket re-reads its account before
  a frame only when an account change has been seen since its last read or
  that read is over 2 s old. A change made through any mediator instance (ACL
  set, role change, account removal; role changes are now published to other
  instances too) still reaches the socket on its next frame; **one made
  directly in the store, behind every instance, can take up to 2 s**.
  `DELETE /delete` reads mux members' copies with one batched read per member
  and works on up to eight ids at once; `POST /outbound` fetches with one
  batched read and deletes after the write eight at a time.
- **Inbound (#198).** The envelope pre-read skips the ciphertext instead of
  copying it into a JSON tree. In Rewrap relay mode the innermost envelope is
  decrypted once, not twice. Forwards borrow their attachment and **read the
  attached envelope only for a local next hop**: one for a remote hop is
  relayed as is and judged by the mediator it goes to. Trust Task requests
  decode only their payload, and the response-signing key (re-resolved every
  5 minutes) and proof verifier are cached.
