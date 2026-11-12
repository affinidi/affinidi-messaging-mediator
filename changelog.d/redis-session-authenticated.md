### Fixed — a Redis session read back after login is marked authenticated

- The Redis store's `get_session` set a session's state but never its
  `authenticated` flag, which Fjall and memory store. Every session on
  Redis was therefore handled as unauthenticated: session / sender matching
  under `security.force_session_did_match` was skipped for forwards and
  direct deliveries, and an authenticated session's routed TSP frames went
  through the relay checks meant for the anonymous relay session. The flag
  now follows the stored state (`Authenticated`). The store conformance test
  checks it after login on every backend.

**Behaviour change (R3.6):** on Redis, `force_session_did_match` (default
on) now applies as documented: a client that authenticated as one DID and
sends forwards or direct deliveries as another is refused, as it already
was on Fjall and memory.
