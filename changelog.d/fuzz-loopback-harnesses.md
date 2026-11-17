### Added — Loopback fuzz harnesses for the mediator's auth, ACL, routing and trust-task invariants

- Five `#[tokio::test]`/proptest harnesses under `fuzz/tests/` drive the real
  `axum` router via `MediatorBuilder` on a loopback socket and assert semantic
  invariants a crash-only byte fuzzer can't reach: `authenticate_token` over the
  header and WebSocket-subprotocol paths (no hostile token forges a `200`),
  `authz` capability enforcement (no account type cross-reads another DID's
  folder), SSRF-adjacent `did:peer:2` endpoint classification (the mediator's own
  address is never a remote relay), and trust-task freshness/retention date
  arithmetic. Test-only, under the detached `fuzz/` crate — no product code or
  dependency-graph change. All 15 tests pass on current `main`. (Refs: SEC-4245)
