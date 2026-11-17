# Fuzz harness map

What each fuzz target actually reaches, so a reviewer can see the mapping from
`fuzz_targets/<name>.rs` → the exact mediator surface it exercises, without
reading every harness. Surfaces are named by function + file (line numbers
drift; where one is given it is from the engagement HEAD and approximate).

Each target's own file header carries the full rationale; this is the index.

## Active targets (`fuzz/fuzz_targets/`)

Coverage-guided libFuzzer targets (`cargo +nightly fuzz run --fuzz-dir fuzz <target>`).

| Target | Source surface reached | Reachability | Oracles | Origin |
|---|---|---|---|---|
| `tsp_meta_envelope` | `affinidi_tsp::is_tsp` / `MetaEnvelope::parse` | Network edge, unauthenticated | no-panic | existing |
| `didcomm_message_json` | `affinidi_messaging_didcomm::Message::from_json` | Every unpacked message, pre-route | no-panic | existing |
| `didcomm_jws` | `affinidi_messaging_didcomm::jws::verify::parse_jws` | Signed envelope, before signature check | no-panic | existing |
| `envelope_detect` | `mediator_common::types::messages::MessageProtocol::detect` | Inbound protocol classifier | no-panic | existing |
| `meta_envelope_new` | `mediator::didcomm_compat::MetaEnvelope::new` | **Unauthenticated**, every inbound DIDComm over REST/WS, before decryption | no-panic **+** recorded `sha256_hash` matches input | SEC-4245 |
| `config_parse` | `mediator_config::env::parse_config` | Operator `--config` TOML/env at startup (startup-DoS) | no-panic | SEC-4245 |
| `forward_queue_roundtrip` | `mediator_common::store::types::ForwardQueueEntry` (Redis `FORWARD_Q` wire type) | Persisted on enqueue, read by the forwarding processor | no-panic **+** byte-identical serialize→deserialize→serialize | SEC-4245 |
| `pubsub_record_roundtrip` | `mediator_common::store::types::PubSubRecord` (Redis pub/sub wire type) | Decoded on every live-delivery notification | no-panic **+** round-trip **+** `#[serde(default)]` legacy decode | SEC-4245 |

## Loopback case-harnesses (`fuzz/tests/`)

These are **not** libFuzzer `&[u8]` targets: they drive the **real `axum`
router** bound to a loopback TCP socket (via the crate's own
`MediatorBuilder` / `test-mediator` fixture) with proptest-generated or
exhaustive case matrices, because their targets (`authenticate_token`,
`authz::*`, `classify_endpoint`) are `pub(crate)` and only reachable through
the full HTTP/WS request path. Run with `cargo test --manifest-path fuzz/Cargo.toml`.
All 15 tests pass against current `main`.

| Target | Source surface reached | Real entry point | Oracle | Status |
|---|---|---|---|---|
| `jwt_auth` | `common::jwt_auth::authenticate_token` | `GET /mediator/v1/whoami` (smallest authenticated route) | no-panic **+** no hostile token ever forges a `200` | ✓ 3 tests |
| `jwt_auth_ws` | `authenticate_token` via `handlers/websocket.rs` `Sec-WebSocket-Protocol: bearer.<jwt>` | Raw HTTP/1.1 WebSocket upgrade | second entry point wired to the same verifier, rejects the same inputs | ✓ 1 test |
| `authz_acl` | `common::authz::{grants, require_capability, check_permissions}` | `POST /fetch`, `/outbound`, `DELETE /delete`, `GET /list/{did_hash}/{folder}` | no account type ever cross-reads another DID's folder (role-confusion) | ✓ 3 tests |
| `routing_classify` | `routing::classify_endpoint` + `server::uri_points_at_self` | `POST /mediator/v1/inbound` → forward pipeline, with attacker-minted `did:peer:2` endpoints | the mediator's own address is never misclassified as a remote relay (SSRF-adjacent) | ✓ 2 tests |
| `trust_task_freshness` | `trust_task_verify` freshness/retention date arithmetic (wraps `trust-tasks-rs` `FreshnessPolicy`) | Authenticated-remote trust-task `issuedAt`/`expiresAt` | no overflow/underflow on attacker-controlled timestamp arithmetic | ✓ 6 tests |

> **Change-detection in action:** on first run against current `main`, `jwt_auth`'s
> boundary matrix flagged that an unknown-session JWT now returns **401**, not the
> **500** recorded at engagement time (AMM-01) — i.e. the mediator fixed that
> status-code mapping independently. The assertion is now pinned to `401` so the
> fix can't silently regress. This is exactly the regression-protection these
> harnesses exist to provide.

## Running

```bash
# libFuzzer targets (nightly):
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60

# coverage for one target (uses the local corpus):
cargo +nightly fuzz coverage --fuzz-dir fuzz <target>
```

Corpora are not committed (`/fuzz/corpus/` is gitignored by repo convention);
libFuzzer rediscovers coverage from the seeds it generates. The weekly `Fuzz`
workflow (`.github/workflows/fuzz.yml`) runs every active target for a few
minutes and uploads any crash reproducer as an artifact.
