# Operating the mediator

A reference for running the mediator in production: the probe and metrics
routes, the `mediator` binary's subcommands, the metrics it exports, its
logs, and what happens on shutdown. Configuration keys are described where
they are set, in [`conf/mediator.toml`](../conf/mediator.toml); every key with
an `Env:` line there can also be set from the environment, and the
environment wins.

Paths below assume the default `api_prefix = "/mediator/v1/"`. With
`api_prefix = ""` they sit at the host root.

## Probe routes

| Route | Answers | Use it for |
|---|---|---|
| `GET /mediator/v1/livez` | `200 {"status":"alive"}` whenever the HTTP server can answer. | Liveness. Restart the process only when this fails. |
| `GET /mediator/v1/readyz` | `200` `ready` or `degraded`, or `503` `not_ready`, with a JSON body of checks. | Readiness. Route traffic to the instance only while it is `200`. |
| `GET /mediator/v1/healthchecker` | `200` with the version and start time. | Humans. Kept for older tooling. |

The probe routes sit outside the per-IP rate limiter, the request body limit
and the request timeout, so a busy mediator never refuses its orchestrator.
They are inside the CORS policy, so a browser console the mediator allows can
read `readyz`.

`livez` is deliberately shallow. A Redis outage or a restarting background
task does not fail it, so an orchestrator does not kill a mediator that is
still serving.

### What `readyz` checks

Cheap, in-process state is read on every request:

| Check | Fails when |
|---|---|
| `shutdown` | The mediator has started shutting down. A draining instance drops out of rotation at once. |
| `redis_circuit_breaker` | The storage circuit breaker is not `closed` (repeated storage failures). |
| `components` | A supervised background task that is load-bearing is not `Running`. A non-load-bearing one only turns the status to `degraded` (still `200`). |

The backend checks cost a storage round trip or a billed secret-store call,
so they run at most once every 5 seconds, however often the route is probed,
and requests in between are answered from the last result:

| Check | Fails when |
|---|---|
| `redis` | Reading the global statistics from the store fails or times out (the name is historical: it is the store check on every backend). |
| `forward_queue` | The forwarding queue cannot be read (`fail`), or is at `limits.forward_task_queue` (`warn`, which also makes the instance `not_ready`). |
| `secrets_backend` | A read-only probe of the secret backend fails or takes over 5 seconds. |
| `vta_cache` | The cached VTA bundle cannot be read (`warn` only; the mediator keeps serving from the keys it holds). |
| `backend_checks` | No backend result is recent enough: the refresh has not completed within roughly two intervals plus its timeouts. |

The body also carries `version`, `uptime_seconds`, `components` (name,
state, load-bearing, restart count, whether it has an error),
`secrets_backend_reachable`, `vta_cache_age_secs` and
`operating_keys_loaded`. Error details are never in the body, because the
route is unauthenticated; they go to the log, once per refresh.

The supervised components are:

| Component | Load-bearing | Runs when |
|---|---|---|
| `forwarding_processor` | yes | `[processors.forwarding] enabled` |
| `vta_refresh` | yes | the `vta` feature and a VTA-linked deployment |
| `websocket_streaming` | no (clients fall back to polling) | `[streaming] enabled` |
| `statistics` | no | always |
| `message_expiry_sweep` | no | `[processors.message_expiry_cleanup] enabled` |
| `session_expiry_sweep` | no | `[processors.session_expiry_cleanup] enabled` |
| `mux_sync`, `monitor_fanout` | no | DID multiplexing enabled (`monitor_fanout` only on a store shared between processes) |
| `redis_stored_functions` | no | Redis: the loaded Lua library differs from the one the binary was built with |

A task that fails or panics is restarted with capped backoff; the mediator
never exits because a background task died.

## `/metrics`

Prometheus text format at `GET /mediator/v1/metrics`. It is outside the
per-IP limiter (a scraper must not compete with traffic) but has its own
gate, applied in this order:

1. **Address.** The client address must be in `[server] metrics_allow_cidrs`
   (env `METRICS_ALLOW_CIDRS`). The default admits loopback, the private
   ranges (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`),
   link-local and IPv6 unique-local. `[]` refuses everyone. Otherwise `403`.
2. **Token.** With `metrics_bearer_token` (env `METRICS_BEARER_TOKEN`) set,
   the request needs `Authorization: Bearer <token>`. Otherwise `401`. An
   empty token is refused at startup.
3. **Rate.** `[limits] metrics_requests_per_second` (default 5, burst twice
   that) is shared by all callers. Over it: `429`.

Refusals are counted in `metrics_requests_refused_total{reason}`. The client
address is resolved the same way as for the rate limiter: behind a reverse
proxy, list the proxy in `[server] trust_xff_cidrs`, or every request appears
to come from the proxy's (usually private) address. The mediator warns at
startup when `/metrics` admits private ranges and `trust_xff_cidrs` is empty.

## The `mediator` binary

```text
mediator [-c <config>]                 run the server
mediator [-c <config>] healthcheck [--url <url>]
mediator [-c <config>] rotate-admin [--dry-run]
```

`-c, --config` defaults to `conf/mediator.toml`, relative to the working
directory.

- **No subcommand** runs the mediator.
- **`healthcheck`** works out the `livez` URL from the config file (with the
  usual environment overrides): `listen_address` (a wildcard bind is probed
  on loopback), `api_prefix` and `use_ssl`. It exits `0` on a `2xx` within 5
  seconds and `1` otherwise, printing one line on failure. The container
  image's `HEALTHCHECK` runs it, so the image needs no curl. It checks
  liveness only, on purpose: a Docker healthcheck that failed on a Redis blip
  would restart a mediator that is fine.
- **`rotate-admin`** (needs the `vta` feature) replaces the mediator's admin
  credential through its VTA: it registers a fresh did:key with the same ACL
  scope, writes it to the secret backend and removes the old entry.
  `--dry-run` prints the plan and changes nothing.

## Metrics catalogue

Counters end in `_total`; every `*_duration_seconds` histogram uses the same
fixed buckets, so it aggregates across instances.

### HTTP and connections

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status` | Requests answered. `status` is `cancelled` when the client went away first. |
| `http_request_duration_seconds` | histogram | `method`, `route` | Request latency. |
| `http_requests_in_flight` | gauge | | Requests being handled now. |
| `http_connections_open` | gauge | | TCP connections held, WebSockets included. |
| `http_connections_refused_total` | counter | | Connections closed on accept at `limits.max_http_connections`. |
| `rate_limited_total` | counter | `scope` (`ip`, `did`, `ws`) | Requests refused, or WebSocket messages delayed, by a rate limit. |
| `rate_limit_attribution_failures_total` | counter | `reason` | Requests the per-IP limiter could not attribute (bad `X-Forwarded-For` from a trusted proxy, no client address). Non-zero is a proxy misconfiguration. |
| `metrics_requests_refused_total` | counter | `reason` (`address`, `token`, `rate`, `no_client_ip`) | `/metrics` refusals. |

### Authentication and access

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `auth_challenges_total` | counter | | Challenges issued. |
| `auth_success_total` | counter | | Completed authentications (DIDComm and TSP). |
| `auth_refresh_total` | counter | | Token refreshes. |
| `auth_failures_total` | counter | `reason` | Refresh-token reuse or a session with no recorded refresh token; the session is ended. |
| `acl_denials_total` | counter | `action` | Requests denied by an ACL check. |
| `mux_login_check_failures_total` | counter | | Direct logins refused because the DID multiplexing unknown-key rule could not be applied. |
| `trust_task_acceptance_failures_total` | counter | `reason`, `mode` (`warn`, `enforce`) | Trust Tasks failing the acceptance checks (stale, identity mismatch, proof, policy, duplicate). |

### Messages and queues

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `messages_inbound_total` | counter | | Messages received. |
| `message_bytes_inbound_total` | counter | | Bytes received on `/inbound`. |
| `messages_stored_total`, `messages_delivered_total`, `messages_deleted_total` | counter | | Store totals, sampled from the store every 60 s. (On Redis, `messages_stored_total` is also incremented on each store between samples.) |
| `store_received_bytes_total`, `store_sent_bytes_total`, `store_deleted_bytes_total` | counter | | Byte totals, sampled likewise. |
| `messages_first_delivered_total` | counter | | Messages handed to a recipient for the first time. |
| `messages_redelivered_total` | counter | | Handovers of a message already delivered. A sustained rate means messages are collected and not released. |
| `messages_poison_suspected_total` | counter | | Handovers of a message delivered many times. Classification only; nothing is evicted. |
| `messages_delivered_expiry_advanced_total` | counter | | Expiries brought forward by `limits.delivered_expiry_seconds`. Absent while that is `0`. |
| `message_store_duration_seconds` | histogram | | Time to store a message (Redis backend). |
| `queue_limit_refusals_total` | counter | `gate` (`peer`, `sender`, `recipient`) | Messages refused by a queue-depth limit. |
| `queue_depth_messages`, `queue_depth_bytes` | gauge | `folder` (`inbox`, `outbox`) | Queued messages and bytes across surveyed accounts. Inbox and outbox count the same messages from each end; do not add them. |
| `queue_oldest_age_seconds` | gauge | `folder` | Age of the oldest queued message probed. The signal for a queue that has stopped draining. `NaN` means unknown, not healthy. |
| `queue_max_saturation_ratio` | gauge | `folder` | Highest used-to-permitted depth on any account; `1.0` is the refusal point. |
| `queue_delivered_unacked_messages`, `queue_delivered_unacked_sample_size` | gauge | `folder` | Sample of queued messages already delivered, and the sample size. |
| `queue_accounts_surveyed`, `queue_survey_truncated` | gauge | | Accounts in the last survey; `1` when it stopped early and the totals are lower bounds. |
| `account_activity_write_failures_total` | counter | | Last-active records that could not be written. |
| `audit_write_failures_total` | counter | | Audit entries that could not be written (the change still happened). |

### Forwarding

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `messages_forwarded_total` | counter | | Forwards enqueued for a remote hop. |
| `forward_queue_length` | gauge | | Forwarding queue depth, sampled every 60 s. |
| `forward_loop_detected_total` | counter | | Forwards dropped for exceeding `max_hops` or looping back. |
| `forward_problem_report_live_publish_failed_total` | counter | | Forwarding problem reports stored but not pushed live. |
| `relay_connections_refused_total` | counter | `reason` (`per_ip`, `no_client_ip`) | Anonymous inter-mediator relay sockets refused. |
| `relay_frames_throttled_total` | counter | `limit` (`frames`, `bytes`) | Relay frames refused for rate; the peer falls back to REST. |

### WebSocket and live delivery

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `active_websocket_connections` | gauge | | Open WebSockets. |
| `websocket_connections_opened_total`, `websocket_connections_closed_total` | counter | | Store totals, sampled every 60 s. |
| `ws_send_buffer_available_bytes` | gauge | | Free bytes in the shared send-buffer pool (`limits.ws_send_buffer`). |
| `ws_live_delivery_dropped_total` | counter | | Live pushes dropped for a full send buffer or queue. Not loss: the message stays in the inbox. |
| `ws_live_resync_sent_total`, `ws_live_resync_suppressed_total` | counter | | Pickup `status` messages sent after a dropped push, and those held back by the per-socket minimum interval. |
| `ws_streaming_lagged_total` | counter | | Times the streaming task fell behind its notification feed; clients are resynced. |
| `ws_write_timeouts_total` | counter | | Writes that missed the write deadline; each closes its socket. |
| `ws_pong_timeouts_total` | counter | | Sockets closed for silence past `limits.ws_pong_timeout_secs`. |
| `websocket_duplicate_replacements_total`, `websocket_duplicate_churn_total`, `websocket_churn_refused_total` | counter | | A newer socket for the same DID replacing an older one; replacements in quick succession; registrations refused to damp a duel. |
| `websocket_redelivered_messages_total` | counter | | Inbox messages re-pushed after a replacement. |
| `streaming_entries_reclaimed_total` | counter | `kind` (`direct`, `mux`), `reason` (`missing`, `dead_owner`, `outranks_mux`) | Live-delivery entries this instance took back. Normally 0 outside upgrades and instance failures. |
| `streaming_entries_evicted_total` | counter | | Entries removed because their owning instance's heartbeat expired. |
| `streaming_heartbeat_lapses_total` | counter | | Times this instance found its own heartbeat had lapsed. |

### DID multiplexing

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mux_connections` | gauge | `wire` (`didcomm`, `tsp`) | Live mux connections on this instance. |
| `mux_members` | gauge | `source` (`grant`, `attach`) | Member DIDs carried. |
| `mux_detach_total` | counter | `reason` | Members detached or refused, by the protocol's detach reason. |
| `mux_queue_fairness_skips_total` | counter | | Pushes refused because one member held its share of the connection's queue. |
| `mux_live_frames_withheld_total` | counter | `outcome` (`nudge`, `drop`) | Frames not written because of the member's scope. |
| `mux_grant_revalidate_failures_total` | counter | `cause` (`resolution`, `store`) | Member key re-checks that reached no decision. |
| `monitor_fanout_dropped_total`, `monitor_fanout_received_total` | counter | `cause` on dropped | Membership events shared with, or received from, other instances. |

See [multiplexing.md](multiplexing.md) for the protocol itself.

### Storage, sessions and secrets

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `circuit_breaker_state` | gauge | | Storage circuit breaker: `0` closed, `1` open, `2` half-open. |
| `circuit_breaker_trips_total` | counter | | Times it opened. |
| `redis_functions_match_build` | gauge | | `1` the loaded Lua library matches this build, `0` it does not, `-1` the check could not run. |
| `sessions_created_total`, `sessions_authenticated_total` | counter | | Store totals, sampled every 60 s. |
| `oob_invites_created_total`, `oob_invites_claimed_total` | counter | | Out-of-band invitation totals, sampled likewise. |
| `vta_refresh_total` | counter | `result` (`vta`, `cache`, `forbidden`, `error`) | VTA secrets-refresh attempts. |
| `vta_refresh_duration_seconds` | histogram | | VTA refresh round trip. |
| `vta_last_success_timestamp_seconds` | gauge | | Last successful refresh from the VTA. Alert on `time() -` this. |

The doc comments on each constant in
[`src/common/metrics.rs`](../src/common/metrics.rs) say how to read the
less obvious ones.

## Logs

| Setting | Env | Effect |
|---|---|---|
| `log_level` | `MEDIATOR_LOG_LEVEL` (or `LOG_LEVEL`) | `trace`, `debug`, `info`, `warn` or `error`. |
| `log_json` | `LOG_JSON` | `true` writes one JSON object per line. |
| | `RUST_LOG` | When set, replaces `log_level` entirely (standard `tracing` filter syntax, e.g. `info,affinidi_messaging_mediator=debug`). |
| | `LOCAL` | When set, coloured output and the start-up banner. Leave unset in production. |

Fields worth indexing:

- Every HTTP request runs in a `request` span with `method`, `path` (no
  query string) and `request_id`, so anything a handler logs carries them.
- One access-log line per request, target `http_access`, with `request_id`,
  `method`, `route` (the matched route, not the raw path), `status` (or
  `outcome = cancelled`) and `latency_ms`.
- `request_id` is the caller's `x-request-id` when it is a plausible id (up
  to 128 characters of letters, digits, `-`, `_`, `.`, `:`), otherwise a new
  UUID. It is echoed back in the `x-request-id` response header.
- Refusals that the client sees only as a generic code (for example 73
  `e.p.delivery.refused`) log the real reason against the `session` id.

Embedded mediators (`MediatorBuilder`) install no tracing subscriber unless
asked to.

## Shutdown

`SIGTERM` or `SIGINT` starts a graceful shutdown (an embedding application
calls `MediatorHandle::shutdown()` instead). All of these start at once:

- `readyz` answers `503` (`shutdown` check) to any probe that still reaches
  it.
- The HTTP server stops accepting connections and gives in-flight requests
  up to 30 seconds.
- Every open WebSocket is closed with code `1001` "mediator shutting down",
  so clients know to reconnect; each deregisters and records its close.
- Supervised background tasks are stopped.

Once the HTTP server has stopped, the process waits up to 10 more seconds for
the sockets to finish closing and the tasks to stop, logs what is still open
if it gives up, then exits. Upgraded WebSockets are not tracked by the HTTP
server's own drain, which is why this second wait exists.

Give the container a stop grace period of at least 45 seconds so this is not
cut short. Messages are durable in the store throughout: a client that
reconnects to another instance picks up what it had not acknowledged.

## Key environment variables

All of these mirror a key in `conf/mediator.toml`, which documents the
values; the template's `Env:` lines list the rest.

| Variable | Sets |
|---|---|
| `MEDIATOR_DID`, `ADMIN_DID` | The mediator's DID and the root admin DID. |
| `MEDIATOR_SECRETS_BACKEND` | The secret backend URL. |
| `MEDIATOR_LISTEN_ADDRESS`, `API_PREFIX` | Where the server listens and mounts its routes. |
| `MEDIATOR_DATABASE_URL` (or `DATABASE_URL`), `DATABASE_CLUSTER_MODE` | Redis. |
| `STORAGE_BACKEND`, `STORAGE_DATA_DIR` | `redis` or `fjall`, and Fjall's directory. |
| `MEDIATOR_USE_SSL`, `SSL_CERTIFICATE_FILE`, `SSL_KEY_FILE` | TLS on the listener. |
| `TRUST_XFF_CIDRS` | Reverse proxies trusted for `X-Forwarded-For`. |
| `METRICS_ALLOW_CIDRS`, `METRICS_BEARER_TOKEN` | `/metrics` access. |
| `STREAMING_ENABLED` | Live delivery over WebSocket. |
| `LIMIT_MUX_ENABLED` | DID multiplexing. |
| `MEDIATOR_ALLOW_TEST_IDENTITY` | Lets a release build start with the sample identities committed to this repository. Test deployments only. |

Limits can also be changed at runtime, without a restart, by a root admin
with the `config/patch` and `config/reload` Trust Tasks.
