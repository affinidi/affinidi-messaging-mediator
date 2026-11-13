### Changed — the HTTP server bounds slow, idle and excess connections

- HTTP/1 clients have `limits.http_header_read_timeout_secs` (default 30) to
  send a request's headers. The clock runs whenever a connection waits for its
  next request, so idle keep-alive connections are closed after it too, and a
  new connection that sends nothing is closed at the same deadline. hyper
  never enforced its header timeout before, because the server had no timer.
  HTTP/2 connections are pinged every 20 s and closed when a ping goes
  unanswered for 20 s.
- Each HTTP request other than `/ws` has `limits.http_request_timeout_secs`
  (default 60), body upload included. Past it the mediator answers **408** and
  drops the request's work. A client uploading a message near `http_size` over
  a slow link may need this raised.
- `limits.max_http_connections` (default 20000, 0 = unlimited) caps the TCP
  connections the listener holds, WebSockets included. A connection over the
  cap is closed as soon as it is accepted, before TLS. New metrics:
  `http_connections_open` and `http_connections_refused_total`.
- An unreadable value for any of the three keys refuses to start. All three
  are documented in `conf/mediator.toml`, with `LIMIT_*` environment overrides.

### Changed — OOB invitation lookups answer with real HTTP status codes

- `GET /oob?_oobid=` for an unknown invitation answers HTTP **404**, and a
  `DELETE /oob` by a non-admin for an unknown invitation answers HTTP **404**.
  Both used to answer HTTP 200 with a body whose `httpCode` was 404 or 204.
  The SDK already treated both answers as errors. A client that read only the
  body's `httpCode` must now also accept a non-2xx status (R3.6).

### Changed — `/fetch` takes its limit from `limits.listed_messages`

- `POST /fetch` accepts a `limit` from 1 to `limits.listed_messages` (default
  100). It was hardcoded to 100, so a mediator configured with another value
  refused, or allowed, the wrong amount. A `start_id` must now be a whole
  message id: one with characters before it used to pass.

### Fixed — request metrics and access logs

- A request whose client disconnects mid-flight no longer leaves
  `http_requests_in_flight` one higher for good. It is counted in
  `http_requests_total` with `status="cancelled"` and logged as cancelled.
- Each request is logged once, at INFO, by the `http_access` line. The
  `TraceLayer` still opens a span per request, so handler logs carry the
  method, path and request id, but it no longer logs its own lines.
- Query strings are no longer logged. The request span records the path
  only, so an OOB invitation id (`/oob?_oobid=`) stays out of the logs.
- An inbound `x-request-id` is reused only if it is 1 to 128 characters of
  ASCII letters, digits, `-`, `_`, `.` or `:`. Anything else is replaced with
  a fresh UUID before it is logged or echoed back.
- Client DIDs in the authentication and REST handler logs are logged as
  hashes (`did_hash`), never raw. A message fetched over `/outbound` is no
  longer logged whole at DEBUG; its id and size are.

### Fixed — peer mediator responses are bounded and escaped before logging

- When a next-hop mediator refuses a forward, at most 2 KB of its response
  body is read, and control and bidirectional-formatting characters in it are
  escaped, before it goes into the logged and reported failure reason. A
  relay-ack `reason` gets the same treatment. Before, the whole body was
  buffered and logged verbatim, so a hostile endpoint could fill memory or
  forge log lines.

### Fixed — the standalone processors

- The standalone `forwarding_processor` refuses to start with
  `report_errors = true`: it has no keys to pack the failure reports with, so
  it silently reported nothing. The shipped `conf/forwarding.toml` now sets
  `report_errors = false` and also has the settings it was missing
  (`future_time_limit` and others), without which it did not parse at all.
- Both standalone processors return config file errors instead of panicking,
  and stop cleanly on SIGINT or SIGTERM.
- A live-delivery notification for a DID no socket on this instance holds is
  logged at DEBUG instead of WARN. The stale streaming claim behind it is
  released, so later messages stop being routed to this instance.

### Changed — `jwt_refresh_expiry` is documented as what it does

- A refresh token is valid for `jwt_refresh_expiry - jwt_access_expiry`
  seconds from issue (85500 s with the shipped values). `conf/mediator.toml`
  described it as the refresh-token lifetime. The behaviour is unchanged.

### Removed — dead code in the request path

- `handlers::LoadState` and `common::jwt_auth::TokenPayload`, which nothing
  used. `SharedData::config` is now `Arc<Config>`, so the configuration is no
  longer deep-cloned on every request, and the `Session` and `MaybeSession`
  extractors take `SharedData` by reference. Code that built a `SharedData`
  by hand must wrap its `Config` in an `Arc`.
