### Changed — `/readyz` reuses its backend checks; `/metrics` has access control and a request bound

- `/readyz` runs its storage, forwarding-queue, secret-backend and VTA-cache
  checks at most once every 5 s and answers every request in between from
  the last result, so polling it often costs no more backend calls than
  polling it once. The refresh runs in its own task, so it completes and is
  stored even if the request that started it times out. While it runs, other
  requests get the previous result, but only while that result is younger
  than two intervals plus the longest a refresh can take; past that,
  `/readyz` answers 503 with a failing `backend_checks` check rather than
  repeat an old answer. Each secret-backend read is bounded at 5 s. Shutdown, the storage circuit breaker and supervised-task state are
  still read on every request, and component errors are logged once per
  refresh rather than once per request. The response body is unchanged.
- **Behaviour change (R3.6):** `/metrics` is served only to clients in
  `[server] metrics_allow_cidrs` (env `METRICS_ALLOW_CIDRS`). The client
  address is resolved as for per-IP rate limiting, through
  `trust_xff_cidrs`. When the key is absent, loopback and the private
  (10/8, 172.16/12, 192.168/16), shared (100.64/10), link-local and IPv6
  unique-local ranges are allowed, so a Prometheus in the same host,
  cluster or VPC keeps scraping. A client on the public internet now gets
  `403`. `[]` refuses everyone.
  - Optional `[server] metrics_bearer_token` (env `METRICS_BEARER_TOKEN`)
    also requires `Authorization: Bearer <token>`; a missing or wrong token
    is `401`. An empty token, in the file or in the environment, is refused
    at startup rather than taken to mean no token; leave the key out to
    require none.
  - `[limits] metrics_requests_per_second` (default 5, burst twice that)
    bounds the endpoint across all callers; over it is `429` with
    `x-rate-limit-source: mediator`.
  - Refusals are counted in `metrics_requests_refused_total{reason}`.
  - The bearer scheme name is matched case-insensitively.
  - At startup, a warning is logged when `trust_xff_cidrs` is empty and
    `metrics_allow_cidrs` is the default.
  - Behind a load balancer that is not in `trust_xff_cidrs`, requests appear
    to come from the balancer's address. If that address is private,
    requests through it are still admitted; add the balancer to
    `trust_xff_cidrs`, or narrow `metrics_allow_cidrs` to the scraper.
- Requires affinidi-rate-limit 0.1.4 (was 0.1.3) for its client-address
  resolver.
