### Changed — forwarding delivers to endpoints concurrently, with per-endpoint backoff

- The forwarding processor delivers to up to `max_concurrent_endpoints`
  next-hop endpoints at once (default 32). Messages for one endpoint still go
  out one at a time, usually in queue order; a retried message can now go
  after later ones. Before, endpoints were served one after another, so a
  slow peer delayed every other peer's forwards.
- Each delivery attempt is bounded by `delivery_timeout_seconds` (default
  90, env `PROCESSOR_FORWARDING_DELIVERY_TIMEOUT_SECONDS`), covering a
  WebSocket attempt and its REST fallback together.
- Backoff now applies to the failing endpoint only. The processor used to
  pause all forwarding for up to `max_backoff_ms` after a failed batch. Now
  the failed message is queued again with a not-before at the end of that
  endpoint's backoff, and the endpoint's other messages are held until the
  same time instead of being sent into the failure. Those were not sent, so
  they keep their retry budget. Every processor sharing the queue honours
  the not-before, so retries are spaced out on multi-processor deployments
  too.
- A processor holds at most `batch_size` × `max_concurrent_endpoints`
  claimed entries, one endpoint at most half of them, and an endpoint that
  is backing off at most `batch_size`, so backlogs for peers that are slow
  or down do not stop other peers' forwards being read. The rest stay
  claimed in the queue and are picked up again by the reclaim sweep.
- Claimed entries are no longer stranded when a processor stops or
  restarts. A processor refreshes the claims on what it holds, and any
  processor takes over an entry whose claim has been idle for
  `reclaim_idle_seconds` (new, default 180, env
  `PROCESSOR_FORWARDING_RECLAIM_IDLE_SECONDS`). Previously such entries were
  reclaimed but never delivered. The sweep follows its cursor over the whole
  pending list, so idle entries behind a long run of busy ones are reached.
  The same sweep delivers a forward with a requested delay (`delay_milli`)
  once it is due; a delay of up to `max_backoff_ms` is held in memory and
  sent on time.
- A processor only finishes an entry it still holds. Acking a delivered,
  refused, expired or abandoned entry, and replacing a failed one with its
  retry, are each one owner-checked write; an entry another processor has
  taken over is left to it. A processor that cannot confirm its claims for
  half of `reclaim_idle_seconds` (its store calls are failing) stops
  sending — including a REST fallback after a WebSocket attempt — reading
  and reclaiming until it can. A send already under way at that point
  completes, so its message can arrive twice; none is lost. Keep
  `reclaim_idle_seconds` at least twice `delivery_timeout_seconds` so such a
  send ends before another processor can take the entry over; the processor
  warns at start when it is not. A processor holding all it may skips the
  reclaim sweep. Reclaimed entries that cannot be parsed are dropped with a
  warning instead of being reclaimed again and again.
- Each delivered entry is acked as soon as the peer accepts it, rather than
  with the rest of its batch.
- A next hop whose URL does not parse, or that the egress policy does not
  admit, is final: the forward is dropped on the first attempt and the
  sender gets a problem report with the new code
  `e.p.me.res.forwarding.endpoint-not-permitted`. It used to be retried
  `max_retries` times and reported as abandoned.
- `ForwardQueueEntry` has a new `not_before_ms` field (unix ms, `0` = none),
  stored as `NOT_BEFORE_MS` on Redis. Entries written before it read as `0`;
  a processor from an earlier release ignores it and retries at once.
  `ForwardOutcome` has a new `NotPermitted` variant. `MediatorStore` has
  new required methods `forward_queue_refresh_claims` and
  `forward_queue_finish`, and `forward_queue_autoclaim` now takes a cursor
  and returns a `ForwardQueueClaimPage` with the cursor to continue from.

**Behaviour change (R3.6):** retries of a failed forward are spaced by the
endpoint's backoff across all processors; forwards to a non-permitted next hop
produce `e.p.me.res.forwarding.endpoint-not-permitted` instead of
`e.p.me.res.forwarding.abandoned`; messages may be relayed in a different
order than they were queued, across endpoints and, after a retry, within one;
and an entry a stopped processor held is delivered by another after
`reclaim_idle_seconds`, which can repeat a delivery the stopped processor made
but had not yet acked.
