### Changed — messages on an authenticated WebSocket are rate limited

- Every text or binary message read from an established, authenticated
  WebSocket is now metered per socket, at the same rate as HTTP requests:
  `limits.ws_messages_per_second` and `limits.ws_message_burst` (new) inherit
  `rate_limit_per_ip` / `rate_limit_burst` (100 a second, burst 50, by
  default) when unset; set them to override. If the per-IP value is `0`
  (per-IP limiting off, as is usual behind a load balancer) the built-in
  100 / 50 apply instead, so turning per-IP limiting off never turns this off.
  Only an explicit `ws_messages_per_second = "0"` disables it, and the
  mediator warns at startup when it is off. Ping, pong and close frames are
  not counted.
- The budget is per socket, not per DID: a DID-multiplexing connection has
  one budget shared by every DID it carries, however many there are. Raise
  `ws_messages_per_second` / `ws_message_burst` for busy multiplexing
  clients, and watch `rate_limited_total{scope="ws"}` to see when they are
  being slowed.
- A `ws_messages_per_second`, `ws_message_burst` or
  `ws_message_throttle_close_secs` value that is not a whole number refuses to
  start with a configuration error naming the key, rather than being replaced
  by a guess.
- When the per-DID limit (`limits.did_rate_limit_per_second` /
  `did_rate_limit_burst`, off by default) is enabled, each WebSocket message
  is also charged, exactly as an HTTP request is, to the sender's DID, so a
  DID shares one budget across all of its sockets. Previously only the `/ws`
  upgrade was charged.
- A message over either rate is held, not dropped: the mediator stops reading
  the socket until the message is due, so the client's further messages wait
  in its own send buffer and nothing is buffered for it on the mediator. Live
  delivery to the client continues meanwhile. A socket that stays over the
  rate for `limits.ws_message_throttle_close_secs` (new, default 10; `0` =
  never close) is closed with 1008 "message rate limit exceeded"; the clock
  resets when a message arrives within the rate.
- Messages that had to wait are counted in `rate_limited_total{scope="ws"}`
  (socket rate) and `rate_limited_total{scope="did"}` (DID rate).
- The mediator's own DID and the configured admin DID are not metered;
  anonymous inter-mediator relay sockets keep their own `limits.relay_*`
  budget.
- Env: `LIMIT_WS_MESSAGES_PER_SECOND`, `LIMIT_WS_MESSAGE_BURST`,
  `LIMIT_WS_MESSAGE_THROTTLE_CLOSE_SECS`. All three can be tightened with
  `config/patch`; a patch applies to sockets opened after it.
- `TestMediatorBuilder::ws_message_rate(per_second, burst, close_after_secs)`
  sets them for tests.

**Behaviour change (R3.6):** this is on by default. A client that sends
messages over one WebSocket faster than 100 a second (after a burst of 50;
or the configured `rate_limit_per_ip` / `rate_limit_burst`) is
now slowed to that rate, and one that keeps exceeding it for 10 seconds is
disconnected with close code 1008. Clients that send in bulk over a single
socket — including DID-multiplexing connections, whose members share the
socket's rate — should pace their sends or reconnect with backoff after a
1008, and operators with such clients should set
`limits.ws_messages_per_second` / `ws_message_burst` (or set
`ws_message_throttle_close_secs = 0` to slow without closing) before
upgrading. This includes deployments with `rate_limit_per_ip = 0`: they get
the built-in 100 / 50 unless they set these keys. With `did_rate_limit_per_second`
enabled, WebSocket messages now count against it.
