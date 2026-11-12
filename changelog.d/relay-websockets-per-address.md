### Changed — anonymous relay WebSockets are limited per address and metered

- **Behaviour change (R3.6):** when `security.enable_inter_mediator_relay`
  is on, one client address may hold at most
  `[limits] relay_connections_per_ip` (default 10) anonymous relay
  WebSockets at once (an IPv6 client is counted by its /64). All relay
  sockets still share the
  `max_websocket_connections_per_did` bucket; this stops one address from
  holding all of it. A socket over the limit is closed with 1013 ("relay
  connection limit reached for this address"). A relay upgrade whose client
  address cannot be determined is refused with `403`. The address is
  resolved as for per-IP rate limiting, so behind a load balancer set
  `trust_xff_cidrs`, or every peer shares the balancer's allowance.
- **Behaviour change (R3.6):** each relay WebSocket has an inbound budget:
  `relay_frames_per_second` / `relay_frame_burst` (50 / 100) and
  `relay_bytes_per_second` (4 MiB/s; the byte budget is never smaller than
  `ws_size`). A frame over budget is not processed. It gets a negative
  `relay-ack` with code 429, so the relaying mediator sends that message
  over REST. The socket stays open, and the relaying mediator does not
  suppress the WebSocket transport for that endpoint over a 429 ack (any
  other failure still suppresses it for five minutes).
- Every refusal is counted: `relay_connections_refused_total{reason}`
  (`per_ip`, `no_client_ip`) and `relay_frames_throttled_total{limit}`
  (`frames`, `bytes`). A refused connection is logged at warn. The first
  throttled frame on a socket is logged at warn, and later ones at debug.
- All five new limits must be greater than 0; startup refuses `0`.
  Authenticated sockets are unchanged.
