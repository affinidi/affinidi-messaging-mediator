### Fixed — a WebSocket client that has gone away is closed within a set time

- The mediator already pinged every WebSocket every 30 s but ignored the
  answer, so a client that vanished without closing (lost network, suspended
  device) kept its connection, slots and queued frames until TCP gave up,
  which can take many minutes. Now, once a ping goes unanswered, the client
  has `limits.ws_pong_timeout_secs` (new, default 90) minus the ping interval
  to send any frame, a pong included. Otherwise the socket is closed with 1001
  "connection unresponsive", within `ws_pong_timeout_secs` of the client's
  last frame. Time the mediator spends not reading (a large flush on connect,
  a slow message) does not count against the client. Its slots and
  live-delivery registration are released as on any other close. Counted in
  the new `ws_pong_timeouts_total`.
- Only complete frames count, so `ws_pong_timeout_secs -
  ws_ping_interval_secs` must cover the slowest single inbound frame upload.
- The ping interval and the write bound are now settings:
  `limits.ws_ping_interval_secs` (new, default 30) and
  `limits.ws_write_timeout_secs` (new, default 30, the value that was
  fixed). Env: `LIMIT_WS_PING_INTERVAL_SECS`, `LIMIT_WS_PONG_TIMEOUT_SECS`,
  `LIMIT_WS_WRITE_TIMEOUT_SECS`. The pong timeout is raised to at least two
  ping intervals, and each value to at least 1 s, with a warning, whether
  the values come from the file or are set in code.
- `TestMediatorBuilder::websocket_liveness(ping, pong, write)` sets all
  three for tests.
- Documented: on the plain `tsp` subprotocol a message is deleted once its
  frame is written to the connection, so a client that goes away can lose
  frames written shortly before the close. Use `tsp-ack` for at-least-once
  delivery.

**Behaviour change (R3.6):** a client that sends the mediator nothing for
90 s, not even a pong, is disconnected. A client answers pings only while it
reads its socket, so it must keep reading to stay connected. A TSP stream
must be read continuously: the TDK `TspStream` answers pings only while the
application is inside `recv()`. DIDComm clients of the TDK SDK read
continuously and send their own keepalive, so they are not affected.
