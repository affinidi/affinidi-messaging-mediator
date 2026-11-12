### Fixed — WebSocket relay to a next hop is time-bounded and dials the checked address

- Every step of a WebSocket relay attempt to a next-hop mediator now has a
  limit: name resolution, TCP connect, TLS and the upgrade together get 10 s;
  the whole attempt (pooled socket, a reconnect if that failed, the send and
  the peer's `relay-ack`) gets 30 s, or a third of `delivery_timeout_seconds`
  if that is less, so the REST fallback always has time left. The close
  handshake on a discarded socket runs on its own task, bounded at 5 s. A
  next hop that accepts the connection and never completes the handshake used
  to hold the attempt until `delivery_timeout_seconds` ran out, with no REST
  fallback, and the same thing happened on every retry; it now falls back to
  REST after 10 s.
- When a next-hop name resolves to several addresses, each gets a share of
  the connect time (at least 2 s), so one that never answers does not stop
  the others being tried.
- The processor logs a warning at startup when `delivery_timeout_seconds` is
  below 60.
- The socket is dialed at an address that the egress policy admitted. A
  next-hop name is resolved once, through the same guarded resolver the REST
  client uses, and the connection goes to one of those addresses; TLS SNI,
  certificate validation and the `Host` header still use the name. Before,
  the name was checked and then resolved again by the WebSocket client.
- A pooled relay socket is taken out of the pool for the exchange and put
  back after it, so the pool lock is never held during network I/O and no
  two deliveries share a socket.
- **Behaviour change (R3.6):** the 30 s wait for the peer's `relay-ack` now
  starts when the attempt starts, not after the connection is open, so a peer
  that takes longer than 30 s from dial to ack is relayed to over REST
  instead. Resolved addresses are now judged by the forwarding egress
  policy, the same check as on REST; in a release build that policy admits
  only globally routable addresses, as before. Discarded relay sockets are
  logged at `info`.
