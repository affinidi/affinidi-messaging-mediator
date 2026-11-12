### Added — DID multiplexing on raw-TSP sockets (`tsp-mux`)

- A raw-TSP WebSocket can now be a mux connection (spec
  `messaging/mux/event/0.1`, "Raw-TSP sockets"). The client offers `tsp`,
  `tsp-ack`, `tsp-mux` in that order. The mediator selects `tsp-mux` only in
  a TSP build with `limits.mux.enabled` on and a streaming task running.
  Otherwise it selects `tsp-ack` or `tsp` as before, so a mediator that will
  not multiplex never claims it will. A `tsp-mux` offer that is not selected
  is no longer echoed back. `tsp-mux` implies `tsp-ack`.
- On a `tsp-mux` socket the mux events (`ready` first, then `attached` for
  grants carried on connect, then `attached`/`detached` as members change)
  are signed `messaging/mux/event` documents. Each is sent as a TSP Direct
  message from the mediator's VID to the principal's, in a Binary frame. Mux
  Trust Tasks use the existing TSP Trust Task path, and their responses
  arrive through the principal's inbox. If `ready` cannot be sealed, the
  socket closes (1011) instead of running a mux connection the client
  cannot see.
- Members' live frames arrive untagged on the principal's socket. The
  client routes each one by the receiver VID in its envelope. A frame stays
  stored until it is acked.
- **In-band refusals.** On a `tsp-mux` socket a refused inbound frame no
  longer closes the socket. The mediator sends a `refused` event with
  `frameId` (lowercase hex SHA-256 of the frame's exact bytes) and `code`
  (the traffic monitor's refusal code). Where it can read them, it adds
  `sender`, `receiver` and `reason`. The socket still closes when the
  principal's token expires, when the principal's account is blocked, on a
  protocol violation (a Text or non-TSP frame), and when the event cannot
  be sealed. Plain `tsp` and `tsp-ack` still close on a refusal.
- **Inbox drain.** On connect, a `tsp-mux` drain empties the principal's
  inbox first. It then goes round-robin through the attached members with
  `pickup`, one bounded page per member per round. A resync drains the
  principal and only the members owed one (per-member resync, as on a
  DIDComm mux connection). The principal's own live notifications drain
  only the principal. Nothing is
  deleted on send. An ack (a delete by message id) is authorised against
  the owning member's `delete` scope, so a member without `delete` keeps
  its frames in its inbox.
- Membership is re-checked before each drain page and each live write, so
  a member detached part-way through a drain gets nothing more. Closing a
  `tsp-mux` socket tears down its mux connection. That now also happens
  when a mux socket closes during flush-on-connect or because its token had
  already expired.
