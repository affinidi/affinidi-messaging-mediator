### Added — `messaging/mux/ack`: acknowledge frames on the mux connection

A `tsp-mux` socket is delete-to-ack, and a client acked out of band, with a
REST delete. Only the connection knows its members and their scopes, so on a
multi-instance mediator a delete landing on an instance that does not hold
the connection was refused for every member's frame, and those frames were
redelivered for ever.

- The mediator serves `messaging/mux/ack` 0.1
  (trustoverip/dtgwg-trust-tasks-tf#1174). The principal sends it on its mux
  connection, naming up to 100 message ids. The answer lists `acked` and
  `refused` (`notFound` / `notPermitted`).
- **Authority:** the principal's own frames, and a member's while it holds
  `delete` and its account stands, as for a REST delete on the connection's
  session. Both now go through one function, so they cannot drift.
- **Privacy:** an id held for no one the connection may act for is
  `notFound`, whoever holds it: an id is a hash of the message, and the
  answer does not confirm another DID's mail.
- On `tsp-mux` the answer is pushed to the socket and not stored.
  Acknowledging is idempotent, and a stored answer would itself need
  acknowledging.
- A store failure fails the request, retryable, rather than reporting a frame
  as not found. Off a mux connection the request is refused
  (`messaging/mux:notMuxConnection`); a plain `tsp-ack` socket closes on it,
  as it does for any refused frame.
- REST deletes behave as before.
