### Breaking — AWS deployments: grant `secretsmanager:UpdateSecretVersionStage` before upgrading

- Grant `secretsmanager:UpdateSecretVersionStage`, next to `PutSecretValue`,
  to every role that writes (`mediator-setup`, the mediator, and whoever runs
  `mediator rotate-admin`) on `<prefix>mediator_secrets_bundle` and, on a
  deployment not yet cut over to the bundle, on the per-key secret names too:
  until the cutover every write goes to the per-key secret first, and that
  write is conditional as well. Without it the first write of a new secret
  still succeeds, and the next one fails with `AccessDeniedException`, so
  `mediator-setup` or `rotate-admin` stops before it finishes.

### Breaking — a Trust Task that does not ask is refused with a problem report again (R3.6)

- **Wire change (R3.6), only for a request that does not ask.** A refused
  Trust Task is answered with a `trust-task-error` document when the request
  carries `"x-errorFormat": "trust-task-error"`, and with the problem report
  `e.p.<code>` otherwise. 0.52 and 0.53.0 sent the document to every
  request; releases up to 0.51 sent only problem reports, and a client
  written for them (`affinidi-messaging-sdk` before 0.46.2) cannot parse the
  document: every refusal reached it as `response is not a Trust Task
  document: unknown field 'code'`.
- `affinidi-messaging-sdk` asks on every Trust Task from 0.46.2, so a client
  on it sees no change.
- **A raw-TSP socket closes on a refusal that does not ask.** Over a `tsp` or
  `tsp-ack` WebSocket, any refused Trust Task that does not ask (an
  `account/add` the sender may not make, a `messaging/mux/ack` off a mux
  connection, …) closes the socket with 1008 again, as any refused frame on
  such a socket does: a raw-TSP socket has no in-band error frame. 0.52 and
  0.53.0 kept the socket open and sealed the document back instead, so a
  hand-built TSP client written for them that does not ask loses its live
  delivery on a refusal and must reconnect. One that asks still gets the
  sealed `trust-task-error` (`messaging/mux:notMuxConnection` for the mux
  ack). A `tsp-mux` socket is unaffected: it reports the refusal with its
  `refused` event.
- The codes do not change: both forms carry the Trust Task code (`e.p.`
  before it in a problem report). A client that matched the mediator's old
  codes (`account.not_found`, `authorization.*`) must still move to the new
  ones.
- The ask is needed while 0.51 is supported, until 2027-02-07. It is to be
  withdrawn in the first release cut after that date, which answers every
  refusal with a document again.
