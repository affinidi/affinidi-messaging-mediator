### Changed — a Trust Task that does not ask is refused with a problem report again (R3.6)

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
- The codes do not change: both forms carry the Trust Task code (`e.p.`
  before it in a problem report). A client that matched the mediator's old
  codes (`account.not_found`, `authorization.*`) must still move to the new
  ones.
- The ask is needed while 0.51 is supported, until 2027-02-07. It is to be
  withdrawn in the first release cut after that date, which answers every
  refusal with a document again.
