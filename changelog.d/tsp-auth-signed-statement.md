### Changed — TSP login signs a statement naming the mediator, the session and an expiry

- **Behaviour change (R3.6):** `POST /tsp/authenticate` now verifies the
  signature over a statement, not over the challenge string alone. The client
  signs the RFC 8785 canonical JSON
  `{"body":{"challenge","session_id"},"created_time","expires_time","from","to","typ"}`
  with `typ` `https://affinidi.com/atm/1.0/tsp/authenticate`, `from` its VID
  and `to` this mediator's DID: the fields of the DIDComm authentication
  message. The request carries `to`, `created_time` and `expires_time` next to
  `vid`, `session_id` and `signature`; the mediator rebuilds the statement
  from the challenge it issued and verifies it. Clients send this from
  `affinidi-messaging-sdk` 0.45.16.
- A statement addressed to another DID is refused with
  `authentication.tsp.statement.audience` (error code 32, `401`); one that has
  expired, was made more than 60 s ahead of the mediator's clock, or is valid
  for longer than 300 s with `authentication.tsp.statement.expired` (31,
  `401`); a request with only some of `to`, `created_time` and `expires_time`
  with `authentication.tsp.statement.incomplete` (28, `400`).
- A request in the older form (no `to`, `created_time` or `expires_time`) is
  refused with `authentication.tsp.statement.required` (32, `401`). Clients on
  `affinidi-messaging-sdk` before 0.45.16 send that form and cannot log in
  over TSP until they upgrade, unless the operator sets the new
  `security.tsp_auth_accept_unbound_until` (env
  `TSP_AUTH_ACCEPT_UNBOUND_UNTIL`) to an RFC 3339 time: until then the older
  form is also accepted, with a warning at boot and on every login that uses
  it. Empty (the default) accepts only the statement; a value that does not
  parse stops the mediator from starting.
- The request body now refuses unknown fields. `TspAuthenticateBody` gains
  the optional `to`, `created_time` and `expires_time` fields, and the
  module exports `signed_statement_bytes` and `TSP_AUTH_TYP`.
- `TestMediatorBuilder::tsp_auth_accept_unbound_until` sets the new setting
  in tests.
