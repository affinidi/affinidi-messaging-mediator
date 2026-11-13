### Breaking — A store failure is an error, never a success carrying it

- **Behaviour change (R1.1, R3.6):** a direct delivery, a TSP or bridged
  message, or a DIDComm v1 envelope that the store fails to keep is now
  answered with the store's error (`me.res.storage.*` 14/503, or the
  `limits.*` refusal) instead of `Stored` with the failure in `errors`.
  A mediator reply addressed to several recipients fails when it was stored
  for none of them; when some were stored it still answers `Stored` with the
  rest in `errors`. Clients that read `errors` out of a success must treat
  the error response as the failure.
- **Behaviour change (R3.6):** an `ephemeral` forward whose recipient has no
  live stream is answered with its own problem report,
  `w.m.delivery.not_live` (99, HTTP 404), instead of the uniform
  `delivery.refused`: the message was not delivered and is not queued.

### Breaking — Deliveries are recorded once the reply is written

- **Behaviour change (R1.1, R3.6):** Message Pickup `delivery` replies
  (DIDComm v2 and v1) no longer stamp messages delivered or emit `delivered`
  monitor events when they are fetched. Both happen once the reply has been
  packed and handed to its transport — the REST response body written, or
  the live stream's push accepted — and only for the messages actually
  attached. A message with no body, or (v1) a body that is not a v1
  envelope, stays queued and unreported.
- **Behaviour change (R1.1, R3.6):** `POST /outbound` with `delete` and
  `POST /fetch` with `FetchDeletePolicy::Optimistic` delete — and emit
  `delivered` — only once the response body has been written. A response
  that is never fully written deletes nothing, so the client can fetch
  again. A delete that fails after the write is logged; `delete_errors` is
  now always empty on both.
- A pickup `delivery` carries at most four `limits.message_size` of stored
  bodies (always at least one message); the rest stay queued for the next
  request.
- Rust API: `handlers::message_outbound_handler` and
  `handlers::inbox_fetch_handler` return `axum::response::Response`.

### Breaking — Trust-ping answers with `ping-response`

- **Wire change (R3.6):** the answer to a DIDComm trust-ping is now
  `https://didcomm.org/trust-ping/2.0/ping-response` (it reused the request
  type, so a conformant peer saw a new ping). Clients that match the answer
  by type should accept both while they may talk to an older mediator.
- Trust-ping and Discover Features requests must be addressed (`to`) to the
  mediator, the same check Message Pickup applies (`message.to`); the reply
  is no longer sent "from" whatever DID the request named.
- A Trust Task `ping` advertises only the protocols the build serves
  (`didcomm`, `tsp`), not both unconditionally.

### Breaking — Forward edge cases are refused, not guessed at

- **Behaviour change (R3.6):** a forward with more than one attachment is
  refused (`protocol.forwarding.attachments.too_many`); only the first used to
  be delivered while the sender was told `Forwarded`.
- **Behaviour change (R3.6):** `delay_milli` must be a whole number from 0 to
  `future_time_limit` × 1000. A negative, fractional or non-numeric value is
  refused (`protocol.forwarding.delay_milli`) instead of being read as 0 or as
  its magnitude.
- A forward's own `hop_count` is no longer read. Only the count an
  authenticated peer mediator carries on a re-wrap layer is used, as a floor,
  and it saturates instead of wrapping.
- **Behaviour change (R3.6):** a queue limit of N now admits N messages (it
  admitted N−1, and a limit of 1 admitted none). A queue limit below −1 in
  `[limits]` refuses to start; one stored on an account admits nothing.
  `account/update` refuses a queue limit below −2 or outside `i32`.

### Breaking — Message Pickup status and live delivery tell the truth

- **Behaviour change (R6.2, R3.6):** turning live delivery on where the
  mediator has no streaming task is refused
  (`protocol.pickup.live_streaming`, 501) instead of answered with a status
  claiming it is on.
- A status for a mux member names the member's DID in `recipient_did` (it
  named the principal's). After a `messages-received` that acknowledged only
  a member's messages, the status returned is the member's.
- `messages-received` names at most 100 ids
  (`protocol.pickup.messages_received.limit`), and no longer reads each
  message before deleting it; its `deleted` monitor events carry no protocol.

### Fixed — TSP Trust Task answers are the mediator's own messages

- A Trust Task answered over TSP is stored as the mediator's message, as the
  DIDComm path stores its replies: no queue or access-list gate after the
  task has run, and not counted against the requester's own queues. The
  requester must still hold an account.
- A relayed TSP message is stored, gated and counted as sent by its verified
  sender (`from_vid`), not by the relaying session.

### Fixed — Bounded work and audited partial outcomes in admin tasks

- `messaging/acl/get` reads all requested ACLs in one batch and refuses more
  than 100 DIDs (the pinned schema has no `maxItems`; the bound is enforced
  in code until the spec adds one).
- `messaging/message/list` scans in fixed chunks of 500 whatever `limit` is,
  and a store error reading delivery state is returned instead of the
  state being silently left out.
- `messaging/message/delete` reports a per-id store failure as
  `deleted: false` (the ids are named under
  `ext["com.affinidi.mediator"].failed`) and carries on, so deletes already
  done are reported and audited; the audit record says `outcome partial`.
- `messaging/queue/purge`, `account/update` and `access-list/update` audit
  an `outcome partial` record when a store failure stops them after part of
  the work was applied.
