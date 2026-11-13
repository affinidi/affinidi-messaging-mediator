### Breaking — one error-code scheme: Trust Task refusals carry Trust Task codes, overloaded numbers split

Error codes are part of the client contract, so this is breaking for every
consumer that matches on them (R3.6). Clients on `affinidi-messaging-sdk`
0.46 that read refusals with `ATMError::refusal_code()` see the new codes
directly; code that matched the old mediator codes through
`ATMError::mediator_code()` must match the new ones below.

**Trust Task refusals.**

- Every refused Trust Task is answered with a `trust-task-error` document
  (SPEC §8), over every transport (DIDComm over REST or WebSocket, TSP, mux
  connections). The request no longer has to ask with
  `x-errorFormat: trust-task-error` (still accepted). A problem report is
  sent only where no document can be: the body is not a Trust Task
  document, the sender is unauthenticated or is not the session's own DID,
  or the document could not be signed. It carries the same code, as
  `e.p.<code>`.
- The code is always the framework's standard code (SPEC §8.3) or the
  `<task>:<code>` the task's specification declares. The mediator's own
  spellings are gone, and so is `details.mediatorCode`:

  | Old code | New code |
  | :------- | :------- |
  | `authorization.permission`, `authorization.account.denied`, `authorization.local`, `authorization.admin_required`, `authorization.queue_limit.admin_required`, `authorization.root_admin_required` (config/patch, config/reload), `message.trust_task.unauthenticated`, `account.update.protected` | `permissionDenied` |
  | root-admin refusals in `messaging/account/update` (was `authorization.permission`) | `messaging/account/update:rootAdminRequired` |
  | `authorization.queue_limit.not_self_manageable`, `authorization.acl.not_self_manageable` | `messaging/account/update:selfChangeDenied` |
  | access-list self-management refused (was `authorization.permission`) | `messaging/access-list/update:selfChangeDenied` |
  | `account.not_found` | `<task>:unknownAccount` (`messaging/account/get`, `messaging/account/update`, `messaging/queue/status`, `messaging/message/list`) |
  | `account.remove.protected` | `messaging/account/remove:protectedAccount` |
  | `message.trust_task.malformed`, `message.trust_task.rejected` (policy) | `malformedRequest` |
  | `message.trust_task.rejected` (basic validation) | `expired` or `wrongRecipient` |
  | `protocol.trust_task.unsupported` | `unsupportedType` |
  | `message.trust_task.stale` | `expired` |
  | `message.trust_task.identity_mismatch` | `identityMismatch` |
  | `message.trust_task.proof_required` / `.proof_invalid` | `proofRequired` / `proofInvalid` |
  | `message.trust_task.id_conflict`, `message.trust_task.duplicate` | `idConflict` |
  | `message.trust_task.unavailable`, `config.storage`, `config.reload.unavailable`, storage full/busy | `unavailable` |
  | `config.reload.invalid` | `taskFailed` |
  | `account.list.cursor`, serialisation failures | `internalError` |

- A `messaging/mux/ack` sent on a raw-TSP socket that is not a mux
  connection is answered with a sealed `trust-task-error`
  (`messaging/mux:notMuxConnection`) pushed on that socket; the socket used
  to be closed with 1008.
- A malformed ACL in `messaging/account/update` or `messaging/account/add`
  is a 400 `malformedRequest`; it was a 500 internal error (14).
- Trust Task refusals have their own numbers, 120–139 (one per standard
  code, 139 for a declared code); they were all 37.

**Numbers.** One number means one condition. Moved to new numbers:

| Old | New | Problem code |
| --: | --: | :----------- |
| 37 | 100 | `e.m.message.size.exceeded` |
| 37 | 101 | `e.p.protocol.unsupported`, `e.p.message.tsp.unsupported`, `e.m.message.didcomm_v1.unsupported` |
| 37 | 102 | `e.m.message.didcomm_v1.*` (malformed DIDComm v1 requests) |
| 37 | 47 | `e.p.message.tsp.reseal`, `e.p.message.tsp.trust_task.seal` / `.serialize`, `e.m.message.didcomm_v1.build` / `.pack` |
| 28 | 103 | `e.p.authentication.tsp.resolve`, `.signature.encoding`, `.signature.length` |
| 38 | 104 | `e.p.authentication.session.refresh_token.expired` |
| 38 | 105 | `e.p.authentication.session.refresh_token.reuse` |
| 44 | 106 | `e.p.authorization.authentication_required` |
| 44 | 60 | TSP `e.p.authorization.send_forwarded` (now the same number as DIDComm) |
| 43 | 107 | `e.p.api.message_outbound.limit` |
| 58 | 108 | `e.p.message.tsp.resolve`, `e.p.message.tsp.mediator.unresolvable` |
| 60 | 109 | `e.p.authorization.relay.untrusted_peer` (and its relay-ack) |
| 10 | 110 | `w.m.database.message.delete.not_found` |
| 10 | 111 | `w.m.database.message.delete.permission_denied` |
| 10, 11 | 3 | `e.p.me.res.storage.connection.blocking` |
| 91–97 | 14 | forwarding-queue storage failures (logged; they collided with client codes) |
| 500 | 17 | internal errors in the Fjall store and at shutdown |

- `w.m.message.header.ephemera.invalid` is spelled
  `w.m.message.header.ephemeral.invalid`, as documented.
- An unpack failure and a message with no recipient no longer echo the
  whole envelope in the problem report's arguments; they name its sha256.

**Registry.** The constants live in
`affinidi_messaging_mediator_common::error_codes` (re-exported as
`affinidi_messaging_mediator::error_codes`) and handlers use them instead of
numbers. `ERRORS.md` lists every number, every problem code and every Trust
Task code, and code 96 is described correctly (the DID that authenticated
the message, not the session). A test fails when a constant, a problem code
written in a handler, or a code a served task declares is missing from it.

**Console.** The admin client and TUI recognise `unsupportedType` and
`unsupportedVersion` as well as the old `protocol.trust_task.unsupported`.
