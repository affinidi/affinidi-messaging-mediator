### Added — Trust Task refusals as `trust-task-error` documents, for a request that asks

- A Trust Task request that carries the top-level member
  `"x-errorFormat": "trust-task-error"` is now refused with a
  `trust-task-error` document (Trust Tasks SPEC §8). It replaces the DIDComm
  problem report the mediator sent before, over DIDComm, TSP and the mux
  sockets. The DIDComm binding says a problem report is not an error response
  (`didcomm/0.2` §4.1). The document carries:
  - `code` and `retryable`;
  - `inResponseTo` (the refused request's type and `id`), with `threadId` set
    to the request's;
  - the `details` the code's specification declares.
  It is signed as a success response is, threaded and delivered like one.
- `details` per the pinned bundles' `detailsSchema`:
  - `currentEpoch` for `messaging/mux/revoke-all:epochMismatch` and
    `messaging/mux/admin-revoke-all:epochMismatch`;
  - `size` for `messaging/message/get:messageTooLarge`.
- The problem report for those codes now also carries the value as its first
  `args` entry. The user's `revoke-all` did not carry it before; the
  administrator's already did. The comment text is unchanged.
- Codes a specification declares (`messaging/mux/…:…`) and standard codes are
  sent as they are. The mediator's own codes are not valid `trust-task-error`
  codes (`authorization.admin_required`, `message.trust_task.stale`,
  `protocol.trust_task.unsupported`, …). Each is sent as the standard code
  that says the same thing (`permissionDenied`, `expired`, `unsupportedType`,
  …), with the original in `details.mediatorCode`.
- An internal or storage failure is `internalError` or `unavailable` with a
  generic message. Its text stays in the log, as it does for an HTTP client.
  An `identityMismatch` names neither identity (SPEC §8.1).
- The refusal of `messaging/mux/ack` is pushed to the connection only, never
  stored, like its answer. It says no more than the problem report did, so an
  ack still does not confirm that another DID's message exists.

### Changed — Trust Task refusals change form for a client that asks (R3.6)

- This is a wire change, but only for a client that asks. A request without
  the member is refused exactly as before.
- `affinidi-messaging-sdk` asks on every Trust Task from 0.46.2, and decodes
  the document into `ATMError::TrustTaskError`. A service that matches
  problem-report codes on Trust Task calls (`ATMError::ProblemReport(code, ..)`)
  and moves to that SDK should match on `ATMError::refusal_code()` or
  `ATMError::mediator_code()`, which give the same answer for both forms.
- A refused Trust Task that asked is now answered like a response: stored and
  delivered, or pushed for `messaging/mux/ack`. Over TSP the inbound POST no
  longer fails for it; the refusal arrives sealed in the inbox, threaded to
  the request.
