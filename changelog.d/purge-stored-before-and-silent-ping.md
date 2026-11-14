### Breaking — a trust-ping asking for no response is a success, not a 500

- A DIDComm trust-ping with `response_requested: false`, and a Trust Task
  over DIDComm that the mediator answers with silence, now succeed with
  nothing in them. Over REST, `/inbound` answers `200` with the usual success
  envelope and `data: "Empty"` (the SDK's `InboundMessageResponse::Empty`,
  "no response expected"), the same status every other accepted message gets.
  Over a WebSocket no frame is sent. Previously both were refused with
  `500 e.p.me.storage.message.error` (code 77), and a WebSocket client was
  sent a problem report, for a message that had been handled.
- Wire change (R3.6): a client that treated that `500` as the expected answer
  to a silent ping must now expect `200` / `data: "Empty"`. Error code 77 is
  no longer returned.

### Added — `messaging/queue/purge` honours `storedBefore`

- The vendored `messaging/queue/purge/0.1` bundle is refreshed to the
  in-place draft revision that adds `storedBefore` (request) and
  `selectedAt` (response) (dtgwg-trust-tasks-tf#1288).
- The mediator selects only messages stored at or before `storedBefore`
  (RFC 3339; floored to the store's millisecond), combined with `peer` and
  `olderThanSeconds`, on every backend. The purge audit entry names it
  (`stored before: …`). A request without it behaves as before.
- A narrowed purge or a dry run is now bounded by the instant its selection
  is taken: a message stored while the walk runs is neither counted nor
  removed.
- `selectedAt` is **not** returned yet. Every published
  `affinidi-messaging-sdk` (0.47.0 and older) parses the purge response with
  unknown members denied, so returning it would make every existing client's
  purge fail. It ships once an SDK that knows the member is released; the
  console then sends the dry run's `selectedAt` as `storedBefore` in place of
  its age-based pin (#122).
