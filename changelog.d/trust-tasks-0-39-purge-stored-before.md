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
