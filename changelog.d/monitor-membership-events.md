### Added — the traffic monitor can report mux membership changes, on request

- `messaging/monitor/subscribe` 0.2 is served beside 0.1. Its optional
  `membership` filter (by DID, change, wire and source) opts a subscription
  in to mux membership events. Without it there are none. `traffic: false`
  makes a membership-only tap. The response echoes the effective
  `membership` filter, and says `traffic: false` when traffic is off.
- A 0.2 subscription receives `messaging/monitor/event` 0.3 batches. An
  opted-in one gets a `membership` array and a `membershipDropped` count on
  every batch; `dropped` still counts traffic events only. One rate ceiling
  covers both kinds.
- Each event mirrors one member change the mediator reports in an
  `attached` or `detached` `messaging/mux/event`: when, which change, the
  principal and member (as DID hashes, like traffic events), the wire
  (`didcomm` or `tsp`), the source (`grant` or `attach`), the reason, and
  the connection's `sessionId`. Metadata only: no statement, nonce, scope or
  key material.
- An administrator may watch any account's membership. Anyone else sees only
  changes it is party to, as principal or member: an omitted `dids` is
  narrowed to its own account, and naming another account is refused with
  `permissionDenied`. The membership filter counts toward the re-check that
  ends an administrator's wide tap when it stops being one, and it is on the
  audit log.
- Membership events are per instance, like traffic: a connection's changes
  are seen by subscribers on the instance holding the connection. A mediator
  without mux enabled grants no membership filter.
- Unchanged for existing clients: a 0.1 subscription still gets event 0.2
  batches, traffic only. Pins `messaging/monitor/event` 0.3 and
  `messaging/monitor/subscribe` 0.2 beside their older versions, and takes
  the in-place draft update of `messaging/mux/notice` 0.1 (a description
  change only).
