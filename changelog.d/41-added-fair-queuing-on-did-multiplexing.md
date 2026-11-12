### Added — fair queuing on DID multiplexing connections

- A mux connection's send queue is now shared fairly among its DIDs (design
  §7.2, step 3). Each DID on the connection, the principal included, may
  have at most 8 frames queued (the depth a direct socket has), and the
  connection at most `limits.mux.max_channel_slots` (default 512, now
  enforced and clamped to 8–65536). The socket writes round-robin across
  DIDs with frames waiting, and member/close events before any of them.
  Before, one busy member filled the connection's single 8-slot queue and
  every other member's live pushes were dropped behind it.
- **Behaviour change for mux clients:** when a member's own share is full,
  only that member's push is dropped, and the resync that follows is a
  pickup `status` for *that member's* inbox (`recipient_did` is the member),
  still packed to the principal. Before, any drop on a mux connection sent a
  status for the principal's own inbox. A member that left the connection is
  not sent one.
- New metric `mux_queue_fairness_skips_total`: pushes refused because that
  DID already held its share (also counted in
  `ws_live_delivery_dropped_total`).
- Unchanged: direct sockets (plain 8-slot queue), the global
  `ws_send_buffer` byte pool, when the `delivered` monitor event is emitted
  (when the frame is queued, as before), and dropping queued frames of a
  member detached after they were queued.
