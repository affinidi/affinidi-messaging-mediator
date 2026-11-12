### Fixed — `delivered` is reported once the frame is written

- A live push or a reconnect redelivery over a websocket was reported
  `delivered` to the traffic monitor when the streaming task put it in the
  socket's send queue, not when the socket wrote it (R1.1). A queued frame
  that was never written still counted as delivered: one for a mux member
  that left before its turn, one on a socket that closed first, or one
  whose write failed. The report now travels with the queued frame, and the
  socket emits it after a successful write.
- On a raw-TSP socket a live push was reported twice: once when queued,
  and again by the inbox drain that wrote it. Only the drain reports it now.
