### Fixed — raw-TSP sockets record only what they write, and never get a DIDComm frame

- **R1.1:** the raw-TSP inbox drain (`tsp`, `tsp-ack`, `tsp-mux`) recorded
  every message on a page as delivered before writing any of them, including
  ones it then skipped (a DIDComm message for the same DID, such as a mux
  notice). With `limits.delivered_expiry_seconds` set, a skipped message's
  expiry was brought forward although no client had seen it. It now records
  only the frames it writes, and writes only TSP frames.
- **R1.1:** the streaming task's inbox redelivery (after a socket is
  replaced, an entry claimed back, or a mux member reactivated) recorded each
  message as delivered when it queued it. Each is now recorded when the socket
  writes it; a raw-TSP socket answers the redelivery with its own drain, so a
  message it cannot carry is not recorded at all.
- A socket the streaming task closes (replaced by a newer one, or the
  mediator shutting down) got a DIDComm problem report as a Text frame before
  the close frame, raw-TSP sockets included. A raw-TSP socket now gets the
  close frame only, whose code and reason say why.
- A raw-TSP socket answers a burst of wake-ups for its own inbox (an inbox
  redelivery queues one per message) with one drain once the queue is empty,
  or every 64 under a steady stream, instead of one whole-inbox walk each.
- `MediatorStore::record_delivered` stamps messages as handed over and
  publishes the delivery metrics; `fetch_messages_delivering` uses it.

New tests for `tsp-mux`, through the SDK client: `detached` for a member's
revoke and `connectionFull`, `superseded` then `reactivated` with the
member's mail redelivered as TSP frames, a replaced socket closing without a
Text frame, the drain recording only what it writes; and
`tsp_mux_two_instances` (Redis, in both CI Redis jobs) for live delivery,
`superseded` and `reactivated` across two instances.
