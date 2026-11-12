### Fixed — TSP empty-route delivery uses the hop's verified sender

- When a routed TSP message addressed to the mediator has no hops left, the
  mediator now applies the recipient's access list against the sender that
  `unpack` verified for that hop, as the last-hop and nested arms already do.
  It previously used the sender named in the clear by the inner message's
  envelope. The inner envelope is now read only for its receiver, and an
  inner that does not parse is refused with `message.tsp.malformed`.
  `affinidi-tsp` 0.3 decodes an empty route as `Nested`, so no message takes
  this path today; unit tests pin the decision so that a decoder change does
  not alter it.
- `deliver_tsp_local` takes the sender from its caller instead of reading it
  from the bytes it stores (unchanged for existing callers).
