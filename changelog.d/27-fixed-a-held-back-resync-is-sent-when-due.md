### Fixed — a held-back resync is sent when due

- A resync raised within 5 s of the last one waited for something else to
  wake the socket, as late as the next ping. It is now sent once the floor
  has passed. This also speeds up the resync after a dropped live push.

**Behaviour change (R3.6):** principals may receive pickup `status`
messages (DIDComm) or drained frames (`tsp-mux`) for `pickup`-only members
while connected, and stop receiving pushes for members narrowed to exclude
`receive`.
