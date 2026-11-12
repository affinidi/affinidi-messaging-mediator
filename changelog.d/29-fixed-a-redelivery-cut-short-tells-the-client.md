### Fixed — a redelivery cut short tells the client

- The inbox redelivery a websocket gets on activation or after replacing
  another socket stops early when the socket's send queue or the byte
  budget is full, at its 1000-message cap, or when a fetch fails. It left
  the rest in the inbox for message-pickup without telling the client, so a
  client that only listens never learned it was there. It now raises the
  client's resync, as a dropped live push already did: a pickup `status` on
  DIDComm, a drain on raw TSP. On a mux connection the resync is owed to
  that member only.
