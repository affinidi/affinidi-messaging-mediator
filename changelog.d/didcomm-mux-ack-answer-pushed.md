### Fixed — the answer to `messaging/mux/ack` on a DIDComm mux connection is not stored

On a `didcomm-mux` connection the answer to `messaging/mux/ack` was stored in
the principal's inbox like any other Trust Task reply. A stored answer needs
acknowledging in turn, and so does the answer to that (spec, consumer rule 4).
It now goes to the connection only, as it already did on `tsp-mux`. When the
connection drops before the answer arrives, the client asks again: acking is
idempotent.

Clients: affinidi-messaging-sdk 0.45.13 sends background deletes on a
`didcomm-mux` connection as `messaging/mux/ack` on the socket, and does not
delete the answer. It needs this change.
