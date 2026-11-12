### Changed — affinidi-messaging-sdk 0.45.5

- The SDK now checks mux events on DIDComm sockets: the mediator must have
  authcrypted them, and they must be addressed to the principal. It also
  keeps each connection's member set (`ATMProfile::mux_members()`,
  `TspMuxWebSocket::members()`). `tests/mux_sdk.rs` checks that set
  against this mediator: grants, an attach, a narrowed grant, a member
  inactive while its own socket is up, and a revoke.
