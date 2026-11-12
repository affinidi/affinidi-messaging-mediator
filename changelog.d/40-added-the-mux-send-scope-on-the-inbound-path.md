### Added — the mux `send` scope on the inbound path

- A mux connection now accepts a frame whose sender is one of its member
  DIDs when that member's grant or attach includes `send`. The frame is
  still signed or authcrypted with the member's own keys. This covers a
  DIDComm `routing/2.0/forward` to the mediator (sender proven by its
  authcrypt or JWS key), a DIDComm direct-delivery envelope (sender as the
  JWE `skid` names it), and raw TSP Direct, Routed and Nested frames on the
  connection.
- An accepted frame is the member's from then on, exactly as if the member
  had sent it on its own connection. It is checked against the member's own
  ACLs: not blocked, `LOCAL` and `SEND_MESSAGES`, read when the frame
  arrives, so a grant cannot outlive a revoked ACL. The forwarding,
  queue-limit and recipient ACL / access-list checks also see the member,
  and the per-account `messages_sent` counters and `stored` monitor events
  name the member, not the principal. Problem reports for the connection
  still go to the principal.
- `send` admits sending only. A member's message to the mediator itself
  (pickup, Trust Tasks, trust ping, mediator administration, a TSP Direct
  or Control message to the mediator) is refused on the principal's
  connection, as before.
- **Behaviour change (R3.6):** with `security.force_session_did_match` on
  (the default), such frames were refused on every socket with
  `authorization.did.session_mismatch`. They are now accepted for `send`
  members only. A frame from a member without `send`, or from a DID that is
  not a member, is still refused with that same problem report and the same
  monitor `refused` code, and the socket stays open. With
  `force_session_did_match` off, nothing changes: any authenticated session
  could already present any sender's frames.
- The rule follows the session, as pickup and delete scopes already do, so
  `POST /inbound` with the token of an open mux connection is covered too.
- Design §7.6 names a `mux.send.not_attached` refusal code. That code is
  not used; refusals keep today's code (see above).
