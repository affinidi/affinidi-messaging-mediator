### Changed — requests to the mediator act for the session's own DID

- Trust ping, discover features, message pickup and every Trust Task
  addressed to the mediator now need an authenticated session whose DID
  authenticated the message (signature or authcrypt). Otherwise they are
  refused before any handler runs:
  - on the anonymous inter-mediator relay session, with
    `44 authorization.authentication_required` (401). That session relays
    forwards only; forwards and blind-relay direct delivery on it are
    unchanged.
  - on an authenticated session, when the message was authenticated as
    another DID, with `52 authorization.did.session_mismatch` (400). An
    anonymous message on an authenticated session is the session's own, as
    before (where `block_anonymous_outer_envelope` lets it through).
- This holds whatever `security.force_session_did_match` says. That switch
  now governs only what a session may send (forwards and direct delivery);
  previously, with it off, a session could carry another DID's requests and
  each handler chose which of the two identities to authorise.
- The same check applies to Trust Tasks over TSP.
- Because the sender is now always the session DID,
  `block_remote_admin_msgs` holds for every administrative task.
- DIDComm v1 coordinate-mediation and pickup are unchanged: the authcrypt
  verkey is the identity there.
- On Redis, a session read back from the store is now marked authenticated
  when its stored state is `Authenticated`, as on Fjall and memory. It never
  was, so on Redis every session was handled as unauthenticated: session /
  sender matching under `force_session_did_match` and the checks TSP applies
  to an authenticated session's routed frames were skipped, and with this
  change every request to the mediator would have been refused.

**Behaviour change (R3.6):** a deployment running with
`force_session_did_match = false` whose clients send requests to the
mediator as a DID other than the one they authenticated as is refused.
SDK clients send as the session DID and need no change. On Redis,
`force_session_did_match` (default on) now applies as documented: a client
that authenticated as one DID and sends forwards or direct deliveries as
another is refused, as it already was on Fjall and memory.
