### Changed — removing an account ends its sessions on every backend

- `get_session` fails with `Unauthorized` for a session past the challenge
  step whose DID has no account. Redis already refused such sessions (as a
  storage error); Fjall and Memory returned them with the ACLs recorded at
  the challenge, so a removed account kept using and refreshing its session
  until it expired.
- Requests carrying such a session's access token get `401` instead of
  `500`, and `/authenticate/refresh` answers `401
  authentication.session.invalid` instead of `503`, so clients authenticate
  again rather than retry.

**Behaviour change (R3.6):** a client that retries a refresh with a token it
already exchanged (for example after losing the response) has its session
ended and must re-authenticate. Tooling that relied on a DID's account
existing as soon as it requested a challenge will see it only after the
first successful authentication. Challenge requests with non-DID-shaped or
oversized `did` values, and refresh requests sent from a DID other than the
session's, are now refused. Sessions of a removed account stop working at
once on Fjall and Memory, as they already did on Redis.
