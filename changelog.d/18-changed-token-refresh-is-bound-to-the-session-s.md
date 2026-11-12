### Changed — token refresh is bound to the session's DID and is single-use

- `/authenticate/refresh` now requires the authcrypt sender, the inner
  message's `from` and the refresh token's subject to name the DID that owns
  the session. A refresh sent from any other DID is refused with
  `authentication.session.mismatch` (error code 33). The blocked check on
  refresh now reads the session owner's ACLs.
- A session with no recorded refresh-token hash can no longer be refreshed.
- The compare and the rotation of the refresh-token hash are one atomic
  store operation on every backend (a Lua script on Redis, under the
  backend's lock on Fjall and Memory). Of two requests presenting the same
  refresh token, at most one succeeds.
- Presenting a refresh token that was already exchanged, or one the session
  has no record of, ends that session: the request gets `401` and the DID
  must authenticate again from the challenge.
- `MediatorStore` gains `rotate_refresh_token_hash` and the
  `RefreshRotation` outcome. The trait default is not atomic; out-of-tree
  backends should override it.
