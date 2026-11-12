### Changed — accounts are registered after the challenge is answered

- In `explicit_deny` mode, `/authenticate/challenge` no longer creates an
  account for an unknown DID. The account is created with
  `global_acl_default` once the DID answers the challenge on `/authenticate`
  or `/tsp/authenticate`, before any token is issued. The blocked and
  `explicit_allow` checks at the challenge step are unchanged.
- `/authenticate/challenge` accepts only a `did:<method>:<id>` string of at
  most 2048 bytes with a lowercase-alphanumeric method and DID URL
  characters; anything else gets `400 authentication.challenge.invalid_did`.
- The authentication routes carry their own body limits: 16 KiB for
  `/authenticate/challenge` and `/tsp/authenticate`, 64 KiB for
  `/authenticate` and `/authenticate/refresh` (previously axum's 2 MiB
  default). A larger body gets `413`.
- Both login steps (`/authenticate`, `/tsp/authenticate`) re-check whether
  the DID is blocked when the challenge is answered, so a DID blocked after
  it was issued a challenge gets no tokens. `/tsp/authenticate` previously
  relied on the check made at the challenge step.
- `/authenticate` now requires the answer to carry the challenge string the
  session issued (`authentication.session.invalid`, error code 34).
- A `ChallengeSent` session is readable before its DID has an account, on
  every backend.
