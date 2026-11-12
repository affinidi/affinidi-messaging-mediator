### Changed — the config template names no identity; release builds refuse the committed test identities

- `conf/mediator.toml` now leaves `mediator_did` and `admin_did` empty, like
  the container profile. It used to set both to the same example DID.
  `mediator-setup` fills them in; otherwise set `MEDIATOR_DID` and
  `ADMIN_DID`.
- **Behaviour change (R3.6):** a release build of the mediator refuses to
  start when `mediator_did` or `admin_did` is one of the sample or test DIDs
  committed to this repository (the old template example and the
  `docker/test/conf` identity), when a loaded operating key is one of those
  DIDs' keys (whatever DID it is published under), or when the JWT signing
  key is the one in `docker/test/conf/secrets.json`. Set
  `MEDIATOR_ALLOW_TEST_IDENTITY=true` for a test deployment;
  `docker-compose.test.yml` does. Debug builds only log a warning, so a
  debug build is not a substitute for this check.
- An `admin_did` equal to `mediator_did` is now logged at `ERROR` on every
  start, not `WARN`, and the message says what it means: the one account
  holds the root-admin role, so the mediator's operating keys can administer
  every account. It is still accepted, since the earlier template set both
  to one DID; give the admin its own DID.
