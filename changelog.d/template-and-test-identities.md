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
- **Behaviour change (R3.6):** the mediator refuses to start, in every
  build, when `admin_did` names the mediator's own DID. The two are compared
  as accounts: a `did://` prefix, a fragment, a query (including a did:scid
  `src` locator) and the case of `did:` and the method do not hide a match.
  One account would otherwise hold the root-admin role, so the mediator's
  operating keys could administer every account. `MediatorBuilder` applies
  the same check, and `mediator-setup` stops before writing such a config.
  Migration: a deployment that set both to one DID (as the earlier template
  did) must give the admin its own DID before upgrading. Run
  `mediator-setup` (Admin step, "Generate did:key"), or create one and set
  `[server] admin_did` / `ADMIN_DID`, and give its keys to whoever
  administers the mediator.
