### Changed — The mediator image runs as UID:GID 10001:10001

- `USER` is now numeric (`10001:10001`, user and group `mediator`), so
  Kubernetes `runAsNonRoot: true` accepts the image without a `runAsUser`.
  It used to be a system-allocated UID for `lowPrivUser`. **Files you mount
  into the container (config, `file://` secrets, TLS keys) must be readable by
  UID 10001**; a deployment that chowned them to the old UID needs updating.
- The image no longer runs `apt-get upgrade` on its digest-pinned base, so a
  given digest always builds the same runtime layer. Base-image fixes arrive as
  digest bumps.
- Only `atm-functions.lua` is copied from the template `conf/` directory; the
  sample `mediator_did.json` and `secrets.json-example` no longer ship in the
  image.

### Added — `mediator healthcheck` and an image HEALTHCHECK

- `mediator healthcheck` GETs the `livez` route of the mediator its config
  describes (`--config`, with the usual environment overrides; a wildcard
  `listen_address` is probed on loopback) and exits 0 on a 2xx, 1 otherwise.
  `--url` probes an explicit URL instead.
- The image declares `HEALTHCHECK CMD ["/usr/local/bin/mediator",
  "healthcheck"]`, so Docker, Compose and ECS see container health without
  extra tools in the image.

### Changed — Release profile tuned for throughput

- `[profile.release]` is now `opt-level = 3`, `lto = "thin"`,
  `codegen-units = 1`, `strip = "symbols"` (was `opt-level = "s"`, fat LTO).
  The image and in-repo release builds are faster on the crypto/JSON hot paths
  and the image build needs far less memory. Binaries are stripped of symbols;
  panics still report file and line. Cargo applies this profile only to builds
  of this workspace: `cargo install affinidi-messaging-mediator` users can
  match it with the environment variables in the README's "Release profile"
  section.
