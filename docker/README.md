# Running the mediator in a container

| Path | What it is |
|---|---|
| [`mediator.Dockerfile`](mediator.Dockerfile) | Builds the production image: the `mediator` and `mediator-setup` binaries, with the default features plus `secrets-aws`. |
| [`conf/mediator.toml`](conf/mediator.toml) | The configuration baked into the image. No identity: supply one at run time. |
| [`quickstart/`](quickstart/) | A local playground: the image and Redis, with a fresh identity generated on first start. |
| [`test/`](test/) | The fixed identity of the CI test harness (`docker-compose.test.yml`). Its keys are committed: never use it outside CI. |
| [`smoke/`](smoke/), [`ci/`](ci/) | Image checks and publishing scripts used by CI. |

## Quickstart (local, generated keys)

From the repository root:

```sh
docker compose -f docker/quickstart/docker-compose.yml up --build
```

The first start builds the image, runs `mediator-setup` once against
[`quickstart/mediator-build.toml`](quickstart/mediator-build.toml) to
generate a did:peer mediator DID, an admin did:key and the JWT key into the
`mediator-conf` volume, and then starts the mediator with Redis. Later starts
reuse that identity. The mediator listens on `127.0.0.1:7037` only.

Check it is up:

```sh
curl -s http://localhost:7037/mediator/v1/livez     # {"status":"alive"}
curl -s http://localhost:7037/mediator/v1/readyz    # "ready" once storage answers
```

Copy the admin profile out (it holds the admin private key; keep it out of
git) and open the console on it:

```sh
docker compose -f docker/quickstart/docker-compose.yml cp \
  mediator:/etc/mediator/conf/admin-monitor.json .
cargo run --release -p affinidi-messaging-mediator-tui -- --profile admin-monitor.json
```

Start over with a new identity with
`docker compose -f docker/quickstart/docker-compose.yml down -v`.

The quickstart is a playground, not a deployment: plaintext file secrets, no
TLS and an open network posture.

## The published image

`ghcr.io/affinidi/messaging-mediator:<version>` (for example `:v0.51.0`;
`:latest` is the newest GA or patch release). Release images are built only
from their release tag and carry a signed build-provenance attestation; pin
by digest and check it with
`gh attestation verify oci://ghcr.io/affinidi/messaging-mediator@sha256:… --owner affinidi`.

- It runs as UID:GID `10001:10001`. Mounted configuration and secret files
  must be readable by that user.
- The working directory is `/app` and the default command reads
  `conf/mediator.toml` there, which is [`conf/mediator.toml`](conf/mediator.toml).
- Its `HEALTHCHECK` runs `mediator healthcheck`, a GET of `livez`. It reads
  `conf/mediator.toml` too; if you pass `-c <path>`, the healthcheck still
  uses the default file unless you override it.
- It listens on `0.0.0.0:7037` and expects TLS to be terminated in front of
  it.

### With your own identity

The baked-in configuration has no DID, so a bare `docker run` refuses to
start. Supply the identity, the store and the secret backend through the
environment (every setting marked `### Env:` in
[the annotated template](../crates/affinidi-messaging-mediator/conf/mediator.toml)
can be):

```sh
docker run --rm -p 7037:7037 \
  -e MEDIATOR_DID=did://did:peer:2.Vz6... \
  -e ADMIN_DID=did:key:z6Mk... \
  -e DATABASE_URL=redis://redis.internal:6379/ \
  -e MEDIATOR_SECRETS_BACKEND=aws_secrets://us-east-1/prod/mediator/ \
  ghcr.io/affinidi/messaging-mediator:<version>
```

The secret backend must already hold the mediator's keys. The usual way to
put them there is to run the wizard against the same backend first: the image
ships it, so
`docker run --rm --entrypoint mediator-setup ghcr.io/affinidi/messaging-mediator:<version> --help`
shows its options, and the quickstart's `setup` service is a worked example.
The image is built with `secrets-aws` only, besides the built-in `file://`;
another backend needs an image built with its feature (see the
[secret backends](../crates/affinidi-messaging-mediator/docs/secrets-backend.md)).

Alternatively, mount a complete configuration directory written by
`mediator-setup` and point the mediator at it:

```sh
docker run --rm -p 7037:7037 \
  -v "$PWD/conf:/etc/mediator/conf:ro" -w /etc/mediator \
  ghcr.io/affinidi/messaging-mediator:<version> -c conf/mediator.toml
```

See [docs/operations.md](../crates/affinidi-messaging-mediator/docs/operations.md)
for the probe routes, metrics and shutdown behaviour.
