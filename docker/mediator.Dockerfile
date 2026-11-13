# syntax=docker/dockerfile:1
#
# Production mediator image. Build context is the repository ROOT:
#   docker build -f docker/mediator.Dockerfile -t messaging-mediator .
#
# Feature set (must match the deployment contract): the runtime is compiled
# with `secrets-aws`, so the binary can open aws_secrets:// / aws_parameter_store://
# backends. Building without it makes the mediator hard-fail at startup when the
# deployment points MEDIATOR_SECRETS_BACKEND / MEDIATOR_DID at an AWS scheme.
#
# The image ships docker/conf/mediator.toml (the container profile), NOT the
# annotated template — the template names `keyring://`, which is not compiled in
# here and has no OS secret service in a container, and it carries a sample DID
# that must never be baked into a published image. See that file's header for
# the run-time contract; docker/ci/boot-probe.sh asserts both boot paths.
#
# Runtime contract worth knowing before you deploy:
#   * runs as UID:GID 10001:10001 (numeric, so Kubernetes `runAsNonRoot: true`
#     accepts it without a `runAsUser`). Mounted config/secrets must be
#     readable by that UID.
#   * HEALTHCHECK runs `mediator healthcheck`, which GETs the `livez` route
#     named by the config (no curl in the image).

ARG PORT=7037

# Both binaries in ONE cargo invocation, so the dependency graph is compiled
# once: didcomm, tsp, redis-backend, jemalloc and vta come from the mediator's
# defaults, plus secrets-aws (which pulls in the `aws` feature required by
# aws_secrets:// / aws_parameter_store://); mediator-setup gets only the AWS
# backends the cloud deployment uses. `--no-default-features` applies to both
# packages, which is why the mediator's `default` is named explicitly.
ARG BUILD_ARGS="--release --locked \
    -p affinidi-messaging-mediator -p affinidi-messaging-mediator-setup \
    --no-default-features \
    --features affinidi-messaging-mediator/default,affinidi-messaging-mediator/secrets-aws,affinidi-messaging-mediator-setup/secrets-aws,affinidi-messaging-mediator-setup/publish-aws"

# Builder base pinned by digest, like the runtime base below: a tag alone can be
# re-pointed upstream. Written out literally (no ARG) so Dependabot can read and
# bump the digest. The Rust version here is the toolchain:
# scripts/check-release-guards.py holds it equal to rust-toolchain.toml's
# channel. When the toolchain moves, look up the new tag's index digest with
#   docker buildx imagetools inspect rust:<version>-slim-bookworm
FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS rust

# build-essential: cc, needed by jemalloc (a default feature) and openssl-sys.
# pkg-config + libdbus: the cross-platform keyring secret store (pulled by the
# TDK layer) links dbus on Linux. libssl: openssl-sys in the dependency graph.
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends \
        build-essential pkg-config libdbus-1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# cargo-chef splits "build the dependency graph" from "build our crates", so a
# source change reuses the cached dependency layer instead of recompiling ~800
# crates. Pinned and --locked so its own graph cannot drift.
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /app

# The recipe is a function of the manifests and Cargo.lock only, so this layer
# (and the cook below) is reused until a dependency changes.
FROM rust AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust AS builder
ARG BUILD_ARGS
COPY --from=planner /app/recipe.json recipe.json
# shellcheck disable=SC2086 # BUILD_ARGS is a word list on purpose
RUN cargo chef cook --recipe-path recipe.json ${BUILD_ARGS}
COPY . .
# shellcheck disable=SC2086
RUN cargo build ${BUILD_ARGS}

# Runtime base pinned by digest: nothing here is rebuilt from source, so the
# digest is the only thing fixing what ships. Dependabot proposes digest bumps
# (which is how CVE fixes arrive); there is deliberately no `apt-get upgrade`,
# which would make the pinned image non-reproducible.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
ARG PORT
LABEL org.opencontainers.image.source="https://github.com/affinidi/affinidi-messaging-mediator" \
      org.opencontainers.image.title="messaging-mediator" \
      org.opencontainers.image.description="Affinidi Secure Messaging Mediator (DIDComm v2 + TSP)" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends ca-certificates \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*
# Fixed, numeric identity: 10001 is outside the range distributions allocate
# system and login users from, and a numeric USER is what Kubernetes needs to
# verify `runAsNonRoot` without a `runAsUser`.
RUN groupadd --system --gid 10001 mediator \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mediator
WORKDIR /app
# Nothing from the template conf directory: copying it would bake in whatever
# the setup wizard left there in a developer's checkout (secrets.json,
# admin-monitor.json, keys/) and the template's sample DID, and the Redis Lua
# library is built into the binary (`database.functions_file` unset). The
# container config provides mediator.toml — the mediator defaults to
# `-c conf/mediator.toml` relative to WORKDIR.
COPY docker/conf/mediator.toml conf/mediator.toml
COPY --from=builder /app/target/release/mediator /usr/local/bin/
COPY --from=builder /app/target/release/mediator-setup /usr/local/bin/
USER 10001:10001
EXPOSE $PORT
# Liveness only (`livez`): a storage blip must not get a healthy mediator
# restarted. Uses the same config (and env overrides) as the server, so it
# follows LISTEN_ADDRESS / API_PREFIX. With `-c <path>` in the container's
# command, the healthcheck still reads conf/mediator.toml relative to the
# working directory; override with `mediator -c <path> healthcheck` if needed.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/mediator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/mediator"]
