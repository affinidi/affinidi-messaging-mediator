# Affinidi Messaging Mediator

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

A DIDComm v2 and TSP mediator: it authenticates agents, stores and forwards
their messages, and delivers them over REST and WebSocket. Also here are
the admin client and terminal console that operate it, and an in-process
test mediator for other projects' integration tests.

The client side (the ATM SDK, DIDComm, TSP, DID resolution) lives in
[affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs) and is taken
from crates.io.

## Crates

All crates are released together and carry the same version.

| Crate | What it is |
|---|---|
| [`affinidi-messaging-mediator`](crates/affinidi-messaging-mediator) | The mediator: the `mediator` binary and an embeddable library (`MediatorBuilder`). |
| [`affinidi-messaging-mediator-common`](crates/affinidi-messaging-mediator/affinidi-messaging-mediator-common) | Storage backends (Redis, Fjall, in-memory), secret stores and shared server types. |
| [`affinidi-messaging-mediator-config`](crates/affinidi-messaging-mediator/affinidi-messaging-mediator-config) | The raw TOML configuration schema. |
| [`affinidi-messaging-mediator-processors`](crates/affinidi-messaging-mediator/affinidi-messaging-mediator-processors) | Standalone message-expiry and forwarding processors. |
| [`affinidi-messaging-mediator-setup`](crates/affinidi-messaging-mediator/tools/mediator-setup) | Interactive setup wizard, the `mediator-setup` binary (not published). |
| [`affinidi-messaging-test-mediator`](crates/affinidi-messaging-test-mediator) | An in-process mediator for integration tests. |
| [`affinidi-messaging-mediator-admin`](crates/affinidi-messaging-mediator-admin) | Headless administration client over Trust Tasks. |
| [`affinidi-messaging-mediator-tui`](crates/affinidi-messaging-mediator-tui) | Terminal console (`mediator-console`). |

## Getting started

The quickest way to a running mediator is a checkout of this repository: the
setup wizard (`mediator-setup`) is not published on crates.io, so it runs
from here. Run every command below from the **repository root**. You need
Rust 1.95 or later and, for the default Redis store, Docker (or any Redis
7.1 or later, below 9.0).

1. **Start Redis.**

   ```sh
   docker run --name=redis-local --publish=6379:6379 --detach redis:7-alpine
   ```

2. **Generate a configuration and keys.** This builds the wizard without the
   cloud secret-manager SDKs (they are not needed for a local file store) and
   writes a did:peer identity, an admin did:key and a JWT key:

   ```sh
   cargo run --locked -p affinidi-messaging-mediator-setup --no-default-features -- \
     --non-interactive --did-method peer --secret-storage file
   ```

   It writes `conf/` in the repository root: `mediator.toml`, the keys in
   `secrets.json` (plaintext, which the wizard accepts only for a local
   deployment), the admin profile `admin-monitor.json` and the Redis
   functions. Git ignores the files that hold keys. Run with no arguments for
   the interactive wizard instead.

   Do not run the wizard from inside `crates/affinidi-messaging-mediator/`:
   its default output, `conf/mediator.toml`, would overwrite the annotated
   template tracked there.

3. **Run the mediator.** The wizard prints the build command for the choices
   you made; for the ones above the default features are enough:

   ```sh
   cargo run --release --locked -p affinidi-messaging-mediator -- -c conf/mediator.toml
   ```

4. **Check it works.**

   ```sh
   curl -s http://localhost:7037/mediator/v1/livez     # {"status":"alive"}
   curl -s http://localhost:7037/mediator/v1/readyz    # "status":"ready" once storage answers
   ```

5. **Open the console** with the admin profile the wizard wrote:

   ```sh
   cargo run --release --locked -p affinidi-messaging-mediator-tui -- --profile conf/admin-monitor.json
   ```

No Redis? Build the mediator with Fjall, an embedded store, instead: add
`--set storage.backend=fjall` to the wizard and run the build command it
prints (it adds the `fjall-backend` feature). The
[mediator README](crates/affinidi-messaging-mediator/README.md) covers the
wizard's other choices (did:webvh, cloud secret backends, TLS) and the
feature flags.

### In a container

`docker compose -f docker/quickstart/docker-compose.yml up --build` builds the
image, generates a fresh identity on first start and serves it on
`http://localhost:7037/mediator/v1/` (loopback only).
[docker/README.md](docker/README.md) covers the quickstart and running the
published image, `ghcr.io/affinidi/messaging-mediator:<version>`, with your
own identity. `docker-compose.test.yml` is the CI test harness: its keys are
committed to this repository, so never use it as a local or shared stack.

### Operating it

[docs/operations.md](crates/affinidi-messaging-mediator/docs/operations.md)
covers the probe routes, the metrics, logs and shutdown;
[docs/architecture.md](crates/affinidi-messaging-mediator/docs/architecture.md)
is a map of the code for contributors.

## Embedding the mediator

`MediatorBuilder` runs the mediator inside another application: no TOML file,
no working-directory assumptions, no global tracing subscriber or signal
handlers unless you ask for them. It returns a `MediatorHandle` with
`shutdown()` and `join()`.

```sh
cargo add affinidi-messaging-mediator --no-default-features --features didcomm,memory-backend
```

Turn the defaults off: they bring in Redis, jemalloc (a binary-only concern;
the library never installs an allocator) and VTA key management (`vta`,
which pulls `vta-sdk`). Note that `install_jwt_crypto_provider()` sets a
process-wide rustls provider. The crate documentation on
[docs.rs](https://docs.rs/affinidi-messaging-mediator) has a full example.

For integration tests, use
[`affinidi-messaging-test-mediator`](crates/affinidi-messaging-test-mediator)
instead: it starts an in-process mediator with generated identities in one
call.

### Release profile

Release builds of this workspace (the container image, `cargo build
--release` here) use:

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "symbols"
```

Cargo applies a workspace's profile only when building that workspace, so
`cargo install affinidi-messaging-mediator` (or a service that embeds the
mediator through `MediatorBuilder`) gets cargo's default release profile
instead: `opt-level = 3` with no LTO and 16 codegen units. To build the same
binary the image ships:

```sh
CARGO_PROFILE_RELEASE_LTO=thin \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CARGO_PROFILE_RELEASE_STRIP=symbols \
  cargo install affinidi-messaging-mediator --locked
```

An embedding service sets the same keys in its own `[profile.release]`.

## Releases and support

Releases are cut from `nightly` onto `release/X.Y` branches and published
from there. Each release is supported for 90 days after its GA, and the
newest release always is. Every minor release is a breaking release under
Cargo's `0.x` rules, so track the newest one and read its **Breaking**
changelog entries before you move. See [RELEASES.md](RELEASES.md#support)
and [CHANGELOG.md](CHANGELOG.md).

Code comments and changelog entries cite rules such as "(R1.1)" or "(R3.6)";
[docs/delivery-rules.md](docs/delivery-rules.md) states them.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (commits need a DCO sign-off) and
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
