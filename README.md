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
| [`mediator-setup`](crates/affinidi-messaging-mediator/tools/mediator-setup) | Interactive setup wizard (not published). |
| [`affinidi-messaging-test-mediator`](crates/affinidi-messaging-test-mediator) | An in-process mediator for integration tests. |
| [`affinidi-messaging-mediator-admin`](crates/affinidi-messaging-mediator-admin) | Headless administration client over Trust Tasks. |
| [`affinidi-messaging-mediator-tui`](crates/affinidi-messaging-mediator-tui) | Terminal console (`mediator-console`). |

## Embedding the mediator

`MediatorBuilder` runs the mediator inside another application: no TOML file,
no working-directory assumptions, no global tracing subscriber or signal
handlers unless you ask for them. It returns a `MediatorHandle` with
`shutdown()` and `join()`.

```toml
affinidi-messaging-mediator = { version = "0.42", default-features = false, features = ["didcomm", "memory-backend"] }
```

Turn the defaults off: they bring in Redis, jemalloc (a binary-only concern;
the library never installs an allocator) and VTA key management (`vta`,
which pulls `vta-sdk`). Note that `install_jwt_crypto_provider()` sets a
process-wide rustls provider.

## Running it

- From source: `cargo run -p affinidi-messaging-mediator --release`, see the
  [mediator README](crates/affinidi-messaging-mediator/README.md).
- Container: `ghcr.io/affinidi/messaging-mediator:<version>`; see
  [`docker/`](docker) and `docker-compose.test.yml` for a local stack.
- First-time configuration: `cargo run -p affinidi-messaging-mediator-setup`.

## Releases and support

Releases are cut from `nightly` onto `release/X.Y` branches and published
from there. The current and previous minor releases are supported. See
[RELEASES.md](RELEASES.md) and [CHANGELOG.md](CHANGELOG.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (commits need a DCO sign-off) and
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
