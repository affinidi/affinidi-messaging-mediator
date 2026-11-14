# affinidi-messaging-mediator

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-messaging-mediator/tree/main/crates/affinidi-messaging-mediator)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-messaging-mediator/blob/main/LICENSE)

A mediator and relay service supporting
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/).
It handles connections, permissions, and message routing between messaging
participants.

## Quick start

The setup wizard is not published on crates.io: run it, and the mediator,
from a checkout of this repository, with the **repository root** as the
working directory. The wizard writes `conf/` relative to where it runs, and
the mediator reads `conf/mediator.toml` relative to where it runs. Never run
the wizard from this crate's directory: its default output path would
overwrite the annotated template tracked in `conf/mediator.toml` here.

The [root README](../../README.md#getting-started) has the shortest path
(file secrets, did:peer, no prompts); this section covers the wizard's
choices.

### 1. Start Redis (skip for Fjall)

Fjall is embedded and keeps its data in a local directory, so it needs no
sidecar. For Redis:

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis \
  --restart=on-failure --detach redis:7-alpine
```

### 2. Run the setup wizard

The wizard generates the configuration, keys, and secrets in one step:

```bash
cargo run --locked --bin mediator-setup
```

It asks for:

1. **Deployment type**: local dev, headless server, or container.
2. **Protocol**: DIDComm v2 only, or DIDComm v2 + TSP.
3. **DID**: did:peer, did:webvh, or VTA-managed.
4. **Key storage**: one of the [secret backends](#secret-storage).
5. **SSL/TLS**: none (use a proxy), existing certificates, or self-signed.
6. **Database**: a Redis URL, or a Fjall data directory (single node).
7. **Admin account**: generate a did:key, paste an existing one, or skip.

The default build of the wizard compiles every secret backend, including the
AWS, GCP and Azure SDKs. If you only need some, build it with
`--no-default-features --features <backends>` (for example
`cargo run --locked -p affinidi-messaging-mediator-setup --no-default-features --features secrets-keyring`;
`file://` is always available).

It writes:

- `conf/mediator.toml`, the full configuration. It holds no secrets.
- `conf/keys/`, SSL certificates (self-signed mode only).
- The admin DID and private key, shown on screen. Save them securely.
- The mediator's secrets, written to the backend you chose.

### 3. Build and run

The wizard prints the exact build and run commands when it finishes. The
default build has only the `file://` secret backend, so add the feature for the
backend you chose (the wizard's default, `keyring://`, needs
`secrets-keyring`; see [Secret backend](#secret-backend)):

```bash
cargo build --release --locked -p affinidi-messaging-mediator --features secrets-keyring
cargo run --release --locked -p affinidi-messaging-mediator --features secrets-keyring -- -c conf/mediator.toml
```

### 4. Check it works

```bash
curl -s http://localhost:7037/mediator/v1/livez    # {"status":"alive"}
curl -s http://localhost:7037/mediator/v1/readyz   # "status":"ready" once storage and secrets answer
```

`mediator healthcheck` does the same `livez` check from the command line (the
container image uses it). [docs/operations.md](docs/operations.md) describes
both routes, `/metrics` and the rest of the operational surface.

## Non-interactive setup (CI/CD)

```bash
# Local development
cargo run --locked --bin mediator-setup -- --non-interactive --did-method peer

# Production server
cargo run --locked --bin mediator-setup -- --non-interactive \
  --deployment server \
  --did-method webvh \
  --public-url "mediator.example.com/mediator/v1" \
  --secret-storage aws \
  --database-url "redis://redis.internal:6379/"

# Container (a plaintext file store outside `local` must be accepted explicitly;
# prefer `--set secrets.storage='file://conf/secrets.json?encrypt=1'`)
cargo run --locked --bin mediator-setup -- --non-interactive \
  --deployment container \
  --did-method peer \
  --secret-storage file --allow-plaintext-file
```

Every headless run is one build recipe: `--from <recipe.toml>` (optional),
then these flags — each a shorthand for one recipe key — then
`--set section.key=value` for any other key (e.g.
`--set security.network_mode=open`). Each override is printed, and so is any
flag the run does not use.

| Flag | Values | Default |
|---|---|---|
| `--deployment` | `local`, `server`, `container` | `local` |
| `--protocol` | `didcomm` (DIDComm only), `tsp` (DIDComm + TSP) | `tsp` |
| `--did-method` | `peer`, `webvh`, `vta` | required with `--non-interactive` (see note) |
| `--public-url` | URL | required for `webvh` |
| `--key-suite` | `p256`, `secp256k1` (repeatable) | none (Ed25519 + X25519 only) |
| `--save-did-web` | flag | off |
| `--secret-storage` | `file`, `keyring`, `aws`, `gcp`, `azure`, `vault`, `k8s` | `keyring` |
| `--allow-plaintext-file` | flag | unencrypted `file://` refused outside `local` |
| `--ssl` | `none`, `self-signed` | `none` |
| `--database-url` | Redis URL | `redis://127.0.0.1/` |
| `--admin` | `generate`, `vta`, `skip` | `generate` |
| `--admin-did` | an existing admin DID | — |
| `--listen-address` | `ip:port` | `0.0.0.0:7037` |
| `-c, --config` | file path | `conf/mediator.toml` |
| `--set` | `section.key=value` (repeatable) | — |
| `--force-reprovision` | flag | refuse to write into a backend that holds a mediator |
| `--show-admin-key` | flag | the admin key is never printed |
| `--uninstall` | flag | delete the stored keys and every file the setup wrote |

`--non-interactive` cannot provision a VTA-managed DID — there is no VTA
session — so `--did-method vta` is refused (exit 5); use a sealed-mint recipe,
the `--setup-key-out` / `--setup-key-file` pair (VTA admin credential, own
DID), or the TUI. The network posture defaults to `open` for `local` and
`closed` for `server` / `container`.

`--secret-storage` picks only the backend kind with its defaults (region,
namespace, service). GCP, Azure and Vault have no usable default: give the
full URL, e.g. `--set secrets.storage=vault://vault.internal:8200/secret/mediator`.
See [docs/setup-guide.md](docs/setup-guide.md#headless-runs) (including the
exit codes) and `tools/mediator-setup/examples/mediator-build.toml`.

## Feature flags

The default build is `didcomm`, `tsp`, `redis-backend`, `jemalloc` and
`vta`. With `--no-default-features`, list at least one protocol and one
storage backend, and add back `vta` and `jemalloc` if you want them.

### Protocol

| Feature | Default | Description |
|---|---|---|
| `didcomm` | Yes | DIDComm v2. |
| `tsp` | Yes | Trust Spanning Protocol. Works with or without `didcomm`: a TSP-only build (`--no-default-features --features tsp,<storage backend>`) authenticates clients with `POST /tsp/authenticate`, and CI builds and tests it. |
| `didcomm-v1` | No | Accepts DIDComm v1 (Aries) forwards alongside v2. Implies `didcomm`. |

**TSP endpoint advertisement.** Other mediators can route TSP to this one
only if its DID document advertises a `TSPTransport` service:

- **did:web**: added automatically at startup, mirroring the
  `DIDCommMessaging` endpoint (both use `/inbound`).
- **did:peer / did:webvh**: the document is bound to the DID, so add the
  `TSPTransport` service when you generate the DID. The mediator logs a
  warning at startup if TSP is enabled and the service is missing.

For TSP usage (sending, receiving, relationships, WebSocket, auth), see the
[TSP cookbook](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/tsp/cookbook.md).

### Storage backend (pick one)

| Feature | Default | Use case |
|---|---|---|
| `redis-backend` | Yes | Multi-mediator clusters; cross-process pub/sub. |
| `fjall-backend` | No | Single-node persistence; embedded LSM, no sidecar. |
| `memory-backend` | No | Tests and in-process integration only. |

Select the backend at runtime with `[storage].backend` in `mediator.toml`
(env `STORAGE_BACKEND`, `redis` or `fjall`).

### Secret backend

`file://` is always compiled in. Every other backend is one opt-in feature.
See [docs/secrets-backend.md](docs/secrets-backend.md#which-backends-are-compiled-in).

| Feature | Backend URL |
|---|---|
| (built in) | `file://`, optionally `?encrypt=1` (AES-256-GCM, Argon2id) |
| `secrets-keyring` | `keyring://` (macOS login Keychain; on Linux the kernel keyring, which is lost on reboot — desktop development only) |
| `secrets-aws` | `aws_secrets://` |
| `secrets-gcp` | `gcp_secrets://` |
| `secrets-azure` | `azure_keyvault://` (Azure CLI login only: wizard / development use) |
| `secrets-vault` | `vault://` (token, Kubernetes, or AppRole auth) |
| `secrets-k8s` | `k8s://` (one Kubernetes `Secret`) |

### Other

| Feature | Default | Description |
|---|---|---|
| `vta` | Yes | VTA-backed key management and `mediator rotate-admin`. Self-hosted mediators don't need it. |
| `jemalloc` | Yes | jemalloc as the global allocator, so RSS falls back after load. |
| `aws` | No | `aws_parameter_store://` and `s3://` sources for `did_web_self_hosted`. Enabled by `secrets-aws`. |

### Example builds

```bash
# Default: DIDComm + TSP + Redis, file:// secrets
cargo build --locked -p affinidi-messaging-mediator

# Single node: Fjall + OS keyring
cargo build --locked -p affinidi-messaging-mediator \
  --no-default-features \
  --features didcomm,tsp,fjall-backend,secrets-keyring,jemalloc,vta

# Cluster with AWS Secrets Manager
cargo build --locked -p affinidi-messaging-mediator \
  --features secrets-aws
```

## Architecture

```mermaid
graph TD
    A["Alice"] -->|DIDComm / TSP| MED["Mediator Service"]
    B["Bob"] -->|DIDComm / TSP| MED
    MED ---|Message Storage| STORE[(Redis or Fjall)]
    MED --- ACL["Access Control<br/>Lists (ACLs)"]
    MED --- PROC["Processors<br/>(Forwarding, Expiry)"]
```

[docs/architecture.md](docs/architecture.md) maps the code: the crates, the
mediator's modules, and the path a message takes from the inbound request to
storage, live delivery or forwarding, and deletion.

## DID multiplexing

One authenticated WebSocket can carry live delivery, pickup and sending for
many DIDs, each of which signs a grant or attach statement allowing it. It is
off by default (`[limits.mux] enabled`), and served over DIDComm
(`didcomm-mux` subprotocol) and raw TSP (`tsp-mux`).
[docs/multiplexing.md](docs/multiplexing.md) covers enabling it, the
subprotocols, grants and scopes, the `messaging/mux/*` Trust Tasks, limits,
metrics and running several instances.

## Prerequisites

- Rust 1.95.0+ (2024 edition)
- For the Redis backend: Redis 7.1 or later, below 9.0 (checked at startup).
  Docker is the easiest way to run it locally.

## Redis security

With the Redis backend, Redis holds all messages, sessions and queues.

Set the connection URL in `mediator.toml` or with the `DATABASE_URL`
environment variable:

```toml
[database]
database_url = "redis://:yourpassword@redis.internal:6379/"   # requirepass
# database_url = "redis://mediator:secretpass@host:6379/"     # ACL user (Redis 6+)
# database_url = "rediss://:yourpassword@redis.internal:6379/" # TLS
# database_url = "redis://127.0.0.1/1"                         # database 1 of 0-15
```

| Environment | Minimum |
|---|---|
| Local dev | No auth. |
| Shared/staging | Password authentication (`requirepass`). |
| Production | ACL users, TLS (`rediss://`) and network isolation. |

At startup the mediator warns when a remote Redis has no authentication
(info level for localhost) and when a remote Redis is used without
`rediss://`.

## Secret storage

The mediator keeps its admin credential, JWT signing key, operating keys,
and VTA cache in one secret backend, named by a URL:

```toml
[secrets]
backend = "aws_secrets://us-east-1/prod/mediator/"   # no default: pick one, see below
cache_ttl = "30d"                          # optional, humantime
```

On keyring, AWS, GCP, Azure and Vault, everything lives in one backend
secret, `mediator_secrets_bundle` (with the URL's prefix). `file://` and
`k8s://` already use one object. A deployment that still has one secret per
key is migrated on first start; if that fails, the mediator stops and says
why.

`vta://` is not a backend. The VTA is a key source; the wizard writes what it
provisions into the backend you pick.

[docs/secrets-backend.md](docs/secrets-backend.md) is the reference: backend
URLs, the bundle and its migration, IAM permissions, entry schemas, `/readyz`,
and HA.

### VTA integration

With a [Verifiable Trust Agent](https://github.com/OpenVTC/verifiable-trust-infrastructure),
the VTA manages the mediator's DID and operating keys. The wizard's
**Online** flow, or the **sealed handoff** for air-gapped hosts, writes the
admin credential into your secret backend. See
[docs/setup-guide.md](docs/setup-guide.md).

### Re-running the wizard, rotation, teardown

```sh
mediator-setup --force-reprovision   # overwrite an existing setup (rotates every key)
mediator-setup --uninstall --config conf/mediator.toml   # delete stored keys and every file the setup wrote
mediator rotate-admin --dry-run      # preview an admin credential rotation
mediator rotate-admin                # rotate it (VTA-linked deployments)
```

## Access control

Access control has four independent layers. [docs/acls.md](docs/acls.md) is
the full guide, including permission flags and deployment recipes.

| Layer | Scope | What it decides |
|---|---|---|
| `mediator_acl_mode` | mediator-wide | Whether unknown DIDs may authenticate, and who may add accounts. |
| `global_acl_default` | mediator-wide | The ACL set given to every new DID. |
| `MediatorACLSet` | per DID | What that DID may do. |
| Access list | per DID | Which senders that DID accepts messages from. |

| `mediator_acl_mode` | Meaning |
|---|---|
| `explicit_deny` | **Open.** Any DID may authenticate; unknown DIDs are registered with `global_acl_default`. |
| `explicit_allow` | **Closed.** Only pre-registered DIDs may authenticate. Only admins may add accounts. |

The shipped configuration is open (`explicit_deny`) with
`global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES"`:
direct messaging only, no relay or invites.

## WebSocket message rate

Messages on an authenticated WebSocket are metered per socket at the same rate
as HTTP requests: unless `[limits] ws_messages_per_second` / `ws_message_burst`
are set, each socket inherits `rate_limit_per_ip` / `rate_limit_burst` (100 a
second, burst 50, by default). Turning per-IP limiting off (`0`, common behind
a load balancer) does not turn this off: the built-in 100 / 50 apply instead.
Only an explicit `ws_messages_per_second = "0"` disables it (warned at
startup), and an unreadable value refuses to start. The budget is per socket:
a DID-multiplexing connection has one budget shared by all the DIDs it
carries, so raise `ws_messages_per_second` / `ws_message_burst` for busy
multiplexing clients and watch `rate_limited_total{scope="ws"}`. When the per-DID limit
(`did_rate_limit_per_second`) is enabled, each message is also charged to the
sender's DID, shared across all of its sockets. A message over the rate is not
dropped: the mediator stops reading the socket until it is due, and a socket
that stays over the rate for `ws_message_throttle_close_secs` (default 10;
`0` = never) is closed with 1008 "message rate limit exceeded". Messages that
had to wait are counted in `rate_limited_total{scope="ws"}` (and
`{scope="did"}`). The mediator's own DID and the admin DID are not metered. See
`conf/mediator.toml` for the details.

## Behind a load balancer

The per-IP rate limiter (`[limits] rate_limit_per_ip`) keys on the socket peer,
so behind a reverse proxy every client shares the proxy's bucket. Set
`[server] trust_xff_cidrs` (env `TRUST_XFF_CIDRS`) to the proxy's ranges and
the limiter charges each request to the client address in `X-Forwarded-For`
instead. List only proxies that append to the header, and make sure the
mediator is reachable only through them. A malformed chain from a listed proxy
is refused with `400` and counted in
`rate_limit_attribution_failures_total`; refusals carry
`x-rate-limit-source: mediator`. See `conf/mediator.toml` for the details.

The same client-address resolution decides who may read `/metrics`: by
default only loopback and private, shared (CGNAT), link-local and IPv6
unique-local addresses, so a scraper in the same host, cluster or VPC works and
a client on the public internet gets `403`. Widen or narrow it with
`[server] metrics_allow_cidrs` (env `METRICS_ALLOW_CIDRS`; `[]` refuses
everyone), require a bearer token with `metrics_bearer_token` (env
`METRICS_BEARER_TOKEN`; an empty value is refused at startup), and bound the request rate with
`[limits] metrics_requests_per_second` (default 5, shared by all callers).
Refusals are counted in `metrics_requests_refused_total{reason}`. Behind a load
balancer that does not appear in `trust_xff_cidrs`, every request seems to come
from the balancer's (usually private) address, so add the balancer's ranges to
`trust_xff_cidrs` or narrow `metrics_allow_cidrs` to the scraper.

## More documentation

| Doc | Covers |
|---|---|
| [setup-guide.md](docs/setup-guide.md) | VTA setup modes (Online, sealed-mint, sealed-export) and recipes. |
| [secrets-backend.md](docs/secrets-backend.md) | Secret backends, entry schemas, migration, HA. |
| [acls.md](docs/acls.md) | Access control. |
| [cors-and-origin.md](docs/cors-and-origin.md) | CORS and WebSocket origin checks. |
| [didcomm-protocols.md](docs/didcomm-protocols.md) | Supported DIDComm protocols. |
| [mediation-and-routing.md](docs/mediation-and-routing.md) | Addressing: v2 is DID-addressed, v1 is keylist-addressed, and what gates reachability. |
| [multi-mediator.md](docs/multi-mediator.md) | Federating mediators: relay hops, blind vs rewrap, config and ACLs. |
| [memory-tuning.md](docs/memory-tuning.md) | Memory use and throughput knobs for Fjall and Redis. |
| [multiplexing.md](docs/multiplexing.md) | DID multiplexing: grants, scopes, the `didcomm-mux` and `tsp-mux` subprotocols, limits, metrics. |
| [operations.md](docs/operations.md) | Health and readiness probes, `/metrics` and its catalogue, logs, shutdown, the `mediator` subcommands. |
| [architecture.md](docs/architecture.md) | Crate and module map, and a message's lifecycle through the code. |
| [delivery-rules.md](../../docs/delivery-rules.md) | The R-numbered delivery and contract rules cited in code and the changelog. |
| [ERRORS.md](ERRORS.md) | Error codes. |

## Managing the mediator

`mediator-console` operates a running mediator from a terminal: statistics,
account queues, messages (inspect, delete, purge), ACLs and queue limits, the
audit log, and a live traffic monitor. Connect with the administrator profile
the wizard wrote (`conf/admin-monitor.json`) to manage the whole mediator, or
with an account's profile to manage that account.

```bash
cargo run --release -p affinidi-messaging-mediator-tui -- --profile conf/admin-monitor.json
```

See [affinidi-messaging-mediator-tui](../affinidi-messaging-mediator-tui/).

For headless administration from code, use
[`affinidi-messaging-mediator-admin`](../affinidi-messaging-mediator-admin/).
The interactive `mediator_administration` tool and more client examples live
in [affinidi-messaging-helpers](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-helpers)
in affinidi-tdk-rs (`cargo run --bin mediator_administration` from that
repository).

## Sub-crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-mediator-setup`](./tools/mediator-setup/) | Setup wizard, the `mediator-setup` binary (TUI and headless). |
| [`affinidi-messaging-mediator-common`](./affinidi-messaging-mediator-common/) | Shared types, storage traits, secret backends. |
| [`affinidi-messaging-mediator-config`](./affinidi-messaging-mediator-config/) | The `mediator.toml` schema. |
| [`affinidi-messaging-mediator-processors`](./affinidi-messaging-mediator-processors/) | Standalone forwarding and expiry processors (Redis). |

## Related crates

All in [affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs):

- [`affinidi-messaging-sdk`](https://crates.io/crates/affinidi-messaging-sdk): client SDK
- [`affinidi-messaging-didcomm`](https://crates.io/crates/affinidi-messaging-didcomm): DIDComm protocol
- [`affinidi-tsp`](https://crates.io/crates/affinidi-tsp): Trust Spanning Protocol
- [`affinidi-messaging-core`](https://crates.io/crates/affinidi-messaging-core): protocol-agnostic messaging traits
- [`affinidi-did-resolver-cache-sdk`](https://crates.io/crates/affinidi-did-resolver-cache-sdk): DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-messaging-mediator/blob/main/LICENSE)
