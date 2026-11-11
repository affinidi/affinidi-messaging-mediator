# Credo mediation interop (developer-only)

Checks the mediator's Aries coordinate-mediation 1.0 and message-pickup 2.0
messages against Credo's own message classes, in both directions. See the
header of `mediation.mjs` for what each half proves.

The test mediator in these tests sets `[didcomm_v1]
allow_unproven_routing_keys = true`. Credo registers a new key for each
connection, not the key it authenticates with, and the mediator accepts such
keys only when this setting is on. A mediator that serves Credo wallets needs
the same setting.

```sh
cd interop/didcomm-v1
npm install
npm run generate   # writes the Credo-built requests to the test-mediator fixtures
cargo test -p affinidi-messaging-test-mediator --features didcomm-v1 --tests
npm run generate   # re-run: now also parses the mediator's replies through Credo
```

The envelope-level interop (`generate.mjs`, packing and unpacking against
Credo) stays with `affinidi-messaging-didcomm-v1` in affinidi-tdk-rs.
