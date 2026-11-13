### Breaking — test mediator keeps private keys on their own side of the boundary

`affinidi-messaging-test-mediator` no longer shares one secrets resolver
between the mediator and the test's client (#149). By default:

- the mediator's private keys stay in the mediator's resolver.
  `TestEnvironment` no longer copies them into the SDK's resolver
  (`env.tdk`), so the SDK cannot decrypt anything addressed to the mediator;
- user keys from `TestMediatorHandle::add_user` / `TestMediator::with_users`
  go into a client-side resolver, and no longer into the mediator's.
  `TestMediatorHandle::secrets_resolver()` now returns that client-side
  resolver, which holds no mediator keys. `TestEnvironment::add_user` follows
  the same rule, so the two `add_user`s now behave alike.

A downstream test that passed only because the keys were shared, such as an
envelope encrypted to the end recipient instead of wrapped in a forward, or
mail unpacked by the wrong party, now fails as it would against a real
mediator. Tests that genuinely act as the mediator (forging what it would
sign) opt in: `TestEnvironment::with_mediator_keys()` copies the mediator's
keys into the SDK's resolver, and `TestMediatorBuilder::share_secrets(true)`
restores the old single shared resolver. `TestMediatorHandle::shares_secrets()`
reports which applies. All users of one `TestEnvironment` still share its SDK
resolver, as before.

### Breaking — dropping a `TestMediatorHandle` stops the mediator

The handle's docs always said it stops on drop, but it did not: a test that
failed or returned early left the server, listener and processors running
until the runtime ended (#153). Dropping the handle (or the
`TestEnvironment` / `TestTopology` that owns it) now cancels the mediator. A
test that let the handle go out of scope while still using the mediator
through its URL must now keep the handle alive. With `fjall-backend` the
store's temp directory is removed only after the server task has ended, not
underneath it. The handle is `#[must_use]`.

### Changed — test mediator suite is one binary

The fixture's ~80 integration-test files are now modules of one binary,
`tests/e2e/main.rs`, which links the mediator, SDK and TDK once instead of
once per file (#157). Select an area with a name filter, e.g.
`cargo test -p affinidi-messaging-test-mediator --test e2e -- mux_send::`.
Only `metrics_endpoint`, `mux_metrics` and `config_reload` remain separate
binaries, since each needs process-wide state to itself. The copies of the
grant, clock, basic-message, mailbox, websocket-token and Redis-store helpers
are now one each in `tests/common`; fixed sleeps in `receive_leg_probe`
(45 s, now done when the probe is answered, about 20 s), `tsp_transport_adapter`
and `websocket_per_did_cap` wait for the condition instead; the no-op
`skip_if_no_redis` is gone; and the forwarding-processor Redis tests move to
logical DBs 5-7 so they no longer collide with the cross-instance tests in the
same process. CI's Redis and TSP jobs select the same suites by filter.

### Security — operator key files are read and written more carefully

- `ProfileFileSource` (the standalone console's `--profile`, such as
  `admin-monitor.json`) refuses on Unix to load a profile that its group or
  other users can access (any of mode `0o077`), naming the `chmod 600` that
  fixes it, as `ssh` does with a private key. `mediator-setup` already writes
  the file at `0600`. The file's bytes are wiped once parsed, and listing
  profiles no longer parses their secrets (#169).
- `AddressBook::save` writes atomically (a temporary file, flushed, then
  renamed over the book), so a crash mid-save leaves the old book whole, and
  creates the file at mode `0600`.
- The test mediator's `standalone` example prints a "TEST FIXTURE — no TLS,
  allow-all ACL" banner when bound to a non-loopback address, and the
  fixture's README says it is test-only.
