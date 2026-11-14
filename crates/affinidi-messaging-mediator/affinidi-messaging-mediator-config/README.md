# affinidi-messaging-mediator-config

Raw TOML configuration **schema** for the Affinidi Messaging Mediator — the
serde `*ConfigRaw` types that mirror `mediator.toml`.

This crate is deliberately dependency-light (serde, toml, logging and
`affinidi-messaging-mediator-types`). `affinidi-messaging-mediator-common`
depends on it, for the defaults table (`defaults`) and the `redact` and
`did_identity` helpers it re-exports. It contains **only the on-disk shape**;
the resolved runtime `Config` (opened secret backends, JWT keys, the
DID-resolver client, the VTA refresher) and every `ConfigRaw → Config`
conversion live in the `affinidi-messaging-mediator` binary, which re-exports
these types.

The goal is one schema with two consumers — the mediator and the
`mediator-setup` wizard — instead of the wizard hand-rendering TOML that can
drift from what the mediator parses.
