### Fixed — `blocked_forwarding_dids` and `limits.to_keys_per_recipient` take effect

- A DIDComm forward or TSP relay whose relay endpoint, relay DID or next hop
  is on `processors.forwarding.blocked_forwarding` is refused instead of
  queued: DIDComm answers `delivery_refused`, TSP error 94. The list holds
  this mediator's own DID and published endpoints, plus each DID in
  `blocked_forwarding_dids` and its endpoints. Both settings were loaded at
  startup but never consulted. Entries and candidates are compared in one
  canonical form, so another spelling of a listed DID or URL is refused too:
  a DID matches with any case of `did:` and its method, and with a query or
  fragment; a URL matches with any case of scheme and host, its default
  port, a trailing dot on the host, a fragment, or an internationalised
  host in either its Unicode or punycode form.
- A reply is not packed for a recipient that publishes more key-agreement
  keys than `limits.to_keys_per_recipient` (default 100); the sender gets
  `message.pack` (47). The recipient lookup this uses replaces one whose
  result was discarded.

**Behaviour change (R3.6):** a forward addressed to this mediator's own
published endpoint, when that endpoint is not covered by `local_endpoints`,
is now refused instead of relayed back to this mediator (where it used to
travel round until `max_hops`). Declare public aliases in `local_endpoints`
to have them delivered locally.
