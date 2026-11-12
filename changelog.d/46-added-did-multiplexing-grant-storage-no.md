### Added — DID multiplexing grant storage (no behaviour change yet)

- Storage for DID multiplexing grants: a member DID's signed permission for a
  *principal* connection to collect its messages (design:
  `design-docs/mediator-did-multiplexing-design.md`). Every grant rule (epoch,
  replay floor, quotas, narrow-only updates, unknown-key suspension, expiry)
  lives once, in `affinidi-messaging-mediator-common::store::mux`; the Redis,
  Fjall and memory backends implement only a versioned compare-and-swap of a
  per-DID record, so they cannot drift on a rule. Nothing reads or writes
  grants yet: the protocol and connection handling follow, opt-in, behind
  `limits.mux.enabled` (off by default).
- `MediatorStore` gains `supports_mux`, `mux_record_get`, `mux_record_cas`,
  `mux_principal_dids` and `mux_principal_count`, all defaulted, so a
  third-party backend keeps compiling and reports mux as unsupported.
- `[limits.mux]` config (and `LIMIT_MUX_*` env overrides), **off by default**.
  Only the exact value `"true"` enables it; anything else is off. A mediator
  with `enabled = "true"` refuses to start on a backend without mux support
  or with live streaming disabled. With several instances behind one Redis, a
  revoke handled by one instance reaches another's live connections within
  one 30-second member sweep (it is immediate on the instance that handled
  it).
- Removing an account removes its mux grants on both sides (as a member DID
  and as a principal), whether or not mux is enabled at the time.
- `mux::proof::StatementVerifier`: verifies the `MuxGrant` / `MuxAttach`
  statements a member DID signs to allow a principal to carry its traffic.
  They use W3C Data Integrity proofs (`eddsa-jcs-2022` / `eddsa-rdfc-2022`),
  the same format and verifier as Trust Tasks, and only an `authentication`
  key may sign one. Statements are closed objects (unknown members are
  refused), bound to the mediator (`audience`), the principal and, for an
  attach, the connection. It can also re-check that a stored grant's signing
  key is still the member's current authentication key; a DID that cannot be
  resolved reports "unknown", never "stale" or "fine".
- `mux::grants`: the transport-free grant operations the protocol handlers
  will call: store (verify, then member standing and scope within the
  member's own ACLs, then the unknown-key rule, then the store rules), revoke
  as principal or member, revoke-all, and key re-validation. Each one returns
  exactly which grants it changed, so the connection layer can detach them.
- The live-delivery streaming task can now carry one DID on a mux
  connection as well as on its own socket. A DID's own (direct) socket always
  wins; a mux entry yields to it and waits on standby, is told it is inactive
  or superseded, and is reactivated (with inbox redelivery, as for any
  replacement) when the direct socket goes away. A mux connection is never
  closed for one of its members. Every queued frame now carries the DID it is
  for. Direct-socket behaviour (newest wins, duel damper, redelivery) is
  unchanged and still pinned by the existing tests.
- `mux::session::MuxSession`: one connection's member set. It admits members
  by session attach (bound to the connection's nonce) or by stored grant on
  connect (re-checking each grant's key; a DID that cannot be resolved is not
  carried), enforces `max_dids_per_connection`, expires and detaches members,
  and answers whether the connection may receive, pick up, delete or send for
  a given DID.
- The `messaging/mux/{grant,list,update,revoke,revoke-all}/0.1` Trust Tasks
  are served (over DIDComm and TSP, through the existing Trust Task core) when
  `limits.mux.enabled` is on; otherwise they answer
  `protocol.trust_task.unsupported`. The specs are pinned from trusttasks.org
  (dtgwg-trust-tasks-tf#1068).
- DIDComm mux connections. A client opens one by offering the
  `affinidi-mux` WebSocket subprotocol (provisional name) alongside its
  bearer token; the mediator echoes it only when mux is enabled. On connect
  the mediator admits the principal's stored grants, registers each member
  with live delivery on the one socket, and sends a signed
  `messaging/mux/event` `ready` (with the attach nonce) and `attached`.
  `messaging/mux/attach` and `detach` act on the connection they arrive on.
  Revoke, revoke-all, unknown-key suspension and narrowing reach every live
  connection carrying the affected DIDs **before** the response is sent, and
  a frame queued for a member that has since left is dropped, not written.
  Members expire on their own clocks and grant members' keys are re-checked
  every `revalidate_interval_secs`. Message pickup (`status-request`,
  `delivery-request`) and `messages-received` accept a member's DID when its
  scope includes `pickup` / `delete`.
