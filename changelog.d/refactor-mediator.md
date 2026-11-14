### Changed — one local-delivery gate for DIDComm, TSP and DIDComm v1 (R3.6)

DIDComm v2 direct delivery, TSP (opaque pass-through and the routed, nested
and to-mediator arms) and the DIDComm v1 forward now pass the same
local-delivery gate (`messages::delivery_gate`). The three copies it replaces
had drifted; where they disagreed the gate keeps the stricter or more correct
answer. These are behaviour changes on the delivery and auth paths, so
consumers that match on them should check:

- **The mediator DID and a claimed sender are compared as accounts**
  (`same_account`, which ignores a did:scid `src` locator) on every path. A
  DIDComm envelope addressed to the mediator under another locator of its
  did:scid DID is now handled as addressed to the mediator rather than as a
  direct delivery, and a DIDComm direct delivery whose `skid` names the session
  DID under another locator is no longer refused with
  `authorization.did.session_mismatch`. TSP already behaved this way.
- **Who a stored message is attributed to** (its queue gates, account stats
  and recorded sender) is the sender verified on the hop, else the
  authenticated session, else the claimed sender. Two cases change: a TSP
  pass-through on an authenticated session with `force_session_did_match`
  off is now charged to the session rather than to the envelope's unchecked
  sender claim; and a DIDComm direct delivery on the anonymous relay session
  (blind relay) is charged to its claimed sender, as TSP already did, rather
  than to the anonymous session.
- **The direct-delivery-disabled refusal** (`direct_delivery.denied`, same
  code) is one problem report on both protocols: sorter `error`, scope
  `message`, and protocol-neutral text. DIDComm sent `warning`; TSP sent scope
  `protocol`.
- **DIDComm direct delivery binds the claimed sender to the session before
  the direct-delivery policy**, as TSP does. A sender that fails both now gets
  `authorization.did.session_mismatch` rather than `direct_delivery.denied`.
- **The relay peer allowlist** (`relay_trusted_mediators`) matches a peer by
  account, so a did:scid peer is recognised under any `src` locator.

### Changed — message processing and connection handling restructured

- No wire or behaviour change beyond the entry above. `messages/inbound.rs`
  is split per protocol (`inbound/{didcomm,tsp,tsp_relay}.rs`),
  `protocols/trust_tasks.rs` by task family, and `handlers/websocket.rs` by
  concern; `serve_internal` is a sequence of named startup phases and the
  WebSocket connection loop is a `ConnectionMode` with one handler per event.
- Message expiry is checked once, before dispatch, for every DIDComm message
  to the mediator. `ProcessMessageResponse` is an enum.

### Deprecated — `messages::WrapperType`

- No longer used by the mediator; removed at the next breaking release.
