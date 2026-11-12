### Fixed — `attached` events for attaches and narrowed grants

Spec event rule 5 says a mediator emits `attached` whenever a member joins
or its scope or expiry changes. Three gaps:

- A DID admitted by `messaging/mux/attach` got no `attached` event, only the
  task response, so a client keeping its member set from events never saw
  it. It now gets one, with reason `attach`.
- Narrowing a grant (`messaging/mux/update`, here or relayed from another
  instance) changed the member's scope and expiry silently. It is now
  reported in an `attached` event with reason `grant`.
- A member joining while connected was always reported
  `deliveryActive: true`, and was labelled `grant` even when it came by
  attach. `deliveryActive` now says whether the member's live traffic comes
  over this connection: `false` while the DID's own socket, or a newer
  connection, holds it, until an `attached` with reason `reactivated`.

**Behaviour change (R3.6):** principals may now see `attached` events where
there were none, and a `grant` join with `deliveryActive: false`. Clients
built on affinidi-messaging-sdk 0.45.5 fold them into `mux_members()`.
