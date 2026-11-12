### Changed — DIDComm v1 `keylist-update` registers only keys the client is known to hold, up to a limit

- **Behaviour change (R3.6):** by default a `keylist-update` add succeeds
  only for the verkey that authenticated the request. Any other key gets
  `client_error`. Coordinate-mediation 1.0 gives the mediator no proof that a
  client holds the other keys it lists. Aries wallets, which register a new
  key per connection, need the new `[didcomm_v1] allow_unproven_routing_keys
  = true` (default `false`).
- **Behaviour change (R3.6):** an account holds at most
  `[didcomm_v1] max_routing_keys_per_account` routing keys (new, default
  256). An add past the limit gets `client_error`, and removing a key frees
  a slot. The account's keys are counted once per request and again after
  its adds. If concurrent requests took the account over the limit, the
  request's newest adds are withdrawn and reported as `client_error`.
- **Behaviour change (R3.6):** an add needs the account to hold
  `RECEIVE_MESSAGES`, the same condition `mediate-request` checks before it
  grants mediation. Otherwise the add gets `client_error`. A remove does not
  need it.
- **Behaviour change (R3.6):** one `keylist-update` may carry at most 100
  entries. A longer one is refused with `400 message.didcomm_v1.keylist`, and
  none of its entries are applied.
- **Behaviour change (R3.6):** a key registered without proof can be taken
  over by its holder. That is the case where another account registered the
  key under `allow_unproven_routing_keys`, and the key's holder then adds it
  in a request that key authenticates. Otherwise a key registered to one
  account is still never moved to another.
- Re-adding a key the account already holds is `no_change` under every
  setting.
- When another account claims a key between the mediator's check and its
  bind, the add gets `client_error`. It used to get `server_error`.
- A remove, or a withdrawn add, deletes the binding only while this account
  still holds it. The deletion is one atomic step in each store. New
  `MediatorStore::v1_routing_key_unbind_if_owner`.
- Every refused add is logged with its reason. The mediator warns at startup
  when `allow_unproven_routing_keys` is on.
- New: `MediatorBuilder::didcomm_v1_routing_keys` and
  `TestMediatorBuilder::didcomm_v1_routing_keys`.
