### Breaking — `MediatorStore` is split into capability traits, with no silent defaults

- `affinidi-messaging-mediator-common`: `MediatorStore` is now a facade with
  no methods of its own over twelve capability traits — `StoreLifecycle`,
  `MessageStore`, `SessionStore`, `AccountStore`, `AclStore`, `StatsStore`,
  `ForwardQueueStore`, `StreamingStore`, `MuxStore`, `V1RoutingKeyStore`,
  `AuditStore` and `AuxiliaryStore` — and is implemented for every type that
  implements them all. A storage backend outside this workspace implements
  each trait instead of `MediatorStore`. Code holding `Arc<dyn MediatorStore>`
  keeps calling methods as before.
- The algorithms no backend overrode move to `MediatorStoreExt`, implemented
  for every `MediatorStore` and not overridable: `delete_message`,
  `fetch_messages_fair`, `fetch_messages_delivering`, `record_delivered`,
  `count_sent`, the four purges, `account_add` and the legacy aliases
  (`create_session`, `update_send_stats`, `add_admin_accounts`,
  `strip_admin_accounts`). Calling them needs
  `use affinidi_messaging_mediator_common::store::MediatorStoreExt;` (or
  `store::prelude::*`). A `MediatorStore::method(...)` call in path form names
  the capability trait instead.
- Every method whose default made a backend degrade silently is now required:
  acknowledgements, outbox receipts and sent-message states, delivery marking
  and state, `peer_queue_count`, the expiry and session sweeps, refresh-token
  reads and rotation, `update_session_authenticated` (whose default was not
  atomic), account activity and counters, `delivery_decision`, Trust Task
  claims, did:scid sources, config overrides, mux and DIDComm v1 primitives,
  the tagged and verbatim publishes, the forward queue's ack-and-delete and
  consumer pruning, `circuit_breaker_state`, `spans_processes`, and the
  cross-instance streaming calls. The only defaults left are loops that are
  correct everywhere (`get_messages`, `delivery_states`, `streaming_owners`).
  Single-process backends call `store::single_process` for the streaming
  claim and release.
- New store operations `AccountStore::account_update` and
  `AclStore::access_list_update`, with the `AccountUpdate`,
  `AccessListUpdate` and `AccessListUpdateOutcome` types.
- The Redis database module's own `MessageMetaData` and `MetadataStats` are
  re-exports of the store types, and the Redis store's identity conversions
  between them are gone (they cloned every forward-queue body).
- No wire changes.

### Fixed — `account/update` and `access-list/update` apply atomically

- `messaging/account/update` wrote the ACL, the queue limits and the role in
  up to four store calls, and `messaging/access-list/update` cleared, added
  and removed in up to three, so a store failure part-way left a partial
  update in place (audited as `outcome partial`). Each is now one store
  operation on every backend: one Lua script on Redis, one batch on Fjall,
  one locked change in memory. A failure leaves the account or list as it
  was, and no reader sees a list cleared and not yet refilled. With Redis
  cluster mode on, the global `ADMINS` set is a separate step, written before
  a promotion and after a demotion; `ROLE_TYPE`, which alone grants admin
  rights, is always in the atomic step.
- `access-list/update` reports a hash listed twice in `remove` once, and its
  `accessListCount` is the count the update left, not a second read.

### Fixed — the Redis store reports its circuit breaker

- `RedisStore` inherited the trait's `circuit_breaker_state` default, which
  always answered `closed`, so `/readyz` never failed its
  `redis_circuit_breaker` check and the store's `health()` always said
  healthy, even with the breaker open. It now reports the breaker's state.
  **Behaviour change (R6.2):** while the breaker is open, `/readyz` answers
  503 `not_ready` until a request (the readiness probe's storage check is
  one) finds Redis back.
- The in-memory store's forward-queue ack-and-delete is one step under its
  lock instead of an ack followed by a delete.
