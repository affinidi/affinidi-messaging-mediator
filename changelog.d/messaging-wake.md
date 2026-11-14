### Added — Waking an account's device on a sender's request (`messaging/wake/set`, `messaging/wake/request`)

- `messaging/wake/set/0.1`: an account gives the mediator the opaque wake
  handle its push gateway issued, or clears it. One record per account, in
  every storage backend, removed with the account. Answered `wakeCapable:
  true` only when the mediator holds the handle and can ring its gateway (a
  DID advertising `DIDCommMessaging`).
- `messaging/wake/request/0.1`: a sender that has just queued mail for an
  account asks the mediator to ring the account's device. Accepted from a
  sender with no account here, relayed by its own mediator, for this type
  only; it never creates an account and is charged to the per-DID inbound
  rate limit. Its proof (`proofPurpose: authentication`) is required and
  checked whatever `security.trust_task_verification` says. Every accepted
  request is answered with the same `{}`, before and whatever the mediator
  decides, so it reveals nothing about the addressee.
- The mediator rings — `push/wake/0.2` to the handle's gateway, signed as the
  mediator, over DIDComm — only when the addressee is an offline account with
  a handle, every named message is queued for it, undelivered and stored in
  the last 10 minutes, a stored authcrypt envelope's sender is the requester,
  the addressee's access list does not refuse the requester, no named message
  has rung before, and the `[processors.wake]` limits allow it (defaults: one
  ring a minute and ten a day per requester and addressee; rings for one
  addressee coalesce over 15 s, at most 30 an hour). A request naming mail not
  stored yet is held for up to 120 s. A gateway answer `tokenUnregistered`
  drops the handle; `notAllowed` stops ringing it until the account sets one.
- New metrics `wake_requests_total{outcome}` and `wake_rings_total{outcome}`;
  new config `[processors.wake]` (`enabled`, `pair_per_minute`,
  `pair_per_day`, `addressee_coalesce_seconds`, `addressee_per_hour`, each
  with a `PROCESSOR_WAKE_*` environment override). Absent, waking is on with
  the defaults above.
- `AuxiliaryStore` gains `wake_handle_set` / `wake_handle_get`, implemented
  by the memory, fjall and redis backends. A third-party backend must
  implement them.

### Breaking — `wake` fields on `ProcessorsConfig`, `ProcessorsConfigRaw` and `SharedData`; two `AuxiliaryStore` methods

- `ProcessorsConfig` and `ProcessorsConfigRaw` gain `wake`, and `SharedData`
  gains `wake`. Code that builds any of them with a struct literal must add
  the field (`WakeConfig::default()`, `WakeConfigRaw::default()`,
  `Default::default()`); code that starts from `Default` is unaffected.
- `AuxiliaryStore` (part of `MediatorStore`) gains the required
  `wake_handle_set` and `wake_handle_get`.
