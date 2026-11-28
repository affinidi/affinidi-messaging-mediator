### Breaking — trust-tasks-rs 0.43, trust-tasks-build 0.3.0, affinidi-messaging-sdk 0.52

- The workspace moves to trust-tasks-rs / trust-tasks-proof 0.43,
  trust-tasks-build 0.3.0, affinidi-messaging-sdk 0.52 and affinidi-tdk 0.51,
  so a downstream service can adopt the `hcp/*` Trust Task suite with one
  `trust-tasks-rs` in its graph. Trust Task types are in the admin client's
  public API, so consumers move with it.
- Generated payload types keep member presence (trust-tasks-tf #1385): an
  optional array is `Option<Vec<T>>` and an optional nullable member is
  `Option<Option<T>>`. The mediator, admin client, TUI and console read them so
  that an absent array behaves as the empty one did. No wire change: delivery,
  ack and auth semantics are unchanged.
- Typed consume validates the payload as received (trust-tasks-tf #1398): a
  forbidden `null` on an optional member is now refused `malformedRequest`
  rather than read as absent.
