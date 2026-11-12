### Changed — live mux members and monitor subscriptions follow account changes
### Changed — live mux members and monitor subscriptions follow account changes; `revoke-all` ends session attaches

- A mux member stays on a connection only while its own account stands: it
  exists, is not blocked, and its ACLs still cover the member's scope. That
  was checked only when the member was admitted. It is now checked again:
  - at once, when `account/update` changes the member's ACLs or
    `account/remove` removes it: on the instance that handled it before it
    answers, and on the other instances sharing a Redis store within one
    pub/sub hop (a new `members` entry on the mux change record; an
    instance that predates it ignores it);
  - when a pickup or delete is made for the member on the connection, or a
    `tsp-mux` drain is about to walk its inbox. A delete checks only the
    member that a message id belongs to, and a good result counts for 10
    seconds, so a burst of requests reads the account once;
  - every 30 seconds, by a standing pass that runs off the socket loop with
    at most 8 store reads in flight. This catches a change made directly in
    the store, or whose pub/sub record was lost.

  A member whose standing has lapsed is detached, with a `detached` event
  naming `accountBlocked` or `accountRemoved`. Members admitted by a session
  attach are covered as well as grant-admitted ones; until now an attach
  outlived its member's removal. ACLs narrowed below the member's scope
  detach the whole member with `accountBlocked`, as admission would have
  refused it; the member is not narrowed to what the ACLs still allow. A
  store failure during a re-check keeps the member, but the request it was
  made for is refused.
- `messaging/mux/revoke-all` now ends the member DID's session attaches as
  well as its grants, on every connection carrying it, before it answers,
  with a `detached` event naming `epochBumped`. Other instances end theirs
  within one pub/sub hop. Only attaches admitted before the `revoke-all` end;
  one made afterwards stays.
- A live frame for a member whose admission has expired is no longer
  written in the moments before the sweep removes the member.
- A `messaging/monitor/subscribe` subscription whose filter reaches beyond
  its owner's own account (one only an administrator may open) now needs its
  owner to still be an administrator (the store's admin check) each time a
  batch is sent. Any subscription also ends when its owner's account is
  removed or blocked. When that happens:
  - pending events are discarded and counted as dropped;
  - the subscription is ended before the subscriber is told, so a renewal
    racing the end also gets `unknownSubscription`;
  - a last batch with no events and `expiresAt` set to now tells the
    subscriber it has ended;
  - if the subscription had administrator reach, its end is written to the
    audit log as `monitorUnsubscribe`.

  A batch whose standing check cannot read the store is withheld and
  counted as dropped; the next batch reports it.

**Behaviour change (R3.6):**
- A principal can lose a member before the grant or attach expires, when an
  administrator blocks or removes the member's account or narrows its ACLs
  below the member's scope. Clients already handle `detached` with these
  reasons, which the event schema defines.
- `revoke-all` ends session attaches. The `messaging/mux/revoke-all` 0.1
  specification said they were unaffected; it is amended to match
  (dtgwg-trust-tasks-tf#1165). A principal relying on an attach
  surviving its member's `revoke-all` must attach again with a new statement.
- An administrator demoted mid-lease stops receiving monitor batches at the
  next batch rather than at the end of the lease. A client that renews only
  shortly before `expiresAt` should treat a batch whose `expiresAt` has
  already passed as the end of the subscription.
