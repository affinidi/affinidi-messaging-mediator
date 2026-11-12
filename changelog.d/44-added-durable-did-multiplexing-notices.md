### Added — durable DID multiplexing notices

- The mediator now stores signed `messaging/mux/notice/0.1` documents in the
  inbox of the party that must act. They are delivered at least once, and
  the recipient acknowledges one by deleting it:
  - `grantsSuspended` goes to each principal whose grants the unknown-key
    rule suspended. Those grants must be recreated with a fresh member
    signature. A principal that was offline finds the notice when it next
    picks up or connects.
  - `grantsRevoked` goes to each principal whose grant was revoked by its
    member (`revokedByMember`), voided by `revoke-all` (`epochBumped`), or
    removed with the member's account (`accountRemoved`). A principal that
    revoked its own grant is not sent one.
  - `grantsPresent` goes to a member DID: when its new key suspended grants,
    and when it authenticates directly (DIDComm) while grants on it exist
    and it has not been told since they changed. It carries counts only,
    never a principal DID.
- The `ready` event's `pendingNotices` now counts the notices waiting in the
  principal's inbox. It was always 0.
- A notice is stored only after the change it reports is committed and its
  members are detached. A `grantsSuspended` or `epochBumped` notice lost to
  a crash is sent when the principal next opens a mux connection. A
  `revokedByMember` or `accountRemoved` notice is best effort, because those
  grants are deleted; `messaging/mux/list` stays the source of truth.
- Removing a member DID's account now detaches it from its principals' live
  connections at once (`accountRemoved`). Before, they kept carrying it until
  the next 30-second sweep.
- **The unknown-key rule now also runs on direct authentication**, comparing
  the proven key only with keys of the same kind. A grant records the member
  DID's `keyAgreement` keys when it is stored. A DIDComm login fires the rule
  only if its authcrypt sender key is none of those. A TSP login fires it
  only if the VID's signing key signed none of the active grants. A member
  that logs in directly with keys it already had keeps its grants; a key
  added since suspends them, with the same notices as any other suspension.
  A DID that listed no `keyAgreement` keys when it granted has none known,
  so its first one suspends its grants. Spec:
  trustoverip/dtgwg-trust-tasks-tf#1072.
- **Behaviour change (login):** for a DID with active mux grants, the
  unknown-key check runs before the login succeeds, and its suspensions are
  committed and detached before tokens are issued. If the check cannot run,
  because the sender key does not resolve or the store fails, the login is
  refused with `me.res.storage.error` (HTTP 503) and the client retries. A
  DID with no active grant is unaffected and never resolved for this.
- A grant whose member DID cannot be resolved for its `keyAgreement` keys is
  refused with `messaging/mux:didUnresolvable` (retryable). Before, it was
  stored with no keys recorded, which switched the DIDComm unknown-key rule
  off for every grant on that DID.
- A mux connection now re-reads its grants once it is published, so a
  revocation or suspension committed while it was opening detaches the
  member at once rather than at the next sweep.
- `grantsExpiring` is stored once per grant, for active grants past about
  three quarters of their lifetime. It is checked when the principal logs
  in, when it opens a mux connection, and on the key re-check timer while
  connected (`revalidate_interval_secs`). The mediator cannot see a client's
  renewal opt-in, so it sends the notice for every such grant; a client that
  renews discards it. A renewed grant starts a new lifetime.
- Not yet: the audit record for a suspension. Each notice is one more inbox
  message, so a principal that never drains its inbox accumulates them.
