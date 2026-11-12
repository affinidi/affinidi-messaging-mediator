### Added — Administrators list and revoke stored mux grants

- The mediator serves three new Trust Tasks (specs 0.1, pinned in
  `trust-tasks.lock`), when `limits.mux.enabled` is on:
  - `messaging/mux/admin-list` lists the stored grants of a principal DID,
    of a member DID, or between the two, a page at a time. Each grant shows
    its parties, state, effective scope and expiry, epoch and signing time,
    never the signed statement. With `member`, the answer carries the
    member's current epoch. Open to `admin`, `rootAdmin` and the mediator's
    own account. Cursors are bound to the requester and the request, and
    continue on any instance of the mediator.
  - `messaging/mux/admin-revoke` revokes grants by principal, by member, by
    both, or by member and grant ids, at most `limit` (500) per request,
    with an exact `remaining` count. Same effect as `messaging/mux/revoke`:
    members are detached on every connection before the answer, the replay
    floor rises, and each principal gets a `detached` event and a durable
    `grantsRevoked` notice, both with reason `admin`.
  - `messaging/mux/admin-revoke-all` advances a member DID's epoch on the
    administrator's standing, compare-and-set on the epoch the request
    names. Same state change as `messaging/mux/revoke-all`, reported with
    reason `admin` instead of `epochBumped`.
- Both revoke tasks are for `admin` and `rootAdmin` only. An `admin` is
  refused (`protectedAccount`) when a selected grant's member or principal
  is a `rootAdmin`, before anything is revoked; a `rootAdmin` may act on any
  grant. Each revocation and epoch advance is written to the audit log.

### Changed — Cross-instance mux detaches keep the reason they were made with

- A mux change record published to the other instances now carries the
  reason the originating instance detached with (`MuxChange::reason`, and
  `reason` on `MemberHint::AttachesEnded`). A receiving instance uses it to
  label a detach the store cannot attribute, so a principal connected to
  another instance sees `admin` or `revokedByPrincipal` rather than
  `revokedByMember` or `epochBumped`. The store still decides whether a
  member leaves. Records without the field read as before, so instances can
  be upgraded one at a time.
- `affinidi-messaging-mediator-common`: `MuxChange` gains a public `reason`
  field and `MemberHint::AttachesEnded` a `reason` field. Code that builds
  either with a struct literal must add them (`None`); `MuxChange::of` is
  unchanged.
