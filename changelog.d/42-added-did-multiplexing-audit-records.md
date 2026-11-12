### Added — DID multiplexing audit records

The `messaging/mux/*` specs require an audit record for each of these, and
the mediator wrote none. Each is now in the audit log (`audit/list`), with
the new actions from affinidi-messaging-mediator-types 0.1.1:

- `mux_grant_revoke`: one entry per grant `messaging/mux/revoke` removed.
  The actor is the party that revoked; the target is the other party.
- `mux_revoke_all`: a `messaging/mux/revoke-all` that advanced the member's
  epoch, with the new epoch and how many grants it voided. The target is the
  member DID.
- `mux_grant_suspend`: one entry per grant the unknown-key rule suspended,
  whether fired by a statement or by a direct login. The actor is the member
  DID whose key fired it; the target is the principal that lost the grant.
  On a direct login it is written before the login answers.

Recording is best-effort, like every audit entry: a failure is logged and
never undoes the change. Every failed audit write, mux or not, now also
counts in the new `audit_write_failures_total` metric.
