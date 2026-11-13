### Added — the console revokes several marked grants at once, grant by grant

- `affinidi-messaging-mediator-tui`: the **Grants** tab marks grants —
  `space` marks or unmarks the selected one, `a` marks every grant listed,
  `c` clears the marks; the marked rows show `●` and the title their count.
  With grants marked, `d` revokes them after one confirmation naming how
  many. Every grant not revoked is then listed with why — a rootAdmin
  party's grant is refused as protected — and stays marked to try again;
  the rest are revoked regardless. `E` acts on one member and is refused
  while grants are marked. Changing the listing clears the marks.
- `affinidi-messaging-mediator-admin`: `MediatorConsole::mux_revoke_each`
  revokes a list of grants (`GrantKey`: member DID and grant id), one
  `messaging/mux/admin-revoke` request each, since the mediator refuses a
  whole request when any grant in it is protected. `BulkRevokeOutcome` says
  what happened to each grant (`GrantRevokeResult`: revoked, no longer
  stored, refused, not confirmed, not sent), with `summary()` and
  `failures()`. A grant is reported revoked only when the mediator's answer
  lists it; after a request lost in transit, the rest are not sent and are
  reported as such.
