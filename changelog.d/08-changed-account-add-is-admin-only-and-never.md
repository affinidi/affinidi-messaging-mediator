### Changed — `account/add` is admin-only and never replaces an existing account

- `messaging/account/add` for a DID that already has an account is refused
  with `messaging/account/add:alreadyExists` (409), and the account is left
  as it was. It used to be written afresh: role back to `standard`, ACLs
  back to `global_acl_default`, queue limits, counters, activity and stats
  cleared. Use `messaging/account/update` to change an existing account.
- `messaging/account/add` now requires an `Admin` or `RootAdmin` account in
  both `mediator_acl_mode`s. In `explicit_deny` any authenticated account
  could call it; its own account always exists by then (authentication
  creates it), so the only accounts it could add were other DIDs'.
- `MediatorStore` gains `account_create`, which creates an account only if
  none exists and returns `None` otherwise, with the check and the write in
  one atomic step (a Lua script on Redis; under the store lock on memory and
  Fjall). `account_add` is now a provided method built on it: it creates
  the account or returns the existing one unchanged, so two first-contact
  requests racing can no longer reset an account's counters. Login
  registration (`/authenticate`, `/tsp/authenticate`) creates the account
  through it in one step, so an account an admin adds or changes while a
  login is in flight is used as it is. A third-party
  `MediatorStore` implements `account_create` in place of `account_add`.
- Storing a message for a party with no account keeps queue counters for
  it, and every backend now agrees that those counters alone are not an
  account: it is not found by `account_exists` / `account_get`, not listed,
  not given ACLs (and so not admitted in `explicit_allow`), and
  `account_create` completes the record, keeping its counters. Memory and
  Fjall used to treat such a record as a deny-all account; Redis's
  `account_exists` counted it too. Fjall marks records with a new
  `is_account` field; records written before it read as accounts.
- Admin set-up at start completes such a record before setting the role,
  so the mediator and root-admin accounts never end up without ACLs.
- `account/add` checks the caller's role in the store, not the role cached
  in its session.

**Behaviour change (R3.6):** a non-admin client calling
`messaging/account/add`, or any caller re-adding an existing account to
reset it, now gets an error.
