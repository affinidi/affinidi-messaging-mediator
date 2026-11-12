### Changed — one set of role rules for account administration

- Role decisions go through one set of rules (`common::roles`):
  - Only `admin` and `rootAdmin` administer accounts. The mediator's own
    account (`mediator`) does not, in any handler.
  - An account whose stored role did not decode (`Unknown`) is gated like a
    `standard` account everywhere. It used to skip the `selfManageList`
    check on access-list writes.
  - A Trust Task's caller role and ACLs, and the caller role for deleting
    an OOB invitation, are read from the store once per request. An `admin`
    / `rootAdmin` role the store does not also list as an administrator is
    not honoured.
- Only a `rootAdmin` may:
  - create an account with a privileged role (`admin`, `rootAdmin`,
    `mediator`) through `messaging/account/add`;
  - grant a privileged role, or change the role of an account that holds
    one, through `messaging/account/update`;
  - change (any member of `account/update`), remove (`account/remove`) or
    change the access list (`access-list/update`) of an account holding a
    privileged role, other than its own. The queue tasks already applied
    this rule. An account whose stored role did not decode counts as
    privileged here, so only a `rootAdmin` can change or repair it.
- The roles of the mediator's own account and of the configured
  `admin_did` cannot be changed through `account/update`
  (`account.update.protected`, 403), as neither can be removed.
- The operator console (mediator-admin) refuses a non-root administrator's
  privileged role grant before sending it, and the TUI offers the role row
  to a `rootAdmin` only.
- An `admin` still creates standard accounts, changes standard accounts and
  their roles, and changes its own account's ACL and queue limits.

**Behaviour change (R3.6):** an `admin` that is not the root admin can no
longer create or promote administrators, change the mediator's account, or
change, remove or edit the access list of another administrator; those calls are refused with
`authorization.permission` (403). `pnm messaging grant --role admin` needs to
run as the root admin (its `admin_did`), as its own message already advises.
