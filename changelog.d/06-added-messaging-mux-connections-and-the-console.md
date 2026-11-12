### Added — `messaging/mux/connections` and the console's Mux tab

- The mediator serves `messaging/mux/connections` 0.1
  (dtgwg-trust-tasks-tf#1083) to administrators. It lists this instance's
  live mux connections: each one's principal, wire (`didcomm`/`tsp`),
  opening time and exact member count. Within the page's member budget it
  also lists each connection's members, with source (grant or attach),
  scope, expiry and whether their live delivery is active there.
  - Filters: `principal`, `member`. Paging: `limit` (up to 100 connections)
    and `memberLimit` (up to 1000 member entries; a large connection is
    split across pages).
  - `coverage` is `allInstances` on an in-process store, and `thisInstance`
    on Redis, where other instances' connections are not visible.
  - A cursor is bound to the requester, the filters and the instance that
    issued it, and expires after 10 minutes. Anything else is refused with
    `messaging/mux/connections:cursorInvalid`.
  - Not served when mux is disabled.
- The operator console has a **Mux** tab. It lists the live connections,
  then the members of the selected one, with their delivery state, and its
  title says when the view covers this instance only.
- Needs affinidi-messaging-sdk 0.45.6 (`TrustTasksOps::mux_connections`).
