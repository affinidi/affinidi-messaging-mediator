### Added — DID multiplexing metrics on `/metrics`

- `mux_connections{wire}` (gauge, `wire` = `didcomm` | `tsp`): live mux
  connections on this instance. It moves only as connections enter and leave
  the mux registry, so it matches `messaging/stats/show`.
- `mux_members{source}` (gauge, `source` = `grant` | `attach`): member DIDs
  carried by those connections. It moves with each connection's member set,
  so every way a member joins or leaves (attach, grant, detach, revoke,
  expiry, a change from another instance, the connection closing) keeps it
  exact. A member admitted both ways counts once, as `grant`.
- `mux_detach_total{reason}` (counter): members detached, or stored grants
  not carried, by the spec's `DetachReason` (`revokedByMember`, `expired`,
  `superseded`, `connectionFull`, …). A connection closing is not counted as
  a detach.
- `mux_grant_revalidate_failures_total{cause}` (counter, `cause` =
  `resolution` | `store`): signing-key re-validations that could not reach a
  decision (the member's DID did not resolve, or a stale key could not be
  recorded).
- `mux_queue_fairness_skips_total` already existed and is unchanged.
- No label carries a DID.
- No `attached`/`detached` stage was added to the traffic monitor. The pinned
  `messaging/monitor/event/0.2` schema closes its stage set, so that needs a
  spec revision first.
