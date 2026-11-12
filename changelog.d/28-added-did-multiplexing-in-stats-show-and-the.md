### Added — DID multiplexing in `stats/show` and the console

- `messaging/stats/show` reports this instance's mux connections and
  members under the extension member `ext["com.affinidi.mux"]`:
  `connections`, `members`, `membersByGrant`, `membersByAttach`,
  `membersInactive`, with `scope: "instance"`, since another instance's
  connections are not counted. It is present only when mux is enabled. The
  spec's `connections` object is closed, so the counts go under `ext`.
- The console's dashboard shows them on one line, and its Audit tab
  highlights mux decisions (`mux_grant_suspend`, `mux_grant_revoke`,
  `mux_revoke_all`), each of which cut a device off from a DID.
