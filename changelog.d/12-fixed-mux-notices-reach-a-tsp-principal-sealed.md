### Fixed — mux notices reach a TSP principal, sealed for TSP

Durable `messaging/mux/notice` documents (grants suspended, revoked or
expiring; delegations present) were always packed as DIDComm. A raw-TSP
socket carries TSP frames only, so a principal on `tsp-mux` never received
them, while its `ready.pendingNotices` counted them.

- A notice is sealed for the wire its recipient last used: a TSP Direct
  message from the mediator's VID (stored as TSP messages are), or DIDComm as
  before. That is the wire of its last mux connection, or, for
  `grantsPresent`, of the direct login that prompted it. DIDComm when
  unknown.
- When a principal opens a mux connection on the other wire, its pending
  notices are re-issued in that wire's form and the old copies deleted,
  before `pendingNotices` is counted. The inbox holds one copy of each.
- The mux record gains `wire` and `noticeForms` (the payloads of the last 32
  notices, at most 64 KB, kept so they can be sealed again). Both are
  optional: an instance on the previous release reads the record as before,
  and counts the same notice ids. A notice older than the kept payloads
  stays in the form it was stored in.
