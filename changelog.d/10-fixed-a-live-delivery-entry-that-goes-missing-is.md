### Fixed — a live-delivery entry that goes missing is claimed back (Redis)

Each instance holds a store entry for every DID it streams. When an entry
went missing while its socket stayed open, messages for the DID were stored
but never pushed, until the client reconnected. An entry goes missing when
an instance that doesn't check owners removes it: during a rolling upgrade
an instance on 0.51 or earlier removes entries whichever instance owns them,
and its `FUNCTION LOAD` at startup brings back a clean start that does the
same. It also goes missing when the store loses data (a failover, a flush).

Every minute each instance now reads the owners of all the DIDs it streams,
direct sockets included (one `HMGET` per 500 DIDs). An entry that has gone
is claimed back, and the inbox is redelivered to a socket that wants live
delivery, so nothing that arrived meanwhile stays unseen. An entry another
instance holds is left alone, as before.
`streaming_entries_reclaimed_total{kind=direct|mux,reason=missing}` counts
the claims; it stays at 0 outside an upgrade or a data loss. `MediatorStore`
gains `streaming_owners`, with a default for single-instance stores.

**Rolling upgrade from 0.51:** a DID whose entry an old instance removes
gets live delivery back within a minute, with a redelivery. Until every
instance is upgraded, a client may see a message pushed twice after such a
claim. Upgrading all instances promptly keeps the window short.
