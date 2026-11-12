### Fixed — a killed instance's DIDs are taken over by the instances still running (Redis)

When an instance died without cleaning up (killed, crashed, or cut off from
the store), its streaming entries stayed in Redis. A mux member whose own
socket had been on that instance stayed inactive on every other instance's
mux connections until the member reconnected somewhere: its messages were
stored, but not pushed. (Pickup still worked.)

- Each instance now renews a heartbeat in the store every 10 s
  (`STREAMING_ALIVE:<uuid>`, lasting 45 s) and lists itself in
  `STREAMING_INSTANCES`.
- The minute recheck also asks whether the owners of the DIDs the instance
  carries are alive. A DID whose owner is listed but has let its heartbeat
  expire is taken over: the dead instance's entry is removed in one script
  that checks both again, and the entry here claims the DID, or a mux entry
  standing by for it takes it, with an inbox redelivery. A DID is taken over
  within about 105 s of its instance dying.
- An instance on an older release never heartbeats, so it is never taken
  for dead: rolling upgrades are unaffected.
- A direct socket that finds its DID held by a mux entry on another instance
  takes it back, since a direct socket outranks a mux entry. That repairs an
  instance taken for dead while it was still serving (its store writes
  failing for longer than the heartbeat lifetime): when its heartbeat comes
  back it logs a warning and rechecks at once.
- Dead instances leave the list a day after their last beat.

Metrics: `streaming_entries_reclaimed_total` gains a `reason` label
(`missing`, `dead_owner`, `outranks_mux`); new
`streaming_entries_evicted_total` and `streaming_heartbeat_lapses_total`.
`MediatorStore` gains `streaming_heartbeat`, `streaming_dead_instances`,
`streaming_evict` and `streaming_mux_owned`, with defaults for
single-instance stores. `MediatorBuilder::streaming_liveness` (and
`TestMediatorBuilder::streaming_liveness`) sets the heartbeat and recheck
timing; the defaults are for production.

**Behaviour change (R3.6):** on a multi-instance mediator, principals see
a member whose own socket was on a killed instance come back `reactivated`
on their mux connection without the member reconnecting, and its unacknowledged
messages redelivered.
