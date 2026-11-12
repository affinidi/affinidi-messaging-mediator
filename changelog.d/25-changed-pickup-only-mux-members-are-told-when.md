### Changed — `pickup`-only mux members are told when mail waits

- A member holding `pickup` but not `receive` is never pushed its messages,
  and until now the principal learned of new ones only by polling (DIDComm)
  or at the next connect (raw TSP, where the drain is the only way to
  collect). New mail for such a member now raises its resync: a pickup
  `status` naming it on DIDComm, a drain of its inbox on `tsp-mux`. Resyncs
  keep their 5 s floor, so this is a batched nudge, not a push.
