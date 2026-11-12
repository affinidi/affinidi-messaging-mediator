### Fixed — live delivery across mediator instances (Redis)

Two instances of one mediator share Redis, and each DID's live-streaming
owner is one entry there. Two bugs:

- **An instance leaving a DID stopped another's live delivery.** Clean-up
  deleted the DID's entry whichever instance owned it: a deregistration, a
  socket found dead, and the clean start an instance runs as it boots. When a
  DID had moved to another instance (its client reconnected there, or it
  became a mux member of a connection there), the old instance's clean-up
  removed the new owner's entry, and messages for the DID were stored but no
  longer pushed until it registered again. Clean-up, and every live-delivery
  change, now touches the entry only while that instance owns it. The memory
  and Fjall stores follow the same rule.
- **A mux connection on one instance took a DID's traffic from the DID's
  own socket on another.** Within one instance a DID's own socket outranks a
  mux connection carrying it (design §7.2); across instances the newest
  registration simply won. A member online on instance A and granted to a
  principal connected to instance B lost its own live traffic, Trust Task
  replies included, to the principal's connection. Now:
  - a mux registration does not take a DID that a direct socket on another
    instance holds. The member stays on the connection, reported inactive
    (`attached`, `deliveryActive: false`);
  - when the direct socket leaves, the instance holding the mux entry is told
    over the mux pub/sub channel and takes the DID back (`reactivated`, with
    an inbox redelivery);
  - a direct socket taking a DID from a mux entry on another instance tells
    that instance, which reports the member `superseded`;
  - every 60 s each instance re-reads the owner of each DID it carries as a
    mux member, so a handoff that was lost (an instance dying between its
    store write and its publish, or a dropped pub/sub message) leaves a
    member in the wrong state for a minute at most.

  Which kind of owner holds a DID is kept in a new hash beside the owner
  entry (`STREAMING_KIND`), with `STREAMING_WAITING` for the mux entries
  waiting on a DID. The owner entry's format is unchanged, so instances on
  the previous release keep routing during a rolling upgrade; they don't
  apply the new rules until upgraded, and what they remove is claimed back
  (below).

**Behaviour change (R3.6):** principals on a multi-instance mediator see
members whose own socket is online elsewhere as inactive, and later
`reactivated`, as they already did on a single instance.
