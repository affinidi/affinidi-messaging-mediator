### Added — DID labels: the DID behind each hash, on request (proof of concept)

- The mediator now keeps the DID beside each account and access-list hash, as
  a write-once label used only for display. It fills the label when that DID
  authenticates, or when an account or access-list Trust Task names it by its
  DID. A label is never changed, and is removed with its account.
- Account and access-list Trust Tasks accept a DID wherever they took a hash
  (`did`, `add`, `remove`, `entries`, `dids`). The mediator hashes it and runs
  the task on the hash, so every response still names hashes.
- A request with `ext["com.affinidi.messaging"].includeDids: true` gets
  `ext["com.affinidi.messaging"].dids`, a `hash → DID` map for the hashes its
  response names that have a label. Without the flag the response is exactly
  as before.
