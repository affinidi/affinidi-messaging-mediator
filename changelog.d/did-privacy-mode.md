### Added — `security.did_privacy_mode`: optionally keep the DID behind each hash (proof of concept)

- New setting `security.did_privacy_mode` (env `DID_PRIVACY_MODE`):
  `strict` (the default) or `permissive`. `strict` is today's behaviour: the
  mediator keeps only the SHA-256 hash of each DID.
- In `permissive` mode, account and access-list Trust Tasks may name each
  account or entry by its hash (as today), its DID (the mediator hashes it), or
  both: the hash in the field and `ext["com.affinidi.messaging"].dids`
  mapping it to its DID. The mediator checks each pair and refuses the request
  with `malformedRequest` on a mismatch.
- `permissive` keeps a `hash → DID` record: the DID of every account that
  authenticates, and the DIDs a caller names for the hashes that task touched.
  Trust Task responses then carry `ext["com.affinidi.messaging"].dids`, a
  `hash → DID` map for the hashes they name. Every existing field still holds
  the hash, so clients that ignore `ext` see no change. The record is removed
  with its account.
