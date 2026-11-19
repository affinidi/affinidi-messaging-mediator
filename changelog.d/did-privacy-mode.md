### Added — `security.did_privacy_mode`: optionally keep the DID behind each hash (proof of concept)

- New setting `security.did_privacy_mode` (env `DID_PRIVACY_MODE`):
  `strict` (the default) or `permissive`. `strict` is today's behaviour: the
  mediator keeps only the SHA-256 hash of each DID.
- `permissive` also keeps a `hash → DID` record: the DID of every account that
  authenticates, and DIDs a caller names in a Trust Task's
  `ext["com.affinidi.messaging"].dids` for the hashes that task touched.
  Trust Task responses then carry `ext["com.affinidi.messaging"].dids`, a
  `hash → DID` map for the hashes they name. Every existing field still holds
  the hash, so clients that ignore `ext` see no change. The record is removed
  with its account.
