### Fixed — resync status honours the `pickup` scope

- On a DIDComm mux connection, a member whose live pushes dropped was sent
  a pickup `status` for its inbox even when its scope lacked `pickup`,
  telling the principal that inbox's counts. A status is message pickup, so
  it is now sent only for a member holding `pickup`. A `receive`-only
  member's dropped frames stay in its inbox, as before. The `tsp-mux` drain
  already skipped such members.
