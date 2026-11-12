### Fixed — narrowing away `receive` stops live pushes

- A live frame for a mux member was written if the DID was still a member,
  whatever its scope. Narrowing a grant to drop `receive` (`mux/update`)
  left its pushes flowing until the next reconnect. Each frame is now
  checked against the member's scope when it is written.
