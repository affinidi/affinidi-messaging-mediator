### Fixed — DID multiplexing

- The `muxNonce` in a mux connection's `ready` event is now 32 random bytes
  as unpadded base64url (43 characters), as `messaging/mux/event/0.1`
  requires. It was 32 alphanumeric characters, which a client parsing the
  event with the generated bindings refused. The end-to-end test now checks
  every mux event against the spec's generated type.
- `DELETE /delete` on a mux connection's session now deletes a member's
  messages when the member's grant or attach includes `delete`, as
  `messages-received` already did. The SDK acknowledges live-stream messages
  this way (`auto_delete`), so before this a principal could receive a
  member's message but never acknowledge it, and it was redelivered.
- A grant stored while its principal is connected is carried on that
  connection at once, with an `attached` event, as the design requires.
  Before, the mediator admitted grants only when the connection opened, so a
  device that granted a new DID had to reconnect before that DID's messages
  arrived. A grant that replaces an earlier one takes over its member, so
  revoking the new grant detaches it.
  The mediator re-reads the member's record before and after it carries a
  grant, without holding the connection's lock across the read, and never
  lets an older grant displace a newer one. So a grant replaced or revoked
  in the meantime, or two grants finishing out of order, cannot leave the
  connection on the wrong scope. A grant the connection has no room for is
  logged at `warn` and carried on the next connection.
