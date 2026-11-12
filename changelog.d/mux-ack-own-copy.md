### Changed — `messaging/mux/ack` removes only a copy held for the connection

- **Behaviour change (R3.6):** with a stored message held per recipient,
  `messaging/mux/ack` is an acknowledgement like message-pickup
  `messages-received`: it removes the copy held for the principal or for a
  member it may delete for (the copy handed over first when several are
  held), never a copy one of them sent to someone else. An id that names
  only such a sent copy is refused as `notFound`. `DELETE /delete` still
  withdraws what the caller sent when it holds no copy of its own.
