### Fixed — WebSocket connections release their resources on every exit

- A socket's global and per-DID connection counts,
  `active_websocket_connections` gauge, streaming registration and
  `WEBSOCKET_CLOSE` stat are now held by one guard and released together on
  every return path, before the final close frame is written. Previously a
  few early exits skipped part of the cleanup, so the count and gauge could
  drift from the sockets actually open.
- A socket's streaming deregistration now names the connection it belongs
  to, not only its session. Two sockets opened with the same access token
  share a session id, so a replaced socket winding down could remove the
  live entry of the socket that replaced it, which then closed with
  "streaming task unavailable".
- An expired token is now refused before anything is reserved or
  registered. A token accepted inside the JWT leeway after its `exp` still
  closes at once with 1008 "authentication token expired", as before.
- `WEBSOCKET_OPEN` is now counted when the connection is admitted (past
  the global and per-DID limits), before it registers for live delivery,
  rather than after registration. It and `WEBSOCKET_CLOSE` always come in
  pairs.
