### Fixed — a slow client no longer holds up live delivery for others

- Replacing a socket whose send queue was full waited for that socket to
  drain before the streaming task could serve anyone else. The `Close` is
  now queued without waiting; when the queue is full it follows the queued
  frames from a task of its own.
- Every WebSocket write is bounded at 30 s. A peer that stops reading is
  closed with 1001 "connection unresponsive" instead of holding its
  connection, and nothing queued for it is reported delivered. Timeouts
  count in the new `ws_write_timeouts_total`.

**Behaviour change (R3.6):** a client that stops reading its socket long
enough for a mediator write to wait 30 s is disconnected.
