### Changed — a DIDComm message refused on a Binary WebSocket frame is answered with a problem report; an oversized frame closes with 1009

- A DIDComm message sent as a Binary frame and refused by the mediator is
  now answered with the same problem report a Text frame gets. Before, the
  refusal was only logged, and a client using Binary framing took the
  message as sent (R1.1).
- A frame over `limits.ws_size` now closes the socket with 1009 "message too
  big". Before, the read error was dropped silently and the socket ended as
  if the client had left (1001 "client disconnected"). Other read errors are
  logged and close with 1001 "connection error".

**Behaviour change (R3.6):** a client that frames DIDComm as Binary may now
receive problem-report Text frames it did not get before, and should handle
them as it does on Text framing. A client that sends an oversized frame sees
1009 instead of 1001, and should not resend the same message unchanged.

### Changed — `join` waits for live WebSockets to close and background tasks to stop

`MediatorHandle::join` (and so a mediator process exiting after SIGTERM) now
waits, for up to 10 seconds after the HTTP server has stopped, for every
WebSocket to finish closing (1001 "mediator shutting down", deregistration,
close statistic) and every supervised background task to stop. Before, it
returned as soon as the HTTP server stopped, which does not track upgraded
sockets, so a process could exit before its sockets' close frames were
written. Shutdown can take up to 10 seconds longer when a socket or task is
slow to finish; the mediator logs what it gave up waiting for.

### Fixed — `limits.max_websocket_connections = 0` means unlimited

A value of `0` is documented as "unlimited", but refused every WebSocket with
1013 "server connection limit reached". It now admits every socket, as the
per-DID cap already did for its `0`. A deployment that set `0` and relied on
it to turn WebSockets off now accepts them.

### Fixed — inbox redelivery is paced to the socket, and raw-TSP sockets get one wake-up

- The redelivery that runs when live delivery turns on, or a socket replaces
  another, now waits for room in the socket's queue (up to 10 seconds per
  frame) instead of stopping at the first full queue. Before, it queued about
  8 messages and then stopped with a resync, so paging and the 1000-message
  cap never took effect. Each message is still recorded as delivered only
  once its frame is written (R1.1).
- A raw-TSP socket, which drains its whole inbox itself on any notification,
  is redelivered to with one wake-up instead of a push per stored message
  (each of which only triggered another drain).
- A repeated live-delivery `Start` for a socket that is already live no
  longer drains the inbox again.

### Fixed — a socket that replaces another gets the redelivery already running for it

The guard that keeps one redelivery per DID skipped the replacing socket's
redelivery while the replaced socket's was still running, so the new socket
got neither the stranded messages nor a resync. A running redelivery now
hands itself over to the newest socket for the DID and starts the inbox again
for it.

### Fixed — a lagged streaming subscription raises every live client's resync

When the streaming task's notification subscription fell behind, the skipped
live notifications were logged and dropped, and no client was told that mail
was waiting (R6.2). Every live client (and each live member of a mux
connection) now has its resync raised, rate-limited by the usual 5-second
floor. New counter `ws_streaming_lagged_total`.

### Fixed — mux member registration is idempotent, and a grant that gains `receive` starts live delivery

- Renewing an attach for a member the connection already carries no longer
  registers it again. Before, the streaming task treated it as a newer
  connection: the client got a spurious `detached: superseded` for a member it
  still carried, `deliveryActive` could read `false` for a live member, an
  extra redelivery ran, and a standby entry was left behind that later
  stopped the real entry from being removed.
- A member carried by a grant without `receive` or `pickup` that is replaced
  by one with either now starts live delivery at once, rather than at the next
  reconnect. A member narrowed to neither has live delivery turned off.

### Fixed — a restart of the streaming task keeps its registered sockets

The registered sockets were held by the streaming task's run, so a
supervised restart forgot every one. A direct socket noticed and reconnected,
but a mux connection stayed up and silently received nothing for its
principal or any member. The registrations now outlive a restart: the
restarted task claims each back and redelivers what arrived while it was
down.

### Fixed — mux member-change events are never dropped

`superseded`, `inactive` and `reactivated` member changes were queued to the
connection without waiting and silently lost when its queue was full (a burst
of members changing at once), leaving `deliveryActive` and the inactive count
wrong. They are now recorded on the connection and the socket woken, so none
is lost and they are reported in order.
