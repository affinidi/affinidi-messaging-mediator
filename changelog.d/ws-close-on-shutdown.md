### Changed — live WebSockets close with 1001 "mediator shutting down" on shutdown

When the mediator shuts down, each live WebSocket now closes at once with
1001 (going away) and the reason "mediator shutting down". The HTTP server's
graceful shutdown does not track upgraded sockets, so before this a socket
closed only once the streaming task had stopped, with 1011 "streaming task
unavailable", which reads as a server fault. Clients reconnect as before; the
code and reason now say it was a shutdown.
