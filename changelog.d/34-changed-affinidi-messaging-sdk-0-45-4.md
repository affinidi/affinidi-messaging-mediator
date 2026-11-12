### Changed — affinidi-messaging-sdk 0.45.4

- The SDK now has a `tsp-mux` client (`TspOps::connect_websocket_mux`), and
  parses `connectionFull` events. `tests/tsp_mux.rs` drives a raw-TSP mux
  connection through it end to end, beside the tests that drive the wire
  by hand.
