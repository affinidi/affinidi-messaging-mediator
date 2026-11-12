### Changed — mux frame decisions are counted; delivery reports hold no body

- A live frame the socket withholds from a mux member, decided against the
  member's scope when it comes up, now counts in
  `mux_live_frames_withheld_total{outcome="nudge"|"drop"}`: `nudge` for a
  `pickup`-only member, whose principal is told mail waits, and `drop` for
  a member that left or holds neither scope. These were visible only in
  debug logs.
- A websocket delivery report, which rides with its queued frame until the
  write, now carries the frame's protocol instead of a copy of its body.
  The monitor only ever used the body to name the protocol and never
  published it, so events are unchanged. Queued frames no longer double
  their memory while a monitor is subscribed. `StreamingTask` no longer
  takes a monitor, and `spawn_supervised_with_monitor` is gone.
