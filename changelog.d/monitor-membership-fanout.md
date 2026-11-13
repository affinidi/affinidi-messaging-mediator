### Changed — membership monitor events cross instances behind a shared Redis

- An opted-in `messaging/monitor/subscribe` 0.2 subscriber now sees the mux
  membership changes of every instance sharing the mediator's Redis, not
  only those of the instance it is connected to. A remote event passes the
  same membership filter, non-administrator narrowing and standing check as
  a local one, and is delivered once: an instance ignores its own events on
  the channel. Traffic events stay per instance.
- Events carry no instance tag: `messaging/monitor/event` 0.3's
  `MonitorMembershipEvent` does not allow one. Telling instances apart needs
  a spec revision.
- Redis traffic only while it is used: an instance with a membership
  subscriber announces it on the mediator's own pub/sub channel
  (`MONITOR_FANOUT:<mediator DID hash>`) when one opens and every 10 s; the
  others publish their membership events for 35 s after each announcement.
  With no membership subscriber anywhere, the channel carries one query per
  instance start.
- Never on the connection path: a membership event is handed to a background
  task through a bounded queue without waiting; a full queue drops the event
  for the other instances only. With Redis down each instance's subscribers
  see that instance's events, a failed publish is logged once per outage, and
  a lost subscription restarts the `monitor_fanout` task under the supervisor
  (readiness shows it degraded meanwhile).
- Subscribers can see what was lost. Events an instance could not hand over
  or publish are reported to the others once publishing works again, and a
  receiver that fell behind on the channel counts what it missed; either
  count is added to `membershipDropped` of every opted-in subscription on the
  receiving instance (an upper bound: the lost events' filters are unknown).
  While the fan-out task is down, each opted-in event 0.3 batch carries
  `ext["com.affinidi.mediator"].membershipCoverage = "thisInstance"`: the
  subscriber is seeing only its own instance's changes.

### Added — monitor fan-out metrics

- `monitor_fanout_dropped_total` (label `cause`: `overflow`, `publish`,
  `lagged`) counts membership events one instance's subscribers missed from
  another; `monitor_fanout_received_total` counts those received.
- `MediatorStore::monitor_fanout_publish` / `monitor_fanout_subscribe`
  (affinidi-messaging-mediator-common), with no-op defaults for
  single-process stores.
