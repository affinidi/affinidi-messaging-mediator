### Added — a test mediator can stand in for one that predates a task version

- `MediatorBuilder::withhold_task_types` and
  `TestMediatorBuilder::withhold_task_types` refuse the named Trust Task
  request types as unsupported (`protocol.trust_task.unsupported`), as a
  mediator that predates them does, so a client's fallback to an older
  version can be tested against a real mediator. Nothing is withheld by
  default and the config file cannot set it.
- The console's live monitor is now tested both ways against a live
  mediator: at `monitor/subscribe` 0.2 with traffic and mux membership, and
  falling back to 0.1, traffic only, when 0.2 is withheld — where asking for
  membership is refused rather than quietly dropped.
