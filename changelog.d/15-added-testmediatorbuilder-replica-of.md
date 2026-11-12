### Added — `TestMediatorBuilder::replica_of`

- A test mediator can run as a second instance of another: the same DID,
  keys and session-token key, on its own port with its own streaming task.
  Paired with a shared Redis store, that gives two instances of one
  mediator, as behind a load balancer. `tests/mux_two_instances.rs` uses
  it: a member grants, sends and revokes through one instance while the
  principal's mux socket is on the other. It found both bugs above, and
  runs in CI against standalone Redis and a Redis cluster.
