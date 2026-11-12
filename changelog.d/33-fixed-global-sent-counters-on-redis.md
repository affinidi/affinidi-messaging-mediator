### Fixed — global sent counters on Redis

- On the Redis backend, fetching a message by id never counted it in the
  global `SENT_COUNT`/`SENT_BYTES` stats: the `HINCRBY` for `SENT_COUNT`
  had no key, so Redis refused the whole `MULTI`. Both counters now move,
  and the store conformance suite checks it.
