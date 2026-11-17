### Fixed — jemalloc tuning is applied

- The mediator exported its jemalloc settings (`background_thread:true`,
  5s dirty/muzzy decay) as `malloc_conf`, but `tikv-jemalloc-sys` builds
  jemalloc with the `_rjem_` symbol prefix, so the setting was never read and
  jemalloc ran on its defaults with no background purge thread. The symbol is
  now `_rjem_malloc_conf`: freed pages are returned to the OS while the
  mediator is idle, and after 5s rather than 10s.
