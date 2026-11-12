### Fixed — the access-list limit holds on Redis

- `access_list_add` on Redis now counts, truncates and adds in one script.
  When a request does not fit, the first `limit - current` hashes are added
  and `truncated` is set, as on Fjall and memory. A list already at its limit
  takes nothing; before, a request made when the list was exactly full was
  added in full, and one made over a lowered limit could fail or add
  everything. An empty request is a no-op instead of a Redis error. A
  request longer than the limit sends only its first `limit` hashes to
  Redis, and is reported truncated.
