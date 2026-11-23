### Security — `url` 2.5.9 (RUSTSEC-2026-0592)

- The workspace requires `url` 2.5.9, which fixes a stack overflow in
  `Url::origin()` on nested `blob:` URLs (RUSTSEC-2026-0592). The lockfiles
  move from 2.5.8.
