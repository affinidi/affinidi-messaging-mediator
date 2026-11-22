### Security — secrets backend errors and the in-memory store hold no stray credentials

- An invalid secrets backend URL is reported with any `user:password@` in it
  replaced by `***@`, so a credential mistakenly written into
  `[secrets].backend` (or `MEDIATOR_SECRETS_BACKEND`) never reaches the logs or
  the startup error.
- The in-memory secret store (tests and the setup wizard's temporary
  sessions; the mediator never uses it) wipes each value from memory when it
  is deleted, overwritten or dropped.
