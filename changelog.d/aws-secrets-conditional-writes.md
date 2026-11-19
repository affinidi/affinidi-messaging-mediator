### Fixed — AWS secrets: a write no longer drops keys from `mediator_secrets_bundle`

- On AWS Secrets Manager a read can return a version older than the
  process's own last write, and the bundle's read-modify-write then dropped
  every key written since: a fresh mediator could fail to start with "JWT
  signing secret is missing from the backend" after `mediator-setup`
  reported the key written.
- A write of a secret the process has read or written is now conditional,
  as on Vault: it is stored as `AWSPENDING` and made `AWSCURRENT` only if the
  secret is still at the version last seen. Otherwise the bundle redoes the
  write from a fresh read; a direct write of a per-key secret, or the probe,
  fails with a conflict error instead of overwriting.

### Breaking — AWS secrets: writers need `secretsmanager:UpdateSecretVersionStage`

- Grant `secretsmanager:UpdateSecretVersionStage` on
  `<prefix>mediator_secrets_bundle` to every role that writes it
  (`mediator-setup` and the mediator), next to `PutSecretValue`. Without it
  the first write of a new secret still succeeds, and the next one fails
  with `AccessDeniedException`, so `mediator-setup` stops before it finishes.
