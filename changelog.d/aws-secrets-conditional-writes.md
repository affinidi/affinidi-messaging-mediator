### Fixed — AWS secrets: a write no longer drops keys from `mediator_secrets_bundle`

- On AWS Secrets Manager a read can return a version older than the
  process's own last write, and the bundle's read-modify-write then dropped
  every key written since: a fresh mediator could fail to start with "JWT
  signing secret is missing from the backend" after `mediator-setup`
  reported the key written.
- A write of a secret the process has read or written is now conditional,
  as on Vault: it is staged under the mediator's own `MEDIATOR_STAGED` label
  and made `AWSCURRENT` only if the secret is still at the version last seen,
  and the label is then removed. Otherwise the bundle redoes the write from a
  fresh read, as do the read-write probe and the cutover on the first start
  after a migration. A direct write of a per-key secret fails with a conflict
  error instead of overwriting, and keeps failing until the secret is read
  again. `AWSPENDING` is left to Secrets Manager rotation; rotation is still
  not supported on these secrets.
- A read-back right after a write (the migration's checks, the cutover, the
  read-write probe) is read again a few times before the write is called
  lost, so a lagging read no longer rolls back a migration that succeeded.
- A cutover that cannot be confirmed is undone only when that drops nothing:
  an entry another process wrote to the bundle since is kept.
- A migration whose own bundle write is refused as a conflict stops with that
  reason and deletes nothing, rather than asking for IAM access the role
  already has.

### Breaking — AWS secrets: writers need `secretsmanager:UpdateSecretVersionStage`

- Grant `secretsmanager:UpdateSecretVersionStage`, next to `PutSecretValue`,
  to every role that writes (`mediator-setup`, the mediator, and whoever runs
  `mediator rotate-admin`) on `<prefix>mediator_secrets_bundle` and, on a
  deployment not yet cut over to the bundle, on the per-key secret names too:
  until the cutover every write goes to the per-key secret first, and that
  write is conditional as well. Without it the first write of a new secret
  still succeeds, and the next one fails with `AccessDeniedException`, so
  `mediator-setup` or `rotate-admin` stops before it finishes.
