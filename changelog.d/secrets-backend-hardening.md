### Breaking — `file://` and `vault://` secret-backend URLs are checked strictly

- `file://…?encrypt=` accepts only `1`, `true`, `yes`, `on` or `0`, `false`,
  `no`, `off` (any case). Any other value (`enabled`, `2`, empty) used to
  mean *plaintext*; it now fails at startup. `?encrypt=TRUE` and `=True`,
  which used to write plaintext, now open the encrypted backend.
- A `file://` URL with a host is refused with "use three slashes for an
  absolute path". `file://conf/secrets.json` used to read and write
  `/secrets.json`.
- `vault://…?insecure=1` is refused at startup by a release build unless
  `MEDIATOR_ALLOW_INSECURE_VAULT=1` is set. Debug and test builds still take
  it. Every open and login with it logs a warning. Trust a private CA with
  the new `?ca_cert=<path>` (a PEM bundle) instead. `insecure=` also takes
  only the values above.
- The never-working `vault://http://…` form is gone: the endpoint is always
  HTTPS.
- The "secrets are plaintext on disk" warning is logged only for an
  unencrypted `file://` store.

### Breaking — the encrypted `file://` store writes format version 2

- Version 2 adds a file MAC (HMAC-SHA256 under a key derived from the
  passphrase key) over the KDF header, the verifier and every entry, and
  names the version in each AEAD's associated data. Deleting an entry,
  rolling one back to an older copy, or editing the header now fails the
  open instead of going unnoticed. Replacing the whole file with an older
  copy is still not detectable.
- Version 1 files are read as before and rewritten as version 2 by the next
  write. **A mediator or `mediator-setup` older than this release cannot read
  a version 2 file**, so keep a copy of the file before upgrading if you may
  roll back.
- On-disk Argon2id parameters outside memory 8 MiB–1 GiB, 1–16 iterations
  and 1–16 lanes are refused before the KDF runs.
- Only a missing file starts a new store. An existing empty file (what an
  interrupted write by an older release left) is now an error rather than a
  silent fresh store with a new salt.

### Fixed — `file://` secret stores are never truncated or replaced on a failed read

- Both `file://` backends write a temp file (`0600`), `fsync` it, rename it
  over the store and `fsync` the directory. A crash, `SIGKILL` or `ENOSPC`
  mid-write leaves the previous store, never a truncated one.
- A plaintext store file that exists but can't be read or parsed now fails a
  `put` or `delete`. It used to be replaced by a store holding only the entry
  being written, losing the admin credential, JWT key and operating keys.
- A write that fails leaves the in-memory copy as it was.

### Fixed — secret backends no longer block async workers or rebuild clients

- The encrypted store's Argon2id KDF, all `file://` I/O, the OS keyring calls
  and the Vault Kubernetes-auth JWT read run on tokio's blocking pool. The
  mediator opens its backend with the new `open_store_async` /
  `MediatorSecrets::from_url_async`.
- The AWS Secrets Manager and Kubernetes backends build their client once and
  reuse it, instead of re-running the credential chain (an STS or IMDS round
  trip on IRSA / ECS roles) and opening a new connection pool on every call.

### Fixed — Vault re-logs in only when the token is actually refused

- A `403` re-authenticates (Kubernetes / AppRole) only when
  `auth/token/lookup-self` also refuses the token; a policy denial is
  returned as is. Each write with a policy lacking `update` on the destroy
  path used to cost a re-login (a new token and lease, and an AppRole
  `secret_id` use) and two refused destroys.
- After the first refused destroy of superseded versions, later writes skip
  the destroy until the mediator restarts.

### Security — secret material is redacted from `Debug` and wiped on drop

- `AdminCredential`, `VtaCachedBundle` and the internal bundle and seed types
  print `<redacted>` (or entry names only) in `Debug`.
- `AdminCredential`'s private key, bundle entries, bootstrap seeds, operating
  keys and the JWT key are zeroised when dropped; the passphrase read from
  the environment or a file is no longer left in an unwiped `String`.
- A cached bundle read is shared rather than copied on every `get`.
- The passphrase env var is left set: removing it is unsound while other
  threads may read the environment. Use
  `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE` to keep it out of the environment.
- **API (affinidi-messaging-mediator-common):** `AdminCredential` implements
  `Drop`, so its fields can't be moved out (struct-update syntax
  `..credential` included); clone them instead. `BackendUrl::Vault` has a new
  `ca_cert` field. New: `open_store_async`, `MediatorSecrets::from_url_async`,
  `BackendUrl::is_plaintext_file`.
