### Breaking — a few rarely used duration spellings are refused

Duration settings (`[secrets] cache_ttl` / `MEDIATOR_SECRETS_CACHE_TTL`, and the
setup tool's `MEDIATOR_BOOTSTRAP_SEED_TTL`) are now read with jiff's duration
syntax. Every value in the shipped templates and docs (`30d`, `12h`, `6h`, `0`,
…) reads exactly as before, and so does every humantime form except these,
which are now refused with an error naming the accepted syntax:

- `M` for months (`1M`): it reads as minutes. Write `1mo` or `1 month`.
- A fraction on days, weeks, months or years (`1.5d`, `0.5y`). Write `1d 12h`
  or `36h`. Fractions on hours and smaller (`1.5h`) still work.
- A fraction before the last unit (`1.5h 30m`), units out of order or repeated
  (`30m 1h`, `1s 1s`), and digits split by a space (`1 0d`).
- Values over roughly 19,998 years.

A refused `cache_ttl` stops the mediator at startup, as any unreadable value
does. A refused `MEDIATOR_BOOTSTRAP_SEED_TTL` falls back to the 24h default
with a warning, as before. Years and months keep their fixed lengths
(365.25 and 30.44 days) and days are 24 hours. Newly accepted: `mo`/`mos`,
`HH:MM:SS`, comma-separated units and spelled-out sub-second units.

`security.tsp_auth_accept_unbound_until` reads RFC 3339 as before, including a
space in place of `T` and no offset meaning UTC. It now also takes lowercase
`t`/`z`, times without seconds, and offsets other than UTC, which are applied.
Before, a non-UTC offset was refused, or ignored when it followed fractional
seconds. A non-UTC offset now logs a startup warning naming the
deadline in UTC, so a value whose meaning moved on upgrade is visible. More than nine fractional-second digits are now refused. The boot
notice still shows the deadline as, e.g., `2026-11-19T10:00:00Z`.

### Security — humantime replaced by jiff (RUSTSEC-2026-0542)

humantime is unmaintained (RUSTSEC-2026-0542, #298) and has left the
dependency graph. Duration and timestamp settings are parsed by one helper,
`affinidi_messaging_mediator_config::time`, built on `jiff` 0.2, which the cloud
SDKs already pulled in. `mediator-common` drops its unused optional humantime
dependency from the `server` feature. The `deny.toml` exception for
RUSTSEC-2026-0542 is removed.
