### Fixed — a challenge session is promoted once

- On Fjall, memory and the trait default, `update_session_authenticated`
  now fails unless the challenge session exists, has not expired and is
  still waiting for its answer (`ChallengeSent`); it used to promote a fresh
  session in place of a missing one. Of two answers to one challenge, only
  the first is accepted, as on Redis. The memory store promotes under its
  state lock.
- Redis `update_refresh_token_hash` fails for a session that has ended
  instead of recreating it as a hash with no expiry.
