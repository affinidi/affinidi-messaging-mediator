### Fixed — the wake rate limiter has a hard size ceiling and sweeps at most once a minute

- The per-(requester, addressee) wake counters are capped at 100,000 entries; past that, the entry whose day window started first is dropped. A pair entry is only made by a ring that passed every earlier rule and spent the addressee's hourly budget, so live entries were already bounded by wake-capable accounts; the cap is a hard ceiling on top. Dropping an entry only resets one requester's budget for one addressee; the addressee's coalescing window and hourly budget still apply.
- Once the counters pass 10,000 entries, closed windows are swept at most once a minute instead of on every wake request, so a map full of live entries is not rescanned per request.
