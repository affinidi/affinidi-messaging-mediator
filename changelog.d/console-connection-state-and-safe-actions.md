### Breaking — console engine: connection state, monitor feed drops, pinned purges (R3.6)

- `MediatorConsole::connection_state()` returns the SDK's live
  `watch::Receiver<ConnState>` (`ConnState` is re-exported): `Disconnected` on
  every drop, `Connected` on every reconnect, `None` when there is no
  websocket (R6.2). The console logs each drop at `warn` (was `debug`) and
  each recovery at `info`.
- `MonitorUpdate` gains `Disconnected` and `Reconnected`, reported by every
  feed the moment the connection drops and recovers, instead of a reader
  inferring it from silence. `MonitorUpdate` is now `#[non_exhaustive]`: a
  `match` on it needs a wildcard arm.
- `MediatorConsole::purge` no longer recounts and refuses with `PlanStale`. It
  sends the purge pinned to the preview's instant (`olderThanSeconds` = any
  requested age plus the time since the preview, rounded up to whole seconds,
  plus `PURGE_TRANSIT_MARGIN_SECS` (30) for the request's transit and
  queueing before the mediator runs it), so it never removes a message that
  arrived after the preview. It can remove **fewer** than
  `PurgePlan::matched`: messages delivered in between, and messages stored in
  the margin before the preview, are left; report `purged`, not `matched`. The old recount let a message that
  arrived after the check be removed, and let a different set with the same
  count through. `ConsoleError::PlanStale` stays, but `purge` no longer
  returns it. A mediator-side "as of" member for `queue/purge` is a separate
  follow-up.

### Added — `MediatorConsole::connect_with_unclaimed` and `connect_exclusive`; `connect_with` deprecated

- The SDK has no receive filtered by message type, so the console's live
  reader takes every message pushed to its DID on its SDK instance, keeping
  only monitor batches. `connect_with` hid that in its name, so it is
  deprecated; it still behaves as before. Choose explicitly instead:
  `connect_exclusive(atm, identity)` for an SDK instance dedicated to the
  console (what `connect_with` did), or
  `connect_with_unclaimed(atm, identity, tx)` for an application sharing its
  SDK instance and DID with the console. Every other
  message then goes to `tx`, with its unpack metadata. The console never
  deletes such a message at the mediator. If `tx` is full, the message is left
  stored for a later pickup.

### Changed — console keys: `Esc` no longer quits; `?` lists every key

- `Esc` only closes popups. On its own it does nothing, so one `Esc` too many
  no longer ends the session. Quit with `q` or `Ctrl-C`.
- `?` opens a help overlay listing every key for the current screen. The
  overlay and the footer come from one key table. The footer fits the width
  and ends with `… ? for more` when cut.
- `y` copies the selected row's full account hash, DID or message id to the
  clipboard (OSC 52). `]` (or reaching the last row) loads the next page of
  a list. `PgUp` / `PgDn` page through tables while the monitor is closed.
- Role, ACL, limit and configuration changes need a confirmation:
  - `s` in the account editor shows each change (`role: admin → rootAdmin`)
    and waits for `y`. It warns when the console's own account would be
    demoted or blocked.
  - A new `limits.*` value shows `from → to` and waits for `y`.
  - `x` on the Config screen (reset an override) now asks first.
- `r` reloads the screen from its first page.

### Fixed — console: background answers land where they were asked for

- Every screen request is tagged with what it was asked for: the account and
  queue, the ranking, the grant query. An answer that arrives after the user
  moved on is dropped, so a slow answer for one account no longer shows on
  another's screen or feeds `e`. A purge count or inspect result for an
  account the user has left is dropped, not shown.
- A screen sends one request per kind at a time, so a slow or unreachable
  mediator no longer gets a new batch every 5 s.
- The selection stays on the same message, account, queue or key across
  refreshes, not on the same row number.
- The delete and purge confirmations name the account and queue. The delete
  confirmation also names the message id, sender and recipient.

### Fixed — console: connection state, audit, paging, colour and copy

- The header shows `● connected`, `◌ connecting` or
  `✗ disconnected Ns — reconnecting` from the SDK's connection signal. The
  monitor writes a line on each drop and recovery, and its title says
  `✗ connection down` at once instead of `● live` for up to 45 s. The screen
  reloads when the connection returns.
- Audit scrolls, pages through `nextCursor` and adds an outcome column. It
  reads the `audit/list` 0.2 fields (`recordedAt`, `actor`, `action`,
  `target`, `outcome`) rather than guessing, and shows `detail` as
  `key=value`.
- The Account, Queues and Accounts lists say how much is shown
  (`200 of 5000 (] more)`) and page on demand, instead of cutting off at 200
  without saying so.
- Accounts loads a page at a time as the list is scrolled, and reloads every
  five minutes or on `r`. Before, it re-read every account every 5 s. The
  queue ranking is asked for again only once a newer survey is due. Monitor
  traffic redraws at most ten times a second.
- `NO_COLOR` now turns colour off on every screen, not just the quota bars.
  Badges and highlights are shown reversed instead.
- The inspect popup scrolls and shows the whole envelope (it was cut at 2,000
  characters). `y` copies the message and `w` writes it to a file.
- A long non-ASCII DID no longer panics the console when shortened.
- Pasted text has control characters removed in every field.
- The `mediator-console` binary turns bracketed paste off when it panics, as
  well as on a normal exit.
