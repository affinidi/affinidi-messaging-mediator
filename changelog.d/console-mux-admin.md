### Added — the console manages stored mux grants

- `affinidi-messaging-mediator-admin`: an administrator lists stored mux
  grants by principal or member DID, a page at a time
  (`MediatorConsole::mux_grants`), with the member's current epoch. It
  revokes chosen grants, a principal's or a member's (`mux_revoke`, with a
  `GrantSelection`), in bounded rounds, and says what was revoked, what still
  matches and why it stopped (`revoke_summary`). It advances a member's epoch
  (`mux_bump_epoch`), naming the epoch it read (`mux_epoch`), so a change made
  meanwhile is not overwritten.
- `ConsoleError::explain` puts the stored-grant refusals in plain words
  (`epochMismatch`, `protectedAccount`, `unknownAccount`, `contended`,
  administrator required). `ConsoleError::current_epoch` reads the epoch in
  force from an `epochMismatch`.
- `affinidi-messaging-mediator-tui`: a **Grants** tab (`8`) lists a
  principal's or member's grants (`/` to look one up, `g` from a Mux
  connection), revokes the selected grant (`d`) or all listed (`D`), and
  advances the member's epoch (`E`) after showing the current one. Each asks
  for confirmation. Number keys now reach the 7th and 8th tabs.
- These need mediator 0.52.0. The console refuses them locally, with the
  reason, on an older mediator it knows the version of.

### Changed — the console's live monitor subscribes at monitor/subscribe 0.2

- The live monitor now subscribes with `messaging/monitor/subscribe` 0.2 and
  reads `messaging/monitor/event` 0.3. On a mediator that refuses 0.2 as an
  unsupported type, or whose version predates 0.52.0, it subscribes at 0.1, as
  before. The SDK marks the 0.1 types superseded; only this fallback uses
  them.
- `MediatorConsole::monitor_with` adds mux membership events.
  `MonitorUpdate::Membership` carries them, after the same batch's
  `Events`. The TUI's monitor shows members attaching and detaching to an
  administrator watching all traffic.
- Breaking for code that names these types: `MonitorFilter` is now the
  subscribe 0.2 filter, and `MonitorEvent` the event 0.3 traffic event (both
  the same JSON as before). `MonitorUpdate` has a new `Membership` variant, and
  `ConsoleError` new `Invalid` and `Unexpected` variants, so an exhaustive
  `match` on either needs an arm for them.
- Needs `affinidi-messaging-sdk` 0.45.17.

### Fixed — a renewed monitor subscription keeps its filter

- The console renewed its monitor lease without the filter. A renewal
  re-filters, so after the first renewal (about four minutes in) an
  administrator's narrowed feed widened to all traffic. Renewals now send the
  filters in force.
