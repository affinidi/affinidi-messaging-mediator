### Changed — DID multiplexing connections (R3.6)

- **Subprotocol `didcomm-mux`.** A DIDComm socket now becomes a mux
  connection by offering `didcomm-mux`, the name `messaging/mux/event/0.1`
  defines (trustoverip/dtgwg-trust-tasks-tf#1078). The provisional
  `affinidi-mux` that SDK 0.45.1 and 0.45.2 offer is still accepted; when a
  client offers both, `didcomm-mux` is selected. SDK 0.45.3 offers the new
  name.
- **`connectionFull`.** A connection already carrying
  `max_dids_per_connection` members now says so instead of leaving the
  client to infer it. On connect, valid grants it has no room for are listed
  in the `detached` event with reason `connectionFull`. A grant stored while
  the principal is connected, which the connection has no room for, gets a
  `detached` / `connectionFull` event too. Previously the first case
  was logged only, with the wrong reason, and the second only logged.
  Grants are now validated before the connection's room is checked, so a
  grant reported `connectionFull` is a valid one.
- **`attachedNow`.** A stored grant's outcome in the `messaging/mux/grant`
  response now carries `attachedNow`, which the schema requires: whether a
  connection on this instance took the member at once.
- **Event entries match the schema.** `detached` entries carry only `did`,
  `reason` and `grantId`. They used to carry `scope`, `expiresAt` and
  (for `superseded`) `deliveryActive`, which the spec allows on `attached`
  entries only. `attached` entries always carry `deliveryActive`. The
  `attached` event that marks a member inactive, because the DID's own
  direct socket keeps its traffic, now gives the reason the member joined by
  (`connect` or `attach`) instead of `superseded`, which is not an attach
  reason.
- **Login check bounded.** The unknown-key check on a direct login now
  reads the DID's grants and resolves its key within 5 s
  (`mux::notice::CHECK_READ_TIMEOUT`). A slow store or resolver refuses the
  login as retryable (`me.res.storage.error`, 503) instead of holding it
  open. The commit and detach that follow are not cut short. Each refusal
  counts in the new `mux_login_check_failures_total` metric.
