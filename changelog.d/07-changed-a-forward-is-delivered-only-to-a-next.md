### Changed — a forward is delivered only to a next hop that has an account

- A forward never creates an account. A local next hop with no account on
  this mediator is refused with `73 delivery.refused`; it used to be
  registered with `global_acl_default`, in either `mediator_acl_mode`. A
  recipient gets its account by authenticating (or from an admin) before
  forwards to it are accepted.
- A forward from a DID with no account here is still checked against the
  least-privilege relay ACL (`SEND_FORWARDED` only, if `global_acl_default`
  grants it), but that DID is no longer registered. Its queued messages
  are still counted per recipient, so `limits.queue.peer` holds it as it
  holds any sender; `limits.queue.sender` (a per-account total) does not
  apply to it. An abandoned relay has no inbox here to report to (logged as
  `FORWARD_PROBLEM_REPORT_UNSENT`). Recipient-side checks, including access
  lists, see the sender's DID.
- A next hop this mediator cannot route is refused instead of stored where
  nothing would collect it. One whose DID document publishes a DIDComm
  service with no usable endpoint, or names a mediator whose document has
  no endpoint URL, gets `73 delivery.refused`. One that names a mediator
  whose DID cannot be resolved gets `74 did.resolve` with 503, so the sender
  can retry. Previously each was stored locally, logged "Storing locally —
  it will not be delivered", and answered as forwarded.
- A next hop whose own DID cannot be resolved is treated as local: it is
  delivered if it holds an account here, so a resolver outage does not stop
  local delivery, and refused with `73` otherwise.
- A forward is answered as forwarded only once it is stored: a storage
  failure while storing it locally is now returned to the sender instead of
  being logged and answered with success. An `ephemeral` forward is accepted
  only when it is handed to the recipient's live stream; a recipient with no
  live stream gets `73 delivery.refused`, and a failed publish a 503.

**Behaviour change (R3.6):** a deployment that forwards to recipients
before they have ever authenticated must now pre-register them with
`messaging/account/add` (admin). Senders that relied on an unresolvable or
unroutable next hop being accepted, or on `ephemeral` forwards to an
offline recipient succeeding, now get an error.
