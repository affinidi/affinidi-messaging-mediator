### Fixed — the same bytes stored for two recipients get a record each

- A stored message is now held per recipient. The same bytes stored for two
  recipients — one multi-recipient message forwarded to two local
  recipients is the usual case — get a record each, with their own sender,
  queue entries, counters and expiry. Previously the second store replaced
  the first recipient's record: its inbox entry was left with nothing
  behind it, its delete was refused, fair pickup skipped it, and once the
  second recipient deleted its copy the first recipient's queue counters
  and the sender's per-peer count never came down. Storing the same bytes
  again for the **same** recipient is still one record, counted once.
- The message id clients see is unchanged: `sha256(body)`. SDKs that derive
  ids from bodies keep working, and nothing on the wire changes.
- How an id is resolved, now that it can name several records:
  - an acknowledgement removes the acknowledging recipient's own copy only,
    never a copy of the same bytes held for someone else: message-pickup
    `messages-received`, TSP delete-on-send over the websocket, DIDComm v1
    `messages-received`, fetch with delete, and live-delivery deletes;
  - when a session holds several copies of an id — a mux principal and a
    member that both received the same bytes — an acknowledgement removes
    the copy that was handed over first, then follows session order;
  - `DELETE /delete` and `/outbound` with delete remove the copy held for
    the session's own DID or, on a mux connection, for a member it may
    delete for. Only when no such copy exists do they withdraw what the
    caller sent (every copy under that id), and not even then when an
    owner on the session already acknowledged its own copy of that id: that
    is a repeated acknowledgement (a redelivered message deleted twice) and
    answers `not_found`. An acknowledgement is remembered per recipient
    until that copy would have expired (7 days for a copy with no recorded
    expiry); a copy removed by expiry, an administrator or its sender is
    not an acknowledgement;
  - `messaging/message/delete` (self or admin) acts on the target account's
    queues: its own copy, else every copy it sent; an admin never removes a
    copy held for another account that the target did not send. Queue
    purge and account removal remove the queue's own copies only;
  - `messaging/message/status` answers for all of the sender's copies (see
    receipts below); `messaging/message/get` and `/outbound` read the
    caller's own copy, else one copy it sent;
  - the expiry sweep, delivery stamps (`mark_delivered`, delivered-TTL) and
    the admin message list act on one recipient's copy.
- Outbox receipts are kept per recipient. Status answers, over every copy:
  `withdrawn`/`discarded` (the latest) when any copy was removed without
  being collected, else `queued` while any copy waits for its first
  handover, else `delivered` (latest first handover) while copies are held,
  else `collected` (latest). It never answers `delivered` or `collected`
  while a copy was discarded or withdrawn.
- A `deleted` monitor event is emitted for each copy a delete removes.
- Anything that is not a message id (64 lowercase hex) names no message and
  is answered as not found, before any storage is addressed.
- The expiry sweep removes a record only when the index entry is at or after
  the record's current expiry. An entry left by an earlier copy of the same
  bytes for the same recipient, or by a deadline that delivered-TTL brought
  forward, is dropped instead of removing a later copy early.
- Redis `purge_folder` no longer stops at an inbox or outbox entry whose
  message is already gone; it drops the entry and carries on.
- Storage layout:
  - Redis: `MSG:<id>:<to>` (body) and `MSG:META:<id>:<to>` (metadata, now
    with `EXPIRES_AT`), plus `MSG:RCPT:<id>`, the set of recipients holding
    a copy. Expiry buckets hold `<id>:<to>`; in cluster mode the queue-id
    hashes are keyed the same way. Every key of one id stays in that id's
    cluster slot. Receipts are a hash per sender and id,
    `RECEIPTS:<from>:<id>` (recipient → receipt); acknowledgements are
    `ACKED:<to>:<id>`, expiring with the copy. `atm-functions.lua`
    changes (`store_message`, `delete_message`, `fetch_messages`); delivery
    stamping moved to a script outside the library, which no longer
    recreates the metadata of a message deleted in between.
  - Fjall: `messages` rows are keyed `{id}:{to}`; expiry entries name the
    row; receipt keys end in `:<to>`; acknowledgements are kept in the
    receipts keyspace under an `ACK` prefix and pruned with the receipts.
  - Memory: records are keyed by `(id, to)`; receipts and acknowledgements
    per recipient.
- Existing data needs no migration. Records stored under the old per-id keys
  (Redis `MSG:<id>` / `MSG:META:<id>`, a Fjall row keyed by the bare id) stay
  readable, deletable, counted and expirable: an operation for a recipient
  falls back to the old record when its `TO` is that recipient, the sweeper
  resolves a bare-id expiry entry through it (every expiry entry of an old
  record is due, as before, since its delivered deadline was never recorded
  on it), and storing the same bytes again for that recipient is still a
  no-op. Old single receipts (Redis `RECEIPT:<from>:<id>`, an unsuffixed
  Fjall receipt key) are still read, for an unknown recipient. Nothing
  writes the old layout any more, so the fallback can be removed once no old
  key remains: after the longest message expiry configured at the upgrade
  (`limits.message_expiry_seconds`, and 24 hours for receipts) has passed,
  and a scan (`SCAN MATCH 'MSG:META:*'` for keys with no `:` after the id;
  Fjall `messages` keys with no `:`) finds none.
- **Behaviour change (R3.6):**
  - A delete by id that finds nothing in the caller's own queues answers
    `database.message.delete.not_found`, also when another account holds a
    copy under the same id, or when the caller is not a party at all. A
    non-party deleting an existing message used to get
    `database.message.delete.permission_denied`. Clients already treat
    `not_found` as "already gone", which is now true from their side.
  - Acknowledgement paths never withdraw: a recipient that also sent the
    same bytes to someone else releases only its own copy.
  - `DELETE /delete` semantics, per id: the session's own copy (or a mux
    member's it may delete for; a delivered copy first) is acknowledged; if
    there is none, a repeat of an earlier acknowledgement by an owner on
    the session answers `not_found`; otherwise every copy the caller sent
    under that id is withdrawn. One request cannot be read both ways: a DID
    that sent the same bytes to itself and to someone else, acknowledged
    its own copy and then deletes the id again is answered as a repeated
    acknowledgement and withdraws nothing. `messaging/message/delete` or
    an outbox purge withdraws it explicitly; `messaging/message/delete`
    withdraws without the repeat check.
  - `messaging/message/status` can answer `withdrawn`/`discarded` for an id
    whose other copies are still held or were collected.
  - Store trait (`affinidi-messaging-mediator-common`):
    `delete_message_in(id, MessageScope, by)` is new, returns the removed
    copies, and is what backends implement; `delete_message(id, by)` is a
    provided method over it, and an owner's id-only delete removes its own
    copy only (withdrawal is `MessageScope::Party`). `mark_delivered`,
    `delivery_state` and `get_message_metadata` take the recipient;
    `delivery_states` takes `MessageRef`s; `outbox_receipts` and
    `acknowledged` are new;
    `ops::sent_message_state` takes every held copy and every receipt.
- **Deploying this release.** Instances of this release and of an earlier
  one must not run against the same database at the same time:
  1. stop **every** mediator instance sharing the database (all replicas, in
     every deployment that points at it);
  2. deploy this release everywhere;
  3. start the new instances. Do not start an instance of an earlier release
     against the database afterwards.

  Why: on single-node Redis the function library is per server and each
  instance loads its own at start, replacing it for every instance. An
  earlier build reads only the old per-id records, so it does not see
  messages a new instance stored, and a new instance running the earlier
  library cannot delete. As a safety net, a new instance that finds the
  earlier library loaded (its `delete_message` refuses the new arguments,
  or `fetch_messages` rows lack the layout marker) logs an error and loads
  its own library again, and the new library answers an earlier build's
  `delete_message` call the way it used to (`OK`): a bare id from the
  earlier build's admin reaches only an old-layout record, and an expiry
  bucket member it passes (`<id>:<to>`) removes that recipient's record
  only once its expiry has passed. A new instance whose `store_message` is
  answered by the earlier library (`OK` rather than `STORED`) keeps the
  message, which that library stored in the old layout this release still
  reads, and loads its own library again. That limits the damage of
  a missed instance; it does not make running both supported, since the two
  keep replacing each other's library. In cluster mode (ElastiCache
  Serverless) there is no shared library — each call carries its script —
  but the two builds still disagree about where a message is stored, so the
  same stop-everything-first order applies. Fjall and the in-memory store
  are single-process.
