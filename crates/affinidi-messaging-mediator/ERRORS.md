# Mediator error codes

Every error the mediator sends a client has a **number** (this table's first
column; the `errorCode` of a REST error body, and what the mediator logs) and
a **code** on the wire:

- a [DIDComm problem report](https://identity.foundation/didcomm-messaging/spec/#problem-reports)
  code of the form `<sorter>.<scope>.<descriptor>`: `e` (error) or `w`
  (warning), then `p` (protocol) or `m` (message); or
- for a refused Trust Task, a Trust Task error code (see
  [Trust Task errors](#trust-task-errors)).

The source is the authority: each number is a constant in
`affinidi-messaging-mediator-common/src/error_codes.rs`, and the test
`tests/errors_md.rs` fails when a constant, a problem code written in a
handler, or a Trust Task code a served task declares is missing here.

Some failures produce no error at all: the message is dropped to protect
the privacy of the system, and higher-level protocols must handle the
non-delivery. Refusals that would reveal whether a recipient exists or what
its ACLs allow all return the same code, 73 `e.p.delivery.refused`; the
reason is logged on the mediator only.

- **REST API**: each request returns a status. A 2xx status does not always
  mean the action completed.
- **WebSocket**: failures may come back as a problem report message. How to
  handle them is up to the client.

The HTTP status shown is the usual one; where a code is raised with another
status, the cause says so. Queue-limit refusals (61, 62, 95) include a
`Retry-After` header. Rows marked "—" are numbers that are no longer
returned; they are kept so a number is never reused.

## Codes

| Error Code | HTTP Status Code | Problem Code(s) | Retryable? | Cause |
| ---------: | :--------------: | :-------------- | :--------: | :---- |
| 0 | 500 | — | No | Internal error raised by a background processor. Never sent to a client |
| 1 | 500 | `e.p.me.res.storage.url` | No | Incorrect database URL in the mediator configuration |
| 2 | 500 | `e.p.me.res.storage.config` | No | Database configuration is invalid, or the database functions (Lua) couldn't be loaded |
| 3 | 503 | `e.p.me.res.storage.connection`<br>`e.p.me.res.storage.connection.blocking` | Yes | A connection to the database couldn't be made (including the blocking connection used for streaming) |
| 4 | 503 | `e.p.me.res.storage.connection.pubsub` | Yes | Couldn't open a database connection for pub/sub |
| 5 | 503 | `e.p.me.res.storage.connection.pubsub.receiver` | Yes | Couldn't get a receiver for the pub/sub connection |
| 6 | 503 | `e.p.me.res.storage.info` | Yes | Querying database server information failed |
| 7 | 500 | `e.p.me.res.storage.version` | No | Can't parse the database server version |
| 8 | 500 | `e.p.me.res.storage.version.incompatible` | No | The database server version is not supported |
| 9 | 500 | `e.p.me.res.storage.version.unknown` | No | Couldn't determine the database server version |
| 10 | 503 | `w.m.database.message.delete.error` | Yes | Deleting a message from the database failed |
| 11 | — | `w.m.database.message.delete.status` | — | No longer returned; a delete that fails is 10 |
| 12 | NA | `e.p.me.config.initialization` | No | Mediator configuration problem, found while starting or reloading |
| 13 | NA | `e.p.me.res.storage.schema` | No | Couldn't set or read the database schema version (at startup) |
| 14 | 503 | `w.m.me.res.storage.error`<br>`e.p.me.res.storage.error` | Yes | A database operation failed |
| 15 | 400 | `w.m.database.admin.accounts.add.limit` | No | At most 100 admin accounts can be added at a time |
| 16 | 400 | `w.m.database.admin.accounts.strip.limit` | No | At most 100 admin accounts can be stripped at a time |
| 17 | 500 | — | No | Internal error (unexpected state, a value that couldn't be converted). The detail is logged, not returned |
| 18 | 400 | `w.m.database.account.remove.protected` | No | Tried to remove a protected account (the mediator or a root admin) |
| 19 | 400 | `w.m.message.serialize`<br>`e.p.message.serialize`<br>`e.p.message.deserialize` | No | A request body or DIDComm message couldn't be serialised or deserialised |
| 20 | 500 | `e.p.database.session.invalid.state` | No | Session record is missing a field or is corrupt (restart authentication) |
| 21 | 500 | `e.p.database.stats.parse` | No | Can't parse a record read from the database (statistics, inbox status, message lists) |
| 22 | 500 | `e.p.database.message.metadata` | No | Can't parse message metadata in the database |
| 23 | 500 | `e.p.me.res.storage.pubsub.clean_start` | No | Initial reset of the pub/sub system failed at startup |
| 24 | 500 | `e.p.me.res.storage.pubsub.publish` | No | Couldn't serialise a pub/sub record |
| 25 | 403 | `e.p.authentication.blocked`<br>`e.m.authorization.blocked` | No | The DID is blocked from using the mediator |
| 26 | 500 | `w.m.database.acl.get.parse` | No | Couldn't parse a DID's stored ACL flags |
| 27 | 400 | `w.m.database.acl.get_dids.limit` | No | At most 100 DIDs can be fetched at a time |
| 28 | 400 | `e.p.authentication.response.parse` | No | Couldn't parse the authentication response (restart authentication) |
| 29 | 400 | `e.p.authentication.response.from`<br>`e.p.authentication.challenge.invalid_did`<br>`e.p.authentication.tsp.invalid_vid` | No | The DID (or TSP VID) to authenticate is missing or not a valid DID |
| 30 | 400 | `e.p.message.type.incorrect` | No | DIDComm message type is missing or incorrect |
| 31 | 400 | `e.p.message.expired` | No | DIDComm message has expired |
| 32 | 403 | `e.p.message.unpack`<br>`e.p.authentication.tsp.signature.invalid` | No | The message couldn't be unpacked or its signature didn't verify (TSP authentication: 401) |
| 33 | 400 | `e.p.authentication.session.mismatch` | No | DIDs do not match throughout the authentication process (401 on TSP authentication) |
| 34 | 400 | `e.p.authentication.session.invalid`<br>`e.p.authentication.session.state` | No | Authentication session is invalid or in the wrong state (restart authentication; 401 where the session is unknown) |
| 35 | 500 | `e.p.authentication.session.access_token` | No | Couldn't create a JWT access token |
| 36 | 500 | `e.p.authentication.session.refresh_token` | No | Couldn't create a JWT refresh token |
| 37 | 400 | `e.p.message.envelope.read`<br>`e.p.message.tsp.malformed`<br>`e.p.message.tsp.route`<br>`e.p.message.tsp.unpack`<br>`e.p.message.bridge.malformed` | No | Couldn't read the message envelope (DIDComm, or a TSP envelope or route) |
| 38 | 400 | `e.p.authentication.session.refresh_token.parse` | No | Couldn't parse the JWT refresh token, or it is not a refresh token |
| 39 | 400 | `e.p.authentication.message.from.missing` | No | Refresh request is missing a `from` header |
| 40 | 403 | `e.p.authorization.local` | No | DID is not local to the mediator |
| 41 | 400 | `e.p.api.inbox_fetch.limit` | No | Invalid number of messages requested from `/fetch` (1 to `limits.listed_messages`) |
| 42 | 400 | `e.p.api.inbox_fetch.start_id` | No | Invalid `start_id`: a UNIX epoch timestamp in milliseconds followed by `-(0-999)` |
| 43 | 400 | `e.p.api.message_delete.limit` | No | Invalid number of messages to delete (1 to `limits.deleted_messages`) |
| 44 | 403 | `e.p.authorization.send` | No | DID may not send messages |
| 45 | 403 | `e.p.authorization.permission` | No | DID does not have permission to access the requested resource |
| 46 | 500 | `e.p.oob.store` | No | Couldn't store an Out-Of-Band (OOB) invitation |
| 47 | 500 | `e.p.message.pack`<br>`e.p.message.tsp.reseal`<br>`e.p.message.tsp.trust_task.serialize`<br>`e.p.message.tsp.trust_task.seal`<br>`e.m.message.didcomm_v1.build`<br>`e.m.message.didcomm_v1.pack` | No | Couldn't pack (DIDComm) or seal (TSP) a message. 400 when the recipient's DID document gives no usable key |
| 48 | 500 | `e.p.me.did.missing` | No | Mediator DID Document configuration is missing |
| 49 | 400 | `w.m.protocol.pickup.return_route` | No | Message Pickup message is missing `return_route`, or it is incorrect |
| 50 | 400 | `w.m.message.anonymous` | No | The message is anonymous, and this transaction requires a sender (403 where an anonymous sender is refused) |
| 51 | 400 | `w.m.message.to` | No | There was a problem with the message `to` header (422 when it names more than one recipient) |
| 52 | 400 | `e.p.authorization.did.session_mismatch` | No | Message DID and session DID differ where they must match |
| 53 | 400 | `w.m.protocol.pickup.delivery_request.limit`<br>`w.m.protocol.pickup.messages_received.limit` | No | Message Pickup limit must be from 1 to 100; a `messages-received` names at most 100 ids |
| 54 | 400 | `w.m.protocol.pickup.parse` | No | Couldn't parse the Message Pickup message body |
| 55 | 500 | `e.p.protocol.pickup.live_streaming` | No | Live streaming couldn't be enabled or disabled; 501 when live delivery is asked for on a mediator without streaming |
| 56 | 400 | `w.m.protocol.forwarding.next.missing` | No | Forward message is missing its `next` field |
| 57 | 400 | `w.m.protocol.forwarding.parse` | No | Couldn't parse the forward message body |
| 58 | 404 | `e.p.message.tsp.no_endpoint` | No | TSP next hop publishes no TSP endpoint |
| 59 | 400 | `w.m.protocol.forwarding.attachments.missing` | No | The forward message has no attachments |
| 60 | 403 | `e.p.authorization.send_forwarded` | No | Sender may not send forwarded (relayed) messages, over DIDComm or TSP |
| 61 | 503 | `e.p.limits.queue.sender` | Yes | Sender has too many messages waiting to be delivered |
| 62 | 503 | `e.p.limits.queue.recipient` | Yes | Recipient has too many messages waiting to be delivered |
| 63 | 400 | `w.m.protocol.forwarding.attachments.too_many` | No | A forward carries exactly one attachment; this one has more |
| 64 | 503 | `e.p.me.res.forwarding.queue.limit` | Yes | Mediator forwarding queue is full; try again later |
| 65 | 400 | `w.m.protocol.forwarding.delay_milli` | No | Forward `delay_milli` is not a whole number from 0 to the configured limit |
| 66 | 501 | `e.p.me.not_implemented` | No | Feature is not implemented by the mediator (400 for an attachment form it does not read) |
| 67 | 400 | `w.m.protocol.forwarding.attachments.json.invalid`<br>`w.m.protocol.forwarding.attachments.unknown` | No | Attachment JSON is invalid, or the attachment type is unknown |
| 68 | 400 | `w.m.protocol.forwarding.attachments.base64` | No | Couldn't decode a base64 attachment |
| 69 | — | `e.p.authorization.receive_anon` | — | No longer returned; reported as 73 |
| 70 | — | `w.m.protocol.forwarding.next.mediator.self` | — | No longer returned; a next hop that is this mediator is delivered locally, and loops are 94 |
| 71 | 403 | `w.m.direct_delivery.denied`<br>`e.p.direct_delivery.denied` | No | Mediator is not accepting direct delivery; messages must be wrapped in a forward |
| 72 | — | `w.m.direct_delivery.recipient.unknown` | — | No longer returned; reported as 73 |
| 73 | 403 | `e.p.delivery.refused`<br>`e.p.authorization.access_list.denied` | No | Message not accepted for delivery: unknown or non-local recipient, missing receive permission, or blocked by the access list. The reason is logged, not returned |
| 74 | 503 | `e.p.did.resolve` | Maybe | A DID couldn't be resolved. On a forward (503, retryable): the mediator its next hop names. 400 when the recipient of a reply can't be resolved |
| 75 | 500 | `e.p.message.recipients.missing` | No | There are no recipients for this message |
| 76 | 500 | `e.p.message.recipients.too_many` | No | There are too many recipients for this message |
| 77 | — | `e.p.me.storage.message.error` | — | No longer returned; a handled message with nothing to answer (a ping with `response_requested: false`) is a `200` with `data: "Empty"` |
| 78 | — | `e.p.me.res.storage.pubsub.subscribe` | — | No longer returned; a failed subscribe is 14 |
| 79 | 400 | `w.m.message.header.ephemeral.invalid` | No | The `ephemeral` header isn't a JSON boolean. Treated as false; the message is still sent |
| 80 | — | `w.m.protocol.acls.change.denied` | — | No longer returned; the Trust Task is refused with `messaging/account/update:selfChangeDenied` |
| 81 | — | `w.m.protocol.mediator.accounts.parse` | — | No longer returned (the retired DIDComm accounts protocol) |
| 82 | — | `w.m.protocol.mediator.acls.parse` | — | No longer returned (the retired DIDComm ACL protocol) |
| 83 | — | `w.m.protocol.mediator.administration.parse` | — | No longer returned (the retired DIDComm administration protocol) |
| 84 | — | `w.m.protocol.mediator.administration.strip.missing` | — | No longer returned (the retired DIDComm administration protocol) |
| 85 | 400 | `e.p.message.from.incorrect` | No | The plaintext `from` does not match the signing or encrypting DID |
| 86 | 400 | `e.p.authentication.message.not_signed_or_encrypted` | No | The DIDComm message must be signed and encrypted for this transaction |
| 87 | 500 | `e.p.oob.retrieve` | Maybe | Retrieving an OOB invitation failed internally |
| 88 | 501 | `e.p.me.not_implemented` | No | A Discover Features disclose was sent to the mediator, which does not read disclosures sent to itself |
| 89 | 400 | `w.m.protocol.discover_features.queries.parse` | No | Couldn't parse the Discover Features queries |
| 90 | 503 | `e.p.me.res.forwarding.enqueue`<br>`e.p.message.tsp.forward.enqueue` | Yes | Couldn't enqueue a message for remote forwarding |
| 91 | 400 | `e.p.message.created_time.missing` | No | Admin messages must include a `created_time` header |
| 92 | 400 | `e.p.message.expires_time.missing` | No | Authentication messages must include an `expires_time` header |
| 93 | 400 | `e.p.protocol.mediator.access_list.limit` | No | Access list batch must contain 1 to 100 entries |
| 94 | 508 | `e.p.protocol.forwarding.loop_detected` | No | Forward exceeded `max_hops`, or its next hop resolves back to this mediator |
| 95 | 503 | `e.p.limits.queue.peer` | Yes | Too many messages already waiting from this sender for this recipient |
| 96 | 403 | `e.p.authorization.sender.mismatch` | No | The message's `from` is not the DID that authenticated the message (its signer or authcrypt sender) where the two must agree |
| 97 | 507 | `e.m.me.res.storage.full` | Yes | Mediator storage is full (data storage maximum reached); retry once space is freed. A cache that evicts first (ElastiCache Serverless) drops keys with a TTL (sessions, invites, receipts) before this error |
| 98 | 503 | `w.m.me.res.storage.busy` | Yes | Mediator storage is busy or unreachable (a command timed out, e.g. throttled at its ECPU maximum), or in cluster mode another store or delete of the same message still holds it; retry later |
| 99 | 404 | `w.m.delivery.not_live` | Yes | An ephemeral forward's recipient has no live stream: the message was not delivered and is not queued. Retry later, or send it non-ephemeral |
| 100 | 413 | `e.m.message.size.exceeded` | No | The message is larger than the mediator accepts (was 37) |
| 101 | 400 | `e.p.protocol.unsupported`<br>`e.p.message.tsp.unsupported`<br>`e.m.message.didcomm_v1.unsupported` | No | The message's protocol or type is not one the mediator serves (was 37) |
| 102 | 400 | `e.m.message.didcomm_v1.malformed`<br>`e.m.message.didcomm_v1.unpack`<br>`e.m.message.didcomm_v1.payload`<br>`e.m.message.didcomm_v1.unexpected`<br>`e.m.message.didcomm_v1.not_forward`<br>`e.m.message.didcomm_v1.destination`<br>`e.m.message.didcomm_v1.keylist`<br>`e.m.message.didcomm_v1.messages_received`<br>`e.m.message.didcomm_v1.anonymous_request` | No | A DIDComm v1 message the mediator can't act on: unreadable, not a forward where one is required, or a malformed coordinate-mediation or pickup request (was 37) |
| 103 | 400 | `e.p.authentication.tsp.resolve`<br>`e.p.authentication.tsp.signature.encoding`<br>`e.p.authentication.tsp.signature.length` | No | TSP authentication: the VID couldn't be resolved, or the signature is not valid base64url Ed25519 (was 28) |
| 104 | 400 | `e.p.authentication.session.refresh_token.expired` | No | The JWT refresh token has expired; authenticate again (was 38) |
| 105 | 401 | `e.p.authentication.session.refresh_token.reuse` | No | A refresh token was used twice; the session is revoked (was 38) |
| 106 | 401 | `e.p.authorization.authentication_required` | No | An anonymous session may send nothing but a DIDComm v1 forward (was 44) |
| 107 | 400 | `e.p.api.message_outbound.limit` | No | Invalid number of messages requested from `/outbound` (was 43) |
| 108 | 502 | `e.p.message.tsp.resolve`<br>`e.p.message.tsp.mediator.unresolvable` | Maybe | TSP next hop, or the mediator it names, couldn't be resolved (was 58) |
| 109 | 403 | `e.p.authorization.relay.untrusted_peer` | No | Relaying peer mediator is not in `relay_trusted_mediators` (was 60) |
| 110 | 404 | `w.m.database.message.delete.not_found` | No | The message to delete is not there (it may already be deleted) (was 10) |
| 111 | 403 | `w.m.database.message.delete.permission_denied` | No | The requester is not a party to the message it asked to delete (was 10) |

## Codes without a number

These are sent as problem reports outside a request, so they have no
`errorCode`.

| Problem Code | Sent when |
| :----------- | :-------- |
| `w.websocket.duplicate-channel` | A new WebSocket connection for the same DID replaced this one |
| `w.websocket.duplicate-channel-refused` | This DID already has a live WebSocket connection, which was kept; this one was refused |
| `w.websocket.unauthenticated-session` | The session reached streaming registration without an authenticated DID |
| `e.p.me.res.forwarding.refused` | A message this mediator forwarded was refused by the next hop (sent to the original sender when the forwarding processor reports errors) |
| `e.p.me.res.forwarding.abandoned` | A message this mediator was forwarding was given up after its retries (likewise) |

## Trust Task errors

A refused Trust Task is answered with a `trust-task-error` document (Trust
Tasks SPEC §8), signed by the mediator as a response is, over whichever
transport carried the request: DIDComm (REST or WebSocket), TSP, or a mux
connection. Its `code` is one of the framework's standard codes below, or a
`<task>:<code>` the task's specification declares. The mediator uses no
other codes for Trust Tasks.

Where no document can be sent, the same code comes back as the problem code
`e.p.<code>` (for example `e.p.permissionDenied`):

- the request is not a Trust Task document (no `id` or `type` to answer), or
  it arrived without an authenticated sender;
- the sender is not the session's own authenticated DID (a relay-only
  session, or a TSP frame signed by another DID): a document costs a
  signature and a stored message, which only a sender who could get a
  response may cause;
- the document could not be built or signed.

The number (for logs and REST error bodies) is in 120–139.

### Standard codes

| Error Code | HTTP Status Code | Trust Task Code | Retryable? | Cause |
| ---------: | :--------------: | :-------------- | :--------: | :---- |
| 120 | 400 | `malformedRequest` | No | The document, its payload or a value in it (an ACL, a cursor, a queue limit) is not valid for the task |
| 121 | 501 | `unsupportedType` | No | The mediator does not serve this Trust Task type (or mux tasks while mux is off) |
| 122 | 501 | `unsupportedVersion` | No | The type is served, but not at this version |
| 123 | 403 | `expired` | No | `expiresAt` has passed, or the document is outside the acceptance window |
| 124 | 403 | `proofRequired` | No | The task requires a `proof` and the document has none |
| 125 | 403 | `proofInvalid` | No | The `proof` did not verify |
| 126 | 403 | `permissionDenied` | No | The requester may not invoke the task, or not on this target |
| 127 | 403 | `wrongRecipient` | No | The document's `recipient` is not this mediator |
| 128 | 403 | `identityMismatch` | No | The in-band `issuer` is not the transport-authenticated sender |
| 129 | 403 | `idConflict` | No | The document's `id` was already accepted (with the same or different content) |
| 130 | — | `cancelled` | — | Not used by the mediator |
| 131 | 422 | `taskFailed` | No | The task was attempted and could not be completed (a configuration that would not reload) |
| 132 | 503 | `unavailable` | Yes | The mediator can't process the task now (storage busy or full, no queue survey yet, nothing to reload). Retryable |
| 133 | 500 | `internalError` | No | An internal failure. The detail is logged, not returned |
| 134 | — | `unsupportedExtension` | — | Not used by the mediator |
| 135 | — | `indeterminate` | — | Not used by the mediator |
| 139 | varies | `<task>:<code>` | varies | A `<task>:<code>` a Trust Task specification declares (see the list below) |

### Codes the task specifications declare

Number 139. The meaning is the specification's; the mediator sends each one
under the conditions its specification gives.

| Task | Trust Task Code | Retryable? | Meaning |
| :--- | :-------------- | :--------: | :------ |
| `audit/list` | `audit/list:invalidCursor` | No | The supplied cursor failed to verify — malformed, or minted before an audit-key rotation. The consumer restarts from the first page rather than retrying. |
| `messaging/access-list/list` | `messaging/access-list/list:unknownAccount` | No | The target DID has no account at this mediator. |
| `messaging/access-list/update` | `messaging/access-list/update:unknownAccount` | No | The target DID has no account at this mediator. |
| `messaging/access-list/update` | `messaging/access-list/update:listFull` | No | Applying the additions would exceed the account's configured maximum access-list size; no change was made. |
| `messaging/access-list/update` | `messaging/access-list/update:selfChangeDenied` | No | The requester is the account's own controller and the account is not permitted to self-manage its access list (selfManageList is not set). |
| `messaging/account/add` | `messaging/account/add:alreadyExists` | No | The target DID already has an account at this mediator. |
| `messaging/account/get` | `messaging/account/get:unknownAccount` | No | The target DID has no account at this mediator. |
| `messaging/account/remove` | `messaging/account/remove:unknownAccount` | No | The target DID has no account at this mediator. |
| `messaging/account/remove` | `messaging/account/remove:protectedAccount` | No | The target account is protected (a mediator or rootAdmin account) and cannot be removed. |
| `messaging/account/update` | `messaging/account/update:unknownAccount` | No | The target DID has no account at this mediator. This task updates; use messaging/account/add to create. |
| `messaging/account/update` | `messaging/account/update:rootAdminRequired` | No | Assigning the rootAdmin role, or updating an account that currently holds it, requires the requester to be a rootAdmin. |
| `messaging/account/update` | `messaging/account/update:selfChangeDenied` | No | The requester is the account's own controller and attempted to change a member it is not permitted to self-manage. |
| `messaging/message/delete` | `messaging/message/delete:unknownAccount` | No | The named account (`did`) has no account at this mediator. |
| `messaging/message/delete` | `messaging/message/delete:rootAdminRequired` | No | The target account holds the admin, rootAdmin, or mediator role, and the requester is not a rootAdmin. |
| `messaging/message/get` | `messaging/message/get:unknownAccount` | No | The named account (`did`) has no account at this mediator. |
| `messaging/message/get` | `messaging/message/get:unknownMessage` | No | No message with this `msgId` is held in the named account's queues — it never existed, was deleted, or expired. |
| `messaging/message/get` | `messaging/message/get:rootAdminRequired` | No | The request names another account's message, and the requester is not a rootAdmin. An admin may see another account's message metadata through messaging/message/list, but not its body. |
| `messaging/message/get` | `messaging/message/get:messageTooLarge` | No | The stored message exceeds the 10 MiB this task can carry. It is refused rather than truncated; it remains in the queue and can still be listed or deleted. |
| `messaging/message/list` | `messaging/message/list:unknownAccount` | No | The named account does not exist at this mediator. |
| `messaging/monitor/subscribe` | `messaging/monitor/subscribe:unknownSubscription` | No | The request names a `subscriptionId` the mediator does not hold for this requester — it never existed, has expired, was ended, or belongs to someone else. Omit `subscriptionId` to open a new subscription. |
| `messaging/monitor/subscribe` | `messaging/monitor/subscribe:tooManySubscriptions` | Yes | The requester already holds the maximum number of concurrent subscriptions the mediator allows. End one, or wait for one to expire. |
| `messaging/monitor/unsubscribe` | `messaging/monitor/unsubscribe:unknownSubscription` | No | No live subscription with this `subscriptionId` exists that the requester may end — it never existed, has already expired or ended, or belongs to another requester and the requester is not a rootAdmin. |
| `messaging/mux/ack` | `messaging/mux:notMuxConnection` | No | The request did not arrive on a mux connection, so there are no members' frames it could acknowledge. Send it on the connection the frames were delivered on. |
| `messaging/mux/admin-list` | `messaging/mux/admin-list:cursorInvalid` | No | `cursor` was not issued by this mediator for this requester and these request members, or it has expired. |
| `messaging/mux/admin-revoke-all` | `messaging/mux/admin-revoke-all:protectedAccount` | No | The member DID is a protected account — a rootAdmin account — and the requester is not a rootAdmin. Nothing changed. |
| `messaging/mux/admin-revoke-all` | `messaging/mux/admin-revoke-all:unknownAccount` | No | The member DID has no account at this mediator, so it has no epoch to advance. |
| `messaging/mux/admin-revoke-all` | `messaging/mux/admin-revoke-all:epochMismatch` | No | The request names an epoch later than the member DID's current one. `details.currentEpoch` carries the epoch in force; send it. |
| `messaging/mux/admin-revoke-all` | `messaging/mux/admin-revoke-all:contended` | Yes | The member DID's record changed under concurrent writes too many times for the epoch advance to be committed. Nothing changed; send the request again. |
| `messaging/mux/admin-revoke` | `messaging/mux/admin-revoke:protectedAccount` | No | A grant the request selects has a protected party — its member DID or its principal DID is a rootAdmin account — and the requester is not a rootAdmin. Nothing was revoked. |
| `messaging/mux/admin-revoke` | `messaging/mux/admin-revoke:contended` | Yes | A member DID's record changed under concurrent writes too many times for the revocation to be committed, and no grant on it was revoked. Send the request again. |
| `messaging/mux/attach` | `messaging/mux:notMuxConnection` | No | The request did not arrive on a mux connection — one the mediator has announced with a `ready` event — so there is no `sessionId` or `muxNonce` an attach could bind to. Attach over the live connection the members should ride. A whole-request error. |
| `messaging/mux/attach` | `messaging/mux:proofPurposeInvalid` | No | Per attachment, in `results[].code`: the embedded proof's `proofPurpose` is not `authentication`. |
| `messaging/mux/attach` | `messaging/mux:statementProofInvalid` | No | Per attachment: the embedded Data Integrity proof does not verify — a bad signature, a verification method not controlled by the statement's `issuer`, or one not in the issuer's current `authentication` relationship. |
| `messaging/mux/attach` | `messaging/mux:didUnresolvable` | Yes | Per attachment: the member DID could not be resolved now, so its proof could not be checked. |
| `messaging/mux/attach` | `messaging/mux:audienceMismatch` | No | Per attachment: the statement's `audience` is not this mediator's DID. |
| `messaging/mux/attach` | `messaging/mux:principalMismatch` | No | Per attachment: the statement's `principal` is not the DID this connection is authenticated as, or equals the statement's `issuer`. |
| `messaging/mux/attach` | `messaging/mux/attach:sessionMismatch` | No | Per attachment: the statement's `sessionId` or `muxNonce` is not this connection's. |
| `messaging/mux/attach` | `messaging/mux:notYetValid` | No | Per attachment: the statement's `iat` is more than 60 seconds in the mediator's future. |
| `messaging/mux/attach` | `messaging/mux:statementExpired` | No | Per attachment: the statement's `exp` has passed. |
| `messaging/mux/attach` | `messaging/mux:lifetimeTooLong` | No | Per attachment: the statement's `exp` is later than the connection's lifetime, or than `iat` plus the mediator's attach maximum. |
| `messaging/mux/attach` | `messaging/mux:emptyScope` | No | Per attachment: the signed scope is empty. An empty scope is refused, never read as "all". |
| `messaging/mux/attach` | `messaging/mux:accountUnavailable` | No | Per attachment: the member DID has no account at this mediator, or it is blocked. |
| `messaging/mux/attach` | `messaging/mux:scopeNotPermitted` | No | Per attachment: the scope exceeds the member DID's own access-control capabilities. |
| `messaging/mux/attach` | `messaging/mux/attach:memberQuota` | Yes | Per attachment: attaching would exceed the members this connection may carry (`maxDidsPerConnection`). |
| `messaging/mux/connections` | `messaging/mux/connections:cursorInvalid` | No | `cursor` was not issued by this mediator — or, where the answer covers one instance only, by this instance — for this requester and these request members, or it has expired. |
| `messaging/mux/detach` | `messaging/mux:notMuxConnection` | No | The request did not arrive on a mux connection, so there is no session attach it could remove. Send it on the connection that holds the attaches. |
| `messaging/mux/grant` | `messaging/mux:proofPurposeInvalid` | No | Per grant, in `results[].code`: the embedded proof's `proofPurpose` is not `authentication`. |
| `messaging/mux/grant` | `messaging/mux:statementProofInvalid` | No | Per grant, in `results[].code`: the embedded Data Integrity proof does not verify — a bad signature, a verification method not controlled by the statement's `issuer`, or one not in the issuer's current `authentication` relationship. |
| `messaging/mux/grant` | `messaging/mux:didUnresolvable` | Yes | Per grant, in `results[].code`: the member DID could not be resolved now, so the grant could not be checked. |
| `messaging/mux/grant` | `messaging/mux:audienceMismatch` | No | Per grant, in `results[].code`: the statement's `audience` is not this mediator's DID. |
| `messaging/mux/grant` | `messaging/mux:principalMismatch` | No | Per grant, in `results[].code`: the statement's `principal` equals its `issuer`. |
| `messaging/mux/grant` | `messaging/mux:notYetValid` | No | Per grant, in `results[].code`: the statement's `iat` is more than 60 seconds in the mediator's future. |
| `messaging/mux/grant` | `messaging/mux:statementExpired` | No | Per grant, in `results[].code`: the statement's `exp` has passed. |
| `messaging/mux/grant` | `messaging/mux:lifetimeTooLong` | No | Per grant, in `results[].code`: `exp − iat` exceeds the mediator's maximum grant lifetime (`maxGrantLifetimeSeconds`). |
| `messaging/mux/grant` | `messaging/mux:emptyScope` | No | Per grant, in `results[].code`: the signed scope is empty. An empty scope is refused, never read as 'all'. |
| `messaging/mux/grant` | `messaging/mux:accountUnavailable` | No | Per grant, in `results[].code`: the member DID has no account at this mediator, or it is blocked. |
| `messaging/mux/grant` | `messaging/mux:scopeNotPermitted` | No | Per grant, in `results[].code`: the signed scope exceeds the member DID's own access-control capabilities. |
| `messaging/mux/grant` | `messaging/mux/grant:epochMismatch` | No | Per grant, in `results[].code`: the statement's `epoch` is not the member DID's current epoch. The outcome carries `currentEpoch`; the member re-signs under it. |
| `messaging/mux/grant` | `messaging/mux/grant:replayed` | No | Per grant, in `results[].code`: the statement's `iat` is not strictly later than the principal's replay floor for this member, or than the `iat` of the grant it would replace — a revoked, replaced or superseded statement submitted again. The outcome carries `replayFloorAt`; the member re-signs with a later `iat`. |
| `messaging/mux/grant` | `messaging/mux/grant:grantIdReused` | No | Per grant, in `results[].code`: the statement's `grantId` is already on the member DID's record. |
| `messaging/mux/grant` | `messaging/mux/grant:didQuota` | No | Per grant, in `results[].code`: storing the grant would exceed the active grants allowed on the member DID. |
| `messaging/mux/grant` | `messaging/mux/grant:principalQuota` | Yes | Per grant, in `results[].code`: storing the grant would exceed the grants allowed per principal. |
| `messaging/mux/grant` | `messaging/mux/grant:contended` | Yes | Per grant, in `results[].code`: the member DID's record changed under concurrent writes too many times for the grant to be committed. Nothing was stored; resubmit the same statement. |
| `messaging/mux/list` | `messaging/mux:memberNotProven` | No | The request asks as `member` for a DID the requester neither is nor holds a live session attach of on the connection that carried the request. |
| `messaging/mux/list` | `messaging/mux/list:cursorInvalid` | No | `cursor` was not issued by this mediator for this requester and these request members. |
| `messaging/mux/revoke-all` | `messaging/mux:proofPurposeInvalid` | No | The embedded proof's `proofPurpose` is not `authentication`. |
| `messaging/mux/revoke-all` | `messaging/mux:statementProofInvalid` | No | The embedded Data Integrity proof does not verify — a bad signature, a verification method not controlled by the statement's `issuer`, or one not in the issuer's current `authentication` relationship. |
| `messaging/mux/revoke-all` | `messaging/mux:didUnresolvable` | Yes | The member DID could not be resolved now, so the statement could not be checked. Retry later. |
| `messaging/mux/revoke-all` | `messaging/mux:audienceMismatch` | No | The statement's `audience` is not this mediator's DID. |
| `messaging/mux/revoke-all` | `messaging/mux:notYetValid` | No | The statement's `iat` is more than 60 seconds in the mediator's future. |
| `messaging/mux/revoke-all` | `messaging/mux:statementExpired` | No | The statement's `exp` has passed. |
| `messaging/mux/revoke-all` | `messaging/mux:lifetimeTooLong` | No | The statement's `exp` lies further after `iat` than the mediator accepts for a revoke-all statement. |
| `messaging/mux/revoke-all` | `messaging/mux/revoke-all:epochMismatch` | No | The statement names an epoch later than the member DID's current one. `details.currentEpoch` carries the epoch in force; re-sign under it. |
| `messaging/mux/revoke-all` | `messaging/mux/revoke-all:contended` | Yes | The member DID's record changed under concurrent writes too many times for the epoch advance to be committed. Nothing changed; send the request again. |
| `messaging/mux/revoke` | `messaging/mux:memberNotProven` | No | The request revokes as `member` for a DID the requester neither is nor holds a live session attach of on the connection that carried the request. |
| `messaging/mux/revoke` | `messaging/mux/revoke:contended` | Yes | A member DID's record changed under concurrent writes too many times for the revocation to be committed, and nothing was revoked. Send the request again. |
| `messaging/mux/update` | `messaging/mux/update:unknownGrant` | No | No grant with this identifier is held for which the requester is the principal, or the member (directly or through a live session attach). Conflates a grant that never existed, one that was removed, and one belonging to others. |
| `messaging/mux/update` | `messaging/mux/update:widenRequiresGrant` | No | The requested scope is not a subset of the grant's effective scope, or the requested expiry is later than its effective expiry. Widening needs a fresh grant signed by the member DID (messaging/mux/grant), which replaces this one. |
| `messaging/mux/update` | `messaging/mux/update:notActive` | No | The grant is `suspended`, `staleKey` or `epochRevoked` and cannot be narrowed. Recreate it with messaging/mux/grant. |
| `messaging/mux/update` | `messaging/mux/update:grantExpired` | No | The grant is past its effective expiry and cannot be narrowed. Recreate it with messaging/mux/grant. |
| `messaging/mux/update` | `messaging/mux/update:expiryNotInFuture` | No | The requested expiry is not in the future. To end a grant now, revoke it with messaging/mux/revoke. |
| `messaging/mux/update` | `messaging/mux/update:contended` | Yes | The member DID's record changed under concurrent writes too many times for the narrowing to be committed. Nothing changed; send the request again. |
| `messaging/queue/purge` | `messaging/queue/purge:unknownAccount` | No | The named account does not exist at this mediator. |
| `messaging/queue/purge` | `messaging/queue/purge:rootAdminRequired` | No | The target account holds the admin, rootAdmin, or mediator role, and purging a privileged account's queue requires the requester to be a rootAdmin. |
| `messaging/queue/status` | `messaging/queue/status:unknownAccount` | No | The named account does not exist at this mediator. |

### Codes the mediator receives

The mediator rings a device's push gateway with `push/wake/0.2` when a
`messaging/wake/request` qualifies. It never sends these codes; it reads them
in the gateway's answer to a ring.

| Task | Trust Task Code | Retryable? | What the mediator does |
| :--- | :-------------- | :--------: | :--------------------- |
| `push/wake` | `push/wake:unknownHandle` | No | Nothing: the account's handle is kept until the account sets another. |
| `push/wake` | `push/wake:notAllowed` | No | Stops ringing the handle (this mediator is not on its allowlist) until the account sets a handle again. The framework's `permissionDenied` is read the same way. |
| `push/wake` | `push/wake:tokenUnregistered` | No | Drops the account's handle. The gateway may also send it as the `tokenUnregistered` status of a `push/wake#response`, which is read the same way. |
