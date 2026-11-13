//! Error code registry for the Affinidi Messaging Mediator.
//!
//! Every numeric error code the mediator (and its storage and processors)
//! raises is a constant here. Handlers use these constants, never integer
//! literals; `ERRORS.md` lists every one with the problem codes it is sent
//! under, and a test in the mediator crate fails when either drifts.
//!
//! A number means one condition. Where one number used to cover several
//! (37, 44, 28, 38, 58, 60, 10), the extra conditions moved to 100–111.
//!
//! ## Ranges
//!
//! | Range   | Category |
//! |---------|----------|
//! | 0–24    | Infrastructure, storage, configuration, internal state |
//! | 25–39   | Authentication and sessions |
//! | 40–45   | Authorization and REST API limits |
//! | 46–48   | OOB, packing, the mediator's own DID |
//! | 49–55   | Message Pickup |
//! | 56–70   | Forwarding and routing |
//! | 71–79   | Delivery and headers |
//! | 80–84   | Retired DIDComm admin protocols (no longer returned) |
//! | 85–99   | Message checks, forwarding queue, storage caps |
//! | 100–119 | Conditions split out of overloaded codes |
//! | 120–139 | Trust Task refusals ([`trust_task_code`]) |
//!
//! Trust Task refusals carry a Trust Task error code on the wire (the
//! framework's standard codes, SPEC §8.3, or a `<task>:<code>` a task's
//! specification declares), in a `trust-task-error` document or, where no
//! document can be sent, as the problem code `e.p.<code>`. The number is the
//! mediator's own, for logs and REST error bodies.

// ── Infrastructure and storage ────────────────────────────────────────────

/// Internal error raised by a background processor. Never sent to a client.
pub const PROCESSOR_ERROR: u16 = 0;

/// Incorrect database URL in the mediator configuration. Problem code
/// `e.p.me.res.storage.url`.
pub const DB_URL_INVALID: u16 = 1;

/// Database configuration is invalid, or the database functions (Lua)
/// couldn't be loaded. Problem code `e.p.me.res.storage.config`.
pub const DB_CONFIG_INVALID: u16 = 2;

/// A connection to the database couldn't be made (including the blocking
/// connection used for streaming). Problem code
/// `e.p.me.res.storage.connection`, `e.p.me.res.storage.connection.blocking`.
pub const DB_CONNECTION_ERROR: u16 = 3;

/// Couldn't open a database connection for pub/sub. Problem code
/// `e.p.me.res.storage.connection.pubsub`.
pub const DB_PUBSUB_CONNECTION_ERROR: u16 = 4;

/// Couldn't get a receiver for the pub/sub connection. Problem code
/// `e.p.me.res.storage.connection.pubsub.receiver`.
pub const DB_PUBSUB_RECEIVER_ERROR: u16 = 5;

/// Querying database server information failed. Problem code
/// `e.p.me.res.storage.info`.
pub const DB_SERVER_INFO_ERROR: u16 = 6;

/// Can't parse the database server version. Problem code
/// `e.p.me.res.storage.version`.
pub const DB_VERSION_PARSE_ERROR: u16 = 7;

/// The database server version is not supported. Problem code
/// `e.p.me.res.storage.version.incompatible`.
pub const DB_VERSION_INCOMPATIBLE: u16 = 8;

/// Couldn't determine the database server version. Problem code
/// `e.p.me.res.storage.version.unknown`.
pub const DB_VERSION_UNKNOWN: u16 = 9;

/// Deleting a message from the database failed. Problem code
/// `w.m.database.message.delete.error`.
pub const DB_DELETE_ERROR: u16 = 10;

/// No longer returned; a delete that fails is 10. Problem code
/// `w.m.database.message.delete.status`.
pub const DB_DELETE_STATUS_ERROR: u16 = 11;

// ── Configuration and internal state ──────────────────────────────────────

/// Mediator configuration problem, found while starting or reloading. Problem
/// code `e.p.me.config.initialization`.
pub const CONFIG_ERROR: u16 = 12;

/// Couldn't set or read the database schema version (at startup). Problem
/// code `e.p.me.res.storage.schema`.
pub const DB_SCHEMA_VERSION_ERROR: u16 = 13;

/// A database operation failed. Problem code `w.m.me.res.storage.error`,
/// `e.p.me.res.storage.error`.
pub const DB_OPERATION_ERROR: u16 = 14;

/// At most 100 admin accounts can be added at a time. Problem code
/// `w.m.database.admin.accounts.add.limit`.
pub const ADMIN_ACCOUNTS_ADD_LIMIT: u16 = 15;

/// At most 100 admin accounts can be stripped at a time. Problem code
/// `w.m.database.admin.accounts.strip.limit`.
pub const ADMIN_ACCOUNTS_STRIP_LIMIT: u16 = 16;

/// Internal error (unexpected state, a value that couldn't be converted). The
/// detail is logged, not returned.
pub const INTERNAL_ERROR: u16 = 17;

/// Tried to remove a protected account (the mediator or a root admin).
/// Problem code `w.m.database.account.remove.protected`.
pub const PROTECTED_ACCOUNT_ERROR: u16 = 18;

/// A request body or DIDComm message couldn't be serialised or deserialised.
/// Problem code `w.m.message.serialize`, `e.p.message.serialize`,
/// `e.p.message.deserialize`.
pub const PARSE_ERROR: u16 = 19;

/// Session record is missing a field or is corrupt (restart authentication).
/// Problem code `e.p.database.session.invalid.state`.
pub const SESSION_INVALID_STATE: u16 = 20;

/// Can't parse a record read from the database (statistics, inbox status,
/// message lists). Problem code `e.p.database.stats.parse`.
pub const DB_PARSE_ERROR: u16 = 21;

/// Can't parse message metadata in the database. Problem code
/// `e.p.database.message.metadata`.
pub const DB_METADATA_PARSE_ERROR: u16 = 22;

/// Initial reset of the pub/sub system failed at startup. Problem code
/// `e.p.me.res.storage.pubsub.clean_start`.
pub const DB_PUBSUB_CLEAN_START: u16 = 23;

/// Couldn't serialise a pub/sub record. Problem code
/// `e.p.me.res.storage.pubsub.publish`.
pub const DB_PUBSUB_PUBLISH: u16 = 24;

// ── Authentication and sessions ───────────────────────────────────────────

/// The DID is blocked from using the mediator. Problem code
/// `e.p.authentication.blocked`, `e.m.authorization.blocked`.
pub const AUTH_DID_BLOCKED: u16 = 25;

/// Couldn't parse a DID's stored ACL flags. Problem code
/// `w.m.database.acl.get.parse`.
pub const ACL_PARSE_ERROR: u16 = 26;

/// At most 100 DIDs can be fetched at a time. Problem code
/// `w.m.database.acl.get_dids.limit`.
pub const ACL_GET_DIDS_LIMIT: u16 = 27;

/// Couldn't parse the authentication response (restart authentication).
/// Problem code `e.p.authentication.response.parse`.
pub const AUTH_RESPONSE_PARSE: u16 = 28;

/// The DID (or TSP VID) to authenticate is missing or not a valid DID.
/// Problem code `e.p.authentication.response.from`,
/// `e.p.authentication.challenge.invalid_did`,
/// `e.p.authentication.tsp.invalid_vid`.
pub const AUTH_INVALID_DID: u16 = 29;

/// DIDComm message type is missing or incorrect. Problem code
/// `e.p.message.type.incorrect`.
pub const MESSAGE_TYPE_INCORRECT: u16 = 30;

/// DIDComm message has expired. Problem code `e.p.message.expired`.
pub const MESSAGE_EXPIRED: u16 = 31;

/// The message couldn't be unpacked or its signature didn't verify (TSP
/// authentication: 401). Problem code `e.p.message.unpack`,
/// `e.p.authentication.tsp.signature.invalid`.
pub const MESSAGE_UNPACK_FAILED: u16 = 32;

/// DIDs do not match throughout the authentication process (401 on TSP
/// authentication). Problem code `e.p.authentication.session.mismatch`.
pub const AUTH_SESSION_MISMATCH: u16 = 33;

/// Authentication session is invalid or in the wrong state (restart
/// authentication; 401 where the session is unknown). Problem code
/// `e.p.authentication.session.invalid`, `e.p.authentication.session.state`.
pub const AUTH_SESSION_INVALID: u16 = 34;

/// Couldn't create a JWT access token. Problem code
/// `e.p.authentication.session.access_token`.
pub const AUTH_ACCESS_TOKEN_ERROR: u16 = 35;

/// Couldn't create a JWT refresh token. Problem code
/// `e.p.authentication.session.refresh_token`.
pub const AUTH_REFRESH_TOKEN_ERROR: u16 = 36;

/// Couldn't read the message envelope (DIDComm, or a TSP envelope or route).
/// Problem code `e.p.message.envelope.read`, `e.p.message.tsp.malformed`,
/// `e.p.message.tsp.route`, `e.p.message.tsp.unpack`,
/// `e.p.message.bridge.malformed`.
pub const MESSAGE_ENVELOPE_READ: u16 = 37;

/// Couldn't parse the JWT refresh token, or it is not a refresh token.
/// Problem code `e.p.authentication.session.refresh_token.parse`.
pub const REFRESH_TOKEN_PARSE: u16 = 38;

/// Refresh request is missing a `from` header. Problem code
/// `e.p.authentication.message.from.missing`.
pub const AUTH_FROM_MISSING: u16 = 39;

// ── Authorization and REST API limits ─────────────────────────────────────

/// DID is not local to the mediator. Problem code `e.p.authorization.local`.
pub const AUTH_NOT_LOCAL: u16 = 40;

/// Invalid number of messages requested from `/fetch` (1 to
/// `limits.listed_messages`). Problem code `e.p.api.inbox_fetch.limit`.
pub const API_INBOX_FETCH_LIMIT: u16 = 41;

/// Invalid `start_id`: a UNIX epoch timestamp in milliseconds followed by
/// `-(0-999)`. Problem code `e.p.api.inbox_fetch.start_id`.
pub const API_INBOX_FETCH_START_ID: u16 = 42;

/// Invalid number of messages to delete (1 to `limits.deleted_messages`).
/// Problem code `e.p.api.message_delete.limit`.
pub const API_MESSAGE_DELETE_LIMIT: u16 = 43;

/// DID may not send messages. Problem code `e.p.authorization.send`.
pub const AUTH_SEND_DENIED: u16 = 44;

/// DID does not have permission to access the requested resource. Problem
/// code `e.p.authorization.permission`.
pub const AUTH_PERMISSION_DENIED: u16 = 45;

// ── Message handling ──────────────────────────────────────────────────────

/// Couldn't store an Out-Of-Band (OOB) invitation. Problem code
/// `e.p.oob.store`.
pub const OOB_STORE_ERROR: u16 = 46;

/// Couldn't pack (DIDComm) or seal (TSP) a message. 400 when the recipient's
/// DID document gives no usable key. Problem code `e.p.message.pack`,
/// `e.p.message.tsp.reseal`, `e.p.message.tsp.trust_task.serialize`,
/// `e.p.message.tsp.trust_task.seal`, `e.m.message.didcomm_v1.build`,
/// `e.m.message.didcomm_v1.pack`.
pub const MESSAGE_PACK_ERROR: u16 = 47;

/// Mediator DID Document configuration is missing. Problem code
/// `e.p.me.did.missing`.
pub const MEDIATOR_DID_MISSING: u16 = 48;

// ── Message Pickup ────────────────────────────────────────────────────────

/// Message Pickup message is missing `return_route`, or it is incorrect.
/// Problem code `w.m.protocol.pickup.return_route`.
pub const PICKUP_RETURN_ROUTE_ERROR: u16 = 49;

/// The message is anonymous, and this transaction requires a sender (403
/// where an anonymous sender is refused). Problem code
/// `w.m.message.anonymous`.
pub const ANON_MESSAGE_ERROR: u16 = 50;

/// There was a problem with the message `to` header (422 when it names more
/// than one recipient). Problem code `w.m.message.to`.
pub const INVALID_TO_HEADER: u16 = 51;

/// Message DID and session DID differ where they must match. Problem code
/// `e.p.authorization.did.session_mismatch`.
pub const SESSION_DID_MISMATCH: u16 = 52;

/// Message Pickup limit must be from 1 to 100; a `messages-received` names at
/// most 100 ids. Problem code `w.m.protocol.pickup.delivery_request.limit`,
/// `w.m.protocol.pickup.messages_received.limit`.
pub const INVALID_LIMIT: u16 = 53;

/// Couldn't parse the Message Pickup message body. Problem code
/// `w.m.protocol.pickup.parse`.
pub const MESSAGE_BODY_PARSE_ERROR: u16 = 54;

/// Live streaming couldn't be enabled or disabled; 501 when live delivery is
/// asked for on a mediator without streaming. Problem code
/// `e.p.protocol.pickup.live_streaming`.
pub const STREAMING_SIGNAL_ERROR: u16 = 55;

// ── Forwarding and routing ────────────────────────────────────────────────

/// Forward message is missing its `next` field. Problem code
/// `w.m.protocol.forwarding.next.missing`.
pub const FORWARD_MISSING_NEXT: u16 = 56;

/// Couldn't parse the forward message body. Problem code
/// `w.m.protocol.forwarding.parse`.
pub const FORWARD_PARSE_ERROR: u16 = 57;

/// TSP next hop publishes no TSP endpoint. Problem code
/// `e.p.message.tsp.no_endpoint`.
pub const TSP_NO_ENDPOINT: u16 = 58;

/// The forward message has no attachments. Problem code
/// `w.m.protocol.forwarding.attachments.missing`.
pub const FORWARD_MISSING_ATTACHMENTS: u16 = 59;

/// Sender may not send forwarded (relayed) messages, over DIDComm or TSP.
/// Problem code `e.p.authorization.send_forwarded`.
pub const FORWARD_SENDER_DENIED: u16 = 60;

/// Sender has too many messages waiting to be delivered. Problem code
/// `e.p.limits.queue.sender`.
pub const SENDER_QUEUE_FULL: u16 = 61;

/// Recipient has too many messages waiting to be delivered. Problem code
/// `e.p.limits.queue.recipient`.
pub const RECIPIENT_QUEUE_FULL: u16 = 62;

/// A forward carries exactly one attachment; this one has more. Problem code
/// `w.m.protocol.forwarding.attachments.too_many`.
pub const TOO_MANY_ATTACHMENTS: u16 = 63;

/// Mediator forwarding queue is full; try again later. Problem code
/// `e.p.me.res.forwarding.queue.limit`.
pub const FORWARD_QUEUE_FULL: u16 = 64;

/// Forward `delay_milli` is not a whole number from 0 to the configured
/// limit. Problem code `w.m.protocol.forwarding.delay_milli`.
pub const FORWARD_INVALID_DELAY: u16 = 65;

/// Feature is not implemented by the mediator (400 for an attachment form it
/// does not read). Problem code `e.p.me.not_implemented`.
pub const FEATURE_NOT_IMPLEMENTED: u16 = 66;

/// Attachment JSON is invalid, or the attachment type is unknown. Problem
/// code `w.m.protocol.forwarding.attachments.json.invalid`,
/// `w.m.protocol.forwarding.attachments.unknown`.
pub const INVALID_ATTACHMENT: u16 = 67;

/// Couldn't decode a base64 attachment. Problem code
/// `w.m.protocol.forwarding.attachments.base64`.
pub const ATTACHMENT_DECODE_ERROR: u16 = 68;

/// No longer returned; reported as 73. Problem code
/// `e.p.authorization.receive_anon`.
pub const ANON_DELIVERY_DENIED: u16 = 69;

/// No longer returned; a next hop that is this mediator is delivered locally,
/// and loops are 94. Problem code
/// `w.m.protocol.forwarding.next.mediator.self`.
pub const FORWARD_NEXT_IS_SELF: u16 = 70;

// ── Delivery ──────────────────────────────────────────────────────────────

/// Mediator is not accepting direct delivery; messages must be wrapped in a
/// forward. Problem code `w.m.direct_delivery.denied`,
/// `e.p.direct_delivery.denied`.
pub const DIRECT_DELIVERY_DISABLED: u16 = 71;

/// No longer returned; reported as 73. Problem code
/// `w.m.direct_delivery.recipient.unknown`.
pub const DIRECT_DELIVERY_UNKNOWN_RECIPIENT: u16 = 72;

/// Message not accepted for delivery: unknown or non-local recipient, missing
/// receive permission, or blocked by the access list. The reason is logged,
/// not returned. Problem code `e.p.delivery.refused`,
/// `e.p.authorization.access_list.denied`.
pub const DELIVERY_REFUSED: u16 = 73;

/// A DID couldn't be resolved. On a forward (503, retryable): the mediator
/// its next hop names. 400 when the recipient of a reply can't be resolved.
/// Problem code `e.p.did.resolve`.
pub const DID_RESOLVE_ERROR: u16 = 74;

/// There are no recipients for this message. Problem code
/// `e.p.message.recipients.missing`.
pub const MESSAGE_RECIPIENTS_MISSING: u16 = 75;

/// There are too many recipients for this message. Problem code
/// `e.p.message.recipients.too_many`.
pub const MESSAGE_RECIPIENTS_TOO_MANY: u16 = 76;

/// Internal error while storing the message. Problem code
/// `e.p.me.storage.message.error`.
pub const MESSAGE_STORE_ERROR: u16 = 77;

/// No longer returned; a failed subscribe is 14. Problem code
/// `e.p.me.res.storage.pubsub.subscribe`.
pub const DB_PUBSUB_SUBSCRIBE: u16 = 78;

// ── Headers and retired protocols ─────────────────────────────────────────

/// The `ephemeral` header isn't a JSON boolean. Treated as false; the message
/// is still sent. Problem code `w.m.message.header.ephemeral.invalid`.
pub const EPHEMERAL_HEADER_INVALID: u16 = 79;

/// No longer returned; the Trust Task is refused with
/// `messaging/account/update:selfChangeDenied`. Problem code
/// `w.m.protocol.acls.change.denied`.
pub const ACL_SELF_CHANGE_DENIED: u16 = 80;

/// No longer returned (the retired DIDComm accounts protocol). Problem code
/// `w.m.protocol.mediator.accounts.parse`.
pub const ACCOUNT_PARSE_ERROR: u16 = 81;

/// No longer returned (the retired DIDComm ACL protocol). Problem code
/// `w.m.protocol.mediator.acls.parse`.
pub const ACL_MESSAGE_PARSE_ERROR: u16 = 82;

/// No longer returned (the retired DIDComm administration protocol). Problem
/// code `w.m.protocol.mediator.administration.parse`.
pub const ADMIN_MESSAGE_PARSE_ERROR: u16 = 83;

/// No longer returned (the retired DIDComm administration protocol). Problem
/// code `w.m.protocol.mediator.administration.strip.missing`.
pub const ADMIN_STRIP_MISSING: u16 = 84;

// ── Message checks, OOB, discovery ────────────────────────────────────────

/// The plaintext `from` does not match the signing or encrypting DID. Problem
/// code `e.p.message.from.incorrect`.
pub const MESSAGE_FROM_INCORRECT: u16 = 85;

/// The DIDComm message must be signed and encrypted for this transaction.
/// Problem code `e.p.authentication.message.not_signed_or_encrypted`.
pub const AUTH_NOT_SIGNED_OR_ENCRYPTED: u16 = 86;

/// Retrieving an OOB invitation failed internally. Problem code
/// `e.p.oob.retrieve`.
pub const OOB_RETRIEVE_ERROR: u16 = 87;

/// A Discover Features disclose was sent to the mediator, which does not read
/// disclosures sent to itself. Problem code `e.p.me.not_implemented`.
pub const DISCLOSE_NOT_READ: u16 = 88;

/// Couldn't parse the Discover Features queries. Problem code
/// `w.m.protocol.discover_features.queries.parse`.
pub const DISCOVER_FEATURES_PARSE: u16 = 89;

// ── Forwarding queue and limits ───────────────────────────────────────────

/// Couldn't enqueue a message for remote forwarding. Problem code
/// `e.p.me.res.forwarding.enqueue`, `e.p.message.tsp.forward.enqueue`.
pub const FORWARD_ENQUEUE_ERROR: u16 = 90;

/// Admin messages must include a `created_time` header. Problem code
/// `e.p.message.created_time.missing`.
pub const ADMIN_MISSING_CREATED_TIME: u16 = 91;

/// Authentication messages must include an `expires_time` header. Problem
/// code `e.p.message.expires_time.missing`.
pub const EXPIRES_TIME_MISSING: u16 = 92;

/// Access list batch must contain 1 to 100 entries. Problem code
/// `e.p.protocol.mediator.access_list.limit`.
pub const ACCESS_LIST_BATCH_SIZE_ERROR: u16 = 93;

/// Forward exceeded `max_hops`, or its next hop resolves back to this
/// mediator. Problem code `e.p.protocol.forwarding.loop_detected`.
pub const FORWARD_LOOP_DETECTED: u16 = 94;

/// Too many messages already waiting from this sender for this recipient.
/// Problem code `e.p.limits.queue.peer`.
pub const PEER_QUEUE_FULL: u16 = 95;

/// The message's `from` is not the DID that authenticated the message (its
/// signer or authcrypt sender) where the two must agree. Problem code
/// `e.p.authorization.sender.mismatch`.
pub const SENDER_MISMATCH: u16 = 96;

// ── Storage caps and live delivery ────────────────────────────────────────

/// Mediator storage is full (data storage maximum reached); retry once space
/// is freed. A cache that evicts first (ElastiCache Serverless) drops keys
/// with a TTL (sessions, invites, receipts) before this error. Problem code
/// `e.m.me.res.storage.full`.
pub const STORAGE_FULL: u16 = 97;

/// Mediator storage is busy or unreachable (a command timed out, e.g.
/// throttled at its ECPU maximum), or in cluster mode another store or delete
/// of the same message still holds it; retry later. Problem code
/// `w.m.me.res.storage.busy`.
pub const STORAGE_BUSY: u16 = 98;

/// An ephemeral forward's recipient has no live stream: the message was not
/// delivered and is not queued. Retry later, or send it non-ephemeral.
/// Problem code `w.m.delivery.not_live`.
pub const DELIVERY_NOT_LIVE: u16 = 99;

// ── Split from overloaded codes (0.53) ────────────────────────────────────

/// The message is larger than the mediator accepts (was 37). Problem code
/// `e.m.message.size.exceeded`.
pub const MESSAGE_SIZE_EXCEEDED: u16 = 100;

/// The message's protocol or type is not one the mediator serves (was 37).
/// Problem code `e.p.protocol.unsupported`, `e.p.message.tsp.unsupported`,
/// `e.m.message.didcomm_v1.unsupported`.
pub const PROTOCOL_UNSUPPORTED: u16 = 101;

/// A DIDComm v1 message the mediator can't act on: unreadable, not a forward
/// where one is required, or a malformed coordinate-mediation or pickup
/// request (was 37). Problem code `e.m.message.didcomm_v1.malformed`,
/// `e.m.message.didcomm_v1.unpack`, `e.m.message.didcomm_v1.payload`,
/// `e.m.message.didcomm_v1.unexpected`, `e.m.message.didcomm_v1.not_forward`,
/// `e.m.message.didcomm_v1.destination`, `e.m.message.didcomm_v1.keylist`,
/// `e.m.message.didcomm_v1.messages_received`,
/// `e.m.message.didcomm_v1.anonymous_request`.
pub const DIDCOMM_V1_MALFORMED: u16 = 102;

/// TSP authentication: the VID couldn't be resolved, or the signature is not
/// valid base64url Ed25519 (was 28). Problem code
/// `e.p.authentication.tsp.resolve`,
/// `e.p.authentication.tsp.signature.encoding`,
/// `e.p.authentication.tsp.signature.length`.
pub const AUTH_TSP_STATEMENT_INVALID: u16 = 103;

/// The JWT refresh token has expired; authenticate again (was 38). Problem
/// code `e.p.authentication.session.refresh_token.expired`.
pub const REFRESH_TOKEN_EXPIRED: u16 = 104;

/// A refresh token was used twice; the session is revoked (was 38). Problem
/// code `e.p.authentication.session.refresh_token.reuse`.
pub const REFRESH_TOKEN_REUSE: u16 = 105;

/// An anonymous session may send nothing but a DIDComm v1 forward (was 44).
/// Problem code `e.p.authorization.authentication_required`.
pub const AUTHENTICATION_REQUIRED: u16 = 106;

/// Invalid number of messages requested from `/outbound` (was 43). Problem
/// code `e.p.api.message_outbound.limit`.
pub const API_MESSAGE_OUTBOUND_LIMIT: u16 = 107;

/// TSP next hop, or the mediator it names, couldn't be resolved (was 58).
/// Problem code `e.p.message.tsp.resolve`,
/// `e.p.message.tsp.mediator.unresolvable`.
pub const TSP_NEXT_HOP_UNRESOLVABLE: u16 = 108;

/// Relaying peer mediator is not in `relay_trusted_mediators` (was 60).
/// Problem code `e.p.authorization.relay.untrusted_peer`.
pub const RELAY_UNTRUSTED_PEER: u16 = 109;

/// The message to delete is not there (it may already be deleted) (was 10).
/// Problem code `w.m.database.message.delete.not_found`.
pub const MESSAGE_NOT_FOUND: u16 = 110;

/// The requester is not a party to the message it asked to delete (was 10).
/// Problem code `w.m.database.message.delete.permission_denied`.
pub const MESSAGE_DELETE_DENIED: u16 = 111;

// ── Trust Task refusals ──────────────────────────────────────────────────

/// Trust Task `malformedRequest`: The document, its payload or a value in it
/// (an ACL, a cursor, a queue limit) is not valid for the task.
pub const TT_MALFORMED_REQUEST: u16 = 120;

/// Trust Task `unsupportedType`: The mediator does not serve this Trust Task
/// type (or mux tasks while mux is off).
pub const TT_UNSUPPORTED_TYPE: u16 = 121;

/// Trust Task `unsupportedVersion`: The type is served, but not at this
/// version.
pub const TT_UNSUPPORTED_VERSION: u16 = 122;

/// Trust Task `expired`: `expiresAt` has passed, or the document is outside
/// the acceptance window.
pub const TT_EXPIRED: u16 = 123;

/// Trust Task `proofRequired`: The task requires a `proof` and the document
/// has none.
pub const TT_PROOF_REQUIRED: u16 = 124;

/// Trust Task `proofInvalid`: The `proof` did not verify.
pub const TT_PROOF_INVALID: u16 = 125;

/// Trust Task `permissionDenied`: The requester may not invoke the task, or
/// not on this target.
pub const TT_PERMISSION_DENIED: u16 = 126;

/// Trust Task `wrongRecipient`: The document's `recipient` is not this
/// mediator.
pub const TT_WRONG_RECIPIENT: u16 = 127;

/// Trust Task `identityMismatch`: The in-band `issuer` is not the transport-
/// authenticated sender.
pub const TT_IDENTITY_MISMATCH: u16 = 128;

/// Trust Task `idConflict`: The document's `id` was already accepted (with
/// the same or different content).
pub const TT_ID_CONFLICT: u16 = 129;

/// Trust Task `cancelled`: Not used by the mediator.
pub const TT_CANCELLED: u16 = 130;

/// Trust Task `taskFailed`: The task was attempted and could not be completed
/// (a configuration that would not reload).
pub const TT_TASK_FAILED: u16 = 131;

/// Trust Task `unavailable`: The mediator can't process the task now (storage
/// busy or full, no queue survey yet, nothing to reload). Retryable.
pub const TT_UNAVAILABLE: u16 = 132;

/// Trust Task `internalError`: An internal failure. The detail is logged, not
/// returned.
pub const TT_INTERNAL_ERROR: u16 = 133;

/// Trust Task `unsupportedExtension`: Not used by the mediator.
pub const TT_UNSUPPORTED_EXTENSION: u16 = 134;

/// Trust Task `indeterminate`: Not used by the mediator.
pub const TT_INDETERMINATE: u16 = 135;

/// A `<task>:<code>` a Trust Task specification declares (see the list
/// below).
pub const TT_DECLARED: u16 = 139;

/// The framework's standard Trust Task error codes (SPEC §8.3) and their
/// numbers, in the order the specification lists them.
pub const TRUST_TASK_STANDARD_CODES: &[(&str, u16)] = &[
    ("malformedRequest", TT_MALFORMED_REQUEST),
    ("unsupportedType", TT_UNSUPPORTED_TYPE),
    ("unsupportedVersion", TT_UNSUPPORTED_VERSION),
    ("expired", TT_EXPIRED),
    ("proofRequired", TT_PROOF_REQUIRED),
    ("proofInvalid", TT_PROOF_INVALID),
    ("permissionDenied", TT_PERMISSION_DENIED),
    ("wrongRecipient", TT_WRONG_RECIPIENT),
    ("identityMismatch", TT_IDENTITY_MISMATCH),
    ("idConflict", TT_ID_CONFLICT),
    ("cancelled", TT_CANCELLED),
    ("taskFailed", TT_TASK_FAILED),
    ("unavailable", TT_UNAVAILABLE),
    ("internalError", TT_INTERNAL_ERROR),
    ("unsupportedExtension", TT_UNSUPPORTED_EXTENSION),
    ("indeterminate", TT_INDETERMINATE),
];

/// The number for a Trust Task error code: its standard code's number, or
/// [`TT_DECLARED`] for a `<task>:<code>` a specification declares. `None`
/// for anything else, which is not a Trust Task code.
pub fn trust_task_code(code: &str) -> Option<u16> {
    if let Some((_, n)) = TRUST_TASK_STANDARD_CODES.iter().find(|(c, _)| *c == code) {
        return Some(*n);
    }
    let (slug, local) = code.split_once(':')?;
    let declared = !slug.is_empty()
        && slug.split('/').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && local.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && local.bytes().all(|b| b.is_ascii_alphanumeric());
    declared.then_some(TT_DECLARED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_codes_have_their_own_numbers() {
        assert_eq!(
            trust_task_code("malformedRequest"),
            Some(TT_MALFORMED_REQUEST)
        );
        assert_eq!(
            trust_task_code("permissionDenied"),
            Some(TT_PERMISSION_DENIED)
        );
        assert_eq!(trust_task_code("unavailable"), Some(TT_UNAVAILABLE));
    }

    #[test]
    fn a_declared_code_is_tt_declared() {
        for code in [
            "messaging/account/get:unknownAccount",
            "messaging/mux:notMuxConnection",
            "audit/list:invalidCursor",
        ] {
            assert_eq!(trust_task_code(code), Some(TT_DECLARED), "{code}");
        }
    }

    #[test]
    fn a_mediator_code_is_not_a_trust_task_code() {
        for code in [
            "authorization.admin_required",
            "account.not_found",
            "message.trust_task.malformed",
            ":x",
            "a:",
            "Messaging/x:y",
        ] {
            assert_eq!(trust_task_code(code), None, "{code}");
        }
    }
}
