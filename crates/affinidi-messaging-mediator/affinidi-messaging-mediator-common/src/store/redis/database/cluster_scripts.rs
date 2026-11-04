//! Lua scripts used in place of the `atm-functions.lua` library when
//! `cluster_mode` is on.
//!
//! Cluster-mode servers (ElastiCache Serverless among them) offer no
//! `FUNCTION`/`FCALL`, and a script may only touch keys it declares, all in
//! one slot. So each library function becomes a few scripts, one per slot,
//! that the Rust caller runs in a crash-safe order. Scripts are sent with
//! `EVALSHA` and reloaded on `NOSCRIPT` by [`redis::Script`].

use redis::Script;
use std::sync::LazyLock;

/// Message slot, first step of a store. Writes the body and metadata unless
/// the message is already fully stored for this recipient.
///
/// KEYS: body, metadata. ARGV: body, bytes, to. Returns 1 when written, 0
/// when already stored.
pub(crate) static STORE_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('HGET', KEYS[2], 'TO') == ARGV[3]
    and redis.call('HEXISTS', KEYS[2], 'RECEIVE_ID') == 1 then
    return 0
end
local t = redis.call('TIME')
local now = string.format('%d%03d', t[1], t[2] / 1000)
redis.call('SET', KEYS[1], ARGV[1])
redis.call('HSET', KEYS[2], 'BYTES', ARGV[2], 'TO', ARGV[3], 'TIMESTAMP', now)
return 1
"#,
    )
});

/// Recipient slot: count the message and add it to the inbox.
///
/// KEYS: account, inbox. ARGV: message hash, bytes, from, queue maxlen (0 for
/// none). Returns the inbox stream id.
pub(crate) static ENQUEUE_INBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_BYTES', ARGV[2])
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_COUNT', 1)
local t = redis.call('TIME')
local id = string.format('%d%03d', t[1], t[2] / 1000) .. '-*'
local maxlen = tonumber(ARGV[4])
if maxlen > 0 then
    return redis.call('XADD', KEYS[2], 'MAXLEN', '~', maxlen, id,
        'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'FROM', ARGV[3])
end
return redis.call('XADD', KEYS[2], id, 'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'FROM', ARGV[3])
"#,
    )
});

/// Sender slot: count the message per sender and per recipient, and add it
/// to the outbox.
///
/// KEYS: account, per-recipient counts, outbox. ARGV: message hash, bytes,
/// to, queue maxlen (0 for none). Returns the outbox stream id.
pub(crate) static ENQUEUE_OUTBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_BYTES', ARGV[2])
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_COUNT', 1)
redis.call('HINCRBY', KEYS[2], ARGV[3], 1)
local t = redis.call('TIME')
local id = string.format('%d%03d', t[1], t[2] / 1000) .. '-*'
local maxlen = tonumber(ARGV[4])
if maxlen > 0 then
    return redis.call('XADD', KEYS[3], 'MAXLEN', '~', maxlen, id,
        'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'TO', ARGV[3])
end
return redis.call('XADD', KEYS[3], id, 'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'TO', ARGV[3])
"#,
    )
});

/// Message slot, last step of a store: record where the message sits in the
/// queues. Skips a message deleted in the meantime rather than recreating
/// its metadata.
///
/// KEYS: metadata. ARGV: field/value pairs. Returns 1 when recorded.
pub(crate) static RECORD_QUEUE_IDS: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('EXISTS', KEYS[1]) == 0 then
    return 0
end
redis.call('HSET', KEYS[1], unpack(ARGV))
return 1
"#,
    )
});

/// Message slot, first step of a delete: check ownership, then remove the
/// message. Removing it here, before any counter moves, means a repeated
/// delete finds nothing and cannot release the counters twice. Errors match
/// the library's `delete_message`.
///
/// KEYS: body, metadata. ARGV: message hash, requester, admin (optional).
/// Returns TO, FROM, BYTES, RECEIVE_ID, SEND_ID ("" when absent).
pub(crate) static CLAIM_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local flat = redis.call('HGETALL', KEYS[2])
if #flat == 0 then
    return redis.error_reply('NOT_FOUND: message_hash (' .. ARGV[1] .. ')')
end
local meta = {}
for i = 1, #flat, 2 do
    meta[flat[i]] = flat[i + 1]
end
local is_owner = (meta.TO == ARGV[2]) or (meta.FROM == ARGV[2])
local is_admin = (#ARGV >= 3 and ARGV[2] == ARGV[3])
if not is_owner and not is_admin then
    return redis.error_reply('PERMISSION_DENIED: Requesting DID does not have ownership of this message')
end
if meta.BYTES == nil then
    return redis.error_reply('message (' .. ARGV[1] .. ') metadata did not contain BYTES field.')
end
redis.call('DEL', KEYS[1], KEYS[2])
return { meta.TO or '', meta.FROM or '', meta.BYTES, meta.RECEIVE_ID or '', meta.SEND_ID or '' }
"#,
    )
});

/// Recipient slot of a delete: release the counters and the inbox entry.
///
/// KEYS: account, inbox. ARGV: bytes, inbox stream id ("" when unknown).
pub(crate) static RELEASE_INBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_BYTES', -tonumber(ARGV[1]))
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_COUNT', -1)
if ARGV[2] ~= '' then
    redis.call('XDEL', KEYS[2], ARGV[2])
end
return 1
"#,
    )
});

/// Sender slot of a delete: release the counters, the per-recipient count
/// (dropped at zero) and the outbox entry.
///
/// KEYS: account, per-recipient counts, outbox. ARGV: bytes, to, outbox
/// stream id.
pub(crate) static RELEASE_OUTBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_BYTES', -tonumber(ARGV[1]))
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_COUNT', -1)
if tonumber(redis.call('HINCRBY', KEYS[2], ARGV[2], -1)) <= 0 then
    redis.call('HDEL', KEYS[2], ARGV[2])
end
redis.call('XDEL', KEYS[3], ARGV[3])
return 1
"#,
    )
});

/// Streaming slot: drop one mediator instance's streaming sessions from the
/// global registry, in batches of 500 as the library does.
///
/// KEYS: the instance's sessions, the global registry. Returns the number
/// removed.
pub(crate) static CLEAN_START_STREAMING: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local count = 0
while count < 500 do
    local popped = redis.call('SPOP', KEYS[1], 1)
    if #popped == 0 then
        break
    end
    redis.call('HDEL', KEYS[2], popped[1])
    count = count + 1
end
return count
"#,
    )
});
