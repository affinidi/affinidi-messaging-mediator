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

/// How long a store or a delete holds a message before another caller may
/// take it over, in milliseconds. Well above any database response timeout,
/// so only a caller that died part-way loses its hold.
pub(crate) const STORE_LEASE_MS: u64 = 30_000;
pub(crate) const DELETE_LEASE_MS: u64 = 30_000;

/// Message slot, first step of a store. Writes the body and metadata and
/// marks the message `STORING` until [`RECORD_QUEUE_IDS`] completes the
/// store, so a delete can't run between the steps and leave queue entries
/// for a message that is gone. The sender is recorded here, before any
/// queue.
///
/// A message whose delete is in progress is refused with
/// `DELETE_IN_PROGRESS` (the caller reports the store as failed, never as
/// stored). A delete that died part-way, past its lease, is taken over: the
/// message is stored again and the enqueue steps re-queue whatever the
/// delete had released.
///
/// KEYS: body, metadata. ARGV: body, bytes, to, from (`ANONYMOUS` for none),
/// delete lease ms.
/// Returns 1 when newly written, 2 when an unfinished store (a retry, the
/// same message stored concurrently, or a taken-over delete) is resumed, and
/// 0 when the message is already fully stored for this recipient.
pub(crate) static STORE_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local meta = redis.call('HMGET', KEYS[2], 'TO', 'RECEIVE_ID', 'STORING', 'DELETING_AT')
local result = 1
if meta[1] then
    if meta[4] then
        if now_ms - tonumber(meta[4]) < tonumber(ARGV[5]) then
            return redis.error_reply('DELETE_IN_PROGRESS message is being deleted')
        end
        redis.call('HDEL', KEYS[2], 'DELETING', 'DELETING_AT')
        result = 2
    elseif meta[1] == ARGV[3] then
        if meta[2] and not meta[3] then
            return 0
        end
        result = 2
    end
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('HSET', KEYS[2], 'BYTES', ARGV[2], 'TO', ARGV[3],
    'TIMESTAMP', string.format('%d%03d', t[1], t[2] / 1000), 'STORING', now_ms)
if ARGV[4] ~= 'ANONYMOUS' then
    redis.call('HSET', KEYS[2], 'FROM', ARGV[4])
end
return result
"#,
    )
});

/// Recipient slot: count the message and add it to the inbox, once. A repeat
/// (a retry, or the same message stored twice at once) returns the id of the
/// first entry and counts nothing, the rule the library's `store_message`
/// keeps for the same recipient.
///
/// KEYS: account, inbox, inbox ids. ARGV: message hash, bytes, from, queue
/// maxlen (0 for none). Returns the inbox stream id.
pub(crate) static ENQUEUE_INBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[3], ARGV[1])
if queued then
    return queued
end
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_BYTES', ARGV[2])
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_COUNT', 1)
local t = redis.call('TIME')
local id = string.format('%d%03d', t[1], t[2] / 1000) .. '-*'
local maxlen = tonumber(ARGV[4])
if maxlen > 0 then
    id = redis.call('XADD', KEYS[2], 'MAXLEN', '~', maxlen, id,
        'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'FROM', ARGV[3])
else
    id = redis.call('XADD', KEYS[2], id, 'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'FROM', ARGV[3])
end
redis.call('HSET', KEYS[3], ARGV[1], id)
return id
"#,
    )
});

/// Sender slot: count the message per sender and per recipient, and add it
/// to the outbox, once, as [`ENQUEUE_INBOX`].
///
/// KEYS: account, per-recipient counts, outbox, outbox ids. ARGV: message
/// hash, bytes, to, queue maxlen (0 for none). Returns the outbox stream id.
pub(crate) static ENQUEUE_OUTBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[4], ARGV[1])
if queued then
    return queued
end
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_BYTES', ARGV[2])
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_COUNT', 1)
redis.call('HINCRBY', KEYS[2], ARGV[3], 1)
local t = redis.call('TIME')
local id = string.format('%d%03d', t[1], t[2] / 1000) .. '-*'
local maxlen = tonumber(ARGV[4])
if maxlen > 0 then
    id = redis.call('XADD', KEYS[3], 'MAXLEN', '~', maxlen, id,
        'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'TO', ARGV[3])
else
    id = redis.call('XADD', KEYS[3], id, 'MSG_ID', ARGV[1], 'BYTES', ARGV[2], 'TO', ARGV[3])
end
redis.call('HSET', KEYS[4], ARGV[1], id)
return id
"#,
    )
});

/// Message slot, last step of a store: record where the message sits in the
/// queues and clear `STORING`, which makes the message deletable. Refuses
/// (returns 0) when the message was deleted, or a delete took it over, in the
/// meantime: the store must then report failure, not success.
///
/// KEYS: metadata. ARGV: field/value pairs. Returns 1 when recorded.
pub(crate) static RECORD_QUEUE_IDS: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('EXISTS', KEYS[1]) == 0
    or redis.call('HEXISTS', KEYS[1], 'DELETING') == 1 then
    return 0
end
redis.call('HSET', KEYS[1], unpack(ARGV))
redis.call('HDEL', KEYS[1], 'STORING')
return 1
"#,
    )
});

/// Message slot, first step of a delete: check ownership, then take the
/// message for this delete alone. Errors match the library's
/// `delete_message`, plus two the caller waits out:
///
/// - `STORE_IN_PROGRESS`: a store hasn't finished queueing the message.
/// - `DELETE_IN_PROGRESS`: another delete holds it. When that delete
///   finishes the message is gone (NOT_FOUND), which is what the library
///   answers the second of two deletes.
///
/// A hold past its lease belongs to a caller that died part-way and is taken
/// over, so the message is never stuck.
///
/// KEYS: metadata. ARGV: message hash, requester, delete token, store lease
/// ms, delete lease ms, admin (optional).
/// Returns TO, FROM ("" for an anonymous sender) and BYTES.
pub(crate) static CLAIM_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local flat = redis.call('HGETALL', KEYS[1])
if #flat == 0 then
    return redis.error_reply('NOT_FOUND: message_hash (' .. ARGV[1] .. ')')
end
local meta = {}
for i = 1, #flat, 2 do
    meta[flat[i]] = flat[i + 1]
end
local is_owner = (meta.TO == ARGV[2]) or (meta.FROM == ARGV[2])
local is_admin = (#ARGV >= 6 and ARGV[2] == ARGV[6])
if not is_owner and not is_admin then
    return redis.error_reply('PERMISSION_DENIED: Requesting DID does not have ownership of this message')
end
if meta.BYTES == nil then
    return redis.error_reply('message (' .. ARGV[1] .. ') metadata did not contain BYTES field.')
end
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if meta.STORING and now_ms - tonumber(meta.STORING) < tonumber(ARGV[4]) then
    return redis.error_reply('STORE_IN_PROGRESS message is still being stored')
end
if meta.DELETING_AT and meta.DELETING ~= ARGV[3]
    and now_ms - tonumber(meta.DELETING_AT) < tonumber(ARGV[5]) then
    return redis.error_reply('DELETE_IN_PROGRESS message is being deleted')
end
redis.call('HSET', KEYS[1], 'DELETING', ARGV[3], 'DELETING_AT', now_ms)
redis.call('HDEL', KEYS[1], 'STORING')
return { meta.TO or '', meta.FROM or '', meta.BYTES }
"#,
    )
});

/// Message slot, last step of a delete: remove the message, but only while
/// this delete still holds it. A delete that lost its hold (it outlived its
/// lease and was taken over) removes nothing, so exactly one delete reports
/// the message removed.
///
/// KEYS: body, metadata. ARGV: delete token. Returns 1 when removed.
pub(crate) static FINISH_DELETE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('HGET', KEYS[2], 'DELETING') ~= ARGV[1] then
    return 0
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"#,
    )
});

/// Recipient slot of a delete: release the counters and the inbox entry,
/// found by message hash in this slot. Releases nothing when the message was
/// never queued here, so counters only move back what they moved forward.
///
/// KEYS: account, inbox, inbox ids. ARGV: message hash, bytes.
pub(crate) static RELEASE_INBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[3], ARGV[1])
if not queued then
    return 0
end
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_BYTES', -tonumber(ARGV[2]))
redis.call('HINCRBY', KEYS[1], 'RECEIVE_QUEUE_COUNT', -1)
redis.call('XDEL', KEYS[2], queued)
redis.call('HDEL', KEYS[3], ARGV[1])
return 1
"#,
    )
});

/// Sender slot of a delete: release the counters, the per-recipient count
/// (dropped at zero) and the outbox entry, as [`RELEASE_INBOX`].
///
/// KEYS: account, per-recipient counts, outbox, outbox ids. ARGV: message
/// hash, bytes, to.
pub(crate) static RELEASE_OUTBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[4], ARGV[1])
if not queued then
    return 0
end
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_BYTES', -tonumber(ARGV[2]))
redis.call('HINCRBY', KEYS[1], 'SEND_QUEUE_COUNT', -1)
if tonumber(redis.call('HINCRBY', KEYS[2], ARGV[3], -1)) <= 0 then
    redis.call('HDEL', KEYS[2], ARGV[3])
end
redis.call('XDEL', KEYS[3], queued)
redis.call('HDEL', KEYS[4], ARGV[1])
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
