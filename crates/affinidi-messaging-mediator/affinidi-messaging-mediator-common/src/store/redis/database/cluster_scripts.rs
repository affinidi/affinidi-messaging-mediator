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
/// marks the message `STORING:<token>` until [`RECORD_QUEUE_IDS`] completes
/// this store, so a delete can't run between the steps and leave queue
/// entries for a message that is gone. One mark per store: the same message
/// stored twice at once stays held until both stores finish. The sender is
/// recorded here, before any queue.
///
/// A message whose delete is in progress is refused with
/// `DELETE_IN_PROGRESS` (the caller reports the store as failed, never as
/// stored). A delete that died or stalled part-way, past its lease, is taken
/// over. The queue entries that delete claimed are moved to `RELEASE_*`
/// fields, and the store releases them before it queues the message again,
/// so the message gets new entries. A stalled delete that resumes later
/// then releases nothing: its claimed entry ids no longer match.
/// `RECORD_QUEUE_IDS` clears the fields once the store completes.
///
/// KEYS: body, metadata. ARGV: body, bytes, to, from (`ANONYMOUS` for none),
/// delete lease ms, store token, store lease ms.
/// Returns `{result, release_to, release_from, release_bytes,
/// release_receive_id, release_send_id}`. `result` is 1 when newly written,
/// 2 when an unfinished store (a retry, the same message stored
/// concurrently, or a taken-over delete) is resumed, and 0 when the message
/// is already fully stored for this recipient. The release fields are ""
/// unless a taken-over delete's entries are still to be released.
pub(crate) static STORE_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local flat = redis.call('HGETALL', KEYS[2])
local meta, storing = {}, false
for i = 1, #flat, 2 do
    if string.sub(flat[i], 1, 8) == 'STORING:' then
        if now_ms - tonumber(flat[i + 1]) < tonumber(ARGV[7]) then
            storing = true
        end
    else
        meta[flat[i]] = flat[i + 1]
    end
end
local result = 1
if meta.TO then
    if meta.DELETING_AT then
        if now_ms - tonumber(meta.DELETING_AT) < tonumber(ARGV[5]) then
            return redis.error_reply('DELETE_IN_PROGRESS message is being deleted')
        end
        if not meta.RELEASE_TO then
            meta.RELEASE_TO = meta.TO
            meta.RELEASE_FROM = meta.FROM or ''
            meta.RELEASE_BYTES = meta.BYTES or '0'
            meta.RELEASE_RECEIVE_ID = meta.RECEIVE_ID or ''
            meta.RELEASE_SEND_ID = meta.SEND_ID or ''
            redis.call('HSET', KEYS[2], 'RELEASE_TO', meta.RELEASE_TO,
                'RELEASE_FROM', meta.RELEASE_FROM, 'RELEASE_BYTES', meta.RELEASE_BYTES,
                'RELEASE_RECEIVE_ID', meta.RELEASE_RECEIVE_ID,
                'RELEASE_SEND_ID', meta.RELEASE_SEND_ID)
        end
        redis.call('HDEL', KEYS[2], 'DELETING', 'DELETING_AT', 'RECEIVE_ID', 'SEND_ID', 'FROM')
        result = 2
    elseif meta.TO == ARGV[3] then
        if meta.RECEIVE_ID and not storing and not meta.RELEASE_TO then
            return { '0', '', '', '', '', '' }
        end
        result = 2
    end
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('HSET', KEYS[2], 'BYTES', ARGV[2], 'TO', ARGV[3],
    'TIMESTAMP', string.format('%d%03d', t[1], t[2] / 1000), 'STORING:' .. ARGV[6], now_ms)
if ARGV[4] ~= 'ANONYMOUS' then
    redis.call('HSET', KEYS[2], 'FROM', ARGV[4])
end
return { tostring(result), meta.RELEASE_TO or '', meta.RELEASE_FROM or '',
    meta.RELEASE_BYTES or '', meta.RELEASE_RECEIVE_ID or '', meta.RELEASE_SEND_ID or '' }
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
/// queues and clear this store's `STORING:<token>`; the message is deletable
/// once no store holds it, and drop the `RELEASE_*` fields of a taken-over
/// delete, whose entries the store has released. Refuses (returns 0) when the
/// message was deleted, or a delete took it over, in the meantime: the store
/// must then report failure, not success, and release what it queued.
///
/// KEYS: metadata. ARGV: store token, then field/value pairs. Returns 1 when
/// recorded.
pub(crate) static RECORD_QUEUE_IDS: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('EXISTS', KEYS[1]) == 0
    or redis.call('HEXISTS', KEYS[1], 'DELETING') == 1 then
    return 0
end
redis.call('HSET', KEYS[1], unpack(ARGV, 2))
redis.call('HDEL', KEYS[1], 'STORING:' .. ARGV[1], 'RELEASE_TO', 'RELEASE_FROM',
    'RELEASE_BYTES', 'RELEASE_RECEIVE_ID', 'RELEASE_SEND_ID')
return 1
"#,
    )
});

/// Message slot, first step of a delete: check ownership, then take the
/// message for this delete alone. Errors match the library's
/// `delete_message`, plus two the caller waits out:
///
/// - `STORE_IN_PROGRESS`: a store hasn't finished queueing the message
///   (any `STORING:<token>` within its lease).
/// - `DELETE_IN_PROGRESS`: another delete holds it. When that delete
///   finishes the message is gone (NOT_FOUND), which is what the library
///   answers the second of two deletes.
///
/// A hold past its lease belongs to a caller that died part-way and is taken
/// over, so the message is never stuck.
///
/// KEYS: metadata. ARGV: message hash, requester, delete token, store lease
/// ms, delete lease ms, admin (optional).
/// Returns TO, FROM ("" for an anonymous sender), BYTES, and the inbox and
/// outbox entry ids ("" when not recorded), which bind the releases to the
/// entries this claim saw. Then the five `RELEASE_*` fields of a taken-over
/// delete whose store died before releasing them ("" when none): the delete
/// releases those entries too.
pub(crate) static CLAIM_MESSAGE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local flat = redis.call('HGETALL', KEYS[1])
if #flat == 0 then
    return redis.error_reply('NOT_FOUND: message_hash (' .. ARGV[1] .. ')')
end
local meta, stores = {}, {}
for i = 1, #flat, 2 do
    if string.sub(flat[i], 1, 8) == 'STORING:' then
        stores[flat[i]] = tonumber(flat[i + 1])
    else
        meta[flat[i]] = flat[i + 1]
    end
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
local expired = {}
for field, since in pairs(stores) do
    if now_ms - since < tonumber(ARGV[4]) then
        return redis.error_reply('STORE_IN_PROGRESS message is still being stored')
    end
    table.insert(expired, field)
end
if meta.DELETING_AT and meta.DELETING ~= ARGV[3]
    and now_ms - tonumber(meta.DELETING_AT) < tonumber(ARGV[5]) then
    return redis.error_reply('DELETE_IN_PROGRESS message is being deleted')
end
redis.call('HSET', KEYS[1], 'DELETING', ARGV[3], 'DELETING_AT', now_ms)
if #expired > 0 then
    redis.call('HDEL', KEYS[1], unpack(expired))
end
return { meta.TO or '', meta.FROM or '', meta.BYTES, meta.RECEIVE_ID or '', meta.SEND_ID or '',
    meta.RELEASE_TO or '', meta.RELEASE_FROM or '', meta.RELEASE_BYTES or '',
    meta.RELEASE_RECEIVE_ID or '', meta.RELEASE_SEND_ID or '' }
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

/// Message slot of a delete whose release step failed: give the hold up
/// now, while this delete still has it, rather than at the end of its lease.
/// The hold is marked expired, not removed, so the next delete or store
/// takes the message over the usual way and finishes the releases.
///
/// KEYS: metadata. ARGV: delete token. Returns 1 when given up.
pub(crate) static ABANDON_DELETE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('HGET', KEYS[1], 'DELETING') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'DELETING_AT', 0)
return 1
"#,
    )
});

/// Recipient slot of a delete: release the counters and the inbox entry,
/// found by message hash in this slot. Releases nothing when the message was
/// never queued here, so counters only move back what they moved forward,
/// nor when the entry isn't the one the claim saw: a delete that stalled
/// past its lease must not release the entry of the message stored again.
///
/// KEYS: account, inbox, inbox ids. ARGV: message hash, bytes, claimed entry
/// id ("" to release whatever is queued).
pub(crate) static RELEASE_INBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[3], ARGV[1])
if not queued or (ARGV[3] ~= '' and queued ~= ARGV[3]) then
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
/// hash, bytes, to, claimed entry id ("" to release whatever is queued).
pub(crate) static RELEASE_OUTBOX: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local queued = redis.call('HGET', KEYS[4], ARGV[1])
if not queued or (ARGV[4] ~= '' and queued ~= ARGV[4]) then
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
/// KEYS: the instance's sessions, the global registry, the owner kinds.
/// ARGV: the
/// instance's uuid: an entry another instance has taken since is kept.
/// Returns the number of sessions cleaned.
pub(crate) static CLEAN_START_STREAMING: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local count = 0
while count < 500 do
    local popped = redis.call('SPOP', KEYS[1], 1)
    if #popped == 0 then
        break
    end
    local owner = redis.call('HGET', KEYS[2], popped[1])
    if owner and string.sub(owner, 1, string.len(ARGV[1]) + 1) == ARGV[1] .. ':' then
        redis.call('HDEL', KEYS[2], popped[1])
        redis.call('HDEL', KEYS[3], popped[1])
    end
    count = count + 1
end
return count
"#,
    )
});

/// The scripts in a fixed interleaving, against the cluster server in
/// `REDIS_URL` when `REDIS_CLUSTER_MODE` is `true` (the cluster CI job);
/// skipped otherwise.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::keys::Keys;
    use redis::cluster_async::ClusterConnection;

    const LEASE_MS: u64 = 30_000;

    async fn cluster() -> Option<ClusterConnection> {
        if std::env::var("REDIS_CLUSTER_MODE").ok()? != "true" {
            return None;
        }
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::cluster::ClusterClientBuilder::new(vec![url])
            .build()
            .expect("cluster client");
        Some(
            client
                .get_async_connection()
                .await
                .expect("cluster connection"),
        )
    }

    struct Message {
        keys: Keys,
        hash: String,
        to: String,
        from: String,
    }

    impl Message {
        fn new() -> Self {
            let id = uuid::Uuid::new_v4();
            Message {
                keys: Keys::new(true),
                hash: format!("race-msg-{id}"),
                to: format!("race-to-{id}"),
                from: format!("race-from-{id}"),
            }
        }

        /// The first step of a store: `{result, release_*}`.
        async fn store(&self, conn: &mut ClusterConnection, token: &str) -> Vec<String> {
            STORE_MESSAGE
                .key(self.keys.msg(&self.hash))
                .key(self.keys.msg_meta(&self.hash))
                .arg("body")
                .arg(4)
                .arg(&self.to)
                .arg(&self.from)
                .arg(LEASE_MS)
                .arg(token)
                .arg(LEASE_MS)
                .invoke_async(conn)
                .await
                .expect("STORE_MESSAGE")
        }

        /// Releases this message's entries `receive_id` and `send_id` (""
        /// for whatever is queued), as `release_queues` does.
        async fn release(&self, conn: &mut ClusterConnection, receive_id: &str, send_id: &str) {
            let _: i64 = RELEASE_INBOX
                .key(self.keys.did(&self.to))
                .key(self.keys.receive_q(&self.to))
                .key(self.keys.receive_ids(&self.to))
                .arg(&self.hash)
                .arg(4)
                .arg(receive_id)
                .invoke_async(conn)
                .await
                .expect("RELEASE_INBOX");
            let _: i64 = RELEASE_OUTBOX
                .key(self.keys.did(&self.from))
                .key(self.keys.peer_q(&self.from))
                .key(self.keys.send_q(&self.from))
                .key(self.keys.send_ids(&self.from))
                .arg(&self.hash)
                .arg(4)
                .arg(&self.to)
                .arg(send_id)
                .invoke_async(conn)
                .await
                .expect("RELEASE_OUTBOX");
        }

        /// The rest of a store, given its first step, as
        /// `store_message_in_steps` runs it: release a taken-over delete's
        /// entries, enqueue, record, and on a refused record release what it
        /// queued.
        async fn finish_store(
            &self,
            conn: &mut ClusterConnection,
            token: &str,
            stored: &[String],
        ) -> i64 {
            if !stored[1].is_empty() {
                self.release(conn, &stored[4], &stored[5]).await;
            }
            let receive_id: String = ENQUEUE_INBOX
                .key(self.keys.did(&self.to))
                .key(self.keys.receive_q(&self.to))
                .key(self.keys.receive_ids(&self.to))
                .arg(&self.hash)
                .arg(4)
                .arg(&self.from)
                .arg(0)
                .invoke_async(conn)
                .await
                .expect("ENQUEUE_INBOX");
            let send_id: String = ENQUEUE_OUTBOX
                .key(self.keys.did(&self.from))
                .key(self.keys.peer_q(&self.from))
                .key(self.keys.send_q(&self.from))
                .key(self.keys.send_ids(&self.from))
                .arg(&self.hash)
                .arg(4)
                .arg(&self.to)
                .arg(0)
                .invoke_async(conn)
                .await
                .expect("ENQUEUE_OUTBOX");
            let recorded: i64 = RECORD_QUEUE_IDS
                .key(self.keys.msg_meta(&self.hash))
                .arg(token)
                .arg(vec!["RECEIVE_ID", &receive_id, "SEND_ID", &send_id])
                .invoke_async(conn)
                .await
                .expect("RECORD_QUEUE_IDS");
            if recorded == 0 {
                self.release(conn, &receive_id, &send_id).await;
            }
            recorded
        }

        async fn claim(
            &self,
            conn: &mut ClusterConnection,
            token: &str,
            store_lease_ms: u64,
        ) -> redis::RedisResult<Vec<String>> {
            self.claim_with(conn, token, store_lease_ms, LEASE_MS).await
        }

        async fn claim_with(
            &self,
            conn: &mut ClusterConnection,
            token: &str,
            store_lease_ms: u64,
            delete_lease_ms: u64,
        ) -> redis::RedisResult<Vec<String>> {
            CLAIM_MESSAGE
                .key(self.keys.msg_meta(&self.hash))
                .arg(&self.hash)
                .arg(&self.to)
                .arg(token)
                .arg(store_lease_ms)
                .arg(delete_lease_ms)
                .invoke_async(conn)
                .await
        }

        /// The release and finish steps of a delete, given its claim.
        async fn finish_delete(
            &self,
            conn: &mut ClusterConnection,
            token: &str,
            claimed: &[String],
        ) -> i64 {
            self.release_claimed(conn, claimed).await;
            FINISH_DELETE
                .key(self.keys.msg(&self.hash))
                .key(self.keys.msg_meta(&self.hash))
                .arg(token)
                .invoke_async(conn)
                .await
                .expect("FINISH_DELETE")
        }

        /// The release step of a delete, given its claim.
        async fn release_claimed(&self, conn: &mut ClusterConnection, claimed: &[String]) {
            if !claimed[5].is_empty() {
                self.release(conn, &claimed[8], &claimed[9]).await;
            }
            self.release(conn, &claimed[3], &claimed[4]).await;
        }

        /// Recipient and sender queue counts, inbox and outbox lengths, and
        /// the sender's count for the recipient.
        async fn queued(&self, conn: &mut ClusterConnection) -> [i64; 5] {
            let mut hget = async |key: String, field: &str| -> i64 {
                redis::cmd("HGET")
                    .arg(key)
                    .arg(field)
                    .query_async::<Option<i64>>(conn)
                    .await
                    .expect("HGET")
                    .unwrap_or(0)
            };
            let receive = hget(self.keys.did(&self.to), "RECEIVE_QUEUE_COUNT").await;
            let send = hget(self.keys.did(&self.from), "SEND_QUEUE_COUNT").await;
            let peer = hget(self.keys.peer_q(&self.from), &self.to).await;
            let mut xlen = async |key: String| -> i64 {
                redis::cmd("XLEN")
                    .arg(key)
                    .query_async(conn)
                    .await
                    .expect("XLEN")
            };
            let inbox = xlen(self.keys.receive_q(&self.to)).await;
            let outbox = xlen(self.keys.send_q(&self.from)).await;
            [receive, send, inbox, outbox, peer]
        }
    }

    /// The same message stored twice at once, deleted after the first store
    /// finishes: the delete waits for the second store, so the message and
    /// every queue entry and count for it go together.
    #[tokio::test]
    async fn test_delete_waits_for_every_store_of_a_message() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        assert_eq!(s1[0], "1");
        let s2 = msg.store(&mut conn, "s2").await;
        assert_eq!(s2[0], "2");
        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 1);

        match msg.claim(&mut conn, "d", LEASE_MS).await {
            Err(err) => assert_eq!(err.code(), Some("STORE_IN_PROGRESS")),
            Ok(claimed) => panic!("claimed while the second store holds it: {claimed:?}"),
        }

        assert_eq!(msg.finish_store(&mut conn, "s2", &s2).await, 1);
        assert_eq!(msg.queued(&mut conn).await, [1; 5]);

        let claimed = msg
            .claim(&mut conn, "d", LEASE_MS)
            .await
            .expect("claim once both stores finished");
        assert_eq!(msg.finish_delete(&mut conn, "d", &claimed).await, 1);
        assert_eq!(
            msg.queued(&mut conn).await,
            [0; 5],
            "nothing is left queued"
        );
    }

    /// A store that died part-way, past its lease, no longer holds the
    /// message: a delete takes it over and clears the store's mark.
    #[tokio::test]
    async fn test_delete_takes_over_an_expired_store() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        assert_eq!(msg.store(&mut conn, "dead").await[0], "1");
        let claimed = msg
            .claim(&mut conn, "d", 0)
            .await
            .expect("an expired store doesn't hold the message");
        let marked: bool = redis::cmd("HEXISTS")
            .arg(msg.keys.msg_meta(&msg.hash))
            .arg("STORING:dead")
            .query_async(&mut conn)
            .await
            .expect("HEXISTS");
        assert!(!marked, "the dead store's mark is cleared");
        assert_eq!(msg.finish_delete(&mut conn, "d", &claimed).await, 1);
    }

    /// A delete that stalled past its lease, after another delete took the
    /// message over and it was stored again, releases nothing of the new
    /// copy: the copy stays queued and the stale delete removes nothing.
    #[tokio::test]
    async fn test_a_stale_delete_spares_a_message_stored_again() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 1);
        let stale = msg
            .claim(&mut conn, "d1", LEASE_MS)
            .await
            .expect("first delete claims");
        let taken = msg
            .claim_with(&mut conn, "d2", LEASE_MS, 0)
            .await
            .expect("second delete takes the stalled one over");
        assert_eq!(msg.finish_delete(&mut conn, "d2", &taken).await, 1);

        let s2 = msg.store(&mut conn, "s2").await;
        assert_eq!(s2[0], "1");
        assert_eq!(msg.finish_store(&mut conn, "s2", &s2).await, 1);
        assert_eq!(msg.finish_delete(&mut conn, "d1", &stale).await, 0);
        assert_eq!(
            msg.queued(&mut conn).await,
            [1; 5],
            "the message stored again is still queued"
        );
    }

    /// Marks the delete holding the message as past its lease, as if it
    /// had stalled for longer than `DELETE_LEASE_MS`.
    async fn expire_delete_hold(msg: &Message, conn: &mut ClusterConnection) {
        let _: () = redis::cmd("HSET")
            .arg(msg.keys.msg_meta(&msg.hash))
            .arg("DELETING_AT")
            .arg(0)
            .query_async(conn)
            .await
            .expect("HSET DELETING_AT");
    }

    /// A delete that stalled past its lease, before its release, while the
    /// message was stored again: the store takes the delete over and gives
    /// the message new entries, so the stalled delete, resuming, releases
    /// nothing and removes nothing. The message stays queued.
    #[tokio::test]
    async fn test_a_store_takes_over_a_stalled_delete() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 1);
        let stalled = msg
            .claim(&mut conn, "d1", LEASE_MS)
            .await
            .expect("the delete claims");
        expire_delete_hold(&msg, &mut conn).await;

        let s2 = msg.store(&mut conn, "s2").await;
        assert_eq!(s2[0], "2", "the store resumes over the stalled delete");
        assert_eq!(s2[1], msg.to, "with the delete's entries to release");
        assert_eq!(msg.finish_store(&mut conn, "s2", &s2).await, 1);
        assert_eq!(msg.queued(&mut conn).await, [1; 5]);

        assert_eq!(
            msg.finish_delete(&mut conn, "d1", &stalled).await,
            0,
            "the stalled delete removes nothing"
        );
        assert_eq!(
            msg.queued(&mut conn).await,
            [1; 5],
            "the message stored again is still queued"
        );
        let fields: Vec<String> = redis::cmd("HKEYS")
            .arg(msg.keys.msg_meta(&msg.hash))
            .query_async(&mut conn)
            .await
            .expect("HKEYS");
        assert!(
            !fields.iter().any(|f| f.starts_with("RELEASE_")),
            "the completed store drops the release fields: {fields:?}"
        );

        let claimed = msg
            .claim(&mut conn, "d2", LEASE_MS)
            .await
            .expect("a later delete claims");
        assert_eq!(msg.finish_delete(&mut conn, "d2", &claimed).await, 1);
        assert_eq!(msg.queued(&mut conn).await, [0; 5]);
    }

    /// As above, but the stalled delete resumes between the store's first
    /// step and its release: the delete releases the old entries and the
    /// store queues new ones. Each entry is released once.
    #[tokio::test]
    async fn test_a_stalled_delete_resuming_mid_takeover_releases_once() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 1);
        let stalled = msg
            .claim(&mut conn, "d1", LEASE_MS)
            .await
            .expect("the delete claims");
        expire_delete_hold(&msg, &mut conn).await;

        let s2 = msg.store(&mut conn, "s2").await;
        assert_eq!(msg.finish_delete(&mut conn, "d1", &stalled).await, 0);
        assert_eq!(msg.queued(&mut conn).await, [0; 5]);
        assert_eq!(msg.finish_store(&mut conn, "s2", &s2).await, 1);
        assert_eq!(msg.queued(&mut conn).await, [1; 5]);
    }

    /// A store that stalled past its lease, while a delete took the message
    /// over and removed it: the store's record step is refused, and the
    /// store releases what it queued, so nothing is left behind.
    #[tokio::test]
    async fn test_a_refused_store_releases_what_it_queued() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        let claimed = msg
            .claim(&mut conn, "d", 0)
            .await
            .expect("the delete takes the stalled store over");
        assert_eq!(msg.finish_delete(&mut conn, "d", &claimed).await, 1);

        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 0);
        assert_eq!(
            msg.queued(&mut conn).await,
            [0; 5],
            "nothing is left queued"
        );
    }

    /// A delete that gave its hold up after a failed release is taken over
    /// at once by the next delete, which finishes the releases.
    #[tokio::test]
    async fn test_an_abandoned_delete_is_taken_over_at_once() {
        let Some(mut conn) = cluster().await else {
            return;
        };
        let msg = Message::new();

        let s1 = msg.store(&mut conn, "s1").await;
        assert_eq!(msg.finish_store(&mut conn, "s1", &s1).await, 1);
        let _ = msg
            .claim(&mut conn, "d1", LEASE_MS)
            .await
            .expect("the delete claims");
        match msg.claim(&mut conn, "d2", LEASE_MS).await {
            Err(err) => assert_eq!(err.code(), Some("DELETE_IN_PROGRESS")),
            Ok(claimed) => panic!("claimed while held: {claimed:?}"),
        }
        let abandoned: i64 = ABANDON_DELETE
            .key(msg.keys.msg_meta(&msg.hash))
            .arg("d1")
            .invoke_async(&mut conn)
            .await
            .expect("ABANDON_DELETE");
        assert_eq!(abandoned, 1);

        let claimed = msg
            .claim(&mut conn, "d2", LEASE_MS)
            .await
            .expect("the next delete takes over at once");
        assert_eq!(msg.finish_delete(&mut conn, "d2", &claimed).await, 1);
        assert_eq!(msg.queued(&mut conn).await, [0; 5]);
    }
}
