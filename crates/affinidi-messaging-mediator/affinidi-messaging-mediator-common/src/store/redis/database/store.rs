use std::time::Instant;

use super::Database;
use super::cluster_scripts::{
    DELETE_LEASE_MS, ENQUEUE_INBOX, ENQUEUE_OUTBOX, RECORD_QUEUE_IDS, STORE_LEASE_MS, STORE_MESSAGE,
};
use crate::database::RedisConnection;
use crate::errors::MediatorError;

// Mirror of the metric names declared in the mediator's
// `common::metrics::names` module — kept as raw strings here so this
// `database/` impl can live in mediator-common without depending on
// the mediator's metrics registry.
mod names {
    pub const MESSAGE_STORE_DURATION_SECONDS: &str = "message_store_duration_seconds";
    pub const MESSAGES_STORED_TOTAL: &str = "messages_stored_total";
}
use serde::{Deserialize, Serialize};
use sha256::digest;
use tracing::{Instrument, Level, debug, event, info, span, warn};

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageMetaData {
    pub bytes: usize,
    pub to_did_hash: String,
    pub from_did_hash: Option<String>,
    pub timestamp: u128,
}

impl Database {
    /// Stores a message in the database
    /// Returns the message_id (hash of the message)
    /// - expires_at: The timestamp at which the message expires (since epoch in seconds)
    /// - `from_hash`: The hash of the DID of the sender
    /// - `queue_maxlen`: Max entries per RECEIVE_Q/SEND_Q stream (0 = unlimited)
    pub async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        queue_maxlen: usize,
    ) -> Result<String, MediatorError> {
        let _span = span!(Level::DEBUG, "store_message", session_id = session_id);
        async move {
            let message_hash = digest(message.as_bytes());

            let from_hash = from_hash.filter(|s| !s.is_empty()).unwrap_or("ANONYMOUS");
            debug!(
                "trying to store msg_id({}), from_hash({:?}) to_hash({}), bytes({})",
                message_hash,
                from_hash,
                to_did_hash,
                message.len()
            );

            let start = Instant::now();
            let mut conn = self.get_connection().await?;
            let stored = if self.keys().cluster_mode() {
                self.store_message_in_steps(
                    &mut conn,
                    &message_hash,
                    message,
                    expires_at,
                    to_did_hash,
                    from_hash,
                    queue_maxlen,
                )
                .await
            } else {
                let mut cmd = redis::cmd("FCALL");
                cmd.arg("store_message")
                    .arg(1)
                    .arg(&message_hash)
                    .arg(message)
                    .arg(expires_at)
                    .arg(message.len())
                    .arg(to_did_hash)
                    .arg(from_hash);
                if queue_maxlen > 0 {
                    cmd.arg(queue_maxlen);
                }
                cmd.exec_async(&mut conn).await
            };
            stored.map_err(|err| {
                event!(Level::ERROR, "Couldn't store message in database: {}", err);
                MediatorError::DatabaseError(
                    14,
                    session_id.into(),
                    format!("Couldn't store message in database: {err}"),
                )
            })?;

            metrics::histogram!(names::MESSAGE_STORE_DURATION_SECONDS)
                .record(start.elapsed().as_secs_f64());
            metrics::counter!(names::MESSAGES_STORED_TOTAL).increment(1);

            info!(
                "Message hash({}) from({}) to({}) stored in database",
                message_hash, from_hash, to_did_hash
            );

            Ok(message_hash)
        }
        .instrument(_span)
        .await
    }

    /// `store_message` for cluster mode, as single-slot steps ordered so a
    /// failure part-way is harmless or repaired by a retry:
    ///
    /// 1. body, metadata and sender, marked `STORING:<token>` for this store
    ///    so no delete can run until step 4 (nothing to do if already stored
    ///    for this recipient; refused while a delete holds the message);
    /// 2. the expiry index, so the sweeper can reach the message from here on;
    /// 3. the recipient's inbox and the sender's outbox, concurrently;
    /// 4. the queue ids on the metadata, clearing this store's mark — the
    ///    message is deletable once no store holds it. Refused if a delete
    ///    took the message over, which fails the store;
    /// 5. the global counters, best-effort, only for a newly written message
    ///    so a retry or a concurrent identical store counts it once.
    ///
    /// Steps 1–4 are idempotent by message, so a retry or the same message
    /// stored twice at once queues and counts it once.
    #[allow(clippy::too_many_arguments)]
    async fn store_message_in_steps(
        &self,
        conn: &mut RedisConnection,
        message_hash: &str,
        message: &str,
        expires_at: u64,
        to_did_hash: &str,
        from_hash: &str,
        queue_maxlen: usize,
    ) -> redis::RedisResult<()> {
        let keys = self.keys();
        let bytes = message.len();
        let token = uuid::Uuid::new_v4().to_string();

        let written: i64 = STORE_MESSAGE
            .key(keys.msg(message_hash))
            .key(keys.msg_meta(message_hash))
            .arg(message)
            .arg(bytes)
            .arg(to_did_hash)
            .arg(from_hash)
            .arg(DELETE_LEASE_MS)
            .arg(&token)
            .arg(STORE_LEASE_MS)
            .invoke_async(conn)
            .await?;
        if written == 0 {
            return Ok(());
        }

        // Index before bucket: a failure between them leaves an empty bucket
        // in the index, which the sweeper passes over.
        let bucket = format!("MSG_EXPIRY:{expires_at}");
        redis::cmd("ZADD")
            .arg("MSG_EXPIRY")
            .arg("NX")
            .arg(expires_at)
            .arg(&bucket)
            .exec_async(conn)
            .await?;
        redis::cmd("SADD")
            .arg(&bucket)
            .arg(message_hash)
            .exec_async(conn)
            .await?;

        let mut inbox_conn = conn.clone();
        let inbox = async {
            ENQUEUE_INBOX
                .key(keys.did(to_did_hash))
                .key(keys.receive_q(to_did_hash))
                .key(keys.receive_ids(to_did_hash))
                .arg(message_hash)
                .arg(bytes)
                .arg(from_hash)
                .arg(queue_maxlen)
                .invoke_async::<String>(&mut inbox_conn)
                .await
        };
        let mut outbox_conn = conn.clone();
        let outbox = async {
            if from_hash == "ANONYMOUS" {
                return Ok(None);
            }
            ENQUEUE_OUTBOX
                .key(keys.did(from_hash))
                .key(keys.peer_q(from_hash))
                .key(keys.send_q(from_hash))
                .key(keys.send_ids(from_hash))
                .arg(message_hash)
                .arg(bytes)
                .arg(to_did_hash)
                .arg(queue_maxlen)
                .invoke_async::<String>(&mut outbox_conn)
                .await
                .map(Some)
        };
        let (receive_id, send_id) = futures_util::future::try_join(inbox, outbox).await?;

        let mut ids = vec!["RECEIVE_ID".to_string(), receive_id];
        if let Some(send_id) = send_id {
            ids.extend(["SEND_ID".to_string(), send_id]);
        }
        let recorded: i64 = RECORD_QUEUE_IDS
            .key(keys.msg_meta(message_hash))
            .arg(&token)
            .arg(ids)
            .invoke_async(conn)
            .await?;
        if recorded == 0 {
            // A delete took the message over (its store outlived the
            // lease). Whatever it queued, the message isn't stored.
            return Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "DELETED_WHILE_STORING",
                format!("message {message_hash} was deleted before its store completed"),
            )));
        }
        if written != 1 {
            return Ok(());
        }

        // One key, so no MULTI: it would only add commands.
        let mut counted = redis::pipe();
        counted
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("RECEIVED_BYTES")
            .arg(bytes)
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("RECEIVED_COUNT")
            .arg(1);
        if let Err(err) = counted.exec_async(conn).await {
            warn!("Couldn't count stored message {message_hash}: {err}");
        }
        Ok(())
    }

    /// Retrieves the message MetaData for a given message hash
    /// - session_id: The session_id for the request
    /// - message_hash: The hash of the message to retrieve
    pub async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "get_message_metadata",
            session_id = session_id,
            message_hash = message_hash
        );
        async move {
            // The `store_message` Lua function keeps a message's metadata in
            // the hash `MSG:META:{id}`: BYTES, TO, TIMESTAMP (unix ms), and
            // FROM when the sender is known. (This read used to look for a
            // `MESSAGE_STORE` hash field that nothing writes, so it could
            // never succeed.)
            let mut conn = self.get_connection().await?;
            let fields: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
                .arg(self.keys().msg_meta(message_hash))
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message metadata from database: {}",
                        err
                    );
                    MediatorError::DatabaseError(
                        14,
                        session_id.into(),
                        format!("Couldn't get message metadata from database: {err}"),
                    )
                })?;
            let metadata = metadata_from_fields(&fields).ok_or_else(|| {
                MediatorError::DatabaseError(
                    22,
                    session_id.into(),
                    format!("No usable metadata for message {message_hash}"),
                )
            })?;

            Ok(metadata)
        }
        .instrument(_span)
        .await
    }
}

/// A `MSG:META:{id}` hash as [`MessageMetaData`]; `None` when the message is
/// gone (an empty hash) or a required field is missing or malformed.
fn metadata_from_fields(
    fields: &std::collections::HashMap<String, String>,
) -> Option<MessageMetaData> {
    Some(MessageMetaData {
        bytes: fields.get("BYTES")?.parse().ok()?,
        to_did_hash: fields.get("TO")?.clone(),
        from_did_hash: fields.get("FROM").cloned(),
        timestamp: fields.get("TIMESTAMP")?.parse().ok()?,
    })
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn a_message_meta_hash_parses_and_an_empty_one_is_absent() {
        let fields: std::collections::HashMap<String, String> = [
            ("BYTES", "42"),
            ("TO", "bob"),
            ("FROM", "alice"),
            ("TIMESTAMP", "1700000000123"),
            ("RECEIVE_ID", "1-0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let meta = metadata_from_fields(&fields).unwrap();
        assert_eq!(meta.bytes, 42);
        assert_eq!(meta.to_did_hash, "bob");
        assert_eq!(meta.from_did_hash.as_deref(), Some("alice"));
        assert_eq!(meta.timestamp, 1_700_000_000_123);

        assert!(metadata_from_fields(&Default::default()).is_none());
    }
}
