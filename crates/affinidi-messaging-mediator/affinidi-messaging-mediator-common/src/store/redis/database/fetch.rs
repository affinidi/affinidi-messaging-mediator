use super::Database;
use crate::database::RedisConnection;
use crate::errors::MediatorError;
use crate::types::messages::{
    FetchDeletePolicy, FetchOptions, GetMessagesResponse, MessageListElement,
};
use itertools::Itertools;
use redis::{Value, from_redis_value};
use std::collections::HashMap;
use tracing::{Instrument, Level, debug, event, span, warn};

impl Database {
    /// Fetch as many messages as possible from the database
    /// - did_hash: DID we are checking
    pub async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "fetch_messages");
        async move {
            let mut conn = self.get_connection().await?;

            let start_id = options.start_id.as_deref().unwrap_or("-");

            let results: Vec<Value> = if self.keys().cluster_mode() {
                self.fetch_messages_in_steps(&mut conn, did_hash, start_id, options.limit)
                    .await
            } else {
                redis::cmd("FCALL")
                    .arg("fetch_messages")
                    .arg(1)
                    .arg(did_hash)
                    .arg(start_id)
                    .arg(options.limit)
                    .query_async(&mut conn)
                    .await
            }
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't fetch_messages() from database: {}",
                    err
                );
                MediatorError::database_from_redis(
                    14,
                    "NA".into(),
                    &err,
                    format!("Couldn't fetch_messages() from database: {err}"),
                )
            })?;

            let mut messages = GetMessagesResponse::default();
            for item in &results {
                let sub_item: Vec<String> = match from_redis_value(item.clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Error parsing redis value: ({:?}). Reason: {:?}", item, e);
                        messages
                            .get_errors
                            .push((format!("{item:?}"), e.to_string()));
                        continue;
                    }
                };
                let mut message = MessageListElement::default();
                for (k, v) in sub_item.iter().tuples() {
                    match k.as_str() {
                        "MSG_ID" => message.msg_id.clone_from(v),
                        "META_SEND_ID" => message.send_id = Some(v.clone()),
                        "META_RECEIVE_ID" => message.receive_id = Some(v.clone()),
                        "META_BYTES" => message.size = v.parse().unwrap_or(0),
                        "META_TIMESTAMP" => message.timestamp = v.parse().unwrap_or(0),
                        "META_TO" => message.to_address = Some(v.clone()),
                        "FROM_DID" => message.from_address = Some(v.clone()),
                        "MSG" => message.msg = Some(v.clone()),
                        _ => {}
                    }
                }
                debug!("Message id({}) fetched", &message.msg_id);

                // Delete message if requested
                if let FetchDeletePolicy::Optimistic = options.delete_policy {
                    match self
                        .handler
                        .delete_message(Some(session_id), did_hash, &message.msg_id, None, None)
                        .await
                    {
                        Ok(_) => {
                            debug!("Message deleted: ({})", message.msg_id);
                        }
                        Err(e) => {
                            warn!("Error deleting message: ({})", e);
                            messages
                                .delete_errors
                                .push((message.msg_id.clone(), e.to_string()));
                        }
                    }
                }
                messages.success.push(message);
            }

            Ok(messages)
        }
        .instrument(_span)
        .await
    }

    /// `fetch_messages` for cluster mode: read the inbox, then each message's
    /// body and metadata (one slot per message) concurrently. Rows have the
    /// library function's shape. A message deleted since it was queued is
    /// skipped.
    async fn fetch_messages_in_steps(
        &self,
        conn: &mut RedisConnection,
        did_hash: &str,
        start_id: &str,
        limit: usize,
    ) -> redis::RedisResult<Vec<Value>> {
        let keys = self.keys();
        // The library treats `start_id` as exclusive.
        let start = if start_id == "-" {
            start_id.to_string()
        } else {
            format!("({start_id}")
        };
        let entries: Vec<(String, Vec<String>)> = redis::cmd("XRANGE")
            .arg(keys.receive_q(did_hash))
            .arg(start)
            .arg("+")
            .arg("COUNT")
            .arg(limit)
            .query_async(conn)
            .await?;

        let rows =
            futures_util::future::try_join_all(entries.into_iter().map(|(stream_id, fields)| {
                let mut conn = conn.clone();
                async move {
                    let field = |name: &str| {
                        fields
                            .chunks(2)
                            .find(|pair| pair[0] == name)
                            .and_then(|pair| pair.get(1).cloned())
                            .unwrap_or_default()
                    };
                    let (msg_id, from) = (field("MSG_ID"), field("FROM"));
                    // Atomic so a delete cannot land between the two reads:
                    // that would return a deleted message with no metadata
                    // (no RECEIVE_ID), and it would be delivered again.
                    let (body, meta): (Option<String>, HashMap<String, String>) = redis::pipe()
                        .atomic()
                        .get(keys.msg(&msg_id))
                        .hgetall(keys.msg_meta(&msg_id))
                        .query_async(&mut conn)
                        .await?;
                    Ok::<_, redis::RedisError>(body.map(|body| {
                        let mut row = vec![
                            "STREAM_ID".to_string(),
                            stream_id,
                            "MSG_ID".to_string(),
                            msg_id,
                            "FROM_DID".to_string(),
                            from,
                            "MSG".to_string(),
                            body,
                        ];
                        for (k, v) in meta {
                            row.push(format!("META_{k}"));
                            row.push(v);
                        }
                        Value::Array(
                            row.into_iter()
                                .map(|item| Value::BulkString(item.into_bytes()))
                                .collect(),
                        )
                    }))
                }
            }))
            .await?;
        Ok(rows.into_iter().flatten().collect())
    }
}
