use super::Database;
use crate::error_codes;
use crate::errors::MediatorError;
use crate::types::messages::MessageListElement;
use itertools::Itertools;
use redis::{Value, from_redis_value};
use subtle::ConstantTimeEq;
use tracing::{Instrument, Level, debug, event, span};

impl Database {
    /// The body and metadata (flat field/value list) of the record of
    /// `msg_id` that `did_hash` may read, resolved as `MessageScope::Party`:
    /// its own inbox copy (per-recipient, else a legacy per-id record whose
    /// TO it is), else a copy it sent. `None` when it is a party to none.
    async fn party_record(
        &self,
        conn: &mut crate::database::RedisConnection,
        did_hash: &str,
        msg_id: &str,
    ) -> redis::RedisResult<Option<(Value, Vec<String>)>> {
        let keys = self.keys();
        // One atomic read of the candidates that need no index lookup.
        #[allow(clippy::type_complexity)]
        let (own_body, own_meta, legacy_body, legacy_meta): (
            Value,
            Vec<String>,
            Value,
            Vec<String>,
        ) = redis::pipe()
            .atomic()
            .get(keys.msg(msg_id, Some(did_hash)))
            .hgetall(keys.msg_meta(msg_id, Some(did_hash)))
            .get(keys.msg(msg_id, None))
            .hgetall(keys.msg_meta(msg_id, None))
            .query_async(conn)
            .await?;
        if !own_meta.is_empty() {
            return Ok(Some((own_body, own_meta)));
        }
        let field = |meta: &[String], name: &str| {
            meta.iter()
                .tuples()
                .find(|(k, _)| k.as_str() == name)
                .map(|(_, v)| v.clone())
        };
        let legacy_to = field(&legacy_meta, "TO");
        if legacy_to.as_deref() == Some(did_hash) {
            return Ok(Some((legacy_body, legacy_meta)));
        }
        if field(&legacy_meta, "FROM").as_deref() == Some(did_hash) {
            return Ok(Some((legacy_body, legacy_meta)));
        }
        // A copy it sent to someone else: found through the id's index.
        let recipients: Vec<String> = redis::cmd("SMEMBERS")
            .arg(keys.msg_recipients(msg_id))
            .query_async(conn)
            .await?;
        for to in recipients {
            let (body, meta): (Value, Vec<String>) = redis::pipe()
                .atomic()
                .get(keys.msg(msg_id, Some(&to)))
                .hgetall(keys.msg_meta(msg_id, Some(&to)))
                .query_async(conn)
                .await?;
            if field(&meta, "FROM").as_deref() == Some(did_hash) {
                return Ok(Some((body, meta)));
            }
        }
        Ok(None)
    }

    /// Get a message from the database
    /// - did_hash: DID Hash of the requesting DID (could be sender or receiver)
    /// - msg_id: The unique identifier of the message
    pub async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError> {
        let _span = span!(Level::DEBUG, "get_message", msg_id = msg_id,);
        async move {
            if !crate::store::ops::is_message_id(msg_id) {
                return Ok(None);
            }
            let mut conn = self.get_connection().await?;
            let Some((didcomm_message, meta_data)) = self
                .party_record(&mut conn, did_hash, msg_id)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message_id({}) from database: {}",
                        msg_id,
                        err
                    );
                    MediatorError::database_from_redis(
                        error_codes::DB_OPERATION_ERROR,
                        "NA".into(),
                        &err,
                        format!("Couldn't get message_id({msg_id}) from database: {err}"),
                    )
                })?
            else {
                return Ok(None);
            };

            let didcomm_message: String = match didcomm_message {
                Value::Nil => {
                    return Ok(None);
                }
                v => from_redis_value(v).map_err(|e| {
                    MediatorError::InternalError(
                        error_codes::INTERNAL_ERROR,
                        did_hash.into(),
                        format!("Couldn't convert didcomm_message to string: {e}"),
                    )
                })?,
            };

            debug!("didcomm_message: {:?}", didcomm_message);
            debug!("metadata: {:?}", meta_data);

            let mut message = MessageListElement {
                msg_id: msg_id.to_string(),
                msg: Some(didcomm_message),
                ..Default::default()
            };

            for (k, v) in meta_data.iter().tuples() {
                match k.as_str() {
                    "MSG_ID" => message.msg_id.clone_from(v),
                    "BYTES" => message.size = v.parse().unwrap_or(0),
                    "FROM" => message.from_address = Some(v.clone()),
                    "TO" => message.to_address = Some(v.clone()),
                    "TIMESTAMP" => message.timestamp = v.parse().unwrap_or(0),
                    "SEND_ID" => message.send_id = Some(v.clone()),
                    "RECEIVE_ID" => message.receive_id = Some(v.clone()),
                    _ => {}
                }
            }

            // Ensure requesting DID is either sender or receiver
            if did_hash
                .as_bytes()
                .ct_eq(
                    message
                        .from_address
                        .as_ref()
                        .unwrap_or(&"".to_string())
                        .as_bytes(),
                )
                .unwrap_u8()
                == 1
                || did_hash
                    .as_bytes()
                    .ct_eq(
                        message
                            .to_address
                            .as_ref()
                            .unwrap_or(&"".to_string())
                            .as_bytes(),
                    )
                    .unwrap_u8()
                    == 1
            {
                // The sent counters move when a handover is recorded, not
                // on a read (see `MediatorStore::count_sent`).
                Ok(Some(message))
            } else {
                // Requesting DID is neither sender nor receiver
                // Return None as safety measure - returning an error could leak that the message exists
                Ok(None)
            }
        }
        .instrument(_span)
        .await
    }
}
