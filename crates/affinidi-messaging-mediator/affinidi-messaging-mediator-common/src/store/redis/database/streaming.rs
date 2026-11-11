use crate::{
    errors::MediatorError,
    store::types::{PubSubRecord, StoredMessageRef},
};
use redis::{Value, from_redis_value};
use tracing::{Level, debug, error, event};

use super::Database;

/// GLOBAL_STREAMING holds `<uuid>:TRUE|FALSE`, the instance streaming each
/// DID, and STREAMING_KIND marks with `mux` the DIDs whose owner is a mux
/// entry rather than the DID's own socket. (A separate hash, so an instance
/// that predates it still reads every owner.) The scripts below keep three
/// rules across the instances sharing the store, as the streaming task keeps
/// them within one:
///
/// - a new registration takes the DID (newest wins), but a mux entry never
///   takes it from a direct socket on another instance;
/// - a live-delivery change, or a deregistration, touches the entry only
///   while its instance owns it;
/// - a mux entry kept from the DID, or displaced from it, is recorded in
///   STREAMING_WAITING, so the owner leaving can tell it to take the DID
///   back.
///
/// All keys share the `{streaming}` hash tag in cluster mode, so the same
/// scripts serve both modes.
///
/// KEYS: [1] this instance's STREAMING_SESSIONS set, [2] GLOBAL_STREAMING,
/// [3] STREAMING_WAITING, [4] STREAMING_KIND.
/// ARGV: [1] did_hash, [2] this instance's uuid, [3] `TRUE`|`FALSE`,
/// [4] `direct`|`mux`, [5] `claim`|`update`.
/// Returns `{held, displaced}`: `held` 1 when this instance now holds the
/// DID, and `displaced` the uuid of a mux entry on another instance this
/// write took it from (empty otherwise).
static CLAIM: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
local cur = redis.call('HGET', KEYS[2], ARGV[1])
local owner = nil
local owner_mux = false
if cur then
  owner = string.match(cur, '^([^:]*):')
  owner_mux = redis.call('HGET', KEYS[4], ARGV[1]) == 'mux'
end
local mine = owner == ARGV[2]
if cur and not mine then
  if ARGV[5] == 'update' then
    return {0, ''}
  end
  if ARGV[4] == 'mux' and not owner_mux then
    redis.call('SADD', KEYS[3], ARGV[1])
    return {0, ''}
  end
end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2] .. ':' .. ARGV[3])
if ARGV[4] == 'mux' then
  redis.call('HSET', KEYS[4], ARGV[1], 'mux')
else
  redis.call('HDEL', KEYS[4], ARGV[1])
end
if cur and not mine and owner_mux then
  redis.call('SADD', KEYS[3], ARGV[1])
  return {1, owner}
end
return {1, ''}
"#,
    )
});

/// Take `did_hash` out of this instance's session set, and out of the global
/// map only if this instance still owns it there: another instance may have
/// taken the DID since (the client reconnected there, or became a mux member
/// of a connection there), and deleting its entry would stop its live
/// delivery.
///
/// KEYS: as [`CLAIM`]. ARGV: [1] did_hash, [2] this instance's uuid.
/// Returns 0 when another instance owns the entry (or there was none), 1 when
/// it was removed, 2 when it was removed and a mux entry somewhere waits for
/// the DID.
static RELEASE: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
redis.call('SREM', KEYS[1], ARGV[1])
local cur = redis.call('HGET', KEYS[2], ARGV[1])
if cur and string.match(cur, '^([^:]*):') == ARGV[2] then
  redis.call('HDEL', KEYS[2], ARGV[1])
  redis.call('HDEL', KEYS[4], ARGV[1])
  if redis.call('SREM', KEYS[3], ARGV[1]) == 1 then
    return 2
  end
  return 1
end
return 0
"#,
    )
});

/// A GLOBAL_STREAMING value: (owner uuid, live).
fn parse_owner(row: &str) -> Option<(&str, bool)> {
    let (owner, live) = row.split_once(':')?;
    match live {
        "TRUE" => Some((owner, true)),
        "FALSE" => Some((owner, false)),
        _ => None,
    }
}

impl Database {
    pub async fn streaming_clean_start(&self, uuid: &str) -> Result<(), MediatorError> {
        let mut conn = self.get_connection().await?;

        let response: Vec<Value> = if self.keys().cluster_mode() {
            super::cluster_scripts::CLEAN_START_STREAMING
                .key(self.keys().streaming_sessions(uuid))
                .key(self.keys().global_streaming())
                .key(self.keys().streaming_kind())
                .arg(uuid)
                .invoke_async::<Value>(&mut conn)
                .await
                .map(|count| vec![count])
        } else {
            redis::pipe()
                .atomic()
                .cmd("FCALL")
                .arg("clean_start_streaming")
                .arg(1)
                .arg(uuid)
                .query_async(&mut conn)
                .await
        }
        .map_err(|err| {
            event!(
                Level::ERROR,
                "redis function clean_start_streaming() failed. Reason: {}",
                err
            );
            MediatorError::database_from_redis(
                14,
                "NA".into(),
                &err,
                format!("redis function clean_start_streaming() failed. Reason: {err}"),
            )
        })?;

        if let Ok(count) = from_redis_value::<i64>(response[0].clone()) {
            event!(
                Level::INFO,
                "clean_start_streaming() cleaned {} sessions",
                count
            );
            Ok(())
        } else {
            event!(
                Level::ERROR,
                "clean_start_streaming() failed to parse response: {:?}",
                response
            );
            Err(MediatorError::DatabaseError(
                23,
                "NA".into(),
                format!("redis fn clean_start_streaming() failed. Response ({response:?})"),
            ))
        }
    }

    /// Checks if the given DID hash is live streaming
    /// did_hash: The DID hash to check
    /// force_delivery: If true, the message will be delivered even if the client is not live streaming
    /// Returns the streaming service ID that the client is connecting to if the DID hash is live streaming
    pub async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String> {
        let mut conn = match self.get_connection().await {
            Ok(conn) => conn,
            _ => {
                error!("is_live_streaming(): Failed to get connection to Redis");
                return None;
            }
        };

        match redis::cmd("HGET")
            .arg(self.keys().global_streaming())
            .arg(did_hash)
            .query_async::<Option<String>>(&mut conn)
            .await
        {
            Ok(response) => {
                if let Some(row) = response {
                    match parse_owner(&row) {
                        // Live, or not live but delivery is forced.
                        Some((owner, live)) if live || force_delivery => Some(owner.to_string()),
                        // Not live, or invalid Redis data.
                        _ => None,
                    }
                } else {
                    // No Redis data found.
                    None
                }
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "check if live_streaming for did_hash({}) failed. Reason: {}",
                    did_hash,
                    err
                );
                None
            }
        }
    }

    /// Publishes a live message to the streaming service
    /// This follows a call to is_live_streaming() to get the streaming service ID if valid
    /// NOTE: There is a chance that a client could close live-streaming between the check and publishing
    ///        Not an issue, as the streaming component will handle this gracefully
    /// NOTE: Why not combine is_live_streaming() and this function into an atomic action?
    ///       While it would be more efficient in some ways, it would also mean pushing the full message to Redis
    ///       on every delivery, as messages get larger this would become less efficient.
    ///       So best compromise is to have the client check if live-streaming is active, then send the message
    pub async fn streaming_publish_message(
        &self,
        did_hash: &str,
        stream_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError> {
        self.publish_record(did_hash, stream_uuid, message, force_delivery, false, None)
            .await
    }

    /// [`streaming_publish_message`](Self::streaming_publish_message), with
    /// `verbatim` deciding whether the body is the frame or a notification.
    pub async fn publish_record(
        &self,
        did_hash: &str,
        stream_uuid: &str,
        message: &str,
        force_delivery: bool,
        verbatim: bool,
        stored: Option<StoredMessageRef>,
    ) -> Result<(), MediatorError> {
        let record = match serde_json::to_string(&PubSubRecord {
            did_hash: did_hash.to_string(),
            message: message.to_string(),
            force_delivery,
            verbatim,
            stored,
        }) {
            Ok(record) => record,
            Err(err) => {
                event!(
                    Level::ERROR,
                    "publish_live_message() for did_hash({}) failed to serialize message. Reason: {}",
                    did_hash,
                    err
                );
                return Err(MediatorError::DatabaseError(
                    24,
                    "NA".into(),
                    format!(
                        "publish_live_message() for did_hash({did_hash}) failed to serialize message. Reason: {err}"
                    ),
                ));
            }
        };

        let mut conn = self.get_connection().await?;

        match redis::cmd("PUBLISH")
            .arg(["CHANNEL:", stream_uuid].concat())
            .arg(record)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "published message to channel(CHANNEL:{}) for did_hash({})",
                    stream_uuid, did_hash
                );
                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "publish_live_message() for did_hash({}) channel(CHANNEL:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::database_from_redis(
                    14,
                    "NA".into(),
                    &err,
                    format!(
                        "publish_live_message() for did_hash({did_hash}) channel(CHANNEL:{stream_uuid}) failed. Reason: {err}"
                    ),
                ))
            }
        }
    }

    /// Deregister through the `RELEASE` script: returns whether a mux entry
    /// waits for the DID.
    pub async fn streaming_release(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<bool, MediatorError> {
        let mut conn = self.get_connection().await?;
        let outcome: i64 = RELEASE
            .key(self.keys().streaming_sessions(stream_uuid))
            .key(self.keys().global_streaming())
            .key(self.keys().streaming_waiting())
            .key(self.keys().streaming_kind())
            .arg(did_hash)
            .arg(stream_uuid)
            .invoke_async(&mut conn)
            .await
            .map_err(|err| {
                error!("streaming_release() for did_hash({did_hash}) from ({stream_uuid}) failed: {err}");
                MediatorError::database_from_redis(
                    14,
                    "NA".into(),
                    &err,
                    format!("streaming_release() for did_hash({did_hash}) failed. Reason: {err}"),
                )
            })?;
        match outcome {
            0 => debug!(
                "did_hash({did_hash}) left ({stream_uuid}); its global entry belongs to another instance, kept"
            ),
            _ => debug!("did_hash({did_hash}) deregistered from ({stream_uuid})"),
        }
        Ok(outcome == 2)
    }

    /// Register `did_hash` on this instance as `kind`, through the `CLAIM`
    /// script.
    pub async fn streaming_claim(
        &self,
        did_hash: &str,
        stream_uuid: &str,
        live: bool,
        kind: crate::store::StreamingKind,
        write: crate::store::StreamingWrite,
    ) -> Result<crate::store::StreamingClaim, MediatorError> {
        use crate::store::{StreamingClaim, StreamingKind, StreamingWrite};
        let mut conn = self.get_connection().await?;
        let (held, displaced): (i64, String) = CLAIM
            .key(self.keys().streaming_sessions(stream_uuid))
            .key(self.keys().global_streaming())
            .key(self.keys().streaming_waiting())
            .key(self.keys().streaming_kind())
            .arg(did_hash)
            .arg(stream_uuid)
            .arg(if live { "TRUE" } else { "FALSE" })
            .arg(match kind {
                StreamingKind::Direct => "direct",
                StreamingKind::Mux => "mux",
            })
            .arg(match write {
                StreamingWrite::Claim => "claim",
                StreamingWrite::Update => "update",
            })
            .invoke_async(&mut conn)
            .await
            .map_err(|err| {
                error!(
                    "streaming_claim() for did_hash({did_hash}) on ({stream_uuid}) failed: {err}"
                );
                MediatorError::database_from_redis(
                    14,
                    "NA".into(),
                    &err,
                    format!("streaming_claim() for did_hash({did_hash}) failed. Reason: {err}"),
                )
            })?;
        if held == 0 {
            debug!("did_hash({did_hash}) is held by another instance; ({stream_uuid}) stands by");
        }
        Ok(StreamingClaim {
            held_here: held == 1,
            displaced_mux: (!displaced.is_empty()).then_some(displaced),
        })
    }
}
