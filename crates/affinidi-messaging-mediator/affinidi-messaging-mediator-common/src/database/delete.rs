/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::errors::MediatorError;
use crate::store::types::{DeletionAuthority, OutboxReceipt};
use crate::store::{OUTBOX_RECEIPT_TTL, ops};
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::http::StatusCode;
use tracing::{Instrument, Level, debug, info, span, warn};

/// Attempts at releasing a deleted message's queues before the delete fails.
const RELEASE_ATTEMPTS: u32 = 3;

/// Pause before each further attempt, multiplied by the attempt number.
const RELEASE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Attempts at claiming a message that a store or another delete is still
/// working on. Both normally finish within milliseconds; together the
/// pauses wait about a second before the delete fails as retryable.
const CLAIM_ATTEMPTS: u32 = 6;

/// Pause before each further claim attempt, multiplied by the attempt number.
const CLAIM_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

impl DatabaseHandler {
    /// Deletes a message in the database.
    ///
    /// The Lua `delete_message` function performs an ownership check:
    /// the requesting DID must be the message's TO, FROM, or match
    /// the `admin_did_hash` (for system operations like expiry cleanup).
    ///
    /// Returns specific errors for not-found and permission-denied cases.
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
        request_msg_id: Option<&str>,
        admin_did_hash: Option<&str>,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::INFO,
            "database_delete",
            session = session_id,
            did_hash = did_hash,
            message_hash = message_hash,
        );
        async move {
            let mut conn = self.get_async_connection().await?;

            // The sender and recipient, for the outbox receipt. The receipt is
            // written here in Rust rather than in the stored function for the
            // reason `mark_delivered` gives: a stale function library loads
            // without complaint and would silently never write it.
            let mut parties: Option<(String, String)> = None;

            let result: Result<String, redis::RedisError> = if self.keys.cluster_mode() {
                // The claim waits out a store in progress and returns the
                // parties, so no read beforehand is needed.
                self.delete_message_in_steps(&mut conn, message_hash, did_hash, admin_did_hash)
                    .await
                    .map(|(to, from)| {
                        parties = (!from.is_empty()).then_some((to, from));
                        "OK".to_string()
                    })
            } else {
                // Read before the delete, because the delete removes the
                // metadata. A read that fails only costs the receipt.
                parties = redis::cmd("HMGET")
                    .arg(self.keys.msg_meta(message_hash))
                    .arg("TO")
                    .arg("FROM")
                    .arg("SEND_ID")
                    .query_async::<Vec<Option<String>>>(&mut conn)
                    .await
                    .ok()
                    .and_then(|fields| match fields.as_slice() {
                        // `SEND_ID` is present exactly when the message sits
                        // in a sender's outbox, i.e. has a recorded sender.
                        [Some(to), Some(from), Some(_)] => Some((to.clone(), from.clone())),
                        _ => None,
                    });
                let mut cmd = redis::cmd("FCALL");
                cmd.arg("delete_message")
                    .arg(1)
                    .arg(message_hash)
                    .arg(did_hash);
                if let Some(admin_hash) = admin_did_hash {
                    cmd.arg(admin_hash);
                }
                cmd.query_async(&mut conn).await
            };

            match result {
                Ok(response) if response == "OK" => {
                    info!("Successfully deleted message_hash({})", message_hash);
                    if let Some((to, from)) = parties {
                        self.record_outbox_receipt(
                            &mut conn,
                            message_hash,
                            did_hash,
                            admin_did_hash.is_some(),
                            &to,
                            &from,
                        )
                        .await;
                    }
                    Ok(())
                }
                Ok(response) => {
                    // Lua returned a non-OK status (shouldn't happen with current script)
                    warn!(
                        "delete_message returned unexpected status: {} for message_hash({})",
                        response, message_hash
                    );
                    Err(MediatorError::problem_with_log(
                        11,
                        "NA",
                        request_msg_id.map(|s| s.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "database.message.delete.status",
                        "delete returned unexpected status ({1}) for message ({2})",
                        vec![response.to_string(), message_hash.to_string()],
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("delete returned unexpected status ({response}) for message ({message_hash})"),
                    ))
                }
                Err(err) => {
                    let err_str = err.to_string();

                    // Parse Lua error responses for specific handling
                    if err_str.contains("NOT_FOUND") {
                        debug!(
                            "Message not found for deletion: message_hash({})",
                            message_hash
                        );
                        Err(ops::delete_not_found(message_hash, request_msg_id))
                    } else if err_str.contains("PERMISSION_DENIED") {
                        warn!(
                            "Permission denied deleting message_hash({}) by did_hash({})",
                            message_hash, did_hash
                        );
                        Err(ops::delete_permission_denied(message_hash, request_msg_id))
                    } else {
                        // Generic database error
                        Err(MediatorError::problem_with_log(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.error",
                            "Couldn't delete message_hash ({1}). Reason: {2}",
                            vec![message_hash.to_string(), err_str],
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("Couldn't delete message_hash ({message_hash}). Reason: {err}"),
                        ))
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// `delete_message` for cluster mode, in steps a repeated delete can finish:
    ///
    /// 1. claim the message in its own slot: check ownership and take it for
    ///    this delete alone. A store still queueing it, or another delete
    ///    holding it, is waited out briefly; the second of two deletes then
    ///    finds the message gone and answers NOT_FOUND, as the library does;
    /// 2. release the recipient's and sender's queues concurrently, each
    ///    finding its entry in its own slot and undoing only what was queued
    ///    there (idempotent, so retried a few times);
    /// 3. remove the message only while this delete still holds it, so
    ///    exactly one delete reports it removed (R1.7), and count it.
    ///
    /// A failure returns an error and leaves the message held. Once the hold
    /// passes its lease the next delete (or the expiry sweeper, which keeps
    /// the message for its next pass) takes it over and finishes. On a full
    /// database step 1's write is refused, so the delete fails before
    /// changing anything, as the library's does.
    ///
    /// Returns the message's TO and FROM ("" for an anonymous sender).
    async fn delete_message_in_steps(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
        did_hash: &str,
        admin_did_hash: Option<&str>,
    ) -> redis::RedisResult<(String, String)> {
        use crate::store::redis::database::cluster_scripts::{
            CLAIM_MESSAGE, DELETE_LEASE_MS, FINISH_DELETE, STORE_LEASE_MS,
        };

        let keys = self.keys;
        let token = uuid::Uuid::new_v4().to_string();
        let mut attempt = 1;
        let (to, from, bytes): (String, String, String) = loop {
            let mut claim = CLAIM_MESSAGE.prepare_invoke();
            claim
                .key(keys.msg_meta(message_hash))
                .arg(message_hash)
                .arg(did_hash)
                .arg(&token)
                .arg(STORE_LEASE_MS)
                .arg(DELETE_LEASE_MS);
            if let Some(admin_hash) = admin_did_hash {
                claim.arg(admin_hash);
            }
            match claim.invoke_async(conn).await {
                Ok(claimed) => break claimed,
                Err(err)
                    if attempt < CLAIM_ATTEMPTS
                        && matches!(
                            err.code(),
                            Some("STORE_IN_PROGRESS" | "DELETE_IN_PROGRESS")
                        ) =>
                {
                    debug!("Waiting to delete message {message_hash}: {err}");
                    tokio::time::sleep(CLAIM_RETRY_DELAY * attempt).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        };

        for attempt in 1..=RELEASE_ATTEMPTS {
            let (inbox, outbox) = futures_util::future::join(
                self.release_inbox(conn.clone(), &to, message_hash, &bytes),
                self.release_outbox(conn.clone(), &from, &to, message_hash, &bytes),
            )
            .await;
            match inbox.and(outbox) {
                Ok(_) => break,
                Err(err) if attempt < RELEASE_ATTEMPTS => {
                    warn!("Retrying the queue release of message {message_hash}: {err}");
                    tokio::time::sleep(RELEASE_RETRY_DELAY * attempt).await;
                }
                Err(err) => return Err(err),
            }
        }

        let removed: i64 = FINISH_DELETE
            .key(keys.msg(message_hash))
            .key(keys.msg_meta(message_hash))
            .arg(&token)
            .invoke_async(conn)
            .await?;
        if removed == 0 {
            // Another delete took the message over; it reports the removal.
            return Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "NOT_FOUND",
                format!("message_hash ({message_hash}) was removed by another delete"),
            )));
        }

        // One key, so no MULTI: it would only add commands.
        let mut counted = redis::pipe();
        counted
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("DELETED_BYTES")
            .arg(&bytes)
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("DELETED_COUNT")
            .arg(1);
        if let Err(err) = counted.exec_async(conn).await {
            warn!("Couldn't count deleted message {message_hash}: {err}");
        }
        Ok((to, from))
    }

    /// Releases the recipient's inbox entry of a message being deleted.
    async fn release_inbox(
        &self,
        mut conn: super::RedisConnection,
        to: &str,
        message_hash: &str,
        bytes: &str,
    ) -> redis::RedisResult<i64> {
        use crate::store::redis::database::cluster_scripts::RELEASE_INBOX;

        if to.is_empty() {
            return Ok(0);
        }
        RELEASE_INBOX
            .key(self.keys.did(to))
            .key(self.keys.receive_q(to))
            .key(self.keys.receive_ids(to))
            .arg(message_hash)
            .arg(bytes)
            .invoke_async(&mut conn)
            .await
    }

    /// Releases the sender's outbox entry of a message being deleted.
    async fn release_outbox(
        &self,
        mut conn: super::RedisConnection,
        from: &str,
        to: &str,
        message_hash: &str,
        bytes: &str,
    ) -> redis::RedisResult<i64> {
        use crate::store::redis::database::cluster_scripts::RELEASE_OUTBOX;

        if from.is_empty() {
            return Ok(0);
        }
        RELEASE_OUTBOX
            .key(self.keys.did(from))
            .key(self.keys.peer_q(from))
            .key(self.keys.send_q(from))
            .key(self.keys.send_ids(from))
            .arg(message_hash)
            .arg(bytes)
            .arg(to)
            .invoke_async(&mut conn)
            .await
    }

    /// Leave `from` a receipt saying why `message_hash` left its outbox.
    ///
    /// Best-effort: the message is already gone, and a receipt that could not
    /// be written reads as `Unknown` to the sender, which it treats as no
    /// evidence. Never as delivery.
    async fn record_outbox_receipt(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
        did_hash: &str,
        as_admin: bool,
        to: &str,
        from: &str,
    ) {
        let authority = if as_admin {
            DeletionAuthority::Admin {
                admin_did_hash: did_hash.to_string(),
            }
        } else {
            DeletionAuthority::Owner {
                did_hash: did_hash.to_string(),
            }
        };
        let Some(reason) = ops::removal_reason(&authority, to, Some(from)) else {
            return;
        };
        let receipt = OutboxReceipt {
            reason,
            at_ms: now_ms(),
        };
        let written: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(self.keys.outbox_receipt(from, message_hash))
            .arg(receipt.encode())
            .arg("EX")
            .arg(OUTBOX_RECEIPT_TTL.as_secs())
            .query_async(conn)
            .await;
        if let Err(err) = written {
            warn!("Couldn't record the outbox receipt for message_hash({message_hash}): {err}");
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
