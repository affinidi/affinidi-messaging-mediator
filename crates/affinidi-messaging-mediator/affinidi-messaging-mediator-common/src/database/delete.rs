/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::database::keys::Keys;
use crate::error_codes;
use crate::errors::{MediatorError, StorageCap};
use crate::store::redis::database::handlers::is_older_library_error;
use crate::store::types::{DeletionAuthority, MessageScope, OutboxReceipt, RemovedCopy};
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

/// One record a delete removed: its recipient, its sender ("" for an
/// anonymous one), and whether it sat in the sender's outbox — which is when
/// the sender is owed a receipt.
struct Removed {
    to: String,
    from: String,
    in_outbox: bool,
    /// The record's expiry (Unix seconds), `0` when it had none recorded.
    expires_at: u64,
}

/// A Redis error carrying `code`, which the reply mapping in
/// [`DatabaseHandler::delete_message`] recognises like a Lua error reply.
fn coded_error(code: &'static str, detail: String) -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::Client, code, detail))
}

impl DatabaseHandler {
    /// Deletes the records of `message_hash` that `scope` names (see
    /// `ops::select_records`; the Lua `delete_message` and the cluster path
    /// below follow the same rules).
    ///
    /// Each removed record is authorised on its own: the requesting DID must
    /// be its TO or FROM, or match `admin_did_hash` (for system operations
    /// like expiry cleanup). `expiry_slot` is set by the expiry sweep only: a
    /// record whose current expiry is later than the slot is not due and is
    /// answered as not found, leaving it in place.
    ///
    /// Returns specific errors for not-found and permission-denied cases.
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
        scope: MessageScope<'_>,
        admin_did_hash: Option<&str>,
        expiry_slot: Option<u64>,
    ) -> Result<Vec<RemovedCopy>, MediatorError> {
        let _span = span!(
            Level::INFO,
            "database_delete",
            session = session_id,
            did_hash = did_hash,
            message_hash = message_hash,
        );
        async move {
            if !ops::is_message_id(message_hash) {
                return Err(ops::delete_not_found(message_hash, None));
            }
            let mut conn = self.get_async_connection().await?;

            // The receipts are written here in Rust rather than in the stored
            // function for the reason `mark_delivered` gives: a stale function
            // library loads without complaint and would silently never write
            // them. Both paths report the parties of each record removed.
            let result: Result<Vec<Removed>, redis::RedisError> = if self.keys.cluster_mode() {
                self.delete_records_in_steps(
                    &mut conn,
                    message_hash,
                    did_hash,
                    scope,
                    admin_did_hash,
                    expiry_slot,
                )
                .await
            } else {
                let (kind, scope_did) = match scope {
                    MessageScope::Recipient(to) => ("R", to),
                    MessageScope::Party(party) => ("P", party),
                    MessageScope::All => ("A", ""),
                };
                let mut cmd = redis::cmd("FCALL");
                cmd.arg("delete_message")
                    .arg(1)
                    .arg(message_hash)
                    .arg(did_hash)
                    .arg(admin_did_hash.unwrap_or(""))
                    .arg(kind)
                    .arg(scope_did)
                    .arg(expiry_slot.map(|slot| slot.to_string()).unwrap_or_default());
                let mut reply = cmd.query_async::<Vec<Vec<String>>>(&mut conn).await;
                // An instance of an earlier build reloaded its own library
                // over this one: load ours again and retry once.
                if let Err(err) = &reply
                    && is_older_library_error(&err.to_string())
                    && self.ensure_library(&mut conn).await
                {
                    reply = cmd.query_async::<Vec<Vec<String>>>(&mut conn).await;
                }
                reply.map(|rows| {
                    rows.into_iter()
                        .filter_map(|row| match row.as_slice() {
                            [to, from, _bytes, outbox, rest @ ..] => Some(Removed {
                                to: to.clone(),
                                from: from.clone(),
                                in_outbox: outbox == "1",
                                expires_at: rest.first().and_then(|v| v.parse().ok()).unwrap_or(0),
                            }),
                            _ => None,
                        })
                        .collect()
                })
            };

            match result {
                Ok(removed) => {
                    info!(
                        "Successfully deleted message_hash({}), {} record(s)",
                        message_hash,
                        removed.len()
                    );
                    let mut copies = Vec::with_capacity(removed.len());
                    for record in removed {
                        // The recipient removing its own copy is an
                        // acknowledgement (`MessageStore::acknowledged`).
                        if admin_did_hash.is_none() && record.to == did_hash {
                            self.record_acknowledged(
                                &mut conn,
                                message_hash,
                                &record.to,
                                record.expires_at,
                            )
                            .await;
                        }
                        // A receipt only for a record that sat in a sender's
                        // outbox, i.e. has a recorded sender.
                        if record.in_outbox && !record.from.is_empty() {
                            self.record_outbox_receipt(
                                &mut conn,
                                message_hash,
                                did_hash,
                                admin_did_hash.is_some(),
                                &record.to,
                                &record.from,
                            )
                            .await;
                        }
                        copies.push(RemovedCopy {
                            from_did_hash: (!record.from.is_empty()).then_some(record.from),
                            to_did_hash: record.to,
                        });
                    }
                    Ok(copies)
                }
                Err(err) => {
                    let err_str = err.to_string();

                    // Parse Lua error responses for specific handling
                    if err_str.contains("NOT_FOUND") {
                        debug!(
                            "Message not found for deletion: message_hash({})",
                            message_hash
                        );
                        Err(ops::delete_not_found(message_hash, None))
                    } else if err_str.contains("PERMISSION_DENIED") {
                        warn!(
                            "Permission denied deleting message_hash({}) by did_hash({})",
                            message_hash, did_hash
                        );
                        Err(ops::delete_permission_denied(message_hash, None))
                    } else if let Some(cap) = StorageCap::of_redis(&err) {
                        Err(MediatorError::storage_cap(
                            cap,
                            error_codes::DB_DELETE_ERROR,
                            "NA",
                            None,
                            format!("Couldn't delete message_hash ({message_hash}). Reason: {err}"),
                        ))
                    } else {
                        // Generic database error
                        Err(MediatorError::problem_with_log(
                            error_codes::DB_DELETE_ERROR,
                            "NA",
                            None,
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

    /// Cluster mode: resolve `scope` to records in Rust (a script may touch
    /// only the keys it declares, and the records of an id are found through
    /// its recipient index), then remove each in steps. Each removal claims
    /// its record and re-checks ownership atomically, so a record that went
    /// away since it was listed is skipped, never removed twice.
    async fn delete_records_in_steps(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
        did_hash: &str,
        scope: MessageScope<'_>,
        admin_did_hash: Option<&str>,
        expiry_slot: Option<u64>,
    ) -> redis::RedisResult<Vec<Removed>> {
        let by = match admin_did_hash {
            Some(admin) if admin == did_hash => DeletionAuthority::Admin {
                admin_did_hash: admin.to_string(),
            },
            _ => DeletionAuthority::Owner {
                did_hash: did_hash.to_string(),
            },
        };
        let records = self.records_of(conn, message_hash).await?;
        let parties: Vec<ops::RecordParties<'_>> = records
            .iter()
            .map(|(_, to, from)| ops::RecordParties {
                to_did_hash: to,
                from_did_hash: from.as_deref(),
            })
            .collect();
        let chosen = ops::select_records(scope, &by, &parties).map_err(|err| match err {
            ops::SelectError::NotFound => {
                coded_error("NOT_FOUND", format!("message_hash ({message_hash})"))
            }
            ops::SelectError::PermissionDenied => coded_error(
                "PERMISSION_DENIED",
                "Requesting DID does not have ownership of this message".to_string(),
            ),
        })?;

        let mut removed = Vec::new();
        let mut failure = None;
        for index in chosen {
            let (key_to, _, _) = &records[index];
            match self
                .delete_record_in_steps(
                    conn,
                    message_hash,
                    key_to.as_deref(),
                    did_hash,
                    admin_did_hash,
                    expiry_slot,
                )
                .await
            {
                Ok((to, from, in_outbox, expires_at)) => removed.push(Removed {
                    to,
                    from,
                    in_outbox,
                    expires_at,
                }),
                Err(err) if err.to_string().contains("NOT_FOUND") => {}
                Err(err) => failure = Some(err),
            }
        }
        if let Some(err) = failure {
            // Receipts for what did go are still owed; the caller reports
            // the failure, so nothing claims the rest were removed.
            for record in &removed {
                if record.in_outbox && !record.from.is_empty() {
                    self.record_outbox_receipt(
                        conn,
                        message_hash,
                        did_hash,
                        admin_did_hash.is_some(),
                        &record.to,
                        &record.from,
                    )
                    .await;
                }
            }
            return Err(err);
        }
        if removed.is_empty() {
            return Err(coded_error(
                "NOT_FOUND",
                format!("message_hash ({message_hash}) was removed by another delete"),
            ));
        }
        Ok(removed)
    }

    /// Every record of `message_hash`, cluster mode: `(key recipient, TO,
    /// FROM)`, where the key recipient is `None` for a legacy per-id record.
    /// Index members whose record is gone are skipped.
    async fn records_of(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
    ) -> redis::RedisResult<Vec<(Option<String>, String, Option<String>)>> {
        let keys = self.keys;
        let (legacy, members): (Vec<Option<String>>, Vec<String>) = redis::pipe()
            .cmd("HMGET")
            .arg(keys.msg_meta(message_hash, None))
            .arg("TO")
            .arg("FROM")
            .cmd("SMEMBERS")
            .arg(keys.msg_recipients(message_hash))
            .query_async(conn)
            .await?;
        let mut records = Vec::new();
        if let [Some(to), from] = legacy.as_slice() {
            records.push((None, to.clone(), from.clone()));
        }
        if members.is_empty() {
            return Ok(records);
        }
        let mut pipe = redis::pipe();
        for to in &members {
            pipe.cmd("HMGET")
                .arg(keys.msg_meta(message_hash, Some(to)))
                .arg("TO")
                .arg("FROM");
        }
        let rows: Vec<Vec<Option<String>>> = pipe.query_async(conn).await?;
        for (member, row) in members.into_iter().zip(rows) {
            if let [Some(to), from] = row.as_slice() {
                records.push((Some(member), to.clone(), from.clone()));
            }
        }
        Ok(records)
    }

    /// One record's delete in cluster mode, in steps a repeated delete can finish:
    ///
    /// 1. claim the message in its own slot: check ownership and take it for
    ///    this delete alone. A store still queueing it, or another delete
    ///    holding it, is waited out briefly; the second of two deletes then
    ///    finds the message gone and answers NOT_FOUND, as the library does;
    /// 2. release the recipient's and sender's queues concurrently, each
    ///    finding its entry in its own slot and undoing only the entry the
    ///    claim saw (idempotent, so retried a few times; a delete that
    ///    outlived its lease spares a copy of the message stored since);
    /// 3. remove the message only while this delete still holds it, so
    ///    exactly one delete reports it removed (R1.7), and count it.
    ///
    /// A failure in step 2 returns an error and gives the hold up, so the next
    /// delete (or the expiry sweeper, on its next pass) takes the message over
    /// at once and finishes; a store of the same message takes it over too and
    /// releases the claimed entries before queueing it again. On a full
    /// database step 1's write is refused, so the delete fails before
    /// changing anything, as the library's does.
    ///
    /// Returns the message's TO and FROM ("" for an anonymous sender), and
    /// whether it sat in the sender's outbox, which is when a receipt is due.
    ///
    /// `to` names the record (`None` for a legacy per-id record).
    async fn delete_record_in_steps(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
        to_key: Option<&str>,
        did_hash: &str,
        admin_did_hash: Option<&str>,
        expiry_slot: Option<u64>,
    ) -> redis::RedisResult<(String, String, bool, u64)> {
        use crate::store::redis::database::cluster_scripts::{
            ABANDON_DELETE, CLAIM_MESSAGE, DELETE_LEASE_MS, FINISH_DELETE, STORE_LEASE_MS,
        };

        let keys = self.keys;
        let meta_key = keys.msg_meta(message_hash, to_key);
        let member = Keys::record_member(message_hash, to_key);
        let token = uuid::Uuid::new_v4().to_string();
        let mut attempt = 1;
        let claimed: [String; 11] = loop {
            let mut claim = CLAIM_MESSAGE.prepare_invoke();
            claim
                .key(&meta_key)
                .arg(message_hash)
                .arg(did_hash)
                .arg(&token)
                .arg(STORE_LEASE_MS)
                .arg(DELETE_LEASE_MS)
                .arg(admin_did_hash.unwrap_or(""))
                .arg(expiry_slot.map(|slot| slot.to_string()).unwrap_or_default());
            match claim.invoke_async::<Vec<String>>(conn).await {
                Ok(claimed) => {
                    break <[String; 11]>::try_from(claimed).map_err(|reply| {
                        redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "CLAIM_MESSAGE reply",
                            format!("expected 11 fields, got {reply:?}"),
                        ))
                    })?;
                }
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

        let [
            to,
            from,
            bytes,
            receive_id,
            send_id,
            release_to,
            release_from,
            release_bytes,
            release_receive_id,
            release_send_id,
            expires_at,
        ] = claimed;
        let expires_at: u64 = expires_at.parse().unwrap_or(0);
        let mut in_outbox = !send_id.is_empty();
        for attempt in 1..=RELEASE_ATTEMPTS {
            // The entries of a taken-over delete whose store died before
            // releasing them, then this message's own.
            let released = async {
                if !release_to.is_empty() {
                    let (_, outbox) = self
                        .release_queues(
                            conn,
                            &member,
                            &release_to,
                            &release_from,
                            &release_bytes,
                            &release_receive_id,
                            &release_send_id,
                        )
                        .await?;
                    in_outbox |= outbox > 0 && release_from == from;
                }
                self.release_queues(conn, &member, &to, &from, &bytes, &receive_id, &send_id)
                    .await
            }
            .await;
            match released {
                Ok((_, outbox)) => {
                    in_outbox |= outbox > 0;
                    break;
                }
                Err(err) if attempt < RELEASE_ATTEMPTS => {
                    warn!("Retrying the queue release of message {message_hash}: {err}");
                    tokio::time::sleep(RELEASE_RETRY_DELAY * attempt).await;
                }
                Err(err) => {
                    // Give the hold up now rather than at the end of its
                    // lease, so the next delete or store takes the message
                    // over at once instead of waiting. The releases are
                    // idempotent, so whoever takes over finishes them.
                    if let Err(abandon) = ABANDON_DELETE
                        .key(&meta_key)
                        .arg(&token)
                        .invoke_async::<i64>(conn)
                        .await
                    {
                        warn!(
                            "Couldn't give up the delete hold on message {message_hash}: {abandon}"
                        );
                    }
                    return Err(err);
                }
            }
        }

        let removed: i64 = FINISH_DELETE
            .key(keys.msg(message_hash, to_key))
            .key(&meta_key)
            .key(keys.msg_recipients(message_hash))
            .arg(&token)
            .arg(to_key.unwrap_or(""))
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
        Ok((to, from, in_outbox, expires_at))
    }

    /// Releases a record's inbox and outbox entries concurrently, each in its
    /// own slot, and returns how many of each were released (0 or 1). The
    /// entries are found by `member` (`Keys::record_member`) in the queue-id
    /// hashes. An empty `from` is an anonymous sender; an empty entry id
    /// releases whatever entry is queued for the record. Idempotent: an entry already
    /// released, or replaced by a new copy of the message, is left alone.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn release_queues(
        &self,
        conn: &super::RedisConnection,
        member: &str,
        to: &str,
        from: &str,
        bytes: &str,
        receive_id: &str,
        send_id: &str,
    ) -> redis::RedisResult<(i64, i64)> {
        let (inbox, outbox) = futures_util::future::join(
            self.release_inbox(conn.clone(), to, member, bytes, receive_id),
            self.release_outbox(conn.clone(), from, to, member, bytes, send_id),
        )
        .await;
        Ok((inbox?, outbox?))
    }

    /// Releases the recipient's inbox entry `receive_id` of a message being
    /// deleted ("" for whatever entry is queued).
    async fn release_inbox(
        &self,
        mut conn: super::RedisConnection,
        to: &str,
        message_hash: &str,
        bytes: &str,
        receive_id: &str,
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
            .arg(receive_id)
            .invoke_async(&mut conn)
            .await
    }

    /// Releases the sender's outbox entry `send_id` of a message being
    /// deleted ("" for whatever entry is queued).
    async fn release_outbox(
        &self,
        mut conn: super::RedisConnection,
        from: &str,
        to: &str,
        message_hash: &str,
        bytes: &str,
        send_id: &str,
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
            .arg(send_id)
            .invoke_async(&mut conn)
            .await
    }

    /// Record that `to` removed its own copy of `message_hash` itself, until
    /// that copy's expiry (`store::acknowledged_until`). Best-effort, like the
    /// receipt: a missing record only makes a later repeated delete by `to`
    /// read as a withdrawal attempt, which removes nothing of another
    /// recipient's unless `to` also sent the same bytes to it.
    async fn record_acknowledged(
        &self,
        conn: &mut super::RedisConnection,
        message_hash: &str,
        to: &str,
        expires_at: u64,
    ) {
        let until = crate::store::acknowledged_until(expires_at, now_ms() / 1_000);
        let written: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(self.keys.acknowledged(to, message_hash))
            .arg(1)
            .arg("EXAT")
            .arg(until)
            .query_async(conn)
            .await;
        if let Err(err) = written {
            warn!("Couldn't record the acknowledgement of message_hash({message_hash}): {err}");
        }
    }

    /// Leave `from` a receipt saying why its copy of `message_hash` held for
    /// `to` left its outbox. One field per recipient in the sender's
    /// `RECEIPTS:<from>:<id>` hash, so one copy's removal never stands for
    /// another's; the hash expires [`OUTBOX_RECEIPT_TTL`] after the latest
    /// removal, and readers drop fields older than that.
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
        let key = self.keys.outbox_receipts(from, message_hash);
        let written: Result<(), redis::RedisError> = redis::pipe()
            .atomic()
            .hset(&key, to, receipt.encode())
            .expire(&key, OUTBOX_RECEIPT_TTL.as_secs() as i64)
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
