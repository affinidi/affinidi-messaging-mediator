/*!
 * Database related routines that deal with the management of raw messages in the database.
 *
 */

use super::Database;
use crate::errors::MediatorError;
use crate::store::ops;
use crate::store::types::{DeletionAuthority, MessageScope, Session};
use crate::types::messages::Folder;
use ahash::AHashMap as HashMap;
use tracing::{Instrument, Level, debug, span, warn};

// Redis-backend implementation behind `RedisStore`.
impl Database {
    /// Will purge/delete all messages from the database for the given DID and folder
    /// Returns the number of messages purged and the total bytes purged.
    /// `by` decides the senders' outbox receipts (see
    /// `MediatorStore::purge_folder_by`).
    pub(crate) async fn purge_messages(
        &self,
        session: &Session,
        did_hash: &str,
        folder: Folder,
        by: &DeletionAuthority,
    ) -> Result<(usize, usize), MediatorError> {
        let mut purge_count: usize = 0;
        let mut purge_bytes: usize = 0;

        while let Some((count, bytes)) =
            self._purge_messages(session, did_hash, &folder, by).await?
        {
            purge_count += count;
            purge_bytes += bytes;
        }

        // Remove the stream key
        self.delete_folder_stream(session, did_hash, &folder)
            .await?;

        Ok((purge_count, purge_bytes))
    }

    // Helper function that does the actual work of purging messages: removes
    // the record behind the folder's first entry, then the entry. Returns
    // `None` once the folder is empty, else what this step removed (`(0, 0)`
    // for an entry whose record was already gone — a concurrent pickup, the
    // expiry sweep, or one left behind before records were per recipient —
    // which is dropped so it cannot hold up the rest of the folder).
    async fn _purge_messages(
        &self,
        session: &Session,
        did_hash: &str,
        folder: &Folder,
        by: &DeletionAuthority,
    ) -> Result<Option<(usize, usize)>, MediatorError> {
        let _span = span!(Level::DEBUG, "purge_messages", did_hash = did_hash, folder = ?folder);

        async move {
            let mut con = self.get_connection().await?;

            // Grab a message from the Stream
            let key = if folder == &Folder::Inbox {
                self.keys().receive_q(did_hash)
            } else {
                self.keys().send_q(did_hash)
            };
            let message: Vec<(String, HashMap<String, String>)> =
                redis::Cmd::xrange_count(&key, "-", "+", 1)
                    .query_async(&mut con)
                    .await
                    .map_err(|e| {
                        MediatorError::database_from_redis(
                            14,
                            session.session_id.clone(),
                            &e,
                            format!("Failed to read messages for purge. Reason: {e}"),
                        )
                    })?;

            let Some((stream_id, message)) = message.first() else {
                debug!("No messages to purge...");
                return Ok(None);
            };

            // Extract the message details. An entry without them names no
            // record; drop it so the purge moves on.
            let Some(message_hash) = message.get("MSG_ID") else {
                warn!("Couldn't find MSG_ID");
                self._delete_msg_stream_record(session, &key, stream_id)
                    .await?;
                return Ok(Some((0, 0)));
            };

            let bytes = if let Some(bytes) = message.get("BYTES") {
                match bytes.parse::<usize>() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            "Invalid BYTES value ({}) in message ({}): {}",
                            bytes, message_hash, e
                        );
                        0_usize
                    }
                }
            } else {
                warn!("BYTES value missing in message ({})", message_hash);
                0_usize
            };

            // The record this entry is for: the folder owner's in an inbox,
            // the entry's recipient in an outbox — never another recipient's
            // copy of the same bytes.
            let scope = match (folder, message.get("TO")) {
                (Folder::Outbox, Some(to)) => MessageScope::Recipient(to),
                (Folder::Outbox, None) => MessageScope::Party(did_hash),
                (Folder::Inbox, _) => MessageScope::Recipient(did_hash),
            };

            // Delete the message. An admin delete passes the admin DID as both
            // requester and admin, as `RedisStore::delete_message` does, so the
            // Lua check accepts it and the receipt reads `discarded`.
            let (requester, admin) = match by {
                DeletionAuthority::Owner { did_hash } => (did_hash.as_str(), None),
                DeletionAuthority::Admin { admin_did_hash } => {
                    (admin_did_hash.as_str(), Some(admin_did_hash.as_str()))
                }
            };
            let removed = match self
                .handler
                .delete_message(
                    Some(&session.session_id),
                    requester,
                    message_hash,
                    scope,
                    admin,
                    None,
                )
                .await
            {
                Ok(_) => (1, bytes),
                Err(e) if ops::is_delete_not_found(&e) => (0, 0),
                Err(e) => return Err(e),
            };

            // Delete the stream entry (the delete removed it already when it
            // removed the record; this covers an entry with no record)
            self._delete_msg_stream_record(session, &key, stream_id)
                .await?;

            Ok(Some(removed))
        }
        .instrument(_span)
        .await
    }

    // Deletes a stream record
    async fn _delete_msg_stream_record(
        &self,
        session: &Session,
        key: &str,
        id: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        redis::Cmd::xdel(key, &[id])
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::database_from_redis(
                    14,
                    session.session_id.clone(),
                    &e,
                    format!("Failed to delete stream record. Reason: {e}"),
                )
            })
    }

    // Deletes a stream record
    pub async fn delete_folder_stream(
        &self,
        session: &Session,
        did_hash: &str,
        folder: &Folder,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let key = if folder == &Folder::Inbox {
            self.keys().receive_q(did_hash)
        } else {
            self.keys().send_q(did_hash)
        };

        redis::Cmd::del(key)
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::database_from_redis(
                    14,
                    session.session_id.clone(),
                    &e,
                    format!("Failed to delete folder stream. Reason: {e}"),
                )
            })
    }
}
