/*!
 * Database related routines that deal with the management of raw messages in the database.
 *
 */

use super::Database;
use crate::errors::MediatorError;
use crate::store::types::Session;
use crate::types::messages::Folder;

// Redis-backend implementation behind `RedisStore`.
impl Database {
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
