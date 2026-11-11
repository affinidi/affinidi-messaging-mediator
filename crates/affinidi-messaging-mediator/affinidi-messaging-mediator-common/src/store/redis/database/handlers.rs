use super::Database;
use crate::database::RedisConnection;
use crate::errors::{MediatorError, StorageCap};
use redis::Value;
use std::fs::read_to_string;
use tracing::{Level, event};

impl Database {
    // Load Redis scripts into the database
    pub async fn load_scripts(&self, scripts_path: &str) -> Result<(), MediatorError> {
        // Cluster-mode servers have no FUNCTION LOAD; the cluster-mode code
        // sends its scripts with each call instead (see `cluster_scripts`).
        if self.keys().cluster_mode() {
            event!(
                Level::INFO,
                "Cluster mode: not loading stored functions from {}",
                scripts_path
            );
            return Ok(());
        }

        // Load the file contents into a string
        let lua_scripts = read_to_string(scripts_path).map_err(|err| {
            MediatorError::ConfigError(
                2,
                "Initialization".into(),
                format!("Couldn't ready database functions_file ({scripts_path}). Reason: {err}"),
            )
        })?;

        let mut conn = self.get_connection().await?;
        match redis::cmd("FUNCTION")
            .arg("LOAD")
            .arg("REPLACE")
            .arg(&lua_scripts)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                event!(
                    Level::INFO,
                    "Loaded LUA scripts into the database from file: {}",
                    scripts_path
                );
                self.handler.remember_library(lua_scripts);
                Ok(())
            }
            // A full database refuses FUNCTION LOAD (it is DENYOOM). That
            // must not stop a restart when the library this build ships is
            // already loaded: nothing would change by loading it again.
            Err(err)
                if StorageCap::of_redis(&err) == Some(StorageCap::Full)
                    && loaded_library_matches(&mut conn, &lua_scripts).await =>
            {
                event!(
                    Level::WARN,
                    "Database is full and refused FUNCTION LOAD, but the loaded library already matches {}; continuing",
                    scripts_path
                );
                self.handler.remember_library(lua_scripts);
                Ok(())
            }
            Err(err) => {
                event!(
                    Level::WARN,
                    "database response for FUNCTION LOAD: ({})",
                    err
                );
                Err(MediatorError::database_from_redis(
                    14,
                    "Initialization".into(),
                    &err,
                    format!("Loading LUA scripts, received database error: {err}"),
                ))
            }
        }
    }
}

/// True when the server already holds the `atm` library with exactly
/// `expected` as its code.
async fn loaded_library_matches(conn: &mut RedisConnection, expected: &str) -> bool {
    let reply: Result<Value, _> = redis::cmd("FUNCTION")
        .arg("LIST")
        .arg("LIBRARYNAME")
        .arg("atm")
        .arg("WITHCODE")
        .query_async(conn)
        .await;
    match reply {
        Ok(value) => find_library_code(&value).as_deref() == Some(expected),
        Err(_) => false,
    }
}

/// Finds the `library_code` field in a FUNCTION LIST reply (RESP2 flat
/// arrays or RESP3 maps).
fn find_library_code(value: &Value) -> Option<String> {
    let text = |v: &Value| redis::from_redis_value::<String>(v.clone()).ok();
    match value {
        Value::Array(items) => {
            for pair in items.windows(2) {
                if text(&pair[0]).as_deref() == Some("library_code") {
                    return text(&pair[1]);
                }
            }
            items.iter().find_map(find_library_code)
        }
        Value::Map(entries) => entries.iter().find_map(|(k, v)| {
            if text(k).as_deref() == Some("library_code") {
                text(v)
            } else {
                find_library_code(v)
            }
        }),
        _ => None,
    }
}

impl crate::database::DatabaseHandler {
    /// Keep `source` as the library this instance runs against.
    pub(crate) fn remember_library(&self, source: String) {
        if let Ok(mut held) = self.functions_source.write() {
            *held = Some(source);
        }
    }

    /// Load this instance's library again, after a call showed the server
    /// holding an older one: an instance of an earlier build sharing the
    /// server loads its own library when it starts, replacing this one for
    /// every instance. Logged as an error because two builds sharing one
    /// server keep replacing each other's library; the deploy must stop every
    /// older instance first (see CHANGELOG). Returns whether it was loaded.
    pub(crate) async fn ensure_library(&self, conn: &mut RedisConnection) -> bool {
        let Some(source) = self.functions_source.read().ok().and_then(|s| s.clone()) else {
            return false;
        };
        event!(
            Level::ERROR,
            "The server holds an older stored-function library than this build; loading this build's again. An instance of an earlier build is sharing this database: stop it."
        );
        redis::cmd("FUNCTION")
            .arg("LOAD")
            .arg("REPLACE")
            .arg(&source)
            .exec_async(conn)
            .await
            .is_ok()
    }
}

/// Whether a stored-function error says the server is running the library of
/// an earlier build (its `delete_message` took at most two arguments).
pub(crate) fn is_older_library_error(err: &str) -> bool {
    err.contains("Requires 1-2 arguments")
}

#[cfg(test)]
mod tests {
    use super::find_library_code;
    use redis::Value;

    fn bulk(s: &str) -> Value {
        Value::BulkString(s.as_bytes().to_vec())
    }

    #[test]
    fn finds_library_code_in_resp2_reply() {
        let reply = Value::Array(vec![Value::Array(vec![
            bulk("library_name"),
            bulk("atm"),
            bulk("engine"),
            bulk("LUA"),
            bulk("functions"),
            Value::Array(vec![]),
            bulk("library_code"),
            bulk("#!lua name=atm\n"),
        ])]);
        assert_eq!(
            find_library_code(&reply).as_deref(),
            Some("#!lua name=atm\n")
        );
    }

    #[test]
    fn missing_library_has_no_code() {
        assert_eq!(find_library_code(&Value::Array(vec![])), None);
    }
}
