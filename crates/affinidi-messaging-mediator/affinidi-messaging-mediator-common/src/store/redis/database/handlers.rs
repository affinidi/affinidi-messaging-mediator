use super::Database;
use crate::database::RedisConnection;
use crate::error_codes;
use crate::errors::{MediatorError, StorageCap};
use redis::Value;
use std::fs::read_to_string;
use tracing::{Level, event};

/// What [`Database::load_library`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryLoad {
    /// The library was loaded (or was already loaded on a full database).
    Loaded {
        /// Its `LIBRARY_VERSION`.
        version: u32,
    },
    /// The server already holds a newer library, which was kept: an instance
    /// of a later build loaded it, and replacing it would take functions away
    /// from that instance.
    KeptNewer {
        /// The server's library version.
        server: u32,
        /// The version this instance would have loaded.
        ours: u32,
    },
    /// Cluster mode: no stored functions (see `cluster_scripts`).
    NotUsed,
}

/// The `LIBRARY_VERSION` an `atm-functions.lua` source declares
/// (`local LIBRARY_VERSION = <n>`), or 0 for a library from before versions.
pub fn library_version_of(source: &str) -> u32 {
    source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("local LIBRARY_VERSION")?
                .trim_start()
                .strip_prefix('=')?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

impl Database {
    /// Load the stored-function library from the file at `scripts_path`.
    /// See [`load_library`](Self::load_library).
    pub async fn load_scripts(&self, scripts_path: &str) -> Result<(), MediatorError> {
        if self.keys().cluster_mode() {
            event!(
                Level::INFO,
                "Cluster mode: not loading stored functions from {}",
                scripts_path
            );
            return Ok(());
        }
        let lua_scripts = read_to_string(scripts_path).map_err(|err| {
            MediatorError::ConfigError(
                error_codes::DB_CONFIG_INVALID,
                "Initialization".into(),
                format!("Couldn't ready database functions_file ({scripts_path}). Reason: {err}"),
            )
        })?;
        self.load_library(&lua_scripts, scripts_path)
            .await
            .map(|_| ())
    }

    /// The version of the stored-function library the server holds: 0 when
    /// it holds none, or one from before libraries carried a version.
    pub async fn server_library_version(&self) -> Result<u32, MediatorError> {
        let mut conn = self.get_connection().await?;
        match redis::cmd("FCALL_RO")
            .arg("library_version")
            .arg(0)
            .query_async::<i64>(&mut conn)
            .await
        {
            Ok(version) => Ok(u32::try_from(version).unwrap_or(0)),
            // No such function: no library, or one that predates versions.
            Err(err) if err.to_string().contains("Function not found") => Ok(0),
            Err(err) => Err(MediatorError::database_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "Initialization".into(),
                &err,
                format!("Couldn't read the stored-function library version: {err}"),
            )),
        }
    }

    /// Load `source` as the stored-function library (`FUNCTION LOAD
    /// REPLACE`), unless the server already holds a newer one. `origin` names
    /// where the source came from, for the log.
    ///
    /// In a rolling deploy every instance loads its library as it starts, so
    /// without the version check the last instance to start decided which
    /// library every instance ran, and an older instance restarting replaced
    /// the functions newer instances depend on.
    pub async fn load_library(
        &self,
        source: &str,
        origin: &str,
    ) -> Result<LibraryLoad, MediatorError> {
        // Cluster-mode servers have no FUNCTION LOAD; the cluster-mode code
        // sends its scripts with each call instead (see `cluster_scripts`).
        if self.keys().cluster_mode() {
            event!(
                Level::INFO,
                "Cluster mode: not loading stored functions from {}",
                origin
            );
            return Ok(LibraryLoad::NotUsed);
        }

        let ours = library_version_of(source);
        let server = self.server_library_version().await?;
        if server > ours {
            event!(
                Level::WARN,
                "The database already holds stored-function library version {server}, newer than this build's version {ours} ({origin}); keeping it. An instance of a later build shares this database."
            );
            return Ok(LibraryLoad::KeptNewer { server, ours });
        }

        let mut conn = self.get_connection().await?;
        match redis::cmd("FUNCTION")
            .arg("LOAD")
            .arg("REPLACE")
            .arg(source)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                event!(
                    Level::INFO,
                    "Loaded stored-function library version {} into the database from {}",
                    ours,
                    origin
                );
                self.handler.remember_library(source.to_string());
                Ok(LibraryLoad::Loaded { version: ours })
            }
            // A full database refuses FUNCTION LOAD (it is DENYOOM). That
            // must not stop a restart when the library this build ships is
            // already loaded: nothing would change by loading it again.
            Err(err)
                if StorageCap::of_redis(&err) == Some(StorageCap::Full)
                    && loaded_library_matches(&mut conn, source).await =>
            {
                event!(
                    Level::WARN,
                    "Database is full and refused FUNCTION LOAD, but the loaded library already matches {}; continuing",
                    origin
                );
                self.handler.remember_library(source.to_string());
                Ok(LibraryLoad::Loaded { version: ours })
            }
            Err(err) => {
                event!(
                    Level::WARN,
                    "database response for FUNCTION LOAD: ({})",
                    err
                );
                Err(MediatorError::database_from_redis(
                    error_codes::DB_OPERATION_ERROR,
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
    fn library_version_is_read_from_its_line() {
        assert_eq!(
            super::library_version_of("#!lua name=atm\n\nlocal LIBRARY_VERSION = 7\n"),
            7
        );
        assert_eq!(super::library_version_of("#!lua name=atm\n"), 0);
        assert!(
            super::library_version_of(include_str!("../../../../../conf/atm-functions.lua")) >= 2
        );
    }

    #[test]
    fn missing_library_has_no_code() {
        assert_eq!(find_library_code(&Value::Array(vec![])), None);
    }
}
