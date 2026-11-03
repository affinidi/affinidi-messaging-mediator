// `DatabaseConfig` (the serde struct in `config.rs`) is always available
// under the `server` feature — the mediator binary parses it regardless
// of which storage backend the deployment selects. `DatabaseHandler`
// and the redis-using helpers below are gated on `redis-backend`.
pub mod config;

#[cfg(feature = "redis-backend")]
pub mod delete;

#[cfg(feature = "redis-backend")]
use crate::errors::MediatorError;
#[cfg(feature = "redis-backend")]
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
#[cfg(feature = "redis-backend")]
use axum::http::StatusCode;
#[cfg(feature = "redis-backend")]
use config::DatabaseConfig;
#[cfg(feature = "redis-backend")]
use redis::aio::{
    ConnectionLike, ConnectionManager, ConnectionManagerConfig, MultiplexedConnection, PubSub,
};
#[cfg(feature = "redis-backend")]
use redis::{
    AsyncConnectionConfig, Cmd, Pipeline, RedisFuture, Value, cluster::ClusterClientBuilder,
    cluster_async::ClusterConnection,
};

#[cfg(feature = "redis-backend")]
use semver::{Version, VersionReq};
#[cfg(feature = "redis-backend")]
use std::time::Duration;
#[cfg(feature = "redis-backend")]
use tokio::time::sleep;
#[cfg(feature = "redis-backend")]
use tracing::{Level, event, info, warn};

/// The mediator's main Redis connection, chosen by `cluster_mode`.
///
/// Both variants multiplex concurrent commands and reconnect on their own,
/// and both are cheap to clone.
#[cfg(feature = "redis-backend")]
#[derive(Clone)]
pub enum RedisConnection {
    /// Single server (cluster mode disabled).
    Single(ConnectionManager),
    /// Cluster-mode server; routes each command to its slot's node.
    Cluster(ClusterConnection),
}

#[cfg(feature = "redis-backend")]
impl ConnectionLike for RedisConnection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        match self {
            Self::Single(conn) => conn.req_packed_command(cmd),
            Self::Cluster(conn) => conn.req_packed_command(cmd),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        match self {
            Self::Single(conn) => conn.req_packed_commands(pipeline, offset, count),
            Self::Cluster(conn) => conn.req_packed_commands(pipeline, offset, count),
        }
    }

    fn get_db(&self) -> i64 {
        match self {
            Self::Single(conn) => conn.get_db(),
            Self::Cluster(conn) => conn.get_db(),
        }
    }
}

/// Low-level Redis connection handler used by the mediator.
///
/// Uses a single multiplexed connection (via `ConnectionManager` for auto-reconnect,
/// or a cluster connection when `cluster_mode` is on) instead of a connection pool.
/// `MultiplexedConnection` handles concurrent commands over one TCP connection,
/// making a pool unnecessary.
#[cfg(feature = "redis-backend")]
#[derive(Clone)]
pub struct DatabaseHandler {
    /// Auto-reconnecting multiplexed connection for normal Redis operations.
    connection: RedisConnection,
    /// Redis connection URL (kept for creating pub/sub and blocking connections).
    redis_url: String,
}

#[cfg(feature = "redis-backend")]
const REDIS_VERSION_REQ: &str = ">=7.1, <9.0";

/// Parses `redis_version`, accepting `major.minor` as `major.minor.0`:
/// ElastiCache Serverless reports `7.2`, which strict semver rejects.
#[cfg(feature = "redis-backend")]
fn parse_server_version(version: &str) -> Result<Version, semver::Error> {
    Version::parse(version).or_else(|err| {
        if version.matches('.').count() == 1 {
            Version::parse(&format!("{version}.0"))
        } else {
            Err(err)
        }
    })
}

#[cfg(feature = "redis-backend")]
impl DatabaseHandler {
    /// Creates a new `DatabaseHandler`, establishing a multiplexed connection and verifying
    /// that the Redis server version is compatible. Retries on connection failure.
    pub async fn new(config: &DatabaseConfig) -> Result<Self, MediatorError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let client = redis::Client::open(config.database_url.as_str()).map_err(|err| {
            MediatorError::problem_with_log(
                1,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.url",
                "Database URL ({1}) is invalid. Reason: {2}",
                vec![config.database_url.clone(), err.to_string()],
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Database URL ({}) is invalid. Reason: {}",
                    config.database_url, err
                ),
            )
        })?;

        let manager_config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(Duration::from_secs(config.database_timeout.into())))
            .set_connection_timeout(Some(Duration::from_secs(config.database_timeout.into())));

        // Single-server connection first, even in cluster mode: the startup
        // checks need one node's answer, and a cluster client cannot connect
        // to a non-cluster server at all.
        let single = loop {
            match client
                .get_connection_manager_with_config(manager_config.clone())
                .await
            {
                Ok(conn) => break conn,
                Err(err) => {
                    event!(Level::WARN, "Error connecting to database: {}", err);
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        };

        // Verify connectivity with PING
        loop {
            let mut conn = single.clone();
            let pong: Result<String, redis::RedisError> =
                redis::cmd("PING").query_async(&mut conn).await;
            match pong {
                Ok(pong) => {
                    event!(
                        Level::INFO,
                        "Database ping ok! Expected (PONG) received ({})",
                        pong
                    );
                    break;
                }
                Err(err) => {
                    event!(
                        Level::WARN,
                        "Can't get connection to database. Reason: {}",
                        err
                    );
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }

        // Check the version of Redis Server
        Self::check_server_version(&mut single.clone()).await?;
        Self::check_cluster_mode(&mut single.clone(), config.cluster_mode).await?;

        let connection = if config.cluster_mode {
            RedisConnection::Cluster(Self::connect_cluster(config).await?)
        } else {
            RedisConnection::Single(single)
        };

        let database = Self {
            connection,
            redis_url: config.database_url.clone(),
        };

        // Warn if Redis connection has no authentication
        database.check_auth_warning(&config.database_url);

        Ok(database)
    }

    /// Returns a clone of the auto-reconnecting multiplexed connection.
    /// This is cheap (Arc clone internally) and supports concurrent use.
    pub async fn get_async_connection(&self) -> Result<RedisConnection, MediatorError> {
        Ok(self.connection.clone())
    }

    /// Opens the cluster connection, retrying until the server is reachable.
    async fn connect_cluster(config: &DatabaseConfig) -> Result<ClusterConnection, MediatorError> {
        let timeout = Duration::from_secs(config.database_timeout.into());
        let client = ClusterClientBuilder::new(vec![config.database_url.as_str()])
            .connection_timeout(timeout)
            .response_timeout(timeout)
            .build()
            .map_err(|err| {
                MediatorError::problem_with_log(
                    1,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.url",
                    "Database URL ({1}) is invalid. Reason: {2}",
                    vec![config.database_url.clone(), err.to_string()],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Database URL ({}) is invalid. Reason: {}",
                        config.database_url, err
                    ),
                )
            })?;

        loop {
            match client.get_async_connection().await {
                Ok(conn) => {
                    info!("Connected to database in cluster mode");
                    return Ok(conn);
                }
                Err(err) => {
                    event!(Level::WARN, "Error connecting to database cluster: {}", err);
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }
    }

    /// Refuses to start when `cluster_mode` doesn't match the server.
    ///
    /// Uses `CLUSTER INFO`: ElastiCache Serverless supports it, and a
    /// non-cluster server rejects it with "cluster support disabled".
    async fn check_cluster_mode(
        conn: &mut ConnectionManager,
        cluster_mode: bool,
    ) -> Result<(), MediatorError> {
        let server_is_cluster = match redis::cmd("CLUSTER")
            .arg("INFO")
            .query_async::<String>(conn)
            .await
        {
            Ok(_) => true,
            Err(err) if err.to_string().contains("cluster support disabled") => false,
            Err(err) => {
                return Err(MediatorError::problem_with_log(
                    6,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.info",
                    "Couldn't query database information. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Couldn't query database information. Reason: {err}"),
                ));
            }
        };

        if server_is_cluster == cluster_mode {
            return Ok(());
        }
        let setting = if cluster_mode { "true" } else { "false" };
        let server = if server_is_cluster {
            "enabled"
        } else {
            "disabled"
        };
        Err(MediatorError::problem_with_log(
            2,
            "NA",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "me.res.storage.config",
            "database.cluster_mode (DATABASE_CLUSTER_MODE) is {1}, but the database server has cluster mode {2}",
            vec![setting.to_string(), server.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "database.cluster_mode (DATABASE_CLUSTER_MODE) is {setting}, but the database server has cluster mode {server}"
            ),
        ))
    }

    /// Returns a dedicated Redis connection with no response timeout.
    /// This must be used for blocking commands (e.g. XREADGROUP BLOCK)
    /// because the normal connection's response timeout will kill the
    /// connection before the block period completes.
    pub async fn get_blocking_connection(&self) -> Result<MultiplexedConnection, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                10,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.blocking",
                "Can't open database connection for blocking ops. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't open database connection for blocking ops. Reason: {err}"),
            )
        })?;

        let config = AsyncConnectionConfig::new().set_response_timeout(None);
        client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(|err| {
                MediatorError::problem_with_log(
                    11,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.connection.blocking",
                    "Can't establish blocking database connection. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Can't establish blocking database connection. Reason: {err}"),
                )
            })
    }

    /// Returns a redis database connector or returns an Error
    /// This should only be used for pubsub operations
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                4,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.pubsub",
                "Can't open database connection for pubsub. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't open database connection for pubsub. Reason: {err}"),
            )
        })?;

        client.get_async_pubsub().await.map_err(|err| {
            MediatorError::problem_with_log(
                5,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.pubsub.receiver",
                "Can't get pubsub receiver. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't get pubsub receiver. Reason: {err}"),
            )
        })
    }

    /// Helper function to check the version of the Redis Server
    async fn check_server_version(conn: &mut ConnectionManager) -> Result<String, MediatorError> {
        let redis_version_req: VersionReq = match VersionReq::parse(REDIS_VERSION_REQ) {
            Ok(result) => result,
            Err(err) => panic!("Couldn't process required Redis version. Reason: {err}"),
        };

        let server_info: String = match redis::cmd("INFO").arg("SERVER").query_async(conn).await {
            Ok(result) => result,
            Err(err) => {
                return Err(MediatorError::problem_with_log(
                    6,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.info",
                    "Couldn't query database information. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Couldn't query database information. Reason: {err}"),
                ));
            }
        };

        let server_version = server_info
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(":").collect();
                if parts.len() == 2 {
                    if parts[0] == "redis_version" {
                        Some(parts[1].to_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next();

        if let Some(version) = server_version {
            let semver_version: Version = match parse_server_version(&version) {
                Ok(result) => result,
                Err(err) => {
                    return Err(MediatorError::problem_with_log(
                        7,
                        "NA",
                        None,
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.version",
                        "Cannot parse database version ({1}). Reason: {2}",
                        vec![version.clone(), err.to_string()],
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Cannot parse database version ({version}). Reason: {err}"),
                    ));
                }
            };
            if redis_version_req.matches(&semver_version) {
                info!("Redis version is compatible: {}", version);
                Ok(version.to_owned())
            } else {
                Err(MediatorError::problem_with_log(
                    8,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.version.incompatible",
                    "Database version {1} does not match expected {2}",
                    vec![version.clone(), redis_version_req.to_string()],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Database version {version} does not match expected {redis_version_req}"
                    ),
                ))
            }
        } else {
            Err(MediatorError::problem(
                9,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.version.unknown",
                "Couldn't determine database version",
                vec![],
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }

    /// Log a warning if the Redis connection URL has no authentication configured.
    /// Local connections (127.0.0.1, localhost, unix sockets) get a softer warning.
    fn check_auth_warning(&self, url: &str) {
        let is_tls = url.starts_with("rediss://");
        let is_local = url.contains("127.0.0.1")
            || url.contains("localhost")
            || url.contains("[::1]")
            || url.starts_with("unix://");

        // Check for password in URL: redis://:password@host or redis://user:pass@host
        let has_auth = url.contains('@');

        if !has_auth {
            if is_local {
                warn!(
                    "Redis connection has no authentication (password). \
                     This is acceptable for local development but should be \
                     secured with requirepass or ACLs for any shared environment."
                );
            } else {
                warn!(
                    "SECURITY WARNING: Redis connection has no authentication! \
                     Configure a password: redis://:yourpassword@host:port/ \
                     or use Redis ACLs. Unauthenticated remote Redis is a critical security risk."
                );
            }
        }

        if !is_tls && !is_local {
            warn!(
                "Redis connection is not using TLS (rediss://). \
                 For production deployments, use rediss:// to encrypt data in transit."
            );
        }

        if is_tls {
            info!("Redis TLS connection detected (rediss://)");
        }
    }
}

#[cfg(all(test, feature = "redis-backend"))]
mod tests {
    use super::*;

    #[test]
    fn server_version_with_patch_parses() {
        assert_eq!(
            parse_server_version("7.2.4").ok(),
            Some(Version::new(7, 2, 4))
        );
    }

    #[test]
    fn server_version_without_patch_parses_as_zero() {
        assert_eq!(
            parse_server_version("7.2").ok(),
            Some(Version::new(7, 2, 0))
        );
    }

    #[test]
    fn server_version_garbage_is_rejected() {
        assert!(parse_server_version("7").is_err());
        assert!(parse_server_version("seven.two").is_err());
    }
}
