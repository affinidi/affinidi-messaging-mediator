// `DatabaseConfig` (the serde struct in `config.rs`) is always available
// under the `server` feature — the mediator binary parses it regardless
// of which storage backend the deployment selects. `DatabaseHandler`
// and the redis-using helpers below are gated on `redis-backend`.
pub mod config;

#[cfg(feature = "redis-backend")]
pub mod delete;
#[cfg(feature = "redis-backend")]
pub mod keys;

#[cfg(feature = "redis-backend")]
use crate::errors::MediatorError;
#[cfg(feature = "redis-backend")]
use crate::redact::redact_url;
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
/// Both kinds multiplex concurrent commands and reconnect on their own, and
/// both are cheap to clone. A connection handed out by the store carries its
/// circuit breaker, and every command sent over it reports its outcome there
/// (see [`with_breaker`](Self::with_breaker)).
#[cfg(feature = "redis-backend")]
#[derive(Clone)]
pub struct RedisConnection {
    link: RedisLink,
    breaker: Option<std::sync::Arc<crate::circuit_breaker::CircuitBreaker>>,
}

#[cfg(feature = "redis-backend")]
#[derive(Clone)]
enum RedisLink {
    /// Single server (cluster mode disabled).
    Single(ConnectionManager),
    /// Cluster-mode server; routes each command to its slot's node.
    Cluster(ClusterConnection),
}

#[cfg(feature = "redis-backend")]
impl RedisConnection {
    fn single(conn: ConnectionManager) -> Self {
        Self {
            link: RedisLink::Single(conn),
            breaker: None,
        }
    }

    fn cluster(conn: ClusterConnection) -> Self {
        Self {
            link: RedisLink::Cluster(conn),
            breaker: None,
        }
    }

    /// This connection, reporting the outcome of every command it sends to
    /// `breaker`: a connection failure or timeout as a failure, anything else
    /// (a reply, including an error reply such as a refused write) as a
    /// success, since the server answered.
    pub fn with_breaker(
        mut self,
        breaker: std::sync::Arc<crate::circuit_breaker::CircuitBreaker>,
    ) -> Self {
        self.breaker = Some(breaker);
        self
    }
}

/// Whether `err` says the server could not be reached or did not answer in
/// time, as opposed to an answer that was an error.
#[cfg(feature = "redis-backend")]
pub(crate) fn is_unavailable(err: &redis::RedisError) -> bool {
    err.is_io_error()
        || err.is_timeout()
        || err.is_connection_dropped()
        || err.is_connection_refusal()
        || err.is_unrecoverable_error()
}

#[cfg(feature = "redis-backend")]
fn record_outcome<T>(
    breaker: &crate::circuit_breaker::CircuitBreaker,
    result: &redis::RedisResult<T>,
) {
    match result {
        Err(err) if is_unavailable(err) => breaker.record_failure(),
        _ => breaker.record_success(),
    }
}

#[cfg(feature = "redis-backend")]
impl ConnectionLike for RedisConnection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        let breaker = self.breaker.clone();
        let sent = match &mut self.link {
            RedisLink::Single(conn) => conn.req_packed_command(cmd),
            RedisLink::Cluster(conn) => conn.req_packed_command(cmd),
        };
        match breaker {
            None => sent,
            Some(breaker) => Box::pin(async move {
                let result = sent.await;
                record_outcome(&breaker, &result);
                result
            }),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        let breaker = self.breaker.clone();
        let sent = match &mut self.link {
            RedisLink::Single(conn) => conn.req_packed_commands(pipeline, offset, count),
            RedisLink::Cluster(conn) => conn.req_packed_commands(pipeline, offset, count),
        };
        match breaker {
            None => sent,
            Some(breaker) => Box::pin(async move {
                let result = sent.await;
                record_outcome(&breaker, &result);
                result
            }),
        }
    }

    fn get_db(&self) -> i64 {
        match &self.link {
            RedisLink::Single(conn) => conn.get_db(),
            RedisLink::Cluster(conn) => conn.get_db(),
        }
    }
}

/// How many times start-up tries to reach the database, 10 seconds apart,
/// before giving up (about five minutes).
#[cfg(feature = "redis-backend")]
const CONNECT_ATTEMPTS: u32 = 30;

/// Whether a start-up connection error will not go away by retrying: the
/// server refused the credentials, or the client configuration is wrong.
#[cfg(feature = "redis-backend")]
fn is_fatal_connect_error(err: &redis::RedisError) -> bool {
    if matches!(
        err.kind(),
        redis::ErrorKind::AuthenticationFailed | redis::ErrorKind::InvalidClientConfig
    ) {
        return true;
    }
    let text = err.to_string();
    [
        "WRONGPASS",
        "NOAUTH",
        "NOPERM",
        "invalid password",
        "invalid username",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

/// After a failed start-up connection `attempt`: fail at once on an error
/// retrying cannot fix, fail after [`CONNECT_ATTEMPTS`], else wait 10 seconds
/// and let the caller try again.
#[cfg(feature = "redis-backend")]
async fn retry_or_fail(err: &redis::RedisError, attempt: u32) -> Result<(), MediatorError> {
    if is_fatal_connect_error(err) {
        event!(Level::ERROR, "Database refused the connection: {}", err);
        return Err(storage_config_error(format!(
            "The database refused the connection ({err}); check database_url's credentials"
        )));
    }
    if attempt >= CONNECT_ATTEMPTS {
        event!(
            Level::ERROR,
            "Couldn't reach the database after {attempt} attempts: {}",
            err
        );
        return Err(MediatorError::DatabaseError(
            crate::error_codes::DB_OPERATION_ERROR,
            "NA".into(),
            format!("Couldn't reach the database after {attempt} attempts: {err}"),
        ));
    }
    event!(Level::WARN, "Error connecting to database: {}", err);
    event!(
        Level::WARN,
        "Retrying database connection in 10 seconds (attempt {attempt} of {CONNECT_ATTEMPTS})"
    );
    sleep(Duration::from_secs(10)).await;
    Ok(())
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
    /// Key names for the configured `cluster_mode`.
    pub(crate) keys: keys::Keys,
    /// The stored-function library this instance loaded at start, kept so it
    /// can be loaded again if an instance running an older build replaces it
    /// on the shared server while this one runs (see `ensure_library`).
    pub(crate) functions_source: std::sync::Arc<std::sync::RwLock<Option<String>>>,
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
                crate::error_codes::DB_URL_INVALID,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.url",
                "Database URL ({1}) is invalid. Reason: {2}",
                vec![redact_url(&config.database_url), err.to_string()],
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Database URL ({}) is invalid. Reason: {}",
                    redact_url(&config.database_url),
                    err
                ),
            )
        })?;

        let manager_config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(Duration::from_secs(config.database_timeout.into())))
            .set_connection_timeout(Some(Duration::from_secs(config.database_timeout.into())));

        // Single-server connection first, even in cluster mode: the startup
        // checks need one node's answer, and a cluster client cannot connect
        // to a non-cluster server at all.
        let mut attempt = 0;
        let single = loop {
            attempt += 1;
            match client
                .get_connection_manager_with_config(manager_config.clone())
                .await
            {
                Ok(conn) => break conn,
                Err(err) => retry_or_fail(&err, attempt).await?,
            }
        };

        // Verify connectivity with PING
        let mut attempt = 0;
        loop {
            attempt += 1;
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
                Err(err) => retry_or_fail(&err, attempt).await?,
            }
        }

        // Check the version of Redis Server
        Self::check_server_version(&mut single.clone()).await?;
        Self::check_cluster_mode(&mut single.clone(), config.cluster_mode).await?;
        if config.cluster_mode {
            Self::check_single_endpoint(&mut single.clone()).await?;
            if is_replica(&mut single.clone()).await {
                return Err(storage_config_error(
                    "database.cluster_mode (DATABASE_CLUSTER_MODE) needs database_url to reach the primary node; it reached a replica".to_string(),
                ));
            }
        }

        let connection = if config.cluster_mode {
            RedisConnection::cluster(Self::connect_cluster(config).await?)
        } else {
            RedisConnection::single(single)
        };

        let database = Self {
            connection,
            redis_url: config.database_url.clone(),
            keys: keys::Keys::new(config.cluster_mode),
            functions_source: Default::default(),
        };

        // Warn if Redis connection has no authentication
        database.check_auth_warning(&config.database_url);
        database.check_key_layout().await?;

        Ok(database)
    }

    /// Refuses to start on data written under the other `cluster_mode`.
    ///
    /// Cluster mode stores per-account keys under hash-tagged names
    /// (`DID:{h}`), while `KNOWN_DIDS` keeps the same name in both modes. So
    /// flipping the setting on an existing dataset would silently orphan
    /// every account and message. Samples a few known accounts and refuses
    /// when none exists under this mode's names but some exist under the
    /// other's. An empty or unreadable `KNOWN_DIDS` passes.
    async fn check_key_layout(&self) -> Result<(), MediatorError> {
        let mut conn = self.connection.clone();
        let sample: Vec<String> = match redis::cmd("SRANDMEMBER")
            .arg("KNOWN_DIDS")
            .arg(5)
            .query_async(&mut conn)
            .await
        {
            Ok(sample) => sample,
            Err(err) => {
                warn!("Couldn't sample KNOWN_DIDS to check the key layout: {err}");
                return Ok(());
            }
        };
        let other = keys::Keys::new(!self.keys.cluster_mode());
        let (mut here, mut there) = (0, 0);
        for did_hash in &sample {
            let exists = |key: String| {
                let mut conn = conn.clone();
                async move {
                    redis::cmd("EXISTS")
                        .arg(key)
                        .query_async::<i64>(&mut conn)
                        .await
                        .unwrap_or(0)
                        > 0
                }
            };
            if exists(self.keys.did(did_hash)).await {
                here += 1;
            } else if exists(other.did(did_hash)).await {
                there += 1;
            }
        }
        if here > 0 || there == 0 {
            return Ok(());
        }
        let (setting, written) = if self.keys.cluster_mode() {
            ("true", "false")
        } else {
            ("false", "true")
        };
        let text = format!(
            "database.cluster_mode (DATABASE_CLUSTER_MODE) is {setting}, but the existing accounts were written with cluster_mode {written}; their data would be unreachable. Keep cluster_mode {written}, or migrate the data first"
        );
        Err(storage_config_error(text))
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
                    crate::error_codes::DB_URL_INVALID,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.url",
                    "Database URL ({1}) is invalid. Reason: {2}",
                    vec![redact_url(&config.database_url), err.to_string()],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Database URL ({}) is invalid. Reason: {}",
                        redact_url(&config.database_url),
                        err
                    ),
                )
            })?;

        let mut attempt = 0;
        loop {
            attempt += 1;
            match client.get_async_connection().await {
                Ok(conn) => {
                    info!("Connected to database in cluster mode");
                    return Ok(conn);
                }
                Err(err) => retry_or_fail(&err, attempt).await?,
            }
        }
    }

    /// Refuses a cluster with more than one primary node. Cluster mode moves
    /// only the main connection to a cluster client; the blocking reads and
    /// pub/sub stay on a single-node connection. A single-endpoint cluster
    /// (ElastiCache Serverless shows one virtual node) routes those, but a
    /// multi-node one answers `MOVED` and forwarding would stop.
    async fn check_single_endpoint(conn: &mut ConnectionManager) -> Result<(), MediatorError> {
        let slots: Vec<Vec<Value>> = redis::cmd("CLUSTER")
            .arg("SLOTS")
            .query_async(conn)
            .await
            .map_err(|err| storage_info_error(&err))?;
        // Each range is [start, end, primary, replicas...]; a primary is
        // [host, port, ...].
        let primaries: std::collections::HashSet<String> = slots
            .iter()
            .filter_map(|range| match range.get(2) {
                Some(Value::Array(node)) => {
                    let host = redis::from_redis_value::<String>(node.first()?.clone()).ok()?;
                    let port = redis::from_redis_value::<i64>(node.get(1)?.clone()).ok()?;
                    Some(format!("{host}:{port}"))
                }
                _ => None,
            })
            .collect();
        if primaries.len() <= 1 {
            return Ok(());
        }
        Err(storage_config_error(format!(
            "database.cluster_mode (DATABASE_CLUSTER_MODE) supports a single-endpoint cluster such as ElastiCache Serverless; this cluster has {} primary nodes",
            primaries.len()
        )))
    }

    /// Refuses to start when `cluster_mode` doesn't match the server.
    ///
    /// With `cluster_mode` off this must never get in the way of a server
    /// that worked before cluster mode existed: it reads `cluster_enabled`
    /// from `INFO cluster` (no extra ACL permission, no error-text matching)
    /// and only refuses on a definite `cluster_enabled:1`. Any error or a
    /// missing field means "not a cluster".
    ///
    /// With `cluster_mode` on it uses `CLUSTER INFO`, which ElastiCache
    /// Serverless supports (it reports `cluster_enabled:1` too).
    async fn check_cluster_mode(
        conn: &mut ConnectionManager,
        cluster_mode: bool,
    ) -> Result<(), MediatorError> {
        let server_is_cluster = if cluster_mode {
            match redis::cmd("CLUSTER")
                .arg("INFO")
                .query_async::<String>(conn)
                .await
            {
                Ok(_) => true,
                Err(err) if err.to_string().contains("cluster support disabled") => false,
                Err(err) => {
                    return Err(storage_info_error(&err));
                }
            }
        } else {
            match redis::cmd("INFO")
                .arg("cluster")
                .query_async::<String>(conn)
                .await
            {
                Ok(info) => info_reports_cluster_enabled(&info),
                Err(err) => {
                    event!(
                        Level::DEBUG,
                        "Couldn't read INFO cluster ({err}); assuming the server is not a cluster"
                    );
                    false
                }
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
        Err(storage_config_error(format!(
            "database.cluster_mode (DATABASE_CLUSTER_MODE) is {setting}, but the database server has cluster mode {server}"
        )))
    }

    /// Returns a dedicated Redis connection with no response timeout.
    /// This must be used for blocking commands (e.g. XREADGROUP BLOCK)
    /// because the normal connection's response timeout will kill the
    /// connection before the block period completes.
    pub async fn get_blocking_connection(&self) -> Result<MultiplexedConnection, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                crate::error_codes::DB_CONNECTION_ERROR,
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
        let mut conn = client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(|err| {
                MediatorError::problem_with_log(
                    crate::error_codes::DB_CONNECTION_ERROR,
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
            })?;
        // In cluster mode this plain connection goes to whichever node the
        // endpoint resolves to. XREADGROUP writes, so a replica would answer
        // MOVED/READONLY; refuse it and let the caller's retry reconnect.
        if self.keys.cluster_mode() && is_replica(&mut conn).await {
            return Err(MediatorError::problem_with_log(
                crate::error_codes::DB_CONNECTION_ERROR,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.blocking",
                "Can't establish blocking database connection. Reason: {1}",
                vec!["the endpoint resolved to a replica node".into()],
                StatusCode::SERVICE_UNAVAILABLE,
                "Can't establish blocking database connection. Reason: the endpoint resolved to a replica node".to_string(),
            ));
        }
        Ok(conn)
    }

    /// Returns a redis database connector or returns an Error
    /// This should only be used for pubsub operations
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                crate::error_codes::DB_PUBSUB_CONNECTION_ERROR,
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
                crate::error_codes::DB_PUBSUB_RECEIVER_ERROR,
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
                return Err(storage_info_error(&err));
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
                        crate::error_codes::DB_VERSION_PARSE_ERROR,
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
                    crate::error_codes::DB_VERSION_INCOMPATIBLE,
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
                crate::error_codes::DB_VERSION_UNKNOWN,
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

/// A query about the database server itself (version, cluster layout)
/// failed.
#[cfg(feature = "redis-backend")]
fn storage_info_error(err: &redis::RedisError) -> MediatorError {
    MediatorError::problem_with_log(
        crate::error_codes::DB_SERVER_INFO_ERROR,
        "NA",
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "me.res.storage.info",
        "Couldn't query database information. Reason: {1}",
        vec![err.to_string()],
        StatusCode::SERVICE_UNAVAILABLE,
        format!("Couldn't query database information. Reason: {err}"),
    )
}

/// A storage configuration that stops the mediator starting, as a problem
/// report whose text is also the log line.
#[cfg(feature = "redis-backend")]
fn storage_config_error(text: String) -> MediatorError {
    MediatorError::problem_with_log(
        crate::error_codes::DB_CONFIG_INVALID,
        "NA",
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "me.res.storage.config",
        "{1}",
        vec![text.clone()],
        StatusCode::INTERNAL_SERVER_ERROR,
        text,
    )
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

/// True only when the node definitely reports itself a replica. A server
/// that doesn't support `ROLE` (some proxies, ElastiCache Serverless) is
/// taken as a primary, so this never refuses a working endpoint.
#[cfg(feature = "redis-backend")]
async fn is_replica<C: redis::aio::ConnectionLike>(conn: &mut C) -> bool {
    match redis::cmd("ROLE").query_async::<Value>(conn).await {
        Ok(Value::Array(items)) => items.first().is_some_and(|role| {
            matches!(
                redis::from_redis_value::<String>(role.clone()).as_deref(),
                Ok("slave" | "replica")
            )
        }),
        _ => false,
    }
}

/// True only when an `INFO cluster` reply says `cluster_enabled:1`.
#[cfg(feature = "redis-backend")]
fn info_reports_cluster_enabled(info: &str) -> bool {
    info.lines()
        .filter_map(|line| line.trim().strip_prefix("cluster_enabled:"))
        .any(|value| value.trim() == "1")
}

#[cfg(all(test, feature = "redis-backend"))]
mod cluster_detection_tests {
    use super::info_reports_cluster_enabled;

    #[test]
    fn info_cluster_enabled_parsing() {
        assert!(info_reports_cluster_enabled(
            "# Cluster\r\ncluster_enabled:1\r\n"
        ));
        assert!(!info_reports_cluster_enabled(
            "# Cluster\r\ncluster_enabled:0\r\n"
        ));
        assert!(!info_reports_cluster_enabled(""));
        assert!(!info_reports_cluster_enabled(
            "# Server\r\nredis_version:7.2.0\r\n"
        ));
    }
}
