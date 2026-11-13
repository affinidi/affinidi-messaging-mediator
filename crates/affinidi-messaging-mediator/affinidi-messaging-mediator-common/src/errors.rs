use crate::error_codes;
use crate::types::{
    messages::GenericDataStruct,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{Level, event};

/// Session ID is a random string of 12 characters
type SessId = String;

/// Error Code (unique code for each error)
type ErrorCode = u16;

/// Structured context carried alongside an error for logging and client responses.
///
/// Attach this to an [`AppError`] via [`AppError::with_context`] so that
/// `request_id`, `session_id`, and `did_hash` appear automatically in log
/// output. Only `request_id` is serialized to the client in [`ErrorResponse`].
#[derive(Debug, Default, Clone, Serialize)]
pub struct ErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_hash: Option<String>,
}

/// Wrapper that converts a [`MediatorError`] into an Axum HTTP response.
pub struct AppError {
    error: MediatorError,
    context: ErrorContext,
}

impl AppError {
    /// Attach structured context (request_id, session_id, did_hash) to this error.
    ///
    /// The context fields will be included in log output and — where appropriate —
    /// in the JSON response sent to the client.
    pub fn with_context(mut self, ctx: ErrorContext) -> Self {
        self.context = ctx;
        self
    }
}

impl<E> From<E> for AppError
where
    E: Into<MediatorError>,
{
    fn from(err: E) -> Self {
        Self {
            error: err.into(),
            context: ErrorContext::default(),
        }
    }
}

/// Errors relating to the Mediator Processors. These are largely internal to the Mediator errors
/// They should not be exposed to the user
#[derive(Clone, Error, Debug)]
#[non_exhaustive]
pub enum ProcessorError {
    /// A general-purpose internal error in a background processor.
    #[error("CommonError: {0}")]
    CommonError(String),
    /// An error that occurred while forwarding a message to a remote mediator.
    #[error("ForwardingError: {0}")]
    ForwardingError(String),
    /// An error during the periodic cleanup of expired messages.
    #[error("MessageExpiryCleanupError: {0}")]
    MessageExpiryCleanupError(String),
}

/// MediatorError the first String is always the session_id
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MediatorError {
    #[error("Internal error handling failure: {2}")]
    ErrorHandlingError(ErrorCode, SessId, String),
    #[error("{2}")]
    InternalError(ErrorCode, SessId, String),
    #[error("Couldn't parse ({2}). Reason: {3}")]
    ParseError(ErrorCode, SessId, String, String),
    #[error("Permission Error: {2}")]
    PermissionError(ErrorCode, SessId, String),
    #[error("Request is invalid: {2}")]
    RequestDataError(ErrorCode, SessId, String),
    #[error("Service Limit exceeded: {2}")]
    ServiceLimitError(ErrorCode, SessId, String),
    #[error("Unauthorized: {2}")]
    Unauthorized(ErrorCode, SessId, String),
    #[error("DID error: did({2}) Reason: {3}")]
    DIDError(ErrorCode, SessId, String, String),
    #[error("Configuration Error: {2}")]
    ConfigError(ErrorCode, SessId, String),
    #[error("Database Error: {2}")]
    DatabaseError(ErrorCode, SessId, String),
    #[error("Failed to unpack message: {2}")]
    MessageUnpackError(ErrorCode, SessId, String),
    #[error("MessageExpired: expiry({2}) now({3})")]
    MessageExpired(ErrorCode, SessId, String, String),
    #[error("Failed to pack message: {2}")]
    MessagePackError(ErrorCode, SessId, String),
    #[error("Feature not implemented: {2}")]
    NotImplemented(ErrorCode, SessId, String),
    #[error("Authorization Session ({1}) error: {2}")]
    SessionError(ErrorCode, SessId, String),
    #[error("Anonymous message error: {2}")]
    AnonymousMessageError(ErrorCode, SessId, String),
    #[error("Forwarding/Routing message error: {2}")]
    ForwardMessageError(ErrorCode, SessId, String),
    #[error("Authentication error: {1}")]
    AuthenticationError(ErrorCode, String),
    #[error("ACL denied: {1}")]
    ACLDenied(ErrorCode, String),
    #[error("Processor ({1}) error: {2}")]
    ProcessorError(ErrorCode, ProcessorError, String),

    /// This is a catch-all for any error that is using DIDComm Problem Reports
    /// `ErrorCode` - Unique Error code
    /// `SessId` - Session ID
    /// `Option<String>` - MSG ID responding to
    /// `ProblemReport` - DIDComm Problem Report
    /// `u16` - HTTP status code
    /// `String` - Log message
    #[error("Mediator Error: code({3}): {4}")]
    MediatorError(
        ErrorCode,
        SessId,
        Option<String>,
        Box<ProblemReport>,
        u16,
        String,
    ),
}

/// The problem-report code of a [`StorageCap::Full`] refusal.
pub const STORAGE_FULL_CODE: &str = "e.m.me.res.storage.full";
/// The problem-report code of a [`StorageCap::Busy`] refusal.
pub const STORAGE_BUSY_CODE: &str = "w.m.me.res.storage.busy";

/// A database limit that refused an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageCap {
    /// Used memory is past its maximum: the database refuses writes, even
    /// one that would change nothing, until space is freed.
    Full,
    /// The database didn't answer within `database_timeout` (it is
    /// throttled at its ECPU maximum, or unreachable), or in cluster mode
    /// another store or delete still holds the message past the wait.
    Busy,
}

impl StorageCap {
    /// The cap a Redis error reports, read from the error itself: a reply
    /// timeout, or the server's error code (`OOM`, `STORE_IN_PROGRESS`,
    /// `DELETE_IN_PROGRESS`). A pipeline or an aborted transaction reports
    /// each command's error, and any of them counts.
    #[cfg(feature = "redis-backend")]
    pub fn of_redis(err: &redis::RedisError) -> Option<Self> {
        if err.is_timeout() {
            return Some(Self::Busy);
        }
        let errors = err.clone().into_server_errors()?;
        let mut cap = None;
        for (_, server) in errors.iter() {
            match server.code() {
                "OOM" => return Some(Self::Full),
                "STORE_IN_PROGRESS" | "DELETE_IN_PROGRESS" => cap = Some(Self::Busy),
                _ => {}
            }
        }
        cap
    }
}

impl MediatorError {
    /// Name `msg_id` as the message this error answers, unless it already
    /// names one.
    ///
    /// The id becomes the problem report's `pthid`, which is how a client
    /// waiting on a reply to `msg_id` recognises the refusal as that reply.
    /// Without it, a refusal sent over a websocket reaches the client but
    /// matches nothing it is waiting for: the call times out and reports "no
    /// response" in place of the real reason. Protocol handlers build most
    /// errors without the id, so the dispatcher applies it once for all of
    /// them.
    pub fn threaded_to(self, msg_id: &str) -> Self {
        match self {
            Self::MediatorError(code, session, None, report, status, log) => {
                Self::MediatorError(code, session, Some(msg_id.to_string()), report, status, log)
            }
            other => other,
        }
    }

    /// A refusal by a database cap, as a problem report that names it.
    ///
    /// Left as a plain database error, a cap reaches an HTTP client as a
    /// generic "Service temporarily unavailable" and a websocket client as
    /// nothing. `msg_id` is the message the refusal answers (its `pthid`),
    /// when known; `cause` is logged.
    pub fn storage_cap(
        cap: StorageCap,
        code: ErrorCode,
        session_id: impl Into<String>,
        msg_id: Option<String>,
        cause: impl std::fmt::Display,
    ) -> Self {
        match cap {
            StorageCap::Full => Self::problem_with_log(
                error_codes::STORAGE_FULL,
                session_id,
                msg_id,
                ProblemReportSorter::Error,
                ProblemReportScope::Message,
                "me.res.storage.full",
                "Mediator storage is full; nothing new can be stored until space is freed",
                vec![],
                StatusCode::INSUFFICIENT_STORAGE,
                format!("Storage full (error {code}): {cause}"),
            ),
            StorageCap::Busy => Self::problem_with_log(
                error_codes::STORAGE_BUSY,
                session_id,
                msg_id,
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "me.res.storage.busy",
                "Mediator storage is busy; retry later",
                vec![],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Storage busy (error {code}): {cause}"),
            ),
        }
    }

    /// Whether this is a [`storage_cap`](Self::storage_cap) refusal. A handler
    /// that wraps a storage error in its own report passes these through, so
    /// the client still learns that storage is full or busy.
    ///
    /// Matched exactly on the error number and problem code that
    /// [`storage_cap`](Self::storage_cap) sets, never on a part of either.
    pub fn is_storage_cap(&self) -> bool {
        matches!(self, Self::MediatorError(error_codes::STORAGE_FULL, _, _, report, _, _) if report.code == STORAGE_FULL_CODE)
            || matches!(self, Self::MediatorError(error_codes::STORAGE_BUSY, _, _, report, _, _) if report.code == STORAGE_BUSY_CODE)
    }

    /// A storage failure as a generic `503` (`me.res.storage.error`) that
    /// says nothing of its cause, for a caller with no session yet: telling
    /// an unauthenticated caller that storage is full or busy would let
    /// anyone probe the mediator's capacity. `cause` is logged only.
    pub fn storage_error_opaque(
        code: ErrorCode,
        session_id: impl Into<String>,
        cause: impl std::fmt::Display,
    ) -> Self {
        Self::problem_with_log(
            code,
            session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "me.res.storage.error",
            "Database transaction error",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Database transaction error: {cause}"),
        )
    }

    /// For a caller with no session yet: a storage cap refusal or a plain
    /// database error becomes [`storage_error_opaque`](Self::storage_error_opaque);
    /// anything else is left as it is.
    pub fn opaque_storage(self) -> Self {
        match self {
            Self::DatabaseError(code, session, text) => {
                Self::storage_error_opaque(code, session, text)
            }
            cap if cap.is_storage_cap() => {
                let (code, session) = match &cap {
                    Self::MediatorError(code, session, ..) => (*code, session.clone()),
                    _ => unreachable!("a cap refusal is a problem report"),
                };
                Self::storage_error_opaque(code, session, cap)
            }
            other => other,
        }
    }

    /// A failed Redis call as a [`DatabaseError`](Self::DatabaseError), or as
    /// the [`storage_cap`](Self::storage_cap) refusal when `err` reports one.
    /// `text` describes the failure and is what gets logged.
    #[cfg(feature = "redis-backend")]
    pub fn database_from_redis(
        code: ErrorCode,
        session_id: SessId,
        err: &redis::RedisError,
        text: String,
    ) -> Self {
        match StorageCap::of_redis(err) {
            Some(cap) => Self::storage_cap(cap, code, session_id, None, text),
            None => Self::DatabaseError(code, session_id, text),
        }
    }

    /// [`database_from_redis`](Self::database_from_redis) for a login or
    /// session write: a [`SessionError`](Self::SessionError) unless `err`
    /// reports a cap.
    #[cfg(feature = "redis-backend")]
    pub fn session_from_redis(
        code: ErrorCode,
        session_id: SessId,
        err: &redis::RedisError,
        text: String,
    ) -> Self {
        match StorageCap::of_redis(err) {
            Some(cap) => Self::storage_cap(cap, code, session_id, None, text),
            None => Self::SessionError(code, session_id, text),
        }
    }

    /// Creates a `MediatorError::MediatorError` with a DIDComm Problem Report.
    ///
    /// The `comment` is also used as the log message. For cases where the log
    /// message should differ (e.g., when comment has `{1}` placeholders but the
    /// log should have interpolated values), use [`problem_with_log`](Self::problem_with_log).
    #[allow(clippy::too_many_arguments)]
    pub fn problem(
        code: u16,
        session_id: impl Into<String>,
        msg_id: Option<String>,
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: &str,
        comment: &str,
        args: Vec<String>,
        http_status: StatusCode,
    ) -> Self {
        Self::MediatorError(
            code,
            session_id.into(),
            msg_id,
            Box::new(ProblemReport::new(
                sorter,
                scope,
                descriptor.into(),
                comment.into(),
                args,
                None,
            )),
            http_status.as_u16(),
            comment.to_string(),
        )
    }

    /// Like [`problem`](Self::problem) but with a separate log message.
    ///
    /// Use this when the Problem Report comment has `{1}`, `{2}` placeholders
    /// but the log message should contain the actual interpolated values.
    #[allow(clippy::too_many_arguments)]
    pub fn problem_with_log(
        code: u16,
        session_id: impl Into<String>,
        msg_id: Option<String>,
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: &str,
        comment: &str,
        args: Vec<String>,
        http_status: StatusCode,
        log_msg: impl Into<String>,
    ) -> Self {
        Self::MediatorError(
            code,
            session_id.into(),
            msg_id,
            Box::new(ProblemReport::new(
                sorter,
                scope,
                descriptor.into(),
                comment.into(),
                args,
                None,
            )),
            http_status.as_u16(),
            log_msg.into(),
        )
    }
}

impl From<MediatorError> for ProcessorError {
    fn from(error: MediatorError) -> Self {
        ProcessorError::CommonError(error.to_string())
    }
}

impl From<ProcessorError> for MediatorError {
    fn from(error: ProcessorError) -> Self {
        MediatorError::ProcessorError(
            error_codes::PROCESSOR_ERROR,
            error.clone(),
            error.to_string(),
        )
    }
}

/// What an HTTP client is told for any [`MediatorError::SessionError`]; the
/// error's own text is logged only.
pub const SESSION_ERROR_MESSAGE: &str = "Session could not be established or found";

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let ctx = &self.context;

        // Build a context suffix for log lines. Contains whichever of
        // request_id / session_id / did_hash are present.
        let ctx_log: String = {
            let mut parts = Vec::new();
            if let Some(ref rid) = ctx.request_id {
                parts.push(format!("request_id={rid}"));
            }
            if let Some(ref sid) = ctx.session_id {
                parts.push(format!("session_id={sid}"));
            }
            if let Some(ref dh) = ctx.did_hash {
                parts.push(format!("did_hash={dh}"));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!(" [{}]", parts.join(" "))
            }
        };

        let request_id = ctx.request_id.clone();

        // Set by the arms that can carry a pacing hint; attached as a
        // `Retry-After` header below.
        let mut retry_after_secs: Option<u64> = None;

        let response = match self.error {
            MediatorError::ErrorHandlingError(error_code, session_id, msg) => {
                event!(
                    Level::WARN,
                    "{}: ErrorHandlingError({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "ErrorHandlingError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::InternalError(error_code, session_id, msg) => {
                event!(
                    Level::WARN,
                    "{}: InternalError({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "InternalError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::ParseError(error_code, session_id, what, msg) => {
                event!(
                    Level::WARN,
                    "{}: ParseError({}): couldn't parse ({}). Reason: {}{}",
                    session_id,
                    error_code,
                    what,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: ParseError".to_string(),
                    message: format!("Couldn't parse ({what})"),
                }
            }
            MediatorError::PermissionError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::FORBIDDEN.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "Forbidden: PermissionError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::RequestDataError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: RequestDataError".to_string(),
                    message: format!("Bad Request: ({msg})"),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ServiceLimitError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: ServiceLimitError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::Unauthorized(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "Unauthorized".to_string(),
                    message: "Unauthorized access".to_string(),
                };
                event!(
                    Level::WARN,
                    "{}: Unauthorized({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                response
            }
            MediatorError::DIDError(error_code, session_id, did, msg) => {
                event!(
                    Level::WARN,
                    "{}: DIDError({}): did({}) Error: {}{}",
                    session_id,
                    error_code,
                    did,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DIDError".to_string(),
                    message: format!("did({did}) Error: invalid or unresolvable DID"),
                }
            }
            MediatorError::ConfigError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: ConfigError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "ConfigError".to_string(),
                    message: "Service configuration error".to_string(),
                }
            }
            MediatorError::DatabaseError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: DatabaseError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DatabaseError".to_string(),
                    message: "Service temporarily unavailable".to_string(),
                }
            }
            MediatorError::MessageUnpackError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: MessageUnpackError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "MessageUnpackError".to_string(),
                    message: "Failed to unpack message".to_string(),
                }
            }
            MediatorError::MessageExpired(error_code, session_id, expired, now) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "MessageExpired".to_string(),
                    message: format!("Message expired: expiry({expired}) now({now})"),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::MessagePackError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: MessagePackError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "MessagePackError".to_string(),
                    message: "Failed to pack message".to_string(),
                }
            }
            MediatorError::NotImplemented(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_IMPLEMENTED.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "NotImplemented".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::SessionError(error_code, session_id, message) => {
                // The text can come from the store (a backend's own error
                // message) and the caller may have no session yet, so it is
                // logged and the client gets a fixed message.
                event!(
                    Level::WARN,
                    "{}: SessionError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "SessionError".to_string(),
                    message: SESSION_ERROR_MESSAGE.to_string(),
                }
            }
            MediatorError::AnonymousMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "AnonymousMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ForwardMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ForwardMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::AuthenticationError(error_code, message) => {
                event!(
                    Level::WARN,
                    "AuthenticationError({}): {}{}",
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "AuthenticationError".to_string(),
                    message: "Authentication failed".to_string(),
                }
            }
            MediatorError::ACLDenied(error_code, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ACLDenied".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ProcessorError(error_code, processor, message) => {
                event!(
                    Level::WARN,
                    "ProcessorError({}): Processor ({}): {}{}",
                    error_code,
                    processor,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ProcessorError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::MediatorError(
                error_code,
                session_id,
                _,
                problem_report,
                http_code,
                log_text,
            ) => {
                event!(Level::WARN, "{}{}", log_text, ctx_log);
                // Read before the report is serialised away: a queue-full
                // refusal carries a pacing hint, and the code is what
                // identifies it.
                retry_after_secs = queue_full_retry_after_secs(&problem_report.code)
                    .or_else(|| storage_busy_retry_after_secs(&problem_report.code));
                ErrorResponse {
                    http_code,
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DIDCommProblemReport".to_string(),
                    message: serde_json::to_string(&problem_report)
                        .unwrap_or_else(|_| "Failed to serialize Problem Report".to_string()),
                }
            }
        };
        let status =
            StatusCode::from_u16(response.http_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        match retry_after_secs {
            Some(secs) => (
                status,
                [(header::RETRY_AFTER, secs.to_string())],
                Json(response),
            )
                .into_response(),
            None => (status, Json(response)).into_response(),
        }
    }
}

/// Seconds a client should wait before resending, for a queue-full refusal.
///
/// A `503` with no `Retry-After` gives a caller nothing to pace on, so it
/// retries as fast as its loop allows — into a queue that is full precisely
/// because nothing is draining it. A modest floor is worth more than an
/// accurate number here, and an accurate number is not available: the
/// condition clears when the *recipient* next collects, which the mediator
/// cannot predict and should not pretend to.
///
/// So this is deliberately a **floor, not a schedule**. It is long enough to
/// stop a hot retry loop and short enough that a queue which drains a moment
/// later is not held back for minutes.
pub const QUEUE_FULL_RETRY_AFTER_SECS: u64 = 30;

/// The pacing hint for a problem-report code, when it is a queue-depth
/// refusal.
///
/// Matched on the code suffix rather than the numeric error code so that the
/// hint follows the documented `limits.queue.*` contract — the same strings a
/// client matches on — rather than a parallel table of numbers that can drift
/// from it.
fn queue_full_retry_after_secs(code: &str) -> Option<u64> {
    const GATES: [&str; 3] = [
        "limits.queue.peer",
        "limits.queue.sender",
        "limits.queue.recipient",
    ];
    GATES
        .iter()
        .any(|gate| code.ends_with(gate))
        .then_some(QUEUE_FULL_RETRY_AFTER_SECS)
}

/// The least a client is told to wait before retrying when storage is busy
/// (throttled or slow). Short: a throttle clears within seconds, but without
/// any hint a client retries in a hot loop and deepens it.
pub const STORAGE_BUSY_RETRY_AFTER_SECS: u64 = 5;

/// Up to this many seconds are added to [`STORAGE_BUSY_RETRY_AFTER_SECS`] at
/// random, so the clients refused in one throttle don't all come back at the
/// same moment and throttle it again.
pub const STORAGE_BUSY_RETRY_JITTER_SECS: u64 = 5;

fn storage_busy_retry_after_secs(code: &str) -> Option<u64> {
    (code == STORAGE_BUSY_CODE).then(|| {
        STORAGE_BUSY_RETRY_AFTER_SECS + rand::rng().random_range(0..=STORAGE_BUSY_RETRY_JITTER_SECS)
    })
}

/// JSON error response body returned by the mediator's HTTP API.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub http_code: u16,
    pub error_code: u16,
    pub error_code_str: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.session_id, self.http_code, self.error_code, self.error_code_str, self.message,
        )?;
        if let Some(ref rid) = self.request_id {
            write!(f, " request_id({rid})")?;
        }
        Ok(())
    }
}
/// JSON success response body returned by the mediator's HTTP API.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub session_id: String,
    pub http_code: u16,
    pub error_code: i32,
    pub error_code_str: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: Option<T>,
}

impl<T: GenericDataStruct> fmt::Display for SuccessResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.session_id, self.http_code, self.error_code, self.error_code_str, self.message,
        )
    }
}

impl<T: GenericDataStruct> SuccessResponse<T> {
    pub fn response(
        session_id: &str,
        http_code: StatusCode,
        msg: &str,
        data: Option<T>,
    ) -> Json<SuccessResponse<T>> {
        let response = SuccessResponse {
            session_id: session_id.to_string(),
            http_code: http_code.as_u16(),
            error_code: 0,
            error_code_str: "Ok".to_string(),
            message: msg.to_string(),
            data,
        };
        event!(Level::INFO, "{response}");
        Json(response)
    }
}

/// Creates a random 12-character alphanumeric session identifier.
pub fn create_session_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
    use axum::http::StatusCode;

    /// A Redis error as the client reads it from the server's reply.
    #[cfg(feature = "redis-backend")]
    fn server_error(reply: &str) -> redis::RedisError {
        redis::parse_redis_value(format!("-{reply}\r\n").as_bytes())
            .and_then(|value| value.extract_error())
            .expect_err("an error reply")
    }

    #[cfg(feature = "redis-backend")]
    #[test]
    fn the_cap_is_read_from_the_redis_error() {
        let oom = server_error("OOM command not allowed when used memory > 'maxmemory'.");
        assert_eq!(StorageCap::of_redis(&oom), Some(StorageCap::Full));
        assert_eq!(
            StorageCap::of_redis(&server_error("OOM reworded by a later server")),
            Some(StorageCap::Full),
            "the code counts, not the wording"
        );
        let timeout = redis::RedisError::from(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(StorageCap::of_redis(&timeout), Some(StorageCap::Busy));
        for held in [
            "STORE_IN_PROGRESS message is still being stored",
            "DELETE_IN_PROGRESS message is being deleted",
        ] {
            assert_eq!(
                StorageCap::of_redis(&server_error(held)),
                Some(StorageCap::Busy),
                "{held}"
            );
        }
        for other in [
            "ERR operation timed out",
            "ERR command not allowed when used memory > 'maxmemory'.",
            "CROSSSLOT Keys in request don't hash to the same slot",
        ] {
            assert_eq!(StorageCap::of_redis(&server_error(other)), None, "{other}");
        }
    }

    /// The problem code and HTTP status of a named refusal, or `None` when
    /// the error is left as it was.
    fn named(err: &MediatorError) -> Option<(String, StatusCode)> {
        match err {
            MediatorError::MediatorError(_, _, _, report, status, _) => Some((
                report.code.clone(),
                StatusCode::from_u16(*status).expect("valid status"),
            )),
            _ => None,
        }
    }

    #[cfg(feature = "redis-backend")]
    #[test]
    fn a_redis_error_is_named_where_it_is_converted() {
        let full = Some((
            "e.m.me.res.storage.full".to_string(),
            StatusCode::INSUFFICIENT_STORAGE,
        ));
        let oom = server_error("OOM command not allowed when used memory > 'maxmemory'.");
        assert_eq!(
            named(&MediatorError::database_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                &oom,
                format!("store: {oom}")
            )),
            full
        );
        assert_eq!(
            named(&MediatorError::session_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                &oom,
                format!("put_session: {oom}")
            )),
            full
        );
        let timeout = redis::RedisError::from(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(
            named(&MediatorError::database_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                &timeout,
                "inbox_status failed".into()
            )),
            Some((
                "w.m.me.res.storage.busy".to_string(),
                StatusCode::SERVICE_UNAVAILABLE
            ))
        );
        let other = server_error("ERR operation timed out");
        assert!(matches!(
            MediatorError::database_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                &other,
                other.to_string()
            ),
            MediatorError::DatabaseError(crate::error_codes::DB_OPERATION_ERROR, _, _)
        ));
        assert!(matches!(
            MediatorError::session_from_redis(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                &other,
                other.to_string()
            ),
            MediatorError::SessionError(crate::error_codes::DB_OPERATION_ERROR, _, _)
        ));
    }

    #[test]
    fn a_cap_keeps_the_request_it_answers() {
        match MediatorError::storage_cap(
            StorageCap::Busy,
            crate::error_codes::DB_DELETE_ERROR,
            "NA",
            Some("req-1".into()),
            "held",
        ) {
            MediatorError::MediatorError(_, _, msg_id, report, _, _) => {
                assert!(report.code.ends_with("storage.busy"));
                assert_eq!(msg_id.as_deref(), Some("req-1"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let waits: std::collections::HashSet<u64> = (0..200)
            .filter_map(|_| storage_busy_retry_after_secs(STORAGE_BUSY_CODE))
            .collect();
        assert!(
            waits.iter().all(|w| (STORAGE_BUSY_RETRY_AFTER_SECS
                ..=STORAGE_BUSY_RETRY_AFTER_SECS + STORAGE_BUSY_RETRY_JITTER_SECS)
                .contains(w)),
            "{waits:?}"
        );
        assert!(waits.len() > 1, "the wait is spread out: {waits:?}");
        assert_eq!(storage_busy_retry_after_secs("x.me.res.storage.busy"), None);
    }

    #[test]
    fn the_cap_codes_are_what_the_builder_sets() {
        let code = |cap| match MediatorError::storage_cap(
            cap,
            crate::error_codes::DB_OPERATION_ERROR,
            "s",
            None,
            "x",
        ) {
            MediatorError::MediatorError(_, _, _, report, _, _) => report.code,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(code(StorageCap::Full), STORAGE_FULL_CODE);
        assert_eq!(code(StorageCap::Busy), STORAGE_BUSY_CODE);
    }

    #[test]
    fn an_opaque_storage_error_says_nothing_of_its_cause() {
        let e = MediatorError::storage_error_opaque(
            crate::error_codes::DB_OPERATION_ERROR,
            "",
            "OOM command not allowed",
        );
        match &e {
            MediatorError::MediatorError(_, _, _, report, status, log) => {
                assert!(report.code.ends_with("me.res.storage.error"));
                assert!(report.args.is_empty());
                assert!(!report.comment.contains("OOM"));
                assert_eq!(*status, 503);
                assert!(log.contains("OOM"), "the cause is logged");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!e.is_storage_cap());
    }

    #[test]
    fn only_storage_failures_are_made_opaque() {
        let opaque = |e: MediatorError| match e.opaque_storage() {
            MediatorError::MediatorError(_, _, _, report, 503, _) => {
                report.code.ends_with("me.res.storage.error") && report.args.is_empty()
            }
            _ => false,
        };
        assert!(opaque(MediatorError::storage_cap(
            StorageCap::Full,
            crate::error_codes::DB_OPERATION_ERROR,
            "s",
            None,
            "x"
        )));
        assert!(opaque(MediatorError::storage_cap(
            StorageCap::Busy,
            crate::error_codes::DB_OPERATION_ERROR,
            "s",
            None,
            "x"
        )));
        assert!(opaque(MediatorError::DatabaseError(
            crate::error_codes::DB_OPERATION_ERROR,
            "s".into(),
            "OOM".into()
        )));
        assert!(matches!(
            MediatorError::SessionError(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                "no such session".into()
            )
            .opaque_storage(),
            MediatorError::SessionError(..)
        ));
        assert!(matches!(
            refusal(None).opaque_storage(),
            MediatorError::MediatorError(crate::error_codes::AUTH_SEND_DENIED, ..)
        ));
    }

    #[test]
    fn a_cap_refusal_is_recognised_for_passing_through() {
        for cap in [StorageCap::Full, StorageCap::Busy] {
            assert!(
                MediatorError::storage_cap(
                    cap,
                    crate::error_codes::DB_OPERATION_ERROR,
                    "s",
                    None,
                    "x"
                )
                .is_storage_cap()
            );
        }
        assert!(!refusal(None).is_storage_cap());
        let lookalike = MediatorError::problem(
            crate::error_codes::STORAGE_FULL,
            "s",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "other.me.res.storage.full",
            "x",
            vec![],
            StatusCode::INSUFFICIENT_STORAGE,
        );
        assert!(!lookalike.is_storage_cap());
        assert!(
            !MediatorError::DatabaseError(
                crate::error_codes::DB_OPERATION_ERROR,
                "s".into(),
                "storage.full".into()
            )
            .is_storage_cap()
        );
    }

    #[tokio::test]
    async fn a_session_error_reaches_an_http_client_without_its_text() {
        let detail = "Failed to retrieve session (abc). Reason: ERR backend detail 10.0.0.7:6379";
        let response = AppError::from(MediatorError::SessionError(
            crate::error_codes::DB_OPERATION_ERROR,
            "abc".into(),
            detail.into(),
        ))
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], SESSION_ERROR_MESSAGE);
        assert_eq!(body["errorCodeStr"], "SessionError");
        assert_eq!(body["errorCode"], 14);
        assert!(!body.to_string().contains("backend detail"));
    }

    #[test]
    fn a_database_error_is_not_named_from_its_text() {
        let error = MediatorError::DatabaseError(
            crate::error_codes::DB_OPERATION_ERROR,
            "s".into(),
            "\"OOM\": command not allowed when used memory > 'maxmemory'. timed out".into(),
        );
        assert_eq!(
            AppError::from(error).into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn a_full_database_reaches_an_http_client_as_507() {
        let error = MediatorError::storage_cap(
            StorageCap::Full,
            crate::error_codes::DB_OPERATION_ERROR,
            "s",
            None,
            "full",
        );
        assert_eq!(
            AppError::from(error).into_response().status(),
            StatusCode::INSUFFICIENT_STORAGE
        );
    }

    fn refusal(msg_id: Option<String>) -> MediatorError {
        MediatorError::problem(
            crate::error_codes::AUTH_SEND_DENIED,
            "s",
            msg_id,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.send",
            "refused",
            vec![],
            StatusCode::FORBIDDEN,
        )
    }

    fn answered(e: &MediatorError) -> Option<&str> {
        match e {
            MediatorError::MediatorError(_, _, msg_id, ..) => msg_id.as_deref(),
            _ => None,
        }
    }

    #[test]
    fn a_refusal_is_threaded_to_the_request_unless_it_already_is() {
        assert_eq!(answered(&refusal(None).threaded_to("req-1")), Some("req-1"));
        assert_eq!(
            answered(&refusal(Some("own".into())).threaded_to("req-1")),
            Some("own"),
            "an id set by the handler is kept"
        );
        // Errors without a problem report pass through unchanged.
        let internal = MediatorError::InternalError(
            crate::error_codes::DB_URL_INVALID,
            "s".into(),
            "x".into(),
        );
        assert!(matches!(
            internal.threaded_to("req-1"),
            MediatorError::InternalError(..)
        ));
    }

    #[test]
    fn test_problem_creates_mediator_error() {
        let err = MediatorError::problem(
            crate::error_codes::AUTH_SEND_DENIED,
            "test-session",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.send",
            "DID isn't allowed to send",
            vec![],
            StatusCode::FORBIDDEN,
        );
        match err {
            MediatorError::MediatorError(code, session, msg_id, report, http, log) => {
                assert_eq!(code, 44);
                assert_eq!(session, "test-session");
                assert!(msg_id.is_none());
                assert_eq!(report.code, "e.p.authorization.send");
                assert_eq!(report.comment, "DID isn't allowed to send");
                assert_eq!(http, 403);
                assert_eq!(log, "DID isn't allowed to send");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_problem_with_log_separate_messages() {
        let err = MediatorError::problem_with_log(
            crate::error_codes::PARSE_ERROR,
            "sess-123",
            Some("msg-456".to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.serialize",
            "Couldn't serialize: {1}",
            vec!["parse error".to_string()],
            StatusCode::BAD_REQUEST,
            "Couldn't serialize message",
        );
        match err {
            MediatorError::MediatorError(code, session, msg_id, report, http, log) => {
                assert_eq!(code, 19);
                assert_eq!(session, "sess-123");
                assert_eq!(msg_id, Some("msg-456".to_string()));
                assert_eq!(report.code, "w.m.message.serialize");
                assert_eq!(report.comment, "Couldn't serialize: {1}");
                assert_eq!(report.args, vec!["parse error"]);
                assert_eq!(http, 400);
                assert_eq!(log, "Couldn't serialize message");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_problem_with_args() {
        let err = MediatorError::problem(
            crate::error_codes::TOO_MANY_ATTACHMENTS,
            "s1",
            Some("m1".to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.forwarding.attachments.too_many",
            "Too many attachments ({1}). Limit ({2})",
            vec!["5".to_string(), "1".to_string()],
            StatusCode::BAD_REQUEST,
        );
        match err {
            MediatorError::MediatorError(_, _, _, report, _, _) => {
                assert_eq!(report.args.len(), 2);
                assert_eq!(report.args[0], "5");
                assert_eq!(report.args[1], "1");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_create_session_id_length() {
        let id = create_session_id();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_create_session_id_uniqueness() {
        let id1 = create_session_id();
        let id2 = create_session_id();
        assert_ne!(id1, id2, "Two session IDs should not be identical");
    }

    /// A `503` with no `Retry-After` gives a caller nothing to pace on, so it
    /// retries as fast as its loop allows — into a queue that is full
    /// precisely because nothing is draining it.
    #[test]
    fn every_queue_gate_carries_a_pacing_hint() {
        for code in [
            "e.p.limits.queue.peer",
            "e.p.limits.queue.sender",
            "e.p.limits.queue.recipient",
        ] {
            assert_eq!(
                queue_full_retry_after_secs(code),
                Some(QUEUE_FULL_RETRY_AFTER_SECS),
                "code {code}"
            );
        }
    }

    /// The hint belongs only to the queue gates: attaching it to every refusal
    /// would tell a caller to wait before retrying things that will never
    /// succeed, and hide the ones that would.
    #[test]
    fn other_refusals_carry_no_hint() {
        for code in [
            "e.p.message.expired",
            "e.p.authorization.local",
            "e.p.limits.queue",
            "",
        ] {
            assert_eq!(queue_full_retry_after_secs(code), None, "code {code}");
        }
    }

    /// Matched on the suffix, so the DIDComm problem-report prefix is not part
    /// of the contract a client has to reproduce.
    #[test]
    fn the_prefix_is_not_part_of_the_match() {
        assert_eq!(
            queue_full_retry_after_secs("limits.queue.peer"),
            Some(QUEUE_FULL_RETRY_AFTER_SECS)
        );
    }

    #[test]
    fn a_queue_refusal_response_carries_retry_after() {
        let err: AppError = MediatorError::problem(
            crate::error_codes::PEER_QUEUE_FULL,
            "session",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "limits.queue.peer",
            "Too many messages already waiting for this recipient",
            vec![],
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .into();
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some(QUEUE_FULL_RETRY_AFTER_SECS.to_string().as_str()),
            "a queue-full refusal must tell the caller how long to wait"
        );
    }

    #[test]
    fn an_unrelated_problem_report_has_no_retry_after() {
        let err: AppError = MediatorError::problem(
            crate::error_codes::MESSAGE_EXPIRED,
            "session",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.expired",
            "Message has expired",
            vec![],
            StatusCode::BAD_REQUEST,
        )
        .into();
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
    }
}
