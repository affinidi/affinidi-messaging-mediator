use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::errors::AppError;
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    response::IntoResponse,
    routing::{delete, get, post},
};
use http::StatusCode;

#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub mod authenticate;
pub mod inbox_fetch;
pub mod message_delete;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub mod message_inbound;
pub mod message_list;
pub mod message_outbound;
pub mod readiness;
pub use readiness::readiness_handler;
#[cfg(feature = "didcomm")]
pub(crate) mod oob_discovery;
pub mod websocket;
pub mod well_known_did_fetch;

/// How much of an `/inbound` body is buffered before the handler sees it.
///
/// The handler takes the body as `Bytes`, which applies axum's own 2 MiB
/// default on top of `http_size`: a mediator configured for messages larger
/// than that refused every one of them. The body *is* the message, so a larger
/// `message_size` needs the same here; nothing smaller than the 2 MiB default
/// is useful, because a body between `message_size` and 2 MiB is still read so
/// the sender gets the `message.size.exceeded` problem report. Every other
/// route keeps axum's default.
fn inbound_body_limit(shared_data: &SharedData) -> usize {
    const AXUM_DEFAULT: usize = 2 * 1024 * 1024;
    shared_data.config.limits.message_size.max(AXUM_DEFAULT)
}

/// Body cap for `/authenticate/challenge` and `/tsp/authenticate`: a DID
/// (at most `MAX_CHALLENGE_DID_LEN` bytes), or a VID, the mediator DID, a
/// session id, two times and a signature, with room for JSON escaping. Both
/// are unauthenticated.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
const AUTH_CHALLENGE_BODY_LIMIT: usize = 16 * 1024;

/// Body cap for `/authenticate` and `/authenticate/refresh`: one authcrypt
/// envelope carrying a challenge or a refresh token. Its headers repeat the
/// sender and recipient key ids, which for `did:peer:2` run to kilobytes, so
/// this is generous, but far below axum's 2 MiB default.
#[cfg(feature = "didcomm")]
const AUTH_MESSAGE_BODY_LIMIT: usize = 64 * 1024;

pub fn application_routes(api_prefix: &str, shared_data: &SharedData) -> Router {
    let mut app = Router::new()
        // Outbound message handling to ATM clients
        .route(
            "/outbound",
            post(message_outbound::message_outbound_handler),
        )
        .route("/fetch", post(inbox_fetch::inbox_fetch_handler))
        // Listing of messages for a DID
        .route(
            "/list/{did_hash}/{folder}",
            get(message_list::message_list_handler),
        )
        // Delete/remove messages stored in ATM
        .route("/delete", delete(message_delete::message_delete_handler))
        // Websocket endpoint for ATM clients
        .route("/ws", get(websocket::websocket_handler))
        // Helps to test if you are who you think you are
        .route("/whoami", get(whoami_handler))
        .route(
            "/.well-known/did",
            get(well_known_did_fetch::well_known_did_fetch_handler),
        );

    // Shared by both protocols: inbound messages (the handler sniffs DIDComm
    // from TSP) and the authentication challenge every client starts from.
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    {
        app = app
            // Inbound message handling from ATM clients
            .route(
                "/inbound",
                post(message_inbound::message_inbound_handler)
                    .layer(DefaultBodyLimit::max(inbound_body_limit(shared_data))),
            )
            // Authentication step 1/2 - Client requests challenge from server
            .route(
                "/authenticate/challenge",
                post(authenticate::authentication_challenge)
                    .layer(DefaultBodyLimit::max(AUTH_CHALLENGE_BODY_LIMIT)),
            );
    }

    // DIDComm-specific routes
    #[cfg(feature = "didcomm")]
    {
        app = app
            // Authentication step 2/2 - Client sends encrypted challenge to server
            .route(
                "/authenticate",
                post(authenticate::authentication_response)
                    .layer(DefaultBodyLimit::max(AUTH_MESSAGE_BODY_LIMIT)),
            )
            .route(
                "/authenticate/refresh",
                post(authenticate::authentication_refresh)
                    .layer(DefaultBodyLimit::max(AUTH_MESSAGE_BODY_LIMIT)),
            )
            // Out Of Band Discovery Routes
            .route("/oob", post(oob_discovery::oob_invite_handler))
            .route("/oob", get(oob_discovery::oobid_handler))
            .route("/oob", delete(oob_discovery::delete_oobid_handler));
    }

    // TSP clients reuse `/authenticate/challenge`, then prove control of their VID
    // by signing the challenge (Ed25519) and posting it here. It mints the same JWT
    // session the DIDComm flow does, and is how a TSP-only mediator's clients log in.
    #[cfg(feature = "tsp")]
    {
        app = app.route(
            "/tsp/authenticate",
            post(authenticate::tsp::tsp_authentication_response)
                .layer(DefaultBodyLimit::max(AUTH_CHALLENGE_BODY_LIMIT)),
        );
    }

    // `api_prefix` arrives in the canonical form produced by
    // `config::helpers::normalize_api_prefix`: either `""` (mount at
    // root) or `"/<segment>"` with no trailing slash (the form axum's
    // `Router::nest` requires).
    let api_router = if api_prefix.is_empty() {
        Router::new().merge(app)
    } else {
        Router::new().nest(api_prefix, app)
    };

    // `/.well-known/did.json` and `/.well-known/did.jsonl` are well-known URIs (RFC 8615);
    // both did:web and did:webvh resolvers fetch them at the bare host root, regardless of
    // any HTTP API prefix the service uses for its other routes. Register them on the
    // outer router so they sit at root even when the inner app is nested under `api_prefix`.
    let api_router = if shared_data.config.mediator_did_doc.is_some() {
        let mut r = api_router.route(
            "/.well-known/did.json",
            get(well_known_did_fetch::well_known_did_json_handler),
        );
        // `did.jsonl` is the webvh log stream — register only when the loaded source
        // actually was a log entry. did:web deployments don't have a log to serve.
        if shared_data.config.mediator_did_log.is_some() {
            r = r.route(
                "/.well-known/did.jsonl",
                get(well_known_did_fetch::well_known_did_jsonl_handler),
            );
        }
        r
    } else {
        api_router
    };

    api_router.with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Secure Messaging Mediator Service, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}

/// Process-liveness probe. Returns 200 whenever the HTTP server can answer
/// — deliberately decoupled from component readiness so an orchestrator
/// does not kill a mediator that is still serving traffic while a
/// background component is degraded or restarting. Use `/readyz` to decide
/// whether an instance should *receive* traffic.
pub async fn liveness_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "alive" })),
    )
}

/// Determine the current load state of the mediator.
/// Used for load shedding decisions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadState {
    /// Normal operation
    Normal,
    /// Elevated load — non-essential operations may be deferred
    Elevated,
    /// Critical load — only essential operations allowed
    Critical,
}

impl LoadState {
    pub async fn current(state: &SharedData) -> Self {
        // Check circuit breaker
        if state.database.circuit_breaker_state() != "closed" {
            return LoadState::Critical;
        }

        // Check shutdown
        if state.shutdown_token.is_cancelled() {
            return LoadState::Critical;
        }

        // Check queue depth
        if let Ok(queue_len) = state.database.forward_queue_len().await {
            let limit = state.limits().forward_task_queue;
            if queue_len >= limit {
                return LoadState::Critical;
            }
            if queue_len >= limit * 80 / 100 {
                return LoadState::Elevated;
            }
        }

        LoadState::Normal
    }
}

/// Handler that returns the DID registered for this session
pub async fn whoami_handler(
    session: Session,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: "".to_string(),
            data: Some(session.did.clone()),
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
        }),
    ))
}
