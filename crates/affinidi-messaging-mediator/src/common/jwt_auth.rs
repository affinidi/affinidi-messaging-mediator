use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::did_rate_limiter,
    common::metrics::names::RATE_LIMITED_TOTAL,
    common::session::{Session, SessionClaims, TokenUse},
};
use affinidi_messaging_mediator_common::errors::{ErrorResponse, MediatorError};
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use axum::{
    Json, RequestPartsExt,
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{StatusCode, request::Parts};
use jsonwebtoken::{TokenData, Validation};
use serde_json::json;
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
};
use tracing::{Level, debug, error, event, info, warn};

#[derive(Debug)]
#[non_exhaustive]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    ExpiredToken,
    InternalServerError(String),
    Blocked,
    /// The authenticated DID has spent its per-DID rate limit
    /// (`limits.did_rate_limit_per_second` / `did_rate_limit_burst`). Answered
    /// with a `429` carrying the rate-limit attribution contract.
    RateLimited {
        retry_after_secs: u64,
    },
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::WrongCredentials => write!(f, "Wrong credentials"),
            AuthError::MissingCredentials => write!(f, "Missing credentials"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::ExpiredToken => write!(f, "Expired token"),
            AuthError::InternalServerError(message) => {
                write!(f, "Internal Server Error: {message}")
            }
            AuthError::Blocked => write!(f, "ACL Blocked"),
            AuthError::RateLimited { retry_after_secs } => {
                write!(
                    f,
                    "Per-DID rate limit exceeded; retry after {retry_after_secs}s"
                )
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        if let AuthError::RateLimited { retry_after_secs } = self {
            return did_rate_limiter::refusal_response(retry_after_secs);
        }
        let status = match self {
            AuthError::WrongCredentials => StatusCode::UNAUTHORIZED,
            AuthError::MissingCredentials => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::ExpiredToken => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Blocked => StatusCode::UNAUTHORIZED,
            AuthError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        };
        let body = Json(json!(ErrorResponse {
            session_id: "UNAUTHORIZED".into(),
            request_id: None::<String>,
            http_code: status.as_u16(),
            error_code: status.as_u16(),
            error_code_str: status.to_string(),
            message: self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// `jsonwebtoken`'s default expiry leeway (seconds). We move the `exp` time
/// comparison off `jsonwebtoken` — which reads the real wall clock and so
/// ignores an injected [`Clock`](affinidi_messaging_mediator_common::types::clock::Clock)
/// — and onto the mediator's clock, but preserve this exact leeway so the
/// accept/reject boundary is unchanged from the previous behaviour.
pub(crate) const JWT_EXP_LEEWAY_SECS: u64 = 60;

/// A [`Validation`] with `exp` *required* but its time check disabled, so expiry
/// is judged against the injected clock (via [`jwt_exp_is_expired`]) rather than
/// `jsonwebtoken`'s internal `SystemTime::now()`. Signature, audience, and the
/// required-claims set are validated exactly as before.
pub(crate) fn clock_aware_validation() -> Validation {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["ATM"]);
    validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id"]);
    // Defer the expiry check to the injected clock; `exp` stays a required claim.
    validation.validate_exp = false;
    validation
}

/// Whether a token with the given `exp` is expired at `now`, using the same
/// leeway `jsonwebtoken` applied by default (`exp < now - leeway`). Written as
/// `exp + leeway < now` to avoid underflow.
pub(crate) fn jwt_exp_is_expired(exp: u64, now: u64) -> bool {
    exp + JWT_EXP_LEEWAY_SECS < now
}

/// Whether a decoded session token may be used as `expected`.
///
/// A token carrying `token_use` is accepted only for that use. A token
/// without it was minted by an earlier release and is judged by
/// [`unmarked_token_accepted`].
pub(crate) fn token_use_accepted(
    claims: &SessionClaims,
    expected: TokenUse,
    now: u64,
    access_lifetime_secs: u64,
) -> bool {
    match claims.token_use {
        Some(token_use) => token_use == expected,
        None => unmarked_token_accepted(claims, expected, now, access_lifetime_secs),
    }
}

/// Transition rule for tokens minted before `token_use` existed. Every such
/// token has expired one refresh-token lifetime (`jwt_refresh_expiry`) after
/// the upgrade, at which point this function and its call can be removed and
/// an unmarked token refused outright.
///
/// - As an **access** token: accepted only if it has no `jti` (refresh tokens
///   have carried one since the previous release) and its `exp` is no further
///   away than one access-token lifetime plus the expiry leeway. Older
///   refresh tokens had neither `jti` nor marker; one with more than an
///   access lifetime left cannot be an access token, so it is refused.
/// - As a **refresh** token: accepted. `/authenticate/refresh` still requires
///   the token's hash to be the session's current refresh-token hash, which
///   an access token never is.
fn unmarked_token_accepted(
    claims: &SessionClaims,
    expected: TokenUse,
    now: u64,
    access_lifetime_secs: u64,
) -> bool {
    match expected {
        TokenUse::Access => {
            claims.jti.is_none()
                && claims.exp <= now.saturating_add(access_lifetime_secs + JWT_EXP_LEEWAY_SECS)
        }
        TokenUse::Refresh => true,
    }
}

/// Validate a raw JWT bearer token and resolve it to an authenticated
/// [`Session`].
///
/// This is the single source of truth for token validation. It is
/// shared by two callers so both apply *identical* signature, claim,
/// expiry, DID-match and ACL checks:
/// - [`Session::from_request_parts`] — the `Authorization: Bearer`
///   header path used by all REST endpoints and by native WebSocket
///   clients (which can set request headers on the upgrade).
/// - [`crate::handlers::websocket::websocket_handler`] — the
///   `Sec-WebSocket-Protocol` subprotocol path used by browsers, which
///   cannot set an `Authorization` header on `new WebSocket(...)`.
///
/// The token's origin (header vs. subprotocol) is irrelevant here: the
/// same JWT yields the same `Session`.
pub(crate) async fn authenticate_token(
    state: &SharedData,
    token: &str,
) -> Result<Session, AuthError> {
    let token_data: TokenData<SessionClaims> = match jsonwebtoken::decode::<SessionClaims>(
        token,
        state.config.security.jwt_decoding_key(),
        &clock_aware_validation(),
    ) {
        Ok(token_data) => token_data,
        Err(err) => {
            event!(Level::WARN, "Decoding JWT failed {:?}", err);
            return Err(AuthError::InvalidToken);
        }
    };

    // Expiry is checked here (not by jsonwebtoken) so it honours the injected
    // clock. Same leeway/boundary as before — see `clock_aware_validation`.
    if jwt_exp_is_expired(token_data.claims.exp, state.clock.unix_secs()) {
        event!(Level::WARN, "JWT access token expired");
        return Err(AuthError::ExpiredToken);
    }

    // Only an access token is a bearer credential; a refresh token is
    // exchanged at `/authenticate/refresh` and nowhere else.
    if !token_use_accepted(
        &token_data.claims,
        TokenUse::Access,
        state.clock.unix_secs(),
        state.config.security.jwt_access_expiry,
    ) {
        warn!(
            session_id = %token_data.claims.session_id,
            token_use = ?token_data.claims.token_use,
            "Token presented as a bearer is not an access token"
        );
        return Err(AuthError::InvalidToken);
    }

    let session_id = token_data.claims.session_id.clone();
    let did = token_data.claims.sub.clone();
    let did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&did);

    // Everything has passed token wise - expensive database operations happen here
    let mut saved_session: Session = state
        .database
        .get_session(&session_id, &did)
        .await
        .map_err(|e| {
            // The account behind the session was removed: the token is no
            // longer good, which is not a server fault.
            if let MediatorError::Unauthorized(..) = e {
                info!("{}: session's account no longer exists", session_id);
                return AuthError::InvalidToken;
            }
            error!(
                "{}: Couldn't get session from database! Reason: {}",
                session_id, e
            );
            AuthError::InternalServerError(format!(
                "Couldn't get session from database! Reason: {e}"
            ))
        })?
        .into();

    // Defence in depth: the session record's DID must match the
    // JWT's `sub`. If they diverge, the session was either created
    // with a different DID (storage corruption, replay across
    // tenants) or get_session returned a partially populated
    // record (legacy data, schema drift). Either way the handler
    // would silently see the wrong DID — surface as InvalidToken
    // here so the failure is loud and the client re-authenticates.
    if !affinidi_messaging_mediator_common::did_identity::same_account(&saved_session.did, &did) {
        warn!(
            session_id = %session_id,
            jwt_did_hash = %did_hash,
            session_did_hash = %saved_session.did_hash,
            "JWT sub does not match session DID — rejecting"
        );
        return Err(AuthError::InvalidToken);
    }

    // Check if ACL is satisfied
    if authz::require_capability(&saved_session.acls, Capability::NotBlocked).is_err() {
        info!(did_hash = %did_hash, "DID is blocked from connecting");
        return Err(AuthError::Blocked);
    }

    // Per-DID rate limit. Charged only here, after the token, the session
    // record and the blocked check have all passed: charging any earlier would
    // let a forged token naming a victim DID spend that DID's quota. Every
    // authenticated HTTP route (and the `/ws` upgrade) comes through this
    // function, so this is where the limit is enforced for requests. Messages
    // on an established WebSocket are charged per message by the socket's
    // message meter (`handlers::ws_message_meter`).
    if let Err(limited) = state.did_rate_limiter.try_acquire(&did_hash) {
        metrics::counter!(RATE_LIMITED_TOTAL, "scope" => did_rate_limiter::PER_DID_SCOPE)
            .increment(1);
        warn!(
            session_id,
            did_hash,
            retry_after_secs = limited.retry_after_secs,
            "Per-DID rate limit exceeded"
        );
        return Err(AuthError::RateLimited {
            retry_after_secs: limited.retry_after_secs,
        });
    }

    // Update the expires at time
    saved_session.expires_at = token_data.claims.exp;

    debug!(session_id, did_hash, "JWT auth accepted");

    Ok(saved_session)
}

// The extractors borrow the router's `SharedData`: extracting it through
// `FromRef` would clone the whole state on every authenticated request.
impl FromRequestParts<SharedData> for Session {
    type Rejection = AuthError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedData,
    ) -> Result<Self, Self::Rejection> {
        if parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .is_none()
        {
            warn!("No remote address in request!");
            return Err(AuthError::MissingCredentials);
        }

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                warn!("No Authorization Bearer header in request!");
                AuthError::MissingCredentials
            })?;

        authenticate_token(state, bearer.token()).await
    }
}

/// Whether an unauthenticated (no-Bearer) inbound request may be accepted as an
/// anonymous session.
///
/// Anonymous inbound exists solely for inter-mediator relay: a remote
/// `ForwardingProcessor` POSTs a forward whose inner authcrypt *is* the
/// authentication. We only honour that when the operator has opted into acting
/// as a relay, signalled by the global default ACL granting `SEND_FORWARDED`
/// (the capability the relay path consumes, gated again per-message in
/// `routing.rs`). On a mediator with the shipped secure default this returns
/// `false`, so anonymous requests are rejected exactly like before.
fn anonymous_inbound_allowed(global_acl_default: &MediatorACLSet) -> bool {
    authz::grants(global_acl_default, Capability::SendForwarded)
}

/// The minimal ACL set granted to an anonymous inter-mediator relay session.
///
/// Anonymous `/inbound` exists only to relay forwards between mediators, so the
/// synthesised session is given the *least privilege* required to traverse the
/// inbound path rather than the full `global_acl_default` (which is `ALLOW_ALL`
/// in practice and would also grant `LOCAL`, `RECEIVE_MESSAGES`, invite
/// creation, and the `self_manage_*` capabilities to an unauthenticated caller).
///
/// Two capabilities are required and sufficient:
/// - `SEND_MESSAGES` — the handler-level gate in `message_inbound_handler`
///   rejects any session without it before the message is processed.
/// - `SEND_FORWARDED` — consumed by the anonymous-forward branch in
///   `routing.rs` when the inner forward carries no `from` field.
///
/// Per-message authorisation downstream (the forward's `from_account` ACL and
/// the recipient's `receive_forwarded` ACL) is unaffected — it is keyed off the
/// envelope/account identities, not this session.
fn relay_anonymous_acls() -> MediatorACLSet {
    // `from_string_ruleset` cannot fail for this static, audited input; fall
    // back to the all-deny default rather than panicking if it ever does.
    MediatorACLSet::from_string_ruleset("DENY_ALL,SEND_MESSAGES,SEND_FORWARDED").unwrap_or_default()
}

/// Session id marking an anonymous session admitted **only** because
/// `[didcomm_v1] allow_unauthenticated_forwards` is on.
///
/// The distinction matters, and `message_inbound_handler` enforces it. An Aries
/// wallet is not an inter-mediator relay: it anoncrypts a
/// `routing/1.0/forward` to the mediator's routing key and presents no
/// credential, which is normal for v1 and abnormal for everything else here.
/// Admitting it must therefore not also open anonymous *v2* inbound — so a
/// session carrying this id is refused unless the body really is a v1 envelope.
#[cfg(feature = "didcomm-v1")]
pub(crate) const ANON_V1_SESSION_ID: &str = "ANON-INBOUND-V1";

/// ACLs for a v1-only anonymous session.
///
/// Deliberately **without** `SEND_FORWARDED`, which the v2 anonymous-forward
/// branch in `routing.rs` consumes: even if the body check were somehow
/// bypassed, this session could not drive a v2 relay forward. `SEND_MESSAGES`
/// alone satisfies the handler-level gate.
#[cfg(feature = "didcomm-v1")]
fn v1_anonymous_acls() -> MediatorACLSet {
    MediatorACLSet::from_string_ruleset("DENY_ALL,SEND_MESSAGES").unwrap_or_default()
}

/// The anonymous inter-mediator relay session, if this mediator is configured
/// to act as a relay.
///
/// The single place the relay-admission decision is made, so the REST
/// `/inbound` route and the WebSocket route cannot drift apart on *who* is let
/// in — only on what they may then do. Relay is enabled by the explicit
/// `enable_inter_mediator_relay` flag or, for backward compatibility, by
/// `global_acl_default` granting `SEND_FORWARDED` (the legacy implicit-relay
/// behaviour, which boot-time validation warns about).
///
/// The session carries [`relay_anonymous_acls`] — `SEND_MESSAGES` +
/// `SEND_FORWARDED`, nothing else — and no DID, which is what stops it from
/// reaching anything that belongs to an account.
pub(crate) fn anonymous_relay_session(
    enable_relay_flag: bool,
    global_acl_default: &MediatorACLSet,
) -> Option<Session> {
    (enable_relay_flag || anonymous_inbound_allowed(global_acl_default)).then(|| Session {
        session_id: ANON_RELAY_SESSION_ID.to_string(),
        acls: relay_anonymous_acls(),
        ..Default::default()
    })
}

/// Session id for an anonymous inter-mediator relay session, on either
/// transport. Carries no DID — see [`anonymous_relay_session`].
pub(crate) const ANON_RELAY_SESSION_ID: &str = "ANON-INBOUND";

/// Decide whether an authentication failure should be downgraded to an anonymous
/// relay session, and if so build that session.
///
/// Only a genuinely *absent* credential ([`AuthError::MissingCredentials`]) is
/// eligible — and only when the mediator is configured as a relay. Every other
/// failure (`InvalidToken`, `ExpiredToken`, `Blocked`, `InternalServerError`,
/// `WrongCredentials`) is propagated unchanged: a caller that *presents* a bad,
/// expired, or blocked token must be rejected, never silently demoted to
/// anonymous, and a backend error must surface as `500` rather than proceed as
/// an unauthenticated relay.
///
/// Relay is enabled when the explicit `enable_inter_mediator_relay` flag is set
/// OR, for backward compatibility, when `global_acl_default` grants
/// `SEND_FORWARDED` (the legacy implicit-relay behaviour, which boot-time
/// validation now warns about). A future release will require the explicit flag.
fn anonymous_session_for(
    err: &AuthError,
    enable_relay_flag: bool,
    global_acl_default: &MediatorACLSet,
    #[cfg_attr(not(feature = "didcomm-v1"), allow(unused_variables))] allow_v1_anon: bool,
) -> Option<Session> {
    if !matches!(err, AuthError::MissingCredentials) {
        return None;
    }

    // Relay admission is unchanged and takes precedence: such a session keeps
    // its SEND_FORWARDED capability and is not restricted to v1 bodies.
    if let Some(session) = anonymous_relay_session(enable_relay_flag, global_acl_default) {
        return Some(session);
    }

    // Otherwise a v1 forward may still be admitted, but only as a v1-scoped
    // session — see [`ANON_V1_SESSION_ID`].
    #[cfg(feature = "didcomm-v1")]
    if allow_v1_anon {
        return Some(Session {
            session_id: ANON_V1_SESSION_ID.to_string(),
            acls: v1_anonymous_acls(),
            ..Default::default()
        });
    }

    None
}

/// Extractor that wraps `Session`, optionally allowing anonymous relay requests.
///
/// When a valid `Authorization: Bearer` token is present the inner `Session`
/// is fully populated (i.e. `session.authenticated == true`). When the header
/// is *absent* the request is accepted — as an anonymous session carrying a
/// minimal relay-scoped ACL (see `relay_anonymous_acls`) — only if the
/// mediator is configured as an inter-mediator relay (see
/// `anonymous_session_for`). A *present but invalid/expired/blocked* token,
/// or a backend error, is propagated unchanged, so a mediator with the shipped
/// secure default keeps rejecting unauthenticated `/inbound` requests.
pub struct MaybeSession(pub Session);

impl FromRequestParts<SharedData> for MaybeSession {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        shared: &SharedData,
    ) -> Result<Self, Self::Rejection> {
        match Session::from_request_parts(parts, shared).await {
            Ok(session) => Ok(MaybeSession(session)),
            Err(e) => {
                let security = &shared.config.security;
                match anonymous_session_for(
                    &e,
                    security.enable_inter_mediator_relay,
                    &security.global_acl_default,
                    shared.config.didcomm_v1.enabled
                        && shared.config.didcomm_v1.allow_unauthenticated_forwards,
                ) {
                    Some(session) => Ok(MaybeSession(session)),
                    None => Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_exp_uses_the_same_leeway_as_jsonwebtoken() {
        // Boundary equivalent to jsonwebtoken's default (`exp < now - leeway`,
        // i.e. expired iff `exp + leeway < now`), with leeway = 60.
        let exp = 1_000_u64;
        // Well within validity.
        assert!(!jwt_exp_is_expired(exp, exp));
        // Exactly at the leeway edge — still accepted.
        assert!(!jwt_exp_is_expired(exp, exp + JWT_EXP_LEEWAY_SECS));
        // One second past the leeway — now expired.
        assert!(jwt_exp_is_expired(exp, exp + JWT_EXP_LEEWAY_SECS + 1));
        // A token issued "in the future" is certainly not expired (no underflow).
        assert!(!jwt_exp_is_expired(exp, 0));
    }

    #[test]
    fn clock_aware_validation_defers_expiry_but_keeps_exp_required() {
        let validation = clock_aware_validation();
        // jsonwebtoken must NOT check expiry (the injected clock does).
        assert!(!validation.validate_exp);
        // ...but `exp` is still a required claim, so a token without it is
        // rejected at decode time exactly as before.
        assert!(validation.required_spec_claims.contains("exp"));
    }

    fn claims(token_use: Option<TokenUse>, jti: Option<&str>, exp: u64) -> SessionClaims {
        SessionClaims {
            aud: "ATM".into(),
            sub: "did:example:alice".into(),
            session_id: "session".into(),
            exp,
            token_use,
            jti: jti.map(str::to_string),
        }
    }

    const NOW: u64 = 1_000_000;
    const ACCESS: u64 = 900;

    #[test]
    fn marked_tokens_are_accepted_only_for_their_own_use() {
        let access = claims(Some(TokenUse::Access), None, NOW + ACCESS);
        let refresh = claims(Some(TokenUse::Refresh), Some("id"), NOW + 85_500);
        assert!(token_use_accepted(&access, TokenUse::Access, NOW, ACCESS));
        assert!(!token_use_accepted(&access, TokenUse::Refresh, NOW, ACCESS));
        assert!(token_use_accepted(&refresh, TokenUse::Refresh, NOW, ACCESS));
        assert!(!token_use_accepted(&refresh, TokenUse::Access, NOW, ACCESS));
        // The marker decides even for a refresh token close to its expiry.
        let late_refresh = claims(Some(TokenUse::Refresh), Some("id"), NOW + 10);
        assert!(!token_use_accepted(
            &late_refresh,
            TokenUse::Access,
            NOW,
            ACCESS
        ));
    }

    #[test]
    fn unmarked_token_without_jti_within_access_lifetime_is_an_access_token() {
        let legacy = claims(None, None, NOW + ACCESS);
        assert!(token_use_accepted(&legacy, TokenUse::Access, NOW, ACCESS));
        // Up to the expiry leeway beyond the access lifetime.
        let edge = claims(None, None, NOW + ACCESS + JWT_EXP_LEEWAY_SECS);
        assert!(token_use_accepted(&edge, TokenUse::Access, NOW, ACCESS));
    }

    #[test]
    fn unmarked_token_outliving_the_access_lifetime_is_not_an_access_token() {
        let legacy_refresh = claims(None, None, NOW + ACCESS + JWT_EXP_LEEWAY_SECS + 1);
        assert!(!token_use_accepted(
            &legacy_refresh,
            TokenUse::Access,
            NOW,
            ACCESS
        ));
        // It is still exchangeable at refresh during the transition.
        assert!(token_use_accepted(
            &legacy_refresh,
            TokenUse::Refresh,
            NOW,
            ACCESS
        ));
    }

    #[test]
    fn unmarked_token_with_jti_is_not_an_access_token() {
        let previous_refresh = claims(None, Some("id"), NOW + 60);
        assert!(!token_use_accepted(
            &previous_refresh,
            TokenUse::Access,
            NOW,
            ACCESS
        ));
        assert!(token_use_accepted(
            &previous_refresh,
            TokenUse::Refresh,
            NOW,
            ACCESS
        ));
    }

    #[test]
    fn token_use_claim_round_trips_and_absence_decodes_as_none() {
        let marked = claims(Some(TokenUse::Access), None, NOW);
        let json = serde_json::to_value(&marked).unwrap();
        assert_eq!(json["token_use"], "access");
        assert!(json.get("jti").is_none());

        let unmarked: SessionClaims = serde_json::from_value(serde_json::json!({
            "aud": "ATM", "sub": "did:example:a", "session_id": "s", "exp": NOW
        }))
        .unwrap();
        assert_eq!(unmarked.token_use, None);
        assert_eq!(unmarked.jti, None);

        // An unknown use is not silently read as unmarked.
        assert!(
            serde_json::from_value::<SessionClaims>(serde_json::json!({
                "aud": "ATM", "sub": "did:example:a", "session_id": "s", "exp": NOW,
                "token_use": "id"
            }))
            .is_err()
        );
    }

    #[test]
    fn anon_inbound_allowed_when_global_default_grants_send_forwarded() {
        let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        assert!(anonymous_inbound_allowed(&acls));
    }

    #[test]
    fn anon_inbound_denied_for_shipped_secure_default() {
        // The shipped default global_acl_default: fine for direct messaging but
        // NOT a relay (no SEND_FORWARDED), so anonymous inbound must be refused.
        let acls =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(!anonymous_inbound_allowed(&acls));
    }

    #[test]
    fn relay_anonymous_acls_grant_only_send_and_forward() {
        // The synthesised relay session must carry exactly the two capabilities
        // the inbound path needs — and none of the ALLOW_ALL extras that would
        // hand an unauthenticated caller broad mediator access.
        let acls = relay_anonymous_acls();
        assert!(
            acls.get_send_messages().0,
            "needs SEND_MESSAGES for the handler gate"
        );
        assert!(
            acls.get_send_forwarded().0,
            "needs SEND_FORWARDED for the relay branch"
        );

        // Everything else must remain denied.
        assert!(!acls.get_local());
        assert!(!acls.get_receive_messages().0);
        assert!(!acls.get_receive_forwarded().0);
        assert!(!acls.get_create_invites().0);
        assert!(!acls.get_anon_receive().0);
        assert!(!acls.get_self_manage_list());
        assert!(!acls.get_self_manage_send_queue_limit());
        assert!(!acls.get_self_manage_receive_queue_limit());
        assert!(!acls.get_blocked());
    }

    #[test]
    fn missing_credentials_downgrades_to_relay_session_only_when_relay_enabled() {
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        // Legacy implicit relay: ACL grants SEND_FORWARDED, flag off.
        let session = anonymous_session_for(&AuthError::MissingCredentials, false, &relay, false)
            .expect("relay-enabled mediator accepts anonymous inbound");
        // Not authenticated, no DID, and scoped to the minimal relay ACL — never
        // the full global default.
        assert!(!session.authenticated);
        assert!(session.did.is_empty());
        assert!(session.acls.get_send_forwarded().0);
        assert!(!session.acls.get_local());

        // Same request on a non-relay mediator is rejected, not downgraded.
        let secure =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(
            anonymous_session_for(&AuthError::MissingCredentials, false, &secure, false).is_none()
        );
    }

    #[test]
    fn explicit_relay_flag_enables_anonymous_inbound_without_the_acl_bit() {
        // The explicit flag enables anonymous relay even when the global default
        // ACL does NOT grant SEND_FORWARDED (the forward-compatible path).
        let secure =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(
            anonymous_session_for(&AuthError::MissingCredentials, true, &secure, false).is_some(),
            "explicit enable_inter_mediator_relay must accept anonymous inbound"
        );
        // ...and with neither the flag nor the ACL bit, it stays rejected.
        assert!(
            anonymous_session_for(&AuthError::MissingCredentials, false, &secure, false).is_none()
        );
    }

    #[test]
    fn presented_but_invalid_credentials_are_never_downgraded() {
        // Even on a relay-enabled mediator, a caller that *presents* a bad,
        // expired, or blocked token — or trips a backend error — must be
        // rejected outright, never silently demoted to an anonymous session.
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        for err in [
            AuthError::InvalidToken,
            AuthError::ExpiredToken,
            AuthError::Blocked,
            AuthError::WrongCredentials,
            AuthError::InternalServerError("backend down".into()),
        ] {
            assert!(
                anonymous_session_for(&err, false, &relay, false).is_none(),
                "{err:?} must not be downgraded to an anonymous session"
            );
        }
    }

    /// `allow_unauthenticated_forwards` admits an anonymous session, but a
    /// **v1-scoped** one: it must not become a general anonymous-inbound
    /// licence. The handler refuses a non-v1 body on this session; the ACL is
    /// the second line of defence.
    #[cfg(feature = "didcomm-v1")]
    #[test]
    fn v1_anonymous_session_is_scoped_and_cannot_relay() {
        let secure =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();

        // Off by default: still rejected.
        assert!(
            anonymous_session_for(&AuthError::MissingCredentials, false, &secure, false).is_none(),
            "v1 anonymous inbound must be opt-in"
        );

        let session = anonymous_session_for(&AuthError::MissingCredentials, false, &secure, true)
            .expect("allow_unauthenticated_forwards admits an anonymous v1 session");

        assert_eq!(
            session.session_id, ANON_V1_SESSION_ID,
            "the session must be identifiable as v1-scoped so the handler can refuse other bodies"
        );
        assert!(!session.authenticated);
        assert!(session.did.is_empty());
        // Enough to pass the handler gate...
        assert!(session.acls.get_send_messages().0);
        // ...but never enough to drive a v2 relay forward.
        assert!(
            !session.acls.get_send_forwarded().0,
            "a v1-scoped anonymous session must not carry SEND_FORWARDED"
        );
        assert!(!session.acls.get_local());
    }

    /// A relay-enabled mediator keeps its existing behaviour: the anonymous
    /// session is the relay one, not the narrower v1 session, so turning on v1
    /// does not silently downgrade inter-mediator relay.
    #[cfg(feature = "didcomm-v1")]
    #[test]
    fn relay_admission_takes_precedence_over_v1() {
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let session = anonymous_session_for(&AuthError::MissingCredentials, true, &relay, true)
            .expect("relay session");
        assert_eq!(session.session_id, "ANON-INBOUND");
        assert!(session.acls.get_send_forwarded().0);
    }

    /// The v1 flag must not rescue a *presented* bad credential either.
    #[cfg(feature = "didcomm-v1")]
    #[test]
    fn v1_flag_does_not_downgrade_invalid_credentials() {
        let secure = MediatorACLSet::from_string_ruleset("DENY_ALL,SEND_MESSAGES").unwrap();
        for err in [
            AuthError::InvalidToken,
            AuthError::ExpiredToken,
            AuthError::Blocked,
            AuthError::WrongCredentials,
        ] {
            assert!(
                anonymous_session_for(&err, false, &secure, true).is_none(),
                "{err:?} must not be downgraded even with v1 anonymous forwards enabled"
            );
        }
    }
}
