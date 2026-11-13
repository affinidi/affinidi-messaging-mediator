//! TSP client authentication — mint the same JWT session as DIDComm.
//!
//! A TSP client (whose VID is a DID, per the phase-1 DID-VID constraint) reuses
//! the protocol-agnostic `POST /authenticate/challenge` to obtain a challenge,
//! signs a statement carrying that challenge with its VID's Ed25519 key, and
//! POSTs the signature here. The mediator resolves the VID's signing key from
//! its DID document and verifies the signature — no mediator TSP keys and no
//! decryption are needed.
//!
//! ## The signed statement
//!
//! The client signs the UTF-8 bytes of this JSON object, written as RFC 8785
//! (JCS) canonical JSON: keys in lexicographic order, no whitespace. It has
//! the fields of the DIDComm authentication message (`typ`, `from`, `to`,
//! `created_time`, `expires_time`, and a `body` of `challenge` and
//! `session_id`), so both login paths state the same things:
//!
//! ```text
//! {"body":{"challenge":"<challenge>","session_id":"<session_id>"},
//!  "created_time":<unix secs>,"expires_time":<unix secs>,
//!  "from":"<client VID>","to":"<mediator DID>",
//!  "typ":"https://affinidi.com/atm/1.0/tsp/authenticate"}
//! ```
//!
//! (shown wrapped; the signed form is one line). The request carries `to`,
//! `created_time` and `expires_time` next to `vid`, `session_id` and
//! `signature`; the mediator takes the challenge from the session it issued,
//! rebuilds the statement and verifies the signature over it. It refuses a
//! statement addressed to another DID, one that has expired, and one whose
//! lifetime is longer than [`MAX_STATEMENT_LIFETIME_SECS`].
//!
//! A request without `to`, `created_time` and `expires_time` is the older form,
//! a signature over the challenge string alone. It is refused unless the
//! operator set `security.tsp_auth_accept_unbound_until` to a time still in the
//! future.
//! On success it mints the **identical** EdDSA `SessionClaims` access+refresh
//! JWT pair the DIDComm path issues, so every downstream ACL / pickup / WS gate
//! is reused unchanged (the session is DID-keyed and protocol-agnostic).

use super::helpers::{_create_access_token, _create_refresh_token, create_random_string};
use crate::error_codes;
use crate::{
    SharedData,
    common::session::{Session, SessionState},
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    AuthorizationResponse,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use affinidi_tsp::DidVidResolver;
use affinidi_tsp::crypto::signing;
use axum::{Json, extract::State};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, debug, span, warn};

/// `typ` of the signed TSP authentication statement: what the signature is
/// for. A signature made for anything else does not verify here.
pub const TSP_AUTH_TYP: &str = "https://affinidi.com/atm/1.0/tsp/authenticate";

/// The longest a signed statement may be valid for (`expires_time` minus
/// `created_time`), in seconds. The SDK uses 60.
pub const MAX_STATEMENT_LIFETIME_SECS: u64 = 300;

/// How far ahead of the mediator's clock `created_time` may be, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Request body for `POST /tsp/authenticate`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TspAuthenticateBody {
    /// The client's VID — a DID, per the phase-1 DID-VID constraint.
    pub vid: String,
    /// The `session_id` returned by `POST /authenticate/challenge`.
    pub session_id: String,
    /// base64url(no-pad) of the Ed25519 signature over the signed statement
    /// (see the [module docs](self)).
    pub signature: String,
    /// The mediator DID the statement is addressed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// When the statement was made (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,
    /// When the statement stops being accepted (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,
}

/// The signed statement. Fields are declared in lexicographic order, and every
/// value is a string or an integer, so `serde_json` writes exactly the RFC 8785
/// canonical form.
#[derive(Serialize)]
struct SignedStatement<'a> {
    body: SignedStatementBody<'a>,
    created_time: u64,
    expires_time: u64,
    from: &'a str,
    to: &'a str,
    typ: &'a str,
}

#[derive(Serialize)]
struct SignedStatementBody<'a> {
    challenge: &'a str,
    session_id: &'a str,
}

/// The bytes a TSP client signs to log in: the canonical JSON statement
/// described in the [module docs](self).
pub fn signed_statement_bytes(
    challenge: &str,
    session_id: &str,
    from: &str,
    to: &str,
    created_time: u64,
    expires_time: u64,
) -> Vec<u8> {
    serde_json::to_vec(&SignedStatement {
        body: SignedStatementBody {
            challenge,
            session_id,
        },
        created_time,
        expires_time,
        from,
        to,
        typ: TSP_AUTH_TYP,
    })
    // Strings and integers only: serialising cannot fail.
    .unwrap_or_default()
}

/// What a request asks the mediator to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form<'a> {
    /// The signed statement naming its audience and expiry.
    Statement {
        to: &'a str,
        created_time: u64,
        expires_time: u64,
    },
    /// The older form: a signature over the challenge string alone.
    Unbound,
}

/// Why a request's form is refused before any signature is checked.
#[derive(Debug, PartialEq, Eq)]
enum FormRefusal {
    /// Some, but not all, of `to`, `created_time` and `expires_time`.
    Incomplete,
    /// `to` is not this mediator's DID.
    Audience,
    /// Expired, not yet valid, or valid for longer than allowed.
    Time,
    /// The older form, with no operator opt-in in force.
    Unbound,
}

/// Decide which form `body` uses and whether it may be verified at all, given
/// this mediator's DID, the time, and the operator's opt-in deadline for the
/// older form.
fn check_form<'a>(
    body: &'a TspAuthenticateBody,
    mediator_did: &str,
    now: u64,
    accept_unbound_until: Option<u64>,
) -> Result<Form<'a>, FormRefusal> {
    match (&body.to, body.created_time, body.expires_time) {
        (Some(to), Some(created_time), Some(expires_time)) => {
            if !affinidi_messaging_mediator_common::did_identity::same_account(to, mediator_did) {
                return Err(FormRefusal::Audience);
            }
            if expires_time <= now
                || created_time >= expires_time
                || created_time > now.saturating_add(MAX_CLOCK_SKEW_SECS)
                || expires_time - created_time > MAX_STATEMENT_LIFETIME_SECS
            {
                return Err(FormRefusal::Time);
            }
            Ok(Form::Statement {
                to,
                created_time,
                expires_time,
            })
        }
        (None, None, None) => match accept_unbound_until {
            Some(until) if now < until => Ok(Form::Unbound),
            _ => Err(FormRefusal::Unbound),
        },
        _ => Err(FormRefusal::Incomplete),
    }
}

impl FormRefusal {
    fn into_error(self, session_id: &str) -> MediatorError {
        let (code, descriptor, comment, status) = match self {
            FormRefusal::Incomplete => (
                28,
                "authentication.tsp.statement.incomplete",
                "`to`, `created_time` and `expires_time` must all be present",
                StatusCode::BAD_REQUEST,
            ),
            FormRefusal::Audience => (
                32,
                "authentication.tsp.statement.audience",
                "The signed statement is addressed to a different DID",
                StatusCode::UNAUTHORIZED,
            ),
            FormRefusal::Time => (
                31,
                "authentication.tsp.statement.expired",
                "The signed statement has expired or its validity window is not acceptable",
                StatusCode::UNAUTHORIZED,
            ),
            FormRefusal::Unbound => (
                32,
                "authentication.tsp.statement.required",
                "A signed statement naming this mediator is required (affinidi-messaging-sdk 0.45.16 or later)",
                StatusCode::UNAUTHORIZED,
            ),
        };
        MediatorError::problem(
            code,
            session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            descriptor,
            comment,
            vec![],
            status,
        )
    }
}

/// Authentication step 2/2 for a TSP client: verify the signed challenge and
/// mint the access + refresh JWT pair.
pub async fn tsp_authentication_response(
    State(state): State<SharedData>,
    Json(body): Json<TspAuthenticateBody>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthorizationResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "tsp_authentication_response",
        session_id = body.session_id
    );
    async move {
        // VID must be a DID (phase-1 DID-VID constraint).
        if !body.vid.starts_with("did:") {
            return Err(MediatorError::problem(
                error_codes::AUTH_INVALID_DID,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.invalid_vid",
                "TSP authentication requires a `did:`-based VID",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }

        // Which form the request uses, and whether it is acceptable at all:
        // checked before any storage or DID resolution.
        let form = check_form(
            &body,
            &state.config.mediator_did,
            state.clock.unix_secs(),
            state.config.security.tsp_auth_accept_unbound_until,
        )
        .map_err(|refusal| refusal.into_error(&body.session_id))?;

        // Load the challenge session and check it is awaiting a response.
        let mut session: Session = state
            .database
            .get_session(&body.session_id, &body.vid)
            .await
            // Unauthenticated: say nothing of storage capacity.
            .map_err(MediatorError::opaque_storage)?
            .into();
        if session.state != SessionState::ChallengeSent {
            return Err(MediatorError::problem(
                error_codes::AUTH_SESSION_INVALID,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.state",
                "Session is not awaiting a challenge response",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
            .into());
        }
        if !affinidi_messaging_mediator_common::did_identity::same_account(&session.did, &body.vid)
        {
            return Err(MediatorError::problem(
                error_codes::AUTH_SESSION_MISMATCH,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.mismatch",
                "VID does not match the challenge session",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
            .into());
        }

        // Decode the Ed25519 signature.
        let sig_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(body.signature.as_bytes())
            .map_err(|e| {
                MediatorError::problem(
                    error_codes::AUTH_TSP_STATEMENT_INVALID,
                    &body.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.tsp.signature.encoding",
                    "Signature is not valid base64url: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                )
            })?;
        let signature: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            MediatorError::problem(
                error_codes::AUTH_TSP_STATEMENT_INVALID,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.signature.length",
                "Ed25519 signature must be 64 bytes",
                vec![],
                StatusCode::BAD_REQUEST,
            )
        })?;

        // Resolve the VID → its Ed25519 signing key from the DID document.
        let resolver = DidVidResolver::new(state.did_resolver.clone());
        let resolved = resolver.resolve_did(&body.vid).await.map_err(|e| {
            MediatorError::problem(
                error_codes::AUTH_TSP_STATEMENT_INVALID,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.resolve",
                "Couldn't resolve the VID's keys: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
            )
        })?;

        // Verify the signature over what this form signs: the statement
        // rebuilt from the issued challenge, this session and the request's
        // fields, or (older form, operator opt-in) the challenge alone. This
        // proves the client controls the VID's signing key.
        let signed = match form {
            Form::Statement {
                to,
                created_time,
                expires_time,
            } => signed_statement_bytes(
                &session.challenge,
                &body.session_id,
                &body.vid,
                to,
                created_time,
                expires_time,
            ),
            Form::Unbound => session.challenge.as_bytes().to_vec(),
        };
        signing::verify(&signed, &signature, &resolved.signing_key).map_err(|_| {
            MediatorError::problem(
                error_codes::MESSAGE_UNPACK_FAILED,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.signature.invalid",
                "TSP challenge signature verification failed",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
        })?;

        if form == Form::Unbound {
            warn!(
                did = %session.did,
                "TSP login accepted in the older form (signature over the challenge alone) \
                 under security.tsp_auth_accept_unbound_until; this client should move to \
                 affinidi-messaging-sdk 0.45.16 or later"
            );
        }

        // The mux unknown-key rule on the VID's signing key, compared with
        // the keys that signed the member's grants, before any token is
        // issued: a login that cannot be checked fails (fail closed).
        let mux_suspended = if state.config.limits.mux.enabled && state.database.supports_mux() {
            Some(
                crate::mux::notice::unknown_key_check(
                    &state,
                    &session.did_hash,
                    crate::mux::notice::DirectKey::Signing(resolved.signing_key.to_vec()),
                )
                .await
                .map_err(super::helpers::mux_check_failed)?,
            )
        } else {
            None
        };

        // The challenge is answered: give the VID its account (or refuse it
        // under `explicit_allow`) before any token exists for it.
        super::helpers::register_account_after_proof(&state, &session.did_hash).await?;

        // Mint the same JWT pair the DIDComm path issues, rotating the session id.
        let now = state.clock.unix_secs();
        let old_sid = session.session_id.clone();
        session.session_id = create_random_string(12);
        let (access_token, access_expires_at) = _create_access_token(
            &session.did,
            &session.session_id,
            state.config.security.jwt_access_expiry,
            now,
            state.config.security.jwt_encoding_key(),
        )?;
        let refresh_expiry =
            state.config.security.jwt_refresh_expiry - state.config.security.jwt_access_expiry;
        let (refresh_token, refresh_expires_at, refresh_token_hash) = _create_refresh_token(
            &session.did,
            &session.session_id,
            refresh_expiry,
            now,
            state.config.security.jwt_encoding_key(),
        )?;

        state
            .database
            .update_session_authenticated(
                &old_sid,
                &session.session_id,
                &session.did,
                &refresh_token_hash,
            )
            .await
            // Unauthenticated: say nothing of storage capacity.
            .map_err(MediatorError::opaque_storage)?;

        debug!("TSP client authenticated: {}", session.did);
        crate::scid_sources::remember(&*state.database, &state.did_resolver, &session.did).await;
        state
            .activity
            .authenticated(&state, &session.did_hash)
            .await;
        // Notices the unknown-key check owes; login does not wait on them.
        if let Some(suspended) = mux_suspended {
            let (state, did, did_hash) =
                (state.clone(), session.did.clone(), session.did_hash.clone());
            tokio::spawn(async move {
                crate::mux::notice::after_direct_auth(
                    &state,
                    &did,
                    &did_hash,
                    suspended,
                    affinidi_messaging_mediator_common::store::mux::NoticeWire::Tsp,
                )
                .await;
            });
        }
        metrics::counter!(crate::common::metrics::names::AUTH_SUCCESS_TOTAL).increment(1);

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthorizationResponse {
                    access_token,
                    access_expires_at,
                    refresh_token,
                    refresh_expires_at,
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        Form, FormRefusal, MAX_STATEMENT_LIFETIME_SECS, TspAuthenticateBody, check_form,
        signed_statement_bytes,
    };
    use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_encoding::{ED25519_PUB, encode_multikey};
    use affinidi_tsp::crypto::signing;
    use affinidi_tsp::{DidVidResolver, PrivateVid};

    const MEDIATOR: &str = "did:web:mediator.example.com";
    const OTHER_MEDIATOR: &str = "did:web:other.example.com";
    const NOW: u64 = 1_800_000_000;

    fn body(to: Option<&str>, created: Option<u64>, expires: Option<u64>) -> TspAuthenticateBody {
        TspAuthenticateBody {
            vid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into(),
            session_id: "Ab3dEf6hIj9k".into(),
            signature: String::new(),
            to: to.map(str::to_string),
            created_time: created,
            expires_time: expires,
        }
    }

    /// The exact bytes a client signs. The SDK's `TspAuthHandler` tests carry
    /// the same vector, so both sides of the wire agree on them.
    #[test]
    fn signed_statement_bytes_are_canonical_json() {
        let bytes = signed_statement_bytes(
            "9fJk2LmN4pQr6StU8vWx0yZaBcDeFgHi",
            "Ab3dEf6hIj9k",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            MEDIATOR,
            1_800_000_000,
            1_800_000_060,
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                r#"{"body":{"challenge":"9fJk2LmN4pQr6StU8vWx0yZaBcDeFgHi","session_id":"Ab3dEf6hIj9k"},"#,
                r#""created_time":1800000000,"expires_time":1800000060,"#,
                r#""from":"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK","#,
                r#""to":"did:web:mediator.example.com","#,
                r#""typ":"https://affinidi.com/atm/1.0/tsp/authenticate"}"#
            )
        );
    }

    #[test]
    fn a_statement_for_this_mediator_within_its_window_is_accepted() {
        let b = body(Some(MEDIATOR), Some(NOW), Some(NOW + 60));
        assert_eq!(
            check_form(&b, MEDIATOR, NOW, None),
            Ok(Form::Statement {
                to: MEDIATOR,
                created_time: NOW,
                expires_time: NOW + 60
            })
        );
    }

    #[test]
    fn a_statement_for_another_mediator_is_refused() {
        let b = body(Some(OTHER_MEDIATOR), Some(NOW), Some(NOW + 60));
        assert_eq!(
            check_form(&b, MEDIATOR, NOW, None),
            Err(FormRefusal::Audience)
        );
    }

    #[test]
    fn a_statement_outside_its_window_is_refused() {
        for (created, expires) in [
            (NOW - 120, NOW - 60),                        // expired
            (NOW - 60, NOW),                              // expires now
            (NOW + 600, NOW + 660),                       // made in the future
            (NOW + 60, NOW + 60),                         // empty window
            (NOW, NOW + MAX_STATEMENT_LIFETIME_SECS + 1), // too long
        ] {
            let b = body(Some(MEDIATOR), Some(created), Some(expires));
            assert_eq!(
                check_form(&b, MEDIATOR, NOW, None),
                Err(FormRefusal::Time),
                "created {created}, expires {expires}"
            );
        }
    }

    #[test]
    fn a_partial_statement_is_refused_even_with_the_opt_in() {
        for b in [
            body(Some(MEDIATOR), None, None),
            body(None, Some(NOW), Some(NOW + 60)),
            body(Some(MEDIATOR), Some(NOW), None),
        ] {
            assert_eq!(
                check_form(&b, MEDIATOR, NOW, Some(NOW + 3600)),
                Err(FormRefusal::Incomplete)
            );
        }
    }

    /// The older form is refused unless the operator's deadline is still
    /// ahead.
    #[test]
    fn the_older_form_needs_an_opt_in_that_has_not_lapsed() {
        let b = body(None, None, None);
        assert_eq!(
            check_form(&b, MEDIATOR, NOW, None),
            Err(FormRefusal::Unbound)
        );
        assert_eq!(
            check_form(&b, MEDIATOR, NOW, Some(NOW)),
            Err(FormRefusal::Unbound)
        );
        assert_eq!(
            check_form(&b, MEDIATOR, NOW, Some(NOW + 1)),
            Ok(Form::Unbound)
        );
    }

    #[test]
    fn unknown_request_fields_are_refused() {
        let raw = r#"{"vid":"did:key:z","session_id":"s","signature":"x","audience":"did:web:a"}"#;
        assert!(serde_json::from_str::<TspAuthenticateBody>(raw).is_err());
        let older = r#"{"vid":"did:key:z","session_id":"s","signature":"x"}"#;
        assert!(serde_json::from_str::<TspAuthenticateBody>(older).is_ok());
    }

    /// The core of TSP auth: a client signs the statement with its VID's
    /// Ed25519 key, and the mediator — having resolved that VID's signing key
    /// from its DID document — verifies it. A signature over the challenge
    /// alone, or over a statement addressed elsewhere, does not verify against
    /// the statement this mediator rebuilds. Uses a `did:key` (resolved
    /// locally, no network).
    #[tokio::test]
    async fn resolve_then_verify_statement_signature() {
        let vid_keys = PrivateVid::generate("placeholder");
        let did = format!(
            "did:key:{}",
            encode_multikey(ED25519_PUB, &vid_keys.verifying_key)
        );
        let challenge = "a-random-32-char-challenge-strin";
        let statement =
            |to: &str| signed_statement_bytes(challenge, "Ab3dEf6hIj9k", &did, to, NOW, NOW + 60);

        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let resolved = DidVidResolver::new(client).resolve_did(&did).await.unwrap();
        let expected = statement(MEDIATOR);

        let good = signing::sign(&expected, &vid_keys.signing_key).unwrap();
        assert!(signing::verify(&expected, &good, &resolved.signing_key).is_ok());

        let bare = signing::sign(challenge.as_bytes(), &vid_keys.signing_key).unwrap();
        assert!(signing::verify(&expected, &bare, &resolved.signing_key).is_err());

        let elsewhere = signing::sign(&statement(OTHER_MEDIATOR), &vid_keys.signing_key).unwrap();
        assert!(signing::verify(&expected, &elsewhere, &resolved.signing_key).is_err());
    }
}
