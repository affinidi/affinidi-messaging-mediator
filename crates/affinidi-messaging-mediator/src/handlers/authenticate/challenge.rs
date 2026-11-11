use super::helpers::create_random_string;
use super::{AuthenticationChallenge, ChallengeBody};
use crate::{
    SharedData,
    common::authz,
    common::session::{Session, SessionState},
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{
        accounts::AccountType,
        acls::{AccessListModeType, MediatorACLSet},
    },
};
use axum::{Json, extract::State};
use http::StatusCode;
use tracing::{Instrument, Level, debug, info, span};

/// POST /authenticate/challenge
/// Request from client to get the challenge
/// This is the first step in the authentication process
/// Creates a new sessionID and a random challenge string to the client
pub async fn authentication_challenge(
    State(state): State<SharedData>,
    Json(body): Json<ChallengeBody>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthenticationChallenge>>), AppError> {
    // Reject empty / non-DID-shaped requests up-front. An empty `did`
    // would otherwise be persisted into a SESSION record, propagate
    // through the JWT, and surface downstream as
    // `e.p.authorization.did.session_mismatch` on the WebSocket — by
    // which point it's hard to localise. The length bound matters because
    // this endpoint is unauthenticated and the DID is stored with the
    // session until it expires.
    if !is_acceptable_challenge_did(&body.did) {
        return Err(MediatorError::problem(
            29,
            "",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.challenge.invalid_did",
            "Challenge body must include a `did:`-shaped DID",
            vec![],
            StatusCode::BAD_REQUEST,
        )
        .into());
    }

    let session = Session {
        session_id: create_random_string(12),
        challenge: create_random_string(32),
        state: SessionState::ChallengeSent,
        did: body.did.clone(),
        did_hash: affinidi_messaging_mediator_common::did_identity::did_hash(&body.did),
        authenticated: false,
        acls: MediatorACLSet::default(), // this will be updated later
        account_type: AccountType::Standard,
        expires_at: 0,
        refresh_token_hash: None,
    };
    let _span = span!(
        Level::DEBUG,
        "authentication_challenge",
        session_id = session.session_id,
        did_hash = session.did_hash.clone()
    );
    async move {
        // ACL checks at the door:
        // 1. Do we know this DID? If so, is it blocked?
        // 2. If we don't know it, `mediator_acl_mode` decides:
        //    - `explicit_allow`: reject. Only DIDs pre-registered by an
        //      admin (via `account_add`) may authenticate.
        //    - `explicit_deny`: issue the challenge. Nothing is written for
        //      the DID here: its account is created only once it answers
        //      (`helpers::register_account_after_proof`), with
        //      `global_acl_default`.
        //
        // The unknown-DID rejection reuses the `authentication.blocked`
        // problem report verbatim: this endpoint is unauthenticated, and a
        // distinguishable error would let anyone probe whether an arbitrary
        // DID holds an account here. See docs/acls.md §2.

        // Check if DID is allowed to connect
        let (allowed, known) = authz::authentication_check(&state, &session.did_hash, None).await?;

        if !allowed {
            info!("DID({}) is blocked from connecting", session.did);
            return Err(MediatorError::problem(
                25,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.blocked",
                "DID is blocked",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        } else if !known
            && state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow
        {
            info!(
                "DID({}) is unknown and mediator_acl_mode is explicit_allow — rejecting",
                session.did
            );
            return Err(MediatorError::problem(
                25,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.blocked",
                "DID is blocked",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        state
            .database
            .create_session(&session.to_store_session())
            .await?;

        metrics::counter!(crate::common::metrics::names::AUTH_CHALLENGES_TOTAL).increment(1);
        debug!("Challenge sent to {}", session.did);

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthenticationChallenge {
                    challenge: session.challenge,
                    session_id: session.session_id.clone(),
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// The longest DID `/authenticate/challenge` accepts, in bytes. Real DIDs,
/// including `did:peer:2` with inline services and `did:webvh`, sit well
/// below this; the DID resolver itself refuses anything over 1000 bytes.
pub(crate) const MAX_CHALLENGE_DID_LEN: usize = 2048;

/// `did:<method>:<method-specific-id>` with a lowercase-alphanumeric method,
/// a non-empty id, no more than [`MAX_CHALLENGE_DID_LEN`] bytes, and only
/// characters a DID URL may carry (RFC 3986 unreserved, sub-delims,
/// `:@/?#` and `%`-escapes). Not a full DID parser: it keeps whitespace,
/// control characters and oversized input out of the session store.
pub(crate) fn is_acceptable_challenge_did(did: &str) -> bool {
    if did.len() > MAX_CHALLENGE_DID_LEN {
        return false;
    }
    let Some(rest) = did.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !id.is_empty()
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'%'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'?'
                        | b'#'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dids_clients_send() {
        for did in [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJhIjpbImRpZGNvbW0vdjIiXX19",
            "did:web:mediator.example.com%3A8443:path",
            "did:webvh:QmScid:example.com:alice",
            "did:scid:vh:1:QmScid?versionId=2",
        ] {
            assert!(is_acceptable_challenge_did(did), "{did} should be accepted");
        }
    }

    #[test]
    fn refuses_malformed_dids() {
        for did in [
            "",
            "did:",
            "did:key",
            "did::abc",
            "did:KEY:abc",
            "did:key:",
            "notadid:key:abc",
            "did:key:abc def",
            "did:key:abc\n",
            "did:key:abc\"",
            "did:key:<script>",
            "did:key:caf\u{e9}",
        ] {
            assert!(
                !is_acceptable_challenge_did(did),
                "{did:?} should be refused"
            );
        }
    }

    #[test]
    fn refuses_dids_over_the_length_cap() {
        let prefix = "did:key:";
        let at_cap = format!(
            "{prefix}{}",
            "a".repeat(MAX_CHALLENGE_DID_LEN - prefix.len())
        );
        assert!(is_acceptable_challenge_did(&at_cap));
        let over = format!("{at_cap}a");
        assert!(!is_acceptable_challenge_did(&over));
    }
}
