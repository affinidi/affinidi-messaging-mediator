//! Signing the mediator's Trust Task responses.
//!
//! Every success response leaves with a Data Integrity proof (`eddsa-jcs-2022`)
//! made with the mediator DID's Ed25519 key, so a client can hold the answer as
//! evidence independent of the transport it came over. `messaging/message/get`
//! requires it outright — that response can carry another account's stored
//! envelope — and the `messaging/*` specs recommend it for the rest.
//!
//! A mediator whose DID has no Ed25519 signing key answers unsigned and says so
//! once in the log; a signing failure with a key in hand is an error, never a
//! silent downgrade to unsigned.

use crate::error_codes;
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use affinidi_did_common::DocumentExt;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use trust_tasks_proof::affinidi::{SignOptions, Verifier, sign_trust_task};

use crate::SharedData;

/// How long a signing key found by [`signing_secret`] is reused before the
/// mediator DID is resolved and its secrets walked again. Bounds how long a
/// change to the DID's keys takes to reach response signing.
const SIGNING_KEY_TTL: Duration = Duration::from_secs(300);

/// Per-mediator Trust Task key material, held in `SharedData` so the hot path
/// neither resolves the mediator's own DID and walks its secrets for every
/// response, nor builds a fresh proof verifier for every request (#198).
#[derive(Default)]
pub(crate) struct TrustTaskKeys {
    /// The last signing key found, and when. Only a key found is kept: a
    /// failed resolution is retried on the next response rather than leaving
    /// responses unsigned for the TTL.
    signing: Mutex<Option<(Instant, Secret)>>,
    verifier: OnceLock<Verifier>,
}

impl TrustTaskKeys {
    /// The proof verifier, built on first use.
    pub(crate) fn verifier(&self, state: &SharedData) -> &Verifier {
        self.verifier
            .get_or_init(|| super::trust_task_verify::proof_verifier(state.did_resolver.clone()))
    }

    fn cached_signing(&self) -> Option<Secret> {
        let slot = self.signing.lock().unwrap_or_else(|e| e.into_inner());
        slot.as_ref()
            .filter(|(at, _)| at.elapsed() < SIGNING_KEY_TTL)
            .map(|(_, secret)| secret.clone())
    }

    fn remember_signing(&self, secret: &Secret) {
        *self.signing.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), secret.clone()));
    }
}

/// Sign a response document (a serialised `TrustTask<R>`) as the mediator.
///
/// `issuer` is set to the mediator DID when the request named no recipient
/// (so `respond_with` left it empty) — the proof binds to the issuer, and the
/// mediator is the one answering. `issuedAt` is stamped if absent.
pub(crate) async fn sign_response(
    mut response: Value,
    state: &SharedData,
) -> Result<Value, MediatorError> {
    let mediator_did = &state.config.mediator_did;
    if let Some(obj) = response.as_object_mut() {
        obj.entry("issuer")
            .or_insert_with(|| Value::String(mediator_did.clone()));
        obj.entry("issuedAt").or_insert_with(|| {
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true))
        });
    }

    let Some(secret) = signing_secret(state).await else {
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                mediator_did = %mediator_did,
                "the mediator DID has no Ed25519 authentication/assertionMethod key \
                 among its secrets; Trust Task responses are sent unsigned, and \
                 messaging/message/get (which requires a signed response) cannot be \
                 answered conformantly"
            );
        });
        return Ok(response);
    };

    sign_trust_task(&response, &secret, SignOptions::new())
        .await
        .map_err(|e| {
            MediatorError::InternalError(
                error_codes::INTERNAL_ERROR,
                "NA".into(),
                format!("couldn't sign the Trust Task response: {e}"),
            )
        })
}

/// The mediator's Ed25519 secret to sign with: an `assertionMethod` key if its
/// DID declares one, else an `authentication` key.
pub(crate) async fn signing_secret(state: &SharedData) -> Option<Secret> {
    if let Some(secret) = state.trust_task_keys.cached_signing() {
        return Some(secret);
    }
    let secret = find_signing_secret(state).await?;
    state.trust_task_keys.remember_signing(&secret);
    Some(secret)
}

/// [`signing_secret`] without the cache: resolve the mediator DID and walk
/// its secrets.
async fn find_signing_secret(state: &SharedData) -> Option<Secret> {
    let did = &state.config.mediator_did;
    let doc = match state.did_resolver.resolve(did).await {
        Ok(resolved) => resolved.doc,
        Err(e) => {
            tracing::warn!(did = %did, error = %e, "couldn't resolve the mediator DID to pick a response-signing key");
            return None;
        }
    };
    let secrets = &state.config.security.mediator_secrets;
    let assertion = doc.find_assertion_method(None);
    let authentication = doc.find_authentication(None);
    for kid in assertion.into_iter().chain(authentication) {
        if let Some(secret) = secrets.get_secret(kid).await
            && secret.get_key_type() == KeyType::Ed25519
        {
            return Some(secret);
        }
    }
    None
}
