//! Boot-time configuration invariant validation.
//!
//! The individual checks (DID syntax, JWT expiry ordering, TLS file presence,
//! and the legal-but-suspicious-combo warnings) live in
//! [`affinidi_messaging_mediator_config::validate`] as pure, reusable helpers.
//! This module wires them against the resolved [`Config`]: it maps hard
//! failures to [`MediatorError::ConfigError`] (aborting startup) and logs the
//! warnings.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_config::validate::{
    ALLOW_SAMPLE_IDENTITY_ENV, check_admin_not_mediator, check_did_syntax, check_jwt_expiry,
    check_not_sample_did, check_not_sample_operating_key, check_tls, check_trust_xff_cidrs,
    warn_implicit_relay, warn_per_peer_not_below_receive_limit,
    warn_permissive_default_with_denylist_mode, warn_remote_admin_allowed,
};
use tracing::warn;

use super::Config;
use crate::common::error_codes;

/// Run all config invariants. Hard conflicts return an error (aborting
/// startup); suspicious-but-legal combinations are logged at WARN.
pub fn validate_config(config: &Config) -> Result<(), MediatorError> {
    let cfg_err =
        |msg: String| MediatorError::ConfigError(error_codes::CONFIG_ERROR, "NA".into(), msg);

    // ── Hard errors ──────────────────────────────────────────────────
    check_did_syntax("mediator_did", &config.mediator_did).map_err(cfg_err)?;
    check_did_syntax("admin_did", &config.admin_did).map_err(cfg_err)?;
    check_admin_not_mediator(&config.admin_did, &config.mediator_did).map_err(cfg_err)?;
    sample_identity_guard(check_not_sample_did("mediator_did", &config.mediator_did))?;
    sample_identity_guard(check_not_sample_did("admin_did", &config.admin_did))?;
    check_jwt_expiry(
        config.security.jwt_access_expiry,
        config.security.jwt_refresh_expiry,
    )
    .map_err(cfg_err)?;
    check_tls(
        config.security.use_ssl,
        config.security.ssl_certificate_file.as_deref(),
        config.security.ssl_key_file.as_deref(),
    )
    .map_err(cfg_err)?;
    check_trust_xff_cidrs(&config.trust_xff_cidrs).map_err(cfg_err)?;

    // ── Warnings (legal, but usually a mistake) ──────────────────────
    if let Some(msg) = warn_permissive_default_with_denylist_mode(
        &config.security.mediator_acl_mode,
        &config.security.global_acl_default,
    ) {
        warn!("{msg}");
    }
    // The default pair every account starts on. An account with its own
    // `queue_receive_limit` is checked where that limit is set — the effective
    // limit is per-account, so a boot-time check of the globals cannot cover it.
    if let Some(msg) = warn_per_peer_not_below_receive_limit(
        config.limits.queued_send_messages_per_peer,
        config.limits.queued_receive_messages_soft,
        "the configured defaults",
    ) {
        warn!("{msg}");
    }
    if let Some(msg) = warn_remote_admin_allowed(config.security.block_remote_admin_msgs) {
        warn!("{msg}");
    }
    if config.security.trust_task_verification == super::TrustTaskVerification::Warn {
        warn!(
            "security.trust_task_verification = \"warn\": Trust Tasks that fail their \
             acceptance checks (missing/invalid proof, stale issuedAt, issuer ≠ sender) \
             are logged and still executed. Set \"enforce\" once your clients sign \
             (affinidi-messaging-sdk 0.26.13+); watch trust_task_acceptance_failures_total \
             to see who does not yet."
        );
    }
    if let Some(msg) = warn_implicit_relay(
        config.security.enable_inter_mediator_relay,
        &config.security.global_acl_default,
    ) {
        warn!("{msg}");
    }

    Ok(())
}

/// Applies the policy for a sample/test identity (see
/// [`check_not_sample_did`]): refused in a release build unless
/// `MEDIATOR_ALLOW_TEST_IDENTITY=true`; a debug build only warns.
pub(crate) fn sample_identity_guard(check: Result<(), String>) -> Result<(), MediatorError> {
    let allowed = cfg!(debug_assertions)
        || std::env::var(ALLOW_SAMPLE_IDENTITY_ENV).is_ok_and(|v| v.eq_ignore_ascii_case("true"));
    sample_identity_policy(check, allowed)
}

/// Applies the sample-identity policy to every loaded operating key. A key
/// whose public form cannot be computed is skipped: it cannot be a listed
/// key.
pub(crate) fn refuse_sample_operating_keys(
    secrets: &[affinidi_secrets_resolver::secrets::Secret],
) -> Result<(), MediatorError> {
    for secret in secrets {
        if let Ok(public) = secret.get_public_keymultibase() {
            sample_identity_guard(check_not_sample_operating_key(&secret.id, &public))?;
        }
    }
    Ok(())
}

fn sample_identity_policy(check: Result<(), String>, allowed: bool) -> Result<(), MediatorError> {
    match check {
        Ok(()) => Ok(()),
        Err(msg) if allowed => {
            warn!(
                "{msg} Continuing: test identities are allowed in this build or by {ALLOW_SAMPLE_IDENTITY_ENV}."
            );
            Ok(())
        }
        Err(msg) => Err(MediatorError::ConfigError(
            error_codes::CONFIG_ERROR,
            "NA".into(),
            format!("{msg} Set {ALLOW_SAMPLE_IDENTITY_ENV}=true only for a test deployment."),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_config::validate::{
        SAMPLE_DID_KEYS, SAMPLE_JWT_PUBLIC_KEYS, check_not_sample_jwt_key,
    };
    use base64::Engine;

    #[test]
    fn a_sample_identity_is_refused_unless_allowed() {
        let sample = Err("admin_did uses a sample/test identity".to_string());
        match sample_identity_policy(sample.clone(), false) {
            Err(MediatorError::ConfigError(_, _, msg)) => {
                assert!(msg.contains(ALLOW_SAMPLE_IDENTITY_ENV));
            }
            other => panic!("expected a config error, got {other:?}"),
        }
        assert!(sample_identity_policy(sample, true).is_ok());
        assert!(sample_identity_policy(Ok(()), false).is_ok());
    }

    fn decode(entry: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(entry.trim_end_matches('='))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(entry))
            .unwrap()
    }

    /// The fixed test identity in `docker/test/conf` is on the lists, so
    /// regenerating it without updating them fails here.
    #[test]
    fn the_committed_test_identity_is_listed() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docker/test/conf");
        let Ok(secrets) = std::fs::read_to_string(dir.join("secrets.json")) else {
            eprintln!("skipping: docker/test/conf not present (not a workspace checkout)");
            return;
        };
        let toml = std::fs::read_to_string(dir.join("mediator.toml")).unwrap();
        for field in ["mediator_did", "admin_did"] {
            let line = toml
                .lines()
                .find(|l| l.starts_with(&format!("{field} = ")))
                .unwrap_or_else(|| panic!("{field} in docker/test/conf/mediator.toml"));
            assert!(
                SAMPLE_DID_KEYS.iter().any(|k| line.contains(k)),
                "{field} in docker/test/conf is not in SAMPLE_DID_KEYS"
            );
        }

        let secrets: serde_json::Value = serde_json::from_str(&secrets).unwrap();
        let entry = secrets["entries"]["mediator_jwt_secret"].as_str().unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&decode(entry)).unwrap();
        let pkcs8: Vec<u8> = envelope["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();

        // Every committed operating key is refused, whatever DID it is used under.
        let entry = secrets["entries"]["mediator_operating_secrets"]
            .as_str()
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&decode(entry)).unwrap();
        let operating: Vec<affinidi_secrets_resolver::secrets::Secret> =
            serde_json::from_value(envelope["data"].clone()).unwrap();
        assert!(!operating.is_empty());
        for secret in &operating {
            assert!(
                matches!(
                    sample_identity_policy(
                        check_not_sample_operating_key(
                            &secret.id,
                            &secret.get_public_keymultibase().unwrap()
                        ),
                        false
                    ),
                    Err(MediatorError::ConfigError(..))
                ),
                "operating key {} in docker/test/conf is not in SAMPLE_DID_KEYS",
                secret.id
            );
        }
        use ring::signature::KeyPair;
        assert!(check_not_sample_jwt_key(pair.public_key().as_ref()).is_err());
        assert!(!SAMPLE_JWT_PUBLIC_KEYS.is_empty());
    }
}
