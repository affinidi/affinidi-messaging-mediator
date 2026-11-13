//! Secret-backend phase: open the backend behind the re-run guard and
//! store the minted secrets in it.

use std::path::Path;

use crate::app;
use crate::consts::*;
use crate::provision::{GenerateOptions, MintedArtefacts};
use crate::{config_writer, exit, reprovision, secret_backend, secure_fs, vta};

/// Phase 1 — open the secret backend the config names, probe it, and run
/// the re-run guard against *that* backend: refuse when it already holds a
/// provisioned mediator, unless `--force-reprovision`.
///
/// Entries that this same run already wrote are not "existing": the TUI
/// persists a VTA session's credential as soon as it connects, and those
/// match the session being provisioned now.
pub(crate) async fn open_guarded_backend(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
    options: &GenerateOptions,
) -> anyhow::Result<affinidi_messaging_mediator_common::MediatorSecrets> {
    let backend_url = config_writer::build_backend_url(config);
    let shown = affinidi_messaging_mediator_common::redact::redact_url(&backend_url);
    out!("  Secret backend: {shown}");
    // macOS Keychain prompts once per keychain item the first time a
    // given binary (code-signature ACL) accesses it, and each `cargo
    // build` produces a new binary. Say so up-front.
    if backend_url.starts_with("keyring://") {
        out!(
            "    \x1b[2mNote: macOS may prompt the Keychain on first access. Click \"Always \
             Allow\" to grant this binary permanent access.\x1b[0m"
        );
    }
    // A file backend's directory is created owner-only before its probe
    // can create it with the default mode. (The config directory is created
    // the same way when the files are written.)
    if let Some(parent) = config_writer::file_backend_host_path(config)
        .as_deref()
        .and_then(Path::parent)
    {
        secure_fs::create_private_dir_all(parent)?;
    }
    let store = secret_backend::open_and_probe_secret_backend(&backend_url, options.probe).await?;

    if !options.force_reprovision {
        let mut found = secret_backend::provisioned_well_known_keys(&store)
            .await
            .map_err(|e| exit::error(exit::REFUSED_EXISTING, format!("{e:#}")))?;
        if let Some(session) = vta_session
            && secret_backend::holds_session(&store, session).await
        {
            found.retain(|k| {
                *k != affinidi_messaging_mediator_common::ADMIN_CREDENTIAL
                    && *k != affinidi_messaging_mediator_common::VTA_LAST_KNOWN_BUNDLE
            });
        }
        if !found.is_empty() {
            return Err(reprovision::refusal(&backend_url, &found, None));
        }
    }
    Ok(store)
}

/// Provision-time invariant: every operating secret must be a verification
/// method of the mediator's own DID (`{did}#…`), and the admin credential key
/// must never be provisioned as an operating secret.
///
/// The runtime registers each operating secret under its id, and a peer
/// encrypts inbound DIDComm to the keyAgreement verification-method id
/// published in the mediator's DID document. If the ids diverge the mediator
/// boots cleanly but fails to decrypt *every* inbound message ("No local secret
/// matches any JWE recipient"). The classic cause is a VTA context whose key
/// *labels* are `did:key:…`/free-text instead of the DID document's `#key-N`
/// ids — `fetch_did_secrets_bundle` uses the label as the kid — so catch it
/// here rather than as a silent per-request runtime outage.
pub(crate) fn validate_operating_secrets(
    did: &str,
    secrets: &[affinidi_secrets_resolver::secrets::Secret],
    admin_did: Option<&str>,
) -> anyhow::Result<()> {
    let vm_prefix = format!("{did}#");
    for secret in secrets {
        if let Some(admin) = admin_did
            && secret.id.starts_with(admin)
        {
            anyhow::bail!(
                "The admin DID key `{admin}` was returned as an operating secret. The admin \
                 credential must not double as a mediator operating key — re-provision the VTA \
                 context so operating secrets contain only the mediator DID's keys."
            );
        }
        if !secret.id.starts_with(&vm_prefix) {
            anyhow::bail!(
                "Operating secret id `{}` is not a verification method of the mediator DID \
                 `{did}` (expected `{did}#…`). The mediator would publish its keyAgreement key \
                 under `{did}#…` but hold the secret under a different id, so every inbound \
                 message would fail to decrypt. If this DID is VTA-managed, set the VTA \
                 context's key labels to the DID document verification-method ids and \
                 re-provision.",
                secret.id
            );
        }
    }
    Ok(())
}

/// Phase 3 — push every well-known entry the mediator runtime expects at
/// startup into the backend [`open_guarded_backend`] opened.
///
/// Self-hosted (did:peer / did:webvh): operating keys + JWT + the generated
/// admin credential (+ the did:webvh update keys).
/// VTA-linked: the VTA admin credential + VTA fallback cache + JWT.
pub(crate) async fn provision_secret_backend(
    store: &affinidi_messaging_mediator_common::MediatorSecrets,
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<()> {
    out!("  Provisioning the secret backend:");

    // JWT signing key — only when generated. Provide-mode skips this
    // and relies on the boot-time env-var/flag path.
    if let Some(ref bytes) = artefacts.jwt_secret {
        store
            .store_jwt_secret(bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store JWT secret: {e}"))?;
        out!(
            "    \x1b[32m\u{2714}\x1b[0m {}",
            affinidi_messaging_mediator_common::JWT_SECRET
        );
    } else {
        out!(
            "    \x1b[33m\u{26A0}\x1b[0m {} (deferred to boot — provide mode)",
            affinidi_messaging_mediator_common::JWT_SECRET
        );
    }

    // Operating keys — only when the wizard generated them locally
    // (peer/webvh). VTA-managed deployments fetch them at startup.
    if !artefacts.mediator_secrets.is_empty() {
        store
            .store_entry(
                affinidi_messaging_mediator_common::OPERATING_SECRETS,
                "operating-secrets",
                &artefacts.mediator_secrets,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store operating secrets: {e}"))?;
        let count = artefacts.mediator_secrets.len();
        out!(
            "    \x1b[32m\u{2714}\x1b[0m {} ({} key{})",
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            count,
            if count == 1 { "" } else { "s" }
        );
    }

    // did:webvh log-update + pre-rotation keys — a separate entry, never
    // loaded by the mediator; what an operator needs to update the DID.
    if let Some(ref keys) = artefacts.webvh_update_keys {
        store
            .store_entry(WEBVH_UPDATE_KEYS, KIND_WEBVH_UPDATE_KEYS, keys)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store the did:webvh update keys: {e}"))?;
        out!("    \x1b[32m\u{2714}\x1b[0m {WEBVH_UPDATE_KEYS} (update + pre-rotation key)");
    }

    if let Some(session) = vta_session {
        // VTA-linked: the session's credential is the mediator↔VTA
        // identity and goes into `mediator_admin_credential`.
        let stored = secret_backend::store_vta_session(store, session).await?;
        out!(
            "    \x1b[32m\u{2714}\x1b[0m {}{}",
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
            if stored.vta_linked {
                " (VTA credential)"
            } else {
                " (self-hosted — session carried no VTA DID)"
            }
        );
        if let Some(count) = stored.cached_keys {
            out!(
                "    \x1b[32m\u{2714}\x1b[0m {} ({} key{})",
                affinidi_messaging_mediator_common::VTA_LAST_KNOWN_BUNDLE,
                count,
                if count == 1 { "" } else { "s" }
            );
        }
        if artefacts.admin_secret.is_some() {
            out!(
                "    \x1b[2mThe generated admin-API did:key is separate from the VTA \
                 credential; its key goes to admin-monitor.json.\x1b[0m"
            );
        }
    } else if let (Some(did), Some(secret)) = (
        artefacts.admin_did.as_ref(),
        artefacts.admin_secret.as_ref(),
    ) {
        // Self-hosted ADMIN_GENERATE: persist the generated admin key under
        // the same well-known entry VTA-linked runs use, with vta_did /
        // vta_url left `None` so the mediator skips its VTA integration.
        let privkey = secret
            .get_private_keymultibase()
            .map_err(|e| anyhow::anyhow!("Failed to encode the admin key: {e}"))?;
        let cred = affinidi_messaging_mediator_common::AdminCredential {
            did: did.clone(),
            private_key_multibase: privkey,
            vta_did: None,
            vta_url: None,
            context: config.vta_context.clone(),
        };
        store
            .store_admin_credential(&cred)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store admin credential: {e}"))?;
        out!(
            "    \x1b[32m\u{2714}\x1b[0m {} (self-hosted)",
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL
        );
    }

    Ok(())
}

#[cfg(test)]
mod operating_secrets_guard_tests {
    use super::validate_operating_secrets;
    use affinidi_secrets_resolver::secrets::Secret;

    const MED: &str =
        "did:webvh:QmQjq4GHRH9fwSXCg4884kxpCMT5EUqHB9XY2U7aXisP8R:webvh.storm.ws:mediator-2";

    fn secret_with_id(id: &str) -> Secret {
        let mut s = Secret::generate_ed25519(None, None);
        s.id = id.to_string();
        s
    }

    #[test]
    fn accepts_secrets_keyed_by_mediator_vm_ids() {
        let secrets = vec![
            secret_with_id(&format!("{MED}#key-0")),
            secret_with_id(&format!("{MED}#key-1")),
        ];
        assert!(validate_operating_secrets(MED, &secrets, None).is_ok());
    }

    #[test]
    fn empty_secrets_is_ok() {
        assert!(validate_operating_secrets(MED, &[], None).is_ok());
    }

    #[test]
    fn rejects_did_key_labelled_secret() {
        // The exact shape that broke a live mediator: a VTA context whose key
        // labels are `did:key:` + free text instead of the DID document's
        // `#key-N` verification-method ids.
        let secrets = vec![secret_with_id(
            "did:key:z6Mkr4JCdsEVcQvYKxcyjf39tPmVriDfg3gALvqv4GQHc5BH key-agreement key",
        )];
        let err = validate_operating_secrets(MED, &secrets, None).unwrap_err();
        assert!(
            err.to_string().contains("not a verification method"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_admin_key_as_operating_secret() {
        let admin = "did:key:z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf";
        let secrets = vec![secret_with_id(&format!(
            "{admin}#{}",
            &admin["did:key:".len()..]
        ))];
        let err = validate_operating_secrets(MED, &secrets, Some(admin)).unwrap_err();
        assert!(err.to_string().contains("admin"), "unexpected error: {err}");
    }
}
