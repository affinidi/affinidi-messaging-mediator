//! Opening the unified secret backend (`MediatorSecrets`).
//!
//! Every provisioning flow (online via `provision_secret_backend`, and the
//! sealed/headless flows in `bootstrap_headless`) opens the configured secret
//! store the same way: `MediatorSecrets::from_url` with consistent error
//! context, optionally followed by a liveness `probe()`. Centralised here so
//! that `from_url` + probe + error-mapping isn't re-inlined per flow.
//!
//! These take an already-resolved `backend_url` (from
//! [`config_writer::build_backend_url`](crate::config_writer::build_backend_url))
//! rather than the wizard config, so callers that also need the URL for their
//! own output — e.g. the keyring first-access note — resolve it once and pass it
//! in.

use affinidi_messaging_mediator_common::MediatorSecrets;
use zeroize::Zeroizing;

/// Open the unified secret backend at `backend_url` (no liveness probe).
/// Prefer [`open_and_probe_secret_backend`] when you want to fail fast on a
/// misconfigured/unreachable store before doing real work.
///
/// `file_passphrase` is the `file://?encrypt=1` passphrase the TUI
/// collected; `None` (every headless flow) reads it from
/// `MEDIATOR_FILE_BACKEND_PASSPHRASE[_FILE]` as the mediator does.
pub fn open_secret_backend(
    backend_url: &str,
    file_passphrase: Option<&Zeroizing<String>>,
) -> anyhow::Result<MediatorSecrets> {
    MediatorSecrets::from_url_with_passphrase(backend_url, file_passphrase.cloned())
        .map_err(|e| anyhow::anyhow!("open secret backend '{backend_url}': {e}"))
}

/// Which liveness probe to run when opening the backend for provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionProbe {
    /// Write round-trip: rewrites `mediator_secrets_bundle` unchanged and
    /// reads it back (on `file://` / `k8s://`, writes, reads and deletes a
    /// `mediator_probe_<uuid>` sentinel). Fails fast on missing **write**
    /// permissions before any crypto material is minted. Used by the interactive wizard, which may be pointed at a fresh
    /// backend the operator must be able to create secrets in.
    ReadWrite,
    /// Read-only reachability check (fixed `mediator_probe_readonly` sentinel,
    /// never written — `Ok` even when absent). Requested by the **headless /
    /// recipe** flow, but honoured **only for `aws_secrets://`** backends,
    /// where the Secrets Manager entry is provisioned out-of-band (e.g. CDK
    /// pre-creates `<prefix>mediator_secrets_bundle`) so setup only
    /// overwrites it and never needs create/delete rights — the IaC-owns-lifecycle contract, matching the
    /// mediator runtime, which also probes read-only at boot and on `/readyz`.
    ///
    /// For every other backend (`file://`, `keyring://`, `vault://`, …) the
    /// setup tool itself creates the secrets, so a requested `ReadOnly` is
    /// narrowed back to [`ReadWrite`](Self::ReadWrite) by
    /// [`open_and_probe_secret_backend`] — the write round-trip still fails
    /// fast on missing permissions, even headless.
    ReadOnly,
}

/// Whether `backend_url` names an AWS-managed secret store (`aws_secrets://`).
/// Only these follow the IaC-owns-lifecycle principle and are eligible for the
/// read-only provisioning probe; see [`ProvisionProbe::ReadOnly`].
fn is_aws_secrets_backend(backend_url: &str) -> bool {
    backend_url.starts_with("aws_secrets://")
}

/// Resolve the probe actually run for `backend_url` from the one `requested`.
/// A `ReadOnly` request is honoured only for AWS-managed backends; for anything
/// else it falls back to `ReadWrite`. `ReadWrite` requests pass through
/// unchanged. Pure so the narrowing rule can be unit-tested directly.
fn effective_probe(backend_url: &str, requested: ProvisionProbe) -> ProvisionProbe {
    match requested {
        ProvisionProbe::ReadOnly if !is_aws_secrets_backend(backend_url) => {
            ProvisionProbe::ReadWrite
        }
        other => other,
    }
}

/// Open the unified secret backend and probe it, so a misconfigured or
/// unreachable store (e.g. `aws_secrets://` with no credentials) fails fast with
/// an actionable error instead of part-way through provisioning.
///
/// A requested [`ProvisionProbe::ReadOnly`] is honoured **only for
/// `aws_secrets://`** backends (the IaC-owns-lifecycle contract); for every
/// other backend it is narrowed back to [`ProvisionProbe::ReadWrite`], so the
/// setup tool — which creates those secrets itself — keeps the write round-trip
/// that fails fast on missing permissions, even in headless flows. Interactive
/// callers always pass `ReadWrite` and are unaffected.
pub async fn open_and_probe_secret_backend(
    backend_url: &str,
    file_passphrase: Option<&Zeroizing<String>>,
    probe: ProvisionProbe,
) -> anyhow::Result<MediatorSecrets> {
    let store = open_secret_backend(backend_url, file_passphrase)?;
    let probe = effective_probe(backend_url, probe);
    let result = match probe {
        ProvisionProbe::ReadWrite => store.probe().await,
        ProvisionProbe::ReadOnly => store.probe_readonly().await,
    };
    result.map_err(|e| anyhow::anyhow!("secret backend '{backend_url}' failed probe: {e}"))?;
    // An existing per-key deployment is moved to the single-secret layout
    // (kept until the mediator confirms it); fail now, not mid-provisioning.
    store.ensure_migrated().await.map_err(|e| {
        anyhow::anyhow!(
            "secret backend '{backend_url}' could not be moved to the single-secret layout: {e}"
        )
    })?;
    Ok(store)
}

/// Every well-known entry whose presence means "a mediator was already
/// provisioned into this backend". The re-run guard refuses to write over
/// any of them without `--force-reprovision`; uninstall deletes each one.
pub const WELL_KNOWN_KEYS: &[&str] = &[
    affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
    affinidi_messaging_mediator_common::JWT_SECRET,
    affinidi_messaging_mediator_common::OPERATING_SECRETS,
    affinidi_messaging_mediator_common::OPERATING_DID_DOCUMENT,
    affinidi_messaging_mediator_common::VTA_LAST_KNOWN_BUNDLE,
    crate::consts::WEBVH_UPDATE_KEYS,
];

/// The well-known entries `store` already holds, in [`WELL_KNOWN_KEYS`]
/// order.
///
/// A read error is returned, not treated as "absent": a guard that cannot
/// tell whether live keys are there must refuse rather than overwrite them.
/// On per-key backends every entry lives in one bundled secret that the
/// store caches, so this is a single backend read (one Keychain prompt on
/// macOS), not one per key.
pub async fn provisioned_well_known_keys(
    store: &MediatorSecrets,
) -> anyhow::Result<Vec<&'static str>> {
    let mut found = Vec::new();
    for key in WELL_KNOWN_KEYS {
        match store.store().get(key).await {
            Ok(Some(_)) => found.push(*key),
            Ok(None) => {}
            Err(e) => anyhow::bail!(
                "could not read `{key}` to check for an existing mediator setup: {e}. \
                 Refusing to write over entries whose presence cannot be checked"
            ),
        }
    }
    Ok(found)
}

/// What [`store_vta_session`] wrote, for the caller to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredVtaSession {
    /// `false` when the session carried no VTA DID, so the admin
    /// credential was stored self-hosted (no VTA linkage).
    pub vta_linked: bool,
    /// Number of keys seeded into the VTA fallback cache; `None` for an
    /// admin-only session, which has no VTA-provisioned DID to cache.
    pub cached_keys: Option<usize>,
}

/// Persist what a VTA session produced: the mediator↔VTA admin credential
/// (`mediator_admin_credential`) and, when the VTA provisioned the mediator
/// DID, the fallback cache the mediator boots from when the VTA is
/// unreachable (`mediator_vta_last_known_bundle`).
///
/// Shared by the final provisioning pass and the TUI, which persists the
/// session as soon as it connects so a later failure or quit does not lose
/// a DID the VTA has already minted. Idempotent: writing the same session
/// twice stores the same values.
pub async fn store_vta_session(
    store: &MediatorSecrets,
    session: &crate::vta::VtaSession,
) -> anyhow::Result<StoredVtaSession> {
    // Both VTA fields are normalised through `non_empty`. A sealed context
    // export whose bundle omitted `vta_did` reaches us as an empty string
    // (`VtaSession::context_export` uses `unwrap_or_default`), and an empty
    // `vta_url` is equally meaningless — storing either verbatim fails the
    // credential's shape validation. `vta_url: None` is a supported shape:
    // the mediator resolves the VTA endpoint from its DID document.
    let non_empty = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
    let vta_did = non_empty(Some(session.vta_did.clone()));
    // A URL with no DID is not a VTA linkage — there is nothing to
    // authenticate against — so it is dropped rather than stored.
    let vta_url = vta_did
        .as_ref()
        .and_then(|_| non_empty(session.rest_url.clone()));
    let vta_linked = vta_did.is_some();
    let cred = affinidi_messaging_mediator_common::AdminCredential {
        did: session.admin_did().to_string(),
        private_key_multibase: session.admin_private_key_mb().to_string(),
        vta_did,
        vta_url,
        context: session.context_id.clone(),
    };
    store
        .store_admin_credential(&cred)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store admin credential: {e}"))?;

    // Seed the VTA fallback cache. The mediator's boot calls
    // `vta_sdk::integration::startup()`, which tries a live fetch and falls
    // back to this cache on any failure, so first boot survives VTA
    // unavailability. TTL `0` = no expiry: the runtime overwrites it with a
    // fresh snapshot on every successful VTA contact.
    let cached_keys = match crate::provision::mint::build_did_secrets_bundle(session) {
        Some(bundle) => {
            let json = serde_json::to_value(&bundle)
                .map_err(|e| anyhow::anyhow!("Failed to serialize cached VTA bundle: {e}"))?;
            store
                .store_vta_cached_bundle(json, 0)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to seed VTA cache: {e}"))?;
            Some(bundle.secrets.len())
        }
        None => None,
    };
    Ok(StoredVtaSession {
        vta_linked,
        cached_keys,
    })
}

/// Whether `store` already holds exactly this session's admin credential —
/// i.e. the entries the re-run guard finds were written by this same run
/// (the TUI persists a session as soon as it connects), not by an earlier
/// mediator.
pub async fn holds_session(store: &MediatorSecrets, session: &crate::vta::VtaSession) -> bool {
    matches!(
        store.load_admin_credential().await,
        Ok(Some(cred)) if cred.did == session.admin_did()
            && cred.private_key_multibase == session.admin_private_key_mb()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trips_a_file_backend_url() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let url = format!("file://{}", dir.path().join("secrets.json").display());
        assert!(
            open_secret_backend(&url, None).is_ok(),
            "a file:// backend URL should open"
        );
    }

    #[test]
    fn readonly_probe_is_honoured_only_for_aws_secrets() {
        // AWS-managed store: IaC owns the lifecycle, so ReadOnly stands.
        assert_eq!(
            effective_probe(
                "aws_secrets://us-east-1/mediator/",
                ProvisionProbe::ReadOnly
            ),
            ProvisionProbe::ReadOnly,
        );
        // Every other backend creates its own secrets → narrow to ReadWrite.
        for url in [
            "file:///tmp/secrets.json",
            "keyring://affinidi-mediator",
            "vault://vault.example.com/secret",
            "gcp_secrets://proj/mediator/",
        ] {
            assert_eq!(
                effective_probe(url, ProvisionProbe::ReadOnly),
                ProvisionProbe::ReadWrite,
                "{url} should fall back to a write round-trip",
            );
        }
    }

    #[test]
    fn readwrite_probe_passes_through_for_every_backend() {
        for url in [
            "aws_secrets://us-east-1/mediator/",
            "file:///tmp/secrets.json",
            "keyring://affinidi-mediator",
        ] {
            assert_eq!(
                effective_probe(url, ProvisionProbe::ReadWrite),
                ProvisionProbe::ReadWrite,
                "{url} must keep an explicit ReadWrite request",
            );
        }
    }
}
