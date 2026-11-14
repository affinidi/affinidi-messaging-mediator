//! Re-run safety, the setup manifest, and the uninstall flow.
//!
//! 1. **Re-run safety**: the wizard refuses to write into a secret backend
//!    that already holds well-known mediator keys unless
//!    `--force-reprovision` is passed — silently rotating the JWT or admin
//!    credential of a running mediator would invalidate every issued token
//!    and VTA session. The binding check runs on the backend about to be
//!    written (`main::open_guarded_backend`); the interactive wizard also
//!    checks the backend of an existing `mediator.toml` before it starts,
//!    so the operator learns early.
//! 2. **Manifest**: every setup records the files it wrote in
//!    `.mediator-setup-manifest.json` next to the config.
//! 3. **Uninstall**: a deliberate teardown — list every well-known key
//!    present in the configured backend, ask for a typed confirmation, then
//!    delete each key and every file the manifest lists.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use affinidi_messaging_mediator_common::MediatorSecrets;
use affinidi_messaging_mediator_common::redact::redact_url;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// What the wizard inferred from a still-on-disk mediator.toml.
pub struct ExistingSetup {
    /// Backend URL recovered from `[secrets].backend`.
    pub backend_url: String,
    /// The well-known keys the backend holds.
    pub provisioned_keys: Vec<&'static str>,
}

impl ExistingSetup {
    pub fn is_provisioned(&self) -> bool {
        !self.provisioned_keys.is_empty()
    }
}

/// Read the backend URL out of an existing `mediator.toml`. Returns
/// `Ok(None)` when the file is missing or has no `[secrets].backend`.
fn read_backend_url(config_path: &Path) -> anyhow::Result<Option<String>> {
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path)?;
    let doc: toml::Value = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {e}", config_path.display()))?;
    let url = doc
        .get("secrets")
        .and_then(|s| s.get("backend"))
        .and_then(|b| b.as_str())
        .map(|s| s.to_string());
    Ok(url)
}

/// Inspect the backend named by an existing `mediator.toml` for
/// provisioned mediator keys. Returns `Ok(None)` when there is nothing to
/// inspect (no config file or no backend URL).
///
/// Says what it is doing first: on a cloud backend this is a network
/// round-trip, and on macOS it can raise a Keychain prompt. A read error is
/// returned rather than treated as "nothing there".
pub async fn inspect_existing(config_path: &Path) -> anyhow::Result<Option<ExistingSetup>> {
    let Some(backend_url) = read_backend_url(config_path)? else {
        return Ok(None);
    };
    err!(
        "Checking the existing setup in {} (from {})…",
        redact_url(&backend_url),
        config_path.display()
    );
    let secrets = MediatorSecrets::from_url(&backend_url).map_err(|e| {
        anyhow::anyhow!(
            "Could not open backend '{}' from {}: {e}",
            redact_url(&backend_url),
            config_path.display()
        )
    })?;
    let provisioned_keys = crate::secret_backend::provisioned_well_known_keys(&secrets)
        .await
        .map_err(|e| crate::exit::error(crate::exit::REFUSED_EXISTING, format!("{e:#}")))?;
    Ok(Some(ExistingSetup {
        backend_url,
        provisioned_keys,
    }))
}

/// The "refusing to overwrite" error (exit code 4), listing what the
/// backend holds and how to proceed.
pub fn refusal(backend_url: &str, keys: &[&str], config_path: Option<&Path>) -> anyhow::Error {
    let mut msg = format!(
        "Refusing to overwrite an existing mediator setup{}.\nBackend {} already holds:\n",
        config_path
            .map(|p| format!(" at {}", p.display()))
            .unwrap_or_default(),
        redact_url(backend_url)
    );
    for key in keys {
        msg.push_str(&format!("  - {key}\n"));
    }
    msg.push_str(
        "Writing a new setup would rotate these: issued JWTs stop verifying, an active VTA \
         session breaks, and every client must re-authenticate.\n\
         To proceed anyway:    re-run with --force-reprovision\n\
         To tear down cleanly: mediator-setup --uninstall --config <mediator.toml>",
    );
    crate::exit::error(crate::exit::REFUSED_EXISTING, msg)
}

// ── Manifest ──────────────────────────────────────────────────────────

/// File name of the setup manifest, next to `mediator.toml`.
pub const MANIFEST_FILE: &str = ".mediator-setup-manifest.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    /// Every file a setup wrote (absolute paths), across re-runs.
    files: BTreeSet<PathBuf>,
}

/// Where the manifest for `config_path` lives.
pub fn manifest_path(config_path: &Path) -> PathBuf {
    crate::config_writer::dir_of(config_path).join(MANIFEST_FILE)
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn read_manifest(path: &Path) -> Manifest {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Record `files` (and the config itself) in the manifest next to
/// `config_path`, merged with what earlier runs recorded.
pub fn write_manifest(config_path: &Path, files: &[PathBuf]) -> anyhow::Result<()> {
    let path = manifest_path(config_path);
    let mut manifest = read_manifest(&path);
    manifest.files.insert(absolute(config_path));
    manifest.files.extend(files.iter().map(|f| absolute(f)));
    let json = serde_json::to_vec_pretty(&manifest)?;
    crate::secure_fs::write_sensitive(&path, json)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", path.display()))
}

/// Files the wizard can write next to `mediator.toml`, removed on uninstall
/// even without a manifest (a setup made by an older wizard).
const COMPANION_FILES: &[&str] = &[
    "atm-functions.lua",
    "did.jsonl",
    "did-web.json",
    "authorization.jsonld",
    "admin-monitor.json",
    "mediator-build.toml",
    "mediator-build.resume.toml",
    "keys/end.cert",
    "keys/end.key",
];

/// Every file uninstall should remove for the setup at `config_path`.
fn files_to_remove(config_path: &Path, backend_url: Option<&str>) -> Vec<PathBuf> {
    let dir = crate::config_writer::dir_of(config_path);
    let mut files: BTreeSet<PathBuf> = read_manifest(&manifest_path(config_path)).files;
    files.insert(absolute(config_path));
    for name in COMPANION_FILES {
        files.insert(absolute(&dir.join(name)));
    }
    // Backups of the config (`mediator.toml.bak`, `mediator.toml.bak.<ts>`).
    if let (Some(name), Ok(entries)) = (
        config_path.file_name().and_then(|n| n.to_str()),
        std::fs::read_dir(dir),
    ) {
        let prefix = format!("{name}.bak");
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
            {
                files.insert(absolute(&entry.path()));
            }
        }
    }
    // The configured file backend, wherever it points.
    if let Some(url) = backend_url
        && let Ok(affinidi_messaging_mediator_common::secrets::BackendUrl::File { path, .. }) =
            affinidi_messaging_mediator_common::secrets::parse_url(url)
    {
        files.insert(absolute(Path::new(&path)));
    }
    files.insert(absolute(&manifest_path(config_path)));
    files.into_iter().collect()
}

/// Run the uninstall flow. Loads the backend, lists keys, prompts for a
/// typed `DELETE` confirmation, then deletes the keys and removes every
/// file the setup wrote. Idempotent: missing files / already-deleted keys
/// are skipped rather than failing.
pub async fn run_uninstall(config_path: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(config_path);
    let setup = inspect_existing(&path).await?;

    match &setup {
        None => {
            out!(
                "No mediator configuration found at {} — nothing to uninstall.",
                path.display()
            );
            return Ok(());
        }
        Some(s) if s.provisioned_keys.is_empty() => {
            out!(
                "Backend {} has no provisioned mediator keys; only local files will be removed.",
                redact_url(&s.backend_url)
            );
        }
        Some(s) => {
            out!("Mediator setup at {} will be removed.", path.display());
            out!("Backend: \x1b[1m{}\x1b[0m", redact_url(&s.backend_url));
            out!("Keys to delete:");
            for key in &s.provisioned_keys {
                out!("  - {key}");
            }
        }
    }
    let files: Vec<PathBuf> =
        files_to_remove(&path, setup.as_ref().map(|s| s.backend_url.as_str()))
            .into_iter()
            .filter(|f| f.exists())
            .collect();
    if !files.is_empty() {
        out!("Files to remove:");
        for f in &files {
            out!("  - {}", f.display());
        }
    }
    out!();
    out_inline!("Type \x1b[1mDELETE\x1b[0m (uppercase) to confirm, anything else aborts: ");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "DELETE" {
        err!("\nAborted — nothing was changed.");
        return Ok(());
    }

    info!(config_path = %path.display(), "Starting mediator uninstall");

    if let Some(setup) = setup {
        let shown = redact_url(&setup.backend_url);
        let secrets = MediatorSecrets::from_url(&setup.backend_url)
            .map_err(|e| anyhow::anyhow!("Could not reopen backend '{shown}': {e}"))?;
        for key in &setup.provisioned_keys {
            match secrets.store().delete(key).await {
                Ok(()) => {
                    info!(backend = %shown, key = %key, "Deleted well-known key");
                    out!("  \x1b[32m\u{2714}\x1b[0m deleted {key}");
                }
                Err(e) => {
                    warn!(backend = %shown, key = %key, error = %e, "Failed to delete well-known key");
                    err!("  \x1b[33m\u{26A0}\x1b[0m {key}: {e}");
                }
            }
        }
        // Deleting each key leaves the (now empty) single-secret bundle and
        // any bootstrap seeds behind; purge removes the rest.
        match secrets.purge().await {
            Ok(()) => info!(backend = %shown, "Removed remaining mediator secrets"),
            Err(e) => {
                warn!(backend = %shown, error = %e, "Failed to remove remaining mediator secrets");
                err!("  \x1b[33m\u{26A0}\x1b[0m remaining secrets: {e}");
            }
        }
    }

    for file in &files {
        match std::fs::remove_file(file) {
            Ok(()) => {
                info!(path = %file.display(), "Removed file");
                out!("  \x1b[32m\u{2714}\x1b[0m removed {}", file.display());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => err!("  \x1b[33m\u{26A0}\x1b[0m {}: {e}", file.display()),
        }
    }
    // An emptied `keys/` directory the wizard created goes too.
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir.join("keys"));
    }

    out!("\n\x1b[32mUninstall complete.\x1b[0m");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_returns_none_for_missing_config() {
        // Missing config = no setup; the wizard treats this as a fresh
        // install.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let path = std::env::temp_dir().join("mediator-setup-nonexistent-9241.toml");
        let _ = std::fs::remove_file(&path);
        let result = rt.block_on(inspect_existing(&path)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_backend_url_pulls_from_secrets_section() {
        let toml = r#"
mediator_did = "did:peer:foo"
[secrets]
backend = "keyring://test-mediator"
"#;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("mediator.toml");
        std::fs::write(&path, toml).unwrap();
        let url = read_backend_url(&path).unwrap();
        assert_eq!(url, Some("keyring://test-mediator".to_string()));
    }

    #[test]
    fn read_backend_url_returns_none_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("mediator.toml");
        std::fs::write(&path, "mediator_did = \"did:peer:foo\"\n").unwrap();
        assert!(read_backend_url(&path).unwrap().is_none());
    }

    #[test]
    fn refusal_carries_its_exit_code_and_lists_keys() {
        let e = refusal("keyring://x", &["mediator_jwt_secret"], None);
        assert_eq!(crate::exit::code_of(&e), crate::exit::REFUSED_EXISTING);
        assert!(e.to_string().contains("mediator_jwt_secret"));
    }

    #[test]
    fn uninstall_covers_manifest_backups_and_the_configured_secrets_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("conf").join("mediator.toml");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "").unwrap();
        let elsewhere = dir.path().join("Dockerfile");
        write_manifest(&config, std::slice::from_ref(&elsewhere)).unwrap();
        let backup = config.with_file_name("mediator.toml.bak.20260101T000000Z");
        std::fs::write(&backup, "").unwrap();
        let secrets = dir.path().join("vault").join("secrets.json");
        let url = format!("file://{}", secrets.display());

        let files = files_to_remove(&config, Some(&url));
        for expected in [
            &config,
            &elsewhere,
            &backup,
            &secrets,
            &config.with_file_name("admin-monitor.json"),
            &config.parent().unwrap().join("keys").join("end.key"),
            &manifest_path(&config),
        ] {
            assert!(
                files.contains(expected),
                "{} missing: {files:?}",
                expected.display()
            );
        }
    }

    #[test]
    fn manifest_merges_across_runs() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("mediator.toml");
        write_manifest(&config, &[dir.path().join("a")]).unwrap();
        write_manifest(&config, &[dir.path().join("b")]).unwrap();
        let m = read_manifest(&manifest_path(&config));
        assert!(m.files.contains(&dir.path().join("a")));
        assert!(m.files.contains(&dir.path().join("b")));
        assert!(m.files.contains(&config));
    }
}
