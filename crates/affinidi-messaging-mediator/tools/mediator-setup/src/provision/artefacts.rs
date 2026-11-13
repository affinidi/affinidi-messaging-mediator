//! Writing phase: `mediator.toml`, the DID log, the did:web copy and the
//! other files next to the config, and publishing the minted DID.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::app;
use crate::app::{Deployment, SecretScheme, SslMode};
use crate::provision::MintedArtefacts;
use crate::{
    admin_monitor_profile, config_writer, docker, generators, publish, recipe, reprovision,
    secure_fs,
};

/// Write a `did.jsonl` log entry next to the mediator's config file.
/// Fatal on failure: `mediator.toml` points `did_web_self_hosted` at this
/// file, and a mediator whose DID log is missing cannot serve its DID.
pub(crate) fn write_did_jsonl(config_path: &str, log_content: &str) -> anyhow::Result<PathBuf> {
    let did_jsonl_path = config_writer::dir_of(Path::new(config_path)).join("did.jsonl");
    // Strict JSON-Lines requires each record to end with `\n`. Some upstream
    // sources (the VTA's `provision.webvh_log()`, the local generator) include
    // a trailing newline already, others don't — normalise to exactly one so
    // `cat`-ing the file or appending future log entries always works.
    let normalised = format!("{}\n", log_content.trim_end_matches('\n'));
    // did.jsonl is the DID's log of public state, but it also pins
    // the mediator's identity. Owner-only on Unix is defence in
    // depth — a public-readable log isn't a confidentiality break,
    // but a co-tenant who can't read the file can't subtly mutate
    // it either if they ever get write access.
    crate::secure_fs::write_sensitive(&did_jsonl_path, normalised)
        .with_context(|| format!("could not write the DID log {}", did_jsonl_path.display()))?;
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Saved DID log: \x1b[36m{}\x1b[0m",
        did_jsonl_path.display()
    );
    Ok(did_jsonl_path)
}

/// Convert the mediator's did:webvh log entry to a did:web DID document
/// and write it next to the config as `did-web.json`. Purely an operator
/// artefact for hosting the DID under did:web — the mediator runtime
/// serves its own document from the webvh log, never this file, so the
/// filename deliberately differs from the runtime-served `did.json`.
/// Failures are surfaced but non-fatal: a bad conversion shouldn't roll
/// back an otherwise-good setup.
pub(crate) fn write_did_web_json(
    config_path: &str,
    log_content: &str,
    webvh_did: &str,
) -> Option<PathBuf> {
    let (web_did, doc) = match generators::did_webvh::webvh_log_to_did_web(log_content, webvh_did) {
        Ok(pair) => pair,
        Err(e) => {
            err!("  \x1b[33mWarning:\x1b[0m could not derive did:web document: {e}");
            return None;
        }
    };
    let did_web_path = config_writer::dir_of(Path::new(config_path)).join("did-web.json");
    // did:web documents are public by definition (the operator hosts
    // them at `/.well-known/did.json`), but mirror the owner-only posture
    // of did.jsonl for defence in depth until the operator copies it out.
    let body = format!("{}\n", doc.trim_end_matches('\n'));
    match crate::secure_fs::write_sensitive(&did_web_path, body) {
        Ok(()) => {
            out!(
                "  \x1b[32m\u{2714}\x1b[0m Saved did:web document (\x1b[36m{web_did}\x1b[0m): \
                 \x1b[36m{}\x1b[0m",
                did_web_path.display()
            );
            Some(did_web_path)
        }
        Err(e) => {
            err!(
                "  \x1b[33mWarning:\x1b[0m could not write {}: {e}",
                did_web_path.display()
            );
            None
        }
    }
}

/// Publish the DID and its log to the recipe's targets. Returns the
/// operator-facing failure message, or `None` when there was nothing to
/// publish or it all succeeded.
pub(crate) async fn publish_minted(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
) -> Option<String> {
    let mut failures = Vec::new();
    if let Err(e) =
        publish::publish_did_artefacts(&artefacts.mediator_did, config.did_target.as_deref()).await
        && let Some(target) = &config.did_target
    {
        failures.push(format!(
            "  did_target {target}: {e:#}\n    retry by publishing the DID by hand, e.g. for \
             SSM: aws ssm put-parameter --overwrite --type String --name <name> --value \
             {}",
            artefacts.mediator_did
        ));
    }
    if let Err(e) = publish::publish_did_log_artefacts(
        artefacts.did_doc.as_deref(),
        config.did_log_target.as_deref(),
    )
    .await
        && let Some(target) = &config.did_log_target
    {
        let log = config_writer::config_dir(config).join("did.jsonl");
        failures.push(format!(
            "  did_log_target {target}: {e:#}\n    retry by uploading {} by hand, e.g. aws s3 \
             cp {} <s3-url>",
            log.display(),
            log.display()
        ));
    }
    (!failures.is_empty()).then(|| {
        format!(
            "Setup complete — the configuration and secrets are written — but publishing \
             failed:\n{}\nThe mediator reads the published DID log at boot when \
             did_log_target is set, so publish it before starting the mediator.",
            failures.join("\n")
        )
    })
}

/// Copy `path` aside as `<name>.bak.<UTC timestamp>` before it is replaced.
/// Returns the backup's path, or `None` when there was nothing to back up.
pub(crate) fn backup_existing(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".bak.{stamp}"));
    let backup = path.with_file_name(name);
    let contents = std::fs::read(path)
        .with_context(|| format!("could not read {} to back it up", path.display()))?;
    secure_fs::write_sensitive(&backup, contents).with_context(|| {
        format!(
            "could not back up {} to {}",
            path.display(),
            backup.display()
        )
    })?;
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Previous {} backed up to \x1b[36m{}\x1b[0m",
        path.display(),
        backup.display()
    );
    Ok(Some(backup))
}

/// Phase 4 — file IO. Self-signed SSL (when requested), `did.jsonl`, the
/// timestamped backup of the config being replaced, `mediator.toml` +
/// `atm-functions.lua`, the authorization VC archive, the admin monitor
/// profile, the build recipe (when requested), the Docker files (container
/// deployments) and, last, the uninstall manifest listing all of them.
pub(crate) fn write_config_artefacts(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    save_recipe: bool,
) -> anyhow::Result<()> {
    let conf_dir = config_writer::config_dir(config);
    secure_fs::create_private_dir_all(&conf_dir)
        .with_context(|| format!("could not create {}", conf_dir.display()))?;
    let mut written: Vec<PathBuf> = Vec::new();

    // Self-signed SSL (when requested). The files go in `keys/` **beside
    // `mediator.toml`**, and the paths written into it are relative to that
    // file — the rule the mediator resolves every configured path by.
    let (ssl_cert_path, ssl_key_path) = if config.ssl_mode == Some(SslMode::SelfSigned) {
        let keys_dir = conf_dir.join("keys");
        let (cert, key) = generators::ssl::generate_self_signed_cert(&keys_dir.to_string_lossy())?;
        written.push(PathBuf::from(cert));
        written.push(PathBuf::from(key));
        (
            Some("keys/end.cert".to_string()),
            Some("keys/end.key".to_string()),
        )
    } else {
        (None, None)
    };

    // The did:webvh log entry, *before* the config that points at it: a
    // failure here is fatal and leaves the previous config in place.
    let did_log_path = match artefacts.did_doc {
        Some(ref doc) => {
            let path = write_did_jsonl(&config.config_path, doc)?;
            written.push(path.clone());
            Some(path)
        }
        None => None,
    };

    let generated = config_writer::GeneratedValues {
        mediator_did: artefacts.mediator_did.clone(),
        jwt_secret: artefacts.jwt_secret.clone(),
        admin_did: artefacts.admin_did.clone(),
        admin_secret: artefacts.admin_secret.clone(),
        ssl_cert_path,
        ssl_key_path,
        did_log_path: did_log_path
            .as_deref()
            .map(|p| config_writer::runtime_file_url(config, p)),
    };

    let config_path = Path::new(&config.config_path);
    if let Some(backup) = backup_existing(config_path)? {
        written.push(backup);
    }
    written.extend(config_writer::write_config(config, &generated)?);

    // Optional did:web export. When the operator asked for it and the
    // minted DID is a did:webvh (local generator or VTA-managed webvh
    // log), rewrite the resolved DID document to its did:web form.
    if let Some(ref doc) = artefacts.did_doc
        && config.save_did_web
    {
        // A did:scid mediator's log is still a did:webvh log; bridge
        // from the log's own did:webvh DID.
        let webvh_did = if artefacts.mediator_did.starts_with("did:webvh:") {
            Some(artefacts.mediator_did.clone())
        } else if artefacts.mediator_did.starts_with("did:scid:") {
            generators::did_webvh::log_webvh_did(doc)
        } else {
            None
        };
        if let Some(webvh_did) = webvh_did {
            written.extend(write_did_web_json(&config.config_path, doc, &webvh_did));
        } else {
            err!(
                "  \x1b[33mNote:\x1b[0m --save-did-web requested but the mediator DID \
                 is not a did:webvh ({}); skipping did:web export.",
                artefacts.mediator_did
            );
        }
    }

    // Authorization VC archive (DidMethod::Vta Full path only). Short-lived
    // (~1h validity) audit trail; a failure is reported but not fatal.
    if let Some(ref vc_text) = artefacts.authorization_vc {
        let vc_path = conf_dir.join("authorization.jsonld");
        match crate::secure_fs::write_sensitive(&vc_path, vc_text) {
            Ok(()) => {
                out!(
                    "  \x1b[32m\u{2714}\x1b[0m Archived authorization VC: \x1b[36m{}\x1b[0m",
                    vc_path.display()
                );
                written.push(vc_path);
            }
            Err(e) => err!(
                "  \x1b[33mWarning:\x1b[0m could not write {}: {e}",
                vc_path.display()
            ),
        }
    }

    // Admin monitor profile (`admin-monitor.json`) — the file
    // `mediator-console --profile <path>` consumes. Written whenever the
    // wizard generated the admin key. Fatal: in a VTA flow it is the only
    // copy of the generated admin key.
    if let (Some(admin_did), Some(admin_secret)) = (&artefacts.admin_did, &artefacts.admin_secret) {
        let path = admin_monitor_profile::write(
            &config.config_path,
            &artefacts.mediator_did,
            admin_did,
            admin_secret,
        )
        .context("could not write the admin monitor profile")?;
        out!(
            "  \x1b[32m\u{2714}\x1b[0m Admin monitor profile: \x1b[1m{}\x1b[0m\n    \
             \x1b[2mUse with: \x1b[36mmediator-console --profile {}\x1b[0m",
            path.display(),
            path.display(),
        );
        written.push(path);
    }

    // Save build recipe for reproducibility (skip when running from --from).
    if save_recipe {
        let recipe_path = conf_dir.join("mediator-build.toml");
        let recipe_content = recipe::from_wizard_config(config);
        // Carries the secret-backend location; owner-only on Unix.
        crate::secure_fs::write_sensitive(&recipe_path, &recipe_content)?;
        out!(
            "  \x1b[32m\u{2714}\x1b[0m Build recipe:  \x1b[1m{}\x1b[0m",
            recipe_path.display()
        );
        written.push(recipe_path);
    }

    // Docker files for container deployments, next to the config.
    if config.deployment_type == Some(Deployment::Container) {
        written.extend(docker::generate_dockerfile(config, &conf_dir)?);
    }

    // The file backend's secrets file, so uninstall can find it.
    if config.secret_storage == Some(SecretScheme::File) {
        let url = config_writer::build_backend_url(config);
        if let Ok(affinidi_messaging_mediator_common::secrets::BackendUrl::File { path, .. }) =
            affinidi_messaging_mediator_common::secrets::parse_url(&url)
        {
            written.push(PathBuf::from(path));
        }
    }

    reprovision::write_manifest(config_path, &written)?;
    Ok(())
}
