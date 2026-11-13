//! The provisioning pipeline every flow ends in: mint the DID and keys,
//! write them to the secret backend, write the config artefacts, publish.
//!
//! - [`mint`]: generate (or take from the VTA session) the key material.
//! - [`backend`]: open, guard and fill the secret backend.
//! - [`artefacts`]: `mediator.toml`, the DID log and the other files.
//! - [`summary`]: the completion summary printed afterwards.

pub(crate) mod artefacts;
pub(crate) mod backend;
pub(crate) mod mint;
pub(crate) mod summary;

use crate::app;
use crate::provision::artefacts::{publish_minted, write_config_artefacts};
use crate::provision::backend::{open_guarded_backend, provision_secret_backend};
use crate::provision::mint::mint_artefacts;
use crate::provision::summary::print_completion_summary;
use crate::{exit, generators, secret_backend, vta};

/// Bag of artefacts the mint phase produces and the later phases
/// consume. Keeps the `generate_and_write` phases coupled by an
/// explicit value type rather than a soup of mutable locals.
///
/// Pure-ish: every field is a value, not a handle to a backend or
/// open file. Side effects (file writes, network calls, stdout) live
/// in `provision_secret_backend`, `write_config_artefacts`, and
/// `print_completion_summary` which take a borrowed `&MintedArtefacts`.
pub(crate) struct MintedArtefacts {
    /// The mediator's DID — `did:peer:…`, `did:webvh:…`, or a
    /// VTA-managed DID forwarded from the Vta sub-flow.
    mediator_did: String,
    /// Operating-key secrets the mediator's runtime loader expects
    /// at `mediator/operating/secrets`. Empty when the VTA hosts
    /// the keys (the runtime fetches them at startup).
    mediator_secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    /// Serialised did:webvh log entry (or VTA-returned log) that
    /// `write_config_artefacts` writes to `did.jsonl`. `None` when
    /// the deployment uses no self-hosted DID log.
    did_doc: Option<String>,
    /// The log-update and pre-rotation keys of a locally generated
    /// did:webvh, stored apart from the operating secrets. `None` for
    /// every other DID method.
    webvh_update_keys: Option<generators::did_webvh::WebvhUpdateKeys>,
    /// Authorization credential JSON the VTA returned with the
    /// minted DID. Archived alongside the config in
    /// `write_config_artefacts`. `None` for non-VTA / OfflineExport
    /// deployments.
    authorization_vc: Option<String>,
    /// Raw PKCS8 bytes of the JWT signing key. `None` under
    /// `jwt_mode = provide` — the runtime expects
    /// `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot.
    jwt_secret: Option<Vec<u8>>,
    /// The mediator's admin-API DID. `None` under `AdminMode::Skip`.
    admin_did: Option<String>,
    /// Secret material of a *generated* admin DID. `None` when the admin
    /// DID is the VTA credential (its key is in the session), a pasted DID
    /// (the wizard holds no key) or skipped.
    admin_secret: Option<affinidi_secrets_resolver::secrets::Secret>,
}

/// How a `generate_and_write` run behaves.
pub(crate) struct GenerateOptions {
    /// Save a `mediator-build.toml` recipe next to the config. Off for
    /// `--from` runs, so the input recipe is never overwritten.
    pub save_recipe: bool,
    /// Which liveness probe to run on the secret backend.
    pub probe: secret_backend::ProvisionProbe,
    /// Write over a backend that already holds a provisioned mediator.
    pub force_reprovision: bool,
    /// Print the generated admin private key (terminal only).
    pub show_admin_key: bool,
}

impl GenerateOptions {
    #[cfg(test)]
    fn for_tests(save_recipe: bool, probe: secret_backend::ProvisionProbe) -> Self {
        Self {
            save_recipe,
            probe,
            force_reprovision: false,
            show_admin_key: false,
        }
    }
}

/// A finished setup. Publishing runs last, after every local write, so its
/// failure does not undo a complete setup; it is reported here instead.
#[must_use]
pub(crate) struct Completed {
    publish_failure: Option<String>,
}

impl Completed {
    /// `Ok` when everything — publishing included — succeeded; otherwise the
    /// "setup complete, publish failed" error with its own exit code.
    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        match self.publish_failure {
            None => Ok(()),
            Some(msg) => Err(exit::error(exit::PUBLISH_FAILED, msg)),
        }
    }
}

/// [`generate_and_write_with`] with the default options; the shape the
/// end-to-end tests drive.
#[cfg(test)]
pub(crate) async fn generate_and_write(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
    save_recipe: bool,
    probe: secret_backend::ProvisionProbe,
) -> anyhow::Result<()> {
    generate_and_write_with(
        config,
        vta_session,
        &GenerateOptions::for_tests(save_recipe, probe),
    )
    .await?
    .into_result()
}

/// Run all generators and write configuration files.
///
/// Phases, in order — each has one concern, and the order is what makes a
/// failure part-way through recoverable:
///
/// 1. [`open_guarded_backend`] — open and probe the secret backend, and
///    refuse (exit 4) if it already holds a provisioned mediator, *before*
///    anything is minted. Catches typos, missing cloud credentials and dead
///    Vault tokens here, not at first mediator boot.
/// 2. [`mint_artefacts`] — pure-ish value computation (DID + JWT + admin
///    DID). No file IO; no network.
/// 3. [`provision_secret_backend`] — push every well-known entry the
///    runtime expects. Before the config, so `mediator.toml` never names
///    secrets that are not there.
/// 4. [`write_config_artefacts`] — file IO: SSL, `did.jsonl` (before the
///    config that references it), `mediator.toml` (after a timestamped
///    backup of the one it replaces) plus Lua, the authorization VC
///    archive, the admin monitor profile, the recipe, the Docker files and
///    the uninstall manifest. Every write is temp + fsync + rename.
/// 5. [`print_completion_summary`] — operator-facing output.
/// 6. Publishing to `[output].did_target` / `did_log_target`, last: the
///    setup is complete whether or not it succeeds (see [`Completed`]).
pub(crate) async fn generate_and_write_with(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
    options: &GenerateOptions,
) -> anyhow::Result<Completed> {
    let store = open_guarded_backend(config, vta_session, options).await?;
    let artefacts = mint_artefacts(config, vta_session).await?;
    provision_secret_backend(&store, config, &artefacts, vta_session).await?;
    write_config_artefacts(config, &artefacts, options.save_recipe)?;
    print_completion_summary(config, &artefacts, vta_session, options.show_admin_key);
    Ok(Completed {
        publish_failure: publish_minted(config, &artefacts).await,
    })
}

/// Integration tests against `generate_and_write` end-to-end.
///
/// Locks down the recipe → wizard config → on-disk artefact contract
/// before refactoring the function into smaller phases. The test
/// shouldn't change behaviour pre- and post-refactor; if the same
/// inputs produce a different `mediator.toml` / `secrets.json` /
/// recipe, the refactor regressed something.
///
/// All tests use a tempdir and `#[serial_test::serial]` because
/// `generate_and_write` writes some artefacts (SSL keys, Dockerfile)
/// to paths relative to CWD via the `conf/` prefix; CWD-mutating
/// tests must not race with each other.
#[cfg(test)]
mod generate_and_write_tests {
    use super::*;
    use crate::app::{AdminMode, Deployment, DidMethod, SecretScheme, SslMode, VtaMode};
    use crate::consts::*;
    use crate::{config_writer, recipe, reprovision};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn decode_service_segments(did: &str) -> Vec<serde_json::Value> {
        did.split('.')
            .filter_map(|segment| segment.strip_prefix('S'))
            .map(|segment| {
                let bytes = URL_SAFE_NO_PAD.decode(segment).unwrap();
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect()
    }

    /// Tempdir + CWD swap, restored on drop. Mirrors the
    /// `bootstrap_headless::tests::CwdGuard` pattern (kept private to
    /// that module). Two-line duplication is cheaper than restructuring
    /// for re-use across binary-private mod tests.
    struct CwdGuard {
        _tmp: tempfile::TempDir,
        path: std::path::PathBuf,
        prev: std::path::PathBuf,
        // Held for the guard's lifetime — see `crate::cwd_lock`. Declared last
        // so it is dropped after the directory is restored.
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CwdGuard {
        fn new() -> Self {
            let lock = crate::cwd_lock();
            let tmp = tempfile::tempdir().unwrap();
            let prev = std::env::current_dir().unwrap();
            let path = tmp.path().to_path_buf();
            std::env::set_current_dir(&path).unwrap();
            Self {
                _tmp: tmp,
                path,
                prev,
                _lock: lock,
            }
        }
        fn dir(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    /// Build a minimal `did:peer` config that exercises every
    /// non-VTA generate_and_write phase: DID generation, JWT mint,
    /// admin did:key generation, file:// backend probe + writes,
    /// mediator.toml write, atm-functions.lua write, recipe write.
    /// Skips SSL (writes to relative `conf/keys/` and is exercised
    /// elsewhere) and Docker (deployment_type-gated).
    fn did_peer_config(dir: &std::path::Path) -> app::WizardConfig {
        let conf_dir = dir.join("conf");
        let secrets_path = dir.join("unified-secrets.json");
        app::WizardConfig {
            config_path: conf_dir
                .join("mediator.toml")
                .to_string_lossy()
                .into_owned(),
            deployment_type: Some(Deployment::Local),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: Some(DidMethod::Peer),
            secret_storage: Some(SecretScheme::File),
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: Some(SslMode::None),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: Some(AdminMode::Generate),
            public_url: "http://localhost:7037".into(),
            ..app::WizardConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_did_peer_emits_full_artefact_set() {
        // End-to-end: did:peer + file:// + JWT generate + admin
        // generate. Every phase except SSL and Docker runs. The
        // assertions cover what the upcoming refactor must preserve:
        // every file lands in the right place with the right shape.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = did_peer_config(&dir);

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ true,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed for did:peer");

        // Phase: write_config — mediator.toml + atm-functions.lua.
        let toml_path = dir.join("conf").join("mediator.toml");
        let lua_path = dir.join("conf").join("atm-functions.lua");
        assert!(toml_path.exists(), "mediator.toml must be written");
        assert!(lua_path.exists(), "atm-functions.lua must be written");

        // mediator.toml must parse and carry every field the wizard
        // sets: mediator DID (did:peer:…), admin DID (did:key:…),
        // backend URL (file://…), api_prefix, listen_address.
        let toml_text = std::fs::read_to_string(&toml_path).unwrap();
        let parsed: toml::Value =
            toml::from_str(&toml_text).expect("mediator.toml must be valid TOML");
        let mediator_did = parsed
            .get("mediator_did")
            .and_then(|v| v.as_str())
            .expect("mediator_did must be present");
        assert!(
            mediator_did.starts_with("did://did:peer:"),
            "mediator_did must be a did:peer (got: {mediator_did})"
        );
        let mediator_did = mediator_did.trim_start_matches("did://");
        assert_eq!(
            mediator_did.matches(".S").count(),
            2,
            "did:peer should advertise DIDComm + #auth services"
        );
        let services = decode_service_segments(mediator_did);
        assert_eq!(services.len(), 2);
        assert_eq!(
            services[0]["s"][0]["uri"],
            "http://localhost:7037/mediator/v1"
        );
        assert_eq!(
            services[0]["s"][1]["uri"],
            "ws://localhost:7037/mediator/v1/ws"
        );
        assert!(services[1]["id"].as_str().unwrap().ends_with("#auth"));
        assert_eq!(
            services[1]["s"],
            "http://localhost:7037/mediator/v1/authenticate"
        );
        let server = parsed.get("server").expect("[server] section");
        let admin_did = server
            .get("admin_did")
            .and_then(|v| v.as_str())
            .expect("admin_did must be present");
        assert!(
            admin_did.starts_with("did://did:key:"),
            "admin_did must be a did:key (got: {admin_did})"
        );
        let secrets = parsed.get("secrets").expect("[secrets] section");
        let backend = secrets
            .get("backend")
            .and_then(|v| v.as_str())
            .expect("[secrets].backend");
        assert!(
            backend.starts_with("file://"),
            "backend must be the file:// URL (got: {backend})"
        );

        // Phase: provision_secret_backend — unified store contains
        // the JWT secret + operating secrets + admin credential.
        // Verify the file backend was populated rather than asserting
        // exact bytes (the JWT key is randomly generated).
        let unified_path = dir.join("unified-secrets.json");
        assert!(
            unified_path.exists(),
            "unified secret backend file must exist after probe + writes"
        );
        let unified_text = std::fs::read_to_string(&unified_path).unwrap();
        // Parse to verify well-formed JSON; assert on the well-known
        // keys mediator-common defines.
        let unified_json: serde_json::Value =
            serde_json::from_str(&unified_text).expect("unified secrets file must be valid JSON");
        let _ = unified_json; // structural-validity check only
        for well_known in [
            affinidi_messaging_mediator_common::JWT_SECRET,
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
        ] {
            assert!(
                unified_text.contains(well_known),
                "unified secret backend missing well-known key '{well_known}': {unified_text}"
            );
        }

        // No legacy `<config_dir>/secrets.json` array is written anymore:
        // the unified backend is the sole owner of secret persistence
        // (#354). The wizard used to emit an `affinidi_secrets_resolver`
        // array here that clobbered the unified file on the default path.
        let legacy_secrets = dir.join("conf").join("secrets.json");
        assert!(
            !legacy_secrets.exists(),
            "wizard must not write a legacy secrets.json array (#354)"
        );

        // Phase: admin-monitor.json — TDKProfile-shaped JSON for
        // `mediator-console --profile`. Emitted by
        // `write_config_artefacts` whenever the wizard has the admin
        // DID's secret material in memory (i.e., AdminMode::Generate).
        let monitor_profile = dir.join("conf").join("admin-monitor.json");
        assert!(
            monitor_profile.exists(),
            "admin-monitor.json must be written when admin DID is generated locally"
        );
        let monitor_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&monitor_profile).unwrap())
                .expect("admin-monitor.json must be valid JSON");
        let monitor_obj = monitor_json
            .as_object()
            .expect("admin-monitor.json top-level must be an object");
        // Mediator DID in the monitor profile must match what the
        // wizard wrote into mediator.toml — same identity used as the
        // JWT audience.
        let monitor_mediator = monitor_obj
            .get("mediator")
            .and_then(serde_json::Value::as_str)
            .expect("admin-monitor.json `mediator` field");
        // mediator.toml stores the DID with a `did://` URI prefix; the
        // monitor profile is the bare DID since TDKProfile.mediator
        // expects a DID, not a URI. Compare by stripping that prefix.
        let toml_did_bare = mediator_did.trim_start_matches("did://");
        assert_eq!(
            monitor_mediator, toml_did_bare,
            "admin-monitor.json mediator DID must match mediator.toml's mediator_did",
        );
        let monitor_admin = monitor_obj
            .get("did")
            .and_then(serde_json::Value::as_str)
            .expect("admin-monitor.json `did` field");
        let toml_admin_bare = admin_did.trim_start_matches("did://");
        assert_eq!(
            monitor_admin, toml_admin_bare,
            "admin-monitor.json admin DID must match mediator.toml's admin_did",
        );
        let monitor_secrets = monitor_obj
            .get("secrets")
            .and_then(serde_json::Value::as_array)
            .expect("admin-monitor.json `secrets` array");
        assert_eq!(
            monitor_secrets.len(),
            1,
            "Some(AdminMode::Generate) produces exactly one Ed25519 admin secret",
        );

        // Phase: recipe write (save_recipe=true).
        let recipe_path = dir.join("conf").join("mediator-build.toml");
        assert!(
            recipe_path.exists(),
            "build recipe must be saved when save_recipe=true"
        );
        let recipe_text = std::fs::read_to_string(&recipe_path).unwrap();
        let recipe_parsed: toml::Value =
            toml::from_str(&recipe_text).expect("recipe must be valid TOML");
        // Round-trip check: parsing back as a BuildRecipe must
        // succeed, otherwise the auto-write produced something the
        // recipe loader can't consume.
        let _: recipe::BuildRecipe = toml::from_str(&recipe_text)
            .expect("auto-written recipe must round-trip through BuildRecipe deserialize");
        assert_eq!(recipe_parsed["deployment"]["type"].as_str(), Some("local"));
        assert_eq!(
            recipe_parsed["identity"]["did_method"].as_str(),
            Some("did:peer")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_skips_recipe_when_save_recipe_false() {
        // Recipe write is gated by save_recipe — passing `false`
        // (the recipe-driven `--from <recipe>` re-run path) must not
        // overwrite the input recipe with a re-rendered copy.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = did_peer_config(&dir);

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed");

        let recipe_path = dir.join("conf").join("mediator-build.toml");
        assert!(
            !recipe_path.exists(),
            "recipe must NOT be written when save_recipe=false"
        );
        // Mediator.toml still lands — the recipe-skip is independent
        // of the main config write.
        assert!(dir.join("conf").join("mediator.toml").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_file_backend_on_default_path_survives(/* #354 */) {
        // Regression for #354. The default `[secrets].storage` path is
        // `<config_dir>/secrets.json` — the very path the now-removed
        // legacy writer hard-coded. Point the file:// backend there and
        // assert the unified `{"entries": …}` envelope survives instead
        // of being clobbered by a legacy `[{…}]` array.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let conf_dir = dir.join("conf");
        let secrets_path = conf_dir.join("secrets.json");
        let config = app::WizardConfig {
            config_path: conf_dir
                .join("mediator.toml")
                .to_string_lossy()
                .into_owned(),
            deployment_type: Some(Deployment::Local),
            didcomm_enabled: true,
            did_method: Some(DidMethod::Peer),
            secret_storage: Some(SecretScheme::File),
            // Collides with the legacy writer's hard-coded target.
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: Some(SslMode::None),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: Some(AdminMode::Generate),
            ..app::WizardConfig::default()
        };

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed for did:peer file:// backend");

        assert!(
            secrets_path.exists(),
            "the unified backend file must exist at the operator's path"
        );
        let text = std::fs::read_to_string(&secrets_path).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&text).expect("secrets file must be valid JSON");

        // The unified envelope is a JSON object keyed by `entries`; the
        // clobbered legacy form was a top-level array. Asserting the
        // object shape is what would have caught #354.
        assert!(
            json.get("entries").and_then(|e| e.as_object()).is_some(),
            "secrets file must be the unified {{\"entries\": …}} envelope, not a legacy array: {text}"
        );
        for well_known in [
            affinidi_messaging_mediator_common::JWT_SECRET,
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
        ] {
            assert!(
                text.contains(well_known),
                "unified backend missing well-known key '{well_known}' after write: {text}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_admin_skip_omits_admin_did_field() {
        // AdminMode::Skip path: no admin DID generated, no admin
        // credential in the unified backend, and `[server].admin_did`
        // is absent from mediator.toml. Lock down so a refactor
        // doesn't accidentally always-mint an admin DID.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.admin_did_mode = Some(AdminMode::Skip);

        generate_and_write(
            &config,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write with Some(AdminMode::Skip)");

        let toml_text = std::fs::read_to_string(dir.join("conf").join("mediator.toml")).unwrap();
        let parsed: toml::Value = toml::from_str(&toml_text).unwrap();
        let server = parsed.get("server").expect("[server] section");
        assert!(
            server.get("admin_did").is_none(),
            "admin_did must be absent under Some(AdminMode::Skip) — got: {server:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn mint_artefacts_did_peer_returns_value_only_bag_no_io() {
        // The `mint_artefacts` phase is the value-only / IO-free
        // counterpart to `provision_secret_backend` /
        // `write_config_artefacts`. This test runs it inside a
        // CWD-isolated tempdir so a regression that sneaks a file
        // write back in (the prior structure had one in the DidMethod::Vta
        // arm — now deferred to write_config_artefacts) shows up as
        // a stray artefact in the tempdir.
        let cwd = CwdGuard::new();
        let cwd_before: std::collections::BTreeSet<_> = std::fs::read_dir(cwd.dir())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();

        let config = app::WizardConfig {
            did_method: Some(DidMethod::Peer),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: Some(AdminMode::Generate),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None)
            .await
            .expect("did:peer mint must succeed");

        // Value contract: did:peer DID, two operating secrets, JWT
        // present, admin DID present, no VC, no DID log.
        assert!(
            artefacts.mediator_did.starts_with("did:peer:"),
            "got: {}",
            artefacts.mediator_did
        );
        assert_eq!(
            artefacts.mediator_secrets.len(),
            2,
            "did:peer mints signing + KA"
        );
        assert!(artefacts.jwt_secret.is_some());
        assert!(
            artefacts
                .admin_did
                .as_deref()
                .map(|d| d.starts_with("did:key:"))
                .unwrap_or(false)
        );
        assert!(artefacts.admin_secret.is_some());
        assert!(artefacts.did_doc.is_none());
        assert!(artefacts.authorization_vc.is_none());

        // IO contract: nothing new in CWD. If a future regression
        // re-introduces a file write inside mint, this catches it.
        let cwd_after: std::collections::BTreeSet<_> = std::fs::read_dir(cwd.dir())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(
            cwd_before, cwd_after,
            "mint_artefacts must not write any files — phase 1 is value-only"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mint_artefacts_admin_skip_returns_no_admin_did() {
        // Lock down the AdminMode::Skip branch at the unit level — the
        // integration test covers the same path end-to-end, but
        // this one runs in microseconds and surfaces the precise
        // value contract.
        let config = app::WizardConfig {
            did_method: Some(DidMethod::Peer),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: Some(AdminMode::Skip),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None).await.unwrap();
        assert!(artefacts.admin_did.is_none());
        assert!(artefacts.admin_secret.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mint_artefacts_jwt_provide_returns_none_jwt_secret() {
        let config = app::WizardConfig {
            did_method: Some(DidMethod::Peer),
            jwt_mode: JWT_MODE_PROVIDE.into(),
            admin_did_mode: Some(AdminMode::Generate),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None).await.unwrap();
        assert!(
            artefacts.jwt_secret.is_none(),
            "jwt_mode = provide must not mint a key"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_jwt_provide_skips_jwt_secret_in_backend() {
        // jwt_mode = provide: the wizard records the choice and DOES
        // NOT mint or store a JWT secret. The mediator's runtime
        // boot picks it up from MEDIATOR_JWT_SECRET / --jwt-secret-file.
        // Refactor must preserve this — silently always-minting would
        // be a security regression.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.jwt_mode = JWT_MODE_PROVIDE.into();

        generate_and_write(
            &config,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap();

        let unified_text = std::fs::read_to_string(dir.join("unified-secrets.json")).unwrap();
        assert!(
            !unified_text.contains(affinidi_messaging_mediator_common::JWT_SECRET),
            "JWT_SECRET key must be absent under jwt_mode = provide"
        );
        // Operating secrets + admin credential still land — they're
        // independent of jwt_mode.
        assert!(unified_text.contains(affinidi_messaging_mediator_common::OPERATING_SECRETS));
        assert!(unified_text.contains(affinidi_messaging_mediator_common::ADMIN_CREDENTIAL));
    }

    fn admin_only_session() -> vta::VtaSession {
        vta::VtaSession::admin_only(
            "mediator".into(),
            "did:webvh:vta.example.com".into(),
            None,
            None,
            "did:key:z6MkVtaCredential".into(),
            "zVtaCredentialPrivate".into(),
        )
    }

    // ── #154: the re-run guard keys on the backend being written ──────

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn a_second_setup_into_the_same_backend_is_refused() {
        // A different config path used to bypass the guard and silently
        // replace the live mediator's keys.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let first = did_peer_config(&dir);
        generate_and_write(
            &first,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap();
        let before = std::fs::read(dir.join("unified-secrets.json")).unwrap();

        let mut second = did_peer_config(&dir);
        second.config_path = dir
            .join("other")
            .join("mediator.toml")
            .to_string_lossy()
            .into_owned();
        let err = generate_and_write(
            &second,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap_err();
        assert_eq!(exit::code_of(&err), exit::REFUSED_EXISTING, "{err:#}");
        assert!(!dir.join("other").join("mediator.toml").exists());
        assert_eq!(
            std::fs::read(dir.join("unified-secrets.json")).unwrap(),
            before,
            "the refused run must not touch the backend"
        );

        // --force-reprovision proceeds, and the replaced config is backed up.
        let mut options =
            GenerateOptions::for_tests(false, secret_backend::ProvisionProbe::ReadWrite);
        options.force_reprovision = true;
        generate_and_write_with(&first, None, &options)
            .await
            .unwrap()
            .into_result()
            .unwrap();
        let backups: Vec<_> = std::fs::read_dir(dir.join("conf"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("mediator.toml.bak.")
            })
            .collect();
        assert_eq!(
            backups.len(),
            1,
            "one timestamped backup of the replaced config"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn entries_this_run_already_persisted_do_not_trip_the_guard() {
        // The TUI stores a VTA session's credential as soon as it connects;
        // the final pass must recognise those entries as its own.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = did_peer_config(&dir);
        let session = admin_only_session();
        let url = config_writer::build_backend_url(&config);
        let store = secret_backend::open_secret_backend(&url).unwrap();
        secret_backend::store_vta_session(&store, &session)
            .await
            .unwrap();
        generate_and_write(
            &config,
            Some(&session),
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap();
    }

    // ── #173: the admin choice is honoured with a VTA session ─────────

    #[tokio::test]
    async fn generated_admin_is_separate_from_the_vta_credential() {
        let dir = tempfile::tempdir().unwrap();
        let session = admin_only_session();
        let mut config = did_peer_config(dir.path());

        config.admin_did_mode = Some(AdminMode::Generate);
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        let admin = a.admin_did.unwrap();
        assert!(admin.starts_with("did:key:"));
        assert_ne!(admin, session.admin_did());
        assert!(a.admin_secret.is_some());

        config.admin_did_mode = Some(AdminMode::Vta);
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        assert_eq!(a.admin_did.as_deref(), Some(session.admin_did()));
        assert!(a.admin_secret.is_none());

        config.admin_did_mode = Some(AdminMode::Paste);
        config.admin_did = "did:web:admin.example.com".into();
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        assert_eq!(a.admin_did.as_deref(), Some("did:web:admin.example.com"));
        assert!(a.admin_secret.is_none());

        config.admin_did = String::new();
        let err = mint_artefacts(&config, Some(&session)).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::IMPORT_WITHOUT_DATA);

        config.admin_did_mode = Some(AdminMode::Vta);
        let err = mint_artefacts(&config, None).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::NO_VTA_SESSION);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn vta_flow_with_generated_admin_writes_the_separate_admin() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.use_vta = true;
        config.vta_mode = Some(VtaMode::Online);
        let session = admin_only_session();
        generate_and_write(
            &config,
            Some(&session),
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap();

        // The backend's admin credential is the VTA credential…
        let store = secret_backend::open_secret_backend(&config_writer::build_backend_url(&config))
            .unwrap();
        let cred = store.load_admin_credential().await.unwrap().unwrap();
        assert_eq!(cred.did, session.admin_did());
        // …while mediator.toml's admin_did is the generated one, whose key
        // is in admin-monitor.json.
        let toml = std::fs::read_to_string(dir.join("conf").join("mediator.toml")).unwrap();
        assert!(!toml.contains(session.admin_did()), "{toml}");
        assert!(dir.join("conf").join("admin-monitor.json").exists());
    }

    // ── #166: no placeholder DIDs ─────────────────────────────────────

    #[tokio::test]
    async fn vta_did_without_a_session_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = did_peer_config(dir.path());
        config.did_method = Some(DidMethod::Vta);
        let err = mint_artefacts(&config, None).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::NO_VTA_SESSION);

        config.did_method = None;
        let err = mint_artefacts(&config, None).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::IMPORT_WITHOUT_DATA);
    }

    // ── #150 / #176 / #185: did:webvh artefacts, paths, manifest ──────

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn webvh_setup_stores_update_keys_and_points_at_the_written_log() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.did_method = Some(DidMethod::Webvh);
        config.public_url = "https://localhost:7037".into();
        generate_and_write(
            &config,
            None,
            true,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap();

        // The update + pre-rotation keys are in their own backend entry.
        let store = secret_backend::open_secret_backend(&config_writer::build_backend_url(&config))
            .unwrap();
        let keys: generators::did_webvh::WebvhUpdateKeys = store
            .load_entry(WEBVH_UPDATE_KEYS, KIND_WEBVH_UPDATE_KEYS)
            .await
            .unwrap()
            .expect("update keys stored");
        let log = std::fs::read_to_string(dir.join("conf").join("did.jsonl")).unwrap();
        assert!(log.contains(&keys.update_key.get_public_keymultibase().unwrap()));

        // did_web_self_hosted names the file actually written, absolutely.
        let toml = std::fs::read_to_string(dir.join("conf").join("mediator.toml")).unwrap();
        let expected = format!("file://{}", dir.join("conf").join("did.jsonl").display());
        assert!(
            toml.contains(&format!("did_web_self_hosted = \"{expected}\"")),
            "{toml}"
        );

        // The manifest lists what uninstall must remove.
        let manifest =
            std::fs::read_to_string(dir.join("conf").join(reprovision::MANIFEST_FILE)).unwrap();
        for name in [
            "mediator.toml",
            "did.jsonl",
            "admin-monitor.json",
            "mediator-build.toml",
        ] {
            assert!(manifest.contains(name), "{name} missing from {manifest}");
        }
        assert!(manifest.contains("unified-secrets.json"));
    }

    // ── #162: ordering and partial failure ────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn a_failed_did_log_write_is_fatal_and_leaves_no_config() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.did_method = Some(DidMethod::Webvh);
        config.public_url = "https://localhost:7037".into();
        // A directory where did.jsonl should go makes its write fail.
        std::fs::create_dir_all(dir.join("conf").join("did.jsonl")).unwrap();
        let err = generate_and_write(
            &config,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("did.jsonl"), "{err:#}");
        assert!(
            !dir.join("conf").join("mediator.toml").exists(),
            "no config may reference a DID log that was not written"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn a_publish_failure_reports_a_complete_setup_with_its_exit_code() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        // The target's parent is a file, so publishing cannot create it.
        std::fs::write(dir.join("blocker"), "").unwrap();
        config.did_target = Some(format!(
            "file://{}",
            dir.join("blocker").join("did.txt").display()
        ));
        let err = generate_and_write(
            &config,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .unwrap_err();
        assert_eq!(exit::code_of(&err), exit::PUBLISH_FAILED);
        assert!(err.to_string().contains("Setup complete"), "{err}");
        // Everything local was written first.
        assert!(dir.join("conf").join("mediator.toml").exists());
    }
}
