use super::config::MEDIATOR_DEFAULT_FEATURES;
use super::*;
use crate::app::{AdminMode, Deployment, DidMethod, SecretScheme, SslMode, VtaMode};
use crate::consts::*;
use crate::vta::{ConnectPhase, VtaIntent, VtaSession};

// ── Fjall data-directory validation ────────────────────────────────

#[test]
fn validate_fjall_rejects_empty() {
    assert!(validate_fjall_data_dir("").is_err());
    assert!(validate_fjall_data_dir("   ").is_err());
}

#[test]
fn validate_fjall_accepts_existing_directory() {
    // Reads the CWD, which other tests change; see `crate::cwd_lock`.
    let _cwd = crate::cwd_lock();
    // The repo root is guaranteed to exist on every CI runner.
    let cwd = std::env::current_dir().unwrap();
    validate_fjall_data_dir(cwd.to_str().unwrap()).expect("CWD is a directory");
}

#[test]
fn validate_fjall_rejects_existing_non_directory() {
    // Reads the CWD, which other tests change; see `crate::cwd_lock`.
    let _cwd = crate::cwd_lock();
    // Cargo.toml is always a regular file relative to the package root.
    let err = validate_fjall_data_dir("Cargo.toml")
        .expect_err("validation must reject paths that exist but aren't directories");
    assert!(err.contains("not a directory"));
}

#[test]
fn validate_fjall_accepts_missing_leaf_with_existing_parent() {
    let mut path = std::env::temp_dir();
    path.push("affinidi-mediator-fjall-validate-test-leaf-42");
    // Best-effort cleanup so reruns work; ignore failure.
    let _ = std::fs::remove_dir_all(&path);
    validate_fjall_data_dir(path.to_str().unwrap())
        .expect("missing leaf under an existing temp dir is acceptable");
}

#[test]
fn validate_fjall_accepts_missing_parent() {
    // Regression: previously rejected `./data/mediator` (the wizard's
    // default) when `./data` didn't yet exist. Fjall calls
    // `std::fs::create_dir_all` on the configured path, so a missing
    // parent is fine — the wizard must not block the default.
    validate_fjall_data_dir("/a-directory-that-does-not-exist-on-this-host-42/mediator")
        .expect("missing parent must be allowed — fjall create_dir_all handles it");
}

#[test]
fn validate_fjall_accepts_bare_relative_leaf() {
    // A bare relative leaf resolves under the mediator's CWD at
    // runtime; the wizard can't introspect that, so it defers.
    validate_fjall_data_dir("mediator-data-leaf-only").expect("bare leaf must validate");
}

#[test]
fn validate_fjall_accepts_default_path() {
    // The wizard pre-fills `./data/mediator`. Fresh installs likely
    // don't have `./data` either; the validator must not reject the
    // default and trap the operator on the screen.
    validate_fjall_data_dir(crate::consts::DEFAULT_FJALL_DATA_DIR)
        .expect("wizard default must always validate");
}

// ── WizardStep navigation ──────────────────────────────────────────

#[test]
fn step_all_returns_10_steps_in_order() {
    // Output was inserted before Summary in the "move config-path
    // into the TUI" refactor, bumping the step count from 9 → 10.
    let steps = WizardStep::all();
    assert_eq!(steps.len(), 10);
    assert_eq!(steps[0], WizardStep::Deployment);
    assert_eq!(steps[1], WizardStep::KeyStorage);
    assert_eq!(steps[2], WizardStep::Vta);
    assert_eq!(steps[8], WizardStep::Output);
    assert_eq!(steps[9], WizardStep::Summary);
}

#[test]
fn step_index_matches_position() {
    for (i, step) in WizardStep::all().iter().enumerate() {
        assert_eq!(step.index(), i);
        assert_eq!(step.step_number(), i + 1);
    }
}

#[test]
fn step_total_matches_all_len() {
    assert_eq!(WizardStep::total(), WizardStep::all().len());
}

#[test]
fn first_step_has_no_prev() {
    assert_eq!(WizardStep::Deployment.prev(), None);
}

#[test]
fn last_step_has_no_next() {
    assert_eq!(WizardStep::Summary.next(), None);
}

#[test]
fn next_prev_are_inverses() {
    let steps = WizardStep::all();
    for i in 0..steps.len() - 1 {
        let next = steps[i].next().unwrap();
        assert_eq!(next, steps[i + 1]);
        assert_eq!(next.prev().unwrap(), steps[i]);
    }
}

// ── WizardConfig ───────────────────────────────────────────────────

#[test]
fn protocol_display_combinations() {
    // Build the test config via struct-update so the initial
    // `didcomm_enabled / tsp_enabled` pair is set in one go;
    // subsequent assertions then mutate just the fields under test.
    let mut cfg = WizardConfig {
        didcomm_enabled: true,
        tsp_enabled: false,
        ..WizardConfig::default()
    };
    assert_eq!(cfg.protocol_display(), "DIDComm v2");

    cfg.tsp_enabled = true;
    assert_eq!(cfg.protocol_display(), "DIDComm v2 + TSP");

    cfg.didcomm_enabled = false;
    assert_eq!(cfg.protocol_display(), "TSP");

    cfg.tsp_enabled = false;
    assert_eq!(cfg.protocol_display(), "None (invalid)");
}

#[test]
fn default_config_has_sensible_values() {
    let cfg = WizardConfig::default();
    assert!(cfg.didcomm_enabled);
    assert!(cfg.tsp_enabled, "TSP is on by default");
    assert_eq!(cfg.config_path, DEFAULT_CONFIG_PATH);
    assert_eq!(cfg.database_url, DEFAULT_REDIS_URL);
    assert_eq!(cfg.listen_address, DEFAULT_LISTEN_ADDR);
}

#[test]
fn cargo_features_default_matches_crate_defaults() {
    // Default WizardConfig with no secret backend chosen yet
    // should still emit a valid feature set, and
    // needs_explicit_features must return false so the wizard
    // doesn't pass `--no-default-features` for the trivial case.
    let cfg = WizardConfig::default();
    assert_eq!(
        cfg.cargo_features(),
        vec!["didcomm", "tsp", "redis-backend", "jemalloc", "vta"]
    );
    assert!(!cfg.needs_explicit_features());
}

/// [`MEDIATOR_DEFAULT_FEATURES`] is a copy of the mediator's own
/// `default`, and the wizard's `--no-default-features` decision is only
/// as right as the copy. It had drifted: the copy said
/// `["didcomm", "redis-backend"]` while the crate also defaulted `jemalloc`
/// and `vta`, so every explicit build the wizard rendered dropped both.
#[test]
fn mediator_default_features_match_the_mediator_crate() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../../../../Cargo.toml")).expect("mediator Cargo.toml");
    let mut actual: Vec<&str> = manifest["features"]["default"]
        .as_array()
        .expect("a default feature list")
        .iter()
        .map(|v| v.as_str().expect("feature names are strings"))
        .collect();
    let mut expected = MEDIATOR_DEFAULT_FEATURES.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

/// Every explicit feature list the wizard renders keeps `vta`: without it
/// the mediator silently skips the VTA integration a VTA-linked config
/// relies on.
#[test]
fn explicit_feature_lists_keep_vta_and_jemalloc() {
    for cfg in [
        WizardConfig {
            storage_backend: "fjall".into(),
            ..Default::default()
        },
        WizardConfig {
            secret_storage: Some(SecretScheme::Aws),
            ..Default::default()
        },
        WizardConfig {
            tsp_enabled: false,
            ..Default::default()
        },
    ] {
        assert!(cfg.needs_explicit_features());
        let f = cfg.cargo_features();
        assert!(f.contains(&"vta") && f.contains(&"jemalloc"), "{f:?}");
    }
}

#[test]
fn cargo_features_fjall_backend_emits_fjall_feature() {
    // Regression: docker.rs's old `build_features` never added a
    // storage backend feature, so a Fjall wizard run produced a
    // Dockerfile that built the mediator without `fjall-backend`
    // (and without `redis-backend` either, when paired with any
    // secret-storage feature that triggered `--no-default-features`).
    let cfg = WizardConfig {
        storage_backend: "fjall".into(),
        ..Default::default()
    };
    assert_eq!(
        cfg.cargo_features(),
        vec!["didcomm", "tsp", "fjall-backend", "jemalloc", "vta"]
    );
    assert!(cfg.needs_explicit_features());
}

#[test]
fn cargo_features_redis_with_secret_backend_keeps_redis() {
    // The original bug: `redis-backend` was a default feature, so
    // when any non-default secret backend was chosen the wizard
    // emitted `--no-default-features --features didcomm,secrets-aws`
    // and the resulting binary had NO storage backend at all. The
    // fix re-asserts `redis-backend` explicitly when secrets-X is
    // set, so the binary still has its backend.
    let cfg = WizardConfig {
        secret_storage: Some(SecretScheme::Aws),
        ..Default::default()
    };
    assert_eq!(
        cfg.cargo_features(),
        vec![
            "didcomm",
            "tsp",
            "redis-backend",
            "jemalloc",
            "vta",
            "secrets-aws"
        ]
    );
    assert!(cfg.needs_explicit_features());
}

#[test]
fn cargo_features_fjall_with_secret_backend_uses_fjall() {
    let cfg = WizardConfig {
        storage_backend: "fjall".into(),
        secret_storage: Some(SecretScheme::Vault),
        ..Default::default()
    };
    assert_eq!(
        cfg.cargo_features(),
        vec![
            "didcomm",
            "tsp",
            "fjall-backend",
            "jemalloc",
            "vta",
            "secrets-vault"
        ]
    );
    assert!(cfg.needs_explicit_features());
}

#[test]
fn cargo_features_unknown_backend_falls_back_to_redis() {
    // Defensive: a malformed recipe with an unrecognised backend
    // string shouldn't produce a binary with no storage at all.
    // Default to redis-backend so the mediator at least starts.
    let cfg = WizardConfig {
        storage_backend: "totally-not-a-real-backend".into(),
        ..Default::default()
    };
    assert!(cfg.cargo_features().contains(&"redis-backend"));
}

#[test]
fn cargo_features_didcomm_only_leaves_tsp_out() {
    let cfg = WizardConfig {
        tsp_enabled: false,
        ..Default::default()
    };
    assert_eq!(
        cfg.cargo_features(),
        vec!["didcomm", "redis-backend", "jemalloc", "vta"]
    );
    assert!(cfg.needs_explicit_features());
}

// ── WizardApp state machine ────────────────────────────────────────

#[test]
fn new_app_starts_at_deployment() {
    let app = WizardApp::new(DEFAULT_CONFIG_PATH.into());
    assert_eq!(app.current_step, WizardStep::Deployment);
    assert_eq!(app.mode, InputMode::Selecting);
    assert_eq!(app.focus, FocusPanel::Content);
    assert!(!app.should_quit);
    assert!(!app.write_config);
}

#[test]
fn advance_moves_to_next_step() {
    let mut app = WizardApp::new("test.toml".into());
    assert_eq!(app.current_step, WizardStep::Deployment);
    app.advance();
    assert_eq!(app.current_step, WizardStep::KeyStorage);
    assert!(app.completed_steps().contains(&WizardStep::Deployment));
}

#[test]
fn advance_sets_text_input_for_database_and_output() {
    let mut app = WizardApp::new("test.toml".into());
    while app.current_step != WizardStep::Admin {
        app.advance();
    }
    // Admin → Output (new text-input step for config path)
    app.advance();
    assert_eq!(app.current_step, WizardStep::Output);
    assert_eq!(app.mode, InputMode::TextInput);
    // Output → Summary (confirmation screen)
    app.advance();
    assert_eq!(app.current_step, WizardStep::Summary);
    assert_eq!(app.mode, InputMode::Confirming);
}

/// Helper: walk forward to the Database step from a fresh wizard.
/// Mirrors the steps a real operator goes through, picking
/// defaults at each prior selection step.
fn advance_to_database_step(app: &mut WizardApp) {
    while app.current_step != WizardStep::Database {
        app.advance();
    }
}

#[test]
fn database_step_starts_on_backend_picker() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    assert_eq!(app.current_step, WizardStep::Database);
    assert_eq!(app.mode, InputMode::Selecting);
    assert_eq!(
        app.database_phase,
        Some(DatabasePhase::SelectBackend),
        "Database step must open on the backend picker"
    );
    // Both options must be present; the help text differs by
    // which one is highlighted.
    let opts = app.current_options();
    assert_eq!(opts.len(), 2);
}

#[test]
fn database_step_redis_choice_transitions_to_url_input() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);

    // Redis is at index 0.
    app.selection_index = 0;
    app.select_current();

    assert_eq!(app.config.storage_backend, "redis");
    assert_eq!(app.database_phase, None, "phase clears after pick");
    assert_eq!(app.mode, InputMode::TextInput);
    // Text input pre-filled with the existing URL value.
    assert_eq!(app.text_input.value(), DEFAULT_REDIS_URL);
}

#[test]
fn database_step_fjall_choice_transitions_to_path_input() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);

    // Fjall is at index 1.
    app.selection_index = 1;
    app.select_current();

    assert_eq!(app.config.storage_backend, "fjall");
    assert_eq!(app.database_phase, None);
    assert_eq!(app.mode, InputMode::TextInput);
    // Text input pre-filled with the Fjall path default rather
    // than the Redis URL — that's the load-bearing assertion: a
    // typo here would store the Redis URL into `fjall_data_dir`
    // (or vice versa) on the next confirm.
    assert_eq!(app.text_input.value(), "./data/mediator");
}

#[test]
fn database_step_esc_from_text_input_returns_to_picker() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);

    app.selection_index = 1; // Fjall
    app.select_current();
    assert_eq!(app.mode, InputMode::TextInput);

    // Esc rewinds to the picker rather than leaving the step.
    app.go_back();
    assert_eq!(app.current_step, WizardStep::Database);
    assert_eq!(app.mode, InputMode::Selecting);
    assert_eq!(app.database_phase, Some(DatabasePhase::SelectBackend));
    // Selection_index should reflect the previously chosen backend
    // so the operator returns to the same highlighted option.
    assert_eq!(app.selection_index, 1);
}

#[test]
fn database_step_text_input_writes_correct_field_per_backend() {
    // Reads the CWD, which other tests change; see `crate::cwd_lock`.
    let _cwd = crate::cwd_lock();
    // Redis path — operator types a URL.
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 0;
    app.select_current();
    app.text_input = tui_input::Input::new("redis://prod-host:6379/2".into());
    app.confirm_text_input();
    assert_eq!(app.config.storage_backend, "redis");
    assert_eq!(app.config.database_url, "redis://prod-host:6379/2");
    assert_eq!(
        app.config.fjall_data_dir, "./data/mediator",
        "Fjall path must remain at default when Redis was picked"
    );

    // Fjall path — operator types an EXISTING directory so the
    // wizard skips the create-dir confirm and advances straight
    // through. The CWD always exists on every CI runner.
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 1;
    app.select_current();
    let cwd = std::env::current_dir().unwrap();
    let cwd_str = cwd.to_str().unwrap().to_string();
    app.text_input = tui_input::Input::new(cwd_str.clone());
    app.confirm_text_input();
    assert_eq!(app.config.storage_backend, "fjall");
    assert_eq!(app.config.fjall_data_dir, cwd_str);
    // Existing path → no create-dir confirm phase.
    assert_eq!(app.database_phase, None);
    assert_eq!(
        app.config.database_url, DEFAULT_REDIS_URL,
        "Redis URL must remain at default when Fjall was picked"
    );
}

#[test]
fn database_fjall_missing_path_routes_to_create_confirm() {
    // Confirming the text input on a path that doesn't exist must
    // NOT silently advance — it routes into ConfirmCreateFjallDir
    // so the operator gets to choose whether to create now.
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 1; // Fjall
    app.select_current();
    let mut path = std::env::temp_dir();
    path.push("affinidi-mediator-create-confirm-test-leaf-1");
    let _ = std::fs::remove_dir_all(&path);
    app.text_input = tui_input::Input::new(path.to_str().unwrap().into());
    app.confirm_text_input();
    assert_eq!(app.current_step, WizardStep::Database);
    assert_eq!(
        app.database_phase,
        Some(DatabasePhase::ConfirmCreateFjallDir)
    );
    assert_eq!(app.mode, InputMode::Selecting);
    assert_eq!(app.selection_index, 0, "Yes is the default option");
}

#[test]
fn database_fjall_create_confirm_yes_creates_and_advances() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 1;
    app.select_current();
    let mut path = std::env::temp_dir();
    path.push("affinidi-mediator-create-confirm-test-leaf-2");
    let _ = std::fs::remove_dir_all(&path);
    app.text_input = tui_input::Input::new(path.to_str().unwrap().into());
    app.confirm_text_input();
    assert_eq!(
        app.database_phase,
        Some(DatabasePhase::ConfirmCreateFjallDir)
    );

    // Confirm Yes — wizard runs `create_dir_all` and advances.
    app.selection_index = 0;
    app.select_current();
    assert!(path.exists(), "directory must be created on confirm");
    assert!(path.is_dir());
    assert_eq!(app.database_phase, None);
    assert!(app.current_step != WizardStep::Database);
    // Cleanup.
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn database_fjall_create_confirm_no_returns_to_text_input() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 1;
    app.select_current();
    let mut path = std::env::temp_dir();
    path.push("affinidi-mediator-create-confirm-test-leaf-3");
    let _ = std::fs::remove_dir_all(&path);
    app.text_input = tui_input::Input::new(path.to_str().unwrap().into());
    app.confirm_text_input();

    // Confirm No — wizard does NOT create the directory and routes
    // back to the text-input phase so the operator can retype.
    app.selection_index = 1;
    app.select_current();
    assert!(
        !path.exists(),
        "directory must NOT be created when No is picked"
    );
    assert_eq!(app.database_phase, None);
    assert_eq!(app.mode, InputMode::TextInput);
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn database_fjall_create_confirm_esc_returns_to_text_input() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to_database_step(&mut app);
    app.selection_index = 1;
    app.select_current();
    let mut path = std::env::temp_dir();
    path.push("affinidi-mediator-create-confirm-test-leaf-4");
    let _ = std::fs::remove_dir_all(&path);
    app.text_input = tui_input::Input::new(path.to_str().unwrap().into());
    app.confirm_text_input();
    assert_eq!(
        app.database_phase,
        Some(DatabasePhase::ConfirmCreateFjallDir)
    );

    // Esc cancels the prompt — same effect as picking No.
    app.go_back();
    assert!(!path.exists());
    assert_eq!(app.database_phase, None);
    assert_eq!(app.mode, InputMode::TextInput);
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn go_back_from_first_step_quits() {
    let mut app = WizardApp::new("test.toml".into());
    app.go_back();
    assert!(app.should_quit);
}

#[test]
fn go_back_returns_to_previous_step() {
    let mut app = WizardApp::new("test.toml".into());
    app.advance(); // Deployment → KeyStorage
    app.advance(); // KeyStorage → Vta
    app.advance(); // Vta → Protocol
    assert_eq!(app.current_step, WizardStep::Protocol);
    app.go_back();
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn local_webvh_url_confirm_enters_did_web_choice() {
    // Non-VTA did:webvh path: after the public URL is confirmed the
    // wizard offers the did:web export as a Yes/No sub-phase instead
    // of advancing straight on.
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Did;
    app.mode = InputMode::Selecting;
    app.selection_index = 0; // "Generate did:webvh"
    app.select_current();
    assert_eq!(app.config.did_method, Some(DidMethod::Webvh));
    assert_eq!(app.mode, InputMode::TextInput);

    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    // The identity-form pick comes first; keep the did:webvh default.
    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    app.select_current();
    assert!(!app.config.present_as_scid);

    assert_eq!(app.did_phase, Some(DidPhase::SaveDidWebChoice));
    assert_eq!(app.mode, InputMode::Selecting);
    assert_eq!(app.current_options().len(), 2);
    // Opt-in: the prompt defaults to the recommended "No" (index 0).
    assert_eq!(app.selection_index, 0);
    assert_eq!(app.config.public_url, "https://mediator.example.com");
}

#[test]
fn did_web_choice_yes_sets_flag_and_advances_past_did() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Did;
    app.mode = InputMode::Selecting;
    app.selection_index = 0;
    app.select_current();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    // The identity-form pick comes first; keep the did:webvh default.
    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    app.select_current();
    assert!(!app.config.present_as_scid);

    // Pick "Yes" (index 1; index 0 is the recommended "No").
    app.selection_index = 1;
    app.select_current();
    assert!(app.config.save_did_web);
    assert!(app.did_phase.is_none());
    assert_ne!(app.current_step, WizardStep::Did);
}

#[test]
fn did_web_choice_no_leaves_flag_unset() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Did;
    app.mode = InputMode::Selecting;
    app.selection_index = 0;
    app.select_current();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    // The identity-form pick comes first; keep the did:webvh default.
    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    app.select_current();
    assert!(!app.config.present_as_scid);

    // Pick "No" (the default highlight).
    app.select_current();
    assert!(!app.config.save_did_web);
    assert!(app.did_phase.is_none());
}

#[test]
fn did_web_choice_back_nav_returns_to_url_input() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Did;
    app.mode = InputMode::Selecting;
    app.selection_index = 0;
    app.select_current();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    // The identity-form pick comes first; keep the did:webvh default.
    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    app.select_current();
    assert!(!app.config.present_as_scid);
    assert_eq!(app.did_phase, Some(DidPhase::SaveDidWebChoice));

    // Back to the identity-form pick, then to the URL.
    app.go_back();
    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    app.go_back();
    assert!(app.did_phase.is_none());
    assert_eq!(app.mode, InputMode::TextInput);
    assert_eq!(app.current_step, WizardStep::Did);
    assert_eq!(app.text_input.value(), "https://mediator.example.com");
}

#[test]
fn identity_form_choice_scid_presents_as_did_scid() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.config.scid_also_known_as = false;
    app.current_step = WizardStep::Did;
    app.mode = InputMode::Selecting;
    app.selection_index = 0;
    app.select_current();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();

    assert_eq!(app.did_phase, Some(DidPhase::IdentityFormChoice));
    assert_eq!(app.current_options().len(), 2);
    // did:webvh is the highlighted default.
    assert_eq!(app.selection_index, 0);
    app.selection_index = 1;
    app.select_current();

    assert!(app.config.present_as_scid);
    // did:scid needs its alias in the log, whatever was set before.
    assert!(app.config.scid_also_known_as);
    assert_eq!(app.did_phase, Some(DidPhase::SaveDidWebChoice));
}

#[test]
fn go_back_from_summary_confirming_returns_to_output() {
    // Output now sits between Admin and Summary (config-path
    // prompt moved into the TUI), so Esc on the confirmation
    // screen lands there rather than at Admin.
    let mut app = WizardApp::new("test.toml".into());
    while app.current_step != WizardStep::Summary {
        app.advance();
    }
    assert_eq!(app.mode, InputMode::Confirming);
    app.go_back();
    assert_eq!(app.current_step, WizardStep::Output);
    assert_eq!(app.mode, InputMode::TextInput);
}

#[test]
fn paste_text_inserts_at_cursor_in_text_input_mode() {
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::TextInput;
    app.text_input = tui_input::Input::new("did:webvh:".into());
    // Place cursor at end.
    app.text_input = tui_input::Input::new("did:webvh:".into()).with_cursor(10);
    app.paste_text("vta.example.com");
    assert_eq!(app.text_input.value(), "did:webvh:vta.example.com");
    assert_eq!(app.text_input.cursor(), 25);
}

#[test]
fn paste_text_strips_newlines_and_tabs() {
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::TextInput;
    app.text_input = tui_input::Input::new(String::new());
    app.paste_text("did:webvh:vta.example.com\n");
    assert_eq!(app.text_input.value(), "did:webvh:vta.example.com");

    app.text_input = tui_input::Input::new(String::new());
    app.paste_text("did:web\tvh:\r\nexample.com");
    assert_eq!(app.text_input.value(), "did:webvh:example.com");
}

#[test]
fn paste_text_preserves_newlines_on_awaiting_bundle() {
    // Sealed-handoff armor requires newlines between its BEGIN/END
    // markers; the default single-line-collapse behaviour would
    // break `armor::decode`. Must preserve \n and \r when the
    // sealed-handoff state is on AwaitingBundle.
    use crate::sealed_handoff::{SealedHandoffState, SealedPhase};
    use crate::vta::VtaIntent;
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::TextInput;
    let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None);
    state.phase = SealedPhase::AwaitingBundle;
    app.sealed_handoff = Some(state);
    app.text_input = tui_input::Input::new(String::new());
    app.paste_text(
        "-----BEGIN VTA SEALED BUNDLE-----\nBundle-Id: abc\n-----END VTA SEALED BUNDLE-----\n",
    );
    assert!(app.text_input.value().contains('\n'));
    assert!(app.text_input.value().contains("-----BEGIN"));
    assert!(app.text_input.value().contains("-----END"));
}

#[test]
fn paste_text_still_strips_newlines_outside_awaiting_bundle() {
    // Other sealed-handoff phases (CollectContext, CollectMediatorUrl,
    // etc.) are single-line prompts — paste must still collapse.
    use crate::sealed_handoff::{SealedHandoffState, SealedPhase};
    use crate::vta::VtaIntent;
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::TextInput;
    let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None);
    state.phase = SealedPhase::CollectContext;
    app.sealed_handoff = Some(state);
    app.text_input = tui_input::Input::new(String::new());
    app.paste_text("mediator-local\nextra");
    assert_eq!(app.text_input.value(), "mediator-localextra");
}

#[test]
fn paste_text_ignored_outside_text_input_mode() {
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::Selecting;
    app.paste_text("did:webvh:vta.example.com");
    assert_eq!(app.text_input.value(), "");
}

#[test]
fn move_up_down_bounds() {
    let mut app = WizardApp::new("test.toml".into());
    app.selection_index = 0;
    app.move_up();
    assert_eq!(app.selection_index, 0); // stays at 0

    let max = app.current_options().len() - 1;
    app.selection_index = max;
    app.move_down();
    assert_eq!(app.selection_index, max); // stays at max
}

#[test]
fn protocol_toggle_prevents_deselecting_both() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.deployment_type = Some(Deployment::Local);
    advance_to(&mut app, WizardStep::Protocol);
    assert!(app.current_step.is_multi_select());

    // Both are selected by default; turn TSP off so DIDComm is the only
    // one left.
    assert!(app.config.didcomm_enabled);
    assert!(app.config.tsp_enabled);
    app.selection_index = 1;
    app.toggle_current_multi_select();
    assert!(!app.config.tsp_enabled);

    // Space toggles the highlighted option — try to turn DIDComm off when
    // it's the only one enabled. The state machine must revert so at
    // least one protocol stays selected.
    app.selection_index = 0;
    app.toggle_current_multi_select();
    assert!(
        app.config.didcomm_enabled,
        "DIDComm must stay on when it's the only protocol enabled"
    );
}

#[test]
fn protocol_multi_select_space_toggle_plus_enter_advance() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.deployment_type = Some(Deployment::Local);
    advance_to(&mut app, WizardStep::Protocol);

    // TSP is on by default; Space turns it off and on again.
    app.selection_index = 1;
    app.toggle_current_multi_select();
    assert!(app.config.didcomm_enabled);
    assert!(!app.config.tsp_enabled);
    app.toggle_current_multi_select();
    assert!(app.config.tsp_enabled);

    // Enter advances — no more "Continue >" pseudo-row.
    app.select_current();
    assert_eq!(app.current_step, WizardStep::Did);
}

#[test]
fn protocol_options_are_two_checkboxes_no_continue_row() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Protocol;
    let opts = app.current_options();
    assert_eq!(
        opts.len(),
        2,
        "Protocol step should only list the two protocol toggles"
    );
}

#[test]
fn deployment_defaults_set_correctly() {
    let mut app = WizardApp::new("test.toml".into());

    // Select "Local development"
    app.selection_index = 0;
    app.select_current();

    assert_eq!(app.config.deployment_type, Some(Deployment::Local));
    assert!(app.config.use_vta);
    assert!(app.config.didcomm_enabled);
    assert_eq!(app.config.ssl_mode, Some(SslMode::None));
    assert_eq!(app.config.database_url, DEFAULT_REDIS_URL);
}

#[test]
fn summary_enter_sets_write_config() {
    let mut app = WizardApp::new("test.toml".into());
    while app.current_step != WizardStep::Summary {
        app.advance();
    }
    assert_eq!(app.mode, InputMode::Confirming);
    app.select_current();
    assert!(app.write_config);
    assert!(app.should_quit);
}

#[test]
fn focus_progress_syncs_index() {
    let mut app = WizardApp::new("test.toml".into());
    app.advance(); // → KeyStorage
    app.advance(); // → Vta
    app.advance(); // → Protocol
    app.advance(); // → Did
    app.focus_progress();
    assert_eq!(app.focus, FocusPanel::Progress);
    assert_eq!(app.progress_index, WizardStep::Did.index());
}

#[test]
fn focus_progress_blocked_during_text_input() {
    let mut app = WizardApp::new("test.toml".into());
    app.mode = InputMode::TextInput;
    app.focus_progress();
    assert_eq!(app.focus, FocusPanel::Content); // didn't switch
}

#[test]
fn jump_to_completed_step() {
    let mut app = WizardApp::new("test.toml".into());
    app.advance(); // → KeyStorage
    app.advance(); // → Vta
    app.advance(); // → Protocol
    app.advance(); // → Did
    app.focus_progress();
    app.progress_index = 0; // Deployment
    app.jump_to_progress_step();
    assert_eq!(app.current_step, WizardStep::Deployment);
}

#[test]
fn jump_to_incomplete_step_does_nothing() {
    let mut app = WizardApp::new("test.toml".into());
    app.advance(); // → KeyStorage
    app.focus_progress();
    app.progress_index = WizardStep::Database.index();
    let before = app.current_step;
    app.jump_to_progress_step();
    assert_eq!(app.current_step, before); // unchanged
}

// ── KeyStorage sub-flow tests ─────────────────────────────────────

#[test]
fn keystorage_file_backend_walks_gate_then_path_then_encrypt_choice() {
    // Phase H added an encrypt/no-encrypt step after the path
    // prompt. The wizard no longer auto-advances to Vta after
    // confirming the path — the operator must answer the
    // encryption question first.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    // "Local file (file://)" lives at index 5 after vta:// and
    // string:// were dropped from the selection list.
    app.selection_index = 6; // file:// (k8s inserted at 5)
    app.select_current();
    assert_eq!(app.config.secret_storage, Some(SecretScheme::File));
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));
    assert_eq!(app.mode, InputMode::TextInput);

    // Type the gate phrase (case-insensitive) — advances to FilePath.
    app.text_input = Input::new(FILE_GATE_PHRASE.to_lowercase());
    app.confirm_text_input();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FilePath));

    // Accept the default path — moves into the encrypt choice.
    app.confirm_text_input();
    assert_eq!(app.config.secret_file_path, DEFAULT_SECRET_FILE_PATH);
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FileEncryptChoice)
    );
    assert_eq!(app.mode, InputMode::Selecting);

    // Pick "no encryption" (index 1) — finishes the sub-flow.
    app.selection_index = 1;
    app.select_current();
    assert!(!app.in_key_storage_subflow());
    assert!(!app.config.secret_file_encrypted);
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn keystorage_file_backend_encrypt_yes_collects_passphrase() {
    // Picking "encrypt" advances to the passphrase prompt, which
    // rejects empty input and keeps the value on confirm.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 6; // file:// (k8s inserted at 5)
    app.select_current();
    // Walk through the gate + path with defaults.
    app.text_input = Input::new(FILE_GATE_PHRASE.into());
    app.confirm_text_input();
    app.confirm_text_input(); // accept default path
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FileEncryptChoice)
    );

    // Encrypt = yes (index 0).
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FilePassphrase));
    assert_eq!(app.mode, InputMode::TextInput);

    // Empty passphrase is rejected — phase doesn't change.
    app.text_input = Input::new(String::new());
    app.confirm_text_input();
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FilePassphrase),
        "empty passphrase must be rejected (Argon2id with no input is trivial)"
    );

    // First passphrase entry advances to the confirm prompt — sub-flow
    // is still in progress, the passphrase must NOT be kept yet.
    app.text_input = Input::new("correct horse battery staple".into());
    app.confirm_text_input();
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FilePassphraseConfirm),
        "first entry must route to the confirm screen, not advance"
    );
    assert!(app.in_key_storage_subflow());
    assert!(
        !app.config.secret_file_encrypted,
        "secret_file_encrypted must not flip until the confirm matches"
    );
    assert!(
        app.file_passphrase.is_none(),
        "the passphrase must not be kept until the confirm matches"
    );

    // Matching confirm finishes the sub-flow, keeps the passphrase, and
    // flips secret_file_encrypted.
    app.text_input = Input::new("correct horse battery staple".into());
    app.confirm_text_input();
    assert!(!app.in_key_storage_subflow());
    assert!(app.config.secret_file_encrypted);
    assert_eq!(app.current_step, WizardStep::Vta);
    assert_eq!(
        app.file_passphrase.as_deref().map(String::as_str),
        Some("correct horse battery staple"),
    );
    // The wizard never exports it to its own environment.
    assert!(std::env::var(affinidi_messaging_mediator_common::PASSPHRASE_ENV).is_err());
    // Pending stash must be cleared so a second entry into the
    // sub-flow doesn't see the previous passphrase.
    assert!(app.pending_passphrase.is_none());
}

#[test]
fn keystorage_file_backend_passphrase_mismatch_returns_to_first_screen() {
    // The whole point of the confirm step is to catch typos.
    // Mismatch must:
    //   1. Bounce the operator back to FilePassphrase
    //   2. Clear the stashed first entry (no leak across attempts)
    //   3. Surface an inline error
    //   4. Leave secret_file_encrypted unchanged
    //   5. Keep no passphrase
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 6; // file:// (k8s inserted at 5)
    app.select_current();
    app.text_input = Input::new(FILE_GATE_PHRASE.into());
    app.confirm_text_input();
    app.confirm_text_input(); // accept default path
    app.selection_index = 0; // encrypt = yes
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FilePassphrase));

    // First entry → confirm screen.
    app.text_input = Input::new("first try".into());
    app.confirm_text_input();
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FilePassphraseConfirm)
    );

    // Confirm types something different → bounce back with error.
    app.text_input = Input::new("second try".into());
    app.confirm_text_input();
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FilePassphrase),
        "mismatch must return to the first screen so the operator starts over"
    );
    assert!(app.pending_passphrase.is_none(), "stash must be dropped");
    assert!(
        app.passphrase_validation_error.is_some(),
        "operator must see why Enter sent them back"
    );
    assert!(!app.config.secret_file_encrypted);
    assert!(app.file_passphrase.is_none());

    // Re-typing both correctly clears the error and finishes.
    app.text_input = Input::new("third time lucky".into());
    app.confirm_text_input();
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::FilePassphraseConfirm)
    );
    app.text_input = Input::new("third time lucky".into());
    app.confirm_text_input();
    assert!(!app.in_key_storage_subflow());
    assert!(app.config.secret_file_encrypted);
    assert!(app.passphrase_validation_error.is_none());
    assert_eq!(
        app.file_passphrase.as_deref().map(String::as_str),
        Some("third time lucky"),
    );
}

#[test]
fn keystorage_file_backend_gate_rejection_clears_choice() {
    // Anything other than the gate phrase aborts the file:// choice
    // entirely — the operator is dropped back on the scheme list
    // with `secret_storage` cleared so they have to re-pick.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 6; // file:// (k8s inserted at 5)
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));

    app.text_input = Input::new("yes".into());
    app.confirm_text_input();

    assert!(app.config.secret_storage.is_none());
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::KeyStorage);
}

#[test]
fn keystorage_file_backend_gate_back_returns_to_scheme_list() {
    // Esc on the gate must rewind to the scheme list rather than
    // the (skipped) FilePath phase, otherwise the operator can't
    // back out without typing the phrase.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 6; // file:// (k8s inserted at 5)
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));

    app.go_back();
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::KeyStorage);
}

#[test]
fn keystorage_keyring_backend_prompts_for_service() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 0; // Keyring (now first in the list)
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::KeyringService));

    app.text_input = Input::new("affinidi-prod-mediator".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_keyring_service, "affinidi-prod-mediator");
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn keystorage_k8s_backend_walks_namespace_then_secret_name() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 5; // Kubernetes Secrets (k8s://)
    app.select_current();
    assert_eq!(app.config.secret_storage, Some(SecretScheme::K8s));
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::K8sNamespace));

    app.text_input = Input::new("affinidi".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_k8s_namespace, "affinidi");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::K8sSecretName));

    app.text_input = Input::new("mediator-secrets".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_k8s_secret_name, "mediator-secrets");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
    assert_eq!(
        crate::config_writer::build_backend_url(&app.config),
        "k8s://affinidi/mediator-secrets"
    );
}

#[test]
fn keystorage_vault_token_auth_finishes_after_method_pick() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 4; // HashiCorp Vault
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultEndpoint));

    app.text_input = Input::new("vault.internal:8200".into());
    app.confirm_text_input();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultMount));

    app.text_input = Input::new("secret/mediator".into());
    app.confirm_text_input();
    // Mount confirmed → the auth-method picker (selection mode).
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::VaultAuthMethod)
    );
    assert_eq!(app.mode, InputMode::Selecting);

    app.selection_index = 0; // Token
    app.select_current();
    assert_eq!(app.config.secret_vault_auth, "token");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
    assert_eq!(
        crate::config_writer::build_backend_url(&app.config),
        "vault://vault.internal:8200/secret/mediator"
    );
}

#[test]
fn keystorage_vault_kubernetes_auth_collects_role_and_namespace() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 4; // Vault
    app.select_current();
    app.text_input = Input::new("vault.internal".into());
    app.confirm_text_input(); // endpoint → mount
    app.text_input = Input::new("secret/mediator".into());
    app.confirm_text_input(); // mount → auth method
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::VaultAuthMethod)
    );

    app.selection_index = 1; // Kubernetes
    app.select_current();
    assert_eq!(app.config.secret_vault_auth, "kubernetes");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultRole));

    app.text_input = Input::new("mediator".into());
    app.confirm_text_input(); // role → k8s mount
    assert_eq!(app.config.secret_vault_role, "mediator");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultK8sMount));

    app.text_input = Input::new(String::new()); // keep the default mount
    app.confirm_text_input(); // k8s mount → namespace
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultNamespace));

    app.text_input = Input::new("team-a".into());
    app.confirm_text_input(); // namespace → done
    assert_eq!(app.config.secret_vault_namespace, "team-a");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
    assert_eq!(
        crate::config_writer::build_backend_url(&app.config),
        "vault://vault.internal/secret/mediator?auth=kubernetes&role=mediator&namespace=team-a"
    );
}

#[test]
fn keystorage_aws_backend_walks_region_then_namespace() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 1; // AWS (renumbered: vta:// removed)
    app.select_current();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsRegion));

    app.text_input = Input::new("eu-west-2".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_aws_region, "eu-west-2");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsNamespace));

    app.text_input = Input::new("prod/mediator/".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_aws_namespace, "prod/mediator/");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn keystorage_gcp_enters_project_then_namespace_subflow() {
    // GCP backend has two text-input phases: project then namespace.
    // The project field is required (no sensible default — GCP
    // project IDs are tenant-scoped); empty input on that screen
    // is rejected and the operator stays on the prompt.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 2; // GCP
    app.select_current();
    assert_eq!(app.config.secret_storage, Some(SecretScheme::Gcp));
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::GcpProject));

    app.text_input = Input::new("my-prod-project".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_gcp_project, "my-prod-project");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::GcpNamespace));

    app.text_input = Input::new("mediator-".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_gcp_namespace, "mediator-");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn keystorage_azure_enters_single_vault_subflow() {
    // Azure has one text-input phase: the vault name (or full URL).
    // Empty input is rejected — there's no sensible default that
    // covers both commercial and sovereign clouds.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 3; // Azure
    app.select_current();
    assert_eq!(app.config.secret_storage, Some(SecretScheme::Azure));
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AzureVault));

    app.text_input = Input::new("my-vault".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_azure_vault, "my-vault");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn keystorage_vault_enters_endpoint_then_mount_subflow() {
    // HashiCorp Vault has two phases: endpoint then mount + namespace.
    // The endpoint field is required (deployment-specific); the
    // mount has a default (`secret/mediator`) so empty input on
    // the mount screen keeps the default.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 4; // Vault
    app.select_current();
    assert_eq!(app.config.secret_storage, Some(SecretScheme::Vault));
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultEndpoint));

    app.text_input = Input::new("vault.internal:8200".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_vault_endpoint, "vault.internal:8200");
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultMount));

    app.text_input = Input::new("kv/prod-mediator".into());
    app.confirm_text_input();
    assert_eq!(app.config.secret_vault_mount, "kv/prod-mediator");
    // Mount now leads into the auth-method picker rather than
    // finishing the step directly.
    assert_eq!(
        app.key_storage_phase,
        Some(KeyStoragePhase::VaultAuthMethod)
    );

    // Pick Token (the default) to complete the sub-flow.
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.config.secret_vault_auth, "token");
    assert!(!app.in_key_storage_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
}

// ── Discovery overlay (F5) state-machine tests ───────────────────

#[test]
fn discovery_request_for_aws_namespace_requires_region() {
    // F5 on AwsNamespace without a region is a no-op (returns None);
    // once the region is set, the request carries it through.
    let mut app = WizardApp::new("test.toml".into());
    app.key_storage_phase = Some(KeyStoragePhase::AwsNamespace);
    app.config.secret_aws_region = String::new();
    assert!(app.discovery_request_for_phase().is_none());
    app.config.secret_aws_region = "eu-west-2".into();
    match app.discovery_request_for_phase() {
        Some(crate::discovery::DiscoveryRequest::Aws { region }) => {
            assert_eq!(region, "eu-west-2");
        }
        other => panic!("expected Aws request, got {other:?}"),
    }
}

#[test]
fn discovery_request_for_azure_uses_current_text_input() {
    // Azure's vault is the field the operator is editing — the
    // request reads from `text_input`, not from the saved config
    // field, so F5 verifies what's typed *now* rather than the
    // last confirmed value.
    let mut app = WizardApp::new("test.toml".into());
    app.key_storage_phase = Some(KeyStoragePhase::AzureVault);
    app.text_input = Input::new("partial-vault-name".into());
    match app.discovery_request_for_phase() {
        Some(crate::discovery::DiscoveryRequest::Azure { vault }) => {
            assert_eq!(vault, "partial-vault-name");
        }
        other => panic!("expected Azure request, got {other:?}"),
    }
}

#[test]
fn discovery_request_for_vault_mount_falls_back_to_default() {
    // F5 with empty mount input falls back to the wizard default
    // so the operator can hit it on a fresh entry to see what's
    // already at `secret/mediator`.
    let mut app = WizardApp::new("test.toml".into());
    app.key_storage_phase = Some(KeyStoragePhase::VaultMount);
    app.config.secret_vault_endpoint = "vault.internal:8200".into();
    app.text_input = Input::new(String::new());
    match app.discovery_request_for_phase() {
        Some(crate::discovery::DiscoveryRequest::Vault { endpoint, mount }) => {
            assert_eq!(endpoint, "vault.internal:8200");
            assert_eq!(mount, DEFAULT_VAULT_MOUNT);
        }
        other => panic!("expected Vault request, got {other:?}"),
    }
}

#[test]
fn discovery_request_none_for_non_discoverable_phases() {
    // Region / project / endpoint screens are upstream of the
    // discoverable namespace — F5 is a no-op there. Same for the
    // file:// / keyring sub-flow.
    let mut app = WizardApp::new("test.toml".into());
    for phase in [
        KeyStoragePhase::AwsRegion,
        KeyStoragePhase::GcpProject,
        KeyStoragePhase::VaultEndpoint,
        KeyStoragePhase::FilePath,
        KeyStoragePhase::KeyringService,
    ] {
        app.key_storage_phase = Some(phase);
        assert!(
            app.discovery_request_for_phase().is_none(),
            "expected no discovery request for {phase:?}"
        );
    }
}

#[test]
fn handle_discovery_key_navigates_loaded_list() {
    use crate::discovery::DiscoveryState;
    use crossterm::event::KeyCode;
    let mut app = WizardApp::new("test.toml".into());
    app.discovery = Some(DiscoveryState::Loaded {
        items: vec!["a/".into(), "b/".into(), "c/".into()],
        cursor: 0,
        scroll: 0,
    });
    // Down moves cursor to 1, then End jumps to last.
    assert!(app.handle_discovery_key(KeyCode::Down));
    match &app.discovery {
        Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 1),
        _ => panic!("expected Loaded state with cursor=1"),
    }
    assert!(app.handle_discovery_key(KeyCode::End));
    match &app.discovery {
        Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 2),
        _ => panic!("expected Loaded state with cursor=2"),
    }
    // Home returns to top.
    assert!(app.handle_discovery_key(KeyCode::Home));
    match &app.discovery {
        Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 0),
        _ => panic!("expected Loaded state with cursor=0"),
    }
}

#[test]
fn handle_discovery_key_enter_copies_selection_into_input() {
    // Enter copies the highlighted secret name verbatim into the
    // prompt; the operator then trims it to the namespace portion
    // they want.
    use crate::discovery::DiscoveryState;
    use crossterm::event::KeyCode;
    let mut app = WizardApp::new("test.toml".into());
    app.text_input = Input::new("operator-typed-namespace".into());
    app.discovery = Some(DiscoveryState::Loaded {
        items: vec!["alpha/admin".into(), "beta/jwt".into()],
        cursor: 1,
        scroll: 0,
    });
    assert!(app.handle_discovery_key(KeyCode::Enter));
    assert_eq!(app.text_input.value(), "beta/jwt");
    assert!(app.discovery.is_none());
}

#[test]
fn handle_discovery_key_esc_dismisses_without_copying() {
    use crate::discovery::DiscoveryState;
    use crossterm::event::KeyCode;
    let mut app = WizardApp::new("test.toml".into());
    app.text_input = Input::new("operator-typed-namespace".into());
    app.discovery = Some(DiscoveryState::Loaded {
        items: vec!["alpha/".into(), "beta/".into()],
        cursor: 1,
        scroll: 0,
    });
    assert!(app.handle_discovery_key(KeyCode::Esc));
    // Text input is untouched.
    assert_eq!(app.text_input.value(), "operator-typed-namespace");
    assert!(app.discovery.is_none());
}

#[test]
fn handle_discovery_key_failed_dismisses_on_any_key() {
    use crate::discovery::DiscoveryState;
    use crossterm::event::KeyCode;
    let mut app = WizardApp::new("test.toml".into());
    app.discovery = Some(DiscoveryState::Failed {
        message: "credentials missing".into(),
    });
    // Any key dismisses — pick something arbitrary.
    assert!(app.handle_discovery_key(KeyCode::Char('x')));
    assert!(app.discovery.is_none());
}

#[test]
fn handle_discovery_key_loading_only_dismisses_on_esc() {
    use crate::discovery::DiscoveryState;
    use crossterm::event::KeyCode;
    let mut app = WizardApp::new("test.toml".into());
    app.discovery = Some(DiscoveryState::Loading);
    // Random key swallowed — wizard stays in Loading.
    assert!(app.handle_discovery_key(KeyCode::Char('x')));
    assert!(matches!(app.discovery, Some(DiscoveryState::Loading)));
    // Esc cancels.
    assert!(app.handle_discovery_key(KeyCode::Esc));
    assert!(app.discovery.is_none());
}

// ── Security JWT sub-phase tests ─────────────────────────────────

#[test]
fn security_ssl_none_then_jwt_generate_advances() {
    // SSL "None" + JWT "generate" + NetworkMode "open" — the common
    // dev path. Walks through all three sub-phases and lands on
    // Database.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = 0; // No SSL
    app.select_current();
    // SSL is now settled; we're in the JWT sub-phase.
    assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));
    assert_eq!(app.current_step, WizardStep::Security);

    // Default selection is "generate" (index 0). Confirming the JWT
    // pick now transitions to NetworkMode rather than advancing the
    // top-level step — Database is reached one confirm later.
    app.select_current();
    assert_eq!(app.config.jwt_mode, JWT_MODE_GENERATE);
    assert_eq!(app.security_phase, Some(SecurityPhase::NetworkMode));
    assert_eq!(app.current_step, WizardStep::Security);

    // Default network-mode selection is "open" (index 0). Confirming
    // it now transitions to the CORS sub-phase rather than advancing.
    app.select_current();
    assert_eq!(app.config.network_mode, crate::consts::NETWORK_MODE_OPEN);
    assert_eq!(app.security_phase, Some(SecurityPhase::CorsPolicy));
    assert_eq!(app.current_step, WizardStep::Security);

    // Default CORS selection is "none" (index 0) — confirming lands
    // on Database.
    app.select_current();
    assert_eq!(app.config.cors_mode, crate::consts::CORS_MODE_NONE);
    assert!(app.security_phase.is_none());
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn security_ssl_none_then_jwt_provide_records_choice() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = 0; // No SSL
    app.select_current();
    assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));

    app.selection_index = 1; // Provide
    app.select_current();
    assert_eq!(app.config.jwt_mode, JWT_MODE_PROVIDE);
    // Network-mode sub-phase now interposes between JWT and Database.
    assert_eq!(app.security_phase, Some(SecurityPhase::NetworkMode));
    assert_eq!(app.current_step, WizardStep::Security);

    // Confirm the default open posture; the CORS sub-phase follows.
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.config.network_mode, crate::consts::NETWORK_MODE_OPEN);
    assert_eq!(app.security_phase, Some(SecurityPhase::CorsPolicy));

    // Default CORS = none → Database.
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.config.cors_mode, crate::consts::CORS_MODE_NONE);
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn security_network_mode_closed_records_choice() {
    // Walk through the full Security flow and pick Closed at the
    // network sub-phase to confirm the choice persists.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = 0; // No SSL
    app.select_current();
    app.select_current(); // JWT default = generate
    assert_eq!(app.security_phase, Some(SecurityPhase::NetworkMode));

    app.selection_index = 1; // Closed
    app.select_current();
    assert_eq!(app.config.network_mode, crate::consts::NETWORK_MODE_CLOSED);
    // Network mode now hands off to the CORS sub-phase.
    assert_eq!(app.security_phase, Some(SecurityPhase::CorsPolicy));

    // Confirm default CORS = none to land on Database.
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.config.cors_mode, crate::consts::CORS_MODE_NONE);
    assert_eq!(app.current_step, WizardStep::Database);
}

// ── Security CORS sub-phase tests ────────────────────────────────

/// Advance an app to the CORS sub-phase via the common SSL-none /
/// JWT-generate / network-open path.
fn app_at_cors_phase() -> WizardApp {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = 0; // No SSL
    app.select_current();
    app.select_current(); // JWT default = generate
    app.select_current(); // Network default = open
    assert_eq!(app.security_phase, Some(SecurityPhase::CorsPolicy));
    app
}

#[test]
fn security_cors_any_advances() {
    let mut app = app_at_cors_phase();
    app.selection_index = 1; // Allow any origin
    app.select_current();
    assert_eq!(app.config.cors_mode, crate::consts::CORS_MODE_ANY);
    assert!(app.security_phase.is_none());
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn security_cors_specific_collects_and_validates_domains() {
    let mut app = app_at_cors_phase();
    app.selection_index = 2; // Specific domains
    app.select_current();
    // We're now in the domains text-input sub-phase, still CorsPolicy.
    assert_eq!(app.config.cors_mode, crate::consts::CORS_MODE_LIST);
    assert_eq!(app.security_phase, Some(SecurityPhase::CorsPolicy));
    assert_eq!(app.mode, InputMode::TextInput);

    // An invalid entry keeps us on the screen with an error.
    app.text_input = Input::new("app.affinidi.com".into());
    app.confirm_text_input();
    assert!(app.cors_validation_error.is_some());
    assert_eq!(app.current_step, WizardStep::Security);

    // A valid mixed exact + wildcard list advances and normalises.
    app.text_input = Input::new("https://app.affinidi.com, https://*.affinidi.com".into());
    app.confirm_text_input();
    assert!(app.cors_validation_error.is_none());
    assert_eq!(
        app.config.cors_domains,
        "https://app.affinidi.com,https://*.affinidi.com"
    );
    assert!(app.security_phase.is_none());
    assert_eq!(app.current_step, WizardStep::Database);
}

#[test]
fn validate_cors_domains_accepts_exact_and_wildcard() {
    assert_eq!(
        validate_cors_domains("https://app.affinidi.com").unwrap(),
        "https://app.affinidi.com"
    );
    assert_eq!(
        validate_cors_domains(" https://*.affinidi.com:8443 ").unwrap(),
        "https://*.affinidi.com:8443"
    );
    // Trims + normalises whitespace around the comma separator.
    assert_eq!(
        validate_cors_domains("https://a.com ,  https://b.com").unwrap(),
        "https://a.com,https://b.com"
    );
}

#[test]
fn validate_cors_domains_rejects_bad_input() {
    assert!(validate_cors_domains("").is_err()); // empty
    assert!(validate_cors_domains("app.affinidi.com").is_err()); // no scheme
    assert!(validate_cors_domains("*").is_err()); // bare wildcard
    assert!(validate_cors_domains("https://app.*.com").is_err()); // misplaced *
    assert!(validate_cors_domains("https://*.").is_err()); // empty suffix
    assert!(validate_cors_domains("https://app.affinidi.com/path").is_err()); // path
    assert!(validate_cors_domains("https://a b.com").is_err()); // whitespace
}

#[test]
fn security_ssl_existing_collects_paths_then_jwt_phase() {
    // Existing-cert path runs two text-input prompts before the JWT
    // selection appears.
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = 1; // Existing certs
    app.select_current();
    // Now in TextInput mode collecting the cert path.
    assert_eq!(app.mode, InputMode::TextInput);
    app.text_input = Input::new("/etc/ssl/cert.pem".into());
    app.confirm_text_input();
    // Still TextInput, now collecting key path.
    assert_eq!(app.mode, InputMode::TextInput);
    app.text_input = Input::new("/etc/ssl/key.pem".into());
    app.confirm_text_input();
    // Both paths saved; JWT phase active.
    assert_eq!(app.config.ssl_cert_path, "/etc/ssl/cert.pem");
    assert_eq!(app.config.ssl_key_path, "/etc/ssl/key.pem");
    assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));
    assert_eq!(app.current_step, WizardStep::Security);
}

#[test]
fn keystorage_back_rewinds_aws_second_phase() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.selection_index = 1; // AWS
    app.select_current();
    app.confirm_text_input(); // AwsRegion → AwsNamespace
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsNamespace));

    app.go_back();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsRegion));

    app.go_back();
    assert!(!app.in_key_storage_subflow());
}

// ── VTA integration tests ─────────────────────────────────────────

/// Advance the wizard to a specific step. Used by the VTA tests so the
/// intermediate step ordering (KeyStorage now sits between Deployment
/// and Vta) doesn't require every test to hardcode a fresh count.
fn advance_to(app: &mut WizardApp, target: WizardStep) {
    let mut guard = 0;
    while app.current_step != target {
        assert!(guard < 20, "advance_to did not reach {target:?}");
        app.advance();
        guard += 1;
    }
}

/// Walk the two-question Vta picker: pick "Full setup" (intent) then
/// "Online" (transport). After this call the wizard is inside the
/// online-VTA sub-flow at `ConnectPhase::EnterDid`.
fn pick_full_setup_online(app: &mut WizardApp) {
    app.selection_index = 0;
    app.select_current(); // SelectIntent → FullSetup
    app.selection_index = 0;
    app.select_current(); // SelectTransport → Online (enters sub-flow)
}

/// Walk the two-question Vta picker: pick "Admin credential only"
/// (intent) then "Sealed handoff" (transport). After this call the
/// wizard is inside the sealed-handoff sub-flow.
fn pick_admin_only_sealed(app: &mut WizardApp) {
    app.selection_index = 1;
    app.select_current(); // SelectIntent → AdminOnly
    app.selection_index = 1;
    app.select_current(); // SelectTransport → Offline (enters sub-flow)
}

#[test]
fn vta_yes_then_online_enters_subflow() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    assert_eq!(app.current_step, WizardStep::Vta);

    // Two-question picker: "Full setup" then "Online".
    pick_full_setup_online(&mut app);

    // Online picks the DID/context-entry sub-flow — the wizard stays on
    // the Vta step until the connection is tested in a later phase.
    assert_eq!(app.current_step, WizardStep::Vta);
    assert!(app.in_vta_subflow(), "should have entered VTA sub-flow");
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterDid));
    assert_eq!(app.mode, InputMode::TextInput);
    assert!(app.config.use_vta);
    assert_eq!(app.config.vta_mode, Some(VtaMode::Online));
    assert_eq!(app.config.did_method, Some(DidMethod::Vta));
    // `secret_storage` is owned by the earlier KeyStorage step — the Vta
    // step deliberately doesn't override whatever was chosen there.
    assert_eq!(app.config.admin_did_mode, Some(AdminMode::Vta));
}

#[test]
fn vta_subflow_collects_did_then_context_then_instructions() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app); // enter sub-flow at EnterDid

    // Enter the VTA DID.
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterContext));
    assert_eq!(
        app.vta_connect.as_ref().unwrap().vta_did,
        "did:webvh:vta.example.com"
    );

    // Accept the default context id ("mediator" is pre-filled).
    app.confirm_text_input();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterMediatorUrl));

    // Enter the mediator URL — the new phase added for
    // provision-integration (template `URL` variable).
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));
    assert_eq!(app.mode, InputMode::Selecting);
    let st = app.vta_connect.as_ref().unwrap();
    assert!(st.setup_key.is_some(), "ephemeral setup key generated");
    assert_eq!(st.mediator_url, "https://mediator.example.com");
    let acl = st.acl_command().unwrap();
    assert!(acl.starts_with("pnm contexts create"));
    assert!(acl.contains("--id mediator"));
    assert!(acl.contains("--admin-did did:key:z6Mk"));
    assert!(acl.contains("--admin-expires 1h"));
}

#[test]
fn vta_subflow_back_rewinds_phases() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app); // EnterDid

    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input(); // → EnterContext
    app.confirm_text_input(); // → EnterMediatorUrl
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input(); // → AwaitingAcl
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));

    app.go_back(); // → EnterMediatorUrl
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterMediatorUrl));

    app.go_back(); // → EnterContext
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterContext));

    app.go_back(); // → EnterDid
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterDid));

    app.go_back(); // → exits sub-flow back to selection
    assert!(!app.in_vta_subflow());
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[tokio::test]
async fn vta_subflow_awaiting_acl_enter_starts_testing() {
    // Pressing Enter on the AwaitingAcl instructions kicks off the
    // provision-integration runner. The test exits before the runner
    // actually contacts any network — we only verify the phase
    // transition and that the channel + diagnostics list are seeded.
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));

    app.select_current();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::Testing));
    let st = app.vta_connect.as_ref().unwrap();
    assert!(st.event_rx.is_some(), "runner channel should be open");
    assert_eq!(st.diagnostics.len(), crate::vta::DiagCheck::all().len());
}

#[tokio::test]
async fn vta_subflow_connected_enter_advances_past_vta_step() {
    use crate::vta::{DiagStatus, Protocol, VtaEvent};

    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    app.select_current(); // → Testing

    // Inject a synthetic success event (bypass the real network runner).
    let st = app.vta_connect.as_mut().unwrap();
    st.event_rx = None; // pretend the runner completed
    st.apply_event(VtaEvent::CheckDone(
        crate::vta::DiagCheck::AuthenticateDIDComm,
        DiagStatus::Ok("ok".into()),
    ));
    st.apply_event(VtaEvent::Connected {
        protocol: Protocol::DidComm,
        rest_url: Some("https://vta.example.com".into()),
        mediator_did: Some("did:webvh:mediator.vta.example.com".into()),
        reply: vta_sdk::provision_client::VtaReply::Full(Box::new(
            vta_sdk::provision_client::test_helpers::sample_provision_result_v2(true, false),
        )),
    });
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::Connected));

    app.select_current();
    assert_eq!(app.current_step, WizardStep::Protocol);
    assert!(!app.in_vta_subflow());
}

#[tokio::test]
async fn vta_subflow_failure_routes_to_recovery_prompt() {
    use crate::vta::VtaEvent;

    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    app.select_current(); // → Testing

    // Simulate runner failure. Slice 2 routes Failed → RecoveryPrompt
    // so the operator picks a path forward (retry / offline / back).
    let st = app.vta_connect.as_mut().unwrap();
    st.event_rx = None;
    st.apply_event(VtaEvent::Failed("ACL not found".into()));
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::RecoveryPrompt));
    assert!(app.vta_connect.as_ref().unwrap().last_error.is_some());

    // RecoveryPrompt offers four options ([R] / [E] / [O] / [B]).
    let opts = app.current_options();
    assert_eq!(opts.len(), 4);
    assert!(opts[0].label.contains("Retry DIDComm"));
    assert!(opts[2].label.contains("Offline"));
    assert!(opts[3].label.contains("Back"));
}

#[tokio::test]
async fn recovery_back_returns_to_awaiting_acl() {
    use crate::vta::VtaEvent;

    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    app.select_current();

    let st = app.vta_connect.as_mut().unwrap();
    st.event_rx = None;
    st.apply_event(VtaEvent::Failed("ACL not found".into()));

    // Select [B] Back (index 3).
    app.selection_index = 3;
    app.select_current();
    assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));
    assert!(
        app.vta_connect.as_ref().unwrap().last_error.is_none(),
        "going back clears the failure so AwaitingAcl renders cleanly"
    );
}

#[tokio::test]
async fn recovery_offline_transitions_to_sealed_handoff_with_carry_over() {
    use crate::vta::VtaEvent;

    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("mediator-prod".into());
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    app.select_current();

    // Mark a DIDComm pre-auth attempt so [R] is enabled and the
    // BothFailed reason fires (rather than NoTransportAvailable).
    let st = app.vta_connect.as_mut().unwrap();
    st.attempted.didcomm = Some(crate::vta::AttemptResult {
        outcome: crate::vta::AttemptResultKind::PreAuthFailure("ACL not found".into()),
        at: std::time::Instant::now(),
    });
    st.event_rx = None;
    st.apply_event(VtaEvent::Failed("ACL not found".into()));

    // Select [O] Offline (index 2).
    app.selection_index = 2;
    app.select_current();
    assert!(
        app.in_sealed_handoff_subflow(),
        "[O] should drop the operator into sealed-handoff"
    );
    assert!(app.vta_connect.is_none());

    let sealed = app.sealed_handoff.as_ref().unwrap();
    assert_eq!(sealed.context_id, "mediator-prod");
    assert_eq!(sealed.mediator_url, "https://mediator.example.com");
    assert!(
        sealed.offline_transition_banner.is_some(),
        "the banner explains why the wizard switched flows"
    );
}

#[test]
fn vta_sealed_handoff_sets_defaults_and_enters_subflow() {
    let mut app = WizardApp::new("test.toml".into());
    app.selection_index = 0;
    app.select_current(); // Deployment → KeyStorage
    advance_to(&mut app, WizardStep::Vta);

    // Two-question picker: "Admin credential only" then "Sealed
    // handoff". Selection captures the mode + enters the dedicated
    // sealed sub-flow rather than advancing the wizard. AdminOnly
    // does NOT force `did_method = VTA` — the operator picks their
    // own DID in the Did step; the VTA only issues an admin
    // credential.
    pick_admin_only_sealed(&mut app);
    assert_eq!(app.current_step, WizardStep::Vta);
    assert!(app.config.use_vta);
    assert_eq!(app.config.vta_mode, Some(VtaMode::SealedMint));
    assert_ne!(
        app.config.did_method,
        Some(DidMethod::Vta),
        "AdminOnly keeps operator's own DID choice (not forced to VTA)",
    );
    assert_eq!(app.config.admin_did_mode, Some(AdminMode::Vta));
    assert!(app.in_sealed_handoff_subflow());
}

#[test]
fn vta_no_clears_vta_options() {
    let mut app = WizardApp::new("test.toml".into());
    app.selection_index = 0;
    app.select_current(); // Deployment → KeyStorage (sets VTA defaults)
    advance_to(&mut app, WizardStep::Vta);
    assert_eq!(app.config.did_method, Some(DidMethod::Vta));

    // Select "No VTA" (index 3 — order: FullSetup, AdminOnly,
    // OfflineExport, No VTA).
    app.selection_index = 3;
    app.select_current();
    assert_eq!(app.current_step, WizardStep::Protocol);
    assert!(!app.config.use_vta);
    // apply_vta_defaults should have switched the DID method + admin
    // mode to non-VTA; `secret_storage` is now chosen in the earlier
    // KeyStorage step and intentionally not touched by Vta.
    assert_eq!(app.config.did_method, Some(DidMethod::Peer));
    assert!(app.config.vta_mode.is_none());
}

#[test]
fn did_options_exclude_vta_when_disabled() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Did;
    let opts = app.current_options();
    assert_eq!(opts.len(), 2); // webvh, peer (no import: #173)
}

#[test]
fn did_options_include_vta_when_full_setup_intent_chosen() {
    // The "Configure via VTA" option only appears for the
    // FullSetup intent, signalled by `did_method == DidMethod::Vta`
    // after `apply_vta_defaults` ran. AdminOnly keeps
    // `use_vta == true` but clears `did_method` so the operator
    // picks a local DID method.
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = true;
    app.config.did_method = Some(DidMethod::Vta);
    app.current_step = WizardStep::Did;
    let opts = app.current_options();
    assert_eq!(opts.len(), 3); // VTA, webvh, peer (no import: #173)
}

#[test]
fn did_options_hide_vta_when_admin_only_intent_chosen() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = true;
    app.config.did_method = Some(DidMethod::Peer);
    app.current_step = WizardStep::Did;
    let opts = app.current_options();
    // AdminOnly — operator picks their own DID method; the
    // "Configure via VTA" option is suppressed.
    assert_eq!(opts.len(), 2); // webvh, peer (no import: #173)
}

#[test]
fn vta_step_select_intent_has_four_options() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Vta;
    app.on_enter_step();
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
    let opts = app.current_options();
    assert_eq!(opts.len(), 4); // FullSetup, AdminOnly, OfflineExport, No VTA
}

#[test]
fn vta_intent_offline_export_skips_transport_phase() {
    // OfflineExport is always offline (no online transport for the
    // v1 sealed_transfer::BootstrapRequest shape) so picking it
    // routes straight into the sealed-handoff sub-flow without
    // ever entering SelectTransport.
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    app.selection_index = 2; // OfflineExport
    app.select_current();
    assert_eq!(app.vta_intent_choice, Some(VtaIntent::OfflineExport));
    assert_eq!(app.config.vta_mode, Some(VtaMode::SealedExport));
    assert!(app.config.use_vta);
    // SelectTransport is bypassed.
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
    // Sealed-handoff sub-flow is now active with OfflineExport
    // intent — context_id is the only further input the operator
    // needs to provide.
    assert!(app.in_sealed_handoff_subflow());
    let st = app.sealed_handoff.as_ref().unwrap();
    assert_eq!(st.intent, VtaIntent::OfflineExport);
}

#[test]
fn vta_step_select_transport_has_two_options_after_intent_pick() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    // Pick "Full setup" — advances to transport sub-phase.
    app.selection_index = 0;
    app.select_current();
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectTransport);
    assert_eq!(app.vta_intent_choice, Some(VtaIntent::FullSetup));
    let opts = app.current_options();
    assert_eq!(opts.len(), 2); // Online, Sealed handoff
    assert!(opts[0].label.starts_with("Online"));
}

#[test]
fn vta_step_go_back_from_transport_rewinds_to_intent() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    app.selection_index = 0;
    app.select_current(); // FullSetup → SelectTransport
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectTransport);

    app.go_back();
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
    assert!(app.vta_intent_choice.is_none());
    assert_eq!(app.current_step, WizardStep::Vta);
}

#[test]
fn vta_full_setup_offline_enters_sealed_subflow_with_correct_intent() {
    // Slice 3: FullSetup + Offline is no longer a stub — it enters
    // the sealed sub-flow with `VtaIntent::FullSetup`, which
    // drives the VP-framed request + template-bootstrap reply
    // path. Operator lands on `CollectContext`.
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    app.selection_index = 0;
    app.select_current(); // FullSetup
    app.selection_index = 1;
    app.select_current(); // Offline
    assert!(app.in_sealed_handoff_subflow());
    let state = app.sealed_handoff.as_ref().unwrap();
    assert_eq!(state.intent, VtaIntent::FullSetup);
    assert_eq!(
        state.phase,
        crate::sealed_handoff::SealedPhase::CollectContext
    );
    assert!(app.vta_stub_notice.is_none());
    assert_eq!(app.config.vta_mode, Some(VtaMode::SealedMint));
}

#[test]
fn vta_admin_only_online_enters_vta_subflow_with_correct_intent() {
    // Slice 4: AdminOnly + Online is no longer a stub — it
    // enters the online VTA sub-flow with
    // `VtaIntent::AdminOnly`, which skips provision-integration
    // and keeps the setup DID as the long-term admin credential.
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    app.selection_index = 1;
    app.select_current(); // AdminOnly
    app.selection_index = 0;
    app.select_current(); // Online
    assert!(app.in_vta_subflow());
    assert!(!app.in_sealed_handoff_subflow());
    assert!(app.vta_stub_notice.is_none());
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.intent, VtaIntent::AdminOnly);
    assert_eq!(st.phase, ConnectPhase::EnterDid);
    assert_eq!(app.config.vta_mode, Some(VtaMode::Online));
}

#[test]
fn vta_step_re_entry_resets_picker_phase() {
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    app.selection_index = 0;
    app.select_current(); // FullSetup — now on SelectTransport

    // Jump back to Vta from somewhere else via go_back; the picker
    // should reset to SelectIntent so the operator can re-answer
    // cleanly instead of continuing with a stale intent pick.
    app.vta_step_phase = VtaStepPhase::SelectIntent; // belt-and-braces
    app.on_enter_step();
    assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
    assert!(app.vta_intent_choice.is_none());
    assert!(app.vta_stub_notice.is_none());
}

// Helpers for the webvh-picker tests below.
fn sample_webvh_server(id: &str, label: Option<&str>) -> vta_sdk::webvh::WebvhServerRecord {
    use chrono::Utc;
    vta_sdk::webvh::WebvhServerRecord {
        id: id.into(),
        did: format!("did:webvh:{id}.example.com"),
        label: label.map(str::to_string),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Drive the wizard far enough to have a `vta_connect` sub-flow
/// with a setup key + context id in place, then fake a preflight
/// with the supplied server catalogue. Returns the wizard ready
/// to exercise picker dispatch.
fn prime_full_setup_picker(servers: Vec<vta_sdk::webvh::WebvhServerRecord>) -> WizardApp {
    use crate::vta::{EphemeralSetupKey, VtaEvent};
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app); // EnterDid
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input(); // → EnterContext
    app.confirm_text_input(); // → EnterMediatorUrl
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input(); // → AwaitingAcl (generates setup key)
    // Synthesise a preflight completion without actually running
    // a DIDComm session.
    let st = app.vta_connect.as_mut().unwrap();
    // Make sure the setup key field is populated (ConnectPhase
    // machinery does this during `confirm_text_input`).
    if st.setup_key.is_none() {
        st.setup_key = Some(EphemeralSetupKey::generate().unwrap());
    }
    st.phase = ConnectPhase::Testing;
    st.event_rx = None;
    st.apply_event(VtaEvent::PreflightDone {
        rest_url: Some("https://vta.example.com".into()),
        mediator_did: "did:webvh:mediator.vta.example.com".into(),
        servers,
    });
    app
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_picker_auto_dispatches_serverless_when_catalogue_empty() {
    // 0 registered servers → wizard skips the picker entirely and
    // kicks the provision flight with `webvh_server_choice = None`
    // (serverless). Phase transitions back to `Testing` while the
    // runner is in flight.
    let mut app = prime_full_setup_picker(vec![]);
    app.drain_vta_events();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::Testing);
    assert!(st.webvh_server_choice.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_picker_auto_picks_single_entry() {
    // 1 registered server → wizard auto-selects it, commits the
    // choice, and transitions to `EnterWebvhPath` so the operator
    // can supply an optional path before the provision flight
    // starts. The text-input mode is activated for that prompt.
    let only = sample_webvh_server("prod-1", Some("Primary"));
    let mut app = prime_full_setup_picker(vec![only]);
    app.drain_vta_events();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::EnterWebvhPath);
    assert_eq!(st.webvh_server_choice.as_deref(), Some("prod-1"));
    assert!(st.webvh_path.is_none());
    assert!(matches!(app.mode, InputMode::TextInput));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_picker_waits_when_catalogue_has_multiple_entries() {
    // 2+ registered servers → stay on `PickWebvhServer`; no
    // provision flight starts until the operator picks.
    let servers = vec![
        sample_webvh_server("prod-1", Some("Primary")),
        sample_webvh_server("backup-1", Some("DR")),
    ];
    let mut app = prime_full_setup_picker(servers);
    app.drain_vta_events();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::PickWebvhServer);
    assert!(st.webvh_server_choice.is_none());
    // Options list: serverless + 2 servers = 3 entries.
    let opts = app.current_options();
    assert_eq!(opts.len(), 3);
    assert!(opts[0].label.starts_with("Serverless"));
    assert!(opts[1].label.contains("prod-1"));
    assert!(opts[2].label.contains("backup-1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_picker_serverless_selection_commits_none_choice() {
    let servers = vec![
        sample_webvh_server("prod-1", Some("Primary")),
        sample_webvh_server("backup-1", Some("DR")),
    ];
    let mut app = prime_full_setup_picker(servers);
    app.drain_vta_events();
    assert_eq!(
        app.vta_connect.as_ref().unwrap().phase,
        ConnectPhase::PickWebvhServer
    );
    app.selection_index = 0; // Serverless
    app.select_current();
    let st = app.vta_connect.as_ref().unwrap();
    assert!(
        st.webvh_server_choice.is_none(),
        "index 0 should commit serverless (None)"
    );
    // Provision flight started.
    assert_eq!(st.phase, ConnectPhase::Testing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_picker_server_selection_routes_through_path_prompt() {
    // Picking a real server commits the choice, but the provision
    // flight doesn't start yet — we stop on `EnterWebvhPath` so
    // the operator can supply an optional path. Only serverless
    // dispatches immediately.
    let servers = vec![
        sample_webvh_server("prod-1", Some("Primary")),
        sample_webvh_server("backup-1", Some("DR")),
    ];
    let mut app = prime_full_setup_picker(servers);
    app.drain_vta_events();
    app.selection_index = 2; // second server ("backup-1")
    app.select_current();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.webvh_server_choice.as_deref(), Some("backup-1"));
    assert_eq!(st.phase, ConnectPhase::EnterWebvhPath);
    assert!(st.webvh_path.is_none());
    assert!(matches!(app.mode, InputMode::TextInput));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_path_prompt_blank_dispatches_with_none() {
    // Blank input on `EnterWebvhPath` means "server auto-assigns".
    // The flight kicks off (phase → Testing), `webvh_path` stays
    // `None` so no `WEBVH_PATH` var is injected downstream, and
    // mode drops back to `Selecting` so the eventual `Connected`
    // "Continue" Enter routes correctly.
    let only = sample_webvh_server("prod-1", Some("Primary"));
    let mut app = prime_full_setup_picker(vec![only]);
    app.drain_vta_events();
    assert_eq!(
        app.vta_connect.as_ref().unwrap().phase,
        ConnectPhase::EnterWebvhPath
    );
    app.text_input = tui_input::Input::default();
    app.confirm_text_input();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::Testing);
    assert!(st.webvh_path.is_none());
    assert!(matches!(app.mode, InputMode::Selecting));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_path_prompt_captures_trimmed_value() {
    // Non-blank input lands on state verbatim (trimmed) and then
    // the provision flight starts. Downstream the runner relays
    // it as the `WEBVH_PATH` template var. Mode drops back to
    // `Selecting` so the `Connected` continue-Enter works.
    let only = sample_webvh_server("prod-1", Some("Primary"));
    let mut app = prime_full_setup_picker(vec![only]);
    app.drain_vta_events();
    app.text_input = tui_input::Input::new("  my-mediator  ".into());
    app.confirm_text_input();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::Testing);
    assert_eq!(st.webvh_path.as_deref(), Some("my-mediator"));
    assert!(matches!(app.mode, InputMode::Selecting));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn webvh_path_back_nav_returns_to_picker_without_losing_path() {
    // Typing a path and then backing out lands on the picker with
    // the typed value preserved on state, so re-entering the
    // prompt (e.g. to switch servers) pre-fills the field.
    let servers = vec![
        sample_webvh_server("prod-1", Some("Primary")),
        sample_webvh_server("backup-1", Some("DR")),
    ];
    let mut app = prime_full_setup_picker(servers);
    app.drain_vta_events();
    app.selection_index = 1;
    app.select_current();
    assert_eq!(
        app.vta_connect.as_ref().unwrap().phase,
        ConnectPhase::EnterWebvhPath
    );
    // Operator types a path, then Esc — the back-nav should
    // retain the state field and rewind to the picker.
    app.vta_connect.as_mut().unwrap().webvh_path = Some("typed".into());
    app.vta_subflow_back();
    let st = app.vta_connect.as_ref().unwrap();
    assert_eq!(st.phase, ConnectPhase::PickWebvhServer);
    assert_eq!(st.webvh_path.as_deref(), Some("typed"));
    assert_eq!(st.webvh_server_choice.as_deref(), Some("prod-1"));
}

/// Drive the wizard to the point where online FullSetup has
/// received a synthetic `Connected` event with a full provision
/// reply. Leaves `current_step == Vta`, phase `Connected`,
/// `vta_session` populated, `did_method = DidMethod::Vta`. Callers
/// typically immediately `select_current()` to advance past the
/// Vta step.
fn prime_full_setup_connected() -> WizardApp {
    use crate::vta::{DiagStatus, Protocol, VtaEvent};
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Vta);
    pick_full_setup_online(&mut app);
    app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
    app.confirm_text_input();
    app.confirm_text_input();
    app.text_input = tui_input::Input::new("https://mediator.example.com".into());
    app.confirm_text_input();
    app.select_current(); // → Testing (runner spawned, we'll detach)
    let st = app.vta_connect.as_mut().unwrap();
    st.event_rx = None;
    st.apply_event(VtaEvent::CheckDone(
        crate::vta::DiagCheck::AuthenticateDIDComm,
        DiagStatus::Ok("ok".into()),
    ));
    st.apply_event(VtaEvent::Connected {
        protocol: Protocol::DidComm,
        rest_url: Some("https://vta.example.com".into()),
        mediator_did: Some("did:webvh:mediator.vta.example.com".into()),
        reply: vta_sdk::provision_client::VtaReply::Full(Box::new(
            vta_sdk::provision_client::test_helpers::sample_provision_result_v2(true, false),
        )),
    });
    app
}

#[tokio::test]
async fn did_step_auto_skipped_on_full_setup_online() {
    // After VTA FullSetup provisions the DID, the Did step has
    // nothing left for the operator to decide — apply_vta_defaults
    // already pinned did_method = DidMethod::Vta and vta_session carries
    // the rendered DID doc + keys. `advance` should jump straight
    // from Protocol to Security (the step after Did).
    let mut app = prime_full_setup_connected();
    app.select_current(); // Vta → Protocol
    assert_eq!(app.current_step, WizardStep::Protocol);
    app.select_current(); // Protocol → (auto-skip Did) → Security
    assert_eq!(app.current_step, WizardStep::Security);
    // Did still marked completed so the progress bar reflects the
    // full walk, not a gap.
    assert!(app.completed_steps().contains(&WizardStep::Did));
}

#[test]
fn admin_options_exclude_vta_on_offline_export() {
    // OfflineExport's bundle carries an auto-minted admin
    // credential meant for mediator↔VTA auth only. Reusing it
    // as the mediator's own admin-API identity overloads one
    // key across two trust scopes, so the "Generate admin DID
    // from VTA" option must NOT appear in the Admin step
    // picker for this intent — and the default mode must be
    // AdminMode::Generate, not AdminMode::Vta.
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = true;
    app.vta_intent_choice = Some(VtaIntent::OfflineExport);
    app.apply_vta_defaults();
    assert_eq!(app.config.admin_did_mode, Some(AdminMode::Generate));

    assert!(!app.admin_options_include_vta());

    app.current_step = WizardStep::Admin;
    let opts = app.current_options();
    assert_eq!(opts.len(), 3, "generate / paste / skip — no VTA entry");
    assert!(!opts.iter().any(|o| o.label.contains("VTA")));
}

#[test]
fn admin_options_include_vta_on_full_setup() {
    // FullSetup's admin-DID rollover is a deliberate handoff
    // of a fresh mediator-admin DID — keep the "Generate admin
    // DID from VTA" option available and default to it.
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = true;
    app.vta_intent_choice = Some(VtaIntent::FullSetup);
    app.apply_vta_defaults();
    assert_eq!(app.config.admin_did_mode, Some(AdminMode::Vta));
    assert!(app.admin_options_include_vta());

    app.current_step = WizardStep::Admin;
    let opts = app.current_options();
    assert_eq!(opts.len(), 4, "generate / paste / VTA / skip");
    assert!(opts.iter().any(|o| o.label.contains("VTA")));
}

#[test]
fn did_step_auto_skipped_on_offline_export() {
    // OfflineExport's ContextProvision reply carries the
    // mediator DID + keys the same way FullSetup's
    // TemplateBootstrap reply does — both should trigger the
    // Did-step auto-skip. Drive the predicate directly with a
    // synthetic VtaSession since the sealed-handoff entry flow
    // is interactive.
    use crate::vta::VtaSession;
    use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::did_secrets::SecretEntry;
    use vta_sdk::keys::KeyType;

    let bundle = ContextProvisionBundle {
        context_id: "mediator-local".into(),
        context_name: "Mediator local".into(),
        vta_url: Some("https://vta.example.com".into()),
        vta_did: Some("did:webvh:vta.example.com".into()),
        credential: CredentialBundle::new(
            "did:key:z6MkAdmin",
            "zAdminPrivate",
            "did:webvh:vta.example.com",
        ),
        admin_did: "did:key:z6MkAdmin".into(),
        did: Some(ProvisionedDid {
            id: "did:webvh:mediator.example.com".into(),
            did_document: None,
            log_entry: None,
            secrets: vec![SecretEntry {
                key_id: "did:webvh:mediator.example.com#key-0".into(),
                key_type: KeyType::Ed25519,
                private_key_multibase: "zSigning".into(),
            }],
        }),
    };

    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = true;
    app.config.did_method = Some(DidMethod::Vta);
    app.vta_session = Some(VtaSession::context_export("mediator-local".into(), bundle));

    // Predicate must fire with the ContextExport shape too —
    // this is the regression the earlier `as_full_provision`-only
    // check caused.
    app.current_step = WizardStep::Did;
    assert!(
        app.should_auto_skip_step(),
        "OfflineExport session with did_method=Some(DidMethod::Vta) must auto-skip the Did step"
    );
}

#[tokio::test]
async fn did_step_back_nav_skips_past_on_full_setup_online() {
    // Coming back the other way should land on Protocol, not on
    // the auto-skipped Did step — same predicate, same behaviour.
    let mut app = prime_full_setup_connected();
    app.select_current(); // Vta → Protocol
    app.select_current(); // Protocol → Security (Did skipped)
    assert_eq!(app.current_step, WizardStep::Security);
    app.go_back(); // Security → (skip Did) → Protocol
    assert_eq!(app.current_step, WizardStep::Protocol);
}

#[test]
fn did_step_not_skipped_without_vta_session() {
    // Sanity: the skip predicate requires all three of
    // `use_vta`, `did_method == DidMethod::Vta`, and a Full provision
    // reply on `vta_session`. Without a VTA session (e.g. No-VTA
    // path, or mid-flow before provisioning succeeds) the Did
    // step must still appear.
    let mut app = WizardApp::new("test.toml".into());
    advance_to(&mut app, WizardStep::Did);
    assert_eq!(app.current_step, WizardStep::Did);
}

// ── #179: one table per step ──────────────────────────────────────

/// Every option of a table-driven step round-trips: picking index `i`
/// stores a value whose default highlight is `i` again.
#[test]
fn every_table_entry_round_trips_through_its_default_index() {
    for (i, choice) in KEY_STORAGE_CHOICES.iter().enumerate() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = i;
        app.select_current();
        assert_eq!(app.config.secret_storage, Some(choice.value));
        app.current_step = WizardStep::KeyStorage;
        assert_eq!(app.default_selection_index(), i, "{:?}", choice.value);
        assert_eq!(app.current_options()[i].label, choice.label);
    }
    for (i, choice) in DEPLOYMENT_CHOICES.iter().enumerate() {
        let mut app = WizardApp::new("test.toml".into());
        app.selection_index = i;
        app.select_current();
        assert_eq!(app.config.deployment_type, Some(choice.value));
        app.current_step = WizardStep::Deployment;
        assert_eq!(app.default_selection_index(), i);
    }
    for (i, choice) in SSL_CHOICES.iter().enumerate() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Security;
        app.selection_index = i;
        app.select_current();
        assert_eq!(app.config.ssl_mode, Some(choice.value));
        assert_eq!(app.default_selection_index(), i);
    }
    for use_vta in [false, true] {
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = use_vta;
        app.config.did_method = Some(DidMethod::Vta);
        for (i, choice) in app.did_choices().iter().enumerate() {
            let mut app = WizardApp::new("test.toml".into());
            app.config.use_vta = use_vta;
            app.config.did_method = Some(DidMethod::Vta);
            app.current_step = WizardStep::Did;
            app.selection_index = i;
            app.select_current();
            assert_eq!(app.config.did_method, Some(choice.value));
            app.current_step = WizardStep::Did;
            // The highlight lands on the chosen method (the VTA row
            // itself comes and goes with it).
            let idx = app.default_selection_index();
            assert_eq!(app.did_choices()[idx].value, choice.value);
        }
        for (i, choice) in app.admin_choices().iter().enumerate() {
            let mut a = WizardApp::new("test.toml".into());
            a.config.use_vta = use_vta;
            a.current_step = WizardStep::Admin;
            a.selection_index = i;
            a.select_current();
            assert_eq!(a.config.admin_did_mode, Some(choice.value));
            a.current_step = WizardStep::Admin;
            assert_eq!(a.default_selection_index(), i);
        }
    }
}

#[test]
fn returning_to_key_storage_after_file_highlights_file_not_k8s() {
    // Regression: the default-index table had `file:// => 5`, the
    // Kubernetes row; Enter there switched the backend.
    let mut app = WizardApp::new("test.toml".into());
    app.config.secret_storage = Some(SecretScheme::File);
    app.current_step = WizardStep::KeyStorage;
    let idx = app.default_selection_index();
    assert_eq!(KEY_STORAGE_CHOICES[idx].value, SecretScheme::File);
}

#[test]
fn no_vta_is_highlighted_for_a_non_vta_setup() {
    // Regression: `_ => 2 // No VTA` pointed at offline export.
    let mut app = WizardApp::new("test.toml".into());
    app.config.use_vta = false;
    app.current_step = WizardStep::Vta;
    let idx = app.default_selection_index();
    assert_eq!(VTA_INTENT_CHOICES[idx].value, None);
    assert_eq!(app.current_options()[idx].label, "No VTA");
}

#[test]
fn re_editing_the_certificate_path_does_not_overwrite_the_key() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Security;
    app.selection_index = index_of(&SSL_CHOICES, SslMode::Existing).unwrap();
    app.select_current();
    app.text_input = Input::new("/tls/a.pem".into());
    app.confirm_text_input();
    app.text_input = Input::new("/tls/a.key".into());
    app.confirm_text_input();
    assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));

    // Back on the SSL list, re-pick "existing" and change the cert.
    app.security_phase = None;
    app.selection_index = index_of(&SSL_CHOICES, SslMode::Existing).unwrap();
    app.select_current();
    app.text_input = Input::new("/tls/b.pem".into());
    app.confirm_text_input();
    assert_eq!(app.config.ssl_cert_path, "/tls/b.pem");
    assert_eq!(
        app.config.ssl_key_path, "/tls/a.key",
        "the key must not change"
    );
    assert_eq!(app.ssl_field, Some(SslField::Key));
    assert_eq!(app.mode, InputMode::TextInput);
}

#[test]
fn empty_required_inputs_say_why() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::KeyStorage;
    app.config.secret_storage = Some(SecretScheme::Gcp);
    app.enter_key_storage_phase(KeyStoragePhase::GcpProject);
    app.text_input = Input::new(String::new());
    app.confirm_text_input();
    assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::GcpProject));
    assert!(app.input_error.as_deref().unwrap().contains("GCP project"));

    app.enter_key_storage_phase(KeyStoragePhase::FileGate);
    app.text_input = Input::new("yes".into());
    app.confirm_text_input();
    assert!(
        app.input_error
            .as_deref()
            .unwrap()
            .contains(FILE_GATE_PHRASE)
    );
}

#[test]
fn re_entering_the_vta_step_discards_the_session_with_a_warning() {
    let mut app = WizardApp::new("test.toml".into());
    app.vta_session = Some(VtaSession::admin_only(
        "mediator".into(),
        "did:webvh:vta.example.com".into(),
        None,
        None,
        "did:key:z6MkAdmin".into(),
        "zKey".into(),
    ));
    app.current_step = WizardStep::Protocol;
    assert!(app.step_back_auto_skipping());
    assert_eq!(app.current_step, WizardStep::Vta);
    assert!(app.vta_session.is_none());
    assert!(
        app.vta_stub_notice
            .as_deref()
            .unwrap()
            .contains("remains on the VTA side")
    );
}

#[test]
fn deployment_info_matches_the_applied_defaults() {
    // Local stays open; server and container start closed.
    for (i, expected) in [
        (0, NETWORK_MODE_OPEN),
        (1, NETWORK_MODE_CLOSED),
        (2, NETWORK_MODE_CLOSED),
    ] {
        let mut app = WizardApp::new("test.toml".into());
        app.selection_index = i;
        app.select_current();
        assert_eq!(app.config.network_mode, expected);
        let info = DEPLOYMENT_CHOICES[i].info;
        assert!(!info.contains("did:peer, inline secrets"));
        assert!(info.contains(if expected == NETWORK_MODE_OPEN {
            "open"
        } else {
            "closed"
        }));
    }
}

// ── #173: admin identity ──────────────────────────────────────────

#[test]
fn pasting_an_admin_did_is_a_real_prompt() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Admin;
    app.selection_index = index_of(&app.admin_choices(), AdminMode::Paste).unwrap();
    app.select_current();
    assert_eq!(app.mode, InputMode::TextInput);
    assert_eq!(app.current_step, WizardStep::Admin);

    app.text_input = Input::new("not-a-did".into());
    app.confirm_text_input();
    assert_eq!(app.current_step, WizardStep::Admin, "a bad DID is refused");
    assert!(app.input_error.is_some());

    app.text_input = Input::new("did:key:z6MkPasted".into());
    app.confirm_text_input();
    assert_eq!(app.config.admin_did, "did:key:z6MkPasted");
    assert_eq!(app.config.admin_did_mode, Some(AdminMode::Paste));
    assert_eq!(app.current_step, WizardStep::Output);
}

// ── #158: quitting with a session, Esc during a flight ────────────

#[test]
fn quitting_with_a_vta_session_asks_first() {
    let mut app = WizardApp::new("test.toml".into());
    app.request_quit();
    assert!(app.should_quit, "no session: quit at once");

    let mut app = WizardApp::new("test.toml".into());
    app.vta_session = Some(VtaSession::admin_only(
        "mediator".into(),
        "did:webvh:vta.example.com".into(),
        None,
        None,
        "did:key:z6MkAdmin".into(),
        "zKey".into(),
    ));
    app.request_quit();
    assert!(!app.should_quit);
    assert!(app.quit_confirm_pending());
    app.answer_quit_confirm(false);
    assert!(!app.should_quit && !app.quit_confirm_pending());
    app.request_quit();
    app.answer_quit_confirm(true);
    assert!(app.should_quit);
}

#[tokio::test]
async fn esc_during_a_flight_aborts_the_task() {
    let mut app = WizardApp::new("test.toml".into());
    app.current_step = WizardStep::Vta;
    app.enter_vta_subflow(VtaIntent::FullSetup);
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    if let Some(st) = app.vta_connect.as_mut() {
        st.phase = ConnectPhase::Testing;
        st.event_rx = Some(rx);
    }
    let task = tokio::spawn(std::future::pending::<()>());
    let abort = task.abort_handle();
    app.vta_task = Some(task);
    assert!(app.provision_in_flight());
    app.go_back();
    tokio::task::yield_now().await;
    assert!(
        abort.is_finished(),
        "the flight must be aborted, not just unheard"
    );
    assert!(!app.provision_in_flight());
}

// ── #158: the backend is checked when KeyStorage completes ────────

async fn settle(app: &mut WizardApp) {
    for _ in 0..200 {
        app.drain_background();
        if !app.backend_check_running() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("backend check did not finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn key_storage_checks_the_backend_before_moving_on() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets.json");
    let mut app = WizardApp::new("test.toml".into());
    app.live_backend = true;
    app.current_step = WizardStep::KeyStorage;
    app.config.secret_storage = Some(SecretScheme::File);
    app.config.secret_file_path = secrets.to_string_lossy().into_owned();
    app.advance();
    assert!(app.backend_check_running());
    assert_eq!(app.current_step, WizardStep::KeyStorage);
    settle(&mut app).await;
    assert_eq!(app.current_step, WizardStep::Vta, "{:?}", app.backend_check);

    // A backend that already holds a mediator is refused on the spot.
    let store = crate::secret_backend::open_secret_backend(
        &crate::config_writer::build_backend_url(&app.config),
        None,
    )
    .unwrap();
    store.store_jwt_secret(b"existing").await.unwrap();
    let mut app2 = WizardApp::new("test.toml".into());
    app2.live_backend = true;
    app2.current_step = WizardStep::KeyStorage;
    app2.config = app.config.clone();
    app2.advance();
    settle(&mut app2).await;
    assert_eq!(app2.current_step, WizardStep::KeyStorage);
    assert!(matches!(
        app2.backend_check,
        Some(BackendCheck::Failed(ref e)) if e.contains("--force-reprovision")
    ));
}

// ── #176: every secret backend has its build feature ──────────────

#[test]
fn every_secret_backend_maps_to_its_build_feature() {
    for (scheme, feature) in [
        (SecretScheme::Keyring, Some("secrets-keyring")),
        (SecretScheme::Aws, Some("secrets-aws")),
        (SecretScheme::Gcp, Some("secrets-gcp")),
        (SecretScheme::Azure, Some("secrets-azure")),
        (SecretScheme::Vault, Some("secrets-vault")),
        (SecretScheme::K8s, Some("secrets-k8s")),
        (SecretScheme::File, None),
    ] {
        let config = WizardConfig {
            secret_storage: Some(scheme),
            ..WizardConfig::default()
        };
        let features = config.cargo_features();
        let secret_features: Vec<_> = features
            .iter()
            .filter(|f| f.starts_with("secrets-"))
            .collect();
        match feature {
            Some(f) => assert_eq!(secret_features, vec![&f], "{scheme:?}"),
            None => assert!(secret_features.is_empty(), "{scheme:?}"),
        }
    }
    // And the table offers no backend the mapping misses.
    for choice in KEY_STORAGE_CHOICES {
        assert!(
            choice.value == SecretScheme::File
                || WizardConfig {
                    secret_storage: Some(choice.value),
                    ..WizardConfig::default()
                }
                .cargo_features()
                .iter()
                .any(|f| f.starts_with("secrets-")),
            "{:?} has no build feature",
            choice.value
        );
    }
}

#[test]
fn keyring_is_flagged_for_containers() {
    let mut app = WizardApp::new("test.toml".into());
    app.config.deployment_type = Some(Deployment::Container);
    app.current_step = WizardStep::KeyStorage;
    let idx = index_of(&KEY_STORAGE_CHOICES, SecretScheme::Keyring).unwrap();
    assert!(
        app.current_options()[idx]
            .label
            .contains("not available inside a container")
    );
}
