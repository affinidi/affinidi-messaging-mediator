/// Serialises every test that reads or writes the process-wide current
/// directory.
///
/// `CwdGuard` (here and in `bootstrap_headless`) calls
/// `std::env::set_current_dir`, which is **process-global** — but tests run in
/// parallel threads, so a guard in one test silently relocates every other
/// test's notion of "." while it is held. `config_writer`'s
/// `test_all_secret_storage_refs` reads `current_dir()` to build its expected
/// value, so it could observe a temp dir mid-swap and compare a canonicalised
/// `/private/var/...` against a `/var/...` the generator resolved a moment
/// earlier.
///
/// The race has been latent: it depends entirely on how the harness happens to
/// interleave the threads, and adding one unrelated test to the binary was
/// enough to make it fire. Every CWD-touching test takes this lock, so the
/// interleaving stops mattering.
#[cfg(test)]
pub(crate) fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A poisoned lock means some other CWD test panicked. The directory is
    // restored on drop regardless, so continuing is correct — refusing here
    // would turn one failure into a cascade of unrelated ones.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[macro_use]
mod style;

mod admin_monitor_profile;
mod app;
mod bootstrap_headless;
mod cli;
mod clipboard;
mod config_writer;
mod consts;
mod discovery;
mod docker;
mod exit;
mod exit_recap;
mod generators;
mod headless;
mod publish;
mod recipe;
mod reprovision;
mod sealed_handoff;
mod secret_backend;
mod secure_fs;
mod ui;
mod vta;

use std::{
    io::{self, Stdout, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use crossterm::event::EventStream;
use ratatui::{
    crossterm::{
        event::{
            DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, Event, KeyCode,
            KeyEventKind, KeyModifiers,
        },
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
};
use tokio_stream::StreamExt;
use tui_input::InputRequest;

use app::{InputMode, WizardApp, WizardConfig};
use cli::Args;
use consts::*;

const RENDERING_TICK_RATE: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = exit::code_of(&e);
            err!("\n\x1b[31mError:\x1b[0m {e:#}");
            std::process::ExitCode::from(code)
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    // Headless modes write to a plain terminal or a CI log, so their
    // `tracing` diagnostics (sweep and cleanup failures, the trust
    // posture of a sealed bundle) go to stderr. The TUI gets no
    // subscriber: output there would draw over the alternate screen.
    let headless = args.from.is_some()
        || args.non_interactive
        || args.uninstall
        || args.setup_key_out.is_some()
        || args.setup_key_file.is_some();
    if headless {
        init_headless_logging();
    }

    // `--uninstall` is mutually exclusive with every other mode (clap
    // enforces it), so flag combinations can't re-provision after teardown.
    if args.uninstall {
        return reprovision::run_uninstall(&args.config_path()).await;
    }

    // Two-phase online admin-only VTA setup.
    if let Some(path) = args.setup_key_out.as_ref() {
        return vta::cli::run_phase1_init(
            path,
            args.vta_did.as_deref(),
            args.vta_context.as_deref(),
            args.mediator_url.as_deref(),
            args.did_method,
        )
        .await;
    }
    if let Some(path) = args.setup_key_file.as_ref() {
        return run_setup_key_phase2(&args, path).await;
    }

    if args.from.is_some() || args.non_interactive {
        return run_headless(&args).await;
    }
    if !args.set.is_empty() {
        anyhow::bail!(
            "--set overrides a recipe value, so it applies to headless runs only \
             (--from <recipe> or --non-interactive)"
        );
    }
    run_tui(&args).await
}

/// The interactive wizard.
async fn run_tui(args: &Args) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(exit::error(
            exit::NOT_A_TERMINAL,
            "the interactive wizard needs a terminal (stdin and stdout). For scripted \
             setups describe the mediator in a recipe and run `mediator-setup --from \
             <recipe.toml>`, or pass `--non-interactive --did-method <peer|webvh>` with the \
             other options as flags. See docs/setup-guide.md.",
        ));
    }

    // Early, friendly re-run check against the existing config's backend,
    // before the operator spends time in the wizard. The binding check runs
    // again against the backend actually chosen, right before anything is
    // written (`open_guarded_backend`).
    let config_path = args.config_path();
    guard_existing_setup(Path::new(&config_path), args.force_reprovision).await?;

    let mut app = WizardApp::new(config_path);
    apply_tui_prefill(args, &mut app.config);
    app.vta_did_prefill = args.vta_did.clone();
    app.vta_context_prefill = args.vta_context.clone();
    app.force_reprovision = args.force_reprovision;
    app.live_backend = true;

    let mut terminal = setup_terminal()?;
    let result = run_event_loop(&mut terminal, &mut app).await;
    restore_terminal(&mut terminal)?;
    result?;

    if !app.write_config {
        out!("\n\x1b[33mSetup cancelled.\x1b[0m");
        if app.vta_session.is_some() {
            out!(
                "  The VTA session's admin credential was stored in the secret backend when it \
                 connected; the VTA-side state (minted DID, used setup ACL) remains."
            );
        }
        return Ok(());
    }

    print_banner();
    out!("  Generating cryptographic material...\n");
    let options = GenerateOptions {
        save_recipe: true,
        probe: secret_backend::ProvisionProbe::ReadWrite,
        force_reprovision: args.force_reprovision,
        show_admin_key: args.show_admin_key,
    };
    match generate_and_write_with(&app.config, app.vta_session.as_ref(), &options).await {
        Ok(completed) => {
            // Clean up the sealed-handoff request file if the setup went
            // through that flow. No-op otherwise.
            if let Some(ref artefacts) = app.tui_bootstrap_artifacts {
                bootstrap_headless::cleanup_artifacts(artefacts);
            }
            offer_build_and_guidance(&app.config);
            // The structured recap goes to normal stdout (the alt-screen
            // has been left) so the operator can scroll back and select
            // DIDs / paths / commands.
            exit_recap::print_exit_recap(&app.config, app.vta_session.as_ref());
            completed.into_result()
        }
        Err(e) => {
            save_resume_recipe(&app.config, app.vta_session.is_some());
            Err(e)
        }
    }
}

/// After a failure past the TUI, keep the operator's answers: write them as
/// a recipe and say how to resume, so nothing has to be re-entered.
fn save_resume_recipe(config: &WizardConfig, had_vta_session: bool) {
    let name = "mediator-build.resume.toml";
    let in_config_dir = config_writer::config_dir(config).join(name);
    let body = recipe::from_wizard_config(config);
    let written = secure_fs::create_private_dir_all(&config_writer::config_dir(config))
        .and_then(|()| secure_fs::write_sensitive(&in_config_dir, &body))
        .map(|()| in_config_dir)
        .or_else(|_| {
            let fallback = std::env::temp_dir().join(name);
            secure_fs::write_sensitive(&fallback, &body).map(|()| fallback)
        });
    match written {
        Ok(path) => {
            err!(
                "\n  Your answers were saved to \x1b[1m{}\x1b[0m.",
                path.display()
            );
            if config.use_vta && config.vta_mode == VTA_MODE_ONLINE {
                err!(
                    "  An online VTA session cannot be replayed from a recipe. {}Re-run \
                     `mediator-setup` to finish; pass --force-reprovision if the backend now \
                     holds this run's entries.",
                    if had_vta_session {
                        "Its admin credential was stored in the secret backend when it \
                         connected. "
                    } else {
                        ""
                    }
                );
            } else {
                err!(
                    "  Fix the problem above, then resume with:\n    \x1b[36mmediator-setup \
                     --from {} --force-reprovision\x1b[0m\n  (--force-reprovision is needed \
                     only if the backend already received this run's entries.)",
                    path.display()
                );
            }
        }
        Err(e) => err!("  Could not save your answers as a recipe: {e}"),
    }
}

/// Apply CLI arguments to the interactive wizard as pre-filled defaults.
fn apply_tui_prefill(args: &Args, config: &mut WizardConfig) {
    if let Some(ref deployment) = args.deployment {
        config.deployment_type = deployment.to_string();
    }
    if let Some(ref protocol) = args.protocol {
        match protocol {
            // TSP is on by default, so naming DIDComm is how a pre-fill opts
            // out of it — the same result `--protocol didcomm` always gave.
            cli::Protocol::Didcomm => {
                config.didcomm_enabled = true;
                config.tsp_enabled = false;
            }
            cli::Protocol::Tsp => {
                config.tsp_enabled = true;
            }
        }
    }
    if let Some(ref did_method) = args.did_method {
        config.did_method = did_method.to_string();
    }
    if let Some(ref public_url) = args.public_url {
        config.public_url = public_url.clone();
    }
    if args.save_did_web {
        config.save_did_web = true;
    }
    if args.present_as_scid {
        config.present_as_scid = true;
    }
    if args.no_scid_alias {
        config.scid_also_known_as = false;
    }
    if !args.key_suite.is_empty() {
        config.key_suite = args.key_suite.clone();
    }
    if let Some(ref secret_storage) = args.secret_storage {
        config.secret_storage = secret_storage.to_string();
    }
    if let Some(ref ssl) = args.ssl {
        config.ssl_mode = ssl.to_string();
    }
    if let Some(ref database_url) = args.database_url {
        config.database_url = database_url.clone();
    }
    if let Some(admin) = args.admin {
        config.admin_did_mode = match admin {
            cli::AdminMode::Generate => ADMIN_GENERATE,
            cli::AdminMode::Vta => ADMIN_VTA,
            cli::AdminMode::Skip => ADMIN_SKIP,
        }
        .into();
    }
    if let Some(ref did) = args.admin_did {
        config.admin_did_mode = ADMIN_PASTE.into();
        config.admin_did = did.clone();
    }
    if let Some(ref listen_address) = args.listen_address {
        config.listen_address = listen_address.clone();
    }
}

/// Early re-run check for the interactive wizard: refuse when the backend
/// named by the existing `mediator.toml` already holds a provisioned
/// mediator, unless `--force-reprovision` is set. Skipped when the operator
/// has already opted in (the scan can trigger a macOS Keychain prompt).
async fn guard_existing_setup(config_path: &Path, force_reprovision: bool) -> anyhow::Result<()> {
    if force_reprovision {
        return Ok(());
    }
    if let Some(setup) = reprovision::inspect_existing(config_path).await?
        && setup.is_provisioned()
    {
        return Err(reprovision::refusal(
            &setup.backend_url,
            &setup.provisioned_keys,
            Some(config_path),
        ));
    }
    Ok(())
}

/// A human description of what the admin choice will produce.
fn admin_summary(config: &WizardConfig) -> String {
    match config.admin_did_mode.as_str() {
        ADMIN_SKIP => "Skip (no admin DID)".into(),
        ADMIN_PASTE => format!("Existing DID {}", config.admin_did),
        ADMIN_VTA => "VTA-issued credential (also the mediator↔VTA credential)".into(),
        ADMIN_GENERATE if config.use_vta => {
            "Generate did:key (separate from the VTA credential)".into()
        }
        ADMIN_GENERATE => "Generate did:key".into(),
        _ => "None".into(),
    }
}

/// The network posture, spelled out — it decides who can message whom.
fn network_summary(config: &WizardConfig) -> String {
    if config.network_mode == NETWORK_MODE_CLOSED {
        "\x1b[1mCLOSED\x1b[0m — DIDs exchange messages only with an explicit ACL grant".into()
    } else {
        "\x1b[1;33mOPEN\x1b[0m — any DID can message any other DID (ACL deny-list); use \
         `--set security.network_mode=closed` for an allow-list"
            .into()
    }
}

/// Print the shared "what we're about to generate" summary used by every
/// headless entry point, so they stay consistent.
fn print_config_summary(config: &WizardConfig) {
    out!("  Deployment:   {}", config.deployment_type);
    out!(
        "  VTA:          {}",
        if config.use_vta {
            format!("Enabled ({})", config.vta_mode)
        } else {
            "Disabled".into()
        }
    );
    out!("  Protocol:     {}", config.protocol_display());
    out!("  DID method:   {}", config.did_method);
    out!(
        "  Key storage:  {}",
        affinidi_messaging_mediator_common::redact::redact_url(&config_writer::build_backend_url(
            config
        ))
    );
    out!("  SSL/TLS:      {}", config.ssl_mode);
    if config.storage_backend == STORAGE_BACKEND_FJALL {
        out!("  Storage:      fjall ({})", config.fjall_data_dir);
    } else {
        out!(
            "  Database:     {}",
            affinidi_messaging_mediator_common::redact::redact_url(&config.database_url)
        );
    }
    out!("  Admin:        {}", admin_summary(config));
    out!("  Network:      {}", network_summary(config));
    out!("  Config file:  {}", config.config_path);
    out!("  Listen:       {}", config.listen_address);
}

/// `DATABASE_URL` from the environment overrides the recipe's Redis URL —
/// the way to supply credentials a recipe never stores. Reported either
/// way; ignored (and said so) for a Fjall setup.
fn apply_database_url_env(config: &mut WizardConfig) -> anyhow::Result<()> {
    match std::env::var("DATABASE_URL") {
        Ok(env_url) if config.storage_backend == STORAGE_BACKEND_FJALL => {
            let _ = env_url;
            out!("  \x1b[2mignored: DATABASE_URL (storage.backend = fjall)\x1b[0m");
        }
        Ok(env_url) => {
            config.database_url = env_url;
            out!("  \x1b[2moverride: database.url from DATABASE_URL\x1b[0m");
        }
        Err(_)
            if config.storage_backend != STORAGE_BACKEND_FJALL
                && recipe::needs_database_credentials(&config.database_url) =>
        {
            anyhow::bail!(
                "The database URL in the recipe needs credentials. Set the DATABASE_URL \
                 environment variable or update the recipe."
            );
        }
        Err(_) => {}
    }
    Ok(())
}

/// Warnings about choices that are legal but likely wrong for the
/// deployment type.
fn print_deployment_warnings(config: &WizardConfig) {
    if config.deployment_type == DEPLOYMENT_CONTAINER && config.secret_storage == STORAGE_KEYRING {
        err!(
            "  \x1b[33mWarning:\x1b[0m keyring:// is the OS keyring of the machine running \
             the wizard; a container has none. The mediator in the container will not find \
             its keys — pick a secret manager or k8s:// instead."
        );
    }
}

/// `--from <recipe>` and `--non-interactive`: build the recipe from the
/// file, the shorthand flags and `--set`, then run the same pipeline the
/// TUI does. Never prompts and never reads stdin.
async fn run_headless(args: &Args) -> anyhow::Result<()> {
    let mode = if args.from.is_some() {
        headless::Mode::Recipe
    } else {
        headless::Mode::Flags
    };
    let built = headless::build(args, mode)?;
    let mut config = recipe::to_wizard_config(&built.recipe)?;

    print_banner();
    match &args.from {
        Some(path) => out!("  \x1b[2mFrom recipe: {path}\x1b[0m"),
        None => out!("  \x1b[2mNon-interactive: flags only\x1b[0m"),
    }
    for note in &built.notes {
        out!("  \x1b[2m{note}\x1b[0m");
    }
    apply_database_url_env(&mut config)?;
    out!();
    print_config_summary(&config);
    print_deployment_warnings(&config);
    out!();

    let force_reprovision = args.force_reprovision;
    let sealed = config.use_vta
        && matches!(
            config.vta_mode.as_str(),
            VTA_MODE_SEALED_MINT | VTA_MODE_SEALED_EXPORT
        );
    if args.bundle.is_some() && !sealed {
        anyhow::bail!(
            "--bundle is phase 2 of a sealed handoff, but this recipe is not a sealed one \
             (deployment.use_vta = true with vta_mode = \"sealed-mint\" or \"sealed-export\")"
        );
    }
    if config.use_vta && !sealed {
        return Err(exit::error(
            exit::NO_VTA_SESSION,
            format!(
                "{} needs a VTA session, which a headless run can only get from a sealed \
                 handoff. Use a recipe with vta_mode = \"sealed-mint\" (or \"sealed-export\"), \
                 the --setup-key-out / --setup-key-file pair (admin credential only, with \
                 --did-method peer|webvh), or the interactive wizard.",
                if config.did_method == DID_VTA {
                    "A VTA-managed mediator DID".to_string()
                } else {
                    format!("vta_mode = \"{}\"", config.vta_mode)
                }
            ),
        ));
    }

    let options = GenerateOptions {
        // Never overwrite the recipe this run was given.
        save_recipe: args.from.is_none(),
        // Headless flows request a read-only probe; it takes effect only for
        // `aws_secrets://` (entries pre-created out-of-band), see
        // `open_and_probe_secret_backend`.
        probe: secret_backend::ProvisionProbe::ReadOnly,
        force_reprovision,
        show_admin_key: args.show_admin_key,
    };

    let completed = if sealed {
        use bootstrap_headless::HeadlessOutcome;
        let outcome = bootstrap_headless::dispatch(
            &config,
            args.bundle.as_deref(),
            bootstrap_headless::DispatchOptions {
                digest: args.digest.as_deref(),
                allow_without_digest: args.allow_bundle_without_digest,
                force_reprovision,
            },
        )
        .await?;
        match outcome {
            HeadlessOutcome::RequestEmitted {
                request_path,
                bundle_id_hex,
                producer_command,
                pnm_command,
            } => {
                print_phase1_next_steps(
                    args.from.as_deref().unwrap_or("<recipe.toml>"),
                    &request_path,
                    &bundle_id_hex,
                    &producer_command,
                    &pnm_command,
                );
                return Ok(());
            }
            HeadlessOutcome::Applied { session, artifacts } => {
                out!("  Generating cryptographic material...\n");
                let completed = generate_and_write_with(&config, Some(&session), &options).await?;
                // Only now that everything is written is the ephemeral seed
                // (and the request file) disposable.
                bootstrap_headless::finish_applied(&config, &artifacts).await;
                out!(
                    "  \x1b[32m\u{2714}\x1b[0m Setup artefacts removed — the mediator has \
                     everything it needs in the configured secret backend.\n"
                );
                completed
            }
        }
    } else {
        out!("  Generating cryptographic material...\n");
        generate_and_write_with(&config, None, &options).await?
    };

    install_or_print_commands(
        &config,
        built.recipe.install.enabled,
        built.recipe.install.path.as_deref(),
    )?;
    print_final_summary(&config, options.save_recipe);
    completed.into_result()
}

/// `--setup-key-file`: authenticate to the VTA with the phase-1 did:key,
/// then provision the mediator with the resulting admin-only session.
async fn run_setup_key_phase2(args: &Args, key_path: &Path) -> anyhow::Result<()> {
    let vta_did = vta::cli::validate_phase2_args(&args.vta_did)?;
    let mediator_url = args.mediator_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "--mediator-url is required for --setup-key-file: it is the public URL the \
             mediator serves at."
        )
    })?;

    // Build and validate the configuration before contacting the VTA, so a
    // flag mistake costs nothing on the VTA side.
    let built = headless::build(args, headless::Mode::SetupKey)?;
    let mut config = recipe::to_wizard_config(&built.recipe)?;
    if config.did_method == DID_VTA {
        return Err(exit::error(
            exit::NO_VTA_SESSION,
            "--setup-key-file obtains an admin credential only; the mediator brings its own \
             DID. Pass --did-method peer or webvh (a VTA-minted DID needs a sealed-mint \
             recipe or the interactive wizard).",
        ));
    }
    config.use_vta = true;
    config.vta_mode = VTA_MODE_ONLINE.into();
    if let Some(ctx) = &args.vta_context {
        config.vta_context = ctx.clone();
    }
    for note in &built.notes {
        out!("  \x1b[2m{note}\x1b[0m");
    }
    apply_database_url_env(&mut config)?;
    out!();
    print_config_summary(&config);
    print_deployment_warnings(&config);

    let session = vta::cli::run_phase2_connect(
        key_path,
        vta_did,
        Some(&config.vta_context),
        mediator_url,
        args.wait_for_acl,
    )
    .await
    .map_err(|e| {
        let code = match e.kind {
            vta::cli::HeadlessFailureKind::NoTransport => exit::VTA_NO_TRANSPORT,
            vta::cli::HeadlessFailureKind::PostAuthFailed => exit::VTA_POST_AUTH,
        };
        exit::error(code, e.to_string())
    })?;

    out!("\n  Generating cryptographic material...\n");
    let options = GenerateOptions {
        save_recipe: args.from.is_none(),
        probe: secret_backend::ProvisionProbe::ReadOnly,
        force_reprovision: args.force_reprovision,
        show_admin_key: args.show_admin_key,
    };
    let completed = generate_and_write_with(&config, Some(&session), &options).await?;

    // The setup did:key is now the long-term admin credential, stored in
    // the secret backend; the plaintext copy in the key file must go.
    match std::fs::remove_file(key_path) {
        Ok(()) => out!(
            "  \x1b[32m\u{2714}\x1b[0m Removed the setup key file {} (the credential now lives \
             in the secret backend).",
            key_path.display()
        ),
        Err(e) => err!(
            "  \x1b[33mWarning:\x1b[0m could not remove the setup key file {}: {e}. It holds \
             the mediator's VTA admin key — delete it by hand.",
            key_path.display()
        ),
    }
    install_or_print_commands(&config, false, None)?;
    print_final_summary(&config, options.save_recipe);
    completed.into_result()
}

/// Run `cargo install` when the recipe asks for it, otherwise print the
/// install and build commands. Never prompts.
fn install_or_print_commands(
    config: &WizardConfig,
    install: bool,
    install_root: Option<&str>,
) -> anyhow::Result<()> {
    let features = config.cargo_features();
    let needs_explicit = config.needs_explicit_features();

    if !install {
        let install_cmd = format!(
            "cargo {}",
            build_install_args(&features, needs_explicit, None).join(" ")
        );
        let build_cmd = format!(
            "cargo {}",
            build_cargo_args(&features, needs_explicit).join(" ")
        );
        out!("  \x1b[1mTo install:\x1b[0m\n    \x1b[36m{install_cmd}\x1b[0m\n");
        out!("  \x1b[1mTo build from source:\x1b[0m\n    \x1b[36m{build_cmd}\x1b[0m\n");
        return Ok(());
    }

    let install_args = build_install_args(&features, needs_explicit, install_root);
    let install_cmd = format!("cargo {}", install_args.join(" "));
    let build_dir = find_workspace_root()
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root for cargo install"))?;
    let install_location = install_root.map(|r| format!("{r}/bin")).unwrap_or_else(|| {
        let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "~/.cargo".into());
        format!("{cargo_home}/bin")
    });

    out!("  \x1b[1mInstall command:\x1b[0m");
    out!(
        "    \x1b[2mcd\x1b[0m \x1b[36m{}\x1b[0m",
        build_dir.display()
    );
    out!("    \x1b[36m{install_cmd}\x1b[0m\n");
    out!(
        "  \x1b[38;5;69mInstalling mediator to {install_location} \
         (this may take a few minutes)...\x1b[0m\n"
    );

    let status = Command::new("cargo")
        .args(&install_args)
        .current_dir(&build_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            out!("\n  \x1b[32m\u{2714} Installation successful!\x1b[0m\n");
            print_run_command(&config.config_path, &install_location);
            Ok(())
        }
        Ok(exit) => anyhow::bail!("cargo install failed with exit code: {exit}"),
        Err(e) => anyhow::bail!("Failed to run cargo: {e}"),
    }
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut WizardApp,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(RENDERING_TICK_RATE);
    let mut crossterm_events = EventStream::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Pick up any events from the online-VTA runner task so
                // the diagnostic checklist updates without waiting on a
                // keypress.
                app.drain_vta_events();
                // Same idea for the F5-triggered cloud-backend
                // discovery: result lands on a tokio mpsc and the
                // wizard transitions Loading → Loaded / Failed.
                app.drain_discovery_events();
                // The KeyStorage backend check and the VTA-session
                // persistence run on spawned tasks too.
                app.drain_background();
            }
            maybe_event = crossterm_events.next() => match maybe_event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    handle_key_event(app, key.code, key.modifiers);
                },
                Some(Ok(Event::Paste(text))) => {
                    app.paste_text(&text);
                },
                None => break,
                _ => (),
            },
        }

        if app.should_quit {
            break;
        }

        terminal
            .draw(|frame| ui::render(frame, app))
            .context("could not render to the terminal")?;
    }

    Ok(())
}

fn handle_key_event(app: &mut WizardApp, code: KeyCode, modifiers: KeyModifiers) {
    let quit_key = code == KeyCode::F(10)
        || (code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL));

    // The quit confirmation (a VTA session exists) takes the next key:
    // `y` — or a second Ctrl+C / F10 — quits, anything else stays.
    if app.quit_confirm_pending() {
        app.answer_quit_confirm(quit_key || matches!(code, KeyCode::Char('y' | 'Y')));
        return;
    }

    // F10 or Ctrl+C quits — at once, unless a VTA session would be lost.
    if quit_key {
        app.request_quit();
        return;
    }

    // Discovery overlay (cloud-backend secrets list via F5) takes
    // every key while it's on screen — Loading swallows everything
    // except Esc, Loaded scrolls / picks (Enter) / cancels (Esc),
    // Failed dismisses on any key. Placed before mode dispatch so
    // normal text-input keys don't leak into the input widget while
    // the overlay is active.
    if app.in_discovery_overlay() {
        app.handle_discovery_key(code);
        return;
    }

    // F5 on a discoverable key-storage phase kicks off the async
    // `list_namespace` call. Discoverable phases are AwsNamespace /
    // GcpNamespace / AzureVault / VaultMount; F5 anywhere else is a
    // no-op so the keystroke isn't actively misleading. The hint
    // footer on each prompt advertises the requirement (e.g. AWS
    // creds in the environment).
    if code == KeyCode::F(5) {
        app.kick_off_discovery();
        return;
    }

    // Bare `c` / `v` / `p` on the sealed-handoff RequestGenerated screen
    // copy one of: the bootstrap request JSON, the `vta bootstrap seal`
    // command, or the `pnm-cli bootstrap seal` command to the system
    // clipboard. Arrow / Page / Home keys scroll the panel — the
    // rendered content (VP JSON + commands + hotkey cheatsheet) exceeds
    // the viewport on smaller terminals. Placed ahead of the mode-based
    // dispatch so it fires in both Selecting and TextInput modes — the
    // RequestGenerated phase uses Selecting mode today, but keeping the
    // hotkey mode-agnostic is cheap and future-proofs against UI
    // shuffling.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('c')
                | KeyCode::Char('C')
                | KeyCode::Char('v')
                | KeyCode::Char('V')
                | KeyCode::Char('p')
                | KeyCode::Char('P')
                | KeyCode::Char('f')
                | KeyCode::Char('F')
                | KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
        )
        && app.in_sealed_handoff_subflow()
        && let Some(state) = app.sealed_handoff.as_mut()
        && state.phase == crate::sealed_handoff::SealedPhase::RequestGenerated
    {
        // Command-copy hotkeys: `v` always copies the `vta …`
        // flavour (the offline producer the wizard recommends for
        // FullSetup / OfflineExport), `p` always copies the
        // `pnm …` flavour (what an operator with an authenticated
        // pnm session against a live VTA runs). For AdminOnly the
        // two collapse — primary is already `pnm contexts bootstrap`.
        // `f` copies the fallback command when one exists.
        //
        // Scroll keys: one line (arrows) or 10 lines (Page).
        // 10 is a compromise between "obvious jump" and "don't
        // shoot past useful content in one keystroke"; the
        // panel is about 40–60 rendered lines typically.
        const PAGE: u16 = 10;
        match code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                state.copy_request_to_clipboard();
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_primary_command_to_clipboard();
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                state.copy_pnm_command_to_clipboard();
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                state.copy_fallback_command_to_clipboard();
            }
            KeyCode::Up => state.scroll_request_up(1),
            KeyCode::Down => state.scroll_request_down(1),
            KeyCode::PageUp => state.scroll_request_up(PAGE),
            KeyCode::PageDown => state.scroll_request_down(PAGE),
            KeyCode::Home => state.scroll_request_home(),
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `m` / `a` / `v` on the sealed-handoff Complete screen copy
    // the mediator / admin / VTA DIDs to the clipboard. Phase-scoped
    // to Complete so the same letters don't conflict with `[v]` /
    // `[p]` on the RequestGenerated screen above.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('m')
                | KeyCode::Char('M')
                | KeyCode::Char('a')
                | KeyCode::Char('A')
                | KeyCode::Char('v')
                | KeyCode::Char('V')
        )
        && app.in_sealed_handoff_subflow()
        && let Some(state) = app.sealed_handoff.as_mut()
        && state.phase == crate::sealed_handoff::SealedPhase::Complete
    {
        match code {
            KeyCode::Char('m') | KeyCode::Char('M') => {
                state.copy_mediator_did_to_clipboard();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                state.copy_admin_did_to_clipboard();
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_vta_did_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `c` / `C` on the online-VTA AwaitingAcl screen copies the
    // rendered `pnm acl create` command to the system clipboard. Same
    // early-return placement as the sealed-handoff hotkey so it fires
    // regardless of InputMode.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(code, KeyCode::Char('c') | KeyCode::Char('C'))
        && let Some(state) = app.vta_connect.as_mut()
        && state.phase == crate::vta::ConnectPhase::AwaitingAcl
    {
        state.copy_acl_command_to_clipboard();
        return;
    }

    // Bare `c` / `b` on the wizard's final Summary screen copy the
    // config-file path and the resolved backend URL respectively.
    // Step-scoped so they don't interfere with the same letters
    // used elsewhere (e.g. `c` on AwaitingAcl).
    if !modifiers.contains(KeyModifiers::CONTROL)
        && app.current_step == app::WizardStep::Summary
        && matches!(
            code,
            KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Char('b') | KeyCode::Char('B')
        )
    {
        match code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                app.copy_config_path_to_clipboard();
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                app.copy_backend_url_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `v` / `m` / `a` on the online-VTA Connected screen copy
    // the VTA / mediator / admin DIDs to the clipboard. Phase-scoped
    // to Connected so the same letter keys can be used for unrelated
    // actions on other phases without ambiguity.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('v')
                | KeyCode::Char('V')
                | KeyCode::Char('m')
                | KeyCode::Char('M')
                | KeyCode::Char('a')
                | KeyCode::Char('A')
        )
        && let Some(state) = app.vta_connect.as_mut()
        && state.phase == crate::vta::ConnectPhase::Connected
    {
        match code {
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_vta_did_to_clipboard();
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                state.copy_mediator_did_to_clipboard();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                state.copy_admin_did_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    match app.mode {
        InputMode::TextInput => match code {
            KeyCode::Enter => app.confirm_text_input(),
            KeyCode::Esc => app.go_back(),
            KeyCode::Char(c) => {
                app.handle_text_input(InputRequest::InsertChar(c));
            }
            KeyCode::Backspace => {
                app.handle_text_input(InputRequest::DeletePrevChar);
            }
            KeyCode::Delete => {
                app.handle_text_input(InputRequest::DeleteNextChar);
            }
            KeyCode::Left => {
                app.handle_text_input(InputRequest::GoToPrevChar);
            }
            KeyCode::Right => {
                app.handle_text_input(InputRequest::GoToNextChar);
            }
            KeyCode::Home => {
                app.handle_text_input(InputRequest::GoToStart);
            }
            KeyCode::End => {
                app.handle_text_input(InputRequest::GoToEnd);
            }
            _ => {}
        },
        InputMode::Selecting => match app.focus {
            app::FocusPanel::Content => match code {
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') if app.current_step.is_multi_select() => {
                    app.toggle_current_multi_select();
                }
                KeyCode::Enter => app.select_current(),
                KeyCode::Esc => app.go_back(),
                KeyCode::Left => app.focus_progress(),
                _ => {}
            },
            app::FocusPanel::Progress => match code {
                KeyCode::Up | KeyCode::Char('k') => app.progress_up(),
                KeyCode::Down | KeyCode::Char('j') => app.progress_down(),
                KeyCode::Enter => app.jump_to_progress_step(),
                KeyCode::Right | KeyCode::Esc => app.focus_content(),
                _ => {}
            },
        },
        InputMode::Confirming => match code {
            KeyCode::Enter => app.select_current(),
            KeyCode::Esc => app.go_back(),
            _ => {}
        },
    }
}

/// Project a [`vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterialV2`]
/// onto the `Secret` shape the mediator-common secrets store expects.
///
/// Emits the signing key, the key-agreement key, **and every additional
/// signing key the VTA minted**, each keyed by its full DID-URL
/// verification-method id. The private bytes move through
/// `Secret::from_multibase`, which decodes the multibase string, detects the
/// key type from its multicodec, and populates the secret's zeroized buffers.
///
/// The additional keys are empty for a v1 template, which is what the mediator
/// uses today. Handling them anyway is not speculative: they are published in
/// the DID document as verification methods, so a mediator that stored only the
/// first two would advertise a key it cannot use — and the failure surfaces at
/// a peer as an unverifiable signature, a long way from here.
fn did_key_material_to_secrets(
    material: &vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterialV2,
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    let decode = |slot: &str, key_id: &str, private: &str| {
        Secret::from_multibase(private, Some(key_id))
            .map_err(|e| anyhow::anyhow!("decode {slot} private key ({key_id}): {e}"))
    };

    let mut secrets = vec![
        decode(
            &material.signing_key.slot,
            &material.signing_key.key_id,
            &material.signing_key.private_key_multibase,
        )?,
        decode(
            &material.ka_key.slot,
            &material.ka_key.key_id,
            &material.ka_key.private_key_multibase,
        )?,
    ];
    for extra in &material.additional_signing_keys {
        secrets.push(decode(
            &extra.slot,
            &extra.key_id,
            &extra.private_key_multibase,
        )?);
    }
    Ok(secrets)
}

/// Convert a flat `Vec<SecretEntry>` (the `ContextProvisionBundle`
/// shape used by the OfflineExport path) into `Secret` values the
/// mediator's runtime loader consumes.
///
/// Sibling to [`did_key_material_to_secrets`] — that one walks a
/// typed (signing, ka) pair grouped by DID; this one iterates a flat
/// list keyed by `key_id` and trusts the multibase prefix on each
/// entry to disambiguate Ed25519 / X25519 / P-256. The loader's
/// `Secret::from_multibase` does the actual key-type detection.
///
/// Both helpers feed into the same downstream sink (`provision_secrets`
/// in `secrets/mod.rs`); the duplication is in *iteration shape*
/// only, not in per-key handling.
fn secret_entries_to_secrets(
    entries: &[vta_sdk::did_secrets::SecretEntry],
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    entries
        .iter()
        .map(|entry| {
            Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id))
                .map_err(|e| anyhow::anyhow!("decode key {}: {e}", entry.key_id))
        })
        .collect()
}

/// Project a completed [`vta::VtaSession`] onto the
/// [`vta_sdk::did_secrets::DidSecretsBundle`] shape the mediator's
/// runtime expects in its VTA fallback cache.
///
/// The mediator boots, tries to reach its VTA, and on any failure
/// (network, timeout, or VTA-side validation — `integration::startup`
/// in vta-sdk doesn't distinguish) loads this bundle to keep serving
/// DIDComm traffic with its existing keys. Pre-populating it at
/// wizard time means first-boot survives VTA unavailability.
///
/// Returns `None` for [`VtaReply::AdminOnly`](crate::vta::VtaReply::AdminOnly) sessions — those don't
/// carry a VTA-provisioned integration DID (the mediator brought its
/// own via the Did step), so there's nothing for the VTA cache to
/// seed. `TemplateBootstrap` and `ContextProvision` replies both map
/// to a bundle; their shapes differ but the target is unified.
fn build_did_secrets_bundle(
    session: &vta::VtaSession,
) -> Option<vta_sdk::did_secrets::DidSecretsBundle> {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

    if let Some(provision) = session.as_full_provision() {
        // TemplateBootstrap path. Every key the VTA minted for this DID, each
        // typed by what the bundle *says* it is rather than by what this code
        // assumes.
        //
        // Both halves of that changed. The discriminants used to be pinned to
        // `Ed25519` / `X25519` literals "to match the didcomm-mediator
        // template's renderer contract" — true while a template could not ask
        // for anything else, and a mislabel the moment one can. `SlotKeyPair`
        // now carries the algorithm the VTA actually minted, so read it.
        //
        // And the additional signing keys are projected too. They are published
        // in the DID document as verification methods, so storing only the pair
        // would advertise a key the mediator cannot sign with — surfacing at a
        // peer as an unverifiable signature, far from here. Empty for a v1
        // template, which is what the mediator uses today.
        let material = provision.integration_key()?;
        let entry = |k: &vta_sdk::sealed_transfer::template_bootstrap::SlotKeyPair| SecretEntry {
            key_id: k.key_id.clone(),
            key_type: k.key_type.clone(),
            private_key_multibase: k.private_key_multibase.clone(),
        };
        let mut secrets = vec![entry(&material.signing_key), entry(&material.ka_key)];
        secrets.extend(material.additional_signing_keys.iter().map(entry));
        return Some(DidSecretsBundle {
            did: provision.integration_did()?.to_string(),
            secrets,
        });
    }

    if let Some(bundle) = session.as_context_export() {
        // OfflineExport path — ContextProvisionBundle already carries
        // a flat `Vec<SecretEntry>` typed by the VTA, so we pass it
        // through verbatim (including any future key types the VTA
        // adds).
        let did = bundle.did.as_ref()?;
        return Some(DidSecretsBundle {
            did: did.id.clone(),
            secrets: did.secrets.clone(),
        });
    }

    // AdminOnly — no VTA-provisioned integration DID to cache.
    None
}

/// Write a `did.jsonl` log entry next to the mediator's config file.
/// Fatal on failure: `mediator.toml` points `did_web_self_hosted` at this
/// file, and a mediator whose DID log is missing cannot serve its DID.
fn write_did_jsonl(config_path: &str, log_content: &str) -> anyhow::Result<PathBuf> {
    let did_jsonl_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("did.jsonl");
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
fn write_did_web_json(config_path: &str, log_content: &str, webvh_did: &str) -> Option<PathBuf> {
    let (web_did, doc) = match generators::did_webvh::webvh_log_to_did_web(log_content, webvh_did) {
        Ok(pair) => pair,
        Err(e) => {
            err!("  \x1b[33mWarning:\x1b[0m could not derive did:web document: {e}");
            return None;
        }
    };
    let did_web_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("did-web.json");
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

/// Drop any HTTP path from a URL, returning `<scheme>://<host>[:<port>]`.
/// Used to derive the did:webvh DID identifier from the operator's full
/// public URL (the trailing `/mediator/v1` would otherwise get baked into
/// the DID and route the resolver away from `/.well-known/did.jsonl`).
fn strip_url_path_owned(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            u.set_path("");
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => raw.to_string(),
    }
}

/// Glue a base URL and an HTTP path prefix together with exactly one
/// `/` between them and no trailing slash. Used to feed the did:webvh
/// template's `URL` variable so service-endpoint URIs match what the
/// mediator actually serves at runtime.
///
/// `combine_url_prefix("https://m.example.com", "/mediator/v1/")`
/// → `"https://m.example.com/mediator/v1"`. An empty or `/` prefix
/// returns the base URL unchanged.
fn combine_url_prefix(base: &str, prefix: &str) -> String {
    let base = base.trim_end_matches('/');
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{prefix}")
    }
}

/// Build the DIDComm base URL advertised inside a generated did:peer.
///
/// `public_url` may be either the host root (`https://m.example.com`) or
/// an already-prefixed URL (`https://m.example.com/mediator/v1`). To stay
/// backward compatible with existing operator habits, append `api_prefix`
/// only when the URL path does not already end with it.
fn did_peer_service_url(public_url: &str, api_prefix: &str) -> Option<String> {
    let public_url = public_url.trim().trim_end_matches('/');
    if public_url.is_empty() {
        return None;
    }

    let prefix = api_prefix.trim_matches('/');
    if prefix.is_empty() {
        return Some(public_url.to_string());
    }

    let already_prefixed = url::Url::parse(public_url)
        .ok()
        .map(|url| {
            let path = url.path().trim_matches('/');
            path == prefix || path.ends_with(&format!("/{prefix}"))
        })
        .unwrap_or(false);

    Some(if already_prefixed {
        public_url.to_string()
    } else {
        combine_url_prefix(public_url, api_prefix)
    })
}

#[cfg(test)]
mod did_peer_service_url_tests {
    use super::did_peer_service_url;

    #[test]
    fn appends_default_api_prefix_for_host_root_public_url() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }

    #[test]
    fn does_not_double_append_existing_api_prefix() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com/mediator/v1/", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }
}

/// Bag of artefacts the mint phase produces and the later phases
/// consume. Keeps the `generate_and_write` phases coupled by an
/// explicit value type rather than a soup of mutable locals.
///
/// Pure-ish: every field is a value, not a handle to a backend or
/// open file. Side effects (file writes, network calls, stdout) live
/// in `provision_secret_backend`, `write_config_artefacts`, and
/// `print_completion_summary` which take a borrowed `&MintedArtefacts`.
struct MintedArtefacts {
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
    /// The mediator's admin-API DID. `None` under `ADMIN_SKIP`.
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
async fn generate_and_write(
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
async fn generate_and_write_with(
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

/// Publish the DID and its log to the recipe's targets. Returns the
/// operator-facing failure message, or `None` when there was nothing to
/// publish or it all succeeded.
async fn publish_minted(config: &app::WizardConfig, artefacts: &MintedArtefacts) -> Option<String> {
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

/// Phase 1 — open the secret backend the config names, probe it, and run
/// the re-run guard against *that* backend: refuse when it already holds a
/// provisioned mediator, unless `--force-reprovision`.
///
/// Entries that this same run already wrote are not "existing": the TUI
/// persists a VTA session's credential as soon as it connects, and those
/// match the session being provisioned now.
async fn open_guarded_backend(
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

/// Phase 2 — pure-ish value computation. Branches on `did_method`,
/// `jwt_mode`, and `admin_did_mode` to determine what the wizard will
/// stamp into the config; produces no file or network side effects.
async fn mint_artefacts(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<MintedArtefacts> {
    // ── DID + operating secrets + (optional) DID log + (optional) VC ──
    let minted = mint_did_material(config, vta_session).await?;

    // ── JWT secret ────────────────────────────────────────────────────
    let jwt_secret: Option<Vec<u8>> = if config.jwt_mode == JWT_MODE_PROVIDE {
        out!(
            "  JWT secret: provide mode — wizard will NOT generate or store a key. \
             Set MEDIATOR_JWT_SECRET or pass --jwt-secret-file <path> when starting \
             the mediator."
        );
        None
    } else {
        Some(generators::jwt::generate_jwt_secret()?)
    };

    // ── Admin DID ─────────────────────────────────────────────────────
    // The admin-API identity is what the operator chose. In a VTA flow the
    // VTA-issued credential is the mediator↔VTA identity; it doubles as the
    // admin-API identity only when explicitly asked for (`ADMIN_VTA`), so a
    // generated admin stays a separate key by default.
    let (admin_did, admin_secret) = match config.admin_did_mode.as_str() {
        ADMIN_GENERATE => {
            let (did, secret) = generators::did_key::generate_admin_did_key()?;
            (Some(did), Some(secret))
        }
        ADMIN_VTA => {
            let session = vta_session.ok_or_else(|| {
                exit::error(
                    exit::NO_VTA_SESSION,
                    "admin = VTA-issued credential, but this run has no VTA session",
                )
            })?;
            out!(
                "  Admin DID: the VTA-issued credential {}",
                session.admin_did()
            );
            (Some(session.admin_did().to_string()), None)
        }
        ADMIN_PASTE => {
            let did = config.admin_did.trim();
            if did.is_empty() {
                return Err(exit::error(
                    exit::IMPORT_WITHOUT_DATA,
                    "admin = existing DID, but no admin DID was given",
                ));
            }
            if !recipe::looks_like_did(did) {
                anyhow::bail!("admin DID '{did}' is not a DID (expected did:<method>:<id>)");
            }
            (Some(did.to_string()), None)
        }
        // ADMIN_SKIP, or no choice recorded.
        _ => (None, None),
    };
    // The admin is a separate identity from the mediator; the mediator
    // refuses to start otherwise, so stop here rather than write that config.
    if let Some(admin) = admin_did.as_deref() {
        affinidi_messaging_mediator_config::validate::check_admin_not_mediator(admin, &minted.did)
            .map_err(|msg| anyhow::anyhow!(msg))?;
    }

    Ok(MintedArtefacts {
        mediator_did: minted.did,
        mediator_secrets: minted.secrets,
        did_doc: minted.did_log,
        webvh_update_keys: minted.webvh_update_keys,
        authorization_vc: minted.authorization_vc,
        jwt_secret,
        admin_did,
        admin_secret,
    })
}

/// What [`mint_did_material`] produces.
struct MintedDid {
    did: String,
    secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    did_log: Option<String>,
    webvh_update_keys: Option<generators::did_webvh::WebvhUpdateKeys>,
    authorization_vc: Option<String>,
}

/// Mint the mediator's DID + operating secrets per `did_method`. The DID
/// log is `None` for non-webvh / non-VTA deployments, the update keys for
/// anything but a locally generated did:webvh, and the authorization VC
/// for anything but a VTA full setup.
async fn mint_did_material(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<MintedDid> {
    let mut webvh_update_keys = None;
    let (did, secrets, did_log, authorization_vc) = match config.did_method.as_str() {
        DID_PEER => {
            let service_uri = did_peer_service_url(&config.public_url, &config.api_prefix);
            let (did, secrets) = generators::did_peer::generate_did_peer(
                service_uri,
                &config.key_suite,
                config.tsp_enabled,
            )?;
            (did, secrets, None, None)
        }
        DID_WEBVH => {
            // The DID identifier should encode the host only (`example.com`)
            // so the resolver fetches `<host>/.well-known/did.jsonl`. The
            // template's URL variable, by contrast, needs the *full* URL
            // including the operator's `api_prefix` so the rendered service
            // endpoints (`#didcomm`, `#auth`, `#whois`) point at the routes
            // the mediator actually serves.
            let raw_url = if config.public_url.is_empty() {
                "https://localhost:7037".to_string()
            } else {
                config.public_url.clone()
            };
            let address = strip_url_path_owned(&raw_url);
            let service_url = combine_url_prefix(&address, &config.api_prefix);
            let result = generators::did_webvh::generate_did_webvh_as(
                &address,
                &service_url,
                &config.key_suite,
                config.tsp_enabled,
                generators::did_webvh::WebvhIdentity {
                    present_as_scid: config.present_as_scid,
                    scid_also_known_as: config.scid_also_known_as,
                },
            )
            .await?;
            webvh_update_keys = Some(result.update_keys);
            (result.did, result.secrets, Some(result.did_doc), None)
        }
        DID_VTA => {
            // VTA-managed DID: two reply shapes carry it.
            // - `Full(ProvisionResultV2)` — fresh template render
            //   (online / offline-mint paths, FullSetup intent).
            // - `ContextExport(ContextProvisionBundle)` — re-export
            //   of already-provisioned material (offline-export path,
            //   OfflineExport intent).
            let from_full = vta_session.and_then(|s| s.as_full_provision());
            let from_export = vta_session.and_then(|s| s.as_context_export());
            if let Some(provision) = from_full {
                let integration_did = provision
                    .integration_did()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "VTA Full reply has no integration DID — the AdminRotation \
                             flow can't drive a mediator (`did_method = vta`); \
                             re-run with a FullSetup intent or pick a different did_method."
                        )
                    })?
                    .to_string();
                out!("  VTA-minted mediator DID: {integration_did}");

                // Persist the integration DID's private keys as `Secret`
                // values — the mediator's runtime secrets loader reads
                // these at startup.
                let secrets = provision
                    .integration_key()
                    .map(did_key_material_to_secrets)
                    .transpose()?
                    .unwrap_or_default();

                // Authorization VC content — actual file write happens
                // in `write_config_artefacts`. Pre-serialise here so the
                // mint phase produces a value-only `Option<String>` and
                // the IO phase has nothing to compute.
                let vc = serde_json::to_string_pretty(provision.authorization_vc()).ok();

                // The VTA also exposes the inner DID document separately
                // on `provision.payload.config.did_document`, but the
                // wizard only needs the log entry — the mediator's
                // loader extracts the DID document from the log envelope
                // for `/.well-known/did.json`.
                let log_entry = provision.webvh_log().map(str::to_string);
                (integration_did, secrets, log_entry, vc)
            } else if let Some(bundle) = from_export {
                // OfflineExport path. Bundle carries the existing
                // mediator DID + operational keys (Vec<SecretEntry>)
                // + did.jsonl entry. No authorization VC — the admin
                // identity is the `bundle.credential` itself.
                let did_view = bundle.did.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "OfflineExport bundle has no DID slot — admin-only contexts \
                         can't drive a mediator (`did_method = vta`); \
                         re-run with `did_method = peer` (admin-only) or \
                         re-export with a DID-bearing context."
                    )
                })?;
                let integration_did = did_view.id.clone();
                out!("  VTA-exported mediator DID: {integration_did}");

                let secrets = secret_entries_to_secrets(&did_view.secrets)?;
                let log_entry = did_view.log_entry.clone();
                (integration_did, secrets, log_entry, None)
            } else {
                // Never write a placeholder DID: the mediator cannot boot
                // with one, and exit 0 would report a broken setup as done.
                return Err(exit::error(
                    exit::NO_VTA_SESSION,
                    match vta_session {
                        Some(_) => {
                            "a VTA-managed mediator DID was requested, but the VTA session \
                             carries no mediator DID (it is an admin-credential-only \
                             session). Choose did:peer or did:webvh for the mediator."
                        }
                        None => {
                            "a VTA-managed mediator DID was requested, but there is no VTA \
                             session to take it from. Use a sealed-mint recipe, the \
                             interactive wizard, or did:peer / did:webvh."
                        }
                    },
                ));
            }
        }
        other => {
            return Err(exit::error(
                exit::IMPORT_WITHOUT_DATA,
                format!(
                    "DID method '{other}' cannot be set up by the wizard (importing an \
                     existing mediator DID is not supported). Choose did:peer, did:webvh or \
                     a VTA-managed DID."
                ),
            ));
        }
    };

    // Provision-time guard — reject any keyset that the mediator could not use
    // to decrypt its own inbound traffic before it ever reaches disk / the VTA.
    let admin_did = vta_session.map(|s| s.admin_did().to_string());
    validate_operating_secrets(&did, &secrets, admin_did.as_deref())?;

    Ok(MintedDid {
        did,
        secrets,
        did_log,
        webvh_update_keys,
        authorization_vc,
    })
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
fn validate_operating_secrets(
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
async fn provision_secret_backend(
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

/// Copy `path` aside as `<name>.bak.<UTC timestamp>` before it is replaced.
/// Returns the backup's path, or `None` when there was nothing to back up.
fn backup_existing(path: &Path) -> anyhow::Result<Option<PathBuf>> {
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
fn write_config_artefacts(
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
    let (ssl_cert_path, ssl_key_path) = if config.ssl_mode == SSL_SELF_SIGNED {
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

    // Authorization VC archive (DID_VTA Full path only). Short-lived
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
    if config.deployment_type == DEPLOYMENT_CONTAINER {
        written.extend(docker::generate_dockerfile(config, &conf_dir)?);
    }

    // The file backend's secrets file, so uninstall can find it.
    if config.secret_storage == STORAGE_FILE {
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

/// Phase 5 — operator-facing terminal output. The admin private key is
/// never printed unless asked for with `--show-admin-key` on a terminal:
/// it is already in the secret backend or `admin-monitor.json`, and stdout
/// often ends up in CI logs or the journal.
fn print_completion_summary(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    vta_session: Option<&vta::VtaSession>,
    show_admin_key: bool,
) {
    let conf_dir = config_writer::config_dir(config);
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Configuration: \x1b[1m{}\x1b[0m",
        config.config_path
    );
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Lua functions: \x1b[1m{}\x1b[0m",
        conf_dir.join("atm-functions.lua").display()
    );

    if let Some(ref did) = artefacts.admin_did {
        out!("  \x1b[32m\u{2714}\x1b[0m Admin DID: \x1b[36m{did}\x1b[0m");
        let key = match (&artefacts.admin_secret, vta_session) {
            (Some(secret), _) => secret.get_private_keymultibase().ok(),
            (None, Some(session)) if config.admin_did_mode == ADMIN_VTA => {
                Some(session.admin_private_key_mb().to_string())
            }
            _ => None,
        };
        if let Some(key) = key {
            print_admin_key(&key, show_admin_key);
        }
    }

    if config.secret_storage == STORAGE_FILE {
        out!(
            "  \x1b[32m\u{2714}\x1b[0m Secrets: \x1b[1m{}\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        out!(
            "  \x1b[32m\u{2714}\x1b[0m SSL certificates: {}",
            conf_dir.join("keys").display()
        );
    }
}

/// Where the admin key is, and — only with `--show-admin-key` on a
/// terminal — the key itself.
fn print_admin_key(privkey_multibase: &str, show_admin_key: bool) {
    use std::io::IsTerminal;
    if !show_admin_key {
        out!(
            "    \x1b[2mThe admin private key is stored in the secret backend / \
             admin-monitor.json; it is not printed (--show-admin-key prints it on a \
             terminal).\x1b[0m"
        );
        return;
    }
    if !io::stdout().is_terminal() {
        err!(
            "  \x1b[33mNote:\x1b[0m --show-admin-key is ignored: stdout is not a terminal, and \
             the key would land in a log."
        );
        return;
    }
    out!();
    out!(
        "  \x1b[41;97m UNSAFE \x1b[0m \x1b[1mAdmin private key printed below (--show-admin-key).\x1b[0m"
    );
    out!("  \x1b[2mCopy it to an offline store now and clear your terminal scrollback.\x1b[0m");
    out!("  \x1b[2mPrivate key (multibase): {privkey_multibase}\x1b[0m");
}

fn print_banner() {
    // Gradient from purple (141) → blue (69) → cyan (43) across rows
    let r = "\x1b[0m";

    out!();
    out!("  \x1b[38;5;141m    ___    _________       _     ___ {r}");
    out!("  \x1b[38;5;135m   /   |  / __/ __(_)___  (_)___/ (_){r}");
    out!("  \x1b[38;5;105m  / /| | / /_/ /_/ / __ \\/ / __  / / {r}");
    out!("  \x1b[38;5;69m / ___ |/ __/ __/ / / / / / /_/ / /  {r}");
    out!("  \x1b[38;5;33m/_/  |_/_/ /_/ /_/_/ /_/_/\\__,_/_/   {r}");
    out!();
    out!("  \x1b[38;5;43m\u{2501}\u{2501}\u{2501}\x1b[0m \x1b[1;38;5;255mMediator Setup\x1b[0m");
    out!("  \x1b[2mSecure, scalable DIDComm & TSP messaging infrastructure\x1b[0m");
    out!();
}

/// Put the terminal back the way the wizard found it: raw mode off, main
/// screen, bracketed paste off, cursor shown. Best-effort and idempotent,
/// so the panic hook and the normal exit path can both call it.
fn reset_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        DisableMouseCapture,
        ratatui::crossterm::cursor::Show
    );
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    // A panic anywhere in the TUI must not leave the shell in raw mode on
    // the alternate screen with the message hidden: restore first, then
    // let the previous hook print the panic.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        reset_terminal();
        previous(info);
    }));

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    // Bracketed paste lets the terminal deliver a multi-char paste as a
    // single `Event::Paste(String)` instead of a flood of individual Key
    // events. Without it, pasting a 30-char DID triggers 30 redraws and
    // feels sluggish.
    if let Err(e) = execute!(
        stdout,
        EnterAlternateScreen,
        EnableBracketedPaste,
        DisableMouseCapture
    ) {
        // Raw mode is already on: undo it before reporting.
        reset_terminal();
        return Err(e.into());
    }
    match Terminal::new(CrosstermBackend::new(stdout)) {
        Ok(terminal) => Ok(terminal),
        Err(e) => {
            reset_terminal();
            Err(e.into())
        }
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    reset_terminal();
    Ok(terminal.show_cursor()?)
}

/// Build the feature flags list based on wizard config choices.
/// Build the cargo build arguments for the mediator. `needs_explicit`
/// must come from [`app::WizardConfig::needs_explicit_features`] so
/// `--no-default-features` is set if and only if the wizard's choices
/// differ from the mediator crate's defaults.
fn build_cargo_args(features: &[&str], needs_explicit: bool) -> Vec<String> {
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        // Same reason as `build_install_args`: build what the lockfile
        // resolved, not whatever is newest today.
        "--locked".to_string(),
        "-p".to_string(),
        "affinidi-messaging-mediator".to_string(),
    ];

    if needs_explicit {
        args.push("--no-default-features".to_string());
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    args
}

/// Find the workspace root by walking up from the current directory
/// looking for a Cargo.toml that contains `[workspace]`.
fn find_workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;

    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists()
            && let Ok(contents) = std::fs::read_to_string(&cargo_toml)
            && contents.contains("[workspace]")
        {
            return Some(dir);
        }

        if !dir.pop() {
            break;
        }
    }
    None
}

/// Resolve the absolute config path for the run command.
fn resolve_config_path(config_path: &str) -> String {
    if Path::new(config_path).is_absolute() {
        return config_path.to_string();
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(abs) = cwd.join(config_path).canonicalize()
    {
        return abs.to_string_lossy().into_owned();
    }
    config_path.to_string()
}

/// Inline selector: renders options with arrow-key navigation in the terminal.
/// Returns the index of the selected option, or `None` if the user pressed Esc/Ctrl+C.
fn inline_select(prompt: &str, options: &[&str], default: usize) -> Option<usize> {
    use ratatui::crossterm::event as ct;

    let mut selected = default;

    // Print the prompt
    out!("  {prompt}\n");

    // Enter raw mode for key capture. Without a terminal there is no
    // answer: report "no choice" rather than act on the default (which
    // used to start a multi-minute `cargo install` unprompted).
    if enable_raw_mode().is_err() {
        return None;
    }

    loop {
        // Render options (overwrite previous lines)
        for (i, option) in options.iter().enumerate() {
            if i == selected {
                // Turquoise bold with › indicator
                print!("\r  \x1b[38;5;80m\x1b[1m› {option}\x1b[0m\x1b[K");
            } else {
                print!("\r  \x1b[2m  {option}\x1b[0m\x1b[K");
            }
            if i < options.len() - 1 {
                out!();
            }
        }
        let _ = io::stdout().flush();

        // Wait for key
        if let Ok(ct::Event::Key(key)) = ct::read() {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if selected < options.len() - 1 => {
                    selected += 1;
                }
                KeyCode::Enter => {
                    let _ = disable_raw_mode();
                    out!();
                    return Some(selected);
                }
                KeyCode::Esc => {
                    let _ = disable_raw_mode();
                    out!();
                    return None;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = disable_raw_mode();
                    out!();
                    return None;
                }
                _ => {}
            }
        }

        // Move cursor back up to re-render
        if options.len() > 1 {
            print!("\x1b[{}A", options.len() - 1);
        }
    }
}

/// Build the `cargo install` arguments for the mediator. `needs_explicit`
/// must come from [`app::WizardConfig::needs_explicit_features`] so
/// `--no-default-features` is set if and only if the wizard's choices
/// differ from the mediator crate's defaults.
fn build_install_args(
    features: &[&str],
    needs_explicit: bool,
    install_root: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "install".to_string(),
        "--path".to_string(),
        "crates/affinidi-messaging-mediator".to_string(),
        // `cargo install` re-resolves every dependency and ignores the
        // workspace lockfile unless it is told not to. That is not a
        // preference: an unlocked resolve is what took `aws-smithy-types`
        // 1.7.0 and failed to compile `aws-smithy-json` inside the registry
        // source, for operators who had changed nothing. The wizard runs this
        // command itself, so an operator passing `--locked` to their own
        // builds could not reach it.
        "--locked".to_string(),
    ];

    if needs_explicit {
        args.push("--no-default-features".to_string());
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    if let Some(root) = install_root {
        args.push("--root".to_string());
        args.push(root.to_string());
    }

    args
}

/// Print the run command for the mediator binary.
/// Emit the "phase 1 complete — now do this on the VTA host, then
/// re-run with --bundle" guidance after the headless dispatcher
/// writes the request file. Mirrors the interactive TUI's
/// `primary_command` screen but addressed to an operator looking at
/// a shell prompt rather than a ratatui panel.
fn print_phase1_next_steps(
    recipe_path: &str,
    request_path: &std::path::Path,
    bundle_id_hex: &str,
    producer_command: &str,
    pnm_command: &str,
) {
    out!("  \x1b[32m\u{2714}\x1b[0m Phase 1 complete — bootstrap request written.");
    out!();
    out!(
        "  \x1b[1mRequest file:\x1b[0m  \x1b[36m{}\x1b[0m",
        request_path.display()
    );
    out!("  \x1b[1mBundle ID:\x1b[0m     \x1b[36m{bundle_id_hex}\x1b[0m");
    out!();
    // `AdminOnly` intent has the same `pnm contexts bootstrap …` shape
    // for both the offline and live-API flavours, so an "unseal first"
    // note doesn't apply — show the single command and move on.
    //
    // `FullSetup` and `OfflineExport` *do* gate the offline `vta …`
    // form on an unsealed VTA. After install or after `vta bootstrap-
    // admin`, the VTA is sealed by default, and the offline command
    // errors with "VTA is sealed (… Offline CLI commands are
    // disabled)" — exactly the coldstart trap a first-time operator
    // hits. The unseal note is the canonical fix; the pnm alternative
    // is shown as an escape hatch for operators who already have a
    // pnm session against an operational VTA.
    if producer_command == pnm_command {
        out!("  \x1b[1mNext — on the VTA host, run:\x1b[0m");
        out!("    \x1b[36m{producer_command}\x1b[0m");
    } else {
        out!("  \x1b[1mNext — on the VTA host, run:\x1b[0m");
        out!("    \x1b[36m{producer_command}\x1b[0m");
        out!();
        out!(
            "  \x1b[2mIf the VTA is sealed (default state after install or after\n  \
             `vta bootstrap-admin`), the command above errors with\n  \
             \"VTA is sealed (… Offline CLI commands are disabled)\".\n  \
             Unseal first (challenge-response with your super-admin key),\n  \
             then re-run the command above:\x1b[0m"
        );
        out!("    \x1b[36mvta unseal\x1b[0m");
        out!();
        out!(
            "  \x1b[2mAlternatively, if you have a `pnm` session authenticated\n  \
             against this VTA, the live-API form skips the unseal step:\x1b[0m"
        );
        out!("    \x1b[36m{pnm_command}\x1b[0m");
    }
    out!();
    out!("  \x1b[1mThen — back on this host, run:\x1b[0m");
    out!(
        "    \x1b[36mmediator-setup --from {recipe_path} --bundle bundle.armor \\\n     --digest <sha256>\x1b[0m"
    );
    out!();
    out!(
        "  \x1b[2mThe --digest is required — paste the SHA-256 the VTA admin\n  \
         prints, received over a separate channel from the bundle.\x1b[0m"
    );
}

fn print_run_command(config_path: &str, install_location: &str) {
    let abs_config = resolve_config_path(config_path);
    out!("  \x1b[1mTo start the mediator:\x1b[0m");
    if abs_config == "conf/mediator.toml" || abs_config.ends_with("/conf/mediator.toml") {
        out!("    \x1b[36mmediator\x1b[0m");
    } else {
        out!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    }
    out!();
    out!("  \x1b[2mThe mediator binary is installed at {install_location}/mediator\x1b[0m");
}

/// Offer to install the mediator after configuration.
fn offer_build_and_guidance(config: &app::WizardConfig) {
    let features = config.cargo_features();
    let needs_explicit = config.needs_explicit_features();
    let build_args = build_cargo_args(&features, needs_explicit);
    let build_cmd = format!("cargo {}", build_args.join(" "));

    // Try to find workspace root
    let workspace_root = find_workspace_root();

    out!("\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Next Steps \u{2501}\u{2501}\u{2501}\x1b[0m\n");

    // Determine build directory first — we need it for both install and manual instructions
    let build_dir = if let Some(root) = workspace_root {
        root
    } else {
        let install_cmd = format!(
            "cargo {}",
            build_install_args(&features, needs_explicit, None).join(" ")
        );
        out!("  \x1b[33mCannot find workspace root.\x1b[0m");
        print_manual_instructions(&install_cmd, &build_cmd, config);
        print_final_summary(config, true);
        return;
    };

    let choice = inline_select(
        "The mediator can be installed as a binary so you can run it from anywhere.",
        &[
            "Install now (may take a few minutes)",
            "Show manual instructions",
            "Skip",
        ],
        0,
    );

    match choice {
        Some(1) => {
            let install_cmd = format!(
                "cargo {}",
                build_install_args(&features, needs_explicit, None).join(" ")
            );
            print_manual_instructions(&install_cmd, &build_cmd, config);
            print_final_summary(config, true);
            return;
        }
        Some(2) | None => {
            print_final_summary(config, true);
            return;
        }
        _ => {} // Install now (0)
    }

    // Ask for custom install path
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "~/.cargo".to_string());
    let default_bin = format!("{cargo_home}/bin");

    out!();
    print!("  \x1b[1mInstall location\x1b[0m [{default_bin}]: ");
    let _ = io::stdout().flush();

    let mut path_input = String::new();
    let install_root = if io::stdin().read_line(&mut path_input).is_ok() {
        let trimmed = path_input.trim();
        if trimmed.is_empty() || trimmed == default_bin {
            None
        } else {
            out!(
                "\n  \x1b[33mNote: installing to a custom path may require elevated \
                 permissions (sudo).\x1b[0m"
            );
            Some(trimmed.to_string())
        }
    } else {
        None
    };

    let install_args = build_install_args(&features, needs_explicit, install_root.as_deref());
    let install_cmd = format!("cargo {}", install_args.join(" "));

    let install_location = install_root
        .as_ref()
        .map(|r| format!("{r}/bin"))
        .unwrap_or_else(|| default_bin.clone());

    // Print the full command + working directory *before* running it.
    // Mirrors `run_from_recipe`'s existing behaviour — the command
    // lives in the operator's scroll history regardless of whether
    // the build succeeds, so a "retry with different flags" or
    // "inspect why this rebuilt everything" follow-up doesn't need
    // them to chase the recipe or memo the feature set.
    out!("\n  \x1b[1mInstall command:\x1b[0m");
    out!(
        "    \x1b[2mcd\x1b[0m \x1b[36m{}\x1b[0m",
        build_dir.display()
    );
    out!("    \x1b[36m{install_cmd}\x1b[0m\n");

    out!(
        "  \x1b[38;5;69mInstalling mediator to {install_location} \
         (this may take a few minutes)...\x1b[0m\n"
    );

    let status = Command::new("cargo")
        .args(&install_args)
        .current_dir(&build_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            out!("\n  \x1b[32m\u{2714} Installation successful!\x1b[0m\n");
            print_run_command(&config.config_path, &install_location);
        }
        Ok(exit) => {
            err!("\n  \x1b[31m\u{2718} Install failed (exit code: {exit})\x1b[0m");
            err!("  Check the output above for errors. You can retry with:");
            err!("    cd {} && {}", build_dir.display(), install_cmd);
        }
        Err(e) => {
            err!("\n  \x1b[31mFailed to run cargo: {e}\x1b[0m");
            err!("  Is cargo installed and in your PATH?");
            print_manual_instructions(&install_cmd, &build_cmd, config);
        }
    }

    print_final_summary(config, true);
}

/// Print manual build/run instructions when auto-install is skipped or fails.
fn print_manual_instructions(install_cmd: &str, build_cmd: &str, config: &app::WizardConfig) {
    let abs_config = resolve_config_path(&config.config_path);
    let run_features_flag = if config.needs_explicit_features() {
        format!(
            " --no-default-features --features {}",
            config.cargo_features().join(",")
        )
    } else {
        String::new()
    };

    out!("  \x1b[1mOption 1 — Install (recommended):\x1b[0m");
    out!("    \x1b[36m{install_cmd}\x1b[0m");
    out!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    out!();
    out!("  \x1b[1mOption 2 — Build and run from source:\x1b[0m");
    out!("    \x1b[36m{build_cmd}\x1b[0m");
    out!(
        "    \x1b[36mcargo run --release -p affinidi-messaging-mediator{run_features_flag} -- -c {abs_config}\x1b[0m"
    );
}

/// Print a final summary of everything that was created and what to do next.
/// `recipe_saved` is false for `--from` runs, which do not write a recipe.
fn print_final_summary(config: &app::WizardConfig, recipe_saved: bool) {
    let abs_config = resolve_config_path(&config.config_path);
    let config_dir = config_writer::config_dir(config);

    out!("\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Summary \u{2501}\u{2501}\u{2501}\x1b[0m\n");

    // Files created
    out!("  \x1b[1mFiles created:\x1b[0m");
    out!("    \x1b[36m{abs_config}\x1b[0m  — mediator configuration");
    out!(
        "    \x1b[36m{}\x1b[0m  — Redis Lua functions",
        config_dir.join("atm-functions.lua").display()
    );

    let recipe_path = config_dir.join("mediator-build.toml");
    if recipe_saved {
        out!(
            "    \x1b[36m{}\x1b[0m  — build recipe (reproducible setup)",
            recipe_path.display()
        );
    }

    if config.secret_storage == STORAGE_FILE {
        // The unified backend writes to the operator's configured
        // `[secrets].storage` path — show that, not a hard-coded
        // `<config_dir>/secrets.json`.
        out!(
            "    \x1b[36m{}\x1b[0m  — \x1b[33mprivate keys (keep secure!)\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        out!("    \x1b[36mkeys/end.cert\x1b[0m  — SSL certificate (beside mediator.toml)");
        out!("    \x1b[36mkeys/end.key\x1b[0m   — SSL private key (beside mediator.toml)");
    }

    if config.did_method == DID_WEBVH {
        let did_log_path = config_dir.join("did.jsonl");
        out!(
            "    \x1b[36m{}\x1b[0m  — did:webvh log entry",
            did_log_path.display()
        );
    }

    if config.deployment_type == DEPLOYMENT_CONTAINER {
        out!(
            "    \x1b[36m{}\x1b[0m  — container build file",
            config_dir.join("Dockerfile").display()
        );
        out!(
            "    \x1b[36m{}\x1b[0m  — mediator + Redis stack",
            config_dir.join("docker-compose.yml").display()
        );
    }
    out!(
        "    \x1b[36m{}\x1b[0m  — list of these files, for --uninstall",
        reprovision::manifest_path(Path::new(&config.config_path)).display()
    );

    // Key information
    if config.secret_storage != STORAGE_FILE {
        out!();
        out!("  \x1b[1mSecrets:\x1b[0m");
        out!(
            "    Stored in: \x1b[36m{}\x1b[0m",
            affinidi_messaging_mediator_common::redact::redact_url(
                &config_writer::build_backend_url(config)
            )
        );
    }

    out!();
    out!(
        "  \x1b[1mNetwork posture:\x1b[0m {}",
        network_summary(config)
    );

    if recipe_saved {
        out!();
        out!("  \x1b[1mReproduce this setup:\x1b[0m");
        out!(
            "    \x1b[36mmediator-setup --from {}\x1b[0m",
            recipe_path.display()
        );
    }

    out!();
}

/// stderr logging for the headless modes. `RUST_LOG` overrides the
/// default, which shows this tool's own info lines and every warning.
fn init_headless_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,mediator_setup=info"));
    // Another subscriber already installed is not an error worth failing on.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
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

#[cfg(test)]
mod cache_bundle_tests {
    use super::build_did_secrets_bundle;
    use crate::vta::VtaSession;
    use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::did_secrets::SecretEntry;
    use vta_sdk::keys::KeyType;

    #[test]
    fn full_provision_projects_to_signing_plus_ka_bundle() {
        // TemplateBootstrap path: mediator DID + typed signing/ka key
        // pair. Must land as two SecretEntries with the correct
        // discriminants (Ed25519 for signing, X25519 for key-agreement)
        // and the raw multibase passthrough.
        let provision = vta_sdk::provision_client::test_helpers::sample_provision_result_v2(
            /*rolled_over=*/ true, /*pq=*/ false,
        );
        let session = VtaSession::full(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            None,
            provision,
        );

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:integration.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert!(matches!(bundle.secrets[0].key_type, KeyType::Ed25519));
        assert!(matches!(bundle.secrets[1].key_type, KeyType::X25519));
        // Multibase passthrough — the runtime's `Secret::from_multibase`
        // is the one doing the actual key decode, so we round-trip the
        // string verbatim.
        assert_eq!(bundle.secrets[0].private_key_multibase, "zPrivateSample");
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKaPrivate");
    }

    /// **A post-quantum signing key the VTA minted must reach the mediator's
    /// secrets store.**
    ///
    /// The mediator's own template is v1, so this cannot happen yet — but the
    /// key would be *published in the DID document* as a verification method
    /// either way. A mediator that stored only the first two keys would
    /// advertise one it cannot sign with, and that failure surfaces at a peer as
    /// an unverifiable signature, a long way from this code.
    ///
    /// Pinned now rather than when a v2 mediator template appears, because at
    /// that point nothing here would fail — it would just quietly drop a key.
    #[test]
    fn an_additional_signing_key_is_projected_alongside_the_pair() {
        let provision = vta_sdk::provision_client::test_helpers::sample_provision_result_v2(
            /*rolled_over=*/ true, /*pq=*/ true,
        );
        let session = VtaSession::full(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            None,
            provision,
        );

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(
            bundle.secrets.len(),
            3,
            "signing + key-agreement + the post-quantum key the VTA minted, got {:?}",
            bundle.secrets.iter().map(|s| &s.key_id).collect::<Vec<_>>()
        );
        assert!(
            bundle.secrets.iter().any(|s| s.key_id.ends_with("#key-2")),
            "the additional key must be stored under the id the DID document publishes: {:?}",
            bundle.secrets.iter().map(|s| &s.key_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn admin_only_yields_no_bundle() {
        // AdminOnly session doesn't carry a VTA-provisioned integration
        // DID — the mediator brought its own. Nothing to cache; the
        // helper must signal that explicitly so the caller doesn't
        // write a malformed bundle keyed to the admin DID.
        let session = VtaSession::admin_only(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            None,
            None,
            "did:key:z6MkAdmin".into(),
            "zAdminPrivate".into(),
        );
        assert!(build_did_secrets_bundle(&session).is_none());
    }

    #[test]
    fn context_export_passes_through_secret_entries() {
        // OfflineExport path: ContextProvisionBundle already has a
        // flat Vec<SecretEntry> (including whatever key types the VTA
        // chose), so the projection is a direct copy.
        let did_view = ProvisionedDid {
            id: "did:webvh:mediator.example.com".into(),
            did_document: None,
            log_entry: None,
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-0".into(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "zSigning".into(),
                },
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-1".into(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "zKa".into(),
                },
            ],
        };
        let ctx_bundle = ContextProvisionBundle {
            context_id: "prod-mediator".into(),
            context_name: "Prod mediator".into(),
            vta_url: None,
            vta_did: Some("did:webvh:vta.example.com".into()),
            credential: CredentialBundle::new(
                "did:key:z6MkAdmin",
                "zAdminPrivate",
                "did:webvh:vta.example.com",
            ),
            admin_did: "did:key:z6MkAdmin".into(),
            did: Some(did_view),
        };
        let session = VtaSession::context_export("prod-mediator".into(), ctx_bundle);

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:mediator.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert_eq!(
            bundle.secrets[0].key_id,
            "did:webvh:mediator.example.com#key-0"
        );
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKa");
    }
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
            deployment_type: DEPLOYMENT_LOCAL.into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: DID_PEER.into(),
            secret_storage: crate::consts::STORAGE_FILE.into(),
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: SSL_NONE.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
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
        // DID's secret material in memory (i.e., ADMIN_GENERATE).
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
            "ADMIN_GENERATE produces exactly one Ed25519 admin secret",
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
            deployment_type: DEPLOYMENT_LOCAL.into(),
            didcomm_enabled: true,
            did_method: DID_PEER.into(),
            secret_storage: crate::consts::STORAGE_FILE.into(),
            // Collides with the legacy writer's hard-coded target.
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: SSL_NONE.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
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
        // ADMIN_SKIP path: no admin DID generated, no admin
        // credential in the unified backend, and `[server].admin_did`
        // is absent from mediator.toml. Lock down so a refactor
        // doesn't accidentally always-mint an admin DID.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.admin_did_mode = ADMIN_SKIP.into();

        generate_and_write(
            &config,
            None,
            false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write with ADMIN_SKIP");

        let toml_text = std::fs::read_to_string(dir.join("conf").join("mediator.toml")).unwrap();
        let parsed: toml::Value = toml::from_str(&toml_text).unwrap();
        let server = parsed.get("server").expect("[server] section");
        assert!(
            server.get("admin_did").is_none(),
            "admin_did must be absent under ADMIN_SKIP — got: {server:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn mint_artefacts_did_peer_returns_value_only_bag_no_io() {
        // The `mint_artefacts` phase is the value-only / IO-free
        // counterpart to `provision_secret_backend` /
        // `write_config_artefacts`. This test runs it inside a
        // CWD-isolated tempdir so a regression that sneaks a file
        // write back in (the prior structure had one in the DID_VTA
        // arm — now deferred to write_config_artefacts) shows up as
        // a stray artefact in the tempdir.
        let cwd = CwdGuard::new();
        let cwd_before: std::collections::BTreeSet<_> = std::fs::read_dir(cwd.dir())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();

        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
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
        // Lock down the ADMIN_SKIP branch at the unit level — the
        // integration test covers the same path end-to-end, but
        // this one runs in microseconds and surfaces the precise
        // value contract.
        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_SKIP.into(),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None).await.unwrap();
        assert!(artefacts.admin_did.is_none());
        assert!(artefacts.admin_secret.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mint_artefacts_jwt_provide_returns_none_jwt_secret() {
        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_PROVIDE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
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

        config.admin_did_mode = ADMIN_GENERATE.into();
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        let admin = a.admin_did.unwrap();
        assert!(admin.starts_with("did:key:"));
        assert_ne!(admin, session.admin_did());
        assert!(a.admin_secret.is_some());

        config.admin_did_mode = ADMIN_VTA.into();
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        assert_eq!(a.admin_did.as_deref(), Some(session.admin_did()));
        assert!(a.admin_secret.is_none());

        config.admin_did_mode = ADMIN_PASTE.into();
        config.admin_did = "did:web:admin.example.com".into();
        let a = mint_artefacts(&config, Some(&session)).await.unwrap();
        assert_eq!(a.admin_did.as_deref(), Some("did:web:admin.example.com"));
        assert!(a.admin_secret.is_none());

        config.admin_did = String::new();
        let err = mint_artefacts(&config, Some(&session)).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::IMPORT_WITHOUT_DATA);

        config.admin_did_mode = ADMIN_VTA.into();
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
        config.vta_mode = VTA_MODE_ONLINE.into();
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
        config.did_method = DID_VTA.into();
        let err = mint_artefacts(&config, None).await.err().unwrap();
        assert_eq!(exit::code_of(&err), exit::NO_VTA_SESSION);

        config.did_method = DID_IMPORT.into();
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
        config.did_method = DID_WEBVH.into();
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
        config.did_method = DID_WEBVH.into();
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
