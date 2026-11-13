//! The interactive (TUI) flow: pre-fill from flags, run the wizard, then
//! provision what it collected.

use std::{io, path::Path};

use crate::app::{AdminMode, VtaMode};
use crate::app::{WizardApp, WizardConfig};
use crate::cli::{self, Args};
use crate::flows::print_banner;
use crate::install::offer_build_and_guidance;
use crate::provision::{GenerateOptions, generate_and_write_with};
use crate::tui::event_loop::{restore_terminal, run_event_loop, setup_terminal};
use crate::{
    bootstrap_headless, config_writer, exit, exit_recap, recipe, reprovision, secret_backend,
    secure_fs,
};

/// The interactive wizard.
pub(crate) async fn run_tui(args: &Args) -> anyhow::Result<()> {
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
pub(crate) fn save_resume_recipe(config: &WizardConfig, had_vta_session: bool) {
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
            if config.use_vta && config.vta_mode == Some(VtaMode::Online) {
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
pub(crate) fn apply_tui_prefill(args: &Args, config: &mut WizardConfig) {
    if let Some(ref deployment) = args.deployment {
        config.deployment_type = Some((*deployment).into());
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
        config.did_method = Some((*did_method).into());
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
        config.secret_storage = Some((*secret_storage).into());
    }
    if let Some(ref ssl) = args.ssl {
        config.ssl_mode = Some((*ssl).into());
    }
    if let Some(ref database_url) = args.database_url {
        config.database_url = database_url.clone();
    }
    if let Some(admin) = args.admin {
        config.admin_did_mode = Some(admin.into());
    }
    if let Some(ref did) = args.admin_did {
        config.admin_did_mode = Some(AdminMode::Paste);
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
pub(crate) async fn guard_existing_setup(
    config_path: &Path,
    force_reprovision: bool,
) -> anyhow::Result<()> {
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
