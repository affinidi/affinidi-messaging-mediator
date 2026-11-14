//! The headless flows: `--from <recipe>`, `--non-interactive` and the
//! `--setup-key-file` phase 2. They never prompt and never read stdin.

use std::path::Path;

use crate::app::WizardConfig;
use crate::app::{AdminMode, Deployment, DidMethod, SecretScheme, SslMode, VtaMode};
#[cfg(feature = "vta")]
use crate::bootstrap_headless;
use crate::cli::Args;
use crate::consts::*;
use crate::flows::print_banner;
use crate::install::{install_or_print_commands, print_final_summary};
use crate::provision::{GenerateOptions, generate_and_write_with};
use crate::ui::labels::label_of;
use crate::{config_writer, exit, headless, recipe, secret_backend, vta};

/// A human description of what the admin choice will produce.
pub(crate) fn admin_summary(config: &WizardConfig) -> String {
    match config.admin_did_mode {
        Some(AdminMode::Skip) => "Skip (no admin DID)".into(),
        Some(AdminMode::Paste) => format!("Existing DID {}", config.admin_did),
        Some(AdminMode::Vta) => "VTA-issued credential (also the mediator↔VTA credential)".into(),
        Some(AdminMode::Generate) if config.use_vta => {
            "Generate did:key (separate from the VTA credential)".into()
        }
        Some(AdminMode::Generate) => "Generate did:key".into(),
        None => "None".into(),
    }
}

/// The network posture, spelled out — it decides who can message whom.
pub(crate) fn network_summary(config: &WizardConfig) -> String {
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
pub(crate) fn print_config_summary(config: &WizardConfig) {
    out!(
        "  Deployment:   {}",
        label_of(config.deployment_type, Deployment::label)
    );
    out!(
        "  VTA:          {}",
        if config.use_vta {
            format!("Enabled ({})", label_of(config.vta_mode, VtaMode::as_str))
        } else {
            "Disabled".into()
        }
    );
    out!("  Protocol:     {}", config.protocol_display());
    out!(
        "  DID method:   {}",
        label_of(config.did_method, DidMethod::label)
    );
    out!(
        "  Key storage:  {}",
        affinidi_messaging_mediator_common::redact::redact_url(&config_writer::build_backend_url(
            config
        ))
    );
    out!(
        "  SSL/TLS:      {}",
        label_of(config.ssl_mode, SslMode::label)
    );
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
pub(crate) fn apply_database_url_env(config: &mut WizardConfig) -> anyhow::Result<()> {
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
pub(crate) fn print_deployment_warnings(config: &WizardConfig) {
    if config.deployment_type == Some(Deployment::Container)
        && config.secret_storage == Some(SecretScheme::Keyring)
    {
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
pub(crate) async fn run_headless(args: &Args) -> anyhow::Result<()> {
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
    let sealed = config.use_vta && config.vta_mode.is_some_and(VtaMode::is_sealed);
    if args.bundle.is_some() && !sealed {
        anyhow::bail!(
            "--bundle is phase 2 of a sealed handoff, but this recipe is not a sealed one \
             (deployment.use_vta = true with vta_mode = \"sealed-mint\" or \"sealed-export\")"
        );
    }
    // Without the `vta` feature no VTA mode can run: refuse before anything
    // is generated or written.
    #[cfg(not(feature = "vta"))]
    if config.use_vta {
        return Err(exit::error(exit::NO_VTA_SESSION, vta::VTA_UNAVAILABLE));
    }
    if config.use_vta && !sealed {
        return Err(exit::error(
            exit::NO_VTA_SESSION,
            format!(
                "{} needs a VTA session, which a headless run can only get from a sealed \
                 handoff. Use a recipe with vta_mode = \"sealed-mint\" (or \"sealed-export\"), \
                 the --setup-key-out / --setup-key-file pair (admin credential only, with \
                 --did-method peer|webvh), or the interactive wizard.",
                if config.did_method == Some(DidMethod::Vta) {
                    "A VTA-managed mediator DID".to_string()
                } else {
                    format!(
                        "vta_mode = \"{}\"",
                        label_of(config.vta_mode, VtaMode::as_str)
                    )
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
        file_passphrase: None,
    };

    #[cfg(not(feature = "vta"))]
    let completed = {
        // `sealed` implies `use_vta`, refused above.
        debug_assert!(!sealed);
        out!("  Generating cryptographic material...\n");
        generate_and_write_with(&config, None, &options).await?
    };
    #[cfg(feature = "vta")]
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

/// `--setup-key-file` without the `vta` feature: refused, the VTA flows are
/// not built in this release.
#[cfg(not(feature = "vta"))]
pub(crate) async fn run_setup_key_phase2(_args: &Args, _key_path: &Path) -> anyhow::Result<()> {
    Err(exit::error(exit::NO_VTA_SESSION, vta::VTA_UNAVAILABLE))
}

/// `--setup-key-file`: authenticate to the VTA with the phase-1 did:key,
/// then provision the mediator with the resulting admin-only session.
#[cfg(feature = "vta")]
pub(crate) async fn run_setup_key_phase2(args: &Args, key_path: &Path) -> anyhow::Result<()> {
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
    if config.did_method == Some(DidMethod::Vta) {
        return Err(exit::error(
            exit::NO_VTA_SESSION,
            "--setup-key-file obtains an admin credential only; the mediator brings its own \
             DID. Pass --did-method peer or webvh (a VTA-minted DID needs a sealed-mint \
             recipe or the interactive wizard).",
        ));
    }
    config.use_vta = true;
    config.vta_mode = Some(VtaMode::Online);
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
        file_passphrase: None,
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

/// Print the run command for the mediator binary.
/// Emit the "phase 1 complete — now do this on the VTA host, then
/// re-run with --bundle" guidance after the headless dispatcher
/// writes the request file. Mirrors the interactive TUI's
/// `primary_command` screen but addressed to an operator looking at
/// a shell prompt rather than a ratatui panel.
#[cfg(feature = "vta")]
pub(crate) fn print_phase1_next_steps(
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
