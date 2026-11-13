//! Building and installing the mediator binary after setup: the `cargo`
//! command lines, the optional install prompt, and the run / next-step
//! guidance printed at the end.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use ratatui::crossterm::{
    event::{KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};

use crate::app::{self, WizardConfig};
use crate::app::{Deployment, DidMethod, SecretScheme, SslMode};
use crate::flows::headless::network_summary;
use crate::{config_writer, reprovision};

/// Run `cargo install` when the recipe asks for it, otherwise print the
/// install and build commands. Never prompts.
pub(crate) fn install_or_print_commands(
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

/// Build the feature flags list based on wizard config choices.
/// Build the cargo build arguments for the mediator. `needs_explicit`
/// must come from [`app::WizardConfig::needs_explicit_features`] so
/// `--no-default-features` is set if and only if the wizard's choices
/// differ from the mediator crate's defaults.
pub(crate) fn build_cargo_args(features: &[&str], needs_explicit: bool) -> Vec<String> {
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
pub(crate) fn find_workspace_root() -> Option<PathBuf> {
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
pub(crate) fn resolve_config_path(config_path: &str) -> String {
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
pub(crate) fn inline_select(prompt: &str, options: &[&str], default: usize) -> Option<usize> {
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
pub(crate) fn build_install_args(
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

pub(crate) fn print_run_command(config_path: &str, install_location: &str) {
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
pub(crate) fn offer_build_and_guidance(config: &app::WizardConfig) {
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
pub(crate) fn print_manual_instructions(
    install_cmd: &str,
    build_cmd: &str,
    config: &app::WizardConfig,
) {
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
pub(crate) fn print_final_summary(config: &app::WizardConfig, recipe_saved: bool) {
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

    if config.secret_storage == Some(SecretScheme::File) {
        // The unified backend writes to the operator's configured
        // `[secrets].storage` path — show that, not a hard-coded
        // `<config_dir>/secrets.json`.
        out!(
            "    \x1b[36m{}\x1b[0m  — \x1b[33mprivate keys (keep secure!)\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == Some(SslMode::SelfSigned) {
        out!("    \x1b[36mkeys/end.cert\x1b[0m  — SSL certificate (beside mediator.toml)");
        out!("    \x1b[36mkeys/end.key\x1b[0m   — SSL private key (beside mediator.toml)");
    }

    if config.did_method == Some(DidMethod::Webvh) {
        let did_log_path = config_dir.join("did.jsonl");
        out!(
            "    \x1b[36m{}\x1b[0m  — did:webvh log entry",
            did_log_path.display()
        );
    }

    if config.deployment_type == Some(Deployment::Container) {
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
    if config.secret_storage != Some(SecretScheme::File) {
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
