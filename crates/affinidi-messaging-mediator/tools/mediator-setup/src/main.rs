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
mod flows;
mod generators;
mod headless;
mod install;
mod provision;
mod publish;
mod recipe;
mod reprovision;
mod sealed_handoff;
mod secret_backend;
mod secure_fs;
mod tui;
mod ui;
mod vta;

use clap::Parser;

use cli::Args;
use flows::{headless::run_headless, headless::run_setup_key_phase2, interactive::run_tui};

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
