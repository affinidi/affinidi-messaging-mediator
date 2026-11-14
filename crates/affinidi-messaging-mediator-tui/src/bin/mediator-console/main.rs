//! `mediator-console` — operate an Affinidi messaging mediator from a terminal.
//!
//! Connects as the DID in a TDK profile file (the one `mediator-setup` writes
//! for its administrator, or any account's). With no command it opens the
//! console: the whole mediator for an administrator, the account's own
//! queues for anyone else. With a command (`stats`, `queues`, `accounts`,
//! `audit`, `purge`, …) it runs that one operation, prints the answer (as
//! JSON with `--json`) and exits with a code a script can act on; see
//! `script.rs`.

mod script;

use std::path::PathBuf;
use std::time::Duration;

use affinidi_messaging_mediator_admin::{
    AddressBook, ConsoleOptions, Identity, IdentitySource, MediatorConsole, Mode, ProfileFileSource,
};
use affinidi_messaging_mediator_tui::{App, LogCapture, default_address_book_path};
use clap::Parser;

#[derive(Parser)]
#[command(name = "mediator-console", version, about, after_help = script::EXIT_CODES)]
struct Args {
    /// TDK profile JSON file(s) to connect with: `{ alias, did, mediator, secrets }`.
    /// Required; before or after the command.
    #[arg(short, long = "profile", global = true)]
    profiles: Vec<PathBuf>,

    /// Which profile to use, by alias or DID, when more than one is given.
    #[arg(long = "as", global = true)]
    choose: Option<String>,

    /// Mediator DID, overriding the profile's (and its DID document's).
    #[arg(long, global = true)]
    mediator: Option<String>,

    /// Address book of account nicknames (a JSON list of `{ name, did }`).
    /// Defaults to `~/.config/mediator-console/address-book.json`.
    #[arg(long)]
    address_book: Option<PathBuf>,

    /// Seconds to wait for each answer from the mediator.
    #[arg(long, default_value_t = 30, global = true)]
    timeout: u64,

    /// Seconds to wait for the connection: resolving, authenticating and
    /// reading the account.
    #[arg(long, default_value_t = 30, global = true)]
    connect_timeout: u64,

    /// Run one operation and exit instead of opening the console.
    #[command(subcommand)]
    command: Option<script::Command>,
}

impl Args {
    fn options(&self) -> ConsoleOptions {
        ConsoleOptions::default()
            .with_request_timeout(Duration::from_secs(self.timeout.max(1)))
            .with_connect_timeout(Duration::from_secs(self.connect_timeout.max(1)))
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.profiles.is_empty() {
        // Global arguments can't be `required` in clap; this is its error.
        use clap::CommandFactory;
        Args::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "the following required arguments were not provided:\n  --profile <PROFILES>",
            )
            .exit();
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    if args.command.is_some() {
        // A command's log goes to stderr, out of the way of its answer.
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
        let code = run_command(args).await;
        std::process::exit(code);
    }
    // Log output goes to stderr until the console opens, then into its log
    // (`l`), where it can't draw over the screen.
    let logs = LogCapture::new();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(logs.make_writer())
        .init();
    if let Err(e) = run(args, logs).await {
        eprintln!("mediator-console: {e}");
        std::process::exit(1);
    }
}

/// Load the identity the arguments choose.
async fn identity(args: &Args) -> Result<Identity, Box<dyn std::error::Error>> {
    let source = ProfileFileSource::new(args.profiles.clone());
    let choices = source.list().await?;
    let choice = match &args.choose {
        Some(want) => choices
            .iter()
            .find(|c| c.label == *want || c.did.as_deref() == Some(want.as_str()))
            .ok_or_else(|| format!("no profile named {want}"))?,
        None => choices.first().ok_or("no profiles")?,
    };
    let mut identity = source.load(choice).await?;
    if args.mediator.is_some() {
        identity.mediator_did = args.mediator.clone();
    }
    Ok(identity)
}

/// Run one command; the process's exit code.
async fn run_command(args: Args) -> i32 {
    let identity = match identity(&args).await {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("mediator-console: {e}");
            return script::EXIT_FAILED;
        }
    };
    let console = match MediatorConsole::connect_with_options(identity, args.options()).await {
        Ok(console) => console,
        Err(e) => {
            eprintln!("mediator-console: {}", e.explain());
            return script::exit_code(&e);
        }
    };
    let command = args.command.expect("a command");
    script::run(&console, command).await
}

async fn run(args: Args, logs: LogCapture) -> Result<(), Box<dyn std::error::Error>> {
    let book_path = args.address_book.clone().or_else(default_address_book_path);
    let book = match &book_path {
        Some(path) => {
            AddressBook::load(path).map_err(|e| format!("address book {}: {e}", path.display()))?
        }
        None => AddressBook::new(),
    };

    let identity = identity(&args).await?;
    eprintln!("connecting as {} …", identity.alias);
    let console = MediatorConsole::connect_with_options(identity, args.options()).await?;
    eprintln!(
        "connected: {}",
        match console.mode() {
            Mode::Admin { root: true } => "rootAdmin",
            Mode::Admin { root: false } => "admin",
            Mode::SelfService => "self-service",
        }
    );

    let mut terminal = ratatui::init();
    // `ratatui::init`'s panic hook restores raw mode and the screen, not
    // bracketed paste: turn that off first, or the shell is left with it on.
    let restore = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
        restore(info);
    }));
    // Bracketed paste: a pasted DID arrives whole, not as keystrokes.
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste);
    let result = App::new(console)
        .with_address_book(book, book_path)
        .with_logs(logs)
        .run(&mut terminal)
        .await;
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    ratatui::restore();
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_arguments_are_well_formed() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["mc", "stats", "--json", "-p", "admin.json"])
            .expect("a command, its options and the profile after it");
        assert_eq!(args.profiles, [PathBuf::from("admin.json")]);
        assert!(args.command.is_some());
        let tui = Args::try_parse_from(["mc", "-p", "a.json", "--timeout", "5"]).expect("the TUI");
        assert!(tui.command.is_none());
        assert_eq!(tui.options().request_timeout, Duration::from_secs(5));
    }
}
