//! The interactive wizard's terminal: raw-mode setup and teardown, and the
//! event loop that drains background work, dispatches keys and redraws.

use std::{
    io::{self, Stdout},
    time::Duration,
};

use anyhow::Context;
use crossterm::event::EventStream;
use ratatui::{
    crossterm::{
        event::{
            DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, Event, KeyEventKind,
        },
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
};
use tokio_stream::StreamExt;

use crate::app::WizardApp;
use crate::tui::keymap::handle_key_event;
use crate::ui;

pub(crate) const RENDERING_TICK_RATE: Duration = Duration::from_millis(250);

pub(crate) async fn run_event_loop(
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

/// Put the terminal back the way the wizard found it: raw mode off, main
/// screen, bracketed paste off, cursor shown. Best-effort and idempotent,
/// so the panic hook and the normal exit path can both call it.
pub(crate) fn reset_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        DisableMouseCapture,
        ratatui::crossterm::cursor::Show
    );
}

pub(crate) fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
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

pub(crate) fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> anyhow::Result<()> {
    reset_terminal();
    Ok(terminal.show_cursor()?)
}
