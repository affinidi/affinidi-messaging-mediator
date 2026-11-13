//! Key bindings: maps a key press to a `WizardApp` action for the step and
//! input mode on screen.

use ratatui::crossterm::event::{KeyCode, KeyModifiers};
use tui_input::InputRequest;

use crate::app::{self, InputMode, WizardApp};

pub(crate) fn handle_key_event(app: &mut WizardApp, code: KeyCode, modifiers: KeyModifiers) {
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
