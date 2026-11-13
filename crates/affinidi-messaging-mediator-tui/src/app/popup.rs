//! Popups over the screen: confirmations, editors, the address book, the
//! help overlay and the captured log.

use std::collections::BTreeSet;

use affinidi_messaging_mediator_admin::{
    AddressBook, GrantKey, GrantSelection, InspectedMessage, PurgePlan, account_hash,
};
use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use serde_json::Value;

use super::format::{config_value, human_bytes, label, short, short_did, wrap_hard};
use super::state::State;
use crate::account_edit::{AccountEdit, Setting};
use crate::keymap;
use crate::logs::LogLevel;

pub(crate) enum Popup {
    Text {
        title: String,
        body: String,
    },
    /// A message, scrolled `scroll` lines down; `y` copies it, `w` writes it
    /// to a file.
    Inspect {
        id: String,
        body: String,
        scroll: u16,
    },
    /// Every key that works here, scrolled `scroll` lines down.
    Help {
        scroll: u16,
    },
    ConfirmDelete {
        target: Option<String>,
        ids: Vec<String>,
        /// Whose message, from which queue, which one, from and to whom.
        about: Vec<String>,
    },
    ConfirmPurge(PurgePlan),
    /// Apply an account edit: what changes, and a warning when it can lock
    /// the console out of its own account.
    ConfirmAccount {
        edit: AccountEdit,
        who: String,
        changes: Vec<String>,
        warning: Option<String>,
    },
    /// Set a configuration key (`to` is `null` to reset its override).
    ConfirmPatch {
        key: String,
        from: String,
        to: Value,
        /// What was typed, to go back to editing.
        typed: Option<String>,
    },
    /// Name an account: `hash` is the selected account, if any; the user
    /// fills in its DID (optional when `hash` is known) and a nickname.
    Name {
        hash: Option<String>,
        did: String,
        name: String,
        /// Which field typing goes to: the name (true) or the DID.
        on_name: bool,
    },
    /// The address book, with the selected entry.
    Book {
        selected: usize,
    },
    /// Change one configuration key.
    EditConfig {
        key: String,
        value: String,
    },
    /// Change an account's role, ACL and queue limits.
    EditAccount(AccountEdit),
    /// The captured log, `back` rows up from its newest.
    Logs {
        back: usize,
    },
    /// Look up stored grants by principal and/or member DID.
    FindGrants {
        principal: String,
        member: String,
        /// Which field typing goes to: the member (true) or the principal.
        on_member: bool,
    },
    /// Revoke the grants a selection names.
    ConfirmRevoke(GrantSelection),
    /// Revoke the marked grants, each on its own.
    ConfirmRevokeMarked(Vec<GrantKey>),
    /// Advance member `did`'s epoch, voiding `epoch`.
    ConfirmBumpEpoch {
        did: String,
        epoch: u64,
    },
}

/// A fetched message, to read: its metadata, and its body decrypted when
/// this session could open it, else the envelope.
pub(crate) fn inspect_popup(m: &InspectedMessage) -> Popup {
    let meta = serde_json::to_string_pretty(&m.meta).unwrap_or_default();
    let body = match &m.opened {
        Some((message, _)) => format!(
            "{meta}\n\n── decrypted ──\n{}",
            serde_json::to_string_pretty(message).unwrap_or_default()
        ),
        // All of it: the popup scrolls, and `y` / `w` take it whole.
        None => format!(
            "{meta}\n\n── encrypted ──\nThis session does not hold the recipient's key.\n\n{}",
            m.envelope
        ),
    };
    Popup::Inspect {
        id: m.meta.msg_id.to_string(),
        body,
        scroll: 0,
    }
}

/// Draw the open popup, if any, over `area`. Writes back only the log
/// popup's scroll position, kept within what there is to scroll.
pub(crate) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    match &s.popup {
        Some(Popup::Logs { back }) => {
            let back = render_logs(f, area, s, *back);
            s.popup = Some(Popup::Logs { back });
        }
        Some(Popup::Help { scroll }) => render_help(f, area, s, *scroll),
        Some(popup) => render_box(f, area, popup, &s.book),
        None => {}
    }
}

/// Every key that works here, over the screen.
fn render_help(f: &mut Frame, area: Rect, s: &State, scroll: u16) {
    let mut text: Vec<Line> = Vec::new();
    for (title, keys) in keymap::help(super::screens::key_context(s)) {
        text.push(Line::styled(
            title,
            Style::default().add_modifier(Modifier::BOLD),
        ));
        for b in keys {
            text.push(Line::from(vec![
                Span::styled(
                    format!("  {:<16}", b.keys),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(b.does),
            ]));
        }
        text.push(Line::raw(""));
    }
    let w = area.width.saturating_sub(8).min(100);
    let h = area.height.saturating_sub(2);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Keys ")
                    .title_bottom(Line::from(" ↑↓ PgUp PgDn scroll  any other key closes ")),
            ),
        rect,
    );
}

/// The captured log over the screen, newest at the bottom, each line
/// wrapped to the width so none of it is cut off. Returns `back` within
/// what there is to scroll.
fn render_logs(f: &mut Frame, area: Rect, s: &State, back: usize) -> usize {
    let w = area.width.saturating_sub(4);
    let h = area.height.saturating_sub(2);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    let inner_w = w.saturating_sub(2).max(1) as usize;
    let inner_h = h.saturating_sub(2) as usize;
    let mut rows: Vec<Line> = Vec::new();
    // Read in place: only the rows that wrap are built, not a copy of
    // every line kept.
    let count = s.logs.as_ref().map_or(0, |logs| {
        logs.with_lines(|lines| {
            for line in lines {
                let color = match line.level {
                    Some(LogLevel::Error) => Color::Red,
                    Some(LogLevel::Warn) => Color::Yellow,
                    Some(LogLevel::Info) => Color::Reset,
                    _ => Color::DarkGray,
                };
                let chunks = match line.repeats {
                    1 => wrap_hard(&line.text, inner_w),
                    n => wrap_hard(&format!("{}  ×{n}", line.text), inner_w),
                };
                for chunk in chunks {
                    rows.push(Line::styled(chunk, Style::default().fg(color)));
                }
            }
            lines.len()
        })
    });
    let back = back.min(rows.len().saturating_sub(inner_h));
    let skip = rows.len().saturating_sub(inner_h + back);
    let shown: Vec<Line> = rows.into_iter().skip(skip).take(inner_h).collect();
    let position = if back > 0 {
        format!(" {back} row(s) newer below · End ")
    } else {
        String::new()
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(shown).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" Log — {count} line(s) "))
                .title_bottom(Line::from(format!(
                    "{position} ↑↓ PgUp PgDn Home End scroll  c clear  Esc close "
                ))),
        ),
        rect,
    );
    back
}

/// A popup's title, its text, and whether it confirms something that
/// cannot be undone. `None` for the popups drawn on their own (help, log).
fn content(popup: &Popup, book: &AddressBook) -> Option<(String, String, bool)> {
    let shown = match popup {
        Popup::Inspect { body, .. } => (
            " Message — ↑↓ PgUp PgDn scroll  y copy  w write to a file  Esc close ".into(),
            body.clone(),
            false,
        ),
        Popup::Help { .. } | Popup::Logs { .. } => return None,
        Popup::ConfirmAccount {
            who,
            changes,
            warning,
            ..
        } => (
            " Change an account ".into(),
            format!(
                "Account  {who}\n\n{}\n{}\ny applies these changes; any other key goes back to \
                 editing.",
                changes
                    .iter()
                    .map(|c| format!("  {c}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                warning
                    .as_deref()
                    .map(|w| format!("\n{w}\n"))
                    .unwrap_or_default(),
            ),
            true,
        ),
        Popup::ConfirmPatch { key, from, to, .. } => (
            " Change the configuration ".into(),
            match to {
                Value::Null => format!(
                    "Reset the override of\n  {key}\n(now {from}) to the configured value?\n\n\
                     y to confirm, any other key to cancel"
                ),
                to => format!(
                    "{key}\n  {from} → {}\n\ny applies it; any other key goes back to editing.",
                    config_value(to)
                ),
            },
            true,
        ),
        Popup::Name {
            hash,
            did,
            name,
            on_name,
        } => {
            let cursor = |on: bool| if on { "▏" } else { "" };
            let account = match hash {
                Some(h) => format!("Account  {h}\n\n"),
                None => String::new(),
            };
            let check = match (hash, did.trim()) {
                (Some(h), d) if !d.is_empty() => {
                    if account_hash(d) == *h {
                        "      ✓ this is the account\n"
                    } else {
                        "      ✗ a different account\n"
                    }
                }
                _ => "",
            };
            (
                " Name an account ".into(),
                format!(
                    "{account}DID   {did}{}\n{check}Name  {name}{}\n\n\
                     Paste or type. Tab switches field, ⏎ saves, Esc cancels.\n\
                     The DID is optional when an account is selected. An empty name \
                     removes the entry.",
                    cursor(!*on_name),
                    cursor(*on_name),
                ),
                false,
            )
        }
        Popup::Book { selected } => {
            let entries = book.entries();
            let body = if entries.is_empty() {
                "No names yet. Select an account and press n, or press a here to add one.".into()
            } else {
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        format!(
                            "{} {:<24} {}  {}",
                            if i == *selected { "▶" } else { " " },
                            e.name,
                            short(&e.hash()),
                            if e.is_bare_hash() {
                                "(no DID)".to_string()
                            } else {
                                short_did(&e.did)
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            (
                " Address book ".into(),
                format!("{body}\n\n↑↓ select  n rename  a add  x remove  any other key closes"),
                false,
            )
        }
        Popup::EditAccount(edit) => {
            let rows = edit
                .rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let here = i == edit.selected;
                    let value = match (&edit.typing, r) {
                        (Some(t), Setting::Limit(..)) if here => format!("{t}▏"),
                        _ => r.shown(),
                    };
                    format!("{} {:<30} {value}", if here { "▶" } else { " " }, r.name())
                })
                .collect::<Vec<_>>()
                .join("\n");
            (
                format!(" Edit account {} ", short(&edit.target)),
                format!(
                    "{rows}\n\n↑↓ select  space toggle / cycle  digits set a limit (-1 = unlimited)\n\
                     s save  Esc cancel. The mediator decides what this session may change."
                ),
                false,
            )
        }
        Popup::EditConfig { key, value } => (
            " Change a limit ".into(),
            format!(
                "{key}\n\nNew value  {value}▏\n\n\
                 ⏎ applies, Esc cancels. A patch can make a limit stricter than the\n\
                 configuration, not looser; the mediator says which keys apply now,\n\
                 which from its next start, and why any are refused."
            ),
            false,
        ),
        Popup::Text { title, body } => (
            title.clone(),
            format!("{body}\n\n(any key to close)"),
            false,
        ),
        Popup::ConfirmDelete { ids, about, .. } => (
            " Delete ".into(),
            format!(
                "Delete {} message(s)? This cannot be undone.\n\n{}\n\ny to confirm, any other key to cancel",
                ids.len(),
                about.join("\n"),
            ),
            true,
        ),
        Popup::FindGrants {
            principal,
            member,
            on_member,
        } => {
            let cursor = |on: bool| if on { "▏" } else { "" };
            (
                " Find stored grants ".into(),
                format!(
                    "Principal DID  {principal}{}\nMember DID     {member}{}\n\n\
                     Paste or type either or both. Tab switches field, ⏎ lists, Esc cancels.\n\
                     A member's listing shows its current epoch.",
                    cursor(!*on_member),
                    cursor(*on_member),
                ),
                false,
            )
        }
        Popup::ConfirmRevoke(selection) => (
            " Revoke grants ".into(),
            format!(
                "Revoke {}?\n\nRevoked grants are deleted and their members detached at once; \
                 the signed statements can never be stored again.\n\n\
                 y to confirm, any other key to cancel",
                selection.describe()
            ),
            true,
        ),
        Popup::ConfirmRevokeMarked(keys) => {
            let members = keys
                .iter()
                .map(|k| &k.member)
                .collect::<BTreeSet<_>>()
                .len();
            (
                " Revoke marked grants ".into(),
                format!(
                    "Revoke {} marked grant(s) of {members} member(s)?\n\n\
                     Each is revoked on its own: one the mediator refuses (a rootAdmin's, \
                     say) leaves the rest to go ahead, and you're told which.\n\n\
                     y to confirm, any other key to cancel",
                    keys.len()
                ),
                true,
            )
        }
        Popup::ConfirmBumpEpoch { did, epoch } => (
            " Advance a member's epoch ".into(),
            format!(
                "Member {did}\nCurrent epoch {epoch} → {}\n\n\
                 Every grant the member gave is voided and its session attaches end, \
                 without its signature. Only epoch {epoch} is named: if it has moved \
                 on since, nothing changes.\n\n\
                 y to confirm, any other key to cancel",
                epoch + 1
            ),
            true,
        ),
        Popup::ConfirmPurge(plan) => (
            " Purge ".into(),
            format!(
                "Account  {}\n\nPurge {} message(s) ({}) from the {} queue{}?\n\
                 Only messages queued before this count can go: one arriving now stays. \
                 Fewer may go, if some are delivered meanwhile.\n\
                 Undelivered messages are gone, not returned to their senders.\n\n\
                 y to confirm, any other key to cancel",
                plan.request
                    .target
                    .as_deref()
                    .map_or_else(|| "your own".to_string(), |t| label(book, t)),
                plan.matched,
                human_bytes(Some(plan.matched_bytes)),
                plan.request.queue,
                plan.request
                    .peer
                    .as_deref()
                    .map(|p| format!(" exchanged with {}", label(book, p)))
                    .unwrap_or_default(),
            ),
            true,
        ),
    };
    Some(shown)
}

/// A popup in a box over the middle of the screen.
fn render_box(f: &mut Frame, area: Rect, popup: &Popup, book: &AddressBook) {
    let Some((title, body, danger)) = content(popup, book) else {
        return;
    };
    let (tall, scroll) = match popup {
        Popup::Inspect { scroll, .. } => (true, *scroll),
        _ => (false, 0),
    };
    let w = area.width.saturating_sub(8).min(100);
    let h = area
        .height
        .saturating_sub(if tall { 2 } else { 4 })
        .min(match (tall, danger) {
            (true, _) => u16::MAX,
            (false, true) => 18,
            (false, false) => 40,
        });
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    let border = if danger { Color::Red } else { Color::Cyan };
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border))
                    .title(title),
            ),
        rect,
    );
}
