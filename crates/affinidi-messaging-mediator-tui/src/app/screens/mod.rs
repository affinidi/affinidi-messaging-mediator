//! The screens, each a function from [`State`] to a frame.
//!
//! Every `render` here reads the state and writes back only what drawing
//! learns — each table's scroll offset, how many rows fit — so a screen can
//! be drawn from typed fixtures with a test backend, no mediator needed.

pub(crate) mod account;
pub(crate) mod accounts;
pub(crate) mod audit;
pub(crate) mod config;
pub(crate) mod dashboard;
pub(crate) mod grants;
pub(crate) mod mux;
pub(crate) mod queues;

use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{ConnState, Mode, OPERATIONS_SINCE};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs, Wrap};

use super::Tab;
use super::format::{human_secs, label, short_did};
use super::state::State;
use crate::keymap;
use crate::quota::ColorDepth;

/// How long a notice stays in the footer before the key hints come back.
const NOTICE_FOR: Duration = Duration::from_secs(12);

/// Draw the whole console into `area`.
pub(crate) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    header(f, rows[0], s);
    tabs(f, rows[1], s);

    let body = if s.monitor.visible {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(rows[2]);
        super::monitor::render(f, split[1], s);
        split[0]
    } else {
        rows[2]
    };
    // A table's header and borders take three or four rows of the body.
    s.page_rows = body.height.saturating_sub(4) as usize;
    if !available(s) {
        unsupported(f, body, s);
    } else {
        match s.tab {
            Tab::Dashboard => dashboard::render(f, body, s),
            Tab::Queues => queues::render(f, body, s, " Queues "),
            Tab::Account => account::render(f, body, s),
            Tab::Audit => audit::render(f, body, s),
            Tab::Accounts => accounts::render(f, body, s),
            Tab::Config => config::render(f, body, s),
            Tab::Mux => mux::render(f, body, s),
            Tab::Grants => grants::render(f, body, s),
        }
    }
    footer(f, rows[3], s);
    super::popup::render(f, area, s);
    if s.depth == ColorDepth::Monochrome {
        crate::theme::strip_colors(f.buffer_mut(), area);
    }
}

/// Whether the current screen can fill on this mediator: one too old for
/// the operations tasks still serves the audit log, the accounts and the
/// configuration.
pub(crate) fn available(s: &State) -> bool {
    s.session.serves_operations || matches!(s.tab, Tab::Audit | Tab::Accounts | Tab::Config)
}

/// What the key table needs to know of the screen.
pub(crate) fn key_context(s: &State) -> keymap::Context {
    keymap::Context {
        tab: s.tab,
        monitor: s.monitor.visible,
        can_patch: s.session.can_patch_config,
    }
}

/// What a screen shows when the mediator predates the tasks it needs.
fn unsupported(f: &mut Frame, area: Rect, s: &State) {
    let (major, minor, patch) = OPERATIONS_SINCE;
    let version = s.session.mediator_version.as_deref().unwrap_or("unknown");
    let mut text = vec![
        Line::styled(
            format!("This mediator is version {version}."),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::raw(format!(
            "Statistics, queues, messages and the traffic monitor need \
             affinidi-messaging-mediator {major}.{minor}.{patch} or later."
        )),
        Line::raw("Upgrade the mediator to use this screen."),
    ];
    if s.session.admin() {
        text.push(Line::raw(""));
        text.push(Line::raw(
            "The Audit screen works on this mediator: press 4 or Tab.",
        ));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Not available on this mediator ")),
        area,
    );
}

fn header(f: &mut Frame, area: Rect, s: &State) {
    let (badge, color) = match s.session.mode {
        Mode::Admin { root: true } => (" ROOT ", Color::Red),
        Mode::Admin { root: false } => (" ADMIN ", Color::Yellow),
        Mode::SelfService => (" SELF ", Color::Cyan),
    };
    let age = s
        .updated
        .map(|t| format!("updated {}s ago", t.elapsed().as_secs()))
        .unwrap_or_else(|| "loading…".into());
    let (link, link_color) = link_badge(s.link, s.link_since.elapsed());
    let mut line = Line::from(vec![
        Span::styled(
            " mediator-console ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(badge, Style::default().fg(Color::Black).bg(color)),
        Span::styled(format!(" {link}"), Style::default().fg(link_color)),
        Span::raw(format!(
            "  {} → {}  ",
            label(&s.book, &s.session.did_hash),
            short_did(&s.session.mediator_did)
        )),
        Span::styled(age, Style::default().fg(Color::DarkGray)),
    ]);
    match &s.session.mediator_version {
        Some(v) if !s.session.serves_operations => line.push_span(Span::styled(
            format!("  ⚠ mediator {v} is too old for most screens"),
            Style::default().fg(Color::Yellow),
        )),
        Some(v) => line.push_span(Span::styled(
            format!("  mediator {v}"),
            Style::default().fg(Color::DarkGray),
        )),
        None => {}
    }
    if let Some(logs) = &s.logs {
        let unseen = logs.unseen();
        if unseen > 0 {
            line.push_span(Span::styled(
                format!("  ⚠ {unseen} log warning(s) — l to read"),
                Style::default().fg(Color::Yellow),
            ));
        }
    }
    f.render_widget(Paragraph::new(line), area);
}

/// The header's connection badge: what the SDK says of the connection, and
/// for how long (`since`) when it is down.
pub(crate) fn link_badge(link: Option<ConnState>, since: Duration) -> (String, Color) {
    match link {
        Some(ConnState::Connected) => ("● connected".into(), Color::Green),
        Some(ConnState::Connecting) => ("◌ connecting".into(), Color::DarkGray),
        Some(ConnState::Disconnected) => (
            format!(
                "✗ disconnected {} — reconnecting",
                human_secs(Some(since.as_secs()))
            ),
            Color::Red,
        ),
        // No websocket (or a state this console doesn't know): say so rather
        // than claim a connection.
        _ => ("? connection unknown".into(), Color::Yellow),
    }
}

fn tabs(f: &mut Frame, area: Rect, s: &State) {
    let tabs = s.tabs();
    let titles: Vec<Line> = tabs
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
        .collect();
    let selected = tabs.iter().position(|t| *t == s.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(titles)
            .select(selected)
            .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        area,
    );
}

fn footer(f: &mut Frame, area: Rect, s: &State) {
    let fresh = s.notice_at.is_some_and(|t| t.elapsed() < NOTICE_FOR);
    let notice = if fresh { s.notice.as_ref() } else { None };
    let line = match notice {
        Some((text, true)) => Line::styled(format!(" ✗ {text}"), Style::default().fg(Color::Red)),
        Some((text, false)) => {
            Line::styled(format!(" ✓ {text}"), Style::default().fg(Color::Green))
        }
        None => Line::styled(
            keymap::footer(key_context(s), area.width as usize),
            Style::default().fg(Color::DarkGray),
        ),
    };
    f.render_widget(Paragraph::new(line), area);
}

/// The table row style that marks the selection.
pub(super) fn selected_style() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// A table header row's style.
pub(super) fn header_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// When something was last loaded, for a title: `loaded 3m ago`.
pub(super) fn loaded_ago(at: Option<Instant>) -> String {
    at.map(|at| {
        format!(
            " · loaded {} ago, r reloads",
            human_secs(Some(at.elapsed().as_secs()))
        )
    })
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod testing {
    //! Draw a screen from fixtures and read back what it shows.
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::super::Tab;
    use super::super::state::{Session, State};
    use affinidi_messaging_mediator_admin::Mode;

    /// A state for an administrator on a current mediator, on `tab`.
    pub fn state(tab: Tab) -> State {
        let session = Session {
            mode: Mode::Admin { root: true },
            did_hash: "a".repeat(64),
            mediator_did: "did:example:mediator".into(),
            mediator_version: Some("0.52.0".into()),
            serves_operations: true,
            can_patch_config: true,
        };
        State::new(session, tab, None)
    }

    /// The text `render` draws into a `width` × `height` screen.
    pub fn draw(s: &mut State, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|f| super::render(f, f.area(), s))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connection_badge_is_never_a_stale_connected() {
        let (up, color) = link_badge(Some(ConnState::Connected), Duration::from_secs(90));
        assert_eq!((up.as_str(), color), ("● connected", Color::Green));
        let (down, color) = link_badge(Some(ConnState::Disconnected), Duration::from_secs(12));
        assert_eq!(color, Color::Red);
        assert!(down.contains("disconnected 12s"), "{down}");
        assert!(down.contains("reconnecting"), "{down}");
        // No websocket: unknown, not connected.
        let (unknown, _) = link_badge(None, Duration::ZERO);
        assert!(unknown.contains("unknown"), "{unknown}");
    }

    #[test]
    fn an_old_mediator_s_screens_say_why_they_are_empty() {
        let mut s = testing::state(Tab::Queues);
        s.session.serves_operations = false;
        s.session.mediator_version = Some("0.26.3".into());
        let shown = testing::draw(&mut s, 120, 20);
        assert!(shown.contains("Not available on this mediator"), "{shown}");
        assert!(shown.contains("version 0.26.3"), "{shown}");
        s.tab = Tab::Audit;
        let shown = testing::draw(&mut s, 120, 20);
        assert!(!shown.contains("Not available"), "{shown}");
    }
}
