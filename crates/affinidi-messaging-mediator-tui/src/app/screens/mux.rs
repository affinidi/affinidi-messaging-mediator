//! Live mux connections and the member DIDs each carries.

use affinidi_messaging_mediator_admin::specs::mux::connections::v0_1::{
    ConnectionMember, MuxCoverage,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::super::format::{did_label, short, stamp};
use super::super::state::{MuxPage, State};
use super::{header_style, selected_style};

/// The Mux tab's title: how many connections, and whether the page covers
/// every instance of the mediator or only the one that answered.
pub(crate) fn mux_title(page: Option<&MuxPage>) -> String {
    let Some(page) = page else {
        return " Mux connections: loading… ".into();
    };
    let n = page.connections.len();
    let more = if page.next_cursor.is_some() { "+" } else { "" };
    let coverage = match page.coverage {
        MuxCoverage::ThisInstance => " (this instance only)",
        _ => "",
    };
    format!(" Mux connections: {n}{more}{coverage} ")
}

/// A grant's or member's scope, as words.
pub(crate) fn scope_words<T: std::fmt::Display>(scope: &[T]) -> String {
    scope
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Min(5)])
        .split(area);
    let book = &s.book;
    let connections = s.mux.as_ref().map_or(&[][..], |p| &p.connections[..]);
    let rows: Vec<Row> = connections
        .iter()
        .map(|c| {
            let inactive = c.members.iter().filter(|m| !m.delivery_active).count();
            Row::new(vec![
                Cell::from(did_label(book, &c.principal)),
                Cell::from(c.wire.to_string()),
                Cell::from(stamp(&c.opened_at)),
                Cell::from(c.member_count.to_string()),
                Cell::from(if inactive > 0 {
                    inactive.to_string()
                } else {
                    String::new()
                })
                .style(Style::default().fg(Color::Yellow)),
                Cell::from(short(&c.session_id)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Length(8),
            Constraint::Length(21),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec![
            "principal",
            "wire",
            "opened",
            "members",
            "inactive",
            "session",
        ])
        .style(header_style()),
    )
    .row_highlight_style(selected_style())
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(mux_title(s.mux.as_ref())),
    );
    let selected = s.mux_table.selected().and_then(|i| connections.get(i));
    let members: &[ConnectionMember] = selected.map_or(&[], |c| &c.members);
    let member_rows: Vec<Row> = members
        .iter()
        .map(|m| {
            Row::new(vec![
                Cell::from(did_label(book, &m.did)),
                Cell::from(m.source.to_string()),
                Cell::from(scope_words(&m.scope.0)),
                Cell::from(stamp(&m.expires_at)),
                Cell::from(if m.delivery_active {
                    "live"
                } else {
                    "inactive"
                })
                .style(Style::default().fg(if m.delivery_active {
                    Color::Green
                } else {
                    Color::Yellow
                })),
            ])
        })
        .collect();
    let shown = members.len() as u64;
    let total = selected.map_or(0, |c| c.member_count);
    let members_title = if shown < total {
        format!(" Members ({shown} of {total} shown) ")
    } else {
        format!(" Members ({total}) ")
    };
    let members = Table::new(
        member_rows,
        [
            Constraint::Fill(2),
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Length(21),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(vec!["member", "source", "scope", "expires", "delivery"]).style(header_style()),
    )
    .block(Block::default().borders(Borders::ALL).title(members_title));
    f.render_stateful_widget(table, parts[0], &mut s.mux_table);
    f.render_widget(members, parts[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mux_title_says_what_the_page_covers() {
        let connection = serde_json::json!({
            "memberCount": 0, "members": [], "openedAt": "2026-09-21T10:00:00Z",
            "principal": "did:example:p", "sessionId": "s", "wire": "didcomm",
        });
        let page: MuxPage = serde_json::from_value(serde_json::json!({
            "connections": [connection.clone(), connection],
            "coverage": "thisInstance", "nextCursor": "c",
        }))
        .unwrap();
        assert_eq!(
            mux_title(Some(&page)),
            " Mux connections: 2+ (this instance only) "
        );
        let all: MuxPage = serde_json::from_value(serde_json::json!({
            "connections": [], "coverage": "allInstances",
        }))
        .unwrap();
        assert_eq!(mux_title(Some(&all)), " Mux connections: 0 ");
    }
}
