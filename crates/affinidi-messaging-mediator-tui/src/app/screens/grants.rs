//! Stored mux grants of a principal or member DID: list, mark, revoke,
//! advance a member's epoch.

use affinidi_messaging_mediator_admin::AddressBook;
use affinidi_messaging_mediator_admin::specs::mux::admin_list::v0_1::GrantState;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use super::super::format::{did_label, short, stamp};
use super::super::state::{GrantQuery, State, grant_key};
use super::{header_style, selected_style};

/// What the tab says before anything is looked up.
const HOW_TO: &str = "Stored mux grants: what each member DID delegated to which principal, \
     in what state, until when.\n\n\
     Press / to look one up by principal or member DID, or g on a \
     connection in the Mux tab.\n\n\
     On a grant: d revokes it, E advances its member's epoch (voiding every \
     grant the member gave), p and g list its principal's or member's grants. \
     Space marks grants (a marks every one listed, c clears) and d then \
     revokes the marked ones, each on its own.";

/// The Grants tab's title: what is listed, the member's epoch, how many.
pub(crate) fn grants_title(
    query: &GrantQuery,
    epoch: Option<u64>,
    shown: usize,
    more: bool,
    marked: usize,
    book: &AddressBook,
) -> String {
    let mut parts = Vec::new();
    if let Some(p) = &query.principal {
        parts.push(format!("principal {}", did_label(book, p)));
    }
    if let Some(m) = &query.member {
        parts.push(format!("member {}", did_label(book, m)));
    }
    if parts.is_empty() {
        return " Stored grants ".into();
    }
    let mut title = format!(" Grants of {}", parts.join(" · "));
    if let Some(e) = epoch {
        title.push_str(&format!(" · member epoch {e}"));
    }
    title.push_str(&format!(
        ": {shown}{} ",
        if more { "+ (] for more)" } else { "" }
    ));
    if marked > 0 {
        title.push_str(&format!("· {marked} marked "));
    }
    title
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let g = &mut s.grants;
    let book = &s.book;
    let block = Block::default().borders(Borders::ALL).title(grants_title(
        &g.query,
        g.epoch,
        g.rows.len(),
        g.next.is_some(),
        g.marks.len(),
        book,
    ));
    if g.query.is_empty() {
        f.render_widget(
            Paragraph::new(HOW_TO)
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
        return;
    }
    let rows: Vec<Row> = g
        .rows
        .iter()
        .map(|grant| {
            let color = match grant.state {
                GrantState::Active => Color::Green,
                GrantState::Suspended | GrantState::StaleKey => Color::Yellow,
                _ => Color::DarkGray,
            };
            let narrowed = if grant.narrowed == Some(true) {
                "*"
            } else {
                ""
            };
            let marked = g.marks.contains(&grant_key(grant));
            Row::new(vec![
                Cell::from(if marked { "●" } else { " " })
                    .style(Style::default().fg(Color::Magenta)),
                Cell::from(did_label(book, &grant.did)),
                Cell::from(did_label(book, &grant.principal)),
                Cell::from(grant.state.to_string()).style(Style::default().fg(color)),
                Cell::from(format!(
                    "{}{narrowed}",
                    super::mux::scope_words(&grant.scope.0)
                )),
                Cell::from(stamp(&grant.expires_at)),
                Cell::from(grant.epoch.to_string()),
                Cell::from(short(&grant.grant_id)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Length(12),
            Constraint::Fill(1),
            Constraint::Length(21),
            Constraint::Length(6),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec![
            "",
            "member",
            "principal",
            "state",
            "scope",
            "expires",
            "epoch",
            "grant",
        ])
        .style(header_style()),
    )
    .row_highlight_style(selected_style())
    .block(block);
    f.render_stateful_widget(table, area, &mut g.table);
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::super::state::fixtures::grant;
    use super::super::testing::{draw, state};
    use super::*;

    #[test]
    fn the_grants_title_says_what_is_listed_and_the_member_s_epoch() {
        let book = AddressBook::new();
        let none = GrantQuery::default();
        assert_eq!(
            grants_title(&none, None, 0, false, 0, &book),
            " Stored grants "
        );
        let member = GrantQuery {
            principal: None,
            member: Some("did:ex:m".into()),
        };
        assert_eq!(
            grants_title(&member, Some(2), 3, true, 0, &book),
            " Grants of member did:ex:m · member epoch 2: 3+ (] for more) "
        );
        let both = GrantQuery {
            principal: Some("did:ex:p".into()),
            member: Some("did:ex:m".into()),
        };
        assert_eq!(
            grants_title(&both, None, 1, false, 0, &book),
            " Grants of principal did:ex:p · member did:ex:m: 1 "
        );
        assert_eq!(
            grants_title(&both, None, 4, false, 2, &book),
            " Grants of principal did:ex:p · member did:ex:m: 4 · 2 marked "
        );
    }

    #[test]
    fn a_marked_grant_shows_its_mark_and_state() {
        let mut s = state(Tab::Grants);
        s.grants.query.member = Some("did:ex:m".into());
        s.grants.rows = vec![grant("did:ex:m", "g1"), grant("did:ex:m", "g2")];
        s.grants.marks.toggle(grant_key(&s.grants.rows[0]));
        let shown = draw(&mut s, 160, 12);
        assert!(shown.contains("● did:ex:m"), "{shown}");
        assert!(shown.contains("active"), "{shown}");
        assert!(shown.contains("1 marked"), "{shown}");
    }
}
