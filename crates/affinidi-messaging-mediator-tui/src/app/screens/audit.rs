//! The audit log, newest first, as `audit/list` 0.2 records each entry:
//! when, who, what, to whom, how it ended, and its detail.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::super::format::{count_shown, detail_line, did_label, when_of};
use super::super::state::State;
use super::{header_style, selected_style};

/// Whether an audit `action` is a DID-multiplexing one (`mux_grant_suspend`,
/// `mux_grant_revoke`, `mux_revoke_all`, and any later `mux_` action).
pub(crate) fn is_mux_action(action: &str) -> bool {
    action.starts_with("mux_")
}

/// The colour of an entry's outcome.
fn outcome_color(outcome: Option<&str>) -> Color {
    match outcome {
        Some("success") => Color::Green,
        None | Some("") => Color::Reset,
        Some("denied" | "failure" | "failed" | "error") => Color::Red,
        Some(_) => Color::Yellow,
    }
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let book = &s.book;
    let rows: Vec<Row> = s
        .audit
        .rows
        .iter()
        .map(|e| {
            let action = e.action.as_str();
            // DID-multiplexing decisions (grants suspended under the
            // unknown-key rule, revoked, an epoch advanced) stand out:
            // each one cut a device off from a DID.
            let style = if is_mux_action(action) {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default()
            };
            // Actor and target are DIDs (absent once redacted).
            let did =
                |d: &Option<String>| d.as_deref().map_or("–".into(), |d| did_label(book, d));
            let outcome = e.outcome.as_deref();
            Row::new(vec![
                Cell::from(when_of(&e.recorded_at)),
                Cell::from(did(&e.actor)),
                Cell::from(action.to_string()),
                Cell::from(did(&e.target)),
                Cell::from(outcome.unwrap_or_default().to_string())
                    .style(Style::default().fg(outcome_color(outcome))),
                Cell::from(detail_line(&e.detail)),
            ])
            .style(style)
        })
        .collect();
    let title = format!(
        " Audit log — {} entries, newest first{} ",
        count_shown(s.audit.rows.len(), None, s.audit.next.is_some()),
        if s.audit.paged() {
            " (paged: r reloads)"
        } else {
            ""
        }
    );
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(15),
                Constraint::Fill(1),
                Constraint::Length(20),
                Constraint::Fill(1),
                Constraint::Length(8),
                Constraint::Fill(3),
            ],
        )
        .header(
            Row::new(vec![
                "when", "actor", "action", "target", "outcome", "detail",
            ])
            .style(header_style()),
        )
        .row_highlight_style(selected_style())
        .block(Block::default().borders(Borders::ALL).title(title)),
        area,
        &mut s.audit.table,
    );
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::testing::{draw, state};
    use super::*;

    #[test]
    fn mux_audit_actions_are_recognised() {
        for a in ["mux_grant_suspend", "mux_grant_revoke", "mux_revoke_all"] {
            assert!(is_mux_action(a), "{a}");
        }
        assert!(!is_mux_action("account_remove"));
    }

    #[test]
    fn an_entry_shows_its_action_outcome_and_detail() {
        let mut s = state(Tab::Audit);
        let entry = serde_json::from_value(serde_json::json!({
            "eventId": "e-1", "action": "account_remove", "actor": "did:example:op",
            "target": "did:example:gone", "outcome": "denied",
            "recordedAt": "2026-09-21T10:00:00Z", "detail": { "reason": "protected" },
        }))
        .expect("an audit entry");
        s.audit
            .take(vec![entry], Some("next".into()), false, |_| {});
        let shown = draw(&mut s, 160, 12);
        for want in [
            "account_remove",
            "denied",
            "reason=protected",
            "1+ (] more)",
        ] {
            assert!(shown.contains(want), "{want}:\n{shown}");
        }
        assert_eq!(outcome_color(Some("denied")), Color::Red);
        assert_eq!(outcome_color(None), Color::Reset);
    }
}
