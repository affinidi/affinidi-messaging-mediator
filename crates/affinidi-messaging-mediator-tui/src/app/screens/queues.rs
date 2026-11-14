//! The queue ranking: every account's queues against their limits, as
//! gradient quota bars (Queues, and the bottom of the Dashboard).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::super::format::{count_shown, fit_width, human_secs, label, limit_of};
use super::super::state::{SORTS, State};
use super::{header_style, selected_style};
use crate::quota::quota_line;

/// The ranking, as a table titled `title`.
pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State, title: &str) {
    let rows = &s.queues.rows;
    // The account column fits the longest name (within reason) and the two
    // quota bars share whatever width is left, so the table uses the pane.
    let names: Vec<String> = rows.iter().map(|q| label(&s.book, &q.did)).collect();
    let inner = area.width.saturating_sub(2);
    const FIXED: u16 = 9 + 11 + 11 + 8 + 6; // role, two counts, oldest, gaps
    let account_width = fit_width(&names, 15, 40);
    let bar_width = (inner.saturating_sub(account_width + FIXED) / 2).clamp(8, 40);
    let depth = s.depth;
    let table_rows: Vec<Row> = rows
        .iter()
        .zip(&names)
        .map(|(q, name)| {
            let (r, d) = (&q.receive, &q.send);
            Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(q.account_type.map(|t| t.to_string()).unwrap_or_default()),
                Cell::from(format!("{}/{}", r.count, limit_of(r.limit))),
                Cell::from(quota_line(r.saturation, bar_width, depth)),
                Cell::from(format!("{}/{}", d.count, limit_of(d.limit))),
                Cell::from(quota_line(d.saturation, bar_width, depth)),
                Cell::from(human_secs(r.oldest_age_seconds.max(d.oldest_age_seconds))),
            ])
        })
        .collect();
    let snapshot = s
        .queues_snapshot
        .map(|at| format!(" survey {} ", at.format("%Y-%m-%d %H:%M:%SZ")))
        .unwrap_or_default();
    let title = format!(
        "{title}— {} by {} of {} queue{snapshot}",
        count_shown(rows.len(), None, s.queues.next.is_some()),
        SORTS[s.sort].1,
        if s.queue_send { "send" } else { "receive" }
    );
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(account_width),
            Constraint::Length(9),
            Constraint::Length(11),
            Constraint::Length(bar_width),
            Constraint::Length(11),
            Constraint::Length(bar_width),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["account", "role", "receive", "", "send", "", "oldest"])
            .style(header_style()),
    )
    .row_highlight_style(selected_style())
    .block(Block::default().borders(Borders::ALL).title(title));
    f.render_stateful_widget(table, area, &mut s.queues.table);
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::testing::{draw, state};

    #[test]
    fn the_ranking_shows_each_queue_against_its_limit() {
        let mut s = state(Tab::Queues);
        let page: super::super::super::state::QueueRow =
            serde_json::from_value(serde_json::json!({
                "did": "b".repeat(64), "accountType": "admin",
                "receive": { "count": 7, "bytes": 70, "limit": 10, "saturation": 0.7 },
                "send": { "count": 2, "bytes": 20, "oldestAgeSeconds": 120 },
            }))
            .expect("a queue row");
        s.queues.take(vec![page], None, false, |_| {});
        let shown = draw(&mut s, 140, 20);
        assert!(shown.contains("7/10"), "{shown}");
        assert!(shown.contains("2/∞"), "{shown}");
        assert!(shown.contains("admin"), "{shown}");
        assert!(shown.contains("2m"), "the oldest message's age: {shown}");
    }
}
