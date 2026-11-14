//! The mediator's configuration, key by key; a rootAdmin changes limits
//! from here.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::super::format::{config_value, fit_width};
use super::super::state::{ConfigRow, State};
use super::{header_style, selected_style};

/// Whether a key's value is an override set at runtime (`config/patch`).
pub(crate) fn is_override(field: &ConfigRow) -> bool {
    field.source.as_str() == "override"
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let fields = &s.config.rows;
    let keys: Vec<String> = fields.iter().map(|c| c.key.to_string()).collect();
    let rows: Vec<Row> = fields
        .iter()
        .zip(&keys)
        .map(|(c, key)| {
            Row::new(vec![
                Cell::from(key.clone()),
                Cell::from(config_value(&c.value)),
                Cell::from(c.source.to_string()).style(if is_override(c) {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
                Cell::from(if c.requires_restart {
                    "restart"
                } else {
                    "live"
                }),
            ])
        })
        .collect();
    let overrides = fields.iter().filter(|c| is_override(c)).count();
    let table = Table::new(
        rows,
        [
            Constraint::Length(fit_width(&keys, 20, 48)),
            Constraint::Fill(2),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(vec!["key", "value", "from", "applies"]).style(header_style()))
    .row_highlight_style(selected_style())
    .block(Block::default().borders(Borders::ALL).title(format!(
        " Configuration — {} keys, {overrides} overridden{} ",
        fields.len(),
        if s.session.can_patch_config {
            ""
        } else {
            " · read only (changing limits needs a rootAdmin)"
        }
    )));
    f.render_stateful_widget(table, area, &mut s.config.table);
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::testing::{draw, state};
    use super::*;

    #[test]
    fn overrides_are_counted_and_read_only_is_said() {
        let mut s = state(Tab::Config);
        s.session.can_patch_config = false;
        let field = |key: &str, source: &str, restart: bool| -> ConfigRow {
            serde_json::from_value(serde_json::json!({
                "key": key, "value": 5, "source": source, "requiresRestart": restart,
            }))
            .expect("a config field")
        };
        s.config.take(
            vec![
                field("limits.a", "override", false),
                field("server.b", "file", true),
            ],
            None,
            false,
            |_| {},
        );
        let shown = draw(&mut s, 140, 12);
        assert!(shown.contains("2 keys, 1 overridden"), "{shown}");
        assert!(shown.contains("read only"), "{shown}");
        assert!(shown.contains("restart"), "{shown}");
    }
}
