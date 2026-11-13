//! Every account on the mediator: role, queues, activity, access list.

use affinidi_messaging_mediator_admin::AddressBook;
use affinidi_messaging_mediator_admin::specs::account::list::v0_2::AccountType;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::super::format::{ago, count_shown, fit_width, human_bytes, label, short};
use super::super::state::{AccountRow, State};
use super::{header_style, loaded_ago, selected_style};

/// The list's order: the mediator and administrators first, then accounts
/// you have named (by name), then the rest by hash.
pub(crate) fn account_order(a: &AccountRow, book: &AddressBook) -> (u8, String) {
    let hash = a.did.as_str();
    let rank = match a.account_type {
        AccountType::Mediator => 0,
        AccountType::RootAdmin => 1,
        AccountType::Admin => 2,
        _ if book.name_of(hash).is_some() => 3,
        _ => 4,
    };
    let key = book
        .name_of(hash)
        .map(str::to_lowercase)
        .unwrap_or_else(|| hash.to_string());
    (rank, key)
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let book = &s.book;
    let names: Vec<String> = s
        .accounts
        .rows
        .iter()
        .map(|a| label(book, &a.did))
        .collect();
    let name_width = fit_width(&names, 15, 40);
    let rows: Vec<Row> = s
        .accounts
        .rows
        .iter()
        .zip(&names)
        .map(|(a, name)| {
            let n = |v: Option<u64>| v.map_or("–".into(), |v| v.to_string());
            let bytes = a.receive_queue_bytes.unwrap_or(0) + a.send_queue_bytes.unwrap_or(0);
            let style = match a.account_type {
                AccountType::RootAdmin => Style::default().fg(Color::Red),
                AccountType::Admin => Style::default().fg(Color::Yellow),
                AccountType::Mediator => Style::default().fg(Color::Cyan),
                _ => Style::default(),
            };
            Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(if book.name_of(&a.did).is_some() {
                    short(&a.did)
                } else {
                    String::new()
                }),
                Cell::from(a.account_type.to_string()).style(style),
                Cell::from(n(a.receive_queue_count)),
                Cell::from(n(a.send_queue_count)),
                Cell::from(human_bytes(Some(bytes))),
                Cell::from(ago(a.last_received_at)),
                Cell::from(ago(a.last_authenticated_at)),
                Cell::from(n(a.access_list_count)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(name_width),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec![
            "account",
            "hash",
            "role",
            "receive",
            "send",
            "queued",
            "msg ago",
            "login ago",
            "access list",
        ])
        .style(header_style()),
    )
    .row_highlight_style(selected_style())
    .block(Block::default().borders(Borders::ALL).title(format!(
        " Accounts — {}{} ",
        count_shown(s.accounts.rows.len(), None, s.accounts.next.is_some()),
        loaded_ago(s.accounts_loaded)
    )));
    f.render_stateful_widget(table, area, &mut s.accounts.table);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(hash: &str, role: &str) -> AccountRow {
        serde_json::from_value(serde_json::json!({
            "did": hash, "accountType": role, "acl": {},
        }))
        .expect("an account row")
    }

    #[test]
    fn privileged_accounts_come_first_then_named_ones() {
        let mut book = AddressBook::new();
        book.insert("did:example:zed", "Zed");
        let zed = affinidi_messaging_mediator_admin::account_hash("did:example:zed");
        let mut rows = [
            row("bb", "standard"),
            row(&zed, "standard"),
            row("aa", "admin"),
            row("mm", "mediator"),
        ];
        rows.sort_by_cached_key(|a| account_order(a, &book));
        let order: Vec<&str> = rows.iter().map(|a| a.did.as_str()).collect();
        assert_eq!(order, ["mm", "aa", zed.as_str(), "bb"]);
    }
}
