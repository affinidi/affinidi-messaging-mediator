//! The Account screen: one account's queues against their limits, who has
//! not collected, its settings, and the messages in one of its queues.

use affinidi_messaging_mediator_admin::specs::account::get::v0_2::{AccountStats, ProtocolCounts};
use affinidi_messaging_mediator_admin::specs::message::list::v0_1::DeliveryState;
use affinidi_messaging_mediator_admin::specs::queue::status::v0_1::QueueDepth;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use super::super::format::{
    ago, count_shown, human_bytes, human_secs, label, limit_of, percent, short, time_of,
};
use super::super::state::{AccountInfo, State};
use super::{header_style, selected_style};
use crate::account_edit::acl_flags;
use crate::quota::QuotaBar;

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Min(4),
        ])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(parts[0]);
    settings(f, top[1], s);
    let who = s.target.as_deref().map_or_else(
        || format!("{} (you)", short(&s.session.did_hash)),
        |t| label(&s.book, t),
    );

    // Two gradient bars: how full each queue is against its limit.
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Account {who} "));
    let inner = block.inner(top[0]);
    f.render_widget(block, top[0]);
    let lines = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1); 4])
        .split(inner);
    let queues = s.status.as_ref().map(|st| &st.queues);
    let sides: [(&str, Option<&QueueDepth>); 2] = [
        ("receive", queues.map(|q| &q.receive)),
        ("send", queues.map(|q| &q.send)),
    ];
    for (i, (side, d)) in sides.into_iter().enumerate() {
        let saturation = d.and_then(|d| d.saturation);
        f.render_widget(
            Paragraph::new(format!(
                "{side:>7}: {} / {}  {}  oldest {}",
                d.map_or(0, |d| d.count),
                limit_of(d.and_then(|d| d.limit)),
                saturation.map_or(String::new(), |_| percent(saturation)),
                human_secs(d.and_then(|d| d.oldest_age_seconds)),
            )),
            lines[i * 2],
        );
        f.render_widget(QuotaBar::new(saturation, s.depth), lines[i * 2 + 1]);
    }

    // Who has not collected: the send queue by recipient.
    let peer_rows: Vec<Row> = s
        .status
        .iter()
        .flat_map(|st| &st.send_peers)
        .map(|p| {
            Row::new(vec![
                label(&s.book, &p.peer),
                p.count.to_string(),
                human_bytes(Some(p.bytes)),
                human_secs(p.oldest_age_seconds),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            peer_rows,
            [
                Constraint::Fill(1),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
        .header(Row::new(vec!["recipient", "waiting", "bytes", "oldest"]).style(header_style()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Send queue by recipient — who hasn't collected "),
        ),
        parts[1],
    );

    let rows: Vec<Row> = s
        .messages
        .rows
        .iter()
        .map(|m| {
            let delivered = m.delivery_state == Some(DeliveryState::Delivered);
            let state = m.delivery_state.map(|d| d.to_string()).unwrap_or_default();
            Row::new(vec![
                Cell::from(time_of(&m.received_at)),
                Cell::from(
                    m.from
                        .as_deref()
                        .map_or_else(|| "anon".to_string(), |h| label(&s.book, h)),
                ),
                Cell::from(m.to.as_deref().map_or("?".into(), |h| label(&s.book, h))),
                Cell::from(human_bytes(Some(m.size))),
                Cell::from(Span::styled(
                    state,
                    Style::default().fg(if delivered {
                        Color::Yellow
                    } else {
                        Color::Reset
                    }),
                )),
                Cell::from(short(&m.msg_id)),
            ])
        })
        .collect();
    // How many the queue holds, from its status: the list is a page of it.
    let total = queues.map(|q| {
        if s.message_send {
            q.send.count
        } else {
            q.receive.count
        }
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["at", "from", "to", "size", "state", "id"]).style(header_style()))
    .row_highlight_style(selected_style())
    .block(Block::default().borders(Borders::ALL).title(format!(
        " {} queue — {} messages{} ",
        if s.message_send { "Send" } else { "Receive" },
        count_shown(s.messages.rows.len(), total, s.messages.next.is_some()),
        if s.messages.paged() {
            " (paged: r reloads)"
        } else {
            ""
        }
    )));
    f.render_stateful_widget(table, parts[2], &mut s.messages.table);
}

/// The settings panel: role, limits, access list, activity, lifetime
/// counters, ACL flags.
fn settings(f: &mut Frame, area: Rect, s: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings — e to edit ");
    let Some(a) = &s.account_info else {
        f.render_widget(Paragraph::new("loading…").block(block), area);
        return;
    };
    f.render_widget(
        Paragraph::new(settings_lines(a))
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// What the settings panel says of account `a`.
pub(crate) fn settings_lines(a: &AccountInfo) -> Vec<Line<'static>> {
    use affinidi_messaging_mediator_admin::specs::account::get::v0_2::AccountType;
    let limit = |l: Option<i64>| match l {
        Some(-1) => "unlimited".to_string(),
        Some(n) => n.to_string(),
        None => "default".to_string(),
    };
    let limits = a.queue_limits.as_ref();
    let role_style = match a.account_type {
        AccountType::RootAdmin => Style::default().fg(Color::Red),
        AccountType::Admin => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
    let flags: Vec<Span> = acl_flags(&a.acl)
        .into_iter()
        .filter_map(|(name, on)| on.map(|on| (name, on)))
        .map(|(name, on)| {
            Span::styled(
                format!("{}{name} ", if on { "✓" } else { "✗" }),
                Style::default().fg(if on { Color::Green } else { Color::DarkGray }),
            )
        })
        .collect();
    vec![
        Line::from(vec![
            Span::raw("role "),
            Span::styled(a.account_type.to_string(), role_style),
        ]),
        Line::raw(format!(
            "limits  send {}  receive {}",
            limit(limits.and_then(|l| l.send_queue_limit)),
            limit(limits.and_then(|l| l.receive_queue_limit))
        )),
        Line::raw(format!(
            "access list  {} ({} entries)",
            a.acl
                .access_list_mode
                .map_or("default".into(), |m| m.to_string()),
            a.access_list_count
                .map_or("?".into(), |n: u64| n.to_string())
        )),
        Line::raw(format!(
            "last message {} ago  last login {} ago",
            ago(a.last_received_at),
            ago(a.last_authenticated_at)
        )),
        Line::raw(a.stats.as_ref().map(lifetime_totals).unwrap_or_default()),
        Line::from(flags),
    ]
}

/// An account's lifetime totals as the mediator counted them — not the
/// monitor's view, which only covers the current session. Absent against a
/// mediator that doesn't serve them.
fn lifetime_totals(stats: &AccountStats) -> String {
    let n = |v: Option<u64>| v.unwrap_or(0);
    let mix = |counts: &Option<ProtocolCounts>| {
        let Some(c) = counts else {
            return String::new();
        };
        let tsp = n(c.tsp);
        let didcomm = n(c.didcomm) + n(c.didcomm_v1);
        match tsp + didcomm {
            0 => String::new(),
            total => format!(" ({}% tsp)", tsp * 100 / total),
        }
    };
    format!(
        "lifetime  in {} / {}{}   out {} / {}{}",
        n(stats.messages_received),
        human_bytes(Some(n(stats.bytes_received))),
        mix(&stats.received_by_protocol),
        n(stats.messages_sent),
        human_bytes(Some(n(stats.bytes_sent))),
        mix(&stats.sent_by_protocol),
    )
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::testing::{draw, state};
    use super::*;

    fn account() -> AccountInfo {
        let now = chrono::Utc::now();
        serde_json::from_value(serde_json::json!({
            "did": "b".repeat(64), "accountType": "admin",
            "acl": { "sendMessages": true, "blocked": false, "accessListMode": "explicitDeny" },
            "accessListCount": 3,
            "queueLimits": { "sendQueueLimit": -1 },
            "lastReceivedAt": (now - chrono::Duration::minutes(5)).to_rfc3339(),
            "lastAuthenticatedAt": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "stats": {
                "messagesReceived": 4, "bytesReceived": 2048,
                "receivedByProtocol": { "tsp": 1, "didcomm": 3 },
            },
        }))
        .expect("an account")
    }

    #[test]
    fn the_settings_read_every_typed_member() {
        let text: Vec<String> = settings_lines(&account())
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
            .collect();
        let text = text.join("\n");
        for want in [
            "role admin",
            "limits  send unlimited  receive default",
            "access list  explicitDeny (3 entries)",
            // Activity times are instants, not seconds: read as such.
            "last message 5m ago  last login 2h ago",
            "lifetime  in 4 / 2.0K (25% tsp)",
            "✓sendMessages",
            "✗blocked",
        ] {
            assert!(text.contains(want), "{want}:\n{text}");
        }
    }

    #[test]
    fn the_account_screen_shows_settings_and_messages() {
        let mut s = state(Tab::Account);
        s.account_info = Some(account());
        s.messages.take(
            vec![super::super::super::state::fixtures::message("m-1")],
            None,
            false,
            |_| {},
        );
        let shown = draw(&mut s, 140, 30);
        assert!(shown.contains("role admin"), "{shown}");
        assert!(shown.contains("Receive queue — 1 messages"), "{shown}");
        assert!(shown.contains("m-1"), "{shown}");
    }
}
