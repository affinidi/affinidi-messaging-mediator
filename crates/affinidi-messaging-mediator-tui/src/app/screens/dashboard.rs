//! The Dashboard: the mediator's statistics, its queue pressure, and the
//! busiest queues.

use affinidi_messaging_mediator_admin::specs::stats::show::v0_1::{
    QueueDepth, ResponseForwardingCircuitBreaker,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use serde::Deserialize;

use super::super::format::{human_secs, percent};
use super::super::state::{State, StatsReport};
use crate::quota::QuotaBar;

/// The `com.affinidi.mux` extension of `stats/show`: DID multiplexing on
/// the instance that answered. Not part of the task's own schema, so read
/// here with every member optional.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct MuxStats {
    pub connections: u64,
    pub members: u64,
    pub members_by_grant: u64,
    pub members_by_attach: u64,
    pub members_inactive: u64,
}

/// The extension's member name.
const MUX_EXTENSION: &str = "com.affinidi.mux";

impl MuxStats {
    /// The extension in `stats`, when the mediator reports it.
    pub fn of(stats: &StatsReport) -> Option<Self> {
        let ext = stats.ext.as_ref()?;
        let (_, value) = ext.iter().find(|(k, _)| k.as_str() == MUX_EXTENSION)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// The dashboard's line for it.
    pub fn line(&self) -> String {
        let mut line = format!(
            "mux {} connections, {} members ({} grant, {} attach)",
            self.connections, self.members, self.members_by_grant, self.members_by_attach
        );
        if self.members_inactive > 0 {
            line.push_str(&format!(", {} inactive", self.members_inactive));
        }
        line
    }
}

pub(super) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(4)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(parts[0]);

    f.render_widget(
        Paragraph::new(mediator_lines(s.stats.as_ref()))
            .block(Block::default().borders(Borders::ALL).title(" Mediator ")),
        top[0],
    );

    // Aggregate queue pressure: the fullest single queue, as a gradient.
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Queue pressure ");
    let inner = block.inner(top[1]);
    f.render_widget(block, top[1]);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1); 6])
        .split(inner);
    let queues = s.stats.as_ref().and_then(|st| st.queues.as_ref());
    let sides: [(&str, Option<&QueueDepth>); 2] = [
        ("receive", queues.and_then(|q| q.receive.as_ref())),
        ("send", queues.and_then(|q| q.send.as_ref())),
    ];
    for (i, (name, depth)) in sides.into_iter().enumerate() {
        let saturation = depth.and_then(|d| d.saturation);
        f.render_widget(
            Paragraph::new(format!(
                "{name}: {} msgs, worst queue {}, oldest {}",
                depth.map_or(0, |d| d.count),
                percent(saturation),
                human_secs(depth.and_then(|d| d.oldest_age_seconds))
            )),
            rows[i * 3],
        );
        f.render_widget(QuotaBar::new(saturation, s.depth), rows[i * 3 + 1]);
    }

    super::queues::render(f, parts[1], s, " Busiest queues ");
}

/// The Mediator panel: version and uptime, connections, lifetime counters,
/// forwarding, and DID multiplexing when the mediator reports it.
fn mediator_lines(stats: Option<&StatsReport>) -> Vec<Line<'static>> {
    let Some(st) = stats else {
        return vec![Line::raw("loading…")];
    };
    let n = |v: Option<u64>| v.map_or("–".into(), |v| v.to_string());
    let breaker = st.forwarding.circuit_breaker;
    let breaker_color = match breaker {
        Some(ResponseForwardingCircuitBreaker::Open) => Color::Red,
        Some(ResponseForwardingCircuitBreaker::HalfOpen) => Color::Yellow,
        _ => Color::Green,
    };
    let mut lines = vec![
        Line::from(format!(
            "version {}   up {}",
            st.version.as_str(),
            human_secs(Some(st.uptime_seconds))
        )),
        Line::from(format!(
            "websockets {} / {}",
            st.connections.websocket_active,
            n(st.connections.websocket_max)
        )),
        Line::from(format!(
            "stored {}   delivered {}   deleted {}",
            st.totals.received_count, st.totals.sent_count, st.totals.deleted_count
        )),
        Line::from(format!(
            "sessions {} ({} authenticated)",
            n(st.totals.sessions_created),
            n(st.totals.sessions_authenticated)
        )),
        Line::from(vec![
            Span::raw(format!(
                "forwarding {} / {}   breaker ",
                st.forwarding.queue_length,
                n(st.forwarding.queue_limit)
            )),
            Span::styled(
                breaker.map_or("–".into(), |b| b.to_string()),
                Style::default().fg(breaker_color),
            ),
        ]),
    ];
    // DID multiplexing, when the mediator reports it (counts are for the
    // instance answering).
    if let Some(mux) = MuxStats::of(st) {
        lines.push(Line::from(mux.line()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::super::super::Tab;
    use super::super::testing::{draw, state};
    use super::*;

    fn stats() -> StatsReport {
        serde_json::from_value(serde_json::json!({
            "version": "0.52.0", "uptimeSeconds": 7200,
            "connections": { "websocketActive": 3, "websocketMax": 100 },
            "forwarding": { "queueLength": 1, "queueLimit": 50, "circuitBreaker": "halfOpen" },
            "totals": {
                "receivedCount": 11, "receivedBytes": 1, "sentCount": 9, "sentBytes": 1,
                "deletedCount": 8, "sessionsCreated": 4, "sessionsAuthenticated": 2,
            },
            "queues": {
                "accounts": 2, "surveyedAt": "2026-09-21T10:00:00Z",
                "receive": { "count": 5, "bytes": 50, "saturation": 0.25 },
            },
            "ext": { "com.affinidi.mux": {
                "scope": "instance", "connections": 2, "members": 5,
                "membersByGrant": 4, "membersByAttach": 1, "membersInactive": 1,
            } },
        }))
        .expect("a stats report")
    }

    #[test]
    fn the_mux_summary_line_reads_the_extension() {
        let mux = MuxStats::of(&stats()).expect("the extension");
        assert_eq!(
            mux.line(),
            "mux 2 connections, 5 members (4 grant, 1 attach), 1 inactive"
        );
        let quiet = MuxStats::default();
        assert_eq!(
            quiet.line(),
            "mux 0 connections, 0 members (0 grant, 0 attach)"
        );
    }

    #[test]
    fn the_dashboard_shows_the_typed_statistics() {
        let mut s = state(Tab::Dashboard);
        s.stats = Some(stats());
        let shown = draw(&mut s, 140, 24);
        for want in [
            "version 0.52.0   up 2h",
            "websockets 3 / 100",
            "stored 11   delivered 9   deleted 8",
            "sessions 4 (2 authenticated)",
            "breaker halfOpen",
            "receive: 5 msgs, worst queue 25%",
            "mux 2 connections",
        ] {
            assert!(shown.contains(want), "{want}:\n{shown}");
        }
    }
}
