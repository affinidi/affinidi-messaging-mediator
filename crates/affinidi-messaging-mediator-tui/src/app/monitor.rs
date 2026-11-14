//! The live traffic monitor: its pane, the feed behind it, and how its
//! lines are drawn.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{
    AddressBook, ConnState, ConsoleError, MediatorConsole, MembershipEvent, MembershipFilter,
    MonitorEvent, MonitorFilter, MonitorUpdate, specs,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use tokio::sync::mpsc;

use super::format::{fit, fit_width, human_bytes, human_secs, label, time_of};
use super::state::State;
use super::{App, Update};
use crate::tally::{ProtocolMix, TrafficTally};

/// A feed this long without even a heartbeat (the mediator sends one every
/// 30 s) is taken as gone, the way a mediator restart leaves it, and replaced.
const MONITOR_SILENCE: Duration = Duration::from_secs(90);
/// First wait before resubscribing the monitor; it doubles up to the cap.
const RESUBSCRIBE: Duration = Duration::from_secs(2);
const RESUBSCRIBE_MAX: Duration = Duration::from_secs(30);
/// Monitor lines kept for scrolling back; older ones are dropped.
const MONITOR_LINES: usize = 2000;

/// One line of the monitor pane. Events are kept as they arrived and drawn
/// on each frame, so naming an account renames it in the lines already shown.
pub(crate) enum MonitorLine {
    Event(MonitorEvent),
    /// A mux member attached to or detached from a principal's connection.
    Membership(MembershipEvent),
    Note(Line<'static>),
    /// The feed was interrupted; one line however many attempts it takes.
    Retry {
        reason: String,
        attempts: u32,
    },
}

/// The monitor pane.
pub(crate) struct MonitorPane {
    pub visible: bool,
    /// A feed task is running (the pane may still be resubscribing).
    pub running: bool,
    pub failures_only: bool,
    pub lines: VecDeque<MonitorLine>,
    pub dropped: u64,
    pub gaps: u64,
    pub last_seen: Option<Instant>,
    pub watching: String,
    /// Totals since the monitor (re)started.
    pub tally: TrafficTally,
    /// Show the per-account totals instead of the live lines.
    pub show_totals: bool,
    /// Lines scrolled back from the newest; 0 follows new traffic.
    pub back: usize,
    /// Rows the pane showed last frame: a page, for scrolling.
    pub page: usize,
    /// When the monitor resubscribes, while it's between feeds.
    pub retry_at: Option<Instant>,
    /// The feed reported the connection down, and not yet back.
    pub link_down: bool,
}

impl MonitorPane {
    pub fn new() -> Self {
        Self {
            visible: false,
            running: false,
            failures_only: false,
            lines: VecDeque::new(),
            dropped: 0,
            gaps: 0,
            last_seen: None,
            watching: String::new(),
            tally: TrafficTally::new(Instant::now()),
            show_totals: false,
            back: 0,
            page: 0,
            retry_at: None,
            link_down: false,
        }
    }

    /// Scroll `by` lines towards older traffic (negative: newer).
    pub fn scroll(&mut self, by: i64) {
        let oldest = self.lines.len().saturating_sub(self.page.max(1));
        let back = (self.back as i64).saturating_add(by);
        self.back = back.clamp(0, oldest as i64) as usize;
    }

    /// Add a line: a view scrolled back stays on what it shows, and the
    /// oldest lines go past the limit.
    pub fn push(&mut self, line: MonitorLine) {
        self.lines.push_back(line);
        if self.back > 0 {
            self.back += 1;
        }
        while self.lines.len() > MONITOR_LINES {
            self.lines.pop_front();
        }
        self.scroll(0);
    }

    /// A coloured note line (kept even while the pane is hidden).
    pub fn note(&mut self, text: String, color: Color) {
        self.push(MonitorLine::Note(Line::styled(
            text,
            Style::default().fg(color),
        )));
    }

    /// The feed is between subscriptions: one line, counting the attempts.
    pub fn retrying(&mut self, reason: String, after: Duration) {
        self.retry_at = Some(Instant::now() + after);
        let attempts = match self.lines.back() {
            Some(MonitorLine::Retry { attempts, .. }) => {
                let n = *attempts;
                self.lines.pop_back();
                n + 1
            }
            _ => 1,
        };
        self.push(MonitorLine::Retry { reason, attempts });
    }
}

impl App {
    pub(crate) fn toggle_monitor(&mut self) {
        self.s.monitor.visible = !self.s.monitor.visible;
        if self.s.monitor.visible {
            self.start_monitor();
        } else {
            self.stop_monitor();
        }
    }

    pub(crate) fn stop_monitor(&mut self) {
        if let Some(task) = self.monitor_task.take() {
            // Dropping the feed inside the task unsubscribes.
            task.abort();
        }
        self.s.monitor.running = false;
    }

    pub(crate) fn start_monitor(&mut self) {
        self.stop_monitor();
        let s = &mut self.s;
        // New subscription, new totals.
        s.monitor.tally = TrafficTally::new(Instant::now());
        let one = match (&s.target, s.tab) {
            (Some(t), super::Tab::Account) => Some(t.clone()),
            _ => None,
        };
        s.monitor.watching = match (&one, s.session.admin()) {
            (Some(d), _) => format!("account {}", label(&s.book, d)),
            (None, true) => "all traffic".into(),
            (None, false) => "your traffic".into(),
        };
        let filter = monitor_filter(one.as_deref(), s.monitor.failures_only);
        // Mux members attaching and detaching too, for an administrator
        // watching everything (they are not failures, nor one account's
        // traffic).
        let membership = (s.session.admin()
            && one.is_none()
            && !s.monitor.failures_only
            && self.console.serves_mux_admin())
        .then(MembershipFilter::default);
        s.monitor.retry_at = None;
        s.monitor.running = true;
        let (console, tx) = (self.console.clone(), self.tx.clone());
        self.monitor_task = Some(tokio::spawn(watch(console, filter, membership, tx)));
    }

    /// This console's own requests to the mediator, and the clean-up of their
    /// replies. From mediator 0.28.22 the mediator leaves all of that out
    /// itself. Before that, a `received` event carried no recipient and a
    /// `deleted` event no sender, so the console's own polling showed through;
    /// this filter keeps the pane clean on those mediators.
    fn is_own_console_traffic(&self, e: &MonitorEvent) -> bool {
        use specs::monitor::event::v0_3::TrafficStage;
        let me = self.s.session.did_hash.as_str();
        let from = e.from.as_deref().map(String::as_str);
        let to = e.to.as_deref().map(String::as_str);
        let own_request = from == Some(me) && to.is_none_or(|to| to == self.mediator_hash);
        let own_reply_cleanup =
            e.stage == TrafficStage::Deleted && to == Some(me) && from.is_none();
        own_request || own_reply_cleanup
    }

    pub(crate) fn monitor_update(&mut self, update: MonitorUpdate) {
        // The connection's state comes from this side, not the mediator: it
        // says nothing about whether the tap is alive.
        match update {
            MonitorUpdate::Disconnected => {
                self.s.monitor.link_down = true;
                return;
            }
            MonitorUpdate::Reconnected => {
                self.s.monitor.link_down = false;
                return;
            }
            _ => {}
        }
        self.s.monitor.last_seen = Some(Instant::now());
        self.s.monitor.retry_at = None;
        match update {
            MonitorUpdate::Events { events, dropped } => {
                self.s.monitor.dropped += dropped;
                for e in events {
                    if !self.is_own_console_traffic(&e) {
                        self.s.monitor.tally.record(&e, Instant::now());
                        self.s.monitor.push(MonitorLine::Event(e));
                    }
                }
            }
            MonitorUpdate::Membership { events, dropped } => {
                self.s.monitor.dropped += dropped;
                for e in events {
                    self.s.monitor.push(MonitorLine::Membership(e));
                }
            }
            MonitorUpdate::Gap { missing } => {
                self.s.monitor.gaps += missing;
                self.s.monitor.note(
                    format!("── {missing} batch(es) lost in transit ──"),
                    Color::Yellow,
                );
            }
            // `Ended` never arrives here from the console's own feed: `watch`
            // turns it into a resubscribe (`Update::MonitorRetrying`). A host
            // feeding updates of its own gets the same: a note, and the pane
            // keeps its state.
            MonitorUpdate::Ended(reason) => self
                .s
                .monitor
                .note(format!("── monitor ended: {reason} ──"), Color::Red),
            _ => {}
        }
    }
}

/// The traffic filter: one account's traffic, or everything this session
/// may see; failures only when asked.
fn monitor_filter(did_hash: Option<&str>, failures_only: bool) -> MonitorFilter {
    use specs::monitor::subscribe::v0_2::Vid;
    let mut filter = MonitorFilter::default();
    filter.dids = did_hash
        .and_then(|d| d.parse::<Vid>().ok())
        .map(|d| vec![d]);
    filter.failures_only = failures_only.then_some(true);
    filter
}

/// The monitor's feed, kept up for as long as the pane is open: a feed that
/// ends (its lease renewal failed, say, with the connection down) or goes
/// silent is replaced, after a backoff. Only a refusal stops it, since asking
/// again would get the same answer.
///
/// `membership` adds mux membership events; a mediator that doesn't serve
/// them (one that predates them, its version unknown) gets the traffic feed
/// alone rather than no feed.
async fn watch(
    console: Arc<MediatorConsole>,
    filter: MonitorFilter,
    mut membership: Option<MembershipFilter>,
    tx: mpsc::UnboundedSender<Update>,
) {
    let mut failures = 0;
    loop {
        let opened = console
            .monitor_with(filter.clone(), membership.clone())
            .await;
        let reason = match opened {
            Err(e) if membership.is_some() && e.is_unsupported() => {
                membership = None;
                continue;
            }
            opened => opened,
        };
        let reason = match reason {
            Ok(mut feed) => loop {
                match tokio::time::timeout(MONITOR_SILENCE, feed.next()).await {
                    Ok(Some(MonitorUpdate::Ended(reason))) => break reason,
                    Ok(Some(update)) => {
                        failures = 0;
                        if tx.send(Update::Monitor(update)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break "the feed closed".to_string(),
                    Err(_) => {
                        break format!(
                            "nothing from the mediator for {}s",
                            MONITOR_SILENCE.as_secs()
                        );
                    }
                }
                // Dropping the feed on the way out unsubscribes it.
            },
            Err(e) if stops_the_monitor(&e) => {
                let _ = tx.send(Update::MonitorFailed(e));
                return;
            }
            Err(e) => e.to_string(),
        };
        let after = resubscribe_after(failures);
        failures += 1;
        if tx.send(Update::MonitorRetrying { reason, after }).is_err() {
            return;
        }
        tokio::time::sleep(after).await;
    }
}

/// A subscribe the mediator (or the console, knowing its answer) turned
/// down for good: asking again gets the same answer.
fn stops_the_monitor(e: &ConsoleError) -> bool {
    e.is_refusal() && !e.is_transient()
}

/// How long to wait before the next subscribe, after `failures` in a row.
fn resubscribe_after(failures: u32) -> Duration {
    RESUBSCRIBE
        .saturating_mul(2u32.saturating_pow(failures.min(8)))
        .min(RESUBSCRIBE_MAX)
}

/// Draw the monitor pane. Writes back only the page height, for scrolling.
pub(crate) fn render(f: &mut Frame, area: Rect, s: &mut State) {
    let m = &s.monitor;
    let alive = match (m.running, m.last_seen) {
        (false, _) => Span::styled("○ stopped", Style::default().fg(Color::Red)),
        // Said as it happens, not after a silence.
        (true, _) if m.link_down || s.link == Some(ConnState::Disconnected) => {
            Span::styled("✗ connection down", Style::default().fg(Color::Red))
        }
        (true, _) if let Some(at) = m.retry_at => Span::styled(
            format!(
                "↻ resubscribing in {}s",
                at.saturating_duration_since(Instant::now()).as_secs()
            ),
            Style::default().fg(Color::Yellow),
        ),
        (true, Some(t)) if t.elapsed() < Duration::from_secs(45) => {
            Span::styled("● live", Style::default().fg(Color::Green))
        }
        (true, Some(_)) => Span::styled("● silent", Style::default().fg(Color::Yellow)),
        (true, None) => Span::styled("◌ connecting", Style::default().fg(Color::DarkGray)),
    };
    let now = Instant::now();
    let tally = &m.tally;
    let title = Line::from(vec![
        Span::raw(format!(" Traffic — {} ", m.watching)),
        alive,
        Span::styled(
            format!(
                "  {} msgs · {:.1}/s (now {:.1}/s) · {}",
                tally.messages,
                tally.rate(now),
                tally.rate_now(now),
                human_secs(Some(now.duration_since(tally.started()).as_secs())),
            ),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            protocol_mix(&tally.protocols),
            Style::default().fg(Color::Blue),
        ),
        Span::raw(format!(
            "  dropped {}  lost {}{} ",
            m.dropped,
            m.gaps,
            if m.failures_only {
                "  failures only"
            } else {
                ""
            },
        )),
    ]);
    let mut block = Block::default().borders(Borders::ALL).title(title);
    // On the bottom edge: the title is often wider than the pane.
    if m.back > 0 && !m.show_totals {
        block = block.title_bottom(
            Line::styled(
                format!(" ⏸ {} newer · End to follow ", m.back),
                Style::default().fg(Color::Black).bg(Color::Yellow),
            )
            .right_aligned(),
        );
    }
    if m.show_totals {
        render_totals(f, area, s, block, now);
        return;
    }
    let inner = block.inner(area);
    let height = inner.height as usize;
    // Sender and recipient as aligned columns, sharing what the fixed
    // columns (time, stage, protocol, channel, size) leave.
    const FIXED: u16 = 8 + 3 + 10 + 10 + 10 + 3 + 6;
    let name_w = (inner.width.saturating_sub(FIXED) / 2).clamp(14, 32) as usize; // a short hash is 13
    let back = m.back.min(m.lines.len().saturating_sub(height));
    let skip = m.lines.len().saturating_sub(height + back);
    let lines: Vec<Line> = m
        .lines
        .iter()
        .skip(skip)
        .take(height)
        .map(|l| match l {
            MonitorLine::Event(e) => event_line(e, &s.book, name_w),
            MonitorLine::Membership(e) => membership_line(e, &s.book, name_w),
            MonitorLine::Note(line) => line.clone(),
            // The count ahead of the reason, which is often a long error
            // the pane cuts off.
            MonitorLine::Retry { reason, attempts } => Line::styled(
                match attempts {
                    1 => format!("── monitor interrupted: {reason} ──"),
                    n => format!("── monitor interrupted ×{n}: {reason} ──"),
                },
                Style::default().fg(Color::Yellow),
            ),
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
    s.monitor.page = height;
}

/// The monitor's per-account totals: the busiest accounts since it started.
fn render_totals(f: &mut Frame, area: Rect, s: &State, block: Block, now: Instant) {
    let top = s.monitor.tally.top(area.height.saturating_sub(3) as usize);
    let names: Vec<String> = top.iter().map(|(h, _)| label(&s.book, h)).collect();
    let rows: Vec<Row> = top
        .iter()
        .zip(&names)
        .map(|((_, a), name)| {
            Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(a.sent.to_string()),
                Cell::from(a.addressed.to_string()),
                Cell::from(a.delivered.to_string()),
                Cell::from(a.refused.to_string()).style(if a.refused > 0 {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default()
                }),
                Cell::from(human_bytes(Some(a.bytes))),
                Cell::from(human_secs(a.last.map(|t| now.duration_since(t).as_secs()))),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(fit_width(&names, 14, 32)),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec![
            "account",
            "sent",
            "to it",
            "delivered",
            "refused",
            "bytes",
            "last",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(block);
    f.render_widget(table, area);
}

/// The wire mix of what arrived: TSP's share, and the counts behind it.
/// Empty until something has arrived — a share of nothing is not 0%.
fn protocol_mix(mix: &ProtocolMix) -> String {
    let Some(share) = mix.tsp_share() else {
        return String::new();
    };
    let mut parts = vec![format!("tsp {share:.0}%")];
    for (name, n) in [
        ("tsp", mix.tsp),
        ("didcomm", mix.didcomm),
        ("v1", mix.didcomm_v1),
        ("other", mix.other),
    ] {
        if n > 0 {
            parts.push(format!("{name} {n}"));
        }
    }
    format!("  {} ", parts.join(" · "))
}

/// One monitor event as a coloured line.
pub(crate) fn event_line(e: &MonitorEvent, book: &AddressBook, name_w: usize) -> Line<'static> {
    use specs::monitor::event::v0_3::{TrafficDirection, TrafficStage};
    let color = match e.stage {
        TrafficStage::Refused => Color::Red,
        TrafficStage::Delivered => Color::Green,
        TrafficStage::Forwarded => Color::Cyan,
        TrafficStage::Stored => Color::Blue,
        TrafficStage::Deleted | TrafficStage::Purged | TrafficStage::Expired => Color::Magenta,
        _ => Color::Reset,
    };
    let arrow = match e.direction {
        TrafficDirection::Inbound => "▶",
        TrafficDirection::Outbound => "◀",
        _ => "·",
    };
    let who = |v: &Option<specs::monitor::event::v0_3::Vid>| {
        v.as_deref().map_or("·".into(), |h| label(book, h))
    };
    let mut spans = vec![
        Span::styled(
            time_of(&e.occurred_at),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {arrow} ")),
        Span::styled(
            format!("{:<9}", e.stage.to_string()),
            Style::default().fg(color),
        ),
        Span::raw(format!(
            " {:<9} {:<9} ",
            e.protocol.to_string(),
            e.channel.to_string()
        )),
        Span::raw(format!(
            "{} → {} ",
            fit(&who(&e.from), name_w),
            fit(&who(&e.to), name_w)
        )),
        Span::styled(human_bytes(e.size), Style::default().fg(Color::DarkGray)),
    ];
    if let Some(outcome) = &e.outcome {
        spans.push(Span::styled(
            format!("  {}", outcome.code.as_str()),
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

/// One mux membership change as a monitor line: who attached to or
/// detached from whose connection, how and why.
pub(crate) fn membership_line(
    e: &MembershipEvent,
    book: &AddressBook,
    name_w: usize,
) -> Line<'static> {
    use specs::monitor::event::v0_3::MembershipChange;
    let (arrow, color) = match e.change {
        MembershipChange::Attached => ("⊕", Color::Green),
        MembershipChange::Detached => ("⊖", Color::Yellow),
        _ => ("·", Color::Reset),
    };
    Line::from(vec![
        Span::styled(
            time_of(&e.occurred_at),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {arrow} ")),
        Span::styled(
            format!("{:<9}", e.change.to_string()),
            Style::default().fg(color),
        ),
        Span::raw(format!(" {:<9} {:<9} ", "mux", e.wire.to_string())),
        Span::raw(format!(
            "{} ⇢ {} ",
            fit(&label(book, &e.member), name_w),
            fit(&label(book, &e.principal), name_w),
        )),
        Span::styled(
            format!("{} {}", e.source, e.reason),
            Style::default().fg(Color::Magenta),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(v: serde_json::Value) -> MonitorEvent {
        serde_json::from_value(v).expect("a monitor event")
    }

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.to_string()).collect()
    }

    #[test]
    fn resubscribing_backs_off_to_a_ceiling() {
        let waits: Vec<u64> = (0..6).map(|n| resubscribe_after(n).as_secs()).collect();
        assert_eq!(waits, [2, 4, 8, 16, 30, 30]);
        assert_eq!(resubscribe_after(u32::MAX), RESUBSCRIBE_MAX);
    }

    #[test]
    fn only_a_lasting_refusal_stops_the_monitor() {
        assert!(stops_the_monitor(&ConsoleError::Refused {
            code: "e.p.req.unauthorized".into(),
            comment: "no".into(),
            current_epoch: None,
        }));
        assert!(stops_the_monitor(&ConsoleError::NotPermitted("monitor")));
        assert!(!stops_the_monitor(&ConsoleError::connect(
            "resolving",
            "dns error"
        )));
        assert!(!stops_the_monitor(&ConsoleError::Timeout {
            operation: "messaging/monitor/subscribe",
            after: Duration::from_secs(30),
        }));
    }

    #[test]
    fn a_named_account_shows_by_its_name_and_others_by_short_hash() {
        let alice = "did:example:alice";
        let mut book = AddressBook::new();
        book.insert(alice, "alice");
        let bob_hash = sha256::digest("did:example:bob");
        let line = event_line(
            &event(serde_json::json!({
                "occurredAt": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "stored",
                "channel": "rest", "protocol": "didcomm",
                "from": sha256::digest(alice), "to": bob_hash,
            })),
            &book,
            14,
        );
        let text = text(&line);
        // Aligned: the sender is padded to the column width.
        assert!(text.contains("alice          → "), "{text}");
        assert!(
            text.contains(&super::super::format::short(&bob_hash)),
            "{text}"
        );
    }

    #[test]
    fn a_refusal_event_shows_its_code_in_red() {
        let line = event_line(
            &event(serde_json::json!({
                "occurredAt": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "refused",
                "channel": "rest", "protocol": "tsp", "from": "a", "size": 10,
                "outcome": { "code": "authorization.send" },
            })),
            &AddressBook::new(),
            14,
        );
        let shown = text(&line);
        assert!(shown.contains("refused") && shown.contains("authorization.send"));
        assert!(line.spans.iter().any(|s| s.style.fg == Some(Color::Red)));
    }

    #[test]
    fn a_membership_event_shows_who_joined_whom_and_why() {
        let e: MembershipEvent = serde_json::from_value(serde_json::json!({
            "occurredAt": "2026-09-21T10:11:12Z", "change": "detached",
            "member": "abcdef0123456789", "principal": "0123456789abcdef",
            "reason": "admin", "source": "grant", "wire": "tsp",
        }))
        .expect("a membership event");
        let shown = text(&membership_line(&e, &AddressBook::new(), 14));
        assert!(shown.contains("⊖ detached"), "{shown}");
        assert!(shown.contains("tsp"), "{shown}");
        assert!(shown.contains("grant admin"), "{shown}");
    }

    #[test]
    fn the_filter_names_one_account_or_none() {
        let one = monitor_filter(Some("abc"), true);
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::json!({ "dids": ["abc"], "failuresOnly": true })
        );
        let all = monitor_filter(None, false);
        assert_eq!(serde_json::to_value(&all).unwrap(), serde_json::json!({}));
    }
}
