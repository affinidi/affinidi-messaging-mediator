//! The console's keys, in one table: the footer's hints and the `?` help
//! overlay are both drawn from it, so neither can drift from the other.

use crate::app::Tab;

/// Where a key works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// On every screen.
    Everywhere,
    /// On these screens.
    On(&'static [Tab]),
    /// On the Config screen, for a session that may change the configuration.
    ConfigChange,
    /// While the monitor pane is open.
    Monitor,
}

/// One key (or set of keys) and what it does.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Binding {
    pub keys: &'static str,
    /// What it does, as the help says it.
    pub does: &'static str,
    pub scope: Scope,
    /// What the footer says it does; empty keeps it out of the footer.
    pub hint: &'static str,
}

use Scope::{ConfigChange, Everywhere, Monitor, On};

const fn k(keys: &'static str, hint: &'static str, does: &'static str, scope: Scope) -> Binding {
    Binding {
        keys,
        does,
        scope,
        hint,
    }
}

const QUEUES: &[Tab] = &[Tab::Dashboard, Tab::Queues];
const ACCOUNT: &[Tab] = &[Tab::Account];
const GRANTS: &[Tab] = &[Tab::Grants];
const TABLES: &[Tab] = &[
    Tab::Dashboard,
    Tab::Queues,
    Tab::Account,
    Tab::Audit,
    Tab::Accounts,
    Tab::Config,
    Tab::Mux,
    Tab::Grants,
];
const PAGED: &[Tab] = &[
    Tab::Dashboard,
    Tab::Queues,
    Tab::Account,
    Tab::Audit,
    Tab::Accounts,
    Tab::Grants,
];

/// Every key, in the order the footer offers them within each scope.
#[rustfmt::skip]
pub(crate) const KEYMAP: &[Binding] = &[
    k("↑↓", "select", "select a row (also j k)", On(TABLES)),
    k("PgUp PgDn", "", "a page of rows; they scroll the monitor instead while it is open", On(TABLES)),
    k("⏎", "open", "open the selected account", On(QUEUES)),
    k("s", "sort", "change the ranking", On(QUEUES)),
    k("x", "recv/send", "switch between the receive and send queue", On(QUEUES)),
    k("e", "edit account", "edit the account's role, ACL flags and limits (shows the changes, y applies)", On(ACCOUNT)),
    k("i", "inspect", "inspect the selected message (scroll, y copy, w write to a file)", On(ACCOUNT)),
    k("d", "delete", "delete the selected message (asks first)", On(ACCOUNT)),
    k("p", "purge", "purge the queue (counts first, then asks)", On(ACCOUNT)),
    k("P", "purge peer", "purge what the selected message's counterparty exchanged", On(ACCOUNT)),
    k("x", "recv/send", "switch between the receive and send queue", On(ACCOUNT)),
    k("o", "own", "back to your own account", On(ACCOUNT)),
    k("⏎", "open", "open the selected account", On(&[Tab::Accounts])),
    k("⏎", "change limit", "change the selected limit (shows the change, y applies)", ConfigChange),
    k("x", "reset override", "reset the selected override (asks first)", ConfigChange),
    k("g", "its grants", "the selected connection's stored grants", On(&[Tab::Mux])),
    k("/", "find", "find grants by principal DID, member DID, or both", On(GRANTS)),
    k("space", "mark", "mark the selected grant, or unmark it", On(GRANTS)),
    k("a", "mark all", "mark every grant listed", On(GRANTS)),
    k("c", "clear marks", "clear the marks", On(GRANTS)),
    k("d", "revoke", "revoke the marked grants, or the selected one (asks first)", On(GRANTS)),
    k("D", "revoke all", "revoke every grant listed (asks first)", On(GRANTS)),
    k("E", "bump epoch", "advance the member's epoch (asks first)", On(GRANTS)),
    k("p", "principal's", "the selected grant's principal's grants", On(GRANTS)),
    k("g", "member's", "the selected grant's member's grants", On(GRANTS)),
    k("]", "more", "load the next page (also on reaching the last row)", On(PAGED)),
    k("t", "totals", "the monitor's live lines ↔ its per-account totals", Monitor),
    k("PgUp PgDn", "scroll", "scroll the monitor back (also ⇧↑ ⇧↓)", Monitor),
    k("Home End", "", "the oldest monitor line kept / follow new traffic", Monitor),
    k("?", "help", "every key", Everywhere),
    k("m", "monitor", "show or hide the traffic monitor", Everywhere),
    k("y", "copy id", "copy the selected row's full hash or DID (OSC 52)", Everywhere),
    k("n", "name", "name an account", Everywhere),
    k("r", "refresh", "refresh now", Everywhere),
    k("q", "quit", "quit", Everywhere),
    k("b", "", "the address book", Everywhere),
    k("f", "", "monitor failures only", Everywhere),
    k("l", "", "the log of warnings and errors", Everywhere),
    k("Tab 1-8", "", "switch screen", Everywhere),
    k("Ctrl-L", "", "repaint the screen", Everywhere),
    k("Ctrl-C", "", "quit", Everywhere),
    k("Esc", "", "close a popup; it never quits", Everywhere),
];

/// What the keys apply to now.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context {
    pub tab: Tab,
    pub monitor: bool,
    pub can_patch: bool,
}

impl Scope {
    fn applies(self, cx: Context) -> bool {
        match self {
            Everywhere => true,
            On(tabs) => tabs.contains(&cx.tab),
            ConfigChange => cx.tab == Tab::Config && cx.can_patch,
            Monitor => cx.monitor,
        }
    }

    /// Screen keys first, then the monitor's, then those that work anywhere.
    fn rank(self) -> u8 {
        match self {
            On(_) | ConfigChange => 0,
            Monitor => 1,
            Everywhere => 2,
        }
    }
}

/// The keys that work in `cx`, screen keys first.
pub(crate) fn bindings(cx: Context) -> Vec<&'static Binding> {
    let mut keys: Vec<&Binding> = KEYMAP.iter().filter(|b| b.scope.applies(cx)).collect();
    keys.sort_by_key(|b| b.scope.rank());
    keys
}

/// What the footer says when there's no notice: the hinted keys for `cx`, cut
/// to `width` columns with a pointer to the help when they don't all fit.
pub(crate) fn footer(cx: Context, width: usize) -> String {
    const MORE: &str = "  … ? for more";
    let hints: Vec<String> = bindings(cx)
        .into_iter()
        .filter(|b| !b.hint.is_empty())
        .map(|b| format!("{} {}", b.keys, b.hint))
        .collect();
    let all = format!(" {}", hints.join("  "));
    if all.chars().count() <= width {
        return all;
    }
    let room = width.saturating_sub(MORE.chars().count());
    let mut line = String::new();
    for hint in &hints {
        let next = if line.is_empty() {
            format!(" {hint}")
        } else {
            format!("{line}  {hint}")
        };
        if next.chars().count() > room {
            break;
        }
        line = next;
    }
    format!("{line}{MORE}")
}

/// The help overlay for `cx`: every key that works here, by where it works.
pub(crate) fn help(cx: Context) -> Vec<(String, Vec<&'static Binding>)> {
    let keys = bindings(cx);
    [
        (format!("{} screen", cx.tab.title()), 0),
        ("Monitor (open)".to_string(), 1),
        ("Everywhere".to_string(), 2),
    ]
    .into_iter()
    .map(|(title, rank)| {
        let section: Vec<&Binding> = keys
            .iter()
            .copied()
            .filter(|b| b.scope.rank() == rank)
            .collect();
        (title, section)
    })
    .filter(|(_, section)| !section.is_empty())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx(tab: Tab) -> Context {
        Context {
            tab,
            monitor: false,
            can_patch: false,
        }
    }

    #[test]
    fn a_wide_footer_shows_every_hint() {
        let line = footer(cx(Tab::Audit), 400);
        assert!(line.contains("? help"), "{line}");
        assert!(line.contains("q quit"), "{line}");
        assert!(!line.contains("… ? for more"), "{line}");
    }

    #[test]
    fn a_narrow_footer_ends_with_the_way_to_the_rest() {
        let line = footer(cx(Tab::Account), 80);
        assert!(line.chars().count() <= 80, "{line}");
        assert!(line.ends_with("… ? for more"), "{line}");
        // Screen keys come first.
        assert!(line.starts_with(" ↑↓ select  e edit account"), "{line}");
    }

    #[test]
    fn the_help_lists_this_screen_and_every_global_key() {
        let help = help(Context {
            tab: Tab::Config,
            monitor: true,
            can_patch: true,
        });
        let titles: Vec<&str> = help.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(titles, ["Config screen", "Monitor (open)", "Everywhere"]);
        let config = &help[0].1;
        assert!(
            config
                .iter()
                .any(|b| b.keys == "x" && b.does.contains("override"))
        );
        let everywhere = &help[2].1;
        assert!(everywhere.iter().any(|b| b.keys == "Esc"));
        assert!(everywhere.iter().any(|b| b.keys == "?"));
    }

    #[test]
    fn config_changes_are_offered_only_to_who_may_make_them() {
        let read_only = footer(cx(Tab::Config), 400);
        assert!(!read_only.contains("reset"), "{read_only}");
        let root = footer(
            Context {
                can_patch: true,
                ..cx(Tab::Config)
            },
            400,
        );
        assert!(root.contains("x reset override"), "{root}");
    }
}
