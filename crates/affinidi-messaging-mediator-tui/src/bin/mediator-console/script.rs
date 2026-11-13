//! `mediator-console <command>`: one operation, its answer on stdout, and an
//! exit code a script can act on.
//!
//! Each command prints a short human-readable answer, or with `--json` the
//! mediator's answer as the Trust Task's own JSON (one document per line),
//! for runbooks and monitoring. Errors go to stderr.

use affinidi_messaging_mediator_admin::{
    ConsoleError, MediatorConsole, PurgeRequest, account_hash, specs,
};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;

/// Exit codes, as `--help` lists them.
pub const EXIT_CODES: &str = "Exit codes:
  0  done
  1  failed (a bad identity or profile, a malformed request, an unexpected answer)
  2  invalid arguments
  3  refused: the mediator (or the console, knowing its rules) said no
  4  unreachable: the connection failed, dropped or timed out; trying again may work";

/// Failed for a reason trying again won't fix.
pub const EXIT_FAILED: i32 = 1;
/// The arguments were wrong (clap's own code for a usage error).
pub const EXIT_USAGE: i32 = 2;
/// The mediator refused.
pub const EXIT_REFUSED: i32 = 3;
/// The mediator could not be reached, or did not answer in time.
pub const EXIT_UNREACHABLE: i32 = 4;

/// The exit code for `e`.
pub fn exit_code(e: &ConsoleError) -> i32 {
    if e.is_transient() {
        EXIT_UNREACHABLE
    } else if e.is_refusal() {
        EXIT_REFUSED
    } else {
        EXIT_FAILED
    }
}

/// How a command prints its answer.
#[derive(Args, Clone, Copy, Debug, Default)]
pub struct Output {
    /// Print the mediator's answer as JSON.
    #[arg(long)]
    json: bool,
}

/// One page of a list.
#[derive(Args, Clone, Debug, Default)]
pub struct Page {
    /// Rows per page.
    #[arg(long)]
    limit: Option<u32>,
    /// Where to start: the `next_cursor` a previous page printed.
    #[arg(long)]
    cursor: Option<String>,
}

/// Which queue the queue ranking ranks by.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum Sort {
    #[default]
    Count,
    Bytes,
    Oldest,
    Saturation,
}

/// An account, by DID or account hash (`sha256(did)`); the console's own
/// when left out.
#[derive(Args, Clone, Debug, Default)]
pub struct Target {
    /// The account: a DID, or its hash. Default: your own.
    account: Option<String>,
}

impl Target {
    /// The account hash, or `None` for the console's own.
    fn target(&self) -> Option<String> {
        self.account.as_deref().map(to_hash)
    }
}

/// An account hash from a DID or a hash.
fn to_hash(account: &str) -> String {
    if account.starts_with("did:") {
        account_hash(account)
    } else {
        account.to_string()
    }
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Mediator statistics (administrators).
    Stats {
        #[command(flatten)]
        out: Output,
    },
    /// Accounts ranked by queue depth, bytes, age or saturation
    /// (administrators).
    Queues {
        /// Rank the send queues instead of the receive queues.
        #[arg(long)]
        send: bool,
        #[arg(long, value_enum, default_value_t)]
        sort: Sort,
        #[command(flatten)]
        page: Page,
        #[command(flatten)]
        out: Output,
    },
    /// Every account on the mediator (administrators).
    Accounts {
        #[command(flatten)]
        page: Page,
        #[command(flatten)]
        out: Output,
    },
    /// One account's settings and queues.
    Account {
        #[command(flatten)]
        account: Target,
        #[command(flatten)]
        out: Output,
    },
    /// The messages in one of an account's queues (metadata only).
    Messages {
        #[command(flatten)]
        account: Target,
        /// The send queue instead of the receive queue.
        #[arg(long)]
        send: bool,
        #[command(flatten)]
        page: Page,
        #[command(flatten)]
        out: Output,
    },
    /// The audit log, newest first (administrators).
    Audit {
        #[command(flatten)]
        page: Page,
        #[command(flatten)]
        out: Output,
    },
    /// The mediator's configuration (administrators).
    Config {
        #[command(flatten)]
        out: Output,
    },
    /// An account's access list.
    AccessList {
        #[command(flatten)]
        account: Target,
        #[command(flatten)]
        page: Page,
        #[command(flatten)]
        out: Output,
    },
    /// Stored mux grants of a principal DID, a member DID, or between the two
    /// (administrators).
    Grants {
        #[arg(long, required_unless_present = "member")]
        principal: Option<String>,
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
        #[command(flatten)]
        out: Output,
    },
    /// Remove messages from a queue for good. Counts them with `--dry-run`;
    /// removes them, pinned to the count, with `--yes`. One is required.
    ///
    /// The removal never takes a message newer than the count, and keeps a
    /// safety margin for the request's transit: messages queued within
    /// `PURGE_TRANSIT_MARGIN_SECS` (30 s) before the count are spared too, so
    /// it can remove fewer than were counted.
    Purge {
        #[command(flatten)]
        account: Target,
        /// The send queue instead of the receive queue.
        #[arg(long)]
        send: bool,
        /// Only messages exchanged with this account (DID or hash).
        #[arg(long)]
        peer: Option<String>,
        /// Only messages queued at least this many seconds.
        #[arg(long)]
        older_than: Option<u64>,
        /// Count what would go; remove nothing.
        #[arg(long, conflicts_with = "yes", required_unless_present = "yes")]
        dry_run: bool,
        /// Remove what the count matched, except what was queued within the
        /// transit margin (30 s) before it.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        out: Output,
    },
}

/// Run `command` on `console`; the exit code.
pub async fn run(console: &MediatorConsole, command: Command) -> i32 {
    match execute(console, command).await {
        Ok(()) => 0,
        Err(Failure::Usage(why)) => {
            eprintln!("mediator-console: {why}");
            EXIT_USAGE
        }
        Err(Failure::Console(e)) => {
            eprintln!("mediator-console: {}", e.explain());
            exit_code(&e)
        }
    }
}

/// Why a command failed.
enum Failure {
    Usage(&'static str),
    Console(ConsoleError),
}

impl From<ConsoleError> for Failure {
    fn from(e: ConsoleError) -> Self {
        Failure::Console(e)
    }
}

/// Print `answer` as JSON, or as the text `text` makes of it.
fn print<T: Serialize>(out: Output, answer: &T, text: impl FnOnce(&T) -> Vec<String>) {
    if out.json {
        match serde_json::to_string(answer) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("mediator-console: the answer would not serialise: {e}"),
        }
    } else {
        for line in text(answer) {
            println!("{line}");
        }
    }
}

/// A `next_cursor` line, when there is another page.
fn more(next: Option<&str>) -> Option<String> {
    next.map(|c| format!("next_cursor {c}"))
}

/// An optional count as text.
fn n(v: Option<u64>) -> String {
    v.map_or("-".into(), |v| v.to_string())
}

/// An optional limit as text: `-` when unlimited or unset.
fn lim(v: Option<i64>) -> String {
    match v {
        Some(l) if l >= 0 => l.to_string(),
        _ => "-".into(),
    }
}

async fn execute(console: &MediatorConsole, command: Command) -> Result<(), Failure> {
    match command {
        Command::Stats { out } => {
            let s = console.stats().await?;
            print(out, &s, |s| {
                vec![
                    format!("version {}", s.version.as_str()),
                    format!("uptime_seconds {}", s.uptime_seconds),
                    format!(
                        "websockets {} / {}",
                        s.connections.websocket_active,
                        n(s.connections.websocket_max)
                    ),
                    format!(
                        "messages stored {} delivered {} deleted {}",
                        s.totals.received_count, s.totals.sent_count, s.totals.deleted_count
                    ),
                    format!(
                        "forwarding {} / {}",
                        s.forwarding.queue_length,
                        n(s.forwarding.queue_limit)
                    ),
                ]
            });
        }
        Command::Queues {
            send,
            sort,
            page,
            out,
        } => {
            use specs::queue::list::v0_1::{PayloadSort, Queue};
            let queue = if send { Queue::Send } else { Queue::Receive };
            let sort = match sort {
                Sort::Count => PayloadSort::Count,
                Sort::Bytes => PayloadSort::Bytes,
                Sort::Oldest => PayloadSort::Oldest,
                Sort::Saturation => PayloadSort::Saturation,
            };
            let r = console
                .queues(Some(queue), Some(sort), page.cursor, page.limit)
                .await?;
            print(out, &r, |r| {
                let mut lines: Vec<String> = r
                    .queues
                    .iter()
                    .map(|q| {
                        format!(
                            "{}  receive {}/{}  send {}/{}",
                            q.did.as_str(),
                            q.receive.count,
                            lim(q.receive.limit),
                            q.send.count,
                            lim(q.send.limit)
                        )
                    })
                    .collect();
                lines.extend(more(r.next_cursor.as_deref().map(String::as_str)));
                lines
            });
        }
        Command::Accounts { page, out } => {
            let r = console.accounts(page.cursor, page.limit).await?;
            print(out, &r, |r| {
                let mut lines: Vec<String> = r
                    .accounts
                    .iter()
                    .map(|a| {
                        format!(
                            "{}  {}  receive {}  send {}",
                            a.did.as_str(),
                            a.account_type,
                            n(a.receive_queue_count),
                            n(a.send_queue_count)
                        )
                    })
                    .collect();
                lines.extend(more(r.next_cursor.as_deref().map(String::as_str)));
                lines
            });
        }
        Command::Account { account, out } => {
            let a = console.account_of(account.target()).await?;
            print(out, &a, |a| {
                vec![
                    format!("account {}", a.did.as_str()),
                    format!("role {}", a.account_type),
                    format!(
                        "queued receive {}  send {}",
                        n(a.receive_queue_count),
                        n(a.send_queue_count)
                    ),
                    format!("access_list_entries {}", n(a.access_list_count)),
                ]
            });
        }
        Command::Messages {
            account,
            send,
            page,
            out,
        } => {
            use specs::message::list::v0_1::Queue;
            let queue = if send { Queue::Send } else { Queue::Receive };
            let r = console
                .messages(account.target(), queue, None, page.cursor, page.limit)
                .await?;
            print(out, &r, |r| {
                let mut lines: Vec<String> = r
                    .messages
                    .iter()
                    .map(|m| {
                        format!(
                            "{}  {}  {} bytes  from {}",
                            m.msg_id.as_str(),
                            m.received_at.to_rfc3339(),
                            m.size,
                            m.from.as_deref().map_or("-", String::as_str)
                        )
                    })
                    .collect();
                lines.extend(more(r.next_cursor.as_deref().map(String::as_str)));
                lines
            });
        }
        Command::Audit { page, out } => {
            let r = console.audit(page.cursor, page.limit).await?;
            print(out, &r, |r| {
                let mut lines: Vec<String> = r
                    .entries
                    .iter()
                    .map(|e| {
                        format!(
                            "{}  {}  {}  actor {}  target {}",
                            e.recorded_at.to_rfc3339(),
                            e.action.as_str(),
                            e.outcome.as_deref().unwrap_or("-"),
                            e.actor.as_deref().unwrap_or("-"),
                            e.target.as_deref().unwrap_or("-")
                        )
                    })
                    .collect();
                lines.extend(more(r.next_cursor.as_deref()));
                lines
            });
        }
        Command::Config { out } => {
            let r = console.config().await?;
            print(out, &r, |r| {
                r.fields
                    .iter()
                    .map(|f| format!("{} = {}  ({})", f.key.as_str(), f.value, f.source.as_str()))
                    .collect()
            });
        }
        Command::AccessList { account, page, out } => {
            let r = console
                .access_list(account.target(), page.cursor, page.limit, None)
                .await?;
            print(out, &r, |r| {
                let mut lines = vec![format!("entries {}", r.access_list_count)];
                lines.extend(r.entries.iter().map(|e| e.to_string()));
                lines.extend(more(r.next_cursor.as_deref().map(String::as_str)));
                lines
            });
        }
        Command::Grants {
            principal,
            member,
            limit,
            cursor,
            out,
        } => {
            if principal.is_none() && member.is_none() {
                return Err(Failure::Usage("name --principal, --member, or both"));
            }
            let r = console
                .mux_grants(principal.as_deref(), member.as_deref(), cursor, limit)
                .await?;
            print(out, &r, |r| {
                let mut lines: Vec<String> = r
                    .epoch
                    .map(|e| format!("member_epoch {e}"))
                    .into_iter()
                    .collect();
                lines.extend(r.grants.iter().map(|g| {
                    format!(
                        "{}  member {}  principal {}  {}  expires {}",
                        g.grant_id.as_str(),
                        g.did.as_str(),
                        g.principal.as_str(),
                        g.state,
                        g.expires_at.to_rfc3339()
                    )
                }));
                lines.extend(more(r.next_cursor.as_deref().map(String::as_str)));
                lines
            });
        }
        Command::Purge {
            account,
            send,
            peer,
            older_than,
            dry_run,
            yes,
            out,
        } => {
            use specs::queue::purge::v0_1::Queue;
            if !dry_run && !yes {
                return Err(Failure::Usage(
                    "a purge removes messages for good: pass --dry-run to count them, \
                     or --yes to remove them",
                ));
            }
            let request = PurgeRequest {
                target: account.target(),
                queue: if send { Queue::Send } else { Queue::Receive },
                peer: peer.as_deref().map(to_hash),
                older_than_seconds: older_than,
            };
            let plan = console.purge_preview(request).await?;
            let purged = if yes && plan.matched > 0 {
                Some(console.purge(plan.clone()).await?.purged)
            } else if yes {
                Some(0)
            } else {
                None
            };
            let answer = PurgeAnswer {
                matched: plan.matched,
                matched_bytes: plan.matched_bytes,
                purged,
            };
            print(out, &answer, |a| match a.purged {
                None => vec![format!(
                    "would purge {} message(s), {} bytes",
                    a.matched, a.matched_bytes
                )],
                Some(p) => vec![format!(
                    "purged {p} of the {} message(s) counted",
                    a.matched
                )],
            });
        }
    }
    Ok(())
}

/// What `purge` prints with `--json`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PurgeAnswer {
    /// What the count matched.
    matched: u64,
    matched_bytes: u64,
    /// What went (`--yes`); absent for a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    purged: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_sdk::errors::ATMError;
    use std::time::Duration;

    #[test]
    fn each_failure_has_its_exit_code() {
        let refused = ConsoleError::Refused {
            code: "e.p.authorization.admin_required".into(),
            comment: "admins only".into(),
            current_epoch: None,
        };
        assert_eq!(exit_code(&refused), EXIT_REFUSED);
        assert_eq!(
            exit_code(&ConsoleError::NotPermitted("admins only")),
            EXIT_REFUSED
        );
        let late = ConsoleError::Timeout {
            operation: "messaging/stats/show",
            after: Duration::from_secs(1),
        };
        assert_eq!(exit_code(&late), EXIT_UNREACHABLE);
        assert_eq!(
            exit_code(&ConsoleError::connect("resolving", "dns error")),
            EXIT_UNREACHABLE
        );
        let lost = ConsoleError::Sdk(ATMError::ConfigError("bad".into()));
        assert_eq!(exit_code(&lost), EXIT_FAILED);
        assert!(EXIT_CODES.contains("3  refused") && EXIT_CODES.contains("4  unreachable"));
    }

    #[test]
    fn an_account_is_named_by_did_or_hash() {
        let hash = account_hash("did:example:alice");
        assert_eq!(to_hash("did:example:alice"), hash);
        assert_eq!(to_hash(&hash), hash);
        assert_eq!(Target::default().target(), None);
    }

    #[test]
    fn the_commands_parse() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: Command,
        }
        let cli = Cli::try_parse_from(["x", "purge", "did:example:a", "--send", "--dry-run"])
            .expect("purge parses");
        assert!(matches!(
            cli.command,
            Command::Purge {
                send: true,
                dry_run: true,
                yes: false,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["x", "purge", "--dry-run", "--yes"]).is_err(),
            "a dry run that removes is refused"
        );
        assert!(
            Cli::try_parse_from(["x", "purge"]).is_err(),
            "a purge says whether it is a dry run"
        );
        assert!(
            Cli::try_parse_from(["x", "grants"]).is_err(),
            "grants of whom?"
        );
        assert!(Cli::try_parse_from(["x", "grants", "--member", "did:example:m"]).is_ok());
        let cli = Cli::try_parse_from(["x", "queues", "--sort", "saturation", "--json"])
            .expect("queues parses");
        assert!(matches!(
            cli.command,
            Command::Queues {
                sort: Sort::Saturation,
                out: Output { json: true },
                ..
            }
        ));
    }
}
