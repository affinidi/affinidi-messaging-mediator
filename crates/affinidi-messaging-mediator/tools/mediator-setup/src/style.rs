//! The one place that decides whether the wizard's output carries colour.
//!
//! Headless output (`--from`, `--non-interactive`, `--uninstall`, the
//! `--setup-key-*` flows and the post-TUI summary) is written with ANSI SGR
//! sequences inline. Those are only wanted on a terminal: piped into a file
//! or a CI log they are noise, and `NO_COLOR` (<https://no-color.org>) asks
//! for none at all. Every line goes through the `out!` / `err!` macros
//! below, which strip the sequences when the stream they
//! write to should not be coloured. The TUI's ratatui theme asks
//! [`tui_color_enabled`] for the same decision.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// `NO_COLOR` set to anything non-empty disables colour everywhere.
fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// `TERM=dumb` terminals render escape sequences literally.
fn dumb_term() -> bool {
    std::env::var("TERM").is_ok_and(|t| t == "dumb")
}

/// Whether stdout output should carry ANSI styling.
pub fn stdout_color() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && !dumb_term() && std::io::stdout().is_terminal())
}

/// Whether stderr output should carry ANSI styling.
pub fn stderr_color() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && !dumb_term() && std::io::stderr().is_terminal())
}

/// Whether the TUI's theme should use colour. The TUI only runs on a
/// terminal, so only `NO_COLOR` matters here.
pub fn tui_color_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color())
}

/// Remove every ANSI CSI sequence (`ESC [ … final-byte`) from `s`.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            // Parameter and intermediate bytes, then one final byte in
            // `@`..=`~`.
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// `s` as it should be written to stdout.
pub fn for_stdout(s: String) -> String {
    if stdout_color() { s } else { strip_ansi(&s) }
}

/// `s` as it should be written to stderr.
pub fn for_stderr(s: String) -> String {
    if stderr_color() { s } else { strip_ansi(&s) }
}

/// `println!` that drops ANSI styling when stdout is not a colour terminal.
macro_rules! out {
    () => { println!() };
    ($($arg:tt)*) => { println!("{}", $crate::style::for_stdout(format!($($arg)*))) };
}

/// `eprintln!` that drops ANSI styling when stderr is not a colour terminal.
macro_rules! err {
    () => { eprintln!() };
    ($($arg:tt)*) => { eprintln!("{}", $crate::style::for_stderr(format!($($arg)*))) };
}

/// `print!` (no newline) counterpart of `out!`.
macro_rules! out_inline {
    ($($arg:tt)*) => { print!("{}", $crate::style::for_stdout(format!($($arg)*))) };
}

#[cfg(test)]
mod tests {
    use super::strip_ansi;

    #[test]
    fn strips_sgr_and_cursor_sequences() {
        assert_eq!(strip_ansi("\x1b[32m\u{2714}\x1b[0m done"), "\u{2714} done");
        assert_eq!(strip_ansi("\x1b[38;5;69mblue\x1b[0m"), "blue");
        assert_eq!(strip_ansi("\x1b[41;97m UNSAFE \x1b[0m"), " UNSAFE ");
        assert_eq!(strip_ansi("up\x1b[3A\x1b[K"), "up");
    }

    #[test]
    fn leaves_plain_text_alone() {
        assert_eq!(strip_ansi("plain [brackets] text"), "plain [brackets] text");
        assert_eq!(strip_ansi("lone \x1b escape"), "lone \x1b escape");
    }
}
