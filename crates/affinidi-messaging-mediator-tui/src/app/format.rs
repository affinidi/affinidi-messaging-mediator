//! How values read on screen: names for accounts, sizes, ages, times,
//! widths. Pure functions, shared by every screen.

use affinidi_messaging_mediator_admin::AddressBook;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// A DID hash shortened for a column.
pub(crate) fn short(s: &str) -> String {
    if s.chars().count() <= 14 {
        s.to_string()
    } else {
        let head: String = s.chars().take(8).collect();
        let tail: String = s
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{head}…{tail}")
    }
}

/// A DID cut to 30 characters (never inside one: DIDs from an address book
/// or a profile need not be ASCII).
pub(crate) fn short_did(s: &str) -> String {
    if s.chars().count() <= 32 {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(30).collect::<String>())
    }
}

/// A time of day, local: `HH:MM:SS`.
pub(crate) fn time_of(at: &DateTime<Utc>) -> String {
    at.with_timezone(&chrono::Local)
        .format("%H:%M:%S")
        .to_string()
}

/// An audit time, local: `MM-DD HH:MM:SS`.
pub(crate) fn when_of(at: &DateTime<Utc>) -> String {
    at.with_timezone(&chrono::Local)
        .format("%m-%d %H:%M:%S")
        .to_string()
}

/// An instant as a column shows it: `YYYY-MM-DD HH:MM:SS`, UTC.
pub(crate) fn stamp(at: &DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn human_secs(s: Option<u64>) -> String {
    match s {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3_600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3_600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

/// How long ago `at` was, for the activity columns. A mediator that doesn't
/// serve the times, or has none for the account, gives `None` — shown the
/// same as any other unknown ("–").
pub(crate) fn ago(at: Option<DateTime<Utc>>) -> String {
    let Some(at) = at else {
        return "–".into();
    };
    // A time slightly in the future (clock skew between mediator and console)
    // reads as "now" rather than as a negative age.
    let secs = (Utc::now() - at).num_seconds().max(0) as u64;
    human_secs(Some(secs))
}

pub(crate) fn human_bytes(b: Option<u64>) -> String {
    match b {
        None => "–".into(),
        Some(b) if b < 1_024 => format!("{b}B"),
        Some(b) if b < 1_048_576 => format!("{:.1}K", b as f64 / 1_024.0),
        Some(b) => format!("{:.1}M", b as f64 / 1_048_576.0),
    }
}

/// A queue limit: `∞` when there is none (`-1`, or not set).
pub(crate) fn limit_of(limit: Option<i64>) -> String {
    match limit {
        Some(l) if l >= 0 => l.to_string(),
        _ => "∞".into(),
    }
}

/// A saturation (0–1) as a percentage, or `–`.
pub(crate) fn percent(saturation: Option<f64>) -> String {
    saturation.map_or("–".into(), |s| format!("{:.0}%", s * 100.0))
}

/// `s` padded or cut (with `…`) to exactly `width` characters.
pub(crate) fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        format!("{s}{}", " ".repeat(width - n))
    } else {
        let cut: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// A column width that fits the longest of `labels` (plus a space), held
/// between `min` and `max`.
pub(crate) fn fit_width(labels: &[String], min: u16, max: u16) -> u16 {
    let longest = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0) as u16;
    (longest + 1).clamp(min, max)
}

/// An account hash as the user knows it: its nickname, else a short hash.
pub(crate) fn label(book: &AddressBook, hash: &str) -> String {
    book.name_of(hash)
        .map(str::to_string)
        .unwrap_or_else(|| short(hash))
}

/// A DID as the console shows it: its address-book name when it has one
/// (the book is keyed by DID hash), otherwise the DID shortened.
pub(crate) fn did_label(book: &AddressBook, did: &str) -> String {
    book.name_of(&sha256::digest(did))
        .map(str::to_string)
        .unwrap_or_else(|| short(did))
}

/// How many rows a list shows: `200`, `200 of 5000` when the total is known,
/// and `+ (] more)` when another page is waiting.
pub(crate) fn count_shown(shown: usize, total: Option<u64>, more: bool) -> String {
    let mut s = shown.to_string();
    match total {
        Some(t) if t > shown as u64 => s.push_str(&format!(" of {t}")),
        _ if more => s.push('+'),
        _ => {}
    }
    if more {
        s.push_str(" (] more)");
    }
    s
}

/// A configuration value as the console shows it.
pub(crate) fn config_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "–".into(),
        other => other.to_string(),
    }
}

/// An audit entry's `detail` object as `key=value` pairs.
pub(crate) fn detail_line(detail: &serde_json::Map<String, Value>) -> String {
    detail
        .iter()
        .map(|(k, v)| match v {
            Value::String(s) => format!("{k}={s}"),
            other => format!("{k}={other}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text` cut into rows of at most `width` characters.
pub(crate) fn wrap_hard(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width.max(1))
        .map(|c| c.iter().collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_keeps_ends_of_a_hash() {
        assert_eq!(short("abcdefghijklmnopqrstuvwxyz"), "abcdefgh…wxyz");
        assert_eq!(short("short"), "short");
    }

    #[test]
    fn short_did_never_cuts_inside_a_character() {
        let did = format!("did:web:{}", "é".repeat(40));
        let cut = short_did(&did);
        assert_eq!(cut.chars().count(), 31);
        assert!(cut.ends_with('…'));
        assert_eq!(short_did("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn human_units() {
        assert_eq!(human_secs(Some(59)), "59s");
        assert_eq!(human_secs(Some(7_200)), "2h");
        assert_eq!(human_bytes(Some(2_048)), "2.0K");
        assert_eq!(human_bytes(None), "–");
        assert_eq!(limit_of(Some(-1)), "∞");
        assert_eq!(limit_of(None), "∞");
        assert_eq!(limit_of(Some(5)), "5");
        assert_eq!(percent(Some(0.5)), "50%");
    }

    #[test]
    fn an_age_is_never_negative_and_unknown_is_a_dash() {
        assert_eq!(ago(None), "–");
        assert_eq!(ago(Some(Utc::now() + chrono::Duration::seconds(30))), "0s");
        assert_eq!(ago(Some(Utc::now() - chrono::Duration::minutes(5))), "5m");
    }

    #[test]
    fn a_list_says_how_much_of_it_is_shown() {
        assert_eq!(count_shown(200, Some(5_000), true), "200 of 5000 (] more)");
        assert_eq!(count_shown(200, None, true), "200+ (] more)");
        assert_eq!(count_shown(3, Some(3), false), "3");
    }

    #[test]
    fn audit_detail_reads_as_key_value_pairs() {
        let detail = serde_json::json!({ "queue": "receive", "purged": 3 });
        assert_eq!(
            detail_line(detail.as_object().unwrap()),
            "purged=3 queue=receive"
        );
        assert_eq!(detail_line(&serde_json::Map::new()), "");
    }

    #[test]
    fn text_is_fitted_to_its_column() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abcd", 4), "abcd");
        let names = vec![
            "short".to_string(),
            "a much longer account name".to_string(),
        ];
        assert_eq!(fit_width(&names, 15, 40), 27);
        assert_eq!(fit_width(&names, 15, 20), 20);
        assert_eq!(fit_width(&[], 15, 40), 15);
    }
}
