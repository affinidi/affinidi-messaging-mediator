//! Duration strings and RFC 3339 timestamps from operator configuration,
//! parsed with `jiff`.
//!
//! Every duration setting goes through [`parse_duration`] (`[secrets]
//! cache_ttl`, the setup tool's `MEDIATOR_BOOTSTRAP_SEED_TTL`), and every
//! timestamp setting through [`parse_utc_timestamp`]
//! (`security.tsp_auth_accept_unbound_until`), so they all take one syntax.
//!
//! # Durations
//!
//! jiff's "friendly" format: whole numbers each followed by a unit, largest
//! unit first and each unit at most once, with or without spaces between them
//! (`30d`, `12h`, `1h30m`, `1h 30m`, `2 hours, 30 minutes`, `01:30:00`). Units,
//! with their accepted spellings:
//!
//! | unit         | spellings                                  | length          |
//! |--------------|--------------------------------------------|-----------------|
//! | year         | `y`, `yr`, `yrs`, `year`, `years`          | 365.25 days     |
//! | month        | `mo`, `mos`, `month`, `months`             | 30.44 days      |
//! | week         | `w`, `wk`, `wks`, `week`, `weeks`          | 7 days          |
//! | day          | `d`, `day`, `days`                         | 24 hours        |
//! | hour         | `h`, `hr`, `hrs`, `hour`, `hours`          |                 |
//! | minute       | `m`, `min`, `mins`, `minute`, `minutes`    |                 |
//! | second       | `s`, `sec`, `secs`, `second`, `seconds`    |                 |
//! | millisecond  | `ms`, `msec`, `millis`, `milliseconds`, …  |                 |
//! | microsecond  | `us`, `µs`, `usec`, `micros`, …            |                 |
//! | nanosecond   | `ns`, `nsec`, `nanos`, `nanoseconds`, …    |                 |
//!
//! Years and months keep the fixed lengths the mediator has always given them
//! (humantime's 365.25 and 30.44 days), and days are 24 hours: these are
//! durations, not calendar arithmetic. Only the last unit may carry a fraction,
//! and only if it is hours or smaller (`1.5h`, `1h 1.5m`). A bare `0` means zero.
//! Surrounding whitespace is ignored. Negative durations (`-1h`, `1h ago`) are
//! refused.
//!
//! Compared with the humantime grammar this replaces, these are no longer
//! accepted, each with an error naming the syntax above: `M` for months (it
//! reads as minutes; write `mo` or `months`), a fraction on days, weeks, months
//! or years (`1.5d`; write `1d 12h` or `36h`), a fraction before the last unit
//! (`1.5h 30m`), units out of order or repeated (`30m 1h`, `1s 1s`), and digits
//! split by spaces (`1 0d`). Values beyond about 19,998 years are refused too.
//!
//! # Timestamps
//!
//! RFC 3339 (`2027-03-01T00:00:00Z`), also with a space or lowercase `t` for
//! the `T`, lowercase `z`, and any numeric offset (`+02:00` is honoured). With
//! no offset at all (`2027-03-01T00:00:00`, `2027-03-01 00:00:00.5`) the time
//! is read as UTC, as before. A date without a time is refused.

use std::time::{Duration, SystemTime};

use jiff::{
    SignedDuration, SpanRelativeTo, Timestamp, civil::DateTime, fmt::friendly::SpanParser,
    tz::TimeZone,
};

/// What [`parse_duration`] accepts, for error messages.
pub const DURATION_SYNTAX: &str = "a duration such as \"30d\", \"12h\" or \"1h 30m\": whole \
     numbers each followed by a unit (y, mo, w, d, h, m, s, ms, us, ns, or a long form such as \
     \"days\"), largest unit first and each unit once; only the last unit may have a fraction, \
     and only if it is hours or smaller (\"1.5h\")";

/// What [`parse_utc_timestamp`] accepts, for error messages.
pub const TIMESTAMP_SYNTAX: &str =
    "an RFC 3339 time such as \"2027-03-01T00:00:00Z\" (no offset means UTC)";

/// A month as a fixed duration: 30.44 days.
const MONTH_SECS: i64 = 2_630_016;
/// A year as a fixed duration: 365.25 days.
const YEAR_SECS: i64 = 31_557_600;

/// A duration or timestamp that could not be read. The message says what was
/// wrong; [`DURATION_SYNTAX`] and [`TIMESTAMP_SYNTAX`] say what is accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ParseTimeError(String);

/// jiff's errors start by naming the format; the caller names the setting.
fn detail(e: jiff::Error) -> ParseTimeError {
    let msg = e.to_string();
    let msg = msg
        .strip_prefix("failed to parse input in the \"friendly\" duration format: ")
        .unwrap_or(&msg);
    ParseTimeError(msg.to_string())
}

/// `M` used as a unit: a lone capital M after a number (`1M`, `2 M 3d`).
fn uses_capital_m(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    chars.iter().enumerate().any(|(i, &c)| {
        let before = chars[..i].iter().rev().find(|c| !c.is_whitespace());
        let after = chars.get(i + 1);
        c == 'M'
            && before.is_some_and(|b| b.is_ascii_digit() || *b == '.')
            && after.is_none_or(|a| a.is_whitespace() || a.is_ascii_digit())
    })
}

/// Parse a duration string (see the [module docs](self) for the syntax).
pub fn parse_duration(input: &str) -> Result<Duration, ParseTimeError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseTimeError("the duration is empty".into()));
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let span = SpanParser::new().parse_span(s).map_err(|e| {
        if uses_capital_m(s) {
            ParseTimeError(
                "\"M\" is not a unit (it reads as minutes); write \"mo\" or \"months\" for months"
                    .into(),
            )
        } else {
            detail(e)
        }
    })?;
    if span.is_negative() {
        return Err(ParseTimeError("a duration cannot be negative".into()));
    }
    // jiff refuses to give years and months a fixed length; the mediator
    // always has, so they are converted here and the rest (days as 24 hours)
    // by jiff.
    let calendar =
        i64::from(span.get_years()) * YEAR_SECS + i64::from(span.get_months()) * MONTH_SECS;
    let rest = span
        .years(0)
        .months(0)
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err(detail)?;
    let total = rest
        .checked_add(SignedDuration::from_secs(calendar))
        .ok_or_else(|| ParseTimeError("the duration is too long".into()))?;
    Duration::try_from(total).map_err(|e| ParseTimeError(e.to_string()))
}

/// No offset (`Z`, `+hh:mm`, `-hh:mm`) or annotation after a full
/// `YYYY-MM-DD?HH:MM:SS`: the shape that is read as UTC.
fn is_offsetless_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19
        && matches!(b[10], b'T' | b't' | b' ')
        && b[13] == b':'
        && b[16] == b':'
        && !b[19..]
            .iter()
            .any(|c| matches!(c, b'Z' | b'z' | b'+' | b'-' | b'['))
}

/// Parse an RFC 3339 timestamp (see the [module docs](self)); a time with no
/// offset is UTC.
pub fn parse_utc_timestamp(input: &str) -> Result<SystemTime, ParseTimeError> {
    let s = input.trim();
    match s.parse::<Timestamp>() {
        Ok(at) => Ok(at.into()),
        Err(_) if is_offsetless_datetime(s) => s
            .parse::<DateTime>()
            .and_then(|dt| dt.to_zoned(TimeZone::UTC))
            .map(|at| at.timestamp().into())
            .map_err(detail),
        Err(e) => Err(detail(e)),
    }
}

/// Format Unix seconds as RFC 3339 UTC with whole seconds, e.g.
/// `2026-11-19T10:00:00Z`. A value past what RFC 3339 can show (year 9999) is
/// written as plain seconds.
pub fn format_utc_seconds(unix_secs: u64) -> String {
    i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| Timestamp::from_second(secs).ok())
        .map_or_else(
            || format!("{unix_secs} (Unix seconds)"),
            |at| at.to_string(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_with_a_multibyte_character_is_refused_not_a_panic() {
        for input in [
            "2027-03-01T00:00:0é",
            "2027-03-01T00:00:00é",
            "2027-03-01T00:00:€0Z",
        ] {
            assert!(parse_utc_timestamp(input).is_err(), "{input}");
        }
    }

    const MIN: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86_400;
    const WEEK: u64 = 7 * DAY;
    const MONTH: u64 = 2_630_016;
    const YEAR: u64 = 31_557_600;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// Every duration that humantime read and this still reads, with the value
    /// humantime gave it. The first rows are the values found in the shipped
    /// templates, docs, wizard defaults and tests.
    #[test]
    fn durations_parse_to_what_they_always_did() {
        let cases: &[(&str, Duration)] = &[
            // Templates, docs, defaults and tests.
            ("30d", secs(30 * DAY)),
            ("12h", secs(12 * HOUR)),
            ("0", Duration::ZERO),
            ("2h", secs(2 * HOUR)),
            ("30m", secs(30 * MIN)),
            ("6h", secs(6 * HOUR)),
            ("7d", secs(7 * DAY)),
            ("24h", secs(24 * HOUR)),
            // Combinations, with and without spaces.
            ("1h30m", secs(HOUR + 30 * MIN)),
            ("1h 30m", secs(HOUR + 30 * MIN)),
            ("1h\t30m", secs(HOUR + 30 * MIN)),
            ("2h 37min", secs(9420)),
            ("30d12h", secs(30 * DAY + 12 * HOUR)),
            ("1d 0h", secs(DAY)),
            ("1 h", secs(HOUR)),
            (
                "1 year 1 month 1 week 1 day",
                secs(YEAR + MONTH + WEEK + DAY),
            ),
            ("1y1d", secs(YEAR + DAY)),
            ("  12h ", secs(12 * HOUR)),
            // Fixed-length months and years.
            ("1month", secs(MONTH)),
            ("2 months", secs(2 * MONTH)),
            ("1y", secs(YEAR)),
            ("1yr", secs(YEAR)),
            ("2yrs", secs(2 * YEAR)),
            ("1year", secs(YEAR)),
            ("10years", secs(10 * YEAR)),
            // Every other humantime spelling.
            ("3nanos", Duration::from_nanos(3)),
            ("3nsec", Duration::from_nanos(3)),
            ("3ns", Duration::from_nanos(3)),
            ("3usec", Duration::from_micros(3)),
            ("3us", Duration::from_micros(3)),
            ("3µs", Duration::from_micros(3)),
            ("3millis", Duration::from_millis(3)),
            ("3msec", Duration::from_millis(3)),
            ("32ms", Duration::from_millis(32)),
            ("3seconds", secs(3)),
            ("1second", secs(1)),
            ("3secs", secs(3)),
            ("3sec", secs(3)),
            ("3s", secs(3)),
            ("3minutes", secs(3 * MIN)),
            ("1minute", secs(MIN)),
            ("3min", secs(3 * MIN)),
            ("3mins", secs(3 * MIN)),
            ("3m", secs(3 * MIN)),
            ("3hours", secs(3 * HOUR)),
            ("1hour", secs(HOUR)),
            ("3hr", secs(3 * HOUR)),
            ("3hrs", secs(3 * HOUR)),
            ("3days", secs(3 * DAY)),
            ("1day", secs(DAY)),
            ("3weeks", secs(3 * WEEK)),
            ("1week", secs(WEEK)),
            ("3wk", secs(3 * WEEK)),
            ("3wks", secs(3 * WEEK)),
            ("3w", secs(3 * WEEK)),
            // Fractions on the last unit, hours or smaller.
            ("1.5h", secs(HOUR + 30 * MIN)),
            ("1h 1.5m", secs(HOUR + 90)),
            ("4.2s", Duration::new(4, 200_000_000)),
            ("0.25 hours", secs(15 * MIN)),
            // Zero in other spellings.
            ("0s", Duration::ZERO),
            ("0d", Duration::ZERO),
        ];
        for (input, want) in cases {
            assert_eq!(parse_duration(input).as_ref(), Ok(want), "{input:?}");
        }
    }

    /// New in jiff's grammar; harmless additions.
    #[test]
    fn durations_jiff_adds_also_parse() {
        for (input, want) in [
            ("1mo", secs(MONTH)),
            ("2mos", secs(2 * MONTH)),
            ("2 milliseconds", Duration::from_millis(2)),
            ("01:30:00", secs(HOUR + 30 * MIN)),
            ("2 hours, 30 minutes", secs(2 * HOUR + 30 * MIN)),
            ("1,5s", Duration::from_millis(1500)),
            ("+1h", secs(HOUR)),
        ] {
            assert_eq!(parse_duration(input), Ok(want), "{input:?}");
        }
    }

    /// Refused, by humantime and still, or (marked) newly.
    #[test]
    fn bad_durations_are_refused() {
        for input in [
            "",
            "   ",
            "forever",
            "30 days please",
            "carrier-pigeon",
            "00",
            "30",
            "1H",
            "1D",
            "-1h",
            "1h ago",
            "PT1H",
            // Newly refused (humantime read these).
            "1M",
            "1y 1M",
            "1.5M",
            "1.5d",
            "1.0d",
            "1.5w",
            "0.5y",
            "1.5 months",
            "1.5h 30m",
            "30m 1h",
            "1s 1s",
            "1 0d",
            "100000y",
        ] {
            assert!(parse_duration(input).is_err(), "{input:?} must be refused");
        }
    }

    #[test]
    fn a_capital_m_says_what_to_write_instead() {
        let err = parse_duration("1M").unwrap_err().to_string();
        assert!(err.contains("\"mo\""), "{err}");
        // Not when the M is part of another word.
        let err = parse_duration("1 Mango").unwrap_err().to_string();
        assert!(!err.contains("\"mo\""), "{err}");
    }

    fn unix(input: &str) -> Result<f64, ParseTimeError> {
        parse_utc_timestamp(input).map(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
        })
    }

    #[test]
    fn timestamps_parse_as_they_always_did() {
        const AT: f64 = 1_803_859_200.0; // 2027-03-01T00:00:00Z
        for (input, want) in [
            ("2027-03-01T00:00:00Z", AT),
            ("2027-03-01T00:00:00+00:00", AT),
            ("2027-03-01T00:00:00", AT),
            ("2027-03-01 00:00:00", AT),
            ("2027-03-01 00:00:00Z", AT),
            ("2027-03-01T00:00:00.5Z", AT + 0.5),
            ("2027-03-01T00:00:00.5", AT + 0.5),
            ("2027-03-01T00:00:00.000000001Z", AT + 1e-9),
            // A leap second is read as :59.
            ("2016-12-31T23:59:60Z", 1_483_228_799.0),
            ("  2027-03-01T00:00:00Z  ", AT),
        ] {
            assert_eq!(unix(input), Ok(want), "{input:?}");
        }
    }

    #[test]
    fn timestamps_jiff_adds_also_parse() {
        const AT: f64 = 1_803_859_200.0;
        for (input, want) in [
            ("2027-03-01t00:00:00z", AT),
            ("2027-03-01T00:00Z", AT),
            ("2027-03-01T00:00:00-00:00", AT),
            // An offset is honoured (humantime refused this).
            ("2027-03-01T02:00:00+02:00", AT),
        ] {
            assert_eq!(unix(input), Ok(want), "{input:?}");
        }
    }

    #[test]
    fn bad_timestamps_are_refused() {
        for input in [
            "",
            "true",
            "1803772800",
            "2027-03-01",
            "next month",
            "2027-02-29T00:00:00Z",
            "2027-03-01T24:00:00Z",
            // Newly refused: more than nine fractional digits.
            "2027-03-01T00:00:00.1234567891Z",
        ] {
            assert!(unix(input).is_err(), "{input:?} must be refused");
        }
    }

    #[test]
    fn timestamps_format_as_rfc3339_seconds() {
        assert_eq!(format_utc_seconds(1_795_082_400), "2026-11-19T10:00:00Z");
        assert_eq!(format_utc_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc_seconds(1_803_859_200), "2027-03-01T00:00:00Z");
        assert_eq!(
            format_utc_seconds(u64::MAX),
            format!("{} (Unix seconds)", u64::MAX)
        );
    }

    #[test]
    fn a_parsed_timestamp_formats_back() {
        let at = parse_utc_timestamp("2027-03-01 12:34:56").unwrap();
        let secs = at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(format_utc_seconds(secs), "2027-03-01T12:34:56Z");
    }
}
