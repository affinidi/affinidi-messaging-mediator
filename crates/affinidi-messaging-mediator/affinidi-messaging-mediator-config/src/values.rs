//! Strict readers for the string-typed values in `mediator.toml`.
//!
//! Every setting in the file is a string (so the environment can override it),
//! and every one is read here the same way: surrounding whitespace is trimmed,
//! enum-like values are lowercased, and a value that does not read is a
//! [`ConfigError::Invalid`] naming `section.key`, the value and what was
//! expected. Nothing falls back to a built-in default — a typo such as
//! `listed_messages = "5O"` must stop the mediator, not quietly run it on a
//! limit the operator did not choose.

use std::str::FromStr;

use crate::error::ConfigError;

/// What a numeric type accepts, in words for an error message.
fn expected_number<T>() -> &'static str {
    match std::any::type_name::<T>() {
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => "a whole number of 0 or more",
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => "a whole number",
        "f32" | "f64" => "a number",
        _ => "a number",
    }
}

/// A number. Trimmed; nothing else is accepted (no units, no separators).
pub fn number<T: FromStr>(key: &str, value: &str) -> Result<T, ConfigError> {
    let value = value.trim();
    value
        .parse()
        .map_err(|_| ConfigError::invalid(key, value, expected_number::<T>()))
}

/// A number, or `default` when the value is empty (a key that is optional in
/// the file: `#[serde(default)]` leaves it empty when absent).
pub fn number_or<T: FromStr>(key: &str, value: &str, default: T) -> Result<T, ConfigError> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    number(key, value)
}

/// A number of at least `min`.
pub fn number_at_least<T>(key: &str, value: &str, min: T) -> Result<T, ConfigError>
where
    T: FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let n: T = number(key, value)?;
    if n < min {
        return Err(ConfigError::invalid(
            key,
            value.trim(),
            format!("a whole number of {min} or more"),
        ));
    }
    Ok(n)
}

/// A queue limit: a whole number of 0 or more, or `-1` for no limit. Any other
/// negative number is refused — it would otherwise be read as unlimited.
pub fn queue_limit(key: &str, value: &str) -> Result<i32, ConfigError> {
    let n: i32 = number(key, value)?;
    if n < -1 {
        return Err(ConfigError::invalid(
            key,
            value.trim(),
            "a whole number of 0 or more, or -1 for no limit",
        ));
    }
    Ok(n)
}

/// `true` or `false`, in any case, trimmed.
pub fn boolean(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::invalid(
            key,
            value.trim(),
            "\"true\" or \"false\"",
        )),
    }
}

/// [`boolean`], or `default` when the value is empty.
pub fn boolean_or(key: &str, value: &str, default: bool) -> Result<bool, ConfigError> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    boolean(key, value)
}

/// One of `legal` (each written in lowercase), compared after trimming and
/// lowercasing the value. Returns the matching entry of `legal`.
pub fn one_of<'a>(key: &str, value: &str, legal: &[&'a str]) -> Result<&'a str, ConfigError> {
    let normalised = value.trim().to_ascii_lowercase();
    legal
        .iter()
        .find(|candidate| **candidate == normalised)
        .copied()
        .ok_or_else(|| {
            let list = legal
                .iter()
                .map(|l| format!("\"{l}\""))
                .collect::<Vec<_>>()
                .join(", ");
            ConfigError::invalid(key, value.trim(), format!("one of {list}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_trimmed_and_nothing_else_is_accepted() {
        assert_eq!(number::<usize>("limits.x", " 42 ").unwrap(), 42);
        for bad in ["5O", "1MB", "10/s", "", "-1", "1_000", "1,000"] {
            let err = number::<usize>("limits.listed_messages", bad).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("limits.listed_messages"), "{msg}");
            assert!(msg.contains("whole number of 0 or more"), "{msg}");
        }
    }

    #[test]
    fn an_error_names_the_key_the_value_and_the_type() {
        let msg = number::<u64>("security.jwt_access_expiry", "15m")
            .unwrap_err()
            .to_string();
        assert_eq!(
            msg,
            "security.jwt_access_expiry = \"15m\" is not valid: expected a whole number of 0 or more"
        );
    }

    #[test]
    fn number_or_defaults_only_when_empty() {
        assert_eq!(number_or("k", "", 7u32).unwrap(), 7);
        assert_eq!(number_or("k", "  ", 7u32).unwrap(), 7);
        assert_eq!(number_or("k", "3", 7u32).unwrap(), 3);
        assert!(number_or("k", "x", 7u32).is_err());
    }

    #[test]
    fn number_at_least_refuses_values_below_the_minimum() {
        assert_eq!(number_at_least("k", "10", 10u64).unwrap(), 10);
        let msg = number_at_least("security.jwt_access_expiry", "9", 10u64)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("10 or more"), "{msg}");
    }

    #[test]
    fn a_queue_limit_takes_minus_one_and_no_other_negative() {
        assert_eq!(queue_limit("k", "-1").unwrap(), -1);
        assert_eq!(queue_limit("k", "0").unwrap(), 0);
        assert_eq!(queue_limit("k", "200").unwrap(), 200);
        for bad in ["-2", "-100", "lots"] {
            assert!(queue_limit("k", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn booleans_are_trimmed_and_case_insensitive() {
        assert!(boolean("k", " TRUE ").unwrap());
        assert!(!boolean("k", "False").unwrap());
        for bad in ["yes", "1", "", "ture", "on"] {
            assert!(boolean("k", bad).is_err(), "{bad}");
        }
        assert!(boolean_or("k", "", true).unwrap());
        assert!(boolean_or("k", "nope", true).is_err());
    }

    #[test]
    fn one_of_lowercases_and_lists_the_legal_values() {
        let legal = ["explicit_allow", "explicit_deny"];
        assert_eq!(
            one_of("security.mediator_acl_mode", " Explicit_Allow ", &legal).unwrap(),
            "explicit_allow"
        );
        let msg = one_of("security.mediator_acl_mode", "explicit-allow", &legal)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("security.mediator_acl_mode"), "{msg}");
        assert!(
            msg.contains("\"explicit_allow\", \"explicit_deny\""),
            "{msg}"
        );
    }
}
