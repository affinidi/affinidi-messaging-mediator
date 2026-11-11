//! Hiding the credentials a URL may carry before it is shown.

/// `s` with the userinfo of a `scheme://user:password@host` URL replaced by
/// `***`; any other string unchanged.
///
/// A store URL such as `redis://:password@host:6379/` carries its password
/// inline, so anything that prints one (the `Debug` of a config struct, a
/// startup error, the `config/show` Trust Task) goes through here.
pub fn redact_url(s: &str) -> String {
    let Some((scheme, rest)) = s.split_once("://") else {
        return s.to_string();
    };
    // Any `@` counts, not only one inside the authority: a password holding
    // an unencoded `/`, `?` or `#` makes the URL unparseable, and that is
    // exactly when it gets printed in an error. Hiding a path segment that
    // happens to contain `@` is the cheaper mistake.
    match rest.rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn userinfo_is_replaced_and_other_strings_are_not() {
        assert_eq!(
            redact_url("redis://:s3cret@db.internal:6379/0"),
            "redis://***@db.internal:6379/0"
        );
        assert_eq!(redact_url("redis://user:pw@host/"), "redis://***@host/");
        assert_eq!(redact_url("rediss://user:pw@host"), "rediss://***@host");
        assert_eq!(redact_url("redis://127.0.0.1/"), "redis://127.0.0.1/");
        assert_eq!(redact_url("did:web:example.com"), "did:web:example.com");
        // A password with an unencoded `/` is still hidden.
        assert_eq!(redact_url("redis://:pa/ss@host/"), "redis://***@host/");
        assert_eq!(redact_url("redis://:p#w?d@host/"), "redis://***@host/");
    }
}
