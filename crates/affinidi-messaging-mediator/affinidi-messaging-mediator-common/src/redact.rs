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
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
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
        // An `@` past the authority is part of the path, not userinfo.
        assert_eq!(redact_url("https://h/a@b"), "https://h/a@b");
    }
}
