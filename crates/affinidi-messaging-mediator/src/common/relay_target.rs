//! One spelling for each relay target on the forwarding block list.
//!
//! `processors.forwarding.blocked_forwarding` holds DIDs and service-endpoint
//! URLs. The same DID or URL can be written more than one way: `DID:Example:x`
//! and `did:example:x`, `https://Mediator.Example:443/` and
//! `https://mediator.example`, a DID URL with a fragment or query, or an
//! internationalised host name and its punycode form. Entries are stored in
//! the form [`canonical_relay_target`] returns, and every candidate is put
//! into that form before the lookup, so equivalent spellings match.

use ahash::AHashSet;

/// The comparison form of a DID or URL.
///
/// - **DID** (`did:` in any case): the `did` scheme and the method name are
///   lowercased; a query (`?…`) and fragment (`#…`) are dropped; in the
///   method-specific id, percent-escapes are written with uppercase hex and
///   an escape of a character the DID syntax allows unescaped (letters,
///   digits, `.`, `-`, `_`) is decoded. The method-specific id is otherwise
///   kept as written: its case is method-defined.
/// - **URL**: parsed; the scheme and host are lowercased, an
///   internationalised host is written in punycode, a trailing `.` on the
///   host is dropped, the scheme's default port is dropped, an empty path
///   becomes `/`, and the fragment is dropped. The query is kept.
/// - Anything else is returned trimmed.
///
/// Surrounding whitespace and double quotes are removed first: a service
/// endpoint read out of a JSON value can arrive quoted.
pub fn canonical_relay_target(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"').trim();
    if trimmed.len() > 4 && trimmed[..4].eq_ignore_ascii_case("did:") {
        return canonical_did(trimmed);
    }
    canonical_url(trimmed).unwrap_or_else(|| trimmed.to_string())
}

/// True when any of `candidates` is on `blocked`. `blocked` must hold
/// [`canonical_relay_target`] forms (see
/// `load_forwarding_protection_blocks`).
pub fn relay_target_blocked<'a>(
    blocked: &AHashSet<String>,
    candidates: impl IntoIterator<Item = &'a str>,
) -> bool {
    candidates
        .into_iter()
        .any(|candidate| blocked.contains(&canonical_relay_target(candidate)))
}

fn canonical_did(did: &str) -> String {
    // A DID URL's query and fragment do not change which DID it names.
    let end = did.find(['?', '#']).unwrap_or(did.len());
    let did = &did[..end];

    // did:<method>:<method-specific-id>
    let mut parts = did.splitn(3, ':');
    let _scheme = parts.next();
    let method = parts.next().unwrap_or_default().to_ascii_lowercase();
    let Some(id) = parts.next() else {
        return format!("did:{method}");
    };
    format!("did:{method}:{}", normalise_percent_encoding(id))
}

/// Uppercase every percent-escape's hex digits, and decode an escape whose
/// character the DID syntax allows unescaped (`ALPHA / DIGIT / "." / "-" /
/// "_"`), as RFC 3986 section 6.2.2 normalises a URI.
fn normalise_percent_encoding(id: &str) -> String {
    let bytes = id.as_bytes();
    let mut out = String::with_capacity(id.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = &id[i + 1..i + 3];
            let value = u8::from_str_radix(hex, 16).unwrap_or_default();
            if value.is_ascii_alphanumeric() || matches!(value, b'.' | b'-' | b'_') {
                out.push(value as char);
            } else {
                out.push('%');
                out.push_str(&hex.to_ascii_uppercase());
            }
            i += 3;
        } else {
            // Copy one whole UTF-8 character.
            let ch = id[i..].chars().next().unwrap_or_default();
            out.push(ch);
            i += ch.len_utf8().max(1);
        }
    }
    out
}

fn canonical_url(raw: &str) -> Option<String> {
    // `Url::parse` lowercases the scheme, lowercases and punycodes the host of
    // a special scheme (http, https, ws, wss), drops that scheme's default
    // port and writes an empty path as `/`.
    let mut url = url::Url::parse(raw).ok()?;
    if !url.has_host() {
        return None;
    }
    if let Some(host) = url.host_str() {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !host.is_empty() && url.host_str() != Some(host.as_str()) {
            url.set_host(Some(&host)).ok()?;
        }
    }
    url.set_fragment(None);
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(entries: &[&str]) -> AHashSet<String> {
        entries.iter().map(|e| canonical_relay_target(e)).collect()
    }

    #[test]
    fn did_spellings_share_one_form() {
        let c = canonical_relay_target;
        assert_eq!(c("did:example:abc"), "did:example:abc");
        assert_eq!(c("DID:Example:abc"), "did:example:abc");
        assert_eq!(c("did:example:abc#key-1"), "did:example:abc");
        assert_eq!(c("did:example:abc?service=x#f"), "did:example:abc");
        assert_eq!(c("\" did:example:abc \""), "did:example:abc");
        // An escaped unreserved character is decoded; other escapes are
        // written with uppercase hex.
        assert_eq!(c("did:example:a%62c"), "did:example:abc");
        assert_eq!(
            c("did:web:host.example%3a8443"),
            "did:web:host.example%3A8443"
        );
        // The method-specific id keeps its case.
        assert_ne!(c("did:example:ABC"), c("did:example:abc"));
    }

    #[test]
    fn url_spellings_share_one_form() {
        let c = canonical_relay_target;
        let want = "https://mediator.example/";
        assert_eq!(c("https://mediator.example"), want);
        assert_eq!(c("HTTPS://Mediator.EXAMPLE/"), want);
        assert_eq!(c("https://mediator.example:443/"), want);
        assert_eq!(c("https://mediator.example./"), want);
        assert_eq!(c("https://mediator.example/#frag"), want);
        assert_eq!(c("\"https://mediator.example\""), want);
        assert_eq!(
            c("wss://mediator.example:443/ws"),
            "wss://mediator.example/ws"
        );
        // A non-default port and the path are significant.
        assert_ne!(c("https://mediator.example:8443/"), want);
        assert_ne!(c("https://mediator.example/api"), want);
        // An internationalised host and its punycode form are one host.
        assert_eq!(
            c("https://bücher.example/api"),
            c("https://xn--bcher-kva.example/api")
        );
        assert_eq!(
            c("https://BÜCHER.example/api"),
            c("https://bücher.example/api")
        );
    }

    #[test]
    fn a_candidate_matches_the_list_in_any_spelling() {
        let blocked = set(&[
            "did:example:mediator",
            "https://mediator.example/api",
            "https://bücher.example",
        ]);
        for candidate in [
            "DID:EXAMPLE:mediator",
            "did:example:mediator#key-1",
            "did:example:mediator?versionId=2",
            "https://MEDIATOR.example:443/api",
            "https://mediator.example./api",
            "\"https://mediator.example/api\"",
            "https://xn--bcher-kva.example/",
        ] {
            assert!(relay_target_blocked(&blocked, [candidate]), "{candidate}");
        }
        for candidate in [
            "did:example:other",
            "did:example:Mediator",
            "https://mediator.example:8443/api",
            "https://mediator.example/api2",
            "https://other.example/api",
        ] {
            assert!(!relay_target_blocked(&blocked, [candidate]), "{candidate}");
        }
    }

    #[test]
    fn text_that_is_neither_is_kept_trimmed() {
        assert_eq!(canonical_relay_target("  not a url "), "not a url");
        assert_eq!(canonical_relay_target("did:"), "did:");
    }
}
