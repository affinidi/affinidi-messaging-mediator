//! Validation of operator input that the wizard checks before accepting it.

/// Safety-check for the Fjall data-directory text input. Rejects only
/// the cases that would unambiguously fail at startup:
///
///   * Empty input — there's no path to open.
///   * A path that already exists but is a regular file, symlink to a
///     non-directory, or other non-directory entry — fjall would error
///     opening it.
///
/// Anything else passes. Fjall calls `std::fs::create_dir_all` on the
/// configured path (`fjall-3.1.4/keyspace/mod.rs:335`), so missing
/// parent directories are created automatically; pre-flighting them
/// here used to reject the wizard's own default (`./data/mediator`)
/// when the parent `./data` was absent on a fresh install.
pub(crate) fn validate_fjall_data_dir(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Fjall data directory path cannot be empty.".into());
    }
    let p = std::path::Path::new(trimmed);
    if p.exists() && !p.is_dir() {
        return Err(format!(
            "'{trimmed}' exists but is not a directory — pick another path.",
        ));
    }
    Ok(())
}

/// Validate the CORS "Specific domains" allowlist the operator typed and
/// return its normalised (trimmed, comma-joined) form.
///
/// Each comma-separated entry must be one of:
///   * an exact, scheme-qualified origin — `https://app.affinidi.com`; or
///   * a leftmost-label sub-domain wildcard — `https://*.affinidi.com`
///     (optionally with a port: `https://*.affinidi.com:8443`).
///
/// Unlike the mediator's lenient server-side parse, the wizard *requires*
/// a scheme on every entry (per the operator's chosen validation policy)
/// and rejects a bare `*` — that's the separate "Allow any origin"
/// choice, not a domain. The matching semantics enforced at runtime live
/// in `affinidi_messaging_mediator`'s `OriginMatcher`; this function
/// mirrors its accepted syntax so typos surface at wizard time rather
/// than on first mediator boot.
pub fn validate_cors_domains(input: &str) -> Result<String, String> {
    let entries: Vec<&str> = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if entries.is_empty() {
        return Err(
            "Enter at least one origin (e.g. https://app.affinidi.com), or go back and pick \
             \"Allow any origin\" / \"Deny all\"."
                .into(),
        );
    }

    for entry in &entries {
        validate_cors_entry(entry)?;
    }

    Ok(entries.join(","))
}

/// Validate a single CORS allowlist entry. See [`validate_cors_domains`].
fn validate_cors_entry(entry: &str) -> Result<(), String> {
    if entry == "*" {
        return Err(
            "A bare '*' is not a domain — go back and pick \"Allow any origin\" instead.".into(),
        );
    }

    let Some((scheme, host_port)) = entry.split_once("://") else {
        return Err(format!(
            "'{entry}' is missing a scheme — write e.g. 'https://app.affinidi.com' or \
             'https://*.affinidi.com'."
        ));
    };
    if scheme.is_empty() {
        return Err(format!("'{entry}' is missing a scheme before '://'."));
    }
    if host_port.is_empty() {
        return Err(format!("'{entry}' is missing a host after '://'."));
    }
    // No path / query / fragment / userinfo — an Origin is scheme + host
    // (+ optional port) only.
    if host_port.contains(['/', '?', '#', '@', '\\']) {
        return Err(format!(
            "'{entry}' must be an origin only (scheme + host [+ :port]) — drop any path, \
             query, or '@'."
        ));
    }

    // Wildcard form: '*' is allowed only as the entire leftmost label.
    if entry.contains('*') {
        let Some(suffix) = host_port.strip_prefix("*.") else {
            return Err(format!(
                "'{entry}': '*' is only allowed as the leftmost host label, written as \
                 '{scheme}://*.suffix'."
            ));
        };
        if suffix.contains('*') {
            return Err(format!(
                "'{entry}': only one leftmost '*' wildcard is allowed."
            ));
        }
        // Validate the suffix shape. We intentionally do NOT require the
        // suffix to contain a dot — `https://*.localhost` and other
        // single-label internal hosts are legitimate, and this keeps the
        // wizard in step with the mediator's own (dot-agnostic) matcher.
        let host_suffix = suffix.rsplit_once(':').map_or(suffix, |(h, _)| h);
        if host_suffix.is_empty() || host_suffix.starts_with('.') {
            return Err(format!(
                "'{entry}': '{host_suffix}' is not a valid wildcard suffix — use e.g. \
                 '{scheme}://*.example.com'."
            ));
        }
    }

    // Final shape check: an origin carries no whitespace or control
    // characters (the mediator parses exact origins into an HTTP
    // `HeaderValue`, which rejects exactly these). Checked here without
    // pulling in the `http` crate — the setup tool intentionally has no
    // dependency on the mediator runtime.
    if entry.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "'{entry}' contains whitespace or control characters that aren't valid in an origin."
        ));
    }
    Ok(())
}
