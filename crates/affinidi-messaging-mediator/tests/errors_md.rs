//! `ERRORS.md` is the registry clients look error codes up in, so it has to
//! list every code the mediator can send. These tests read the source and
//! fail when a code is added (or a handler goes back to a bare number)
//! without the registry following:
//!
//! - every constant in `error_codes` has a row in `ERRORS.md`;
//! - no handler passes an integer literal where an error code goes;
//! - every problem code written in a problem-report constructor appears in
//!   `ERRORS.md`;
//! - every Trust Task error code (the framework's standard codes and each
//!   code a served task's specification declares) appears in `ERRORS.md`.

use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn errors_md() -> String {
    fs::read_to_string(root().join("ERRORS.md")).expect("ERRORS.md")
}

/// Every `.rs` file under the source trees that send errors to clients.
fn sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [
        "src",
        "affinidi-messaging-mediator-common/src",
        "affinidi-messaging-mediator-processors/src",
    ] {
        walk(&root().join(dir), &mut out);
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A file's code before its first test module: tests build errors with any
/// number they like.
fn non_test(text: &str) -> &str {
    let re = Regex::new(r"(?m)^#\[cfg\((all\()?test").unwrap();
    match re.find(text) {
        Some(m) => &text[..m.start()],
        None => text,
    }
}

/// The arguments of the call whose `(` is at `open`, split at top-level
/// commas. Strings and nested brackets are skipped over.
fn call_args(text: &str, open: usize) -> Vec<&str> {
    let bytes = text.as_bytes();
    let (mut depth, mut start, mut i) = (0usize, open + 1, open);
    let mut args = Vec::new();
    let mut in_str = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        args.push(text[start..i].trim());
                        return args;
                    }
                }
                b',' if depth == 1 => {
                    args.push(text[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    args
}

#[test]
fn every_error_code_constant_has_a_row() {
    let md = errors_md();
    let src =
        fs::read_to_string(root().join("affinidi-messaging-mediator-common/src/error_codes.rs"))
            .expect("error_codes.rs");
    let constant = Regex::new(r"(?m)^pub const ([A-Z0-9_]+): u16 = (\d+);").unwrap();
    let mut seen = std::collections::HashMap::new();
    let mut missing = Vec::new();
    for c in constant.captures_iter(&src) {
        let (name, number) = (&c[1], &c[2]);
        if let Some(other) = seen.insert(number.to_string(), name.to_string()) {
            panic!("error code {number} is both {other} and {name}");
        }
        let row = Regex::new(&format!(r"(?m)^\|\s*{number}\s*\|")).unwrap();
        if !row.is_match(&md) {
            missing.push(format!("{number} ({name})"));
        }
    }
    assert!(seen.len() > 100, "the registry was not read");
    assert!(missing.is_empty(), "ERRORS.md has no row for: {missing:?}");
}

#[test]
fn handlers_use_the_error_code_constants() {
    // A literal number where an error code goes: the first argument of a
    // `MediatorError` variant or constructor, the second of the transport
    // helpers.
    let first = Regex::new(
        r"(?s)(MediatorError::[A-Za-z]+|problem|problem_with_log|database_from_redis|session_from_redis|storage_error_opaque)\(\s*\d+\s*,",
    )
    .unwrap();
    let second =
        Regex::new(r"(?s)(tsp_problem|v1_problem|storage_cap)\(\s*[A-Za-z_&.]+\s*,\s*\d+\s*,")
            .unwrap();
    let mut found = Vec::new();
    for path in sources() {
        let text = fs::read_to_string(&path).unwrap();
        let code = non_test(&text);
        for m in first.find_iter(code).chain(second.find_iter(code)) {
            let line = code[..m.start()].lines().count() + 1;
            found.push(format!("{}:{line}", path.display()));
        }
    }
    assert!(
        found.is_empty(),
        "use an `error_codes` constant, not a number: {found:#?}"
    );
}

#[test]
fn every_problem_code_in_the_source_is_documented() {
    let md = errors_md();
    // Which argument holds the problem code, per constructor.
    let calls = [
        ("problem(", 5),
        ("problem_with_log(", 5),
        ("tsp_problem(", 2),
        ("v1_problem(", 2),
        ("tt_problem(", 1),
        ("tt_problem_with_args(", 1),
        ("ProblemReport::new(", 2),
    ];
    let literal = Regex::new(r#"^"([A-Za-z0-9_./:-]+)"(\.into\(\)|\.to_string\(\))?$"#).unwrap();
    let constant =
        Regex::new(r#"(?m)^pub const [A-Z_]*(CODE|NOT_FOUND|DENIED|INVALID|PROTECTED|UNKNOWN)[A-Z_]*: &str = "([^"]+)";"#)
            .unwrap();
    let mut checked = 0;
    let mut missing = Vec::new();
    for path in sources() {
        let text = fs::read_to_string(&path).unwrap();
        let code = non_test(&text);
        let mut found: Vec<String> = Vec::new();
        for (name, pos) in calls {
            let mut from = 0;
            while let Some(i) = code[from..].find(name) {
                let at = from + i;
                from = at + name.len();
                // `tsp_problem(` also contains `problem(`: only whole names.
                let before = code[..at].chars().last().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' {
                    continue;
                }
                let args = call_args(code, at + name.len() - 1);
                if let Some(c) = args.get(pos).and_then(|a| literal.captures(a)) {
                    found.push(c[1].to_string());
                }
            }
        }
        for c in constant.captures_iter(code) {
            found.push(c[2].to_string());
        }
        for code in found {
            checked += 1;
            // Written with its sorter and scope (`e.p.`), or a Trust Task
            // code on its own.
            let bare = code
                .strip_prefix("e.p.")
                .or_else(|| code.strip_prefix("e.m."))
                .or_else(|| code.strip_prefix("w.m."))
                .or_else(|| code.strip_prefix("w.p."))
                .unwrap_or(&code);
            let documented = md.contains(&format!(".{bare}`")) || md.contains(&format!("`{bare}`"));
            if !documented {
                missing.push(format!("{bare} ({})", path.display()));
            }
        }
    }
    assert!(checked > 150, "only {checked} problem codes were read");
    missing.sort();
    missing.dedup();
    assert!(missing.is_empty(), "not in ERRORS.md: {missing:#?}");
}

#[test]
fn every_trust_task_error_code_is_documented() {
    let md = errors_md();
    let mut codes: Vec<String> =
        affinidi_messaging_mediator::error_codes::TRUST_TASK_STANDARD_CODES
            .iter()
            .map(|(c, _)| c.to_string())
            .collect();
    let mut bundles = Vec::new();
    walk_bundles(&root().join("trust-tasks"), &mut bundles);
    assert!(!bundles.is_empty(), "no pinned Trust Task bundles");
    for bundle in bundles {
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&bundle).unwrap()).unwrap();
        collect_declared(&doc, &mut codes);
    }
    let mut missing: Vec<_> = codes
        .into_iter()
        .filter(|c| !md.contains(&format!("`{c}`")))
        .collect();
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "Trust Task codes not in ERRORS.md: {missing:#?}"
    );
}

fn walk_bundles(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("trust-tasks dir") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk_bundles(&path, out);
        } else if path.to_string_lossy().ends_with(".bundle.json") {
            out.push(path);
        }
    }
}

/// Every `errorCodes[].code` in a bundle.
fn collect_declared(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "errorCodes"
                    && let Some(list) = v.as_array()
                {
                    for e in list {
                        if let Some(c) = e.get("code").and_then(|c| c.as_str()) {
                            out.push(c.to_string());
                        }
                    }
                } else {
                    collect_declared(v, out);
                }
            }
        }
        serde_json::Value::Array(list) => list.iter().for_each(|v| collect_declared(v, out)),
        _ => {}
    }
}
