//! Target: `affinidi_messaging_mediator_config::env::parse_config`
//! Recon tag: T6 (P2) — pure TOML-parsing surface shared by the mediator
//! binary (`--config <path>`, operator-controlled at process start) and the
//! `mediator-setup` wizard. Local/operator reachability, not remote, but a
//! panic here is a startup DoS an operator can trigger with a malformed file,
//! and the function is explicitly `pub` (two consumers depend on it per its
//! own doc comment), so it is real published API, not a reach-around.
//! Technique: cargo-fuzz + libFuzzer treating the corpus as raw TOML text,
//! oracle tier 1 (no-panic).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // `parse_config` returns `Result<(ConfigRaw, Vec<String>), ConfigError>` —
    // any Ok or Err is acceptable; the only oracle is "does not panic" on
    // hostile TOML (deeply nested tables, huge arrays, boundary integers in
    // every numeric field, truncated UTF-8 inside quoted strings, duplicate
    // keys, etc).
    let _ = affinidi_messaging_mediator_config::env::parse_config(s);
});
