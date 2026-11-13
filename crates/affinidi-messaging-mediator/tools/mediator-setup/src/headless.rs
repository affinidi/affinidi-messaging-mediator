//! Headless input: one recipe, built from three layers.
//!
//! Every headless run (`--from`, `--non-interactive`, `--setup-key-file`)
//! describes the mediator as a [`BuildRecipe`]:
//!
//! 1. the recipe file given with `--from`, or an empty recipe;
//! 2. the per-option flags (`--did-method`, `--secret-storage`, …), each a
//!    shorthand for one recipe key;
//! 3. `--set section.key=value` overrides, in order.
//!
//! Later layers win. Every value a flag or `--set` changes is reported with
//! one line, and so is every flag this run does not use, so a script never
//! has an input dropped without a word. The merged table is then
//! deserialised with the recipe's `deny_unknown_fields`, so a mistyped
//! `--set` key is an error rather than a no-op.

use toml::{Table, Value};

use crate::cli::{Args, DeploymentType, DidMethod, Protocol, SslMode};
use crate::recipe::BuildRecipe;

/// Which headless entry point is building the recipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--from <recipe>`.
    Recipe,
    /// `--non-interactive` without `--from`.
    Flags,
    /// `--setup-key-file` (phase 2 of the online admin-only VTA flow).
    SetupKey,
}

/// A merged recipe and the lines reporting how it was put together.
pub struct HeadlessRecipe {
    pub recipe: BuildRecipe,
    pub notes: Vec<String>,
}

/// Build the run's recipe from `--from`, the shorthand flags and `--set`.
pub fn build(args: &Args, mode: Mode) -> anyhow::Result<HeadlessRecipe> {
    let mut notes = Vec::new();
    let mut table = match (&args.from, mode) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Cannot read build recipe '{path}': {e}"))?;
            text.parse::<Table>()
                .map_err(|e| anyhow::anyhow!("Invalid build recipe '{path}': {e}"))?
        }
        (None, _) => Table::new(),
    };

    if args.from.is_none() {
        if args.did_method.is_none() {
            anyhow::bail!(
                "{} needs --did-method (peer or webvh) — or a recipe via --from. There is no \
                 default: a VTA-managed DID cannot be minted without a VTA session (use a \
                 sealed-mint recipe for that).",
                match mode {
                    Mode::SetupKey => "--setup-key-file",
                    _ => "--non-interactive",
                }
            );
        }
        // An empty recipe still needs its one required key.
        if args.deployment.is_none() {
            set(
                &mut table,
                "deployment.type",
                Value::from("local"),
                None,
                &mut notes,
            )?;
        }
    }

    // ── Shorthand flags ───────────────────────────────────────────────
    if let Some(path) = &args.config {
        set(
            &mut table,
            "output.config_path",
            path.as_str().into(),
            Some("--config"),
            &mut notes,
        )?;
    }
    if let Some(d) = args.deployment {
        let v = match d {
            DeploymentType::Local => "local",
            DeploymentType::Server => "server",
            DeploymentType::Container => "container",
        };
        set(
            &mut table,
            "deployment.type",
            v.into(),
            Some("--deployment"),
            &mut notes,
        )?;
    }
    if let Some(p) = args.protocol {
        let v: Vec<Value> = match p {
            Protocol::Didcomm => vec!["didcomm".into()],
            Protocol::Tsp => vec!["didcomm".into(), "tsp".into()],
        };
        set(
            &mut table,
            "deployment.protocols",
            Value::Array(v),
            Some("--protocol"),
            &mut notes,
        )?;
    }
    if let Some(m) = args.did_method {
        let v = match m {
            DidMethod::Peer => "did:peer",
            DidMethod::Webvh => "did:webvh",
            DidMethod::Vta => "vta",
        };
        set(
            &mut table,
            "identity.did_method",
            v.into(),
            Some("--did-method"),
            &mut notes,
        )?;
    }
    if let Some(url) = &args.public_url {
        set(
            &mut table,
            "identity.public_url",
            url.as_str().into(),
            Some("--public-url"),
            &mut notes,
        )?;
    }
    if args.save_did_web {
        set(
            &mut table,
            "identity.save_did_web",
            true.into(),
            Some("--save-did-web"),
            &mut notes,
        )?;
    }
    if args.present_as_scid {
        set(
            &mut table,
            "identity.present_as",
            "scid".into(),
            Some("--present-as-scid"),
            &mut notes,
        )?;
    }
    if args.no_scid_alias {
        set(
            &mut table,
            "identity.scid_also_known_as",
            false.into(),
            Some("--no-scid-alias"),
            &mut notes,
        )?;
    }
    if !args.key_suite.is_empty() {
        let v = args
            .key_suite
            .iter()
            .map(|s| Value::from(s.to_string()))
            .collect();
        set(
            &mut table,
            "identity.extra_key_suites",
            Value::Array(v),
            Some("--key-suite"),
            &mut notes,
        )?;
    }
    if let Some(s) = args.secret_storage {
        set(
            &mut table,
            "secrets.storage",
            s.to_string().into(),
            Some("--secret-storage"),
            &mut notes,
        )?;
    }
    if args.allow_plaintext_file {
        set(
            &mut table,
            "secrets.allow_plaintext_file",
            true.into(),
            Some("--allow-plaintext-file"),
            &mut notes,
        )?;
    }
    if let Some(ssl) = args.ssl {
        let v = match ssl {
            SslMode::None => "none",
            SslMode::SelfSigned => "self-signed",
        };
        set(
            &mut table,
            "security.ssl",
            v.into(),
            Some("--ssl"),
            &mut notes,
        )?;
    }
    if let Some(url) = &args.database_url {
        set(
            &mut table,
            "database.url",
            url.as_str().into(),
            Some("--database-url"),
            &mut notes,
        )?;
    }
    if let Some(admin) = args.admin {
        set(
            &mut table,
            "security.admin",
            admin.recipe_value().into(),
            Some("--admin"),
            &mut notes,
        )?;
    }
    if let Some(did) = &args.admin_did {
        set(
            &mut table,
            "security.admin",
            "import".into(),
            Some("--admin-did"),
            &mut notes,
        )?;
        set(
            &mut table,
            "security.admin_did",
            did.as_str().into(),
            Some("--admin-did"),
            &mut notes,
        )?;
    }
    if let Some(addr) = &args.listen_address {
        set(
            &mut table,
            "output.listen_address",
            addr.as_str().into(),
            Some("--listen-address"),
            &mut notes,
        )?;
    }
    if let Some(ctx) = &args.vta_context {
        set(
            &mut table,
            "vta.context",
            ctx.as_str().into(),
            Some("--vta-context"),
            &mut notes,
        )?;
    }

    // `--mediator-url` is the public URL in the setup-key flow.
    if let Some(url) = &args.mediator_url {
        if mode == Mode::SetupKey {
            if get(&table, "identity.public_url").is_none() {
                set(
                    &mut table,
                    "identity.public_url",
                    url.as_str().into(),
                    Some("--mediator-url"),
                    &mut notes,
                )?;
            }
        } else {
            notes.push(ignored(
                "--mediator-url",
                "it is read by --setup-key-file only",
            ));
        }
    }
    if mode != Mode::SetupKey && args.vta_did.is_some() {
        notes.push(ignored(
            "--vta-did",
            "it pre-fills the interactive wizard and drives --setup-key-*; a recipe run takes \
             the VTA from the sealed bundle",
        ));
    }

    // ── --set overrides ───────────────────────────────────────────────
    for raw in &args.set {
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--set '{raw}': expected section.key=value"))?;
        set(
            &mut table,
            key.trim(),
            parse_value(value),
            Some("--set"),
            &mut notes,
        )?;
    }

    let recipe: BuildRecipe = Value::Table(table)
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid build recipe: {e}"))?;
    Ok(HeadlessRecipe { recipe, notes })
}

/// A `--set` value: TOML when it parses as a TOML value, else a string.
fn parse_value(raw: &str) -> Value {
    let raw = raw.trim();
    format!("v = {raw}")
        .parse::<Table>()
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| Value::from(raw))
}

fn get<'a>(table: &'a Table, path: &str) -> Option<&'a Value> {
    let (section, key) = path.split_once('.')?;
    table.get(section)?.as_table()?.get(key)
}

fn ignored(flag: &str, why: &str) -> String {
    format!("ignored: {flag} ({why})")
}

/// Set `section.key` to `value`, recording a note when `source` names the
/// flag that did it.
fn set(
    table: &mut Table,
    path: &str,
    value: Value,
    source: Option<&str>,
    notes: &mut Vec<String>,
) -> anyhow::Result<()> {
    let (section, key) = path
        .split_once('.')
        .filter(|(s, k)| !s.is_empty() && !k.is_empty() && !k.contains('.'))
        .ok_or_else(|| anyhow::anyhow!("'{path}' is not a recipe key (expected section.key)"))?;
    let section_table = table
        .entry(section.to_string())
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("recipe key '{section}' is not a [section]"))?;
    let previous = section_table.insert(key.to_string(), value.clone());
    if let Some(source) = source {
        let shown = if is_sensitive(path) {
            "<redacted>".to_string()
        } else {
            value.to_string()
        };
        notes.push(match previous {
            Some(old) if old != value => {
                let old = if is_sensitive(path) {
                    "<redacted>".to_string()
                } else {
                    old.to_string()
                };
                format!("override: {path} = {shown} ({source}; was {old})")
            }
            _ => format!("set: {path} = {shown} ({source})"),
        });
    }
    Ok(())
}

/// Recipe values that may carry credentials when given on the command line.
fn is_sensitive(path: &str) -> bool {
    path == "database.url"
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(list: &[&str]) -> Args {
        Args::parse_from(std::iter::once("mediator-setup").chain(list.iter().copied()))
    }

    #[test]
    fn non_interactive_requires_a_did_method() {
        let err = build(&args(&["--non-interactive"]), Mode::Flags)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("--did-method"), "{err}");
    }

    #[test]
    fn flags_map_onto_recipe_keys_with_a_line_each() {
        let built = build(
            &args(&[
                "--non-interactive",
                "--did-method",
                "peer",
                "--deployment",
                "server",
                "--secret-storage",
                "aws",
                "--admin",
                "skip",
                "--key-suite",
                "secp256k1",
            ]),
            Mode::Flags,
        )
        .unwrap();
        let r = &built.recipe;
        assert_eq!(r.deployment.deployment_type, "server");
        assert_eq!(r.identity.did_method, "did:peer");
        assert_eq!(r.secrets.storage, "aws_secrets://");
        assert_eq!(r.security.admin, "skip");
        assert_eq!(r.identity.extra_key_suites, vec!["secp256k1"]);
        for key in [
            "deployment.type",
            "identity.did_method",
            "secrets.storage",
            "security.admin",
            "identity.extra_key_suites",
        ] {
            assert!(
                built.notes.iter().any(|n| n.contains(key)),
                "no line for {key}: {:?}",
                built.notes
            );
        }
    }

    #[test]
    fn set_overrides_a_recipe_value_and_says_so() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("r.toml");
        std::fs::write(
            &path,
            "[deployment]\ntype = \"local\"\n[identity]\ndid_method = \"did:peer\"\n\
             [security]\nnetwork_mode = \"open\"\n",
        )
        .unwrap();
        let built = build(
            &args(&[
                "--from",
                path.to_str().unwrap(),
                "--set",
                "security.network_mode=closed",
                "--set",
                "output.trust_xff_cidrs=[\"10.0.0.0/8\"]",
            ]),
            Mode::Recipe,
        )
        .unwrap();
        assert_eq!(
            built.recipe.security.network_mode.as_deref(),
            Some("closed")
        );
        assert_eq!(built.recipe.output.trust_xff_cidrs, vec!["10.0.0.0/8"]);
        assert!(
            built
                .notes
                .iter()
                .any(|n| n.starts_with("override: security.network_mode")),
            "{:?}",
            built.notes
        );
    }

    #[test]
    fn a_mistyped_set_key_is_an_error() {
        let err = build(
            &args(&[
                "--non-interactive",
                "--did-method",
                "peer",
                "--set",
                "security.network_mod=closed",
            ]),
            Mode::Flags,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("network_mod"), "{err}");
        assert!(
            build(
                &args(&[
                    "--non-interactive",
                    "--did-method",
                    "peer",
                    "--set",
                    "nodot"
                ]),
                Mode::Flags
            )
            .is_err()
        );
    }

    #[test]
    fn unused_flags_are_reported() {
        let built = build(
            &args(&[
                "--non-interactive",
                "--did-method",
                "peer",
                "--vta-did",
                "did:web:vta.example.com",
                "--mediator-url",
                "https://m.example.com",
            ]),
            Mode::Flags,
        )
        .unwrap();
        assert!(
            built
                .notes
                .iter()
                .any(|n| n.starts_with("ignored: --vta-did"))
        );
        assert!(
            built
                .notes
                .iter()
                .any(|n| n.starts_with("ignored: --mediator-url"))
        );
    }

    #[test]
    fn database_url_credentials_are_not_echoed() {
        let built = build(
            &args(&[
                "--non-interactive",
                "--did-method",
                "peer",
                "--database-url",
                "redis://:hunter2@db/",
            ]),
            Mode::Flags,
        )
        .unwrap();
        assert!(built.notes.iter().all(|n| !n.contains("hunter2")));
    }
}
