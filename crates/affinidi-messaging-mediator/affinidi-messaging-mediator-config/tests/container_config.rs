//! Drift guard for the config baked into the published container image
//! (`docker/conf/mediator.toml`, shipped by `docker/mediator.Dockerfile`).
//!
//! The image is built with `secrets-aws` and no identity of its own, so its
//! config is NOT the annotated template in `../conf/mediator.toml` — it is a
//! container profile with an empty `mediator_did` / `admin_did` and a backend
//! the binary actually compiles. Image builds are opt-in (they only run on a
//! release tag, a manual dispatch, or a PR labelled `ci:image`), so without
//! this test a newly-required config field would rot the shipped image silently
//! and only surface at release.
//!
//! Lives in `tests/` rather than a `#[cfg(test)]` module so the file it reads
//! stays outside the crate's own source tree — `docker/` is a workspace path,
//! not part of the published crate.

use std::path::PathBuf;

use affinidi_messaging_mediator_config::{ConfigRaw, env::parse_config};

/// `docker/conf/mediator.toml`, relative to this crate's manifest.
fn container_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docker/conf/mediator.toml")
}

/// `docker/test/conf/mediator.toml` — the test deployment's config
/// (`docker-compose.test.yml`), relative to this crate's manifest.
fn test_container_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docker/test/conf/mediator.toml")
}

/// The annotated template, `conf/mediator.toml`, relative to this crate's manifest.
fn template_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conf/mediator.toml")
}

/// A config's `[limits]` section as a TOML table, so two configs can be
/// compared key by key.
fn limits_table(raw: &ConfigRaw) -> toml::Table {
    toml::Table::try_from(&raw.limits).expect("[limits] serialises to a TOML table")
}

#[test]
fn container_mediator_toml_parses() {
    let path = container_config_path();
    if !path.exists() {
        // Built from the published .crate tarball rather than the workspace:
        // `docker/` isn't packaged, so there is nothing to guard here.
        eprintln!(
            "skipping: {} not present (not a workspace checkout)",
            path.display()
        );
        return;
    }

    let toml = std::fs::read_to_string(&path).expect("read docker/conf/mediator.toml");
    let (raw, unknown): (ConfigRaw, _) =
        parse_config(&toml).expect("docker/conf/mediator.toml parses as ConfigRaw");

    // Every key in the image's config is one the mediator reads; an unknown one
    // would warn on every container start (Keyring VTI-06).
    assert!(
        unknown.is_empty(),
        "unknown keys in image config: {unknown:?}"
    );

    // A published image must carry no identity: both DIDs come from the
    // environment at run time (MEDIATOR_DID / ADMIN_DID).
    assert!(
        raw.mediator_did.is_empty(),
        "image must ship no mediator_did"
    );
    assert!(
        raw.server.admin_did.is_empty(),
        "image must ship no admin_did"
    );

    // The image compiles `secrets-aws` (plus the always-available `file://`
    // backend) — `keyring://` is NOT compiled in, and naming it here is exactly
    // what used to make `docker run <image>` hard-fail at startup.
    assert!(
        raw.secrets.backend.starts_with("file://"),
        "container backend must be file:// (cloud overrides it via \
         MEDIATOR_SECRETS_BACKEND), got '{}'",
        raw.secrets.backend
    );
}

/// A container config's `[limits]` must match the annotated template. The
/// image config overwrites the template in the published container, so a
/// limit that differs here is the one every container deployment actually
/// runs, while the template, the Rust defaults and the docs all say otherwise.
/// The send-queue limits shipped at 200 / 1000 against a documented 2000 /
/// 10000 this way — in the image, and again in the test deployment's config.
///
/// If a config needs a limit that differs on purpose, change the template too,
/// or carve the key out here with a comment saying why.
fn assert_limits_match_template(container: PathBuf, name: &str) {
    let template = template_config_path();
    if !container.exists() || !template.exists() {
        eprintln!("skipping: container or template config not present (not a workspace checkout)");
        return;
    }

    let parse = |path: &PathBuf| -> ConfigRaw {
        let toml = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        parse_config(&toml)
            .unwrap_or_else(|e| panic!("{} parses as ConfigRaw: {e}", path.display()))
            .0
    };
    let image = limits_table(&parse(&container));
    let documented = limits_table(&parse(&template));

    let drift: Vec<String> = documented
        .keys()
        .chain(image.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|key| image.get(*key) != documented.get(*key))
        .map(|key| {
            format!(
                "{key}: {name} {:?}, template {:?}",
                image.get(key),
                documented.get(key)
            )
        })
        .collect();

    assert!(
        drift.is_empty(),
        "{name} [limits] drifted from conf/mediator.toml:\n  {}",
        drift.join("\n  ")
    );
}

#[test]
fn container_limits_match_template() {
    assert_limits_match_template(container_config_path(), "docker/conf/mediator.toml");
}

#[test]
fn test_container_limits_match_template() {
    assert_limits_match_template(
        test_container_config_path(),
        "docker/test/conf/mediator.toml",
    );
}

/// The test deployment's config parses, and has no key the mediator does not
/// read.
#[test]
fn test_container_mediator_toml_parses() {
    let path = test_container_config_path();
    if !path.exists() {
        eprintln!(
            "skipping: {} not present (not a workspace checkout)",
            path.display()
        );
        return;
    }
    let toml = std::fs::read_to_string(&path).expect("read docker/test/conf/mediator.toml");
    let (raw, unknown): (ConfigRaw, _) =
        parse_config(&toml).expect("docker/test/conf/mediator.toml parses as ConfigRaw");
    assert!(
        unknown.is_empty(),
        "unknown keys in test config: {unknown:?}"
    );
    assert!(raw.secrets.backend.starts_with("file://"));
}
