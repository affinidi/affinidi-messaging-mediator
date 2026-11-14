//! `mediator-console <command>` against a live in-process mediator: the
//! answer on stdout, and the exit code a script acts on.

use std::path::PathBuf;
use std::process::Output;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};

/// A profile file for `user`, private to this user as the console requires.
fn profile(env: &TestEnvironment, user: &TestUser) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mediator-console-{}-{}.json",
        user.alias,
        uuid::Uuid::new_v4()
    ));
    let body = serde_json::json!({
        "alias": user.alias,
        "did": user.did,
        "mediator": env.mediator.did(),
        "secrets": user.secrets,
    });
    std::fs::write(&path, body.to_string()).expect("write the profile");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("make the profile private");
    }
    path
}

/// Run the console with `args`, off the test's runtime.
async fn console(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_mediator-console"))
            .args(&args)
            .env("RUST_LOG", "error")
            .output()
            .expect("run mediator-console")
    })
    .await
    .expect("the console ran")
}

fn args(profile: &std::path::Path, rest: &[&str]) -> Vec<String> {
    let mut all = vec!["-p".to_string(), profile.display().to_string()];
    all.extend(rest.iter().map(|s| s.to_string()));
    all
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_answer_in_json_and_exit_codes_tell_refused_from_done() {
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("environment");
    let op = env.add_user("operator").await.expect("operator");
    let bob = env.add_user("bob").await.expect("bob");
    env.mediator
        .store()
        .account_set_role(&op.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    let admin = profile(&env, &op);
    let standard = profile(&env, &bob);

    // An administrator's statistics, as the Trust Task's JSON.
    let out = console(args(&admin, &["stats", "--json"])).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let stats: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    assert!(stats["version"].is_string(), "{stats}");

    // The account list, in text: one line per account.
    let out = console(args(&admin, &["accounts"])).await;
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&bob.did_hash()), "{text}");

    // A dry-run purge counts and removes nothing.
    let target = bob.did_hash();
    let out = console(args(&admin, &["purge", &target, "--dry-run", "--json"])).await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let purge: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(purge["matched"], 0);
    assert!(purge.get("purged").is_none(), "{purge}");

    // A standard account is refused the mediator-wide views: exit 3.
    let out = console(args(&standard, &["stats"])).await;
    assert_eq!(out.status.code(), Some(3));
    // …but reads its own account.
    let out = console(args(&standard, &["account", "--json"])).await;
    assert_eq!(out.status.code(), Some(0));

    // A purge that doesn't say whether to remove is a usage error: exit 2,
    // and nothing is sent.
    let out = console(args(&admin, &["purge"])).await;
    assert_eq!(out.status.code(), Some(2));

    let _ = std::fs::remove_file(admin);
    let _ = std::fs::remove_file(standard);
}
