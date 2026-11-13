//! The console's stored-grant administration against a live in-process
//! mediator with mux enabled: list a principal's and a member's grants,
//! revoke chosen ones and the rest, advance a member's epoch with a
//! compare-and-set — and watch the members detach on a membership feed.

use std::time::Duration;

use affinidi_messaging_mediator_admin::{
    ConsoleError, GrantKey, GrantRevokeResult, GrantSelection, Identity, MediatorConsole,
    MembershipEvent, MonitorFilter, MonitorUpdate, revoke_summary,
};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use serde_json::{Value, json};
use tokio::time::timeout;

async fn env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("environment")
}

fn identity(env: &TestEnvironment, user: &TestUser) -> Identity {
    Identity {
        alias: user.alias.clone(),
        did: user.did.clone(),
        secrets: user.secrets.clone(),
        mediator_did: Some(env.mediator.did().to_string()),
    }
}

async fn promote(env: &TestEnvironment, user: &TestUser, role: AccountType) {
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("promote");
}

/// Open `principal`'s mux connection and wait for its `ready`.
async fn open_mux(env: &TestEnvironment, principal: &TestUser) {
    env.atm
        .profile_enable_mux_websocket(&principal.profile)
        .await
        .expect("mux websocket");
    let mut ready = principal.profile.mux_ready().await.expect("ready watch");
    timeout(Duration::from_secs(5), async {
        while ready.borrow().is_none() {
            ready.changed().await.unwrap();
        }
    })
    .await
    .expect("ready within 5s");
}

/// `member` grants `principal` receive and pickup, presented by the
/// principal; returns the grant id.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) -> String {
    let (g, id) = sign_grant(
        &env.atm,
        &member.did,
        &principal.did,
        env.mediator.did(),
        &[MuxCapability::Receive, MuxCapability::Pickup],
        0,
        3600,
    )
    .await
    .expect("sign grant");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&principal.profile, vec![g])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    id
}

/// Membership events from `feed` until `done` holds over them.
async fn membership_until(
    feed: &mut affinidi_messaging_mediator_admin::MonitorFeed,
    done: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let mut seen = Vec::new();
    timeout(Duration::from_secs(10), async {
        while !done(&seen) {
            match feed.next().await.expect("the feed is open") {
                MonitorUpdate::Membership { events, .. } => {
                    seen.extend(
                        events
                            .into_iter()
                            .map(|e: MembershipEvent| serde_json::to_value(e).unwrap()),
                    );
                }
                MonitorUpdate::Ended(reason) => panic!("feed ended: {reason}"),
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("membership events: {seen:#?}"));
    seen
}

fn has(events: &[Value], change: &str, member: &str, reason: &str) -> bool {
    events
        .iter()
        .any(|e| e["change"] == change && e["member"] == member && e["reason"] == reason)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_lists_revokes_and_bumps_an_epoch_and_sees_members_detach() {
    let env = env().await;
    let op = env.add_user("operator").await.expect("operator");
    promote(&env, &op, AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();

    let console = MediatorConsole::connect(identity(&env, &op))
        .await
        .expect("operator connects");
    assert!(console.serves_mux_admin());

    // Traffic quietened to the operator's own account; every membership change.
    let quiet: MonitorFilter = serde_json::from_value(json!({ "dids": [op.did_hash()] })).unwrap();
    let mut feed = console
        .monitor_with(quiet, Some(serde_json::from_value(json!({})).unwrap()))
        .await
        .expect("a membership feed");
    assert!(feed.membership().is_some(), "mux is on: membership is sent");

    open_mux(&env, &device).await;
    let work_on_device = grant(&env, &work, &device).await;
    let home_on_device = grant(&env, &home, &device).await;
    env.atm
        .profile_add(&laptop.profile, true)
        .await
        .expect("laptop websocket");
    grant(&env, &work, &laptop).await;
    let (work_hash, home_hash) = (work.did_hash(), home.did_hash());
    membership_until(&mut feed, |e| {
        has(e, "attached", &work_hash, "grant") && has(e, "attached", &home_hash, "grant")
    })
    .await;

    // By principal: the device's two grants, no epoch (no member named).
    let page = console
        .mux_grants(Some(&device.did), None, None, Some(10))
        .await
        .expect("list by principal");
    assert_eq!(page.grants.len(), 2);
    assert_eq!(page.epoch, None);
    // By member, paged one at a time: work's two grants and its epoch.
    let first = console
        .mux_grants(None, Some(&work.did), None, Some(1))
        .await
        .expect("list by member");
    assert_eq!((first.grants.len(), first.epoch), (1, Some(0)));
    let cursor = first.next_cursor.as_ref().map(|c| c.to_string());
    assert!(cursor.is_some(), "a second page");
    let second = console
        .mux_grants(None, Some(&work.did), cursor, Some(1))
        .await
        .expect("second page");
    assert_eq!(second.grants.len(), 1);
    assert!(second.next_cursor.is_none());
    // Naming neither DID is refused before anything is sent.
    assert!(matches!(
        console.mux_grants(None, None, None, None).await,
        Err(ConsoleError::Invalid(_))
    ));

    // Revoke one chosen grant by member and id: home leaves the device.
    let outcome = console
        .mux_revoke(&GrantSelection::grants(
            &home.did,
            vec![home_on_device.clone()],
        ))
        .await
        .expect("revoke one grant");
    assert!(outcome.is_done(), "{outcome:?}");
    assert_eq!(outcome.revoked.len(), 1);
    assert_eq!(revoke_summary(&outcome), "revoked 1 grant(s); none remain");
    membership_until(&mut feed, |e| has(e, "detached", &home_hash, "admin")).await;

    // Bump work's epoch: read it, then name it.
    let epoch = console.mux_epoch(&work.did).await.expect("work's epoch");
    assert_eq!(epoch, 0);
    // A later epoch than the current is refused, with the current one.
    let mismatch = console
        .mux_bump_epoch(&work.did, epoch + 5)
        .await
        .expect_err("a future epoch");
    assert_eq!(mismatch.current_epoch(), Some(0), "{mismatch}");
    assert!(mismatch.explain().contains("current epoch is 0"));

    let bumped = console
        .mux_bump_epoch(&work.did, epoch)
        .await
        .expect("advance the epoch");
    assert!(bumped.epoch_advanced);
    assert_eq!((bumped.epoch, bumped.revoked_grants), (1, 2));
    membership_until(&mut feed, |e| has(e, "detached", &work_hash, "admin")).await;
    // Naming the voided epoch again changes nothing.
    let again = console
        .mux_bump_epoch(&work.did, epoch)
        .await
        .expect("the same epoch again");
    assert!(!again.epoch_advanced);
    assert_eq!(console.mux_epoch(&work.did).await.unwrap(), 1);

    // Voided grants stay listed; revoking the principal's removes them all.
    let listed = console
        .mux_grants(None, Some(&work.did), None, None)
        .await
        .unwrap();
    assert!(
        listed
            .grants
            .iter()
            .all(|g| g.state.to_string() == "epochRevoked"),
        "{listed:?}"
    );
    let outcome = console
        .mux_revoke(&GrantSelection::principal(&device.did))
        .await
        .expect("revoke by principal");
    assert!(outcome.is_done());
    assert_eq!(outcome.revoked.len(), 1);
    assert_eq!(outcome.revoked[0].grant_id.to_string(), work_on_device);
    let left = console
        .mux_grants(Some(&device.did), None, None, None)
        .await
        .unwrap();
    assert!(left.grants.is_empty(), "{left:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_standard_account_cannot_administer_grants_and_a_root_admin_s_are_protected() {
    let env = env().await;
    let root = env.add_user("root").await.unwrap();
    promote(&env, &root, AccountType::RootAdmin).await;
    let op = env.add_user("operator").await.unwrap();
    promote(&env, &op, AccountType::Admin).await;
    let someone = env.add_user("someone").await.unwrap();

    let console = MediatorConsole::connect(identity(&env, &someone))
        .await
        .expect("someone connects");
    assert!(matches!(
        console.mux_grants(Some(&root.did), None, None, None).await,
        Err(ConsoleError::NotPermitted(_))
    ));

    let console = MediatorConsole::connect(identity(&env, &op))
        .await
        .expect("operator connects");
    let epoch = console.mux_epoch(&root.did).await.expect("root's epoch");
    let refused = console
        .mux_bump_epoch(&root.did, epoch)
        .await
        .expect_err("a rootAdmin is protected");
    assert!(
        refused
            .refusal_code()
            .is_some_and(|c| c.ends_with(":protectedAccount")),
        "{refused}"
    );
    assert!(refused.explain().contains("only a rootAdmin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bulk_revocation_reports_each_grant_and_a_protected_one_does_not_stop_the_rest() {
    let env = env().await;
    let root = env.add_user("root").await.unwrap();
    promote(&env, &root, AccountType::RootAdmin).await;
    let op = env.add_user("operator").await.unwrap();
    promote(&env, &op, AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    for principal in [&device, &root] {
        env.atm
            .profile_add(&principal.profile, true)
            .await
            .expect("principal websocket");
    }
    let work_on_device = grant(&env, &work, &device).await;
    let home_on_device = grant(&env, &home, &device).await;
    // The principal is a rootAdmin: only a rootAdmin may revoke this one.
    let home_on_root = grant(&env, &home, &root).await;
    // Signed but never stored.
    let (_, never_stored) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        env.mediator.did(),
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .unwrap();

    let console = MediatorConsole::connect(identity(&env, &op))
        .await
        .expect("operator connects");
    let asked = [
        GrantKey::new(&work.did, &work_on_device),
        GrantKey::new(&home.did, &home_on_root),
        GrantKey::new(&work.did, &never_stored),
        GrantKey::new(&home.did, &home_on_device),
    ];
    let outcome = console.mux_revoke_each(&asked).await.expect("bulk revoke");
    let results: Vec<_> = outcome
        .results
        .iter()
        .map(|(k, r)| (k.clone(), r))
        .collect();
    assert_eq!(
        results.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        asked,
        "every grant reported, in order"
    );
    assert!(results[0].1.is_revoked(), "{outcome:?}");
    assert!(
        matches!(results[1].1, GrantRevokeResult::Refused(e)
            if e.refusal_code().is_some_and(|c| c.ends_with(":protectedAccount"))),
        "{outcome:?}"
    );
    assert!(
        matches!(results[2].1, GrantRevokeResult::NotStored),
        "{outcome:?}"
    );
    assert!(
        results[3].1.is_revoked(),
        "the refusal did not stop the rest"
    );
    assert_eq!(
        outcome.summary(),
        "revoked 2 of 4 grant(s); 1 no longer stored, 1 refused"
    );
    assert!(outcome.failures()[0].contains("only a rootAdmin"));

    // The mediator agrees: the device's grants are gone, the root's stays.
    let device_left = console
        .mux_grants(Some(&device.did), None, None, None)
        .await
        .unwrap();
    assert!(device_left.grants.is_empty(), "{device_left:?}");
    let root_left = console
        .mux_grants(Some(&root.did), None, None, None)
        .await
        .unwrap();
    assert_eq!(root_left.grants.len(), 1, "{root_left:?}");
}
