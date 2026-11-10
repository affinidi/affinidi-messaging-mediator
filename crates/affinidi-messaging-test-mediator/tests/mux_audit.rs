//! The audit records DID multiplexing owes (specs `messaging/mux/revoke`
//! rule 7, `revoke-all`, and the unknown-key rule): a revocation, an
//! advanced epoch, and a grant suspended by a statement signed with a key
//! the member's grants did not list.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    types::audit::{AuditAction, AuditLogEntry},
};
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant, sign_revoke_all};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

async fn audit(env: &TestEnvironment, action: AuditAction) -> Vec<AuditLogEntry> {
    let page = env
        .mediator
        .store()
        .audit_log_list(0, 1000)
        .await
        .expect("audit log");
    page.entries
        .into_iter()
        .filter(|e| e.action == action)
        .collect()
}

/// `member` grants `principal`, presented by the member; returns the grant id.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) -> String {
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &principal.did,
        env.mediator.did(),
        &[MuxCapability::Receive],
        0,
        3600,
    )
    .await
    .expect("sign grant");
    present(env, member, g).await
}

async fn present(env: &TestEnvironment, presenter: &TestUser, statement: Value) -> String {
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&presenter.profile, vec![statement])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    r["results"][0]["grantId"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn revocations_epochs_and_suspensions_are_audited() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_multi_key_user("home", 2).await.unwrap();
    let tablet = env.add_user("tablet").await.unwrap();
    for u in [&phone, &laptop, &work, &home, &tablet] {
        env.atm.profile_add(&u.profile, true).await.unwrap();
    }

    // A member revokes its grant: the member is the actor, the principal
    // the target.
    let id = grant(&env, &work, &phone).await;
    env.atm
        .trust_tasks()
        .mux_revoke(&work.profile, true, vec![id.clone()], vec![])
        .await
        .expect("revoke");
    let revoked = audit(&env, AuditAction::MuxGrantRevoke).await;
    assert_eq!(revoked.len(), 1, "{revoked:#?}");
    assert_eq!(revoked[0].actor_did_hash, did_hash(&work.did));
    assert_eq!(revoked[0].target_did_hash, did_hash(&phone.did));
    assert!(revoked[0].detail.contains(&id), "{}", revoked[0].detail);

    // A principal revokes: the principal is the actor, the member the target.
    grant(&env, &home, &phone).await;
    env.atm
        .trust_tasks()
        .mux_revoke(&phone.profile, false, vec![], vec![home.did.clone()])
        .await
        .expect("revoke as principal");
    let revoked = audit(&env, AuditAction::MuxGrantRevoke).await;
    assert_eq!(revoked.len(), 2, "{revoked:#?}");
    let by_phone = revoked
        .iter()
        .find(|e| e.actor_did_hash == did_hash(&phone.did))
        .expect("the principal's revocation");
    assert_eq!(by_phone.target_did_hash, did_hash(&home.did));

    // revoke-all advancing the epoch: one entry, targeting the member.
    grant(&env, &work, &laptop).await;
    let st = sign_revoke_all(&env.atm, &work.did, env.mediator.did(), 0)
        .await
        .unwrap();
    env.atm
        .trust_tasks()
        .mux_revoke_all(&work.profile, st)
        .await
        .expect("revoke-all");
    let all = audit(&env, AuditAction::MuxRevokeAll).await;
    assert_eq!(all.len(), 1, "{all:#?}");
    assert_eq!(all[0].target_did_hash, did_hash(&work.did));
    assert!(
        all[0].detail.contains("1 grants voided"),
        "{}",
        all[0].detail
    );

    // A grant signed with the member's second key suspends the tablet's
    // grant, signed with the first: the member is the actor, the tablet the
    // target. (A fresh principal: home's grant to the phone was revoked
    // this second, so the phone's replay floor would refuse a new one.)
    let key1 = home
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .unwrap();
    let key2 = home
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-2"))
        .unwrap();
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = |principal: &str| {
        json!({
            "type": "muxGrant", "issuer": home.did, "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(), "principal": principal,
            "scope": ["receive"], "epoch": 0, "iat": t, "exp": t + 3600,
        })
    };
    let g1 = sign_trust_task(&body(&tablet.did), key1, SignOptions::new())
        .await
        .unwrap();
    let tablet_grant = present(&env, &tablet, g1).await;
    let g2 = sign_trust_task(&body(&laptop.did), key2, SignOptions::new())
        .await
        .unwrap();
    present(&env, &laptop, g2).await;
    let suspended = audit(&env, AuditAction::MuxGrantSuspend).await;
    assert_eq!(suspended.len(), 1, "{suspended:#?}");
    assert_eq!(suspended[0].actor_did_hash, did_hash(&home.did));
    assert_eq!(suspended[0].target_did_hash, did_hash(&tablet.did));
    assert!(
        suspended[0].detail.contains(&tablet_grant),
        "{}",
        suspended[0].detail
    );
}
