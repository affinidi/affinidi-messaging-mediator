//! Durable mux notices (`messaging/mux/notice/0.1`) end to end: what the
//! mediator stores in a principal's or member DID's inbox when grants are
//! suspended or revoked, or when a member DID authenticates directly while
//! grants on it exist; and the `ready` event's `pendingNotices` count.
//!
//! Grants go through the `messaging/mux/grant` Trust Task (the SDK's
//! `mux_grant`), because that is where notices are produced. Inboxes are read
//! from the store and unpacked as the recipient, so each assertion is about
//! what the recipient would receive.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_sdk::messages::Folder;
use affinidi_messaging_sdk::protocols::mux::sign_revoke_all;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

/// A grant from `member` to `principal`, signed with the member's `key`
/// (`"key-1"`, `"key-2"`, …).
async fn signed_grant(
    env: &TestEnvironment,
    member: &TestUser,
    key: &str,
    principal: &TestUser,
) -> Value {
    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with(&format!("#{key}")))
        .unwrap_or_else(|| panic!("member has no {key}"));
    let t = now();
    sign_trust_task(
        &json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(),
            "principal": principal.did,
            "scope": ["receive", "pickup", "delete"],
            "epoch": 0,
            "iat": t,
            "exp": t + 3600,
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign grant")
}

/// Open `user`'s websocket: the SDK takes Trust Task responses on it.
async fn online(env: &TestEnvironment, user: &TestUser) {
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("enable websocket");
}

/// The principal presents `statement` (a grant naming it) with the
/// `messaging/mux/grant` task; it must be stored.
async fn present(env: &TestEnvironment, principal: &TestUser, statement: Value) {
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&principal.profile, vec![statement])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
}

/// Every mux notice in `user`'s inbox, as the signed Trust Task documents the
/// user unpacks. Each must parse as the spec's generated notice type.
async fn notices(env: &TestEnvironment, user: &TestUser) -> Vec<Value> {
    use affinidi_messaging_mediator::task_specs::messaging::mux::notice::v0_1::Payload;
    let store = env.mediator.store();
    let hash = user.did_hash();
    let list = store
        .list_messages(&hash, Folder::Inbox, None, 100)
        .await
        .expect("list inbox");
    let mut out = Vec::new();
    for m in list {
        let Some(full) = store.get_message(&hash, &m.msg_id).await.unwrap() else {
            continue;
        };
        let (msg, meta) = env
            .atm
            .unpack(full.msg.as_deref().expect("stored body"))
            .await
            .expect("unpack as the recipient");
        if msg.body["type"] != NOTICE_TYPE {
            continue;
        }
        assert!(
            meta.authenticated,
            "a notice is authcrypted by the mediator"
        );
        assert_eq!(msg.from.as_deref(), Some(env.mediator.did()));
        assert_eq!(msg.body["issuer"], env.mediator.did());
        assert_eq!(msg.body["recipient"], user.did);
        assert!(
            msg.body["proof"].is_object(),
            "a notice is signed: {:#}",
            msg.body
        );
        serde_json::from_value::<trust_tasks_rs::TrustTask<Payload>>(msg.body.clone())
            .unwrap_or_else(|e| panic!("notice does not match the spec: {e}\n{:#}", msg.body));
        out.push(msg.body);
    }
    out
}

/// Wait (briefly) for `user` to have `n` notices: a direct authentication
/// stores its `grantsPresent` in the background.
async fn wait_for_notices(env: &TestEnvironment, user: &TestUser, n: usize) -> Vec<Value> {
    timeout(Duration::from_secs(5), async {
        loop {
            let got = notices(env, user).await;
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} notices for {}", n, user.alias))
}

/// Open a raw mux socket as `principal` and return its `ready` payload.
async fn ready(env: &TestEnvironment, principal: &TestUser) -> Value {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(
            principal.did.clone(),
            env.mediator.did().to_string(),
            3,
            None,
        )
        .await
        .expect("authenticate principal");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.expect("upgrade");
    loop {
        let frame = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5s")
            .expect("socket open")
            .expect("frame");
        if let Message::Text(t) = frame {
            let (msg, _) = env.atm.unpack(&t).await.expect("unpack event");
            if msg.body["payload"]["event"] == "ready" {
                return msg.body["payload"].clone();
            }
        }
    }
}

#[tokio::test]
async fn a_new_key_suspends_grants_and_tells_both_sides_durably() {
    init_tracing();
    let env = env().await;
    let member = env.add_multi_key_user("work", 2).await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    for u in [&phone, &laptop] {
        online(&env, u).await;
    }

    // The phone holds a grant signed with key-1. Nothing is owed yet.
    let first = signed_grant(&env, &member, "key-1", &phone).await;
    let first_id = first["grantId"].as_str().unwrap().to_string();
    present(&env, &phone, first).await;
    assert!(notices(&env, &phone).await.is_empty());

    // A grant signed with key-2, which signed no active grant, suspends the
    // phone's grant (the unknown-key rule) and is itself stored active.
    present(
        &env,
        &laptop,
        signed_grant(&env, &member, "key-2", &laptop).await,
    )
    .await;

    // The phone, offline throughout, has a durable notice to recreate.
    let phone_notices = notices(&env, &phone).await;
    assert_eq!(phone_notices.len(), 1, "{phone_notices:#?}");
    let p = &phone_notices[0]["payload"];
    assert_eq!(p["notice"], "grantsSuspended");
    assert_eq!(p["suspensions"][0]["did"], member.did);
    assert_eq!(p["suspensions"][0]["grantIds"], json!([first_id]));
    assert_eq!(p["suspensions"][0]["reason"], "suspendedUnknownKey");

    // The laptop's own grant was not suspended: it is told nothing.
    assert!(notices(&env, &laptop).await.is_empty());

    // The member DID learns delegations of it exist: counts only, never a
    // principal DID.
    let member_notices = notices(&env, &member).await;
    assert_eq!(member_notices.len(), 1, "{member_notices:#?}");
    assert_eq!(
        member_notices[0]["payload"],
        json!({ "notice": "grantsPresent", "did": member.did, "count": 2, "suspended": 1, "epoch": 0 })
    );

    // When the phone connects, `ready` says a notice waits.
    assert_eq!(ready(&env, &phone).await["pendingNotices"], 1);
}

#[tokio::test]
async fn revocations_tell_the_other_side_only() {
    init_tracing();
    let env = env().await;
    let member = env.add_user("work").await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let tablet = env.add_user("tablet").await.unwrap();
    for u in [&member, &phone, &laptop, &tablet] {
        online(&env, u).await;
    }
    for p in [&phone, &laptop] {
        present(&env, p, signed_grant(&env, &member, "key-1", p).await).await;
    }

    // The laptop revokes its own grant: it is not sent a notice.
    env.atm
        .trust_tasks()
        .mux_revoke(&laptop.profile, false, vec![], vec![member.did.clone()])
        .await
        .expect("principal revoke");
    assert!(notices(&env, &laptop).await.is_empty());

    // The member revokes the phone's grant: the phone is told.
    env.atm
        .trust_tasks()
        .mux_revoke(&member.profile, true, vec![], vec![phone.did.clone()])
        .await
        .expect("member revoke");
    let got = notices(&env, &phone).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0]["payload"]["notice"], "grantsRevoked");
    assert_eq!(got[0]["payload"]["revocations"][0]["did"], member.did);
    assert_eq!(
        got[0]["payload"]["revocations"][0]["reason"],
        "revokedByMember"
    );

    // revoke-all advances the epoch: the tablet's grant is voided and the
    // tablet is told.
    present(
        &env,
        &tablet,
        signed_grant(&env, &member, "key-1", &tablet).await,
    )
    .await;
    let st = sign_revoke_all(&env.atm, &member.did, env.mediator.did(), 0)
        .await
        .expect("sign revoke-all");
    env.atm
        .trust_tasks()
        .mux_revoke_all(&member.profile, st)
        .await
        .expect("revoke-all");
    let got = notices(&env, &tablet).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0]["payload"]["revocations"][0]["reason"], "epochBumped");
    assert_eq!(ready(&env, &tablet).await["pendingNotices"], 1);
}

#[tokio::test]
async fn direct_authentication_tells_the_member_once_per_change() {
    init_tracing();
    let env = env().await;
    let member = env.add_user("work").await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    online(&env, &phone).await;

    // The phone presents the member's grant; the member has not
    // authenticated since it existed.
    present(
        &env,
        &phone,
        signed_grant(&env, &member, "key-1", &phone).await,
    )
    .await;
    assert!(notices(&env, &member).await.is_empty());

    // A real DID Auth handshake each time, not the SDK's cached tokens.
    let auth = || async {
        let auth = env.tdk.authentication();
        auth.invalidate(member.did.clone(), env.mediator.did().to_string())
            .await;
        auth.authenticate(member.did.clone(), env.mediator.did().to_string(), 3, None)
            .await
            .expect("authenticate member");
    };

    auth().await;
    let got = wait_for_notices(&env, &member, 1).await;
    assert_eq!(
        got[0]["payload"],
        json!({ "notice": "grantsPresent", "did": member.did, "count": 1, "suspended": 0, "epoch": 0 })
    );

    // Nothing changed: authenticating again stores nothing new.
    auth().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(notices(&env, &member).await.len(), 1);

    // A second grant changes the set: the next authentication tells it again.
    let laptop = env.add_user("laptop").await.unwrap();
    online(&env, &laptop).await;
    present(
        &env,
        &laptop,
        signed_grant(&env, &member, "key-1", &laptop).await,
    )
    .await;
    auth().await;
    let got = wait_for_notices(&env, &member, 2).await;
    assert!(got.iter().any(|n| n["payload"]["count"] == 2), "{got:#?}");
}

#[tokio::test]
async fn removing_a_member_account_tells_its_principals() {
    init_tracing();
    let env = env().await;
    let member = env.add_user("work").await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    for u in [&member, &phone] {
        online(&env, u).await;
    }
    present(
        &env,
        &phone,
        signed_grant(&env, &member, "key-1", &phone).await,
    )
    .await;

    let removed = env
        .atm
        .trust_tasks()
        .account_remove(&member.profile, None)
        .await
        .expect("member removes its own account");
    assert!(removed);

    let got = notices(&env, &phone).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0]["payload"]["notice"], "grantsRevoked");
    assert_eq!(got[0]["payload"]["revocations"][0]["did"], member.did);
    assert_eq!(
        got[0]["payload"]["revocations"][0]["reason"],
        "accountRemoved"
    );
}

#[tokio::test]
async fn a_notice_lost_to_a_crash_is_sent_when_the_principal_connects() {
    use affinidi_messaging_mediator_common::store::mux::{self, MuxGrantState, MuxLimits};
    init_tracing();
    let env = env().await;
    let member = env.add_user("work").await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    online(&env, &phone).await;
    present(
        &env,
        &phone,
        signed_grant(&env, &member, "key-1", &phone).await,
    )
    .await;

    // The grant is suspended and the process dies before its notice is
    // stored: the record says suspended, and nothing is in the inbox.
    let store = env.mediator.store();
    mux::modify(
        &*store,
        &member.did_hash(),
        &MuxLimits::default(),
        now(),
        None,
        |rec, _| {
            for g in rec.grants.iter_mut() {
                g.state = MuxGrantState::Suspended;
                g.state_changed_at = Some(now());
            }
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(notices(&env, &phone).await.is_empty());

    // On connect the owed notice is stored before `ready` counts it.
    assert_eq!(ready(&env, &phone).await["pendingNotices"], 1);
    let got = notices(&env, &phone).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0]["payload"]["notice"], "grantsSuspended");

    // And only once: a second connect finds nothing more owed.
    assert_eq!(ready(&env, &phone).await["pendingNotices"], 1);
    assert_eq!(notices(&env, &phone).await.len(), 1);
}
