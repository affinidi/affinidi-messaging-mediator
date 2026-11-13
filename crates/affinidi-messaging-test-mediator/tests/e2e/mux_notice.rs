//! Durable mux notices (`messaging/mux/notice/0.1`) end to end: what the
//! mediator stores in a principal's or member DID's inbox when grants are
//! suspended or revoked, or when a member DID authenticates directly while
//! grants on it exist; and the `ready` event's `pendingNotices` count.
//!
//! Grants go through the `messaging/mux/grant` Trust Task (the SDK's
//! `mux_grant`), because that is where notices are produced. Inboxes are read
//! from the store and unpacked as the recipient, so each assertion is about
//! what the recipient would receive.

use crate::common;
use crate::common::now;

use std::time::Duration;

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
    let t = now();
    signed_grant_for(env, member, key, principal, t, t + 3600).await
}

/// As [`signed_grant`], with an explicit `iat` and `exp`.
async fn signed_grant_for(
    env: &TestEnvironment,
    member: &TestUser,
    key: &str,
    principal: &TestUser,
    iat: u64,
    exp: u64,
) -> Value {
    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with(&format!("#{key}")))
        .unwrap_or_else(|| panic!("member has no {key}"));
    sign_trust_task(
        &json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(),
            "principal": principal.did,
            "scope": ["receive", "pickup", "delete"],
            "epoch": 0,
            "iat": iat,
            "exp": exp,
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
    // The member logged in with a key-agreement key its DID listed when it
    // granted: known, so the phone's grant was not suspended.
    assert!(notices(&env, &phone).await.is_empty());

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

/// The authenticate-as-`user` handshake, fresh rather than the SDK's cached
/// tokens.
async fn fresh_login(env: &TestEnvironment, user: &TestUser) {
    let auth = env.tdk.authentication();
    auth.invalidate(user.did.clone(), env.mediator.did().to_string())
        .await;
    auth.authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
}

#[tokio::test]
async fn a_login_with_a_key_agreement_key_added_since_the_grant_suspends_it() {
    use affinidi_messaging_mediator_common::store::mux::{self, MuxLimits};
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

    // The grant recorded the member's key-agreement key. A did:peer document
    // cannot change, so stand in for "a key added since" by making the
    // recorded set name a different key.
    let store = env.mediator.store();
    let rec = mux::load(&*store, &member.did_hash(), &MuxLimits::default(), now())
        .await
        .unwrap();
    assert_eq!(
        rec.grants[0].key_agreement_fps.len(),
        1,
        "recorded at grant time"
    );
    mux::modify(
        &*store,
        &member.did_hash(),
        &MuxLimits::default(),
        now(),
        None,
        |rec, _| {
            rec.grants[0].key_agreement_fps = vec!["a-key-the-member-did-not-list".into()];
            Ok(())
        },
    )
    .await
    .unwrap();

    fresh_login(&env, &member).await;

    // Committed before the login answered, not in the background.
    let rec = mux::load(&*store, &member.did_hash(), &MuxLimits::default(), now())
        .await
        .unwrap();
    assert_eq!(
        rec.grants[0].state,
        mux::MuxGrantState::Suspended,
        "suspended by the time the login succeeds"
    );
    // Audited before the login answered too: the member's key fired it, the
    // phone lost the grant.
    let audit = store.audit_log_list(0, 100).await.unwrap();
    let entry = audit
        .entries
        .iter()
        .find(|e| {
            e.action
                == affinidi_messaging_mediator_common::types::audit::AuditAction::MuxGrantSuspend
        })
        .expect("a mux_grant_suspend audit entry");
    assert_eq!(entry.actor_did_hash, member.did_hash());
    assert_eq!(entry.target_did_hash, phone.did_hash());
    assert!(
        entry.detail.contains("direct DIDComm authentication"),
        "{}",
        entry.detail
    );

    let got = wait_for_notices(&env, &phone, 1).await;
    assert_eq!(got[0]["payload"]["notice"], "grantsSuspended");
    assert_eq!(
        got[0]["payload"]["suspensions"][0]["reason"],
        "suspendedUnknownKey"
    );
    let got = wait_for_notices(&env, &member, 1).await;
    assert_eq!(got[0]["payload"]["notice"], "grantsPresent");
    assert_eq!(got[0]["payload"]["suspended"], 1);
}

#[tokio::test]
async fn a_grant_past_three_quarters_of_its_life_is_announced_once() {
    init_tracing();
    let env = env().await;
    let member = env.add_user("work").await.unwrap();
    let phone = env.add_user("phone").await.unwrap();
    online(&env, &phone).await;

    // An hour-long grant, 50 minutes in: past three quarters.
    let t = now();
    let st = signed_grant_for(&env, &member, "key-1", &phone, t - 3000, t + 600).await;
    let grant_id = st["grantId"].as_str().unwrap().to_string();
    present(&env, &phone, st).await;
    assert!(
        notices(&env, &phone).await.is_empty(),
        "not until a check runs"
    );

    // Connecting is a check.
    assert_eq!(ready(&env, &phone).await["pendingNotices"], 1);
    let got = notices(&env, &phone).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    let p = &got[0]["payload"];
    assert_eq!(p["notice"], "grantsExpiring");
    assert_eq!(p["expiring"][0]["grantId"], grant_id);
    assert_eq!(p["expiring"][0]["did"], member.did);

    // Once per grant: another connect and a login add nothing.
    ready(&env, &phone).await;
    fresh_login(&env, &phone).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(notices(&env, &phone).await.len(), 1);

    // A renewal is a new grant with its own lifetime: nothing is owed.
    // The member presents it: the raw sockets above displaced the phone's SDK
    // socket.
    online(&env, &member).await;
    present(
        &env,
        &member,
        signed_grant(&env, &member, "key-1", &phone).await,
    )
    .await;
    ready(&env, &phone).await;
    assert_eq!(notices(&env, &phone).await.len(), 1);
}

// ─── Direct TSP login ───────────────────────────────────────────────────────

/// The unknown-key rule and `grantsPresent` on the other direct login: a
/// pure-TSP `POST /tsp/authenticate`, which proves the VID's signing key (its
/// first Ed25519 `authentication` key) rather than a key-agreement key. The
/// rule compares that key with the keys that signed the member's active
/// grants, and the member's `grantsPresent` is sealed for TSP, the wire it
/// logged in on.
#[cfg(feature = "tsp")]
mod tsp_login {
    use super::*;
    use affinidi_messaging_mediator_common::store::mux::{self, MuxGrantState, MuxLimits};
    use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    /// A real `/tsp/authenticate` handshake as `user`: a statement carrying the
    /// challenge and naming this mediator, signed with `#key-1`, the key the
    /// mediator resolves as the VID's signing key.
    async fn tsp_login(env: &TestEnvironment, user: &TestUser) {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let post = async |path: &str, body: Value| {
            let resp = http
                .post(format!("{}{path}", env.mediator.endpoint()))
                .json(&body)
                .send()
                .await
                .expect("request");
            let status = resp.status().as_u16();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            assert_eq!(status, 200, "{path}: {body:#}");
            body
        };
        let challenge = post("authenticate/challenge", json!({ "did": user.did })).await;
        let key: [u8; 32] = user
            .secrets
            .iter()
            .find(|s| s.id.ends_with("#key-1"))
            .expect("the VID's signing key")
            .get_private_bytes()
            .try_into()
            .unwrap();
        // The statement names this mediator, the session and an expiry.
        let mediator = env.mediator.did().to_string();
        let session_id = challenge["data"]["session_id"].as_str().unwrap();
        let created_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_time = created_time + 60;
        let statement =
            affinidi_messaging_mediator::handlers::authenticate::tsp::signed_statement_bytes(
                challenge["data"]["challenge"].as_str().unwrap(),
                session_id,
                &user.did,
                &mediator,
                created_time,
                expires_time,
            );
        let signature = affinidi_tsp::crypto::signing::sign(&statement, &key).unwrap();
        post(
            "tsp/authenticate",
            json!({
                "vid": user.did,
                "session_id": session_id,
                "signature": BASE64_URL_SAFE_NO_PAD.encode(signature),
                "to": mediator,
                "created_time": created_time,
                "expires_time": expires_time,
            }),
        )
        .await;
    }

    /// The relationship a TSP client holds with its mediator, seeded so the
    /// SDK opens the mediator's Direct messages to `user`.
    async fn relate_to_mediator(env: &TestEnvironment, user: &TestUser) {
        let mediator = env.mediator.did().to_string();
        for (ours, theirs) in [(&user.did, &mediator), (&mediator, &user.did)] {
            env.relationship_store
                .set(ours, theirs, RelationshipState::Bidirectional)
                .await
                .expect("seed the relationship with the mediator");
        }
    }

    /// Every mux notice in `user`'s inbox sealed for TSP (a Direct message
    /// from the mediator's VID), opened as `user`. Each must parse as the
    /// spec's notice type. DIDComm messages are skipped, not failed.
    async fn tsp_notices(env: &TestEnvironment, user: &TestUser) -> Vec<Value> {
        use affinidi_messaging_mediator::task_specs::messaging::mux::notice::v0_1::Payload;
        let store = env.mediator.store();
        let hash = user.did_hash();
        let mut out = Vec::new();
        for m in store
            .list_messages(&hash, Folder::Inbox, None, 100)
            .await
            .expect("list inbox")
        {
            let Some(full) = store.get_message(&hash, &m.msg_id).await.unwrap() else {
                continue;
            };
            let Some(qb2) = full
                .msg
                .as_deref()
                .and_then(|b| BASE64_URL_SAFE_NO_PAD.decode(b).ok())
                .filter(|b| affinidi_tsp::is_tsp(b))
            else {
                continue;
            };
            let (payload, sender) = env
                .atm
                .tsp()
                .unpack_bytes(&user.profile, &qb2)
                .await
                .expect("open as the recipient");
            assert_eq!(sender, env.mediator.did(), "sealed by the mediator");
            let doc: Value = serde_json::from_slice(&payload).expect("a JSON document");
            if doc["type"] != NOTICE_TYPE {
                continue;
            }
            assert_eq!(doc["issuer"], env.mediator.did());
            assert_eq!(doc["recipient"], user.did);
            assert!(doc["proof"].is_object(), "a notice is signed: {doc:#}");
            serde_json::from_value::<trust_tasks_rs::TrustTask<Payload>>(doc.clone())
                .unwrap_or_else(|e| panic!("notice does not match the spec: {e}\n{doc:#}"));
            out.push(doc);
        }
        out
    }

    async fn wait_for_tsp_notices(env: &TestEnvironment, user: &TestUser, n: usize) -> Vec<Value> {
        timeout(Duration::from_secs(5), async {
            loop {
                let got = tsp_notices(env, user).await;
                if got.len() >= n {
                    return got;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{} TSP notices for {}", n, user.alias))
    }

    async fn grant_states(env: &TestEnvironment, member: &TestUser) -> Vec<MuxGrantState> {
        mux::load(
            &*env.mediator.store(),
            &member.did_hash(),
            &MuxLimits::default(),
            now(),
        )
        .await
        .unwrap()
        .grants
        .iter()
        .map(|g| g.state)
        .collect()
    }

    /// Mirrors `a_login_with_a_key_agreement_key_added_since_the_grant_suspends_it`
    /// for TSP: the grant was signed with `key-2`; the TSP login proves
    /// `key-1`, which signed no active grant, so the grant is suspended before
    /// the login answers. The principal gets `grantsSuspended`, the member a
    /// `grantsPresent` sealed for TSP.
    #[tokio::test]
    async fn a_tsp_login_with_a_key_that_signed_no_grant_suspends_it() {
        init_tracing();
        let env = env().await;
        let member = env.add_multi_key_user("work", 2).await.unwrap();
        let phone = env.add_user("phone").await.unwrap();
        online(&env, &phone).await;
        relate_to_mediator(&env, &member).await;

        let statement = signed_grant(&env, &member, "key-2", &phone).await;
        let grant_id = statement["grantId"].as_str().unwrap().to_string();
        present(&env, &phone, statement).await;
        assert_eq!(grant_states(&env, &member).await, [MuxGrantState::Active]);

        tsp_login(&env, &member).await;

        // Committed and audited before the login answered.
        assert_eq!(
            grant_states(&env, &member).await,
            [MuxGrantState::Suspended],
            "suspended by the time the TSP login succeeds"
        );
        let audit = env.mediator.store().audit_log_list(0, 100).await.unwrap();
        let entry = audit
            .entries
            .iter()
            .find(|e| {
                e.action
                    == affinidi_messaging_mediator_common::types::audit::AuditAction::MuxGrantSuspend
            })
            .expect("a mux_grant_suspend audit entry");
        assert_eq!(entry.actor_did_hash, member.did_hash());
        assert_eq!(entry.target_did_hash, phone.did_hash());
        assert!(
            entry.detail.contains("direct TSP authentication"),
            "{}",
            entry.detail
        );

        // The principal, offline throughout, has the durable notice to
        // recreate the grant.
        let got = wait_for_notices(&env, &phone, 1).await;
        assert_eq!(got.len(), 1, "{got:#?}");
        let p = &got[0]["payload"];
        assert_eq!(p["notice"], "grantsSuspended");
        assert_eq!(p["suspensions"][0]["did"], member.did);
        assert_eq!(p["suspensions"][0]["grantIds"], json!([grant_id]));
        assert_eq!(p["suspensions"][0]["reason"], "suspendedUnknownKey");

        // The member learns delegations of it existed, sealed for TSP.
        let got = wait_for_tsp_notices(&env, &member, 1).await;
        assert_eq!(got.len(), 1, "{got:#?}");
        assert_eq!(
            got[0]["payload"],
            json!({ "notice": "grantsPresent", "did": member.did, "count": 1, "suspended": 1, "epoch": 0 })
        );
    }

    /// Mirrors `direct_authentication_tells_the_member_once_per_change` for
    /// TSP: a login with the key that signed the grant suspends nothing, and
    /// the member is told once, sealed for TSP, that delegations of it exist.
    #[tokio::test]
    async fn a_tsp_login_tells_the_member_its_grants_exist() {
        init_tracing();
        let env = env().await;
        let member = env.add_user("work").await.unwrap();
        let phone = env.add_user("phone").await.unwrap();
        online(&env, &phone).await;
        relate_to_mediator(&env, &member).await;
        present(
            &env,
            &phone,
            signed_grant(&env, &member, "key-1", &phone).await,
        )
        .await;
        assert!(tsp_notices(&env, &member).await.is_empty());

        tsp_login(&env, &member).await;
        let got = wait_for_tsp_notices(&env, &member, 1).await;
        assert_eq!(
            got[0]["payload"],
            json!({ "notice": "grantsPresent", "did": member.did, "count": 1, "suspended": 0, "epoch": 0 })
        );
        // The key that signed the grant is known: nothing suspended, and the
        // phone is told nothing.
        assert_eq!(grant_states(&env, &member).await, [MuxGrantState::Active]);
        assert!(notices(&env, &phone).await.is_empty());

        // Nothing changed: logging in again stores nothing new.
        tsp_login(&env, &member).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(tsp_notices(&env, &member).await.len(), 1);
    }
}
