//! The administrator's stored-grant tasks, end to end:
//! `messaging/mux/admin-list`, `admin-revoke` and `admin-revoke-all` (specs
//! 0.1, design §7.8).
//!
//! The SDK does not send these tasks yet, so each is built by hand, signed
//! with the requester's Ed25519 key and sent over DIDComm, against a mediator
//! that enforces Trust Task proofs. Grants go through `messaging/mux/grant`
//! and live members through the SDK's mux connection, so a revocation is
//! seen the way a principal sees it: a `detached` event and a durable
//! `grantsRevoked` notice, both with reason `admin`.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator::task_specs::messaging::mux as spec;
use affinidi_messaging_mediator_common::{
    did_identity::did_hash,
    types::{
        accounts::AccountType,
        audit::{AuditAction, AuditLogEntry},
    },
};
use affinidi_messaging_sdk::messages::Folder;
use affinidi_messaging_sdk::protocols::mux::{MuxCapability, MuxMembers, sign_attach, sign_grant};
use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
use affinidi_messaging_sdk::transports::SendMessageResponse;
use affinidi_messaging_test_mediator::{
    TestEnvironment, TestMediator, TestUser, TrustTaskVerification,
};
use affinidi_secrets_resolver::secrets::KeyType;
use common::init_tracing;
use serde_json::{Value, json};
use tokio::time::timeout;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

const LIST: &str = "https://trusttasks.org/spec/messaging/mux/admin-list/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/messaging/mux/admin-revoke/0.1";
const REVOKE_ALL: &str = "https://trusttasks.org/spec/messaging/mux/admin-revoke-all/0.1";
const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

async fn env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .trust_task_verification(TrustTaskVerification::Enforce)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

/// A user with `role`, online (Trust Task answers come back on its socket).
async fn with_role(env: &TestEnvironment, alias: &str, role: AccountType) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("set role");
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("websocket");
    user
}

/// A refusal: the problem report's body, as text, so a test can look for
/// the code in it.
#[derive(Debug)]
struct Refused(String);

impl Refused {
    fn has(&self, code: &str) -> bool {
        self.0.contains(code)
    }
}

/// Checks a response payload against the spec's generated `Response` type.
type Conforms = fn(Value) -> Result<(), serde_json::Error>;

/// Send one signed Trust Task as `from` and return the response payload, or
/// the refusal. A response must be the task's `#response` and pass
/// `conforms`.
async fn task(
    env: &TestEnvironment,
    from: &TestUser,
    type_uri: &str,
    payload: Value,
    conforms: Conforms,
) -> Result<Value, Refused> {
    let mediator_did = env.mediator.did().to_string();
    let now = chrono::Utc::now();
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuer": from.did,
        "recipient": mediator_did,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    let key = from
        .secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .expect("an Ed25519 signing key");
    let doc = sign_trust_task(&doc, key, SignOptions::new())
        .await
        .expect("sign the task");
    let secs = now.timestamp() as u64;
    let msg = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        ENVELOPE_TYPE.to_string(),
        doc,
    )
    .to(mediator_did.clone())
    .from(from.did.clone())
    .created_time(secs)
    .expires_time(secs + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&from.did), None)
        .await
        .expect("authcrypt");
    let reply = match env
        .atm
        .send_message(&from.profile, &packed, &msg_id, true, true)
        .await
    {
        Ok(SendMessageResponse::Message(reply)) => reply,
        Ok(other) => panic!("expected a reply message, got {other:?}"),
        Err(e) => return Err(Refused(e.to_string())),
    };
    if reply.typ.contains("problem-report") {
        return Err(Refused(reply.body.to_string()));
    }
    assert_eq!(
        reply.body["type"],
        format!("{type_uri}#response"),
        "{:#}",
        reply.body
    );
    let payload = reply.body["payload"].clone();
    conforms(payload.clone())
        .unwrap_or_else(|e| panic!("response does not match the spec: {e}\n{payload:#}"));
    Ok(payload)
}

async fn list(env: &TestEnvironment, from: &TestUser, payload: Value) -> Result<Value, Refused> {
    task(env, from, LIST, payload, |v| {
        serde_json::from_value::<spec::admin_list::v0_1::Response>(v).map(drop)
    })
    .await
}

async fn revoke(env: &TestEnvironment, from: &TestUser, payload: Value) -> Result<Value, Refused> {
    task(env, from, REVOKE, payload, |v| {
        serde_json::from_value::<spec::admin_revoke::v0_1::Response>(v).map(drop)
    })
    .await
}

async fn revoke_all(
    env: &TestEnvironment,
    from: &TestUser,
    payload: Value,
) -> Result<Value, Refused> {
    task(env, from, REVOKE_ALL, payload, |v| {
        serde_json::from_value::<spec::admin_revoke_all::v0_1::Response>(v).map(drop)
    })
    .await
}

/// `member` grants `principal`, presented by the member over its own socket
/// (opened if need be). Returns the signed statement and its grant id.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) -> (Value, String) {
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
    env.atm
        .profile_add(&member.profile, true)
        .await
        .expect("member websocket");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&member.profile, vec![g.clone()])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    (g, id)
}

fn dids(page: &Value, field: &str) -> Vec<String> {
    page["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g[field].as_str().unwrap().to_string())
        .collect()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

async fn audit(env: &TestEnvironment, action: AuditAction) -> Vec<AuditLogEntry> {
    env.mediator
        .store()
        .audit_log_list(0, 1000)
        .await
        .expect("audit log")
        .entries
        .into_iter()
        .filter(|e| e.action == action)
        .collect()
}

/// The mux notices in `user`'s inbox, unpacked as the user.
async fn stored_notices(env: &TestEnvironment, user: &TestUser) -> Vec<Value> {
    let store = env.mediator.store();
    let hash = user.did_hash();
    let mut out = Vec::new();
    for m in store
        .list_messages(&hash, Folder::Inbox, None, 100)
        .await
        .expect("inbox")
    {
        let Some(full) = store.get_message(&hash, &m.msg_id).await.unwrap() else {
            continue;
        };
        let (msg, _) = env
            .atm
            .unpack(full.msg.as_deref().expect("stored body"))
            .await
            .expect("unpack as the recipient");
        if msg.body["type"] == NOTICE_TYPE {
            out.push(msg.body["payload"].clone());
        }
    }
    out
}

/// Open `principal`'s SDK mux connection and wait for `ready`.
async fn mux_online(env: &TestEnvironment, principal: &TestUser) -> (String, String) {
    env.atm
        .profile_enable_mux_websocket(&principal.profile)
        .await
        .expect("mux websocket");
    let mut ready_rx = principal.profile.mux_ready().await.expect("ready watch");
    let ready = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = ready_rx.borrow().clone() {
                return r;
            }
            ready_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("ready within 5s");
    (ready.session_id, ready.mux_nonce)
}

async fn members_until(
    principal: &TestUser,
    what: &str,
    done: impl Fn(&MuxMembers) -> bool,
) -> MuxMembers {
    let mut rx = principal.profile.mux_members().await.unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let m = rx.borrow_and_update().clone();
            if done(&m) {
                return m;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("member set: {what}: {:?}", rx.borrow()))
}

/// The next `detached` event naming `did`; returns its reason.
async fn detached_reason(
    events: &mut tokio::sync::broadcast::Receiver<affinidi_messaging_sdk::protocols::mux::MuxEvent>,
    did: &str,
) -> String {
    timeout(Duration::from_secs(5), async {
        loop {
            let ev = events.recv().await.expect("event stream");
            let v = serde_json::to_value(&ev).unwrap();
            if v["event"] != "detached" {
                continue;
            }
            if let Some(d) = v["dids"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["did"] == did)
            {
                return d["reason"].as_str().unwrap().to_string();
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no detached event for {did}"))
}

/// `admin-list` by principal, by member and by both; paging with a bound
/// cursor; the member's epoch; and who may read.
#[tokio::test]
async fn an_administrator_lists_stored_grants() {
    init_tracing();
    let env = env().await;
    let admin = with_role(&env, "operator", AccountType::Admin).await;
    let service = with_role(&env, "service", AccountType::Mediator).await;
    let device = env.add_user("device").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let (_, work_device) = grant(&env, &work, &device).await;
    grant(&env, &home, &device).await;
    grant(&env, &work, &laptop).await;

    // By principal: the device's two grants, in member-DID order, without
    // their statements and without an epoch.
    let page = list(&env, &admin, json!({ "principal": device.did }))
        .await
        .expect("list by principal");
    assert_eq!(
        dids(&page, "did"),
        sorted(vec![work.did.clone(), home.did.clone()])
    );
    assert!(page.get("epoch").is_none(), "{page:#}");
    assert!(page.get("nextCursor").is_none(), "{page:#}");
    let g = page["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["did"] == work.did.as_str())
        .unwrap();
    assert_eq!(g["grantId"], work_device.as_str());
    assert_eq!(g["principal"], device.did.as_str());
    assert_eq!(g["state"], "active");
    assert_eq!(g["scope"], json!(["receive", "pickup"]));
    assert_eq!(g["epoch"], 0);
    assert!(g["signedAt"].is_string() && g["expiresAt"].is_string());
    assert!(g.get("statement").is_none(), "never the statement: {g:#}");

    // By member: both principals on `work`, and its epoch.
    let page = list(&env, &admin, json!({ "member": work.did }))
        .await
        .expect("list by member");
    assert_eq!(
        dids(&page, "principal"),
        sorted(vec![device.did.clone(), laptop.did.clone()])
    );
    assert_eq!(page["epoch"], 0);

    // Both: the one grant between them.
    let page = list(
        &env,
        &admin,
        json!({ "principal": device.did, "member": work.did }),
    )
    .await
    .expect("list between");
    assert_eq!(dids(&page, "grantId"), vec![work_device.clone()]);

    // A DID with no grants (and one with no account) is an empty page.
    let page = list(&env, &admin, json!({ "member": "did:example:nobody" }))
        .await
        .expect("empty");
    assert_eq!(page["grants"], json!([]));
    assert_eq!(page["epoch"], 0);

    // Paging one at a time; the cursor belongs to these request members.
    let p1 = list(&env, &admin, json!({ "principal": device.did, "limit": 1 }))
        .await
        .expect("page 1");
    let cursor = p1["nextCursor"].as_str().expect("more to come").to_string();
    let p2 = list(
        &env,
        &admin,
        json!({ "principal": device.did, "limit": 1, "cursor": cursor }),
    )
    .await
    .expect("page 2");
    assert!(p2.get("nextCursor").is_none(), "{p2:#}");
    assert_eq!(
        sorted([dids(&p1, "did"), dids(&p2, "did")].concat()),
        sorted(vec![work.did.clone(), home.did.clone()])
    );
    let wrong = list(
        &env,
        &admin,
        json!({ "principal": laptop.did, "limit": 1, "cursor": cursor }),
    )
    .await
    .expect_err("a cursor for other request members");
    assert!(
        wrong.has("messaging/mux/admin-list:cursorInvalid"),
        "{wrong:?}"
    );
    let forged = list(
        &env,
        &admin,
        json!({ "principal": device.did, "cursor": "bm90LWEtY3Vyc29y" }),
    )
    .await
    .expect_err("a cursor this mediator did not issue");
    assert!(forged.has("cursorInvalid"), "{forged:?}");

    // Neither filter: malformed.
    let none = list(&env, &admin, json!({}))
        .await
        .expect_err("a filter is required");
    assert!(none.has("malformedRequest"), "{none:?}");

    // The mediator's own account may read; a standard account may not.
    list(&env, &service, json!({ "principal": device.did }))
        .await
        .expect("the mediator account lists");
    env.atm.profile_add(&device.profile, true).await.unwrap();
    let denied = list(&env, &device, json!({ "principal": device.did }))
        .await
        .expect_err("a standard account is refused");
    assert!(denied.has("admin_required"), "{denied:?}");
}

/// `admin-revoke` by principal: the live member is detached with reason
/// `admin`, the principal is told by a `grantsRevoked` notice with reason
/// `admin`, the revocation is audited, and the statement cannot come back.
#[tokio::test]
async fn an_admin_revoke_detaches_and_tells_the_principal() {
    init_tracing();
    let env = env().await;
    let admin = with_role(&env, "operator", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    mux_online(&env, &device).await;
    let mut events = device.profile.mux_events().await.expect("events");
    let mut notices = device.profile.mux_notices().await.expect("notices");
    let (statement, id) = grant(&env, &work, &device).await;
    grant(&env, &work, &laptop).await;
    // `work` goes offline so its own socket does not take its traffic.
    work.profile.stop_websocket().await.unwrap();
    members_until(&device, "work joins", |m| m.len() == 1).await;

    let r = revoke(&env, &admin, json!({ "principal": device.did }))
        .await
        .expect("admin revoke");
    assert_eq!(
        r["revoked"],
        json!([{ "grantId": id, "did": work.did, "principal": device.did }])
    );
    assert_eq!(r["remaining"], 0);
    // Detached before the answer, with reason `admin`.
    assert_eq!(detached_reason(&mut events, &work.did).await, "admin");
    members_until(&device, "work left", |m| m.is_empty()).await;

    let delivery = timeout(Duration::from_secs(5), notices.recv())
        .await
        .expect("notice within 5s")
        .unwrap();
    let p = serde_json::to_value(&delivery.document.payload).unwrap();
    assert_eq!(p["notice"], "grantsRevoked", "{p:#}");
    assert_eq!(p["revocations"][0]["did"], work.did.as_str());
    assert_eq!(p["revocations"][0]["reason"], "admin", "{p:#}");

    // The laptop's grant on `work` is untouched; the device's is gone.
    let left = list(&env, &admin, json!({ "member": work.did }))
        .await
        .unwrap();
    assert_eq!(dids(&left, "principal"), vec![laptop.did.clone()]);

    // Audited: the administrator, the member, the grant.
    let entries = audit(&env, AuditAction::MuxGrantRevoke).await;
    assert_eq!(entries.len(), 1, "{entries:#?}");
    assert_eq!(entries[0].actor_did_hash, admin.did_hash());
    assert_eq!(entries[0].target_did_hash, work.did_hash());
    assert!(entries[0].detail.contains(&id), "{}", entries[0].detail);
    assert!(entries[0].detail.contains("administrator"));

    // Revoking what is gone succeeds with nothing to do.
    let again = revoke(&env, &admin, json!({ "principal": device.did }))
        .await
        .unwrap();
    assert_eq!(again["revoked"], json!([]));
    assert_eq!(again["remaining"], 0);

    // The replay floor keeps the revoked statement out.
    let replay = env
        .atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![statement])
        .await
        .expect("grant task answers");
    let replay = serde_json::to_value(&replay).unwrap();
    assert_eq!(replay["results"][0]["status"], "refused", "{replay:#}");
}

/// Selectors, `limit` with an exact `remaining`, named grant ids, and who
/// may revoke.
#[tokio::test]
async fn admin_revoke_selects_and_pages_by_remaining() {
    init_tracing();
    let env = env().await;
    let admin = with_role(&env, "operator", AccountType::Admin).await;
    let service = with_role(&env, "service", AccountType::Mediator).await;
    let device = env.add_user("device").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let a = env.add_user("a").await.unwrap();
    let b = env.add_user("b").await.unwrap();
    let c = env.add_user("c").await.unwrap();
    for m in [&a, &b, &c] {
        grant(&env, m, &device).await;
    }
    let (_, a_laptop) = grant(&env, &a, &laptop).await;

    // Malformed selections.
    let r = revoke(&env, &admin, json!({}))
        .await
        .expect_err("no selector");
    assert!(r.has("malformedRequest"), "{r:?}");
    let r = revoke(
        &env,
        &admin,
        json!({ "principal": device.did, "grantIds": [a_laptop] }),
    )
    .await
    .expect_err("grantIds without member");
    assert!(r.has("malformedRequest"), "{r:?}");

    // The mediator's own account may list but not revoke.
    let r = revoke(&env, &service, json!({ "principal": device.did }))
        .await
        .expect_err("the mediator account may not revoke");
    assert!(r.has("admin_required"), "{r:?}");
    let r = revoke_all(&env, &service, json!({ "did": a.did, "epoch": 0 }))
        .await
        .expect_err("nor advance an epoch");
    assert!(r.has("admin_required"), "{r:?}");

    // Two of the device's three grants, then the last.
    let first = revoke(&env, &admin, json!({ "principal": device.did, "limit": 2 }))
        .await
        .expect("first batch");
    assert_eq!(first["revoked"].as_array().unwrap().len(), 2, "{first:#}");
    assert_eq!(first["remaining"], 1);
    let mut want = [a.did.clone(), b.did.clone(), c.did.clone()];
    want.sort();
    let got: Vec<&str> = first["revoked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["did"].as_str().unwrap())
        .collect();
    assert_eq!(got, [want[0].as_str(), want[1].as_str()], "member order");
    let second = revoke(&env, &admin, json!({ "principal": device.did, "limit": 2 }))
        .await
        .expect("second batch");
    assert_eq!(second["revoked"][0]["did"], want[2].as_str());
    assert_eq!(second["remaining"], 0);

    // A member and named grant ids: one known, one not.
    let r = revoke(
        &env,
        &admin,
        json!({ "member": a.did, "grantIds": [a_laptop, "no-such-grant"] }),
    )
    .await
    .expect("named grants");
    assert_eq!(r["revoked"][0]["grantId"], a_laptop.as_str());
    assert_eq!(r["revoked"][0]["principal"], laptop.did.as_str());
    assert_eq!(r["unmatchedGrantIds"], json!(["no-such-grant"]));
    assert_eq!(r["remaining"], 0);
}

/// An `admin` cannot revoke a grant whose member or principal is a
/// `rootAdmin`, nor advance a `rootAdmin`'s epoch; nothing in the selection
/// is revoked when it is refused. A `rootAdmin` may do both.
#[tokio::test]
async fn root_admin_grants_are_protected_from_an_admin() {
    init_tracing();
    let env = env().await;
    let admin = with_role(&env, "operator", AccountType::Admin).await;
    let root = with_role(&env, "root", AccountType::RootAdmin).await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    grant(&env, &work, &device).await;
    grant(&env, &root, &device).await;

    let r = revoke(&env, &admin, json!({ "principal": device.did }))
        .await
        .expect_err("a rootAdmin's grant is in the selection");
    assert!(
        r.has("messaging/mux/admin-revoke:protectedAccount"),
        "{r:?}"
    );
    // Nothing revoked, not even the unprotected grant.
    let page = list(&env, &admin, json!({ "principal": device.did }))
        .await
        .unwrap();
    assert_eq!(page["grants"].as_array().unwrap().len(), 2, "{page:#}");
    // The unprotected grant alone may be revoked by the admin.
    let r = revoke(
        &env,
        &admin,
        json!({ "principal": device.did, "member": work.did }),
    )
    .await
    .expect("an unprotected selection");
    assert_eq!(r["revoked"].as_array().unwrap().len(), 1);

    let r = revoke_all(&env, &admin, json!({ "did": root.did, "epoch": 0 }))
        .await
        .expect_err("a rootAdmin's epoch");
    assert!(
        r.has("messaging/mux/admin-revoke-all:protectedAccount"),
        "{r:?}"
    );

    // A rootAdmin may.
    let r = revoke(&env, &root, json!({ "principal": device.did }))
        .await
        .expect("root revokes");
    assert_eq!(r["revoked"][0]["did"], root.did.as_str());
    let r = revoke_all(&env, &root, json!({ "did": root.did, "epoch": 0 }))
        .await
        .expect("root advances");
    assert_eq!(r["epoch"], 1);
}

/// `admin-revoke-all`: a compare-and-set on the member's epoch that voids
/// its grants, ends its session attaches, and reports reason `admin`.
#[tokio::test]
async fn admin_revoke_all_advances_the_epoch_once() {
    init_tracing();
    let env = env().await;
    let admin = with_role(&env, "operator", AccountType::Admin).await;
    let device = env.add_user("device").await.unwrap();
    let laptop = env.add_user("laptop").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let mediator_did = env.mediator.did().to_string();

    let (session_id, nonce) = mux_online(&env, &device).await;
    let mut events = device.profile.mux_events().await.expect("events");
    let mut notices = device.profile.mux_notices().await.expect("notices");
    grant(&env, &work, &device).await;
    grant(&env, &work, &laptop).await;
    work.profile.stop_websocket().await.unwrap();
    // `temp` rides the device's connection on a session attach only.
    let a = sign_attach(
        &env.atm,
        &temp.did,
        &device.did,
        &mediator_did,
        &session_id,
        &nonce,
        &[MuxCapability::Receive],
        600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_attach(&device.profile, vec![a])
        .await
        .expect("attach");
    members_until(&device, "work and temp", |m| m.len() == 2).await;

    // The epoch to name, as admin-list reports it.
    let page = list(&env, &admin, json!({ "member": work.did }))
        .await
        .unwrap();
    assert_eq!(page["epoch"], 0);

    // A future epoch: refused, with the current one; nothing changed.
    let r = revoke_all(&env, &admin, json!({ "did": work.did, "epoch": 5 }))
        .await
        .expect_err("a future epoch");
    assert!(
        r.has("messaging/mux/admin-revoke-all:epochMismatch"),
        "{r:?}"
    );
    assert!(r.has("current epoch is 0"), "{r:?}");

    let r = revoke_all(&env, &admin, json!({ "did": work.did, "epoch": 0 }))
        .await
        .expect("advance");
    assert_eq!(
        r,
        json!({ "did": work.did, "epoch": 1, "epochAdvanced": true, "revokedGrants": 2 })
    );
    assert_eq!(detached_reason(&mut events, &work.did).await, "admin");

    // Voided grants stay listed as epochRevoked; the epoch is 1.
    let page = list(&env, &admin, json!({ "member": work.did }))
        .await
        .unwrap();
    assert_eq!(page["epoch"], 1);
    for g in page["grants"].as_array().unwrap() {
        assert_eq!(g["state"], "epochRevoked", "{g:#}");
    }

    // Each principal whose grant was voided is told, connected or not.
    let delivery = timeout(Duration::from_secs(5), notices.recv())
        .await
        .expect("notice within 5s")
        .unwrap();
    let p = serde_json::to_value(&delivery.document.payload).unwrap();
    assert_eq!(p["notice"], "grantsRevoked", "{p:#}");
    assert_eq!(p["revocations"][0]["reason"], "admin", "{p:#}");
    let offline = stored_notices(&env, &laptop).await;
    assert_eq!(offline.len(), 1, "{offline:#?}");
    assert_eq!(offline[0]["revocations"][0]["reason"], "admin");

    // The same request again: the epoch it names is already void.
    let r = revoke_all(&env, &admin, json!({ "did": work.did, "epoch": 0 }))
        .await
        .expect("replay");
    assert_eq!(
        r,
        json!({ "did": work.did, "epoch": 1, "epochAdvanced": false, "revokedGrants": 0 })
    );

    // A session attach ends with the epoch advance, reason `admin`.
    let r = revoke_all(&env, &admin, json!({ "did": temp.did, "epoch": 0 }))
        .await
        .expect("advance temp");
    assert_eq!(r["revokedGrants"], 0);
    assert_eq!(detached_reason(&mut events, &temp.did).await, "admin");
    members_until(&device, "both gone", |m| m.is_empty()).await;

    // Audited once per advance, with the epochs.
    let entries = audit(&env, AuditAction::MuxRevokeAll).await;
    assert_eq!(entries.len(), 2, "{entries:#?}");
    let work_entry = entries
        .iter()
        .find(|e| e.target_did_hash == did_hash(&work.did))
        .unwrap();
    assert_eq!(work_entry.actor_did_hash, admin.did_hash());
    assert!(
        work_entry.detail.contains("from 0 to 1"),
        "{}",
        work_entry.detail
    );

    // A DID with no account has no epoch.
    let r = revoke_all(
        &env,
        &admin,
        json!({ "did": "did:example:nobody", "epoch": 0 }),
    )
    .await
    .expect_err("unknown account");
    assert!(
        r.has("messaging/mux/admin-revoke-all:unknownAccount"),
        "{r:?}"
    );
}
