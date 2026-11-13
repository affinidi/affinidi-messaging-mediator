//! A mux member stays on a connection only while its own account stands: it
//! exists, is not blocked, and its ACLs still cover the member's scope. That
//! is checked when the member is admitted, and again while it stays — at once
//! when an administrator changes the account on this instance, and at the
//! next request made for the member when the account changed some other way
//! — for members admitted by a session attach as much as by a stored grant.
//! Each departure reaches the principal as a `detached` event naming why.

use crate::common;

use std::time::Duration;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_sdk::{
    messages::DeleteMessageRequest,
    protocols::mux::{MuxCapability, MuxEvent, MuxMembers, MuxReady, sign_attach, sign_grant},
    tasks::messaging::account::update::v0_2::MediatorAcl,
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use tokio::{sync::broadcast, time::timeout};

async fn mux_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

async fn admin(env: &TestEnvironment) -> TestUser {
    let admin = env.add_user("operator").await.expect("operator");
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin websocket");
    admin
}

/// Open `device`'s mux connection and wait for `ready`.
async fn open(
    env: &TestEnvironment,
    device: &TestUser,
) -> (MuxReady, broadcast::Receiver<MuxEvent>) {
    env.atm
        .profile_enable_mux_websocket(&device.profile)
        .await
        .expect("mux websocket");
    let events = device.profile.mux_events().await.expect("mux events");
    let mut ready_rx = device.profile.mux_ready().await.expect("mux ready");
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
    (ready, events)
}

/// `member` attaches to `device`'s connection with `receive`.
async fn attach(env: &TestEnvironment, device: &TestUser, ready: &MuxReady, member: &TestUser) {
    let a = sign_attach(
        &env.atm,
        &member.did,
        &device.did,
        env.mediator.did(),
        &ready.session_id,
        &ready.mux_nonce,
        &[MuxCapability::Receive],
        600,
    )
    .await
    .unwrap();
    let r = env
        .atm
        .trust_tasks()
        .mux_attach(&device.profile, vec![a])
        .await
        .expect("attach");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "attached", "{r:#}");
}

async fn members_until(
    device: &TestUser,
    what: &str,
    done: impl Fn(&MuxMembers) -> bool,
) -> MuxMembers {
    let mut rx = device.profile.mux_members().await.expect("mux members");
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

/// The reason the next `detached` event gives for `did`.
async fn detached_reason(events: &mut broadcast::Receiver<MuxEvent>, did: &str) -> String {
    timeout(Duration::from_secs(5), async {
        loop {
            let ev = events.recv().await.expect("mux event");
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

fn blocked() -> MediatorAcl {
    MediatorAcl::builder()
        .blocked(Some(true))
        .try_into()
        .expect("MediatorAcl has no required member")
}

/// An administrator blocks a DID attached to a live connection: it leaves at
/// once, before the update is answered, with `accountBlocked`. An attach has
/// no stored grant, so only the member's own standing can end it early.
#[tokio::test]
async fn blocking_an_attached_member_detaches_it() {
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let admin = admin(&env).await;

    let (ready, mut events) = open(&env, &device).await;
    attach(&env, &device, &ready, &temp).await;
    members_until(&device, "temp attached", |m| m.is_reachable(&temp.did)).await;

    env.atm
        .trust_tasks()
        .account_update(
            &admin.profile,
            Some(temp.did_hash()),
            None,
            Some(blocked()),
            None,
        )
        .await
        .expect("admin blocks temp");

    assert_eq!(
        detached_reason(&mut events, &temp.did).await,
        "accountBlocked"
    );
    members_until(&device, "temp gone", |m| m.get(&temp.did).is_none()).await;
}

/// Removing the account behind an attached member detaches it with
/// `accountRemoved`, as removal already did for grant-admitted members.
#[tokio::test]
async fn removing_an_attached_members_account_detaches_it() {
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let admin = admin(&env).await;

    let (ready, mut events) = open(&env, &device).await;
    attach(&env, &device, &ready, &temp).await;
    members_until(&device, "temp attached", |m| m.is_reachable(&temp.did)).await;

    let removed = env
        .atm
        .trust_tasks()
        .account_remove(&admin.profile, Some(temp.did_hash()))
        .await
        .expect("admin removes temp");
    assert!(removed);

    assert_eq!(
        detached_reason(&mut events, &temp.did).await,
        "accountRemoved"
    );
    members_until(&device, "temp gone", |m| m.get(&temp.did).is_none()).await;
}

/// `member` grants `device` the capabilities in `scope`, while connected.
async fn grant(
    env: &TestEnvironment,
    device: &TestUser,
    member: &TestUser,
    scope: &[MuxCapability],
) {
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &device.did,
        env.mediator.did(),
        scope,
        0,
        3600,
    )
    .await
    .unwrap();
    env.atm
        .trust_tasks()
        .mux_grant(&device.profile, vec![g])
        .await
        .expect("grant");
}

/// Send `to` a message from `from` for direct delivery; returns its stored
/// id (the SHA-256 of the packed message).
async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser) -> String {
    use affinidi_messaging_didcomm::message::Message;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        serde_json::json!({ "content": "standing probe" }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(t)
    .expires_time(t + 600)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &to.did, Some(&from.did), Some(&from.did))
        .await
        .expect("pack");
    env.atm
        .send_message(&from.profile, &packed, &msg.id, false, false)
        .await
        .expect("send");
    sha256::digest(&packed)
}

/// Whether `device`'s delete of `id` over REST succeeded.
async fn delete(env: &TestEnvironment, device: &TestUser, id: &str) -> bool {
    let r = env
        .atm
        .delete_messages_direct(
            &device.profile,
            &DeleteMessageRequest {
                message_ids: vec![id.to_string()],
            },
        )
        .await
        .expect("delete request answered");
    r.success.iter().any(|s| s == id)
}

/// A member's account blocked without going through an administrator task
/// (here, straight in the store, as a change no handler saw looks) is caught
/// by the next request made for the member: a delete of the member's message
/// re-checks that member's standing, detaches it, and does not delete.
#[tokio::test]
async fn a_request_for_a_member_rechecks_its_standing() {
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();

    let (_ready, mut events) = open(&env, &device).await;
    // No `receive`: the message stays stored rather than being pushed.
    grant(
        &env,
        &device,
        &work,
        &[MuxCapability::Pickup, MuxCapability::Delete],
    )
    .await;
    members_until(&device, "work carried", |m| m.get(&work.did).is_some()).await;
    let id = send(&env, &sender, &work).await;

    let mut acl = affinidi_messaging_test_mediator::acl::allow_all();
    acl.set_blocked(true);
    env.mediator.set_acl(&work.did, acl).await.expect("block");

    assert!(
        !delete(&env, &device, &id).await,
        "not deleted for a lapsed member"
    );
    assert_eq!(
        detached_reason(&mut events, &work.did).await,
        "accountBlocked"
    );
    members_until(&device, "work gone", |m| m.get(&work.did).is_none()).await;
}

/// A store that cannot say whether the member still stands refuses the
/// request made for it, and keeps the member: a failed read is neither a
/// lapse nor a pass. Once the store answers, the request goes through.
#[tokio::test]
async fn an_unreadable_standing_refuses_the_request_and_keeps_the_member() {
    use affinidi_messaging_mediator::mux::connection::test_hooks;
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();

    let (_ready, mut events) = open(&env, &device).await;
    grant(
        &env,
        &device,
        &work,
        &[MuxCapability::Pickup, MuxCapability::Delete],
    )
    .await;
    members_until(&device, "work carried", |m| m.get(&work.did).is_some()).await;
    let id = send(&env, &sender, &work).await;

    test_hooks::set_standing_unreadable(&work.did_hash(), true);
    let refused = !delete(&env, &device, &id).await;
    test_hooks::set_standing_unreadable(&work.did_hash(), false);
    assert!(refused, "refused while standing is unreadable");
    assert!(
        timeout(Duration::from_millis(500), async {
            loop {
                let v = serde_json::to_value(events.recv().await.unwrap()).unwrap();
                if v["event"] == "detached" {
                    return v;
                }
            }
        })
        .await
        .is_err(),
        "the member stays"
    );
    assert!(delete(&env, &device, &id).await, "deleted once readable");
}

/// The standing pass catches a change that no request and no handler saw:
/// a member blocked in the store leaves at the next pass, with its event.
#[tokio::test]
async fn the_standing_pass_detaches_a_member_blocked_behind_its_back() {
    use affinidi_messaging_mediator::mux::connection::test_hooks;
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();

    test_hooks::standing_pass_every(&device.did_hash(), Duration::from_millis(200));
    let (ready, mut events) = open(&env, &device).await;
    attach(&env, &device, &ready, &temp).await;
    members_until(&device, "temp attached", |m| m.is_reachable(&temp.did)).await;

    let mut acl = affinidi_messaging_test_mediator::acl::allow_all();
    acl.set_blocked(true);
    env.mediator.set_acl(&temp.did, acl).await.expect("block");

    assert_eq!(
        detached_reason(&mut events, &temp.did).await,
        "accountBlocked"
    );
}

/// ACLs narrowed below the member's scope, with the account not blocked:
/// the member leaves at once (`accountBlocked`), as it would have been
/// refused admission with them.
#[tokio::test]
async fn narrowing_a_members_acls_below_its_scope_detaches_it() {
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let admin = admin(&env).await;

    let (ready, mut events) = open(&env, &device).await;
    attach(&env, &device, &ready, &temp).await;
    members_until(&device, "temp attached", |m| m.is_reachable(&temp.did)).await;

    let no_receive: MediatorAcl = MediatorAcl::builder()
        .receive_messages(Some(false))
        .try_into()
        .expect("MediatorAcl has no required member");
    env.atm
        .trust_tasks()
        .account_update(
            &admin.profile,
            Some(temp.did_hash()),
            None,
            Some(no_receive),
            None,
        )
        .await
        .expect("admin narrows temp's ACLs");

    assert_eq!(
        detached_reason(&mut events, &temp.did).await,
        "accountBlocked"
    );
}

/// A member DID's `revoke-all` ends its session attaches too, before the
/// answer, with `epochBumped`; the principal's other members stay.
#[tokio::test]
async fn revoke_all_ends_a_session_attach() {
    use affinidi_messaging_sdk::protocols::mux::sign_revoke_all;
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    let home = env.add_user("home").await.unwrap();

    let (ready, mut events) = open(&env, &device).await;
    attach(&env, &device, &ready, &temp).await;
    attach(&env, &device, &ready, &home).await;
    members_until(&device, "both attached", |m| {
        m.is_reachable(&temp.did) && m.is_reachable(&home.did)
    })
    .await;

    let statement = sign_revoke_all(&env.atm, &temp.did, env.mediator.did(), 0)
        .await
        .unwrap();
    let r = env
        .atm
        .trust_tasks()
        .mux_revoke_all(&device.profile, statement)
        .await
        .expect("revoke-all");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["epochAdvanced"], true, "{r:#}");

    assert_eq!(detached_reason(&mut events, &temp.did).await, "epochBumped");
    let members = members_until(&device, "temp gone", |m| m.get(&temp.did).is_none()).await;
    assert!(
        members.is_reachable(&home.did),
        "another DID's attach stays"
    );
}
