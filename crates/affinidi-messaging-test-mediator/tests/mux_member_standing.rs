//! A mux member stays on a connection only while its own account stands: it
//! exists, is not blocked, and its ACLs still cover the member's scope. That
//! is checked when the member is admitted, and again while it stays — at once
//! when an administrator changes the account on this instance, and at the
//! next request made for the member when the account changed some other way
//! — for members admitted by a session attach as much as by a stored grant.
//! Each departure reaches the principal as a `detached` event naming why.

mod common;

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

/// A member's account blocked without going through an administrator task
/// (here, straight in the store, as another instance's change would look to
/// this one) is caught by the next request made for the member: a delete on
/// the principal's session re-checks each member it would act for, detaches
/// the blocked one, and does not act for it.
#[tokio::test]
async fn a_request_for_a_member_rechecks_its_standing() {
    init_tracing();
    let env = mux_env().await;
    let device = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();

    let (_ready, mut events) = open(&env, &device).await;
    let (g, _) = sign_grant(
        &env.atm,
        &work.did,
        &device.did,
        env.mediator.did(),
        &[
            MuxCapability::Receive,
            MuxCapability::Pickup,
            MuxCapability::Delete,
        ],
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
    members_until(&device, "work carried", |m| m.is_reachable(&work.did)).await;

    let mut acl = affinidi_messaging_test_mediator::acl::allow_all();
    acl.set_blocked(true);
    env.mediator.set_acl(&work.did, acl).await.expect("block");

    env.atm
        .delete_messages_direct(
            &device.profile,
            &DeleteMessageRequest {
                message_ids: vec!["0".repeat(64)],
            },
        )
        .await
        .expect("delete request answered");

    assert_eq!(
        detached_reason(&mut events, &work.did).await,
        "accountBlocked"
    );
    members_until(&device, "work gone", |m| m.get(&work.did).is_none()).await;
}
