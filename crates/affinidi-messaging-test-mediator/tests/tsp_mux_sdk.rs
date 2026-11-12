//! The SDK's `tsp-mux` client against this mediator, for what goes *on* the
//! socket: mux Trust Tasks answered on it, acks with `messaging/mux/ack`,
//! sending from another task while one reads, and the connection state
//! (R6.2). `tsp_mux.rs` covers the wire itself.
#![cfg(feature = "tsp")]

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_mediator::mux::{
    grants::{Ctx, store_grant},
    proof::StatementVerifier,
};
use affinidi_messaging_mediator_common::{store::mux::MuxLimits, types::acls::MediatorACLSet};
use affinidi_messaging_sdk::protocols::{
    mux::{MuxCapability, sign_attach},
    tsp::RelationshipState,
    tsp_mux::{TspMuxFrame, TspMuxState, TspMuxWebSocket},
};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::{Value, json};
use tokio::time::timeout;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use uuid::Uuid;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn mux_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    TestEnvironment::new(mediator).await.expect("env")
}

async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser, scope: &[&str]) {
    let signer = member
        .secrets
        .iter()
        .find(|s| s.id.ends_with("#key-1"))
        .expect("member's Ed25519 authentication key");
    let t = now();
    let statement = sign_trust_task(
        &json!({
            "type": "muxGrant",
            "issuer": member.did,
            "audience": env.mediator.did(),
            "grantId": Uuid::new_v4().to_string(),
            "principal": principal.did,
            "scope": scope,
            "epoch": 0,
            "iat": t,
            "exp": t + 3600,
        }),
        signer,
        SignOptions::new(),
    )
    .await
    .expect("sign grant");
    let store = env.mediator.store();
    let verifier = StatementVerifier::new(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap(),
    );
    let acl = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
    let ctx = Ctx {
        store: &*store,
        verifier: &verifier,
        mediator_did: env.mediator.did(),
        limits: MuxLimits::default(),
        default_acl: &acl,
        now: now(),
    };
    store_grant(&ctx, &member.did, &statement)
        .await
        .unwrap_or_else(|e| panic!("store grant: {e}"));
}

async fn relate_to_mediator(env: &TestEnvironment, user: &TestUser) {
    let mediator = env.mediator.did().to_string();
    for (ours, theirs) in [(&user.did, &mediator), (&mediator, &user.did)] {
        env.relationship_store
            .set(ours, theirs, RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship with the mediator");
    }
}

async fn next(sock: &mut TspMuxWebSocket) -> TspMuxFrame {
    timeout(Duration::from_secs(5), sock.recv())
        .await
        .expect("a frame within 5s")
        .expect("socket readable")
        .expect("socket open")
}

/// The next event of kind `event`, as JSON; fails on a data frame from the
/// mediator to the principal (an answer the socket should have kept).
async fn event(sock: &mut TspMuxWebSocket, principal: &str, mediator: &str, event: &str) -> Value {
    loop {
        match next(sock).await {
            TspMuxFrame::Event(e) => {
                let e = serde_json::to_value(&*e).unwrap();
                if e["event"] == event {
                    return e;
                }
            }
            TspMuxFrame::Data {
                receiver, sender, ..
            } => assert!(
                !(receiver == principal && sender == mediator),
                "a frame from the mediator reached the application"
            ),
            _ => {}
        }
    }
}

/// A session attach and a detach, sent on the socket as Trust Tasks and
/// answered there: the members follow, and no answer reaches `recv`.
#[tokio::test]
async fn attach_and_detach_go_on_the_socket() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let temp = env.add_user("temp").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    let mediator = env.mediator.did().to_string();

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    let sender = sock.sender();
    let ready = sock.ready().clone();
    let statement = sign_attach(
        &env.atm,
        &temp.did,
        &principal.did,
        &mediator,
        &ready.session_id,
        &ready.mux_nonce,
        &[MuxCapability::Receive, MuxCapability::Delete],
        600,
    )
    .await
    .expect("sign attach");
    // The answer comes while `recv` is not being called: the socket task
    // routes it.
    let answer = sender
        .attach(vec![statement])
        .await
        .expect("attach on the socket");
    let answer = serde_json::to_value(&answer).unwrap();
    assert_eq!(answer["results"][0]["did"], temp.did, "{answer:#}");
    let attached = event(&mut sock, &principal.did, &mediator, "attached").await;
    assert_eq!(attached["dids"][0]["did"], temp.did);
    assert!(sock.members().is_reachable(&temp.did));

    let answer = sender
        .detach(vec![temp.did.clone()])
        .await
        .expect("detach on the socket");
    assert_eq!(
        serde_json::to_value(&answer).unwrap()["detached"][0],
        temp.did
    );
    event(&mut sock, &principal.did, &mediator, "detached").await;
    assert!(!sock.members().is_reachable(&temp.did));
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// A frame sent from another task while this one waits on `recv`, and acks
/// with `messaging/mux/ack` on the socket, per member scope.
#[tokio::test]
async fn one_task_sends_and_acks_while_another_reads() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let peer = env.add_user("peer").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    for m in [&work, &home] {
        env.relate_directly(&peer, m).await.unwrap();
    }
    env.relate_directly(&work, &peer).await.unwrap();
    grant(&env, &work, &principal, &["receive", "delete", "send"]).await;
    grant(&env, &home, &principal, &["receive"]).await;

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    let mediator = env.mediator.did().to_string();
    event(&mut sock, &principal.did, &mediator, "attached").await;

    // Another task sends as `work` while this one reads.
    let sender = sock.sender();
    let frame = env
        .atm
        .tsp()
        .pack(&work.profile, &peer.did, b"sent from another task")
        .await
        .unwrap();
    let sending = tokio::spawn(async move { sender.send(&frame).await });

    for m in [&work, &home] {
        env.atm
            .tsp()
            .send(&peer.profile, &m.did, b"for a member")
            .await
            .unwrap();
    }
    let mut frames = Vec::new();
    while frames.len() < 2 {
        if let TspMuxFrame::Data {
            frame, receiver, ..
        } = next(&mut sock).await
        {
            assert!(receiver == work.did || receiver == home.did);
            frames.push((receiver, frame));
        }
    }
    sending
        .await
        .unwrap()
        .expect("sent while the other task read");

    let refs: Vec<&[u8]> = frames.iter().map(|(_, f)| f.as_slice()).collect();
    let acked = sock.acker().ack(&refs).await.expect("ack on the socket");
    assert_eq!(acked.acked.len(), 1, "{acked:?}");
    assert_eq!(acked.refused.len(), 1, "{acked:?}");
    assert_eq!(acked.refused[0].1, "notPermitted", "{acked:?}");
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// A Trust Task sent another way (sealed to the mediator and sent over TSP,
/// as the SDK's inbox-polling path does) while a `tsp-mux` socket is open: its
/// answer is stored and drained to the socket too, which leaves it for its
/// owner, neither handing it over nor acknowledging it (R1.7).
#[tokio::test]
async fn an_answer_for_another_request_is_left_alone() {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    grant(&env, &work, &principal, &["receive"]).await;
    let mediator = env.mediator.did().to_string();

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    event(&mut sock, &principal.did, &mediator, "attached").await;

    let request_id = format!("urn:uuid:{}", Uuid::new_v4());
    let doc = json!({
        "id": request_id,
        "type": "https://trusttasks.org/spec/messaging/mux/list/0.1",
        "issuer": principal.did,
        "recipient": mediator,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "as": "principal" },
    });
    env.atm
        .tsp()
        .send(
            &principal.profile,
            &mediator,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("send the request over TSP");

    // Its answer reaches the inbox, and stays there for its owner.
    let store = env.mediator.store();
    let answer = timeout(Duration::from_secs(5), async {
        loop {
            let inbox = store
                .fetch_messages(
                    "test",
                    &principal.did_hash(),
                    &affinidi_messaging_sdk::messages::fetch::FetchOptions::default(),
                )
                .await
                .unwrap();
            for m in inbox.success {
                let Some(body) = m.msg else { continue };
                let Ok(qb2) = BASE64_URL_SAFE_NO_PAD.decode(&body) else {
                    continue;
                };
                if let Ok((payload, _)) = env.atm.tsp().unpack_bytes(&principal.profile, &qb2).await
                    && let Ok(d) = serde_json::from_slice::<Value>(&payload)
                    && d["threadId"] == request_id
                {
                    return m.msg_id;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the answer is stored");
    // Nothing from the mediator reached the application.
    while let Ok(Ok(Some(f))) = timeout(Duration::from_millis(500), sock.recv()).await {
        if let TspMuxFrame::Data {
            receiver, sender, ..
        } = f
        {
            assert!(
                !(receiver == principal.did && sender == mediator),
                "handed over"
            );
        }
    }
    assert!(
        store
            .delivery_state(&principal.did_hash(), &answer)
            .await
            .unwrap()
            .is_some(),
        "not acknowledged by the socket"
    );
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// When the mediator closes the socket (here: the principal's next socket
/// replaces it), the state says so with the reason, `recv` ends, and a sender
/// fails rather than reporting a frame written (R1.1, R6.2). A socket the
/// client closes says so too.
#[tokio::test]
async fn the_state_turns_closed_when_the_socket_goes() {
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    let mut state = sock.state();
    assert_eq!(*state.borrow(), TspMuxState::Open);
    let sender = sock.sender();

    let second = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("the next tsp-mux socket");
    timeout(
        Duration::from_secs(10),
        state.wait_for(|s| matches!(s, TspMuxState::Closed { .. })),
    )
    .await
    .expect("closed within 10s")
    .expect("state");
    let ended = timeout(Duration::from_secs(5), sock.recv())
        .await
        .expect("recv ends");
    assert!(!matches!(ended, Ok(Some(_))), "{ended:?}");
    assert!(
        sender.send(b"after").await.is_err(),
        "no frame reported written"
    );

    let mut state = second.state();
    second.close().await.expect("close");
    match &*state.borrow_and_update() {
        TspMuxState::Closed { reason } => assert!(reason.contains("client"), "{reason}"),
        other => panic!("{other:?}"),
    }
    env.shutdown().await.expect("shutdown");
}

/// `messaging/mux/list` sent on the `tsp-mux` socket and answered there: as
/// principal, the grants the socket's principal holds; as member, none (the
/// principal granted nothing). No answer reaches `recv`.
#[tokio::test]
async fn mux_list_is_answered_on_the_socket() {
    use affinidi_messaging_sdk::tasks::messaging::mux::list::v0_1::Payload;
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    relate_to_mediator(&env, &principal).await;
    grant(&env, &work, &principal, &["receive", "delete"]).await;
    grant(&env, &home, &principal, &["receive"]).await;
    let mediator = env.mediator.did().to_string();

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    event(&mut sock, &principal.did, &mediator, "attached").await;
    let sender = sock.sender();

    let answer = sender
        .request::<Payload, Value>(json!({ "as": "principal" }))
        .await
        .expect("list on the socket");
    let p = &answer.payload;
    assert_eq!(p["as"], "principal", "{p:#}");
    let grants = p["grants"].as_array().expect("grants");
    let mut members: Vec<(String, Value)> = grants
        .iter()
        .map(|g| {
            assert_eq!(g["state"], "active", "{g:#}");
            assert_eq!(g["statement"]["principal"], principal.did, "{g:#}");
            (
                g["statement"]["issuer"].as_str().unwrap().to_string(),
                g["scope"].clone(),
            )
        })
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want = vec![
        (work.did.clone(), json!(["receive", "delete"])),
        (home.did.clone(), json!(["receive"])),
    ];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(members, want, "{p:#}");

    // As member: the principal's own DID carries no grants.
    let answer = sender
        .request::<Payload, Value>(json!({ "as": "member" }))
        .await
        .expect("list as member on the socket");
    assert_eq!(answer.payload["as"], "member");
    assert_eq!(answer.payload["grants"], json!([]));

    // The answers were routed to their requests, never handed to `recv`.
    while let Ok(Ok(Some(f))) = timeout(Duration::from_millis(500), sock.recv()).await {
        if let TspMuxFrame::Data {
            receiver, sender, ..
        } = f
        {
            assert!(
                !(receiver == principal.did && sender == mediator),
                "an answer reached the application"
            );
        }
    }
    sock.close().await.expect("close");
    env.shutdown().await.expect("shutdown");
}

/// `messaging/mux/connections` reports a `tsp-mux` connection with wire
/// `tsp`, its session id, and its members (the DIDComm view is in
/// `mux_sdk.rs`, `an_administrator_lists_live_mux_connections`).
#[tokio::test]
async fn an_administrator_sees_a_tsp_mux_connection_as_wire_tsp() {
    use affinidi_messaging_mediator_common::types::accounts::AccountType;
    use affinidi_messaging_sdk::protocols::trust_tasks::MuxConnectionsQuery;
    init_tracing();
    let env = mux_env().await;
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let admin = env.add_user("operator").await.unwrap();
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin websocket");
    relate_to_mediator(&env, &principal).await;
    grant(&env, &work, &principal, &["receive", "delete"]).await;
    grant(&env, &home, &principal, &["receive"]).await;
    let mediator = env.mediator.did().to_string();

    let mut sock = env
        .atm
        .tsp()
        .connect_websocket_mux(&principal.profile)
        .await
        .expect("tsp-mux");
    event(&mut sock, &principal.did, &mediator, "attached").await;

    let page = serde_json::to_value(
        env.atm
            .trust_tasks()
            .mux_connections(&admin.profile, &MuxConnectionsQuery::all())
            .await
            .expect("mux_connections"),
    )
    .unwrap();
    let conns = page["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1, "{page:#}");
    let c = &conns[0];
    assert_eq!(c["principal"], principal.did.as_str());
    assert_eq!(c["wire"], "tsp", "{c:#}");
    assert_eq!(c["sessionId"], sock.ready().session_id.as_str());
    assert_eq!(c["memberCount"], 2);
    let members = c["members"].as_array().unwrap();
    let mut dids: Vec<&str> = members.iter().map(|m| m["did"].as_str().unwrap()).collect();
    dids.sort();
    let mut want = [work.did.as_str(), home.did.as_str()];
    want.sort();
    assert_eq!(dids, want);
    for m in members {
        assert_eq!(m["source"], "grant", "{m:#}");
        assert!(m["grantId"].is_string(), "{m:#}");
        assert_eq!(m["deliveryActive"], true, "{m:#}");
        let scope = if m["did"] == work.did.as_str() {
            json!(["receive", "delete"])
        } else {
            json!(["receive"])
        };
        assert_eq!(m["scope"], scope, "{m:#}");
    }

    // Closed: the connection leaves the view.
    sock.close().await.expect("close");
    let gone = timeout(Duration::from_secs(5), async {
        loop {
            let page = serde_json::to_value(
                env.atm
                    .trust_tasks()
                    .mux_connections(&admin.profile, &MuxConnectionsQuery::all())
                    .await
                    .expect("mux_connections"),
            )
            .unwrap();
            if page["connections"] == json!([]) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        gone.is_ok(),
        "a closed tsp-mux connection is no longer listed"
    );
    env.shutdown().await.expect("shutdown");
}
