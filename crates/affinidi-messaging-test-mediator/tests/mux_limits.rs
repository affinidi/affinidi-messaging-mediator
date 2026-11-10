//! A mux connection's limits, end to end: the `didcomm-mux` subprotocol (and
//! the provisional `affinidi-mux` it replaced), and grants a full connection
//! has no room for, which are reported `detached` with reason
//! `connectionFull` rather than left for the client to infer.

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::protocols::mux::{MuxCapability, sign_grant};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::Value;
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const SCOPE: [MuxCapability; 2] = [MuxCapability::Receive, MuxCapability::Pickup];

/// The event document must parse as the spec's generated
/// `messaging/mux/event` type, as a client using the bindings parses it.
fn conforms_to_spec(doc: &Value) {
    use affinidi_messaging_mediator::task_specs::messaging::mux::event::v0_1::Payload;
    serde_json::from_value::<trust_tasks_rs::TrustTask<Payload>>(doc.clone())
        .unwrap_or_else(|e| panic!("mux/event does not match the spec: {e}\n{doc:#}"));
}

/// Open a socket for `user` offering `protocols`, and return it with the
/// subprotocol the mediator selected.
async fn open(
    env: &TestEnvironment,
    user: &TestUser,
    protocols: &[&str],
) -> (Socket, Option<String>) {
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate");
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let mut request = ClientRequestBuilder::new(ws_uri);
    for p in protocols {
        request = request.with_sub_protocol(p.to_string());
    }
    let request = request.with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (ws, response) = connect_async(request).await.expect("upgrade");
    let selected = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (ws, selected)
}

const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";

/// The next mux event on `ws`, unpacked, checked against the spec, and
/// returned as its payload.
async fn next_event(env: &TestEnvironment, ws: &mut Socket) -> Value {
    loop {
        let frame = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5s")
            .expect("socket open")
            .expect("frame");
        // Members' own traffic rides the connection too; skip it.
        if let Message::Text(t) = frame
            && let Ok((msg, _)) = env.atm.unpack(t.as_str()).await
            && msg.body["type"] == EVENT_TYPE
        {
            conforms_to_spec(&msg.body);
            return msg.body["payload"].clone();
        }
    }
}

/// `member` grants `principal` over the `messaging/mux/grant` Trust Task,
/// presented by the member itself (the principal's live socket here is a raw
/// one, which would take the SDK's reply); returns the grant's outcome.
async fn grant(env: &TestEnvironment, member: &TestUser, principal: &TestUser) -> Value {
    let (g, _) = sign_grant(
        &env.atm,
        &member.did,
        &principal.did,
        env.mediator.did(),
        &SCOPE,
        0,
        3600,
    )
    .await
    .expect("sign grant");
    // The SDK takes Trust Task responses on the presenter's websocket.
    env.atm
        .profile_add(&member.profile, true)
        .await
        .expect("enable websocket");
    let r = env
        .atm
        .trust_tasks()
        .mux_grant(&member.profile, vec![g])
        .await
        .expect("mux_grant");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["results"][0]["status"], "stored", "{r:#}");
    // Offline again, so the member's own socket does not take its live
    // traffic from the principal's connection.
    member
        .profile
        .stop_websocket()
        .await
        .expect("stop websocket");
    r["results"][0].clone()
}

/// The next event that changes the member set, skipping restatements of a
/// member's live-delivery state (the member's own socket taking or giving
/// back its traffic), which race with the member going offline.
async fn next_change(env: &TestEnvironment, ws: &mut Socket) -> Value {
    loop {
        let e = next_event(env, ws).await;
        let restatement = e["event"] == "attached"
            && e["dids"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["reason"] == "reactivated" || d["deliveryActive"] == false);
        let superseded = e["event"] == "detached"
            && e["dids"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["reason"] == "superseded");
        if !(restatement || superseded) {
            return e;
        }
    }
}

fn dids(event: &Value) -> Vec<(String, String)> {
    event["dids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["did"].as_str().unwrap().to_string(),
                d["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn didcomm_mux_is_selected_and_the_provisional_name_still_works() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .spawn()
        .await
        .expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();

    for (offer, want) in [
        (&["didcomm-mux"][..], "didcomm-mux"),
        (&["affinidi-mux"][..], "affinidi-mux"),
        (&["affinidi-mux", "didcomm-mux"][..], "didcomm-mux"),
    ] {
        let (mut ws, selected) = open(&env, &principal, offer).await;
        assert_eq!(selected.as_deref(), Some(want), "offered {offer:?}");
        assert_eq!(next_event(&env, &mut ws).await["event"], "ready");
    }
}

#[tokio::test]
async fn without_mux_enabled_didcomm_mux_is_not_selected() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let (_ws, selected) = open(&env, &principal, &["didcomm-mux", "affinidi.test"]).await;
    assert!(
        !matches!(selected.as_deref(), Some("didcomm-mux" | "affinidi-mux")),
        "a mediator that will not multiplex must not say it will: {selected:?}"
    );
}

#[tokio::test]
async fn grants_a_full_connection_has_no_room_for_are_reported_connection_full() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .mux_max_dids_per_connection(2)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let work = env.add_user("work").await.unwrap();
    let home = env.add_user("home").await.unwrap();
    let spare = env.add_user("spare").await.unwrap();

    // One grant before the connection opens.
    grant(&env, &work, &principal).await;
    let (mut ws, selected) = open(&env, &principal, &["didcomm-mux"]).await;
    assert_eq!(selected.as_deref(), Some("didcomm-mux"));
    assert_eq!(next_event(&env, &mut ws).await["event"], "ready");
    let attached = next_change(&env, &mut ws).await;
    assert_eq!(attached["event"], "attached");
    assert_eq!(dids(&attached), vec![(work.did.clone(), "connect".into())]);

    // A second fits and attaches at once.
    let outcome = grant(&env, &home, &principal).await;
    assert_eq!(outcome["attachedNow"], true, "{outcome:#}");
    let attached = next_change(&env, &mut ws).await;
    assert_eq!(attached["event"], "attached");
    assert_eq!(dids(&attached), vec![(home.did.clone(), "grant".into())]);

    // A third does not fit: stored, not attached, and the connection is told.
    let outcome = grant(&env, &spare, &principal).await;
    assert_eq!(outcome["attachedNow"], false, "{outcome:#}");
    let detached = next_change(&env, &mut ws).await;
    assert_eq!(detached["event"], "detached");
    assert_eq!(
        dids(&detached),
        vec![(spare.did.clone(), "connectionFull".into())]
    );
    let entry = &detached["dids"][0];
    assert_eq!(entry["grantId"], outcome["grantId"]);
    assert!(
        entry.get("scope").is_none() && entry.get("expiresAt").is_none(),
        "a detached entry carries only did, reason and grantId: {entry:#}"
    );

    // On the next connection the same two fill it, and the third is
    // reported in the connect-time `detached` event.
    drop(ws);
    let (mut ws, _) = open(&env, &principal, &["didcomm-mux"]).await;
    assert_eq!(next_event(&env, &mut ws).await["event"], "ready");
    let attached = next_change(&env, &mut ws).await;
    assert_eq!(attached["event"], "attached");
    assert_eq!(attached["dids"].as_array().unwrap().len(), 2);
    let detached = next_change(&env, &mut ws).await;
    assert_eq!(detached["event"], "detached");
    let left_out = dids(&detached);
    assert_eq!(left_out.len(), 1);
    assert_eq!(left_out[0].1, "connectionFull");
    let carried: Vec<String> = dids(&attached).into_iter().map(|(d, _)| d).collect();
    assert!(!carried.contains(&left_out[0].0));
}
