//! Fair queuing on a mux connection (design §7.2, "Back-pressure"): one
//! member flooding the connection must not starve another member's live
//! delivery on the same socket.
//!
//! The principal stops reading its socket while one member (`busy`) is sent
//! far more than the socket buffers can hold, so the mediator's writer stalls
//! and `busy`'s share of the send queue fills. A message for a second member
//! (`quiet`) then arrives. When the principal reads again:
//!
//! - `quiet`'s frame arrives live. Before fair queuing, the busy member owned
//!   the connection's whole queue, so it was dropped and only a pickup could
//!   find it.
//! - It is not stuck behind `busy`'s queued backlog: frames of `busy` still
//!   arrive after it, because the writer serves members round-robin.
//! - The resync for `busy`'s dropped pushes is `busy`'s, not the socket's: a
//!   pickup `status` for `busy`'s inbox, addressed to the principal; `quiet`
//!   is owed none.

use crate::common;
use crate::common::now;
use crate::common::store_grant as grant;

use std::time::{Duration, Instant};

use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use uuid::Uuid;

/// Messages sent to the busy member, and the size of each. Together far more
/// than loopback socket buffers hold, so the writer must stall.
const FLOOD: usize = 80;
const FLOOD_BYTES: usize = 256 * 1024;

/// The DIDs a packed DIDComm frame is encrypted to (its JWE recipient kids).
fn recipients(frame: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(frame).unwrap_or(Value::Null);
    v["recipients"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .filter_map(|r| r["header"]["kid"].as_str())
                .map(|kid| kid.split('#').next().unwrap_or(kid).to_string())
                .collect()
        })
        .unwrap_or_default()
}

async fn send(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) {
    let t = now();
    let msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.did.clone())
    .from(from.did.clone())
    .created_time(t)
    .expires_time(t + 120)
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
}

#[derive(Debug, PartialEq)]
enum Seen {
    Busy,
    Quiet,
    /// A pickup `status` to the principal, for this DID's inbox.
    Status(String),
    Other,
}

const FULL: &[&str] = &["receive", "pickup", "delete"];

#[tokio::test]
async fn a_flooded_member_does_not_starve_another_members_live_delivery() {
    flood(FULL).await;
}

/// A resync `status` is message pickup for that member's inbox, so a member
/// whose scope lacks `pickup` is never reported, however many of its pushes
/// dropped.
#[tokio::test]
async fn a_receive_only_member_is_owed_no_resync_status() {
    flood(&["receive"]).await;
}

/// Flood `busy` (granted `busy_scope`) while the principal stops reading,
/// then check that `quiet` is still served, and who is owed a resync.
async fn flood(busy_scope: &[&str]) {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .queue_send_limit_per_peer(-1)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let busy = env.add_user("busy").await.unwrap();
    let quiet = env.add_user("quiet").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    grant(&env, &busy, &principal, busy_scope).await;
    grant(&env, &quiet, &principal, FULL).await;

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

    // `ready`, then `attached` for both members.
    for want in ["ready", "attached"] {
        let frame = loop {
            match timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame within 5s")
                .expect("socket open")
                .expect("frame")
            {
                Message::Text(t) => break t.to_string(),
                _ => continue,
            }
        };
        let (msg, _) = env.atm.unpack(&frame).await.expect("unpack event");
        assert_eq!(msg.body["payload"]["event"], want);
    }

    // Stop reading, and flood the busy member.
    let filler = "x".repeat(FLOOD_BYTES);
    for i in 0..FLOOD {
        send(&env, &sender, &busy, &format!("{i}:{filler}")).await;
    }
    // Let the streaming task push (and drop) the flood before the quiet
    // member's message arrives behind it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    send(&env, &sender, &quiet, "for quiet").await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Read again, recording what arrives in order, until the socket is idle.
    let resumed = Instant::now();
    let mut seen = Vec::new();
    let mut quiet_after = None;
    while let Ok(Some(frame)) = timeout(Duration::from_secs(3), ws.next()).await {
        let Message::Text(text) = frame.expect("frame") else {
            continue;
        };
        let to = recipients(&text);
        let s = if to == [busy.did.clone()] {
            Seen::Busy
        } else if to == [quiet.did.clone()] {
            quiet_after.get_or_insert(resumed.elapsed());
            Seen::Quiet
        } else if to == [principal.did.clone()] {
            let (msg, _) = env.atm.unpack(&text).await.expect("unpack control");
            if msg.typ == "https://didcomm.org/messagepickup/3.0/status" {
                Seen::Status(msg.body["recipient_did"].as_str().unwrap_or("").to_string())
            } else {
                Seen::Other
            }
        } else {
            Seen::Other
        };
        seen.push(s);
    }

    let busy_live = seen.iter().filter(|s| **s == Seen::Busy).count();
    let summary: Vec<String> = seen
        .iter()
        .map(|s| match s {
            Seen::Busy => "B".to_string(),
            Seen::Quiet => "Q".to_string(),
            Seen::Status(d) if *d == busy.did => "S(busy)".to_string(),
            Seen::Status(d) => format!("S({d})"),
            Seen::Other => "?".to_string(),
        })
        .collect();
    let summary = summary.join(" ");

    // The flood really did congest the socket: not all of it was pushed.
    assert!(
        busy_live < FLOOD,
        "the flood must overrun the socket for this test to mean anything \
         ({busy_live}/{FLOOD} pushed live): {summary}"
    );

    // The quiet member's frame arrived live, promptly.
    let quiet_at = seen
        .iter()
        .position(|s| *s == Seen::Quiet)
        .unwrap_or_else(|| panic!("the quiet member's frame never arrived live: {summary}"));
    assert!(
        quiet_after.is_some_and(|d| d < Duration::from_secs(5)),
        "the quiet member's frame took {quiet_after:?}: {summary}"
    );

    // ... and was not queued behind the busy member's backlog: the writer
    // served it in turn, with busy frames still queued behind it.
    let busy_after_quiet = seen[quiet_at..]
        .iter()
        .filter(|s| **s == Seen::Busy)
        .count();
    assert!(
        busy_after_quiet > 0,
        "the quiet member's frame waited out the busy member's whole queue: {summary}"
    );

    // The resync is the busy member's: its inbox, addressed to the principal,
    // and only when its scope includes `pickup`.
    if busy_scope.contains(&"pickup") {
        assert!(
            seen.contains(&Seen::Status(busy.did.clone())),
            "the busy member is told to resync: {summary}"
        );
    } else {
        assert!(
            !seen.contains(&Seen::Status(busy.did.clone())),
            "a member without pickup is owed no status for its inbox: {summary}"
        );
    }
    assert!(
        !seen.contains(&Seen::Status(quiet.did.clone())),
        "the quiet member lost nothing and is owed no resync: {summary}"
    );
    assert!(
        !seen.contains(&Seen::Status(principal.did.clone())),
        "the principal lost nothing and is owed no resync: {summary}"
    );
}
