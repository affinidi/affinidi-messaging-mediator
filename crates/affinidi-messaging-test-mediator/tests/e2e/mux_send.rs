//! The mux `send` scope on the inbound path (design §5.5, §7.6).
//!
//! A frame on a principal's mux connection whose authenticated sender is a
//! member DID is accepted only when the connection carries that member with
//! `send`, and then it is the member's frame: the recipient sees the member as
//! sender and the member's counters move, never the principal's. A member
//! without `send`, or a DID that is not a member, is refused exactly as on any
//! socket (`authorization.did.session_mismatch`, a problem report to the
//! principal, the socket stays open). `send` admits sending only: a member's
//! message *to the mediator* (here a trust ping) is refused.

use crate::common;
use crate::common::now;
use crate::common::store_grant as grant;
use crate::forge;

use std::time::Duration;

use affinidi_crypto::jose::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::document::DocumentExt;
use affinidi_messaging_didcomm::jwe::encrypt;
use affinidi_messaging_didcomm::{Attachment, Message as DidcommMessage};
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use forge::b64;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use uuid::Uuid;

async fn key_agreement_public(env: &TestEnvironment, did: &str) -> (String, PublicKeyAgreement) {
    let doc = env.tdk.did_resolver().resolve(did).await.unwrap().doc;
    let kid = doc.find_key_agreement(None).first().unwrap().to_string();
    let kid = if kid.starts_with('#') {
        format!("{did}{kid}")
    } else {
        kid
    };
    let (_, bytes) = doc
        .get_verification_method(&kid)
        .unwrap()
        .decode_public_key()
        .unwrap();
    (
        kid,
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, &bytes).unwrap(),
    )
}

fn key_agreement_private(user: &TestUser) -> (String, PrivateKeyAgreement) {
    let secret = user
        .secrets
        .iter()
        .find(|secret| secret.id.ends_with("#key-2"))
        .unwrap();
    (
        secret.id.clone(),
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, secret.get_private_bytes()).unwrap(),
    )
}

/// Frames `from` would send on its own connection, built with its own keys.
struct Frames {
    /// A basic message to the recipient, authcrypted by `from` — a direct
    /// delivery envelope.
    direct: String,
    /// The same, inside a `forward` to the mediator authcrypted by `from`.
    forward: String,
    /// A trust ping to the mediator, authcrypted by `from`.
    ping: String,
}

async fn frames(env: &TestEnvironment, from: &TestUser, to: &TestUser, text: &str) -> Frames {
    let mediator_did = env.mediator.did().to_string();
    let (mediator_kid, mediator_public) = key_agreement_public(env, &mediator_did).await;
    let (to_kid, to_public) = key_agreement_public(env, &to.did).await;
    let (from_kid, from_private) = key_agreement_private(from);
    let t = now();

    let basic = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message",
        json!({ "content": text }),
    )
    .from(from.did.clone())
    .to(to.did.clone())
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let direct = encrypt::authcrypt(
        &basic.to_json().unwrap(),
        &from_kid,
        &from_private,
        &[(to_kid.as_str(), &to_public)],
    )
    .unwrap();

    let to_mediator = [(mediator_kid.as_str(), &mediator_public)];
    let fwd = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/routing/2.0/forward",
        json!({ "next": to.did }),
    )
    .from(from.did.clone())
    .to(mediator_did.clone())
    .expires_time(t + 60)
    .attachment(Attachment::base64(b64(direct.as_bytes())).finalize())
    .finalize();
    let forward = encrypt::authcrypt(
        &fwd.to_json().unwrap(),
        &from_kid,
        &from_private,
        &to_mediator,
    )
    .unwrap();

    let ping = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping",
        json!({ "response_requested": false }),
    )
    .from(from.did.clone())
    .to(mediator_did)
    .created_time(t)
    .expires_time(t + 60)
    .finalize();
    let ping = encrypt::authcrypt(
        &ping.to_json().unwrap(),
        &from_kid,
        &from_private,
        &to_mediator,
    )
    .unwrap();

    Frames {
        direct,
        forward,
        ping,
    }
}

/// `(from, content)` of every basic message in `user`'s inbox.
async fn inbox(env: &TestEnvironment, user: &TestUser) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for element in env
        .atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .unwrap()
        .success
    {
        let (msg, meta) = env
            .atm
            .unpack(&element.msg.unwrap_or_default())
            .await
            .expect("recipient unpacks its message");
        assert!(meta.authenticated, "the member's own authcrypt survives");
        out.push((
            msg.from.unwrap_or_default(),
            msg.body["content"].as_str().unwrap_or_default().to_string(),
        ));
    }
    out.sort();
    out
}

#[tokio::test]
async fn send_scope_admits_exactly_members_holding_it() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with mux");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let principal = env.add_user("device").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let reader = env.add_user("reader").await.unwrap();
    let stranger = env.add_user("stranger").await.unwrap();
    let recipient = env.add_user("recipient").await.unwrap();

    grant(&env, &sender, &principal, &["send"]).await;
    grant(&env, &reader, &principal, &["receive", "pickup", "delete"]).await;

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

    async fn next_doc(
        env: &TestEnvironment,
        ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
    ) -> DidcommMessage {
        loop {
            match timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame within 5s")
                .expect("socket open")
                .expect("frame")
            {
                Message::Text(t) => {
                    return env.atm.unpack(&t).await.expect("unpack frame").0;
                }
                _ => continue,
            }
        }
    }

    // `ready`, then `attached` naming both members.
    let ready = next_doc(&env, &mut ws).await;
    assert_eq!(ready.body["payload"]["event"], "ready");
    let attached = next_doc(&env, &mut ws).await;
    assert_eq!(attached.body["payload"]["event"], "attached");
    assert_eq!(
        attached.body["payload"]["dids"].as_array().unwrap().len(),
        2
    );

    let store = env.mediator.store();
    let sent =
        async |u: &TestUser| store.account_stats(&[u.did_hash()]).await.unwrap()[0].messages_sent;

    // (1) The member holding `send` sends on the principal's socket, both as a
    //     forward and as a direct-delivery envelope: delivered as the member.
    let f = frames(&env, &sender, &recipient, "forwarded by member").await;
    ws.send(Message::Text(f.forward.into())).await.unwrap();
    let f = frames(&env, &sender, &recipient, "direct by member").await;
    ws.send(Message::Text(f.direct.into())).await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), async {
        while got.len() < 2 {
            got = inbox(&env, &recipient).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("both member frames delivered; inbox: {got:?}"));
    assert_eq!(
        got,
        vec![
            (sender.did.clone(), "direct by member".to_string()),
            (sender.did.clone(), "forwarded by member".to_string()),
        ]
    );
    assert_eq!(sent(&sender).await, 2, "counted as the member's sends");
    assert_eq!(sent(&principal).await, 0, "not the principal's");

    // (2) A member without `send`, (3) a DID that is not a member, and a
    //     `send` member's message to the mediator itself: each refused with
    //     the problem report any socket gets for a foreign sender, and the
    //     socket stays open.
    let no_send = frames(&env, &reader, &recipient, "reader").await;
    let foreign = frames(&env, &stranger, &recipient, "stranger").await;
    let member_ping = frames(&env, &sender, &recipient, "unused").await.ping;
    for (name, frame) in [
        ("member without send: forward", no_send.forward),
        ("member without send: direct", no_send.direct),
        ("non-member: forward", foreign.forward),
        ("non-member: direct", foreign.direct),
        ("send member: ping to the mediator", member_ping),
    ] {
        ws.send(Message::Text(frame.into())).await.unwrap();
        let report = next_doc(&env, &mut ws).await;
        assert_eq!(
            report.typ, "https://didcomm.org/report-problem/2.0/problem-report",
            "{name}: {report:?}"
        );
        assert_eq!(report.to, Some(vec![principal.did.clone()]), "{name}");
        let code = report.body["code"].as_str().unwrap_or_default();
        assert!(
            code.ends_with("authorization.did.session_mismatch"),
            "{name}: refused as a foreign sender, got {code:?}"
        );
    }
    assert_eq!(
        inbox(&env, &recipient).await.len(),
        2,
        "nothing more delivered"
    );
    assert_eq!(sent(&reader).await, 0);
    assert_eq!(sent(&stranger).await, 0);

    // (4) The principal still sends as itself on the same socket.
    let own = frames(&env, &principal, &recipient, "from the principal").await;
    ws.send(Message::Text(own.forward.into())).await.unwrap();
    timeout(Duration::from_secs(5), async {
        while inbox(&env, &recipient).await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the principal's own message delivered");
    assert!(
        inbox(&env, &recipient)
            .await
            .contains(&(principal.did.clone(), "from the principal".to_string()))
    );
    assert_eq!(sent(&principal).await, 1);
    assert_eq!(sent(&sender).await, 2);

    // (5) `send` never outlives the member's own standing: once its ACLs stop
    //     allowing SEND_MESSAGES, its frames are refused on the principal's
    //     socket though the grant still names `send`.
    let mut acls = store
        .get_did_acl(&sender.did_hash())
        .await
        .unwrap()
        .expect("sender has an ACL record");
    acls.set_send_messages(false, false, true).unwrap();
    store.set_did_acl(&sender.did_hash(), &acls).await.unwrap();
    let f = frames(&env, &sender, &recipient, "after revocation").await;
    ws.send(Message::Text(f.forward.into())).await.unwrap();
    let report = next_doc(&env, &mut ws).await;
    assert!(
        report.body["code"]
            .as_str()
            .is_some_and(|c| c.ends_with("authorization.did.session_mismatch")),
        "{report:?}"
    );
    assert_eq!(inbox(&env, &recipient).await.len(), 3);
}

/// Raw TSP on the same socket goes through the same rule: a TSP Direct
/// message whose sender VID is a `send` member is stored as the member's, and
/// one from a member without `send` is refused.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn tsp_frames_follow_the_same_rule() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let principal = env.add_user("device").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let reader = env.add_user("reader").await.unwrap();
    let recipient = env.add_user("recipient").await.unwrap();
    env.relate_directly(&sender, &recipient).await.unwrap();
    env.relate_directly(&reader, &recipient).await.unwrap();
    grant(&env, &sender, &principal, &["send"]).await;
    grant(&env, &reader, &principal, &["receive"]).await;

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
        .unwrap();
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi-mux")
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.unwrap();

    let refused = env
        .atm
        .tsp()
        .pack(&reader.profile, &recipient.did, b"reader")
        .await
        .unwrap();
    ws.send(Message::Binary(refused.into())).await.unwrap();
    let report = loop {
        match timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5s")
            .unwrap()
            .unwrap()
        {
            Message::Text(t) => {
                let (m, _) = env.atm.unpack(&t).await.unwrap();
                if m.typ == "https://didcomm.org/report-problem/2.0/problem-report" {
                    break m;
                }
            }
            _ => continue,
        }
    };
    assert!(
        report.body["code"]
            .as_str()
            .is_some_and(|c| c.ends_with("authorization.did.session_mismatch")),
        "{report:?}"
    );

    let accepted = env
        .atm
        .tsp()
        .pack(&sender.profile, &recipient.did, b"sender")
        .await
        .unwrap();
    ws.send(Message::Binary(accepted.into())).await.unwrap();
    let stored = timeout(Duration::from_secs(5), async {
        loop {
            let got = env
                .atm
                .fetch_messages(&recipient.profile, &FetchOptions::default())
                .await
                .unwrap()
                .success;
            if !got.is_empty() {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the member's TSP frame is stored");
    assert_eq!(stored.len(), 1, "only the `send` member's frame");
    let (payload, from) = env
        .atm
        .tsp()
        .unpack(&recipient.profile, stored[0].msg.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(
        (payload.as_slice(), from.as_str()),
        (&b"sender"[..], sender.did.as_str())
    );
    let stats = env
        .mediator
        .store()
        .account_stats(&[sender.did_hash(), principal.did_hash()])
        .await
        .unwrap();
    assert_eq!(stats[0].messages_sent, 1, "the member's send");
    assert_eq!(stats[1].messages_sent, 0, "not the principal's");
}

/// Without mux, a socket refuses a frame another DID sent, as before.
#[tokio::test]
async fn a_plain_socket_still_refuses_a_foreign_sender() {
    init_tracing();
    let mediator = TestMediator::builder()
        .mux_enabled(true)
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let principal = env.add_user("device").await.unwrap();
    let sender = env.add_user("sender").await.unwrap();
    let recipient = env.add_user("recipient").await.unwrap();
    // A `send` grant exists, but this socket is not a mux connection.
    grant(&env, &sender, &principal, &["send"]).await;

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
        .unwrap();
    let ws_uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(ws_uri)
        .with_header("Authorization", format!("Bearer {}", tokens.access_token));
    let (mut ws, _) = connect_async(request).await.unwrap();

    let f = frames(&env, &sender, &recipient, "not on a mux socket").await;
    ws.send(Message::Text(f.forward.into())).await.unwrap();
    let report = loop {
        match timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame within 5s")
            .unwrap()
            .unwrap()
        {
            Message::Text(t) => {
                let (m, _) = env.atm.unpack(&t).await.unwrap();
                if m.typ == "https://didcomm.org/report-problem/2.0/problem-report" {
                    break m;
                }
            }
            _ => continue,
        }
    };
    let v: Value = report.body;
    assert!(
        v["code"]
            .as_str()
            .is_some_and(|c| c.ends_with("authorization.did.session_mismatch")),
        "{v:#}"
    );
    assert!(inbox(&env, &recipient).await.is_empty());
}
