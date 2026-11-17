//! Technique 07 — JWT verification via the WebSocket upgrade entry point
//! (`authenticate_token`, called from `handlers/websocket.rs:255`'s
//! `Sec-WebSocket-Protocol: bearer.<jwt>` path) — deterministic reachability
//! confirmation, raw-socket HTTP/1.1.
//!
//! ## Why this file is separate from `jwt_auth_fuzz.rs`
//! The brief names TWO real call sites for `authenticate_token`:
//! `jwt_auth.rs:282` (the `Authorization` header extractor, fuzzed
//! extensively in `jwt_auth_fuzz.rs` via `/whoami`) and
//! `handlers/websocket.rs:255` (the `Sec-WebSocket-Protocol: bearer.<jwt>`
//! subprotocol path browsers use, since `new WebSocket(...)` cannot set
//! request headers). Both call the exact same `pub(crate) async fn
//! authenticate_token` with the exact same `Session` result — per that
//! function's own doc comment — so the 600 proptest cases already run
//! against the header path exercise the identical verification logic. This
//! file is the complementary, deterministic proof that the SECOND entry
//! point is wired to the same function and rejects the same hostile inputs,
//! closing the "both real entry points" requirement without duplicating
//! the full fuzz volume.
//!
//! `reqwest` cannot perform a WebSocket upgrade, and `tokio_tungstenite`'s
//! client always offers the handshake correctly (no way to send a
//! deliberately-malformed-token subprotocol and still get a parseable HTTP
//! response through its API), so this writes the HTTP/1.1 upgrade request by
//! hand over a raw `TcpStream` and reads back the status line — exactly the
//! bytes a hostile non-browser client would send.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Serialize)]
struct Claims {
    aud: String,
    sub: String,
    session_id: String,
    exp: u64,
}

fn sign(pkcs8: &[u8], sub: &str, session_id: &str, exp: u64) -> String {
    let key = EncodingKey::from_ed_der(pkcs8);
    encode(
        &Header::new(Algorithm::EdDSA),
        &Claims {
            aud: "ATM".to_string(),
            sub: sub.to_string(),
            session_id: session_id.to_string(),
            exp,
        },
        &key,
    )
    .expect("sign")
}

/// Perform a raw HTTP/1.1 WebSocket upgrade request against `/ws` carrying
/// `token` as a `bearer.<token>` entry in `Sec-WebSocket-Protocol`, and
/// return the response's HTTP status code (101 on a successful upgrade,
/// whatever `AuthError::into_response()` produced otherwise). Reads only
/// the status line + headers, then drops the connection — sufficient to
/// observe the auth decision without completing a real WS handshake.
async fn ws_subprotocol_status(host: &str, port: u16, path: &str, token: &str) -> u16 {
    let mut stream = TcpStream::connect((host, port))
        .await
        .expect("connect to mediator");

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Protocol: bearer.{token}\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request (possible server-side panic/crash if this fails)");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until we have a full status line + header block, or the peer
    // closes the connection (which also answers the question: a dropped
    // connection with zero bytes is itself a Tier-1 finding).
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .expect("read response (possible server-side panic/crash)");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            break;
        }
    }
    assert!(
        !buf.is_empty(),
        "server closed the connection with zero bytes — possible panic in the WebSocket upgrade handler"
    );
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().expect("at least a status line");
    // "HTTP/1.1 401 Unauthorized" -> 401
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse status line: {status_line:?}"))
}

#[tokio::test]
async fn ws_subprotocol_entry_point_rejects_the_same_hostile_tokens() {
    let fx = common::spawn().await;
    let host = fx
        .base_url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    let port: u16 = fx
        .base_url
        .trim_start_matches("http://")
        .split(':')
        .nth(1)
        .unwrap()
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let ws_path = "/mediator/v1/ws";

    let did = "did:example:ws-user";
    let session_id = "ws-session";
    fx.register_session(
        did,
        session_id,
        affinidi_messaging_mediator_common::types::acls::MediatorACLSet::from_string_ruleset(
            "ALLOW_ALL",
        )
        .unwrap(),
        affinidi_messaging_mediator_common::types::accounts::AccountType::Standard,
    )
    .await;
    let n = now();

    // 1. Genuinely valid token over the Sec-WebSocket-Protocol path -> 101.
    let valid = sign(&fx.jwt_pkcs8, did, session_id, n + 900);
    assert_eq!(
        ws_subprotocol_status(&host, port, ws_path, &valid).await,
        101,
        "a genuinely valid token via Sec-WebSocket-Protocol must complete the upgrade"
    );

    // 2. Expired token -> same 401 the header path gives, not a bypass and
    //    not a crash.
    let expired = sign(&fx.jwt_pkcs8, did, session_id, n.saturating_sub(120));
    assert_eq!(
        ws_subprotocol_status(&host, port, ws_path, &expired).await,
        401,
        "an expired token via Sec-WebSocket-Protocol must be rejected, exactly as the header path is"
    );

    // 3. Tampered signature (bit-flip) -> 401, not a crash.
    let mut tampered = valid.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered = String::from_utf8_lossy(&tampered).to_string();
    assert_eq!(
        ws_subprotocol_status(&host, port, ws_path, &tampered).await,
        401,
        "a tampered signature via Sec-WebSocket-Protocol must be rejected"
    );

    // 4. Garbage (not a JWT at all) -> 401, not a crash/hang.
    assert_eq!(
        ws_subprotocol_status(&host, port, ws_path, "not-a-jwt-at-all").await,
        401
    );

    // 5. alg:none -> 401, not a bypass.
    {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64.encode(
            serde_json::json!({"aud":"ATM","sub":did,"session_id":session_id,"exp": n + 900})
                .to_string()
                .as_bytes(),
        );
        let none_tok = format!("{header}.{payload}.");
        assert_eq!(
            ws_subprotocol_status(&host, port, ws_path, &none_tok).await,
            401,
            "alg:none must never authenticate the WebSocket upgrade either"
        );
    }

    fx.shutdown();
}
