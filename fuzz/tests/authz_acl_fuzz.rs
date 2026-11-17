//! Technique 06 — ACL / authorization enforcement (`common::authz`) —
//! proptest + `#[tokio::test]` against the real `axum` router.
//!
//! ## Target
//! `crates/affinidi-messaging-mediator/src/common/authz.rs` — `grants`,
//! `require_capability`, `check_permissions` (all `pub(crate)`). Every
//! handler in `handlers/{message_outbound,inbox_fetch,message_delete,
//! message_list}.rs` gates on `authz::require_capability(&session.acls,
//! Capability::Local)` as its first action; `message_list_handler`
//! additionally compares the requested `did_hash` path segment against
//! `session.did_hash` with `ConstantTimeEq` before touching storage, with
//! **no admin override** — a deliberate design point worth fuzzing for
//! role confusion specifically.
//!
//! ## Real entry point (no `pub(crate)` reach-around)
//! `POST /mediator/v1/fetch`, `POST /mediator/v1/outbound`,
//! `DELETE /mediator/v1/delete`, `GET /mediator/v1/list/{did_hash}/{folder}`
//! — all real routes on the real router (`handlers/mod.rs::
//! application_routes`), driven with sessions carrying proptest-generated
//! ACL bit combinations and account types, authenticated with genuinely
//! signed JWTs (see `tests/common/mod.rs`).
//!
//! ## Oracle (Tier 4 — role confusion / privilege escalation)
//! 1. The `Local` capability is the *sole* determinant of whether any of
//!    the four handlers' ACL gate fires, independent of every other ACL
//!    bit and of `account_type` (Standard/Admin/RootAdmin) — denial must
//!    carry `errorCode: 40` ("authorization.local") and HTTP 403.
//! 2. On `/list/{did_hash}/{folder}`, no `account_type` (`Standard`,
//!    `Admin`, or `RootAdmin`) may read a DID hash other than the
//!    authenticated session's own — this handler has no admin-override
//!    branch, so an admin session succeeding against a foreign `did_hash`
//!    would itself be the finding.

mod common;

use affinidi_messaging_mediator_common::types::acls::MediatorACLSet;
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use proptest::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn sign(pkcs8: &[u8], sub: &str, session_id: &str) -> String {
    let key = EncodingKey::from_ed_der(pkcs8);
    encode(
        &Header::new(Algorithm::EdDSA),
        &Claims {
            aud: "ATM".to_string(),
            sub: sub.to_string(),
            session_id: session_id.to_string(),
            exp: now() + 900,
        },
        &key,
    )
    .expect("sign")
}

/// Build a `MediatorACLSet` from independent bit choices (boundary-value
/// style: every corner of the 8-bit space is reachable, not just
/// ALLOW_ALL/DENY_ALL).
fn acl_from_bits(
    blocked: bool,
    local: bool,
    send_messages: bool,
    receive_messages: bool,
    send_forwarded: bool,
    receive_forwarded: bool,
    create_invites: bool,
    anon_receive: bool,
) -> MediatorACLSet {
    let mut acls = MediatorACLSet::default();
    acls.set_blocked(blocked);
    acls.set_local(local);
    let _ = acls.set_send_messages(send_messages, false, true);
    let _ = acls.set_receive_messages(receive_messages, false, true);
    let _ = acls.set_send_forwarded(send_forwarded, false, true);
    let _ = acls.set_receive_forwarded(receive_forwarded, false, true);
    let _ = acls.set_create_invites(create_invites, false, true);
    let _ = acls.set_anon_receive(anon_receive, false, true);
    acls
}

fn account_type_from_u8(n: u8) -> AccountType {
    match n % 3 {
        0 => AccountType::Standard,
        1 => AccountType::Admin,
        _ => AccountType::RootAdmin,
    }
}

async fn post_json(base_url: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .post(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request completed");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn delete_json(base_url: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .delete(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request completed");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn get(base_url: &str, path: &str, token: &str) -> (u16, Value) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .get(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request completed");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// Is this response specifically the `Capability::Local` denial (`errorCode
/// 40`, `authorization.local`)? Distinguishes the ACL gate under test from
/// any unrelated downstream 4xx (e.g. a body-shape validation error) that
/// would otherwise confound a bare status-code oracle.
fn is_local_denied(status: u16, body: &Value) -> bool {
    status == 403 && body.get("errorCode").and_then(Value::as_u64) == Some(40)
}

/// Is this response specifically the `/list` same-DID-only denial
/// (`errorCode 45`, `authorization.permission`)?
fn is_cross_did_denied(status: u16, body: &Value) -> bool {
    status == 403 && body.get("errorCode").and_then(Value::as_u64) == Some(45)
}

static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

static FIXTURE: tokio::sync::OnceCell<common::Fixture> = tokio::sync::OnceCell::const_new();
async fn fixture() -> &'static common::Fixture {
    FIXTURE.get_or_init(common::spawn).await
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Across the full 8-bit ACL space x 3 account types, the `Local`
    /// capability is the sole determinant of the `/fetch`, `/outbound`,
    /// `/delete` ACL gate — never any other bit, never account_type.
    #[test]
    fn local_capability_is_sole_gate_on_message_handlers(
        blocked in any::<bool>(),
        local in any::<bool>(),
        send_messages in any::<bool>(),
        receive_messages in any::<bool>(),
        send_forwarded in any::<bool>(),
        receive_forwarded in any::<bool>(),
        create_invites in any::<bool>(),
        anon_receive in any::<bool>(),
        account_type_n in any::<u8>(),
        handler in 0u8..3,
        did_suffix in "[a-z0-9]{4,12}",
    ) {
        rt().block_on(async {
            let fx = fixture().await;
            let acls = acl_from_bits(
                blocked, local, send_messages, receive_messages,
                send_forwarded, receive_forwarded, create_invites, anon_receive,
            );
            let account_type = account_type_from_u8(account_type_n);
            let did = format!("did:example:acl-{did_suffix}");
            let session_id = format!("sess-{did_suffix}");
            fx.register_session(&did, &session_id, acls.clone(), account_type).await;

            // A JWT-blocked ('blocked' bit) session can't even authenticate
            // (authenticate_token's NotBlocked gate fires first), so the
            // Capability::Local gate inside the handler is unreachable —
            // skip that combination here; it's covered by jwt_auth_fuzz's
            // blocked-ACL case instead.
            if blocked {
                return Ok(());
            }

            let token = sign(&fx.jwt_pkcs8, &did, &session_id);

            let (status, body) = match handler {
                0 => post_json(&fx.base_url, "fetch", &token, json!({"limit": 10, "start_id": null, "delete_policy": "DoNotDelete"})).await,
                1 => post_json(&fx.base_url, "outbound", &token, json!({"message_ids": [], "delete": false})).await,
                _ => delete_json(&fx.base_url, "delete", &token, json!({"message_ids": []})).await,
            };

            if local {
                prop_assert!(
                    !is_local_denied(status, &body),
                    "Local=true (account_type={:?}, other bits: blocked={} send_msg={} recv_msg={} send_fwd={} recv_fwd={} invites={} anon={}) must never hit the authorization.local gate; got status={} body={:?}",
                    account_type, blocked, send_messages, receive_messages, send_forwarded, receive_forwarded, create_invites, anon_receive, status, body
                );
            } else {
                prop_assert!(
                    is_local_denied(status, &body),
                    "Local=false must ALWAYS hit the authorization.local gate regardless of every other bit/account_type (account_type={:?}, send_msg={} recv_msg={} send_fwd={} recv_fwd={} invites={} anon={}); got status={} body={:?} -- a non-denial here is a privilege-escalation finding",
                    account_type, send_messages, receive_messages, send_forwarded, receive_forwarded, create_invites, anon_receive, status, body
                );
            }
            Ok(())
        })?;
    }

    /// Role-confusion / privilege-escalation oracle on `/list/{did_hash}/
    /// {folder}`: no account_type (including Admin/RootAdmin) may read a
    /// DID hash other than its own authenticated session's, because this
    /// handler's gate is a direct ConstantTimeEq against `session.did_hash`
    /// with no admin-override branch (unlike `authz::check_permissions`,
    /// which this handler deliberately does NOT call — see message_list.rs
    /// source comment on the PR #286 follow-up).
    #[test]
    fn list_handler_never_admits_cross_did_access_for_any_account_type(
        account_type_n in any::<u8>(),
        requester_suffix in "[a-z0-9]{4,10}",
        victim_suffix in "[a-z0-9]{4,10}",
        case_flip_victim_hash in any::<bool>(),
    ) {
        rt().block_on(async {
            let fx = fixture().await;
            if requester_suffix == victim_suffix {
                return Ok(()); // not a cross-DID case
            }
            let account_type = account_type_from_u8(account_type_n);
            let requester_did = format!("did:example:list-{requester_suffix}");
            let requester_session = format!("list-sess-{requester_suffix}");
            let local_allow_all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
            fx.register_session(&requester_did, &requester_session, local_allow_all, account_type).await;
            let token = sign(&fx.jwt_pkcs8, &requester_did, &requester_session);

            let victim_did = format!("did:example:list-{victim_suffix}");
            let mut victim_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&victim_did);
            if case_flip_victim_hash {
                // Same bytes under a different case -- ConstantTimeEq must
                // treat this as NOT equal (it compares raw bytes), so this
                // must deny exactly like any other foreign hash.
                victim_hash = victim_hash.to_uppercase();
            }

            let (status, body) = get(&fx.base_url, &format!("list/{victim_hash}/inbox"), &token).await;
            prop_assert!(
                is_cross_did_denied(status, &body),
                "account_type={:?} must never read another DID's folder (victim_hash={}, expected errorCode 45/403); got status={} body={:?}",
                account_type, victim_hash, status, body
            );
            Ok(())
        })?;
    }

    /// Control / non-regression: a session reading its OWN did_hash, with
    /// Local granted, must succeed (200) regardless of account_type —
    /// otherwise the two properties above would vacuously pass against a
    /// mediator that denies everyone.
    #[test]
    fn list_handler_admits_own_did_hash_for_any_account_type(
        account_type_n in any::<u8>(),
        suffix in "[a-z0-9]{4,10}",
    ) {
        rt().block_on(async {
            let fx = fixture().await;
            let account_type = account_type_from_u8(account_type_n);
            let did = format!("did:example:list-own-{suffix}");
            let session_id = format!("list-own-sess-{suffix}");
            let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
            fx.register_session(&did, &session_id, acls, account_type).await;
            let token = sign(&fx.jwt_pkcs8, &did, &session_id);
            let did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&did);

            let (status, body) = get(&fx.base_url, &format!("list/{did_hash}/inbox"), &token).await;
            prop_assert_eq!(status, 200, "own did_hash with Local granted must succeed; got body={:?}", body);
            Ok(())
        })?;
    }
}
