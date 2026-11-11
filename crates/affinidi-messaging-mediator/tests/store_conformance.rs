//! Backend-conformance suite for `MediatorStore` (mediator T15).
//!
//! Fjall and Redis must stay *semantically* aligned, but they can't share
//! code — the Redis logic lives in Lua. This suite expresses one set of
//! backend-agnostic semantic checks against an `Arc<dyn MediatorStore>` and
//! instantiates them against every in-process backend compiled in, so a
//! divergence between two independent implementations surfaces as a named
//! failing test (e.g. `fjall::message_store_and_counters`).
//!
//! Run it with the in-process backends enabled:
//! ```text
//! cargo test -p affinidi-messaging-mediator \
//!   --no-default-features --features didcomm,memory-backend,fjall-backend \
//!   --test store_conformance
//! ```
//!
//! Coverage (against **Memory** and **Fjall**) — eleven semantic areas:
//! account lifecycle; ACL set/get; message store + inbox counters;
//! forward-queue consumer-group claim/ack, delete, and autoclaim (crashed-
//! consumer recovery); session put/get/delete lifecycle; session-expiry sweep;
//! access-list add/count/remove/clear; access-list *mode* (allow-list vs
//! deny-list) evaluation; audit-log record + newest-first cursor pagination.
//!
//! Memory and Fjall agree on all of these, with **one documented divergence**
//! the suite surfaced: `sweep_expired_sessions`'s `now_secs` argument is
//! honored by Fjall (wall-clock) but ignored by Memory (monotonic `Instant`) —
//! benign in production, see `check_session_expiry_sweep` and the trait doc.
//!
//! The same checks also run against **Redis** under `redis-backend`, gated on a
//! `REDIS_URL` environment variable (CI sets it via a `redis:7` service; a plain
//! local `cargo test` without it skips them). Redis keys are global (no per-test
//! namespace), so each Redis check is pinned to its own logical DB index and
//! `FLUSHDB`-ed at setup — that gives the same fresh-store-per-test isolation the
//! in-process backends get for free. See `redis_backend` and `conformance_for_redis!`.

#![cfg(any(
    feature = "memory-backend",
    feature = "fjall-backend",
    feature = "redis-backend"
))]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::{
    ForwardQueueEntry, MessageMetaData, Session, SessionState, StreamingClientState,
};
use affinidi_messaging_mediator_common::store::{
    MediatorStore, RefreshRotation, TrustTaskClaim, mux,
};
use affinidi_messaging_mediator_common::types::accounts::{
    AccountStatsDelta, ActivityKind, StatsDirection, StatsWire,
};
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
use affinidi_messaging_sdk::protocols::mediator::{
    accounts::{Account, AccountType},
    acls::{AccessListModeType, MediatorACLSet},
};

/// Far-future expiry so stored messages don't lapse mid-test.
const NEVER: u64 = 9_999_999_999;

fn allow_all() -> MediatorACLSet {
    MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ALLOW_ALL ruleset")
}

/// A default ACL set with an explicit access-list `mode` applied.
fn acls_with_mode(mode: AccessListModeType) -> MediatorACLSet {
    let mut acls = MediatorACLSet::default();
    // admin = true so the bit can be set on a fresh set.
    acls.set_access_list_mode(mode, false, true)
        .expect("set_access_list_mode");
    acls
}

/// An admin session, used as the authority for account/message removal.
fn admin_session(admin_did_hash: &str) -> Session {
    Session {
        did_hash: admin_did_hash.to_string(),
        account_type: AccountType::RootAdmin,
        ..Default::default()
    }
}

/// Count a DID's access-list entries by paging `access_list_list`. The store
/// has no standalone count primitive (callers derive it from the listing or
/// from `account_get().access_list_count`); this mirrors that.
///
/// **Backend divergence in the terminal-cursor convention** (surfaced by this
/// suite): the in-process backends signal "no more pages" with `cursor: None`,
/// while Redis pages via `SSCAN`, whose terminal cursor is `0` — so it returns
/// `cursor: Some(0)`. Production never loops on this itself (the handler returns
/// the cursor straight to the client), so both conventions ship; a correct
/// cursor consumer must therefore treat **either `None` or `Some(0)`** as
/// terminal. A consumer that stops only on `None` loops forever against Redis.
/// See the `access_list_list` trait doc.
async fn access_list_len(store: &Arc<dyn MediatorStore>, did_hash: &str) -> usize {
    let mut total = 0;
    let mut cursor = 0u64;
    loop {
        let page = store
            .access_list_list(did_hash, cursor)
            .await
            .expect("access_list_list");
        total += page.did_hashes.len();
        match page.cursor {
            // `None` (in-process backends) or `0` (Redis/SSCAN) both mean done.
            None | Some(0) => break,
            Some(next) => cursor = next,
        }
    }
    total
}

// ─── Conformance checks (backend-agnostic) ──────────────────────────────────

/// Account create → exists → fetch → remove → gone.
async fn check_account_lifecycle(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_account_lifecycle";

    assert!(
        !store.account_exists(did).await.expect("account_exists"),
        "account must not exist before it is added"
    );
    // An anonymous session's DID hash is empty: no account, not an error.
    assert!(
        store
            .account_get("")
            .await
            .expect("account_get of an empty hash")
            .is_none(),
        "an empty DID hash names no account"
    );

    let added: Account = store
        .account_add(did, &allow_all(), None)
        .await
        .expect("account_add");
    assert_eq!(
        added.did_hash, did,
        "account_add returns the created account"
    );

    assert!(
        store.account_exists(did).await.expect("account_exists"),
        "account must exist after add"
    );
    let fetched = store
        .account_get(did)
        .await
        .expect("account_get")
        .expect("account present after add");
    assert_eq!(fetched.did_hash, did);

    let removed = store
        .account_remove(&admin_session("admin_hash"), did)
        .await
        .expect("account_remove");
    assert!(
        removed,
        "account_remove reports success for an existing account"
    );
    assert!(
        !store.account_exists(did).await.expect("account_exists"),
        "account must be gone after remove"
    );
}

/// `account_add` on an existing account does not change its role, ACLs,
/// limits, counters, activity or stats; `account_create` reports it as
/// existing and writes nothing; and of two concurrent creates exactly one
/// wins.
async fn check_account_add_keeps_existing_account(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_existing_account";
    let sender = "did_hash_existing_account_sender";
    let original = acls_with_mode(AccessListModeType::ExplicitAllow);

    store
        .account_create(did, &original, None)
        .await
        .expect("account_create")
        .expect("a new account is created");
    store
        .account_add(sender, &allow_all(), None)
        .await
        .expect("account_add sender");
    store
        .account_set_role(did, &AccountType::Admin)
        .await
        .expect("account_set_role");
    store
        .account_change_queue_limits(did, Some(7), Some(9))
        .await
        .expect("account_change_queue_limits");
    store
        .store_message(
            "session-id",
            "{\"protected\":\"keep\"}",
            did,
            Some(sender),
            NEVER,
            1000,
        )
        .await
        .expect("store_message");
    store
        .account_activity_record(did, ActivityKind::Received, 111)
        .await
        .expect("account_activity_record");
    store
        .account_stats_bump(
            did,
            AccountStatsDelta::new(StatsDirection::Received, StatsWire::DidComm, 10),
        )
        .await
        .expect("account_stats_bump");

    let before = store
        .account_get(did)
        .await
        .expect("account_get")
        .expect("account present");
    let ids = [did.to_string()];
    let activity_before = store.account_activity(&ids).await.expect("activity");
    let stats_before = store.account_stats(&ids).await.expect("stats");

    let other = MediatorACLSet::from_string_ruleset("DENY_ALL").expect("DENY_ALL");
    assert!(
        store
            .account_create(did, &other, Some(1))
            .await
            .expect("account_create on an existing account")
            .is_none(),
        "account_create reports an existing account and creates nothing"
    );
    let returned = store
        .account_add(did, &other, Some(1))
        .await
        .expect("account_add on an existing account");
    assert_eq!(
        returned.acls, before.acls,
        "account_add returns the existing account"
    );

    let after = store
        .account_get(did)
        .await
        .expect("account_get")
        .expect("account still present");
    assert_eq!(after._type, AccountType::Admin, "role unchanged");
    assert_eq!(after.acls, original.to_u64(), "ACLs unchanged");
    assert_eq!(
        after.queue_send_limit, before.queue_send_limit,
        "send limit unchanged"
    );
    assert_eq!(
        after.queue_receive_limit, before.queue_receive_limit,
        "receive limit unchanged"
    );
    assert_eq!(after.receive_queue_count, 1, "queued message still counted");
    assert_eq!(after.receive_queue_count, before.receive_queue_count);
    assert_eq!(after.receive_queue_bytes, before.receive_queue_bytes);
    assert_eq!(after.send_queue_count, before.send_queue_count);
    assert_eq!(after.send_queue_bytes, before.send_queue_bytes);
    assert_eq!(
        store.account_activity(&ids).await.expect("activity")[0].last_received,
        activity_before[0].last_received,
        "activity unchanged"
    );
    assert_eq!(
        store.account_stats(&ids).await.expect("stats")[0].messages_received,
        stats_before[0].messages_received,
        "stats unchanged"
    );

    // Two first-contact creates racing: one creates, the other sees it.
    let racing = "did_hash_racing_account";
    let acls = allow_all();
    let (a, b) = tokio::join!(
        store.account_create(racing, &acls, None),
        store.account_create(racing, &acls, None),
    );
    let created = [a.expect("create a"), b.expect("create b")]
        .iter()
        .filter(|r| r.is_some())
        .count();
    assert_eq!(created, 1, "exactly one concurrent create wins");
}

/// Storing a message for a sender with no account keeps its queue counters
/// but does not make it an account, in every backend: it is not found, listed
/// or given ACLs, `account_create` completes the record (keeping the
/// counters), and admin set-up on such a record leaves an account with ACLs.
async fn check_counters_only_record_is_not_an_account(store: Arc<dyn MediatorStore>) {
    let to = "did_hash_counters_only_recipient";
    let sender = "did_hash_counters_only_sender";
    let admin = "did_hash_counters_only_admin";
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");
    for from in [sender, admin] {
        store
            .store_message(
                "session-id",
                &format!("{{\"protected\":\"{from}\"}}"),
                to,
                Some(from),
                NEVER,
                1000,
            )
            .await
            .expect("store_message");
    }

    assert!(
        !store.account_exists(sender).await.expect("account_exists"),
        "a counters-only record is not an account"
    );
    assert!(
        store
            .account_get(sender)
            .await
            .expect("account_get")
            .is_none()
    );
    assert!(
        store
            .get_did_acl(sender)
            .await
            .expect("get_did_acl")
            .is_none()
    );
    assert!(
        store
            .get_did_acls(&[sender.to_string()], AccessListModeType::ExplicitDeny)
            .await
            .expect("get_did_acls")
            .acl_response
            .is_empty(),
        "a counters-only record has no ACL"
    );
    let listed = store.account_list(0, 100).await.expect("account_list");
    assert!(
        !listed.accounts.iter().any(|a| a.did_hash == sender),
        "a counters-only record is not listed"
    );
    assert_eq!(
        store
            .peer_queue_count(sender, to)
            .await
            .expect("peer_queue_count"),
        1,
        "the sender is still counted per relationship"
    );

    assert!(
        store
            .account_create(sender, &allow_all(), None)
            .await
            .expect("account_create")
            .is_some(),
        "account_create completes a counters-only record"
    );
    let created = store
        .account_get(sender)
        .await
        .expect("account_get")
        .expect("an account now");
    assert_eq!(created.acls, allow_all().to_u64(), "given ACLs applied");
    assert_eq!(created._type, AccountType::Standard);
    assert_eq!(created.send_queue_count, 1, "queued message still counted");

    store
        .setup_admin_account(admin, AccountType::Admin, &allow_all())
        .await
        .expect("setup_admin_account");
    let admin_account = store
        .account_get(admin)
        .await
        .expect("account_get")
        .expect("admin account present");
    assert_eq!(admin_account._type, AccountType::Admin);
    assert_eq!(
        admin_account.acls,
        allow_all().to_u64(),
        "an admin set up over a counters-only record has its ACLs"
    );
}

/// Setting a DID's ACL is read back verbatim.
async fn check_acl_set_get_roundtrip(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_acl_roundtrip";
    store
        .account_add(did, &MediatorACLSet::default(), None)
        .await
        .expect("account_add");

    let acls = allow_all();
    let written = store.set_did_acl(did, &acls).await.expect("set_did_acl");
    assert_eq!(
        written.to_u64(),
        acls.to_u64(),
        "set_did_acl returns the value it stored"
    );

    let read = store
        .get_did_acl(did)
        .await
        .expect("get_did_acl")
        .expect("ACL present after set");
    assert_eq!(
        read.to_u64(),
        acls.to_u64(),
        "get_did_acl reads back exactly what set_did_acl wrote"
    );
}

/// Storing a message updates the recipient's inbox counters; the message is
/// then individually retrievable.
async fn check_message_store_and_counters(store: Arc<dyn MediatorStore>) {
    let to = "did_hash_recipient_msg";
    let from = "did_hash_sender_msg";
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");

    let before = store.inbox_status(to).await.expect("inbox_status before");
    assert_eq!(before.message_count, 0, "inbox starts empty");

    let body = "{\"protected\":\"conformance-test-message\"}";
    let id = store
        .store_message("session-id", body, to, Some(from), NEVER, 1000)
        .await
        .expect("store_message");
    assert!(!id.is_empty(), "store_message returns a non-empty id");

    let after = store.inbox_status(to).await.expect("inbox_status after");
    assert_eq!(
        after.message_count, 1,
        "storing one message increments message_count"
    );
    assert!(
        after.total_bytes >= body.len() as u64,
        "total_bytes reflects the stored payload ({} >= {})",
        after.total_bytes,
        body.len()
    );

    let fetched = store
        .get_message(to, &id)
        .await
        .expect("get_message")
        .expect("stored message is retrievable by id");
    assert_eq!(
        fetched.msg_id, id,
        "fetched message id matches the stored id"
    );
    assert!(fetched.size > 0, "fetched message reports a non-zero size");
}

/// Forward-queue consumer-group semantics: enqueue → len → read (claim) →
/// ack. The claimed entry round-trips its addressing fields.
async fn check_forward_queue_claim_ack(store: Arc<dyn MediatorStore>) {
    assert_eq!(
        store.forward_queue_len().await.expect("forward_queue_len"),
        0,
        "forward queue starts empty"
    );

    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "relay-envelope".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    };
    let stream_id = store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");
    assert!(!stream_id.is_empty(), "enqueue assigns a stream id");

    assert_eq!(
        store.forward_queue_len().await.expect("forward_queue_len"),
        1,
        "len reflects the enqueued entry"
    );

    let claimed = store
        .forward_queue_read(
            "conformance-group",
            "consumer-1",
            10,
            Duration::from_millis(50),
        )
        .await
        .expect("forward_queue_read");
    assert_eq!(claimed.len(), 1, "read claims the one queued entry");
    let got = &claimed[0];
    assert_eq!(got.to_did, "did:peer:next");
    assert_eq!(got.endpoint_url, "https://peer.example.com/inbound");
    assert!(!got.stream_id.is_empty(), "read populates the stream id");

    let ids: Vec<&str> = claimed.iter().map(|e| e.stream_id.as_str()).collect();
    store
        .forward_queue_ack("conformance-group", &ids)
        .await
        .expect("forward_queue_ack");
}

/// Session put → get (found) → delete → get (gone). `get_session` joins the
/// session record with the DID account, so the account is created first.
async fn check_session_lifecycle(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_session_user";
    let did_hash = sha256::digest(did);
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add for session DID");

    let session = Session {
        session_id: "conformance-session-1".to_string(),
        did: did.to_string(),
        did_hash: did_hash.clone(),
        // A realistic state: production only ever persists sessions in a valid
        // state. Redis's `get_session` rejects `SessionState::Unknown` (the
        // `..Default::default()` value) as a corrupt pre-0.14 record, so a
        // backend-agnostic test must store a real state to round-trip on Redis.
        state: SessionState::Authenticated,
        ..Default::default()
    };
    store
        .put_session(&session, Duration::from_secs(300))
        .await
        .expect("put_session");

    let fetched = store
        .get_session(&session.session_id, did)
        .await
        .expect("get_session returns the stored session");
    assert_eq!(fetched.did, did, "round-tripped session keeps its DID");

    store
        .delete_session(&session.session_id)
        .await
        .expect("delete_session");
    assert!(
        store.get_session(&session.session_id, did).await.is_err(),
        "get_session must error once the session is deleted"
    );

    // A challenge is answered once: promoting needs the challenge session,
    // and a second promotion of it finds nothing to promote.
    assert!(
        store
            .update_session_authenticated(
                "conformance-no-such-challenge",
                "conformance-x",
                did,
                "r"
            )
            .await
            .is_err(),
        "promoting a session that does not exist must fail"
    );
    let challenge = Session {
        session_id: "conformance-challenge-1".to_string(),
        did: did.to_string(),
        did_hash: did_hash.clone(),
        state: SessionState::ChallengeSent,
        ..Default::default()
    };
    store
        .put_session(&challenge, Duration::from_secs(300))
        .await
        .expect("put_session (challenge)");
    store
        .update_session_authenticated(&challenge.session_id, "conformance-auth-1", did, "r1")
        .await
        .expect("first promotion");
    assert!(
        store
            .update_session_authenticated(&challenge.session_id, "conformance-auth-2", did, "r2")
            .await
            .is_err(),
        "a second promotion of the same challenge must fail"
    );
    assert!(
        store.get_session("conformance-auth-2", did).await.is_err(),
        "the failed promotion leaves no session behind"
    );
    assert_eq!(
        store
            .get_session("conformance-auth-1", did)
            .await
            .expect("promoted session")
            .state,
        SessionState::Authenticated
    );

    // Updating the refresh hash of a session that has ended must not bring
    // it back.
    store
        .delete_session("conformance-auth-1")
        .await
        .expect("delete_session");
    assert!(
        store
            .update_refresh_token_hash("conformance-auth-1", "r3")
            .await
            .is_err(),
        "updating an ended session must fail"
    );
    assert!(store.get_session("conformance-auth-1", did).await.is_err());
}

/// Access-list add → count → list → remove → clear.
async fn check_access_list_lifecycle(store: Arc<dyn MediatorStore>) {
    let owner = "did_hash_access_list_owner";
    store
        .account_add(owner, &allow_all(), None)
        .await
        .expect("account_add owner");

    assert_eq!(
        access_list_len(&store, owner).await,
        0,
        "access list starts empty"
    );

    let sender = "did_hash_listed_sender".to_string();
    store
        .access_list_add(1000, owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_add");
    assert_eq!(
        access_list_len(&store, owner).await,
        1,
        "count reflects the added entry"
    );

    store
        .access_list_remove(owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_remove");
    assert_eq!(
        access_list_len(&store, owner).await,
        0,
        "count returns to zero after remove"
    );

    // Clear is idempotent on an already-empty list.
    store
        .access_list_clear(owner)
        .await
        .expect("access_list_clear");
    assert_eq!(access_list_len(&store, owner).await, 0);

    // The limit holds below, at and above it, the same on every backend.
    let limited = "did_hash_access_list_limited";
    let batch = |from: usize, n: usize| -> Vec<String> {
        (from..from + n)
            .map(|i| format!("did_hash_member_{i}"))
            .collect()
    };

    let empty = store
        .access_list_add(3, limited, &[])
        .await
        .expect("access_list_add with nothing to add");
    assert!(empty.did_hashes.is_empty() && !empty.truncated);

    let below = store
        .access_list_add(3, limited, &batch(0, 2))
        .await
        .expect("access_list_add below the limit");
    assert_eq!(below.did_hashes, batch(0, 2));
    assert!(!below.truncated);

    let to_limit = store
        .access_list_add(3, limited, &batch(2, 3))
        .await
        .expect("access_list_add across the limit");
    assert_eq!(
        to_limit.did_hashes,
        batch(2, 1),
        "only the room left is used"
    );
    assert!(to_limit.truncated);
    assert_eq!(access_list_len(&store, limited).await, 3);

    let at_limit = store
        .access_list_add(3, limited, &batch(5, 2))
        .await
        .expect("access_list_add at the limit");
    assert!(at_limit.did_hashes.is_empty(), "a full list takes nothing");
    assert!(at_limit.truncated);
    assert_eq!(access_list_len(&store, limited).await, 3);

    // A limit lowered below the current size adds nothing and does not fail.
    let above = store
        .access_list_add(1, limited, &batch(7, 1))
        .await
        .expect("access_list_add over a lowered limit");
    assert!(above.did_hashes.is_empty() && above.truncated);
    assert_eq!(access_list_len(&store, limited).await, 3);
    store
        .access_list_clear(limited)
        .await
        .expect("access_list_clear");

    // One request larger than the whole limit adds the first `limit` hashes.
    let oversized = store
        .access_list_add(3, limited, &batch(100, 50))
        .await
        .expect("access_list_add larger than the limit");
    assert_eq!(oversized.did_hashes, batch(100, 3));
    assert!(oversized.truncated);
    assert_eq!(access_list_len(&store, limited).await, 3);
    store
        .access_list_clear(limited)
        .await
        .expect("access_list_clear");
}

/// Forward-queue: an unread enqueued entry can be deleted directly, dropping
/// the queue length back to zero.
async fn check_forward_queue_delete(store: Arc<dyn MediatorStore>) {
    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "to-delete".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    };
    let stream_id = store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");
    assert_eq!(store.forward_queue_len().await.expect("len"), 1);

    store
        .forward_queue_delete(&[stream_id.as_str()])
        .await
        .expect("forward_queue_delete");
    assert_eq!(
        store.forward_queue_len().await.expect("len after delete"),
        0,
        "deleting the entry empties the queue"
    );
}

/// Forward-queue autoclaim: an entry claimed by one consumer and left idle is
/// reclaimable by another (the recovery path for a crashed consumer).
async fn check_forward_queue_autoclaim(store: Arc<dyn MediatorStore>) {
    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "to-reclaim".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    };
    store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");

    // Consumer 1 claims it, then leaves it pending (no ack).
    let claimed = store
        .forward_queue_read("g", "consumer-1", 10, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    assert_eq!(claimed.len(), 1, "consumer-1 claims the entry");

    // Consumer 2 reclaims anything idle beyond zero — i.e. the pending entry.
    let reclaimed = store
        .forward_queue_autoclaim("g", "consumer-2", Duration::ZERO, 10, "0-0")
        .await
        .expect("forward_queue_autoclaim")
        .entries;
    assert_eq!(
        reclaimed.len(),
        1,
        "consumer-2 reclaims the idle pending entry"
    );

    let ids: Vec<&str> = reclaimed.iter().map(|e| e.stream_id.as_str()).collect();
    store.forward_queue_ack("g", &ids).await.expect("ack");
}

/// Forward-queue claim refresh: the holder can keep an entry from going idle,
/// so another consumer's autoclaim does not take it; a refresh by anyone else
/// moves nothing and reports the entry as not theirs; an entry that is done
/// is reported too.
async fn check_forward_queue_refresh_claims(store: Arc<dyn MediatorStore>) {
    let group = "refresh-g";
    let mut ours = Vec::new();
    for message in ["refresh-kept", "refresh-done"] {
        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: message.to_string(),
            to_did_hash: "next_hash".to_string(),
            from_did_hash: "from_hash".to_string(),
            from_did: "did:peer:from".to_string(),
            to_did: "did:peer:next".to_string(),
            endpoint_url: "https://peer.example.com/inbound".to_string(),
            received_at_ms: 1,
            delay_milli: 0,
            expires_at: NEVER,
            retry_count: 0,
            hop_count: 1,
            not_before_ms: 0,
        };
        ours.push(
            store
                .forward_queue_enqueue(&entry, 0)
                .await
                .expect("forward_queue_enqueue"),
        );
    }
    // The group reads from the start of the queue, which on a shared Redis DB
    // may hold other checks' entries; only ours are used below.
    let claimed = store
        .forward_queue_read(group, "holder", 1000, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    for id in &ours {
        assert!(
            claimed.iter().any(|e| &e.stream_id == id),
            "the holder claims {id}"
        );
    }
    let kept = ours[0].as_str();
    let done = ours[1].as_str();
    store
        .forward_queue_ack_and_delete(group, &[done])
        .await
        .expect("ack and delete");

    // Another consumer's refresh moves nothing and owns nothing.
    let lost = store
        .forward_queue_refresh_claims(group, "bystander", &[kept])
        .await
        .expect("refresh by a bystander");
    assert_eq!(lost, vec![kept.to_string()], "not the bystander's");

    // The holder still holds the one it kept, and not the one it finished.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let lost = store
        .forward_queue_refresh_claims(group, "holder", &[kept, done])
        .await
        .expect("refresh by the holder");
    assert_eq!(
        lost,
        vec![done.to_string()],
        "the finished entry is not held"
    );

    // Just refreshed, so it is not idle long enough for another to take.
    let taken = store
        .forward_queue_autoclaim(group, "bystander", Duration::from_millis(200), 1000, "0-0")
        .await
        .expect("autoclaim")
        .entries;
    assert!(
        taken.iter().all(|e| e.stream_id != kept),
        "a refreshed claim is not reclaimed"
    );

    // Left alone, it goes idle and is reclaimable; then the holder has lost it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let taken = store
        .forward_queue_autoclaim(group, "bystander", Duration::from_millis(200), 1000, "0-0")
        .await
        .expect("autoclaim")
        .entries;
    assert!(
        taken.iter().any(|e| e.stream_id == kept),
        "reclaimed once idle"
    );
    let lost = store
        .forward_queue_refresh_claims(group, "holder", &[kept])
        .await
        .expect("refresh after losing it");
    assert_eq!(lost, vec![kept.to_string()], "taken over by the bystander");

    store
        .forward_queue_ack_and_delete(group, &[kept])
        .await
        .expect("ack and delete");
}

fn forward_entry_for_check(message: &str) -> ForwardQueueEntry {
    ForwardQueueEntry {
        stream_id: String::new(),
        message: message.to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
        not_before_ms: 0,
    }
}

/// Forward-queue autoclaim pages: idle entries behind a long run of held,
/// refreshed ones are still reached by following the cursor. One call
/// examines only a bounded stretch of the pending list (on Redis, ten times
/// the count), so a sweep that stopped at the first empty page would never
/// get past the held head.
async fn check_forward_queue_autoclaim_pages_past_held_entries(store: Arc<dyn MediatorStore>) {
    let group = "paging-g";
    let mut ours = Vec::new();
    for i in 0..300 {
        ours.push(
            store
                .forward_queue_enqueue(&forward_entry_for_check(&format!("paging-{i}")), 0)
                .await
                .expect("forward_queue_enqueue"),
        );
    }
    let claimed = store
        .forward_queue_read(group, "holder", 10_000, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    assert!(
        ours.iter()
            .all(|id| claimed.iter().any(|e| &e.stream_id == id))
    );

    // The head stays busy; the last few go idle.
    let (head, tail) = ours.split_at(ours.len() - 5);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let head_ids: Vec<&str> = head.iter().map(String::as_str).collect();
    let lost = store
        .forward_queue_refresh_claims(group, "holder", &head_ids)
        .await
        .expect("refresh the head");
    assert!(lost.is_empty());

    let mut cursor = "0-0".to_string();
    let mut reclaimed = Vec::new();
    let mut pages = 0;
    loop {
        let page = store
            .forward_queue_autoclaim(group, "sweeper", Duration::from_millis(200), 5, &cursor)
            .await
            .expect("forward_queue_autoclaim");
        pages += 1;
        if pages == 1 {
            assert!(
                page.entries.iter().all(|e| !tail.contains(&e.stream_id)),
                "the first page cannot reach past the held head"
            );
        }
        reclaimed.extend(page.entries.into_iter().map(|e| e.stream_id));
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
        assert!(pages < 1_000, "the scan must end");
    }
    let mut reclaimed_ours: Vec<&String> =
        reclaimed.iter().filter(|id| ours.contains(id)).collect();
    reclaimed_ours.sort();
    let mut expected: Vec<&String> = tail.iter().collect();
    expected.sort();
    assert_eq!(
        reclaimed_ours, expected,
        "exactly the idle tail is reclaimed"
    );

    let ids: Vec<&str> = ours.iter().map(String::as_str).collect();
    store
        .forward_queue_ack_and_delete(group, &ids)
        .await
        .expect("ack and delete");
}

/// Forward-queue finish: only the consumer holding an entry can finish it,
/// and a finish with a replacement writes the replacement only then.
async fn check_forward_queue_finish_is_owner_conditional(store: Arc<dyn MediatorStore>) {
    let group = "finish-g";
    let first = store
        .forward_queue_enqueue(&forward_entry_for_check("finish-first"), 0)
        .await
        .expect("forward_queue_enqueue");
    let second = store
        .forward_queue_enqueue(&forward_entry_for_check("finish-second"), 0)
        .await
        .expect("forward_queue_enqueue");
    let claimed = store
        .forward_queue_read(group, "holder", 10_000, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    let first_entry = claimed
        .iter()
        .find(|e| e.stream_id == first)
        .expect("holder claims the first")
        .clone();

    // A bystander cannot finish what the holder holds.
    assert!(
        !store
            .forward_queue_finish(group, "bystander", &first, None)
            .await
            .expect("finish by a bystander")
    );
    let lost = store
        .forward_queue_refresh_claims(group, "holder", &[&first])
        .await
        .expect("refresh");
    assert!(lost.is_empty(), "the holder still holds it");

    // The holder replaces it with a retry, in one step.
    let mut retry = first_entry.clone();
    retry.retry_count = 1;
    assert!(
        store
            .forward_queue_finish(group, "holder", &first, Some(&retry))
            .await
            .expect("finish with a retry")
    );
    let lost = store
        .forward_queue_refresh_claims(group, "holder", &[&first])
        .await
        .expect("refresh");
    assert_eq!(lost, vec![first.clone()], "the original is gone");
    let next = store
        .forward_queue_read(group, "holder", 10_000, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    let replacement = next
        .iter()
        .find(|e| e.message == "finish-first")
        .expect("the retry is queued");
    assert_eq!(replacement.retry_count, 1);

    // Once another consumer has taken an entry over, the old holder's finish
    // changes nothing, retry or not; the new holder's does.
    let mut cursor = "0-0".to_string();
    loop {
        let page = store
            .forward_queue_autoclaim(group, "bystander", Duration::ZERO, 1_000, &cursor)
            .await
            .expect("forward_queue_autoclaim");
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert!(
        !store
            .forward_queue_finish(group, "holder", &second, Some(&retry))
            .await
            .expect("finish after a takeover")
    );
    assert!(
        store
            .forward_queue_finish(group, "bystander", &second, None)
            .await
            .expect("finish by the new holder")
    );
    assert!(
        store
            .forward_queue_finish(group, "bystander", &replacement.stream_id, None)
            .await
            .expect("finish the retry")
    );
    let after = store
        .forward_queue_read(group, "holder", 10_000, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    assert!(
        after.iter().all(|e| !e.message.starts_with("finish-")),
        "the refused finish queued no second retry"
    );
}

/// Session-expiry: a session whose TTL has lapsed is reclaimed by
/// `sweep_expired_sessions`, so `get_session` then errors. Both in-process
/// backends must agree on this (the trait default is a no-op, so each
/// overrides it).
///
/// DOCUMENTED DIVERGENCE (surfaced by this suite): the `now_secs` argument is
/// **not** honored uniformly. `FjallStore` (and Redis) treat it as the
/// wall-clock cutoff and sweep records whose stored `expires_at_unix <=
/// now_secs`. `MemoryStore` ignores `now_secs` entirely and sweeps against its
/// own monotonic `Instant::now()` (matching its lazy-expiry path). In
/// production this is benign — the `session_expiry_sweep` task always passes
/// the real clock, so both reclaim the same lapsed sessions — but a caller
/// that passed a *synthetic* `now_secs` (as a naive test would) would see
/// Fjall act on it and Memory not. This test therefore lets the TTL lapse in
/// real time so both backends agree regardless of how they read `now_secs`.
async fn check_session_expiry_sweep(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_expiry_user";
    let did_hash = sha256::digest(did);
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add");

    let session = Session {
        session_id: "conformance-expiring-session".to_string(),
        did: did.to_string(),
        did_hash,
        // Valid state so Redis's `get_session` accepts the record (see
        // `check_session_lifecycle`); the in-process backends ignore it.
        state: SessionState::Authenticated,
        ..Default::default()
    };
    store
        .put_session(&session, Duration::from_secs(1))
        .await
        .expect("put_session");
    assert!(
        store.get_session(&session.session_id, did).await.is_ok(),
        "session is present before its 1s TTL lapses"
    );

    // Let the 1-second TTL lapse in real (monotonic *and* wall-clock) time, so
    // both the Instant-based (Memory) and now_secs-based (Fjall) sweeps agree.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    store
        .sweep_expired_sessions(NEVER)
        .await
        .expect("sweep_expired_sessions");
    assert!(
        store.get_session(&session.session_id, did).await.is_err(),
        "session is gone after the sweep reclaims the lapsed record"
    );
}

/// Access-list *mode* evaluation: `ExplicitAllow` is an allow-list (only listed
/// senders may send), `ExplicitDeny` is a deny-list (only listed senders are
/// blocked). The two backends must agree on this gate — it is the per-recipient
/// authorization the mediator enforces on every delivery.
async fn check_access_list_mode_semantics(store: Arc<dyn MediatorStore>) {
    let listed = "did_hash_listed_sender".to_string();
    let unlisted = "did_hash_unlisted_sender";

    // ExplicitAllow (allow-list): listed → allowed, unlisted → denied.
    let allow_owner = "did_hash_allowlist_owner";
    store
        .account_add(
            allow_owner,
            &acls_with_mode(AccessListModeType::ExplicitAllow),
            None,
        )
        .await
        .expect("add allow-list owner");
    store
        .access_list_add(1000, allow_owner, std::slice::from_ref(&listed))
        .await
        .expect("add to allow-list");
    assert!(
        store.access_list_allowed(allow_owner, Some(&listed)).await,
        "allow-list admits a listed sender"
    );
    assert!(
        !store.access_list_allowed(allow_owner, Some(unlisted)).await,
        "allow-list rejects an unlisted sender"
    );

    // ExplicitDeny (deny-list): listed → denied, unlisted → allowed.
    let deny_owner = "did_hash_denylist_owner";
    store
        .account_add(
            deny_owner,
            &acls_with_mode(AccessListModeType::ExplicitDeny),
            None,
        )
        .await
        .expect("add deny-list owner");
    store
        .access_list_add(1000, deny_owner, std::slice::from_ref(&listed))
        .await
        .expect("add to deny-list");
    assert!(
        !store.access_list_allowed(deny_owner, Some(&listed)).await,
        "deny-list rejects a listed sender"
    );
    assert!(
        store.access_list_allowed(deny_owner, Some(unlisted)).await,
        "deny-list admits an unlisted sender"
    );
}

/// `delivery_decision` must answer exactly what the three calls it replaces
/// would have: `None` for an unknown recipient (standing in for
/// `account_exists`), the recipient's stored ACL set (standing in for
/// `get_did_acl`), and a verdict identical to `access_list_allowed`.
///
/// The direct-delivery path now trusts this single call for all three facts,
/// and backends are free to implement it as one batched read, so a backend
/// whose optimised version drifts from the generic path would silently change
/// who may deliver to whom. Pinning it against `access_list_allowed` on the
/// same store keeps the fast path honest.
async fn check_delivery_decision_matches_access_list(store: Arc<dyn MediatorStore>) {
    let listed = "did_hash_dd_listed".to_string();
    let unlisted = "did_hash_dd_unlisted";

    // Unknown recipient → None. This is what replaces the `account_exists`
    // probe, so it has to be a *distinguishable* answer, not a denying one.
    assert!(
        store
            .delivery_decision("did_hash_dd_nobody", Some(&listed))
            .await
            .expect("delivery_decision on unknown recipient")
            .is_none(),
        "unknown recipient yields None"
    );

    // Both access-list modes, and for each: a listed sender, an unlisted
    // sender, and an anonymous sender (whose verdict comes from anon_receive
    // rather than the list).
    for mode in [
        AccessListModeType::ExplicitAllow,
        AccessListModeType::ExplicitDeny,
    ] {
        let owner = match mode {
            AccessListModeType::ExplicitAllow => "did_hash_dd_allow_owner",
            AccessListModeType::ExplicitDeny => "did_hash_dd_deny_owner",
        };
        let acls = acls_with_mode(mode);
        store
            .account_add(owner, &acls, None)
            .await
            .expect("add delivery-decision owner");
        store
            .access_list_add(1000, owner, std::slice::from_ref(&listed))
            .await
            .expect("add to access list");

        for sender in [Some(listed.as_str()), Some(unlisted), None] {
            let decision = store
                .delivery_decision(owner, sender)
                .await
                .expect("delivery_decision")
                .expect("known recipient yields Some");

            assert_eq!(
                decision.acls.to_u64(),
                acls.to_u64(),
                "returns the recipient's stored ACL set (owner={owner}, sender={sender:?})"
            );
            assert_eq!(
                decision.access_list_allows,
                store.access_list_allowed(owner, sender).await,
                "verdict matches access_list_allowed (owner={owner}, sender={sender:?})"
            );
        }
    }
}

// ─── Backend instantiation + test generation ────────────────────────────────

/// A constructed backend plus anything that must outlive it (Fjall's temp dir).
struct Backend {
    store: Arc<dyn MediatorStore>,
    #[allow(dead_code)]
    keepalive: Option<Box<dyn std::any::Any>>,
}

/// Build a backend, run its `initialize()` (a no-op for the in-process
/// backends, Lua-script load for Redis), and hand back the ready store.
async fn ready(backend: Backend) -> Arc<dyn MediatorStore> {
    backend.store.initialize().await.expect("store initialize");
    backend.store
}

#[cfg(feature = "memory-backend")]
fn memory_backend() -> Backend {
    use affinidi_messaging_mediator::store::MemoryStore;
    Backend {
        store: Arc::new(MemoryStore::new()),
        keepalive: None,
    }
}

#[cfg(feature = "fjall-backend")]
fn fjall_backend() -> Backend {
    use affinidi_messaging_mediator::store::FjallStore;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Arc::new(FjallStore::open(dir.path()).expect("FjallStore::open"));
    Backend {
        store,
        keepalive: Some(Box::new(dir)),
    }
}

/// Build a Redis-backed store on a dedicated logical DB (`db_index`), or `None`
/// when `REDIS_URL` is unset so a plain `cargo test` skips the Redis checks
/// instead of failing on a missing server. CI sets `REDIS_URL` to a `redis:7`
/// service and runs every index.
///
/// Isolation: Redis keys are global (counters, the forward-queue stream,
/// `SCHEMA_MIGRATIONS`), so two checks sharing a DB would interfere. Each check
/// gets its own index and a `FLUSHDB` here wipes anything a prior run left —
/// reproducing the fresh-store-per-test guarantee the in-process backends have.
#[cfg(feature = "redis-backend")]
async fn redis_backend(db_index: u8) -> Option<Backend> {
    Some(Backend {
        store: Arc::new(redis_store_flushed(db_index).await?),
        keepalive: None,
    })
}

/// A `RedisStore` on logical DB `db_index`, flushed; `None` without `REDIS_URL`.
#[cfg(feature = "redis-backend")]
async fn redis_store_flushed(
    db_index: u8,
) -> Option<affinidi_messaging_mediator::store::RedisStore> {
    let store = redis_store(db_index).await?;
    // Wipe this logical DB so the check starts from a clean keyspace. Loaded
    // Lua FUNCTIONs are server-global, not per-DB, so FLUSHDB doesn't disturb
    // them (and `initialize()` reloads them anyway).
    flush_db(&store).await;
    Some(store)
}

/// A Redis store on logical DB `db_index`, left as it is, or `None` when
/// `REDIS_URL` is unset.
#[cfg(feature = "redis-backend")]
async fn redis_store(db_index: u8) -> Option<affinidi_messaging_mediator::store::RedisStore> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis conformance (db {db_index}): REDIS_URL not set");
            return None;
        }
    };
    // Append the DB index as the URL path component Redis reads as `SELECT`.
    let database_url = format!("{}/{db_index}", base.trim_end_matches('/'));

    // The mediator's own Lua functions — the Redis backend can't operate
    // without them. `initialize()` (called by `ready`) loads this file.
    let functions_file = concat!(env!("CARGO_MANIFEST_DIR"), "/conf/atm-functions.lua").to_string();

    let config = DatabaseConfig {
        functions_file: Some(functions_file.clone()),
        database_url,
        database_timeout: 2,
        // CI's cluster job runs the same checks against a cluster-mode server.
        cluster_mode: std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true"),
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };

    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL — is the server reachable?");
    Some(RedisStore::new(
        handler,
        config.circuit_breaker_threshold,
        config.circuit_breaker_recovery_secs,
        config.functions_file.clone(),
    ))
}

#[cfg(feature = "redis-backend")]
async fn flush_db(store: &affinidi_messaging_mediator::store::RedisStore) {
    let mut conn = store.get_connection().await.expect("redis connection");
    // `::redis` — the extern crate, not the sibling `mod redis` this suite's
    // test-generation macro creates (which would shadow a bare `redis::`).
    ::redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .expect("FLUSHDB");
}

/// The Redis start-up path the mediator runs before serving: schema
/// migrations, then the mediator and root-admin accounts. It runs on every
/// start, so a second run must succeed too.
#[cfg(feature = "redis-backend")]
async fn check_redis_startup(store: &affinidi_messaging_mediator::store::RedisStore) {
    use affinidi_messaging_mediator_common::store::redis::RedisInitConfig;

    let config = RedisInitConfig {
        mediator_did_hash: "did_hash_startup_mediator".to_string(),
        admin_did: "did:example:startup_admin".to_string(),
        global_acl_default: allow_all(),
    };
    for _ in 0..2 {
        store
            .initialize_redis(&config)
            .await
            .expect("initialize_redis");
    }

    let admin_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&config.admin_did);
    assert!(
        store
            .check_admin_account(&admin_hash)
            .await
            .expect("check_admin_account"),
        "the root admin is an admin after start-up"
    );
    let mediator = store
        .account_get(&config.mediator_did_hash)
        .await
        .expect("account_get")
        .expect("the mediator account exists after start-up");
    assert_eq!(mediator._type, AccountType::Mediator);
}

/// Audit log: recording, newest-first ordering, cursor pagination, and
/// round-trip fidelity of a record. (The bounded-ring trim at
/// `AUDIT_LOG_MAX_ENTRIES` is not exercised here — filling it would cost tens of
/// thousands of writes; the trim is small and reviewed at each backend.)
async fn check_audit_log_lifecycle(store: Arc<dyn MediatorStore>) {
    // Fresh store: empty, terminal cursor.
    let page = store.audit_log_list(0, 100).await.expect("list empty");
    assert!(page.entries.is_empty(), "fresh store has no audit entries");
    assert_eq!(page.cursor, 0);

    // Record five entries in order 0..5.
    for i in 0..5u64 {
        let entry = AuditLogEntry {
            timestamp: 1000 + i,
            actor_did_hash: format!("admin{i}"),
            target_did_hash: format!("target{i}"),
            action: AuditAction::SetAcl,
            detail: format!("entry {i}"),
        };
        store.audit_log_record(&entry).await.expect("record");
    }

    // Single page: newest-first (entry 4 first, entry 0 last), cursor exhausted.
    let page = store.audit_log_list(0, 100).await.expect("list all");
    assert_eq!(page.entries.len(), 5);
    assert_eq!(page.entries[0].detail, "entry 4");
    assert_eq!(page.entries[4].detail, "entry 0");
    assert_eq!(page.cursor, 0, "single page exhausts the log");

    // Round-trip fidelity of the newest record.
    assert_eq!(page.entries[0].actor_did_hash, "admin4");
    assert_eq!(page.entries[0].target_did_hash, "target4");
    assert_eq!(page.entries[0].action, AuditAction::SetAcl);
    assert_eq!(page.entries[0].timestamp, 1004);

    // Pagination, 2 per page, newest-first across page boundaries.
    let p0 = store.audit_log_list(0, 2).await.expect("page 0");
    assert_eq!(
        p0.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 4", "entry 3"]
    );
    assert_ne!(p0.cursor, 0, "more pages remain");

    let p1 = store.audit_log_list(p0.cursor, 2).await.expect("page 1");
    assert_eq!(
        p1.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 2", "entry 1"]
    );
    assert_ne!(p1.cursor, 0);

    let p2 = store.audit_log_list(p1.cursor, 2).await.expect("page 2");
    assert_eq!(
        p2.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 0"]
    );
    assert_eq!(p2.cursor, 0, "last page is terminal");
}

/// OOB discovery invitation: store → get (round-trips invite + DID) → delete →
/// get-is-gone, plus delete-of-missing reports `false`.
///
/// Regression guard for the Redis backend: its `oob_discovery_get` and
/// `oob_discovery_delete` trait methods previously recursed into themselves
/// (no inherent method of the same name existed), so the first call to either
/// stack-overflowed. Driving the round-trip against every backend — Redis
/// included — would have surfaced that immediately.
async fn check_oob_discovery_roundtrip(store: Arc<dyn MediatorStore>) {
    let did_hash = "did_hash_oob_roundtrip";
    let invite_b64 = "eyJvb2IiOiJpbnZpdGUtcGF5bG9hZCJ9";
    // Far-future absolute expiry (year 2100) so the invite is live on every
    // backend: Redis stamps it with `EXPIREAT`, the in-process backends keep it
    // while `expires_at > now`.
    let expires_at = 4_102_444_800u64;

    let oob_id = store
        .oob_discovery_store(did_hash, invite_b64, expires_at)
        .await
        .expect("oob_discovery_store");

    let got = store
        .oob_discovery_get(&oob_id)
        .await
        .expect("oob_discovery_get")
        .expect("invite present after store");
    assert_eq!(
        got,
        (invite_b64.to_string(), did_hash.to_string()),
        "oob_discovery_get round-trips (invite, did_hash)"
    );

    assert!(
        store
            .oob_discovery_delete(&oob_id)
            .await
            .expect("oob_discovery_delete"),
        "delete reports success for a stored invite"
    );

    assert!(
        store
            .oob_discovery_get(&oob_id)
            .await
            .expect("oob_discovery_get after delete")
            .is_none(),
        "invite is gone after delete"
    );

    assert!(
        !store
            .oob_discovery_delete(&oob_id)
            .await
            .expect("oob_discovery_delete missing"),
        "deleting a missing invite reports false"
    );
}

/// DIDComm v1 routing-key index: the bridge from a v1 forward's base58 verkey
/// to the DID everything else in the mediator is keyed by.
///
/// The exclusivity assertion is the load-bearing one. If a verkey could be
/// bound by two accounts, any account could claim another's routing key and
/// capture its inbound v1 traffic — so a backend that lets the second bind
/// through is not merely lax, it is a delivery-hijack primitive.
async fn check_v1_routing_keys(store: Arc<dyn MediatorStore>) {
    assert!(
        store.supports_v1_routing_keys(),
        "an in-tree backend must implement the v1 routing-key index"
    );

    // Bindings carry the DID; the reverse index is keyed by its hash. Both
    // forms appear here because forward ingress needs the DID while account
    // removal works from the hash.
    let alice = "did:example:v1_alice";
    let bob = "did:example:v1_bob";
    let alice_hash = sha256::digest(alice.as_bytes());
    let bob_hash = sha256::digest(bob.as_bytes());
    let verkey = "3hLMcPh9X6vtEJfuJmCinWRHAYFMjea1cfLA2eCvWA5A";
    let other = "9tovpLUbsf4mzkP1YVaZK31W7iWvcetc24QrnfhiFkkN";

    store
        .account_add(&alice_hash, &allow_all(), None)
        .await
        .expect("add alice");
    store
        .account_add(&bob_hash, &allow_all(), None)
        .await
        .expect("add bob");

    assert_eq!(
        store.v1_routing_key_lookup(verkey).await.expect("lookup"),
        None,
        "an unbound verkey must not resolve"
    );

    store
        .v1_routing_key_bind(verkey, alice)
        .await
        .expect("bind");
    assert_eq!(
        store.v1_routing_key_lookup(verkey).await.expect("lookup"),
        Some(alice.to_string())
    );

    // Re-binding to the same owner is idempotent.
    store
        .v1_routing_key_bind(verkey, alice)
        .await
        .expect("re-bind by the same owner is idempotent");

    // ...but another account may not take it.
    assert!(
        store.v1_routing_key_bind(verkey, bob).await.is_err(),
        "a verkey bound to one account must not be claimable by another"
    );
    assert_eq!(
        store.v1_routing_key_lookup(verkey).await.expect("lookup"),
        Some(alice.to_string()),
        "the failed claim must not have changed the owner"
    );

    // A conditional unbind removes the binding only for its owner.
    assert!(
        !store
            .v1_routing_key_unbind_if_owner(verkey, bob)
            .await
            .expect("conditional unbind"),
        "a conditional unbind by another account must report false"
    );
    assert_eq!(
        store.v1_routing_key_lookup(verkey).await.expect("lookup"),
        Some(alice.to_string()),
        "a conditional unbind by another account must leave the binding"
    );
    let third = "6QHqHQvwwh8xbgzNnUCsYaNbfAMSqUGkGkSFHqDu9dXq";
    store
        .v1_routing_key_bind(third, alice)
        .await
        .expect("bind third");
    assert!(
        store
            .v1_routing_key_unbind_if_owner(third, alice)
            .await
            .expect("conditional unbind"),
        "a conditional unbind by the owner removes the binding"
    );
    assert_eq!(
        store.v1_routing_key_lookup(third).await.expect("lookup"),
        None
    );
    assert!(
        !store
            .v1_routing_keys_for(&alice_hash)
            .await
            .expect("keys_for")
            .contains(&third.to_string()),
        "a conditionally unbound key leaves the owner's index"
    );

    // Reverse index.
    store
        .v1_routing_key_bind(other, alice)
        .await
        .expect("bind second");
    let mut expected = vec![other.to_string(), verkey.to_string()];
    expected.sort();
    assert_eq!(
        store
            .v1_routing_keys_for(&alice_hash)
            .await
            .expect("keys_for"),
        expected,
        "both of alice's verkeys must be listed, in a stable order"
    );
    assert!(
        store
            .v1_routing_keys_for(&bob_hash)
            .await
            .expect("keys_for")
            .is_empty(),
        "bob owns no routing keys"
    );

    // Unbind is reported truthfully and frees the verkey for another account.
    assert!(store.v1_routing_key_unbind(other).await.expect("unbind"));
    assert!(
        !store
            .v1_routing_key_unbind(other)
            .await
            .expect("unbind twice"),
        "unbinding an already-unbound verkey reports false"
    );
    store
        .v1_routing_key_bind(other, bob)
        .await
        .expect("a released verkey may be claimed by another account");

    // Removing an account drops its bindings, or its verkeys keep resolving to
    // a mailbox that no longer exists.
    store
        .account_remove(&admin_session("admin_hash"), &alice_hash)
        .await
        .expect("account_remove");
    assert_eq!(
        store.v1_routing_key_lookup(verkey).await.expect("lookup"),
        None,
        "a removed account's routing keys must stop resolving"
    );
    assert!(
        store
            .v1_routing_keys_for(&alice_hash)
            .await
            .expect("keys_for")
            .is_empty(),
        "a removed account owns no routing keys"
    );
    assert_eq!(
        store.v1_routing_key_lookup(other).await.expect("lookup"),
        Some(bob.to_string()),
        "removing one account must not disturb another's bindings"
    );
}

/// The Trust Task duplicate-execution record: first claim wins, the same
/// document again is a duplicate, a different document under the same key is a
/// conflict, keys are independent, and a lapsed record is gone. The lapse uses
/// the real clock because Redis expires keys on wall time.
async fn check_trust_task_claim(store: Arc<dyn MediatorStore>) {
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let t = now();
    let long = t + 600;

    assert_eq!(
        store.trust_task_claim("k1", "d1", long, t).await.unwrap(),
        TrustTaskClaim::Fresh
    );
    assert_eq!(
        store.trust_task_claim("k1", "d1", long, t).await.unwrap(),
        TrustTaskClaim::Duplicate,
        "the same document again must not run twice"
    );
    assert_eq!(
        store.trust_task_claim("k1", "d2", long, t).await.unwrap(),
        TrustTaskClaim::Conflict,
        "a different document under a used id must be refused"
    );
    assert_eq!(
        store.trust_task_claim("k2", "d1", long, t).await.unwrap(),
        TrustTaskClaim::Fresh,
        "keys are independent"
    );

    // A record that has lapsed is absent: the key can be claimed afresh.
    assert_eq!(
        store.trust_task_claim("k3", "d1", t + 1, t).await.unwrap(),
        TrustTaskClaim::Fresh
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let later = now();
    store
        .sweep_expired_trust_task_claims(later)
        .await
        .expect("sweep");
    assert_eq!(
        store
            .trust_task_claim("k3", "d9", later + 600, later)
            .await
            .unwrap(),
        TrustTaskClaim::Fresh,
        "a lapsed record must not block a new claim"
    );
    // …and the sweep left live records alone.
    assert_eq!(
        store
            .trust_task_claim("k1", "d1", long, later)
            .await
            .unwrap(),
        TrustTaskClaim::Duplicate
    );
}

/// The observed expiry sweep reports each message it removes, with the
/// metadata it had, and nothing it leaves.
async fn check_expiry_sweep_reports_each_message(store: Arc<dyn MediatorStore>) {
    use std::sync::Mutex;
    let to = "did_hash_recipient_expiry";
    let from = "did_hash_sender_expiry";
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body = "{\"protected\":\"expiring\"}";
    let expiring = store
        .store_message("s", body, to, Some(from), now - 10, 1000)
        .await
        .expect("store expiring");
    let kept = store
        .store_message("s", "{\"protected\":\"kept\"}", to, Some(from), NEVER, 1000)
        .await
        .expect("store kept");

    // Readable by id on every backend (Redis read a key nothing wrote).
    let meta = store
        .get_message_metadata(to, &expiring)
        .await
        .expect("metadata");
    assert_eq!(meta.to_did_hash, to);
    assert_eq!(meta.from_did_hash.as_deref(), Some(from));

    let seen: Mutex<Vec<(String, MessageMetaData)>> = Mutex::new(Vec::new());
    let observe = |id: &str, meta: &MessageMetaData| {
        seen.lock().unwrap().push((id.to_string(), meta.clone()));
    };
    let report = store
        .sweep_expired_messages_observed(now, "did_hash_admin_expiry", Some(&observe))
        .await
        .expect("sweep");
    assert_eq!(report.expired, 1, "{report:?}");

    let seen = seen.into_inner().unwrap();
    assert_eq!(seen.len(), 1, "only the expired message is reported");
    let (id, meta) = &seen[0];
    assert_eq!(id, &expiring);
    assert_eq!(meta.to_did_hash, to);
    assert_eq!(meta.from_did_hash.as_deref(), Some(from));
    assert!(meta.bytes >= body.len(), "{} >= {}", meta.bytes, body.len());

    assert!(store.get_message(to, &expiring).await.unwrap().is_none());
    assert!(store.get_message(to, &kept).await.unwrap().is_some());

    // The sweep unlisted what it removed: a second pass finds nothing.
    let again = store
        .sweep_expired_messages(now, "did_hash_admin_expiry")
        .await
        .expect("second sweep");
    assert_eq!((again.expired, again.already_deleted), (0, 0), "{again:?}");
}

/// Store four messages for the outbox-receipt checks: three from `from` and one
/// anonymous, all to `to`.
async fn receipt_fixture(
    store: &Arc<dyn MediatorStore>,
    to: &str,
    from: &str,
    tag: &str,
) -> [String; 4] {
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");
    store
        .account_add(from, &allow_all(), None)
        .await
        .expect("account_add sender");
    let mut ids = Vec::new();
    for (label, sender) in [
        ("collected", Some(from)),
        ("withdrawn", Some(from)),
        ("discarded", Some(from)),
        ("anonymous", None),
    ] {
        let body = format!("{{\"protected\":\"receipts-{tag}-{label}\"}}");
        ids.push(
            store
                .store_message("s", &body, to, sender, NEVER, 1000)
                .await
                .expect("store_message"),
        );
    }
    ids.try_into().expect("four ids")
}

/// Remove the fixture's messages: the first by the recipient, the second by
/// the sender, the third by the mediator, the fourth (anonymous) by the
/// recipient.
async fn remove_receipt_fixture(
    store: &Arc<dyn MediatorStore>,
    ids: &[String; 4],
    to: &str,
    from: &str,
    admin: &str,
) {
    use affinidi_messaging_mediator_common::store::DeletionAuthority;
    let owner = |did: &str| DeletionAuthority::Owner {
        did_hash: did.to_string(),
    };
    let admin = DeletionAuthority::Admin {
        admin_did_hash: admin.to_string(),
    };
    for (id, by) in [
        (&ids[0], owner(to)),
        (&ids[1], owner(from)),
        (&ids[2], admin),
        (&ids[3], owner(to)),
    ] {
        store.delete_message(id, by).await.expect("delete_message");
    }
}

/// Outbox receipts (`messaging/message/status/0.1`): a sender learns why each
/// of its messages left the queue, from who removed it, and nobody else learns
/// anything.
async fn check_outbox_receipts(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::{RemovalReason, SentMessageState};
    let (to, from, admin) = (
        "did_hash_recipient_receipts",
        "did_hash_sender_receipts",
        "did_hash_admin_receipts",
    );
    let fixture = receipt_fixture(&store, to, from, "reasons").await;
    let mut ids = fixture.to_vec();
    ids.push("no-such-message".to_string());
    let reason = |state: SentMessageState| match state {
        SentMessageState::Removed(receipt) => Some(receipt.reason),
        _ => None,
    };

    // Held: queued to its sender, unknown to everyone else — the recipient
    // included, since it did not send it.
    let states = store.sent_message_states(from, &ids).await.expect("states");
    assert_eq!(states[0], SentMessageState::Queued, "{states:?}");
    assert_eq!(
        states[3],
        SentMessageState::Unknown,
        "anonymous: {states:?}"
    );
    assert_eq!(states[4], SentMessageState::Unknown, "{states:?}");
    let recipient_view = store.sent_message_states(to, &ids).await.expect("states");
    assert!(
        recipient_view
            .iter()
            .all(|s| *s == SentMessageState::Unknown),
        "{recipient_view:?}"
    );

    // Handed over, not yet removed.
    store
        .mark_delivered(to, &ids[..1], 1_700_000_000_000, 0)
        .await
        .expect("mark_delivered");
    let states = store.sent_message_states(from, &ids).await.expect("states");
    assert_eq!(
        states[0],
        SentMessageState::Delivered {
            at_ms: 1_700_000_000_000
        },
        "{states:?}"
    );

    // Removed: the reason is who removed it.
    remove_receipt_fixture(&store, &fixture, to, from, admin).await;
    let states = store.sent_message_states(from, &ids).await.expect("states");
    assert_eq!(
        reason(states[0]),
        Some(RemovalReason::Collected),
        "{states:?}"
    );
    assert_eq!(
        reason(states[1]),
        Some(RemovalReason::Withdrawn),
        "{states:?}"
    );
    assert_eq!(
        reason(states[2]),
        Some(RemovalReason::Discarded),
        "{states:?}"
    );
    assert_eq!(
        states[3],
        SentMessageState::Unknown,
        "an anonymous message leaves no receipt: {states:?}"
    );
    assert_eq!(states[4], SentMessageState::Unknown, "{states:?}");

    // The receipts are the sender's alone.
    let recipient_view = store.sent_message_states(to, &ids).await.expect("states");
    assert!(
        recipient_view
            .iter()
            .all(|s| *s == SentMessageState::Unknown),
        "{recipient_view:?}"
    );
}

/// Purges and account removal give senders the receipt matching who removed
/// the messages: an owner purging its own inbox collected them; an admin
/// purging someone else's, or the mediator removing the account, discarded
/// them. (Both of the latter used to read as `collected`.)
async fn check_purge_and_removal_receipts(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::{
        DeletionAuthority, PurgeFilter, RemovalReason, SentMessageState,
    };
    use affinidi_messaging_mediator_common::types::messages::Folder;
    let admin = DeletionAuthority::Admin {
        admin_did_hash: "did_hash_admin_purge".into(),
    };
    async fn first_reason(
        store: &Arc<dyn MediatorStore>,
        from: &str,
        ids: &[String; 4],
    ) -> Option<RemovalReason> {
        let states = store
            .sent_message_states(from, &ids[..1])
            .await
            .expect("states");
        match states[0] {
            SentMessageState::Removed(receipt) => Some(receipt.reason),
            _ => None,
        }
    }

    let (to, from) = ("did_hash_rcpt_own_purge", "did_hash_sndr_own_purge");
    let ids = receipt_fixture(&store, to, from, "own-purge").await;
    store
        .purge_folder("s", to, Folder::Inbox)
        .await
        .expect("purge");
    assert_eq!(
        first_reason(&store, from, &ids).await,
        Some(RemovalReason::Collected),
        "the owner purging its own inbox collected them"
    );

    let (to, from) = ("did_hash_rcpt_admin_purge", "did_hash_sndr_admin_purge");
    let ids = receipt_fixture(&store, to, from, "admin-purge").await;
    store
        .purge_folder_by("s", to, Folder::Inbox, admin.clone())
        .await
        .expect("purge");
    assert_eq!(
        first_reason(&store, from, &ids).await,
        Some(RemovalReason::Discarded),
        "an admin purge is not a collection"
    );

    let (to, from) = (
        "did_hash_rcpt_admin_filtered",
        "did_hash_sndr_admin_filtered",
    );
    let ids = receipt_fixture(&store, to, from, "admin-filtered").await;
    store
        .purge_folder_filtered_by(to, Folder::Inbox, &PurgeFilter::default(), admin)
        .await
        .expect("filtered purge");
    assert_eq!(
        first_reason(&store, from, &ids).await,
        Some(RemovalReason::Discarded),
        "an admin filtered purge is not a collection"
    );

    // The trait's default `purge_folder_by`, which a backend gets if it does
    // not override it, honours the authority too (every backend here
    // overrides it, so call the default's body directly).
    let (to, from) = ("did_hash_rcpt_default_by", "did_hash_sndr_default_by");
    let ids = receipt_fixture(&store, to, from, "default-by").await;
    let (purged, _) = affinidi_messaging_mediator_common::store::purge_folder_by_listing(
        store.as_ref(),
        "s",
        to,
        Folder::Inbox,
        DeletionAuthority::Admin {
            admin_did_hash: "did_hash_admin_purge".into(),
        },
    )
    .await
    .expect("default purge");
    assert_eq!(purged, 4, "the default purge empties the folder");
    assert_eq!(
        first_reason(&store, from, &ids).await,
        Some(RemovalReason::Discarded),
        "the default purge_folder_by honours the authority"
    );

    let (to, from) = ("did_hash_rcpt_removed", "did_hash_sndr_removed");
    let ids = receipt_fixture(&store, to, from, "removed").await;
    store
        .account_remove(&admin_session("did_hash_admin_purge"), to)
        .await
        .expect("account_remove");
    assert_eq!(
        first_reason(&store, from, &ids).await,
        Some(RemovalReason::Discarded),
        "removing the recipient's account is not a collection"
    );
}

/// Receipts are dropped once their retention has passed. In-process backends
/// only: Redis expires them on the key's own TTL, which a sweep with a
/// far-future clock cannot advance.
#[cfg(any(feature = "memory-backend", feature = "fjall-backend"))]
async fn check_outbox_receipt_retention(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::{OUTBOX_RECEIPT_TTL, SentMessageState};
    let (to, from, admin) = (
        "did_hash_recipient_retention",
        "did_hash_sender_retention",
        "did_hash_admin_retention",
    );
    let fixture = receipt_fixture(&store, to, from, "retention").await;
    remove_receipt_fixture(&store, &fixture, to, from, admin).await;
    let states = store
        .sent_message_states(from, &fixture)
        .await
        .expect("states");
    assert!(
        matches!(states[0], SentMessageState::Removed(_)),
        "{states:?}"
    );

    let after_retention = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + OUTBOX_RECEIPT_TTL.as_secs()
        + 60;
    store
        .sweep_expired_messages(after_retention, admin)
        .await
        .expect("sweep");
    // The sweep removed them; a lookup now would also filter them by expiry,
    // but only at wall-clock time, so this reads what the sweep left.
    let states = store
        .sent_message_states(from, &fixture)
        .await
        .expect("states");
    assert!(
        states.iter().all(|s| *s == SentMessageState::Unknown),
        "{states:?}"
    );
}

/// Configuration overrides round-trip, replace as a whole, and start absent.
async fn check_config_overrides(store: Arc<dyn MediatorStore>) {
    assert_eq!(store.config_overrides_get().await.unwrap(), None);
    store
        .config_overrides_set(r#"{"limits.listed_messages":7}"#)
        .await
        .expect("set");
    assert_eq!(
        store.config_overrides_get().await.unwrap().as_deref(),
        Some(r#"{"limits.listed_messages":7}"#)
    );
    store.config_overrides_set("{}").await.expect("clear");
    assert_eq!(
        store.config_overrides_get().await.unwrap().as_deref(),
        Some("{}")
    );
}

/// did:scid source records (VTI-KEY-162): stored per account, replaced on a
/// later put, listed back for seeding the resolver at boot, and removed with
/// the account.
async fn check_scid_sources(store: Arc<dyn MediatorStore>) {
    assert!(store.scid_source_list().await.unwrap().is_empty());

    store
        .scid_source_put("hash-a", r#"{"did":"a","v":1}"#)
        .await
        .unwrap();
    store
        .scid_source_put("hash-b", r#"{"did":"b","v":1}"#)
        .await
        .unwrap();
    // A later record for the same account replaces the earlier one.
    store
        .scid_source_put("hash-a", r#"{"did":"a","v":2}"#)
        .await
        .unwrap();

    let mut listed = store.scid_source_list().await.unwrap();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            r#"{"did":"a","v":2}"#.to_string(),
            r#"{"did":"b","v":1}"#.to_string(),
        ]
    );

    // Removing an account removes its record, so the store never holds more
    // records than there are accounts.
    store
        .account_add("hash-b", &allow_all(), None)
        .await
        .expect("account_add");
    store
        .scid_source_put("hash-b", r#"{"did":"b","v":2}"#)
        .await
        .unwrap();
    assert!(
        store
            .account_remove(&admin_session("admin_hash"), "hash-b")
            .await
            .expect("account_remove")
    );
    assert_eq!(
        store.scid_source_list().await.unwrap(),
        vec![r#"{"did":"a","v":2}"#.to_string()]
    );
}

/// Admin set-up (twice: it runs on every start) → demote → promote → bulk
/// promote and strip → removing an admin account. Demotion must take effect.
async fn check_admin_roles(store: Arc<dyn MediatorStore>) {
    let admin = "did_hash_admin_roles";
    let other = "did_hash_admin_roles_other";
    let is_admin = |did: &'static str| {
        let store = store.clone();
        async move {
            store
                .check_admin_account(did)
                .await
                .expect("check_admin_account")
        }
    };

    for _ in 0..2 {
        store
            .setup_admin_account(admin, AccountType::Admin, &allow_all())
            .await
            .expect("setup_admin_account");
    }
    assert!(is_admin(admin).await, "a set-up admin is an admin");

    store
        .account_set_role(admin, &AccountType::Standard)
        .await
        .expect("account_set_role standard");
    assert!(!is_admin(admin).await, "a demoted admin is not an admin");
    let demoted = store.account_get(admin).await.expect("account_get");
    assert_eq!(
        demoted.expect("account present")._type,
        AccountType::Standard
    );

    store
        .account_set_role(admin, &AccountType::Admin)
        .await
        .expect("account_set_role admin");
    assert!(is_admin(admin).await, "a promoted account is an admin");

    store
        .account_add(other, &allow_all(), None)
        .await
        .expect("account_add other");
    store
        .add_admin_accounts(vec![other.to_string()], &allow_all())
        .await
        .expect("add_admin_accounts");
    assert!(is_admin(other).await, "a bulk-promoted account is an admin");

    store
        .strip_admin_accounts(vec![admin.to_string(), other.to_string()])
        .await
        .expect("strip_admin_accounts");
    assert!(!is_admin(admin).await, "stripped accounts are not admins");
    assert!(!is_admin(other).await, "stripped accounts are not admins");

    // Removing an admin account strips its admin rights on the way out.
    store
        .account_set_role(other, &AccountType::Admin)
        .await
        .expect("account_set_role admin");
    assert!(
        store
            .account_remove(&admin_session("root_admin_hash"), other)
            .await
            .expect("account_remove admin"),
        "an admin account can be removed"
    );
    assert!(!store.account_exists(other).await.expect("account_exists"));
}

/// A challenge session is readable before its DID has an account (accounts
/// are created only once the challenge is answered), and it can be promoted
/// to an authenticated session.
async fn check_challenge_session_without_account(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_unregistered_user";
    let challenge_id = "conformance-unregistered-challenge";
    store
        .create_session(&Session {
            session_id: challenge_id.to_string(),
            challenge: "conformance-challenge".to_string(),
            state: SessionState::ChallengeSent,
            did: did.to_string(),
            did_hash: sha256::digest(did),
            ..Default::default()
        })
        .await
        .expect("create_session");
    assert!(
        !store
            .account_exists(&sha256::digest(did))
            .await
            .expect("account_exists"),
        "creating a challenge session must not create an account"
    );
    let session = store
        .get_session(challenge_id, did)
        .await
        .expect("a challenge session is readable without an account");
    assert_eq!(session.did, did);
    assert_eq!(session.state, SessionState::ChallengeSent);

    store
        .update_session_authenticated(
            challenge_id,
            "conformance-unregistered-session",
            did,
            "refresh-1",
        )
        .await
        .expect("update_session_authenticated");
}

/// Removing an account ends its sessions: `get_session` for an
/// authenticated session whose DID no longer has an account fails with
/// `Unauthorized`, so callers send the client back to authenticate.
async fn check_removed_account_ends_session(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_removed_user";
    let did_hash = sha256::digest(did);
    let session_id = "conformance-removed-session";
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add");
    store
        .put_session(
            &Session {
                session_id: session_id.to_string(),
                challenge: "c".to_string(),
                state: SessionState::Authenticated,
                did: did.to_string(),
                did_hash: did_hash.clone(),
                refresh_token_hash: Some("hash".to_string()),
                ..Default::default()
            },
            Duration::from_secs(300),
        )
        .await
        .expect("put_session");
    store
        .get_session(session_id, did)
        .await
        .expect("session readable while the account exists");

    assert!(
        store
            .account_remove(&admin_session("admin_hash"), &did_hash)
            .await
            .expect("account_remove")
    );
    match store.get_session(session_id, did).await {
        Err(MediatorError::Unauthorized(..)) => {}
        other => panic!("a session without its account must be refused, got {other:?}"),
    }
}

/// Refresh-token rotation is a compare-and-swap: only the current hash
/// rotates, a stale or absent one changes nothing, and of many concurrent
/// rotations with one hash exactly one wins.
async fn check_refresh_rotation(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_refresh_user";
    let did_hash = sha256::digest(did);
    let session_id = "conformance-refresh-session";
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add");
    let mut session = Session {
        session_id: session_id.to_string(),
        challenge: "c".to_string(),
        state: SessionState::Authenticated,
        did: did.to_string(),
        did_hash: did_hash.clone(),
        refresh_token_hash: Some("hash-1".to_string()),
        ..Default::default()
    };
    store
        .put_session(&session, Duration::from_secs(300))
        .await
        .expect("put_session");

    let rotate = |presented: &'static str, new: &'static str| {
        let store = store.clone();
        async move {
            store
                .rotate_refresh_token_hash(session_id, presented, new)
                .await
                .expect("rotate_refresh_token_hash")
        }
    };

    assert_eq!(rotate("hash-1", "hash-2").await, RefreshRotation::Rotated);
    assert_eq!(
        store.get_refresh_token_hash(session_id).await.unwrap(),
        Some("hash-2".to_string())
    );
    // The hash just exchanged no longer matches, and nothing is written.
    assert_eq!(rotate("hash-1", "hash-3").await, RefreshRotation::Mismatch);
    assert_eq!(
        store.get_refresh_token_hash(session_id).await.unwrap(),
        Some("hash-2".to_string())
    );

    // Concurrent rotations with the same current hash: exactly one wins.
    let racers: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .rotate_refresh_token_hash(session_id, "hash-2", "hash-race")
                    .await
                    .expect("rotate_refresh_token_hash")
            })
        })
        .collect();
    let mut rotated = 0;
    for racer in racers {
        if racer.await.unwrap() == RefreshRotation::Rotated {
            rotated += 1;
        }
    }
    assert_eq!(rotated, 1, "one presented hash rotates exactly once");

    // A session without a recorded hash never matches.
    session.refresh_token_hash = None;
    store.delete_session(session_id).await.unwrap();
    store
        .put_session(&session, Duration::from_secs(300))
        .await
        .expect("put_session without a hash");
    assert_eq!(rotate("", "hash-4").await, RefreshRotation::Missing);
    assert_eq!(
        rotate("hash-race", "hash-4").await,
        RefreshRotation::Missing
    );

    // Nor does a session that does not exist.
    store.delete_session(session_id).await.unwrap();
    assert_eq!(
        rotate("hash-race", "hash-4").await,
        RefreshRotation::Missing
    );
}

/// The login path: a challenge session is authenticated under a new id (the
/// challenge id stops working), then its refresh token is rotated. Both steps
/// count in the global stats.
async fn check_login_session(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_login_user";
    let did_hash = sha256::digest(did);
    let challenge_id = "conformance-login-challenge";
    let session_id = "conformance-login-session";
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add for login DID");
    let before = store.get_global_stats().await.expect("get_global_stats");

    store
        .create_session(&Session {
            session_id: challenge_id.to_string(),
            challenge: "conformance-challenge".to_string(),
            state: SessionState::ChallengeSent,
            did: did.to_string(),
            did_hash: did_hash.clone(),
            ..Default::default()
        })
        .await
        .expect("create_session");
    let challenge = store
        .get_session(challenge_id, did)
        .await
        .expect("get_session for the challenge");
    assert_eq!(challenge.challenge, "conformance-challenge");
    assert_eq!(challenge.state, SessionState::ChallengeSent);

    store
        .update_session_authenticated(challenge_id, session_id, did, "refresh-1")
        .await
        .expect("update_session_authenticated");
    assert!(
        store.get_session(challenge_id, did).await.is_err(),
        "the challenge session id must stop working once authenticated"
    );
    let session = store
        .get_session(session_id, did)
        .await
        .expect("get_session for the authenticated session");
    assert_eq!(session.state, SessionState::Authenticated);
    assert!(
        session.authenticated,
        "a session read back after login is marked authenticated"
    );
    assert!(
        !challenge.authenticated,
        "a challenge session is not marked authenticated"
    );
    assert_eq!(
        store
            .get_refresh_token_hash(session_id)
            .await
            .expect("get_refresh_token_hash"),
        Some("refresh-1".to_string())
    );

    store
        .update_refresh_token_hash(session_id, "refresh-2")
        .await
        .expect("update_refresh_token_hash");
    assert_eq!(
        store
            .get_refresh_token_hash(session_id)
            .await
            .expect("get_refresh_token_hash"),
        Some("refresh-2".to_string())
    );

    let after = store.get_global_stats().await.expect("get_global_stats");
    assert_eq!(after.sessions_created, before.sessions_created + 1);
    assert_eq!(after.sessions_success, before.sessions_success + 1);
}

/// Listing and reading several accounts at once: the account list, their
/// ACLs, activity times and lifetime counters.
async fn check_bulk_account_reads(store: Arc<dyn MediatorStore>) {
    let dids: Vec<String> = ["did_hash_bulk_a", "did_hash_bulk_b", "did_hash_bulk_c"]
        .map(String::from)
        .to_vec();
    for did in &dids {
        store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }

    let mut listed = Vec::new();
    let mut cursor = 0;
    loop {
        let page = store.account_list(cursor, 100).await.expect("account_list");
        listed.extend(page.accounts.into_iter().map(|account| account.did_hash));
        if page.cursor == 0 {
            break;
        }
        cursor = page.cursor;
    }
    for did in &dids {
        assert!(listed.contains(did), "account_list includes {did}");
    }

    let acls = store
        .get_did_acls(&dids, AccessListModeType::ExplicitDeny)
        .await
        .expect("get_did_acls");
    let with_acls: Vec<&str> = acls
        .acl_response
        .iter()
        .map(|acl| acl.did_hash.as_str())
        .collect();
    for did in &dids {
        assert!(
            with_acls.contains(&did.as_str()),
            "get_did_acls returns {did}"
        );
    }

    store
        .account_activity_record(&dids[0], ActivityKind::Received, 111)
        .await
        .expect("account_activity_record");
    store
        .account_activity_record(&dids[1], ActivityKind::Authenticated, 222)
        .await
        .expect("account_activity_record");
    let activity = store
        .account_activity(&dids)
        .await
        .expect("account_activity");
    assert_eq!(activity.len(), dids.len(), "one activity row per account");
    assert_eq!(activity[0].last_received, Some(111));
    assert_eq!(activity[1].last_authenticated, Some(222));
    assert_eq!(activity[2].last_received, None);

    store
        .account_stats_bump(
            &dids[0],
            AccountStatsDelta::new(StatsDirection::Received, StatsWire::DidComm, 10),
        )
        .await
        .expect("account_stats_bump");
    let stats = store.account_stats(&dids).await.expect("account_stats");
    assert_eq!(stats.len(), dids.len(), "one stats row per account");
    assert_eq!(stats[0].messages_received, 1);
    assert_eq!(stats[0].bytes_received, 10);
    assert_eq!(stats[2].messages_received, 0);
}

/// Live delivery: a client registers and goes live (the WebSocket flow), a
/// notification published for its mediator instance reaches that instance's
/// subscriber, and a clean start or a disconnect drops the client.
/// An instance leaving a DID it no longer owns keeps the current owner's
/// entry. Two instances share one store: the client was on A, then
/// registered on B (it reconnected there, or became a mux member of a
/// connection there). A's socket closing afterwards used to delete the
/// DID's global entry outright, and B's live delivery for it stopped.
async fn check_streaming_deregister_keeps_another_owner(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_streaming_two_owners";
    let (a, b) = ("conformance-instance-a", "conformance-instance-b");
    for (uuid, state) in [
        (a, StreamingClientState::Registered),
        (a, StreamingClientState::Live),
        (b, StreamingClientState::Registered),
        (b, StreamingClientState::Live),
    ] {
        store
            .streaming_set_state(did, uuid, state)
            .await
            .expect("streaming_set_state");
    }
    assert_eq!(
        store.streaming_is_client_live(did, false).await.as_deref(),
        Some(b),
        "the newest registration owns the DID"
    );
    store
        .streaming_set_state(did, a, StreamingClientState::Deregistered)
        .await
        .expect("A deregisters");
    assert_eq!(
        store.streaming_is_client_live(did, false).await.as_deref(),
        Some(b),
        "A leaving must not take B's live delivery with it"
    );
    store
        .streaming_set_state(did, b, StreamingClientState::Deregistered)
        .await
        .expect("B deregisters");
    assert_eq!(
        store.streaming_is_client_live(did, true).await,
        None,
        "the owner leaving removes the entry"
    );
}

/// `streaming_owners` answers in the order asked: the owning instance for a
/// registered DID, live or not, and `None` for one nobody registered, across
/// more DIDs than one batch.
async fn check_streaming_owners(store: Arc<dyn MediatorStore>) {
    assert!(
        store
            .streaming_owners(&[])
            .await
            .expect("no DIDs")
            .is_empty()
    );
    let (a, b) = ("conformance-owners-a", "conformance-owners-b");
    let dids: Vec<String> = (0..1203)
        .map(|i| format!("did_hash_streaming_owners_{i}"))
        .collect();
    let mut expected = Vec::with_capacity(dids.len());
    for (i, did) in dids.iter().enumerate() {
        let owner = match i % 3 {
            0 => None,
            1 => Some((a, StreamingClientState::Registered)),
            _ => Some((b, StreamingClientState::Live)),
        };
        if let Some((uuid, state)) = owner {
            store
                .streaming_set_state(did, uuid, state)
                .await
                .expect("streaming_set_state");
        }
        expected.push(owner.map(|(uuid, _)| uuid.to_string()));
    }
    assert_eq!(
        store
            .streaming_owners(&dids)
            .await
            .expect("streaming_owners"),
        expected
    );
    for (did, owner) in dids.iter().zip(&expected) {
        if let Some(uuid) = owner {
            store
                .streaming_set_state(did, uuid, StreamingClientState::Deregistered)
                .await
                .expect("deregister");
        }
    }
}

/// Cross-instance precedence on a shared store (Redis): a direct socket
/// outranks a mux entry on another instance, the newest registration wins
/// otherwise, a stale instance never overwrites the owner, and a mux entry
/// kept from or displaced from a DID learns when it may take it back.
#[cfg(feature = "redis-backend")]
async fn check_streaming_cross_instance_precedence(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::{StreamingKind, StreamingWrite};
    let did = "did_hash_streaming_precedence";
    let (a, b, c) = ("precedence-a", "precedence-b", "precedence-c");
    let claim = |uuid: &'static str, live, kind, write| {
        let store = store.clone();
        async move {
            store
                .streaming_claim(did, uuid, live, kind, write)
                .await
                .expect("streaming_claim")
        }
    };
    let live_on = || async { store.streaming_is_client_live(did, false).await };

    // A's direct socket holds the DID.
    assert!(
        claim(a, true, StreamingKind::Direct, StreamingWrite::Claim)
            .await
            .held_here
    );
    // B's mux entry is refused, and recorded as waiting.
    let refused = claim(b, true, StreamingKind::Mux, StreamingWrite::Claim).await;
    assert!(
        !refused.held_here,
        "a mux entry never takes a DID from a direct socket"
    );
    assert_eq!(live_on().await.as_deref(), Some(a));
    // A stale instance's update changes nothing.
    assert!(
        !claim(c, false, StreamingKind::Direct, StreamingWrite::Update)
            .await
            .held_here
    );
    assert_eq!(
        live_on().await.as_deref(),
        Some(a),
        "an update is owner-checked"
    );

    // A leaves: the entry goes, and B is reported waiting.
    assert!(
        store.streaming_release(did, a).await.expect("release"),
        "a mux entry waits for the DID"
    );
    assert_eq!(live_on().await, None);
    // B takes it.
    assert!(
        claim(b, true, StreamingKind::Mux, StreamingWrite::Claim)
            .await
            .held_here
    );
    assert_eq!(
        live_on().await.as_deref(),
        Some(b),
        "a mux owner is found like any other"
    );

    // C's direct socket takes it from B's mux entry, and says so.
    let took = claim(c, true, StreamingKind::Direct, StreamingWrite::Claim).await;
    assert!(took.held_here);
    assert_eq!(took.displaced_mux.as_deref(), Some(b));
    // B, no longer the owner, cannot remove C's entry.
    assert!(!store.streaming_release(did, b).await.expect("release by B"));
    assert_eq!(live_on().await.as_deref(), Some(c));

    // B restarting cleans only its own entries.
    store.streaming_clean_start(b).await.expect("clean start B");
    assert_eq!(
        live_on().await.as_deref(),
        Some(c),
        "clean start keeps another's entry"
    );
    // C leaves: the displaced B waits, so it is told.
    assert!(store.streaming_release(did, c).await.expect("release by C"));
    assert_eq!(live_on().await, None);
}

async fn check_streaming_pubsub(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_streaming";
    let uuid = "conformance-mediator-uuid";
    let connect = || async {
        for state in [StreamingClientState::Registered, StreamingClientState::Live] {
            store
                .streaming_set_state(did, uuid, state)
                .await
                .expect("streaming_set_state");
        }
    };
    connect().await;
    assert_eq!(
        store.streaming_is_client_live(did, false).await.as_deref(),
        Some(uuid),
        "a live client is found on its mediator instance"
    );

    let mut rx = store
        .streaming_subscribe(uuid)
        .await
        .expect("streaming_subscribe");
    // A subscription can take a moment to reach the server, and pub/sub does
    // not replay: publish until one lands.
    let record = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            store
                .streaming_publish_message(did, uuid, "conformance-notification", false)
                .await
                .expect("streaming_publish_message");
            if let Ok(Ok(record)) =
                tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
            {
                break record;
            }
        }
    })
    .await
    .expect("a published notification reaches the subscriber");
    assert_eq!(record.did_hash, did);
    assert_eq!(record.message, "conformance-notification");

    store
        .streaming_clean_start(uuid)
        .await
        .expect("streaming_clean_start");
    assert_eq!(
        store.streaming_is_client_live(did, false).await,
        None,
        "a clean start drops the instance's clients"
    );

    connect().await;
    store
        .streaming_set_state(did, uuid, StreamingClientState::Deregistered)
        .await
        .expect("streaming_set_state deregistered");
    assert_eq!(
        store.streaming_is_client_live(did, false).await,
        None,
        "a disconnected client is not live"
    );
}

/// The same message stored twice, one after the other and at the same time,
/// is queued and counted once on each side; deleting it releases both sides.
async fn check_repeated_store(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::DeletionAuthority;
    use affinidi_messaging_mediator_common::types::messages::Folder;

    let (to, from) = ("did_hash_repeat_to", "did_hash_repeat_from");
    for did in [to, from] {
        store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }
    let store_message = |body: &'static str| {
        let store = store.clone();
        async move {
            store
                .store_message("s", body, to, Some(from), NEVER, 0)
                .await
                .expect("store_message")
        }
    };
    let queued = |did: &'static str, folder: Folder| {
        let store = store.clone();
        async move {
            let account = store
                .account_get(did)
                .await
                .expect("account_get")
                .expect("account present");
            let listed = store
                .list_messages(did, folder, None, 100)
                .await
                .expect("list_messages")
                .len();
            (
                account.receive_queue_count,
                account.send_queue_count,
                listed,
            )
        }
    };

    let first = store_message("repeat-one-after-the-other").await;
    assert_eq!(store_message("repeat-one-after-the-other").await, first);
    let (a, b) = tokio::join!(
        store_message("repeat-at-once"),
        store_message("repeat-at-once")
    );
    assert_eq!(a, b, "both stores name the same message");

    assert_eq!(
        queued(to, Folder::Inbox).await,
        (2, 0, 2),
        "the recipient has each message queued and counted once"
    );
    assert_eq!(
        queued(from, Folder::Outbox).await,
        (0, 2, 2),
        "the sender has each message queued and counted once"
    );

    for id in [&first, &a] {
        store
            .delete_message(
                id,
                DeletionAuthority::Owner {
                    did_hash: to.to_string(),
                },
            )
            .await
            .expect("delete_message");
    }
    assert_eq!(
        queued(to, Folder::Inbox).await,
        (0, 0, 0),
        "nothing is left queued"
    );
    assert_eq!(
        queued(from, Folder::Outbox).await,
        (0, 0, 0),
        "nothing is left queued"
    );
}

/// Several deletes of one message at once: exactly one removes it and the
/// rest find it gone (R1.7), and nothing is left queued or counted. The
/// Redis library is atomic; cluster mode must give the same answer.
async fn check_concurrent_delete(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::DeletionAuthority;
    use affinidi_messaging_mediator_common::store::ops::is_delete_not_found;

    let (to, from) = ("did_hash_concurrent_to", "did_hash_concurrent_from");
    for did in [to, from] {
        store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }
    for round in 0..5 {
        let body = format!("concurrent-delete-{round}");
        let id = store
            .store_message("s", &body, to, Some(from), NEVER, 0)
            .await
            .expect("store_message");
        let delete = |did: &'static str| {
            let store = store.clone();
            let id = id.clone();
            async move {
                store
                    .delete_message(
                        &id,
                        DeletionAuthority::Owner {
                            did_hash: did.to_string(),
                        },
                    )
                    .await
            }
        };
        let results = [delete(to), delete(from), delete(to), delete(from)];
        let results = futures_util::future::join_all(results).await;
        let removed = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(removed, 1, "round {round}: exactly one delete removes it");
        for result in &results {
            if let Err(err) = result {
                assert!(
                    is_delete_not_found(err),
                    "round {round}: the others find it gone, got {err}"
                );
            }
        }
    }
    for did in [to, from] {
        let account = store
            .account_get(did)
            .await
            .expect("account_get")
            .expect("account present");
        assert_eq!(
            (account.receive_queue_count, account.send_queue_count),
            (0, 0),
            "nothing is left counted for {did}"
        );
    }
}

// ─── DID multiplexing ────────────────────────────────────────────────────────

fn mux_grant(
    id: &str,
    member: &str,
    principal: &str,
    kid: &str,
    iat: u64,
    epoch: u64,
) -> mux::MuxGrant {
    mux::MuxGrant {
        grant_id: id.into(),
        did: format!("did:example:{member}"),
        did_hash: member.into(),
        principal: format!("did:example:{principal}"),
        principal_hash: principal.into(),
        kid: kid.into(),
        key_fp: "fp".into(),
        did_version: None,
        epoch,
        scope: mux::MuxScope::new([mux::MuxCapability::Receive]).unwrap(),
        iat,
        exp: iat + 3600,
        narrowed_scope: None,
        narrowed_exp: None,
        state: mux::MuxGrantState::Active,
        state_changed_at: None,
        statement: serde_json::json!({}),
        noticed: false,
        key_agreement_fps: Vec::new(),
        expiring_noticed: false,
    }
}

/// The two backend primitives: version-checked replace, and the principal
/// index moving in the same step.
async fn check_mux_primitives(store: Arc<dyn MediatorStore>) {
    assert!(store.supports_mux());
    let member = "mux-prim-member";
    assert_eq!(store.mux_record_get(member).await.unwrap(), None);

    let rec = mux::MuxDidRecord {
        version: 1,
        epoch: 0,
        ..Default::default()
    };
    let add = mux::MuxIndexDelta {
        add: vec!["mux-prim-p1".into(), "mux-prim-p2".into()],
        remove: vec![],
    };

    // Expecting a version that isn't there loses, and writes nothing.
    assert!(
        !store
            .mux_record_cas(member, Some(7), Some(&rec), &add)
            .await
            .unwrap()
    );
    assert_eq!(store.mux_record_get(member).await.unwrap(), None);
    assert_eq!(store.mux_principal_count("mux-prim-p1").await.unwrap(), 0);

    // Create.
    assert!(
        store
            .mux_record_cas(member, None, Some(&rec), &add)
            .await
            .unwrap()
    );
    assert_eq!(
        store.mux_record_get(member).await.unwrap(),
        Some(rec.clone())
    );
    assert_eq!(
        store
            .mux_principal_dids("mux-prim-p1", None, 10)
            .await
            .unwrap(),
        vec![member.to_string()]
    );

    // A second create (expects absence) loses.
    assert!(
        !store
            .mux_record_cas(member, None, Some(&rec), &add)
            .await
            .unwrap()
    );

    // Replace at the right version, moving p2 out of the index.
    let rec2 = mux::MuxDidRecord {
        version: 2,
        epoch: 1,
        ..Default::default()
    };
    let rm = mux::MuxIndexDelta {
        add: vec![],
        remove: vec!["mux-prim-p2".into()],
    };
    assert!(
        store
            .mux_record_cas(member, Some(1), Some(&rec2), &rm)
            .await
            .unwrap()
    );
    assert_eq!(
        store.mux_record_get(member).await.unwrap().unwrap().epoch,
        1
    );
    assert_eq!(store.mux_principal_count("mux-prim-p2").await.unwrap(), 0);
    assert_eq!(store.mux_principal_count("mux-prim-p1").await.unwrap(), 1);

    // Delete.
    let rm1 = mux::MuxIndexDelta {
        add: vec![],
        remove: vec!["mux-prim-p1".into()],
    };
    assert!(
        store
            .mux_record_cas(member, Some(2), None, &rm1)
            .await
            .unwrap()
    );
    assert_eq!(store.mux_record_get(member).await.unwrap(), None);
    assert!(
        store
            .mux_principal_dids("mux-prim-p1", None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // Index paging is ascending and strictly after the cursor.
    for m in ["mux-prim-c", "mux-prim-a", "mux-prim-b"] {
        let one = mux::MuxIndexDelta {
            add: vec!["mux-prim-pager".into()],
            remove: vec![],
        };
        assert!(
            store
                .mux_record_cas(m, None, Some(&rec), &one)
                .await
                .unwrap()
        );
    }
    let page1 = store
        .mux_principal_dids("mux-prim-pager", None, 2)
        .await
        .unwrap();
    assert_eq!(
        page1,
        vec!["mux-prim-a".to_string(), "mux-prim-b".to_string()]
    );
    let page2 = store
        .mux_principal_dids("mux-prim-pager", Some("mux-prim-b"), 2)
        .await
        .unwrap();
    assert_eq!(page2, vec!["mux-prim-c".to_string()]);
    assert_eq!(
        store.mux_principal_count("mux-prim-pager").await.unwrap(),
        3
    );
}

/// The grant rules end to end through `mux::modify`, so each backend is shown
/// to carry them — including two writers racing on one record.
async fn check_mux_grant_flows(store: Arc<dyn MediatorStore>) {
    let limits = mux::MuxLimits::default();
    let now = 1_800_000_000;
    let member = "mux-flow-member";

    // Two principals granted, concurrently: both must land.
    let (a, b) = tokio::join!(
        mux::modify(
            &*store,
            member,
            &limits,
            now,
            Some("mux-flow-p"),
            |rec, n| {
                mux::put_grant(
                    rec,
                    mux_grant("g1", member, "mux-flow-p", "k1", now, 0),
                    &limits,
                    now,
                    n,
                )
            }
        ),
        mux::modify(
            &*store,
            member,
            &limits,
            now,
            Some("mux-flow-q"),
            |rec, n| {
                mux::put_grant(
                    rec,
                    mux_grant("g2", member, "mux-flow-q", "k1", now, 0),
                    &limits,
                    now,
                    n,
                )
            }
        ),
    );
    a.unwrap();
    b.unwrap();
    let rec = mux::load(&*store, member, &limits, now).await.unwrap();
    assert_eq!(rec.grants.len(), 2);

    let (page, next) = mux::grants_for_principal(&*store, "mux-flow-p", None, 10, &limits, now)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].grant_id, "g1");
    assert!(next.is_none());

    // An unknown key suspends both.
    let suspended = mux::modify(&*store, member, &limits, now + 1, None, |rec, _| {
        Ok(mux::suspend_unless_known_kid(rec, "k2", now + 1))
    })
    .await
    .unwrap();
    assert_eq!(suspended.len(), 2);

    // Revoke-all bumps the epoch; an old-epoch grant is then refused.
    let (epoch, _) = mux::modify(&*store, member, &limits, now + 2, None, |rec, _| {
        Ok(mux::revoke_all(rec, now + 2))
    })
    .await
    .unwrap();
    assert_eq!(epoch, 1);
    let err = mux::modify(
        &*store,
        member,
        &limits,
        now + 3,
        Some("mux-flow-p"),
        |rec, n| {
            mux::put_grant(
                rec,
                mux_grant("g3", member, "mux-flow-p", "k2", now + 3, 0),
                &limits,
                now + 3,
                n,
            )
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, mux::MuxStoreError::EpochMismatch { .. }));
    mux::modify(
        &*store,
        member,
        &limits,
        now + 3,
        Some("mux-flow-p"),
        |rec, n| {
            mux::put_grant(
                rec,
                mux_grant("g3", member, "mux-flow-p", "k2", now + 3, 1),
                &limits,
                now + 3,
                n,
            )
        },
    )
    .await
    .unwrap();

    // Removing the principal's account drops its grant everywhere.
    let other = "mux-flow-member2";
    mux::modify(
        &*store,
        other,
        &limits,
        now,
        Some("mux-flow-p"),
        |rec, n| {
            mux::put_grant(
                rec,
                mux_grant("g4", other, "mux-flow-p", "k1", now, 0),
                &limits,
                now,
                n,
            )
        },
    )
    .await
    .unwrap();
    assert_eq!(store.mux_principal_count("mux-flow-p").await.unwrap(), 2);
    mux::remove_account(&*store, "mux-flow-p", &limits, now + 4)
        .await
        .unwrap();
    assert_eq!(store.mux_principal_count("mux-flow-p").await.unwrap(), 0);
    let rec = mux::load(&*store, other, &limits, now + 4).await.unwrap();
    assert!(rec.grants.is_empty());

    // Removing the member's account drops its record and every index entry.
    mux::remove_account(&*store, member, &limits, now + 5)
        .await
        .unwrap();
    assert_eq!(store.mux_record_get(member).await.unwrap(), None);
    assert_eq!(store.mux_principal_count("mux-flow-q").await.unwrap(), 0);
}

/// A single-process backend has no other instance to tell about mux grant
/// changes: publishing succeeds and does nothing, and there is nothing to
/// subscribe to.
#[cfg(any(feature = "memory-backend", feature = "fjall-backend"))]
async fn check_mux_changes_single_process(store: Arc<dyn MediatorStore>) {
    let record = mux::MuxChangeRecord {
        origin: "instance-a".into(),
        changes: vec![mux::MuxChange {
            did_hash: "member".into(),
            principal_hash: "principal".into(),
            stored: true,
        }],
        streaming: Vec::new(),
        members: Vec::new(),
    };
    store.mux_changes_publish(&record).await.unwrap();
    assert!(store.mux_changes_subscribe().await.unwrap().is_none());
}

/// Two Redis-backed instances: a mux change one publishes reaches the other
/// (and the publisher's own subscription, which the mediator filters by
/// `origin`). Pub/sub channels are server-wide, not per logical DB, so this
/// needs no DB of its own and flushes nothing.
#[cfg(feature = "redis-backend")]
#[tokio::test]
async fn redis_mux_changes_reach_every_instance() {
    let (Some(a), Some(b)) = (redis_store(0).await, redis_store(0).await) else {
        return;
    };
    let mut on_a = a
        .mux_changes_subscribe()
        .await
        .unwrap()
        .expect("redis subscribes");
    let mut on_b = b
        .mux_changes_subscribe()
        .await
        .unwrap()
        .expect("redis subscribes");
    // A second subscriber on one instance shares its bridge.
    let mut on_b2 = b.mux_changes_subscribe().await.unwrap().unwrap();

    let record = mux::MuxChangeRecord {
        origin: format!("instance-a-{}", uuid::Uuid::new_v4()),
        changes: vec![mux::MuxChange {
            did_hash: "member".into(),
            principal_hash: "principal".into(),
            stored: false,
        }],
        streaming: Vec::new(),
        members: Vec::new(),
    };
    a.mux_changes_publish(&record).await.unwrap();

    // Other suites' runs may publish on the same server: wait for ours.
    for rx in [&mut on_b, &mut on_b2, &mut on_a] {
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let r = rx.recv().await.expect("subscription open");
                if r.origin == record.origin {
                    return r;
                }
            }
        })
        .await
        .expect("the record arrives within 5s");
        assert_eq!(got, record);
    }
}

/// Redis only: fetching a message by id counts it as sent in the global
/// stats. The two counters are one MULTI, so a malformed command in it
/// drops both.
#[cfg(feature = "redis-backend")]
async fn check_fetch_counts_sent(store: Arc<dyn MediatorStore>) {
    let to = "did_hash_recipient_sent_stats";
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");
    let body = "{\"protected\":\"sent-stats\"}";
    let id = store
        .store_message("session-id", body, to, None, NEVER, 1000)
        .await
        .expect("store_message");

    let before = store.get_global_stats().await.expect("stats before");
    let fetched = store
        .get_message(to, &id)
        .await
        .expect("get_message")
        .expect("stored message is retrievable by id");
    let after = store.get_global_stats().await.expect("stats after");
    assert_eq!(
        after.sent_count - before.sent_count,
        1,
        "a fetch counts one message sent"
    );
    assert_eq!(
        after.sent_bytes - before.sent_bytes,
        fetched.size as i64,
        "a fetch counts the message's bytes sent"
    );
}

// ─── One body, several recipients ───────────────────────────────────────────

/// Queue counters for `did`: (receive count, receive bytes, send count, send
/// bytes). An absent account reads as zeros.
async fn queue_counters(store: &Arc<dyn MediatorStore>, did: &str) -> (u32, u64, u32, u64) {
    store
        .account_get(did)
        .await
        .expect("account_get")
        .map(|a| {
            (
                a.receive_queue_count,
                a.receive_queue_bytes,
                a.send_queue_count,
                a.send_queue_bytes,
            )
        })
        .unwrap_or_default()
}

/// Asserts `dids` have nothing queued or counted, `from` has no per-peer count
/// towards any of them, and their folders are empty.
async fn assert_nothing_queued(store: &Arc<dyn MediatorStore>, from: &str, dids: &[&str]) {
    use affinidi_messaging_mediator_common::types::messages::Folder;
    for did in dids {
        assert_eq!(
            queue_counters(store, did).await,
            (0, 0, 0, 0),
            "nothing is left counted for {did}"
        );
        for folder in [Folder::Inbox, Folder::Outbox] {
            let listed = store
                .list_messages(did, folder.clone(), None, 100)
                .await
                .expect("list_messages");
            assert!(listed.is_empty(), "{did} {folder:?} is empty: {listed:?}");
        }
        assert_eq!(
            store.peer_queue_count(from, did).await.expect("peer count"),
            0,
            "no per-peer count is left from {from} to {did}"
        );
    }
}

/// The same bytes stored for two recipients get a record each: both can read,
/// fetch and delete their own, one's delete leaves the other's intact, every
/// counter (receive, send, per-peer) returns to zero, purge works, and one
/// copy's expiry does not remove the other. Previously the second store
/// replaced the first recipient's record, leaving its inbox entry and counters
/// with nothing behind them.
async fn check_same_body_for_two_recipients(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::{
        DeletionAuthority, MessageScope, RemovalReason, SentMessageState,
    };
    use affinidi_messaging_mediator_common::store::ops::is_delete_not_found;
    use affinidi_messaging_mediator_common::types::messages::{
        FetchDeletePolicy, FetchOptions, Folder,
    };

    let (a, b, from) = (
        "did_hash_two_copies_a",
        "did_hash_two_copies_b",
        "did_hash_two_copies_sender",
    );
    for did in [a, b, from] {
        store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }
    let owner = |did: &str| DeletionAuthority::Owner {
        did_hash: did.to_string(),
    };
    let body = "{\"protected\":\"one-body-two-recipients\"}";
    let len = body.len() as u64;
    let store_for = |to: &'static str, expires_at: u64| {
        let store = store.clone();
        async move {
            store
                .store_message("s", body, to, Some(from), expires_at, 0)
                .await
                .expect("store_message")
        }
    };

    // ── Both stored: one id, a record each, each counted once ─────────────
    let id = store_for(a, NEVER).await;
    assert_eq!(store_for(b, NEVER).await, id, "the id is the body hash");
    assert_eq!(store_for(a, NEVER).await, id, "a repeat for a is a no-op");
    assert_eq!(queue_counters(&store, a).await, (1, len, 0, 0));
    assert_eq!(queue_counters(&store, b).await, (1, len, 0, 0));
    assert_eq!(queue_counters(&store, from).await, (0, 0, 2, 2 * len));
    for to in [a, b] {
        assert_eq!(store.peer_queue_count(from, to).await.unwrap(), 1);
        let own = store
            .get_message(to, &id)
            .await
            .expect("get_message")
            .unwrap_or_else(|| panic!("{to} reads its copy"));
        assert_eq!(own.to_address.as_deref(), Some(to), "{to}'s own copy");
        assert_eq!(own.from_address.as_deref(), Some(from));
        assert_eq!(own.msg.as_deref(), Some(body));
        assert_eq!(
            store
                .get_message_metadata(to, &id)
                .await
                .expect("metadata")
                .to_did_hash,
            to
        );
    }
    assert_eq!(
        store
            .list_messages(from, Folder::Outbox, None, 100)
            .await
            .expect("outbox")
            .len(),
        2,
        "the sender has an outbox entry per copy"
    );

    // ── Delivery is per copy ────────────────────────────────────────────────
    let fetched = store
        .fetch_messages_delivering(
            "s",
            a,
            &FetchOptions {
                limit: 10,
                start_id: None,
                delete_policy: FetchDeletePolicy::DoNotDelete,
            },
            1_700_000_000_000,
            0,
            false,
        )
        .await
        .expect("fetch");
    assert_eq!(fetched.success.len(), 1);
    assert_eq!(fetched.success[0].msg.as_deref(), Some(body), "a's body");
    assert!(
        store
            .delivery_state(a, &id)
            .await
            .unwrap()
            .is_some_and(|s| s.first_delivered_at_ms.is_some()),
        "a's copy is marked delivered"
    );
    if let Some(state) = store.delivery_state(b, &id).await.unwrap() {
        assert_eq!(state.first_delivered_at_ms, None, "b's copy is not");
    }
    let sent = store.sent_message_states(from, std::slice::from_ref(&id)).await.unwrap();
    assert!(
        matches!(sent[0], SentMessageState::Queued | SentMessageState::Unknown),
        "one copy still waits: {sent:?}"
    );

    // ── a deletes its own; b's is untouched ────────────────────────────────
    store
        .delete_message(&id, owner(a))
        .await
        .expect("a deletes its copy");
    let again = store.delete_message(&id, owner(a)).await;
    assert!(
        again.as_ref().is_err_and(is_delete_not_found),
        "a's second delete finds nothing of its own: {again:?}"
    );
    assert_eq!(queue_counters(&store, a).await, (0, 0, 0, 0));
    assert_eq!(queue_counters(&store, b).await, (1, len, 0, 0));
    assert_eq!(queue_counters(&store, from).await, (0, 0, 1, len));
    assert_eq!(store.peer_queue_count(from, a).await.unwrap(), 0);
    assert_eq!(store.peer_queue_count(from, b).await.unwrap(), 1);
    assert!(store.get_message(a, &id).await.unwrap().is_none());
    assert!(store.get_message(b, &id).await.unwrap().is_some());
    let fetched = store
        .fetch_messages(
            "s",
            b,
            &FetchOptions {
                limit: 10,
                start_id: None,
                delete_policy: FetchDeletePolicy::Optimistic,
            },
        )
        .await
        .expect("b fetches");
    assert_eq!(fetched.success.len(), 1);
    assert_eq!(fetched.success[0].msg.as_deref(), Some(body), "b's body");
    assert!(fetched.delete_errors.is_empty(), "{:?}", fetched.delete_errors);
    assert_nothing_queued(&store, from, &[a, b, from]).await;

    // ── A purge removes the purger's copy only ─────────────────────────────
    store_for(a, NEVER).await;
    store_for(b, NEVER).await;
    let (count, bytes) = store
        .purge_folder("s", a, Folder::Inbox)
        .await
        .expect("purge a's inbox");
    assert_eq!((count, bytes as u64), (1, len));
    assert_eq!(queue_counters(&store, b).await, (1, len, 0, 0));
    assert!(store.get_message(b, &id).await.unwrap().is_some());
    let (count, _) = store
        .purge_folder("s", b, Folder::Inbox)
        .await
        .expect("purge b's inbox");
    assert_eq!(count, 1);
    assert_nothing_queued(&store, from, &[a, b, from]).await;

    // ── The sender withdrawing by id withdraws every copy it sent ──────────
    store_for(a, NEVER).await;
    store_for(b, NEVER).await;
    let stranger = store.delete_message(&id, owner("did_hash_two_copies_x")).await;
    assert!(stranger.is_err(), "a non-party may not delete: {stranger:?}");
    store
        .delete_message(&id, owner(from))
        .await
        .expect("the sender withdraws");
    assert_nothing_queued(&store, from, &[a, b, from]).await;
    let sent = store.sent_message_states(from, std::slice::from_ref(&id)).await.unwrap();
    assert_eq!(
        sent[0],
        SentMessageState::Removed(affinidi_messaging_mediator_common::store::OutboxReceipt {
            reason: RemovalReason::Withdrawn,
            ..match sent[0] {
                SentMessageState::Removed(receipt) => receipt,
                other => panic!("withdrawn, got {other:?}"),
            }
        })
    );

    // ── An admin acting on one account's queue removes that copy only ─────
    store_for(a, NEVER).await;
    store_for(b, NEVER).await;
    store
        .delete_message_in(
            &id,
            MessageScope::Party(a),
            DeletionAuthority::Admin {
                admin_did_hash: "did_hash_two_copies_admin".to_string(),
            },
        )
        .await
        .expect("admin removes a's copy");
    assert_eq!(queue_counters(&store, a).await, (0, 0, 0, 0));
    assert_eq!(queue_counters(&store, b).await, (1, len, 0, 0));
    store
        .delete_message(&id, owner(b))
        .await
        .expect("b deletes its copy");
    assert_nothing_queued(&store, from, &[a, b, from]).await;

    // ── One copy's expiry does not remove the other ────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    store_for(a, now - 10).await;
    store_for(b, NEVER).await;
    let report = store
        .sweep_expired_messages(now, "did_hash_two_copies_admin")
        .await
        .expect("sweep");
    assert_eq!(report.expired, 1, "only a's copy was due: {report:?}");
    assert!(store.get_message(a, &id).await.unwrap().is_none());
    assert!(store.get_message(b, &id).await.unwrap().is_some());
    assert_eq!(queue_counters(&store, b).await, (1, len, 0, 0));
    store
        .delete_message(&id, owner(b))
        .await
        .expect("b deletes its copy");
    assert_nothing_queued(&store, from, &[a, b, from]).await;
}

/// An expiry entry left by an earlier copy of the same bytes for the same
/// recipient does not remove a later copy before its own expiry: the sweeper
/// drops the entry and keeps the record.
async fn check_stale_expiry_entry_keeps_a_later_copy(store: Arc<dyn MediatorStore>) {
    use affinidi_messaging_mediator_common::store::DeletionAuthority;

    let (to, from) = ("did_hash_stale_expiry_to", "did_hash_stale_expiry_from");
    for did in [to, from] {
        store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = "{\"protected\":\"stale-expiry-entry\"}";

    // First copy: due ten seconds ago, collected before the sweep ran.
    let id = store
        .store_message("s", body, to, Some(from), now - 10, 0)
        .await
        .expect("first store");
    store
        .delete_message(
            &id,
            DeletionAuthority::Owner {
                did_hash: to.to_string(),
            },
        )
        .await
        .expect("collected");

    // Second copy of the same bytes, with an expiry far away.
    store
        .store_message("s", body, to, Some(from), NEVER, 0)
        .await
        .expect("second store");

    let report = store
        .sweep_expired_messages(now, "did_hash_stale_expiry_admin")
        .await
        .expect("sweep");
    assert_eq!(report.expired, 0, "nothing was due: {report:?}");
    assert!(
        store.get_message(to, &id).await.unwrap().is_some(),
        "the later copy is still held"
    );
    assert_eq!(queue_counters(&store, to).await.0, 1);

    // The stale entry is gone: a second sweep finds nothing to look at.
    let again = store
        .sweep_expired_messages(now, "did_hash_stale_expiry_admin")
        .await
        .expect("second sweep");
    assert_eq!((again.expired, again.already_deleted), (0, 0), "{again:?}");

    store
        .delete_message(
            &id,
            DeletionAuthority::Owner {
                did_hash: to.to_string(),
            },
        )
        .await
        .expect("delete");
    assert_nothing_queued(&store, from, &[to, from]).await;
}

/// Checks that share Redis DB 0, run one after another so neither flushes the
/// other's keys mid-run.
#[cfg(feature = "redis-backend")]
async fn check_db0_in_sequence(store: Arc<dyn MediatorStore>) {
    // Store-only checks first, so a failure in the message path (Lua) can't
    // hide them.
    check_admin_roles(store.clone()).await;
    check_account_add_keeps_existing_account(store.clone()).await;
    check_counters_only_record_is_not_an_account(store.clone()).await;
    check_login_session(store.clone()).await;
    check_challenge_session_without_account(store.clone()).await;
    check_refresh_rotation(store.clone()).await;
    check_removed_account_ends_session(store.clone()).await;
    check_bulk_account_reads(store.clone()).await;
    check_streaming_pubsub(store.clone()).await;
    check_streaming_deregister_keeps_another_owner(store.clone()).await;
    check_streaming_owners(store.clone()).await;
    check_streaming_cross_instance_precedence(store.clone()).await;
    check_repeated_store(store.clone()).await;
    check_concurrent_delete(store.clone()).await;
    check_fetch_counts_sent(store.clone()).await;
    check_same_body_for_two_recipients(store.clone()).await;
    check_stale_expiry_entry_keeps_a_later_copy(store.clone()).await;
    check_scid_sources(store.clone()).await;
    check_expiry_sweep_reports_each_message(store.clone()).await;
    check_config_overrides(store.clone()).await;
    check_outbox_receipts(store.clone()).await;
    check_purge_and_removal_receipts(store.clone()).await;
    check_mux_primitives(store.clone()).await;
    check_forward_queue_refresh_claims(store.clone()).await;
    check_forward_queue_autoclaim_pages_past_held_entries(store.clone()).await;
    check_forward_queue_finish_is_owner_conditional(store.clone()).await;
    check_mux_grant_flows(store).await;
}

/// Generate one `#[tokio::test]` per check for a backend `$ctor`.
/// Gated to the in-process backends that use it — a Redis-only build drives the
/// async `conformance_for_redis!` instead, so an ungated def would warn (unused)
/// under `-D warnings`.
#[cfg(any(feature = "memory-backend", feature = "fjall-backend"))]
macro_rules! conformance_for {
    ($modname:ident, $ctor:expr) => {
        mod $modname {
            use super::*;

            #[tokio::test]
            async fn account_lifecycle() {
                check_account_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn acl_set_get_roundtrip() {
                check_acl_set_get_roundtrip(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn account_add_keeps_existing_account() {
                check_account_add_keeps_existing_account(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn counters_only_record_is_not_an_account() {
                check_counters_only_record_is_not_an_account(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn message_store_and_counters() {
                check_message_store_and_counters(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_claim_ack() {
                check_forward_queue_claim_ack(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn session_lifecycle() {
                check_session_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn access_list_lifecycle() {
                check_access_list_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_delete() {
                check_forward_queue_delete(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_autoclaim() {
                check_forward_queue_autoclaim(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_refresh_claims() {
                check_forward_queue_refresh_claims(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_autoclaim_pages_past_held_entries() {
                check_forward_queue_autoclaim_pages_past_held_entries(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_finish_is_owner_conditional() {
                check_forward_queue_finish_is_owner_conditional(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn session_expiry_sweep() {
                check_session_expiry_sweep(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn access_list_mode_semantics() {
                check_access_list_mode_semantics(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn audit_log_lifecycle() {
                check_audit_log_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn oob_discovery_roundtrip() {
                check_oob_discovery_roundtrip(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn delivery_decision_matches_access_list() {
                check_delivery_decision_matches_access_list(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn v1_routing_keys() {
                check_v1_routing_keys(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn trust_task_claim() {
                check_trust_task_claim(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn scid_sources() {
                check_scid_sources(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn expiry_sweep_reports_each_message() {
                check_expiry_sweep_reports_each_message(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn config_overrides() {
                check_config_overrides(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn outbox_receipts() {
                check_outbox_receipts(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn purge_and_removal_receipts() {
                check_purge_and_removal_receipts(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn outbox_receipt_retention() {
                check_outbox_receipt_retention(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn admin_roles() {
                check_admin_roles(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn login_session() {
                check_login_session(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn challenge_session_without_account() {
                check_challenge_session_without_account(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn refresh_rotation() {
                check_refresh_rotation(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn removed_account_ends_session() {
                check_removed_account_ends_session(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn bulk_account_reads() {
                check_bulk_account_reads(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn streaming_pubsub() {
                check_streaming_pubsub(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn streaming_deregister_keeps_another_owner() {
                check_streaming_deregister_keeps_another_owner(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn streaming_owners() {
                check_streaming_owners(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn repeated_store() {
                check_repeated_store(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn concurrent_delete() {
                check_concurrent_delete(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn same_body_for_two_recipients() {
                check_same_body_for_two_recipients(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn stale_expiry_entry_keeps_a_later_copy() {
                check_stale_expiry_entry_keeps_a_later_copy(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn mux_primitives() {
                check_mux_primitives(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn mux_grant_flows() {
                check_mux_grant_flows(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn mux_changes_single_process() {
                check_mux_changes_single_process(ready($ctor).await).await;
            }
        }
    };
}

#[cfg(feature = "memory-backend")]
conformance_for!(memory, memory_backend());

#[cfg(feature = "fjall-backend")]
conformance_for!(fjall, fjall_backend());

/// Like [`conformance_for!`] but for the async, `REDIS_URL`-gated Redis ctor.
/// Each test is pinned to a distinct logical DB index for isolation and skips
/// (returns early) when `redis_backend` yields `None` (no `REDIS_URL`).
#[cfg(feature = "redis-backend")]
macro_rules! conformance_for_redis {
    ($modname:ident, $($test:ident => $check:ident @ $db:literal),+ $(,)?) => {
        mod $modname {
            use super::*;
            $(
                #[tokio::test]
                async fn $test() {
                    let Some(backend) = redis_backend($db).await else { return };
                    $check(ready(backend).await).await;
                }
            )+
        }
    };
}

// One distinct DB index per check (1..=10) so the global keys (counters, the
// forward-queue stream) never collide across the suite running in parallel.
#[cfg(feature = "redis-backend")]
conformance_for_redis!(redis,
    account_lifecycle        => check_account_lifecycle        @ 1,
    acl_set_get_roundtrip    => check_acl_set_get_roundtrip    @ 2,
    message_store_and_counters => check_message_store_and_counters @ 3,
    forward_queue_claim_ack  => check_forward_queue_claim_ack  @ 4,
    session_lifecycle        => check_session_lifecycle        @ 5,
    access_list_lifecycle    => check_access_list_lifecycle    @ 6,
    forward_queue_delete     => check_forward_queue_delete     @ 7,
    forward_queue_autoclaim  => check_forward_queue_autoclaim  @ 8,
    session_expiry_sweep     => check_session_expiry_sweep     @ 9,
    access_list_mode_semantics => check_access_list_mode_semantics @ 10,
    audit_log_lifecycle      => check_audit_log_lifecycle      @ 11,
    oob_discovery_roundtrip  => check_oob_discovery_roundtrip  @ 12,
    delivery_decision_matches_access_list => check_delivery_decision_matches_access_list @ 13,
    v1_routing_keys          => check_v1_routing_keys          @ 14,
    trust_task_claim         => check_trust_task_claim         @ 15,
);

/// A FORWARD_Q entry that does not parse is dropped by the consumer that
/// claims it — by a read, or by the reclaim sweep — instead of staying
/// pending to be reclaimed, and skipped, on every sweep. Uses a group of its
/// own and touches only the entries it adds; part of the DB 0 sequence.
#[cfg(feature = "redis-backend")]
async fn check_redis_malformed_forward_entries_are_dropped(
    store: &affinidi_messaging_mediator::store::RedisStore,
) {
    let group = format!("malformed-{}", uuid::Uuid::new_v4());
    let mut conn = store.get_connection().await.expect("redis connection");
    use affinidi_messaging_mediator_common::database::RedisConnection;
    async fn xadd(conn: &mut RedisConnection) -> String {
        ::redis::cmd("XADD")
            .arg("FORWARD_Q")
            .arg("*")
            .arg("NOT_A_FORWARD")
            .arg("1")
            .query_async::<String>(conn)
            .await
            .expect("XADD")
    }
    async fn exists(conn: &mut RedisConnection, id: String) -> bool {
        let rows: Vec<::redis::Value> = ::redis::cmd("XRANGE")
            .arg("FORWARD_Q")
            .arg(&id)
            .arg(&id)
            .query_async(conn)
            .await
            .expect("XRANGE");
        !rows.is_empty()
    }

    // The group starts at the end of the stream, so it sees only ours.
    ::redis::cmd("XGROUP")
        .arg("CREATE")
        .arg("FORWARD_Q")
        .arg(&group)
        .arg("$")
        .arg("MKSTREAM")
        .query_async::<()>(&mut conn)
        .await
        .expect("XGROUP CREATE");

    // Read: dropped at once.
    let read_bad = xadd(&mut conn).await;
    let read =
        MediatorStore::forward_queue_read(store, &group, "reader", 10, Duration::from_millis(50))
            .await
            .expect("forward_queue_read");
    assert!(read.is_empty());
    assert!(!exists(&mut conn, read_bad).await, "dropped by the read");

    // Already pending (claimed before it could be parsed): dropped by the
    // sweep that reclaims it.
    let swept_bad = xadd(&mut conn).await;
    ::redis::cmd("XREADGROUP")
        .arg("GROUP")
        .arg(&group)
        .arg("raw")
        .arg("COUNT")
        .arg(10)
        .arg("STREAMS")
        .arg("FORWARD_Q")
        .arg(">")
        .query_async::<::redis::Value>(&mut conn)
        .await
        .expect("XREADGROUP");
    let page =
        MediatorStore::forward_queue_autoclaim(store, &group, "sweeper", Duration::ZERO, 10, "0-0")
            .await
            .expect("forward_queue_autoclaim");
    assert!(page.entries.is_empty());
    assert!(!exists(&mut conn, swept_bad).await, "dropped by the sweep");

    let _ = ::redis::cmd("XGROUP")
        .arg("DESTROY")
        .arg("FORWARD_Q")
        .arg(&group)
        .query_async::<i64>(&mut conn)
        .await;
}

/// Writes a message in the layout used before records were per recipient —
/// one `MSG:<id>` / `MSG:META:<id>` per body, its id alone in the expiry
/// bucket and (in cluster mode) as the queue-id field — with the queue
/// entries and counters the earlier library kept. Returns the id.
#[cfg(feature = "redis-backend")]
async fn write_legacy_redis_record(
    store: &affinidi_messaging_mediator::store::RedisStore,
    body: &str,
    to: &str,
    from: &str,
    expires_at: u64,
) -> String {
    use affinidi_messaging_mediator_common::database::keys::Keys;
    let keys = Keys::new(std::env::var("REDIS_CLUSTER_MODE").is_ok_and(|v| v == "true"));
    let id = sha256::digest(body.as_bytes());
    let bytes = body.len();
    let mut conn = store.get_connection().await.expect("redis connection");
    let receive_id: String = ::redis::cmd("XADD")
        .arg(keys.receive_q(to))
        .arg("*")
        .arg("MSG_ID")
        .arg(&id)
        .arg("BYTES")
        .arg(bytes)
        .arg("FROM")
        .arg(from)
        .query_async(&mut conn)
        .await
        .expect("XADD inbox");
    let send_id: String = ::redis::cmd("XADD")
        .arg(keys.send_q(from))
        .arg("*")
        .arg("MSG_ID")
        .arg(&id)
        .arg("BYTES")
        .arg(bytes)
        .arg("TO")
        .arg(to)
        .query_async(&mut conn)
        .await
        .expect("XADD outbox");
    let bucket = format!("MSG_EXPIRY:{expires_at}");
    let commands: Vec<::redis::Cmd> = vec![
        ::redis::cmd("SET")
            .arg(keys.msg(&id, None))
            .arg(body)
            .to_owned(),
        ::redis::cmd("HSET")
            .arg(keys.msg_meta(&id, None))
            .arg("BYTES")
            .arg(bytes)
            .arg("TO")
            .arg(to)
            .arg("FROM")
            .arg(from)
            .arg("TIMESTAMP")
            .arg(1_700_000_000_000u64)
            .arg("RECEIVE_ID")
            .arg(&receive_id)
            .arg("SEND_ID")
            .arg(&send_id)
            .to_owned(),
        ::redis::cmd("HINCRBY")
            .arg(keys.did(to))
            .arg("RECEIVE_QUEUE_COUNT")
            .arg(1)
            .to_owned(),
        ::redis::cmd("HINCRBY")
            .arg(keys.did(to))
            .arg("RECEIVE_QUEUE_BYTES")
            .arg(bytes)
            .to_owned(),
        ::redis::cmd("HINCRBY")
            .arg(keys.did(from))
            .arg("SEND_QUEUE_COUNT")
            .arg(1)
            .to_owned(),
        ::redis::cmd("HINCRBY")
            .arg(keys.did(from))
            .arg("SEND_QUEUE_BYTES")
            .arg(bytes)
            .to_owned(),
        ::redis::cmd("HINCRBY")
            .arg(keys.peer_q(from))
            .arg(to)
            .arg(1)
            .to_owned(),
        ::redis::cmd("ZADD")
            .arg("MSG_EXPIRY")
            .arg(expires_at)
            .arg(&bucket)
            .to_owned(),
        ::redis::cmd("SADD").arg(&bucket).arg(&id).to_owned(),
        ::redis::cmd("HSET")
            .arg(keys.receive_ids(to))
            .arg(&id)
            .arg(&receive_id)
            .to_owned(),
        ::redis::cmd("HSET")
            .arg(keys.send_ids(from))
            .arg(&id)
            .arg(&send_id)
            .to_owned(),
    ];
    for cmd in commands {
        cmd.query_async::<::redis::Value>(&mut conn)
            .await
            .expect("legacy write");
    }
    id
}

/// Messages stored before records were per recipient keep working: the
/// recipient fetches, reads and deletes them; storing the same bytes again
/// for that recipient is still one record; the same bytes for another
/// recipient get a record of their own; purge and expiry remove them; and
/// every counter returns to zero. Part of the DB 0 sequence.
#[cfg(feature = "redis-backend")]
async fn check_redis_legacy_records_keep_working(
    store: &affinidi_messaging_mediator::store::RedisStore,
) {
    use affinidi_messaging_mediator_common::store::{DeletionAuthority, SentMessageState};
    use affinidi_messaging_mediator_common::types::messages::{
        FetchDeletePolicy, FetchOptions, Folder,
    };

    let dyn_store: Arc<dyn MediatorStore> = Arc::new(store.clone());
    let (a, b, from) = (
        "did_hash_legacy_a",
        "did_hash_legacy_b",
        "did_hash_legacy_sender",
    );
    for did in [a, b, from] {
        dyn_store
            .account_add(did, &allow_all(), None)
            .await
            .expect("account_add");
    }
    let body = "{\"protected\":\"legacy-record\"}";
    let len = body.len() as u64;
    let id = write_legacy_redis_record(store, body, a, from, NEVER).await;
    assert_eq!(queue_counters(&dyn_store, a).await, (1, len, 0, 0));

    // Read and fetched by its recipient, read by its sender.
    let fetched = dyn_store
        .fetch_messages(
            "s",
            a,
            &FetchOptions {
                limit: 10,
                start_id: None,
                delete_policy: FetchDeletePolicy::DoNotDelete,
            },
        )
        .await
        .expect("fetch");
    assert_eq!(fetched.success.len(), 1);
    assert_eq!(fetched.success[0].msg.as_deref(), Some(body));
    for party in [a, from] {
        let read = dyn_store
            .get_message(party, &id)
            .await
            .expect("get_message")
            .unwrap_or_else(|| panic!("{party} reads the legacy record"));
        assert_eq!(read.to_address.as_deref(), Some(a));
    }
    assert_eq!(
        dyn_store
            .get_message_metadata(a, &id)
            .await
            .expect("metadata")
            .to_did_hash,
        a
    );

    // Stored again for its recipient: still one record. For another: a new one.
    dyn_store
        .store_message("s", body, a, Some(from), NEVER, 0)
        .await
        .expect("store again for a");
    assert_eq!(queue_counters(&dyn_store, a).await, (1, len, 0, 0));
    dyn_store
        .store_message("s", body, b, Some(from), NEVER, 0)
        .await
        .expect("store for b");
    assert_eq!(queue_counters(&dyn_store, b).await, (1, len, 0, 0));
    assert_eq!(queue_counters(&dyn_store, from).await, (0, 0, 2, 2 * len));

    // Delivery is recorded on the legacy record, and only there.
    dyn_store
        .mark_delivered(a, std::slice::from_ref(&id), 1_700_000_000_000, 0)
        .await
        .expect("mark");
    assert!(
        dyn_store
            .delivery_state(a, &id)
            .await
            .unwrap()
            .is_some_and(|s| s.first_delivered_at_ms.is_some())
    );
    assert_eq!(
        dyn_store
            .delivery_state(b, &id)
            .await
            .unwrap()
            .and_then(|s| s.first_delivered_at_ms),
        None
    );
    let sent = dyn_store
        .sent_message_states(from, std::slice::from_ref(&id))
        .await
        .unwrap();
    assert_eq!(sent[0], SentMessageState::Queued, "b's copy still waits");

    // The recipient deletes its legacy record; b's copy stays.
    dyn_store
        .delete_message(
            &id,
            DeletionAuthority::Owner {
                did_hash: a.to_string(),
            },
        )
        .await
        .expect("a deletes the legacy record");
    assert_eq!(queue_counters(&dyn_store, a).await, (0, 0, 0, 0));
    assert_eq!(queue_counters(&dyn_store, from).await, (0, 0, 1, len));
    assert_eq!(dyn_store.peer_queue_count(from, a).await.unwrap(), 0);
    assert!(dyn_store.get_message(b, &id).await.unwrap().is_some());
    dyn_store
        .delete_message(
            &id,
            DeletionAuthority::Owner {
                did_hash: b.to_string(),
            },
        )
        .await
        .expect("b deletes its copy");
    assert_nothing_queued(&dyn_store, from, &[a, b, from]).await;

    // A purge removes a legacy record at the head of the inbox.
    write_legacy_redis_record(store, "{\"protected\":\"legacy-purge\"}", a, from, NEVER).await;
    let (count, _) = dyn_store
        .purge_folder("s", a, Folder::Inbox)
        .await
        .expect("purge");
    assert_eq!(count, 1);
    assert_nothing_queued(&dyn_store, from, &[a, b, from]).await;

    // The sweeper expires a legacy record from its bare-id bucket entry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiring =
        write_legacy_redis_record(store, "{\"protected\":\"legacy-expiry\"}", a, from, now - 10)
            .await;
    let report = dyn_store
        .sweep_expired_messages(now, "did_hash_legacy_admin")
        .await
        .expect("sweep");
    assert_eq!(report.expired, 1, "{report:?}");
    assert!(dyn_store.get_message(a, &expiring).await.unwrap().is_none());
    assert_nothing_queued(&dyn_store, from, &[a, b, from]).await;
}

/// DB 0: every numbered index a default Redis offers (0..=15) is in use, so
/// the checks added since share it, one after another in a single test. The
/// start-up check needs the concrete `RedisStore`, so this test is written out
/// rather than generated.
#[cfg(feature = "redis-backend")]
#[tokio::test]
async fn redis_db0_checks() {
    let Some(store) = redis_store_flushed(0).await else {
        return;
    };
    store.initialize().await.expect("store initialize");
    check_redis_startup(&store).await;
    flush_db(&store).await;
    check_redis_malformed_forward_entries_are_dropped(&store).await;
    check_redis_legacy_records_keep_working(&store).await;
    check_db0_in_sequence(Arc::new(store)).await;
}
