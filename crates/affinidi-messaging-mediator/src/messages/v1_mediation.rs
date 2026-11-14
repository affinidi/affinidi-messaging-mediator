//! DIDComm v1 mediation protocols: coordinate-mediation 1.0 and
//! message-pickup 2.0.
//!
//! Stage 1 taught the mediator to *receive* v1 forwards. This is what lets a
//! wallet set that up for itself and collect what arrives: register routing
//! keys, then poll for messages.
//!
//! # These messages are authenticated; forwards are not
//!
//! A `routing/1.0/forward` is anon-packed by design, so
//! [`crate::messages::inbound_v1`] has no sender to authorise against and leans
//! on the recipient's ACL. Everything here is the opposite: the client
//! **authcrypts** to the mediator, so opening the envelope proves which verkey
//! sent it, and that key is the identity every decision below is made against.
//! There is nothing to spoof — a v1 plaintext has no `from` header to lie in.
//!
//! # Account identity
//!
//! v1 has no DIDs, so the client's account is keyed by the `did:key` derived
//! from its authenticated verkey. Deterministic, needs no extra state, and it
//! is the same identifier Aries uses for a connection's keys.
//!
//! Provisioning deliberately mirrors `crate::handlers::authenticate::response`
//! rather than inventing a second policy: an unknown account is created with
//! `global_acl_default`, unless `mediator_acl_mode` is `explicit_allow`, in
//! which case mediation is denied. One admission gate, two entry points.

use crate::error_codes;
use affinidi_messaging_didcomm_v1::identity::Verkey;
use affinidi_messaging_didcomm_v1::message::MessageV1;
use affinidi_messaging_didcomm_v1::protocols::coordinate_mediation as cm;
use affinidi_messaging_didcomm_v1::protocols::message_pickup as mp;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::MediatorStoreExt;
use affinidi_messaging_mediator_common::store::types::{DeletionAuthority, MessageScope};
use affinidi_messaging_mediator_common::types::messages::{FetchDeletePolicy, FetchOptions};
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use http::StatusCode;
use tracing::{debug, warn};

use crate::SharedData;
use crate::common::authz::{self, Capability};
use crate::common::session::Session;

/// Most messages a `delivery-request` may return when it names no `limit`.
///
/// A client that asks for everything still gets a bounded page; it can keep
/// requesting. Matches the store's own default fetch limit.
const DEFAULT_DELIVERY_LIMIT: u32 = 10;

/// Hard cap on a `delivery-request`, whatever `limit` it asks for.
///
/// The request is authenticated but the number is attacker-chosen, and each
/// message is copied into a response the mediator has to build in memory.
const MAX_DELIVERY_LIMIT: u32 = 100;

/// Cap on `message_id_list` in one `messages-received`.
const MAX_ACK_IDS: usize = 100;

/// Cap on `updates` in one `keylist-update`.
///
/// Each entry costs store round trips, so one request must not be able to
/// queue an unbounded amount of work. The per-account total is a separate,
/// configured limit (`[didcomm_v1] max_routing_keys_per_account`).
const MAX_KEYLIST_UPDATES: usize = 100;

/// A v1 request the mediator answers directly, rather than routing.
pub(crate) enum V1Request {
    CoordinateMediation(cm::CoordinateMediation),
    MessagePickup(mp::MessagePickup),
}

impl V1Request {
    /// Classify `msg`, or `None` when it is not a protocol this module serves.
    pub(crate) fn classify(msg: &MessageV1) -> Option<Self> {
        if let Some(kind) = cm::CoordinateMediation::classify(msg) {
            return Some(Self::CoordinateMediation(kind));
        }
        mp::MessagePickup::classify(msg).map(Self::MessagePickup)
    }
}

/// Handle an authenticated v1 protocol message, returning the reply to send
/// back.
///
/// `sender` is the verkey that authenticated the envelope — not anything the
/// message claimed.
pub(crate) async fn handle(
    state: &SharedData,
    session: &Session,
    request: V1Request,
    msg: &MessageV1,
    sender: &Verkey,
) -> Result<MessageV1, MediatorError> {
    let account = client_account(state, session, sender).await?;

    match request {
        V1Request::CoordinateMediation(kind) => {
            coordinate_mediation(state, session, kind, msg, &account).await
        }
        V1Request::MessagePickup(kind) => message_pickup(state, session, kind, msg, &account).await,
    }
}

/// The client's account: the `did:key` for its authenticated verkey, created on
/// first contact under the same policy as first authentication.
struct ClientAccount {
    did: String,
    did_hash: String,
    /// The verkey that authenticated this request: the one key the client has
    /// shown the mediator it holds.
    verkey: Verkey,
}

async fn client_account(
    state: &SharedData,
    session: &Session,
    sender: &Verkey,
) -> Result<ClientAccount, MediatorError> {
    let did = sender.to_did_key();
    let did_hash = affinidi_messaging_mediator_common::did_identity::did_hash(&did);

    if !state.database.account_exists(&did_hash).await? {
        // Same gate as `handlers::authenticate::response`: in explicit-allow
        // mode an unknown identity is refused rather than self-registered.
        if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow {
            warn!(
                %did,
                "v1 mediation refused: no account and mediator_acl_mode is explicit_allow"
            );
            return Err(v1_problem(
                session,
                error_codes::AUTH_DID_BLOCKED,
                "authorization.blocked",
                "This mediator does not accept mediation requests from unknown clients".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }

        debug!(%did, "v1 mediation: registering a new account for the client verkey");
        state
            .database
            .account_add(&did_hash, &state.config.security.global_acl_default, None)
            .await?;
    }

    Ok(ClientAccount {
        did,
        did_hash,
        verkey: *sender,
    })
}

async fn coordinate_mediation(
    state: &SharedData,
    session: &Session,
    kind: cm::CoordinateMediation,
    msg: &MessageV1,
    account: &ClientAccount,
) -> Result<MessageV1, MediatorError> {
    match kind {
        cm::CoordinateMediation::MediateRequest => {
            // Do not grant mediation the account cannot actually use. Without
            // RECEIVE_MESSAGES every forward for this client would be refused
            // *after* it had been told mediation was granted and had published
            // the routing keys — a silent black hole the client has no way to
            // detect. `mediate-deny` says so immediately instead.
            //
            // Reached when `global_acl_default` does not grant receive; the
            // operator either intends that (and v1 clients are not welcome) or
            // has misconfigured it, and both are better surfaced than hidden.
            if !account_can_receive(state, account).await? {
                warn!(
                    did = %account.did,
                    "denying v1 mediation: the account is not permitted to receive messages, so \
                     granting it would promise routing the mediator would then refuse"
                );
                return cm::mediate_deny(&msg.id).map_err(|e| v1_build_error(session, e));
            }

            let identity = state.didcomm_v1_identity().await?;
            let endpoint = mediator_endpoint(state);

            debug!(did = %account.did, "granting v1 mediation");
            cm::mediate_grant(
                &msg.id,
                &endpoint,
                &[identity.verkey()],
                cm::KeyFormat::Base58,
            )
            .map_err(|e| v1_build_error(session, e))
        }

        cm::CoordinateMediation::KeylistUpdate => {
            let updates = cm::parse_keylist_update(msg).map_err(|e| {
                v1_problem(
                    session,
                    error_codes::DIDCOMM_V1_MALFORMED,
                    "message.didcomm_v1.keylist",
                    format!("malformed keylist-update: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            if updates.len() > MAX_KEYLIST_UPDATES {
                return Err(v1_problem(
                    session,
                    error_codes::DIDCOMM_V1_MALFORMED,
                    "message.didcomm_v1.keylist",
                    format!(
                        "keylist-update lists {} updates, exceeding the maximum of \
                         {MAX_KEYLIST_UPDATES}",
                        updates.len()
                    ),
                    StatusCode::BAD_REQUEST,
                ));
            }

            // Adding a key is only meaningful for an account mediation would
            // be granted to, the same precondition `mediate-request` applies.
            // Read once for the batch; removes do not need it, so a client can
            // always clean up after itself.
            let can_receive = if updates
                .iter()
                .any(|u| matches!(u.action, cm::KeylistAction::Add))
            {
                account_can_receive(state, account).await?
            } else {
                false
            };

            let mut batch = KeylistBatch {
                can_receive,
                held: None,
                added: Vec::new(),
            };
            let mut outcomes = Vec::with_capacity(updates.len());
            for (index, update) in updates.iter().enumerate() {
                outcomes
                    .push(apply_keylist_update(state, account, &mut batch, index, update).await);
            }
            batch.settle(state, account, &mut outcomes).await;

            let results: Vec<cm::KeylistUpdated> = updates
                .into_iter()
                .zip(outcomes)
                .map(|(update, result)| cm::KeylistUpdated {
                    recipient_key: update.recipient_key,
                    action: update.action,
                    result,
                })
                .collect();

            cm::keylist_update_response(&msg.id, &results, cm::KeyFormat::Base58)
                .map_err(|e| v1_build_error(session, e))
        }

        cm::CoordinateMediation::KeylistQuery => {
            let keys = state
                .database
                .v1_routing_keys_for(&account.did_hash)
                .await?
                .iter()
                .filter_map(|k| Verkey::from_base58(k).ok())
                .collect::<Vec<_>>();

            cm::keylist(&msg.id, &keys, cm::KeyFormat::Base58)
                .map_err(|e| v1_build_error(session, e))
        }

        // Responses, not requests: a client sending one to the mediator is
        // confused, but it is not an error worth a problem report either.
        cm::CoordinateMediation::MediateGrant
        | cm::CoordinateMediation::MediateDeny
        | cm::CoordinateMediation::KeylistUpdateResponse
        | cm::CoordinateMediation::Keylist => Err(v1_problem(
            session,
            error_codes::DIDCOMM_V1_MALFORMED,
            "message.didcomm_v1.unexpected",
            format!(
                "`{}` is a mediator-to-client message; the mediator does not accept it",
                msg.typ
            ),
            StatusCode::BAD_REQUEST,
        )),

        // `CoordinateMediation` is `#[non_exhaustive]`.
        _ => Err(v1_problem(
            session,
            error_codes::PROTOCOL_UNSUPPORTED,
            "message.didcomm_v1.unsupported",
            format!("unsupported coordinate-mediation message `{}`", msg.typ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Whether the account holds `RECEIVE_MESSAGES` — the condition for granting
/// mediation, and so for registering routing keys that would route to it.
async fn account_can_receive(
    state: &SharedData,
    account: &ClientAccount,
) -> Result<bool, MediatorError> {
    Ok(state
        .database
        .get_did_acl(&account.did_hash)
        .await?
        .is_some_and(|acls| authz::require_capability(&acls, Capability::ReceiveMessages).is_ok()))
}

/// What one `keylist-update` has done so far, so the account's keys are
/// counted once per request rather than once per entry.
struct KeylistBatch {
    /// The account holds `RECEIVE_MESSAGES`.
    can_receive: bool,
    /// Keys the account holds, counted when first needed and kept current as
    /// this request adds and removes.
    held: Option<usize>,
    /// Entries this request added, by index and verkey, in order.
    added: Vec<(usize, String)>,
}

impl KeylistBatch {
    /// How many keys the account holds, counting only on first use.
    async fn held(
        &mut self,
        state: &SharedData,
        account: &ClientAccount,
    ) -> Result<usize, MediatorError> {
        if let Some(held) = self.held {
            return Ok(held);
        }
        let held = held_routing_keys(state, account).await?;
        self.held = Some(held);
        Ok(held)
    }

    fn record_add(&mut self, index: usize, verkey: String) {
        if let Some(held) = self.held.as_mut() {
            *held += 1;
        }
        self.added.push((index, verkey));
    }

    fn record_remove(&mut self, verkey: &str) {
        if let Some(held) = self.held.as_mut() {
            *held = held.saturating_sub(1);
        }
        self.added.retain(|(_, added)| added != verkey);
    }

    /// Enforce the limit once more against what the store now holds.
    ///
    /// Concurrent requests for one account can each pass their own count.
    /// Counting again after this request's adds catches that: if the account
    /// is over its limit, this request's newest adds are withdrawn (only
    /// while still bound to this account) and reported as refused. Two
    /// racing requests may then both lose keys, but the account never keeps
    /// more than its limit.
    async fn settle(
        &self,
        state: &SharedData,
        account: &ClientAccount,
        outcomes: &mut [cm::KeylistResult],
    ) {
        if self.added.is_empty() {
            return;
        }
        let max = state.config.didcomm_v1.max_routing_keys_per_account as usize;
        let (withdraw, refused) = match held_routing_keys(state, account).await {
            Ok(held) if held <= max => return,
            Ok(held) => {
                warn!(
                    did = %account.did,
                    held,
                    max,
                    "v1 keylist adds withdrawn: concurrent adds took the account over its limit"
                );
                (held - max, cm::KeylistResult::ClientError)
            }
            Err(e) => {
                warn!(
                    did = %account.did,
                    error = %e,
                    "v1 keylist recount failed; withdrawing this request's adds"
                );
                (self.added.len(), cm::KeylistResult::ServerError)
            }
        };

        for (index, verkey) in self.added.iter().rev().take(withdraw) {
            outcomes[*index] = match state
                .database
                .v1_routing_key_unbind_if_owner(verkey, &account.did)
                .await
            {
                Ok(_) => refused,
                Err(e) => {
                    warn!(%verkey, error = %e, "v1 keylist add could not be withdrawn");
                    cm::KeylistResult::ServerError
                }
            };
        }
    }
}

/// Apply one keylist change, reporting the per-key outcome rather than failing
/// the whole batch — RFC 0211 expects a result for every entry.
async fn apply_keylist_update(
    state: &SharedData,
    account: &ClientAccount,
    batch: &mut KeylistBatch,
    index: usize,
    update: &cm::KeylistUpdate,
) -> cm::KeylistResult {
    let verkey = update.recipient_key.to_base58();

    match update.action {
        cm::KeylistAction::Add => add_routing_key(state, account, batch, index, update).await,

        cm::KeylistAction::Remove => {
            match state.database.v1_routing_key_lookup(&verkey).await {
                // Removed only while still this account's: a binding another
                // account made in the meantime is left alone.
                Ok(Some(owner)) if owner == account.did => match state
                    .database
                    .v1_routing_key_unbind_if_owner(&verkey, &account.did)
                    .await
                {
                    Ok(true) => {
                        batch.record_remove(&verkey);
                        cm::KeylistResult::Success
                    }
                    Ok(false) => cm::KeylistResult::NoChange,
                    Err(e) => {
                        warn!(%verkey, error = %e, "v1 keylist remove failed");
                        cm::KeylistResult::ServerError
                    }
                },
                // Not bound at all — a no-op, not an error.
                Ok(None) => cm::KeylistResult::NoChange,
                // Bound to someone else: refuse, and report it the same way as
                // any other rejected request so this cannot be used to probe
                // which keys other accounts hold.
                Ok(Some(_)) => cm::KeylistResult::ClientError,
                Err(e) => {
                    warn!(%verkey, error = %e, "v1 keylist lookup failed");
                    cm::KeylistResult::ServerError
                }
            }
        }

        // `KeylistAction` is `#[non_exhaustive]`.
        _ => cm::KeylistResult::ClientError,
    }
}

/// Register one routing key for `account`. Every refusal is `client_error`,
/// so the reply does not say which rule applied; the reason is logged.
///
/// A key belongs to at most one account. The one exception to "first add
/// wins": a key registered by an account that never showed it holds it can
/// be taken over by the key's own holder, the account whose requests that
/// key authenticates. Otherwise, with `allow_unproven_routing_keys` on, the
/// first account to list a key could keep its real holder from ever
/// registering it.
async fn add_routing_key(
    state: &SharedData,
    account: &ClientAccount,
    batch: &mut KeylistBatch,
    index: usize,
    update: &cm::KeylistUpdate,
) -> cm::KeylistResult {
    let verkey = update.recipient_key.to_base58();
    let policy = &state.config.didcomm_v1;

    let owner = match state.database.v1_routing_key_lookup(&verkey).await {
        Ok(owner) => owner,
        Err(e) => {
            warn!(%verkey, error = %e, "v1 keylist lookup failed");
            return cm::KeylistResult::ServerError;
        }
    };
    // Already ours: nothing to do, and say so rather than claiming to have
    // made a change.
    if owner.as_deref() == Some(account.did.as_str()) {
        return cm::KeylistResult::NoChange;
    }

    if !batch.can_receive {
        warn!(
            did = %account.did,
            %verkey,
            "v1 keylist add refused: the account is not permitted to receive messages"
        );
        return cm::KeylistResult::ClientError;
    }

    // Coordinate-mediation 1.0 lets a client list any key, with nothing to
    // show it holds one. The key that authenticated this request is the only
    // one it has demonstrably used, so by default it is the only one it may
    // register. Deployments serving Aries wallets, which register a new key
    // per connection, opt in to accepting the others.
    let proven = update.recipient_key == account.verkey;
    if !proven && !policy.allow_unproven_routing_keys {
        warn!(
            did = %account.did,
            %verkey,
            "v1 keylist add refused: the key is not the one that authenticated the request \
             and [didcomm_v1] allow_unproven_routing_keys is off"
        );
        return cm::KeylistResult::ClientError;
    }

    // Another account holds it. Only the key's holder may take it over, and
    // only from an account other than the holder's own (which, the account
    // being the holder's `did:key`, is the one case `proven` excludes here).
    if owner.is_some() && !proven {
        warn!(
            did = %account.did,
            %verkey,
            "v1 keylist add refused: the key is registered to another account"
        );
        return cm::KeylistResult::ClientError;
    }

    let max = policy.max_routing_keys_per_account as usize;
    match batch.held(state, account).await {
        Ok(held) if held >= max => {
            warn!(
                did = %account.did,
                %verkey,
                held,
                max,
                "v1 keylist add refused: the account holds the maximum number of routing keys"
            );
            return cm::KeylistResult::ClientError;
        }
        Ok(_) => {}
        Err(e) => {
            warn!(%verkey, error = %e, "v1 keylist count failed");
            return cm::KeylistResult::ServerError;
        }
    }

    if let Some(previous) = owner.as_deref() {
        // Released only while `previous` still holds it; if it changed hands
        // meanwhile, the bind below finds the new owner and is refused.
        match state
            .database
            .v1_routing_key_unbind_if_owner(&verkey, previous)
            .await
        {
            Ok(_) => warn!(
                did = %account.did,
                previous_owner = %previous,
                %verkey,
                "v1 routing key taken over by its holder from an account that registered it \
                 without proof"
            ),
            Err(e) => {
                warn!(%verkey, error = %e, "v1 keylist takeover failed");
                return cm::KeylistResult::ServerError;
            }
        }
    }

    #[cfg(feature = "test-hooks")]
    test_hooks::on_before_bind(&verkey).await;

    match state
        .database
        .v1_routing_key_bind(&verkey, &account.did)
        .await
    {
        Ok(()) => {
            batch.record_add(index, verkey);
            cm::KeylistResult::Success
        }
        // The bind is refused when another account took the key after the
        // lookup above. That is a refusal like any other, not a fault.
        Err(e) => match state.database.v1_routing_key_lookup(&verkey).await {
            Ok(Some(other)) if other != account.did => {
                warn!(
                    did = %account.did,
                    %verkey,
                    "v1 keylist add refused: the key is registered to another account"
                );
                cm::KeylistResult::ClientError
            }
            _ => {
                warn!(%verkey, error = %e, "v1 keylist add failed");
                cm::KeylistResult::ServerError
            }
        },
    }
}

/// How many routing keys the account holds now.
async fn held_routing_keys(
    state: &SharedData,
    account: &ClientAccount,
) -> Result<usize, MediatorError> {
    Ok(state
        .database
        .v1_routing_keys_for(&account.did_hash)
        .await?
        .len())
}

/// Pause points for tests that need to land a change inside a race window.
/// Compiled only with the `test-hooks` feature, which no release build enables.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use tokio::sync::oneshot;

    struct Pause {
        reached: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    static BEFORE_BIND: LazyLock<Mutex<HashMap<String, Pause>>> = LazyLock::new(Default::default);

    /// Pause the next `keylist-update` add of `verkey` (base58) after its
    /// checks and before it binds the key. The first receiver fires once the
    /// add is paused there; sending on (or dropping) the returned sender lets
    /// it go on.
    pub fn pause_before_bind(verkey: &str) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        BEFORE_BIND.lock().expect("hook map").insert(
            verkey.to_string(),
            Pause {
                reached: reached_tx,
                resume: resume_rx,
            },
        );
        (reached_rx, resume_tx)
    }

    pub(super) async fn on_before_bind(verkey: &str) {
        let pause = BEFORE_BIND.lock().expect("hook map").remove(verkey);
        if let Some(p) = pause {
            let _ = p.reached.send(());
            let _ = p.resume.await;
        }
    }
}

async fn message_pickup(
    state: &SharedData,
    session: &Session,
    kind: mp::MessagePickup,
    msg: &MessageV1,
    account: &ClientAccount,
) -> Result<MessageV1, MediatorError> {
    match kind {
        mp::MessagePickup::StatusRequest => {
            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        mp::MessagePickup::DeliveryRequest => {
            let limit = mp::delivery_limit(msg)
                .unwrap_or(DEFAULT_DELIVERY_LIMIT)
                .min(MAX_DELIVERY_LIMIT);

            // Pickup 2.0 acknowledges separately: deleting on delivery would
            // lose any message whose delivery was lost in flight. See the
            // protocol module docs. Nothing is recorded here either: what the
            // reply carries is stamped delivered and reported once the REST
            // body is written (R1.1).
            let fetched = crate::after_write::fetch_for_handover(
                state,
                &session.session_id,
                &account.did_hash,
                &FetchOptions {
                    limit: limit as usize,
                    start_id: None,
                    delete_policy: FetchDeletePolicy::DoNotDelete,
                },
            )
            .await?;

            // Only what goes into the reply is handed over: a record without
            // a body, or a body that is not a v1 envelope (a stored TSP
            // message, say), stays queued rather than being reported as
            // delivered. Bodies stop at the same byte budget as a v2 pickup.
            let budget = crate::messages::protocols::message_pickup::delivery_byte_budget(
                state.limits().message_size,
            );
            let mut handed_over = crate::after_write::HandedOver::new(&account.did_hash);
            let mut messages: Vec<mp::QueuedMessage> = Vec::new();
            let mut used = 0usize;
            for element in &fetched.success {
                let Some(body) = element.msg.as_deref() else {
                    continue;
                };
                let Ok(envelope) = serde_json::from_str(body) else {
                    continue;
                };
                if !messages.is_empty() && used.saturating_add(body.len()) > budget {
                    break;
                }
                used = used.saturating_add(body.len());
                messages.push(mp::QueuedMessage {
                    id: element.msg_id.clone(),
                    envelope,
                });
                handed_over
                    .messages
                    .push(crate::after_write::HandedOverMessage::of(element));
            }

            // Nothing queued → answer with a status, as RFC 0685 specifies;
            // an empty `delivery` would look like a delivery that dropped
            // everything.
            if messages.is_empty() {
                let status = state.database.inbox_status(&account.did_hash).await?;
                return mp::status(&msg.id, status.message_count, None, false)
                    .map_err(|e| v1_build_error(session, e));
            }

            let reply =
                mp::delivery(&msg.id, &messages, None).map_err(|e| v1_build_error(session, e))?;
            // v1 is answered over REST only, so the completion waits for the
            // body; with no REST scope the reply reaches no transport.
            crate::after_write::defer_or_run(
                handed_over.completion(state, crate::monitor::current_channel()),
                false,
            )
            .await;
            Ok(reply)
        }

        mp::MessagePickup::MessagesReceived => {
            let ids = mp::parse_messages_received(msg).map_err(|e| {
                v1_problem(
                    session,
                    error_codes::DIDCOMM_V1_MALFORMED,
                    "message.didcomm_v1.messages_received",
                    format!("malformed messages-received: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            if ids.len() > MAX_ACK_IDS {
                return Err(v1_problem(
                    session,
                    error_codes::DIDCOMM_V1_MALFORMED,
                    "message.didcomm_v1.messages_received",
                    format!(
                        "messages-received lists {} ids, exceeding the maximum of {MAX_ACK_IDS}",
                        ids.len()
                    ),
                    StatusCode::BAD_REQUEST,
                ));
            }

            for id in &ids {
                // `Owner` authority makes the store reject an id the client
                // neither sent nor received, so one client cannot delete
                // another's messages by guessing ids.
                match state
                    .database
                    // An acknowledgement: this mailbox's own copy only.
                    .delete_message_in(
                        id,
                        MessageScope::Recipient(&account.did_hash),
                        DeletionAuthority::Owner {
                            did_hash: account.did_hash.clone(),
                        },
                    )
                    .await
                {
                    Ok(_) => state.monitor.deleted(
                        id,
                        &account.did_hash,
                        None,
                        Some(&account.did_hash),
                        crate::monitor::current_channel(),
                        // A v1 mailbox holds v1 envelopes; the body is not in
                        // hand here, so the stage is reported unclassified
                        // rather than guessed.
                        None,
                    ),
                    Err(e) => debug!(%id, error = %e, "v1 messages-received: delete failed"),
                }
            }

            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        mp::MessagePickup::LiveDeliveryChange => {
            // Live delivery would need a persistent connection to this client.
            // RFC 0685 has a problem-report for exactly this case; answering
            // with a truthful `live_delivery: false` status is the honest
            // alternative to silently accepting and never pushing.
            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        // Mediator-to-client messages.
        mp::MessagePickup::Status | mp::MessagePickup::Delivery => Err(v1_problem(
            session,
            error_codes::DIDCOMM_V1_MALFORMED,
            "message.didcomm_v1.unexpected",
            format!(
                "`{}` is a mediator-to-client message; the mediator does not accept it",
                msg.typ
            ),
            StatusCode::BAD_REQUEST,
        )),

        _ => Err(v1_problem(
            session,
            error_codes::PROTOCOL_UNSUPPORTED,
            "message.didcomm_v1.unsupported",
            format!("unsupported message-pickup message `{}`", msg.typ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// The endpoint a `mediate-grant` publishes for inbound traffic.
fn mediator_endpoint(state: &SharedData) -> String {
    // The DID document's DIDComm service endpoint is the authoritative answer;
    // fall back to the configured listen address so a development mediator
    // still returns something usable.
    state
        .config
        .mediator_did_document
        .as_ref()
        .and_then(|doc| {
            doc.service
                .iter()
                .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
                .and_then(|s| s.service_endpoint.get_uri())
        })
        .unwrap_or_else(|| state.config.listen_address.clone())
}

fn v1_build_error(session: &Session, error: impl std::fmt::Display) -> MediatorError {
    v1_problem(
        session,
        error_codes::MESSAGE_PACK_ERROR,
        "message.didcomm_v1.build",
        format!("couldn't build the DIDComm v1 reply: {error}"),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

fn v1_problem(
    session: &Session,
    code: u16,
    descriptor: &str,
    detail: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        code,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Message,
        descriptor,
        "{1}",
        vec![detail],
        status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verkey(seed: u8) -> Verkey {
        Verkey::from_bytes([seed; 32])
    }

    #[test]
    fn classifies_both_protocols_and_nothing_else() {
        let request = cm::mediate_request().unwrap();
        assert!(matches!(
            V1Request::classify(&request),
            Some(V1Request::CoordinateMediation(
                cm::CoordinateMediation::MediateRequest
            ))
        ));

        let status = mp::status_request(None).unwrap();
        assert!(matches!(
            V1Request::classify(&status),
            Some(V1Request::MessagePickup(mp::MessagePickup::StatusRequest))
        ));

        let forward = MessageV1::new(
            affinidi_messaging_didcomm_v1::protocols::forward::FORWARD_TYPE,
            json!({}),
        )
        .unwrap();
        assert!(
            V1Request::classify(&forward).is_none(),
            "a forward is routed, not answered"
        );

        let basic = affinidi_messaging_didcomm_v1::protocols::basic_message::BasicMessage::new("x")
            .unwrap()
            .finalize();
        assert!(V1Request::classify(&basic).is_none());
    }

    /// The account identifier must be derived purely from the authenticated
    /// verkey, so two requests from one key always reach the same account and a
    /// different key never does.
    #[test]
    fn account_did_is_derived_from_the_verkey() {
        let a = verkey(1).to_did_key();
        let b = verkey(1).to_did_key();
        let c = verkey(2).to_did_key();

        assert_eq!(a, b, "the same verkey must always yield the same account");
        assert_ne!(a, c);
        assert!(a.starts_with("did:key:z6Mk"));
        assert_eq!(
            Verkey::from_did_key(&a).unwrap(),
            verkey(1),
            "the derivation must be reversible, so a bound key can be read back"
        );
    }

    #[test]
    fn delivery_limits_are_bounded() {
        // Asks for more than the cap → capped.
        let big = mp::delivery_request(10_000, None).unwrap();
        assert_eq!(
            mp::delivery_limit(&big).unwrap().min(MAX_DELIVERY_LIMIT),
            MAX_DELIVERY_LIMIT
        );

        // Asks for nothing → the default, not unbounded.
        let none = MessageV1::new(mp::DELIVERY_REQUEST_TYPE, json!({})).unwrap();
        assert_eq!(
            mp::delivery_limit(&none).unwrap_or(DEFAULT_DELIVERY_LIMIT),
            DEFAULT_DELIVERY_LIMIT
        );

        const { assert!(DEFAULT_DELIVERY_LIMIT <= MAX_DELIVERY_LIMIT) };
    }
}
