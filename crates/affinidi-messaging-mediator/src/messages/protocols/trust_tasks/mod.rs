//! Trust Tasks framework consumer — handles inbound [Trust Task] documents
//! carried over the DIDComm binding envelope.
//!
//! A Trust Task request arrives as a DIDComm message whose `type` is the binding
//! envelope URI and whose `body` is the full `TrustTask<P>` document. This module
//! is the *single core*: it runs the framework's `consume_inbound` pipeline and
//! the per-task handlers (which delegate to the `state.database.*` store
//! methods). The response is a `TrustTask<R>` packed back
//! through the mediator's existing outbound path — exactly like the trust-ping
//! pong — so no separate binding/agent plumbing is needed here.
//!
//! This consumes the **rationalized** `messaging/*` surface
//! (affinidi/affinidi-tdk-rs#667; the served list is `served_tasks!`):
//! `account/update` replaces the retired
//! `change-type` / `change-queue-limits` / `acl/set` / `admin/add` /
//! `admin/strip`; `access-list/update` replaces `access-list/{add,remove,clear}`;
//! the role-filtered `account/list` replaces `admin/list`; the `entries`
//! membership filter on `access-list/list` replaces `access-list/get`; and the
//! generic `audit/list` / `config/show` tasks replace `admin/audit-log` /
//! `admin/config`. The retired URIs are **not** dual-accepted — they answer
//! `unsupportedType` like any other unknown type.
//!
//! This module holds the dispatch (`consume`, `served_tasks!`) and the helpers
//! every handler shares; the handlers live with their family: `accounts`,
//! `access_lists`, `admin` (audit and config), `mux`, and the wire mapping in
//! `wire`.
//!
//! [Trust Task]: https://trusttasks.org

// The handlers here are written against the 0.1 types. Seven of them also
// serve 0.2 (see `trust_task_versions`); the 0.1 types are marked superseded,
// and stay until 0.1 is withdrawn.
#![allow(deprecated)]

mod access_lists;
mod accounts;
mod admin;
mod mux;
mod wire;

use access_lists::*;
use accounts::*;
use admin::*;
use mux::*;
use wire::*;

use crate::error_codes;
use crate::task_specs::messaging::{
    access_list, account, acl, message, monitor, ping, queue, stats,
};
use crate::task_specs::{audit, config};
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::redact::redact_url;
use affinidi_messaging_mediator_common::store::{AccessListUpdate, AccountUpdate};
use affinidi_messaging_mediator_common::types::accounts::{Account, AccountType};
use affinidi_messaging_mediator_common::types::acls::{
    ACLError, AccessListModeType, MediatorACLSet,
};
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde_json::Value;
use sha256::digest;
use std::collections::HashSet;
use std::str::FromStr;
use subtle::ConstantTimeEq;
use trust_tasks_rs::{
    ConsumeChecks, ConsumeOutcome, NoValidator, Payload, PayloadPolicy, ProofPolicy, ProofVerifier,
    SpecPolicy, TransportContext, TransportHandler, TrustTask, TypeUri, VerificationError,
    consume_inbound,
};
use uuid::Uuid;

use crate::SharedData;
use crate::common::authz::check_permissions;
use crate::common::roles;
use crate::common::session::Session;
#[cfg(feature = "didcomm")]
use crate::messages::ProcessMessageResponse;
use crate::messages::protocols::mediator::record_audit;
use crate::messages::protocols::trust_task_versions::NewerVersion;
use crate::messages::protocols::{mediator_ops, trust_task_sign, trust_task_verify};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
/// Stable identifier for this transport binding.
const BINDING_URI: &str = "https://trusttasks.org/binding/didcomm/0.1";

/// The mediator's [`TransportHandler`] for one inbound exchange. The DIDComm
/// layer already verified the sender, so the framework's transport-authenticated
/// `issuer` is that DID and the `recipient` is the mediator.
struct MediatorTransport {
    mediator_did: String,
    sender_did: String,
}

impl TransportHandler for MediatorTransport {
    fn binding_uri(&self) -> &str {
        BINDING_URI
    }

    fn derive_parties(&self) -> TransportContext {
        TransportContext {
            issuer: Some(self.sender_did.clone()),
            recipient: Some(self.mediator_did.clone()),
        }
    }
}

/// No-op proof verifier — the management tasks are transport-authenticated, so
/// the consume pipeline runs with [`ProofPolicy::AcceptUnverified`] and this is
/// never invoked; it only satisfies the type parameter.
struct NoProof;

#[async_trait::async_trait]
impl ProofVerifier for NoProof {
    async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
    where
        P: serde::Serialize + Send + Sync,
    {
        Ok(())
    }
}

/// Consume an inbound Trust Tasks envelope and produce the response.
/// The DIDComm binding: a Trust Task carried in a DIDComm envelope, answered
/// in one. The TSP binding is `inbound::tsp::dispatch_tsp_trust_task`.
#[cfg(feature = "didcomm")]
pub(crate) async fn process(
    message: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let mediator_did = state.config.mediator_did.clone();

    // The DIDComm-verified sender (prefer the JWS signer, fall back to the
    // authcrypt sender), stripped of its key fragment → the framework VID.
    let sender_kid = metadata
        .sign_from
        .clone()
        .or_else(|| metadata.encrypted_from_kid.clone())
        .ok_or_else(|| {
            tt_problem(
                session,
                "permissionDenied",
                "Trust Task envelopes require an authenticated sender".into(),
                StatusCode::BAD_REQUEST,
            )
        })?;

    // The body is the full TrustTask document.
    let doc: TrustTask<Value> = serde_json::from_value(message.body.clone()).map_err(|e| {
        tt_problem(
            session,
            "malformedRequest",
            format!("body is not a Trust Task document: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let now_secs = state.clock.unix_secs();
    let sender_did = vid_of(&sender_kid);
    let request_type = doc.type_uri.to_string();
    // A refusal is answered with a `trust-task-error` document where one can
    // be sent (see `trust_task_error`).
    let refusing = crate::messages::protocols::trust_task_error::Refusing::of(&doc);
    let consumed = consume(
        doc,
        &message.body,
        state,
        session,
        &sender_kid,
        now_secs,
        TaskTransport::DidComm,
    )
    .await;
    let response_value = match consumed {
        Ok(Some(v)) => v,
        // identity_mismatch with no transport sender → emit nothing.
        Ok(None) => return Ok(ProcessMessageResponse::Nothing),
        Err(e) => match refusing.document(&e, session, &sender_did, state).await {
            Some(doc) => doc,
            None => return Err(e),
        },
    };
    // The answer to `messaging/mux/ack`, or its refusal, goes to the
    // connection only, never stored (`mux::tasks::answer_is_pushed`): a
    // stored one would need acknowledging in turn. Lost with the connection,
    // it is recovered by asking again.
    let push_only = crate::mux::tasks::answer_is_pushed(&response_value, &request_type);

    // Pack the response back through the mediator's existing outbound path.
    // `thid` threads it to the request so the caller's live-stream correlates it.
    let response_msg = Message::build(
        Uuid::new_v4().to_string(),
        ENVELOPE_TYPE.to_string(),
        response_value,
    )
    .thid(message.id.clone())
    .to(sender_did)
    .from(mediator_did)
    .created_time(now_secs)
    .expires_time(now_secs + 300)
    .finalize();

    Ok(if push_only {
        ProcessMessageResponse::EphemeralReply {
            message: Box::new(response_msg),
            force_live_delivery: true,
            handed_over: None,
        }
    } else {
        ProcessMessageResponse::Reply(Box::new(response_msg))
    })
}

/// Strip a key fragment from a `did#key` to get the framework VID.
pub(crate) fn vid_of(kid: &str) -> String {
    kid.split('#').next().unwrap_or(kid).to_string()
}

/// Which transport carried a Trust Task request in. Almost nothing cares —
/// the framework is transport-agnostic — but a monitor subscription is served
/// back over the transport it was opened on, because that decides how its
/// batches are sealed and delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskTransport {
    #[cfg(feature = "didcomm")]
    DidComm,
    #[cfg(feature = "tsp")]
    Tsp,
}

/// Consume one Trust Task document from an authenticated sender and produce the
/// response document. `None` means "emit nothing" (a ping identity mismatch).
///
/// **Transport-agnostic on purpose.** Every `consume_*` handler below takes the
/// document, the authenticated sender and `state`/`session` — nothing about a
/// DIDComm envelope — so the only transport-specific work is establishing
/// `sender_kid` and packing the reply, which the callers do. That is what lets
/// the same management surface answer over TSP: see the TSP arm in
/// [`crate::messages::inbound`], which unpacks a `Direct`/`Control` message
/// addressed to this mediator and calls straight into here.
///
/// `sender_kid` MUST have been established cryptographically by the caller — a
/// DIDComm authcrypt/JWS unpack, or a TSP unpack (Ed25519 over
/// envelope‖ciphertext plus HPKE-Auth). Handlers authorise against it, so a
/// caller that passes an unverified claim hands an attacker the admin surface.
///
/// Every refusal it returns carries a Trust Task error code
/// ([`trust_task_error::normalize`](crate::messages::protocols::trust_task_error::normalize)),
/// whichever handler or helper raised it.
pub(crate) async fn consume(
    doc: TrustTask<Value>,
    raw: &Value,
    state: &SharedData,
    session: &Session,
    sender_kid: &str,
    now_secs: u64,
    transport: TaskTransport,
) -> Result<Option<Value>, MediatorError> {
    consume_task(doc, raw, state, session, sender_kid, now_secs, transport)
        .await
        .map_err(crate::messages::protocols::trust_task_error::normalize)
}

async fn consume_task(
    doc: TrustTask<Value>,
    raw: &Value,
    state: &SharedData,
    session: &Session,
    sender_kid: &str,
    now_secs: u64,
    transport: TaskTransport,
) -> Result<Option<Value>, MediatorError> {
    let mediator_did = state.config.mediator_did.clone();
    let sender_kid = sender_kid.to_string();
    let sender_did = vid_of(&sender_kid);
    let now = chrono::DateTime::from_timestamp(now_secs as i64, 0).unwrap_or_else(chrono::Utc::now);

    // One identity for the whole request: the authenticated session, which
    // must be the DID that sent the task. Handlers authorise on the session,
    // the mux tasks on the sender and the audit log records the session, so
    // the two have to be the same account before any of them runs.
    crate::common::authz::require_session_sender(session, Some(&sender_did), None)?;
    // The caller's role and ACLs as the store holds them now.
    let principal = roles::principal(state, session).await?;
    let session = &principal;

    // Route by task type. The match is exhaustive over `ServedTask`, so a type
    // registered in `served_tasks!` without a handler here fails to compile.
    let sk = Some(sender_kid.clone());
    // A type withheld by the embedder (a test standing in for an older
    // mediator) is refused below as one that isn't served at all.
    let withheld = !state.config.withheld_task_types.is_empty()
        && state
            .config
            .withheld_task_types
            .iter()
            .any(|t| *t == doc.type_uri.to_string());
    // A 0.2 request is served by its 0.1 task's handler (`newer` says which
    // version was asked for; see `trust_task_versions`).
    let served = ServedTask::from_type_uri(&doc.type_uri).filter(|_| !withheld);
    let (task, newer) = match served {
        Some(task) => (task, None),
        None => match NewerVersion::from_type_uri(&doc.type_uri).filter(|_| !withheld) {
            Some(newer) => (newer.base(), Some(newer)),
            None => {
                return Err(tt_problem(
                    session,
                    "unsupportedType",
                    format!("unsupported Trust Task type: {}", doc.type_uri),
                    StatusCode::NOT_IMPLEMENTED,
                ));
            }
        },
    };
    // The §7.2 acceptance checks (freshness, issuer binding, proof, spec
    // policy) for every management task. `ping` keeps its own pipeline: it is
    // not consequential, and it answers an identity mismatch with silence.
    // A wake request runs its own acceptance, which no verification mode
    // relaxes (`wake::request::handle`).
    if !matches!(task, ServedTask::Ping | ServedTask::WakeRequest) {
        trust_task_verify::accept(
            &doc,
            raw,
            // Accepted under the rules of the version that was sent.
            newer.map_or_else(|| task.spec_policy(), NewerVersion::spec_policy),
            &sender_did,
            now,
            state,
            session,
        )
        .await?;
    }

    let doc = match newer {
        Some(newer) => newer.to_v0_1_request(doc),
        None => doc,
    };

    let response_value: Value = match task {
        ServedTask::Ping => {
            match consume_ping(downcast(&doc, session)?, &mediator_did, &sender_did, now).await? {
                Some(value) => value,
                // identity_mismatch with no transport sender → emit nothing.
                None => return Ok(None),
            }
        }
        ServedTask::AccountGet => {
            consume_account_get(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AccountList => {
            consume_account_list(downcast(&doc, session)?, state, session, &mediator_did, now)
                .await?
        }
        ServedTask::AccountUpdate => {
            consume_account_update(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AccountRemove => {
            consume_account_remove(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AccountAdd => {
            consume_account_add(downcast(&doc, session)?, state, session, &mediator_did, now)
                .await?
        }
        ServedTask::AclGet => {
            consume_acl_get(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AccessListUpdate => {
            consume_access_list_update(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AccessListList => {
            consume_access_list_list(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::AuditList => {
            consume_audit_list(downcast(&doc, session)?, state, session, &mediator_did, now).await?
        }
        ServedTask::ConfigReload => {
            mediator_ops::consume_config_reload(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::ConfigPatch => {
            mediator_ops::consume_config_patch(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::ConfigShow => {
            consume_config_show(downcast(&doc, session)?, state, session, &mediator_did, now)
                .await?
        }
        ServedTask::StatsShow => {
            mediator_ops::consume_stats_show(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MessageList => {
            mediator_ops::consume_message_list(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MessageGet => {
            mediator_ops::consume_message_get(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MessageStatus => {
            mediator_ops::consume_message_status(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MessageDelete => {
            mediator_ops::consume_message_delete(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::QueuePurge => {
            mediator_ops::consume_queue_purge(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MonitorSubscribe => {
            mediator_ops::consume_monitor_subscribe(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
                transport,
            )
            .await?
        }
        ServedTask::MonitorSubscribeV0_2 => {
            mediator_ops::consume_monitor_subscribe_v0_2(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
                transport,
            )
            .await?
        }
        ServedTask::MonitorUnsubscribe => {
            mediator_ops::consume_monitor_unsubscribe(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::QueueStatus => {
            mediator_ops::consume_queue_status(
                downcast(&doc, session)?,
                state,
                session,
                &sk,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::QueueList => {
            mediator_ops::consume_queue_list(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::MuxAck
        | ServedTask::MuxAttach
        | ServedTask::MuxDetach
        | ServedTask::MuxGrant
        | ServedTask::MuxList
        | ServedTask::MuxUpdate
        | ServedTask::MuxRevoke
        | ServedTask::MuxRevokeAll => {
            consume_mux(task, &doc, state, session, &sender_did, &mediator_did, now).await?
        }
        ServedTask::MuxConnections => {
            consume_mux_connections(&doc, state, session, &mediator_did, now).await?
        }
        ServedTask::MuxAdminList | ServedTask::MuxAdminRevoke | ServedTask::MuxAdminRevokeAll => {
            consume_mux_admin(task, &doc, state, session, &mediator_did, now).await?
        }
        ServedTask::WakeSet => {
            crate::wake::set::consume_wake_set(
                downcast(&doc, session)?,
                state,
                session,
                &mediator_did,
                now,
            )
            .await?
        }
        ServedTask::WakeRequest => {
            crate::wake::request::handle(state, session, doc.clone(), raw, &sender_did, false)
                .await?
        }
    };

    // Answer in the version that was asked for, before signing.
    let response_value = match newer {
        Some(newer) => newer
            .to_v0_2_response(response_value)
            .map_err(serialize_err_msg)?,
        None => response_value,
    };

    // Every success response is signed as the mediator (see `trust_task_sign`).
    let response_value = trust_task_sign::sign_response(response_value, state).await?;

    Ok(Some(response_value))
}

/// Declares every Trust Task type this mediator serves — the **single list**.
///
/// It generates [`ServedTask`], whose variants [`consume`] matches exhaustively,
/// and [`ServedTask::ALL`], which [`parse_if_served`] (the TSP arm) and discovery
/// read. Before this, the dispatch chain and a hand-kept `served_type_uris()`
/// array had to be edited in step; a type added to the dispatch but not the
/// array was silently filed into the mediator's inbox when it arrived over TSP.
/// Now a new type is one line here, and the compiler refuses to build until
/// [`consume`] has an arm for it.
macro_rules! served_tasks {
    ($($variant:ident => $payload:ty),+ $(,)?) => {
        /// A Trust Task type this mediator serves. See [`served_tasks!`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum ServedTask {
            $($variant),+
        }

        impl ServedTask {
            /// Every served type, in declaration order.
            pub(crate) const ALL: &'static [ServedTask] = &[$(ServedTask::$variant),+];

            /// The canonical request type URI of this task.
            pub(crate) fn type_uri(self) -> TypeUri {
                match self {
                    $(ServedTask::$variant => type_uri_of::<$payload>()),+
                }
            }

            /// The spec's presence rules (proof, `issuedAt`, recipient) for
            /// this task, read off its generated payload type.
            pub(crate) fn spec_policy(self) -> SpecPolicy {
                match self {
                    $(ServedTask::$variant => SpecPolicy::of::<$payload>()),+
                }
            }
        }
    };
}

served_tasks! {
    Ping => ping::v0_1::Payload,
    AccountGet => account::get::v0_1::Payload,
    AccountList => account::list::v0_1::Payload,
    AccountUpdate => account::update::v0_1::Payload,
    AccountRemove => account::remove::v0_1::Payload,
    AccountAdd => account::add::v0_1::Payload,
    AclGet => acl::get::v0_1::Payload,
    AccessListUpdate => access_list::update::v0_1::Payload,
    AccessListList => access_list::list::v0_1::Payload,
    AuditList => audit::list::v0_1::Payload,
    ConfigShow => config::show::v0_1::Payload,
    ConfigPatch => config::patch::v0_1::Payload,
    ConfigReload => config::reload::v0_1::Payload,
    StatsShow => stats::show::v0_1::Payload,
    QueueList => queue::list::v0_1::Payload,
    QueueStatus => queue::status::v0_1::Payload,
    MessageList => message::list::v0_1::Payload,
    MessageGet => message::get::v0_1::Payload,
    MessageDelete => message::delete::v0_1::Payload,
    MessageStatus => message::status::v0_1::Payload,
    QueuePurge => queue::purge::v0_1::Payload,
    MonitorSubscribe => monitor::subscribe::v0_1::Payload,
    // 0.2 extends 0.1 with requests 0.1's handler cannot take (the
    // membership opt-in), so it is its own task rather than a rewrite.
    MonitorSubscribeV0_2 => monitor::subscribe::v0_2::Payload,
    MonitorUnsubscribe => monitor::unsubscribe::v0_1::Payload,
    MuxAck => crate::task_specs::messaging::mux::ack::v0_1::Payload,
    MuxAttach => crate::task_specs::messaging::mux::attach::v0_1::Payload,
    MuxDetach => crate::task_specs::messaging::mux::detach::v0_1::Payload,
    MuxGrant => crate::task_specs::messaging::mux::grant::v0_1::Payload,
    MuxList => crate::task_specs::messaging::mux::list::v0_1::Payload,
    MuxUpdate => crate::task_specs::messaging::mux::update::v0_1::Payload,
    MuxRevoke => crate::task_specs::messaging::mux::revoke::v0_1::Payload,
    MuxRevokeAll => crate::task_specs::messaging::mux::revoke_all::v0_1::Payload,
    MuxConnections => crate::task_specs::messaging::mux::connections::v0_1::Payload,
    MuxAdminList => crate::task_specs::messaging::mux::admin_list::v0_1::Payload,
    MuxAdminRevoke => crate::task_specs::messaging::mux::admin_revoke::v0_1::Payload,
    MuxAdminRevokeAll => crate::task_specs::messaging::mux::admin_revoke_all::v0_1::Payload,
    WakeSet => crate::task_specs::messaging::wake::set::v0_1::Payload,
    // Over DIDComm a wake request is taken before the session checks, from
    // any authenticated sender (`wake::didcomm`); this arm serves an
    // account's request over TSP.
    WakeRequest => crate::task_specs::messaging::wake::request::v0_1::Payload,
}

impl ServedTask {
    /// The served task a document's `type` names, if any. Only an exact match
    /// on a request type URI is served — a `#response` or a retired URI is not.
    pub(crate) fn from_type_uri(uri: &TypeUri) -> Option<Self> {
        Self::ALL.iter().copied().find(|t| t.type_uri() == *uri)
    }
}

/// Parse `payload` as a Trust Task document, but only claim it when this
/// mediator actually serves the type.
///
/// Used by the TSP arm, which has no envelope tag to switch on: the client packs
/// the bare task document. Being strict about the type is what keeps that safe —
/// an ordinary message that merely happens to deserialise into the document
/// shape is *not* claimed, so it still reaches the mediator's inbox. The cost of
/// being wrong runs one way only: a served type mis-parsed as mail would be
/// silently filed, so the type check is the thing that must not drift, which is
/// why it reads [`ServedTask`] — the same list the dispatch matches on.
#[cfg(feature = "tsp")]
pub(crate) fn parse_if_served(payload: &[u8]) -> Option<TrustTask<Value>> {
    let doc: TrustTask<Value> = serde_json::from_slice(payload).ok()?;
    let served = ServedTask::from_type_uri(&doc.type_uri).is_some()
        || NewerVersion::from_type_uri(&doc.type_uri).is_some();
    served.then_some(doc)
}

/// The canonical request type URI of a generated payload `P`.
fn type_uri_of<P: Payload>() -> TypeUri {
    TypeUri::from_str(P::TYPE_URI).expect("generated payload has a valid type URI")
}

/// Re-deserialise a type-erased document into the typed payload `P`.
fn downcast<P: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    session: &Session,
) -> Result<TrustTask<P>, MediatorError> {
    // Only the payload changes type, so only it is decoded, in place: the
    // whole document is not serialised to a `Value` and parsed back (#198).
    let payload = P::deserialize(&doc.payload).map_err(|e| {
        tt_problem(
            session,
            "malformedRequest",
            format!("payload does not match the task type: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    Ok(TrustTask {
        id: doc.id.clone(),
        thread_id: doc.thread_id.clone(),
        parent_thread_id: doc.parent_thread_id.clone(),
        ceremony: doc.ceremony.clone(),
        type_uri: doc.type_uri.clone(),
        issuer: doc.issuer.clone(),
        recipient: doc.recipient.clone(),
        issued_at: doc.issued_at,
        expires_at: doc.expires_at,
        payload,
        context: doc.context.clone(),
        proof: doc.proof.clone(),
        extra: doc.extra.clone(),
    })
}

/// The transport protocols this build serves, as a Trust Task ping reports
/// them: never one it was built without.
fn served_protocols() -> Vec<String> {
    let mut protocols = Vec::new();
    if cfg!(feature = "didcomm") {
        protocols.push("didcomm".to_string());
    }
    if cfg!(feature = "tsp") {
        protocols.push("tsp".to_string());
    }
    protocols
}

pub(crate) fn require_admin(session: &Session, task: &str) -> Result<(), MediatorError> {
    if roles::can_administer(session.account_type) {
        Ok(())
    } else {
        Err(tt_problem(
            session,
            "permissionDenied",
            format!("{task} requires an admin account"),
            StatusCode::FORBIDDEN,
        ))
    }
}

/// A Trust Task refusal under `code`: one of the framework's standard codes
/// (SPEC §8.3: `permissionDenied`, `malformedRequest`, …) or a
/// `<task>:<code>` the task's specification declares. It is answered with a
/// `trust-task-error` document carrying `code`, or, where no document can be
/// sent, a problem report `e.p.<code>`
/// ([`trust_task_error`](crate::messages::protocols::trust_task_error)).
pub(crate) fn tt_problem(
    session: &Session,
    code: &str,
    message: String,
    status: StatusCode,
) -> MediatorError {
    tt_problem_with_args(session, code, message, vec![], status)
}

/// [`tt_problem`] with problem-report arguments: the values a declared
/// code's `details` are built from (`currentEpoch`, `size`).
pub(crate) fn tt_problem_with_args(
    session: &Session,
    code: &str,
    message: String,
    args: Vec<String>,
    status: StatusCode,
) -> MediatorError {
    let number = crate::error_codes::trust_task_code(code);
    debug_assert!(number.is_some(), "{code} is not a Trust Task error code");
    MediatorError::problem(
        number.unwrap_or(crate::error_codes::TT_TASK_FAILED),
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        code,
        &message,
        args,
        status,
    )
}

/// Framework basics: the request is addressed to this mediator and not expired.
pub(crate) fn validate_tt_basic<P>(
    typed: &TrustTask<P>,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), MediatorError> {
    typed.validate_basic(now, mediator_did).map_err(|reason| {
        // `expired` or `wrongRecipient`, as the framework names them.
        tt_problem(
            session,
            reason.code().as_str(),
            format!(
                "Trust Task failed basic validation: {}",
                reason.wire_message()
            ),
            StatusCode::FORBIDDEN,
        )
    })
}

/// Finish a generated document builder.
///
/// trust-tasks-rs 0.17 made the generated payload and response structs
/// `#[non_exhaustive]`, so this crate can no longer name every member in a
/// struct literal. That is deliberate: the registry can add an OPTIONAL member
/// without breaking every consumer that had spelled out the old member list.
///
/// The trade is that "is every required member set?" moves from compile time to
/// this conversion — the builder starts each required member as
/// `Err("no value supplied for …")`. Every call below therefore sets its
/// required members explicitly and lets only optional ones default.
pub(crate) fn build<T, B>(builder: B) -> Result<T, MediatorError>
where
    B: TryInto<T>,
    B::Error: std::fmt::Display,
{
    builder
        .try_into()
        .map_err(|e| serialize_err_msg(format!("couldn't build Trust Task document: {e}")))
}

/// An ACL in a request that is not a valid ACL: the client's error, so a
/// `malformedRequest` (400), never an internal one.
fn malformed_acl(msg: String) -> MediatorError {
    MediatorError::RequestDataError(error_codes::TT_MALFORMED_REQUEST, "NA".to_string(), msg)
}

fn serialize_err_msg(msg: String) -> MediatorError {
    MediatorError::InternalError(error_codes::INTERNAL_ERROR, "NA".to_string(), msg)
}

pub(crate) fn serialize_err(e: serde_json::Error) -> MediatorError {
    MediatorError::InternalError(
        error_codes::INTERNAL_ERROR,
        "NA".to_string(),
        format!("couldn't serialise Trust Task response: {e}"),
    )
}

/// Run the `ping` task through the framework's consume pipeline, returning the
/// response document as JSON (`None` when the framework suppresses the response).
async fn consume_ping(
    doc: TrustTask<ping::v0_1::Payload>,
    mediator_did: &str,
    sender_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Value>, MediatorError> {
    let transport = MediatorTransport {
        mediator_did: mediator_did.to_string(),
        sender_did: sender_did.to_string(),
    };
    let outcome = consume_inbound(
        &transport,
        ProofPolicy::<NoProof>::AcceptUnverified,
        // SPEC §7.2 item 2. `AcceptUnvalidated` keeps the behaviour this call
        // has always had, now stated rather than implied: `ping::v0_1::Payload`
        // is a codegen struct with `deny_unknown_fields` and validating
        // newtypes, so deserializing into it already enforced the required
        // members, their types, and the pattern/length constraints. What
        // `Validate` would add is the residue a Rust type cannot express
        // (`minProperties`, `minItems` on an optional array, conditional
        // subschemas), and `ping` declares none of it.
        //
        // Turning this to `Validate` is a behaviour change, not a tidy-up: it
        // can start refusing documents a peer sends today. Do it as its own
        // change, with its own rollout, never folded into a version bump.
        PayloadPolicy::<NoValidator>::AcceptUnvalidated,
        // SPEC §7.2 items 4 and 11, required as one argument since
        // `trust-tasks-rs` 0.12 so a deployment cannot configure a replay
        // record and an unbounded acceptance window and believe it has a
        // replay defence.
        //
        // `ping` is not a *consequential Trust Task* (§2): answering it grants
        // no access, moves no value, discloses nothing beyond a nonce echo and
        // the protocol list, and executing it twice leaves the mediator
        // exactly as executing it once did. So item 11 is knowingly
        // disapplied and no record is kept — for a liveness probe, a
        // per-document record would be pure cost on the hottest path this
        // module has.
        //
        // `not_consequential` still applies `FreshnessPolicy::default`, which
        // is the part that matters here: a future-dated document and one whose
        // validity interval never contained an instant are malformed whatever
        // the task does. That is new behaviour for this call — before 0.12 the
        // only temporal check was `expiresAt`, and `issuedAt` was parsed and
        // never looked at.
        ConsumeChecks::not_consequential(),
        doc,
        mediator_did,
        now,
        || Uuid::new_v4().to_string(),
        |req, _parties| async move {
            // `expect`, not `?`: this closure answers with a
            // `TrustTask<ErrorPayload>`, and there is no error to report. The
            // builder's only failure mode is an unset required member, and all
            // four are set on the next four lines.
            let response: ping::v0_1::Response = ping::v0_1::Response::builder()
                .nonce(req.payload.nonce.clone())
                .protocols(served_protocols())
                .server_time(now)
                .status(ping::v0_1::ResponseStatus::Ok)
                .try_into()
                .expect("every required member of the ping response is set above");
            Ok(req.respond_with(Uuid::new_v4().to_string(), response))
        },
    )
    .await;

    Ok(match outcome {
        ConsumeOutcome::Handled(resp) => Some(serde_json::to_value(&resp).map_err(serialize_err)?),
        ConsumeOutcome::Rejected(err) => Some(serde_json::to_value(&err).map_err(serialize_err)?),
        ConsumeOutcome::Suppressed => None,
        // Unreachable under `ReplayPolicy::NotConsequential` — no record is
        // kept, so nothing can be recognised as a duplicate. Matched rather
        // than `unreachable!()` so that turning this call consequential later
        // is a compile-time prompt to decide what to return, not a panic in
        // production on the first retried ping.
        ConsumeOutcome::Duplicate { prior_response, .. } => prior_response
            .map(|r| serde_json::to_value(&r).map_err(serialize_err))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reverse ACL map (`merge_wire_acl`) must exactly invert the decode
    /// (`decode_acl_canonical`): decoding a bitfield to the wire form and merging it
    /// back onto the same base must reproduce the original `u64`. Covers the value
    /// bits, the preserved per-capability change bits, and the self-manage flags.
    #[test]
    fn acl_reverse_map_round_trips() {
        let cases = [
            MediatorACLSet::default().to_u64(),
            MediatorACLSet::from_string_ruleset("ALLOW_ALL")
                .expect("ALLOW_ALL ruleset")
                .to_u64(),
            MediatorACLSet::from_string_ruleset("DENY_ALL")
                .expect("DENY_ALL ruleset")
                .to_u64(),
            MediatorACLSet::from_string_ruleset("ALLOW_ALL, ALLOW_ALL_SELF_CHANGE")
                .expect("mixed ruleset")
                .to_u64(),
        ];
        for bits in cases {
            let decoded = decode_acl_canonical(&MediatorACLSet::from_u64(bits));
            let value = serde_json::to_value(&decoded).expect("acl serialises");
            let merged =
                merge_wire_acl(value, MediatorACLSet::from_u64(bits)).expect("merge succeeds");
            assert_eq!(
                merged.to_u64(),
                bits,
                "decode→merge must reproduce {bits:#018x}"
            );
        }
    }
    use trust_tasks_rs::TrustTask;

    /// `(send, receive)` hard limits standing in for a mediator's configuration.
    const HARD: (i32, i32) = (2_000, 1_000);

    /// A standard account that self-manages both queue limits.
    fn self_managing_account() -> Session {
        let mut acls = MediatorACLSet::default();
        acls.set_self_manage_send_queue_limit(true);
        acls.set_self_manage_receive_queue_limit(true);
        Session {
            session_id: "test-session".to_string(),
            account_type: AccountType::Standard,
            acls,
            ..Default::default()
        }
    }

    fn admin_account() -> Session {
        Session {
            session_id: "test-session".to_string(),
            account_type: AccountType::Admin,
            ..Default::default()
        }
    }

    /// The problem-report code and HTTP status an error carries, or a panic when
    /// it is not a problem report — a refusal the caller cannot read is a no-op
    /// with extra steps.
    fn problem_of(err: &MediatorError) -> (String, u16) {
        match err {
            MediatorError::MediatorError(_, _, _, report, status, _) => {
                (report.code.clone(), *status)
            }
            other => panic!("expected a problem report, got {other:?}"),
        }
    }

    #[test]
    fn a_standard_account_cannot_switch_a_queue_limit_off() {
        // The bug: `-1` means *no limit*, and being below every maximum it slid
        // past the over-hard clamp and was stored verbatim, after which the
        // sender gate never refused the account again. Permission to raise a
        // limit is not permission to remove it, so this is refused outright.
        for requested in [(Some(-1), None), (None, Some(-1))] {
            let err = resolve_queue_limits(&self_managing_account(), false, requested, HARD)
                .expect_err("-1 must be refused for a standard account");
            let (code, status) = problem_of(&err);
            assert!(
                code.ends_with("permissionDenied"),
                "unexpected problem code {code}"
            );
            assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
        }

        // Nothing past `-2` is a limit either, and the gate casts to `u32`, so
        // `-5` would read as four billion. Same refusal.
        for value in [-3, -5, i32::MIN] {
            assert!(
                resolve_queue_limits(&self_managing_account(), false, (Some(value), None), HARD)
                    .is_err(),
                "{value} must be refused for a standard account"
            );
        }
    }

    #[test]
    fn a_standard_account_may_still_reset_to_the_mediator_default() {
        // `-2` is not a limit value: the store turns it into an `HDEL` of the
        // per-account override. It must keep passing through untouched.
        assert_eq!(
            resolve_queue_limits(&self_managing_account(), false, (Some(-2), Some(-2)), HARD)
                .expect("-2 is a reset, not an unlimited value"),
            (Some(-2), Some(-2))
        );
    }

    #[test]
    fn a_standard_account_is_clamped_to_the_hard_limit() {
        assert_eq!(
            resolve_queue_limits(
                &self_managing_account(),
                false,
                (Some(50_000), Some(50_000)),
                HARD
            )
            .expect("an oversized value is clamped, not refused"),
            (Some(HARD.0), Some(HARD.1))
        );
        // A value within the limit is stored as asked.
        assert_eq!(
            resolve_queue_limits(
                &self_managing_account(),
                false,
                (Some(500), Some(500)),
                HARD
            )
            .expect("an in-range value stands"),
            (Some(500), Some(500))
        );
        // A limit the account does not self-manage is refused outright, the way
        // `ensure_self_manageable` refuses a capability it may not change — not
        // dropped, which would echo the old value back as a success.
        let mut session = self_managing_account();
        session.acls.set_self_manage_send_queue_limit(false);
        let err = resolve_queue_limits(&session, false, (Some(500), Some(500)), HARD)
            .expect_err("a limit the account does not self-manage is refused");
        let (code, status) = problem_of(&err);
        assert!(
            code.ends_with("messaging/account/update:selfChangeDenied"),
            "unexpected problem code {code}"
        );
        assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
    }

    #[test]
    fn an_unbounded_mediator_has_no_ceiling_to_clamp_to() {
        // `hard = -1` is the operator saying this limit is not bounded. Clamping
        // against it would invert: `500 > -1` holds, so an account asking to be
        // held to 500 would have been stored as unlimited — reaching the very
        // state the gate above refuses, by asking for something *tighter*.
        assert_eq!(
            resolve_queue_limits(
                &self_managing_account(),
                false,
                (Some(500), Some(500)),
                (-1, -1)
            )
            .expect("a finite request stands when the mediator is unbounded"),
            (Some(500), Some(500))
        );
        // And `-1` is still not the account's to ask for, bounded or not.
        assert!(
            resolve_queue_limits(&self_managing_account(), false, (Some(-1), None), (-1, -1))
                .is_err(),
            "an unbounded mediator does not hand out its own exemption"
        );
    }

    #[test]
    fn a_limit_the_account_does_not_self_manage_is_only_refused_when_it_is_asked_for() {
        // Both limits run through the gate on every request. An account that
        // self-manages send but not receive must still be able to set send: the
        // omitted receive member is nothing to refuse.
        let mut session = self_managing_account();
        session.acls.set_self_manage_receive_queue_limit(false);
        assert_eq!(
            resolve_queue_limits(&session, false, (Some(42), None), HARD)
                .expect("an omitted member is not a request to change it"),
            (Some(42), None)
        );
        // Asking for it is still refused.
        assert!(
            resolve_queue_limits(&session, false, (Some(42), Some(42)), HARD).is_err(),
            "the receive limit is not this account's to set"
        );
    }

    #[test]
    fn an_account_whose_type_did_not_decode_is_gated_like_a_standard_one() {
        // The gate runs on the caller's admin test, not on "anything that is not
        // Standard". `Unknown` is not an admin — `account/update` refuses its ACL
        // member for exactly that reason — so it must not slip past this one.
        let mut session = self_managing_account();
        session.account_type = AccountType::Unknown;
        assert!(
            resolve_queue_limits(&session, false, (Some(-1), None), HARD).is_err(),
            "a non-admin session must be gated whatever its account type"
        );
    }

    #[test]
    fn an_admin_may_still_set_a_queue_limit_to_unlimited() {
        // The gate is for self-service only. An admin's request stands as sent,
        // unlimited included, and is never clamped to the hard limit.
        assert_eq!(
            resolve_queue_limits(&admin_account(), true, (Some(-1), Some(-1)), HARD)
                .expect("an admin sets any value"),
            (Some(-1), Some(-1))
        );
        assert_eq!(
            resolve_queue_limits(&admin_account(), true, (Some(50_000), Some(-2)), HARD)
                .expect("an admin sets any value"),
            (Some(50_000), Some(-2))
        );
    }

    #[tokio::test]
    async fn ping_consume_returns_ok_and_echoes_nonce() {
        let payload: ping::v0_1::Payload = ping::v0_1::Payload::builder()
            .nonce(Some("nonce-xyz".to_string()))
            .try_into()
            .expect("the ping payload has no required member");
        let mut doc = TrustTask::for_payload("urn:uuid:ping-1", payload);
        doc.issuer = Some("did:example:alice".to_string());
        doc.recipient = Some("did:example:mediator".to_string());

        let value = consume_ping(
            doc,
            "did:example:mediator",
            "did:example:alice",
            chrono::Utc::now(),
        )
        .await
        .expect("consume ok")
        .expect("a response, not suppressed");

        let resp: TrustTask<ping::v0_1::Response> =
            serde_json::from_value(value).expect("ping response document");
        assert!(matches!(
            resp.payload.status,
            ping::v0_1::ResponseStatus::Ok
        ));
        assert_eq!(resp.payload.nonce.as_deref(), Some("nonce-xyz"));
        assert_eq!(resp.payload.protocols, super::served_protocols());
        // respond_with swaps the parties: the mediator answers alice.
        assert_eq!(resp.issuer.as_deref(), Some("did:example:mediator"));
        assert_eq!(resp.recipient.as_deref(), Some("did:example:alice"));
    }
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_dispatch_tests {
    use super::*;

    /// A minimal but structurally valid Trust Task document of `type_uri`.
    fn doc_json(type_uri: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:2b1e0a1e-0000-4000-8000-000000000001",
            "type": type_uri,
            "issuer": "did:key:zSender",
            "recipient": "did:key:zMediator",
            "createdAt": "2026-01-01T00:00:00Z",
            "payload": {},
        }))
        .expect("test document serialises")
    }

    #[test]
    fn a_served_management_task_is_claimed() {
        // The whole point of the TSP arm: `account/update` addressed to the
        // mediator must be *answered*, not filed into its inbox.
        let uri = type_uri_of::<account::update::v0_1::Payload>();
        let claimed = parse_if_served(&doc_json(&uri.to_string()))
            .expect("a served type must be claimed for dispatch");
        assert_eq!(claimed.type_uri, uri);
    }

    #[test]
    fn every_served_task_is_claimed_by_its_own_type_uri() {
        // `consume` matches `ServedTask` exhaustively, so "dispatched but not
        // served" and "served but not dispatched" no longer compile. What is
        // left to check is the lookup itself: each registered type must map
        // back to itself — two variants sharing a payload type would make one
        // of them unreachable — and must be claimed by the TSP arm.
        let mut seen = std::collections::HashSet::new();
        for &task in ServedTask::ALL {
            let uri = task.type_uri();
            assert!(
                seen.insert(uri.to_string()),
                "{task:?} duplicates a type URI"
            );
            assert_eq!(ServedTask::from_type_uri(&uri), Some(task));
            assert!(
                parse_if_served(&doc_json(&uri.to_string())).is_some(),
                "{task:?} is served but the TSP arm would file it as mail"
            );
        }
    }

    #[test]
    fn every_newer_version_is_claimed() {
        // A 0.2 request is served beside its 0.1, so the TSP arm must claim it
        // too, not file it into the mediator's inbox.
        for &newer in NewerVersion::ALL {
            let uri = newer.type_uri().to_string();
            assert!(
                parse_if_served(&doc_json(&uri)).is_some(),
                "{newer:?} is served but the TSP arm would file it as mail"
            );
        }
    }

    #[test]
    fn a_response_type_is_not_served() {
        // Only requests are dispatched. A `#response` addressed to the mediator
        // is a reply to something it sent, never a management request.
        let uri = format!("{}#response", ServedTask::AccountGet.type_uri());
        assert!(parse_if_served(&doc_json(&uri)).is_none());
    }

    #[test]
    fn an_unserved_trust_task_is_left_alone() {
        // Shape alone must not be enough. A Trust Task the mediator does not
        // serve is someone else's traffic that happens to be addressed here —
        // it belongs in the inbox, not in the management dispatch.
        assert!(
            parse_if_served(&doc_json(
                "https://trusttasks.org/spec/vta/contexts/list/1.0"
            ))
            .is_none(),
            "a type this mediator does not serve must fall through to delivery"
        );
    }

    #[test]
    fn ordinary_traffic_is_left_alone() {
        // The TSP arm sees every Direct/Control message addressed to the
        // mediator, most of which is not a Trust Task at all.
        for payload in [
            &b"not json at all"[..],
            &b"{}"[..],
            &br#"{"hello":"world"}"#[..],
            &b""[..],
        ] {
            assert!(
                parse_if_served(payload).is_none(),
                "non-Trust-Task payload must fall through to delivery"
            );
        }
    }

    #[test]
    fn the_vid_helper_strips_a_key_fragment() {
        // DIDComm gives a `did#key`; TSP gives a bare VID. Handlers authorise on
        // the VID, so both must land on the same string.
        assert_eq!(vid_of("did:key:zAlice#z6Mk"), "did:key:zAlice");
        assert_eq!(vid_of("did:key:zAlice"), "did:key:zAlice");
    }
}

#[cfg(test)]
mod config_show_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credentials_in_a_url_are_redacted_and_other_strings_are_not() {
        assert_eq!(
            redact_url("redis://:s3cret@db.internal:6379/0"),
            "redis://***@db.internal:6379/0"
        );
        assert_eq!(redact_url("redis://user:pw@host/"), "redis://***@host/");
        assert_eq!(redact_url("redis://127.0.0.1/"), "redis://127.0.0.1/");
        assert_eq!(redact_url("did:web:example.com"), "did:web:example.com");
        // Any `@` is treated as ending userinfo, so a malformed password
        // (unencoded `/`) is still hidden.
        assert_eq!(redact_url("redis://:pa/ss@host/"), "redis://***@host/");
    }

    #[test]
    fn configuration_flattens_to_dotted_scalars() {
        let mut out = Vec::new();
        flatten_config(
            "",
            &json!({
                "database": { "database_url": "redis://:pw@h/", "database_timeout": 2 },
                "local_endpoints": ["a", "b"],
                "listen_address": "0.0.0.0:7037"
            }),
            &mut out,
        );
        let get = |k: &str| out.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(get("database.database_url"), Some(json!("redis://***@h/")));
        assert_eq!(get("database.database_timeout"), Some(json!(2)));
        assert_eq!(get("local_endpoints"), Some(json!("[\"a\",\"b\"]")));
        assert_eq!(get("listen_address"), Some(json!("0.0.0.0:7037")));
        assert!(out.iter().all(|(_, v)| !v.is_object() && !v.is_array()));

        // A credential inside an array is redacted too.
        let mut out = Vec::new();
        flatten_config(
            "",
            &json!({ "endpoints": ["https://u:pw@a.example/", "https://b.example/"] }),
            &mut out,
        );
        let text = out[0].1.as_str().unwrap().to_string();
        assert!(!text.contains("pw"), "{text}");
        assert!(text.contains("***@a.example"), "{text}");
    }
}

#[cfg(test)]
mod served_protocols_tests {
    /// A Trust Task ping advertises only the protocols this build serves.
    #[test]
    fn ping_advertises_only_the_protocols_built_in() {
        let protocols = super::served_protocols();
        assert_eq!(
            protocols.contains(&"didcomm".to_string()),
            cfg!(feature = "didcomm")
        );
        assert_eq!(
            protocols.contains(&"tsp".to_string()),
            cfg!(feature = "tsp")
        );
    }
}
