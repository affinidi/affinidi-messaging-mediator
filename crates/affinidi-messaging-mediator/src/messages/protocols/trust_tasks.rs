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
//! This consumes the **rationalized** `messaging/*` surface (19 → 9 active
//! tasks, affinidi/affinidi-tdk-rs#667): `account/update` replaces the retired
//! `change-type` / `change-queue-limits` / `acl/set` / `admin/add` /
//! `admin/strip`; `access-list/update` replaces `access-list/{add,remove,clear}`;
//! the role-filtered `account/list` replaces `admin/list`; the `entries`
//! membership filter on `access-list/list` replaces `access-list/get`; and the
//! generic `audit/list` / `config/show` tasks replace `admin/audit-log` /
//! `admin/config`. The retired URIs are **not** dual-accepted — they answer
//! `unsupportedType` like any other unknown type.
//!
//! [Trust Task]: https://trusttasks.org

// The handlers here are written against the 0.1 types. Seven of them also
// serve 0.2 (see `trust_task_versions`); the 0.1 types are marked superseded,
// and stay until 0.1 is withdrawn.
#![allow(deprecated)]

use crate::error_codes;
use crate::task_specs::messaging::{
    access_list, account, acl, message, monitor, ping, queue, stats,
};
use crate::task_specs::{audit, config};
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::redact::redact_url;
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
use crate::messages::protocols::mediator::record_audit;
use crate::messages::protocols::trust_task_versions::NewerVersion;
use crate::messages::protocols::{mediator_ops, trust_task_sign, trust_task_verify};
#[cfg(feature = "didcomm")]
use crate::messages::{ProcessMessageResponse, WrapperType};

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
/// in one. The TSP binding is `inbound::dispatch_tsp_trust_task`.
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
        Ok(None) => return Ok(ProcessMessageResponse::default()),
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

    Ok(ProcessMessageResponse {
        handed_over: None,
        store_message: !push_only,
        force_live_delivery: push_only,
        data: WrapperType::Message(Box::new(response_msg)),
        forward_message: false,
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
    if task != ServedTask::Ping {
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
    serde_json::from_value(serde_json::to_value(doc).map_err(serialize_err)?).map_err(|e| {
        tt_problem(
            session,
            "malformedRequest",
            format!("payload does not match the task type: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Handle `messaging/account/get`: read-only, self-or-admin. Returns the
/// mediator's view of the named account as a `TrustTask<Response>` JSON value.
async fn consume_account_get(
    typed: TrustTask<account::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    // Framework basics: addressed to this mediator and not expired.
    validate_tt_basic(&typed, session, mediator_did, now)?;

    // Authz: the caller must be the target account itself, or an admin.
    let target_hash = typed.payload.did.to_string();
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to read account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    let account = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/get:unknownAccount",
                format!("account {target_hash} not found"),
                StatusCode::NOT_FOUND,
            )
        })?;

    let mut wire = map_account_get(&account);
    if typed.payload.include_stats.unwrap_or(false) {
        let stats = state
            .database
            .account_stats(std::slice::from_ref(&target_hash))
            .await?;
        if let Some(stats) = stats.first() {
            wire.stats = Some(to_wire_stats(stats));
        }
    }
    if typed.payload.include_activity.unwrap_or(false) {
        let activity = state
            .database
            .account_activity(std::slice::from_ref(&target_hash))
            .await?;
        if let Some(activity) = activity.first() {
            wire.last_received_at = activity.last_received;
            wire.last_authenticated_at = activity.last_authenticated;
        }
    }
    let response: account::get::v0_1::Response =
        build(account::get::v0_1::Response::builder().account(wire))?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/list`: admin-only, read-only. Returns one page of the
/// mediator's accounts (with an opaque continuation cursor) as a `TrustTask<Response>`.
/// An `accountType` filter restricts the page to one role — filtering on `admin` /
/// `rootAdmin` enumerates the administrators (this subsumes the retired
/// `messaging/admin/list`). The filter applies per page, so a filtered page may
/// hold fewer than `limit` entries while `nextCursor` still advances.
async fn consume_account_list(
    typed: TrustTask<account::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    // Authz: admin-only (listing every account is an administrative action).
    require_admin(session, "account/list")?;

    // The wire cursor is an opaque string over the store's numeric cursor.
    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed.payload.limit.map(|n| n.get() as u32).unwrap_or(100);

    // Optional role filter (subsumes the retired `messaging/admin/list`).
    let type_filter = typed.payload.account_type.as_ref().map(|t| {
        use account::list::v0_1::AccountType as WireType;
        match t {
            WireType::Standard => AccountType::Standard,
            WireType::Admin => AccountType::Admin,
            WireType::RootAdmin => AccountType::RootAdmin,
            WireType::Mediator => AccountType::Mediator,
            // No wildcard: the wire enum is generated in this crate from the
            // pinned bundle, so a role added to the spec only arrives with a
            // pin move, and then this match fails to compile until it is
            // mapped. (A role this build does not know cannot be decoded.)
        }
    });

    let page = state.database.account_list(cursor, limit).await?;
    // Annotated: the element type used to be pinned by the response struct
    // literal below, and the builder's `TryInto` setter no longer pins it.
    let mut accounts: Vec<account::list::v0_1::Account> = page
        .accounts
        .iter()
        .filter(|a| type_filter.as_ref().is_none_or(|t| a._type == *t))
        .map(to_wire_account::<account::list::v0_1::Account>)
        .collect();
    // The times are read for the page as it is returned, in one call, so a
    // filtered-out account costs nothing.
    if typed.payload.include_stats.unwrap_or(false) {
        let hashes: Vec<String> = accounts.iter().map(|a| a.did.to_string()).collect();
        for (account, stats) in accounts
            .iter_mut()
            .zip(state.database.account_stats(&hashes).await?)
        {
            account.stats = Some(to_wire_stats_as(&stats));
        }
    }
    if typed.payload.include_activity.unwrap_or(false) {
        let hashes: Vec<String> = accounts.iter().map(|a| a.did.to_string()).collect();
        for (account, activity) in accounts
            .iter_mut()
            .zip(state.database.account_activity(&hashes).await?)
        {
            account.last_received_at = activity.last_received;
            account.last_authenticated_at = activity.last_authenticated;
        }
    }
    // The store returns cursor 0 when the listing is exhausted.
    let next_cursor = (page.cursor != 0)
        .then(|| account::list::v0_1::ResponseNextCursor::from_str(&page.cursor.to_string()))
        .transpose()
        .map_err(|e| {
            tt_problem(
                session,
                "internalError",
                format!("couldn't encode the continuation cursor: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let response: account::list::v0_1::Response = build(
        account::list::v0_1::Response::builder()
            .accounts(accounts)
            .next_cursor(next_cursor),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/update`: one partial update of a served account's
/// role, capabilities, and queue limits — the merge of the retired
/// `change-type` / `change-queue-limits` / `acl/set` handlers, with their guards
/// applied per member:
///
/// - `accountType` — admin only; only a root admin may grant a privileged role
///   (admin, root admin, mediator) or change the role of an account holding one.
///
/// An account that holds a privileged role is changed only by itself or by a
/// root admin, whichever members the update carries (see `common::roles`).
/// - `acl` — self-or-admin; a non-admin may only change flags it self-manages.
/// - `queueLimits` — self-or-admin; a standard account may only change limits it
///   self-manages, capped at the mediator's hard maximum.
///
/// Guards run before anything is applied so a refused member refuses the whole
/// update. Returns the account's realized view after the change.
async fn consume_account_update(
    typed: TrustTask<account::update::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::update::v0_1::AccountType as WireType;

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    let is_admin = roles::can_administer(session.account_type);
    let denied = |reason: &str| {
        tt_problem(
            session,
            "permissionDenied",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // The task updates; it does not create.
    let current = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/update:unknownAccount",
                format!("account {target_hash} not found"),
                StatusCode::NOT_FOUND,
            )
        })?;

    // ---- Guards first, so a refused member refuses the whole update. ----

    // An account holding a privileged role (admin, root admin, the mediator's
    // own) is changed only by itself or by a root admin.
    if !roles::may_modify_account(
        session.account_type,
        &session.did_hash,
        current._type,
        &target_hash,
    ) {
        return Err(tt_problem(
            session,
            "messaging/account/update:rootAdminRequired",
            "root-admin access is required to modify a privileged account".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // This one *writes* the role, so it must never store something the caller
    // did not ask for. No wildcard: the wire enum is generated in this crate
    // from the pinned bundle, so a role added to the spec only arrives with a
    // pin move, and then this match fails to compile until it is mapped. A
    // role this build does not know cannot be decoded at all.
    let new_type = typed.payload.account_type.as_ref().map(|t| match t {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
    });
    if let Some(new_type) = new_type {
        // Must be an admin to change roles at all.
        if !roles::can_administer(session.account_type) {
            return Err(denied("admin access is required to change account types"));
        }
        // The mediator's own account and the configured root admin keep the
        // roles configuration gave them.
        if is_configured_account(state, &target_hash) {
            return Err(tt_problem(
                session,
                "permissionDenied",
                "the roles of the mediator and root-admin accounts cannot be changed".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }
        // Granting a privileged role, or changing the role of an account that
        // holds one, is for a root admin.
        if !roles::can_assign_role(session.account_type, Some(current._type), new_type) {
            return Err(tt_problem(
                session,
                "messaging/account/update:rootAdminRequired",
                "root-admin access is required to grant or change a privileged role".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }
    }

    // Capabilities and queue limits are self-or-admin.
    let acl_value = match &typed.payload.acl {
        Some(acl) => Some(serde_json::to_value(acl).map_err(serialize_err)?),
        None => None,
    };
    if (acl_value.is_some() || typed.payload.queue_limits.is_some())
        && !check_permissions(
            session,
            std::slice::from_ref(&target_hash),
            state.config.security.block_remote_admin_msgs,
            sender_kid,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to update account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }
    if let Some(acl_value) = &acl_value {
        // A non-admin may only change flags it is permitted to self-manage.
        if !is_admin {
            ensure_self_manageable(acl_value, &MediatorACLSet::from_u64(current.acls), session)?;
        }
    }

    // Queue limits are resolved here rather than at the write below, because a
    // refusal must refuse the *whole* update: by the time the write runs, the ACL
    // member has already been stored and audited. The wire carries i64 and the
    // store works in i32; a member omitted is left unchanged.
    let queue_limits = typed
        .payload
        .queue_limits
        .as_ref()
        .map(|limits| {
            resolve_queue_limits(
                session,
                is_admin,
                (
                    wire_queue_limit(limits.send_queue_limit, "send_queue_limit", session)?,
                    wire_queue_limit(limits.receive_queue_limit, "receive_queue_limit", session)?,
                ),
                (
                    state.limits().queued_send_messages_hard,
                    state.limits().queued_receive_messages_hard,
                ),
            )
        })
        .transpose()?;

    // ---- Apply: capabilities, then queue limits, then the role. ----
    //
    // Three writes, not one transaction: the store has no compound update.
    // Every refusal was decided above, so only a store failure can stop this
    // part-way; when it does after an earlier write landed, that is audited
    // as a partial update before the error goes back.
    let mut applied: Vec<&'static str> = Vec::new();

    if let Some(acl_value) = acl_value {
        let base = state
            .database
            .get_did_acl(&target_hash)
            .await?
            .unwrap_or_default();
        let merged = merge_wire_acl(acl_value, base)?;
        let stored = state.database.set_did_acl(&target_hash, &merged).await?;
        applied.push("acl");
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::SetAcl,
            format!("acl -> {:#018x}", stored.to_u64()),
        )
        .await;
        // A live mux connection carrying the account as a member drops it
        // now if the new ACLs no longer cover its scope, before this answers;
        // other instances are told to do the same.
        crate::mux::connection::account_changed(state, &target_hash).await;
    }

    if let Some((send_queue_limit, receive_queue_limit)) = queue_limits {
        if let Err(e) = state
            .database
            .account_change_queue_limits(&target_hash, send_queue_limit, receive_queue_limit)
            .await
        {
            audit_partial_update(state, session, &target_hash, &applied, "queue limits", &e).await;
            return Err(e);
        }
        applied.push("queue limits");
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccountChangeQueueLimits,
            format!("send={send_queue_limit:?} receive={receive_queue_limit:?}"),
        )
        .await;
    }

    if let Some(new_type) = new_type {
        // A faithful port of the legacy admin-set transitions (promote / demote /
        // switch); the guards above already authorized the change.
        if current._type != new_type
            && let Err(e) = apply_role_change(state, &target_hash, &current, new_type).await
        {
            audit_partial_update(state, session, &target_hash, &applied, "role", &e).await;
            return Err(e);
        }
        if current._type != new_type {
            record_audit(
                state,
                session,
                &target_hash,
                AuditAction::AccountChangeType,
                format!("type -> {new_type}"),
            )
            .await;
        }
    }

    let account = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/update:unknownAccount",
                format!("account {target_hash} not found after update"),
                StatusCode::NOT_FOUND,
            )
        })?;
    let response: account::update::v0_1::Response = build(
        account::update::v0_1::Response::builder()
            .account(to_wire_account::<account::update::v0_1::Account>(&account)),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Change `target_hash`'s role from `current`'s to `new_type`: a faithful port
/// of the legacy admin-set transitions (promote / demote / switch).
async fn apply_role_change(
    state: &SharedData,
    target_hash: &str,
    current: &Account,
    new_type: AccountType,
) -> Result<(), MediatorError> {
    if current._type.is_admin() && !new_type.is_admin() {
        // Demotion — strip admin rights first, then set the plain role.
        state
            .database
            .strip_admin_accounts(vec![target_hash.to_string()])
            .await?;
        state
            .database
            .account_set_role(target_hash, &new_type)
            .await?;
    } else if !current._type.is_admin() && new_type.is_admin() {
        // Promotion — add admin rights, carrying the account's current ACL
        // set (re-read so an `acl` member in this same update is honoured).
        let acls = state
            .database
            .account_get(target_hash)
            .await?
            .map(|a| a.acls)
            .unwrap_or(current.acls);
        state
            .database
            .setup_admin_account(target_hash, new_type, &MediatorACLSet::from_u64(acls))
            .await?;
    } else {
        // Switching between admin roles is a plain set-role.
        state
            .database
            .account_set_role(target_hash, &new_type)
            .await?;
    }
    Ok(())
}

/// Audit an `account/update` that a store failure stopped after `applied`
/// had already been written: the record says the update is partial and what
/// did and did not land. Nothing is recorded when nothing was applied.
async fn audit_partial_update(
    state: &SharedData,
    session: &Session,
    target_hash: &str,
    applied: &[&str],
    failed: &str,
    error: &MediatorError,
) {
    if applied.is_empty() {
        return;
    }
    record_audit(
        state,
        session,
        target_hash,
        AuditAction::SetAcl,
        format!(
            "outcome partial: account/update applied {} but its {failed} failed: {error}",
            applied.join(", ")
        ),
    )
    .await;
}

/// The stored `(send, receive)` queue limits for a `(requested send, requested
/// receive)` pair. An admin's request stands as sent; anyone else's goes through
/// [`gate_self_managed_limit`]. `None` in either position leaves that limit
/// unchanged. `hard` is `(send, receive)` from the mediator's limits.
///
/// `is_admin` is the caller's own admin test, so that the two self-or-admin members
/// of one `account/update` — the ACL and these limits — cannot disagree about who
/// an admin is. It had tested `account_type != Standard` here while the ACL member
/// tested `Admin | RootAdmin`, which let an account whose type did not decode
/// (`Unknown`) past this gate but not that one.
fn resolve_queue_limits(
    session: &Session,
    is_admin: bool,
    requested: (Option<i32>, Option<i32>),
    hard: (i32, i32),
) -> Result<(Option<i32>, Option<i32>), MediatorError> {
    if is_admin {
        return Ok(requested);
    }
    Ok((
        gate_self_managed_limit(
            requested.0,
            session.acls.get_self_manage_send_queue_limit(),
            hard.0,
            "send_queue_limit",
            session,
        )?,
        gate_self_managed_limit(
            requested.1,
            session.acls.get_self_manage_receive_queue_limit(),
            hard.1,
            "receive_queue_limit",
            session,
        )?,
    ))
}

/// A standard account may change a queue limit only if it self-manages that limit,
/// and may not switch it off. Permission to adjust a limit is not permission to
/// remove it, so `-1` (unlimited) and anything past `-2` are refused: being below
/// every maximum they would slip past the clamp and be stored verbatim. `-2` resets
/// to the mediator default and passes through; a value above `hard` is clamped; a
/// negative `hard` is unbounded, so there is no ceiling to clamp against. Not
/// self-managed → refused, as `ensure_self_manageable` refuses a capability the
/// account may not change. Admins do not come here.
fn gate_self_managed_limit(
    requested: Option<i32>,
    self_managed: bool,
    hard: i32,
    limit_name: &str,
    session: &Session,
) -> Result<Option<i32>, MediatorError> {
    // Both limits are gated on every request, so an omitted member is nothing to
    // gate — it must be answered before the permission test, or an account that
    // self-manages one limit and not the other could never set the one it does.
    let Some(requested) = requested else {
        return Ok(None);
    };
    if !self_managed {
        // A member the account may not touch is refused, not quietly dropped: the
        // response echoes the stored account, so a silent no-op reaches the caller
        // as a success carrying the old value, which reads as "applied".
        return Err(tt_problem(
            session,
            "messaging/account/update:selfChangeDenied",
            format!("this account may not self-manage its `{limit_name}`"),
            StatusCode::FORBIDDEN,
        ));
    }
    match requested {
        RESET_QUEUE_LIMIT_TO_DEFAULT => Ok(Some(RESET_QUEUE_LIMIT_TO_DEFAULT)),
        limit if limit < 0 => Err(tt_problem(
            session,
            "permissionDenied",
            format!(
                "admin access is required to set an unlimited `{limit_name}` ({limit}); \
                 this account may set a limit of 0 or more, or \
                 {RESET_QUEUE_LIMIT_TO_DEFAULT} to reset it to the mediator default"
            ),
            StatusCode::FORBIDDEN,
        )),
        limit if hard >= 0 && limit > hard => Ok(Some(hard)),
        limit => Ok(Some(limit)),
    }
}

/// A queue limit from the wire (i64) as the store holds it (i32): `-1`
/// (unlimited), `-2` (reset to the default) or `0` and more. A value outside
/// that — any other negative, or one past `i32` — is refused rather than
/// wrapped or stored with no meaning, whoever asks.
fn wire_queue_limit(
    requested: Option<i64>,
    limit_name: &str,
    session: &Session,
) -> Result<Option<i32>, MediatorError> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    match i32::try_from(requested) {
        Ok(limit) if limit >= RESET_QUEUE_LIMIT_TO_DEFAULT => Ok(Some(limit)),
        _ => Err(tt_problem(
            session,
            "malformedRequest",
            format!(
                "`{limit_name}` must be -1 (unlimited), {RESET_QUEUE_LIMIT_TO_DEFAULT} (reset to \
                 the default) or a limit from 0 to {}; got {requested}",
                i32::MAX
            ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Most DIDs one `messaging/acl/get` may name: the store's batch read limit.
const ACL_GET_MAX_DIDS: usize = 100;

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

/// The queue-limit sentinel meaning "drop this account's override and fall back to
/// the mediator default" — `_change_queue_limit` in the store turns it into an
/// `HDEL`. It is not a limit value, so it is never clamped.
const RESET_QUEUE_LIMIT_TO_DEFAULT: i32 = -2;

/// Handle `messaging/account/remove`: self-or-admin. Refuses to remove the
/// mediator's own account or the root admin (both compared in constant time).
/// Returns the target id and whether a record was removed.
async fn consume_account_remove(
    typed: TrustTask<account::remove::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to remove account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    // Never remove the mediator's own account or the root admin.
    if is_configured_account(state, &target_hash) {
        return Err(tt_problem(
            session,
            "messaging/account/remove:protectedAccount",
            "the mediator and root-admin accounts cannot be removed".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    // Another privileged account is removed only by a root admin.
    if let Some(target) = state.database.account_get(&target_hash).await?
        && !roles::may_modify_account(
            session.account_type,
            &session.did_hash,
            target._type,
            &target_hash,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "root-admin access is required to remove a privileged account".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    let removed = state
        .database
        .account_remove(&session.to_store_session(), &target_hash)
        .await?;
    // Mux grants on either side of the removed account go too, whether or not
    // mux is enabled now: grants left from when it was would otherwise come
    // back to life if the DID re-registered. Done after the account removal,
    // so a failure here cannot leave a half-removed account; it is logged
    // loudly because the grants then outlive the account (R6.3).
    if removed && state.database.supports_mux() {
        let limits = state.config.limits.mux.store_limits();
        match affinidi_messaging_mediator_common::store::mux::remove_account(
            &*state.database,
            &target_hash,
            &limits,
            state.clock.unix_secs(),
        )
        .await
        {
            // Principals carrying the removed DID drop it now and are told.
            Ok(as_member) if !as_member.is_empty() => {
                use crate::mux::session::LeaveReason;
                state
                    .mux
                    .detach_grants(
                        state.streaming_task.as_ref(),
                        &as_member,
                        LeaveReason::AccountRemoved,
                    )
                    .await;
                let changes: Vec<_> = as_member
                    .iter()
                    .map(|g| {
                        affinidi_messaging_mediator_common::store::mux::MuxChange::of(g, false)
                    })
                    .collect();
                crate::mux::sync::publish(state, &changes).await;
                let changed = crate::mux::tasks::Changed {
                    removed: as_member,
                    reason: Some(LeaveReason::AccountRemoved),
                    ..Default::default()
                };
                crate::mux::notice::after_change(state, &changed).await;
            }
            Ok(_) => {}
            Err(e) => tracing::error!(
                did_hash = %target_hash,
                "account removed, but its DID multiplexing grants could not be: {e}"
            ),
        }
    }
    // Members admitted by a session attach hold no stored grant, so the
    // detach above does not reach them; the account is gone, so its standing
    // check detaches them (`accountRemoved`) on every connection here.
    if removed {
        crate::mux::connection::account_changed(state, &target_hash).await;
    }
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountRemove,
        "account removed".to_string(),
    )
    .await;

    let response: account::remove::v0_1::Response = build(
        account::remove::v0_1::Response::builder()
            .did(typed.payload.did.clone())
            .removed(removed),
    )?;
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Whether `target_hash` is the mediator's own account or the configured root
/// admin (`admin_did`), compared in constant time. Neither is removed, and
/// neither has its role changed, through a Trust Task: both are set up from
/// configuration at startup.
fn is_configured_account(state: &SharedData, target_hash: &str) -> bool {
    state
        .config
        .mediator_did_hash
        .as_bytes()
        .ct_eq(target_hash.as_bytes())
        .unwrap_u8()
        == 1
        || affinidi_messaging_mediator_common::did_identity::did_hash(&state.config.admin_did)
            .as_bytes()
            .ct_eq(target_hash.as_bytes())
            .unwrap_u8()
            == 1
}

/// Handle `messaging/account/add`. Only an admin may add accounts, in either
/// `mediator_acl_mode`: an account for the caller itself already exists (it is
/// created when the DID first authenticates), so the only accounts this task
/// can create belong to other DIDs, which is account administration. The admin
/// may supply the new account's ACL (applied onto the mediator default).
/// Creating an account with a privileged role (admin, root admin, mediator)
/// requires a root admin.
///
/// An account that already exists is refused with `alreadyExists` and left
/// exactly as it was; `messaging/account/update` changes an existing account.
/// Returns the created account's realized view.
async fn consume_account_add(
    typed: TrustTask<account::add::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::add::v0_1::AccountType as WireType;

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    let new_type = match typed.payload.account_type {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
        // No wildcard: a role added to the spec only arrives with a pin move,
        // and then this match fails to compile until the role is mapped. A
        // role this build does not know cannot be decoded, so it is never
        // stored as a privilege level the mediator cannot reason about.
    };
    let denied = |reason: &str| {
        tt_problem(
            session,
            "permissionDenied",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // The role was read from the store for this request (see `principal`), so
    // a role removed since the session was issued no longer grants this.
    if !roles::can_administer(session.account_type) {
        return Err(denied("admin access is required to add accounts"));
    }
    // Creating a privileged account is for a root admin.
    if !roles::can_assign_role(session.account_type, None, new_type) {
        return Err(denied(
            "root-admin access is required to create a privileged account",
        ));
    }

    // ACLs: the admin may supply them (applied onto the mediator default).
    let acls = match &typed.payload.acl {
        Some(acl) => merge_wire_acl(
            serde_json::to_value(acl).map_err(serialize_err)?,
            state.config.security.global_acl_default.clone(),
        )?,
        None => state.config.security.global_acl_default.clone(),
    };

    let account = state
        .database
        .account_create(&target_hash, &acls, None)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "messaging/account/add:alreadyExists",
                format!("account {target_hash} already exists"),
                StatusCode::CONFLICT,
            )
        })?;
    // Apply a non-standard role if requested (the guards above already authorized it).
    let account = if new_type != AccountType::Standard {
        state
            .database
            .account_set_role(&target_hash, &new_type)
            .await?;
        state
            .database
            .account_get(&target_hash)
            .await?
            .unwrap_or(account)
    } else {
        account
    };

    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountAdd,
        "account created".to_string(),
    )
    .await;

    let response: account::add::v0_1::Response = build(
        account::add::v0_1::Response::builder()
            .account(to_wire_account::<account::add::v0_1::Account>(&account)),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/acl/get`: self-or-admin, read-only, batched. Returns one entry
/// per known DID and lists any unknown DIDs separately.
async fn consume_acl_get(
    typed: TrustTask<acl::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use acl::get::v0_1::{Entry, Response, Vid};

    validate_tt_basic(&typed, session, mediator_did, now)?;

    let dids: Vec<String> = typed.payload.dids.iter().map(|v| v.to_string()).collect();
    // Bounded here because the pinned schema does not bound it (no
    // `maxItems` on `dids`): every DID is a store read.
    if dids.len() > ACL_GET_MAX_DIDS {
        return Err(tt_problem(
            session,
            "malformedRequest",
            format!(
                "`dids` may name at most {ACL_GET_MAX_DIDS} accounts; this request names {}",
                dids.len()
            ),
            StatusCode::BAD_REQUEST,
        ));
    }
    if !check_permissions(
        session,
        &dids,
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "not permitted to read one or more of the requested ACLs".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // One batched read for every requested DID, not one round trip each.
    let found: std::collections::HashMap<String, MediatorACLSet> = state
        .database
        .get_did_acls(&dids, state.config.security.mediator_acl_mode.clone())
        .await?
        .acl_response
        .into_iter()
        .map(|entry| (entry.did_hash, entry.acls))
        .collect();
    let mut entries = Vec::new();
    let mut unknown = Vec::new();
    for did in &dids {
        let vid = Vid::from_str(did).expect("a requested DID is a valid Vid");
        match found.get(did) {
            Some(aclset) => entries.push(build(
                Entry::builder()
                    .acl(to_wire_acl::<acl::get::v0_1::MediatorAcl>(aclset))
                    .did(vid),
            )?),
            None => unknown.push(vid),
        }
    }

    let response: Response = build(Response::builder().entries(entries).unknown(unknown))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Access-list authz: self-or-admin for the target, plus the `self_manage_list`
/// capability for a standard account performing a write.
async fn authorize_access_list(
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    target_hash: &str,
    write: bool,
) -> Result<(), MediatorError> {
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash.to_string()),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "permissionDenied",
            format!("not permitted to access the access list for {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }
    if write && !roles::can_administer(session.account_type) && !session.acls.get_self_manage_list()
    {
        return Err(tt_problem(
            session,
            "messaging/access-list/update:selfChangeDenied",
            "this account may not self-manage its access list".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    // Another privileged account's list is changed only by a root admin.
    if write
        && let Some(target) = state.database.account_get(target_hash).await?
        && !roles::may_modify_account(
            session.account_type,
            &session.did_hash,
            target._type,
            target_hash,
        )
    {
        return Err(tt_problem(
            session,
            "permissionDenied",
            "root-admin access is required to change a privileged account's access list"
                .to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// The current size of a DID's access list (0 if the account is unknown).
async fn access_list_count(state: &SharedData, target_hash: &str) -> u64 {
    state
        .database
        .account_get(target_hash)
        .await
        .ok()
        .flatten()
        .map(|a| a.access_list_count as u64)
        .unwrap_or(0)
}

/// Gate a non-admin `acl/set`: a standard account may change a capability only when
/// its per-capability self-change bit is set, and may never touch the admin-only flags
/// (`blocked`, `local`, the `selfManage*` bits). A flag whose requested value equals
/// the current value is not a change. Faithful to the legacy `acls_set` self-service
/// rules.
fn ensure_self_manageable(
    acl_value: &Value,
    base: &MediatorACLSet,
    session: &Session,
) -> Result<(), MediatorError> {
    let req: account::get::v0_1::MediatorAcl = serde_json::from_value(acl_value.clone())
        .map_err(|e| malformed_acl(format!("invalid ACL payload: {e}")))?;
    let cur = decode_acl_canonical(base);
    let deny = |flag: &str| -> Result<(), MediatorError> {
        Err(tt_problem(
            session,
            "messaging/account/update:selfChangeDenied",
            format!("this account may not change `{flag}`"),
            StatusCode::FORBIDDEN,
        ))
    };

    // Capabilities self-manageable when the account's self-change bit is set.
    if req.access_list_mode.is_some()
        && req.access_list_mode != cur.access_list_mode
        && !base.get_access_list_mode().1
    {
        return deny("accessListMode");
    }
    if req.send_messages.is_some()
        && req.send_messages != cur.send_messages
        && !base.get_send_messages().1
    {
        return deny("sendMessages");
    }
    if req.receive_messages.is_some()
        && req.receive_messages != cur.receive_messages
        && !base.get_receive_messages().1
    {
        return deny("receiveMessages");
    }
    if req.send_forwarded.is_some()
        && req.send_forwarded != cur.send_forwarded
        && !base.get_send_forwarded().1
    {
        return deny("sendForwarded");
    }
    if req.receive_forwarded.is_some()
        && req.receive_forwarded != cur.receive_forwarded
        && !base.get_receive_forwarded().1
    {
        return deny("receiveForwarded");
    }
    if req.create_invites.is_some()
        && req.create_invites != cur.create_invites
        && !base.get_create_invites().1
    {
        return deny("createInvites");
    }
    if req.anon_receive.is_some()
        && req.anon_receive != cur.anon_receive
        && !base.get_anon_receive().1
    {
        return deny("anonReceive");
    }

    // Admin-only flags: a non-admin may never change these.
    if req.blocked.is_some() && req.blocked != cur.blocked {
        return deny("blocked");
    }
    if req.local.is_some() && req.local != cur.local {
        return deny("local");
    }
    if req.self_manage_list.is_some() && req.self_manage_list != cur.self_manage_list {
        return deny("selfManageList");
    }
    if req.self_manage_send_queue_limit.is_some()
        && req.self_manage_send_queue_limit != cur.self_manage_send_queue_limit
    {
        return deny("selfManageSendQueueLimit");
    }
    if req.self_manage_receive_queue_limit.is_some()
        && req.self_manage_receive_queue_limit != cur.self_manage_receive_queue_limit
    {
        return deny("selfManageReceiveQueueLimit");
    }

    Ok(())
}

/// Handle `messaging/access-list/update`: self-or-admin (+ `self_manage_list` for
/// a standard account). One write task for the whole access list — the merge of
/// the retired `access-list/add` / `remove` / `clear` handlers. Members apply in
/// the spec's fixed order **`clear`, `add`, `remove`**, so `clear + add` replaces
/// the list wholesale. Reports the entries actually added and removed plus the
/// resulting count.
async fn consume_access_list_update(
    typed: TrustTask<access_list::update::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::update::v0_1::{Response, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, true).await?;

    // Up to three writes (clear, add, remove), not one transaction. Each
    // audits itself once it lands; a store failure after an earlier one
    // landed is audited as a partial update before the error goes back.
    let mut applied: Vec<&'static str> = Vec::new();

    // 1. `clear` empties the list before any additions.
    if typed.payload.clear == Some(true) {
        state.database.access_list_clear(&target_hash).await?;
        applied.push("clear");
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListClear,
            "access list cleared".to_string(),
        )
        .await;
    }

    // 2. `add` — idempotent at the set level, truncated at the mediator limit.
    let mut added: Vec<Vid> = Vec::new();
    if !typed.payload.add.is_empty() {
        let hashes: Vec<String> = typed.payload.add.iter().map(|v| v.to_string()).collect();
        let result = match state
            .database
            .access_list_add(state.limits().access_list_limit, &target_hash, &hashes)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                audit_partial_access_list(state, session, &target_hash, &applied, "add", &e).await;
                return Err(e);
            }
        };
        applied.push("add");
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListAdd,
            format!("added {} entries", result.did_hashes.len()),
        )
        .await;
        added = result
            .did_hashes
            .iter()
            .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
            .collect();
    }

    // 3. `remove` — those present before removal are exactly those removed.
    let mut removed: Vec<Vid> = Vec::new();
    if !typed.payload.remove.is_empty() {
        let hashes: Vec<String> = typed.payload.remove.iter().map(|v| v.to_string()).collect();
        let removal = async {
            let present = state
                .database
                .access_list_get(&target_hash, &hashes)
                .await?
                .did_hashes;
            state
                .database
                .access_list_remove(&target_hash, &hashes)
                .await?;
            Ok::<_, MediatorError>(present)
        };
        let present = match removal.await {
            Ok(present) => present,
            Err(e) => {
                audit_partial_access_list(state, session, &target_hash, &applied, "remove", &e)
                    .await;
                return Err(e);
            }
        };
        record_audit(
            state,
            session,
            &target_hash,
            AuditAction::AccessListRemove,
            format!("removed {} entries", present.len()),
        )
        .await;
        removed = present
            .iter()
            .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
            .collect();
    }

    let response: Response = build(
        Response::builder()
            .access_list_count(access_list_count(state, &target_hash).await)
            .added(added)
            .did(typed.payload.did.clone())
            .removed(removed),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Audit an `access-list/update` that a store failure stopped after `applied`
/// had already been written. Nothing is recorded when nothing was applied.
async fn audit_partial_access_list(
    state: &SharedData,
    session: &Session,
    target_hash: &str,
    applied: &[&str],
    failed: &str,
    error: &MediatorError,
) {
    if applied.is_empty() {
        return;
    }
    record_audit(
        state,
        session,
        target_hash,
        if failed == "add" {
            AuditAction::AccessListAdd
        } else {
            AuditAction::AccessListRemove
        },
        format!(
            "outcome partial: access-list update applied {} but its {failed} failed: {error}",
            applied.join(", ")
        ),
    )
    .await;
}

/// Handle `messaging/access-list/list`: self-or-admin, read-only, cursor-paged.
/// An `entries` filter turns the enumeration into a membership check (subsuming
/// the retired `messaging/access-list/get`): only the supplied DIDs present in
/// the list are returned, unpaged, with `accessListCount` still the whole-list
/// total.
async fn consume_access_list_list(
    typed: TrustTask<access_list::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::list::v0_1::{Response, ResponseNextCursor, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, false).await?;

    // Membership check (subsumes the retired `messaging/access-list/get`): return
    // exactly the supplied entries that are present; a supplied DID absent from
    // the response is not a member.
    if !typed.payload.entries.is_empty() {
        let hashes: Vec<String> = typed
            .payload
            .entries
            .iter()
            .map(|v| v.to_string())
            .collect();
        let present: HashSet<String> = state
            .database
            .access_list_get(&target_hash, &hashes)
            .await?
            .did_hashes
            .into_iter()
            .collect();
        let entries: Vec<Vid> = typed
            .payload
            .entries
            .iter()
            .filter(|v| present.contains(v.as_str()))
            .cloned()
            .collect();

        // `next_cursor` stays unset: a membership check answers in one page.
        let response: Response = build(
            Response::builder()
                .access_list_count(access_list_count(state, &target_hash).await)
                .did(typed.payload.did.clone())
                .entries(entries),
        )?;
        return serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err);
    }

    let cursor: u64 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let page = state
        .database
        .access_list_list(&target_hash, cursor)
        .await?;
    let entries: Vec<Vid> = page
        .did_hashes
        .iter()
        .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
        .collect();
    // Both `None` and `Some(0)` mean the listing is exhausted.
    let next_cursor = match page.cursor {
        None | Some(0) => None,
        Some(c) => Some(
            ResponseNextCursor::from_str(&c.to_string())
                .map_err(|e| serialize_err_msg(format!("cursor: {e}")))?,
        ),
    };

    let response: Response = build(
        Response::builder()
            .access_list_count(access_list_count(state, &target_hash).await)
            .did(typed.payload.did.clone())
            .entries(entries)
            .next_cursor(next_cursor),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Reject a non-admin caller of an admin-only task.
/// `messaging/mux/connections`: this instance's live mux connections, for an
/// administrator. See [`crate::mux::admin`].
async fn consume_mux_connections(
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::admin;
    use crate::task_specs::messaging::mux::connections::v0_1 as connections;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;
    require_admin(session, "messaging/mux/connections")?;

    let query = admin::Query::from_payload(&doc.payload);
    let mut views = Vec::new();
    for conn in state.mux.all() {
        views.push(admin::view(&conn).await);
    }
    let binding = admin::Binding {
        requester: &session.did_hash,
        instance: &state.config.streaming_uuid,
        now: now.timestamp().max(0) as u64,
    };
    let page = admin::page(views, &query, &binding, !state.database.spans_processes()).map_err(
        |admin::PageError::CursorInvalid| {
            tt_problem(
                session,
                admin::CURSOR_INVALID,
                "the cursor was not issued by this instance for this request, or has expired; \
                 start again without one"
                    .into(),
                StatusCode::BAD_REQUEST,
            )
        },
    )?;
    let response: connections::Response = super::mediator_ops::from_json(page)?;
    let typed: TrustTask<connections::Payload> = downcast(doc, session)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
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

/// Handle the generic `audit/list`: admin-only. Pages the mediator's
/// privileged-change log, newest first, as `AuditEnvelope`s — the messaging
/// profile of the generic task that replaces the retired
/// `messaging/admin/audit-log` (request `limit` → `pageSize`; response
/// `nextCursor` → `cursor` + `truncated`).
///
/// Filter support is per page: `action` / `actor` / `from` / `to` are applied to
/// the fetched page (the cursor still advances page-by-page). The mediator's log
/// tracks neither `outcome` nor `contextId`, so a filter on those matches
/// nothing.
async fn consume_audit_list(
    typed: TrustTask<audit::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use audit::list::v0_1::Response;
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "audit/list")?;

    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed
        .payload
        .page_size
        .map(|n| n.get() as u32)
        .unwrap_or(100);

    let page = state.database.audit_log_list(cursor, limit).await?;
    let entries = page
        .entries
        .iter()
        .filter(|e| audit_filters_match(&typed.payload, e))
        .map(map_audit_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = page.cursor != 0;

    let response: Response = build(
        Response::builder()
            .cursor(truncated.then(|| page.cursor.to_string()))
            .entries(entries)
            .truncated(truncated),
    )?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Apply the generic `audit/list` filters to one internal log entry.
fn audit_filters_match(payload: &audit::list::v0_1::Payload, e: &AuditLogEntry) -> bool {
    // The mediator's log tracks neither outcome nor context: a filter on them
    // matches nothing (honest emptiness rather than a silently ignored filter).
    if payload.outcome.is_some() || payload.context_id.is_some() {
        return false;
    }
    if let Some(action) = &payload.action
        && **action != audit_action_name(e.action)
    {
        return false;
    }
    if let Some(actor) = &payload.actor
        && **actor != e.actor_did_hash
    {
        return false;
    }
    let recorded = e.timestamp as i64;
    if let Some(from) = &payload.from
        && recorded < from.timestamp()
    {
        return false;
    }
    if let Some(to) = &payload.to
        && recorded >= to.timestamp()
    {
        return false;
    }
    true
}

/// Map one internal audit record onto the generic `AuditEnvelope` profile:
/// `timestamp` → `recordedAt`, `actor`/`target` hashes → `actor`/`target`,
/// the action's shared-schema name → `action`, and the free-text detail →
/// `detail.detail`. The mediator's log has no native event id, so a stable one
/// is minted as the digest of the entry's content.
fn map_audit_envelope(
    e: &AuditLogEntry,
) -> Result<audit::list::v0_1::AuditEnvelope, MediatorError> {
    use audit::list::v0_1::{AuditEnvelope, AuditEnvelopeAction, AuditEnvelopeEventId};

    let action = audit_action_name(e.action);
    let event_id = digest(format!(
        "{}:{}:{}:{}:{}",
        e.timestamp, e.actor_did_hash, e.target_did_hash, action, e.detail
    ));
    let mut detail = serde_json::Map::new();
    detail.insert("detail".to_string(), Value::String(e.detail.clone()));

    // `contextId`, `entryHash`, `outcome`, `prevHash` and `schemaVersion` are
    // left unset: this mediator's audit rows carry no equivalent.
    build(
        AuditEnvelope::builder()
            .action(
                AuditEnvelopeAction::from_str(action)
                    .map_err(|err| serialize_err_msg(format!("audit action: {err}")))?,
            )
            .actor(Some(e.actor_did_hash.clone()))
            .detail(detail)
            .event_id(
                AuditEnvelopeEventId::from_str(&event_id)
                    .map_err(|err| serialize_err_msg(format!("audit event id: {err}")))?,
            )
            .recorded_at(
                chrono::DateTime::from_timestamp(e.timestamp as i64, 0)
                    .unwrap_or_else(chrono::Utc::now),
            )
            .target(Some(e.target_did_hash.clone())),
    )
}

/// The shared-schema (`messaging.schema.json#/$defs/AuditAction`) name of an
/// internal audit action — the maintainer-defined action vocabulary this
/// mediator reports through the generic `audit/list`.
fn audit_action_name(a: AuditAction) -> &'static str {
    match a {
        AuditAction::SetAcl => "setAcl",
        AuditAction::AccessListAdd => "accessListAdd",
        AuditAction::AccessListRemove => "accessListRemove",
        AuditAction::AccessListClear => "accessListClear",
        AuditAction::AccountAdd => "accountAdd",
        AuditAction::AccountRemove => "accountRemove",
        AuditAction::AccountChangeType => "accountChangeType",
        AuditAction::AccountChangeQueueLimits => "accountChangeQueueLimits",
        AuditAction::AdminAdd => "adminAdd",
        AuditAction::AdminStrip => "adminStrip",
        AuditAction::MessageRead => "messageRead",
        AuditAction::MessageDelete => "messageDelete",
        AuditAction::QueuePurge => "queuePurge",
        AuditAction::MonitorSubscribe => "monitorSubscribe",
        AuditAction::MonitorUnsubscribe => "monitorUnsubscribe",
        AuditAction::ConfigPatch => "configPatch",
        AuditAction::ConfigReload => "configReload",
        // A kind added to the common crate before this mapping learns it.
        _ => "other",
    }
}

/// Handle the generic `config/show`: admin-only. Returns the mediator's
/// configuration as per-key `ConfigField`s — the messaging profile of the
/// generic task that replaces the retired `messaging/admin/config` (each
/// top-level member of the old opaque `config` blob becomes a field; the old
/// `version` member is the `mediator.version` key). The mediator loads its
/// configuration at startup, so every key reports `requiresRestart: true` with
/// source `mediator`.
async fn consume_config_show(
    typed: TrustTask<config::show::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::common::config::overrides::{KeyClass, class_of, parse_stored};
    use config::show::v0_1::{ConfigField, ConfigFieldKey, ConfigFieldSource, Response};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "config/show")?;

    // The configuration as dotted scalar keys (`limits.listed_messages`,
    // `database.database_url`), with the limits as they are in effect now
    // rather than as they were at startup.
    let mut config_object = serde_json::to_value(&state.config).map_err(serialize_err)?;
    config_object["limits"] = serde_json::to_value(&*state.limits()).map_err(serialize_err)?;
    let mut flat = Vec::new();
    flatten_config("", &config_object, &mut flat);

    // Which keys a `config/patch` override supplies.
    let overridden = parse_stored(
        state
            .database
            .config_overrides_get()
            .await
            .ok()
            .flatten()
            .as_deref(),
    );

    // Optional `keys` filter: return only the requested keys.
    let wanted: Option<HashSet<String>> = typed
        .payload
        .keys
        .as_ref()
        .map(|ks| ks.iter().map(|k| (**k).clone()).collect());

    let mut fields = Vec::new();
    let mut push_field = |key: String, value: Value| -> Result<(), MediatorError> {
        if wanted.as_ref().is_some_and(|w| !w.contains(&key)) {
            return Ok(());
        }
        let requires_restart = class_of(&key) != Some(KeyClass::Live);
        let source = if overridden.contains_key(&key) {
            "override"
        } else {
            "mediator"
        };
        fields.push(build(
            ConfigField::builder()
                .key(
                    ConfigFieldKey::from_str(&key)
                        .map_err(|e| serialize_err_msg(format!("config key: {e}")))?,
                )
                .requires_restart(requires_restart)
                .source(
                    ConfigFieldSource::from_str(source)
                        .map_err(|e| serialize_err_msg(format!("config source: {e}")))?,
                )
                .value(value),
        )?);
        Ok(())
    };
    push_field(
        "mediator.version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    )?;
    for (key, value) in flat {
        push_field(key, value)?;
    }

    let response: Response = build(Response::builder().fields(fields))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Flatten `value` into `prefix.key` → scalar pairs. Arrays, which the spec's
/// scalar `value` cannot hold, become their JSON text. Credentials embedded in
/// a URL are redacted: the spec requires it of any secret-bearing value, and a
/// store URL such as `redis://:password@host` is one.
fn flatten_config(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_config(&key, v, out);
            }
        }
        Value::Array(_) => out.push((
            prefix.to_string(),
            Value::String(redact_strings(value).to_string()),
        )),
        Value::String(s) => out.push((prefix.to_string(), Value::String(redact_url(s)))),
        scalar => out.push((prefix.to_string(), scalar.clone())),
    }
}

/// `value` with every string in it, at any depth, passed through [`redact_url`].
fn redact_strings(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_url(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_strings(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Map the mediator's internal [`Account`] to the wire `account/get` shape.
///
/// The DID is carried as the mediator's account hash — a valid `Vid` per the
/// messaging spec's privacy note (the mediator never holds the full DID). The
/// `u64` ACL bitfield is decoded into the spec's named booleans; `didcommEnabled`
/// / `tspEnabled` have no bitfield slot and are reported as `None`.
fn map_account_get(acc: &Account) -> account::get::v0_1::Account {
    use account::get::v0_1::{Account as WireAccount, AccountType as WireType, QueueLimits, Vid};

    let queue_limits: QueueLimits = QueueLimits::builder()
        .send_queue_limit(acc.queue_send_limit.map(|v| v as i64))
        .receive_queue_limit(acc.queue_receive_limit.map(|v| v as i64))
        .try_into()
        .expect("QueueLimits has no required member");

    WireAccount::builder()
        .did(Vid::from_str(&acc.did_hash).expect("an account hash is a non-empty Vid string"))
        .account_type(match acc._type {
            AccountType::Standard => WireType::Standard,
            AccountType::Admin => WireType::Admin,
            AccountType::RootAdmin => WireType::RootAdmin,
            AccountType::Mediator => WireType::Mediator,
            AccountType::Unknown => WireType::Standard,
        })
        .acl(decode_acl_canonical(&MediatorACLSet::from_u64(acc.acls)))
        .access_list_count(Some(acc.access_list_count as u64))
        .queue_limits(Some(queue_limits))
        .send_queue_count(Some(acc.send_queue_count as u64))
        .send_queue_bytes(Some(acc.send_queue_bytes))
        .receive_queue_count(Some(acc.receive_queue_count as u64))
        .receive_queue_bytes(Some(acc.receive_queue_bytes))
        .try_into()
        .expect("every required member of the wire Account is set above")
}

/// Map the mediator's [`AccountStats`] onto the wire shape. Every counter is
/// reported: this mediator keeps all of them, so an absent member on the wire
/// would say "not kept" of something it has.
fn to_wire_stats(
    stats: &affinidi_messaging_mediator_common::types::accounts::AccountStats,
) -> account::get::v0_1::AccountStats {
    use account::get::v0_1::{AccountStats as WireStats, ProtocolCounts};
    use affinidi_messaging_mediator_common::types::accounts::ProtocolCounts as Counts;

    let counts = |c: &Counts| -> ProtocolCounts {
        ProtocolCounts::builder()
            .didcomm(Some(c.didcomm))
            .didcomm_v1(Some(c.didcomm_v1))
            .tsp(Some(c.tsp))
            .other(Some(c.other))
            .try_into()
            .expect("ProtocolCounts has no required member")
    };
    WireStats::builder()
        .messages_received(Some(stats.messages_received))
        .messages_sent(Some(stats.messages_sent))
        .bytes_received(Some(stats.bytes_received))
        .bytes_sent(Some(stats.bytes_sent))
        .received_by_protocol(Some(counts(&stats.received_by_protocol)))
        .sent_by_protocol(Some(counts(&stats.sent_by_protocol)))
        .try_into()
        .expect("AccountStats has no required member")
}

/// [`to_wire_stats`] into another `messaging/*` module's copy of the shared
/// `AccountStats` type, the same JSON round-trip [`to_wire_account`] uses and
/// for the same reason: typify generates one copy per spec module.
fn to_wire_stats_as<T: serde::de::DeserializeOwned>(
    stats: &affinidi_messaging_mediator_common::types::accounts::AccountStats,
) -> T {
    serde_json::from_value(
        serde_json::to_value(to_wire_stats(stats)).expect("get AccountStats serialises"),
    )
    .expect("messaging AccountStats types share the one shared schema")
}

/// Re-shape [`map_account_get`]'s output into another `messaging/*` module's copy of
/// the shared `Account` type. typify generates a structurally-identical `Account`
/// per spec module; they all derive from the one shared schema, so a JSON round-trip
/// converts between them without re-implementing the bitfield decode.
fn decode_acl_canonical(acl: &MediatorACLSet) -> account::get::v0_1::MediatorAcl {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    // `didcommEnabled` / `tspEnabled` are left unset: they have no bitfield
    // slot, so there is nothing to decode into them.
    MediatorAcl::builder()
        .access_list_mode(Some(match acl.get_access_list_mode().0 {
            AccessListModeType::ExplicitAllow => MediatorAclAccessListMode::ExplicitAllow,
            AccessListModeType::ExplicitDeny => MediatorAclAccessListMode::ExplicitDeny,
        }))
        .blocked(Some(acl.get_blocked()))
        .local(Some(acl.get_local()))
        .send_messages(Some(acl.get_send_messages().0))
        .receive_messages(Some(acl.get_receive_messages().0))
        .send_forwarded(Some(acl.get_send_forwarded().0))
        .receive_forwarded(Some(acl.get_receive_forwarded().0))
        .create_invites(Some(acl.get_create_invites().0))
        .anon_receive(Some(acl.get_anon_receive().0))
        .self_manage_list(Some(acl.get_self_manage_list()))
        .self_manage_send_queue_limit(Some(acl.get_self_manage_send_queue_limit()))
        .self_manage_receive_queue_limit(Some(acl.get_self_manage_receive_queue_limit()))
        .try_into()
        .expect("MediatorAcl has no required member")
}

/// Decode an ACL set into any `messaging/*` module's copy of `MediatorAcl`.
fn to_wire_acl<T: serde::de::DeserializeOwned>(acl: &MediatorACLSet) -> T {
    serde_json::from_value(serde_json::to_value(decode_acl_canonical(acl)).expect("acl serialises"))
        .expect("messaging MediatorAcl types share the one shared schema")
}

/// Apply a wire `MediatorAcl` (from any module, passed as JSON) onto a base ACL set
/// as a **partial update**: each present value flag is set; absent flags and the
/// per-capability "self-change" bits — which the wire form does not carry — are left
/// as they are in `base`. `didcommEnabled`/`tspEnabled` have no bitfield slot and are
/// ignored. This is the reverse of [`decode_acl_canonical`].
fn merge_wire_acl(
    acl_value: Value,
    mut base: MediatorACLSet,
) -> Result<MediatorACLSet, MediatorError> {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    let acl: MediatorAcl = serde_json::from_value(acl_value)
        .map_err(|e| malformed_acl(format!("invalid ACL payload: {e}")))?;
    let acl_err = |e: ACLError| malformed_acl(format!("ACL update rejected: {e}"));

    if let Some(mode) = acl.access_list_mode {
        let mode = match mode {
            MediatorAclAccessListMode::ExplicitAllow => AccessListModeType::ExplicitAllow,
            MediatorAclAccessListMode::ExplicitDeny => AccessListModeType::ExplicitDeny,
            // No wildcard: the mode decides whether the list allows or denies,
            // and a mode this build does not know cannot be decoded, so it is
            // never guessed. A new mode arrives only with a pin move, and then
            // this match fails to compile until it is mapped.
        };
        let self_change = base.get_access_list_mode().1;
        base.set_access_list_mode(mode, self_change, true)
            .map_err(acl_err)?;
    }
    if let Some(v) = acl.blocked {
        base.set_blocked(v);
    }
    if let Some(v) = acl.local {
        base.set_local(v);
    }
    if let Some(v) = acl.send_messages {
        let sc = base.get_send_messages().1;
        base.set_send_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_messages {
        let sc = base.get_receive_messages().1;
        base.set_receive_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.send_forwarded {
        let sc = base.get_send_forwarded().1;
        base.set_send_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_forwarded {
        let sc = base.get_receive_forwarded().1;
        base.set_receive_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.create_invites {
        let sc = base.get_create_invites().1;
        base.set_create_invites(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.anon_receive {
        let sc = base.get_anon_receive().1;
        base.set_anon_receive(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.self_manage_list {
        base.set_self_manage_list(v);
    }
    if let Some(v) = acl.self_manage_send_queue_limit {
        base.set_self_manage_send_queue_limit(v);
    }
    if let Some(v) = acl.self_manage_receive_queue_limit {
        base.set_self_manage_receive_queue_limit(v);
    }
    Ok(base)
}

fn to_wire_account<T: serde::de::DeserializeOwned>(acc: &Account) -> T {
    serde_json::from_value(
        serde_json::to_value(map_account_get(acc)).expect("get Account serialises"),
    )
    .expect("messaging Account types share the one shared schema")
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

/// A mux task's request-level refusal as a problem report. An
/// `epochMismatch` carries the epoch in force as its first argument, which a
/// `trust-task-error` turns into `details.currentEpoch`
/// ([`trust_task_error`](crate::messages::protocols::trust_task_error)); the comment says it too, for older clients.
fn task_refusal(session: &Session, e: crate::mux::tasks::TaskError) -> MediatorError {
    let args = e
        .current_epoch
        .map(|c| vec![c.to_string()])
        .unwrap_or_default();
    tt_problem_with_args(
        session,
        &e.code,
        e.message,
        args,
        if e.retryable {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_REQUEST
        },
    )
}

/// Serve a connection-independent `messaging/mux/*` task (design §4).
///
/// Off unless `limits.mux.enabled`, in which case the type is unsupported, as
/// the specs require. The response payload is built as JSON and checked
/// against the generated `Response` type before it is wrapped, so a shape the
/// schema does not allow fails here rather than on the client.
async fn consume_mux(
    task: ServedTask,
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    sender_did: &str,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::{grants::Ctx, proof::StatementVerifier, tasks};
    use crate::task_specs::messaging::mux;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;

    let verifier = StatementVerifier::new(state.did_resolver.clone());
    let ctx = Ctx {
        store: &*state.database,
        verifier: &verifier,
        mediator_did,
        limits: state.config.limits.mux.store_limits(),
        default_acl: &state.config.security.global_acl_default,
        now: now.timestamp().max(0) as u64,
    };
    let payload = &doc.payload;
    let refused = |e: tasks::TaskError| task_refusal(session, e);

    // attach / detach act on the connection the request arrived on.
    let conn = || {
        state.mux.get(&session.session_id).ok_or_else(|| {
            tt_problem(
                session,
                "messaging/mux:notMuxConnection",
                "this request must be sent on a mux connection".to_string(),
                StatusCode::BAD_REQUEST,
            )
        })
    };
    let streaming = state.streaming_task.as_ref();

    let (mut response, changed) = match task {
        ServedTask::MuxAttach => {
            tasks::attach(
                &ctx,
                &*conn()?,
                streaming,
                state.config.limits.mux.max_attach_lifetime_secs,
                payload,
            )
            .await
        }
        ServedTask::MuxDetach => (
            tasks::detach(&*conn()?, streaming, payload).await,
            tasks::Changed::default(),
        ),
        ServedTask::MuxAck => {
            conn()?;
            (
                tasks::ack(state, session, payload).await.map_err(refused)?,
                tasks::Changed::default(),
            )
        }
        ServedTask::MuxGrant => tasks::grant(&ctx, sender_did, payload).await,
        ServedTask::MuxList => (
            tasks::list(&ctx, sender_did, payload)
                .await
                .map_err(refused)?,
            tasks::Changed::default(),
        ),
        ServedTask::MuxUpdate => tasks::update(&ctx, sender_did, payload)
            .await
            .map_err(refused)?,
        ServedTask::MuxRevoke => tasks::revoke(&ctx, sender_did, payload)
            .await
            .map_err(refused)?,
        ServedTask::MuxRevokeAll => tasks::revoke_all(&ctx, payload).await.map_err(refused)?,
        _ => unreachable!("consume_mux is only called for mux tasks"),
    };

    let carried = apply_mux_change(state, &ctx, &changed).await;
    // `attachedNow` on each stored grant: whether a connection on this
    // instance took the member. Another instance's connection takes it
    // moments later and is not counted.
    if !changed.stored.is_empty()
        && let Some(results) = response.get_mut("results").and_then(Value::as_array_mut)
    {
        for r in results {
            if r.get("status").and_then(Value::as_str) == Some("stored") {
                let id = r.get("grantId").and_then(Value::as_str).unwrap_or_default();
                r["attachedNow"] = Value::Bool(carried.contains(id));
            }
        }
    }
    // Audit records the specs require: revocations, an advanced epoch, and
    // grants the unknown-key rule suspended.
    match task {
        ServedTask::MuxRevoke => {
            crate::mux::audit::revoked(state, &session.did_hash, &changed).await
        }
        ServedTask::MuxRevokeAll => {
            crate::mux::audit::revoked_all(state, &session.did_hash, &response).await
        }
        _ => {}
    }
    crate::mux::audit::suspended(
        state,
        &changed.suspended,
        crate::mux::audit::SuspendedBy::Statement,
    )
    .await;

    fn respond<P, R>(
        doc: &TrustTask<Value>,
        session: &Session,
        response: Value,
    ) -> Result<Value, MediatorError>
    where
        P: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned + serde::Serialize,
    {
        let typed: TrustTask<P> = downcast(doc, session)?;
        let response: R = serde_json::from_value(response).map_err(|e| {
            serialize_err_msg(format!("mux response does not match its schema: {e}"))
        })?;
        serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err)
    }
    match task {
        ServedTask::MuxAttach => {
            respond::<mux::attach::v0_1::Payload, mux::attach::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxDetach => {
            respond::<mux::detach::v0_1::Payload, mux::detach::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxAck => {
            respond::<mux::ack::v0_1::Payload, mux::ack::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxGrant => {
            respond::<mux::grant::v0_1::Payload, mux::grant::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxList => {
            respond::<mux::list::v0_1::Payload, mux::list::v0_1::Response>(doc, session, response)
        }
        ServedTask::MuxUpdate => {
            respond::<mux::update::v0_1::Payload, mux::update::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxRevoke => {
            respond::<mux::revoke::v0_1::Payload, mux::revoke::v0_1::Response>(
                doc, session, response,
            )
        }
        ServedTask::MuxRevokeAll => respond::<
            mux::revoke_all::v0_1::Payload,
            mux::revoke_all::v0_1::Response,
        >(doc, session, response),
        _ => unreachable!("consume_mux is only called for mux tasks"),
    }
}

/// Carry a committed mux change to every live connection, then tell the
/// other instances and the affected principals. Every `messaging/mux/*` task
/// that changes grants comes through here — a party's own `revoke` or
/// `revoke-all`, and an administrator's `admin-revoke` or `admin-revoke-all`
/// — so they detach, publish and notify identically; only the reason in
/// `changed` differs. Returns the ids of stored grants a connection on this
/// instance took.
async fn apply_mux_change(
    state: &SharedData,
    ctx: &crate::mux::grants::Ctx<'_>,
    changed: &crate::mux::tasks::Changed,
) -> std::collections::HashSet<String> {
    use crate::mux::session::LeaveReason;
    let streaming = state.streaming_task.as_ref();
    // Drop the members whose grants this task removed, voided or suspended,
    // and re-scope narrowed ones, on every live connection that carries them
    // — *before* answering, so no frame for them leaves after the response
    // says they are gone (§7.3, R1.1/R7.2).
    if !changed.removed.is_empty() {
        state
            .mux
            .detach_grants(
                streaming,
                &changed.removed,
                changed.reason.unwrap_or(LeaveReason::RevokedByMember),
            )
            .await;
    }
    if !changed.suspended.is_empty() {
        state
            .mux
            .detach_grants(
                streaming,
                &changed.suspended,
                LeaveReason::SuspendedUnknownKey,
            )
            .await;
    }
    if !changed.narrowed.is_empty() {
        state
            .mux
            .narrow(state.streaming_task.as_ref(), &changed.narrowed)
            .await;
    }
    // An epoch advance ends the member's session attaches as well as its
    // grants, on every connection here, before answering (design §5.2).
    let attaches_reason = changed.reason.unwrap_or(LeaveReason::EpochBumped);
    if let Some(member) = &changed.attaches_ended {
        state
            .mux
            .detach_attaches(streaming, member, ctx.now, attaches_reason)
            .await;
    }
    let carried = if changed.stored.is_empty() {
        Default::default()
    } else {
        state
            .mux
            .admit_grants(streaming, ctx.store, &ctx.limits, ctx.now, &changed.stored)
            .await
    };
    // The same principals' connections on other instances sharing the store
    // follow within one pub/sub hop (§7.4); this answer does not wait for them.
    crate::mux::sync::publish(state, &crate::mux::sync::changes_of(changed)).await;
    if let Some(member) = &changed.attaches_ended {
        crate::mux::sync::publish_members(
            state,
            &[
                affinidi_messaging_mediator_common::store::mux::MemberHint::AttachesEnded {
                    did_hash: member.clone(),
                    at: ctx.now,
                    // Only a reason other than the member's own is sent, so
                    // an instance that predates the field reads the same.
                    reason: (attaches_reason != LeaveReason::EpochBumped)
                        .then(|| attaches_reason.wire().to_string()),
                },
            ],
        )
        .await;
    }
    // Durable notices for what this task suspended or revoked: only now,
    // once the change is committed and its members detached (spec rule 2).
    crate::mux::notice::after_change(state, changed).await;
    carried
}

/// Serve an administrator's stored-grant task: `messaging/mux/admin-list`,
/// `admin-revoke` or `admin-revoke-all` (see [`crate::mux::admin_grants`]).
///
/// Authorised as `messaging/mux/connections` is — the §7.2 checks have run
/// (proof, `issuedAt`, freshness) and the requester's stored role decides —
/// with the read open to the mediator's own account and the two destructive
/// tasks to `admin` and `rootAdmin` only. A revocation is applied through
/// [`apply_mux_change`], as a party's own `revoke` is, before the answer.
async fn consume_mux_admin(
    task: ServedTask,
    doc: &TrustTask<Value>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use crate::mux::{admin_grants, grants::Ctx, proof::StatementVerifier, tasks};
    use crate::task_specs::messaging::mux;

    if !state.config.limits.mux.enabled {
        return Err(tt_problem(
            session,
            "unsupportedType",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    validate_tt_basic(doc, session, mediator_did, now)?;
    match task {
        // The read: administrators and the mediator's own account.
        ServedTask::MuxAdminList => {
            if !roles::is_privileged(session.account_type) {
                return Err(tt_problem(
                    session,
                    "permissionDenied",
                    "messaging/mux/admin-list requires an administrator account".into(),
                    StatusCode::FORBIDDEN,
                ));
            }
        }
        // Destructive: an operator decides, never the service.
        ServedTask::MuxAdminRevoke => require_admin(session, "messaging/mux/admin-revoke")?,
        ServedTask::MuxAdminRevokeAll => require_admin(session, "messaging/mux/admin-revoke-all")?,
        _ => unreachable!("consume_mux_admin is only called for mux admin tasks"),
    }

    let verifier = StatementVerifier::new(state.did_resolver.clone());
    let ctx = Ctx {
        store: &*state.database,
        verifier: &verifier,
        mediator_did,
        limits: state.config.limits.mux.store_limits(),
        default_acl: &state.config.security.global_acl_default,
        now: now.timestamp().max(0) as u64,
    };
    let root_admin_hash =
        affinidi_messaging_mediator_common::did_identity::did_hash(&state.config.admin_did);
    let requester = admin_grants::Requester {
        root: roles::is_root(session.account_type),
        root_admin_hash: &root_admin_hash,
    };
    let refused = |e: tasks::TaskError| task_refusal(session, e);

    fn respond<P, R>(
        doc: &TrustTask<Value>,
        session: &Session,
        response: Value,
    ) -> Result<Value, MediatorError>
    where
        P: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned + serde::Serialize,
    {
        let typed: TrustTask<P> = downcast(doc, session)?;
        let response: R = serde_json::from_value(response).map_err(|e| {
            serialize_err_msg(format!("mux response does not match its schema: {e}"))
        })?;
        serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
            .map_err(serialize_err)
    }

    match task {
        ServedTask::MuxAdminList => {
            let key = admin_list_cursor_key(state).await;
            let binding = admin_grants::CursorBinding {
                requester: &session.did_hash,
                now: ctx.now,
                key: &key,
            };
            let page = admin_grants::admin_list(&ctx, &doc.payload, &binding)
                .await
                .map_err(refused)?;
            respond::<mux::admin_list::v0_1::Payload, mux::admin_list::v0_1::Response>(
                doc, session, page,
            )
        }
        ServedTask::MuxAdminRevoke => {
            let (result, changed) =
                admin_grants::admin_revoke(&ctx, &requester, &doc.payload).await;
            // Whatever was revoked is detached, published and notified, even
            // when a later member's record refused the write (spec rule 10).
            if !changed.removed.is_empty() {
                apply_mux_change(state, &ctx, &changed).await;
                let selection = admin_selection(&doc.payload);
                crate::mux::audit::admin_revoked(
                    state,
                    &session.did_hash,
                    &selection,
                    &changed.removed,
                )
                .await;
            }
            respond::<mux::admin_revoke::v0_1::Payload, mux::admin_revoke::v0_1::Response>(
                doc,
                session,
                result.map_err(refused)?,
            )
        }
        ServedTask::MuxAdminRevokeAll => {
            let (response, changed, voided_epoch) =
                admin_grants::admin_revoke_all(&ctx, &requester, &doc.payload)
                    .await
                    .map_err(refused)?;
            apply_mux_change(state, &ctx, &changed).await;
            if let (Some(before), Some(member)) = (voided_epoch, &changed.attaches_ended) {
                crate::mux::audit::admin_revoked_all(
                    state,
                    &session.did_hash,
                    member,
                    before,
                    before + 1,
                    changed.removed.len(),
                )
                .await;
            }
            respond::<mux::admin_revoke_all::v0_1::Payload, mux::admin_revoke_all::v0_1::Response>(
                doc, session, response,
            )
        }
        _ => unreachable!("consume_mux_admin is only called for mux admin tasks"),
    }
}

/// An `admin-revoke` selection for the audit record, as DID hashes.
fn admin_selection(payload: &Value) -> String {
    use affinidi_messaging_mediator_common::did_identity::did_hash;
    let mut parts = Vec::new();
    if let Some(p) = payload.get("principal").and_then(Value::as_str) {
        parts.push(format!("principal {}", did_hash(p)));
    }
    if let Some(m) = payload.get("member").and_then(Value::as_str) {
        parts.push(format!("member {}", did_hash(m)));
    }
    if let Some(ids) = payload.get("grantIds").and_then(Value::as_array) {
        parts.push(format!("{} named grant ids", ids.len()));
    }
    parts.join(", ")
}

/// The key `messaging/mux/admin-list` cursors are tagged with. Derived from
/// the mediator's own signing key, so every instance of one mediator holds
/// the same key and a listing paged on one continues on another; a mediator
/// without a signing key falls back to a key that lives only in this
/// process, and its cursors then continue only here.
async fn admin_list_cursor_key(state: &SharedData) -> Vec<u8> {
    static PROCESS_KEY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        k[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        k
    });
    match super::trust_task_sign::signing_secret(state).await {
        Some(secret) => ring::digest::digest(
            &ring::digest::SHA256,
            &[
                b"affinidi-mediator/mux/admin-list/cursor\n".as_slice(),
                secret.get_private_bytes(),
            ]
            .concat(),
        )
        .as_ref()
        .to_vec(),
        None => PROCESS_KEY.to_vec(),
    }
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
fn build<T, B>(builder: B) -> Result<T, MediatorError>
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
