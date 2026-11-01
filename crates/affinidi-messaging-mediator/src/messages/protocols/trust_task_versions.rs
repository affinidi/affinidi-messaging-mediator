//! Serving the 0.2 version of a task beside its 0.1.
//!
//! Seven tasks have a 0.2 that changes the wire without extending 0.1, so a
//! 0.1 client cannot be routed to it: `ping`, `account/{get,list,add,update}`,
//! `audit/list` and `message/status`. The mediator serves both versions until
//! 0.1 is withdrawn.
//!
//! The two versions differ in a handful of members, so each task keeps one
//! handler. A 0.2 request has already been accepted under its own 0.2 rules
//! (freshness, issuer binding, proof, spec policy). It is then rewritten as the
//! 0.1 request its handler takes, and the handler's reply is rewritten as the
//! 0.2 response. The rewritten reply is parsed as the generated 0.2
//! `Response`, so a rewrite that drifts from the spec fails here instead of
//! reaching a client.
//!
//! What moves, per the specs' "Changes from 0.1":
//!
//! | Task | Request | Response |
//! |---|---|---|
//! | `messaging/ping` | — | `serverTime` → `respondedAt` |
//! | `messaging/account/{get,add,update}` | — | `account.lastReceivedAt` / `lastAuthenticatedAt`: Unix seconds → RFC 3339 |
//! | `messaging/account/list` | — | the same, on each of `accounts` |
//! | `audit/list` | `limit` → `pageSize` | `cursor` → `nextCursor`; `truncated` removed |
//! | `messaging/message/status` | — | `statuses[].at` → `reachedAt` |
//!
//! `messaging/monitor/event` is pushed at 0.2 only (`at` → `occurredAt`); it
//! is not served, so there is no 0.1 to keep beside it (see `crate::monitor`).

use std::str::FromStr;

use chrono::{DateTime, SecondsFormat};
use serde_json::{Map, Value};
use trust_tasks_rs::{Payload, SpecPolicy, TrustTask, TypeUri};

use super::trust_tasks::ServedTask;
use crate::task_specs::audit;
use crate::task_specs::messaging::{account, message, ping};

/// A task served at 0.2 beside its 0.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NewerVersion {
    Ping,
    AccountGet,
    AccountList,
    AccountAdd,
    AccountUpdate,
    AuditList,
    MessageStatus,
}

impl NewerVersion {
    /// Every task served at 0.2.
    pub(crate) const ALL: &'static [NewerVersion] = &[
        NewerVersion::Ping,
        NewerVersion::AccountGet,
        NewerVersion::AccountList,
        NewerVersion::AccountAdd,
        NewerVersion::AccountUpdate,
        NewerVersion::AuditList,
        NewerVersion::MessageStatus,
    ];

    /// The 0.2 request type URI.
    pub(crate) fn type_uri(self) -> TypeUri {
        match self {
            NewerVersion::Ping => uri::<ping::v0_2::Payload>(),
            NewerVersion::AccountGet => uri::<account::get::v0_2::Payload>(),
            NewerVersion::AccountList => uri::<account::list::v0_2::Payload>(),
            NewerVersion::AccountAdd => uri::<account::add::v0_2::Payload>(),
            NewerVersion::AccountUpdate => uri::<account::update::v0_2::Payload>(),
            NewerVersion::AuditList => uri::<audit::list::v0_2::Payload>(),
            NewerVersion::MessageStatus => uri::<message::status::v0_2::Payload>(),
        }
    }

    /// The 0.2 spec's presence rules (proof, `issuedAt`, recipient).
    pub(crate) fn spec_policy(self) -> SpecPolicy {
        match self {
            NewerVersion::Ping => SpecPolicy::of::<ping::v0_2::Payload>(),
            NewerVersion::AccountGet => SpecPolicy::of::<account::get::v0_2::Payload>(),
            NewerVersion::AccountList => SpecPolicy::of::<account::list::v0_2::Payload>(),
            NewerVersion::AccountAdd => SpecPolicy::of::<account::add::v0_2::Payload>(),
            NewerVersion::AccountUpdate => SpecPolicy::of::<account::update::v0_2::Payload>(),
            NewerVersion::AuditList => SpecPolicy::of::<audit::list::v0_2::Payload>(),
            NewerVersion::MessageStatus => SpecPolicy::of::<message::status::v0_2::Payload>(),
        }
    }

    /// The 0.1 task whose handler serves this version.
    pub(crate) fn base(self) -> ServedTask {
        match self {
            NewerVersion::Ping => ServedTask::Ping,
            NewerVersion::AccountGet => ServedTask::AccountGet,
            NewerVersion::AccountList => ServedTask::AccountList,
            NewerVersion::AccountAdd => ServedTask::AccountAdd,
            NewerVersion::AccountUpdate => ServedTask::AccountUpdate,
            NewerVersion::AuditList => ServedTask::AuditList,
            NewerVersion::MessageStatus => ServedTask::MessageStatus,
        }
    }

    /// The task a request type URI names at 0.2, if any. A `#response` is not
    /// a request and is never matched.
    pub(crate) fn from_type_uri(uri: &TypeUri) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.type_uri() == *uri)
    }

    /// Rewrite an accepted 0.2 request as the 0.1 request its handler takes.
    pub(crate) fn to_v0_1_request(self, mut doc: TrustTask<Value>) -> TrustTask<Value> {
        doc.type_uri = self.base().type_uri();
        if self == NewerVersion::AuditList
            && let Some(payload) = doc.payload.as_object_mut()
        {
            rename(payload, "limit", "pageSize");
        }
        doc
    }

    /// Rewrite the 0.1 handler's reply as the 0.2 response.
    ///
    /// Only a `#response` to the 0.1 request is rewritten. Anything else (a
    /// `trust-task-error` document, for one) carries no version-specific
    /// members and passes through unchanged.
    pub(crate) fn to_v0_2_response(self, mut reply: Value) -> Result<Value, String> {
        let v0_1 = format!("{}#response", self.base().type_uri());
        if reply.get("type").and_then(Value::as_str) != Some(v0_1.as_str()) {
            return Ok(reply);
        }
        let Some(doc) = reply.as_object_mut() else {
            return Ok(reply);
        };
        doc.insert(
            "type".into(),
            Value::String(format!("{}#response", self.type_uri())),
        );
        let payload = doc
            .get_mut("payload")
            .and_then(Value::as_object_mut)
            .ok_or("the 0.1 reply has no payload object")?;

        match self {
            NewerVersion::Ping => rename(payload, "serverTime", "respondedAt"),
            NewerVersion::AccountGet | NewerVersion::AccountAdd | NewerVersion::AccountUpdate => {
                if let Some(account) = payload.get_mut("account").and_then(Value::as_object_mut) {
                    activity_instants_to_rfc3339(account)?;
                }
            }
            NewerVersion::AccountList => {
                if let Some(accounts) = payload.get_mut("accounts").and_then(Value::as_array_mut) {
                    for account in accounts.iter_mut().filter_map(Value::as_object_mut) {
                        activity_instants_to_rfc3339(account)?;
                    }
                }
            }
            NewerVersion::AuditList => {
                payload.remove("truncated");
                rename(payload, "cursor", "nextCursor");
            }
            NewerVersion::MessageStatus => {
                if let Some(statuses) = payload.get_mut("statuses").and_then(Value::as_array_mut) {
                    for status in statuses.iter_mut().filter_map(Value::as_object_mut) {
                        rename(status, "at", "reachedAt");
                    }
                }
            }
        }

        let payload = Value::Object(payload.clone());
        self.check_response(payload)?;
        Ok(reply)
    }

    /// Parse a rewritten payload as the generated 0.2 `Response`.
    fn check_response(self, payload: Value) -> Result<(), String> {
        fn parse<R: serde::de::DeserializeOwned>(payload: Value) -> Result<(), String> {
            serde_json::from_value::<R>(payload)
                .map(|_| ())
                .map_err(|e| format!("the rewritten 0.2 response does not match its schema: {e}"))
        }
        match self {
            NewerVersion::Ping => parse::<ping::v0_2::Response>(payload),
            NewerVersion::AccountGet => parse::<account::get::v0_2::Response>(payload),
            NewerVersion::AccountList => parse::<account::list::v0_2::Response>(payload),
            NewerVersion::AccountAdd => parse::<account::add::v0_2::Response>(payload),
            NewerVersion::AccountUpdate => parse::<account::update::v0_2::Response>(payload),
            NewerVersion::AuditList => parse::<audit::list::v0_2::Response>(payload),
            NewerVersion::MessageStatus => parse::<message::status::v0_2::Response>(payload),
        }
    }
}

fn uri<P: Payload>() -> TypeUri {
    TypeUri::from_str(P::TYPE_URI).expect("generated payload has a valid type URI")
}

fn rename(obj: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = obj.remove(from) {
        obj.insert(to.to_string(), v);
    }
}

/// 0.1 carries an account's activity instants as Unix seconds; 0.2 as RFC 3339.
fn activity_instants_to_rfc3339(account: &mut Map<String, Value>) -> Result<(), String> {
    for key in ["lastReceivedAt", "lastAuthenticatedAt"] {
        let Some(value) = account.get(key) else {
            continue;
        };
        let rfc3339 = match value {
            Value::Number(n) => {
                let secs = n
                    .as_i64()
                    .ok_or_else(|| format!("{key} is not a whole number of seconds"))?;
                DateTime::from_timestamp(secs, 0)
                    .ok_or_else(|| format!("{key} is out of range"))?
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
            }
            Value::Null => {
                account.remove(key);
                continue;
            }
            other => return Err(format!("{key} is {other}, not Unix seconds")),
        };
        account.insert(key.to_string(), Value::String(rfc3339));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply(task: NewerVersion, payload: Value) -> Value {
        json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
            "type": format!("{}#response", task.base().type_uri()),
            "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "issuer": "did:example:mediator",
            "recipient": "did:example:alice",
            "payload": payload,
        })
    }

    #[test]
    fn every_newer_version_is_a_distinct_newer_uri_of_its_base() {
        let mut seen = std::collections::HashSet::new();
        for &v in NewerVersion::ALL {
            let new = v.type_uri().to_string();
            let old = v.base().type_uri().to_string();
            assert!(seen.insert(new.clone()), "{v:?} duplicates a type URI");
            assert!(new.ends_with("/0.2"), "{v:?}: {new}");
            assert_eq!(new.trim_end_matches("/0.2"), old.trim_end_matches("/0.1"));
            assert_eq!(NewerVersion::from_type_uri(&v.type_uri()), Some(v));
            assert_eq!(ServedTask::from_type_uri(&v.type_uri()), None);
        }
    }

    #[test]
    fn a_v0_2_request_runs_as_v0_1() {
        let doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "type": NewerVersion::AuditList.type_uri().to_string(),
            "payload": {"limit": 50, "cursor": "abc"},
        }))
        .unwrap();
        let doc = NewerVersion::AuditList.to_v0_1_request(doc);
        assert_eq!(doc.type_uri, ServedTask::AuditList.type_uri());
        assert_eq!(doc.payload, json!({"pageSize": 50, "cursor": "abc"}));
    }

    #[test]
    fn ping_reply_names_responded_at() {
        let out = NewerVersion::Ping
            .to_v0_2_response(reply(
                NewerVersion::Ping,
                json!({"status": "ok", "nonce": "n1", "protocols": ["didcomm", "tsp"],
                       "serverTime": "2026-10-27T10:00:00Z"}),
            ))
            .unwrap();
        assert_eq!(
            out["type"],
            format!("{}#response", NewerVersion::Ping.type_uri())
        );
        assert_eq!(out["payload"]["respondedAt"], "2026-10-27T10:00:00Z");
        assert!(out["payload"].get("serverTime").is_none());
    }

    #[test]
    fn audit_reply_pages_with_next_cursor() {
        let out = NewerVersion::AuditList
            .to_v0_2_response(reply(
                NewerVersion::AuditList,
                json!({"entries": [], "cursor": "next", "truncated": true}),
            ))
            .unwrap();
        assert_eq!(out["payload"], json!({"entries": [], "nextCursor": "next"}));

        let last = NewerVersion::AuditList
            .to_v0_2_response(reply(
                NewerVersion::AuditList,
                json!({"entries": [], "truncated": false}),
            ))
            .unwrap();
        assert_eq!(last["payload"], json!({"entries": []}));
    }

    #[test]
    fn message_status_reply_names_reached_at() {
        let out = NewerVersion::MessageStatus
            .to_v0_2_response(reply(
                NewerVersion::MessageStatus,
                json!({"statuses": [{"msgId": "m1", "state": "delivered",
                                     "at": "2026-10-27T10:00:00Z"}]}),
            ))
            .unwrap();
        let status = &out["payload"]["statuses"][0];
        assert_eq!(status["reachedAt"], "2026-10-27T10:00:00Z");
        assert!(status.get("at").is_none());
    }

    #[test]
    fn account_activity_instants_become_rfc3339() {
        let mut account = Map::new();
        account.insert("lastReceivedAt".into(), json!(1_793_095_200));
        account.insert("lastAuthenticatedAt".into(), Value::Null);
        activity_instants_to_rfc3339(&mut account).unwrap();
        assert_eq!(account["lastReceivedAt"], "2026-10-27T10:00:00Z");
        assert!(!account.contains_key("lastAuthenticatedAt"));
        account.insert("lastAuthenticatedAt".into(), json!("yesterday"));
        assert!(activity_instants_to_rfc3339(&mut account).is_err());
    }

    #[test]
    fn an_error_reply_passes_through() {
        let err = json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000003",
            "type": "https://trusttasks.org/spec/trust-task-error/0.1",
            "payload": {"code": "malformedRequest"},
        });
        assert_eq!(
            NewerVersion::Ping.to_v0_2_response(err.clone()).unwrap(),
            err
        );
    }

    #[test]
    fn a_reply_that_breaks_the_v0_2_schema_is_refused() {
        // A ping reply with no `serverTime` has no `respondedAt`, which 0.2
        // requires, so it cannot be sent as 0.2.
        let out = NewerVersion::Ping.to_v0_2_response(reply(
            NewerVersion::Ping,
            json!({"status": "ok", "nonce": "n1", "protocols": []}),
        ));
        assert!(out.is_err());
    }
}
