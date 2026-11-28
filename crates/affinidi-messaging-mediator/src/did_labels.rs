//! The DID label behind each hash.
//!
//! The mediator keys accounts and access-list entries by the SHA-256 of a DID
//! (`did_identity::did_hash`), and every Trust Task field that names one holds
//! that hash. Alongside it the mediator now keeps a **label**: the DID itself,
//! written once and never changed, used only to show which DID a hash is. No
//! check or lookup ever reads it.
//!
//! - [`remember`] fills the label of every account that authenticates;
//! - [`prepare`] lets an account or access-list task name an account or entry
//!   by its DID as well as by its hash: a `did:` value is hashed here, so the
//!   task runs on hashes as it always has;
//! - [`annotate`] fills the labels of the DIDs a caller named, and, only when
//!   the request asked with `ext["com.affinidi.messaging"].includeDids: true`,
//!   adds `ext["com.affinidi.messaging"].dids`, a `hash → DID` map, to the
//!   response.
//!
//! Every existing field keeps the hash and `ext` is the Trust Task spec's
//! extension member (SPEC §4.5.1), so a caller that sends hashes and doesn't
//! ask for the labels sees exactly what it saw before.

use crate::{SharedData, messages::protocols::trust_tasks::ServedTask};
use affinidi_messaging_mediator_common::did_identity;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// The `ext` namespace this mediator reads and writes (SPEC §4.5.1).
pub const EXT_NAMESPACE: &str = "com.affinidi.messaging";

/// `did` (with `did_hash`) completed authentication: fill its label if empty.
pub(crate) async fn remember(state: &SharedData, did: &str, did_hash: &str) {
    let did = did_identity::account_did(did);
    if let Err(e) = state.database.did_label_fill(did_hash, &did).await {
        warn!("couldn't record the DID label of {did_hash}: {e}");
    }
}

/// The tasks that name accounts or access-list entries by hash. Only these
/// take a DID in place of a hash, and only these return labels.
fn names_accounts(task: ServedTask) -> bool {
    matches!(
        task,
        ServedTask::AccountGet
            | ServedTask::AccountList
            | ServedTask::AccountAdd
            | ServedTask::AccountUpdate
            | ServedTask::AccountRemove
            | ServedTask::AclGet
            | ServedTask::AccessListUpdate
            | ServedTask::AccessListList
    )
}

/// The request fields that name an account or access-list entry by hash.
const REQUEST_HASH_FIELDS: [&str; 5] = ["did", "add", "remove", "entries", "dids"];

/// What [`prepare`] found in a request, for [`annotate`].
#[derive(Debug, Default)]
pub(crate) struct Prepared {
    task: Option<ServedTask>,
    /// `hash → DID` for every DID the caller named in place of a hash.
    named: HashMap<String, String>,
    /// The caller asked for the labels.
    include_dids: bool,
}

/// Before an account or access-list task runs: replace every `did:` value in
/// a hash field (`did`, `add`, `remove`, `entries`, `dids`) by its hash, and
/// read the `includeDids` flag. A value that isn't a DID is a hash, as today.
/// Other tasks are left untouched.
pub(crate) fn prepare(task: ServedTask, request_payload: &mut Value) -> Prepared {
    if !names_accounts(task) {
        return Prepared::default();
    }
    let include_dids = request_payload
        .pointer(&format!("/ext/{EXT_NAMESPACE}/includeDids"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut named = HashMap::new();
    if let Some(payload) = request_payload.as_object_mut() {
        let mut hash_in_place = |v: &mut Value| {
            if let Some(did) = v.as_str().filter(|d| d.starts_with("did:")) {
                let did = did_identity::account_did(did).into_owned();
                let hash = did_identity::did_hash(&did);
                *v = Value::String(hash.clone());
                named.insert(hash, did);
            }
        };
        for field in REQUEST_HASH_FIELDS {
            match payload.get_mut(field) {
                Some(Value::Array(items)) => items.iter_mut().for_each(&mut hash_in_place),
                Some(v) => hash_in_place(v),
                None => {}
            }
        }
    }
    Prepared {
        task: Some(task),
        named,
        include_dids,
    }
}

/// After the task succeeded: fill the label of each DID the caller named whose
/// hash the response keeps (not one it removed), then, if the caller asked,
/// add `ext["com.affinidi.messaging"].dids` for every hash the response names
/// that has a label.
pub(crate) async fn annotate(state: &SharedData, prepared: Prepared, mut response: Value) -> Value {
    let Some(task) = prepared.task else {
        return response;
    };
    let Some(payload) = response.get_mut("payload").and_then(Value::as_object_mut) else {
        return response;
    };

    // Only DIDs whose hash this task added or touched, so a caller can't fill
    // the store with DIDs that have nothing to do with this mediator, and not
    // the account a removal just deleted with its label.
    if task != ServedTask::AccountRemove && !prepared.named.is_empty() {
        for hash in hashes_in(payload, false) {
            if let Some(did) = prepared.named.get(&hash)
                && let Err(e) = state.database.did_label_fill(&hash, did).await
            {
                warn!("couldn't record the DID label of {hash}: {e}");
            }
        }
    }

    if !prepared.include_dids {
        return response;
    }
    let hashes: Vec<String> = hashes_in(payload, true).into_iter().collect();
    let dids: Map<String, Value> = if hashes.is_empty() {
        Map::new()
    } else {
        match state.database.did_labels_get(&hashes).await {
            Ok(dids) => dids
                .into_iter()
                .map(|(h, d)| (h, Value::String(d)))
                .collect(),
            Err(e) => {
                // The response is still right without the labels.
                warn!("couldn't read the DID labels of a response's hashes: {e}");
                return response;
            }
        }
    };
    // Present (possibly empty) whenever asked, so a caller can tell a mediator
    // that has no label for a hash from one that doesn't know the flag.
    let ext = payload
        .entry("ext")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(ext) = ext.as_object_mut() {
        ext.insert(EXT_NAMESPACE.into(), serde_json::json!({ "dids": dids }));
    }
    response
}

/// The DID hashes a response payload names: `did`, `account.did`,
/// `accounts[].did`, and the `entries` (or `entries[].did`) / `added` lists,
/// plus `removed` / `unknown` when `all`.
fn hashes_in(payload: &Map<String, Value>, all: bool) -> HashSet<String> {
    let mut hashes = HashSet::new();
    let mut push = |v: Option<&Value>| {
        if let Some(h) = v.and_then(Value::as_str) {
            hashes.insert(h.to_string());
        }
    };
    push(payload.get("did"));
    push(payload.get("account").and_then(|a| a.get("did")));
    for account in payload
        .get("accounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        push(account.get("did"));
    }
    let lists: &[&str] = if all {
        &["entries", "added", "removed", "unknown"]
    } else {
        &["entries", "added"]
    };
    for list in lists {
        for entry in payload
            .get(*list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // `acl/get` entries are objects with a `did`.
            push(entry.get("did").or(Some(entry)));
        }
    }
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sorted(set: HashSet<String>) -> Vec<String> {
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        v
    }

    #[test]
    fn finds_every_hash_a_response_names() {
        let payload = json!({
            "did": "a",
            "account": { "did": "b" },
            "accounts": [{ "did": "c" }, { "did": "d" }],
            "entries": ["e", { "did": "h" }],
            "added": ["f"],
            "removed": ["g"],
            "unknown": ["i"],
            "accessListCount": 3,
        });
        let payload = payload.as_object().unwrap();
        assert_eq!(
            sorted(hashes_in(payload, true)),
            ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
        );
        // Labels are filled only for hashes the task kept.
        assert_eq!(
            sorted(hashes_in(payload, false)),
            ["a", "b", "c", "d", "e", "f", "h"]
        );
    }

    #[test]
    fn a_did_stands_in_for_its_hash_and_a_hash_is_left_alone() {
        let carol = "did:example:carol";
        let hash = "0".repeat(64);
        let mut payload = json!({
            "did": carol,
            "add": [hash, carol],
            "ext": { EXT_NAMESPACE: { "includeDids": true } },
        });
        let prepared = prepare(ServedTask::AccessListUpdate, &mut payload);
        let carol_hash = did_identity::did_hash(carol);
        assert_eq!(payload["did"], carol_hash);
        assert_eq!(payload["add"], json!([hash, carol_hash]));
        assert_eq!(prepared.named[&carol_hash], carol);
        assert!(prepared.include_dids);
    }

    #[test]
    fn other_tasks_are_untouched() {
        let mut payload = json!({ "did": "did:example:carol" });
        let prepared = prepare(ServedTask::QueueList, &mut payload);
        assert_eq!(payload["did"], "did:example:carol");
        assert!(prepared.task.is_none());
    }
}
