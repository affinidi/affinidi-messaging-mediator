//! `security.did_privacy_mode = "permissive"`: the DID behind each hash.
//!
//! The mediator keys accounts and access-list entries by the SHA-256 of a DID
//! and, in the default `strict` mode, never holds the DID itself. In
//! `permissive` mode it also keeps a `hash → DID` record and hands it back, so
//! an operator (or a console such as a portal) can show which DID a hash is:
//!
//! - [`remember`] records the DID of every account that authenticates;
//! - [`annotate`] records the DIDs a caller offers in a Trust Task's
//!   `ext["com.affinidi.messaging"].dids` (a list of DIDs, hashed here, so a
//!   caller can never pair a hash with the wrong DID) for the hashes the task
//!   touched, and adds `ext["com.affinidi.messaging"].dids`, a `hash → DID`
//!   map, to the response for every hash it names that has a record.
//!
//! Every existing field keeps the hash, and `ext` is the Trust Task spec's
//! extension member, so a client that ignores it sees no change. In `strict`
//! mode none of this runs: nothing is read, written or returned.

use crate::{SharedData, common::config::DidPrivacyMode};
use affinidi_messaging_mediator_common::did_identity;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// The `ext` namespace this mediator reads and writes (SPEC §4.5.1).
pub const EXT_NAMESPACE: &str = "com.affinidi.messaging";

fn permissive(state: &SharedData) -> bool {
    state.config.security.did_privacy_mode == DidPrivacyMode::Permissive
}

/// `did` (with `did_hash`) completed authentication: record it.
pub(crate) async fn remember(state: &SharedData, did: &str, did_hash: &str) {
    if !permissive(state) {
        return;
    }
    let did = did_identity::account_did(did);
    if let Err(e) = state.database.did_map_set(did_hash, Some(&did)).await {
        warn!("couldn't record the DID behind {did_hash}: {e}");
    }
}

/// The DIDs a request offers in `payload.ext["com.affinidi.messaging"].dids`,
/// as `hash → DID`. Taken before the task runs; nothing is stored yet.
pub(crate) fn offered(state: &SharedData, request_payload: &Value) -> HashMap<String, String> {
    if !permissive(state) {
        return HashMap::new();
    }
    request_payload
        .pointer(&format!("/ext/{EXT_NAMESPACE}/dids"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|did| did.starts_with("did:"))
        .map(|did| {
            let did = did_identity::account_did(did);
            (did_identity::did_hash(&did), did.into_owned())
        })
        .collect()
}

/// After a task succeeded: record the `offered` DIDs whose hash its response
/// names, then add `ext["com.affinidi.messaging"].dids` to the response for
/// every hash it names that has a record. Strict mode returns it unchanged.
pub(crate) async fn annotate(
    state: &SharedData,
    offered: HashMap<String, String>,
    mut response: Value,
) -> Value {
    if !permissive(state) {
        return response;
    }
    let Some(payload) = response.get_mut("payload").and_then(Value::as_object_mut) else {
        return response;
    };
    let hashes: Vec<String> = hashes_in(payload).into_iter().collect();
    if hashes.is_empty() {
        return response;
    }

    // Only DIDs whose hash this task touched, so a caller can't fill the
    // store with DIDs that have nothing to do with this mediator.
    for hash in &hashes {
        if let Some(did) = offered.get(hash)
            && let Err(e) = state.database.did_map_set(hash, Some(did)).await
        {
            warn!("couldn't record the DID behind {hash}: {e}");
        }
    }

    let dids = match state.database.did_map_get(&hashes).await {
        Ok(dids) if !dids.is_empty() => dids,
        Ok(_) => return response,
        Err(e) => {
            // The response is still right without the DIDs.
            warn!("couldn't read the DIDs behind a response's hashes: {e}");
            return response;
        }
    };
    let ext = payload
        .entry("ext")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(ext) = ext.as_object_mut() {
        ext.insert(EXT_NAMESPACE.into(), serde_json::json!({ "dids": dids }));
    }
    response
}

/// The DID hashes a response payload names: `did`, `account.did`,
/// `accounts[].did`, and the `entries` / `added` / `removed` lists.
fn hashes_in(payload: &Map<String, Value>) -> HashSet<String> {
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
    for list in ["entries", "added", "removed"] {
        for entry in payload
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            push(Some(entry));
        }
    }
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_every_hash_a_response_names() {
        let payload = json!({
            "did": "a",
            "account": { "did": "b" },
            "accounts": [{ "did": "c" }, { "did": "d" }],
            "entries": ["e"],
            "added": ["f"],
            "removed": ["g"],
            "accessListCount": 3,
        });
        let mut found: Vec<String> = hashes_in(payload.as_object().unwrap())
            .into_iter()
            .collect();
        found.sort();
        assert_eq!(found, ["a", "b", "c", "d", "e", "f", "g"]);
    }
}
