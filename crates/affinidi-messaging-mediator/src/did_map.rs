//! `security.did_privacy_mode = "permissive"`: the DID behind each hash.
//!
//! The mediator keys accounts and access-list entries by the SHA-256 of a DID
//! and, in the default `strict` mode, never holds the DID itself. In
//! `permissive` mode it also keeps a `hash → DID` record and hands it back, so
//! an operator (or a console such as a portal) can show which DID a hash is:
//!
//! - [`remember`] records the DID of every account that authenticates;
//! - [`prepare`] lets a Trust Task name an account or entry by its hash, its
//!   DID (hashed here) or both (`ext["com.affinidi.messaging"].dids`, a
//!   `hash → DID` map, checked here: a mismatch refuses the request);
//! - [`annotate`] records those DIDs for the hashes the task touched, and adds
//!   `ext["com.affinidi.messaging"].dids`, a `hash → DID` map, to the response
//!   for every hash it names that has a record.
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

/// The request fields that name an account or access-list entry by hash.
const REQUEST_HASH_FIELDS: [&str; 5] = ["did", "add", "remove", "entries", "dids"];

/// Before the task runs, in permissive mode, a caller may name each account or
/// entry by its hash, its DID, or both:
///
/// - **DID only**: a `did:` value in a hash field (`did`, `add`, `remove`,
///   `entries`, `dids`) is replaced by its hash, so the task runs on hashes
///   as it always has;
/// - **both**: the field holds the hash and
///   `ext["com.affinidi.messaging"].dids` maps it to its DID. The mediator
///   hashes the DID itself and refuses the whole request on a mismatch;
/// - **hash only**: unchanged.
///
/// Returns the `hash → DID` pairs offered. Nothing is stored yet. Strict mode
/// leaves the payload untouched.
pub(crate) fn prepare(
    state: &SharedData,
    request_payload: &mut Value,
) -> Result<HashMap<String, String>, String> {
    let mut offered = HashMap::new();
    if !permissive(state) {
        return Ok(offered);
    }
    let pair = |did: &str| {
        let did = did_identity::account_did(did);
        (did_identity::did_hash(&did), did.into_owned())
    };

    // Both: every DID the caller pairs with a hash must hash to it.
    if let Some(dids) = request_payload
        .pointer(&format!("/ext/{EXT_NAMESPACE}/dids"))
        .and_then(Value::as_object)
    {
        for (hash, did) in dids {
            let did = did
                .as_str()
                .filter(|d| d.starts_with("did:"))
                .ok_or_else(|| format!("ext dids: the value for {hash} is not a DID"))?;
            let (computed, did) = pair(did);
            if computed != *hash {
                return Err(format!("ext dids: {did} hashes to {computed}, not {hash}"));
            }
            offered.insert(computed, did);
        }
    }

    // DID only: hash it in place.
    let Some(payload) = request_payload.as_object_mut() else {
        return Ok(offered);
    };
    let mut hash_in_place = |v: &mut Value| {
        if let Some(did) = v.as_str().filter(|d| d.starts_with("did:")) {
            let (hash, did) = pair(did);
            *v = Value::String(hash.clone());
            offered.insert(hash, did);
        }
    };
    for field in REQUEST_HASH_FIELDS {
        match payload.get_mut(field) {
            Some(Value::Array(items)) => items.iter_mut().for_each(&mut hash_in_place),
            Some(v) => hash_in_place(v),
            None => {}
        }
    }
    Ok(offered)
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
/// `accounts[].did`, and the `entries` (or `entries[].did`) / `added` /
/// `removed` / `unknown` lists.
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
    for list in ["entries", "added", "removed", "unknown"] {
        for entry in payload
            .get(list)
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
        let mut found: Vec<String> = hashes_in(payload.as_object().unwrap())
            .into_iter()
            .collect();
        found.sort();
        assert_eq!(found, ["a", "b", "c", "d", "e", "f", "g", "h", "i"]);
    }
}
