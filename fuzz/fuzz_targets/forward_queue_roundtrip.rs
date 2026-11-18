//! Target: `affinidi_messaging_mediator_common::store::types::ForwardQueueEntry`
//! Recon tag: T7 (P2) — the wire type persisted to the Redis `FORWARD_Q`
//! stream (and the Fjall/memory equivalents) and read back by the forwarding
//! processor. Directly descends from old finding #5 ("DB list
//! `from_redis_value().unwrap()` on malformed Redis data") — this harness
//! checks the *type* at the center of that finding for round-trip fidelity
//! under boundary-value fields (huge `u128`/`u64`/`u32` counters, empty and
//! maximal strings), independent of which backend stores it.
//! Technique: cargo-fuzz + libFuzzer. Two oracles:
//!   - Tier 1: deserializing arbitrary JSON bytes into the type must not panic.
//!   - Tier 3 (encoder-side differential): a struct built from fuzz-controlled
//!     field values must survive serialize -> deserialize -> serialize with a
//!     byte-identical second serialization (Morales 2025 round-trip lesson).
#![no_main]

use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fn build_entry(u: &mut Unstructured<'_>) -> arbitrary::Result<ForwardQueueEntry> {
    Ok(ForwardQueueEntry {
        stream_id: String::arbitrary(u)?,
        message: String::arbitrary(u)?,
        to_did_hash: String::arbitrary(u)?,
        from_did_hash: String::arbitrary(u)?,
        from_did: String::arbitrary(u)?,
        to_did: String::arbitrary(u)?,
        endpoint_url: String::arbitrary(u)?,
        received_at_ms: u128::arbitrary(u)?,
        delay_milli: i64::arbitrary(u)?,
        expires_at: u64::arbitrary(u)?,
        retry_count: u32::arbitrary(u)?,
        hop_count: u32::arbitrary(u)?,
        not_before_ms: u128::arbitrary(u)?,
    })
}

fuzz_target!(|data: &[u8]| {
    // Half the corpus budget probes raw-JSON parsing (Tier 1); the other half
    // probes round-trip fidelity on structurally valid instances (Tier 3).
    if let Some((&tag, rest)) = data.split_first() {
        if tag & 1 == 0 {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = serde_json::from_str::<ForwardQueueEntry>(s);
            }
            return;
        }
        let mut u = Unstructured::new(rest);
        let Ok(entry) = build_entry(&mut u) else {
            return;
        };
        let first = serde_json::to_string(&entry).expect("serialize is infallible for this type");
        let decoded: ForwardQueueEntry =
            serde_json::from_str(&first).expect("own serialization must deserialize");
        let second = serde_json::to_string(&decoded).expect("serialize is infallible");
        assert_eq!(
            first, second,
            "ForwardQueueEntry did not round-trip byte-identically"
        );
        // NOTE: the `#[serde(default)] not_before_ms` backward-compat contract
        // is *not* re-checked here by dropping the key from a re-parsed
        // `serde_json::Value` — that untyped round-trip is lossy for this
        // type's `u128` fields (`received_at_ms`, `not_before_ms`) and would
        // test the harness, not the mediator. The typed round-trip above
        // already exercises `not_before_ms`; the serde-default contract is
        // covered losslessly by `pubsub_record_roundtrip` (whose type has no
        // u128 field).
    }
});
