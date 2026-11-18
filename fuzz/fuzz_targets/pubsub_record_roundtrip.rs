//! Target: `affinidi_messaging_mediator_common::store::types::PubSubRecord`
//! Recon tag: T8 (P1) — the Redis pub/sub payload the WebSocket streaming
//! task's subscriber decodes on every live-delivery notification. This is
//! the exact type behind old finding #4 ("WebSocket-streaming
//! `from_str().unwrap()` on malformed Redis pubsub JSON"); production code
//! at `affinidi-messaging-mediator-common/src/store/redis/store.rs` now
//! matches on `serde_json::from_str::<PubSubRecord>(..)` instead of
//! unwrapping (see recon report), so this harness is the regression tripwire
//! for that fix plus a round-trip check on the two `#[serde(default)]`
//! fields (`verbatim` and `stored`) that make this type
//! deliberately backward-compatible with records from an older mediator
//! version sharing the same Redis.
//! Technique: cargo-fuzz + libFuzzer. Tier 1 (no-panic on raw JSON) + Tier 3
//! (encoder-side round-trip).
#![no_main]

use affinidi_messaging_mediator_common::store::types::{PubSubRecord, StoredMessageRef};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fn build_record(u: &mut Unstructured<'_>) -> arbitrary::Result<PubSubRecord> {
    let stored = if bool::arbitrary(u)? {
        Some(StoredMessageRef {
            msg_id: String::arbitrary(u)?,
            from_did_hash: Option::<String>::arbitrary(u)?,
        })
    } else {
        None
    };
    Ok(PubSubRecord {
        did_hash: String::arbitrary(u)?,
        message: String::arbitrary(u)?,
        force_delivery: bool::arbitrary(u)?,
        verbatim: bool::arbitrary(u)?,
        stored,
    })
}

fuzz_target!(|data: &[u8]| {
    if let Some((&tag, rest)) = data.split_first() {
        if tag & 1 == 0 {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = serde_json::from_str::<PubSubRecord>(s);
            }
            return;
        }
        let mut u = Unstructured::new(rest);
        let Ok(record) = build_record(&mut u) else {
            return;
        };
        let first = serde_json::to_string(&record).expect("serialize is infallible for this type");
        let decoded: PubSubRecord =
            serde_json::from_str(&first).expect("own serialization must deserialize");
        let second = serde_json::to_string(&decoded).expect("serialize is infallible");
        assert_eq!(
            first, second,
            "PubSubRecord did not round-trip byte-identically"
        );

        // `verbatim` is `#[serde(default)]` for backward compatibility with
        // records published by an older mediator that never set the field —
        // dropping it from the JSON must decode to `false`, not an error.
        let without_verbatim = {
            let mut v: serde_json::Value = serde_json::from_str(&first).unwrap();
            v.as_object_mut().unwrap().remove("verbatim");
            v.to_string()
        };
        let legacy: PubSubRecord = serde_json::from_str(&without_verbatim)
            .expect("a record missing `verbatim` (pre-field mediator) must still deserialize");
        assert!(
            !legacy.verbatim,
            "a record missing `verbatim` must default to false"
        );
    }
});
