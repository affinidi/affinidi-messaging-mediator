//! The inbound protocol classifier (DIDComm / TSP / other) that decides which
//! parser a stored or received body is handed to.
#![no_main]

use affinidi_messaging_mediator_common::types::messages::MessageProtocol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = MessageProtocol::detect(s);
    }
});
