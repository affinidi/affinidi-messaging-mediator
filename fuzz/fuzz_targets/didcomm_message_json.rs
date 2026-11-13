//! DIDComm plaintext message parsing (`Message::from_json`), which every
//! unpacked envelope goes through before the mediator routes it.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = affinidi_messaging_didcomm::Message::from_json(data);
});
