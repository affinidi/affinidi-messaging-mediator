//! DIDComm signed-envelope (JWS) parsing, ahead of any signature check: the
//! structure, base64url segments and protected headers come from the sender.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = affinidi_messaging_didcomm::jws::verify::parse_jws(s);
    }
});
