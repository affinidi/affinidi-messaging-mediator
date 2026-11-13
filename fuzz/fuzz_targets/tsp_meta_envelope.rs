//! The TSP meta-envelope parser: the first thing the mediator runs on a TSP
//! frame from the network (`messages::inbound`, the monitor's receiver lookup).
//! It must reject anything malformed with an error, never panic or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = affinidi_tsp::is_tsp(data);
    let _ = affinidi_tsp::MetaEnvelope::parse(data);
});
