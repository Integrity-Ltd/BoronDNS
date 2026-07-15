#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    borondns_server::fuzz_lifecycle_sequence(data);
});
