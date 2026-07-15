#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxidedns_server::fuzz_lifecycle_sequence(data);
});
