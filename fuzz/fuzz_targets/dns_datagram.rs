#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidedns_core::{
    dns::{answer_datagram, Header, Question},
    zone::ZoneStore,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::parse(data) {
        if header.qdcount > 0 {
            let _ = Question::parse(data);
        }
    }

    let zones = ZoneStore::new();
    let _ = answer_datagram(data, &zones);
});
