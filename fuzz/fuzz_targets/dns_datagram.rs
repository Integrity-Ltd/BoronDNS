#![no_main]

use borondns_core::{
    dns::{Header, Question, answer_datagram},
    zone::ZoneStore,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::parse(data)
        && header.qdcount > 0
    {
        let _ = Question::parse(data);
    }

    let zones = ZoneStore::new();
    let _ = answer_datagram(data, &zones);
});
