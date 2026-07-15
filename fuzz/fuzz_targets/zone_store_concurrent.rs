#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidedns_core::{
    dns::DomainName,
    zone::{ZoneSnapshot, ZoneState, ZoneStore},
};

const ZONE_COUNT: usize = 16;
const WORKER_COUNT: usize = 4;
const MAX_OPERATIONS: usize = 512;

fuzz_target!(|data: &[u8]| {
    let store = ZoneStore::new();
    let zones = (0..ZONE_COUNT)
        .map(|index| {
            DomainName::from_absolute_str(&format!("zone{index}.concurrent-state-fuzz."))
                .expect("static fuzz zone is valid")
        })
        .collect::<Vec<_>>();
    let operations = data
        .chunks(4)
        .take(MAX_OPERATIONS)
        .map(|operation| {
            let mut copied = [0u8; 4];
            copied[..operation.len()].copy_from_slice(operation);
            copied
        })
        .collect::<Vec<_>>();

    std::thread::scope(|scope| {
        for worker in 0..WORKER_COUNT {
            let store = store.clone();
            let zones = &zones;
            let operations = &operations;
            scope.spawn(move || {
                for operation in operations
                    .iter()
                    .filter(|operation| (operation[0] as usize >> 6) == worker)
                {
                    let opcode = operation[0] & 0x0f;
                    let origin = &zones[operation[1] as usize % zones.len()];
                    let serial = u32::from_be_bytes([
                        operation[2],
                        operation[3],
                        operation[0],
                        operation[1],
                    ]);
                    match opcode % 8 {
                        0 => store.insert_loading(origin.clone()),
                        1 => store.insert_loading_hidden(origin.clone()),
                        2 => store.insert_snapshot(ZoneSnapshot::active(
                            origin.clone(),
                            Some(serial),
                            Vec::new(),
                        )),
                        3 => {
                            store.hide_zone(origin);
                        }
                        4 => {
                            store.show_zone(origin);
                        }
                        5 => {
                            store.expire_zone(origin);
                        }
                        6 => {
                            store.remove_zone(origin);
                        }
                        _ => {
                            let second = &zones[(operation[1] as usize + 1) % zones.len()];
                            let remove_first = &zones[(operation[1] as usize + 2) % zones.len()];
                            let remove_second = &zones[(operation[1] as usize + 3) % zones.len()];
                            store.apply_atomic_directory_update(
                                &[origin.clone(), second.clone()],
                                &[remove_first.clone(), remove_second.clone()],
                                &[],
                                &[],
                            );
                        }
                    }
                    if operation[3] & 0x1f == 0 {
                        std::thread::yield_now();
                    }
                }
            });
        }
    });

    let all = store.zone_metadata();
    let published = store.published_zone_metadata();
    let active = published
        .iter()
        .filter(|metadata| metadata.state == ZoneState::Active)
        .count();
    assert_eq!(store.active_count(), active);
    assert_eq!(store.has_active_zone(), active > 0);
    assert!(published.len() <= all.len());
    for metadata in all {
        let exact = store
            .exact_zone_control_metadata(&metadata.origin)
            .expect("enumerated zone remains present after workers join");
        assert_eq!(exact.origin_key, metadata.origin_key);
        assert_eq!(exact.state, metadata.state);
        assert_eq!(exact.serial, metadata.serial);
        let hidden = store.is_hidden(&metadata.origin);
        assert_eq!(
            store.find_published_zone(&metadata.origin).is_some(),
            !hidden
        );
    }
});
