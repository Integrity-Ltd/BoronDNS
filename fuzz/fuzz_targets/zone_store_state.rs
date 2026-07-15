#![no_main]

use borondns_core::{
    dns::DomainName,
    zone::{ZoneSnapshot, ZoneState, ZoneStore},
};
use libfuzzer_sys::fuzz_target;

const ZONE_COUNT: usize = 8;
const MAX_OPERATIONS: usize = 512;

#[derive(Clone, Copy, Default)]
struct ModelZone {
    present: bool,
    hidden: bool,
    state: Option<ZoneState>,
    serial: u32,
}

fuzz_target!(|data: &[u8]| {
    let store = ZoneStore::new();
    let zones = (0..ZONE_COUNT)
        .map(|index| {
            DomainName::from_absolute_str(&format!("zone{index}.state-fuzz{index}."))
                .expect("static fuzz zone is valid")
        })
        .collect::<Vec<_>>();
    let mut model = [ModelZone::default(); ZONE_COUNT];

    for operation in data.chunks(3).take(MAX_OPERATIONS) {
        let opcode = operation.first().copied().unwrap_or(0) % 8;
        let index = operation.get(1).copied().unwrap_or(0) as usize % ZONE_COUNT;
        let serial_delta = u32::from(operation.get(2).copied().unwrap_or(0));
        let origin = &zones[index];
        let expected = &mut model[index];

        match opcode {
            0 => {
                store.insert_loading(origin.clone());
                expected.present = true;
                expected.state = Some(ZoneState::Loading);
            }
            1 => {
                store.insert_loading_hidden(origin.clone());
                expected.present = true;
                expected.hidden = true;
                expected.state = Some(ZoneState::Loading);
            }
            2 => {
                expected.serial = expected.serial.wrapping_add(serial_delta).wrapping_add(1);
                store.insert_snapshot(ZoneSnapshot::active(
                    origin.clone(),
                    Some(expected.serial),
                    Vec::new(),
                ));
                expected.present = true;
                expected.state = Some(ZoneState::Active);
            }
            3 => {
                store.hide_zone(origin);
                if expected.present {
                    expected.hidden = true;
                }
            }
            4 => {
                store.show_zone(origin);
                if expected.present {
                    expected.hidden = false;
                }
            }
            5 => {
                let changed = store.expire_zone(origin);
                let expected_changed =
                    expected.present && expected.state != Some(ZoneState::Expired);
                assert_eq!(changed, expected_changed);
                if expected_changed {
                    expected.state = Some(ZoneState::Expired);
                }
            }
            6 => {
                assert_eq!(store.remove_zone(origin), expected.present);
                *expected = ModelZone::default();
            }
            _ => {
                expected.serial = expected.serial.wrapping_add(serial_delta).wrapping_add(1);
                store.insert_snapshot(ZoneSnapshot::active(
                    origin.clone(),
                    Some(expected.serial),
                    Vec::new(),
                ));
                expected.present = true;
                expected.state = Some(ZoneState::Active);
                if operation.get(2).copied().unwrap_or(0) & 0x80 != 0 {
                    store.hide_zone(origin);
                    expected.hidden = true;
                }
            }
        }

        assert_store_matches_model(&store, &zones, &model);
    }
});

fn assert_store_matches_model(store: &ZoneStore, zones: &[DomainName], model: &[ModelZone]) {
    let expected_present = model.iter().filter(|zone| zone.present).count();
    let expected_published = model
        .iter()
        .filter(|zone| zone.present && !zone.hidden)
        .count();
    let expected_active = model
        .iter()
        .filter(|zone| zone.present && !zone.hidden && zone.state == Some(ZoneState::Active))
        .count();

    assert_eq!(store.zone_metadata().len(), expected_present);
    assert_eq!(store.published_zone_metadata().len(), expected_published);
    assert_eq!(store.active_count(), expected_active);
    assert_eq!(store.has_active_zone(), expected_active > 0);

    for (origin, expected) in zones.iter().zip(model) {
        assert_eq!(
            store.contains_exact_zone_for_control(origin),
            expected.present
        );
        assert_eq!(store.is_hidden(origin), expected.present && expected.hidden);
        let metadata = store.exact_zone_control_metadata(origin);
        assert_eq!(metadata.is_some(), expected.present);
        if let Some(metadata) = metadata {
            assert_eq!(Some(metadata.state), expected.state);
        }
        assert_eq!(
            store.find_published_zone(origin).is_some(),
            expected.present && !expected.hidden
        );
    }
}
