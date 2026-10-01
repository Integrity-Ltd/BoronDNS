//! A bounded direct-probe front table with an exact overflow map. No unsafe
//! table internals: a first candidate can be read before its full key is used.
//! Holes never end a probe sequence, so removals need no tombstone maintenance.
use super::{ExactAnswer, KEY_BYTES, Key, PrehashedKeyHasher};
use std::{collections::HashMap, hash::BuildHasherDefault};

const PROBES: usize = 4;
type Overflow = HashMap<Key, ExactAnswer, BuildHasherDefault<PrehashedKeyHasher>>;

#[derive(Debug, Clone)]
#[repr(C)]
struct Slot {
    // Keep the first dependent read at the candidate address, rather than
    // behind a separate control-byte array. Empty slots have no value; digest
    // zero is NOT a reserved hash and still needs the full-key/value check.
    digest: u64,
    bytes: [u8; KEY_BYTES],
    value: Option<ExactAnswer>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            digest: 0,
            bytes: [0; KEY_BYTES],
            value: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct FirstProbe<'a> {
    slot: &'a Slot,
    digest: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DirectMap {
    slots: Vec<Slot>,
    overflow: Overflow,
    len: usize,
}

impl DirectMap {
    fn index(&self, key: &Key, probe: usize) -> usize {
        (key.digest as usize).wrapping_add(probe) & (self.slots.len() - 1)
    }

    pub(super) fn read_first(&self, key: &Key) -> Option<FirstProbe<'_>> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = &self.slots[self.index(key, 0)];
        Some(FirstProbe {
            slot,
            digest: slot.digest,
        })
    }

    pub(super) fn resolve_first<'a>(
        &'a self,
        key: &Key,
        first: FirstProbe<'a>,
    ) -> Option<&'a ExactAnswer> {
        if first.digest == key.digest && first.slot.bytes == key.bytes {
            return first.slot.value.as_ref();
        }
        for probe in 1..PROBES {
            let slot = &self.slots[self.index(key, probe)];
            if slot.digest == key.digest && slot.bytes == key.bytes {
                return slot.value.as_ref();
            }
        }
        self.overflow.get(key)
    }

    pub(super) fn get(&self, key: &Key) -> Option<&ExactAnswer> {
        self.resolve_first(key, self.read_first(key)?)
    }

    fn find_slot(&self, key: &Key) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        (0..PROBES).map(|probe| self.index(key, probe)).find(|&i| {
            let slot = &self.slots[i];
            slot.value.is_some() && slot.digest == key.digest && slot.bytes == key.bytes
        })
    }

    pub(super) fn insert(&mut self, key: Key, value: ExactAnswer) -> Option<ExactAnswer> {
        if let Some(i) = self.find_slot(&key) {
            return self.slots[i].value.replace(value);
        }
        if let Some(old) = self.overflow.get_mut(&key) {
            return Some(std::mem::replace(old, value));
        }
        if self.len >= self.slots.len() / 2 {
            self.grow();
        }
        self.place(key, value);
        self.len += 1;
        None
    }

    fn place(&mut self, key: Key, value: ExactAnswer) {
        for probe in 0..PROBES {
            let i = self.index(&key, probe);
            if self.slots[i].value.is_none() {
                self.slots[i] = Slot {
                    digest: key.digest,
                    bytes: key.bytes,
                    value: Some(value),
                };
                return;
            }
        }
        let previous = self.overflow.insert(key, value);
        debug_assert!(previous.is_none());
    }

    fn grow(&mut self) {
        let capacity = self
            .slots
            .len()
            .checked_mul(2)
            .expect("addressable table capacity")
            .max(8);
        let old = std::mem::replace(&mut self.slots, vec![Slot::default(); capacity]);
        for slot in old {
            if let Some(value) = slot.value {
                self.place(
                    Key {
                        digest: slot.digest,
                        bytes: slot.bytes,
                    },
                    value,
                );
            }
        }
        for (key, value) in std::mem::take(&mut self.overflow) {
            self.place(key, value);
        }
    }

    pub(super) fn remove(&mut self, key: &Key) -> Option<ExactAnswer> {
        let removed = if let Some(i) = self.find_slot(key) {
            std::mem::take(&mut self.slots[i]).value
        } else {
            self.overflow.remove(key)
        };
        if removed.is_some() {
            self.len -= 1;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_image::FusedDirectAnswer;

    fn key(id: u64, digest: u64) -> Key {
        let mut bytes = [0; KEY_BYTES];
        bytes[..8].copy_from_slice(&id.to_le_bytes());
        bytes[KEY_BYTES - 1] = 10; // Valid keys never have an all-zero byte array.
        Key { bytes, digest }
    }
    fn value(id: u64) -> ExactAnswer {
        ExactAnswer {
            incarnation: id,
            answer: FusedDirectAnswer::new(&[42; 80], 5).unwrap(),
        }
    }

    #[test]
    fn first_probe_is_independent_of_full_key_and_collision_resolution() {
        let mut map = DirectMap::default();
        assert!(map.read_first(&key(1, 0)).is_none());
        map.insert(key(1, 0), value(1));
        map.insert(key(2, 0), value(2));
        let probe = map.read_first(&key(2, 0)).unwrap();
        assert_eq!(probe.slot.bytes, key(1, 0).bytes);
        assert_eq!(map.resolve_first(&key(2, 0), probe).unwrap().incarnation, 2);
        assert!(map.get(&key(3, 0)).is_none());
    }

    #[test]
    fn collisions_spill_and_removal_holes_preserve_all_keys() {
        let mut map = DirectMap::default();
        for id in 0..40 {
            assert!(map.insert(key(id, 0), value(id)).is_none());
        }
        assert_eq!(map.overflow.len(), 40 - PROBES);
        let frozen = map.clone();
        for id in [0, 2, 7, 39] {
            assert_eq!(map.remove(&key(id, 0)).unwrap().incarnation, id);
        }
        for id in 0..40 {
            assert_eq!(
                map.get(&key(id, 0)).map(|v| v.incarnation),
                (!matches!(id, 0 | 2 | 7 | 39)).then_some(id)
            );
            assert_eq!(frozen.get(&key(id, 0)).unwrap().incarnation, id);
        }
        assert_eq!(map.insert(key(8, 0), value(99)).unwrap().incarnation, 8);
        assert_eq!(map.get(&key(8, 0)).unwrap().incarnation, 99);
        assert_eq!(frozen.get(&key(8, 0)).unwrap().incarnation, 8);
    }

    #[test]
    fn grow_replace_remove_matches_reference_and_pinned_clones() {
        let mut map = DirectMap::default();
        let mut reference = HashMap::new();
        let mut state = 0x1234_5678_90ab_cdef_u64;
        for step in 0..10000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let id = (state >> 32) % 500;
            let k = key(id, id.wrapping_mul(0x9e37_79b9));
            if state & 3 == 0 {
                assert_eq!(map.remove(&k).map(|v| v.incarnation), reference.remove(&k));
            } else {
                assert_eq!(
                    map.insert(k, value(step)).map(|v| v.incarnation),
                    reference.insert(k, step)
                );
            }
            assert_eq!(map.len, reference.len());
            if step % 100 == 0 {
                let frozen = map.clone();
                for id in 0..500 {
                    let k = key(id, id.wrapping_mul(0x9e37_79b9));
                    assert_eq!(
                        frozen.get(&k).map(|v| v.incarnation),
                        reference.get(&k).copied()
                    );
                }
            }
        }
    }
}
