//! Experimental co-allocation of direct descriptors and their answer bodies.
use super::*;

#[derive(Debug, Default)]
pub(crate) struct PackedDirectIndex {
    storage: Box<[u8]>,
    slots: usize,
    start: usize,
}

impl PackedDirectIndex {
    pub(super) fn new(entries: &[DirectAnswerEntry], wire: &[u8]) -> Option<Self> {
        if entries.is_empty() {
            return Some(Self::default());
        }
        let table_bytes = entries.len().checked_mul(64)?;
        let mut body_bytes = 0_usize;
        for entry in entries.iter().filter(|entry| entry.key_len != 0) {
            let begin = usize::try_from(entry.wire_offset).ok()?;
            wire.get(begin..begin.checked_add(entry.body_len as usize)?)?;
            body_bytes = body_bytes.checked_add(entry.body_len as usize)?;
        }
        let size = table_bytes.checked_add(body_bytes)?.checked_add(63)?;
        let mut storage = Vec::new();
        storage.try_reserve_exact(size).ok()?;
        storage.resize(size, 0);
        let storage = storage.into_boxed_slice();
        // Only compute an offset from the address; all access remains through
        // checked slices. No cast to a typed pointer and no unsafe code.
        let start = (64 - (storage.as_ptr() as usize & 63)) & 63;
        let mut packed = Self {
            storage,
            slots: entries.len(),
            start,
        };
        let data = packed.data_mut();
        let mut cursor = table_bytes;
        for (i, source) in entries.iter().enumerate() {
            let mut entry = *source;
            if entry.key_len != 0 {
                let old = usize::try_from(entry.wire_offset).ok()?;
                let end = cursor + entry.body_len as usize;
                data[cursor..end].copy_from_slice(&wire[old..old + entry.body_len as usize]);
                entry.wire_offset = cursor as u64;
                cursor = end;
            }
            let slot = &mut data[i * 64..(i + 1) * 64];
            slot[..8].copy_from_slice(&entry.wire_offset.to_le_bytes());
            slot[8..32].copy_from_slice(&entry.key);
            slot[32..36].copy_from_slice(&entry.body_len.to_le_bytes());
            slot[36..40].copy_from_slice(&entry.record_count.to_le_bytes());
            slot[40..42].copy_from_slice(&entry.rr_type.to_le_bytes());
            slot[42] = entry.key_len;
        }
        Some(packed)
    }

    fn data_mut(&mut self) -> &mut [u8] {
        let len = self.storage.len().saturating_sub(63);
        &mut self.storage[self.start..self.start + len]
    }

    pub(super) fn wire(&self) -> &[u8] {
        let len = self.storage.len().saturating_sub(63);
        &self.storage[self.start..self.start + len]
    }

    pub(super) fn table(&self) -> &[[u8; 64]] {
        self.wire()[..self.slots * 64].as_chunks::<64>().0
    }

    pub(super) fn len(&self) -> usize {
        self.slots
    }
    pub(super) fn is_empty(&self) -> bool {
        self.slots == 0
    }
    pub(super) fn allocated_bytes(&self) -> usize {
        self.storage.len()
    }
}

impl Clone for PackedDirectIndex {
    fn clone(&self) -> Self {
        if self.is_empty() {
            return Self::default();
        }
        let storage = vec![0; self.storage.len()].into_boxed_slice();
        let start = (64 - (storage.as_ptr() as usize & 63)) & 63;
        let mut result = Self {
            storage,
            slots: self.slots,
            start,
        };
        result.data_mut().copy_from_slice(self.wire());
        result
    }
}

impl PartialEq for PackedDirectIndex {
    fn eq(&self, other: &Self) -> bool {
        self.slots == other.slots && self.wire() == other.wire()
    }
}
impl Eq for PackedDirectIndex {}

pub(super) fn decode(slot: &[u8; 64]) -> DirectAnswerEntry {
    DirectAnswerEntry {
        wire_offset: u64::from_le_bytes(slot[..8].try_into().unwrap()),
        key: slot[8..32].try_into().unwrap(),
        body_len: u32::from_le_bytes(slot[32..36].try_into().unwrap()),
        record_count: u32::from_le_bytes(slot[36..40].try_into().unwrap()),
        rr_type: u16::from_le_bytes(slot[40..42].try_into().unwrap()),
        key_len: slot[42],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_entries_and_bodies_share_one_allocation() {
        let wire: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let entries = vec![
            DirectAnswerEntry {
                wire_offset: 17,
                body_len: 129,
                record_count: 4,
                rr_type: 1,
                key_len: 1,
                key: [0; KEY_BYTES],
            };
            8
        ];
        let packed = PackedDirectIndex::new(&entries, &wire).unwrap();
        let begin = packed.storage.as_ptr() as usize;
        let end = begin + packed.storage.len();
        let table = packed.table().as_ptr() as usize;
        assert!(
            table >= begin && table < end,
            "index and wire must share allocation"
        );
        assert_eq!(table % 64, 0);
        for slot in packed.table() {
            let entry = decode(slot);
            let start = entry.wire_offset as usize;
            assert_eq!(
                &packed.wire()[start..start + entry.body_len as usize],
                &wire[17..146]
            );
        }
        let cloned = packed.clone();
        assert_eq!(cloned, packed);
        assert_eq!(cloned.table().as_ptr() as usize % 64, 0);
        assert_ne!(cloned.storage.as_ptr(), packed.storage.as_ptr());
    }

    #[test]
    fn packed_index_rejects_bad_offsets_and_preserves_empty_slots() {
        let mut entries = [DirectAnswerEntry::default(); 8];
        assert!(PackedDirectIndex::new(&[], &[]).unwrap().is_empty());
        entries[3].key_len = 1;
        entries[3].wire_offset = u64::MAX;
        entries[3].body_len = 2;
        assert!(PackedDirectIndex::new(&entries, &[]).is_none());
        entries[3].wire_offset = 2;
        assert!(PackedDirectIndex::new(&entries, &[1, 2, 3]).is_none());
        entries[3].wire_offset = 1;
        let index = PackedDirectIndex::new(&entries, &[1, 2, 3]).unwrap();
        for i in [0, 1, 2, 4, 5, 6, 7] {
            assert_eq!(decode(&index.table()[i]), DirectAnswerEntry::default());
        }
        let offset = decode(&index.table()[3]).wire_offset as usize;
        assert_eq!(&index.wire()[offset..offset + 2], &[2, 3]);
    }
}
