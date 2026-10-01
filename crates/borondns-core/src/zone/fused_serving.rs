//! Publication-built exact answers for bounded, leaf authorities. A successful
//! query bypasses both authority suffix search and per-zone RRset search.
//! Any configured descendant conservatively disables its ancestors' shortcuts,
//! even if hidden/expired; the reference resolver decides those cases.
use super::*;
use crate::zone_image::{FusedDirectAnswer, ZoneImageDirectRrset};

const GROUPS: usize = 64;
const MAPS_PER_GROUP: usize = 64;
#[cfg(feature = "experimental-compact-fused-keys")]
const KEY_BYTES: usize = 32;
#[cfg(not(feature = "experimental-compact-fused-keys"))]
const KEY_BYTES: usize = 64;
#[cfg(test)]
type FusedSelection<'a> = (
    PublishedZoneRef<'a>,
    SelectedZoneQuery<'a>,
    ZoneImageDirectRrset<'a>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    // Last byte holds the encoded length. It replaces either zero padding or
    // the mandatory root terminator of a maximum-length key, never label data.
    bytes: [u8; KEY_BYTES],
    digest: u64,
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_u64(self.digest);
    }
}

impl Key {
    fn wire(owner: &[u8], qtype: u16, hash_builder: &RandomState) -> Option<Self> {
        if owner.len() + 2 > KEY_BYTES {
            return None;
        }
        debug_assert_eq!(owner.last(), Some(&0));
        let mut bytes = [0; KEY_BYTES];
        bytes[..2].copy_from_slice(&qtype.to_be_bytes());
        bytes[2..owner.len() + 2].copy_from_slice(owner);
        Some(Self::finish(bytes, owner.len() + 2, hash_builder))
    }
    fn query(
        name: &DomainName,
        qtype: u16,
        lowercase: bool,
        hash_builder: &RandomState,
    ) -> Option<Self> {
        let mut bytes = [0; KEY_BYTES];
        let mut len = 2;
        bytes[..2].copy_from_slice(&qtype.to_be_bytes());
        for label in name.labels() {
            let start = len;
            if start + 1 + label.len() >= KEY_BYTES {
                return None;
            }
            bytes[start] = label.len() as u8;
            bytes[start + 1..start + 1 + label.len()].copy_from_slice(label);
            if !lowercase {
                bytes[start + 1..start + 1 + label.len()].make_ascii_lowercase();
            }
            len += 1 + label.len();
        }
        Some(Self::finish(bytes, len + 1, hash_builder))
    }
    fn finish(mut bytes: [u8; KEY_BYTES], len: usize, hash_builder: &RandomState) -> Self {
        let digest = hash_builder.hash_one(&bytes[..len]);
        bytes[KEY_BYTES - 1] = len as u8;
        Self { bytes, digest }
    }
    fn partition(&self) -> (usize, usize) {
        // Use middle bits for sharding, leaving low bucket bits and high table
        // fingerprint bits unfixed within a shard. Reusing the LOW partition
        // bits for bucket selection would cluster all entries in that shard.
        let hash = (self.digest >> 32) as usize;
        (hash & (GROUPS - 1), (hash >> 6) & (MAPS_PER_GROUP - 1))
    }
}

#[derive(Default)]
struct PrehashedKeyHasher(u64);
impl Hasher for PrehashedKeyHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("only Key's precomputed keyed digest may enter this table")
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "experimental-dense-answers"), derive(Copy))]
struct ExactAnswer {
    // Authority ownership belongs to the directory publication, not an answer.
    // Dense overflow bodies share immutable bytes, never zone ownership. The
    // incarnation identifies which zone may remove/replace this exact key.
    // Presence in this immutable index proves active, visible leaf authority
    // without a dirty overlay. Frozen readers retain the same proof and bytes.
    incarnation: u64,
    answer: FusedDirectAnswer,
}

#[cfg(not(feature = "experimental-direct-buckets"))]
type AnswerMap = HashMap<Key, ExactAnswer, std::hash::BuildHasherDefault<PrehashedKeyHasher>>;
#[cfg(feature = "experimental-direct-buckets")]
mod direct_buckets;
#[cfg(feature = "experimental-direct-buckets")]
use direct_buckets::DirectMap as AnswerMap;
type AnswerGroup = [Arc<AnswerMap>; MAPS_PER_GROUP];
type DescendantMaps = [Arc<HashMap<String, usize>>; ZONE_DIRECTORY_SHARD_COUNT];

#[derive(Debug, Clone)]
pub(super) struct FusedDirectory {
    groups: [Arc<AnswerGroup>; GROUPS],
    hash_builder: RandomState,
    // Zone-content replacement does not change ancestry. Share this complete
    // cold-plane directory until an authority is actually added or removed.
    descendants: Arc<DescendantMaps>,
}
impl Default for FusedDirectory {
    fn default() -> Self {
        Self {
            groups: std::array::from_fn(|_| {
                Arc::new(std::array::from_fn(|_| Arc::new(AnswerMap::default())))
            }),
            hash_builder: RandomState::new(),
            descendants: Arc::new(std::array::from_fn(|_| Arc::new(HashMap::new()))),
        }
    }
}

impl FusedDirectory {
    fn map_mut(&mut self, key: &Key) -> &mut AnswerMap {
        let (group, map) = key.partition();
        Arc::make_mut(&mut Arc::make_mut(&mut self.groups[group])[map])
    }
    fn has_descendants(&self, key: &str) -> bool {
        self.descendants[zone_directory_shard(key.as_bytes())].contains_key(key)
    }
    fn change_descendants(&mut self, key: String, add: bool) {
        let maps = Arc::make_mut(&mut self.descendants);
        let counts = Arc::make_mut(&mut maps[zone_directory_shard(key.as_bytes())]);
        if add {
            *counts.entry(key).or_default() += 1;
        } else {
            let count = counts.get_mut(&key).expect("configured descendant counted");
            *count -= 1;
            if *count == 0 {
                counts.remove(&key);
            }
        }
    }
    fn remove_answers(&mut self, entry: &ZoneStoreEntry) {
        let Some(image) = &entry.image else { return };
        image.visit_fused_answers(|owner, qtype, _, _| {
            let Some(key) = Key::wire(owner, qtype, &self.hash_builder) else {
                return;
            };
            let (group, map) = key.partition();
            if self.groups[group][map]
                .get(&key)
                .is_some_and(|old| old.incarnation == entry.incarnation)
            {
                self.map_mut(&key).remove(&key);
            }
        });
    }
    fn add_answers(&mut self, entry: &Arc<ZoneStoreEntry>) {
        if entry.state != ZoneState::Active
            || entry.hidden
            || entry.overlay_dirty.is_some()
            || self.has_descendants(&entry.origin_key)
        {
            return;
        }
        let Some(image) = &entry.image else { return };
        image.visit_fused_answers(|owner, qtype, body, count| {
            let Some(key) = Key::wire(owner, qtype, &self.hash_builder) else {
                return;
            };
            let Some(answer) = FusedDirectAnswer::new(body, count) else {
                return;
            };
            let value = ExactAnswer {
                incarnation: entry.incarnation,
                answer,
            };
            let old = self.map_mut(&key).insert(key, value);
            debug_assert!(old.is_none_or(|old| old.incarnation == entry.incarnation));
        });
    }
}

impl ZoneDirectory {
    pub(super) fn update_fused(
        &mut self,
        entry: &Arc<ZoneStoreEntry>,
        previous: Option<&Arc<ZoneStoreEntry>>,
    ) {
        if let Some(previous) = previous {
            self.fused.remove_answers(previous);
        } else {
            let mut ancestor = entry.origin.parent();
            while let Some(name) = ancestor {
                let key = name.canonical_key();
                self.fused.change_descendants(key.clone(), true);
                if let Some(parent) = self.get(&key).cloned() {
                    self.fused.remove_answers(&parent);
                }
                ancestor = name.parent();
            }
        }
        self.fused.add_answers(entry);
    }
    pub(super) fn remove_fused(&mut self, entry: &ZoneStoreEntry) {
        self.fused.remove_answers(entry);
        let mut ancestor = entry.origin.parent();
        while let Some(name) = ancestor {
            let key = name.canonical_key();
            self.fused.change_descendants(key.clone(), false);
            if let Some(parent) = self.get(&key).cloned() {
                self.fused.add_answers(&parent);
            }
            ancestor = name.parent();
        }
    }
}

impl BatchZoneSelector<'_> {
    pub(crate) fn select_fused_many<'a>(
        &'a self,
        queries: &[Option<(&'a DomainName, u16, bool)>],
    ) -> SmallVec<[Option<ZoneImageDirectRrset<'a>>; crate::dns::DNS_SERVING_BATCH_SIZE]> {
        assert!(queries.len() <= crate::dns::DNS_SERVING_BATCH_SIZE);
        if !self.directory.small.is_empty() {
            return std::iter::repeat_n(None, queries.len()).collect();
        }
        let keys: SmallVec<[_; crate::dns::DNS_SERVING_BATCH_SIZE]> = queries
            .iter()
            .map(|query| {
                let (name, qtype, lowercase) = (*query)?;
                if qtype == RecordType::Ds as u16 {
                    return None;
                }
                Key::query(name, qtype, lowercase, &self.directory.fused.hash_builder)
            })
            .collect();
        let maps: SmallVec<[_; crate::dns::DNS_SERVING_BATCH_SIZE]> = keys
            .iter()
            .map(|key| {
                let key = key.as_ref()?;
                let (group, map) = key.partition();
                Some((self.directory.fused.groups[group][map].as_ref(), key))
            })
            .collect();
        #[cfg(feature = "experimental-direct-buckets")]
        let first: SmallVec<[_; crate::dns::DNS_SERVING_BATCH_SIZE]> = maps
            .iter()
            .map(|probe| probe.and_then(|(map, key)| map.read_first(key)))
            .collect();
        // Direct buckets read the first candidate's digest for the entire
        // group before consuming full keys/answers. The standard map path
        // cannot separate its internal control-byte and candidate loads.
        let hits: SmallVec<[_; crate::dns::DNS_SERVING_BATCH_SIZE]> = maps
            .iter()
            .enumerate()
            .map(|(_index, probe)| {
                let (map, key) = (*probe)?;
                #[cfg(not(feature = "experimental-direct-buckets"))]
                let hit = map.get(key);
                #[cfg(feature = "experimental-direct-buckets")]
                let hit = map.resolve_first(key, first[_index]?);
                hit
            })
            .collect();
        hits.into_iter()
            .map(|hit| hit.map(|hit| hit.answer.view()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn select_fused<'a>(
        &'a self,
        qname: &'a DomainName,
        qtype: u16,
        lowercase: bool,
    ) -> Option<FusedSelection<'a>> {
        let answer = self.select_fused_many(&[Some((qname, qtype, lowercase))])[0]?;
        let (zone, selected) = self.select(qname, lowercase, false)?;
        Some((zone, selected?, answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "experimental-dense-answers")]
    fn dense_answers_keep_short_bucket_within_160_bytes() {
        assert!(
            std::mem::size_of::<(Key, ExactAnswer)>() <= 160,
            "short-answer buckets must fit within 160 bytes"
        );
        assert!(std::mem::size_of::<FusedDirectAnswer>() <= 80);
        // This storage experiment must not narrow the admitted answer range.
        for len in 0..=128 {
            let bytes: Vec<_> = (0..len).map(|i| i as u8).collect();
            let answer = FusedDirectAnswer::new(&bytes, 8).unwrap();
            assert_eq!(
                answer
                    .view()
                    .template_answer()
                    .unwrap()
                    .wire_body()
                    .unwrap(),
                bytes
            );
        }
        assert!(FusedDirectAnswer::new(&[0; 129], 1).is_none());
    }

    #[test]
    #[cfg(all(
        feature = "experimental-dense-answers",
        feature = "experimental-compact-fused-keys",
        not(feature = "experimental-compact-a-answers")
    ))]
    fn compact_keys_and_dense_answers_keep_bucket_within_two_cache_lines() {
        assert_eq!(std::mem::size_of::<Key>(), 40);
        assert_eq!(std::mem::size_of::<FusedDirectAnswer>(), 80);
        assert_eq!(std::mem::size_of::<ExactAnswer>(), 88);
        assert_eq!(
            std::mem::size_of::<(Key, ExactAnswer)>(),
            128,
            "combined common fused bucket must fit within two cache lines"
        );
        let builder = RandomState::new();
        let corpus_boundary = name("wwwxx.z0ed53d02.s2.gx10.test.");
        assert_eq!(corpus_boundary.to_wire().len() + 2, KEY_BYTES);
        assert!(Key::wire(&corpus_boundary.to_wire(), 1, &builder).is_some());
        assert!(Key::query(&corpus_boundary, 1, true, &builder).is_some());

        let beyond_boundary = name("wwwxxx.z0ed53d02.s2.gx10.test.");
        assert_eq!(beyond_boundary.to_wire().len() + 2, KEY_BYTES + 1);
        assert!(Key::wire(&beyond_boundary.to_wire(), 1, &builder).is_none());
        assert!(Key::query(&beyond_boundary, 1, true, &builder).is_none());
    }

    #[test]
    #[cfg(all(
        feature = "experimental-compact-a-answers",
        feature = "experimental-compact-fused-keys"
    ))]
    fn compact_a_answers_keep_common_entry_within_96_bytes() {
        assert_eq!(std::mem::size_of::<FusedDirectAnswer>(), 48);
        assert_eq!(std::mem::size_of::<ExactAnswer>(), 56);
        assert_eq!(std::mem::size_of::<(Key, ExactAnswer)>(), 96);

        let mut body = Vec::new();
        for octet in 1..=4 {
            body.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            body.extend_from_slice(&300u32.to_be_bytes());
            body.extend_from_slice(&[0, 4, 192, 0, 2, octet]);
        }
        let answer = FusedDirectAnswer::new(&body, 4).unwrap();
        let template = answer.view().template_answer().unwrap();
        assert!(template.wire_body().is_none());
        assert_eq!(template.body_wire_len(), body.len());
        let mut rebuilt = Vec::new();
        template.append_body(|bytes| rebuilt.extend_from_slice(bytes));
        assert_eq!(rebuilt, body);

        let mut mixed_ttl = body.clone();
        mixed_ttl[16 + 9] ^= 1;
        assert!(
            FusedDirectAnswer::new(&mixed_ttl, 4)
                .unwrap()
                .view()
                .template_answer()
                .unwrap()
                .wire_body()
                .is_some()
        );
    }

    #[test]
    fn dense_answers_cross_storage_boundary_without_staling_frozen_readers() {
        let store = populated();
        let query = name("www.z0.test.");
        let publish = |count: u8| {
            store.insert_snapshot(ZoneSnapshot::active(
                name("z0.test."),
                Some(u32::from(count)),
                vec![Rrset::new(
                    query.clone(),
                    1,
                    1,
                    60,
                    (0..count).map(|i| vec![192, 0, 2, i]).collect(),
                )],
            ));
        };
        // Single-record RRsets use the existing records path, not a fused
        // template. Two A records are the smallest template in this fixture.
        for initial in [2, 4, 5, 8] {
            publish(initial);
            store.with_batch_selector(|frozen| {
                let old = answer(&frozen, &query).unwrap();
                assert_eq!(old.len(), usize::from(initial) * 16);
                for count in [5, 4, 8, 2, 6] {
                    publish(count);
                    store.with_batch_selector(|current| {
                        let wire = answer(&current, &query).unwrap();
                        assert_eq!(wire.len(), usize::from(count) * 16);
                        assert_eq!(&wire[wire.len() - 4..], &[192, 0, 2, count - 1]);
                    });
                    assert_eq!(answer(&frozen, &query).unwrap(), old);
                }
            });
        }
    }

    #[test]
    fn fused_serving_key_hash_consumes_only_a_precomputed_digest() {
        #[derive(Default)]
        struct DigestOnly(Option<u64>);
        impl Hasher for DigestOnly {
            fn write(&mut self, _: &[u8]) {
                panic!("name bytes hashed again")
            }
            fn write_u64(&mut self, value: u64) {
                assert!(self.0.replace(value).is_none());
            }
            fn finish(&self) -> u64 {
                self.0.unwrap()
            }
        }
        let key = Key::wire(&name("a.test.").to_wire(), 1, &RandomState::new()).unwrap();
        let mut hasher = DigestOnly::default();
        key.hash(&mut hasher);
        assert!(hasher.0.is_some());
    }

    #[test]
    fn fused_serving_prehashed_collisions_still_require_full_keys() {
        let builder = RandomState::new();
        let a = Key::wire(&name("a.test.").to_wire(), 1, &builder).unwrap();
        let mut b = Key::wire(&name("b.test.").to_wire(), 1, &builder).unwrap();
        let mut absent = Key::wire(&name("absent.test.").to_wire(), 1, &builder).unwrap();
        b.digest = a.digest;
        absent.digest = a.digest;
        let mut map: HashMap<Key, u8, std::hash::BuildHasherDefault<PrehashedKeyHasher>> =
            HashMap::default();
        map.insert(a, 1);
        map.insert(b, 2);
        assert_eq!(map.get(&a), Some(&1));
        assert_eq!(map.get(&b), Some(&2));
        assert_eq!(map.get(&absent), None);
        assert_eq!(map.remove(&b), Some(2));
        assert_eq!(map.get(&a), Some(&1));
        assert!(std::mem::size_of::<Key>() <= 72);
    }

    #[test]
    fn fused_serving_partition_preserves_table_bucket_and_fingerprint_bits() {
        let builder = RandomState::new();
        let mut a = Key::wire(&name("a.test.").to_wire(), 1, &builder).unwrap();
        let mut b = a;
        a.digest = 0x1200_0123_0000_0001;
        b.digest = 0xa200_0123_0000_0002;
        assert_eq!(a.partition(), b.partition());
        let hash_a = std::hash::BuildHasherDefault::<PrehashedKeyHasher>::default().hash_one(a);
        let hash_b = std::hash::BuildHasherDefault::<PrehashedKeyHasher>::default().hash_one(b);
        assert_eq!(hash_a, a.digest);
        assert_eq!(hash_b, b.digest);
        assert_ne!(hash_a as u32, hash_b as u32);
        assert_ne!(hash_a >> 57, hash_b >> 57);
    }

    #[test]
    fn fused_serving_directory_clone_shares_descendant_bookkeeping() {
        let mut original = FusedDirectory::default();
        original.change_descendants("test.".to_owned(), true);
        let mut next = original.clone();
        // An ordinary zone-content publication does not alter ancestry. It
        // must not individually clone all 256 descendant-map references.
        for shard in original.descendants.iter() {
            assert_eq!(Arc::strong_count(shard), 1);
        }
        next.change_descendants("test.".to_owned(), false);
        next.change_descendants("other.".to_owned(), true);
        assert!(original.has_descendants("test."));
        assert!(!original.has_descendants("other."));
        assert!(!next.has_descendants("test."));
        assert!(next.has_descendants("other."));
    }

    #[test]
    #[cfg(not(feature = "experimental-dense-answers"))]
    fn fused_serving_exact_values_have_no_per_answer_ownership() {
        assert!(!std::mem::needs_drop::<ExactAnswer>());
        assert!(std::mem::size_of::<ExactAnswer>() <= 144);
    }

    #[test]
    fn fused_serving_body_storage_and_clone_preserve_bytes() {
        for len in [0, 1, 32, 63, 64, 65, 96, FusedDirectAnswer::MAX_BODY_LEN] {
            let input: Vec<_> = (0..len).map(|i| i as u8).collect();
            let answer = FusedDirectAnswer::new(&input, 6).unwrap();
            #[cfg(not(feature = "experimental-dense-answers"))]
            let cloned = answer;
            #[cfg(feature = "experimental-dense-answers")]
            let cloned = answer.clone();
            let inline = !cfg!(feature = "experimental-dense-answers")
                || len
                    <= if cfg!(feature = "experimental-compact-a-answers") {
                        32
                    } else {
                        64
                    };
            assert!(std::mem::size_of_val(&answer) <= 136);
            for value in [&answer, &cloned] {
                let template = value.view().template_answer().unwrap();
                let body = template.wire_body().unwrap();
                assert_eq!(body, input);
                let start = std::ptr::from_ref(value) as usize;
                let body_start = body.as_ptr() as usize;
                if inline {
                    assert!(body_start >= start);
                    assert!(body_start + len <= start + std::mem::size_of_val(value));
                } else {
                    assert!(
                        body_start < start || body_start >= start + std::mem::size_of_val(value)
                    );
                }
                assert_eq!(
                    template.section_count_header_bytes(false),
                    [0, 6, 0, 0, 0, 0]
                );
                assert_eq!(
                    template.section_count_header_bytes(true),
                    [0, 6, 0, 0, 0, 1]
                );
            }
            assert_eq!(
                answer
                    .view()
                    .template_answer()
                    .unwrap()
                    .wire_body()
                    .unwrap()
                    .as_ptr()
                    == cloned
                        .view()
                        .template_answer()
                        .unwrap()
                        .wire_body()
                        .unwrap()
                        .as_ptr(),
                !inline
            );
            drop(input);
            assert_eq!(
                answer
                    .view()
                    .template_answer()
                    .unwrap()
                    .wire_body()
                    .unwrap(),
                cloned
                    .view()
                    .template_answer()
                    .unwrap()
                    .wire_body()
                    .unwrap()
            );
        }
        assert!(FusedDirectAnswer::new(&[0; 129], 6).is_none());
    }

    #[test]
    #[cfg(feature = "experimental-dense-answers")]
    fn dense_answers_overflow_clone_survives_original_drop() {
        for len in [65, 80, 128] {
            let input: Vec<_> = (0..len).map(|i| i as u8).collect();
            let original = FusedDirectAnswer::new(&input, 8).unwrap();
            let cloned = original.clone();
            drop(original);
            let view = cloned.view();
            assert_eq!(view.template_answer().unwrap().wire_body().unwrap(), input);
            assert_eq!(view.record_count(), 8);
        }
    }

    #[test]
    fn fused_serving_inline_boundary_replacement_keeps_large_answer_and_frozen_view() {
        let store = populated();
        let query = name("www.z0.test.");
        let make = |count: u8| {
            ZoneSnapshot::active(
                name("z0.test."),
                Some(u32::from(count)),
                vec![Rrset::new(
                    query.clone(),
                    1,
                    1,
                    60,
                    (0..count).map(|i| vec![192, 0, 2, i]).collect(),
                )],
            )
        };
        store.insert_snapshot(make(8)); // Exactly128 body bytes.
        store.with_batch_selector(|frozen| {
            let old = answer(&frozen, &query).unwrap();
            assert_eq!(old.len(), 128);
            store.insert_snapshot(make(9)); //144bytes: normal compact path.
            store.with_batch_selector(|s| {
                assert!(s.select_fused(&query, 1, true).is_none());
                let (_, selected) = s.select(&query, true, false).unwrap();
                let selected = selected.unwrap();
                let direct = selected
                    .image
                    .lookup_compact_direct(&query, 1, 1, true)
                    .unwrap();
                assert_eq!(direct.body_wire_len, 144);
                assert_eq!(direct.record_count(), 9);
            });
            assert_eq!(answer(&frozen, &query).unwrap(), old);
            store.insert_snapshot(make(2));
            store.with_batch_selector(|s| assert_eq!(answer(&s, &query).unwrap().len(), 32));
            assert_eq!(answer(&frozen, &query).unwrap(), old);
        });
    }
    fn name(text: &str) -> DomainName {
        DomainName::from_absolute_str(text).unwrap()
    }
    fn snapshot(origin: &str, owner: &str, octet: u8) -> ZoneSnapshot {
        ZoneSnapshot::active(
            name(origin),
            Some(u32::from(octet)),
            vec![Rrset::new(
                name(owner),
                1,
                1,
                60,
                vec![vec![192, 0, 1, octet], vec![192, 0, 2, octet]],
            )],
        )
    }
    fn populated() -> ZoneStore {
        let store = ZoneStore::new();
        for i in 0..8 {
            store.insert_snapshot(snapshot(
                &format!("z{i}.test."),
                &format!("www.z{i}.test."),
                1,
            ));
        }
        store
    }
    fn answer(selector: &BatchZoneSelector<'_>, query: &DomainName) -> Option<Vec<u8>> {
        let (view, selected, direct) = selector.select_fused(query, 1, false)?;
        let (reference, _) = selector.select(query, false, false).unwrap();
        assert_eq!(view.origin_key(), reference.origin_key());
        assert!(std::ptr::eq(
            selected.image,
            reference.active_zone_image_ref()
        ));
        let mut bytes = Vec::new();
        selected
            .image
            .append_eligible_direct_answer_wire(&direct, &mut bytes);
        let expected = selected
            .image
            .lookup_compact_direct(query, 1, 1, false)
            .unwrap();
        let mut reference = Vec::new();
        selected
            .image
            .append_eligible_direct_answer_wire(&expected, &mut reference);
        assert_eq!(bytes, reference);
        Some(bytes)
    }

    #[test]
    fn fused_serving_blocks_shadowing_for_both_insertion_orders_and_frozen_readers() {
        for child_first in [false, true] {
            let store = populated();
            let query = name("WWW.c.e.test.");
            if child_first {
                store.insert_loading(name("c.e.test."));
            }
            store.insert_snapshot(snapshot("e.test.", "www.c.e.test.", 2));
            store.with_batch_selector(|before| {
                assert_eq!(answer(&before, &query).is_some(), !child_first);
                if !child_first {
                    store.insert_loading(name("c.e.test."));
                }
                store.with_batch_selector(|s| assert!(answer(&s, &query).is_none()));
                store.insert_snapshot(snapshot("c.e.test.", "www.c.e.test.", 3));
                store.with_batch_selector(|s| {
                    assert!(answer(&s, &query).unwrap().ends_with(&[192, 0, 2, 3]))
                });
                store.hide_zone(&name("c.e.test."));
                store.with_batch_selector(|s| {
                    assert!(s.select_fused(&query, 1, false).is_none());
                    assert_eq!(
                        s.select(&query, false, false).unwrap().0.origin_key(),
                        "e.test."
                    );
                });
                store.remove_zone(&name("c.e.test."));
                store.with_batch_selector(|s| {
                    assert!(answer(&s, &query).unwrap().ends_with(&[192, 0, 2, 2]))
                });
                assert_eq!(answer(&before, &query).is_some(), !child_first);
            });
        }
    }

    #[test]
    fn fused_serving_replacement_expiry_and_dirty_ixfr_cannot_reuse_old_answers() {
        let store = populated();
        let query = name("www.z0.test.");
        store.with_batch_selector(|old| {
            assert!(answer(&old, &query).unwrap().ends_with(&[192, 0, 2, 1]));
            store.insert_snapshot(snapshot("z0.test.", "www.z0.test.", 2));
            store.with_batch_selector(|s| {
                assert!(answer(&s, &query).unwrap().ends_with(&[192, 0, 2, 2]))
            });
            store.expire_zone(&name("z0.test."));
            store.with_batch_selector(|s| assert!(s.select_fused(&query, 1, true).is_none()));
            assert!(answer(&old, &query).unwrap().ends_with(&[192, 0, 2, 1]));
        });
        let store = ZoneStore::with_publication_policy(ZonePublicationPolicy {
            strategy: ZonePublicationStrategy::Sharded,
            sharded_rrset_threshold: 1,
            ..ZonePublicationPolicy::default()
        });
        let base = snapshot("z0.test.", "www.z0.test.", 1);
        store.insert_snapshot(base.clone());
        for i in 1..8 {
            store.insert_snapshot(snapshot(
                &format!("z{i}.test."),
                &format!("www.z{i}.test."),
                1,
            ));
        }
        store.with_batch_selector(|s| assert!(s.select_fused(&query, 1, true).is_some()));
        let updated = base.with_cow_rrset_replacements(
            2,
            vec![(
                query.canonical_key(),
                1,
                1,
                Some(Rrset::new(
                    query.clone(),
                    1,
                    1,
                    60,
                    vec![vec![192, 0, 2, 8], vec![192, 0, 2, 9]],
                )),
            )],
        );
        store.insert_snapshot(updated);
        store.with_batch_selector(|s| {
            assert!(
                s.select(&query, true, false)
                    .unwrap()
                    .0
                    .has_incremental_overlay()
            );
            assert!(s.select_fused(&query, 1, true).is_none());
        });
    }

    #[test]
    fn fused_serving_keys_preserve_binary_labels_case_type_and_length_boundaries() {
        let builder = RandomState::new();
        for query in [
            name("WWW.Example.TEST."),
            DomainName::from_uncompressed_wire(b"\x03a\0B\x04test\0").unwrap(),
            name("."),
            name(&format!("{}.", "a".repeat(60))),
        ] {
            let mut wire = query.to_wire();
            wire.make_ascii_lowercase();
            assert_eq!(
                Key::wire(&wire, 1, &builder),
                Key::query(&query, 1, false, &builder.clone())
            );
            let a = Key::query(&query, 1, false, &builder);
            let aaaa = Key::query(&query, 28, false, &builder);
            assert_eq!(a.is_some(), aaaa.is_some());
            if a.is_some() {
                assert_ne!(a, aaaa);
            }
        }
        #[cfg(not(feature = "experimental-compact-fused-keys"))]
        assert!(Key::query(&name(&format!("{}.", "a".repeat(60))), 1, true, &builder).is_some());
        #[cfg(feature = "experimental-compact-fused-keys")]
        {
            assert!(
                Key::query(&name(&format!("{}.", "a".repeat(60))), 1, true, &builder).is_none()
            );
            assert!(
                Key::query(&name("wwwxx.z0ed53d02.s2.gx10.test."), 1, true, &builder).is_some()
            );
        }
        assert!(Key::query(&name(&format!("{}.", "a".repeat(61))), 1, true, &builder).is_none());
        let store = populated();
        store.with_batch_selector(|s| {
            assert!(s.select_fused(&name("www.z0.test."), 43, true).is_none());
            assert!(s.select_fused(&name("absent.z0.test."), 1, true).is_none());
        });
    }

    #[test]
    fn fused_serving_large_image_falls_back_and_removes_previous_bounded_index() {
        let store = populated();
        let query = name("www.z0.test.");
        let mut rrsets = vec![Rrset::new(
            query.clone(),
            1,
            1,
            60,
            vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
        )];
        for i in 0..64 {
            rrsets.push(Rrset::new(
                name(&format!("n{i}.z0.test.")),
                1,
                1,
                60,
                vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
            ));
        }
        store.insert_snapshot(ZoneSnapshot::active(name("z0.test."), Some(2), rrsets));
        store.with_batch_selector(|s| {
            assert!(s.select_fused(&query, 1, true).is_none());
            assert!(s.select(&query, true, false).unwrap().1.is_some());
        });
    }

    #[test]
    fn fused_serving_waves_preserve_mixed_hit_miss_slots() {
        let store = populated();
        let a = name("www.z0.test.");
        let b = name("WWW.z7.test.");
        let missing = name("missing.z0.test.");
        let long = name(&format!("{}.z0.test.", "a".repeat(60)));
        store.with_batch_selector(|selector| {
            assert!(selector.select_fused_many(&[]).is_empty());
            let queries = [
                Some((&a, 1, true)),
                None,
                Some((&missing, 1, true)),
                Some((&a, 43, true)),
                Some((&b, 1, false)),
                Some((&long, 1, true)),
                Some((&a, 28, true)),
                Some((&a, 1, true)),
            ];
            let hits = selector.select_fused_many(&queries);
            assert_eq!(
                hits.iter().map(Option::is_some).collect::<Vec<_>>(),
                [true, false, false, false, true, false, false, true]
            );
            for i in [0, 4, 7] {
                let direct = hits[i].unwrap();
                let (zone, selected) = selector
                    .select(queries[i].unwrap().0, false, false)
                    .unwrap();
                let selected = selected.unwrap();
                assert!(std::ptr::eq(selected.qname, queries[i].unwrap().0));
                let mut bytes = Vec::new();
                zone.active_zone_image_ref()
                    .append_eligible_direct_answer_wire(&direct, &mut bytes);
                assert_eq!(bytes, answer(&selector, queries[i].unwrap().0).unwrap());
            }
        });
    }
}
