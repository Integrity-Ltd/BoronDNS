//! Publication-local serving metadata and inline suffix keys. The control
//! entry remains reachable for uncommon/control operations, but selecting an
//! ordinary answer needs neither its metadata nor a separate short-key heap.
use super::*;
use std::borrow::Borrow;

const INLINE_SUFFIX_BYTES: usize = 23;

#[derive(Debug, Clone)]
pub(super) enum ServingOriginKey {
    Inline(u8, [u8; INLINE_SUFFIX_BYTES]),
    Heap(Box<[u8]>),
}

impl ServingOriginKey {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline(len, bytes) => &bytes[..usize::from(*len)],
            Self::Heap(bytes) => bytes,
        }
    }
}

impl From<Vec<u8>> for ServingOriginKey {
    fn from(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE_SUFFIX_BYTES {
            let mut inline = [0; INLINE_SUFFIX_BYTES];
            inline[..bytes.len()].copy_from_slice(&bytes);
            Self::Inline(bytes.len() as u8, inline)
        } else {
            Self::Heap(bytes.into_boxed_slice())
        }
    }
}

impl Borrow<[u8]> for ServingOriginKey {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Hash for ServingOriginKey {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}

impl PartialEq for ServingOriginKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for ServingOriginKey {}

#[derive(Debug, Clone)]
pub(super) struct ServingDirectoryEntry {
    pub(super) control: Arc<ZoneStoreEntry>,
    image: Option<Arc<ZoneImage>>,
    state: ZoneState,
    pub(super) hidden: bool,
    has_overlay: bool,
    #[cfg(feature = "experimental-selected-query")]
    origin_label_count: u16,
}

impl From<Arc<ZoneStoreEntry>> for ServingDirectoryEntry {
    fn from(control: Arc<ZoneStoreEntry>) -> Self {
        Self {
            image: control.image.clone(),
            state: control.state,
            hidden: control.hidden,
            has_overlay: control.overlay_dirty.is_some(),
            #[cfg(feature = "experimental-selected-query")]
            origin_label_count: control.origin_label_count as u16,
            control,
        }
    }
}

impl ServingDirectoryEntry {
    pub(super) fn view(&self) -> PublishedZoneRef<'_> {
        PublishedZoneRef {
            entry: &self.control,
            serving_state: self.state,
            serving_image: self.image.as_deref(),
            serving_has_overlay: self.has_overlay,
            #[cfg(feature = "experimental-selected-query")]
            serving_origin_label_count: usize::from(self.origin_label_count),
        }
    }
}

impl ZoneDirectory {
    pub(super) fn find_query_serving_view(
        &self,
        qname: &DomainName,
        lowercase: bool,
        prefer_parent: bool,
    ) -> Option<PublishedZoneRef<'_>> {
        // Keep the established tiny-directory shortcut. Its entries are hot
        // and a suffix-map probe is unnecessary for the single-zone case.
        if !prefer_parent && !self.small.is_empty() {
            return self
                .find_best_match_ref(qname, lowercase)
                .map(PublishedZoneRef::from_entry);
        }
        let (key, prefixes) = canonical_reverse_label_key_with_prefixes(qname, lowercase);
        if prefer_parent
            && !prefixes.is_empty()
            && let Some(exact) = self.suffix_get_indexed(&key).filter(|entry| !entry.hidden)
        {
            // DS belongs to the closest visible strict parent. If there is
            // none, retain the existing child behavior, including its state.
            for length in prefixes[..prefixes.len() - 1].iter().rev() {
                if let Some(parent) = self
                    .suffix_get_indexed(&key[..*length])
                    .filter(|entry| !entry.hidden)
                {
                    return Some(parent.view());
                }
            }
            return Some(
                self.suffix_get_indexed(&[])
                    .filter(|entry| !entry.hidden)
                    .unwrap_or(exact)
                    .view(),
            );
        }
        for length in prefixes.iter().rev() {
            if let Some(entry) = self
                .suffix_get_indexed(&key[..*length])
                .filter(|entry| !entry.hidden)
            {
                return Some(entry.view());
            }
        }
        self.suffix_get_indexed(&[])
            .filter(|entry| !entry.hidden)
            .map(ServingDirectoryEntry::view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "experimental-selected-query")]
    #[test]
    fn selected_query_proof_is_bound_to_query_image_and_parent_selection() {
        let store = ZoneStore::new();
        for text in [
            ".",
            "test.",
            "example.test.",
            "child.example.test.",
            "other.test.",
        ] {
            let name = DomainName::from_absolute_str(text).unwrap();
            store.insert_snapshot(ZoneSnapshot::active(
                name.clone(),
                Some(1),
                vec![Rrset::new(
                    name,
                    1,
                    1,
                    60,
                    vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
                )],
            ));
        }
        let query = DomainName::from_absolute_str("CHILD.Example.Test.").unwrap();
        store
            .with_selected_query_zone(&query, false, false, |view, selected| {
                let selected = selected.unwrap();
                assert_eq!(selected.relative_labels, 0);
                assert!(std::ptr::eq(selected.qname, &query));
                let image = view.active_zone_image_ref();
                let actual = selected.lookup_compact(image, 1, 1, false).unwrap();
                let reference = image.lookup_compact_direct(&query, 1, 1, false).unwrap();
                let mut a = Vec::new();
                let mut b = Vec::new();
                image.append_eligible_direct_answer_wire(&actual, &mut a);
                image.append_eligible_direct_answer_wire(&reference, &mut b);
                assert_eq!(a, b);
                let other = image.clone();
                assert!(selected.lookup_compact(&other, 1, 1, false).is_none());
            })
            .unwrap();
        store
            .with_selected_query_zone(&query, false, true, |view, selected| {
                assert_eq!(view.origin_key(), "example.test.");
                assert_eq!(selected.unwrap().relative_labels, 1);
            })
            .unwrap();
        store.expire_zone(&DomainName::from_absolute_str("child.example.test.").unwrap());
        store
            .with_selected_query_zone(&query, false, false, |_, selected| {
                assert!(selected.is_none());
            })
            .unwrap();
    }

    #[cfg(feature = "experimental-selected-query")]
    #[test]
    fn selected_query_miss_does_not_repeat_compact_lookup_but_other_image_does() {
        let store = ZoneStore::new();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        store.insert_snapshot(ZoneSnapshot::active(origin, Some(1), Vec::new()));
        let query = DomainName::from_absolute_str("missing.example.test.").unwrap();
        store
            .with_selected_query_zone(&query, true, false, |view, selected| {
                let selected = selected.unwrap();
                let image = view.active_zone_image_ref();
                for (qtype, qclass) in [(1, 1), (28, 1), (255, 1), (1, 255)] {
                    assert!(
                        selected
                            .lookup_compact_or_else(image, qtype, qclass, true, || {
                                panic!("trusted descriptor miss must not repeat compact lookup")
                            })
                            .is_none()
                    );
                }
                let other = image.clone();
                let called = std::cell::Cell::new(false);
                assert!(
                    selected
                        .lookup_compact_or_else(&other, 1, 1, true, || {
                            called.set(true);
                            other.lookup_compact_direct(&query, 1, 1, true)
                        })
                        .is_none()
                );
                assert!(called.get(), "alternate image must use checked fallback");
            })
            .unwrap();
    }

    #[test]
    fn serving_suffix_keys_match_borrowed_hash_for_inline_heap_and_binary_keys() {
        assert!(mem::size_of::<ServingOriginKey>() + mem::size_of::<ServingDirectoryEntry>() <= 64);
        let mut map = HashMap::new();
        for len in [0, 1, 23, 24, 63, 128, 255] {
            let bytes: Vec<_> = (0..len).map(|i| (i * 31) as u8).collect();
            let key = ServingOriginKey::from(bytes.clone());
            assert_eq!(
                matches!(key, ServingOriginKey::Inline(..)),
                len <= INLINE_SUFFIX_BYTES
            );
            map.insert(key, len);
            assert_eq!(map.get(bytes.as_slice()), Some(&len));
            assert_eq!(map.remove(bytes.as_slice()), Some(len));
        }
    }

    #[test]
    fn serving_directory_matches_reference_across_lifecycle_and_parent_selection() {
        let store = ZoneStore::new();
        let names: Vec<_> = [
            ".",
            "test.",
            "example.test.",
            "child.example.test.",
            "a-long-origin-label-for-heap-key.example.test.",
            "other.test.",
        ]
        .iter()
        .map(|s| DomainName::from_absolute_str(s).unwrap())
        .collect();
        let mut queries = names.clone();
        queries.extend(
            [
                "WWW.Child.Example.Test.",
                "www.a-long-origin-label-for-heap-key.example.test.",
                "absent.invalid.",
                "www.other.test.",
            ]
            .iter()
            .map(|s| DomainName::from_absolute_str(s).unwrap()),
        );
        queries.push(DomainName::from_uncompressed_wire(b"\x03a\0b\x07example\x04test\0").unwrap());
        let check = |directory: &ZoneDirectory| {
            for name in &queries {
                for parent in [false, true] {
                    let expected = parent
                        .then(|| directory.find_parent_of_exact_match_ref(name, false))
                        .flatten()
                        .or_else(|| directory.find_best_match_ref(name, false));
                    let actual = directory.find_query_serving_view(name, false, parent);
                    assert_eq!(
                        actual.as_ref().map(PublishedZoneView::origin_key),
                        expected.map(|e| e.origin_key.as_ref())
                    );
                    if let (Some(actual), Some(expected)) = (actual, expected) {
                        assert_eq!(actual.state(), expected.state);
                        assert_eq!(actual.serial(), expected.serial);
                        assert_eq!(
                            actual.has_incremental_overlay(),
                            expected.overlay_dirty.is_some()
                        );
                        if expected.state == ZoneState::Active {
                            assert!(std::ptr::eq(
                                actual.active_zone_image_ref(),
                                expected.image.as_deref().unwrap()
                            ));
                        }
                    }
                }
            }
        };
        check(&store.zones.load());
        for name in &names {
            store.insert_loading(name.clone());
            check(&store.zones.load());
            store.insert_snapshot(ZoneSnapshot::active(name.clone(), Some(1), Vec::new()));
            check(&store.zones.load());
        }
        let frozen = store.zones.load_full();
        for name in names.iter().rev() {
            store.hide_zone(name);
            check(&store.zones.load());
            store.show_zone(name);
            check(&store.zones.load());
            store.expire_zone(name);
            check(&store.zones.load());
            store.insert_snapshot(ZoneSnapshot::active(name.clone(), Some(2), Vec::new()));
            check(&store.zones.load());
            assert!(store.remove_zone(name));
            check(&store.zones.load());
            check(&frozen);
        }
        assert_eq!(
            frozen
                .find_query_serving_view(&names[3], true, false)
                .unwrap()
                .serial(),
            Some(1)
        );
    }
}
