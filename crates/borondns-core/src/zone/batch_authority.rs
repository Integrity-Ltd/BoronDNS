//! Bounded, publication-local authority probes in independent waves. No new
//! per-zone index or cache: the established suffix maps and authority rules
//! remain authoritative. The scalar path handles tiny directories and DS.
use super::*;
use crate::dns::DNS_SERVING_BATCH_SIZE;

type Query<'a> = Option<(&'a DomainName, bool, bool)>;
type Selection<'a> = Option<(PublishedZoneRef<'a>, Option<SelectedZoneQuery<'a>>)>;

struct Pending {
    key: SmallVec<[u8; 128]>,
    lengths: SmallVec<[usize; 8]>,
    remaining: usize,
}

impl Pending {
    fn new(name: &DomainName, lowercase: bool) -> Self {
        let (key, lengths) = canonical_reverse_label_key_with_prefixes(name, lowercase);
        let remaining = lengths.len() + 1; // Includes the root key.
        Self {
            key,
            lengths,
            remaining,
        }
    }

    fn next<'a>(&'a mut self, directory: &ZoneDirectory) -> Option<&'a [u8]> {
        while self.remaining != 0 {
            self.remaining -= 1;
            let len = if self.remaining == 0 {
                0
            } else {
                self.lengths[self.remaining - 1]
            };
            if directory
                .suffix_key_lengths
                .get(len / 64)
                .is_some_and(|bits| bits & (1 << (len % 64)) == 0)
            {
                continue;
            }
            return Some(&self.key[..len]);
        }
        None
    }
}

impl BatchZoneSelector<'_> {
    pub(crate) fn select_many<'a>(
        &'a self,
        queries: &[Query<'a>],
    ) -> SmallVec<[Selection<'a>; DNS_SERVING_BATCH_SIZE]> {
        assert!(queries.len() <= DNS_SERVING_BATCH_SIZE);
        if !self.directory.small.is_empty() {
            return queries
                .iter()
                .map(|q| q.and_then(|(name, lower, parent)| self.select(name, lower, parent)))
                .collect();
        }
        let mut results = SmallVec::<[Selection<'a>; DNS_SERVING_BATCH_SIZE]>::new();
        let mut pending = SmallVec::<[Option<Pending>; DNS_SERVING_BATCH_SIZE]>::new();
        // Prepare all names before touching suffix-table buckets. DS retains
        // exact-child/strict-parent selection, including hidden-child fallback.
        for query in queries {
            let mut selected = None;
            pending.push(query.and_then(|(name, lowercase, parent)| {
                if parent {
                    selected = self.select(name, lowercase, true);
                    None
                } else {
                    Some(Pending::new(name, lowercase))
                }
            }));
            results.push(selected);
        }
        loop {
            // Resolve shard headers for the whole wave before bucket probes.
            let probes: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = pending
                .iter_mut()
                .map(|p| {
                    let key = p.as_mut()?.next(self.directory)?;
                    Some((
                        self.directory.suffix_index[main_directory_shard(key)].as_ref(),
                        key,
                    ))
                })
                .collect();
            if probes.iter().all(Option::is_none) {
                break;
            }
            let hits: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> = probes
                .iter()
                .map(|p| {
                    let (table, key) = (*p)?;
                    #[cfg(test)]
                    tests::SUFFIX_HASH_PROBES.with(|probes| probes.set(probes.get() + 1));
                    table.get(key)
                })
                .collect();
            drop(probes);
            // Consume all hit metadata after independent table probes have
            // completed. Hidden entries continue at their next parent suffix.
            for (i, hit) in hits.into_iter().enumerate() {
                let Some(entry) = hit.filter(|entry| !entry.hidden) else {
                    continue;
                };
                let view = entry.view();
                let (qname, _, _) = queries[i].expect("a probe has a query");
                let selected = (view.state() == ZoneState::Active
                    && !view.has_incremental_overlay())
                .then(|| SelectedZoneQuery {
                    qname,
                    image: view.serving_image.expect("active published image"),
                    relative_labels: qname.label_count() - view.serving_origin_label_count,
                });
                results[i] = Some((view, selected));
                pending[i] = None;
            }
        }
        results
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    #[test]
    fn authority_waves_match_scalar_for_parent_root_hidden_and_publication_changes() {
        let store = ZoneStore::new();
        let names: Vec<_> = [
            ".",
            "test.",
            "example.test.",
            "child.example.test.",
            "other.test.",
            "outside.",
        ]
        .iter()
        .map(|s| DomainName::from_absolute_str(s).unwrap())
        .collect();
        let mut queries: Vec<_> = [
            ".",
            "test.",
            "EXAMPLE.test.",
            "www.child.example.test.",
            "child.example.test.",
            "missing.invalid.",
            "other.test.",
        ]
        .iter()
        .map(|s| DomainName::from_absolute_str(s).unwrap())
        .collect();
        queries.push(DomainName::from_uncompressed_wire(b"\x03a\0b\x07example\x04test\0").unwrap());
        queries.push(
            DomainName::from_absolute_str(&format!(
                "{}.{}.{}.example.test.",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63)
            ))
            .unwrap(),
        );
        let check = |selector: &BatchZoneSelector<'_>| {
            assert!(selector.select_many(&[]).is_empty());
            for parent in [false, true] {
                for chunk in queries.chunks(DNS_SERVING_BATCH_SIZE - 1) {
                    let mut inputs: SmallVec<[_; DNS_SERVING_BATCH_SIZE]> =
                        chunk.iter().map(|q| Some((q, false, parent))).collect();
                    inputs.push(None);
                    let batch = selector.select_many(&inputs);
                    for (input, got) in inputs.iter().zip(&batch) {
                        let expected =
                            input.and_then(|(q, lower, ds)| selector.select(q, lower, ds));
                        assert_eq!(
                            got.as_ref().map(|(v, _)| v.origin_key()),
                            expected.as_ref().map(|(v, _)| v.origin_key())
                        );
                        if let (Some((actual, selected)), Some((expected, proof))) = (got, expected)
                        {
                            assert!(std::ptr::eq(actual.entry, expected.entry));
                            assert_eq!(actual.state(), expected.state());
                            assert_eq!(selected.is_some(), proof.is_some());
                            if let (Some(selected), Some(proof)) = (selected, proof) {
                                assert!(std::ptr::eq(selected.image, proof.image));
                                assert_eq!(selected.relative_labels, proof.relative_labels);
                            }
                        }
                    }
                }
            }
        };
        store.with_batch_selector(|s| check(&s));
        for name in &names {
            store.insert_loading(name.clone());
            store.with_batch_selector(|s| check(&s));
            store.insert_snapshot(ZoneSnapshot::active(name.clone(), Some(1), Vec::new()));
            store.with_batch_selector(|s| check(&s));
        }
        store.with_batch_selector(|frozen| {
            for name in names.iter().rev() {
                store.hide_zone(name);
                store.with_batch_selector(|s| check(&s));
                check(&frozen);
                store.show_zone(name);
                store.with_batch_selector(|s| check(&s));
                store.expire_zone(name);
                store.with_batch_selector(|s| check(&s));
                store.insert_snapshot(ZoneSnapshot::active(name.clone(), Some(2), Vec::new()));
                store.with_batch_selector(|s| check(&s));
                assert!(store.remove_zone(name));
                store.with_batch_selector(|s| check(&s));
                check(&frozen);
            }
        });
    }
}
