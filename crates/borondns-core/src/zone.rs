use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::RandomState},
    hash::{BuildHasher, Hash, Hasher},
    mem,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use arc_swap::ArcSwap;
use sha1::{Digest, Sha1};
use smallvec::SmallVec;
use tracing::{info, warn};

use crate::dns::{
    AnyResponseMode, DEFAULT_MAX_CNAME_CHAIN, DomainName, LookupResult, LookupTermination, Rcode,
    RecordType, canonical_name_key_from_labels,
};
use crate::zone_image::{
    ZoneImage, ZoneImageBuildError, ZoneImageLookupOutcome, ZoneImageLookupPlan, ZoneImageRrsetId,
    ZoneImageStats,
};

// BDS-NFR-MAINT-004 principal functional requirement references for the
// in-memory authoritative zone store:
// - BDS-FR-ZONE-001 BDS-FR-ZONE-002 BDS-FR-ZONE-003
// - BDS-FR-ZONE-004 BDS-FR-ZONE-005 BDS-FR-ZONE-006
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneState {
    Loading,
    Active,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZonePublicationStrategy {
    #[default]
    Compact,
    Sharded,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonePublicationPolicy {
    pub strategy: ZonePublicationStrategy,
    pub sharded_rrset_threshold: usize,
    /// Number of unique dirty owners that triggers an out-of-band compact
    /// image rebuild. Zero disables automatic compaction.
    pub overlay_compaction_dirty_owner_threshold: usize,
}

impl Default for ZonePublicationPolicy {
    fn default() -> Self {
        Self {
            strategy: ZonePublicationStrategy::Compact,
            sharded_rrset_threshold: 1_000_000,
            overlay_compaction_dirty_owner_threshold: 100_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneOverlayCompactionOutcome {
    NotNeeded,
    AlreadyRunning,
    Compacted { remaining_dirty_owners: usize },
    Obsolete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoaTimers {
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSnapshot {
    pub origin: DomainName,
    pub state: ZoneState,
    pub serial: Option<u32>,
    pub soa_timers: Option<SoaTimers>,
    soa_record_count: usize,
    dnssec_rrset_count: usize,
    rdata_record_count: usize,
    denial_indexes: DenialIndexes,
    shape_summary_cache: ZoneShapeSummary,
    rdata_count_frequencies: Arc<BTreeMap<usize, usize>>,
    lineage: ZoneSnapshotLineage,
    origin_key: NameKey,
    rrsets: ShardedRrsets,
    name_classes: Arc<NameClassIndex>,
    empty_non_terminal_classes: Arc<NameClassIndex>,
    delegation_rrsets: ShardedRrsetKeys,
    dname_rrsets: ShardedRrsetKeys,
}

#[derive(Debug, Clone)]
struct ZoneSnapshotLineage {
    identity: Arc<()>,
    parent_identity: Option<Arc<()>>,
    changed_rrset_keys: Arc<[RrsetKey]>,
}

impl Default for ZoneSnapshotLineage {
    fn default() -> Self {
        Self {
            identity: Arc::new(()),
            parent_identity: None,
            changed_rrset_keys: Arc::from([]),
        }
    }
}

impl PartialEq for ZoneSnapshotLineage {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ZoneSnapshotLineage {}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct ZoneSnapshotOfflineOracle<'a> {
    snapshot: &'a ZoneSnapshot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZoneShapeSummary {
    pub rrset_count: usize,
    pub rdata_count: usize,
    pub single_rdata_rrset_count: usize,
    pub multi_rdata_rrset_count: usize,
    pub spilled_rdata_rrset_count: usize,
    pub max_rdata_per_rrset: usize,
    pub owner_name_count: usize,
    pub empty_non_terminal_name_count: usize,
    pub rdata_payload_bytes: usize,
    pub name_key_logical_bytes: usize,
    pub name_key_unique_bytes: usize,
    pub name_key_deduplicated_bytes: usize,
    pub in_only_class_index_bytes_saved: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneShapeHistogramBucket {
    pub bucket: &'static str,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneShapeHistogramSummary {
    pub child_name_fanout_names: Vec<ZoneShapeHistogramBucket>,
    pub rrsets_per_owner_name: Vec<ZoneShapeHistogramBucket>,
    pub rdata_records_per_rrset: Vec<ZoneShapeHistogramBucket>,
    pub rdata_payload_bytes_per_rrset: Vec<ZoneShapeHistogramBucket>,
}

#[derive(Debug, Clone, Copy)]
struct ZoneShapeBucketDefinition {
    label: &'static str,
    upper_bound: Option<usize>,
}

struct DnssecAugmentationState {
    dnssec_augmented: bool,
    nsec3_iterations_exceeded: bool,
    nsec3_max_iterations: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DenialIndexes {
    nsec: PersistentOrderIndex<NsecOrderKey>,
    nsec3: PersistentOrderIndex<Nsec3OrderKey>,
    nsec3_param_counts: Arc<HashMap<(u16, Nsec3Params), u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NsecOrderKey {
    class: u16,
    owner: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Nsec3OrderKey {
    class: u16,
    params: Nsec3Params,
    owner_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistentOrderIndex<K> {
    root: Option<Arc<PersistentOrderNode<K>>>,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistentOrderNode<K> {
    key: K,
    value: RrsetKey,
    priority: u64,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
}

impl<K> Default for PersistentOrderIndex<K> {
    fn default() -> Self {
        Self { root: None, len: 0 }
    }
}

impl<K> PersistentOrderIndex<K>
where
    K: Clone + Hash + Ord,
{
    fn insert(&mut self, key: K, value: RrsetKey) {
        let existed = persistent_order_get(&self.root, &key).is_some();
        self.root = Some(persistent_order_insert(self.root.take(), key, value));
        if !existed {
            self.len += 1;
        }
    }

    fn remove(&mut self, key: &K) {
        if persistent_order_get(&self.root, key).is_none() {
            return;
        }
        self.root = persistent_order_remove(self.root.take(), key);
        self.len -= 1;
    }

    fn predecessor(&self, key: &K) -> Option<(&K, &RrsetKey)> {
        let mut node = self.root.as_deref();
        let mut found = None;
        while let Some(current) = node {
            if current.key <= *key {
                found = Some((&current.key, &current.value));
                node = current.right.as_deref();
            } else {
                node = current.left.as_deref();
            }
        }
        found
    }

    fn last_before(&self, upper_exclusive: &K) -> Option<(&K, &RrsetKey)> {
        let mut node = self.root.as_deref();
        let mut found = None;
        while let Some(current) = node {
            if current.key < *upper_exclusive {
                found = Some((&current.key, &current.value));
                node = current.right.as_deref();
            } else {
                node = current.left.as_deref();
            }
        }
        found
    }
}

fn persistent_order_priority<K: Hash>(key: &K) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

fn persistent_order_get<'a, K: Ord>(
    root: &'a Option<Arc<PersistentOrderNode<K>>>,
    key: &K,
) -> Option<&'a RrsetKey> {
    let mut node = root.as_deref();
    while let Some(current) = node {
        match key.cmp(&current.key) {
            std::cmp::Ordering::Less => node = current.left.as_deref(),
            std::cmp::Ordering::Greater => node = current.right.as_deref(),
            std::cmp::Ordering::Equal => return Some(&current.value),
        }
    }
    None
}

fn persistent_order_insert<K>(
    root: Option<Arc<PersistentOrderNode<K>>>,
    key: K,
    value: RrsetKey,
) -> Arc<PersistentOrderNode<K>>
where
    K: Clone + Hash + Ord,
{
    let priority = persistent_order_priority(&key);
    let Some(node) = root else {
        return Arc::new(PersistentOrderNode {
            key,
            value,
            priority,
            left: None,
            right: None,
        });
    };
    match key.cmp(&node.key) {
        std::cmp::Ordering::Equal => Arc::new(PersistentOrderNode {
            key,
            value,
            priority,
            left: node.left.clone(),
            right: node.right.clone(),
        }),
        _ if priority < node.priority => {
            let (left, right) = persistent_order_split(Some(node), &key);
            Arc::new(PersistentOrderNode {
                key,
                value,
                priority,
                left,
                right,
            })
        }
        std::cmp::Ordering::Less => Arc::new(PersistentOrderNode {
            key: node.key.clone(),
            value: node.value.clone(),
            priority: node.priority,
            left: Some(persistent_order_insert(node.left.clone(), key, value)),
            right: node.right.clone(),
        }),
        std::cmp::Ordering::Greater => Arc::new(PersistentOrderNode {
            key: node.key.clone(),
            value: node.value.clone(),
            priority: node.priority,
            left: node.left.clone(),
            right: Some(persistent_order_insert(node.right.clone(), key, value)),
        }),
    }
}

fn persistent_order_split<K: Clone + Ord>(
    root: Option<Arc<PersistentOrderNode<K>>>,
    key: &K,
) -> (
    Option<Arc<PersistentOrderNode<K>>>,
    Option<Arc<PersistentOrderNode<K>>>,
) {
    let Some(node) = root else {
        return (None, None);
    };
    if node.key < *key {
        let (middle, right) = persistent_order_split(node.right.clone(), key);
        (
            Some(Arc::new(PersistentOrderNode {
                key: node.key.clone(),
                value: node.value.clone(),
                priority: node.priority,
                left: node.left.clone(),
                right: middle,
            })),
            right,
        )
    } else {
        let (left, middle) = persistent_order_split(node.left.clone(), key);
        (
            left,
            Some(Arc::new(PersistentOrderNode {
                key: node.key.clone(),
                value: node.value.clone(),
                priority: node.priority,
                left: middle,
                right: node.right.clone(),
            })),
        )
    }
}

fn persistent_order_remove<K: Clone + Ord>(
    root: Option<Arc<PersistentOrderNode<K>>>,
    key: &K,
) -> Option<Arc<PersistentOrderNode<K>>> {
    let node = root?;
    match key.cmp(&node.key) {
        std::cmp::Ordering::Less => Some(Arc::new(PersistentOrderNode {
            key: node.key.clone(),
            value: node.value.clone(),
            priority: node.priority,
            left: persistent_order_remove(node.left.clone(), key),
            right: node.right.clone(),
        })),
        std::cmp::Ordering::Greater => Some(Arc::new(PersistentOrderNode {
            key: node.key.clone(),
            value: node.value.clone(),
            priority: node.priority,
            left: node.left.clone(),
            right: persistent_order_remove(node.right.clone(), key),
        })),
        std::cmp::Ordering::Equal => persistent_order_merge(node.left.clone(), node.right.clone()),
    }
}

fn persistent_order_merge<K: Clone + Ord>(
    left: Option<Arc<PersistentOrderNode<K>>>,
    right: Option<Arc<PersistentOrderNode<K>>>,
) -> Option<Arc<PersistentOrderNode<K>>> {
    match (left, right) {
        (None, right) => right,
        (left, None) => left,
        (Some(left), Some(right)) if left.priority < right.priority => {
            Some(Arc::new(PersistentOrderNode {
                key: left.key.clone(),
                value: left.value.clone(),
                priority: left.priority,
                left: left.left.clone(),
                right: persistent_order_merge(left.right.clone(), Some(right)),
            }))
        }
        (Some(left), Some(right)) => Some(Arc::new(PersistentOrderNode {
            key: right.key.clone(),
            value: right.value.clone(),
            priority: right.priority,
            left: persistent_order_merge(Some(left), right.left.clone()),
            right: right.right.clone(),
        })),
    }
}

const ZONE_SHAPE_COUNT_BUCKETS: &[ZoneShapeBucketDefinition] = &[
    ZoneShapeBucketDefinition {
        label: "0",
        upper_bound: Some(0),
    },
    ZoneShapeBucketDefinition {
        label: "1",
        upper_bound: Some(1),
    },
    ZoneShapeBucketDefinition {
        label: "2_4",
        upper_bound: Some(4),
    },
    ZoneShapeBucketDefinition {
        label: "5_8",
        upper_bound: Some(8),
    },
    ZoneShapeBucketDefinition {
        label: "9_16",
        upper_bound: Some(16),
    },
    ZoneShapeBucketDefinition {
        label: "17_32",
        upper_bound: Some(32),
    },
    ZoneShapeBucketDefinition {
        label: "33_64",
        upper_bound: Some(64),
    },
    ZoneShapeBucketDefinition {
        label: "65_128",
        upper_bound: Some(128),
    },
    ZoneShapeBucketDefinition {
        label: "129_256",
        upper_bound: Some(256),
    },
    ZoneShapeBucketDefinition {
        label: "gt_256",
        upper_bound: None,
    },
];

const ZONE_SHAPE_BYTE_BUCKETS: &[ZoneShapeBucketDefinition] = &[
    ZoneShapeBucketDefinition {
        label: "0",
        upper_bound: Some(0),
    },
    ZoneShapeBucketDefinition {
        label: "1_16",
        upper_bound: Some(16),
    },
    ZoneShapeBucketDefinition {
        label: "17_32",
        upper_bound: Some(32),
    },
    ZoneShapeBucketDefinition {
        label: "33_64",
        upper_bound: Some(64),
    },
    ZoneShapeBucketDefinition {
        label: "65_128",
        upper_bound: Some(128),
    },
    ZoneShapeBucketDefinition {
        label: "129_256",
        upper_bound: Some(256),
    },
    ZoneShapeBucketDefinition {
        label: "257_512",
        upper_bound: Some(512),
    },
    ZoneShapeBucketDefinition {
        label: "513_1024",
        upper_bound: Some(1024),
    },
    ZoneShapeBucketDefinition {
        label: "1025_2048",
        upper_bound: Some(2048),
    },
    ZoneShapeBucketDefinition {
        label: "gt_2048",
        upper_bound: None,
    },
];

impl ZoneSnapshot {
    pub fn loading(origin: DomainName) -> Self {
        let origin_key = NameKey::from(origin.canonical_key());
        Self {
            origin,
            state: ZoneState::Loading,
            serial: None,
            soa_timers: None,
            soa_record_count: 0,
            dnssec_rrset_count: 0,
            rdata_record_count: 0,
            denial_indexes: DenialIndexes::default(),
            shape_summary_cache: ZoneShapeSummary::default(),
            rdata_count_frequencies: Arc::new(BTreeMap::new()),
            lineage: ZoneSnapshotLineage::default(),
            origin_key,
            rrsets: ShardedRrsets::empty(),
            name_classes: Arc::new(NameClassIndex::in_only()),
            empty_non_terminal_classes: Arc::new(NameClassIndex::in_only()),
            delegation_rrsets: ShardedRrsetKeys::new(1),
            dname_rrsets: ShardedRrsetKeys::new(1),
        }
    }

    pub fn active(origin: DomainName, serial: Option<u32>, rrsets: Vec<Rrset>) -> Self {
        let mut name_interner = NameInterner::default();
        let origin_key = name_interner.intern_domain(&origin);
        let by_key = ShardedRrsets::from_rrsets(rrsets, &mut name_interner);
        let soa_timers = soa_timers_from_rrsets(&origin_key, &by_key);
        let soa_record_count = by_key
            .values()
            .filter(|rrset| rrset.rr_type == RecordType::Soa as u16)
            .map(|rrset| rrset.rdatas.len())
            .sum();
        let dnssec_rrset_count = by_key
            .values()
            .filter(|rrset| is_dnssec_rr_type(rrset.rr_type))
            .count();
        let rdata_record_count = by_key.values().map(|rrset| rrset.rdatas.len()).sum();
        let denial_indexes = DenialIndexes::build(&by_key, &origin);
        let indexes = ZoneSnapshotIndexes::build(&origin, &by_key, &mut name_interner);

        let mut snapshot = Self {
            origin,
            state: ZoneState::Active,
            serial,
            soa_timers,
            soa_record_count,
            dnssec_rrset_count,
            rdata_record_count,
            denial_indexes,
            shape_summary_cache: ZoneShapeSummary::default(),
            rdata_count_frequencies: Arc::new(rrset_rdata_count_frequencies(&by_key)),
            lineage: ZoneSnapshotLineage::default(),
            origin_key,
            rrsets: by_key,
            name_classes: Arc::new(indexes.name_classes),
            empty_non_terminal_classes: Arc::new(indexes.empty_non_terminal_classes),
            delegation_rrsets: indexes.delegation_rrsets,
            dname_rrsets: indexes.dname_rrsets,
        };
        snapshot.shape_summary_cache = snapshot.compute_shape_summary();
        snapshot
    }

    pub fn with_state(&self, state: ZoneState) -> Self {
        Self {
            origin: self.origin.clone(),
            state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            soa_record_count: self.soa_record_count,
            dnssec_rrset_count: self.dnssec_rrset_count,
            rdata_record_count: self.rdata_record_count,
            denial_indexes: self.denial_indexes.clone(),
            shape_summary_cache: self.shape_summary_cache,
            rdata_count_frequencies: self.rdata_count_frequencies.clone(),
            lineage: self.lineage.clone(),
            origin_key: self.origin_key.clone(),
            rrsets: self.rrsets.clone(),
            name_classes: self.name_classes.clone(),
            empty_non_terminal_classes: self.empty_non_terminal_classes.clone(),
            delegation_rrsets: self.delegation_rrsets.clone(),
            dname_rrsets: self.dname_rrsets.clone(),
        }
    }

    pub fn soa_record_view(&self, qclass: u16) -> Option<SoaRecordView<'_>> {
        let rrset = self.soa_rrset(qclass)?;
        let rdata = rrset.rdatas.first()?;
        Some(SoaRecordView {
            owner: &rrset.owner,
            class: rrset.class,
            ttl: rrset.ttl,
            rdata,
        })
    }

    pub(crate) fn transfer_soa_record(&self, qclass: u16) -> Option<ResourceRecord> {
        self.soa_rrset(qclass)
            .and_then(|rrset| rrset.records().into_iter().next())
    }

    #[cfg(test)]
    pub(crate) fn transfer_records(&self) -> Vec<ResourceRecord> {
        self.rrsets
            .iter()
            .flat_map(|(key, rrset)| {
                rrset.rdatas.iter().map(move |rdata| ResourceRecord {
                    owner: rrset.owner.clone(),
                    rr_type: rrset.rr_type,
                    class: rrset.class,
                    ttl: self.record_ttl_by_owner_key(
                        key.owner.as_ref(),
                        rrset.class,
                        rrset.rr_type,
                        rrset.ttl,
                        rdata,
                    ),
                    rdata: rdata.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn rrsets(&self) -> impl Iterator<Item = &Rrset> {
        self.rrsets.values()
    }

    pub(crate) fn transfer_rrset_records_by_key(
        &self,
        owner_key: &str,
        rr_type: u16,
        class: u16,
    ) -> Vec<ResourceRecord> {
        let Some(rrset) = self
            .rrsets
            .get(&RrsetKey::new_from_key(owner_key, rr_type, class))
        else {
            return Vec::new();
        };
        rrset
            .rdatas
            .iter()
            .map(|rdata| ResourceRecord {
                owner: rrset.owner.clone(),
                rr_type,
                class,
                ttl: self.record_ttl_by_owner_key(owner_key, class, rr_type, rrset.ttl, rdata),
                rdata: rdata.clone(),
            })
            .collect()
    }

    pub(crate) fn transfer_records_at_name_key(&self, owner_key: &str) -> Vec<ResourceRecord> {
        self.rrsets
            .values_at_owner(owner_key)
            .flat_map(|rrset| {
                rrset.rdatas.iter().map(move |rdata| ResourceRecord {
                    owner: rrset.owner.clone(),
                    rr_type: rrset.rr_type,
                    class: rrset.class,
                    ttl: self.record_ttl_by_owner_key(
                        owner_key,
                        rrset.class,
                        rrset.rr_type,
                        rrset.ttl,
                        rdata,
                    ),
                    rdata: rdata.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn with_cow_rrset_replacements(
        &self,
        serial: u32,
        replacements: Vec<(String, u16, u16, Option<Rrset>)>,
    ) -> Self {
        let changed_rrset_keys = replacements
            .iter()
            .map(|(owner_key, rr_type, class, _)| {
                RrsetKey::new_from_key(owner_key, *rr_type, *class)
            })
            .collect::<Vec<_>>();
        let mut soa_record_count = self.soa_record_count;
        let mut dnssec_rrset_count = self.dnssec_rrset_count;
        let mut rdata_record_count = self.rdata_record_count;
        let mut shape_summary = self.shape_summary_cache;
        let mut rdata_count_frequencies = self.rdata_count_frequencies.clone();
        let mut rrset_presence_changes = Vec::<(String, u16, bool)>::new();
        let mut special_index_changes = Vec::<(RrsetKey, bool, bool)>::new();
        for (owner_key, rr_type, class, replacement) in &replacements {
            let key = RrsetKey::new_from_key(owner_key, *rr_type, *class);
            let previous_rrset = self.rrsets.get(&key);
            let previous_present = previous_rrset.is_some();
            let replacement_present = replacement.is_some();
            if let Some(previous) = previous_rrset {
                remove_rrset_from_shape(
                    &mut shape_summary,
                    Arc::make_mut(&mut rdata_count_frequencies),
                    previous,
                );
            }
            if let Some(next) = replacement {
                add_rrset_to_shape(
                    &mut shape_summary,
                    Arc::make_mut(&mut rdata_count_frequencies),
                    next,
                );
            }
            let previous_rdata_count = previous_rrset.map_or(0, |rrset| rrset.rdatas.len());
            let replacement_rdata_count =
                replacement.as_ref().map_or(0, |rrset| rrset.rdatas.len());
            rdata_record_count =
                rdata_record_count.saturating_sub(previous_rdata_count) + replacement_rdata_count;
            if previous_present != replacement_present {
                rrset_presence_changes.push((owner_key.clone(), *class, replacement_present));
                if is_dnssec_rr_type(*rr_type) {
                    if replacement_present {
                        dnssec_rrset_count = dnssec_rrset_count.saturating_add(1);
                    } else {
                        dnssec_rrset_count = dnssec_rrset_count.saturating_sub(1);
                    }
                }
            }
            if previous_present != replacement_present {
                let is_delegation = *rr_type == RecordType::Ns as u16
                    && owner_key.as_str() != self.origin_key.as_ref();
                let is_dname = *rr_type == RecordType::Dname as u16;
                if is_delegation || is_dname {
                    special_index_changes.push((
                        RrsetKey::new_from_key(owner_key, *rr_type, *class),
                        replacement_present,
                        is_delegation,
                    ));
                }
            }
            if *rr_type != RecordType::Soa as u16 {
                continue;
            }
            let previous = self
                .rrsets
                .get(&RrsetKey::new_from_key(owner_key, *rr_type, *class))
                .map_or(0, |rrset| rrset.rdatas.len());
            let next = replacement.as_ref().map_or(0, |rrset| rrset.rdatas.len());
            soa_record_count = soa_record_count.saturating_sub(previous) + next;
        }
        let rrsets = self.rrsets.with_replacements(replacements);
        let denial_indexes = self
            .denial_indexes
            .updated(&self.rrsets, &rrsets, &self.origin);
        let mut name_classes = (*self.name_classes).clone();
        let mut empty_non_terminal_classes = (*self.empty_non_terminal_classes).clone();
        let mut affected_names = HashSet::<String>::new();
        for (owner_key, class, added) in &rrset_presence_changes {
            affected_names.insert(owner_key.clone());
            let owner = NameKey::from(owner_key.as_str());
            if *added {
                name_classes.insert(owner, *class);
            } else {
                name_classes.remove(owner_key, *class);
            }
            let mut ancestor = parent_name_key(owner_key);
            while let Some(name) = ancestor {
                affected_names.insert(name.clone());
                if *added {
                    empty_non_terminal_classes.insert(NameKey::from(name.as_str()), *class);
                } else {
                    empty_non_terminal_classes.remove(&name, *class);
                }
                if name == self.origin_key.as_ref() {
                    break;
                }
                ancestor = parent_name_key(&name);
            }
        }
        for name in affected_names {
            update_name_shape_membership(
                &mut shape_summary,
                &name,
                self.name_classes.contains_name(&name),
                name_classes.contains_name(&name),
                self.empty_non_terminal_classes.contains_name(&name),
                empty_non_terminal_classes.contains_name(&name),
            );
        }
        let mut delegation_rrsets = self.delegation_rrsets.clone();
        let mut dname_rrsets = self.dname_rrsets.clone();
        for (key, added, is_delegation) in special_index_changes {
            let index = if is_delegation {
                &mut delegation_rrsets
            } else {
                &mut dname_rrsets
            };
            if added {
                shape_summary.name_key_logical_bytes += key.owner.len();
                index.insert(key);
            } else {
                shape_summary.name_key_logical_bytes = shape_summary
                    .name_key_logical_bytes
                    .saturating_sub(key.owner.len());
                index.remove(&key);
            }
        }
        shape_summary.max_rdata_per_rrset = rdata_count_frequencies
            .last_key_value()
            .map_or(0, |(count, _)| *count);
        shape_summary.owner_name_count = name_classes.len();
        shape_summary.empty_non_terminal_name_count = empty_non_terminal_classes.len();
        shape_summary.in_only_class_index_bytes_saved =
            name_classes.value_bytes_saved() + empty_non_terminal_classes.value_bytes_saved();
        shape_summary.name_key_deduplicated_bytes = shape_summary
            .name_key_logical_bytes
            .saturating_sub(shape_summary.name_key_unique_bytes);
        Self {
            origin: self.origin.clone(),
            state: ZoneState::Active,
            serial: Some(serial),
            soa_timers: soa_timers_from_rrsets(&self.origin_key, &rrsets),
            soa_record_count,
            dnssec_rrset_count,
            rdata_record_count,
            denial_indexes,
            shape_summary_cache: shape_summary,
            rdata_count_frequencies,
            lineage: ZoneSnapshotLineage {
                identity: Arc::new(()),
                parent_identity: Some(self.lineage.identity.clone()),
                changed_rrset_keys: Arc::from(changed_rrset_keys),
            },
            origin_key: self.origin_key.clone(),
            rrsets,
            name_classes: Arc::new(name_classes),
            empty_non_terminal_classes: Arc::new(empty_non_terminal_classes),
            delegation_rrsets,
            dname_rrsets,
        }
    }

    pub(crate) fn soa_record_count(&self) -> usize {
        self.soa_record_count
    }

    fn has_dnssec_rrsets(&self) -> bool {
        self.dnssec_rrset_count != 0
    }

    pub fn rdata_record_count(&self) -> usize {
        self.rdata_record_count
    }

    fn changed_rrset_keys_from(&self, previous: &Self) -> Option<Vec<RrsetKey>> {
        if self
            .lineage
            .parent_identity
            .as_ref()
            .is_some_and(|parent| Arc::ptr_eq(parent, &previous.lineage.identity))
        {
            return Some(self.lineage.changed_rrset_keys.to_vec());
        }
        if self.origin_key != previous.origin_key
            || self.rrsets.shards.len() != previous.rrsets.shards.len()
        {
            return None;
        }
        let mut changed = Vec::new();
        for (current, old) in self.rrsets.shards.iter().zip(&previous.rrsets.shards) {
            if Arc::ptr_eq(current, old) {
                continue;
            }
            for (key, old_rrset) in old.iter() {
                if current.get(key) != Some(old_rrset) {
                    changed.push(key.clone());
                }
            }
            for key in current.keys() {
                if !old.contains_key(key) {
                    changed.push(key.clone());
                }
            }
        }
        Some(changed)
    }

    #[doc(hidden)]
    pub fn rrset_storage_shard_count(&self) -> usize {
        self.rrsets.shards.len()
    }

    #[doc(hidden)]
    pub fn shared_rrset_storage_shards(&self, other: &Self) -> usize {
        self.rrsets
            .shards
            .iter()
            .zip(other.rrsets.shards.iter())
            .filter(|(left, right)| Arc::ptr_eq(left, right))
            .count()
    }

    pub(crate) fn record_ttl_by_owner_key(
        &self,
        owner_key: &str,
        class: u16,
        rr_type: u16,
        fallback_ttl: u32,
        rdata: &[u8],
    ) -> u32 {
        if rr_type != RecordType::Rrsig as u16 || rdata.len() < 2 {
            return fallback_ttl;
        }
        let covered_type = u16::from_be_bytes([rdata[0], rdata[1]]);
        self.rrset_by_name_key(owner_key, covered_type, class)
            .map_or(fallback_ttl, |covered| covered.ttl)
    }

    /// Return a narrow borrowed view for RFC 9432 catalog-zone parsing.
    pub fn catalog_zone_view(&self) -> CatalogZoneView<'_> {
        CatalogZoneView {
            origin: &self.origin,
            rrsets: &self.rrsets,
        }
    }

    pub fn shape_summary(&self) -> ZoneShapeSummary {
        self.shape_summary_cache
    }

    fn compute_shape_summary(&self) -> ZoneShapeSummary {
        let mut summary = ZoneShapeSummary {
            rrset_count: self.rrsets.len(),
            owner_name_count: self.name_classes.len(),
            empty_non_terminal_name_count: self.empty_non_terminal_classes.len(),
            in_only_class_index_bytes_saved: self.name_classes.value_bytes_saved()
                + self.empty_non_terminal_classes.value_bytes_saved(),
            ..ZoneShapeSummary::default()
        };

        for rrset in self.rrsets.values() {
            let rdata_count = rrset.rdatas.len();
            summary.rdata_count += rdata_count;
            summary.rdata_payload_bytes += rrset.rdatas.iter().map(Vec::len).sum::<usize>();
            summary.max_rdata_per_rrset = summary.max_rdata_per_rrset.max(rdata_count);
            if rdata_count == 1 {
                summary.single_rdata_rrset_count += 1;
            } else if rdata_count > 1 {
                summary.multi_rdata_rrset_count += 1;
            }
            if rrset.rdatas.spilled() {
                summary.spilled_rdata_rrset_count += 1;
            }
        }

        let mut unique_name_keys = HashSet::<NameKey>::new();
        for key in self.rrsets.keys() {
            summary.name_key_logical_bytes += key.owner.len();
            unique_name_keys.insert(key.owner.clone());
        }
        for key in self.name_classes.keys() {
            summary.name_key_logical_bytes += key.len();
            unique_name_keys.insert(key.clone());
        }
        for key in self.empty_non_terminal_classes.keys() {
            summary.name_key_logical_bytes += key.len();
            unique_name_keys.insert(key.clone());
        }
        for key in self
            .delegation_rrsets
            .iter()
            .chain(self.dname_rrsets.iter())
        {
            summary.name_key_logical_bytes += key.owner.len();
            unique_name_keys.insert(key.owner.clone());
        }

        summary.name_key_unique_bytes = unique_name_keys.iter().map(|key| key.len()).sum();
        summary.name_key_deduplicated_bytes = summary
            .name_key_logical_bytes
            .saturating_sub(summary.name_key_unique_bytes);
        summary
    }

    pub fn shape_histogram_summary(&self) -> ZoneShapeHistogramSummary {
        let mut known_names = HashSet::<NameKey>::new();
        known_names.extend(self.name_classes.keys().cloned());
        known_names.extend(self.empty_non_terminal_classes.keys().cloned());

        let mut child_counts = known_names
            .iter()
            .map(|name| (name.clone(), 0usize))
            .collect::<HashMap<_, _>>();
        for name in &known_names {
            if name.as_ref() == self.origin_key.as_ref() {
                continue;
            }
            let Some(parent) = parent_name_key(name.as_ref()) else {
                continue;
            };
            if let Some(count) = child_counts.get_mut(parent.as_str()) {
                *count += 1;
            }
        }

        let mut rrsets_per_owner = self
            .name_classes
            .keys()
            .map(|name| (name.clone(), 0usize))
            .collect::<HashMap<_, _>>();
        for key in self.rrsets.keys() {
            *rrsets_per_owner.entry(key.owner.clone()).or_insert(0) += 1;
        }

        ZoneShapeHistogramSummary {
            child_name_fanout_names: bucketize_zone_shape_values(
                child_counts.values().copied(),
                ZONE_SHAPE_COUNT_BUCKETS,
            ),
            rrsets_per_owner_name: bucketize_zone_shape_values(
                rrsets_per_owner.values().copied(),
                ZONE_SHAPE_COUNT_BUCKETS,
            ),
            rdata_records_per_rrset: bucketize_zone_shape_values(
                self.rrsets.values().map(|rrset| rrset.rdatas.len()),
                ZONE_SHAPE_COUNT_BUCKETS,
            ),
            rdata_payload_bytes_per_rrset: bucketize_zone_shape_values(
                self.rrsets
                    .values()
                    .map(|rrset| rrset.rdatas.iter().map(Vec::len).sum::<usize>()),
                ZONE_SHAPE_BYTE_BUCKETS,
            ),
        }
    }

    #[doc(hidden)]
    pub fn offline_oracle(&self) -> ZoneSnapshotOfflineOracle<'_> {
        ZoneSnapshotOfflineOracle { snapshot: self }
    }

    fn offline_oracle_lookup(&self, qname: &DomainName, qtype: u16, qclass: u16) -> LookupResult {
        self.lookup_with_options(
            qname,
            qtype,
            qclass,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        )
    }

    pub(crate) fn lookup_with_options(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> LookupResult {
        let qname_key = qname.canonical_key();
        if let Some(delegation) = self.delegation_for(qname, qclass)
            && !(qtype == RecordType::Ds as u16 && qname_key == delegation.owner.canonical_key())
        {
            let authorities = delegation.records();
            let additionals = self.glue_for_ns_records(&delegation.owner, &authorities, qclass);
            return LookupResult::referral(authorities, additionals);
        }

        if qtype == 255 {
            let answers = self
                .any_rrsets_at_name_key(qname_key.as_str(), qclass, any_response)
                .into_iter()
                .flat_map(Rrset::records)
                .collect::<Vec<_>>();

            if !answers.is_empty() {
                let additionals = self.additionals_for_answer_records(&answers, qclass);
                return LookupResult::positive_with_additionals(answers, additionals);
            }
        } else if let Some(rrset) = self.rrset_by_name_key(qname_key.as_str(), qtype, qclass) {
            let answers = rrset.records();
            let additionals = self.additionals_for_answer_records(&answers, qclass);
            return LookupResult::positive_with_additionals(answers, additionals);
        } else if qtype != RecordType::Cname as u16 {
            let cname_result = self.lookup_cname_chain(qname, qtype, qclass, max_cname_chain);
            if !cname_result.answers.is_empty() {
                return cname_result;
            }
        }

        if let Some(dname_result) = self.lookup_dname(qname, qtype, qclass, max_cname_chain) {
            return dname_result;
        }

        if self.name_exists_or_is_empty_non_terminal_key(qname_key.as_str(), qclass) {
            LookupResult::nodata(self.soa_rrset(qclass))
        } else if let Some(wildcard_result) =
            self.lookup_wildcard(qname, qtype, qclass, max_cname_chain, any_response)
        {
            wildcard_result
        } else {
            LookupResult::nxdomain(self.soa_rrset(qclass))
        }
    }

    pub(crate) fn augment_lookup_result_with_dnssec(
        &self,
        lookup: LookupResult,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        nsec3_max_iterations: u16,
    ) -> (LookupResult, bool, bool) {
        let mut seen = HashSet::new();
        let mut dnssec_state = DnssecAugmentationState {
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations,
        };
        let nodata_candidate =
            lookup.rcode == Rcode::NoError && lookup.authoritative && lookup.answers.is_empty();
        let nxdomain_candidate =
            lookup.rcode == Rcode::NxDomain && lookup.authoritative && lookup.answers.is_empty();
        let wildcard_candidate = self.is_wildcard_synthesis(qname, qtype, qclass, &lookup);
        let authorities =
            self.add_referral_dnssec_augmentations(lookup.authorities, &mut dnssec_state);
        let authorities = self.add_nodata_nsec_augmentations(
            qname,
            qtype,
            qclass,
            nodata_candidate,
            authorities,
            &mut dnssec_state,
        );
        let authorities = self.add_nxdomain_nsec_augmentations(
            qname,
            qclass,
            nxdomain_candidate,
            authorities,
            &mut dnssec_state,
        );
        let authorities = self.add_wildcard_nsec_augmentations(
            qname,
            qclass,
            wildcard_candidate,
            authorities,
            &mut dnssec_state,
        );
        let answers = self.add_rrsig_augmentations(
            lookup.answers,
            &mut seen,
            &mut dnssec_state.dnssec_augmented,
        );
        let authorities = self.add_rrsig_augmentations(
            authorities,
            &mut seen,
            &mut dnssec_state.dnssec_augmented,
        );
        let additionals = self.add_rrsig_augmentations(
            lookup.additionals,
            &mut seen,
            &mut dnssec_state.dnssec_augmented,
        );

        (
            LookupResult {
                answers,
                authorities,
                additionals,
                nsec3_iterations_exceeded: dnssec_state.nsec3_iterations_exceeded,
                ..lookup
            },
            dnssec_state.dnssec_augmented,
            dnssec_state.nsec3_iterations_exceeded,
        )
    }

    fn is_wildcard_synthesis(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        lookup: &LookupResult,
    ) -> bool {
        if lookup.rcode != Rcode::NoError
            || !lookup.authoritative
            || lookup.answers.is_empty()
            || lookup
                .answers
                .first()
                .is_none_or(|record| record.owner != *qname)
            || self.name_exists(qname, qclass)
        {
            return false;
        }
        let Some(wildcard) = self
            .closest_encloser(qname, qclass)
            .map(|closest| closest.wildcard_child())
        else {
            return false;
        };
        if qtype == 255 {
            !self.rrsets_at_name(&wildcard, qclass).is_empty()
        } else {
            self.rrset(&wildcard, qtype, qclass).is_some()
                || (qtype != RecordType::Cname as u16
                    && self
                        .rrset(&wildcard, RecordType::Cname as u16, qclass)
                        .is_some())
        }
    }

    fn lookup_cname_chain(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
    ) -> LookupResult {
        self.resolve_cname_at(
            qname.clone(),
            qtype,
            qclass,
            Vec::new(),
            vec![qname.canonical_key()],
            max_cname_chain,
        )
    }

    fn resolve_cname_at(
        &self,
        current: DomainName,
        qtype: u16,
        qclass: u16,
        mut answers: Vec<ResourceRecord>,
        visited: Vec<String>,
        remaining: usize,
    ) -> LookupResult {
        if remaining == 0 {
            let original_qname = visited.first().map(String::as_str).unwrap_or("<unknown>");
            warn!(
                qname = %original_qname,
                zone = %self.origin,
                reason = "cname_chain_limit",
                current = %current,
                "CNAME chain limit reached; returning SERVFAIL with partial chain"
            );
            return LookupResult::servfail_records_with_termination(
                answers,
                LookupTermination::CnameChainLimit,
            );
        }

        let Some(cname_rrset) = self.rrset(&current, RecordType::Cname as u16, qclass) else {
            return LookupResult::positive_records(answers);
        };
        let cname_records = cname_rrset.records();
        let Some(target) = cname_records.first().and_then(cname_target) else {
            answers.extend(cname_records);
            return LookupResult::positive_records(answers);
        };
        answers.extend(cname_records);

        self.resolve_indirection_target(target, qtype, qclass, answers, visited, remaining - 1)
    }

    fn resolve_indirection_target(
        &self,
        target: DomainName,
        qtype: u16,
        qclass: u16,
        mut answers: Vec<ResourceRecord>,
        mut visited: Vec<String>,
        remaining: usize,
    ) -> LookupResult {
        if !target.is_equal_or_subdomain_of(&self.origin) {
            return LookupResult::positive_records(answers);
        }

        let target_key = target.canonical_key();
        if let Some(delegation) = self.delegation_for(&target, qclass)
            && !(qtype == RecordType::Ds as u16 && target_key == delegation.owner.canonical_key())
        {
            return LookupResult::positive_records(answers);
        }
        if visited.contains(&target_key) {
            let original_qname = visited.first().map(String::as_str).unwrap_or("<unknown>");
            warn!(
                qname = %original_qname,
                zone = %self.origin,
                reason = "cname_loop",
                looping_target = %target,
                "CNAME chain loop detected; returning SERVFAIL with partial chain"
            );
            return LookupResult::servfail_records_with_termination(
                answers,
                LookupTermination::CnameLoop,
            );
        }
        visited.push(target_key);

        if let Some(rrset) = self.rrset(&target, qtype, qclass) {
            answers.extend(rrset.records());
            let additionals = self.additionals_for_answer_records(&answers, qclass);
            return LookupResult::positive_with_additionals(answers, additionals);
        }

        if self
            .rrset(&target, RecordType::Cname as u16, qclass)
            .is_some()
        {
            return self.resolve_cname_at(target, qtype, qclass, answers, visited, remaining);
        }

        if self.name_exists(&target, qclass) {
            return LookupResult::nodata_with_answers(answers, self.soa_rrset(qclass));
        }
        LookupResult::nxdomain_with_answers(answers, self.soa_rrset(qclass))
    }

    fn lookup_dname(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
    ) -> Option<LookupResult> {
        let dname_rrset = self.dname_for(qname, qclass)?;
        let dname_records = dname_rrset.records();
        if dname_records.len() != 1 {
            warn!(
                qname = %qname,
                zone = %self.origin,
                dname_owner = %dname_rrset.owner,
                record_count = dname_records.len(),
                "DNAME RRset contained multiple records; returning SERVFAIL"
            );
            return Some(LookupResult::servfail_records_with_termination(
                dname_records,
                LookupTermination::MalformedDname,
            ));
        }
        let Some(target) = dname_records.first().and_then(dname_target) else {
            warn!(
                qname = %qname,
                zone = %self.origin,
                dname_owner = %dname_rrset.owner,
                "DNAME RRset contained invalid target RDATA; returning SERVFAIL"
            );
            return Some(LookupResult::servfail_records_with_termination(
                dname_records,
                LookupTermination::MalformedDname,
            ));
        };
        let Some(synthesized_target) = qname.with_replaced_suffix(&dname_rrset.owner, &target)
        else {
            return Some(LookupResult::yxdomain_with_answers(
                dname_records,
                self.soa_rrset(qclass),
            ));
        };

        let mut answers = dname_records;
        answers.push(ResourceRecord {
            owner: qname.clone(),
            rr_type: RecordType::Cname as u16,
            class: dname_rrset.class,
            ttl: dname_rrset.ttl,
            rdata: synthesized_target.to_wire(),
        });

        Some(self.resolve_indirection_target(
            synthesized_target,
            qtype,
            qclass,
            answers,
            vec![qname.canonical_key()],
            max_cname_chain.saturating_sub(1),
        ))
    }

    fn lookup_wildcard(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> Option<LookupResult> {
        let closest = self.closest_encloser(qname, qclass)?;
        let wildcard = closest.wildcard_child();

        if qtype == 255 {
            let answers = self
                .any_rrsets_at_name(&wildcard, qclass, any_response)
                .into_iter()
                .flat_map(|rrset| rrset.records_with_owner(qname))
                .collect::<Vec<_>>();

            if !answers.is_empty() {
                let additionals = self.additionals_for_answer_records(&answers, qclass);
                return Some(LookupResult::positive_with_additionals(
                    answers,
                    additionals,
                ));
            }
        } else if let Some(rrset) = self.rrset(&wildcard, qtype, qclass) {
            let answers = rrset.records_with_owner(qname);
            let additionals = self.additionals_for_answer_records(&answers, qclass);
            return Some(LookupResult::positive_with_additionals(
                answers,
                additionals,
            ));
        } else if qtype != RecordType::Cname as u16
            && let Some(cname_rrset) = self.rrset(&wildcard, RecordType::Cname as u16, qclass)
        {
            let answers = cname_rrset.records_with_owner(qname);
            let Some(target) = answers.first().and_then(cname_target) else {
                return Some(LookupResult::positive_records(answers));
            };
            return Some(self.resolve_indirection_target(
                target,
                qtype,
                qclass,
                answers,
                vec![qname.canonical_key()],
                max_cname_chain.saturating_sub(1),
            ));
        }

        if self.name_exists(&wildcard, qclass) {
            return Some(LookupResult::nodata(self.soa_rrset(qclass)));
        }

        None
    }

    fn delegation_for(&self, qname: &DomainName, qclass: u16) -> Option<&Rrset> {
        let mut candidate = Some(qname.clone());
        while let Some(name) = candidate {
            if !name.is_equal_or_subdomain_of(&self.origin) {
                return None;
            }
            let is_origin = name.label_count() == self.origin.label_count();
            if !is_origin && let Some(rrset) = self.rrset(&name, RecordType::Ns as u16, qclass) {
                return Some(rrset);
            }
            if is_origin {
                return None;
            }
            candidate = name.parent();
        }
        None
    }

    fn dname_for(&self, qname: &DomainName, qclass: u16) -> Option<&Rrset> {
        let mut candidate = qname.parent();
        while let Some(name) = candidate {
            if !name.is_equal_or_subdomain_of(&self.origin) {
                return None;
            }
            let is_origin = name.label_count() == self.origin.label_count();
            if let Some(rrset) = self.rrset(&name, RecordType::Dname as u16, qclass) {
                return Some(rrset);
            }
            if is_origin {
                return None;
            }
            candidate = name.parent();
        }
        None
    }

    fn glue_for_ns_records(
        &self,
        _delegation_owner: &DomainName,
        ns_records: &[ResourceRecord],
        qclass: u16,
    ) -> Vec<ResourceRecord> {
        let mut glue = Vec::new();
        for record in ns_records {
            let Some(target) = ns_target(record) else {
                continue;
            };
            if !target.is_equal_or_subdomain_of(&self.origin) {
                continue;
            }

            for rr_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
                if let Some(rrset) = self.rrset(&target, rr_type, qclass) {
                    glue.extend(rrset.records());
                }
            }
        }
        glue
    }

    fn additionals_for_answer_records(
        &self,
        answer_records: &[ResourceRecord],
        qclass: u16,
    ) -> Vec<ResourceRecord> {
        let mut additionals = Vec::new();
        let mut seen = HashSet::new();

        for record in answer_records {
            let Some(target) = additional_address_target(record) else {
                continue;
            };
            if !target.is_equal_or_subdomain_of(&self.origin) {
                continue;
            }
            if self.delegation_for(&target, qclass).is_some() {
                continue;
            }

            if (record.rr_type == RecordType::Svcb as u16
                || record.rr_type == RecordType::Https as u16)
                && target != record.owner
                && let Some(rrset) = self.rrset(&target, record.rr_type, qclass)
            {
                for additional in rrset.records() {
                    let key = (
                        additional.owner.canonical_key(),
                        additional.rr_type,
                        additional.class,
                        additional.rdata.clone(),
                    );
                    if seen.insert(key) {
                        additionals.push(additional);
                    }
                }
            }

            for rr_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
                if let Some(rrset) = self.rrset(&target, rr_type, qclass) {
                    for additional in rrset.records() {
                        let key = (
                            additional.owner.canonical_key(),
                            additional.rr_type,
                            additional.class,
                            additional.rdata.clone(),
                        );
                        if seen.insert(key) {
                            additionals.push(additional);
                        }
                    }
                }
            }
        }

        additionals
    }

    fn add_referral_dnssec_augmentations(
        &self,
        authorities: Vec<ResourceRecord>,
        dnssec_state: &mut DnssecAugmentationState,
    ) -> Vec<ResourceRecord> {
        let mut augmented = authorities.clone();
        let mut seen = authorities
            .iter()
            .map(record_identity)
            .collect::<HashSet<_>>();
        for record in &authorities {
            if record.rr_type != RecordType::Ns as u16 {
                continue;
            }
            let proof_rrset = self
                .rrset(&record.owner, RecordType::Ds as u16, record.class)
                .or_else(|| self.rrset(&record.owner, RecordType::Nsec as u16, record.class));
            if let Some(proof_rrset) = proof_rrset {
                push_rrset_records(
                    proof_rrset,
                    &mut augmented,
                    &mut seen,
                    &mut dnssec_state.dnssec_augmented,
                );
            } else {
                self.push_nsec3_for_name(
                    &record.owner,
                    record.class,
                    true,
                    &mut augmented,
                    &mut seen,
                    dnssec_state,
                );
            }
        }
        augmented
    }

    fn add_nodata_nsec_augmentations(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        nodata_candidate: bool,
        authorities: Vec<ResourceRecord>,
        dnssec_state: &mut DnssecAugmentationState,
    ) -> Vec<ResourceRecord> {
        if !nodata_candidate
            || !authorities
                .iter()
                .any(|record| record.rr_type == RecordType::Soa as u16)
            || self.rrset(qname, qtype, qclass).is_some()
        {
            return authorities;
        }
        let mut augmented = authorities.clone();
        let mut seen = authorities
            .iter()
            .map(record_identity)
            .collect::<HashSet<_>>();
        if let Some(nsec_rrset) = self.rrset(qname, RecordType::Nsec as u16, qclass) {
            push_rrset_records(
                nsec_rrset,
                &mut augmented,
                &mut seen,
                &mut dnssec_state.dnssec_augmented,
            );
        } else {
            self.push_nsec3_for_name(qname, qclass, true, &mut augmented, &mut seen, dnssec_state);
        }
        augmented
    }

    fn add_nxdomain_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        nxdomain_candidate: bool,
        authorities: Vec<ResourceRecord>,
        dnssec_state: &mut DnssecAugmentationState,
    ) -> Vec<ResourceRecord> {
        if !nxdomain_candidate
            || !authorities
                .iter()
                .any(|record| record.rr_type == RecordType::Soa as u16)
        {
            return authorities;
        }
        let mut augmented = authorities.clone();
        let mut seen = authorities
            .iter()
            .map(record_identity)
            .collect::<HashSet<_>>();
        self.push_nsec_covering_name(
            qname,
            qclass,
            &mut augmented,
            &mut seen,
            &mut dnssec_state.dnssec_augmented,
        );
        if let Some(closest_encloser) = self.closest_encloser(qname, qclass) {
            self.push_nsec_covering_name(
                &closest_encloser.wildcard_child(),
                qclass,
                &mut augmented,
                &mut seen,
                &mut dnssec_state.dnssec_augmented,
            );
            self.push_nsec3_for_name(
                &closest_encloser,
                qclass,
                true,
                &mut augmented,
                &mut seen,
                dnssec_state,
            );
            if let Some(next_closer) = next_closer_name(qname, &closest_encloser) {
                self.push_nsec3_for_name(
                    &next_closer,
                    qclass,
                    false,
                    &mut augmented,
                    &mut seen,
                    dnssec_state,
                );
            }
            self.push_nsec3_for_name(
                &closest_encloser.wildcard_child(),
                qclass,
                false,
                &mut augmented,
                &mut seen,
                dnssec_state,
            );
        }
        augmented
    }

    fn add_wildcard_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        wildcard_candidate: bool,
        authorities: Vec<ResourceRecord>,
        dnssec_state: &mut DnssecAugmentationState,
    ) -> Vec<ResourceRecord> {
        if !wildcard_candidate {
            return authorities;
        }
        let mut augmented = authorities.clone();
        let mut seen = authorities
            .iter()
            .map(record_identity)
            .collect::<HashSet<_>>();
        self.push_nsec_covering_name(
            qname,
            qclass,
            &mut augmented,
            &mut seen,
            &mut dnssec_state.dnssec_augmented,
        );
        self.push_nsec3_for_name(
            qname,
            qclass,
            false,
            &mut augmented,
            &mut seen,
            dnssec_state,
        );
        augmented
    }

    fn push_nsec_covering_name(
        &self,
        name: &DomainName,
        qclass: u16,
        records: &mut Vec<ResourceRecord>,
        seen: &mut HashSet<(String, u16, u16, Vec<u8>)>,
        dnssec_augmented: &mut bool,
    ) {
        let Some(nsec_rrset) = self.nsec_rrset_covering_name(name, qclass) else {
            return;
        };
        push_rrset_records(nsec_rrset, records, seen, dnssec_augmented);
    }

    fn nsec_rrset_covering_name(&self, name: &DomainName, qclass: u16) -> Option<&Rrset> {
        let class = if qclass == 255 { 1 } else { qclass };
        let key = self.denial_indexes.nsec_candidate(name, class)?;
        let rrset = self.rrsets.get(key)?;
        rrset
            .rdatas
            .iter()
            .any(|rdata| nsec_covers_name(&rrset.owner, rdata, name))
            .then_some(rrset)
    }

    fn push_nsec3_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        require_exact: bool,
        records: &mut Vec<ResourceRecord>,
        seen: &mut HashSet<(String, u16, u16, Vec<u8>)>,
        dnssec_state: &mut DnssecAugmentationState,
    ) {
        let Some(nsec3_rrset) = self.nsec3_rrset_for_name(
            name,
            qclass,
            require_exact,
            &mut dnssec_state.nsec3_iterations_exceeded,
            dnssec_state.nsec3_max_iterations,
        ) else {
            return;
        };
        push_rrset_records(
            nsec3_rrset,
            records,
            seen,
            &mut dnssec_state.dnssec_augmented,
        );
    }

    fn nsec3_rrset_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        require_exact: bool,
        nsec3_iterations_exceeded: &mut bool,
        nsec3_max_iterations: u16,
    ) -> Option<&Rrset> {
        let class = if qclass == 255 { 1 } else { qclass };
        let params = self.active_nsec3_params(class)?;
        if params.iterations > nsec3_max_iterations {
            *nsec3_iterations_exceeded = true;
            return None;
        }
        let hash = nsec3_hash_name(name, &params)?;
        let key = self.denial_indexes.nsec3_candidate(&hash, class, &params)?;
        let rrset = self.rrsets.get(key)?;
        let owner_hash = nsec3_owner_hash_label(&rrset.owner, &self.origin)?;
        rrset
            .rdatas
            .iter()
            .any(|rdata| {
                nsec3_params_from_rdata(rdata).as_ref() == Some(&params)
                    && nsec3_next_hash_label(rdata).is_some_and(|next_hash| {
                        hash == owner_hash
                            || (!require_exact
                                && nsec3_range_covers_hash(&owner_hash, &next_hash, &hash))
                    })
            })
            .then_some(rrset)
    }

    fn active_nsec3_params(&self, class: u16) -> Option<Nsec3Params> {
        let rrset = self.rrsets.get(&RrsetKey::from_name_key(
            self.origin_key.clone(),
            RecordType::Nsec3Param as u16,
            class,
        ))?;
        rrset.rdatas.iter().find_map(|rdata| {
            let params = nsec3param_params_from_rdata(rdata)?;
            self.denial_indexes
                .nsec3_param_counts
                .contains_key(&(class, params.clone()))
                .then_some(params)
        })
    }

    fn add_rrsig_augmentations(
        &self,
        records: Vec<ResourceRecord>,
        seen: &mut HashSet<(String, u16, u16, Vec<u8>)>,
        dnssec_augmented: &mut bool,
    ) -> Vec<ResourceRecord> {
        let mut augmented = records.clone();
        for record in &records {
            if record.rr_type == RecordType::Rrsig as u16 {
                continue;
            }
            let Some(rrsig_rrset) =
                self.rrset(&record.owner, RecordType::Rrsig as u16, record.class)
            else {
                continue;
            };
            for rrsig in rrsig_rrset.records() {
                if rrsig_type_covered(&rrsig.rdata) != Some(record.rr_type) {
                    continue;
                }
                if seen.insert(record_identity(&rrsig)) {
                    augmented.push(rrsig);
                    *dnssec_augmented = true;
                }
            }
        }
        augmented
    }

    fn closest_encloser(&self, qname: &DomainName, qclass: u16) -> Option<DomainName> {
        let mut candidate = qname.parent()?;
        loop {
            if !candidate.is_equal_or_subdomain_of(&self.origin) {
                return None;
            }
            let candidate_key = candidate.canonical_key();
            if self.name_exists_or_is_empty_non_terminal_key(candidate_key.as_str(), qclass) {
                return Some(candidate);
            }
            if candidate == self.origin {
                return None;
            }
            candidate = candidate.parent()?;
        }
    }

    fn rrset(&self, owner: &DomainName, rr_type: u16, qclass: u16) -> Option<&Rrset> {
        let owner_key = owner.canonical_key();
        self.rrset_by_name_key(owner_key.as_str(), rr_type, qclass)
    }

    fn rrset_by_name_key(&self, owner_key: &str, rr_type: u16, qclass: u16) -> Option<&Rrset> {
        if qclass == 255 {
            self.rrsets
                .values_at_owner(owner_key)
                .find(|rrset| rrset.rr_type == rr_type)
        } else {
            self.rrsets
                .get(&RrsetKey::new_from_key(owner_key, rr_type, qclass))
        }
    }

    fn rrsets_at_name(&self, owner: &DomainName, qclass: u16) -> Vec<&Rrset> {
        let owner_key = owner.canonical_key();
        self.rrsets_at_name_key(owner_key.as_str(), qclass)
    }

    fn rrsets_at_name_key(&self, owner_key: &str, qclass: u16) -> Vec<&Rrset> {
        self.rrsets
            .values_at_owner(owner_key)
            .filter(|rrset| qclass == 255 || rrset.class == qclass)
            .collect()
    }

    fn any_rrsets_at_name(
        &self,
        owner: &DomainName,
        qclass: u16,
        any_response: AnyResponseMode,
    ) -> Vec<&Rrset> {
        let mut rrsets = self
            .rrsets_at_name(owner, qclass)
            .into_iter()
            .filter(|rrset| !is_dnssec_proof_or_signature_type(rrset.rr_type))
            .collect::<Vec<_>>();
        rrsets.sort_by_key(|rrset| (rrset.class, rrset.rr_type));
        if any_response == AnyResponseMode::Minimal {
            rrsets.truncate(1);
        }
        rrsets
    }

    fn any_rrsets_at_name_key(
        &self,
        owner_key: &str,
        qclass: u16,
        any_response: AnyResponseMode,
    ) -> Vec<&Rrset> {
        let mut rrsets = self
            .rrsets_at_name_key(owner_key, qclass)
            .into_iter()
            .filter(|rrset| !is_dnssec_proof_or_signature_type(rrset.rr_type))
            .collect::<Vec<_>>();
        rrsets.sort_by_key(|rrset| (rrset.class, rrset.rr_type));
        if any_response == AnyResponseMode::Minimal {
            rrsets.truncate(1);
        }
        rrsets
    }

    fn name_exists(&self, name: &DomainName, qclass: u16) -> bool {
        let name_key = name.canonical_key();
        self.name_exists_key(name_key.as_str(), qclass)
    }

    fn name_exists_key(&self, name_key: &str, qclass: u16) -> bool {
        self.name_classes.contains(name_key, qclass)
    }

    fn name_exists_or_is_empty_non_terminal_key(&self, name_key: &str, qclass: u16) -> bool {
        self.name_exists_key(name_key, qclass)
            || self.empty_non_terminal_classes.contains(name_key, qclass)
    }

    fn soa_rrset(&self, qclass: u16) -> Option<&Rrset> {
        let class = if qclass == 255 { 1 } else { qclass };
        self.rrsets.get(&RrsetKey::from_name_key(
            self.origin_key.clone(),
            RecordType::Soa as u16,
            class,
        ))
    }
}

impl ZoneSnapshotOfflineOracle<'_> {
    pub fn lookup(&self, qname: &DomainName, qtype: u16, qclass: u16) -> LookupResult {
        self.snapshot.offline_oracle_lookup(qname, qtype, qclass)
    }

    pub fn lookup_with_options(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> LookupResult {
        self.snapshot
            .lookup_with_options(qname, qtype, qclass, max_cname_chain, any_response)
    }
}

fn soa_timers_from_rrsets(origin_key: &NameKey, rrsets: &ShardedRrsets) -> Option<SoaTimers> {
    let soa = rrsets.get(&RrsetKey::from_name_key(
        origin_key.clone(),
        RecordType::Soa as u16,
        1,
    ))?;
    soa.rdatas.first().and_then(|rdata| soa_timers(rdata))
}

fn bucketize_zone_shape_values(
    values: impl IntoIterator<Item = usize>,
    buckets: &[ZoneShapeBucketDefinition],
) -> Vec<ZoneShapeHistogramBucket> {
    let mut counts = vec![0usize; buckets.len()];
    for value in values {
        let index = buckets
            .iter()
            .position(|bucket| match bucket.upper_bound {
                Some(upper_bound) => value <= upper_bound,
                None => true,
            })
            .expect("zone shape histogram must have an open-ended final bucket");
        counts[index] += 1;
    }

    buckets
        .iter()
        .zip(counts)
        .map(|(bucket, count)| ZoneShapeHistogramBucket {
            bucket: bucket.label,
            count,
        })
        .collect()
}

fn rrset_rdata_count_frequencies(rrsets: &ShardedRrsets) -> BTreeMap<usize, usize> {
    let mut frequencies = BTreeMap::new();
    for rrset in rrsets.values() {
        *frequencies.entry(rrset.rdatas.len()).or_insert(0) += 1;
    }
    frequencies
}

fn remove_rrset_from_shape(
    summary: &mut ZoneShapeSummary,
    rdata_count_frequencies: &mut BTreeMap<usize, usize>,
    rrset: &Rrset,
) {
    let rdata_count = rrset.rdatas.len();
    summary.rrset_count = summary.rrset_count.saturating_sub(1);
    summary.rdata_count = summary.rdata_count.saturating_sub(rdata_count);
    summary.rdata_payload_bytes = summary
        .rdata_payload_bytes
        .saturating_sub(rrset.rdatas.iter().map(Vec::len).sum::<usize>());
    summary.name_key_logical_bytes = summary
        .name_key_logical_bytes
        .saturating_sub(rrset.owner.canonical_key().len());
    if rdata_count == 1 {
        summary.single_rdata_rrset_count = summary.single_rdata_rrset_count.saturating_sub(1);
    } else if rdata_count > 1 {
        summary.multi_rdata_rrset_count = summary.multi_rdata_rrset_count.saturating_sub(1);
    }
    if rrset.rdatas.spilled() {
        summary.spilled_rdata_rrset_count = summary.spilled_rdata_rrset_count.saturating_sub(1);
    }
    if let Some(frequency) = rdata_count_frequencies.get_mut(&rdata_count) {
        if *frequency > 1 {
            *frequency -= 1;
        } else {
            rdata_count_frequencies.remove(&rdata_count);
        }
    }
}

fn add_rrset_to_shape(
    summary: &mut ZoneShapeSummary,
    rdata_count_frequencies: &mut BTreeMap<usize, usize>,
    rrset: &Rrset,
) {
    let rdata_count = rrset.rdatas.len();
    summary.rrset_count += 1;
    summary.rdata_count += rdata_count;
    summary.rdata_payload_bytes += rrset.rdatas.iter().map(Vec::len).sum::<usize>();
    summary.name_key_logical_bytes += rrset.owner.canonical_key().len();
    if rdata_count == 1 {
        summary.single_rdata_rrset_count += 1;
    } else if rdata_count > 1 {
        summary.multi_rdata_rrset_count += 1;
    }
    if rrset.rdatas.spilled() {
        summary.spilled_rdata_rrset_count += 1;
    }
    *rdata_count_frequencies.entry(rdata_count).or_insert(0) += 1;
}

fn update_name_shape_membership(
    summary: &mut ZoneShapeSummary,
    name: &str,
    old_owner: bool,
    new_owner: bool,
    old_empty_non_terminal: bool,
    new_empty_non_terminal: bool,
) {
    let name_len = name.len();
    let old_logical_copies = usize::from(old_owner) + usize::from(old_empty_non_terminal);
    let new_logical_copies = usize::from(new_owner) + usize::from(new_empty_non_terminal);
    summary.name_key_logical_bytes = summary
        .name_key_logical_bytes
        .saturating_sub(old_logical_copies.saturating_mul(name_len))
        .saturating_add(new_logical_copies.saturating_mul(name_len));

    match (
        old_owner || old_empty_non_terminal,
        new_owner || new_empty_non_terminal,
    ) {
        (false, true) => summary.name_key_unique_bytes += name_len,
        (true, false) => {
            summary.name_key_unique_bytes = summary.name_key_unique_bytes.saturating_sub(name_len)
        }
        _ => {}
    }
}

fn parent_name_key(name_key: &str) -> Option<String> {
    let without_root = name_key.strip_suffix('.')?;
    let (_, parent) = without_root.split_once('.')?;
    Some(format!("{parent}."))
}

struct ZoneSnapshotIndexes {
    name_classes: NameClassIndex,
    empty_non_terminal_classes: NameClassIndex,
    delegation_rrsets: ShardedRrsetKeys,
    dname_rrsets: ShardedRrsetKeys,
}

#[cfg(test)]
type ClassSet = SmallVec<[u16; 1]>;
type ClassCounts = SmallVec<[(u16, u32); 1]>;
type NameKey = Arc<str>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NameClassIndex {
    InOnly(ShardedInClassCounts),
    MultiClass(ShardedMultiClassCounts),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardedInClassCounts {
    shards: Box<[Arc<HashMap<NameKey, u32>>]>,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardedMultiClassCounts {
    shards: Box<[Arc<HashMap<NameKey, ClassCounts>>]>,
    len: usize,
}

impl NameClassIndex {
    fn in_only() -> Self {
        Self::InOnly(ShardedInClassCounts::new(1))
    }

    fn for_rrsets(rrsets: &ShardedRrsets) -> Self {
        if rrsets.values().all(|rrset| rrset.class == 1) {
            Self::InOnly(ShardedInClassCounts::new(rrsets.shards.len()))
        } else {
            Self::MultiClass(ShardedMultiClassCounts::new(rrsets.shards.len()))
        }
    }

    fn insert(&mut self, name: NameKey, class: u16) {
        if class != 1 && matches!(self, Self::InOnly(_)) {
            self.promote_to_multi_class();
        }
        match self {
            Self::InOnly(counts) => {
                debug_assert_eq!(class, 1);
                counts.increment(name);
            }
            Self::MultiClass(counts) => {
                counts.increment(name, class);
            }
        }
    }

    fn remove(&mut self, name: &str, class: u16) {
        match self {
            Self::InOnly(counts) => {
                debug_assert_eq!(class, 1);
                counts.decrement(name);
            }
            Self::MultiClass(counts) => counts.decrement(name, class),
        }
    }

    fn contains(&self, name: &str, qclass: u16) -> bool {
        match self {
            Self::InOnly(counts) => matches!(qclass, 1 | 255) && counts.contains(name),
            Self::MultiClass(counts) => counts.contains(name, qclass),
        }
    }

    fn contains_name(&self, name: &str) -> bool {
        match self {
            Self::InOnly(counts) => {
                let shard = rrset_shard_index(name, counts.shards.len());
                counts.shards[shard].contains_key(name)
            }
            Self::MultiClass(counts) => {
                let shard = rrset_shard_index(name, counts.shards.len());
                counts.shards[shard].contains_key(name)
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::InOnly(counts) => counts.len,
            Self::MultiClass(counts) => counts.len,
        }
    }

    fn keys(&self) -> impl Iterator<Item = &NameKey> {
        let in_only = match self {
            Self::InOnly(counts) => Some(counts.keys()),
            Self::MultiClass(_) => None,
        };
        let multi_class = match self {
            Self::MultiClass(counts) => Some(counts.keys()),
            Self::InOnly(_) => None,
        };
        in_only
            .into_iter()
            .flatten()
            .chain(multi_class.into_iter().flatten())
    }

    fn value_bytes_saved(&self) -> usize {
        match self {
            Self::InOnly(counts) => counts
                .len
                .saturating_mul(mem::size_of::<SmallVec<[u16; 1]>>()),
            Self::MultiClass(_) => 0,
        }
    }

    fn promote_to_multi_class(&mut self) {
        let Self::InOnly(in_only) = self else {
            return;
        };
        let mut multi = ShardedMultiClassCounts::new(in_only.shards.len());
        for shard in &in_only.shards {
            for (name, count) in shard.iter() {
                multi.insert_count(name.clone(), 1, *count);
            }
        }
        *self = Self::MultiClass(multi);
    }
}

impl ShardedInClassCounts {
    fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count).map(|_| Arc::new(HashMap::new())).collect(),
            len: 0,
        }
    }

    fn increment(&mut self, name: NameKey) {
        let shard = rrset_shard_index(name.as_ref(), self.shards.len());
        let counts = Arc::make_mut(&mut self.shards[shard]);
        let count = counts.entry(name).or_insert(0);
        if *count == 0 {
            self.len += 1;
        }
        *count = count.saturating_add(1);
    }

    fn decrement(&mut self, name: &str) {
        let shard = rrset_shard_index(name, self.shards.len());
        let counts = Arc::make_mut(&mut self.shards[shard]);
        let Some(count) = counts.get_mut(name) else {
            return;
        };
        if *count > 1 {
            *count -= 1;
        } else {
            counts.remove(name);
            self.len -= 1;
        }
    }

    fn contains(&self, name: &str) -> bool {
        let shard = rrset_shard_index(name, self.shards.len());
        self.shards[shard].contains_key(name)
    }

    fn keys(&self) -> impl Iterator<Item = &NameKey> {
        self.shards.iter().flat_map(|shard| shard.keys())
    }
}

impl ShardedMultiClassCounts {
    fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count).map(|_| Arc::new(HashMap::new())).collect(),
            len: 0,
        }
    }

    fn increment(&mut self, name: NameKey, class: u16) {
        self.insert_count(name, class, 1);
    }

    fn insert_count(&mut self, name: NameKey, class: u16, amount: u32) {
        let shard = rrset_shard_index(name.as_ref(), self.shards.len());
        let counts = Arc::make_mut(&mut self.shards[shard]);
        let classes = counts.entry(name).or_insert_with(|| {
            self.len += 1;
            SmallVec::new()
        });
        if let Some((_, count)) = classes.iter_mut().find(|(existing, _)| *existing == class) {
            *count = count.saturating_add(amount);
        } else {
            classes.push((class, amount));
        }
    }

    fn decrement(&mut self, name: &str, class: u16) {
        let shard = rrset_shard_index(name, self.shards.len());
        let counts = Arc::make_mut(&mut self.shards[shard]);
        let Some(classes) = counts.get_mut(name) else {
            return;
        };
        if let Some(index) = classes.iter().position(|(existing, _)| *existing == class) {
            if classes[index].1 > 1 {
                classes[index].1 -= 1;
            } else {
                classes.swap_remove(index);
            }
        }
        if classes.is_empty() {
            counts.remove(name);
            self.len -= 1;
        }
    }

    fn contains(&self, name: &str, qclass: u16) -> bool {
        let shard = rrset_shard_index(name, self.shards.len());
        self.shards[shard].get(name).is_some_and(|classes| {
            qclass == 255 || classes.iter().any(|(class, _)| *class == qclass)
        })
    }

    fn keys(&self) -> impl Iterator<Item = &NameKey> {
        self.shards.iter().flat_map(|shard| shard.keys())
    }
}

impl ZoneSnapshotIndexes {
    fn build(
        origin: &DomainName,
        rrsets: &ShardedRrsets,
        name_interner: &mut NameInterner,
    ) -> Self {
        let mut indexes = Self {
            name_classes: NameClassIndex::for_rrsets(rrsets),
            empty_non_terminal_classes: NameClassIndex::for_rrsets(rrsets),
            delegation_rrsets: ShardedRrsetKeys::new(rrsets.shards.len()),
            dname_rrsets: ShardedRrsetKeys::new(rrsets.shards.len()),
        };
        let origin_key = origin.canonical_key();

        for (key, rrset) in rrsets.iter() {
            indexes.name_classes.insert(key.owner.clone(), rrset.class);
            indexes.index_empty_non_terminals(origin, &rrset.owner, rrset.class, name_interner);

            if rrset.rr_type == RecordType::Ns as u16 && key.owner.as_ref() != origin_key {
                indexes.delegation_rrsets.insert(key.clone());
            } else if rrset.rr_type == RecordType::Dname as u16 {
                indexes.dname_rrsets.insert(key.clone());
            }
        }

        indexes
    }

    fn index_empty_non_terminals(
        &mut self,
        origin: &DomainName,
        owner: &DomainName,
        class: u16,
        name_interner: &mut NameInterner,
    ) {
        let mut parent = owner.parent();
        while let Some(name) = parent {
            if !name.is_equal_or_subdomain_of(origin) {
                break;
            }

            self.empty_non_terminal_classes
                .insert(name_interner.intern_domain(&name), class);

            if name == *origin {
                break;
            }
            parent = name.parent();
        }
    }
}

#[derive(Default)]
struct NameInterner {
    names: HashMap<String, NameKey>,
}

impl NameInterner {
    fn intern_domain(&mut self, name: &DomainName) -> NameKey {
        self.intern(name.canonical_key())
    }

    fn intern(&mut self, name: String) -> NameKey {
        if let Some(existing) = self.names.get(name.as_str()) {
            return existing.clone();
        }

        let interned = NameKey::from(name.as_str());
        self.names.insert(name, interned.clone());
        interned
    }
}

fn soa_timers(rdata: &[u8]) -> Option<SoaTimers> {
    let (_, consumed_mname) = DomainName::parse(rdata, 0).ok()?;
    let rname_offset = consumed_mname;
    let (_, consumed_rname) = DomainName::parse(rdata, rname_offset).ok()?;
    let serial_offset = rname_offset + consumed_rname;
    if serial_offset + 20 != rdata.len() {
        return None;
    }

    Some(SoaTimers {
        refresh: u32::from_be_bytes([
            rdata[serial_offset + 4],
            rdata[serial_offset + 5],
            rdata[serial_offset + 6],
            rdata[serial_offset + 7],
        ]),
        retry: u32::from_be_bytes([
            rdata[serial_offset + 8],
            rdata[serial_offset + 9],
            rdata[serial_offset + 10],
            rdata[serial_offset + 11],
        ]),
        expire: u32::from_be_bytes([
            rdata[serial_offset + 12],
            rdata[serial_offset + 13],
            rdata[serial_offset + 14],
            rdata[serial_offset + 15],
        ]),
        minimum: u32::from_be_bytes([
            rdata[serial_offset + 16],
            rdata[serial_offset + 17],
            rdata[serial_offset + 18],
            rdata[serial_offset + 19],
        ]),
    })
}

fn rrsig_type_covered(rdata: &[u8]) -> Option<u16> {
    (rdata.len() >= 2).then(|| u16::from_be_bytes([rdata[0], rdata[1]]))
}

fn nsec_covers_name(owner: &DomainName, rdata: &[u8], name: &DomainName) -> bool {
    let Ok((next_owner, _)) = DomainName::parse(rdata, 0) else {
        return false;
    };
    canonical_nsec_range_covers(owner, &next_owner, name)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Nsec3Params {
    hash_algorithm: u8,
    iterations: u16,
    salt: Vec<u8>,
}

impl DenialIndexes {
    fn build(rrsets: &ShardedRrsets, origin: &DomainName) -> Self {
        let mut indexes = Self::default();
        for (key, rrset) in rrsets.iter() {
            indexes.insert_rrset(key, rrset, origin);
        }
        indexes
    }

    fn updated(
        &self,
        previous: &ShardedRrsets,
        current: &ShardedRrsets,
        origin: &DomainName,
    ) -> Self {
        if previous.shards.len() != current.shards.len() {
            return Self::build(current, origin);
        }
        let mut indexes = self.clone();
        for (old_shard, current_shard) in previous.shards.iter().zip(&current.shards) {
            if Arc::ptr_eq(old_shard, current_shard) {
                continue;
            }
            for (key, old_rrset) in old_shard.iter() {
                if !is_denial_rr_type(old_rrset.rr_type) {
                    continue;
                }
                if current_shard.get(key) != Some(old_rrset) {
                    indexes.remove_rrset(key, old_rrset, origin);
                    if let Some(new_rrset) = current_shard.get(key) {
                        indexes.insert_rrset(key, new_rrset, origin);
                    }
                }
            }
            for (key, rrset) in current_shard.iter() {
                if is_denial_rr_type(rrset.rr_type) && !old_shard.contains_key(key) {
                    indexes.insert_rrset(key, rrset, origin);
                }
            }
        }
        indexes
    }

    fn insert_rrset(&mut self, key: &RrsetKey, rrset: &Rrset, origin: &DomainName) {
        if rrset.rr_type == RecordType::Nsec as u16 {
            self.nsec.insert(
                NsecOrderKey {
                    class: rrset.class,
                    owner: canonical_order_key(&rrset.owner),
                },
                key.clone(),
            );
        } else if rrset.rr_type == RecordType::Nsec3 as u16 {
            let Some(owner_hash) = nsec3_owner_hash_label(&rrset.owner, origin) else {
                return;
            };
            for rdata in &rrset.rdatas {
                let Some(params) = nsec3_params_from_rdata(rdata) else {
                    continue;
                };
                self.nsec3.insert(
                    Nsec3OrderKey {
                        class: rrset.class,
                        params: params.clone(),
                        owner_hash: owner_hash.clone(),
                    },
                    key.clone(),
                );
                let counts = Arc::make_mut(&mut self.nsec3_param_counts);
                *counts.entry((rrset.class, params)).or_insert(0) += 1;
            }
        }
    }

    fn remove_rrset(&mut self, _key: &RrsetKey, rrset: &Rrset, origin: &DomainName) {
        if rrset.rr_type == RecordType::Nsec as u16 {
            self.nsec.remove(&NsecOrderKey {
                class: rrset.class,
                owner: canonical_order_key(&rrset.owner),
            });
        } else if rrset.rr_type == RecordType::Nsec3 as u16 {
            let Some(owner_hash) = nsec3_owner_hash_label(&rrset.owner, origin) else {
                return;
            };
            for rdata in &rrset.rdatas {
                let Some(params) = nsec3_params_from_rdata(rdata) else {
                    continue;
                };
                self.nsec3.remove(&Nsec3OrderKey {
                    class: rrset.class,
                    params: params.clone(),
                    owner_hash: owner_hash.clone(),
                });
                let counts = Arc::make_mut(&mut self.nsec3_param_counts);
                if let Some(count) = counts.get_mut(&(rrset.class, params.clone())) {
                    if *count > 1 {
                        *count -= 1;
                    } else {
                        counts.remove(&(rrset.class, params));
                    }
                }
            }
        }
    }

    fn nsec_candidate(&self, name: &DomainName, class: u16) -> Option<&RrsetKey> {
        let target = NsecOrderKey {
            class,
            owner: canonical_order_key(name),
        };
        if let Some((key, value)) = self.nsec.predecessor(&target)
            && key.class == class
        {
            return Some(value);
        }
        let upper = NsecOrderKey {
            class: class.saturating_add(1),
            owner: Vec::new(),
        };
        self.nsec
            .last_before(&upper)
            .and_then(|(key, value)| (key.class == class).then_some(value))
    }

    fn nsec3_candidate(&self, hash: &str, class: u16, params: &Nsec3Params) -> Option<&RrsetKey> {
        let target = Nsec3OrderKey {
            class,
            params: params.clone(),
            owner_hash: hash.to_owned(),
        };
        if let Some((key, value)) = self.nsec3.predecessor(&target)
            && key.class == class
            && key.params == *params
        {
            return Some(value);
        }
        let upper = Nsec3OrderKey {
            class,
            params: params.clone(),
            owner_hash: "\u{7f}".to_owned(),
        };
        self.nsec3
            .last_before(&upper)
            .and_then(|(key, value)| (key.class == class && key.params == *params).then_some(value))
    }
}

fn is_denial_rr_type(rr_type: u16) -> bool {
    rr_type == RecordType::Nsec as u16 || rr_type == RecordType::Nsec3 as u16
}

fn nsec3_params_from_rdata(rdata: &[u8]) -> Option<Nsec3Params> {
    if rdata.len() < 5 {
        return None;
    }
    let salt_len = rdata[4] as usize;
    if rdata.len() < 5 + salt_len + 1 {
        return None;
    }
    Some(Nsec3Params {
        hash_algorithm: rdata[0],
        iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
        salt: rdata[5..5 + salt_len].to_vec(),
    })
}

fn nsec3param_params_from_rdata(rdata: &[u8]) -> Option<Nsec3Params> {
    if rdata.len() < 5 || rdata[1] != 0 {
        return None;
    }
    let salt_len = rdata[4] as usize;
    (rdata.len() == 5 + salt_len).then(|| Nsec3Params {
        hash_algorithm: rdata[0],
        iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
        salt: rdata[5..].to_vec(),
    })
}

fn nsec3_next_hash_label(rdata: &[u8]) -> Option<String> {
    let params = nsec3_params_from_rdata(rdata)?;
    let hash_len_offset = 5 + params.salt.len();
    let hash_len = *rdata.get(hash_len_offset)? as usize;
    let hash_start = hash_len_offset + 1;
    let hash_end = hash_start.checked_add(hash_len)?;
    (hash_end <= rdata.len()).then(|| base32hex_no_padding_lower(&rdata[hash_start..hash_end]))
}

fn nsec3_hash_name(name: &DomainName, params: &Nsec3Params) -> Option<String> {
    if params.hash_algorithm != 1 {
        return None;
    }
    let canonical = DomainName::from_absolute_str(&name.canonical_key())
        .ok()?
        .to_wire();
    let mut digest = Sha1::new();
    digest.update(&canonical);
    digest.update(&params.salt);
    let mut hash = digest.finalize().to_vec();
    for _ in 0..params.iterations {
        let mut digest = Sha1::new();
        digest.update(&hash);
        digest.update(&params.salt);
        hash = digest.finalize().to_vec();
    }
    Some(base32hex_no_padding_lower(&hash))
}

fn nsec3_owner_hash_label(owner: &DomainName, origin: &DomainName) -> Option<String> {
    let owner_key = owner.canonical_key();
    let origin_key = origin.canonical_key();
    let prefix = owner_key.strip_suffix(&origin_key)?;
    let hash_label = prefix.strip_suffix('.')?;
    (!hash_label.is_empty() && !hash_label.contains('.')).then(|| hash_label.to_owned())
}

fn nsec3_range_covers_hash(owner_hash: &str, next_hash: &str, hash: &str) -> bool {
    if owner_hash < next_hash {
        owner_hash < hash && hash < next_hash
    } else if owner_hash > next_hash {
        owner_hash < hash || hash < next_hash
    } else {
        hash != owner_hash
    }
}

fn base32hex_no_padding_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

fn canonical_nsec_range_covers(
    owner: &DomainName,
    next_owner: &DomainName,
    name: &DomainName,
) -> bool {
    let owner_key = canonical_order_key(owner);
    let next_key = canonical_order_key(&next_owner);
    let name_key = canonical_order_key(name);
    if owner_key < next_key {
        owner_key < name_key && name_key < next_key
    } else {
        owner_key < name_key || name_key < next_key
    }
}

fn next_closer_name(qname: &DomainName, closest_encloser: &DomainName) -> Option<DomainName> {
    let mut candidate = qname.clone();
    loop {
        let parent = candidate.parent()?;
        if parent == *closest_encloser {
            return Some(candidate);
        }
        candidate = parent;
    }
}

fn canonical_order_key(name: &DomainName) -> Vec<u8> {
    let mut key = Vec::with_capacity(name.wire_len());
    for label in name.labels().iter().rev() {
        key.push(label.len() as u8);
        key.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    key.push(0);
    key
}

fn record_identity(record: &ResourceRecord) -> (String, u16, u16, Vec<u8>) {
    (
        record.owner.canonical_key(),
        record.rr_type,
        record.class,
        record.rdata.clone(),
    )
}

fn push_rrset_records(
    rrset: &Rrset,
    records: &mut Vec<ResourceRecord>,
    seen: &mut HashSet<(String, u16, u16, Vec<u8>)>,
    dnssec_augmented: &mut bool,
) {
    for record in rrset.records() {
        if seen.insert(record_identity(&record)) {
            records.push(record);
            *dnssec_augmented = true;
        }
    }
}

fn is_dnssec_proof_or_signature_type(rr_type: u16) -> bool {
    rr_type == RecordType::Rrsig as u16
        || rr_type == RecordType::Nsec as u16
        || rr_type == RecordType::Nsec3 as u16
}

fn is_dnssec_rr_type(rr_type: u16) -> bool {
    matches!(
        rr_type,
        value if value == RecordType::Ds as u16
            || value == RecordType::Rrsig as u16
            || value == RecordType::Nsec as u16
            || value == RecordType::Dnskey as u16
            || value == RecordType::Nsec3 as u16
            || value == RecordType::Nsec3Param as u16
    )
}

fn cname_target(record: &ResourceRecord) -> Option<DomainName> {
    parse_single_name_rdata(record)
}

fn ns_target(record: &ResourceRecord) -> Option<DomainName> {
    parse_single_name_rdata(record)
}

fn dname_target(record: &ResourceRecord) -> Option<DomainName> {
    parse_single_name_rdata(record)
}

fn additional_address_target(record: &ResourceRecord) -> Option<DomainName> {
    match record.rr_type {
        rr_type if rr_type == RecordType::Ns as u16 => ns_target(record),
        rr_type if rr_type == RecordType::Mx as u16 => mx_exchange(record),
        rr_type if rr_type == RecordType::Srv as u16 => srv_target(record),
        rr_type if rr_type == RecordType::Naptr as u16 => naptr_replacement(record),
        rr_type if rr_type == RecordType::Svcb as u16 || rr_type == RecordType::Https as u16 => {
            let target = svcb_target_name(record)?;
            let priority = u16::from_be_bytes([record.rdata[0], record.rdata[1]]);
            if priority != 0 && target.label_count() == 0 {
                Some(record.owner.clone())
            } else {
                Some(target)
            }
        }
        _ => None,
    }
}

fn mx_exchange(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 3 {
        return None;
    }

    let (exchange, consumed) = DomainName::parse(&record.rdata, 2).ok()?;
    if 2 + consumed == record.rdata.len() {
        Some(exchange)
    } else {
        None
    }
}

fn srv_target(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 7 {
        return None;
    }

    let (target, consumed) = DomainName::parse(&record.rdata, 6).ok()?;
    if 6 + consumed == record.rdata.len() {
        Some(target)
    } else {
        None
    }
}

fn naptr_replacement(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 7 {
        return None;
    }

    let mut offset = 4;
    for _ in 0..3 {
        offset = skip_character_string(&record.rdata, offset)?;
    }

    let (replacement, consumed) = DomainName::parse(&record.rdata, offset).ok()?;
    if offset + consumed == record.rdata.len() {
        Some(replacement)
    } else {
        None
    }
}

fn svcb_target_name(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 3 {
        return None;
    }

    let (target, consumed) = DomainName::parse(&record.rdata, 2).ok()?;
    if 2 + consumed <= record.rdata.len() {
        Some(target)
    } else {
        None
    }
}

fn skip_character_string(rdata: &[u8], offset: usize) -> Option<usize> {
    let len = *rdata.get(offset)? as usize;
    let next = offset.checked_add(1)?.checked_add(len)?;
    if next <= rdata.len() {
        Some(next)
    } else {
        None
    }
}

fn parse_single_name_rdata(record: &ResourceRecord) -> Option<DomainName> {
    let (target, consumed) = DomainName::parse(&record.rdata, 0).ok()?;
    if consumed == record.rdata.len() {
        Some(target)
    } else {
        None
    }
}

#[derive(Debug, Clone, Default)]
struct ZoneDirectory {
    by_origin: HashMap<String, Arc<ZoneStoreEntry>>,
    suffix_index: HashMap<Vec<u8>, Arc<ZoneStoreEntry>>,
    active_count: usize,
}

#[derive(Debug, Clone)]
pub struct ZoneStore {
    zones: Arc<ArcSwap<ZoneDirectory>>,
    publish_lock: Arc<Mutex<()>>,
    next_incarnation: Arc<AtomicU64>,
    publication_policy: ZonePublicationPolicy,
    compacting_zones: Arc<Mutex<HashSet<String>>>,
    #[cfg(test)]
    publication_clone_work: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct PublishedZone {
    entry: Arc<ZoneStoreEntry>,
}

#[derive(Debug, Clone, Copy)]
pub struct PublishedZoneRef<'a> {
    entry: &'a ZoneStoreEntry,
}

#[derive(Debug, Clone)]
pub struct TransferZoneSnapshot {
    snapshot: Arc<ZoneSnapshot>,
    installed_snapshot: Arc<ZoneSnapshot>,
    metadata: ZoneMetadata,
}

#[derive(Debug, Clone)]
pub struct OfflineZoneSnapshot {
    snapshot: Arc<ZoneSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneMetadata {
    pub origin: DomainName,
    pub origin_key: Arc<str>,
    pub origin_name: Arc<str>,
    pub state: ZoneState,
    pub serial: Option<u32>,
    pub soa_timers: Option<SoaTimers>,
    pub shape: Option<ZoneShapeSummary>,
    pub shape_histograms: Option<ZoneShapeHistogramSummary>,
    pub zone_image_stats: Option<ZoneImageStats>,
}

impl TransferZoneSnapshot {
    /// Return cached control metadata for scalar transfer decisions.
    pub fn metadata(&self) -> &ZoneMetadata {
        &self.metadata
    }

    /// Consume the transfer view and return cached control metadata.
    pub fn into_metadata(self) -> ZoneMetadata {
        self.metadata
    }

    /// Borrow the old snapshot layout only for transfer/oracle work that still
    /// genuinely needs builder-state records.
    pub fn snapshot_for_transfer(&self) -> &ZoneSnapshot {
        &self.snapshot
    }

    /// Return the shared old-layout handle for tests and identity checks.
    pub fn snapshot_arc_for_transfer(&self) -> &Arc<ZoneSnapshot> {
        &self.snapshot
    }
}

impl OfflineZoneSnapshot {
    /// Return the offline snapshot origin.
    pub fn origin(&self) -> &DomainName {
        &self.snapshot.origin
    }

    /// Return the offline snapshot publication state.
    pub fn state(&self) -> ZoneState {
        self.snapshot.state
    }

    /// Return the offline snapshot serial.
    pub fn serial(&self) -> Option<u32> {
        self.snapshot.serial
    }

    /// Borrow the old snapshot layout only for offline oracle/baseline work.
    pub fn snapshot_for_offline_oracle(&self) -> &ZoneSnapshot {
        &self.snapshot
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CatalogZoneView<'a> {
    origin: &'a DomainName,
    rrsets: &'a ShardedRrsets,
}

impl<'a> CatalogZoneView<'a> {
    pub fn origin(&self) -> &'a DomainName {
        self.origin
    }

    pub(crate) fn rrsets(&self) -> impl Iterator<Item = &'a Rrset> {
        self.rrsets.values()
    }
}

#[derive(Debug)]
struct ZoneStoreEntry {
    origin: DomainName,
    origin_label_count: usize,
    origin_key: Arc<str>,
    origin_name: Arc<str>,
    state: ZoneState,
    serial: Option<u32>,
    soa_timers: Option<SoaTimers>,
    snapshot: Arc<ZoneSnapshot>,
    image: Option<Arc<ZoneImage>>,
    image_snapshot: Option<Arc<ZoneSnapshot>>,
    overlay_dirty: Option<Arc<ZoneOverlayDirty>>,
    shape: Option<ZoneShapeSummary>,
    shape_histograms: Option<ZoneShapeHistogramSummary>,
    hidden: bool,
    incarnation: u64,
}

impl Default for ZoneStore {
    fn default() -> Self {
        Self {
            zones: Arc::new(ArcSwap::from_pointee(ZoneDirectory::default())),
            publish_lock: Arc::new(Mutex::new(())),
            next_incarnation: Arc::new(AtomicU64::new(0)),
            publication_policy: ZonePublicationPolicy::default(),
            compacting_zones: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(test)]
            publication_clone_work: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ZoneStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_publication_policy(publication_policy: ZonePublicationPolicy) -> Self {
        Self {
            publication_policy,
            ..Self::default()
        }
    }

    pub fn overlay_compaction_due(&self, origin: &DomainName) -> bool {
        let threshold = self
            .publication_policy
            .overlay_compaction_dirty_owner_threshold;
        if threshold == 0 {
            return false;
        }
        self.zones
            .load()
            .get(&origin.canonical_key())
            .and_then(|entry| entry.overlay_dirty.as_deref())
            .is_some_and(|dirty| dirty.changed_owners.len >= threshold)
    }

    /// Compile a new compact base outside the publication lock, then rebase
    /// any IXFRs that arrived during compilation onto that base. At most two
    /// passes are attempted so a continuously changing zone cannot monopolize
    /// a blocking worker indefinitely.
    pub fn compact_overlay_if_due(
        &self,
        origin: &DomainName,
    ) -> Result<ZoneOverlayCompactionOutcome, ZoneImageBuildError> {
        let key = origin.canonical_key();
        {
            let mut running = self
                .compacting_zones
                .lock()
                .expect("zone compaction set lock poisoned");
            if !running.insert(key.clone()) {
                return Ok(ZoneOverlayCompactionOutcome::AlreadyRunning);
            }
        }

        let result = (|| {
            let mut outcome = ZoneOverlayCompactionOutcome::NotNeeded;
            for _ in 0..2 {
                outcome = self.compact_overlay_once_if_due(&key)?;
                let ZoneOverlayCompactionOutcome::Compacted {
                    remaining_dirty_owners,
                } = outcome
                else {
                    break;
                };
                let threshold = self
                    .publication_policy
                    .overlay_compaction_dirty_owner_threshold;
                if threshold == 0 || remaining_dirty_owners < threshold {
                    break;
                }
            }
            Ok(outcome)
        })();

        self.compacting_zones
            .lock()
            .expect("zone compaction set lock poisoned")
            .remove(&key);
        result
    }

    fn compact_overlay_once_if_due(
        &self,
        key: &str,
    ) -> Result<ZoneOverlayCompactionOutcome, ZoneImageBuildError> {
        let threshold = self
            .publication_policy
            .overlay_compaction_dirty_owner_threshold;
        if threshold == 0 {
            return Ok(ZoneOverlayCompactionOutcome::NotNeeded);
        }
        let candidate = {
            let directory = self.zones.load();
            let Some(entry) = directory.get(key) else {
                return Ok(ZoneOverlayCompactionOutcome::Obsolete);
            };
            let Some(dirty) = entry.overlay_dirty.as_deref() else {
                return Ok(ZoneOverlayCompactionOutcome::NotNeeded);
            };
            if dirty.changed_owners.len < threshold {
                return Ok(ZoneOverlayCompactionOutcome::NotNeeded);
            }
            (entry.snapshot.clone(), entry.incarnation)
        };

        let compact_image = Arc::new(ZoneImage::compile(&candidate.0)?);
        Ok(self.publish_compacted_base(key, &candidate.0, candidate.1, compact_image))
    }

    fn publish_compacted_base(
        &self,
        key: &str,
        candidate_snapshot: &Arc<ZoneSnapshot>,
        candidate_incarnation: u64,
        compact_image: Arc<ZoneImage>,
    ) -> ZoneOverlayCompactionOutcome {
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current_directory = self.zones.load_full();
        let Some(current) = current_directory.get(key) else {
            return ZoneOverlayCompactionOutcome::Obsolete;
        };
        if current.incarnation != candidate_incarnation
            || current.state != ZoneState::Active
            || current.overlay_dirty.is_none()
        {
            return ZoneOverlayCompactionOutcome::Obsolete;
        }

        let Some(changes) = current.snapshot.changed_rrset_keys_from(candidate_snapshot) else {
            return ZoneOverlayCompactionOutcome::Obsolete;
        };
        let overlay_dirty = (!changes.is_empty()).then(|| {
            Arc::new(ZoneOverlayDirty::with_changes(
                None,
                &changes,
                key,
                current.snapshot.rrsets.shards.len(),
                &current.snapshot,
                candidate_snapshot,
                &compact_image,
            ))
        });
        let remaining_dirty_owners = overlay_dirty
            .as_deref()
            .map_or(0, |dirty| dirty.changed_owners.len);
        let replacement = Arc::new(ZoneStoreEntry {
            origin: current.origin.clone(),
            origin_label_count: current.origin_label_count,
            origin_key: current.origin_key.clone(),
            origin_name: current.origin_name.clone(),
            state: current.state,
            serial: current.serial,
            soa_timers: current.soa_timers,
            snapshot: current.snapshot.clone(),
            image: Some(compact_image),
            image_snapshot: Some(candidate_snapshot.clone()),
            overlay_dirty,
            shape: current.shape,
            shape_histograms: None,
            hidden: current.hidden,
            incarnation: current.incarnation,
        });
        let mut next = self.clone_directory_for_publication(current_directory.as_ref());
        next.insert(key.to_owned(), replacement);
        self.zones.store(Arc::new(next));
        info!(
            event = "zone_overlay_compacted",
            zone = %current.origin,
            remaining_dirty_owners,
            "rebased incremental zone overlay onto a newly compiled compact image"
        );
        ZoneOverlayCompactionOutcome::Compacted {
            remaining_dirty_owners,
        }
    }

    pub fn insert_loading(&self, origin: DomainName) {
        let snapshot = Arc::new(ZoneSnapshot::loading(origin));
        self.replace_snapshot(snapshot, false);
    }

    pub fn insert_loading_hidden(&self, origin: DomainName) {
        let snapshot = Arc::new(ZoneSnapshot::loading(origin));
        self.replace_snapshot(snapshot, true);
    }

    /// Publish many initial LOADING zones with one copy-on-write directory
    /// update. This keeps startup and catalog-scale provisioning linear in the
    /// number of zones rather than cloning the growing directory per zone.
    pub fn insert_loading_batch(&self, visible: &[DomainName], hidden: &[DomainName]) {
        let mut loading = Vec::with_capacity(visible.len().saturating_add(hidden.len()));
        loading.extend_from_slice(visible);
        loading.extend_from_slice(hidden);
        self.apply_atomic_directory_update(&loading, &[], &[], hidden);
    }

    /// Atomically publish a set of query-visible directory changes.
    ///
    /// Catalog reconciliation stages policy and lifecycle bookkeeping outside
    /// the query path, then uses this single directory swap so readers observe
    /// either the complete old membership or the complete new membership.
    pub fn apply_atomic_directory_update(
        &self,
        loading_origins: &[DomainName],
        removed_origins: &[DomainName],
        visible_origins: &[DomainName],
        hidden_origins: &[DomainName],
    ) {
        if loading_origins.is_empty()
            && removed_origins.is_empty()
            && visible_origins.is_empty()
            && hidden_origins.is_empty()
        {
            return;
        }

        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current = self.zones.load_full();
        let mut next = self.clone_directory_for_publication(current.as_ref());
        let hidden_loading = hidden_origins
            .iter()
            .map(DomainName::canonical_key)
            .collect::<HashSet<_>>();

        for origin in removed_origins {
            next.remove(&origin.canonical_key());
        }
        for origin in loading_origins {
            let snapshot = Arc::new(ZoneSnapshot::loading(origin.clone()));
            let key = origin.canonical_key();
            let incarnation = next
                .get(&key)
                .map(|entry| entry.incarnation)
                .unwrap_or_else(|| self.allocate_incarnation());
            let entry = Arc::new(
                ZoneStoreEntry::try_new(
                    key.clone(),
                    snapshot,
                    hidden_loading.contains(key.as_str()),
                    incarnation,
                )
                .expect("loading zone image construction cannot fail"),
            );
            next.insert(key, entry);
        }
        for (origins, hidden) in [(visible_origins, false), (hidden_origins, true)] {
            for origin in origins {
                let key = origin.canonical_key();
                if let Some(entry) = next.get(&key)
                    && entry.hidden != hidden
                {
                    next.insert(key, Arc::new(entry.with_hidden(hidden)));
                }
            }
        }

        self.zones.store(Arc::new(next));
    }

    pub fn insert_snapshot(&self, snapshot: ZoneSnapshot) {
        let snapshot = Arc::new(snapshot);
        self.replace_snapshot(snapshot, false);
    }

    /// Publish a transfer-built snapshot that already has shared ownership.
    ///
    /// This is for transfer/catalog control paths that need to publish the
    /// snapshot and retain a handle for follow-up control work without cloning
    /// the full old layout.
    pub fn insert_snapshot_arc_for_transfer(
        &self,
        snapshot: Arc<ZoneSnapshot>,
    ) -> Result<ZoneMetadata, ZoneImageBuildError> {
        self.try_replace_snapshot(snapshot, false)
            .map(|entry| entry.control_metadata())
    }

    pub fn remove_zone(&self, origin: &DomainName) -> bool {
        let key = origin.canonical_key();
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current = self.zones.load_full();
        if !current.contains_key(&key) {
            return false;
        }

        let mut next = self.clone_directory_for_publication(current.as_ref());
        next.remove(&key);
        self.zones.store(Arc::new(next));
        true
    }

    pub fn hide_zone(&self, origin: &DomainName) {
        self.set_hidden(origin, true);
    }

    pub fn show_zone(&self, origin: &DomainName) {
        self.set_hidden(origin, false);
    }

    pub fn is_hidden(&self, origin: &DomainName) -> bool {
        self.zones
            .load()
            .get(&origin.canonical_key())
            .is_some_and(|entry| entry.hidden)
    }

    pub fn expire_zone(&self, origin: &DomainName) -> bool {
        let key = origin.canonical_key();
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current = self.zones.load_full();
        let Some(entry) = current.get(&key) else {
            return false;
        };
        if entry.state == ZoneState::Expired {
            return false;
        }

        let mut next = self.clone_directory_for_publication(current.as_ref());
        next.insert(key, Arc::new(entry.with_state(ZoneState::Expired)));
        self.zones.store(Arc::new(next));
        true
    }

    /// Expire `current` only while the exact snapshot captured by the caller is
    /// still installed for its origin.
    ///
    /// Refresh lifecycle code uses this compare-and-publish boundary so a
    /// catalog remove/re-add cannot let an expiration decision made for the old
    /// incarnation mutate the replacement zone entry.
    pub fn expire_zone_if_snapshot(&self, current: &TransferZoneSnapshot) -> bool {
        let key = current.metadata.origin_key.as_ref();
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let directory = self.zones.load_full();
        let Some(entry) = directory.get(key) else {
            return false;
        };
        if entry.state == ZoneState::Expired || !Arc::ptr_eq(&entry.snapshot, &current.snapshot) {
            return false;
        }

        let mut next = self.clone_directory_for_publication(directory.as_ref());
        next.insert(
            key.to_owned(),
            Arc::new(entry.with_state(ZoneState::Expired)),
        );
        self.zones.store(Arc::new(next));
        true
    }

    /// Confirm that `current` is still the installed snapshot and make it
    /// query-active again when it was previously expired.
    ///
    /// A successful SOA/IXFR current response is a successful refresh even when
    /// the held serial did not change. The refresh path uses this atomic
    /// compare-and-publish operation so an EXPIRED zone can return to ACTIVE
    /// without allowing a remove/re-add or replacement snapshot to be revived.
    pub fn activate_zone_if_snapshot(
        &self,
        current: &TransferZoneSnapshot,
    ) -> Result<Option<ZoneMetadata>, ZoneImageBuildError> {
        let key = current.metadata.origin_key.as_ref();
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let directory = self.zones.load_full();
        let Some(entry) = directory.get(key) else {
            return Ok(None);
        };
        if !Arc::ptr_eq(&entry.snapshot, &current.installed_snapshot) {
            return Ok(None);
        }
        if entry.state == ZoneState::Active {
            return Ok(Some(entry.control_metadata()));
        }
        if entry.state != ZoneState::Expired {
            return Ok(None);
        }

        // Expiration changes only the directory entry's serving state, leaving
        // the last validated ACTIVE snapshot intact. Rebuild its query image
        // while holding the same publication lock used for the identity check.
        let active_snapshot = if current.installed_snapshot.state == ZoneState::Active {
            current.installed_snapshot.clone()
        } else {
            Arc::new(current.installed_snapshot.with_state(ZoneState::Active))
        };
        let active_entry = Arc::new(ZoneStoreEntry::try_new(
            key.to_owned(),
            active_snapshot,
            entry.hidden,
            entry.incarnation,
        )?);
        let metadata = active_entry.control_metadata();
        let mut next = self.clone_directory_for_publication(directory.as_ref());
        next.insert(key.to_owned(), active_entry);
        self.zones.store(Arc::new(next));
        Ok(Some(metadata))
    }

    /// Return the exact-origin snapshot plus cached control metadata for IXFR
    /// transfer work that still genuinely needs the old builder/oracle layout.
    pub fn exact_snapshot_for_transfer(&self, origin: &DomainName) -> Option<TransferZoneSnapshot> {
        self.zones
            .load()
            .get(&origin.canonical_key())
            .map(|entry| TransferZoneSnapshot {
                snapshot: entry.snapshot_for_control(),
                installed_snapshot: entry.snapshot.clone(),
                metadata: entry.control_metadata(),
            })
    }

    /// Return the exact-origin snapshot for IXFR transfer work only when the
    /// cached control metadata has a serial that can seed an IXFR query.
    pub fn exact_snapshot_with_serial_for_transfer(
        &self,
        origin: &DomainName,
    ) -> Option<TransferZoneSnapshot> {
        self.zones
            .load()
            .get(&origin.canonical_key())
            .filter(|entry| entry.serial.is_some())
            .map(|entry| TransferZoneSnapshot {
                snapshot: entry.snapshot_for_control(),
                installed_snapshot: entry.snapshot.clone(),
                metadata: entry.control_metadata(),
            })
    }

    /// Check exact-origin presence for transfer/catalog/NOTIFY control work
    /// without cloning the underlying snapshot. Query serving should use
    /// `find_published_zone` and answer from the published `ZoneImage`.
    pub fn contains_exact_zone_for_control(&self, origin: &DomainName) -> bool {
        self.zones.load().contains_key(&origin.canonical_key())
    }

    /// Return exact-origin metadata without cloning the underlying snapshot.
    pub fn exact_zone_metadata(&self, origin: &DomainName) -> Option<ZoneMetadata> {
        self.zones
            .load()
            .get(&origin.canonical_key())
            .map(|entry| entry.metadata())
    }

    /// Return exact-origin control metadata without status-only shape fields.
    pub fn exact_zone_control_metadata(&self, origin: &DomainName) -> Option<ZoneMetadata> {
        self.zones
            .load()
            .get(&origin.canonical_key())
            .map(|entry| entry.control_metadata())
    }

    pub fn find_published_zone(&self, qname: &DomainName) -> Option<PublishedZone> {
        self.find_published_zone_with_ascii_lowercase_hint(qname, false)
    }

    /// Return the most-specific published zone for a query name.
    ///
    /// Set `qname_ascii_lowercase` only when the caller already proved every
    /// query-name label byte is lowercase ASCII, for example while parsing the
    /// DNS packet. Call `find_published_zone` when that fact is not available.
    pub fn find_published_zone_with_ascii_lowercase_hint(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<PublishedZone> {
        let zones = self.zones.load();
        zones
            .find_best_match(qname, qname_ascii_lowercase)
            .map(|entry| PublishedZone { entry })
    }

    /// Return whether `published` still belongs to the current lifecycle
    /// incarnation for its origin.
    ///
    /// Snapshot and serving-state publications replace the directory entry's
    /// `Arc` while preserving its incarnation. Consumers that retain a
    /// published-zone handle across another subsystem's lock acquisition must
    /// accept those ordinary refreshes, but reject an incarnation removed and
    /// re-added in the meantime.
    pub fn is_current_published_zone(&self, published: &PublishedZone) -> bool {
        self.is_current_zone_incarnation(published.origin_key(), published.incarnation())
    }

    /// Check the current exact-origin incarnation, including non-serving
    /// LOADING and EXPIRED entries.
    pub fn is_current_zone_incarnation(&self, origin_key: &str, incarnation: u64) -> bool {
        self.zones
            .load()
            .get(origin_key)
            .is_some_and(|entry| entry.incarnation == incarnation)
    }

    /// Borrow the most-specific published zone for the duration of `visit`.
    ///
    /// This avoids cloning the underlying published-zone handle on hot query
    /// paths while keeping the loaded directory snapshot alive for the closure.
    pub fn with_published_zone_with_ascii_lowercase_hint<R>(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
        visit: impl FnOnce(PublishedZoneRef<'_>) -> R,
    ) -> Option<R> {
        let zones = self.zones.load();
        let entry = zones.find_best_match_ref(qname, qname_ascii_lowercase)?;
        Some(visit(PublishedZoneRef { entry }))
    }

    /// Borrow the query's published zone, optionally preferring the closest
    /// visible strict parent when the query name is an exact published origin.
    ///
    /// RFC 4035 places a child-apex DS RRset in the parent zone. Query serving
    /// uses this only for DS when both the child and its parent are configured
    /// locally; ordinary queries continue to use longest-zone matching.
    pub fn with_published_zone_for_query_with_ascii_lowercase_hint<R>(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
        prefer_parent_of_exact_child: bool,
        visit: impl FnOnce(PublishedZoneRef<'_>) -> R,
    ) -> Option<R> {
        let zones = self.zones.load();
        let entry = prefer_parent_of_exact_child
            .then(|| zones.find_parent_of_exact_match_ref(qname, qname_ascii_lowercase))
            .flatten()
            .or_else(|| zones.find_best_match_ref(qname, qname_ascii_lowercase))?;
        Some(visit(PublishedZoneRef { entry }))
    }

    /// Return cheap published-zone metadata for status and metrics without
    /// cloning the underlying snapshots. Query serving should use
    /// `find_published_zone` and answer from the published `ZoneImage`.
    pub fn zone_metadata(&self) -> Vec<ZoneMetadata> {
        let zones = self.zones.load();
        let mut entries = zones.values().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.origin_key.cmp(&right.origin_key));
        entries.into_iter().map(|entry| entry.metadata()).collect()
    }

    /// Return metadata only for zones visible on the authoritative query
    /// interface. Hidden catalog snapshots remain available to control and
    /// observability paths through `zone_metadata`, but must not satisfy
    /// serving-readiness checks or served-zone aggregate gauges.
    pub fn published_zone_metadata(&self) -> Vec<ZoneMetadata> {
        let zones = self.zones.load();
        let mut entries = zones
            .values()
            .filter(|entry| !entry.hidden)
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.origin_key.cmp(&right.origin_key));
        entries.into_iter().map(|entry| entry.metadata()).collect()
    }

    /// Return all snapshots for offline evidence collection and test oracles.
    /// Query serving, status, metrics, and catalog membership paths should use
    /// narrower published-zone, metadata, or exact-presence views.
    pub fn offline_snapshots(&self) -> Vec<OfflineZoneSnapshot> {
        let zones = self.zones.load();
        let mut entries = zones.values().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.origin_key.cmp(&right.origin_key));
        entries
            .into_iter()
            .map(|entry| OfflineZoneSnapshot {
                snapshot: entry.snapshot_for_control(),
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.zones.load().len()
    }

    pub fn active_count(&self) -> usize {
        self.zones.load().active_count()
    }

    pub fn has_active_zone(&self) -> bool {
        self.active_count() > 0
    }

    pub fn is_empty(&self) -> bool {
        self.zones.load().is_empty()
    }

    fn replace_snapshot(
        &self,
        snapshot: Arc<ZoneSnapshot>,
        force_hidden: bool,
    ) -> Arc<ZoneStoreEntry> {
        self.try_replace_snapshot(snapshot, force_hidden)
            .expect("active zone image compiles")
    }

    fn try_replace_snapshot(
        &self,
        snapshot: Arc<ZoneSnapshot>,
        force_hidden: bool,
    ) -> Result<Arc<ZoneStoreEntry>, ZoneImageBuildError> {
        let key = snapshot.origin.canonical_key();
        let publication_origin = snapshot.origin.clone();
        let publication_active = snapshot.state == ZoneState::Active;
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current = self.zones.load_full();
        let hidden = force_hidden || current.get(&key).is_some_and(|entry| entry.hidden);
        let incarnation = current
            .get(&key)
            .map(|entry| entry.incarnation)
            .unwrap_or_else(|| self.allocate_incarnation());
        if publication_active {
            info!(
                event = "zone_store_publication_phase",
                phase = "directory_clone_start",
                zone = %publication_origin,
                directory_zone_count = current.len(),
                "zone store publication phase"
            );
        }
        let mut next = self.clone_directory_for_publication(current.as_ref());
        let entry = Arc::new(ZoneStoreEntry::try_new_replacing(
            key.clone(),
            snapshot,
            hidden,
            incarnation,
            current.get(&key).map(Arc::as_ref),
            self.publication_policy,
        )?);
        next.insert(key.clone(), entry.clone());
        self.zones.store(Arc::new(next));
        if publication_active {
            info!(
                event = "zone_store_publication_phase",
                phase = "directory_published",
                zone = %publication_origin,
                "zone store publication phase"
            );
        }
        drop(current);
        if publication_active {
            info!(
                event = "zone_store_publication_phase",
                phase = "publication_temporaries_released",
                zone = %publication_origin,
                "zone store publication phase"
            );
        }
        Ok(entry)
    }

    fn set_hidden(&self, origin: &DomainName, hidden: bool) {
        let key = origin.canonical_key();
        let _publish_guard = self
            .publish_lock
            .lock()
            .expect("zone store publish lock poisoned");
        let current = self.zones.load_full();
        let Some(entry) = current.get(&key) else {
            return;
        };
        if entry.hidden == hidden {
            return;
        }

        let mut next = self.clone_directory_for_publication(current.as_ref());
        next.insert(key, Arc::new(entry.with_hidden(hidden)));
        self.zones.store(Arc::new(next));
    }

    fn clone_directory_for_publication(&self, current: &ZoneDirectory) -> ZoneDirectory {
        #[cfg(test)]
        self.publication_clone_work
            .fetch_add(current.len(), Ordering::Relaxed);
        current.clone()
    }

    fn allocate_incarnation(&self) -> u64 {
        self.next_incarnation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    #[cfg(test)]
    fn publication_clone_work(&self) -> usize {
        self.publication_clone_work.load(Ordering::Relaxed)
    }
}

pub trait PublishedZoneView {
    fn origin(&self) -> &DomainName;

    fn origin_key(&self) -> &str;

    fn origin_label_count(&self) -> usize;

    fn origin_key_arc(&self) -> Arc<str>;

    fn serial(&self) -> Option<u32>;

    fn state(&self) -> ZoneState;

    fn active_zone_image_ref(&self) -> &ZoneImage;

    fn active_snapshot_ref(&self) -> &ZoneSnapshot;

    fn has_incremental_overlay(&self) -> bool;

    fn overlay_allows_compact_direct_shape(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool;

    fn overlay_allows_compact_plan(&self, plan: &ZoneImageLookupPlan) -> bool;

    fn overlay_allows_compact_response_plan(&self, plan: &ZoneImageLookupPlan) -> bool;
}

impl PublishedZone {
    pub fn origin(&self) -> &DomainName {
        &self.entry.origin
    }

    pub fn origin_key(&self) -> &str {
        &self.entry.origin_key
    }

    /// Stable identity of this installed zone entry. Replacing or removing and
    /// re-adding the same origin produces a different incarnation.
    pub fn incarnation(&self) -> u64 {
        self.entry.incarnation
    }

    pub fn origin_label_count(&self) -> usize {
        self.entry.origin_label_count
    }

    pub fn origin_key_arc(&self) -> Arc<str> {
        self.entry.origin_key.clone()
    }

    pub fn serial(&self) -> Option<u32> {
        self.entry.serial
    }

    pub fn state(&self) -> ZoneState {
        self.entry.state
    }

    pub fn active_zone_image_ref(&self) -> &ZoneImage {
        debug_assert_eq!(self.entry.state, ZoneState::Active);
        self.entry
            .image
            .as_deref()
            .expect("active published zone must include a compiled ZoneImage")
    }

    pub fn active_snapshot_ref(&self) -> &ZoneSnapshot {
        debug_assert_eq!(self.entry.state, ZoneState::Active);
        &self.entry.snapshot
    }

    pub fn has_incremental_overlay(&self) -> bool {
        self.entry.overlay_dirty.is_some()
    }

    pub fn overlay_allows_compact_direct(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        let Some(dirty) = self.entry.overlay_dirty.as_deref() else {
            return false;
        };
        if !dirty.allows_compact_direct_shape(&self.entry.snapshot, qname, qtype, qclass) {
            return false;
        }
        let ZoneImageLookupOutcome::Found(plan) = self
            .active_zone_image_ref()
            .lookup_exact_plan(qname, qtype, qclass)
        else {
            return true;
        };
        dirty.allows_compact_plan(&plan)
    }

    pub fn overlay_allows_compact_direct_shape(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        self.entry.overlay_dirty.as_deref().is_some_and(|dirty| {
            dirty.allows_compact_direct_shape(&self.entry.snapshot, qname, qtype, qclass)
        })
    }

    pub fn overlay_allows_compact_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        self.entry
            .overlay_dirty
            .as_deref()
            .is_some_and(|dirty| dirty.allows_compact_plan(plan))
    }

    pub fn overlay_allows_compact_response_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        self.entry
            .overlay_dirty
            .as_deref()
            .is_some_and(|dirty| dirty.allows_compact_response_plan(plan))
    }
}

impl PublishedZoneView for PublishedZone {
    fn origin(&self) -> &DomainName {
        PublishedZone::origin(self)
    }

    fn origin_key(&self) -> &str {
        PublishedZone::origin_key(self)
    }

    fn origin_label_count(&self) -> usize {
        PublishedZone::origin_label_count(self)
    }

    fn origin_key_arc(&self) -> Arc<str> {
        PublishedZone::origin_key_arc(self)
    }

    fn serial(&self) -> Option<u32> {
        PublishedZone::serial(self)
    }

    fn state(&self) -> ZoneState {
        PublishedZone::state(self)
    }

    fn active_zone_image_ref(&self) -> &ZoneImage {
        PublishedZone::active_zone_image_ref(self)
    }

    fn active_snapshot_ref(&self) -> &ZoneSnapshot {
        PublishedZone::active_snapshot_ref(self)
    }

    fn has_incremental_overlay(&self) -> bool {
        PublishedZone::has_incremental_overlay(self)
    }

    fn overlay_allows_compact_direct_shape(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        PublishedZone::overlay_allows_compact_direct_shape(self, qname, qtype, qclass)
    }

    fn overlay_allows_compact_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        PublishedZone::overlay_allows_compact_plan(self, plan)
    }

    fn overlay_allows_compact_response_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        PublishedZone::overlay_allows_compact_response_plan(self, plan)
    }
}

impl PublishedZoneView for PublishedZoneRef<'_> {
    fn origin(&self) -> &DomainName {
        &self.entry.origin
    }

    fn origin_key(&self) -> &str {
        &self.entry.origin_key
    }

    fn origin_label_count(&self) -> usize {
        self.entry.origin_label_count
    }

    fn origin_key_arc(&self) -> Arc<str> {
        self.entry.origin_key.clone()
    }

    fn serial(&self) -> Option<u32> {
        self.entry.serial
    }

    fn state(&self) -> ZoneState {
        self.entry.state
    }

    fn active_zone_image_ref(&self) -> &ZoneImage {
        debug_assert_eq!(self.entry.state, ZoneState::Active);
        self.entry
            .image
            .as_deref()
            .expect("active published zone must include a compiled ZoneImage")
    }

    fn active_snapshot_ref(&self) -> &ZoneSnapshot {
        debug_assert_eq!(self.entry.state, ZoneState::Active);
        &self.entry.snapshot
    }

    fn has_incremental_overlay(&self) -> bool {
        self.entry.overlay_dirty.is_some()
    }

    fn overlay_allows_compact_direct_shape(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        self.entry.overlay_dirty.as_deref().is_some_and(|dirty| {
            dirty.allows_compact_direct_shape(&self.entry.snapshot, qname, qtype, qclass)
        })
    }

    fn overlay_allows_compact_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        self.entry
            .overlay_dirty
            .as_deref()
            .is_some_and(|dirty| dirty.allows_compact_plan(plan))
    }

    fn overlay_allows_compact_response_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        self.entry
            .overlay_dirty
            .as_deref()
            .is_some_and(|dirty| dirty.allows_compact_response_plan(plan))
    }
}

impl ZoneDirectory {
    fn insert(&mut self, key: String, entry: Arc<ZoneStoreEntry>) {
        let suffix_key = canonical_reverse_label_key(&entry.origin);
        if let Some(previous) = self.by_origin.insert(key.clone(), entry.clone()) {
            self.active_count = self.active_count.saturating_sub(usize::from(
                previous.state == ZoneState::Active && !previous.hidden,
            ));
        }
        self.active_count = self.active_count.saturating_add(usize::from(
            entry.state == ZoneState::Active && !entry.hidden,
        ));
        self.suffix_index.insert(suffix_key, entry);
    }

    fn remove(&mut self, key: &str) -> Option<Arc<ZoneStoreEntry>> {
        let entry = self.by_origin.remove(key)?;
        self.active_count = self.active_count.saturating_sub(usize::from(
            entry.state == ZoneState::Active && !entry.hidden,
        ));
        self.suffix_index
            .remove(canonical_reverse_label_key(&entry.origin).as_slice());
        Some(entry)
    }

    fn contains_key(&self, key: &str) -> bool {
        self.by_origin.contains_key(key)
    }

    fn get(&self, key: &str) -> Option<&Arc<ZoneStoreEntry>> {
        self.by_origin.get(key)
    }

    fn values(&self) -> impl Iterator<Item = &Arc<ZoneStoreEntry>> {
        self.by_origin.values()
    }

    fn len(&self) -> usize {
        self.by_origin.len()
    }

    fn active_count(&self) -> usize {
        self.active_count
    }

    fn is_empty(&self) -> bool {
        self.by_origin.is_empty()
    }

    fn find_best_match(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<Arc<ZoneStoreEntry>> {
        self.find_best_match_arc(qname, qname_ascii_lowercase)
            .cloned()
    }

    fn find_best_match_ref(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<&ZoneStoreEntry> {
        self.find_best_match_arc(qname, qname_ascii_lowercase)
            .map(Arc::as_ref)
    }

    fn find_best_match_arc(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<&Arc<ZoneStoreEntry>> {
        let (qname_key, prefix_lengths) =
            canonical_reverse_label_key_with_prefixes(qname, qname_ascii_lowercase);
        for prefix_len in prefix_lengths.into_iter().rev() {
            if let Some(entry) = self.suffix_index.get(&qname_key[..prefix_len])
                && !entry.hidden
            {
                return Some(entry);
            }
        }
        if let Some(entry) = self.suffix_index.get([].as_slice())
            && !entry.hidden
        {
            return Some(entry);
        }
        None
    }

    fn find_parent_of_exact_match_ref(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<&ZoneStoreEntry> {
        let (qname_key, prefix_lengths) =
            canonical_reverse_label_key_with_prefixes(qname, qname_ascii_lowercase);
        let exact = self.suffix_index.get(qname_key.as_slice())?;
        if exact.hidden || prefix_lengths.is_empty() {
            return None;
        }

        for prefix_len in prefix_lengths[..prefix_lengths.len() - 1].iter().rev() {
            if let Some(entry) = self.suffix_index.get(&qname_key[..*prefix_len])
                && !entry.hidden
            {
                return Some(entry.as_ref());
            }
        }
        self.suffix_index
            .get([].as_slice())
            .filter(|entry| !entry.hidden)
            .map(Arc::as_ref)
    }
}

fn canonical_reverse_label_key(name: &DomainName) -> Vec<u8> {
    let (key, _) = canonical_reverse_label_key_with_prefixes(name, false);
    key.to_vec()
}

fn canonical_reverse_label_key_with_prefixes(
    name: &DomainName,
    labels_are_ascii_lowercase: bool,
) -> (SmallVec<[u8; 128]>, SmallVec<[usize; 8]>) {
    let key_capacity = name.labels().iter().map(|label| label.len() + 1).sum();
    let mut key = SmallVec::<[u8; 128]>::with_capacity(key_capacity);
    let mut prefix_lengths = SmallVec::<[usize; 8]>::new();
    if labels_are_ascii_lowercase {
        for label in name.labels().iter().rev() {
            key.push(label.len() as u8);
            key.extend_from_slice(label);
            prefix_lengths.push(key.len());
        }
    } else {
        for label in name.labels().iter().rev() {
            key.push(label.len() as u8);
            key.extend(label.iter().map(u8::to_ascii_lowercase));
            prefix_lengths.push(key.len());
        }
    }
    (key, prefix_lengths)
}

impl ZoneStoreEntry {
    fn try_new(
        origin_key: String,
        snapshot: Arc<ZoneSnapshot>,
        hidden: bool,
        incarnation: u64,
    ) -> Result<Self, ZoneImageBuildError> {
        Self::try_new_replacing(
            origin_key,
            snapshot,
            hidden,
            incarnation,
            None,
            ZonePublicationPolicy::default(),
        )
    }

    fn try_new_replacing(
        origin_key: String,
        snapshot: Arc<ZoneSnapshot>,
        hidden: bool,
        incarnation: u64,
        previous: Option<&Self>,
        publication_policy: ZonePublicationPolicy,
    ) -> Result<Self, ZoneImageBuildError> {
        let incremental = (snapshot.state == ZoneState::Active)
            .then(|| {
                let previous = previous.filter(|entry| entry.state == ZoneState::Active)?;
                let use_overlay = match publication_policy.strategy {
                    ZonePublicationStrategy::Compact => false,
                    ZonePublicationStrategy::Sharded => true,
                    ZonePublicationStrategy::Auto => {
                        snapshot.rrsets.len() >= publication_policy.sharded_rrset_threshold
                    }
                };
                if !use_overlay {
                    return None;
                }
                let changes = snapshot.changed_rrset_keys_from(&previous.snapshot)?;
                if changes.is_empty() {
                    return None;
                }
                let base_image = previous.image.clone()?;
                let image_snapshot = previous.image_snapshot.clone()?;
                let dirty = ZoneOverlayDirty::with_changes(
                    previous.overlay_dirty.as_deref(),
                    &changes,
                    &origin_key,
                    snapshot.rrsets.shards.len(),
                    &snapshot,
                    &image_snapshot,
                    &base_image,
                );
                Some((base_image, image_snapshot, Arc::new(dirty)))
            })
            .flatten();
        let overlay_published = incremental.is_some();
        let (image, image_snapshot, overlay_dirty) =
            if let Some((image, image_snapshot, dirty)) = incremental {
                info!(
                    event = "zone_overlay_publication",
                    zone = %snapshot.origin,
                    signed = snapshot.has_dnssec_rrsets(),
                    dirty_rrsets = dirty.changed_rrset_count,
                    "publishing structurally shared IXFR overlay"
                );
                (Some(image), Some(image_snapshot), Some(dirty))
            } else if snapshot.state == ZoneState::Active {
                let image = ZoneImage::compile(&snapshot)?;
                let stats = image.stats();
                info!(
                    zone = %snapshot.origin,
                    nsec_indexed_groups = stats.nsec_indexed_range_group_count,
                    nsec_fallback_groups = stats
                        .nsec_range_group_count
                        .saturating_sub(stats.nsec_indexed_range_group_count),
                    nsec3_indexed_groups = stats.nsec3_indexed_range_group_count,
                    nsec3_fallback_groups = stats
                        .nsec3_range_group_count
                        .saturating_sub(stats.nsec3_indexed_range_group_count),
                    "compiled ZoneImage DNSSEC denial lookup indexes"
                );
                (Some(Arc::new(image)), Some(snapshot.clone()), None)
            } else {
                (None, None, None)
            };
        let shape = (snapshot.state == ZoneState::Active).then(|| snapshot.shape_summary());
        let shape_histograms = (snapshot.state == ZoneState::Active && !overlay_published)
            .then(|| snapshot.shape_histogram_summary());
        Ok(Self {
            origin: snapshot.origin.clone(),
            origin_label_count: snapshot.origin.label_count(),
            origin_key: Arc::from(origin_key),
            origin_name: Arc::from(snapshot.origin.to_string()),
            state: snapshot.state,
            serial: snapshot.serial,
            soa_timers: snapshot.soa_timers,
            snapshot,
            image,
            image_snapshot,
            overlay_dirty,
            shape,
            shape_histograms,
            hidden,
            incarnation,
        })
    }

    fn metadata(&self) -> ZoneMetadata {
        ZoneMetadata {
            origin: self.origin.clone(),
            origin_key: self.origin_key.clone(),
            origin_name: self.origin_name.clone(),
            state: self.state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            shape: self.shape,
            shape_histograms: self.shape_histograms.clone(),
            zone_image_stats: self.image.as_deref().map(ZoneImage::stats),
        }
    }

    fn control_metadata(&self) -> ZoneMetadata {
        ZoneMetadata {
            origin: self.origin.clone(),
            origin_key: self.origin_key.clone(),
            origin_name: self.origin_name.clone(),
            state: self.state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            shape: None,
            shape_histograms: None,
            zone_image_stats: None,
        }
    }

    fn snapshot_for_control(&self) -> Arc<ZoneSnapshot> {
        if self.snapshot.state == self.state {
            self.snapshot.clone()
        } else {
            Arc::new(self.snapshot.with_state(self.state))
        }
    }

    fn with_hidden(&self, hidden: bool) -> Self {
        Self {
            origin: self.origin.clone(),
            origin_label_count: self.origin_label_count,
            origin_key: self.origin_key.clone(),
            origin_name: self.origin_name.clone(),
            state: self.state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            snapshot: self.snapshot.clone(),
            image: self.image.clone(),
            image_snapshot: self.image_snapshot.clone(),
            overlay_dirty: self.overlay_dirty.clone(),
            shape: self.shape,
            shape_histograms: self.shape_histograms.clone(),
            hidden,
            incarnation: self.incarnation,
        }
    }

    fn with_state(&self, state: ZoneState) -> Self {
        Self {
            origin: self.origin.clone(),
            origin_label_count: self.origin_label_count,
            origin_key: self.origin_key.clone(),
            origin_name: self.origin_name.clone(),
            state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            snapshot: self.snapshot.clone(),
            image: (state == ZoneState::Active)
                .then(|| self.image.clone())
                .flatten(),
            image_snapshot: (state == ZoneState::Active)
                .then(|| self.image_snapshot.clone())
                .flatten(),
            overlay_dirty: (state == ZoneState::Active)
                .then(|| self.overlay_dirty.clone())
                .flatten(),
            shape: (state == ZoneState::Active).then_some(self.shape).flatten(),
            shape_histograms: (state == ZoneState::Active)
                .then(|| self.shape_histograms.clone())
                .flatten(),
            hidden: self.hidden,
            incarnation: self.incarnation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub owner: DomainName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoaRecordView<'a> {
    pub owner: &'a DomainName,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrset {
    pub owner: DomainName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    rdatas: SmallVec<[Vec<u8>; 1]>,
}

impl Rrset {
    pub fn new(
        owner: DomainName,
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdatas: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            owner,
            rr_type,
            class,
            ttl,
            rdatas: SmallVec::from_vec(rdatas),
        }
    }

    pub(crate) fn records(&self) -> Vec<ResourceRecord> {
        self.records_with_owner(&self.owner)
    }

    pub(crate) fn records_with_owner(&self, owner: &DomainName) -> Vec<ResourceRecord> {
        self.rdatas
            .iter()
            .map(|rdata| ResourceRecord {
                owner: owner.clone(),
                rr_type: self.rr_type,
                class: self.class,
                ttl: self.ttl,
                rdata: rdata.clone(),
            })
            .collect()
    }

    pub(crate) fn rdatas(&self) -> &[Vec<u8>] {
        self.rdatas.as_slice()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RrsetKey {
    owner: NameKey,
    rr_type: u16,
    class: u16,
}

const RRSET_SHARD_TARGET_LEN: usize = 256;
const RRSET_SHARD_MIN_TOTAL_LEN: usize = 65_536;
const RRSET_SHARD_MAX_COUNT: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardedRrsets {
    shards: Box<[Arc<HashMap<RrsetKey, Rrset>>]>,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardedRrsetKeys {
    shards: Box<[Arc<HashSet<RrsetKey>>]>,
}

#[derive(Debug, Clone)]
struct ZoneOverlayDirty {
    changed_owners: ShardedNameSet,
    changed_direct_rrsets: ShardedRrsetIdBitset,
    changed_cut_owners: ShardedNameSet,
    changed_rrset_count: usize,
    structure_or_denial_changed: bool,
}

#[derive(Debug, Clone)]
struct ShardedNameSet {
    shards: Box<[Arc<HashMap<u64, SmallVec<[NameKey; 1]>>>]>,
    len: usize,
    bloom: [u64; 4],
}

#[derive(Debug, Clone)]
struct ShardedRrsetIdBitset {
    pages: Box<[Arc<[u64; Self::WORDS_PER_PAGE]>]>,
}

impl ZoneOverlayDirty {
    fn with_changes(
        previous: Option<&Self>,
        changes: &[RrsetKey],
        origin_key: &str,
        shard_count: usize,
        current_snapshot: &ZoneSnapshot,
        image_snapshot: &ZoneSnapshot,
        image: &ZoneImage,
    ) -> Self {
        let mut dirty = previous.cloned().unwrap_or_else(|| Self {
            changed_owners: ShardedNameSet::new(shard_count),
            changed_direct_rrsets: ShardedRrsetIdBitset::new(image.stats().rrset_count),
            changed_cut_owners: ShardedNameSet::new(shard_count),
            changed_rrset_count: 0,
            structure_or_denial_changed: false,
        });
        for key in changes {
            dirty.changed_owners.insert(key.owner.clone());
            let current_rrset = current_snapshot.rrsets.get(key);
            let image_rrset = image_snapshot.rrsets.get(key);
            dirty.structure_or_denial_changed |= current_rrset.is_some() != image_rrset.is_some()
                || matches!(
                    key.rr_type,
                    rr_type if rr_type == RecordType::Nsec as u16
                        || rr_type == RecordType::Nsec3 as u16
                        || rr_type == RecordType::Nsec3Param as u16
                        || rr_type == RecordType::Dname as u16
                );
            if let Some(rrset) = current_rrset.or(image_rrset)
                && let ZoneImageLookupOutcome::Found(plan) =
                    image.lookup_exact_plan(&rrset.owner, key.rr_type, key.class)
            {
                for rrset_id in plan.answer_rrsets() {
                    dirty.changed_direct_rrsets.insert(*rrset_id);
                }
            }
            if key.rr_type == RecordType::Dname as u16
                || (key.rr_type == RecordType::Ns as u16 && key.owner.as_ref() != origin_key)
            {
                dirty.changed_cut_owners.insert(key.owner.clone());
            }
        }
        dirty.changed_rrset_count = dirty.changed_rrset_count.saturating_add(changes.len());
        dirty
    }

    fn allows_compact_direct_shape(
        &self,
        snapshot: &ZoneSnapshot,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        if qclass != 1
            || !matches!(
                qtype,
                rr_type if rr_type == RecordType::A as u16
                    || rr_type == RecordType::Aaaa as u16
                    || rr_type == RecordType::Txt as u16
            )
        {
            return false;
        }
        if self.changed_cut_owners.len != 0 {
            let origin_labels = snapshot.origin.label_count();
            for suffix_start in 0..=qname.label_count().saturating_sub(origin_labels) {
                if self
                    .changed_cut_owners
                    .contains_domain_suffix(qname, suffix_start)
                {
                    return false;
                }
            }
        }
        true
    }

    fn allows_compact_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        plan.answer_rrsets()
            .iter()
            .all(|rrset_id| !self.changed_direct_rrsets.contains(rrset_id))
    }

    fn allows_compact_response_plan(&self, plan: &ZoneImageLookupPlan) -> bool {
        !self.structure_or_denial_changed
            && plan
                .referenced_rrsets()
                .all(|rrset_id| !self.changed_direct_rrsets.contains(&rrset_id))
    }
}

impl ShardedNameSet {
    fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count).map(|_| Arc::new(HashMap::new())).collect(),
            len: 0,
            bloom: [0; 4],
        }
    }

    fn insert(&mut self, name: NameKey) {
        let digest = canonical_name_hash_str(name.as_ref());
        self.bloom_insert(digest);
        let shard = digest as usize & (self.shards.len() - 1);
        let names = Arc::make_mut(&mut self.shards[shard])
            .entry(digest)
            .or_default();
        if !names.iter().any(|existing| existing == &name) {
            names.push(name);
            self.len += 1;
        }
    }

    fn contains_domain_suffix(&self, name: &DomainName, suffix_start: usize) -> bool {
        let digest = canonical_domain_suffix_hash(name, suffix_start);
        if !self.bloom_may_contain(digest) {
            return false;
        }
        let shard = digest as usize & (self.shards.len() - 1);
        let Some(candidates) = self.shards[shard].get(&digest) else {
            return false;
        };
        let canonical = canonical_domain_suffix_key(name, suffix_start);
        candidates
            .iter()
            .any(|candidate| candidate.as_ref() == canonical)
    }

    fn bloom_insert(&mut self, digest: u64) {
        for bit in [digest as usize & 255, digest.rotate_left(29) as usize & 255] {
            self.bloom[bit / 64] |= 1u64 << (bit % 64);
        }
    }

    fn bloom_may_contain(&self, digest: u64) -> bool {
        [digest as usize & 255, digest.rotate_left(29) as usize & 255]
            .into_iter()
            .all(|bit| self.bloom[bit / 64] & (1u64 << (bit % 64)) != 0)
    }
}

impl ShardedRrsetIdBitset {
    const WORDS_PER_PAGE: usize = 64;
    const BITS_PER_PAGE: usize = Self::WORDS_PER_PAGE * u64::BITS as usize;

    fn new(rrset_count: usize) -> Self {
        let page_count = rrset_count.div_ceil(Self::BITS_PER_PAGE);
        Self {
            pages: (0..page_count)
                .map(|_| Arc::new([0; Self::WORDS_PER_PAGE]))
                .collect(),
        }
    }

    fn insert(&mut self, value: ZoneImageRrsetId) {
        let value = value.index() as usize;
        let page = value / Self::BITS_PER_PAGE;
        let within_page = value % Self::BITS_PER_PAGE;
        let word = within_page / u64::BITS as usize;
        let bit = within_page % u64::BITS as usize;
        Arc::make_mut(&mut self.pages[page])[word] |= 1u64 << bit;
    }

    fn contains(&self, value: &ZoneImageRrsetId) -> bool {
        let value = value.index() as usize;
        let page = value / Self::BITS_PER_PAGE;
        let within_page = value % Self::BITS_PER_PAGE;
        let word = within_page / u64::BITS as usize;
        let bit = within_page % u64::BITS as usize;
        self.pages
            .get(page)
            .is_some_and(|page| page[word] & (1u64 << bit) != 0)
    }
}

impl ShardedRrsetKeys {
    fn new(shard_count: usize) -> Self {
        Self {
            shards: (0..shard_count).map(|_| Arc::new(HashSet::new())).collect(),
        }
    }

    fn insert(&mut self, key: RrsetKey) {
        let shard = rrset_shard_index(key.owner.as_ref(), self.shards.len());
        Arc::make_mut(&mut self.shards[shard]).insert(key);
    }

    fn remove(&mut self, key: &RrsetKey) {
        let shard = rrset_shard_index(key.owner.as_ref(), self.shards.len());
        Arc::make_mut(&mut self.shards[shard]).remove(key);
    }

    fn iter(&self) -> impl Iterator<Item = &RrsetKey> {
        self.shards.iter().flat_map(|shard| shard.iter())
    }
}

impl ShardedRrsets {
    fn empty() -> Self {
        Self {
            shards: vec![Arc::new(HashMap::new())].into_boxed_slice(),
            len: 0,
        }
    }

    fn from_rrsets(rrsets: Vec<Rrset>, name_interner: &mut NameInterner) -> Self {
        let shard_count = rrset_shard_count(rrsets.len());
        let capacity = rrsets.len().div_ceil(shard_count);
        let mut shards = (0..shard_count)
            .map(|_| HashMap::with_capacity(capacity))
            .collect::<Vec<_>>();
        for rrset in rrsets {
            let key =
                RrsetKey::new_interned(&rrset.owner, rrset.rr_type, rrset.class, name_interner);
            let shard = rrset_shard_index(key.owner.as_ref(), shard_count);
            shards[shard].insert(key, rrset);
        }
        let len = shards.iter().map(HashMap::len).sum();
        Self {
            shards: shards.into_iter().map(Arc::new).collect(),
            len,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, key: &RrsetKey) -> Option<&Rrset> {
        let shard = rrset_shard_index(key.owner.as_ref(), self.shards.len());
        self.shards[shard].get(key)
    }

    fn values(&self) -> impl Iterator<Item = &Rrset> {
        self.shards.iter().flat_map(|shard| shard.values())
    }

    fn iter(&self) -> impl Iterator<Item = (&RrsetKey, &Rrset)> {
        self.shards.iter().flat_map(|shard| shard.iter())
    }

    fn keys(&self) -> impl Iterator<Item = &RrsetKey> {
        self.shards.iter().flat_map(|shard| shard.keys())
    }

    fn values_at_owner(&self, owner_key: &str) -> impl Iterator<Item = &Rrset> {
        let shard = rrset_shard_index(owner_key, self.shards.len());
        self.shards[shard]
            .iter()
            .filter_map(move |(key, rrset)| (key.owner.as_ref() == owner_key).then_some(rrset))
    }

    fn with_replacements(&self, replacements: Vec<(String, u16, u16, Option<Rrset>)>) -> Self {
        let mut shards = self.shards.to_vec();
        let mut len = self.len;
        for (owner_key, rr_type, class, replacement) in replacements {
            let shard = rrset_shard_index(&owner_key, shards.len());
            let shard = Arc::make_mut(&mut shards[shard]);
            let key = RrsetKey::new_from_key(&owner_key, rr_type, class);
            match replacement {
                Some(rrset) => {
                    if shard.insert(key, rrset).is_none() {
                        len += 1;
                    }
                }
                None => {
                    if shard.remove(&key).is_some() {
                        len -= 1;
                    }
                }
            }
        }
        Self {
            shards: shards.into_boxed_slice(),
            len,
        }
    }
}

fn rrset_shard_count(rrset_count: usize) -> usize {
    if rrset_count < RRSET_SHARD_MIN_TOTAL_LEN {
        return 1;
    }
    rrset_count
        .div_ceil(RRSET_SHARD_TARGET_LEN)
        .next_power_of_two()
        .min(RRSET_SHARD_MAX_COUNT)
}

fn rrset_shard_index(owner_key: &str, shard_count: usize) -> usize {
    debug_assert!(shard_count.is_power_of_two());
    // A one-shard zone has no routing decision to make. Keep the common
    // small-zone lookup path free of the keyed-hash cost.
    if shard_count == 1 {
        return 0;
    }
    canonical_name_hash_str(owner_key) as usize & (shard_count - 1)
}

fn canonical_name_hash_str(owner_key: &str) -> u64 {
    let mut hasher = shard_hash_state().build_hasher();
    hasher.write(owner_key.as_bytes());
    hasher.finish()
}

fn canonical_domain_suffix_hash(name: &DomainName, suffix_start: usize) -> u64 {
    let mut hasher = shard_hash_state().build_hasher();
    for label in &name.labels()[suffix_start..] {
        for byte in label {
            let byte = byte.to_ascii_lowercase();
            if matches!(byte, b'\\' | b'.' | 0x00..=0x20 | 0x7f..=0xff) {
                for escaped in [
                    b'\\',
                    b'0' + byte / 100,
                    b'0' + (byte / 10) % 10,
                    b'0' + byte % 10,
                ] {
                    hasher.write_u8(escaped);
                }
            } else {
                hasher.write_u8(byte);
            }
        }
        hasher.write_u8(b'.');
    }
    if suffix_start == name.label_count() {
        hasher.write_u8(b'.');
    }
    hasher.finish()
}

fn shard_hash_state() -> &'static RandomState {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    STATE.get_or_init(RandomState::new)
}

fn canonical_domain_suffix_key(name: &DomainName, suffix_start: usize) -> String {
    canonical_name_key_from_labels(name.labels()[suffix_start..].iter().map(Vec::as_slice))
}

impl RrsetKey {
    fn new_from_key(owner_key: &str, rr_type: u16, class: u16) -> Self {
        Self {
            owner: NameKey::from(owner_key),
            rr_type,
            class,
        }
    }

    fn from_name_key(owner: NameKey, rr_type: u16, class: u16) -> Self {
        Self {
            owner,
            rr_type,
            class,
        }
    }

    fn new_interned(
        owner: &DomainName,
        rr_type: u16,
        class: u16,
        name_interner: &mut NameInterner,
    ) -> Self {
        Self {
            owner: name_interner.intern_domain(owner),
            rr_type,
            class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn in_only_class_removal_does_not_shrink_core_rrset_layouts() {
        #[allow(dead_code)]
        struct ClasslessRrsetKey {
            owner: NameKey,
            rr_type: u16,
        }
        #[allow(dead_code)]
        struct ClasslessRrset {
            owner: DomainName,
            rr_type: u16,
            ttl: u32,
            rdatas: SmallVec<[Vec<u8>; 1]>,
        }

        assert_eq!(
            mem::size_of::<RrsetKey>(),
            mem::size_of::<ClasslessRrsetKey>()
        );
        assert_eq!(mem::size_of::<Rrset>(), mem::size_of::<ClasslessRrset>());
        assert_eq!(mem::size_of::<ClassSet>(), 24);
    }

    #[test]
    fn name_class_index_compacts_in_only_zones_and_preserves_multiclass_semantics() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let in_only = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        );
        assert!(matches!(
            in_only.name_classes.as_ref(),
            NameClassIndex::InOnly(_)
        ));
        assert!(in_only.name_exists(&origin, 1));
        assert!(in_only.name_exists(&origin, 255));
        assert!(!in_only.name_exists(&origin, 3));
        assert_eq!(
            in_only.shape_summary().in_only_class_index_bytes_saved,
            mem::size_of::<ClassSet>()
        );

        let chaos = DomainName::from_absolute_str("chaos.example.test.").unwrap();
        let multiclass = ZoneSnapshot::active(
            origin.clone(),
            Some(2),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    chaos.clone(),
                    RecordType::Txt as u16,
                    3,
                    300,
                    vec![vec![3, b'c', b'h', b'a']],
                ),
            ],
        );
        assert!(matches!(
            multiclass.name_classes.as_ref(),
            NameClassIndex::MultiClass(_)
        ));
        assert!(multiclass.name_exists(&chaos, 3));
        assert!(multiclass.name_exists(&chaos, 255));
        assert!(!multiclass.name_exists(&chaos, 1));
        assert_eq!(
            multiclass.shape_summary().in_only_class_index_bytes_saved,
            0
        );
    }

    #[test]
    fn active_snapshot_extracts_soa_timers() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin,
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        );

        assert_eq!(
            snapshot.soa_timers,
            Some(SoaTimers {
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            })
        );
    }

    #[test]
    fn offline_oracle_does_not_treat_mixed_case_origin_ns_as_delegation() {
        let origin = DomainName::from_absolute_str("Example.Test.").unwrap();
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin,
            Some(1),
            vec![
                Rrset::new(
                    apex.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    apex,
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("ns.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
            ],
        );

        let lookup = snapshot
            .offline_oracle()
            .lookup(&www, RecordType::A as u16, 1);

        assert_eq!(lookup.answers.len(), 1);
        assert!(lookup.authorities.is_empty());
    }

    #[test]
    fn sharded_publication_reuses_compact_image_and_gates_dirty_direct_answers() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let unchanged = DomainName::from_absolute_str("unchanged.example.test.").unwrap();
        let changed = DomainName::from_absolute_str("changed.example.test.").unwrap();
        let base = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    origin.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("ns.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    unchanged.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 2]],
                ),
            ],
        );
        let store = ZoneStore::with_publication_policy(ZonePublicationPolicy {
            strategy: ZonePublicationStrategy::Sharded,
            sharded_rrset_threshold: 1,
            ..ZonePublicationPolicy::default()
        });
        store.insert_snapshot(base.clone());
        let base_image = store
            .find_published_zone(&unchanged)
            .unwrap()
            .active_zone_image_ref() as *const ZoneImage;

        let mut soa2 = soa_rdata();
        soa2[44..48].copy_from_slice(&2u32.to_be_bytes());
        let updated = base.with_cow_rrset_replacements(
            2,
            vec![
                (
                    origin.canonical_key(),
                    RecordType::Soa as u16,
                    1,
                    Some(Rrset::new(
                        origin,
                        RecordType::Soa as u16,
                        1,
                        300,
                        vec![soa2],
                    )),
                ),
                (
                    changed.canonical_key(),
                    RecordType::A as u16,
                    1,
                    Some(Rrset::new(
                        changed.clone(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![198, 51, 100, 2]],
                    )),
                ),
            ],
        );
        let updated_shape = updated.shape_summary();
        store.insert_snapshot(updated);

        let published = store.find_published_zone(&unchanged).unwrap();
        assert!(published.has_incremental_overlay());
        assert_eq!(published.serial(), Some(2));
        assert_eq!(published.active_zone_image_ref().serial(), Some(1));
        assert_eq!(
            published.active_zone_image_ref() as *const ZoneImage,
            base_image
        );
        assert!(published.overlay_allows_compact_direct(&unchanged, RecordType::A as u16, 1));
        assert!(!published.overlay_allows_compact_direct(&changed, RecordType::A as u16, 1));
        assert!(!published.overlay_allows_compact_direct(&unchanged, RecordType::Mx as u16, 1));
        let metadata = store
            .zone_metadata()
            .into_iter()
            .find(|metadata| metadata.origin == base.origin)
            .expect("overlay metadata");
        assert_eq!(metadata.shape, Some(updated_shape));
        assert!(metadata.shape_histograms.is_none());
    }

    #[test]
    fn due_overlay_compaction_installs_current_compact_image() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let changed = DomainName::from_absolute_str("changed.example.test.").unwrap();
        let base = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
            ],
        );
        let store = ZoneStore::with_publication_policy(ZonePublicationPolicy {
            strategy: ZonePublicationStrategy::Sharded,
            sharded_rrset_threshold: 1,
            overlay_compaction_dirty_owner_threshold: 1,
        });
        store.insert_snapshot(base.clone());
        let updated = base.with_cow_rrset_replacements(
            2,
            vec![(
                changed.canonical_key(),
                RecordType::A as u16,
                1,
                Some(Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![198, 51, 100, 1]],
                )),
            )],
        );
        store.insert_snapshot(updated);
        assert!(store.overlay_compaction_due(&origin));

        assert_eq!(
            store.compact_overlay_if_due(&origin).unwrap(),
            ZoneOverlayCompactionOutcome::Compacted {
                remaining_dirty_owners: 0,
            }
        );
        assert!(!store.overlay_compaction_due(&origin));
        let published = store.find_published_zone(&changed).unwrap();
        assert!(!published.has_incremental_overlay());
        assert_eq!(published.serial(), Some(2));
        assert_eq!(published.active_zone_image_ref().serial(), Some(2));
    }

    #[test]
    fn new_owner_overlay_skips_dirty_hash_and_relies_on_compact_exact_gate() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.example.test.").unwrap();
        let ordinary_new = DomainName::from_absolute_str("new.example.test.").unwrap();
        let wildcard_new = DomainName::from_absolute_str("covered.example.test.").unwrap();
        for (base_extra, added) in [
            (None, ordinary_new),
            (
                Some(Rrset::new(
                    wildcard,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 9]],
                )),
                wildcard_new,
            ),
        ] {
            let mut rrsets = vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )];
            rrsets.extend(base_extra);
            let base = ZoneSnapshot::active(origin.clone(), Some(1), rrsets);
            let store = ZoneStore::with_publication_policy(ZonePublicationPolicy {
                strategy: ZonePublicationStrategy::Sharded,
                sharded_rrset_threshold: 1,
                ..ZonePublicationPolicy::default()
            });
            store.insert_snapshot(base.clone());
            let updated = base.with_cow_rrset_replacements(
                2,
                vec![(
                    added.canonical_key(),
                    RecordType::A as u16,
                    1,
                    Some(Rrset::new(
                        added.clone(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![198, 51, 100, 1]],
                    )),
                )],
            );
            store.insert_snapshot(updated);
            let published = store.find_published_zone(&added).unwrap();
            assert!(published.overlay_allows_compact_direct(&added, RecordType::A as u16, 1,));
            assert!(!matches!(
                published.active_zone_image_ref().lookup_exact_plan(
                    &added,
                    RecordType::A as u16,
                    1
                ),
                ZoneImageLookupOutcome::Found(_)
            ));
        }
    }

    #[test]
    fn completed_compaction_rebases_ixfr_that_arrived_during_rebuild() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let changed = DomainName::from_absolute_str("changed.example.test.").unwrap();
        let base = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
            ],
        );
        let store = ZoneStore::with_publication_policy(ZonePublicationPolicy {
            strategy: ZonePublicationStrategy::Sharded,
            sharded_rrset_threshold: 1,
            overlay_compaction_dirty_owner_threshold: 1,
        });
        store.insert_snapshot(base.clone());
        let version_two = Arc::new(base.with_cow_rrset_replacements(
            2,
            vec![(
                changed.canonical_key(),
                RecordType::A as u16,
                1,
                Some(Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![198, 51, 100, 2]],
                )),
            )],
        ));
        store
            .insert_snapshot_arc_for_transfer(version_two.clone())
            .unwrap();
        let candidate_incarnation = store
            .zones
            .load()
            .get(&origin.canonical_key())
            .unwrap()
            .incarnation;
        let candidate_image = Arc::new(ZoneImage::compile(&version_two).unwrap());

        let version_three = version_two.with_cow_rrset_replacements(
            3,
            vec![(
                changed.canonical_key(),
                RecordType::A as u16,
                1,
                Some(Rrset::new(
                    changed.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![203, 0, 113, 3]],
                )),
            )],
        );
        store.insert_snapshot(version_three);

        assert_eq!(
            store.publish_compacted_base(
                &origin.canonical_key(),
                &version_two,
                candidate_incarnation,
                candidate_image,
            ),
            ZoneOverlayCompactionOutcome::Compacted {
                remaining_dirty_owners: 1,
            }
        );
        let published = store.find_published_zone(&changed).unwrap();
        assert_eq!(published.serial(), Some(3));
        assert_eq!(published.active_zone_image_ref().serial(), Some(2));
        assert!(published.has_incremental_overlay());
        assert!(!published.overlay_allows_compact_direct(&changed, RecordType::A as u16, 1));
    }

    #[test]
    fn shape_summary_reports_rrset_and_name_key_distribution() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let api = DomainName::from_absolute_str("api.deep.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
                ),
                Rrset::new(api, RecordType::A as u16, 1, 300, vec![vec![192, 0, 2, 3]]),
            ],
        );

        let shape = snapshot.shape_summary();
        assert_eq!(shape.rrset_count, 3);
        assert_eq!(shape.rdata_count, 4);
        assert_eq!(shape.single_rdata_rrset_count, 2);
        assert_eq!(shape.multi_rdata_rrset_count, 1);
        assert_eq!(shape.spilled_rdata_rrset_count, 1);
        assert_eq!(shape.max_rdata_per_rrset, 2);
        assert_eq!(shape.owner_name_count, 3);
        assert_eq!(shape.empty_non_terminal_name_count, 2);
        assert_eq!(shape.rdata_payload_bytes, soa_rdata().len() + 12);
        assert!(shape.name_key_logical_bytes > shape.name_key_unique_bytes);
        assert_eq!(
            shape.name_key_deduplicated_bytes,
            shape.name_key_logical_bytes - shape.name_key_unique_bytes
        );
    }

    #[test]
    fn rrset_sharding_resists_names_colliding_under_the_legacy_unkeyed_hash() {
        const SHARD_COUNT: usize = 256;
        const COLLIDER_COUNT: usize = 256;
        const LEGACY_FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const LEGACY_FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut occupancy = [0usize; SHARD_COUNT];
        let mut colliders = 0usize;
        for candidate in 0usize.. {
            let owner = format!("host{candidate}.hostile.example.");
            let mut legacy_digest = LEGACY_FNV_OFFSET;
            for byte in owner.bytes() {
                legacy_digest ^= u64::from(byte);
                legacy_digest = legacy_digest.wrapping_mul(LEGACY_FNV_PRIME);
            }
            if legacy_digest as usize & (SHARD_COUNT - 1) != 0 {
                continue;
            }
            occupancy[rrset_shard_index(&owner, SHARD_COUNT)] += 1;
            colliders += 1;
            if colliders == COLLIDER_COUNT {
                break;
            }
        }

        assert_eq!(colliders, COLLIDER_COUNT);
        assert!(
            occupancy.into_iter().max().unwrap_or(0) < COLLIDER_COUNT / 4,
            "attacker-selected names must not retain their legacy deterministic shard collision"
        );
    }

    #[test]
    fn cow_replacements_keep_exact_cached_shape_summary() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let multi = DomainName::from_absolute_str("multi.example.test.").unwrap();
        let delegated = DomainName::from_absolute_str("delegated.example.test.").unwrap();
        let old_leaf = DomainName::from_absolute_str("old.deep.example.test.").unwrap();
        let base = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    multi.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
                ),
                Rrset::new(
                    delegated.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("ns.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    old_leaf.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![vec![3, b'o', b'l', b'd']],
                ),
            ],
        );
        let new_leaf = DomainName::from_absolute_str("new.other.example.test.").unwrap();
        let updated = base.with_cow_rrset_replacements(
            2,
            vec![
                (
                    multi.canonical_key(),
                    RecordType::A as u16,
                    1,
                    Some(Rrset::new(
                        multi,
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![198, 51, 100, 1]],
                    )),
                ),
                (delegated.canonical_key(), RecordType::Ns as u16, 1, None),
                (old_leaf.canonical_key(), RecordType::Txt as u16, 1, None),
                (
                    new_leaf.canonical_key(),
                    RecordType::Aaaa as u16,
                    1,
                    Some(Rrset::new(
                        new_leaf,
                        RecordType::Aaaa as u16,
                        1,
                        300,
                        vec![vec![0; 16], vec![1; 16], vec![2; 16]],
                    )),
                ),
            ],
        );
        let fresh =
            ZoneSnapshot::active(origin, Some(2), updated.rrsets.values().cloned().collect());

        assert_eq!(updated.shape_summary(), updated.compute_shape_summary());
        assert_eq!(updated.shape_summary(), fresh.shape_summary());
    }

    #[test]
    fn shape_histogram_summary_reports_layout_distributions() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let api = DomainName::from_absolute_str("api.deep.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
                ),
                Rrset::new(api, RecordType::A as u16, 1, 300, vec![vec![192, 0, 2, 3]]),
            ],
        );

        let histograms = snapshot.shape_histogram_summary();
        assert_eq!(
            histogram_bucket_count(&histograms.child_name_fanout_names, "0"),
            2
        );
        assert_eq!(
            histogram_bucket_count(&histograms.child_name_fanout_names, "1"),
            1
        );
        assert_eq!(
            histogram_bucket_count(&histograms.child_name_fanout_names, "2_4"),
            1
        );
        assert_eq!(
            histogram_bucket_count(&histograms.rrsets_per_owner_name, "1"),
            3
        );
        assert_eq!(
            histogram_bucket_count(&histograms.rdata_records_per_rrset, "1"),
            2
        );
        assert_eq!(
            histogram_bucket_count(&histograms.rdata_records_per_rrset, "2_4"),
            1
        );
        assert_eq!(
            histogram_bucket_count(&histograms.rdata_payload_bytes_per_rrset, "1_16"),
            2
        );
        assert_eq!(
            histograms
                .child_name_fanout_names
                .iter()
                .map(|bucket| bucket.count)
                .sum::<usize>(),
            4
        );
    }

    fn histogram_bucket_count(buckets: &[ZoneShapeHistogramBucket], bucket: &str) -> usize {
        buckets
            .iter()
            .find(|candidate| candidate.bucket == bucket)
            .map(|candidate| candidate.count)
            .unwrap_or(0)
    }

    #[test]
    fn transfer_publication_rejects_uncompilable_snapshot_without_replacing_active_zone() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let outside = DomainName::from_absolute_str("ns1.provider.test.").unwrap();
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        ));
        let rejected = Arc::new(ZoneSnapshot::active(
            origin.clone(),
            Some(2),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    300,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    outside,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        ));

        let error = store
            .insert_snapshot_arc_for_transfer(rejected)
            .expect_err("transfer publication rejects uncompilable snapshot");

        assert!(matches!(error, ZoneImageBuildError::OutOfZoneOwner { .. }));
        assert_eq!(
            store
                .exact_zone_control_metadata(&origin)
                .expect("previous active zone remains published")
                .serial,
            Some(1)
        );
    }

    #[test]
    fn expire_zone_marks_snapshot_expired() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        ));

        assert!(store.expire_zone(&origin));
        assert_eq!(
            store
                .exact_snapshot_for_transfer(&origin)
                .expect("expired zone")
                .metadata()
                .state,
            ZoneState::Expired
        );
        assert_eq!(
            store
                .exact_zone_control_metadata(&origin)
                .expect("expired metadata")
                .state,
            ZoneState::Expired
        );
        assert_eq!(
            store
                .offline_snapshots()
                .into_iter()
                .find(|snapshot| snapshot.origin() == &origin)
                .expect("expired offline snapshot")
                .state(),
            ZoneState::Expired
        );
        assert_eq!(
            store
                .find_published_zone(&origin)
                .expect("expired zone remains published for not-ready response")
                .state(),
            ZoneState::Expired
        );
        assert!(!store.expire_zone(&origin));
    }

    #[test]
    fn active_count_tracks_active_zone_snapshots() {
        let store = ZoneStore::new();
        let active = DomainName::from_absolute_str("active.test.").unwrap();
        let loading = DomainName::from_absolute_str("loading.test.").unwrap();

        store.insert_loading(loading);
        assert_eq!(store.active_count(), 0);
        assert!(!store.has_active_zone());

        store.insert_snapshot(ZoneSnapshot::active(active.clone(), Some(1), Vec::new()));
        assert_eq!(store.active_count(), 1);
        assert!(store.has_active_zone());

        assert!(store.expire_zone(&active));
        assert_eq!(store.active_count(), 0);
        assert!(!store.has_active_zone());

        store.insert_snapshot(ZoneSnapshot::active(active.clone(), Some(2), Vec::new()));
        assert_eq!(store.active_count(), 1);
        store.insert_loading(active.clone());
        assert_eq!(store.active_count(), 0);
        store.insert_snapshot(ZoneSnapshot::active(active.clone(), Some(3), Vec::new()));
        assert_eq!(store.active_count(), 1);
        assert!(store.remove_zone(&active));
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn active_count_and_published_metadata_exclude_hidden_catalog_snapshots() {
        let store = ZoneStore::new();
        let catalog = DomainName::from_absolute_str("catalog.test.").unwrap();

        store.insert_loading_hidden(catalog.clone());
        store.insert_snapshot(ZoneSnapshot::active(catalog.clone(), Some(1), Vec::new()));

        assert_eq!(store.active_count(), 0);
        assert!(!store.has_active_zone());
        assert!(store.published_zone_metadata().is_empty());
        assert_eq!(store.zone_metadata().len(), 1);

        store.show_zone(&catalog);
        assert_eq!(store.active_count(), 1);
        assert_eq!(store.published_zone_metadata().len(), 1);

        store.hide_zone(&catalog);
        assert_eq!(store.active_count(), 0);
        assert!(store.published_zone_metadata().is_empty());
    }

    #[test]
    fn offline_snapshots_returns_zones_in_stable_order() {
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("z.test.").unwrap());
        store.insert_loading(DomainName::from_absolute_str("a.test.").unwrap());

        let origins = store
            .offline_snapshots()
            .into_iter()
            .map(|snapshot| snapshot.origin().to_string())
            .collect::<Vec<_>>();

        assert_eq!(origins, vec!["a.test.", "z.test."]);
    }

    #[test]
    fn zone_metadata_returns_cached_shape_without_snapshot_clone_or_sort_key_rebuild() {
        let store = ZoneStore::new();
        let loading = DomainName::from_absolute_str("loading.test.").unwrap();
        let active = DomainName::from_absolute_str("active.test.").unwrap();
        store.insert_loading(loading);
        store.insert_snapshot(ZoneSnapshot::active(
            active.clone(),
            Some(7),
            vec![Rrset::new(
                active.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        ));

        let metadata = store.zone_metadata();
        assert_eq!(
            metadata
                .iter()
                .map(|zone| zone.origin.to_string())
                .collect::<Vec<_>>(),
            vec!["active.test.", "loading.test."]
        );
        let active_metadata = &metadata[0];
        assert_eq!(active_metadata.origin_key.as_ref(), "active.test.");
        assert_eq!(active_metadata.origin_name.as_ref(), "active.test.");
        assert_eq!(active_metadata.state, ZoneState::Active);
        assert_eq!(active_metadata.serial, Some(7));
        assert_eq!(
            active_metadata
                .shape
                .expect("active shape is cached")
                .rrset_count,
            1
        );
        assert!(active_metadata.shape_histograms.is_some());
        assert!(metadata[1].shape.is_none());
        let active_control_metadata = store
            .exact_zone_control_metadata(&active)
            .expect("active control metadata");
        assert_eq!(active_control_metadata.state, ZoneState::Active);
        assert_eq!(active_control_metadata.serial, Some(7));
        assert!(active_control_metadata.shape.is_none());
        assert!(active_control_metadata.shape_histograms.is_none());

        assert!(store.expire_zone(&active));
        let expired = store
            .zone_metadata()
            .into_iter()
            .find(|zone| zone.origin == active)
            .expect("expired zone metadata");
        assert_eq!(expired.state, ZoneState::Expired);
        assert!(expired.shape.is_none());
        assert!(expired.shape_histograms.is_none());
    }

    #[test]
    fn transfer_snapshot_view_carries_cached_control_metadata() {
        let store = ZoneStore::new();
        let origin = DomainName::from_absolute_str("transfer.example.").unwrap();
        store.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(42),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata()],
            )],
        ));

        let view = store
            .exact_snapshot_for_transfer(&origin)
            .expect("transfer snapshot view");
        let metadata = view.metadata();
        assert_eq!(view.snapshot_for_transfer().serial, Some(42));
        assert_eq!(metadata.origin, origin);
        assert_eq!(metadata.origin_key.as_ref(), "transfer.example.");
        assert_eq!(metadata.origin_name.as_ref(), "transfer.example.");
        assert_eq!(metadata.serial, Some(42));
        assert_eq!(metadata.state, ZoneState::Active);
        assert!(metadata.shape.is_none());
        assert!(metadata.shape_histograms.is_none());
    }

    #[test]
    fn serial_gated_transfer_snapshot_skips_zones_without_current_serial() {
        let store = ZoneStore::new();
        let serial_origin = DomainName::from_absolute_str("serial.example.").unwrap();
        let no_serial_origin = DomainName::from_absolute_str("no-serial.example.").unwrap();
        store.insert_snapshot(ZoneSnapshot::active(
            serial_origin.clone(),
            Some(42),
            Vec::new(),
        ));
        store.insert_snapshot(ZoneSnapshot::active(
            no_serial_origin.clone(),
            None,
            Vec::new(),
        ));

        let serial_view = store
            .exact_snapshot_with_serial_for_transfer(&serial_origin)
            .expect("serial-bearing transfer snapshot view");
        assert_eq!(serial_view.snapshot_for_transfer().serial, Some(42));
        assert_eq!(serial_view.metadata().serial, Some(42));
        assert!(serial_view.metadata().shape.is_none());
        assert!(serial_view.metadata().shape_histograms.is_none());

        assert!(
            store
                .exact_snapshot_with_serial_for_transfer(&no_serial_origin)
                .is_none(),
            "serial-gated IXFR view must not expose old-layout snapshots that cannot seed IXFR"
        );
        assert!(
            store
                .exact_snapshot_for_transfer(&no_serial_origin)
                .is_some(),
            "broader transfer/oracle view remains available for callers that genuinely need it"
        );
    }

    #[test]
    fn hidden_zone_is_available_exactly_but_not_for_query_lookup() {
        let store = ZoneStore::new();
        let origin = DomainName::from_absolute_str("catalog.example.").unwrap();
        let child = DomainName::from_absolute_str("member.catalog.example.").unwrap();

        store.insert_loading_hidden(origin.clone());

        assert!(store.exact_snapshot_for_transfer(&origin).is_some());
        assert!(store.find_published_zone(&origin).is_none());
        assert!(store.find_published_zone(&child).is_none());
        assert!(store.is_hidden(&origin));

        store.show_zone(&origin);
        assert!(store.find_published_zone(&child).is_some());
    }

    #[test]
    fn published_zone_lookup_uses_most_specific_suffix() {
        let store = ZoneStore::new();
        let parent = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let mixed_case_qname = DomainName::from_absolute_str("WWW.Child.Example.Test.").unwrap();

        store.insert_snapshot(ZoneSnapshot::active(parent.clone(), Some(1), Vec::new()));
        store.insert_snapshot(ZoneSnapshot::active(child.clone(), Some(1), Vec::new()));

        let published = store
            .find_published_zone_with_ascii_lowercase_hint(&qname, true)
            .expect("published child zone");
        assert_eq!(published.origin(), &child);
        assert_eq!(published.origin_key(), "child.example.test.");

        let mixed_case_published = store
            .find_published_zone_with_ascii_lowercase_hint(&mixed_case_qname, false)
            .expect("published child zone for mixed case query");
        assert_eq!(mixed_case_published.origin(), &child);
    }

    #[test]
    fn borrowed_published_zone_lookup_matches_owned_suffix_behavior() {
        let store = ZoneStore::new();
        let parent = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let mixed_case_qname = DomainName::from_absolute_str("WWW.Child.Example.Test.").unwrap();

        store.insert_snapshot(ZoneSnapshot::active(parent.clone(), Some(1), Vec::new()));
        store.insert_snapshot(ZoneSnapshot::active(child.clone(), Some(2), Vec::new()));

        let borrowed = store
            .with_published_zone_with_ascii_lowercase_hint(&qname, true, |zone| {
                (
                    zone.origin().clone(),
                    zone.origin_key().to_owned(),
                    zone.serial(),
                )
            })
            .expect("borrowed child zone");
        assert_eq!(
            borrowed,
            (child.clone(), "child.example.test.".to_owned(), Some(2))
        );

        let mixed_case_borrowed = store
            .with_published_zone_with_ascii_lowercase_hint(&mixed_case_qname, false, |zone| {
                zone.origin().clone()
            })
            .expect("borrowed mixed-case child zone");
        assert_eq!(mixed_case_borrowed, child);
    }

    #[test]
    fn published_zone_lookup_skips_hidden_suffix_and_uses_visible_parent() {
        let store = ZoneStore::new();
        let parent = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();

        store.insert_snapshot(ZoneSnapshot::active(parent.clone(), Some(1), Vec::new()));
        store.insert_loading_hidden(child.clone());
        store.insert_snapshot(ZoneSnapshot::active(child.clone(), Some(1), Vec::new()));

        let hidden_child = store
            .find_published_zone(&qname)
            .expect("published parent zone");
        assert_eq!(hidden_child.origin(), &parent);

        store.show_zone(&child);
        let visible_child = store
            .find_published_zone(&qname)
            .expect("published child zone");
        assert_eq!(visible_child.origin(), &child);
    }

    #[test]
    fn published_zone_lookup_updates_after_removal() {
        let store = ZoneStore::new();
        let parent = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();

        store.insert_snapshot(ZoneSnapshot::active(parent.clone(), Some(1), Vec::new()));
        store.insert_snapshot(ZoneSnapshot::active(child.clone(), Some(1), Vec::new()));
        assert_eq!(
            store
                .find_published_zone(&qname)
                .expect("published child zone")
                .origin(),
            &child
        );

        assert!(store.remove_zone(&child));
        assert_eq!(
            store
                .find_published_zone(&qname)
                .expect("published parent zone")
                .origin(),
            &parent
        );
    }

    #[test]
    fn zone_directory_suffix_prefixes_stay_inline_for_common_qnames() {
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();

        let (key, prefix_lengths) = canonical_reverse_label_key_with_prefixes(&qname, true);

        assert!(!key.spilled());
        assert!(!prefix_lengths.spilled());
        assert_eq!(key.as_slice(), b"\x04test\x07example\x05child\x03www");
        assert_eq!(prefix_lengths.as_slice(), &[5, 13, 19, 23]);
    }

    #[test]
    fn atomic_directory_update_never_exposes_partial_multi_zone_membership() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let store = ZoneStore::new();
        let old = (0..32)
            .map(|index| {
                DomainName::from_absolute_str(&format!("old-{index}.catalog-atomic.test.")).unwrap()
            })
            .collect::<Vec<_>>();
        let new = (0..32)
            .map(|index| {
                DomainName::from_absolute_str(&format!("new-{index}.catalog-atomic.test.")).unwrap()
            })
            .collect::<Vec<_>>();
        store.apply_atomic_directory_update(&old, &[], &[], &[]);
        let old_keys = old
            .iter()
            .map(DomainName::canonical_key)
            .collect::<std::collections::HashSet<_>>();
        let new_keys = new
            .iter()
            .map(DomainName::canonical_key)
            .collect::<std::collections::HashSet<_>>();
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let store = store.clone();
            let stop = stop.clone();
            let old_keys = old_keys.clone();
            let new_keys = new_keys.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let observed = store
                        .zone_metadata()
                        .into_iter()
                        .map(|metadata| metadata.origin.canonical_key())
                        .collect::<std::collections::HashSet<_>>();
                    assert!(
                        observed == old_keys || observed == new_keys,
                        "reader observed a partial directory publication"
                    );
                }
            })
        };

        for _ in 0..256 {
            store.apply_atomic_directory_update(&new, &old, &[], &[]);
            store.apply_atomic_directory_update(&old, &new, &[], &[]);
        }
        stop.store(true, Ordering::Release);
        reader.join().expect("directory reader does not panic");
    }

    #[test]
    fn ten_thousand_zone_batch_publication_has_linear_clone_work() {
        let store = ZoneStore::new();
        let initial = (0..10_000)
            .map(|index| {
                DomainName::from_absolute_str(&format!("zone-{index:05}.scale.test.")).unwrap()
            })
            .collect::<Vec<_>>();
        store.insert_loading_batch(&initial, &[]);

        assert_eq!(store.len(), initial.len());
        assert_eq!(
            store.publication_clone_work(),
            0,
            "one empty-to-10k batch must not repeatedly clone the growing directory"
        );

        let replacements = (0..1_000)
            .map(|index| {
                DomainName::from_absolute_str(&format!("replacement-{index:05}.scale.test."))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        store.apply_atomic_directory_update(&replacements, &initial[..1_000], &[], &[]);

        assert_eq!(store.len(), 10_000);
        assert_eq!(
            store.publication_clone_work(),
            10_000,
            "a 1k-zone replacement must clone the 10k directory once, not once per zone"
        );
        assert!(store.contains_exact_zone_for_control(&replacements[999]));
        assert!(!store.contains_exact_zone_for_control(&initial[999]));
    }

    #[test]
    fn zone_directory_suffix_key_uses_lowercase_hint_only_when_safe() {
        let lowercase = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let mixed_case = DomainName::from_absolute_str("WWW.Child.Example.Test.").unwrap();

        let (lowercase_key, lowercase_prefixes) =
            canonical_reverse_label_key_with_prefixes(&lowercase, true);
        let (mixed_case_key, mixed_case_prefixes) =
            canonical_reverse_label_key_with_prefixes(&mixed_case, false);

        assert_eq!(lowercase_key, mixed_case_key);
        assert_eq!(lowercase_prefixes, mixed_case_prefixes);
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
}
