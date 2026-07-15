use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use arc_swap::ArcSwap;
use smallvec::SmallVec;
use tracing::warn;

use crate::dns::{
    AnyResponseMode, DEFAULT_MAX_CNAME_CHAIN, DomainName, LookupResult, LookupTermination,
    RecordType,
};
use crate::zone_image::{ZoneImage, ZoneImageBuildError};

// ODS-NFR-MAINT-004 principal functional requirement references for the
// in-memory authoritative zone store:
// - ODS-FR-ZONE-001 ODS-FR-ZONE-002 ODS-FR-ZONE-003
// - ODS-FR-ZONE-004 ODS-FR-ZONE-005 ODS-FR-ZONE-006
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneState {
    Loading,
    Active,
    Expired,
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
    origin_key: NameKey,
    rrsets: HashMap<RrsetKey, Rrset>,
    name_classes: HashMap<NameKey, ClassSet>,
    empty_non_terminal_classes: HashMap<NameKey, ClassSet>,
    delegation_rrsets: Vec<RrsetKey>,
    dname_rrsets: Vec<RrsetKey>,
}

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
            origin_key,
            rrsets: HashMap::new(),
            name_classes: HashMap::new(),
            empty_non_terminal_classes: HashMap::new(),
            delegation_rrsets: Vec::new(),
            dname_rrsets: Vec::new(),
        }
    }

    pub fn active(origin: DomainName, serial: Option<u32>, rrsets: Vec<Rrset>) -> Self {
        let mut name_interner = NameInterner::default();
        let origin_key = name_interner.intern_domain(&origin);
        let mut by_key = HashMap::new();
        for rrset in rrsets {
            by_key.insert(
                RrsetKey::new_interned(
                    &rrset.owner,
                    rrset.rr_type,
                    rrset.class,
                    &mut name_interner,
                ),
                rrset,
            );
        }
        let soa_timers = soa_timers_from_rrsets(&origin_key, &by_key);
        let indexes = ZoneSnapshotIndexes::build(&origin, &by_key, &mut name_interner);

        Self {
            origin,
            state: ZoneState::Active,
            serial,
            soa_timers,
            origin_key,
            rrsets: by_key,
            name_classes: indexes.name_classes,
            empty_non_terminal_classes: indexes.empty_non_terminal_classes,
            delegation_rrsets: indexes.delegation_rrsets,
            dname_rrsets: indexes.dname_rrsets,
        }
    }

    pub fn with_state(&self, state: ZoneState) -> Self {
        Self {
            origin: self.origin.clone(),
            state,
            serial: self.serial,
            soa_timers: self.soa_timers,
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

    pub(crate) fn transfer_records(&self) -> Vec<ResourceRecord> {
        self.rrsets.values().flat_map(Rrset::records).collect()
    }

    pub(crate) fn rrsets(&self) -> impl Iterator<Item = &Rrset> {
        self.rrsets.values()
    }

    /// Return a narrow borrowed view for RFC 9432 catalog-zone parsing.
    pub fn catalog_zone_view(&self) -> CatalogZoneView<'_> {
        CatalogZoneView {
            origin: &self.origin,
            rrsets: &self.rrsets,
        }
    }

    pub fn shape_summary(&self) -> ZoneShapeSummary {
        let mut summary = ZoneShapeSummary {
            rrset_count: self.rrsets.len(),
            owner_name_count: self.name_classes.len(),
            empty_non_terminal_name_count: self.empty_non_terminal_classes.len(),
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
        self.offline_oracle_lookup_with_options(
            qname,
            qtype,
            qclass,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        )
    }

    fn offline_oracle_lookup_with_options(
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
        self.delegation_rrsets
            .iter()
            .filter_map(|key| self.rrsets.get(key))
            .filter(|rrset| {
                qclass_matches(rrset.class, qclass) && qname.is_equal_or_subdomain_of(&rrset.owner)
            })
            .max_by_key(|rrset| rrset.owner.label_count())
    }

    fn dname_for(&self, qname: &DomainName, qclass: u16) -> Option<&Rrset> {
        self.dname_rrsets
            .iter()
            .filter_map(|key| self.rrsets.get(key))
            .filter(|rrset| {
                qclass_matches(rrset.class, qclass)
                    && rrset.owner != *qname
                    && qname.is_equal_or_subdomain_of(&rrset.owner)
            })
            .max_by_key(|rrset| rrset.owner.label_count())
    }

    fn glue_for_ns_records(
        &self,
        delegation_owner: &DomainName,
        ns_records: &[ResourceRecord],
        qclass: u16,
    ) -> Vec<ResourceRecord> {
        let mut glue = Vec::new();
        for record in ns_records {
            let Some(target) = ns_target(record) else {
                continue;
            };
            if !target.is_equal_or_subdomain_of(delegation_owner) {
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
                .iter()
                .find(|(key, rrset)| key.owner.as_ref() == owner_key && rrset.rr_type == rr_type)
                .map(|(_, rrset)| rrset)
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
            .iter()
            .filter_map(|(key, rrset)| {
                if key.owner.as_ref() == owner_key && (qclass == 255 || rrset.class == qclass) {
                    Some(rrset)
                } else {
                    None
                }
            })
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
        self.name_classes
            .get(name_key)
            .is_some_and(|classes| classes_match(classes, qclass))
    }

    fn name_exists_or_is_empty_non_terminal_key(&self, name_key: &str, qclass: u16) -> bool {
        self.name_exists_key(name_key, qclass)
            || self
                .empty_non_terminal_classes
                .get(name_key)
                .is_some_and(|classes| classes_match(classes, qclass))
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
        self.snapshot.offline_oracle_lookup_with_options(
            qname,
            qtype,
            qclass,
            max_cname_chain,
            any_response,
        )
    }
}

fn soa_timers_from_rrsets(
    origin_key: &NameKey,
    rrsets: &HashMap<RrsetKey, Rrset>,
) -> Option<SoaTimers> {
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

fn parent_name_key(name_key: &str) -> Option<String> {
    let without_root = name_key.strip_suffix('.')?;
    let (_, parent) = without_root.split_once('.')?;
    Some(format!("{parent}."))
}

struct ZoneSnapshotIndexes {
    name_classes: HashMap<NameKey, ClassSet>,
    empty_non_terminal_classes: HashMap<NameKey, ClassSet>,
    delegation_rrsets: Vec<RrsetKey>,
    dname_rrsets: Vec<RrsetKey>,
}

type ClassSet = SmallVec<[u16; 1]>;
type NameKey = Arc<str>;

impl ZoneSnapshotIndexes {
    fn build(
        origin: &DomainName,
        rrsets: &HashMap<RrsetKey, Rrset>,
        name_interner: &mut NameInterner,
    ) -> Self {
        let mut indexes = Self {
            name_classes: HashMap::new(),
            empty_non_terminal_classes: HashMap::new(),
            delegation_rrsets: Vec::new(),
            dname_rrsets: Vec::new(),
        };
        let origin_key = origin.canonical_key();

        for (key, rrset) in rrsets {
            indexes
                .name_classes
                .entry(key.owner.clone())
                .and_modify(|classes| insert_class(classes, rrset.class))
                .or_insert_with(|| class_set(rrset.class));
            indexes.index_empty_non_terminals(origin, &rrset.owner, rrset.class, name_interner);

            if rrset.rr_type == RecordType::Ns as u16 && key.owner.as_ref() != origin_key {
                indexes.delegation_rrsets.push(key.clone());
            } else if rrset.rr_type == RecordType::Dname as u16 {
                indexes.dname_rrsets.push(key.clone());
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
                .entry(name_interner.intern_domain(&name))
                .and_modify(|classes| insert_class(classes, class))
                .or_insert_with(|| class_set(class));

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

fn classes_match(classes: &ClassSet, qclass: u16) -> bool {
    qclass == 255 || classes.contains(&qclass)
}

fn class_set(class: u16) -> ClassSet {
    let mut classes = SmallVec::new();
    classes.push(class);
    classes
}

fn insert_class(classes: &mut ClassSet, class: u16) {
    if !classes.contains(&class) {
        classes.push(class);
    }
}

fn qclass_matches(class: u16, qclass: u16) -> bool {
    qclass == 255 || class == qclass
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

fn is_dnssec_proof_or_signature_type(rr_type: u16) -> bool {
    rr_type == RecordType::Rrsig as u16
        || rr_type == RecordType::Nsec as u16
        || rr_type == RecordType::Nsec3 as u16
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
            svcb_target_name(record)
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
    rrsets: &'a HashMap<RrsetKey, Rrset>,
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
            #[cfg(test)]
            publication_clone_work: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ZoneStore {
    pub fn new() -> Self {
        Self::default()
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
        let mut next = self.clone_directory_for_publication(current.as_ref());
        let entry = Arc::new(ZoneStoreEntry::try_new(
            key.clone(),
            snapshot,
            hidden,
            incarnation,
        )?);
        next.insert(key.clone(), entry.clone());
        self.zones.store(Arc::new(next));
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
        let image = if snapshot.state == ZoneState::Active {
            Some(Arc::new(ZoneImage::compile(&snapshot)?))
        } else {
            None
        };
        let shape = (snapshot.state == ZoneState::Active).then(|| snapshot.shape_summary());
        let shape_histograms =
            (snapshot.state == ZoneState::Active).then(|| snapshot.shape_histogram_summary());
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
