use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    mem,
};

use sha1::{Digest, Sha1};
use smallvec::SmallVec;
use thiserror::Error;
use tracing::warn;

use crate::{
    dns::{AnyResponseMode, DomainName, LookupTermination, Rcode, RecordType},
    zone::ZoneSnapshot,
};

// ODS-NFR-MAINT-004 principal functional requirement references for the
// experimental immutable query data-plane image:
// - ODS-FR-ZONE-001 ODS-FR-ZONE-002 ODS-FR-ZONE-003
// - ODS-FR-QRY-001 ODS-FR-QRY-002 ODS-FR-QRY-003
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneImage {
    origin: DomainName,
    serial: Option<u32>,
    nodes: Box<[NameNode]>,
    edges: Box<[NameEdge]>,
    rrsets: Box<[ImageRrset]>,
    records: Box<[ImageRecord]>,
    delegation_rrsets: Box<[ZoneImageRrsetId]>,
    dname_rrsets: Box<[ZoneImageRrsetId]>,
    rrsig_covered: Box<[ImageRrsigCovered]>,
    nsec_rrsets: Box<[ZoneImageRrsetId]>,
    nsec3_rrsets: Box<[ZoneImageRrsetId]>,
    labels: Box<[u8]>,
    names: Box<[u8]>,
    rdata: Box<[u8]>,
    wire: Box<[u8]>,
    stats: ZoneImageStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneImageStats {
    pub record_count: usize,
    pub rrset_count: usize,
    pub name_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub max_child_fanout: usize,
    pub max_rrsets_per_name: usize,
    pub max_depth: usize,
    pub average_depth_times_1000: usize,
    pub rdata_bytes: usize,
    pub wire_bytes: usize,
    pub hot_bytes: usize,
    pub cold_bytes: usize,
    pub bytes_per_record: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneImageRrsetId(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneImageLookupPlan {
    rcode: Rcode,
    authoritative: bool,
    answer_rrsets: SmallVec<[ZoneImageRrsetId; 4]>,
    answer_items: SmallVec<[PlanAnswer; 1]>,
    authority_rrsets: SmallVec<[ZoneImageRrsetId; 4]>,
    additional_rrsets: SmallVec<[ZoneImageRrsetId; 8]>,
    owner_overrides: Vec<Vec<u8>>,
    synthesized_answers: Vec<ZoneImageSynthesizedRecord>,
    synthesized_authorities: Vec<ZoneImageSynthesizedRecord>,
    synthesized_additionals: Vec<ZoneImageSynthesizedRecord>,
    dnssec_augmented: bool,
    nsec3_iterations_exceeded: bool,
    termination: Option<LookupTermination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlanAnswer {
    Rrset(ZoneImageRrsetId),
    RrsetWithOwner {
        rrset_id: ZoneImageRrsetId,
        owner_index: usize,
    },
    Synthesized(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneImageSynthesizedRecord {
    owner_wire: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ZoneImageLookupOutcome {
    Found(ZoneImageLookupPlan),
    NoData,
    NameError,
    OutOfZone,
    Unsupported,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ZoneImageBuildError {
    #[error("zone image cannot encode more than u32::MAX {kind}")]
    TooManyItems { kind: &'static str },

    #[error("zone image arena {name} exceeds u32::MAX bytes")]
    ArenaTooLarge { name: &'static str },

    #[error("record owner {owner} is outside zone origin {origin}")]
    OutOfZoneOwner { owner: String, origin: String },

    #[error("compiled owner name could not be parsed back from wire form")]
    InvalidCompiledOwner,

    #[error("record RDATA exceeds DNS wire-format rdlength")]
    RdataTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneImagePlanSummary {
    pub rcode: Rcode,
    pub authoritative: bool,
    pub answers: ZoneImagePlanSectionSummary,
    pub authorities: ZoneImagePlanSectionSummary,
    pub additionals: ZoneImagePlanSectionSummary,
    pub termination: Option<LookupTermination>,
    pub nsec3_iterations_exceeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneImagePlanSectionSummary {
    pub count: usize,
    pub digest: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZoneImageWireRecord<'a> {
    pub owner_wire: &'a [u8],
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NameNode {
    first_edge: u32,
    edge_count: u16,
    first_rrset: u32,
    rrset_count: u16,
    parent: u32,
    depth: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NameEdge {
    label: BlobRange,
    child: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrset {
    owner_wire: BlobRange,
    rr_type: u16,
    class: u16,
    ttl: u32,
    negative_ttl: u32,
    first_record: u32,
    record_count: u16,
    wire: BlobRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRecord {
    rdata: BlobRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrsigCovered {
    rrset_id: ZoneImageRrsetId,
    covered_type: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlobRange {
    offset: u32,
    len: u32,
}

#[derive(Debug, Clone, Default)]
struct BuildNode {
    parent: u32,
    depth: u16,
    children: BTreeMap<Vec<u8>, u32>,
    rrsets: Vec<ZoneImageRrsetId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RrsetGroupKey {
    owner_key: String,
    rr_type: u16,
    class: u16,
    ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainState {
    visited: Vec<String>,
    remaining: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnssecSection {
    Answer,
    Authority,
    Additional,
}

struct ZoneImageDnssecState {
    seen_records: HashSet<(Vec<u8>, u16, u16, Vec<u8>)>,
    dnssec_augmented: bool,
    nsec3_iterations_exceeded: bool,
    nsec3_max_iterations: u16,
}

#[derive(Debug, Clone, Copy)]
struct ZoneImagePlanSectionAccumulator {
    count: usize,
    digest: u64,
}

impl Default for ZoneImagePlanSectionAccumulator {
    fn default() -> Self {
        Self {
            count: 0,
            digest: FNV_OFFSET_BASIS,
        }
    }
}

impl ZoneImagePlanSectionAccumulator {
    fn observe(&mut self, record: ZoneImageWireRecord<'_>) -> Result<(), ZoneImageBuildError> {
        self.count += 1;
        let owner_key = canonical_owner_key_from_wire(record.owner_wire)?;
        self.digest = fnv1a_u64(
            self.digest,
            hash_record_identity(
                owner_key.as_bytes(),
                record.rr_type,
                record.class,
                record.ttl,
                record.rdata,
            ),
        );
        Ok(())
    }

    fn finish(self) -> ZoneImagePlanSectionSummary {
        ZoneImagePlanSectionSummary {
            count: self.count,
            digest: self.digest,
        }
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn observe_zone_image_record_summary(
    record: ZoneImageWireRecord<'_>,
    accumulator: &mut ZoneImagePlanSectionAccumulator,
    error: &mut Option<ZoneImageBuildError>,
) {
    if error.is_some() {
        return;
    }
    if let Err(next_error) = accumulator.observe(record) {
        *error = Some(next_error);
    }
}

fn canonical_owner_key_from_wire(owner_wire: &[u8]) -> Result<String, ZoneImageBuildError> {
    let (owner, consumed) =
        DomainName::parse(owner_wire, 0).map_err(|_| ZoneImageBuildError::InvalidCompiledOwner)?;
    if consumed != owner_wire.len() {
        return Err(ZoneImageBuildError::InvalidCompiledOwner);
    }
    Ok(owner.canonical_key())
}

fn hash_record_identity(owner_key: &[u8], rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> u64 {
    let mut digest = FNV_OFFSET_BASIS;
    digest = fnv1a_bytes(digest, owner_key);
    digest = fnv1a_bytes(digest, &rr_type.to_be_bytes());
    digest = fnv1a_bytes(digest, &class.to_be_bytes());
    digest = fnv1a_bytes(digest, &ttl.to_be_bytes());
    digest = fnv1a_bytes(digest, &(rdata.len() as u64).to_be_bytes());
    fnv1a_bytes(digest, rdata)
}

fn fnv1a_u64(digest: u64, value: u64) -> u64 {
    fnv1a_bytes(digest, &value.to_be_bytes())
}

fn fnv1a_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(FNV_PRIME);
    }
    digest
}

impl ZoneImage {
    pub fn compile(snapshot: &ZoneSnapshot) -> Result<Self, ZoneImageBuildError> {
        let origin_key = snapshot.origin.canonical_key();
        let mut owner_names = HashMap::<String, DomainName>::new();
        let mut grouped = BTreeMap::<RrsetGroupKey, Vec<Vec<u8>>>::new();

        for record in snapshot.records() {
            let owner_key = record.owner.canonical_key();
            if !record.owner.is_equal_or_subdomain_of(&snapshot.origin) {
                return Err(ZoneImageBuildError::OutOfZoneOwner {
                    owner: owner_key,
                    origin: origin_key,
                });
            }

            owner_names
                .entry(owner_key.clone())
                .or_insert_with(|| record.owner.clone());
            grouped
                .entry(RrsetGroupKey {
                    owner_key,
                    rr_type: record.rr_type,
                    class: record.class,
                    ttl: record.ttl,
                })
                .or_default()
                .push(record.rdata);
        }

        let mut builder = ZoneImageBuilder::new(snapshot.origin.clone());
        for (group, mut rdatas) in grouped {
            rdatas.sort();
            let owner = owner_names
                .get(&group.owner_key)
                .expect("grouped owner must be present");
            let rrset_id =
                builder.push_rrset(owner, group.rr_type, group.class, group.ttl, &rdatas)?;
            builder.attach_rrset(owner, rrset_id)?;
        }

        builder.finish(snapshot.serial)
    }

    pub fn origin(&self) -> &DomainName {
        &self.origin
    }

    pub fn serial(&self) -> Option<u32> {
        self.serial
    }

    pub fn stats(&self) -> ZoneImageStats {
        self.stats
    }

    pub fn lookup_exact_plan(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> ZoneImageLookupOutcome {
        if qtype == 255 {
            return ZoneImageLookupOutcome::Unsupported;
        }
        let Some(node_index) = self.find_node(qname) else {
            return if qname.is_equal_or_subdomain_of(&self.origin) {
                ZoneImageLookupOutcome::NameError
            } else {
                ZoneImageLookupOutcome::OutOfZone
            };
        };
        let node = &self.nodes[node_index as usize];
        let mut plan = ZoneImageLookupPlan::positive();
        for offset in 0..node.rrset_count {
            let rrset_id = node.first_rrset + u32::from(offset);
            let rrset = self.rrsets[rrset_id as usize];
            if rrset.rr_type == qtype && qclass_matches(rrset.class, qclass) {
                plan.push_answer_rrset(ZoneImageRrsetId(rrset_id));
            }
        }

        if plan.answer_rrsets.is_empty() {
            ZoneImageLookupOutcome::NoData
        } else {
            ZoneImageLookupOutcome::Found(plan)
        }
    }

    pub fn lookup_direct_answer_plan(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> Option<ZoneImageLookupPlan> {
        if qtype == 255 {
            return None;
        }

        let node_index = self.find_node(qname)?;
        if self.covering_delegation_blocks_direct_answer(node_index, qtype, qclass)
            || self.covering_dname_blocks_direct_answer(node_index, qclass)
        {
            return None;
        }

        let rrset_id = self.find_rrset_at_node(node_index, qtype, qclass)?;
        let rr_type = self.rrsets[rrset_id.0 as usize].rr_type;
        if rr_type_may_have_additional_address_target(rr_type) {
            return None;
        }

        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_answer_rrset(rrset_id);
        Some(plan)
    }

    pub fn lookup_response_plan(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        if let Some(delegation) = self.delegation_for(qname, qclass)
            && !(qtype == RecordType::Ds as u16
                && qname.canonical_key() == self.rrset_owner(delegation)?.canonical_key())
        {
            let mut plan = ZoneImageLookupPlan::referral();
            plan.authority_rrsets.push(delegation);
            self.add_glue_for_ns_rrset(delegation, qclass, &mut plan)?;
            return Ok(plan);
        }

        if qtype == 255 {
            if let Some(node_index) = self.find_node(qname) {
                let mut plan = ZoneImageLookupPlan::positive();
                for rrset in self.any_rrsets_at_node(node_index, qclass, any_response) {
                    plan.push_answer_rrset(rrset);
                }
                if !plan.answer_rrsets.is_empty() {
                    self.add_additionals_for_answer_plan(&mut plan, qclass)?;
                    return Ok(plan);
                }
            }
        } else if let Some(rrset) = self.find_rrset(qname, qtype, qclass) {
            let mut plan = ZoneImageLookupPlan::positive();
            plan.push_answer_rrset(rrset);
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        }

        if qtype != RecordType::Cname as u16
            && let Some(cname) = self.find_rrset(qname, RecordType::Cname as u16, qclass)
        {
            let plan = self.resolve_cname_at(
                qname.clone(),
                qtype,
                qclass,
                ZoneImageLookupPlan::positive(),
                ChainState {
                    visited: vec![qname.canonical_key()],
                    remaining: max_cname_chain,
                },
                Some(cname),
            )?;
            return Ok(plan);
        }

        if let Some(dname) = self.dname_for(qname, qclass) {
            return self.lookup_dname(qname, qtype, qclass, max_cname_chain, dname);
        }

        if self.node_exists(qname) {
            return Ok(self.nodata_plan(qclass));
        }

        if let Some(wildcard_plan) =
            self.lookup_wildcard(qname, qtype, qclass, max_cname_chain, any_response)?
        {
            return Ok(wildcard_plan);
        }

        Ok(self.nxdomain_plan(qclass))
    }

    pub fn augment_lookup_plan_with_dnssec(
        &self,
        mut plan: ZoneImageLookupPlan,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        nsec3_max_iterations: u16,
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        let mut state = ZoneImageDnssecState {
            seen_records: self.plan_record_identity_set(&plan),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations,
        };
        let nodata_candidate = plan.rcode == Rcode::NoError
            && plan.authoritative
            && self.answer_record_count(&plan)? == 0;
        let nxdomain_candidate = plan.rcode == Rcode::NxDomain
            && plan.authoritative
            && self.answer_record_count(&plan)? == 0;
        let wildcard_candidate = self.is_wildcard_synthesis(qname, qtype, qclass, &plan);

        self.add_referral_dnssec_augmentations(&mut plan, &mut state)?;
        self.add_nodata_nsec_augmentations(
            qname,
            qtype,
            qclass,
            nodata_candidate,
            &mut plan,
            &mut state,
        )?;
        self.add_nxdomain_nsec_augmentations(
            qname,
            qclass,
            nxdomain_candidate,
            &mut plan,
            &mut state,
        )?;
        self.add_wildcard_nsec_augmentations(
            qname,
            qclass,
            wildcard_candidate,
            &mut plan,
            &mut state,
        )?;
        self.add_rrsig_augmentations(&mut plan, &mut state)?;

        plan.dnssec_augmented = state.dnssec_augmented;
        plan.nsec3_iterations_exceeded = state.nsec3_iterations_exceeded;
        Ok(plan)
    }

    pub fn rrset_wire(&self, rrset_id: ZoneImageRrsetId) -> Option<&[u8]> {
        let rrset = self.rrsets.get(rrset_id.0 as usize)?;
        Some(self.blob(&self.wire, rrset.wire))
    }

    pub(crate) fn rrset_owner_wire(&self, rrset_id: ZoneImageRrsetId) -> Option<&[u8]> {
        let rrset = self.rrsets.get(rrset_id.0 as usize)?;
        Some(self.blob(&self.names, rrset.owner_wire))
    }

    pub fn rrset_type(&self, rrset_id: ZoneImageRrsetId) -> Option<u16> {
        self.rrsets
            .get(rrset_id.0 as usize)
            .map(|rrset| rrset.rr_type)
    }

    pub fn append_plan_wire(
        &self,
        plan: &ZoneImageLookupPlan,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let mut record_count = self.append_answer_wire(plan, out)?;
        record_count += self.append_authority_wire(plan, out)?;
        record_count += self.append_additional_wire(plan, out)?;
        Ok(record_count)
    }

    pub fn plan_section_record_counts(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<(usize, usize, usize), ZoneImageBuildError> {
        Ok((
            self.answer_record_count(plan)?,
            self.rrset_list_record_count(&plan.authority_rrsets)?
                + plan.synthesized_authorities.len(),
            self.rrset_list_record_count(&plan.additional_rrsets)?
                + plan.synthesized_additionals.len(),
        ))
    }

    pub fn plan_summary(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<ZoneImagePlanSummary, ZoneImageBuildError> {
        let mut answers = ZoneImagePlanSectionAccumulator::default();
        let mut authorities = ZoneImagePlanSectionAccumulator::default();
        let mut additionals = ZoneImagePlanSectionAccumulator::default();
        let mut answer_error = None;
        let mut authority_error = None;
        let mut additional_error = None;
        self.visit_plan_record_sections(
            plan,
            |record| observe_zone_image_record_summary(record, &mut answers, &mut answer_error),
            |record| {
                observe_zone_image_record_summary(record, &mut authorities, &mut authority_error)
            },
            |record| {
                observe_zone_image_record_summary(record, &mut additionals, &mut additional_error)
            },
        );
        if let Some(error) = answer_error.or(authority_error).or(additional_error) {
            return Err(error);
        }
        Ok(ZoneImagePlanSummary {
            rcode: plan.rcode(),
            authoritative: plan.authoritative(),
            answers: answers.finish(),
            authorities: authorities.finish(),
            additionals: additionals.finish(),
            termination: plan.termination(),
            nsec3_iterations_exceeded: plan.nsec3_iterations_exceeded(),
        })
    }

    pub(crate) fn plan_wire_upper_bound(&self, plan: &ZoneImageLookupPlan) -> usize {
        let mut bytes = self.answer_wire_upper_bound(plan);
        bytes = bytes.saturating_add(self.rrset_list_wire_upper_bound(&plan.authority_rrsets));
        bytes = bytes.saturating_add(
            plan.synthesized_authorities
                .iter()
                .map(synthesized_record_wire_len)
                .sum::<usize>(),
        );
        bytes = bytes.saturating_add(self.rrset_list_wire_upper_bound(&plan.additional_rrsets));
        bytes = bytes.saturating_add(
            plan.synthesized_additionals
                .iter()
                .map(synthesized_record_wire_len)
                .sum::<usize>(),
        );
        bytes
    }

    pub fn append_answer_wire(
        &self,
        plan: &ZoneImageLookupPlan,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        if plan.answer_items.is_empty() {
            return self.append_rrset_list_wire(&plan.answer_rrsets, out);
        }

        let mut record_count = 0usize;
        for item in &plan.answer_items {
            record_count += match item {
                PlanAnswer::Rrset(rrset_id) => self.append_rrset_wire(*rrset_id, None, out)?,
                PlanAnswer::RrsetWithOwner {
                    rrset_id,
                    owner_index,
                } => self.append_rrset_wire_with_owner(
                    *rrset_id,
                    &plan.owner_overrides[*owner_index],
                    None,
                    out,
                )?,
                PlanAnswer::Synthesized(index) => {
                    let record = &plan.synthesized_answers[*index];
                    append_synthesized_record_wire(record, out)?;
                    1
                }
            };
        }
        Ok(record_count)
    }

    fn append_rrset_list_wire(
        &self,
        rrsets: &[ZoneImageRrsetId],
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let mut record_count = 0usize;
        for rrset_id in rrsets {
            record_count += self.append_rrset_wire(*rrset_id, None, out)?;
        }
        Ok(record_count)
    }

    pub fn append_authority_wire(
        &self,
        plan: &ZoneImageLookupPlan,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let mut record_count = 0usize;
        for rrset_id in &plan.authority_rrsets {
            let ttl_override = self.authority_ttl_override(plan, *rrset_id);
            record_count += self.append_rrset_wire(*rrset_id, ttl_override, out)?;
        }
        for record in &plan.synthesized_authorities {
            append_synthesized_record_wire(record, out)?;
            record_count += 1;
        }
        Ok(record_count)
    }

    pub fn append_additional_wire(
        &self,
        plan: &ZoneImageLookupPlan,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let mut record_count = 0usize;
        for rrset_id in &plan.additional_rrsets {
            record_count += self.append_rrset_wire(*rrset_id, None, out)?;
        }
        for record in &plan.synthesized_additionals {
            append_synthesized_record_wire(record, out)?;
            record_count += 1;
        }
        Ok(record_count)
    }

    pub(crate) fn visit_plan_records<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        mut visit: impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        if plan.answer_items.is_empty() {
            for rrset_id in &plan.answer_rrsets {
                self.visit_rrset_records(*rrset_id, None, &mut visit);
            }
        } else {
            for item in &plan.answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => {
                        self.visit_rrset_records(*rrset_id, None, &mut visit)
                    }
                    PlanAnswer::RrsetWithOwner {
                        rrset_id,
                        owner_index,
                    } => self.visit_rrset_records_with_owner(
                        *rrset_id,
                        &plan.owner_overrides[*owner_index],
                        None,
                        &mut visit,
                    ),
                    PlanAnswer::Synthesized(index) => {
                        let record = &plan.synthesized_answers[*index];
                        visit(synthesized_wire_record(record));
                    }
                }
            }
        }

        for rrset_id in &plan.authority_rrsets {
            let ttl_override = self.authority_ttl_override(plan, *rrset_id);
            self.visit_rrset_records(*rrset_id, ttl_override, &mut visit);
        }
        for record in &plan.synthesized_authorities {
            visit(synthesized_wire_record(record));
        }

        for rrset_id in &plan.additional_rrsets {
            self.visit_rrset_records(*rrset_id, None, &mut visit);
        }
        for record in &plan.synthesized_additionals {
            visit(synthesized_wire_record(record));
        }
    }

    pub(crate) fn visit_plan_record_sections<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        mut answer_visit: impl FnMut(ZoneImageWireRecord<'a>),
        mut authority_visit: impl FnMut(ZoneImageWireRecord<'a>),
        mut additional_visit: impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        if plan.answer_items.is_empty() {
            for rrset_id in &plan.answer_rrsets {
                self.visit_rrset_records(*rrset_id, None, &mut answer_visit);
            }
        } else {
            for item in &plan.answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => {
                        self.visit_rrset_records(*rrset_id, None, &mut answer_visit)
                    }
                    PlanAnswer::RrsetWithOwner {
                        rrset_id,
                        owner_index,
                    } => self.visit_rrset_records_with_owner(
                        *rrset_id,
                        &plan.owner_overrides[*owner_index],
                        None,
                        &mut answer_visit,
                    ),
                    PlanAnswer::Synthesized(index) => {
                        let record = &plan.synthesized_answers[*index];
                        answer_visit(synthesized_wire_record(record));
                    }
                }
            }
        }

        for rrset_id in &plan.authority_rrsets {
            let ttl_override = self.authority_ttl_override(plan, *rrset_id);
            self.visit_rrset_records(*rrset_id, ttl_override, &mut authority_visit);
        }
        for record in &plan.synthesized_authorities {
            authority_visit(synthesized_wire_record(record));
        }

        for rrset_id in &plan.additional_rrsets {
            self.visit_rrset_records(*rrset_id, None, &mut additional_visit);
        }
        for record in &plan.synthesized_additionals {
            additional_visit(synthesized_wire_record(record));
        }
    }

    fn answer_wire_upper_bound(&self, plan: &ZoneImageLookupPlan) -> usize {
        if plan.answer_items.is_empty() {
            return self.rrset_list_wire_upper_bound(&plan.answer_rrsets);
        }

        let mut bytes = 0usize;
        for item in &plan.answer_items {
            bytes = bytes.saturating_add(match item {
                PlanAnswer::Rrset(rrset_id) => self.rrset_wire_upper_bound(*rrset_id, None),
                PlanAnswer::RrsetWithOwner {
                    rrset_id,
                    owner_index,
                } => self.rrset_wire_upper_bound(
                    *rrset_id,
                    Some(plan.owner_overrides[*owner_index].len()),
                ),
                PlanAnswer::Synthesized(index) => {
                    synthesized_record_wire_len(&plan.synthesized_answers[*index])
                }
            });
        }
        bytes
    }

    fn rrset_list_wire_upper_bound(&self, rrsets: &[ZoneImageRrsetId]) -> usize {
        rrsets
            .iter()
            .map(|rrset_id| self.rrset_wire_upper_bound(*rrset_id, None))
            .sum()
    }

    fn rrset_wire_upper_bound(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire_len_override: Option<usize>,
    ) -> usize {
        let rrset = self.rrsets[rrset_id.0 as usize];
        if owner_wire_len_override.is_none() {
            return self.blob(&self.wire, rrset.wire).len();
        }

        let owner_wire_len = owner_wire_len_override.unwrap_or(0);
        let mut bytes = 0usize;
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            bytes = bytes
                .saturating_add(owner_wire_len)
                .saturating_add(10)
                .saturating_add(self.blob(&self.rdata, record.rdata).len());
        }
        bytes
    }

    fn visit_rrset_records<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        ttl_override: Option<u32>,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = self.blob(&self.names, rrset.owner_wire);
        self.visit_rrset_records_with_owner(rrset_id, owner_wire, ttl_override, visit);
    }

    fn visit_rrset_records_with_owner<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &'a [u8],
        ttl_override: Option<u32>,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            visit(ZoneImageWireRecord {
                owner_wire,
                rr_type: rrset.rr_type,
                class: rrset.class,
                ttl: ttl_override.unwrap_or(rrset.ttl),
                rdata: self.blob(&self.rdata, record.rdata),
            });
        }
    }

    fn answer_record_count(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<usize, ZoneImageBuildError> {
        if plan.answer_items.is_empty() {
            return self.rrset_list_record_count(&plan.answer_rrsets);
        }

        let mut record_count = 0usize;
        for item in &plan.answer_items {
            record_count += match item {
                PlanAnswer::Rrset(rrset_id) => self.rrset_record_count(*rrset_id)?,
                PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                    self.rrset_record_count(*rrset_id)?
                }
                PlanAnswer::Synthesized(_) => 1,
            };
        }
        Ok(record_count)
    }

    fn rrset_list_record_count(
        &self,
        rrsets: &[ZoneImageRrsetId],
    ) -> Result<usize, ZoneImageBuildError> {
        let mut record_count = 0usize;
        for rrset_id in rrsets {
            record_count += self.rrset_record_count(*rrset_id)?;
        }
        Ok(record_count)
    }

    fn rrset_record_count(&self, rrset_id: ZoneImageRrsetId) -> Result<usize, ZoneImageBuildError> {
        let Some(rrset) = self.rrsets.get(rrset_id.0 as usize) else {
            return Err(ZoneImageBuildError::InvalidCompiledOwner);
        };
        Ok(rrset.record_count as usize)
    }

    fn append_rrset_wire(
        &self,
        rrset_id: ZoneImageRrsetId,
        ttl_override: Option<u32>,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        if ttl_override.is_none() {
            out.extend_from_slice(self.blob(&self.wire, rrset.wire));
            return Ok(rrset.record_count as usize);
        }

        let owner_wire = self.blob(&self.names, rrset.owner_wire);
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = self.blob(&self.rdata, record.rdata);
            append_record_fields_wire(
                owner_wire,
                rrset.rr_type,
                rrset.class,
                ttl_override.unwrap_or(rrset.ttl),
                rdata,
                out,
            )?;
        }
        Ok(rrset.record_count as usize)
    }

    fn append_rrset_wire_with_owner(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &[u8],
        ttl_override: Option<u32>,
        out: &mut Vec<u8>,
    ) -> Result<usize, ZoneImageBuildError> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = self.blob(&self.rdata, record.rdata);
            append_record_fields_wire(
                owner_wire,
                rrset.rr_type,
                rrset.class,
                ttl_override.unwrap_or(rrset.ttl),
                rdata,
                out,
            )?;
        }
        Ok(rrset.record_count as usize)
    }

    fn authority_ttl_override(
        &self,
        plan: &ZoneImageLookupPlan,
        rrset_id: ZoneImageRrsetId,
    ) -> Option<u32> {
        if !plan.authoritative {
            return None;
        }
        let rrset = self.rrsets[rrset_id.0 as usize];
        if rrset.rr_type != RecordType::Soa as u16 {
            return None;
        }
        Some(rrset.negative_ttl)
    }

    fn nodata_plan(&self, qclass: u16) -> ZoneImageLookupPlan {
        let mut plan = ZoneImageLookupPlan::nodata();
        if let Some(soa) = self.soa_rrset(qclass) {
            plan.authority_rrsets.push(soa);
        }
        plan
    }

    fn nxdomain_plan(&self, qclass: u16) -> ZoneImageLookupPlan {
        let mut plan = ZoneImageLookupPlan::nxdomain();
        if let Some(soa) = self.soa_rrset(qclass) {
            plan.authority_rrsets.push(soa);
        }
        plan
    }

    fn find_rrset(
        &self,
        owner: &DomainName,
        rr_type: u16,
        qclass: u16,
    ) -> Option<ZoneImageRrsetId> {
        let node_index = self.find_node(owner)?;
        self.find_rrset_at_node(node_index, rr_type, qclass)
    }

    fn find_rrset_at_node(
        &self,
        node_index: u32,
        rr_type: u16,
        qclass: u16,
    ) -> Option<ZoneImageRrsetId> {
        let node = &self.nodes[node_index as usize];
        for offset in 0..node.rrset_count {
            let rrset_id = ZoneImageRrsetId(node.first_rrset + u32::from(offset));
            let rrset = self.rrsets[rrset_id.0 as usize];
            if rrset.rr_type == rr_type && qclass_matches(rrset.class, qclass) {
                return Some(rrset_id);
            }
        }
        None
    }

    fn any_rrsets_at_node(
        &self,
        node_index: u32,
        qclass: u16,
        any_response: AnyResponseMode,
    ) -> Vec<ZoneImageRrsetId> {
        let node = &self.nodes[node_index as usize];
        let mut rrsets = Vec::new();
        for offset in 0..node.rrset_count {
            let rrset_id = ZoneImageRrsetId(node.first_rrset + u32::from(offset));
            let rrset = self.rrsets[rrset_id.0 as usize];
            if qclass_matches(rrset.class, qclass)
                && !is_dnssec_proof_or_signature_type(rrset.rr_type)
            {
                rrsets.push(rrset_id);
            }
        }
        rrsets.sort_by_key(|rrset_id| {
            let rrset = self.rrsets[rrset_id.0 as usize];
            (rrset.class, rrset.rr_type)
        });
        if any_response == AnyResponseMode::Minimal {
            rrsets.truncate(1);
        }
        rrsets
    }

    fn node_exists(&self, owner: &DomainName) -> bool {
        self.find_node(owner).is_some()
    }

    fn soa_rrset(&self, qclass: u16) -> Option<ZoneImageRrsetId> {
        let class = if qclass == 255 { 1 } else { qclass };
        self.find_rrset(&self.origin, RecordType::Soa as u16, class)
    }

    fn rrset_owner(&self, rrset_id: ZoneImageRrsetId) -> Result<DomainName, ZoneImageBuildError> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let (owner, _) = DomainName::parse(self.blob(&self.names, rrset.owner_wire), 0)
            .map_err(|_| ZoneImageBuildError::InvalidCompiledOwner)?;
        Ok(owner)
    }

    fn delegation_for(&self, qname: &DomainName, qclass: u16) -> Option<ZoneImageRrsetId> {
        let node_index = self
            .find_node(qname)
            .or_else(|| self.closest_encloser_node(qname))?;
        self.delegation_for_node(node_index, qclass)
    }

    fn delegation_for_node(&self, mut node_index: u32, qclass: u16) -> Option<ZoneImageRrsetId> {
        while node_index != 0 {
            if let Some(rrset) = self.find_rrset_at_node(node_index, RecordType::Ns as u16, qclass)
            {
                return Some(rrset);
            }
            node_index = self.nodes[node_index as usize].parent;
        }
        None
    }

    fn dname_for(&self, qname: &DomainName, qclass: u16) -> Option<ZoneImageRrsetId> {
        let exact_node = self.find_node(qname);
        let mut node_index = exact_node.or_else(|| self.closest_encloser_node(qname))?;
        loop {
            if Some(node_index) != exact_node
                && let Some(rrset) =
                    self.find_rrset_at_node(node_index, RecordType::Dname as u16, qclass)
            {
                return Some(rrset);
            }
            if node_index == 0 {
                return None;
            }
            node_index = self.nodes[node_index as usize].parent;
        }
    }

    fn covering_delegation_blocks_direct_answer(
        &self,
        node_index: u32,
        qtype: u16,
        qclass: u16,
    ) -> bool {
        let Some(delegation) = self.delegation_for_node(node_index, qclass) else {
            return false;
        };
        if qtype != RecordType::Ds as u16 {
            return true;
        }
        self.find_rrset_at_node(node_index, RecordType::Ns as u16, qclass) != Some(delegation)
    }

    fn covering_dname_blocks_direct_answer(&self, node_index: u32, qclass: u16) -> bool {
        let mut parent = self.nodes[node_index as usize].parent;
        while parent != 0 {
            if self
                .find_rrset_at_node(parent, RecordType::Dname as u16, qclass)
                .is_some()
            {
                return true;
            }
            parent = self.nodes[parent as usize].parent;
        }
        false
    }

    fn lookup_dname(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        dname: ZoneImageRrsetId,
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        if self.rrsets[dname.0 as usize].record_count != 1 {
            let mut plan = ZoneImageLookupPlan::servfail(LookupTermination::MalformedDname);
            plan.push_answer_rrset(dname);
            return Ok(plan);
        }
        let Some(target) = self.first_single_name_rrset_target(dname) else {
            let mut plan = ZoneImageLookupPlan::servfail(LookupTermination::MalformedDname);
            plan.push_answer_rrset(dname);
            return Ok(plan);
        };
        let dname_owner = self.rrset_owner(dname)?;
        let Some(synthesized_target) = qname.with_replaced_suffix(&dname_owner, &target) else {
            let mut plan = ZoneImageLookupPlan::yxdomain();
            plan.push_answer_rrset(dname);
            if let Some(soa) = self.soa_rrset(qclass) {
                plan.authority_rrsets.push(soa);
            }
            return Ok(plan);
        };

        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_answer_rrset(dname);
        plan.push_synthesized_answer(
            qname,
            RecordType::Cname as u16,
            self.rrsets[dname.0 as usize].class,
            self.rrsets[dname.0 as usize].ttl,
            synthesized_target.to_wire(),
        );
        self.resolve_indirection_target(
            synthesized_target,
            qtype,
            qclass,
            plan,
            ChainState {
                visited: vec![qname.canonical_key()],
                remaining: max_cname_chain.saturating_sub(1),
            },
        )
    }

    fn lookup_wildcard(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> Result<Option<ZoneImageLookupPlan>, ZoneImageBuildError> {
        let Some(closest_node) = self.closest_encloser_node(qname) else {
            return Ok(None);
        };
        let Some(wildcard_node) = self.find_child(closest_node, b"*") else {
            return Ok(None);
        };

        if qtype == 255 {
            let rrsets = self.any_rrsets_at_node(wildcard_node, qclass, any_response);
            if !rrsets.is_empty() {
                let mut plan = ZoneImageLookupPlan::positive();
                for rrset in rrsets {
                    plan.push_answer_rrset_with_owner(rrset, qname);
                }
                self.add_additionals_for_answer_plan(&mut plan, qclass)?;
                return Ok(Some(plan));
            }
        } else if let Some(rrset) = self.find_rrset_at_node(wildcard_node, qtype, qclass) {
            let mut plan = ZoneImageLookupPlan::positive();
            plan.push_answer_rrset_with_owner(rrset, qname);
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(Some(plan));
        }

        if qtype != RecordType::Cname as u16
            && let Some(cname) =
                self.find_rrset_at_node(wildcard_node, RecordType::Cname as u16, qclass)
        {
            let mut plan = ZoneImageLookupPlan::positive();
            plan.push_answer_rrset_with_owner(cname, qname);
            let Some(target) = self.first_single_name_rrset_target(cname) else {
                return Ok(Some(plan));
            };
            let plan = self.resolve_indirection_target(
                target,
                qtype,
                qclass,
                plan,
                ChainState {
                    visited: vec![qname.canonical_key()],
                    remaining: max_cname_chain.saturating_sub(1),
                },
            )?;
            return Ok(Some(plan));
        }

        if self.nodes[wildcard_node as usize].rrset_count > 0 {
            return Ok(Some(self.nodata_plan(qclass)));
        }
        Ok(None)
    }

    fn resolve_cname_at(
        &self,
        current: DomainName,
        qtype: u16,
        qclass: u16,
        mut plan: ZoneImageLookupPlan,
        state: ChainState,
        cname_rrset: Option<ZoneImageRrsetId>,
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        if state.remaining == 0 {
            let original_qname = state
                .visited
                .first()
                .map(String::as_str)
                .unwrap_or("<unknown>");
            warn!(
                qname = %original_qname,
                zone = %self.origin,
                reason = "cname_chain_limit",
                current = %current,
                "CNAME chain limit reached; returning SERVFAIL with partial chain"
            );
            return Ok(plan.into_servfail(LookupTermination::CnameChainLimit));
        }

        let Some(cname) =
            cname_rrset.or_else(|| self.find_rrset(&current, RecordType::Cname as u16, qclass))
        else {
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        };
        plan.push_answer_rrset(cname);
        let Some(target) = self.first_single_name_rrset_target(cname) else {
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        };

        self.resolve_indirection_target(
            target,
            qtype,
            qclass,
            plan,
            ChainState {
                visited: state.visited,
                remaining: state.remaining - 1,
            },
        )
    }

    fn resolve_indirection_target(
        &self,
        target: DomainName,
        qtype: u16,
        qclass: u16,
        mut plan: ZoneImageLookupPlan,
        mut state: ChainState,
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        if !target.is_equal_or_subdomain_of(&self.origin) {
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        }

        let target_key = target.canonical_key();
        if state.visited.contains(&target_key) {
            let original_qname = state
                .visited
                .first()
                .map(String::as_str)
                .unwrap_or("<unknown>");
            warn!(
                qname = %original_qname,
                zone = %self.origin,
                reason = "cname_loop",
                looping_target = %target,
                "CNAME chain loop detected; returning SERVFAIL with partial chain"
            );
            return Ok(plan.into_servfail(LookupTermination::CnameLoop));
        }
        state.visited.push(target_key);

        if let Some(rrset) = self.find_rrset(&target, qtype, qclass) {
            plan.push_answer_rrset(rrset);
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        }

        if let Some(cname) = self.find_rrset(&target, RecordType::Cname as u16, qclass) {
            return self.resolve_cname_at(target, qtype, qclass, plan, state, Some(cname));
        }

        if self.node_exists(&target) {
            plan.rcode = Rcode::NoError;
            if let Some(soa) = self.soa_rrset(qclass) {
                plan.authority_rrsets.push(soa);
            }
        } else {
            plan.rcode = Rcode::NxDomain;
            if let Some(soa) = self.soa_rrset(qclass) {
                plan.authority_rrsets.push(soa);
            }
        }
        Ok(plan)
    }

    fn add_glue_for_ns_rrset(
        &self,
        ns_rrset: ZoneImageRrsetId,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
    ) -> Result<(), ZoneImageBuildError> {
        let delegation_owner = self.rrset_owner(ns_rrset)?;
        let rrset = self.rrsets[ns_rrset.0 as usize];
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            let Some(target) = ns_target_rdata(self.blob(&self.rdata, record.rdata)) else {
                continue;
            };
            if !target.is_equal_or_subdomain_of(&delegation_owner) {
                continue;
            }
            self.push_address_rrsets(&target, qclass, &mut plan.additional_rrsets);
        }
        Ok(())
    }

    fn add_additionals_for_answer_plan(
        &self,
        plan: &mut ZoneImageLookupPlan,
        qclass: u16,
    ) -> Result<(), ZoneImageBuildError> {
        let plan_needs_additionals = if plan.answer_items.is_empty() {
            plan.answer_rrsets.iter().any(|rrset_id| {
                rr_type_may_have_additional_address_target(self.rrsets[rrset_id.0 as usize].rr_type)
            })
        } else {
            plan.answer_items.iter().any(|item| match item {
                PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                    rr_type_may_have_additional_address_target(
                        self.rrsets[rrset_id.0 as usize].rr_type,
                    )
                }
                PlanAnswer::Synthesized(index) => rr_type_may_have_additional_address_target(
                    plan.synthesized_answers[*index].rr_type,
                ),
            })
        };
        if !plan_needs_additionals {
            return Ok(());
        }

        let mut seen = Vec::<ZoneImageRrsetId>::new();
        if plan.answer_items.is_empty() {
            let answer_rrsets = plan.answer_rrsets.clone();
            for rrset_id in answer_rrsets {
                self.push_additionals_for_rrset_targets(
                    rrset_id,
                    qclass,
                    &mut seen,
                    &mut plan.additional_rrsets,
                );
            }
        } else {
            let answer_items = plan.answer_items.clone();
            for item in answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => self.push_additionals_for_rrset_targets(
                        rrset_id,
                        qclass,
                        &mut seen,
                        &mut plan.additional_rrsets,
                    ),
                    PlanAnswer::RrsetWithOwner { rrset_id, .. } => self
                        .push_additionals_for_rrset_targets(
                            rrset_id,
                            qclass,
                            &mut seen,
                            &mut plan.additional_rrsets,
                        ),
                    PlanAnswer::Synthesized(index) => {
                        let record = &plan.synthesized_answers[index];
                        if let Some(target) =
                            additional_address_target_rdata(record.rr_type, &record.rdata)
                        {
                            self.push_additionals_for_target(
                                &target,
                                qclass,
                                &mut seen,
                                &mut plan.additional_rrsets,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn push_additionals_for_rrset_targets(
        &self,
        rrset_id: ZoneImageRrsetId,
        qclass: u16,
        seen: &mut Vec<ZoneImageRrsetId>,
        additional_rrsets: &mut SmallVec<[ZoneImageRrsetId; 8]>,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        if !rr_type_may_have_additional_address_target(rrset.rr_type) {
            return;
        }
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = self.blob(&self.rdata, record.rdata);
            let Some(target) = additional_address_target_rdata(rrset.rr_type, rdata) else {
                continue;
            };
            self.push_additionals_for_target(&target, qclass, seen, additional_rrsets);
        }
    }

    fn push_additionals_for_target(
        &self,
        target: &DomainName,
        qclass: u16,
        seen: &mut Vec<ZoneImageRrsetId>,
        additional_rrsets: &mut SmallVec<[ZoneImageRrsetId; 8]>,
    ) {
        if !target.is_equal_or_subdomain_of(&self.origin) {
            return;
        }
        for rr_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
            if let Some(rrset) = self.find_rrset(target, rr_type, qclass)
                && !seen.contains(&rrset)
                && !additional_rrsets.contains(&rrset)
            {
                seen.push(rrset);
                additional_rrsets.push(rrset);
            }
        }
    }

    fn add_referral_dnssec_augmentations(
        &self,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        let authority_rrsets = plan.authority_rrsets.clone();
        for rrset_id in authority_rrsets {
            let rrset = self.rrsets[rrset_id.0 as usize];
            if rrset.rr_type != RecordType::Ns as u16 {
                continue;
            }

            let owner = self.rrset_owner(rrset_id)?;
            if let Some(ds) = self.find_rrset(&owner, RecordType::Ds as u16, rrset.class) {
                self.push_authority_rrset(plan, ds, state);
            } else if let Some(nsec) = self.find_rrset(&owner, RecordType::Nsec as u16, rrset.class)
            {
                self.push_authority_rrset(plan, nsec, state);
            } else {
                self.push_nsec3_for_name(&owner, rrset.class, plan, state)?;
            }
        }
        Ok(())
    }

    fn add_nodata_nsec_augmentations(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        nodata_candidate: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        if !nodata_candidate
            || !self.plan_has_authority_type(plan, RecordType::Soa as u16)
            || self.find_rrset(qname, qtype, qclass).is_some()
        {
            return Ok(());
        }

        if let Some(nsec) = self.find_rrset(qname, RecordType::Nsec as u16, qclass) {
            self.push_authority_rrset(plan, nsec, state);
        } else {
            self.push_nsec3_for_name(qname, qclass, plan, state)?;
        }
        Ok(())
    }

    fn add_nxdomain_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        nxdomain_candidate: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        if !nxdomain_candidate || !self.plan_has_authority_type(plan, RecordType::Soa as u16) {
            return Ok(());
        }

        self.push_nsec_covering_name(qname, qclass, plan, state)?;
        self.push_nsec3_for_name(qname, qclass, plan, state)?;
        if let Some(closest_encloser) = self.closest_encloser_name(qname) {
            self.push_nsec_covering_name(&closest_encloser.wildcard_child(), qclass, plan, state)?;
            self.push_nsec3_for_name(&closest_encloser, qclass, plan, state)?;
            self.push_nsec3_for_name(&closest_encloser.wildcard_child(), qclass, plan, state)?;
        }
        Ok(())
    }

    fn add_wildcard_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        wildcard_candidate: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        if !wildcard_candidate {
            return Ok(());
        }

        self.push_nsec_covering_name(qname, qclass, plan, state)?;
        self.push_nsec3_for_name(qname, qclass, plan, state)
    }

    fn add_rrsig_augmentations(
        &self,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        if plan.answer_items.is_empty() {
            let answer_rrsets = plan.answer_rrsets.clone();
            for rrset_id in answer_rrsets {
                self.push_rrsig_for_rrset(DnssecSection::Answer, rrset_id, plan, state);
            }
        } else {
            let answer_items = plan.answer_items.clone();
            for item in answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => {
                        self.push_rrsig_for_rrset(DnssecSection::Answer, rrset_id, plan, state);
                    }
                    PlanAnswer::RrsetWithOwner { .. } | PlanAnswer::Synthesized(_) => {}
                }
            }
        }

        let authority_rrsets = plan.authority_rrsets.clone();
        for rrset_id in authority_rrsets {
            self.push_rrsig_for_rrset(DnssecSection::Authority, rrset_id, plan, state);
        }

        let additional_rrsets = plan.additional_rrsets.clone();
        for rrset_id in additional_rrsets {
            self.push_rrsig_for_rrset(DnssecSection::Additional, rrset_id, plan, state);
        }
        Ok(())
    }

    fn push_authority_rrset(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset_id: ZoneImageRrsetId,
        state: &mut ZoneImageDnssecState,
    ) {
        if !plan.authority_rrsets.contains(&rrset_id) {
            plan.authority_rrsets.push(rrset_id);
            state.dnssec_augmented = true;
            self.record_rrset_identities(rrset_id, None, &mut state.seen_records);
        }
    }

    fn push_nsec_covering_name(
        &self,
        name: &DomainName,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        let Some(nsec) = self.nsec_rrset_covering_name(name, qclass)? else {
            return Ok(());
        };
        self.push_authority_rrset(plan, nsec, state);
        Ok(())
    }

    fn nsec_rrset_covering_name(
        &self,
        name: &DomainName,
        qclass: u16,
    ) -> Result<Option<ZoneImageRrsetId>, ZoneImageBuildError> {
        for rrset_id in &self.nsec_rrsets {
            let rrset = self.rrsets[rrset_id.0 as usize];
            if !qclass_matches(rrset.class, qclass) {
                continue;
            }
            let owner = self.rrset_owner(*rrset_id)?;
            for offset in 0..rrset.record_count {
                let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
                if nsec_covers_name(&owner, self.blob(&self.rdata, record.rdata), name) {
                    return Ok(Some(*rrset_id));
                }
            }
        }
        Ok(None)
    }

    fn push_nsec3_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) -> Result<(), ZoneImageBuildError> {
        let Some(nsec3) = self.nsec3_rrset_for_name(
            name,
            qclass,
            &mut state.nsec3_iterations_exceeded,
            state.nsec3_max_iterations,
        )?
        else {
            return Ok(());
        };
        self.push_authority_rrset(plan, nsec3, state);
        Ok(())
    }

    fn nsec3_rrset_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        nsec3_iterations_exceeded: &mut bool,
        nsec3_max_iterations: u16,
    ) -> Result<Option<ZoneImageRrsetId>, ZoneImageBuildError> {
        let mut candidates = Vec::new();
        for rrset_id in &self.nsec3_rrsets {
            let rrset = self.rrsets[rrset_id.0 as usize];
            if !qclass_matches(rrset.class, qclass) || rrset.record_count == 0 {
                continue;
            }
            let record = self.records[rrset.first_record as usize];
            let rdata = self.blob(&self.rdata, record.rdata);
            let Some(params) = nsec3_params_from_rdata(rdata) else {
                continue;
            };
            if params.iterations > nsec3_max_iterations {
                *nsec3_iterations_exceeded = true;
                continue;
            }
            let Some(hash) = nsec3_hash_name(name, &params) else {
                continue;
            };
            let owner = self.rrset_owner(*rrset_id)?;
            let Some(owner_hash) = nsec3_owner_hash_label(&owner, &self.origin) else {
                continue;
            };
            let Some(next_hash) = nsec3_next_hash_label(rdata) else {
                continue;
            };
            candidates.push((*rrset_id, hash, owner_hash, next_hash));
        }

        Ok(candidates
            .iter()
            .find(|(_, hash, owner_hash, _)| hash == owner_hash)
            .map(|(rrset_id, _, _, _)| *rrset_id)
            .or_else(|| {
                candidates
                    .iter()
                    .find(|(_, hash, owner_hash, next_hash)| {
                        nsec3_range_covers_hash(owner_hash, next_hash, hash)
                    })
                    .map(|(rrset_id, _, _, _)| *rrset_id)
            }))
    }

    fn push_rrsig_for_rrset(
        &self,
        section: DnssecSection,
        covered_rrset_id: ZoneImageRrsetId,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        let covered_rrset = self.rrsets[covered_rrset_id.0 as usize];
        if covered_rrset.rr_type == RecordType::Rrsig as u16 {
            return;
        }
        let owner_wire = self.blob(&self.names, covered_rrset.owner_wire).to_vec();
        for index in &self.rrsig_covered {
            if index.covered_type != covered_rrset.rr_type {
                continue;
            }
            let rrsig_rrset = self.rrsets[index.rrset_id.0 as usize];
            if rrsig_rrset.class != covered_rrset.class
                || self.blob(&self.names, rrsig_rrset.owner_wire) != owner_wire
            {
                continue;
            }
            for offset in 0..rrsig_rrset.record_count {
                let record = self.records[(rrsig_rrset.first_record + u32::from(offset)) as usize];
                let rdata = self.blob(&self.rdata, record.rdata);
                if rrsig_type_covered_rdata(rdata) != Some(covered_rrset.rr_type) {
                    continue;
                }
                let identity = (
                    owner_wire.clone(),
                    rrsig_rrset.rr_type,
                    rrsig_rrset.class,
                    rdata.to_vec(),
                );
                if !state.seen_records.insert(identity) {
                    continue;
                }
                let record = ZoneImageSynthesizedRecord {
                    owner_wire: owner_wire.clone(),
                    rr_type: rrsig_rrset.rr_type,
                    class: rrsig_rrset.class,
                    ttl: rrsig_rrset.ttl,
                    rdata: rdata.to_vec(),
                };
                plan.push_synthesized_section(section, record);
                state.dnssec_augmented = true;
            }
        }
    }

    fn plan_record_identity_set(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> HashSet<(Vec<u8>, u16, u16, Vec<u8>)> {
        let mut seen = HashSet::new();
        self.record_plan_identities(plan, &mut seen);
        seen
    }

    fn record_plan_identities(
        &self,
        plan: &ZoneImageLookupPlan,
        seen: &mut HashSet<(Vec<u8>, u16, u16, Vec<u8>)>,
    ) {
        if plan.answer_items.is_empty() {
            for rrset_id in &plan.answer_rrsets {
                self.record_rrset_identities(*rrset_id, None, seen);
            }
        } else {
            for item in &plan.answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => {
                        self.record_rrset_identities(*rrset_id, None, seen)
                    }
                    PlanAnswer::RrsetWithOwner {
                        rrset_id,
                        owner_index,
                    } => self.record_rrset_identities(
                        *rrset_id,
                        Some(&plan.owner_overrides[*owner_index]),
                        seen,
                    ),
                    PlanAnswer::Synthesized(index) => {
                        record_synthesized_identity(&plan.synthesized_answers[*index], seen);
                    }
                }
            }
        }
        for rrset_id in &plan.authority_rrsets {
            self.record_rrset_identities(*rrset_id, None, seen);
        }
        for rrset_id in &plan.additional_rrsets {
            self.record_rrset_identities(*rrset_id, None, seen);
        }
        for record in &plan.synthesized_authorities {
            record_synthesized_identity(record, seen);
        }
        for record in &plan.synthesized_additionals {
            record_synthesized_identity(record, seen);
        }
    }

    fn record_rrset_identities(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_override: Option<&[u8]>,
        seen: &mut HashSet<(Vec<u8>, u16, u16, Vec<u8>)>,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = owner_override
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| self.blob(&self.names, rrset.owner_wire).to_vec());
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            seen.insert((
                owner_wire.clone(),
                rrset.rr_type,
                rrset.class,
                self.blob(&self.rdata, record.rdata).to_vec(),
            ));
        }
    }

    fn plan_has_authority_type(&self, plan: &ZoneImageLookupPlan, rr_type: u16) -> bool {
        plan.authority_rrsets
            .iter()
            .any(|rrset_id| self.rrsets[rrset_id.0 as usize].rr_type == rr_type)
            || plan
                .synthesized_authorities
                .iter()
                .any(|record| record.rr_type == rr_type)
    }

    fn is_wildcard_synthesis(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        plan: &ZoneImageLookupPlan,
    ) -> bool {
        if plan.rcode != Rcode::NoError
            || !plan.authoritative
            || self.answer_record_count(plan).ok().unwrap_or_default() == 0
            || self.node_exists(qname)
        {
            return false;
        }
        let Some(first_owner) = self.first_answer_owner_wire(plan) else {
            return false;
        };
        if !wire_names_equal_ignore_ascii_case(&first_owner, &qname.to_wire()) {
            return false;
        }
        let Some(closest) = self.closest_encloser_name(qname) else {
            return false;
        };
        let wildcard = closest.wildcard_child();
        self.find_rrset(&wildcard, qtype, qclass).is_some()
            || (qtype != RecordType::Cname as u16
                && self
                    .find_rrset(&wildcard, RecordType::Cname as u16, qclass)
                    .is_some())
    }

    fn first_answer_owner_wire(&self, plan: &ZoneImageLookupPlan) -> Option<Vec<u8>> {
        if plan.answer_items.is_empty() {
            let rrset_id = *plan.answer_rrsets.first()?;
            return Some(
                self.blob(&self.names, self.rrsets[rrset_id.0 as usize].owner_wire)
                    .to_vec(),
            );
        }
        match plan.answer_items.first()? {
            PlanAnswer::Rrset(rrset_id) => Some(
                self.blob(&self.names, self.rrsets[rrset_id.0 as usize].owner_wire)
                    .to_vec(),
            ),
            PlanAnswer::RrsetWithOwner { owner_index, .. } => {
                Some(plan.owner_overrides[*owner_index].clone())
            }
            PlanAnswer::Synthesized(index) => {
                Some(plan.synthesized_answers[*index].owner_wire.clone())
            }
        }
    }

    fn closest_encloser_name(&self, qname: &DomainName) -> Option<DomainName> {
        let mut candidate = qname.parent()?;
        loop {
            if !candidate.is_equal_or_subdomain_of(&self.origin) {
                return None;
            }
            if self.find_node(&candidate).is_some() {
                return Some(candidate);
            }
            if candidate == self.origin {
                return None;
            }
            candidate = candidate.parent()?;
        }
    }

    fn push_address_rrsets(
        &self,
        target: &DomainName,
        qclass: u16,
        rrsets: &mut SmallVec<[ZoneImageRrsetId; 8]>,
    ) {
        for rr_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
            if let Some(rrset) = self.find_rrset(target, rr_type, qclass)
                && !rrsets.contains(&rrset)
            {
                rrsets.push(rrset);
            }
        }
    }

    fn first_single_name_rrset_target(&self, rrset_id: ZoneImageRrsetId) -> Option<DomainName> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        if rrset.record_count == 0 {
            return None;
        }
        let record = self.records[rrset.first_record as usize];
        single_name_rdata_bytes(self.blob(&self.rdata, record.rdata))
    }

    fn closest_encloser_node(&self, qname: &DomainName) -> Option<u32> {
        let mut candidate = qname.parent()?;
        loop {
            if !candidate.is_equal_or_subdomain_of(&self.origin) {
                return None;
            }
            if let Some(node) = self.find_node(&candidate) {
                return Some(node);
            }
            if candidate == self.origin {
                return None;
            }
            candidate = candidate.parent()?;
        }
    }

    fn find_child(&self, node_index: u32, label: &[u8]) -> Option<u32> {
        let node = &self.nodes[node_index as usize];
        let edges = &self.edges
            [node.first_edge as usize..(node.first_edge + u32::from(node.edge_count)) as usize];
        let mut left = 0usize;
        let mut right = edges.len();
        while left < right {
            let mid = left + (right - left) / 2;
            let edge_label = self.blob(&self.labels, edges[mid].label);
            match cmp_lowercase_label(edge_label, label) {
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid,
                Ordering::Equal => return Some(edges[mid].child),
            }
        }
        None
    }

    fn find_node(&self, qname: &DomainName) -> Option<u32> {
        let labels = relative_label_slice(qname, &self.origin)?;
        let mut node_index = 0u32;
        for label in labels.iter().rev() {
            node_index = self.find_child(node_index, label)?;
        }
        Some(node_index)
    }

    fn blob<'a>(&self, arena: &'a [u8], range: BlobRange) -> &'a [u8] {
        let start = range.offset as usize;
        let end = start + range.len as usize;
        &arena[start..end]
    }
}

impl ZoneImageLookupPlan {
    fn positive() -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answer_rrsets: SmallVec::new(),
            answer_items: SmallVec::new(),
            authority_rrsets: SmallVec::new(),
            additional_rrsets: SmallVec::new(),
            owner_overrides: Vec::new(),
            synthesized_answers: Vec::new(),
            synthesized_authorities: Vec::new(),
            synthesized_additionals: Vec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            termination: None,
        }
    }

    fn referral() -> Self {
        Self {
            authoritative: false,
            ..Self::positive()
        }
    }

    fn nodata() -> Self {
        Self::positive()
    }

    fn nxdomain() -> Self {
        Self {
            rcode: Rcode::NxDomain,
            ..Self::positive()
        }
    }

    fn yxdomain() -> Self {
        Self {
            rcode: Rcode::YxDomain,
            ..Self::positive()
        }
    }

    fn servfail(termination: LookupTermination) -> Self {
        Self {
            rcode: Rcode::ServFail,
            termination: Some(termination),
            ..Self::positive()
        }
    }

    fn into_servfail(mut self, termination: LookupTermination) -> Self {
        self.rcode = Rcode::ServFail;
        self.authoritative = true;
        self.termination = Some(termination);
        self.authority_rrsets.clear();
        self.additional_rrsets.clear();
        self
    }

    pub fn answer_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.answer_rrsets
    }

    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    pub fn authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn termination(&self) -> Option<LookupTermination> {
        self.termination
    }

    pub fn synthesized_answer_count(&self) -> usize {
        self.synthesized_answers.len()
    }

    pub fn dnssec_augmented(&self) -> bool {
        self.dnssec_augmented
    }

    pub fn nsec3_iterations_exceeded(&self) -> bool {
        self.nsec3_iterations_exceeded
    }

    fn push_answer_rrset(&mut self, rrset: ZoneImageRrsetId) {
        self.answer_rrsets.push(rrset);
        if !self.answer_items.is_empty() {
            self.answer_items.push(PlanAnswer::Rrset(rrset));
        }
    }

    fn push_answer_rrset_with_owner(&mut self, rrset: ZoneImageRrsetId, owner: &DomainName) {
        self.ensure_answer_items();
        let owner_index = self.owner_overrides.len();
        self.owner_overrides.push(owner.to_wire());
        self.answer_items.push(PlanAnswer::RrsetWithOwner {
            rrset_id: rrset,
            owner_index,
        });
    }

    fn push_synthesized_answer(
        &mut self,
        owner: &DomainName,
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    ) {
        self.ensure_answer_items();
        let index = self.synthesized_answers.len();
        self.synthesized_answers.push(ZoneImageSynthesizedRecord {
            owner_wire: owner.to_wire(),
            rr_type,
            class,
            ttl,
            rdata,
        });
        self.answer_items.push(PlanAnswer::Synthesized(index));
    }

    fn push_synthesized_section(
        &mut self,
        section: DnssecSection,
        record: ZoneImageSynthesizedRecord,
    ) {
        match section {
            DnssecSection::Answer => {
                self.ensure_answer_items();
                let index = self.synthesized_answers.len();
                self.synthesized_answers.push(record);
                self.answer_items.push(PlanAnswer::Synthesized(index));
            }
            DnssecSection::Authority => self.synthesized_authorities.push(record),
            DnssecSection::Additional => self.synthesized_additionals.push(record),
        }
    }

    fn ensure_answer_items(&mut self) {
        if self.answer_items.is_empty() {
            self.answer_items
                .extend(self.answer_rrsets.iter().copied().map(PlanAnswer::Rrset));
        }
    }

    pub fn authority_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.authority_rrsets
    }

    pub fn additional_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.additional_rrsets
    }
}

struct ZoneImageBuilder {
    origin: DomainName,
    build_nodes: Vec<BuildNode>,
    image_rrsets: Vec<ImageRrset>,
    image_records: Vec<ImageRecord>,
    delegation_rrsets: Vec<ZoneImageRrsetId>,
    dname_rrsets: Vec<ZoneImageRrsetId>,
    rrsig_covered: Vec<ImageRrsigCovered>,
    nsec_rrsets: Vec<ZoneImageRrsetId>,
    nsec3_rrsets: Vec<ZoneImageRrsetId>,
    labels: Vec<u8>,
    names: Vec<u8>,
    rdata: Vec<u8>,
    wire: Vec<u8>,
}

impl ZoneImageBuilder {
    fn new(origin: DomainName) -> Self {
        Self {
            origin,
            build_nodes: vec![BuildNode::default()],
            image_rrsets: Vec::new(),
            image_records: Vec::new(),
            delegation_rrsets: Vec::new(),
            dname_rrsets: Vec::new(),
            rrsig_covered: Vec::new(),
            nsec_rrsets: Vec::new(),
            nsec3_rrsets: Vec::new(),
            labels: Vec::new(),
            names: Vec::new(),
            rdata: Vec::new(),
            wire: Vec::new(),
        }
    }

    fn push_rrset(
        &mut self,
        owner: &DomainName,
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdatas: &[Vec<u8>],
    ) -> Result<ZoneImageRrsetId, ZoneImageBuildError> {
        let rrset_index = checked_u32(self.image_rrsets.len(), "rrsets").map(ZoneImageRrsetId)?;
        let owner_wire = owner.to_wire();
        let owner_wire_ref = push_blob(&mut self.names, &owner_wire, "names")?;
        let first_record = checked_u32(self.image_records.len(), "records")?;
        let wire_start = checked_u32(self.wire.len(), "wire")?;

        for rdata in rdatas {
            let rdata_ref = push_blob(&mut self.rdata, rdata, "rdata")?;
            self.image_records.push(ImageRecord { rdata: rdata_ref });
            self.wire.extend_from_slice(&owner_wire);
            self.wire.extend_from_slice(&rr_type.to_be_bytes());
            self.wire.extend_from_slice(&class.to_be_bytes());
            self.wire.extend_from_slice(&ttl.to_be_bytes());
            self.wire
                .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            self.wire.extend_from_slice(rdata);
        }

        let wire_end = checked_u32(self.wire.len(), "wire")?;
        let negative_ttl = if rr_type == RecordType::Soa as u16 {
            rdatas
                .first()
                .and_then(|rdata| soa_minimum(rdata))
                .map_or(ttl, |minimum| ttl.min(minimum))
        } else {
            ttl
        };
        self.image_rrsets.push(ImageRrset {
            owner_wire: owner_wire_ref,
            rr_type,
            class,
            ttl,
            negative_ttl,
            first_record,
            record_count: checked_u16(rdatas.len(), "records")?,
            wire: BlobRange {
                offset: wire_start,
                len: wire_end - wire_start,
            },
        });
        if rr_type == RecordType::Ns as u16 && *owner != self.origin {
            self.delegation_rrsets.push(rrset_index);
        } else if rr_type == RecordType::Dname as u16 {
            self.dname_rrsets.push(rrset_index);
        } else if rr_type == RecordType::Nsec as u16 {
            self.nsec_rrsets.push(rrset_index);
        } else if rr_type == RecordType::Nsec3 as u16 {
            self.nsec3_rrsets.push(rrset_index);
        } else if rr_type == RecordType::Rrsig as u16 {
            let mut covered_types = Vec::new();
            for rdata in rdatas {
                let Some(covered_type) = rrsig_type_covered_rdata(rdata) else {
                    continue;
                };
                if !covered_types.contains(&covered_type) {
                    covered_types.push(covered_type);
                }
            }
            covered_types.sort_unstable();
            for covered_type in covered_types {
                self.rrsig_covered.push(ImageRrsigCovered {
                    rrset_id: rrset_index,
                    covered_type,
                });
            }
        }
        Ok(rrset_index)
    }

    fn attach_rrset(
        &mut self,
        owner: &DomainName,
        rrset_id: ZoneImageRrsetId,
    ) -> Result<(), ZoneImageBuildError> {
        let mut node_index = 0u32;
        for label in relative_reversed_labels_owned(owner, &self.origin).ok_or_else(|| {
            ZoneImageBuildError::OutOfZoneOwner {
                owner: owner.canonical_key(),
                origin: self.origin.canonical_key(),
            }
        })? {
            let existing = self.build_nodes[node_index as usize]
                .children
                .get(&label)
                .copied();
            node_index = match existing {
                Some(child) => child,
                None => {
                    let child = checked_u32(self.build_nodes.len(), "nodes")?;
                    let depth = self.build_nodes[node_index as usize].depth + 1;
                    self.build_nodes.push(BuildNode {
                        parent: node_index,
                        depth,
                        children: BTreeMap::new(),
                        rrsets: Vec::new(),
                    });
                    self.build_nodes[node_index as usize]
                        .children
                        .insert(label, child);
                    child
                }
            };
        }
        self.build_nodes[node_index as usize].rrsets.push(rrset_id);
        Ok(())
    }

    fn finish(self, serial: Option<u32>) -> Result<ZoneImage, ZoneImageBuildError> {
        let mut nodes = Vec::with_capacity(self.build_nodes.len());
        let mut edges = Vec::new();
        let mut labels = self.labels;

        for build_node in &self.build_nodes {
            let first_edge = checked_u32(edges.len(), "edges")?;
            for (label, child) in &build_node.children {
                let label_ref = push_blob(&mut labels, label, "labels")?;
                edges.push(NameEdge {
                    label: label_ref,
                    child: *child,
                });
            }
            let first_rrset = build_node.rrsets.first().map(|id| id.0).unwrap_or(u32::MAX);
            nodes.push(NameNode {
                first_edge,
                edge_count: checked_u16(build_node.children.len(), "edges")?,
                first_rrset,
                rrset_count: checked_u16(build_node.rrsets.len(), "rrsets")?,
                parent: build_node.parent,
                depth: build_node.depth,
            });
        }

        let total_depth = self
            .build_nodes
            .iter()
            .map(|node| node.depth as usize)
            .sum::<usize>();
        let average_depth_times_1000 = if self.build_nodes.is_empty() {
            0
        } else {
            (total_depth * 1000) / self.build_nodes.len()
        };
        let record_count = self.image_records.len();
        let hot_bytes = nodes.len() * mem::size_of::<NameNode>()
            + edges.len() * mem::size_of::<NameEdge>()
            + self.image_rrsets.len() * mem::size_of::<ImageRrset>()
            + self.image_records.len() * mem::size_of::<ImageRecord>()
            + self.delegation_rrsets.len() * mem::size_of::<ZoneImageRrsetId>()
            + self.dname_rrsets.len() * mem::size_of::<ZoneImageRrsetId>()
            + self.rrsig_covered.len() * mem::size_of::<ImageRrsigCovered>()
            + self.nsec_rrsets.len() * mem::size_of::<ZoneImageRrsetId>()
            + self.nsec3_rrsets.len() * mem::size_of::<ZoneImageRrsetId>();
        let cold_bytes = labels.len() + self.names.len() + self.rdata.len() + self.wire.len();
        let stats = ZoneImageStats {
            record_count,
            rrset_count: self.image_rrsets.len(),
            name_count: self
                .build_nodes
                .iter()
                .filter(|node| !node.rrsets.is_empty())
                .count(),
            node_count: nodes.len(),
            edge_count: edges.len(),
            max_child_fanout: nodes
                .iter()
                .map(|node| usize::from(node.edge_count))
                .max()
                .unwrap_or_default(),
            max_rrsets_per_name: nodes
                .iter()
                .map(|node| usize::from(node.rrset_count))
                .max()
                .unwrap_or_default(),
            max_depth: self
                .build_nodes
                .iter()
                .map(|node| node.depth as usize)
                .max()
                .unwrap_or_default(),
            average_depth_times_1000,
            rdata_bytes: self.rdata.len(),
            wire_bytes: self.wire.len(),
            hot_bytes,
            cold_bytes,
            bytes_per_record: (hot_bytes + cold_bytes)
                .checked_div(record_count)
                .unwrap_or_default(),
        };

        Ok(ZoneImage {
            origin: self.origin,
            serial,
            nodes: nodes.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            rrsets: self.image_rrsets.into_boxed_slice(),
            records: self.image_records.into_boxed_slice(),
            delegation_rrsets: self.delegation_rrsets.into_boxed_slice(),
            dname_rrsets: self.dname_rrsets.into_boxed_slice(),
            rrsig_covered: self.rrsig_covered.into_boxed_slice(),
            nsec_rrsets: self.nsec_rrsets.into_boxed_slice(),
            nsec3_rrsets: self.nsec3_rrsets.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
            names: self.names.into_boxed_slice(),
            rdata: self.rdata.into_boxed_slice(),
            wire: self.wire.into_boxed_slice(),
            stats,
        })
    }
}

fn relative_label_slice<'a>(name: &'a DomainName, origin: &DomainName) -> Option<&'a [Vec<u8>]> {
    let name_labels = name.labels();
    let origin_labels = origin.labels();
    if origin_labels.len() > name_labels.len() {
        return None;
    }

    let prefix_len = name_labels.len() - origin_labels.len();
    let suffix_matches = name_labels[prefix_len..]
        .iter()
        .zip(origin_labels)
        .all(|(left, right)| left.eq_ignore_ascii_case(right));
    suffix_matches.then_some(&name_labels[..prefix_len])
}

fn relative_reversed_labels_owned(name: &DomainName, origin: &DomainName) -> Option<Vec<Vec<u8>>> {
    let mut labels = relative_label_slice(name, origin)?
        .iter()
        .map(|label| label.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    labels.reverse();
    Some(labels)
}

fn cmp_lowercase_label(stored_lowercase: &[u8], query_label: &[u8]) -> Ordering {
    let mut left = stored_lowercase.iter().copied();
    let mut right = query_label.iter().map(u8::to_ascii_lowercase);
    loop {
        match (left.next(), right.next()) {
            (Some(left), Some(right)) => match left.cmp(&right) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn append_record_fields_wire(
    owner_wire: &[u8],
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), ZoneImageBuildError> {
    let rdlength = u16::try_from(rdata.len()).map_err(|_| ZoneImageBuildError::RdataTooLarge)?;
    out.extend_from_slice(owner_wire);
    out.extend_from_slice(&rr_type.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(rdata);
    Ok(())
}

fn append_synthesized_record_wire(
    record: &ZoneImageSynthesizedRecord,
    out: &mut Vec<u8>,
) -> Result<(), ZoneImageBuildError> {
    append_record_fields_wire(
        &record.owner_wire,
        record.rr_type,
        record.class,
        record.ttl,
        &record.rdata,
        out,
    )
}

fn synthesized_record_wire_len(record: &ZoneImageSynthesizedRecord) -> usize {
    record
        .owner_wire
        .len()
        .saturating_add(10)
        .saturating_add(record.rdata.len())
}

fn synthesized_wire_record(record: &ZoneImageSynthesizedRecord) -> ZoneImageWireRecord<'_> {
    ZoneImageWireRecord {
        owner_wire: &record.owner_wire,
        rr_type: record.rr_type,
        class: record.class,
        ttl: record.ttl,
        rdata: &record.rdata,
    }
}

fn push_blob(
    arena: &mut Vec<u8>,
    bytes: &[u8],
    name: &'static str,
) -> Result<BlobRange, ZoneImageBuildError> {
    let offset =
        u32::try_from(arena.len()).map_err(|_| ZoneImageBuildError::ArenaTooLarge { name })?;
    let len =
        u32::try_from(bytes.len()).map_err(|_| ZoneImageBuildError::ArenaTooLarge { name })?;
    arena.extend_from_slice(bytes);
    if arena.len() > u32::MAX as usize {
        return Err(ZoneImageBuildError::ArenaTooLarge { name });
    }
    Ok(BlobRange { offset, len })
}

fn checked_u32(value: usize, kind: &'static str) -> Result<u32, ZoneImageBuildError> {
    u32::try_from(value).map_err(|_| ZoneImageBuildError::TooManyItems { kind })
}

fn checked_u16(value: usize, kind: &'static str) -> Result<u16, ZoneImageBuildError> {
    u16::try_from(value).map_err(|_| ZoneImageBuildError::TooManyItems { kind })
}

fn qclass_matches(class: u16, qclass: u16) -> bool {
    qclass == 255 || class == qclass
}

fn record_synthesized_identity(
    record: &ZoneImageSynthesizedRecord,
    seen: &mut HashSet<(Vec<u8>, u16, u16, Vec<u8>)>,
) {
    seen.insert((
        record.owner_wire.clone(),
        record.rr_type,
        record.class,
        record.rdata.clone(),
    ));
}

fn single_name_rdata_bytes(rdata: &[u8]) -> Option<DomainName> {
    let (target, consumed) = DomainName::parse(rdata, 0).ok()?;
    (consumed == rdata.len()).then_some(target)
}

fn ns_target_rdata(rdata: &[u8]) -> Option<DomainName> {
    single_name_rdata_bytes(rdata)
}

fn rrsig_type_covered_rdata(rdata: &[u8]) -> Option<u16> {
    if rdata.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([rdata[0], rdata[1]]))
}

fn nsec_covers_name(owner: &DomainName, rdata: &[u8], name: &DomainName) -> bool {
    let Ok((next_owner, _)) = DomainName::parse(rdata, 0) else {
        return false;
    };
    canonical_nsec_range_covers(owner, &next_owner, name)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Nsec3Params {
    hash_algorithm: u8,
    iterations: u16,
    salt: Vec<u8>,
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

fn nsec3_next_hash_label(rdata: &[u8]) -> Option<String> {
    let params = nsec3_params_from_rdata(rdata)?;
    let hash_len_offset = 5 + params.salt.len();
    let hash_len = *rdata.get(hash_len_offset)? as usize;
    let hash_start = hash_len_offset + 1;
    let hash_end = hash_start.checked_add(hash_len)?;
    if hash_end > rdata.len() {
        return None;
    }

    Some(base32hex_no_padding_lower(&rdata[hash_start..hash_end]))
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
    if hash_label.is_empty() || hash_label.contains('.') {
        return None;
    }

    Some(hash_label.to_owned())
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
    let owner_key = owner.canonical_order_key();
    let next_key = next_owner.canonical_order_key();
    let name_key = name.canonical_order_key();

    if owner_key < next_key {
        owner_key < name_key && name_key < next_key
    } else {
        owner_key < name_key || name_key < next_key
    }
}

fn wire_names_equal_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    let Ok((left_name, left_consumed)) = DomainName::parse(left, 0) else {
        return false;
    };
    let Ok((right_name, right_consumed)) = DomainName::parse(right, 0) else {
        return false;
    };
    left_consumed == left.len()
        && right_consumed == right.len()
        && left_name.canonical_key() == right_name.canonical_key()
}

fn additional_address_target_rdata(rr_type: u16, rdata: &[u8]) -> Option<DomainName> {
    match rr_type {
        rr_type if rr_type == RecordType::Ns as u16 => ns_target_rdata(rdata),
        rr_type if rr_type == RecordType::Mx as u16 => mx_exchange_rdata(rdata),
        rr_type if rr_type == RecordType::Srv as u16 => srv_target_rdata(rdata),
        rr_type if rr_type == RecordType::Naptr as u16 => naptr_replacement_rdata(rdata),
        rr_type if rr_type == RecordType::Svcb as u16 || rr_type == RecordType::Https as u16 => {
            svcb_target_name_rdata(rdata)
        }
        _ => None,
    }
}

fn rr_type_may_have_additional_address_target(rr_type: u16) -> bool {
    rr_type == RecordType::Ns as u16
        || rr_type == RecordType::Mx as u16
        || rr_type == RecordType::Srv as u16
        || rr_type == RecordType::Naptr as u16
        || rr_type == RecordType::Svcb as u16
        || rr_type == RecordType::Https as u16
}

fn is_dnssec_proof_or_signature_type(rr_type: u16) -> bool {
    rr_type == RecordType::Rrsig as u16
        || rr_type == RecordType::Nsec as u16
        || rr_type == RecordType::Nsec3 as u16
}

fn mx_exchange_rdata(rdata: &[u8]) -> Option<DomainName> {
    if rdata.len() < 3 {
        return None;
    }

    let (exchange, consumed) = DomainName::parse(rdata, 2).ok()?;
    (2 + consumed == rdata.len()).then_some(exchange)
}

fn srv_target_rdata(rdata: &[u8]) -> Option<DomainName> {
    if rdata.len() < 7 {
        return None;
    }

    let (target, consumed) = DomainName::parse(rdata, 6).ok()?;
    (6 + consumed == rdata.len()).then_some(target)
}

fn naptr_replacement_rdata(rdata: &[u8]) -> Option<DomainName> {
    if rdata.len() < 7 {
        return None;
    }

    let mut offset = 4;
    for _ in 0..3 {
        offset = skip_character_string(rdata, offset)?;
    }

    let (replacement, consumed) = DomainName::parse(rdata, offset).ok()?;
    (offset + consumed == rdata.len()).then_some(replacement)
}

fn svcb_target_name_rdata(rdata: &[u8]) -> Option<DomainName> {
    if rdata.len() < 3 {
        return None;
    }

    let (target, consumed) = DomainName::parse(rdata, 2).ok()?;
    (2 + consumed <= rdata.len()).then_some(target)
}

fn skip_character_string(rdata: &[u8], offset: usize) -> Option<usize> {
    let len = *rdata.get(offset)? as usize;
    let next = offset.checked_add(1)?.checked_add(len)?;
    (next <= rdata.len()).then_some(next)
}

fn soa_minimum(rdata: &[u8]) -> Option<u32> {
    let (_, consumed_mname) = DomainName::parse(rdata, 0).ok()?;
    let rname_offset = consumed_mname;
    let (_, consumed_rname) = DomainName::parse(rdata, rname_offset).ok()?;
    let serial_offset = rname_offset + consumed_rname;
    if serial_offset + 20 != rdata.len() {
        return None;
    }

    Some(u32::from_be_bytes([
        rdata[serial_offset + 16],
        rdata[serial_offset + 17],
        rdata[serial_offset + 18],
        rdata[serial_offset + 19],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns::{DEFAULT_MAX_CNAME_CHAIN, Rcode, RecordType},
        zone::{ResourceRecord, Rrset, ZoneSnapshot},
    };

    #[test]
    fn exact_lookup_matches_snapshot_for_direct_positive_answer() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1)
        else {
            panic!("expected exact A lookup to find an answer");
        };

        let snapshot_lookup = snapshot.lookup(&qname, RecordType::A as u16, 1);
        assert_eq!(snapshot_lookup.rcode, Rcode::NoError);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes").answers,
            records_summary(&snapshot_lookup.answers)
        );
        assert_eq!(plan.answer_rrsets().len(), 1);
        assert!(
            !image
                .rrset_wire(plan.answer_rrsets()[0])
                .unwrap()
                .is_empty()
        );

        let mixed_case_qname = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        assert!(matches!(
            image.lookup_exact_plan(&mixed_case_qname, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::Found(_)
        ));

        let mut wire = Vec::new();
        let record_count = image
            .append_plan_wire(&plan, &mut wire)
            .expect("plan wire appends");
        assert_eq!(record_count, snapshot_lookup.answers.len());
        assert_eq!(wire, image.rrset_wire(plan.answer_rrsets()[0]).unwrap());
    }

    #[test]
    fn exact_lookup_supports_any_class_for_direct_answers() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255)
        else {
            panic!("expected ANY-class direct A lookup to find an answer");
        };

        assert_eq!(image.plan_summary(&plan).unwrap().answers.count, 2);
    }

    #[test]
    fn exact_lookup_matches_snapshot_for_direct_rrtype_corpus() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(7),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x05hello".to_vec()],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Svcb as u16,
                    1,
                    300,
                    vec![svc_param_rdata("svc.example.test.")],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Https as u16,
                    1,
                    300,
                    vec![svc_param_rdata(".")],
                ),
                Rrset::new(www.clone(), 65_280, 1, 300, vec![b"unknown".to_vec()]),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for rr_type in [
            RecordType::A as u16,
            RecordType::Aaaa as u16,
            RecordType::Mx as u16,
            RecordType::Txt as u16,
            RecordType::Svcb as u16,
            RecordType::Https as u16,
            65_280,
        ] {
            assert_exact_matches_snapshot(&snapshot, &image, &www, rr_type, 1);
        }
    }

    #[test]
    fn exact_lookup_reports_nodata_nameerror_and_out_of_zone() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let existing = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let outside = DomainName::from_absolute_str("www.example.invalid.").unwrap();

        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Aaaa as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&missing, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::NameError
        );
        assert_eq!(
            image.lookup_exact_plan(&outside, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::OutOfZone
        );
    }

    #[test]
    fn semantic_lookup_matches_snapshot_for_name_semantics() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for (qname, rr_type) in [
            ("alias.example.test.", RecordType::A as u16),
            ("host.wild.example.test.", RecordType::A as u16),
            ("ent.example.test.", RecordType::A as u16),
            ("www.child.example.test.", RecordType::A as u16),
            ("www.subtree.example.test.", RecordType::A as u16),
            ("missing.example.test.", RecordType::A as u16),
        ] {
            let qname = DomainName::from_absolute_str(qname).unwrap();
            let image_plan = image
                .lookup_response_plan(
                    &qname,
                    rr_type,
                    1,
                    DEFAULT_MAX_CNAME_CHAIN,
                    AnyResponseMode::Minimal,
                )
                .expect("zone image lookup plan builds");
            let snapshot_lookup = snapshot.lookup(&qname, rr_type, 1);
            assert_eq!(
                image.plan_summary(&image_plan).expect("plan summarizes"),
                lookup_summary(&snapshot_lookup),
                "lookup mismatch for {qname}"
            );
        }
    }

    #[test]
    fn qtype_any_plan_serves_exact_and_wildcard_rrsets() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let exact = DomainName::from_absolute_str("multi.example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let wildcard_qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(45),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    exact.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![vec![7, b'p', b'r', b'e', b's', b'e', b'n', b't']],
                ),
                Rrset::new(
                    exact,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![vec![0, 1, 2, 3]],
                ),
                Rrset::new(
                    wildcard.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    wildcard.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![vec![8, b'w', b'i', b'l', b'd', b'c', b'a', b'r', b'd']],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![vec![0, 1, 2, 3]],
                ),
                Rrset::new(
                    mail,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let exact_minimal = image
            .lookup_response_plan(
                &DomainName::from_absolute_str("multi.example.test.").unwrap(),
                255,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            )
            .expect("exact minimal ANY plan builds");
        assert_eq!(
            plan_answer_types(&image, &exact_minimal),
            vec![RecordType::A as u16]
        );

        let exact_full = image
            .lookup_response_plan(
                &DomainName::from_absolute_str("multi.example.test.").unwrap(),
                255,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Full,
            )
            .expect("exact full ANY plan builds");
        assert_eq!(
            plan_answer_types(&image, &exact_full),
            vec![RecordType::A as u16, RecordType::Txt as u16]
        );

        let wildcard_full = image
            .lookup_response_plan(
                &wildcard_qname,
                255,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Full,
            )
            .expect("wildcard full ANY plan builds");
        assert_eq!(
            plan_answer_types(&image, &wildcard_full),
            vec![RecordType::Mx as u16, RecordType::Txt as u16]
        );
        assert_eq!(wildcard_full.additional_rrsets().len(), 1);
        assert!(wildcard_full.answer_items.iter().all(|item| {
            matches!(
                item,
                PlanAnswer::RrsetWithOwner {
                    owner_index,
                    ..
                } if wildcard_full.owner_overrides[*owner_index].as_slice()
                    == wildcard_qname.to_wire().as_slice()
            )
        }));
    }

    #[test]
    fn wildcard_owner_override_plan_emits_wire_and_additionals_from_handles() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    wildcard,
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    mail,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let plan = image
            .lookup_response_plan(
                &qname,
                RecordType::Mx as u16,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            )
            .expect("zone image lookup plan builds");

        assert_eq!(plan.synthesized_answer_count(), 0);
        assert!(matches!(
            plan.answer_items.as_slice(),
            [PlanAnswer::RrsetWithOwner { .. }]
        ));
        assert_eq!(plan.additional_rrsets().len(), 1);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.lookup(&qname, RecordType::Mx as u16, 1))
        );

        let mut visited = Vec::new();
        image.visit_plan_records(&plan, |record| {
            visited.push(record.owner_wire.to_vec());
        });
        assert_eq!(visited.first(), Some(&qname.to_wire()));
        assert!(
            visited.contains(
                &DomainName::from_absolute_str("mail.example.test.")
                    .unwrap()
                    .to_wire()
            )
        );
    }

    #[test]
    fn plan_wire_upper_bound_matches_uncompressed_plan_wire() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for (qname, rr_type) in [
            ("host.wild.example.test.", RecordType::A as u16),
            ("www.subtree.example.test.", RecordType::A as u16),
            ("missing.example.test.", RecordType::A as u16),
        ] {
            let qname = DomainName::from_absolute_str(qname).unwrap();
            let plan = image
                .lookup_response_plan(
                    &qname,
                    rr_type,
                    1,
                    DEFAULT_MAX_CNAME_CHAIN,
                    AnyResponseMode::Minimal,
                )
                .expect("zone image lookup plan builds");
            let mut wire = Vec::new();
            image
                .append_plan_wire(&plan, &mut wire)
                .expect("plan wire appends");

            assert_eq!(
                image.plan_wire_upper_bound(&plan),
                wire.len(),
                "wire upper bound mismatch for {qname}"
            );
        }
    }

    #[test]
    fn direct_answer_plan_preserves_delegation_dname_and_additional_semantics() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let direct = DomainName::from_absolute_str("www.example.test.").unwrap();
        let delegated_glue = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let under_dname = DomainName::from_absolute_str("www.subtree.example.test.").unwrap();
        let delegated_child = DomainName::from_absolute_str("child.example.test.").unwrap();

        assert!(
            image
                .lookup_direct_answer_plan(&direct, RecordType::A as u16, 1)
                .is_some()
        );
        assert!(
            image
                .lookup_direct_answer_plan(&delegated_glue, RecordType::A as u16, 1)
                .is_none(),
            "direct shortcut must not serve glue below a delegation as authoritative data"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&under_dname, RecordType::A as u16, 1)
                .is_none(),
            "direct shortcut must not bypass ancestor DNAME synthesis"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&delegated_child, RecordType::Ns as u16, 1)
                .is_none(),
            "direct shortcut must not bypass referral handling at the cut"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&direct, RecordType::Srv as u16, 1)
                .is_none(),
            "direct shortcut must not skip additional-address processing"
        );
    }

    #[test]
    fn compile_reports_shape_statistics() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let stats = image.stats();

        assert_eq!(stats.rrset_count, 3);
        assert_eq!(stats.record_count, 4);
        assert_eq!(stats.name_count, 3);
        assert!(stats.node_count >= stats.name_count);
        assert!(stats.edge_count >= 2);
        assert!(stats.max_child_fanout >= 1);
        assert!(stats.max_rrsets_per_name >= 1);
        assert!(stats.max_depth >= 1);
        assert!(stats.rdata_bytes > 0);
        assert!(stats.wire_bytes > stats.rdata_bytes);
        assert!(stats.hot_bytes > 0);
        assert!(stats.cold_bytes > 0);
        assert!(stats.bytes_per_record > 0);
    }

    fn sample_snapshot() -> ZoneSnapshot {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let mx = DomainName::from_absolute_str("mail.example.test.").unwrap();
        ZoneSnapshot::active(
            origin.clone(),
            Some(42),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10], vec![192, 0, 2, 11]],
                ),
                Rrset::new(mx, RecordType::A as u16, 1, 300, vec![vec![192, 0, 2, 20]]),
            ],
        )
    }

    fn semantic_snapshot() -> ZoneSnapshot {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let leaf = DomainName::from_absolute_str("leaf.ent.example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let target = DomainName::from_absolute_str("www.target.example.test.").unwrap();
        ZoneSnapshot::active(
            origin.clone(),
            Some(43),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    alias,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("www.example.test.")],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
                Rrset::new(
                    leaf,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 56]],
                ),
                Rrset::new(
                    child,
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 57]],
                ),
                Rrset::new(
                    subtree,
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    target,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 58]],
                ),
                Rrset::new(
                    www,
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("target.example.test.")],
                ),
            ],
        )
    }

    fn assert_exact_matches_snapshot(
        snapshot: &ZoneSnapshot,
        image: &ZoneImage,
        qname: &DomainName,
        rr_type: u16,
        qclass: u16,
    ) {
        let ZoneImageLookupOutcome::Found(plan) = image.lookup_exact_plan(qname, rr_type, qclass)
        else {
            panic!("expected exact lookup to find rrtype {rr_type}");
        };
        let snapshot_lookup = snapshot.lookup(qname, rr_type, qclass);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes").answers,
            records_summary(&snapshot_lookup.answers)
        );
    }

    fn lookup_summary(lookup: &crate::dns::LookupResult) -> ZoneImagePlanSummary {
        ZoneImagePlanSummary {
            rcode: lookup.rcode,
            authoritative: lookup.authoritative,
            answers: records_summary(&lookup.answers),
            authorities: records_summary(&lookup.authorities),
            additionals: records_summary(&lookup.additionals),
            termination: lookup.termination,
            nsec3_iterations_exceeded: lookup.nsec3_iterations_exceeded,
        }
    }

    fn records_summary(records: &[ResourceRecord]) -> ZoneImagePlanSectionSummary {
        let mut summary = ZoneImagePlanSectionAccumulator::default();
        for record in records {
            summary.digest = fnv1a_u64(
                summary.digest,
                hash_record_identity(
                    record.owner.canonical_key().as_bytes(),
                    record.rr_type,
                    record.class,
                    record.ttl,
                    &record.rdata,
                ),
            );
            summary.count += 1;
        }
        summary.finish()
    }

    fn plan_answer_types(image: &ZoneImage, plan: &ZoneImageLookupPlan) -> Vec<u16> {
        if plan.answer_items.is_empty() {
            return plan
                .answer_rrsets()
                .iter()
                .map(|rrset_id| image.rrsets[rrset_id.0 as usize].rr_type)
                .collect();
        }
        plan.answer_items
            .iter()
            .map(|item| {
                let rrset_id = match item {
                    PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                        rrset_id
                    }
                    PlanAnswer::Synthesized(_) => panic!("expected rrset answer"),
                };
                image.rrsets[rrset_id.0 as usize].rr_type
            })
            .collect()
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        DomainName::from_absolute_str(name).unwrap().to_wire()
    }

    fn mx_rdata(exchange: &str) -> Vec<u8> {
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&DomainName::from_absolute_str(exchange).unwrap().to_wire());
        rdata
    }

    fn svc_param_rdata(target: &str) -> Vec<u8> {
        let mut rdata = 1u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&DomainName::from_absolute_str(target).unwrap().to_wire());
        rdata
    }

    fn srv_rdata(target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&443u16.to_be_bytes());
        rdata.extend_from_slice(&DomainName::from_absolute_str(target).unwrap().to_wire());
        rdata
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
}
