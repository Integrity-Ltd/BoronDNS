use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    mem,
};

use smallvec::SmallVec;
use thiserror::Error;

use crate::{
    dns::{
        DEFAULT_MAX_CNAME_CHAIN, DomainName, LookupResult, LookupTermination, Rcode, RecordType,
    },
    zone::{ResourceRecord, ZoneSnapshot},
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
    synthesized_answers: Vec<ResourceRecord>,
    termination: Option<LookupTermination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlanAnswer {
    Rrset(ZoneImageRrsetId),
    Synthesized(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    first_record: u32,
    record_count: u16,
    wire: BlobRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRecord {
    rdata: BlobRange,
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
    ) -> Result<ZoneImageLookupPlan, ZoneImageBuildError> {
        if qtype == 255 {
            return Ok(ZoneImageLookupPlan::unsupported());
        }

        if let Some(delegation) = self.delegation_for(qname, qclass)
            && !(qtype == RecordType::Ds as u16
                && qname.canonical_key() == self.rrset_owner(delegation)?.canonical_key())
        {
            let mut plan = ZoneImageLookupPlan::referral();
            plan.authority_rrsets.push(delegation);
            self.add_glue_for_ns_rrset(delegation, qclass, &mut plan)?;
            return Ok(plan);
        }

        if let Some(rrset) = self.find_rrset(qname, qtype, qclass) {
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

        if let Some(wildcard_plan) = self.lookup_wildcard(qname, qtype, qclass, max_cname_chain)? {
            return Ok(wildcard_plan);
        }

        Ok(self.nxdomain_plan(qclass))
    }

    pub fn lookup_response(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
    ) -> Result<LookupResult, ZoneImageBuildError> {
        self.lookup_response_with_options(qname, qtype, qclass, DEFAULT_MAX_CNAME_CHAIN)
    }

    pub fn lookup_response_with_options(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
    ) -> Result<LookupResult, ZoneImageBuildError> {
        let plan = self.lookup_response_plan(qname, qtype, qclass, max_cname_chain)?;
        self.materialize_lookup_result(&plan)
    }

    pub fn materialize_answers(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        self.materialize_answer_records(plan)
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
            self.rrset_list_record_count(&plan.authority_rrsets)?,
            self.rrset_list_record_count(&plan.additional_rrsets)?,
        ))
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
                PlanAnswer::Synthesized(index) => {
                    let record = &plan.synthesized_answers[*index];
                    append_record_wire(&record.owner.to_wire(), record, out)?;
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
        Ok(record_count)
    }

    pub fn materialize_lookup_result(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<LookupResult, ZoneImageBuildError> {
        self.materialize_plan_lookup_result(plan)
    }

    pub(crate) fn visit_plan_records(
        &self,
        plan: &ZoneImageLookupPlan,
        mut visit: impl FnMut(ZoneImageWireRecord<'_>),
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
                    PlanAnswer::Synthesized(index) => {
                        let record = &plan.synthesized_answers[*index];
                        let owner_wire = record.owner.to_wire();
                        visit(ZoneImageWireRecord {
                            owner_wire: &owner_wire,
                            rr_type: record.rr_type,
                            class: record.class,
                            ttl: record.ttl,
                            rdata: &record.rdata,
                        });
                    }
                }
            }
        }

        for rrset_id in &plan.authority_rrsets {
            let ttl_override = self.authority_ttl_override(plan, *rrset_id);
            self.visit_rrset_records(*rrset_id, ttl_override, &mut visit);
        }

        for rrset_id in &plan.additional_rrsets {
            self.visit_rrset_records(*rrset_id, None, &mut visit);
        }
    }

    fn visit_rrset_records(
        &self,
        rrset_id: ZoneImageRrsetId,
        ttl_override: Option<u32>,
        visit: &mut impl FnMut(ZoneImageWireRecord<'_>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = self.blob(&self.names, rrset.owner_wire);
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

        let owner_wire = self.blob(&self.names, rrset.owner_wire).to_vec();
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = self.blob(&self.rdata, record.rdata);
            append_record_fields_wire(
                &owner_wire,
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
        if rrset.rr_type != RecordType::Soa as u16 || rrset.record_count == 0 {
            return None;
        }
        let record = self.records[rrset.first_record as usize];
        let minimum = soa_minimum(self.blob(&self.rdata, record.rdata))?;
        Some(rrset.ttl.min(minimum))
    }

    fn materialize_rrset(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        self.materialize_rrset_with_owner(rrset_id, None)
    }

    fn materialize_rrset_with_owner(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_override: Option<&DomainName>,
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner = match owner_override {
            Some(owner) => owner.clone(),
            None => self.rrset_owner(rrset_id)?,
        };
        let mut records = Vec::with_capacity(rrset.record_count as usize);
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            records.push(ResourceRecord {
                owner: owner.clone(),
                rr_type: rrset.rr_type,
                class: rrset.class,
                ttl: rrset.ttl,
                rdata: self.blob(&self.rdata, record.rdata).to_vec(),
            });
        }
        Ok(records)
    }

    fn materialize_plan_lookup_result(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<LookupResult, ZoneImageBuildError> {
        Ok(LookupResult {
            rcode: plan.rcode,
            authoritative: plan.authoritative,
            answers: self.materialize_answer_records(plan)?,
            authorities: self.materialize_authority_records(plan)?,
            additionals: self.materialize_rrset_list(&plan.additional_rrsets)?,
            termination: plan.termination,
            nsec3_iterations_exceeded: false,
        })
    }

    fn materialize_answer_records(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        if plan.answer_items.is_empty() {
            return self.materialize_rrset_list(&plan.answer_rrsets);
        }

        let mut records = Vec::new();
        for item in &plan.answer_items {
            match item {
                PlanAnswer::Rrset(rrset_id) => records.extend(self.materialize_rrset(*rrset_id)?),
                PlanAnswer::Synthesized(index) => {
                    records.push(plan.synthesized_answers[*index].clone());
                }
            }
        }
        Ok(records)
    }

    fn materialize_rrset_list(
        &self,
        rrsets: &[ZoneImageRrsetId],
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        let mut records = Vec::new();
        for rrset_id in rrsets {
            records.extend(self.materialize_rrset(*rrset_id)?);
        }
        Ok(records)
    }

    fn materialize_authority_records(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> Result<Vec<ResourceRecord>, ZoneImageBuildError> {
        let mut records = self.materialize_rrset_list(&plan.authority_rrsets)?;
        if plan.authoritative {
            for record in &mut records {
                if record.rr_type == RecordType::Soa as u16
                    && let Some(minimum) = soa_minimum(&record.rdata)
                {
                    record.ttl = record.ttl.min(minimum);
                }
            }
        }
        Ok(records)
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
        let dname_records = self.materialize_rrset(dname)?;
        if dname_records.len() != 1 {
            let mut plan = ZoneImageLookupPlan::servfail(LookupTermination::MalformedDname);
            plan.push_answer_rrset(dname);
            return Ok(plan);
        }
        let Some(target) = dname_records.first().and_then(single_name_rdata) else {
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
        plan.push_synthesized_answer(ResourceRecord {
            owner: qname.clone(),
            rr_type: RecordType::Cname as u16,
            class: self.rrsets[dname.0 as usize].class,
            ttl: self.rrsets[dname.0 as usize].ttl,
            rdata: synthesized_target.to_wire(),
        });
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
    ) -> Result<Option<ZoneImageLookupPlan>, ZoneImageBuildError> {
        let Some(closest_node) = self.closest_encloser_node(qname) else {
            return Ok(None);
        };
        let Some(wildcard_node) = self.find_child(closest_node, b"*") else {
            return Ok(None);
        };

        if let Some(rrset) = self.find_rrset_at_node(wildcard_node, qtype, qclass) {
            let mut plan = ZoneImageLookupPlan::positive();
            for record in self.materialize_rrset_with_owner(rrset, Some(qname))? {
                plan.push_synthesized_answer(record);
            }
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(Some(plan));
        }

        if qtype != RecordType::Cname as u16
            && let Some(cname) =
                self.find_rrset_at_node(wildcard_node, RecordType::Cname as u16, qclass)
        {
            let mut plan = ZoneImageLookupPlan::positive();
            let cname_records = self.materialize_rrset_with_owner(cname, Some(qname))?;
            let Some(target) = cname_records.first().and_then(single_name_rdata) else {
                for record in cname_records {
                    plan.push_synthesized_answer(record);
                }
                return Ok(Some(plan));
            };
            for record in cname_records {
                plan.push_synthesized_answer(record);
            }
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
            return Ok(plan.into_servfail(LookupTermination::CnameChainLimit));
        }

        let Some(cname) =
            cname_rrset.or_else(|| self.find_rrset(&current, RecordType::Cname as u16, qclass))
        else {
            self.add_additionals_for_answer_plan(&mut plan, qclass)?;
            return Ok(plan);
        };
        plan.push_answer_rrset(cname);
        let cname_records = self.materialize_rrset(cname)?;
        let Some(target) = cname_records.first().and_then(single_name_rdata) else {
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
        for record in self.materialize_rrset(ns_rrset)? {
            let Some(target) = ns_target(&record) else {
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
        let rrset_needs_additionals = plan.answer_rrsets.iter().any(|rrset_id| {
            rr_type_may_have_additional_address_target(self.rrsets[rrset_id.0 as usize].rr_type)
        });
        let synthesized_needs_additionals = plan
            .synthesized_answers
            .iter()
            .any(|record| rr_type_may_have_additional_address_target(record.rr_type));
        if !rrset_needs_additionals && !synthesized_needs_additionals {
            return Ok(());
        }

        let mut seen = Vec::<ZoneImageRrsetId>::new();
        for record in self.materialize_answer_records(plan)? {
            let Some(target) = additional_address_target(&record) else {
                continue;
            };
            if !target.is_equal_or_subdomain_of(&self.origin) {
                continue;
            }
            for rr_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
                if let Some(rrset) = self.find_rrset(&target, rr_type, qclass)
                    && !seen.contains(&rrset)
                    && !plan.additional_rrsets.contains(&rrset)
                {
                    seen.push(rrset);
                    plan.additional_rrsets.push(rrset);
                }
            }
        }
        Ok(())
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
            synthesized_answers: Vec::new(),
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

    fn unsupported() -> Self {
        Self {
            rcode: Rcode::NotImp,
            authoritative: false,
            answer_rrsets: SmallVec::new(),
            answer_items: SmallVec::new(),
            authority_rrsets: SmallVec::new(),
            additional_rrsets: SmallVec::new(),
            synthesized_answers: Vec::new(),
            termination: None,
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

    pub fn is_unsupported(&self) -> bool {
        self.rcode == Rcode::NotImp && !self.authoritative && self.answer_items.is_empty()
    }

    pub fn synthesized_answer_count(&self) -> usize {
        self.synthesized_answers.len()
    }

    fn push_answer_rrset(&mut self, rrset: ZoneImageRrsetId) {
        self.answer_rrsets.push(rrset);
        if !self.answer_items.is_empty() {
            self.answer_items.push(PlanAnswer::Rrset(rrset));
        }
    }

    fn push_synthesized_answer(&mut self, record: ResourceRecord) {
        self.ensure_answer_items();
        let index = self.synthesized_answers.len();
        self.synthesized_answers.push(record);
        self.answer_items.push(PlanAnswer::Synthesized(index));
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
        self.image_rrsets.push(ImageRrset {
            owner_wire: owner_wire_ref,
            rr_type,
            class,
            ttl,
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
            + self.dname_rrsets.len() * mem::size_of::<ZoneImageRrsetId>();
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

fn append_record_wire(
    owner_wire: &[u8],
    record: &ResourceRecord,
    out: &mut Vec<u8>,
) -> Result<(), ZoneImageBuildError> {
    append_record_fields_wire(
        owner_wire,
        record.rr_type,
        record.class,
        record.ttl,
        &record.rdata,
        out,
    )
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

fn single_name_rdata(record: &ResourceRecord) -> Option<DomainName> {
    let (target, consumed) = DomainName::parse(&record.rdata, 0).ok()?;
    (consumed == record.rdata.len()).then_some(target)
}

fn ns_target(record: &ResourceRecord) -> Option<DomainName> {
    single_name_rdata(record)
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

fn rr_type_may_have_additional_address_target(rr_type: u16) -> bool {
    rr_type == RecordType::Ns as u16
        || rr_type == RecordType::Mx as u16
        || rr_type == RecordType::Srv as u16
        || rr_type == RecordType::Naptr as u16
        || rr_type == RecordType::Svcb as u16
        || rr_type == RecordType::Https as u16
}

fn mx_exchange(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 3 {
        return None;
    }

    let (exchange, consumed) = DomainName::parse(&record.rdata, 2).ok()?;
    (2 + consumed == record.rdata.len()).then_some(exchange)
}

fn srv_target(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 7 {
        return None;
    }

    let (target, consumed) = DomainName::parse(&record.rdata, 6).ok()?;
    (6 + consumed == record.rdata.len()).then_some(target)
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
    (offset + consumed == record.rdata.len()).then_some(replacement)
}

fn svcb_target_name(record: &ResourceRecord) -> Option<DomainName> {
    if record.rdata.len() < 3 {
        return None;
    }

    let (target, consumed) = DomainName::parse(&record.rdata, 2).ok()?;
    (2 + consumed <= record.rdata.len()).then_some(target)
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
        dns::{Rcode, RecordType},
        zone::{Rrset, ZoneSnapshot},
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

        let image_answers = image
            .materialize_answers(&plan)
            .expect("answers materialize");
        let snapshot_lookup = snapshot.lookup(&qname, RecordType::A as u16, 1);
        assert_eq!(snapshot_lookup.rcode, Rcode::NoError);
        assert_eq!(image_answers, snapshot_lookup.answers);
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
        assert_eq!(record_count, image_answers.len());
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

        let image_answers = image
            .materialize_answers(&plan)
            .expect("answers materialize");
        assert_eq!(image_answers.len(), 2);
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
            let image_lookup = image
                .lookup_response(&qname, rr_type, 1)
                .expect("zone image lookup materializes");
            let snapshot_lookup = snapshot.lookup(&qname, rr_type, 1);
            assert_eq!(image_lookup, snapshot_lookup, "lookup mismatch for {qname}");
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
        let image_answers = image
            .materialize_answers(&plan)
            .expect("answers materialize");
        let snapshot_lookup = snapshot.lookup(qname, rr_type, qclass);
        assert_eq!(image_answers, snapshot_lookup.answers);
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
