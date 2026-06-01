use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    mem,
};

use sha1::{Digest, Sha1};
use smallvec::SmallVec;
use thiserror::Error;
use tracing::warn;

use crate::{
    dns::{
        AnyResponseMode, DomainName, InlineNameWire, LookupTermination, Rcode, RecordType,
        wire_name_len_at,
    },
    zone::ZoneSnapshot,
};

const LABEL_INLINE_CAPACITY: usize = 64;
const NO_RELATION_OFFSET: u16 = u16::MAX;
const PLAN_FLAG_ANSWER_HAS_RECORDS: u8 = 1 << 0;
const PLAN_FLAG_AUTHORITY_HAS_SOA: u8 = 1 << 1;
const PLAN_FLAG_WILDCARD_SYNTHESIZED: u8 = 1 << 2;
const PLAN_FLAG_DNSSEC_AUGMENTED: u8 = 1 << 3;
const PLAN_FLAG_NSEC3_ITERATIONS_EXCEEDED: u8 = 1 << 4;
const PLAN_FLAG_DIRECT_ANSWER_CANDIDATE: u8 = 1 << 5;
const PLAN_FLAG_AUTHORITATIVE: u8 = 1 << 6;
const PLAN_FLAG_AUTHORITY_FIRST_RRSET_IS_SOA: u8 = 1 << 7;
const DIRECT_ANSWER_BODY_RECORDS_FALLBACK: u32 = u32::MAX;
const LOW_RRTYPE_BITMAP_WORDS: usize = 4;
const NO_AUTHORITY_SOA_INDEX: u16 = u16::MAX;
const NO_NODE_LOW_RRTYPE_BITMAP: u16 = u16::MAX;
type OwnerOverrideWire = InlineNameWire;
type LowercaseLabelKey = SmallVec<[u8; LABEL_INLINE_CAPACITY]>;
pub(crate) type ZoneImageRecordFixedFields = [u8; 8];

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
    child_hashes: Box<[ImageChildHash]>,
    child_hash_slots: Box<[u16]>,
    node_low_rrtype_bitmaps: Box<[u64]>,
    rrsets: Box<[ImageRrset]>,
    low_rrtype_bitmap: [u64; LOW_RRTYPE_BITMAP_WORDS],
    additional_address_rrset_flags: Box<[u64]>,
    rrsig_rrset_flags: Box<[u64]>,
    records: Box<[ImageRecord]>,
    rrset_relations: Box<[ImageRrsetRelation]>,
    rrset_relation_spans: Box<[ImageRrsetRelationSpan]>,
    single_name_targets: Box<[ImageSingleNameTarget]>,
    nsec_ranges: Box<[ImageNsecRange]>,
    nsec3_param_sets: Box<[ImageNsec3ParamSet]>,
    nsec3_ranges: Box<[ImageNsec3Range]>,
    apex_in_soa_rrset: Option<ZoneImageRrsetId>,
    dnssec_augmentation_possible: bool,
    dnssec_denial_augmentation_possible: bool,
    dnssec_referral_augmentation_possible: bool,
    dnssec_rrsig_augmentation_possible: bool,
    any_class_delegation_policy_is_in_only: bool,
    any_class_dname_policy_is_in_only: bool,
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
    pub child_hash_count: usize,
    pub child_hash_slot_count: usize,
    pub child_hash_slot_bytes: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZoneImageChildLookupProfile {
    pub fanout: usize,
    pub labels: Vec<Vec<u8>>,
}

pub(crate) struct ZoneImageDirectRrset<'a> {
    pub body_wire_len: usize,
    section_count_header_bytes: [u8; 6],
    section_count_header_bytes_with_edns: [u8; 6],
    body: ZoneImageDirectRrsetBody<'a>,
}

impl ZoneImageDirectRrset<'_> {
    pub(crate) fn section_count_header_bytes(&self, edns: bool) -> [u8; 6] {
        if edns {
            self.section_count_header_bytes_with_edns
        } else {
            self.section_count_header_bytes
        }
    }

    #[cfg(test)]
    pub(crate) fn record_count(&self) -> u16 {
        u16::from_be_bytes([
            self.section_count_header_bytes[0],
            self.section_count_header_bytes[1],
        ])
    }
}

enum ZoneImageDirectRrsetBody<'a> {
    Template(&'a [u8]),
    Records {
        records: &'a [ImageRecord],
        record_prefix: [u8; 10],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneImageRrsetId(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneImageLookupPlan {
    rcode: Rcode,
    answer_rrsets: SmallVec<[ZoneImageRrsetId; 1]>,
    answer_items: SmallVec<[PlanAnswer; 1]>,
    authority_rrsets: SmallVec<[ZoneImageRrsetId; 2]>,
    additional_rrsets: SmallVec<[ZoneImageRrsetId; 4]>,
    owner_overrides: SmallVec<[OwnerOverrideWire; 1]>,
    dynamic_answers: SmallVec<[ZoneImageSynthesizedRecord; 1]>,
    selected_authorities: SmallVec<[ZoneImageSelectedRecord; 1]>,
    selected_additionals: SmallVec<[ZoneImageSelectedRecord; 1]>,
    answer_record_count: u32,
    authority_record_count: u32,
    additional_record_count: u32,
    answer_wire_upper_bound: u32,
    body_wire_upper_bound: u32,
    referral_ns_rrset: u32,
    authority_soa_index: u16,
    flags: u8,
    termination: Option<LookupTermination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanAnswer {
    Rrset(ZoneImageRrsetId),
    RrsetWithOwner {
        rrset_id: ZoneImageRrsetId,
        owner_index: u16,
    },
    DynamicRecord(u16),
    SelectedRecord(ZoneImageSelectedRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneImageSynthesizedRecord {
    owner_wire: InlineNameWire,
    fixed_fields: ZoneImageRecordFixedFields,
    rdlength_bytes: [u8; 2],
    rdata_encoding: PackedRdataEncoding,
    rdata: InlineNameWire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZoneImageSelectedRecord {
    rrset_id: ZoneImageRrsetId,
    wire_len: u32,
    fixed_fields: ZoneImageRecordFixedFields,
    rdata: RdataRange,
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
    pub fixed_fields: ZoneImageRecordFixedFields,
    pub rdlength_bytes: [u8; 2],
    pub rdata_encoding: PackedRdataEncoding,
    pub rdata: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackedRdataEncoding(u16);

impl PackedRdataEncoding {
    const COPY: u16 = 0;
    const SINGLE_NAME: u16 = 1;
    const MX: u16 = 2;

    pub(crate) const fn copy() -> Self {
        Self(Self::COPY)
    }

    pub(crate) const fn single_name() -> Self {
        Self(Self::SINGLE_NAME)
    }

    pub(crate) const fn soa(mname_len: u8, rname_len: u8) -> Self {
        Self(((mname_len as u16) << 8) | rname_len as u16)
    }

    pub(crate) const fn mx() -> Self {
        Self(Self::MX)
    }

    pub(crate) const fn is_copy(self) -> bool {
        self.0 == Self::COPY
    }

    pub(crate) const fn is_single_name(self) -> bool {
        self.0 == Self::SINGLE_NAME
    }

    pub(crate) const fn is_mx(self) -> bool {
        self.0 == Self::MX
    }

    pub(crate) const fn soa_lengths(self) -> Option<(u8, u8)> {
        if self.0 > Self::MX {
            Some(((self.0 >> 8) as u8, self.0 as u8))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NameNode {
    first_edge: u32,
    edge_count: u16,
    low_rrtype_bitmap: u16,
    first_rrset: u32,
    rrset_count: u16,
    parent: u32,
    depth: u16,
    nearest_in_delegation: u32,
    nearest_in_dname: u32,
    child_hash: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NameEdge {
    label: BlobRange,
    child: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageChildHash {
    first_slot: u32,
    slot_mask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrset {
    owner_wire: BlobRange,
    fixed_fields: ZoneImageRecordFixedFields,
    negative_ttl_bytes: [u8; 4],
    first_record: u32,
    record_count: u16,
    owner_label_count: u16,
    relation_span: u32,
    direct_answer_body_len: u32,
    ownerless_wire_len: u32,
    wire: BlobRange,
}

impl ImageRrset {
    fn rr_type(self) -> u16 {
        u16::from_be_bytes([self.fixed_fields[0], self.fixed_fields[1]])
    }

    fn class(self) -> u16 {
        u16::from_be_bytes([self.fixed_fields[2], self.fixed_fields[3]])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRecord {
    rdata: RdataRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZoneImageRrsetPlanMetrics {
    rr_type: u16,
    record_count: usize,
    wire_upper_bound: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageSingleNameTarget {
    rrset_id: ZoneImageRrsetId,
    name: DomainName,
    rdata: RdataRange,
    node_hint: ImageTargetNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageTargetNode {
    OutOfZone,
    OutOfZoneParentSuffix,
    InZoneMissing,
    InZoneNode(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageNsecRange {
    rrset_id: ZoneImageRrsetId,
    class: u16,
    owner_key: BlobRange,
    next_key: BlobRange,
    owner_before_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageNsec3ParamSet {
    hash_algorithm: u8,
    iterations: u16,
    salt: BlobRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageNsec3Range {
    rrset_id: ZoneImageRrsetId,
    class: u16,
    param_set: u16,
    owner_hash: [u8; 20],
    next_hash: [u8; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrsigCovered {
    rrset_id: ZoneImageRrsetId,
    covered_type: u16,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageRrsetRelationKind {
    AdditionalAddress = 1,
    Rrsig = 2,
    ReferralGlue = 3,
    SingleNameTarget = 4,
    DelegationDs = 5,
    DelegationNsec = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrsetRelation {
    kind: ImageRrsetRelationKind,
    rrset_id: ZoneImageRrsetId,
    record_index: u32,
    rdata_len: u16,
    owner_wire_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageRrsetRelationSpan {
    first_relation: u32,
    relation_count: u16,
    single_name_target_offset: u16,
    rrsig_offset: u16,
    referral_glue_offset: u16,
    delegation_dnssec_offset: u16,
    additional_address_offset: u16,
}

impl ImageRrsetRelationSpan {
    fn new(
        first_relation: u32,
        relation_count: u16,
        relations: &[ImageRrsetRelation],
    ) -> Result<Self, ZoneImageBuildError> {
        Ok(Self {
            first_relation,
            relation_count,
            single_name_target_offset: relation_kind_offset(
                relations,
                ImageRrsetRelationKind::SingleNameTarget,
            )?,
            rrsig_offset: relation_kind_offset(relations, ImageRrsetRelationKind::Rrsig)?,
            referral_glue_offset: relation_kind_offset(
                relations,
                ImageRrsetRelationKind::ReferralGlue,
            )?,
            delegation_dnssec_offset: relation_kind_offset(
                relations,
                ImageRrsetRelationKind::DelegationDs,
            )?
            .min(relation_kind_offset(
                relations,
                ImageRrsetRelationKind::DelegationNsec,
            )?),
            additional_address_offset: relation_kind_offset(
                relations,
                ImageRrsetRelationKind::AdditionalAddress,
            )?,
        })
    }

    #[cfg(test)]
    fn kind_offsets(&self, kind: ImageRrsetRelationKind) -> Option<(u16, u16)> {
        let (start, end) = match kind {
            ImageRrsetRelationKind::SingleNameTarget => (
                self.single_name_target_offset,
                self.next_relation_offset_after_single_name_target(),
            ),
            ImageRrsetRelationKind::Rrsig => {
                (self.rrsig_offset, self.next_relation_offset_after_rrsig())
            }
            ImageRrsetRelationKind::ReferralGlue => (
                self.referral_glue_offset,
                self.next_relation_offset_after_referral_glue(),
            ),
            ImageRrsetRelationKind::DelegationDs | ImageRrsetRelationKind::DelegationNsec => (
                self.delegation_dnssec_offset,
                self.next_relation_offset_after_delegation_dnssec(),
            ),
            ImageRrsetRelationKind::AdditionalAddress => {
                (self.additional_address_offset, self.relation_count)
            }
        };
        if start == NO_RELATION_OFFSET {
            return None;
        }
        Some((start, end))
    }

    #[cfg(test)]
    fn next_relation_offset_after_single_name_target(&self) -> u16 {
        first_relation_offset([
            self.rrsig_offset,
            self.referral_glue_offset,
            self.delegation_dnssec_offset,
            self.additional_address_offset,
        ])
        .unwrap_or(self.relation_count)
    }

    fn next_relation_offset_after_rrsig(&self) -> u16 {
        first_relation_offset([
            self.referral_glue_offset,
            self.delegation_dnssec_offset,
            self.additional_address_offset,
        ])
        .unwrap_or(self.relation_count)
    }

    fn next_relation_offset_after_referral_glue(&self) -> u16 {
        first_relation_offset([
            self.delegation_dnssec_offset,
            self.additional_address_offset,
        ])
        .unwrap_or(self.relation_count)
    }

    #[cfg(test)]
    fn next_relation_offset_after_delegation_dnssec(&self) -> u16 {
        first_relation_offset([self.additional_address_offset]).unwrap_or(self.relation_count)
    }
}

fn first_relation_offset<const N: usize>(offsets: [u16; N]) -> Option<u16> {
    offsets
        .into_iter()
        .find(|offset| *offset != NO_RELATION_OFFSET)
}

fn relation_kind_offset(
    relations: &[ImageRrsetRelation],
    kind: ImageRrsetRelationKind,
) -> Result<u16, ZoneImageBuildError> {
    relations
        .iter()
        .position(|relation| relation.kind == kind)
        .map(|offset| checked_u16(offset, "rrset relation offset"))
        .transpose()
        .map(|offset| offset.unwrap_or(NO_RELATION_OFFSET))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlobRange {
    offset: u32,
    len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RdataRange {
    offset: u32,
    len: u16,
    rdata_encoding: PackedRdataEncoding,
}

impl RdataRange {
    fn blob_range(self) -> BlobRange {
        BlobRange {
            offset: self.offset,
            len: u32::from(self.len),
        }
    }

    fn len(self) -> usize {
        usize::from(self.len)
    }

    fn rdlength_bytes(self) -> [u8; 2] {
        self.len.to_be_bytes()
    }
}

#[derive(Debug, Clone, Default)]
struct BuildNode {
    parent: u32,
    depth: u16,
    children: BTreeMap<Vec<u8>, u32>,
    rrsets: Vec<ZoneImageRrsetId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainState<'a> {
    original_qname: &'a DomainName,
    original_node: Option<u32>,
    visited_target_nodes: SmallVec<[u32; 4]>,
    remaining: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndirectionTargetWire<'a> {
    Borrowed(&'a [u8]),
    DynamicAnswer(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnssecSection {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone, Copy)]
struct NameLabelView<'a> {
    prefix: Option<&'a [u8]>,
    labels: &'a [Vec<u8>],
    ascii_lowercase: bool,
}

struct ZoneImageDnssecState {
    appended_authority_rrsets: SmallVec<[ZoneImageRrsetId; 2]>,
    original_authority_rrset_count: u16,
    seen_selected_records: SmallVec<[ZoneImageSelectedRecord; 4]>,
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
            hash_record_identity(owner_key.as_bytes(), record.fixed_fields, record.rdata),
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
const SMALL_CHILD_LINEAR_SCAN_THRESHOLD: u16 = 4;
const CHILD_HASH_FANOUT_THRESHOLD: usize = 1024;

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
    canonical_key_from_uncompressed_wire(owner_wire)
        .ok_or(ZoneImageBuildError::InvalidCompiledOwner)
}

fn owner_override_wire(owner: &DomainName) -> OwnerOverrideWire {
    let mut wire = OwnerOverrideWire::new();
    for label in owner.labels() {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    wire
}

fn hash_record_identity(
    owner_key: &[u8],
    fixed_fields: ZoneImageRecordFixedFields,
    rdata: &[u8],
) -> u64 {
    let mut digest = FNV_OFFSET_BASIS;
    digest = fnv1a_bytes(digest, owner_key);
    digest = fnv1a_bytes(digest, &fixed_fields);
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

fn child_label_hash(label: &[u8]) -> usize {
    child_label_hash_with_ascii_lowercase_hint(label, false)
}

fn child_label_hash_with_ascii_lowercase_hint(label: &[u8], label_ascii_lowercase: bool) -> usize {
    let mut digest = FNV_OFFSET_BASIS;
    if label_ascii_lowercase {
        for byte in label {
            digest ^= u64::from(*byte);
            digest = digest.wrapping_mul(FNV_PRIME);
        }
    } else {
        for byte in label {
            digest ^= u64::from(byte.to_ascii_lowercase());
            digest = digest.wrapping_mul(FNV_PRIME);
        }
    }
    digest as usize
}

impl ZoneImage {
    pub fn compile(snapshot: &ZoneSnapshot) -> Result<Self, ZoneImageBuildError> {
        let origin_key = snapshot.origin.canonical_key();
        let mut rrsets = Vec::new();

        for rrset in snapshot.rrsets() {
            let owner_key = rrset.owner.canonical_key();
            if !rrset.owner.is_equal_or_subdomain_of(&snapshot.origin) {
                return Err(ZoneImageBuildError::OutOfZoneOwner {
                    owner: owner_key,
                    origin: origin_key,
                });
            }

            rrsets.push((owner_key, rrset));
        }
        rrsets.sort_by(|(left_owner, left), (right_owner, right)| {
            left_owner
                .cmp(right_owner)
                .then_with(|| left.class.cmp(&right.class))
                .then_with(|| left.rr_type.cmp(&right.rr_type))
                .then_with(|| left.ttl.cmp(&right.ttl))
        });

        let mut builder = ZoneImageBuilder::new(snapshot.origin.clone());
        for (owner_key, rrset) in rrsets {
            let mut rdatas = rrset
                .rdatas()
                .iter()
                .map(Vec::as_slice)
                .collect::<SmallVec<[&[u8]; 1]>>();
            rdatas.sort_unstable();
            let rrset_id = builder.push_rrset(
                owner_key,
                &rrset.owner,
                rrset.rr_type,
                rrset.class,
                rrset.ttl,
                &rdatas,
            )?;
            builder.attach_rrset(&rrset.owner, rrset_id)?;
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

    #[doc(hidden)]
    pub fn widest_child_lookup_profile(&self) -> Option<ZoneImageChildLookupProfile> {
        let node = self.nodes.iter().max_by_key(|node| node.edge_count)?;
        let edges = &self.edges
            [node.first_edge as usize..(node.first_edge + u32::from(node.edge_count)) as usize];
        let labels = edges
            .iter()
            .map(|edge| self.blob(&self.labels, edge.label).to_vec())
            .collect::<Vec<_>>();

        Some(ZoneImageChildLookupProfile {
            fanout: edges.len(),
            labels,
        })
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

        if !self.low_rrtype_may_exist(qtype) {
            return ZoneImageLookupOutcome::NoData;
        }

        if qclass != 255 {
            return if let Some(rrset_id) = self.find_rrset_at_node(node_index, qtype, qclass) {
                let mut plan = ZoneImageLookupPlan::positive();
                self.push_answer_rrset_to_plan(&mut plan, rrset_id);
                ZoneImageLookupOutcome::Found(plan)
            } else {
                ZoneImageLookupOutcome::NoData
            };
        }

        let node = &self.nodes[node_index as usize];
        if let Some(bitmap) = self.node_low_rrtype_bitmap(node_index)
            && !node_low_rrtype_bitmap_may_contain(bitmap, qtype)
        {
            return ZoneImageLookupOutcome::NoData;
        }
        let mut plan = ZoneImageLookupPlan::positive();
        for offset in 0..node.rrset_count {
            let rrset_id = node.first_rrset + u32::from(offset);
            let rrset = self.rrsets[rrset_id as usize];
            if rrset.rr_type() == qtype && qclass_matches(rrset.class(), qclass) {
                let rrset_id = ZoneImageRrsetId(rrset_id);
                let metrics = self.rrset_plan_metrics(rrset_id);
                plan.push_answer_rrset(rrset_id, metrics);
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
        self.lookup_direct_answer_plan_with_ascii_lowercase_hint(qname, qtype, qclass, false)
    }

    pub(crate) fn lookup_direct_answer_plan_with_ascii_lowercase_hint(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        qname_ascii_lowercase: bool,
    ) -> Option<ZoneImageLookupPlan> {
        if qtype == 255 {
            return None;
        }
        if rr_type_may_have_additional_address_target(qtype) {
            return None;
        }
        if !self.low_rrtype_may_exist(qtype) {
            return None;
        }

        let node_index = self.find_node_with_ascii_lowercase_hint(qname, qname_ascii_lowercase)?;
        let rrset_id = self.find_rrset_at_node(node_index, qtype, qclass)?;
        if self.covering_delegation_blocks_direct_answer(node_index, qtype, qclass)
            || self.covering_dname_blocks_direct_answer(node_index, qclass)
        {
            return None;
        }

        let mut plan = ZoneImageLookupPlan::positive();
        self.push_answer_rrset_to_plan(&mut plan, rrset_id);
        plan.mark_direct_answer_candidate();
        Some(plan)
    }

    pub fn lookup_response_plan(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> ZoneImageLookupPlan {
        self.lookup_response_plan_with_ascii_lowercase_hint(
            qname,
            qtype,
            qclass,
            max_cname_chain,
            any_response,
            false,
        )
    }

    pub(crate) fn lookup_response_plan_with_ascii_lowercase_hint(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
        qname_ascii_lowercase: bool,
    ) -> ZoneImageLookupPlan {
        let (exact_node, closest_or_exact_node) =
            self.query_node_handles(qname, qname_ascii_lowercase);
        if let Some(node_index) = closest_or_exact_node
            && let Some(delegation) = self.delegation_for_node(node_index, qclass)
            && !self.query_is_ds_at_delegation_owner(exact_node, node_index, qtype, delegation)
        {
            let metrics = self.rrset_plan_metrics(delegation);
            let mut plan = ZoneImageLookupPlan::referral(delegation, metrics);
            self.add_glue_for_ns_rrset(delegation, &mut plan);
            return plan;
        }

        if qtype == 255 {
            if let Some(node_index) = exact_node {
                if any_response == AnyResponseMode::Minimal {
                    if let Some(rrset) = self.minimal_any_rrset_at_node(node_index, qclass) {
                        let mut plan = ZoneImageLookupPlan::positive();
                        self.push_answer_rrset_to_plan(&mut plan, rrset);
                        self.add_precomputed_additionals_for_single_answer_rrset(rrset, &mut plan);
                        return plan;
                    }
                } else {
                    let mut plan = ZoneImageLookupPlan::positive();
                    self.push_full_any_rrsets_at_node(node_index, qclass, &mut plan);
                    if plan.has_flag(PLAN_FLAG_ANSWER_HAS_RECORDS) {
                        return plan;
                    }
                }
            }
        } else if self.low_rrtype_may_exist(qtype)
            && let Some(node_index) = exact_node
            && let Some(rrset) = self.find_rrset_at_node(node_index, qtype, qclass)
        {
            let mut plan = ZoneImageLookupPlan::positive();
            self.push_answer_rrset_to_plan(&mut plan, rrset);
            let added_additionals =
                self.add_precomputed_additionals_for_single_answer_rrset(rrset, &mut plan);
            if !added_additionals {
                plan.mark_direct_answer_candidate();
            }
            return plan;
        }

        if qtype != RecordType::Cname as u16
            && self.low_rrtype_may_exist(RecordType::Cname as u16)
            && let Some(node_index) = exact_node
            && let Some(cname) =
                self.find_rrset_at_node(node_index, RecordType::Cname as u16, qclass)
        {
            let plan = self.resolve_cname_at(
                qname,
                qtype,
                qclass,
                ZoneImageLookupPlan::positive(),
                chain_state_start(qname, exact_node, max_cname_chain),
                cname,
            );
            return plan;
        }

        if self.low_rrtype_may_exist(RecordType::Dname as u16)
            && let Some(node_index) = closest_or_exact_node
            && let Some(dname) = self.dname_for_node(exact_node, node_index, qclass)
        {
            return self.lookup_dname(qname, qtype, qclass, max_cname_chain, exact_node, dname);
        }

        if exact_node.is_some() {
            return self.nodata_plan(qclass);
        }

        if let Some(closest_node) = closest_or_exact_node
            && let Some(wildcard_plan) = self.lookup_wildcard_at_closest_node(
                closest_node,
                qname,
                qtype,
                qclass,
                max_cname_chain,
                any_response,
            )
        {
            return wildcard_plan;
        }

        self.nxdomain_plan(qclass)
    }

    pub fn augment_lookup_plan_with_dnssec(
        &self,
        plan: ZoneImageLookupPlan,
        qname: &DomainName,
        qclass: u16,
        nsec3_max_iterations: u16,
    ) -> ZoneImageLookupPlan {
        self.augment_lookup_plan_with_dnssec_ascii_lowercase_hint(
            plan,
            qname,
            qclass,
            nsec3_max_iterations,
            false,
        )
    }

    pub(crate) fn augment_lookup_plan_with_dnssec_ascii_lowercase_hint(
        &self,
        mut plan: ZoneImageLookupPlan,
        qname: &DomainName,
        qclass: u16,
        nsec3_max_iterations: u16,
        qname_ascii_lowercase: bool,
    ) -> ZoneImageLookupPlan {
        if !self.dnssec_augmentation_possible {
            return plan;
        }

        let referral_candidate = self.dnssec_referral_augmentation_possible
            && !plan.authoritative()
            && plan.referral_ns_rrset().is_some();
        let (nodata_candidate, nxdomain_candidate, wildcard_candidate) =
            if self.dnssec_denial_augmentation_possible {
                let answer_has_records = plan.answer_has_records();
                (
                    plan_is_nodata_candidate(&plan, answer_has_records),
                    plan_is_nxdomain_candidate(&plan, answer_has_records),
                    plan_is_wildcard_synthesis_candidate(&plan, answer_has_records),
                )
            } else {
                (false, false, false)
            };
        if !referral_candidate
            && !self.dnssec_rrsig_augmentation_possible
            && !nodata_candidate
            && !nxdomain_candidate
            && !wildcard_candidate
        {
            return plan;
        }

        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: self.initial_dnssec_seen_selected_records(&plan),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations,
        };
        if referral_candidate {
            self.add_referral_dnssec_augmentations(&mut plan, &mut state);
        }
        if self.dnssec_denial_augmentation_possible {
            let denial_candidate = nodata_candidate || nxdomain_candidate;
            let denial_has_authority_soa = if denial_candidate {
                plan.authority_has_soa()
            } else {
                false
            };
            let (exact_qname_node, closest_qname_node) = if denial_has_authority_soa {
                self.query_node_handles(qname, qname_ascii_lowercase)
            } else {
                (None, None)
            };

            if nodata_candidate && denial_has_authority_soa {
                self.add_nodata_nsec_augmentations(
                    qname,
                    qclass,
                    exact_qname_node,
                    qname_ascii_lowercase,
                    &mut plan,
                    &mut state,
                );
            }
            if nxdomain_candidate && denial_has_authority_soa {
                self.add_nxdomain_nsec_augmentations(
                    qname,
                    qclass,
                    closest_qname_node,
                    qname_ascii_lowercase,
                    &mut plan,
                    &mut state,
                );
            }
            if wildcard_candidate {
                self.add_wildcard_nsec_augmentations(
                    qname,
                    qclass,
                    qname_ascii_lowercase,
                    &mut plan,
                    &mut state,
                );
            }
        }
        if self.dnssec_rrsig_augmentation_possible {
            self.add_rrsig_augmentations(&mut plan, &mut state);
        }

        plan.set_flag(PLAN_FLAG_DNSSEC_AUGMENTED, state.dnssec_augmented);
        plan.set_flag(
            PLAN_FLAG_NSEC3_ITERATIONS_EXCEEDED,
            state.nsec3_iterations_exceeded,
        );
        plan
    }

    #[cfg(test)]
    pub(crate) fn rrset_wire(&self, rrset_id: ZoneImageRrsetId) -> Option<&[u8]> {
        let rrset = self.rrsets.get(rrset_id.0 as usize)?;
        Some(self.blob(&self.wire, rrset.wire))
    }

    pub(crate) fn low_rrtype_may_exist(&self, rr_type: u16) -> bool {
        low_rrtype_bitmap_may_contain(&self.low_rrtype_bitmap, rr_type)
    }

    #[cfg(test)]
    pub(crate) fn node_low_rrtype_may_exist(
        &self,
        owner: &DomainName,
        rr_type: u16,
    ) -> Option<bool> {
        let node_index = self.find_node(owner)?;
        Some(
            self.node_low_rrtype_bitmap(node_index)
                .is_none_or(|bitmap| node_low_rrtype_bitmap_may_contain(bitmap, rr_type)),
        )
    }

    #[cfg(test)]
    pub(crate) fn rrset_owner_wire(&self, rrset_id: ZoneImageRrsetId) -> Option<&[u8]> {
        let rrset = self.rrsets.get(rrset_id.0 as usize)?;
        Some(self.blob(&self.names, rrset.owner_wire))
    }

    pub(crate) fn direct_rrset_wire(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> Option<ZoneImageDirectRrset<'_>> {
        let rrset_index = rrset_id.0 as usize;
        let rrset = self.rrsets.get(rrset_index)?;
        if rrset.direct_answer_body_len == 0 {
            return None;
        }
        debug_assert_ne!(
            rrset.record_count, 0,
            "eligible direct-answer RRset must contain at least one record"
        );
        let (body, body_wire_len) =
            if rrset.direct_answer_body_len == DIRECT_ANSWER_BODY_RECORDS_FALLBACK {
                let first_record = rrset.first_record as usize;
                let record_count = usize::from(rrset.record_count);
                let records = self
                    .records
                    .get(first_record..first_record.checked_add(record_count)?)?;
                (
                    ZoneImageDirectRrsetBody::Records {
                        records,
                        record_prefix: direct_answer_record_prefix(rrset.fixed_fields),
                    },
                    direct_answer_non_owner_wire_len(rrset)
                        .saturating_add(2usize.saturating_mul(record_count)),
                )
            } else {
                let body_offset = rrset.wire.offset.checked_add(rrset.wire.len)?;
                (
                    ZoneImageDirectRrsetBody::Template(self.blob(
                        &self.wire,
                        BlobRange {
                            offset: body_offset,
                            len: rrset.direct_answer_body_len,
                        },
                    )),
                    rrset.direct_answer_body_len as usize,
                )
            };
        Some(ZoneImageDirectRrset {
            body_wire_len,
            section_count_header_bytes: section_count_header_bytes(rrset.record_count, 0, 0),
            section_count_header_bytes_with_edns: section_count_header_bytes(
                rrset.record_count,
                0,
                1,
            ),
            body,
        })
    }

    pub(crate) fn append_eligible_direct_answer_wire(
        &self,
        rrset: &ZoneImageDirectRrset<'_>,
        out: &mut Vec<u8>,
    ) {
        match &rrset.body {
            ZoneImageDirectRrsetBody::Template(body_wire) => out.extend_from_slice(body_wire),
            ZoneImageDirectRrsetBody::Records {
                records,
                record_prefix,
            } => {
                for record in *records {
                    let rdata = self.rdata_blob(record.rdata);
                    out.extend_from_slice(record_prefix);
                    out.extend_from_slice(&record.rdata.rdlength_bytes());
                    out.extend_from_slice(rdata);
                }
            }
        }
    }

    fn has_precomputed_additional_address_relations(&self, rrset_index: usize) -> bool {
        rrset_flag(&self.additional_address_rrset_flags, rrset_index)
    }

    fn has_precomputed_rrsig_relations(&self, rrset_index: usize) -> bool {
        rrset_flag(&self.rrsig_rrset_flags, rrset_index)
    }

    pub fn append_plan_wire(&self, plan: &ZoneImageLookupPlan, out: &mut Vec<u8>) -> usize {
        self.append_answer_wire(plan, out);
        self.append_authority_wire(plan, out);
        self.append_additional_wire(plan, out);
        plan.total_record_count()
    }

    #[cfg(test)]
    pub(crate) fn plan_accounting_direct(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> (usize, usize, usize, usize) {
        let (answer_count, mut wire_upper_bound) = self.answer_count_and_wire_upper_bound(plan);
        let (authority_count, authority_wire_upper_bound) =
            self.rrset_list_count_and_wire_upper_bound(&plan.authority_rrsets);
        wire_upper_bound = wire_upper_bound.saturating_add(authority_wire_upper_bound);
        let mut authority_count = authority_count;
        for selected in &plan.selected_authorities {
            authority_count += 1;
            wire_upper_bound =
                wire_upper_bound.saturating_add(self.selected_record_wire_len(*selected));
        }

        let (additional_count, additional_wire_upper_bound) =
            self.rrset_list_count_and_wire_upper_bound(&plan.additional_rrsets);
        wire_upper_bound = wire_upper_bound.saturating_add(additional_wire_upper_bound);
        let mut additional_count = additional_count;
        for selected in &plan.selected_additionals {
            additional_count += 1;
            wire_upper_bound =
                wire_upper_bound.saturating_add(self.selected_record_wire_len(*selected));
        }

        (
            answer_count,
            authority_count,
            additional_count,
            wire_upper_bound,
        )
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

    #[cfg(test)]
    pub(crate) fn plan_wire_upper_bound(&self, plan: &ZoneImageLookupPlan) -> usize {
        let mut bytes = self.answer_wire_upper_bound(plan);
        bytes = bytes.saturating_add(self.rrset_list_wire_upper_bound(&plan.authority_rrsets));
        bytes = bytes.saturating_add(
            plan.selected_authorities
                .iter()
                .map(|selected| self.selected_record_wire_len(*selected))
                .sum::<usize>(),
        );
        bytes = bytes.saturating_add(self.rrset_list_wire_upper_bound(&plan.additional_rrsets));
        bytes = bytes.saturating_add(
            plan.selected_additionals
                .iter()
                .map(|selected| self.selected_record_wire_len(*selected))
                .sum::<usize>(),
        );
        bytes
    }

    fn append_answer_wire(&self, plan: &ZoneImageLookupPlan, out: &mut Vec<u8>) {
        if plan.answer_items.is_empty() {
            self.append_rrset_list_wire(&plan.answer_rrsets, out);
            return;
        }

        for item in &plan.answer_items {
            match item {
                PlanAnswer::Rrset(rrset_id) => self.append_rrset_wire(*rrset_id, out),
                PlanAnswer::RrsetWithOwner {
                    rrset_id,
                    owner_index,
                } => self.append_rrset_wire_with_owner(
                    *rrset_id,
                    &plan.owner_overrides[usize::from(*owner_index)],
                    out,
                ),
                PlanAnswer::DynamicRecord(index) => {
                    append_synthesized_record_wire(&plan.dynamic_answers[usize::from(*index)], out);
                }
                PlanAnswer::SelectedRecord(selected) => {
                    self.append_selected_record_wire(*selected, out);
                }
            };
        }
    }

    fn append_rrset_list_wire(&self, rrsets: &[ZoneImageRrsetId], out: &mut Vec<u8>) {
        for rrset_id in rrsets {
            self.append_rrset_wire(*rrset_id, out);
        }
    }

    fn append_authority_wire(&self, plan: &ZoneImageLookupPlan, out: &mut Vec<u8>) {
        if plan.authority_first_rrset_is_soa() {
            self.append_authority_wire_with_first_soa(plan, out)
        } else if plan.authority_has_soa() {
            self.append_authority_wire_with_indexed_soa(plan, out)
        } else {
            self.append_rrset_list_wire(&plan.authority_rrsets, out)
        };
        for selected in &plan.selected_authorities {
            self.append_selected_record_wire(*selected, out);
        }
    }

    fn append_authority_wire_with_first_soa(&self, plan: &ZoneImageLookupPlan, out: &mut Vec<u8>) {
        let Some((&soa_rrset, rest)) = plan.authority_rrsets.split_first() else {
            return;
        };
        self.append_rrset_wire_with_fixed_fields(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            out,
        );
        self.append_rrset_list_wire(rest, out);
    }

    fn append_authority_wire_with_indexed_soa(
        &self,
        plan: &ZoneImageLookupPlan,
        out: &mut Vec<u8>,
    ) {
        let Some(soa_index) = plan.authority_soa_index() else {
            self.append_rrset_list_wire(&plan.authority_rrsets, out);
            return;
        };
        let Some((prefix, soa_and_rest)) = plan.authority_rrsets.split_at_checked(soa_index) else {
            self.append_rrset_list_wire(&plan.authority_rrsets, out);
            return;
        };
        let Some((&soa_rrset, rest)) = soa_and_rest.split_first() else {
            self.append_rrset_list_wire(&plan.authority_rrsets, out);
            return;
        };
        self.append_rrset_list_wire(prefix, out);
        self.append_rrset_wire_with_fixed_fields(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            out,
        );
        self.append_rrset_list_wire(rest, out);
    }

    fn append_additional_wire(&self, plan: &ZoneImageLookupPlan, out: &mut Vec<u8>) {
        for rrset_id in &plan.additional_rrsets {
            self.append_rrset_wire(*rrset_id, out);
        }
        for selected in &plan.selected_additionals {
            self.append_selected_record_wire(*selected, out);
        }
    }

    pub(crate) fn visit_plan_records<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        mut visit: impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        self.visit_plan_answer_records(plan, &mut visit);
        self.visit_plan_authority_records(plan, &mut visit);
        self.visit_plan_additional_records(plan, &mut visit);
    }

    pub(crate) fn visit_plan_record_sections<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        mut answer_visit: impl FnMut(ZoneImageWireRecord<'a>),
        mut authority_visit: impl FnMut(ZoneImageWireRecord<'a>),
        mut additional_visit: impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        self.visit_plan_answer_records(plan, &mut answer_visit);
        self.visit_plan_authority_records(plan, &mut authority_visit);
        self.visit_plan_additional_records(plan, &mut additional_visit);
    }

    pub(crate) fn visit_plan_record_sections_with_authority_removability<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        mut answer_visit: impl FnMut(ZoneImageWireRecord<'a>),
        mut authority_visit: impl FnMut(ZoneImageWireRecord<'a>, bool),
        mut additional_visit: impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        self.visit_plan_answer_records(plan, &mut answer_visit);
        self.visit_plan_authority_records_with_removability(plan, &mut authority_visit);
        self.visit_plan_additional_records(plan, &mut additional_visit);
    }

    fn visit_plan_answer_records<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        if plan.answer_items.is_empty() {
            for rrset_id in &plan.answer_rrsets {
                self.visit_rrset_records(*rrset_id, visit);
            }
        } else {
            for item in &plan.answer_items {
                match item {
                    PlanAnswer::Rrset(rrset_id) => self.visit_rrset_records(*rrset_id, visit),
                    PlanAnswer::RrsetWithOwner {
                        rrset_id,
                        owner_index,
                    } => self.visit_rrset_records_with_owner(
                        *rrset_id,
                        &plan.owner_overrides[usize::from(*owner_index)],
                        visit,
                    ),
                    PlanAnswer::DynamicRecord(index) => {
                        visit(synthesized_wire_record(
                            &plan.dynamic_answers[usize::from(*index)],
                        ));
                    }
                    PlanAnswer::SelectedRecord(selected) => {
                        visit(self.selected_wire_record(*selected));
                    }
                }
            }
        }
    }

    fn visit_plan_authority_records<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        if plan.authority_first_rrset_is_soa() {
            self.visit_authority_records_with_first_soa(plan, visit);
        } else if plan.authority_has_soa() {
            self.visit_authority_records_with_indexed_soa(plan, visit);
        } else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records(*rrset_id, visit);
            }
        }
        for selected in &plan.selected_authorities {
            visit(self.selected_wire_record(*selected));
        }
    }

    fn visit_plan_authority_records_with_removability<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>, bool),
    ) {
        if plan.authority_first_rrset_is_soa() {
            self.visit_authority_records_with_first_soa_removability(plan, visit);
        } else if plan.authority_has_soa() {
            self.visit_authority_records_with_indexed_soa_removability(plan, visit);
        } else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records_with_removability(*rrset_id, true, visit);
            }
        }
        for selected in &plan.selected_authorities {
            visit(self.selected_wire_record(*selected), true);
        }
    }

    fn visit_authority_records_with_first_soa<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let Some((&soa_rrset, rest)) = plan.authority_rrsets.split_first() else {
            return;
        };
        self.visit_rrset_records_with_fixed_fields_override(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            visit,
        );
        for rrset_id in rest {
            self.visit_rrset_records(*rrset_id, visit);
        }
    }

    fn visit_authority_records_with_first_soa_removability<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>, bool),
    ) {
        let Some((&soa_rrset, rest)) = plan.authority_rrsets.split_first() else {
            return;
        };
        self.visit_rrset_records_with_fixed_fields_override_removability(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            false,
            visit,
        );
        for rrset_id in rest {
            self.visit_rrset_records_with_removability(*rrset_id, true, visit);
        }
    }

    fn visit_authority_records_with_indexed_soa<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let Some(soa_index) = plan.authority_soa_index() else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records(*rrset_id, visit);
            }
            return;
        };
        let Some((prefix, soa_and_rest)) = plan.authority_rrsets.split_at_checked(soa_index) else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records(*rrset_id, visit);
            }
            return;
        };
        let Some((&soa_rrset, rest)) = soa_and_rest.split_first() else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records(*rrset_id, visit);
            }
            return;
        };
        for rrset_id in prefix {
            self.visit_rrset_records(*rrset_id, visit);
        }
        self.visit_rrset_records_with_fixed_fields_override(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            visit,
        );
        for rrset_id in rest {
            self.visit_rrset_records(*rrset_id, visit);
        }
    }

    fn visit_authority_records_with_indexed_soa_removability<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>, bool),
    ) {
        let Some(soa_index) = plan.authority_soa_index() else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records_with_removability(*rrset_id, true, visit);
            }
            return;
        };
        let Some((prefix, soa_and_rest)) = plan.authority_rrsets.split_at_checked(soa_index) else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records_with_removability(*rrset_id, true, visit);
            }
            return;
        };
        let Some((&soa_rrset, rest)) = soa_and_rest.split_first() else {
            for rrset_id in &plan.authority_rrsets {
                self.visit_rrset_records_with_removability(*rrset_id, true, visit);
            }
            return;
        };
        for rrset_id in prefix {
            self.visit_rrset_records_with_removability(*rrset_id, true, visit);
        }
        self.visit_rrset_records_with_fixed_fields_override_removability(
            soa_rrset,
            self.negative_authority_soa_fixed_fields(soa_rrset),
            false,
            visit,
        );
        for rrset_id in rest {
            self.visit_rrset_records_with_removability(*rrset_id, true, visit);
        }
    }

    fn visit_plan_additional_records<'a>(
        &'a self,
        plan: &'a ZoneImageLookupPlan,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        for rrset_id in &plan.additional_rrsets {
            self.visit_rrset_records(*rrset_id, visit);
        }
        for selected in &plan.selected_additionals {
            visit(self.selected_wire_record(*selected));
        }
    }

    #[cfg(test)]
    fn answer_wire_upper_bound(&self, plan: &ZoneImageLookupPlan) -> usize {
        self.answer_count_and_wire_upper_bound(plan).1
    }

    #[cfg(test)]
    fn answer_count_and_wire_upper_bound(&self, plan: &ZoneImageLookupPlan) -> (usize, usize) {
        if plan.answer_items.is_empty() {
            return self.rrset_list_count_and_wire_upper_bound(&plan.answer_rrsets);
        }

        let mut record_count = 0usize;
        let mut bytes = 0usize;
        for item in &plan.answer_items {
            let (item_count, item_bytes) = match item {
                PlanAnswer::Rrset(rrset_id) => {
                    self.rrset_count_and_wire_upper_bound(*rrset_id, None)
                }
                PlanAnswer::RrsetWithOwner {
                    rrset_id,
                    owner_index,
                } => self.rrset_count_and_wire_upper_bound(
                    *rrset_id,
                    Some(plan.owner_overrides[usize::from(*owner_index)].len()),
                ),
                PlanAnswer::DynamicRecord(index) => (
                    1,
                    synthesized_record_wire_len(&plan.dynamic_answers[usize::from(*index)]),
                ),
                PlanAnswer::SelectedRecord(selected) => {
                    (1, self.selected_record_wire_len(*selected))
                }
            };
            record_count += item_count;
            bytes = bytes.saturating_add(item_bytes);
        }
        (record_count, bytes)
    }

    #[cfg(test)]
    fn rrset_list_wire_upper_bound(&self, rrsets: &[ZoneImageRrsetId]) -> usize {
        self.rrset_list_count_and_wire_upper_bound(rrsets).1
    }

    #[cfg(test)]
    fn rrset_list_count_and_wire_upper_bound(&self, rrsets: &[ZoneImageRrsetId]) -> (usize, usize) {
        let mut record_count = 0usize;
        let mut bytes = 0usize;
        for rrset_id in rrsets {
            let (rrset_record_count, rrset_bytes) =
                self.rrset_count_and_wire_upper_bound(*rrset_id, None);
            record_count += rrset_record_count;
            bytes = bytes.saturating_add(rrset_bytes);
        }
        (record_count, bytes)
    }

    #[cfg(test)]
    fn rrset_count_and_wire_upper_bound(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire_len_override: Option<usize>,
    ) -> (usize, usize) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let record_count = usize::from(rrset.record_count);
        let bytes = if let Some(owner_wire_len) = owner_wire_len_override {
            let original_owner_wire_bytes = blob_len(rrset.owner_wire).saturating_mul(record_count);
            let non_owner_wire_bytes =
                blob_len(rrset.wire).saturating_sub(original_owner_wire_bytes);
            owner_wire_len
                .saturating_mul(record_count)
                .saturating_add(non_owner_wire_bytes)
        } else {
            blob_len(rrset.wire)
        };
        (record_count, bytes)
    }

    fn visit_rrset_records<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = self.blob(&self.names, rrset.owner_wire);
        self.visit_rrset_records_with_owner(rrset_id, owner_wire, visit);
    }

    fn visit_rrset_records_with_fixed_fields_override<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        fixed_fields: ZoneImageRecordFixedFields,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = self.blob(&self.names, rrset.owner_wire);
        self.visit_rrset_records_with_owner_and_fixed_fields(
            rrset_id,
            owner_wire,
            fixed_fields,
            visit,
        );
    }

    fn visit_rrset_records_with_removability<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        removable: bool,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>, bool),
    ) {
        let mut visit_record = |record| visit(record, removable);
        self.visit_rrset_records(rrset_id, &mut visit_record);
    }

    fn visit_rrset_records_with_fixed_fields_override_removability<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        fixed_fields: ZoneImageRecordFixedFields,
        removable: bool,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>, bool),
    ) {
        let mut visit_record = |record| visit(record, removable);
        self.visit_rrset_records_with_fixed_fields_override(
            rrset_id,
            fixed_fields,
            &mut visit_record,
        );
    }

    fn visit_rrset_records_with_owner<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &'a [u8],
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        self.visit_rrset_records_with_owner_and_fixed_fields(
            rrset_id,
            owner_wire,
            rrset.fixed_fields,
            visit,
        );
    }

    fn visit_rrset_records_with_owner_and_fixed_fields<'a>(
        &'a self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &'a [u8],
        fixed_fields: ZoneImageRecordFixedFields,
        visit: &mut impl FnMut(ZoneImageWireRecord<'a>),
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            visit(ZoneImageWireRecord {
                owner_wire,
                fixed_fields,
                rdlength_bytes: record.rdata.rdlength_bytes(),
                rdata_encoding: record.rdata.rdata_encoding,
                rdata: self.rdata_blob(record.rdata),
            });
        }
    }

    fn rrset_plan_metrics(&self, rrset_id: ZoneImageRrsetId) -> ZoneImageRrsetPlanMetrics {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let rr_type = rrset.rr_type();
        ZoneImageRrsetPlanMetrics {
            rr_type,
            record_count: usize::from(rrset.record_count),
            wire_upper_bound: blob_len(rrset.wire),
        }
    }

    fn rrset_plan_metrics_with_owner_len(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire_len: usize,
    ) -> ZoneImageRrsetPlanMetrics {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let rr_type = rrset.rr_type();
        let record_count = usize::from(rrset.record_count);
        ZoneImageRrsetPlanMetrics {
            rr_type,
            record_count,
            wire_upper_bound: owner_wire_len
                .saturating_mul(record_count)
                .saturating_add(rrset.ownerless_wire_len as usize),
        }
    }

    fn push_answer_rrset_to_plan(&self, plan: &mut ZoneImageLookupPlan, rrset: ZoneImageRrsetId) {
        let metrics = self.rrset_plan_metrics(rrset);
        plan.push_answer_rrset(rrset, metrics);
    }

    fn push_answer_rrset_with_owner_to_plan(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset: ZoneImageRrsetId,
        owner: &DomainName,
    ) {
        let owner_wire = owner_override_wire(owner);
        let metrics = self.rrset_plan_metrics_with_owner_len(rrset, owner_wire.len());
        plan.push_answer_rrset_with_owner_wire(rrset, owner_wire, metrics);
    }

    fn push_answer_rrset_with_owner_index_to_plan(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset: ZoneImageRrsetId,
        owner_index: usize,
        owner_wire_len: usize,
    ) {
        let metrics = self.rrset_plan_metrics_with_owner_len(rrset, owner_wire_len);
        plan.push_answer_rrset_with_owner_index(rrset, owner_index, metrics);
    }

    fn push_authority_rrset_to_plan(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset: ZoneImageRrsetId,
    ) {
        let metrics = self.rrset_plan_metrics(rrset);
        plan.push_authority_rrset(rrset, metrics);
    }

    fn push_additional_rrset_to_plan(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset: ZoneImageRrsetId,
    ) {
        let metrics = self.rrset_plan_metrics(rrset);
        plan.push_additional_rrset(rrset, metrics);
    }

    fn push_full_any_rrsets_at_node(
        &self,
        node_index: u32,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
    ) {
        debug_assert!(plan.answer_rrsets.is_empty());
        debug_assert!(plan.additional_rrsets.is_empty());
        let mut seen_additionals = SmallVec::<[ZoneImageRrsetId; 4]>::new();
        self.for_each_any_rrset_at_node(node_index, qclass, |rrset| {
            self.push_answer_rrset_to_plan(plan, rrset);
            self.push_additionals_for_rrset_targets(rrset, &mut seen_additionals, plan);
        });
    }

    fn push_full_any_rrsets_with_owner_at_node(
        &self,
        node_index: u32,
        qclass: u16,
        owner: &DomainName,
        plan: &mut ZoneImageLookupPlan,
    ) {
        debug_assert!(plan.answer_rrsets.is_empty());
        debug_assert!(plan.answer_items.is_empty());
        debug_assert!(plan.owner_overrides.is_empty());
        debug_assert!(plan.additional_rrsets.is_empty());
        let mut owner_index_and_len = None;
        let mut seen_additionals = SmallVec::<[ZoneImageRrsetId; 4]>::new();
        self.for_each_any_rrset_at_node(node_index, qclass, |rrset| {
            let (owner_index, owner_wire_len) = *owner_index_and_len.get_or_insert_with(|| {
                plan.set_flag(PLAN_FLAG_WILDCARD_SYNTHESIZED, true);
                let owner_index = plan.owner_overrides.len();
                plan.owner_overrides.push(owner_override_wire(owner));
                (owner_index, plan.owner_overrides[owner_index].len())
            });
            self.push_answer_rrset_with_owner_index_to_plan(
                plan,
                rrset,
                owner_index,
                owner_wire_len,
            );
            self.push_additionals_for_rrset_targets(rrset, &mut seen_additionals, plan);
        });
    }

    fn append_selected_record_wire(&self, selected: ZoneImageSelectedRecord, out: &mut Vec<u8>) {
        let rrset = self.rrsets[selected.rrset_id.0 as usize];
        append_stored_record_fields_wire(
            self.blob(&self.names, rrset.owner_wire),
            selected.fixed_fields,
            selected.rdata,
            self.rdata_blob(selected.rdata),
            out,
        );
    }

    #[cfg(test)]
    fn selected_record_wire_len(&self, selected: ZoneImageSelectedRecord) -> usize {
        selected.wire_len as usize
    }

    fn selected_wire_record(&self, selected: ZoneImageSelectedRecord) -> ZoneImageWireRecord<'_> {
        let rrset = self.rrsets[selected.rrset_id.0 as usize];
        ZoneImageWireRecord {
            owner_wire: self.blob(&self.names, rrset.owner_wire),
            fixed_fields: selected.fixed_fields,
            rdlength_bytes: selected.rdata.rdlength_bytes(),
            rdata_encoding: selected.rdata.rdata_encoding,
            rdata: self.rdata_blob(selected.rdata),
        }
    }

    fn append_rrset_wire(&self, rrset_id: ZoneImageRrsetId, out: &mut Vec<u8>) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        out.extend_from_slice(self.blob(&self.wire, rrset.wire));
    }

    fn append_rrset_wire_with_fixed_fields(
        &self,
        rrset_id: ZoneImageRrsetId,
        fixed_fields: ZoneImageRecordFixedFields,
        out: &mut Vec<u8>,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let owner_wire = self.blob(&self.names, rrset.owner_wire);
        self.append_rrset_wire_with_owner_and_fixed_fields(rrset_id, owner_wire, fixed_fields, out)
    }

    fn append_rrset_wire_with_owner(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &[u8],
        out: &mut Vec<u8>,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        self.append_rrset_wire_with_owner_and_fixed_fields(
            rrset_id,
            owner_wire,
            rrset.fixed_fields,
            out,
        )
    }

    fn append_rrset_wire_with_owner_and_fixed_fields(
        &self,
        rrset_id: ZoneImageRrsetId,
        owner_wire: &[u8],
        fixed_fields: ZoneImageRecordFixedFields,
        out: &mut Vec<u8>,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        for offset in 0..rrset.record_count {
            let record = self.records[(rrset.first_record + u32::from(offset)) as usize];
            append_stored_record_fields_wire(
                owner_wire,
                fixed_fields,
                record.rdata,
                self.rdata_blob(record.rdata),
                out,
            );
        }
    }

    fn negative_authority_soa_fixed_fields(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> ZoneImageRecordFixedFields {
        let rrset = self.rrsets[rrset_id.0 as usize];
        debug_assert_eq!(rrset.rr_type(), RecordType::Soa as u16);
        let mut fixed_fields = rrset.fixed_fields;
        fixed_fields[4..8].copy_from_slice(&rrset.negative_ttl_bytes);
        fixed_fields
    }

    fn nodata_plan(&self, qclass: u16) -> ZoneImageLookupPlan {
        let mut plan = ZoneImageLookupPlan::nodata();
        if let Some(soa) = self.soa_rrset(qclass) {
            self.push_authority_rrset_to_plan(&mut plan, soa);
        }
        plan
    }

    fn nxdomain_plan(&self, qclass: u16) -> ZoneImageLookupPlan {
        let mut plan = ZoneImageLookupPlan::nxdomain();
        if let Some(soa) = self.soa_rrset(qclass) {
            self.push_authority_rrset_to_plan(&mut plan, soa);
        }
        plan
    }

    #[cfg(test)]
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
        if node.rrset_count == 0 {
            return None;
        }
        let rrset_start = node.first_rrset as usize;
        let rrset_end = rrset_start + usize::from(node.rrset_count);
        if let [rrset] = &self.rrsets[rrset_start..rrset_end] {
            return (rrset.rr_type() == rr_type && qclass_matches(rrset.class(), qclass))
                .then_some(ZoneImageRrsetId(node.first_rrset));
        }
        if let Some(bitmap) = self.node_low_rrtype_bitmap(node_index)
            && !node_low_rrtype_bitmap_may_contain(bitmap, rr_type)
        {
            return None;
        }
        for offset in 0..node.rrset_count {
            let rrset_id = ZoneImageRrsetId(node.first_rrset + u32::from(offset));
            let rrset = self.rrsets[rrset_id.0 as usize];
            if qclass != 255 {
                match rrset.class().cmp(&qclass) {
                    Ordering::Less => continue,
                    Ordering::Greater => break,
                    Ordering::Equal if rrset.rr_type() > rr_type => break,
                    Ordering::Equal => {}
                }
            }
            if rrset.rr_type() == rr_type && qclass_matches(rrset.class(), qclass) {
                return Some(rrset_id);
            }
        }
        None
    }

    fn node_low_rrtype_bitmap(&self, node_index: u32) -> Option<u64> {
        let index = self.nodes[node_index as usize].low_rrtype_bitmap;
        if index == NO_NODE_LOW_RRTYPE_BITMAP {
            return None;
        }
        self.node_low_rrtype_bitmaps
            .get(usize::from(index))
            .copied()
    }

    fn minimal_any_rrset_at_node(&self, node_index: u32, qclass: u16) -> Option<ZoneImageRrsetId> {
        let node = &self.nodes[node_index as usize];
        if node.rrset_count == 0 {
            return None;
        }
        let rrset_start = node.first_rrset as usize;
        let rrset_end = rrset_start + usize::from(node.rrset_count);
        if let [rrset] = &self.rrsets[rrset_start..rrset_end] {
            return (qclass_matches(rrset.class(), qclass)
                && !is_dnssec_proof_or_signature_type(rrset.rr_type()))
            .then_some(ZoneImageRrsetId(node.first_rrset));
        }
        for offset in 0..node.rrset_count {
            let rrset_id = ZoneImageRrsetId(node.first_rrset + u32::from(offset));
            let rrset = self.rrsets[rrset_id.0 as usize];
            if qclass != 255 {
                match rrset.class().cmp(&qclass) {
                    Ordering::Less => continue,
                    Ordering::Greater => break,
                    Ordering::Equal => {}
                }
            }
            if qclass_matches(rrset.class(), qclass)
                && !is_dnssec_proof_or_signature_type(rrset.rr_type())
            {
                return Some(rrset_id);
            }
        }
        None
    }

    fn for_each_any_rrset_at_node(
        &self,
        node_index: u32,
        qclass: u16,
        mut visit: impl FnMut(ZoneImageRrsetId),
    ) {
        let node = &self.nodes[node_index as usize];
        if node.rrset_count == 0 {
            return;
        }
        let rrset_start = node.first_rrset as usize;
        let rrset_end = rrset_start + usize::from(node.rrset_count);
        if let [rrset] = &self.rrsets[rrset_start..rrset_end] {
            if qclass_matches(rrset.class(), qclass)
                && !is_dnssec_proof_or_signature_type(rrset.rr_type())
            {
                visit(ZoneImageRrsetId(node.first_rrset));
            }
            return;
        }
        for offset in 0..node.rrset_count {
            let rrset_id = ZoneImageRrsetId(node.first_rrset + u32::from(offset));
            let rrset = self.rrsets[rrset_id.0 as usize];
            if qclass != 255 {
                match rrset.class().cmp(&qclass) {
                    Ordering::Less => continue,
                    Ordering::Greater => break,
                    Ordering::Equal => {}
                }
            }
            if qclass_matches(rrset.class(), qclass)
                && !is_dnssec_proof_or_signature_type(rrset.rr_type())
            {
                visit(rrset_id);
            }
        }
    }

    fn soa_rrset(&self, qclass: u16) -> Option<ZoneImageRrsetId> {
        let class = if qclass == 255 { 1 } else { qclass };
        if class == 1 {
            return self.apex_in_soa_rrset;
        }
        self.find_rrset_at_node(0, RecordType::Soa as u16, class)
    }

    fn delegation_for_node(&self, mut node_index: u32, qclass: u16) -> Option<ZoneImageRrsetId> {
        if qclass == 1 || (qclass == 255 && self.any_class_delegation_policy_is_in_only) {
            return rrset_id_from_policy(self.nodes[node_index as usize].nearest_in_delegation);
        }

        while node_index != 0 {
            if let Some(rrset) = self.find_rrset_at_node(node_index, RecordType::Ns as u16, qclass)
            {
                return Some(rrset);
            }
            node_index = self.nodes[node_index as usize].parent;
        }
        None
    }

    fn dname_for_node(
        &self,
        exact_node: Option<u32>,
        mut node_index: u32,
        qclass: u16,
    ) -> Option<ZoneImageRrsetId> {
        if qclass == 1 || (qclass == 255 && self.any_class_dname_policy_is_in_only) {
            let node = self.nodes[node_index as usize];
            return rrset_id_from_policy(if Some(node_index) == exact_node {
                self.nearest_inherited_in_dname(node_index)
            } else {
                node.nearest_in_dname
            });
        }

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
        if qclass == 1 || (qclass == 255 && self.any_class_delegation_policy_is_in_only) {
            return !self.node_owns_policy_rrset(node_index, delegation);
        }
        self.find_rrset_at_node(node_index, RecordType::Ns as u16, qclass) != Some(delegation)
    }

    fn node_owns_policy_rrset(&self, node_index: u32, rrset_id: ZoneImageRrsetId) -> bool {
        let node = self.nodes[node_index as usize];
        let rrset = self.rrsets[rrset_id.0 as usize];
        usize::from(rrset.owner_label_count)
            == self
                .origin
                .labels()
                .len()
                .saturating_add(node.depth as usize)
    }

    fn query_is_ds_at_delegation_owner(
        &self,
        exact_node: Option<u32>,
        node_index: u32,
        qtype: u16,
        delegation: ZoneImageRrsetId,
    ) -> bool {
        qtype == RecordType::Ds as u16
            && exact_node == Some(node_index)
            && self.node_owns_policy_rrset(node_index, delegation)
    }

    fn covering_dname_blocks_direct_answer(&self, node_index: u32, qclass: u16) -> bool {
        if !self.low_rrtype_may_exist(RecordType::Dname as u16) {
            return false;
        }
        if qclass == 1 || (qclass == 255 && self.any_class_dname_policy_is_in_only) {
            return rrset_id_from_policy(self.nearest_inherited_in_dname(node_index)).is_some();
        }

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

    fn nearest_inherited_in_dname(&self, node_index: u32) -> u32 {
        let parent = self.nodes[node_index as usize].parent;
        if parent == node_index {
            return u32::MAX;
        }
        self.nodes[parent as usize].nearest_in_dname
    }

    fn lookup_dname(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        exact_node: Option<u32>,
        dname: ZoneImageRrsetId,
    ) -> ZoneImageLookupPlan {
        if self.rrsets[dname.0 as usize].record_count != 1 {
            let mut plan = ZoneImageLookupPlan::servfail(LookupTermination::MalformedDname);
            self.push_answer_rrset_to_plan(&mut plan, dname);
            return plan;
        }
        let Some(target) = self.single_name_rrset_target(dname) else {
            let mut plan = ZoneImageLookupPlan::servfail(LookupTermination::MalformedDname);
            self.push_answer_rrset_to_plan(&mut plan, dname);
            return plan;
        };
        let dname_owner_wire = self.blob(&self.names, self.rrsets[dname.0 as usize].owner_wire);
        let target_wire = self.single_name_target_wire(target);
        if target.node_hint == ImageTargetNode::OutOfZone {
            let Some((synthesized_target_wire, _prefix_len)) = qname
                .with_replaced_wire_suffix_wire_counted(
                    dname_owner_wire,
                    usize::from(self.rrsets[dname.0 as usize].owner_label_count),
                    target_wire,
                )
            else {
                let mut plan = ZoneImageLookupPlan::yxdomain();
                self.push_answer_rrset_to_plan(&mut plan, dname);
                if let Some(soa) = self.soa_rrset(qclass) {
                    self.push_authority_rrset_to_plan(&mut plan, soa);
                }
                return plan;
            };

            let mut plan = ZoneImageLookupPlan::positive();
            self.push_answer_rrset_to_plan(&mut plan, dname);
            let synthesized_cname_fixed_fields =
                synthesized_cname_fixed_fields_from_rrset(self.rrsets[dname.0 as usize]);
            plan.push_synthesized_answer(
                qname,
                synthesized_cname_fixed_fields,
                PackedRdataEncoding::single_name(),
                synthesized_target_wire,
            );
            return plan;
        }
        let Some((synthesized_target, synthesized_target_wire, prefix_len)) = qname
            .with_replaced_wire_suffix_and_stored_wire_parts_counted(
                dname_owner_wire,
                usize::from(self.rrsets[dname.0 as usize].owner_label_count),
                &target.name,
                target_wire,
            )
        else {
            let mut plan = ZoneImageLookupPlan::yxdomain();
            self.push_answer_rrset_to_plan(&mut plan, dname);
            if let Some(soa) = self.soa_rrset(qclass) {
                self.push_authority_rrset_to_plan(&mut plan, soa);
            }
            return plan;
        };
        let mut plan = ZoneImageLookupPlan::positive();
        self.push_answer_rrset_to_plan(&mut plan, dname);
        let synthesized_cname_fixed_fields =
            synthesized_cname_fixed_fields_from_rrset(self.rrsets[dname.0 as usize]);
        let synthesized_index = plan.push_synthesized_answer(
            qname,
            synthesized_cname_fixed_fields,
            PackedRdataEncoding::single_name(),
            synthesized_target_wire,
        );
        self.resolve_indirection_target(
            &synthesized_target,
            IndirectionTargetWire::DynamicAnswer(synthesized_index),
            self.dname_synthesized_target_node_hint(target, &synthesized_target, qname, prefix_len),
            qtype,
            qclass,
            plan,
            chain_state_start(qname, exact_node, max_cname_chain.saturating_sub(1)),
        )
    }

    fn lookup_wildcard_at_closest_node(
        &self,
        closest_node: u32,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> Option<ZoneImageLookupPlan> {
        let Some(wildcard_node) = self.find_child(closest_node, b"*") else {
            return None;
        };

        if qtype == 255 {
            if any_response == AnyResponseMode::Minimal {
                if let Some(rrset) = self.minimal_any_rrset_at_node(wildcard_node, qclass) {
                    let mut plan = ZoneImageLookupPlan::positive();
                    self.push_answer_rrset_with_owner_to_plan(&mut plan, rrset, qname);
                    self.add_precomputed_additionals_for_single_answer_rrset(rrset, &mut plan);
                    return Some(plan);
                }
            } else {
                let mut plan = ZoneImageLookupPlan::positive();
                self.push_full_any_rrsets_with_owner_at_node(
                    wildcard_node,
                    qclass,
                    qname,
                    &mut plan,
                );
                if plan.has_flag(PLAN_FLAG_ANSWER_HAS_RECORDS) {
                    return Some(plan);
                }
            }
        } else if self.low_rrtype_may_exist(qtype)
            && let Some(rrset) = self.find_rrset_at_node(wildcard_node, qtype, qclass)
        {
            let mut plan = ZoneImageLookupPlan::positive();
            self.push_answer_rrset_with_owner_to_plan(&mut plan, rrset, qname);
            self.add_precomputed_additionals_for_single_answer_rrset(rrset, &mut plan);
            return Some(plan);
        }

        if qtype != RecordType::Cname as u16
            && self.low_rrtype_may_exist(RecordType::Cname as u16)
            && let Some(cname) =
                self.find_rrset_at_node(wildcard_node, RecordType::Cname as u16, qclass)
        {
            let mut plan = ZoneImageLookupPlan::positive();
            self.push_answer_rrset_with_owner_to_plan(&mut plan, cname, qname);
            let Some(target) = self.single_name_rrset_target(cname) else {
                return Some(plan);
            };
            let plan = self.resolve_indirection_target(
                &target.name,
                IndirectionTargetWire::Borrowed(self.single_name_target_wire(target)),
                target.node_hint,
                qtype,
                qclass,
                plan,
                chain_state_start(qname, None, max_cname_chain.saturating_sub(1)),
            );
            return Some(plan);
        }

        if self.nodes[wildcard_node as usize].rrset_count > 0 {
            return Some(self.nodata_plan(qclass));
        }
        None
    }

    fn resolve_cname_at<'a>(
        &'a self,
        current: &DomainName,
        qtype: u16,
        qclass: u16,
        mut plan: ZoneImageLookupPlan,
        state: ChainState<'a>,
        cname: ZoneImageRrsetId,
    ) -> ZoneImageLookupPlan {
        if state.remaining == 0 {
            warn!(
                qname = %state.original_qname,
                zone = %self.origin,
                reason = "cname_chain_limit",
                current = %current,
                "CNAME chain limit reached; returning SERVFAIL with partial chain"
            );
            return plan.into_servfail(LookupTermination::CnameChainLimit);
        }

        self.push_answer_rrset_to_plan(&mut plan, cname);
        let Some(target) = self.single_name_rrset_target(cname) else {
            return plan;
        };

        self.resolve_indirection_target(
            &target.name,
            IndirectionTargetWire::Borrowed(self.single_name_target_wire(target)),
            target.node_hint,
            qtype,
            qclass,
            plan,
            ChainState {
                original_qname: state.original_qname,
                original_node: state.original_node,
                visited_target_nodes: state.visited_target_nodes,
                remaining: state.remaining - 1,
            },
        )
    }

    fn resolve_indirection_target<'a>(
        &'a self,
        target: &DomainName,
        target_wire: IndirectionTargetWire<'_>,
        target_node: ImageTargetNode,
        qtype: u16,
        qclass: u16,
        mut plan: ZoneImageLookupPlan,
        mut state: ChainState<'a>,
    ) -> ZoneImageLookupPlan {
        if target_matches_original_query(target, target_wire, target_node, &state, &plan) {
            warn!(
                qname = %state.original_qname,
                zone = %self.origin,
                reason = "cname_loop",
                looping_target = %target,
                "CNAME chain loop detected; returning SERVFAIL with partial chain"
            );
            return plan.into_servfail(LookupTermination::CnameLoop);
        }

        match target_node {
            ImageTargetNode::OutOfZone | ImageTargetNode::OutOfZoneParentSuffix => {}
            ImageTargetNode::InZoneNode(target_node) => {
                if state
                    .visited_target_nodes
                    .iter()
                    .any(|visited| *visited == target_node)
                {
                    warn!(
                        qname = %state.original_qname,
                        zone = %self.origin,
                        reason = "cname_loop",
                        looping_target = %target,
                        "CNAME chain loop detected; returning SERVFAIL with partial chain"
                    );
                    return plan.into_servfail(LookupTermination::CnameLoop);
                }
                state.visited_target_nodes.push(target_node);

                if self.low_rrtype_may_exist(qtype)
                    && let Some(rrset) = self.find_rrset_at_node(target_node, qtype, qclass)
                {
                    self.push_answer_rrset_to_plan(&mut plan, rrset);
                    self.add_precomputed_additionals_for_single_answer_rrset(rrset, &mut plan);
                    return plan;
                }

                if qtype != RecordType::Cname as u16
                    && self.low_rrtype_may_exist(RecordType::Cname as u16)
                    && let Some(cname) =
                        self.find_rrset_at_node(target_node, RecordType::Cname as u16, qclass)
                {
                    return self.resolve_cname_at(target, qtype, qclass, plan, state, cname);
                }

                plan.rcode = Rcode::NoError;
                if let Some(soa) = self.soa_rrset(qclass) {
                    self.push_authority_rrset_to_plan(&mut plan, soa);
                }
            }
            ImageTargetNode::InZoneMissing => {
                plan.rcode = Rcode::NxDomain;
                if let Some(soa) = self.soa_rrset(qclass) {
                    self.push_authority_rrset_to_plan(&mut plan, soa);
                }
            }
        }
        plan
    }

    fn add_glue_for_ns_rrset(&self, ns_rrset: ZoneImageRrsetId, plan: &mut ZoneImageLookupPlan) {
        debug_assert!(plan.additional_rrsets.is_empty());
        for relation in self.precomputed_referral_glue_relations(ns_rrset) {
            self.push_additional_rrset_to_plan(plan, relation.rrset_id);
        }
    }

    fn add_precomputed_additionals_for_single_answer_rrset(
        &self,
        rrset_id: ZoneImageRrsetId,
        plan: &mut ZoneImageLookupPlan,
    ) -> bool {
        debug_assert!(plan.additional_rrsets.is_empty());
        if !rr_type_may_have_additional_address_target(self.rrsets[rrset_id.0 as usize].rr_type()) {
            return false;
        }
        let mut added = false;
        for relation in self.precomputed_additional_relations_if_present(rrset_id) {
            self.push_additional_rrset_to_plan(plan, relation.rrset_id);
            added = true;
        }
        added
    }

    fn push_additionals_for_rrset_targets(
        &self,
        rrset_id: ZoneImageRrsetId,
        seen: &mut SmallVec<[ZoneImageRrsetId; 4]>,
        plan: &mut ZoneImageLookupPlan,
    ) {
        for relation in self.precomputed_additional_relations_if_present(rrset_id) {
            let rrset = relation.rrset_id;
            if !seen.contains(&rrset) {
                seen.push(rrset);
                self.push_additional_rrset_to_plan(plan, rrset);
            }
        }
    }

    #[cfg(test)]
    fn precomputed_additional_rrsets(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> impl Iterator<Item = ZoneImageRrsetId> + '_ {
        self.precomputed_additional_relations(rrset_id)
            .iter()
            .map(|relation| relation.rrset_id)
    }

    fn precomputed_additional_relations_if_present(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> &[ImageRrsetRelation] {
        if !self.has_precomputed_additional_address_relations(rrset_id.0 as usize) {
            return &[];
        }
        self.precomputed_additional_relations(rrset_id)
    }

    fn precomputed_additional_relations(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> &[ImageRrsetRelation] {
        let Some(span) = self.rrset_relation_span_for_rrset(rrset_id) else {
            return &[];
        };
        let relations = self.rrset_relations_from_offsets(
            span,
            span.additional_address_offset,
            span.relation_count,
        );
        debug_assert!(
            relations
                .iter()
                .all(|relation| relation.kind == ImageRrsetRelationKind::AdditionalAddress)
        );
        relations
    }

    #[cfg(test)]
    fn precomputed_referral_glue_rrsets(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> impl Iterator<Item = ZoneImageRrsetId> + '_ {
        self.precomputed_referral_glue_relations(rrset_id)
            .iter()
            .map(|relation| relation.rrset_id)
    }

    fn precomputed_referral_glue_relations(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> &[ImageRrsetRelation] {
        let Some(span) = self.rrset_relation_span_for_rrset(rrset_id) else {
            return &[];
        };
        let relations = self.rrset_relations_from_offsets(
            span,
            span.referral_glue_offset,
            span.next_relation_offset_after_referral_glue(),
        );
        debug_assert!(
            relations
                .iter()
                .all(|relation| relation.kind == ImageRrsetRelationKind::ReferralGlue)
        );
        relations
    }

    fn precomputed_referral_dnssec_rrset(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> Option<ImageRrsetRelation> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let span = self.rrset_relation_span(rrset.relation_span)?;
        if span.delegation_dnssec_offset == NO_RELATION_OFFSET {
            return None;
        }
        self.rrset_relations
            .get(span.first_relation as usize + usize::from(span.delegation_dnssec_offset))
            .copied()
    }

    #[cfg(test)]
    fn rrset_relations_of_kind(
        &self,
        rrset_id: ZoneImageRrsetId,
        kind: ImageRrsetRelationKind,
    ) -> &[ImageRrsetRelation] {
        let Some(span) = self.rrset_relation_span_for_rrset(rrset_id) else {
            return &[];
        };
        let Some((start_offset, end_offset)) = span.kind_offsets(kind) else {
            return &[];
        };
        self.rrset_relations_from_offsets(span, start_offset, end_offset)
    }

    fn rrset_relation_span_for_rrset(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> Option<&ImageRrsetRelationSpan> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        self.rrset_relation_span(rrset.relation_span)
    }

    fn rrset_relations_from_offsets(
        &self,
        span: &ImageRrsetRelationSpan,
        start_offset: u16,
        end_offset: u16,
    ) -> &[ImageRrsetRelation] {
        if start_offset == NO_RELATION_OFFSET {
            return &[];
        }
        let start = span.first_relation as usize + usize::from(start_offset);
        let end = span.first_relation as usize + usize::from(end_offset);
        &self.rrset_relations[start..end]
    }

    fn rrset_relation_span(&self, relation_span: u32) -> Option<&ImageRrsetRelationSpan> {
        if relation_span == u32::MAX {
            return None;
        }
        self.rrset_relation_spans.get(relation_span as usize)
    }

    fn add_referral_dnssec_augmentations(
        &self,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        let Some(rrset_id) = plan.referral_ns_rrset().filter(|_| !plan.authoritative()) else {
            return;
        };
        self.add_referral_dnssec_for_ns_rrset(rrset_id, plan, state);
    }

    fn add_referral_dnssec_for_ns_rrset(
        &self,
        rrset_id: ZoneImageRrsetId,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        let rrset = self.rrsets[rrset_id.0 as usize];
        debug_assert_eq!(rrset.rr_type(), RecordType::Ns as u16);
        if let Some(relation) = self.precomputed_referral_dnssec_rrset(rrset_id) {
            self.push_authority_rrset(plan, relation.rrset_id, state);
        } else {
            let owner_wire = self.blob(&self.names, rrset.owner_wire);
            self.push_nsec3_for_wire_name(owner_wire, rrset.class(), plan, state);
        }
    }

    fn add_nodata_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        exact_qname_node: Option<u32>,
        qname_ascii_lowercase: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        let Some(qname_node) = exact_qname_node else {
            return;
        };

        let has_nsec_ranges = !self.nsec_ranges.is_empty();
        if has_nsec_ranges
            && let Some(nsec) = self.find_rrset_at_node(qname_node, RecordType::Nsec as u16, qclass)
        {
            self.push_authority_rrset(plan, nsec, state);
        } else if !self.nsec3_ranges.is_empty() {
            self.push_nsec3_for_name(qname, qclass, qname_ascii_lowercase, plan, state);
        }
    }

    fn add_nxdomain_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        closest_qname_node: Option<u32>,
        qname_ascii_lowercase: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        let has_nsec_ranges = !self.nsec_ranges.is_empty();
        let has_nsec3_ranges = !self.nsec3_ranges.is_empty();
        if has_nsec_ranges {
            self.push_nsec_covering_name(qname, qclass, plan, state);
        }
        if has_nsec3_ranges {
            self.push_nsec3_for_name(qname, qclass, qname_ascii_lowercase, plan, state);
        }
        if (has_nsec_ranges || has_nsec3_ranges)
            && let Some(closest_labels) =
                self.closest_encloser_labels_from_node(qname, closest_qname_node)
        {
            let closest_encloser = NameLabelView {
                prefix: None,
                labels: closest_labels,
                ascii_lowercase: qname_ascii_lowercase,
            };
            let wildcard_child = NameLabelView {
                prefix: Some(b"*"),
                labels: closest_labels,
                ascii_lowercase: qname_ascii_lowercase,
            };
            if has_nsec_ranges {
                self.push_nsec_covering_label_view(wildcard_child, qclass, plan, state);
            }
            if has_nsec3_ranges {
                self.push_nsec3_for_label_view(closest_encloser, qclass, plan, state);
                self.push_nsec3_for_label_view(wildcard_child, qclass, plan, state);
            }
        }
    }

    fn add_wildcard_nsec_augmentations(
        &self,
        qname: &DomainName,
        qclass: u16,
        qname_ascii_lowercase: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if !self.nsec_ranges.is_empty() {
            self.push_nsec_covering_name(qname, qclass, plan, state);
        }
        if !self.nsec3_ranges.is_empty() {
            self.push_nsec3_for_name(qname, qclass, qname_ascii_lowercase, plan, state);
        }
    }

    fn add_rrsig_augmentations(
        &self,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if plan.answer_items.is_empty() {
            let answer_rrset_count = plan.answer_rrsets.len();
            for index in 0..answer_rrset_count {
                let rrset_id = plan.answer_rrsets[index];
                self.push_rrsig_for_rrset(DnssecSection::Answer, rrset_id, plan, state);
            }
        } else {
            let answer_item_count = plan.answer_items.len();
            for index in 0..answer_item_count {
                let item = plan.answer_items[index];
                match item {
                    PlanAnswer::Rrset(rrset_id) => {
                        self.push_rrsig_for_rrset(DnssecSection::Answer, rrset_id, plan, state);
                    }
                    PlanAnswer::RrsetWithOwner { .. }
                    | PlanAnswer::DynamicRecord(_)
                    | PlanAnswer::SelectedRecord(_) => {}
                }
            }
        }

        let authority_rrset_count = plan.authority_rrsets.len();
        for index in 0..authority_rrset_count {
            let rrset_id = plan.authority_rrsets[index];
            self.push_rrsig_for_rrset(DnssecSection::Authority, rrset_id, plan, state);
        }

        let additional_rrset_count = plan.additional_rrsets.len();
        for index in 0..additional_rrset_count {
            let rrset_id = plan.additional_rrsets[index];
            self.push_rrsig_for_rrset(DnssecSection::Additional, rrset_id, plan, state);
        }
    }

    fn push_authority_rrset(
        &self,
        plan: &mut ZoneImageLookupPlan,
        rrset_id: ZoneImageRrsetId,
        state: &mut ZoneImageDnssecState,
    ) {
        let original_authority_rrset_count =
            usize::from(state.original_authority_rrset_count).min(plan.authority_rrsets.len());
        let original_authority_rrsets = &plan.authority_rrsets[..original_authority_rrset_count];

        if state.appended_authority_rrsets.contains(&rrset_id)
            || original_authority_rrsets.contains(&rrset_id)
        {
            return;
        }
        state.appended_authority_rrsets.push(rrset_id);
        self.push_authority_rrset_to_plan(plan, rrset_id);
        state.dnssec_augmented = true;
    }

    fn push_nsec_covering_name(
        &self,
        name: &DomainName,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if self.nsec_ranges.is_empty() {
            return;
        }
        let Some(nsec) = self.nsec_rrset_covering_name(name, qclass) else {
            return;
        };
        self.push_authority_rrset(plan, nsec, state);
    }

    fn push_nsec_covering_label_view(
        &self,
        name: NameLabelView<'_>,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if self.nsec_ranges.is_empty() {
            return;
        }
        let Some(nsec) = self.nsec_rrset_covering_label_view(name, qclass) else {
            return;
        };
        self.push_authority_rrset(plan, nsec, state);
    }

    fn nsec_rrset_covering_name(&self, name: &DomainName, qclass: u16) -> Option<ZoneImageRrsetId> {
        self.nsec_rrset_covering_label_view(
            NameLabelView {
                prefix: None,
                labels: name.labels(),
                ascii_lowercase: false,
            },
            qclass,
        )
    }

    fn nsec_rrset_covering_label_view(
        &self,
        name: NameLabelView<'_>,
        qclass: u16,
    ) -> Option<ZoneImageRrsetId> {
        for range in &self.nsec_ranges {
            if !qclass_matches(range.class, qclass) {
                continue;
            }
            if nsec_range_keys_cover_label_view(
                self.blob(&self.names, range.owner_key),
                self.blob(&self.names, range.next_key),
                range.owner_before_next,
                name,
            ) {
                return Some(range.rrset_id);
            }
        }
        None
    }

    fn push_nsec3_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        qname_ascii_lowercase: bool,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if self.nsec3_ranges.is_empty() {
            return;
        }
        let Some(nsec3) = self.nsec3_rrset_for_name(
            name,
            qclass,
            &mut state.nsec3_iterations_exceeded,
            state.nsec3_max_iterations,
            qname_ascii_lowercase,
        ) else {
            return;
        };
        self.push_authority_rrset(plan, nsec3, state);
    }

    fn push_nsec3_for_label_view(
        &self,
        name: NameLabelView<'_>,
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if self.nsec3_ranges.is_empty() {
            return;
        }
        let Some(nsec3) = self.nsec3_rrset_for_label_view(
            name,
            qclass,
            &mut state.nsec3_iterations_exceeded,
            state.nsec3_max_iterations,
        ) else {
            return;
        };
        self.push_authority_rrset(plan, nsec3, state);
    }

    fn push_nsec3_for_wire_name(
        &self,
        wire_name: &[u8],
        qclass: u16,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        if self.nsec3_ranges.is_empty() {
            return;
        }
        let Some(nsec3) = self.nsec3_rrset_for_wire_name(
            wire_name,
            qclass,
            &mut state.nsec3_iterations_exceeded,
            state.nsec3_max_iterations,
        ) else {
            return;
        };
        self.push_authority_rrset(plan, nsec3, state);
    }

    fn nsec3_rrset_for_name(
        &self,
        name: &DomainName,
        qclass: u16,
        nsec3_iterations_exceeded: &mut bool,
        nsec3_max_iterations: u16,
        qname_ascii_lowercase: bool,
    ) -> Option<ZoneImageRrsetId> {
        self.nsec3_rrset_for_label_view(
            NameLabelView {
                prefix: None,
                labels: name.labels(),
                ascii_lowercase: qname_ascii_lowercase,
            },
            qclass,
            nsec3_iterations_exceeded,
            nsec3_max_iterations,
        )
    }

    fn nsec3_rrset_for_wire_name(
        &self,
        wire_name: &[u8],
        qclass: u16,
        nsec3_iterations_exceeded: &mut bool,
        nsec3_max_iterations: u16,
    ) -> Option<ZoneImageRrsetId> {
        let mut hash_cache = SmallVec::<[(u16, Option<[u8; 20]>); 1]>::new();
        let mut covering_rrset = None;
        for range in &self.nsec3_ranges {
            if !qclass_matches(range.class, qclass) {
                continue;
            }
            let param_set = self.nsec3_param_set(range.param_set);
            if param_set.iterations > nsec3_max_iterations {
                *nsec3_iterations_exceeded = true;
                continue;
            }
            let hash_index = self.nsec3_hash_wire_name_param_cache_index(
                wire_name,
                range.param_set,
                param_set,
                &mut hash_cache,
            );
            let Some(hash) = hash_cache[hash_index].1.as_ref() else {
                continue;
            };
            if hash == &range.owner_hash {
                return Some(range.rrset_id);
            }
            if covering_rrset.is_none()
                && nsec3_range_covers_hash(&range.owner_hash, &range.next_hash, hash)
            {
                covering_rrset = Some(range.rrset_id);
            }
        }

        covering_rrset
    }

    fn nsec3_rrset_for_label_view(
        &self,
        name: NameLabelView<'_>,
        qclass: u16,
        nsec3_iterations_exceeded: &mut bool,
        nsec3_max_iterations: u16,
    ) -> Option<ZoneImageRrsetId> {
        let mut hash_cache = SmallVec::<[(u16, Option<[u8; 20]>); 1]>::new();
        let mut covering_rrset = None;
        for range in &self.nsec3_ranges {
            if !qclass_matches(range.class, qclass) {
                continue;
            }
            let param_set = self.nsec3_param_set(range.param_set);
            if param_set.iterations > nsec3_max_iterations {
                *nsec3_iterations_exceeded = true;
                continue;
            }
            let hash_index = self.nsec3_hash_label_view_param_cache_index(
                name,
                range.param_set,
                param_set,
                &mut hash_cache,
            );
            let Some(hash) = hash_cache[hash_index].1.as_ref() else {
                continue;
            };
            if hash == &range.owner_hash {
                return Some(range.rrset_id);
            }
            if covering_rrset.is_none()
                && nsec3_range_covers_hash(&range.owner_hash, &range.next_hash, hash)
            {
                covering_rrset = Some(range.rrset_id);
            }
        }

        covering_rrset
    }

    fn nsec3_param_set(&self, param_set: u16) -> &ImageNsec3ParamSet {
        &self.nsec3_param_sets[usize::from(param_set)]
    }

    fn nsec3_params_from_set<'a>(&'a self, param_set: &'a ImageNsec3ParamSet) -> Nsec3Params<'a> {
        Nsec3Params {
            hash_algorithm: param_set.hash_algorithm,
            iterations: param_set.iterations,
            salt: self.blob(&self.rdata, param_set.salt),
        }
    }

    fn nsec3_hash_label_view_param_cache_index(
        &self,
        name: NameLabelView<'_>,
        param_set_index: u16,
        param_set: &ImageNsec3ParamSet,
        cache: &mut SmallVec<[(u16, Option<[u8; 20]>); 1]>,
    ) -> usize {
        if let Some(index) = cache
            .iter()
            .position(|(cached_param_set, _)| *cached_param_set == param_set_index)
        {
            return index;
        }

        let params = self.nsec3_params_from_set(param_set);
        let hash = nsec3_hash_label_view(name, params);
        cache.push((param_set_index, hash));
        cache.len() - 1
    }

    fn nsec3_hash_wire_name_param_cache_index(
        &self,
        wire_name: &[u8],
        param_set_index: u16,
        param_set: &ImageNsec3ParamSet,
        cache: &mut SmallVec<[(u16, Option<[u8; 20]>); 1]>,
    ) -> usize {
        if let Some(index) = cache
            .iter()
            .position(|(cached_param_set, _)| *cached_param_set == param_set_index)
        {
            return index;
        }

        let params = self.nsec3_params_from_set(param_set);
        let hash = nsec3_hash_wire_name(wire_name, params);
        cache.push((param_set_index, hash));
        cache.len() - 1
    }

    fn push_rrsig_for_rrset(
        &self,
        section: DnssecSection,
        covered_rrset_id: ZoneImageRrsetId,
        plan: &mut ZoneImageLookupPlan,
        state: &mut ZoneImageDnssecState,
    ) {
        for signature in self.precomputed_rrsig_relations(covered_rrset_id) {
            let selected = self.selected_record_from_relation(*signature);
            if !insert_selected_record(&mut state.seen_selected_records, selected) {
                continue;
            }
            plan.push_selected_record_section(section, selected);
            state.dnssec_augmented = true;
        }
    }

    #[cfg(test)]
    fn precomputed_rrsig_records(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> impl Iterator<Item = ImageRrsetRelation> + '_ {
        self.precomputed_rrsig_relations(rrset_id).iter().copied()
    }

    fn selected_record_from_relation(
        &self,
        relation: ImageRrsetRelation,
    ) -> ZoneImageSelectedRecord {
        let rrset = self.rrsets[relation.rrset_id.0 as usize];
        let record = self.records[relation.record_index as usize];
        let wire_len = usize::from(relation.owner_wire_len)
            .saturating_add(10)
            .saturating_add(usize::from(relation.rdata_len));
        ZoneImageSelectedRecord {
            rrset_id: relation.rrset_id,
            wire_len: u32::try_from(wire_len)
                .expect("selected immutable DNS record wire length must fit u32"),
            fixed_fields: rrset.fixed_fields,
            rdata: record.rdata,
        }
    }

    fn precomputed_rrsig_relations(&self, rrset_id: ZoneImageRrsetId) -> &[ImageRrsetRelation] {
        if !self.has_precomputed_rrsig_relations(rrset_id.0 as usize) {
            return &[];
        }
        let Some(span) = self.rrset_relation_span_for_rrset(rrset_id) else {
            return &[];
        };
        let relations = self.rrset_relations_from_offsets(
            span,
            span.rrsig_offset,
            span.next_relation_offset_after_rrsig(),
        );
        debug_assert!(
            relations
                .iter()
                .all(|relation| relation.kind == ImageRrsetRelationKind::Rrsig)
        );
        relations
    }

    fn initial_dnssec_seen_selected_records(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> SmallVec<[ZoneImageSelectedRecord; 4]> {
        if self.dnssec_rrsig_augmentation_possible && plan.dnssec_augmented() {
            self.plan_selected_record_identities(plan)
        } else {
            SmallVec::new()
        }
    }

    fn plan_selected_record_identities(
        &self,
        plan: &ZoneImageLookupPlan,
    ) -> SmallVec<[ZoneImageSelectedRecord; 4]> {
        let mut seen = SmallVec::new();
        self.record_plan_selected_identities(plan, &mut seen);
        seen
    }

    fn record_plan_selected_identities(
        &self,
        plan: &ZoneImageLookupPlan,
        seen: &mut SmallVec<[ZoneImageSelectedRecord; 4]>,
    ) {
        for item in &plan.answer_items {
            match item {
                PlanAnswer::SelectedRecord(selected) => {
                    insert_selected_record(seen, *selected);
                }
                PlanAnswer::Rrset(_)
                | PlanAnswer::RrsetWithOwner { .. }
                | PlanAnswer::DynamicRecord(_) => {}
            }
        }
        for selected in &plan.selected_authorities {
            insert_selected_record(seen, *selected);
        }
        for selected in &plan.selected_additionals {
            insert_selected_record(seen, *selected);
        }
    }

    fn single_name_rrset_target(
        &self,
        rrset_id: ZoneImageRrsetId,
    ) -> Option<&ImageSingleNameTarget> {
        let rrset = self.rrsets[rrset_id.0 as usize];
        let span = self.rrset_relation_span(rrset.relation_span)?;
        if span.single_name_target_offset == NO_RELATION_OFFSET {
            return None;
        }
        let relation = self
            .rrset_relations
            .get(span.first_relation as usize + usize::from(span.single_name_target_offset))?;
        debug_assert_eq!(relation.kind, ImageRrsetRelationKind::SingleNameTarget);
        self.single_name_targets.get(relation.record_index as usize)
    }

    fn single_name_target_wire(&self, target: &ImageSingleNameTarget) -> &[u8] {
        self.rdata_blob(target.rdata)
    }

    #[cfg(test)]
    fn closest_encloser_proof_name(&self, qname: &DomainName) -> Option<DomainName> {
        let closest_node = self.closest_encloser_node(qname)?;
        self.closest_encloser_proof_name_from_node(qname, Some(closest_node))
    }

    #[cfg(test)]
    fn closest_encloser_proof_name_from_node(
        &self,
        qname: &DomainName,
        closest_node: Option<u32>,
    ) -> Option<DomainName> {
        let closest_node = closest_node?;
        let relative_depth = usize::from(self.nodes[closest_node as usize].depth);
        let origin_labels = self.origin.label_count();
        let relative_labels = qname.label_count().checked_sub(origin_labels)?;
        if relative_depth > relative_labels {
            return None;
        }

        qname.suffix_from_label_index(relative_labels - relative_depth)
    }

    fn closest_encloser_labels_from_node<'a>(
        &self,
        qname: &'a DomainName,
        closest_node: Option<u32>,
    ) -> Option<&'a [Vec<u8>]> {
        let closest_node = closest_node?;
        let relative_depth = usize::from(self.nodes[closest_node as usize].depth);
        let origin_labels = self.origin.label_count();
        let relative_labels = qname.label_count().checked_sub(origin_labels)?;
        if relative_depth > relative_labels {
            return None;
        }

        Some(&qname.labels()[relative_labels - relative_depth..])
    }

    #[cfg(test)]
    fn closest_encloser_node(&self, qname: &DomainName) -> Option<u32> {
        let labels = relative_label_slice(qname, &self.origin)?;
        if labels.is_empty() {
            return None;
        }

        let mut node_index = 0u32;
        let mut closest = Some(node_index);
        for label in labels.iter().rev().take(labels.len() - 1) {
            let Some(child) = self.find_child(node_index, label) else {
                break;
            };
            node_index = child;
            closest = Some(node_index);
        }
        closest
    }

    fn find_child(&self, node_index: u32, label: &[u8]) -> Option<u32> {
        self.find_child_with_ascii_lowercase_hint(node_index, label, false)
    }

    fn find_child_with_ascii_lowercase_hint(
        &self,
        node_index: u32,
        label: &[u8],
        label_ascii_lowercase: bool,
    ) -> Option<u32> {
        let node = &self.nodes[node_index as usize];
        if node.edge_count == 0 {
            return None;
        }
        let edges = &self.edges
            [node.first_edge as usize..(node.first_edge + u32::from(node.edge_count)) as usize];
        if let [edge] = edges {
            return lowercase_stored_label_eq_with_ascii_lowercase_hint(
                self.blob(&self.labels, edge.label),
                label,
                label_ascii_lowercase,
            )
            .then_some(edge.child);
        }
        if node.edge_count <= SMALL_CHILD_LINEAR_SCAN_THRESHOLD {
            return self.find_child_by_linear_scan(edges, label, label_ascii_lowercase);
        }
        if let Some(child) = self.find_child_in_hash(*node, edges, label, label_ascii_lowercase) {
            return child;
        }
        let mut left = 0usize;
        let mut right = edges.len();
        while left < right {
            let mid = left + (right - left) / 2;
            let edge_label = self.blob(&self.labels, edges[mid].label);
            match cmp_lowercase_label_with_ascii_lowercase_hint(
                edge_label,
                label,
                label_ascii_lowercase,
            ) {
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid,
                Ordering::Equal => return Some(edges[mid].child),
            }
        }
        None
    }

    fn find_child_by_linear_scan(
        &self,
        edges: &[NameEdge],
        label: &[u8],
        label_ascii_lowercase: bool,
    ) -> Option<u32> {
        edges.iter().find_map(|edge| {
            lowercase_stored_label_eq_with_ascii_lowercase_hint(
                self.blob(&self.labels, edge.label),
                label,
                label_ascii_lowercase,
            )
            .then_some(edge.child)
        })
    }

    fn find_child_in_hash(
        &self,
        node: NameNode,
        edges: &[NameEdge],
        label: &[u8],
        label_ascii_lowercase: bool,
    ) -> Option<Option<u32>> {
        if node.child_hash == u32::MAX {
            return None;
        }
        let hash = *self.child_hashes.get(node.child_hash as usize)?;
        let first_slot = hash.first_slot as usize;
        let mask = hash.slot_mask as usize;
        let mut slot =
            child_label_hash_with_ascii_lowercase_hint(label, label_ascii_lowercase) & mask;
        for _ in 0..=mask {
            let edge_offset = self.child_hash_slots[first_slot + slot];
            if edge_offset == u16::MAX {
                return Some(None);
            }
            let edge = edges[edge_offset as usize];
            if lowercase_stored_label_eq_with_ascii_lowercase_hint(
                self.blob(&self.labels, edge.label),
                label,
                label_ascii_lowercase,
            ) {
                return Some(Some(edge.child));
            }
            slot = (slot + 1) & mask;
        }
        Some(None)
    }

    fn find_node(&self, qname: &DomainName) -> Option<u32> {
        self.find_node_with_ascii_lowercase_hint(qname, false)
    }

    fn find_node_with_ascii_lowercase_hint(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> Option<u32> {
        let labels = relative_label_slice(qname, &self.origin)?;
        let mut node_index = 0u32;
        for label in labels.iter().rev() {
            node_index = self.find_child_with_ascii_lowercase_hint(
                node_index,
                label,
                qname_ascii_lowercase,
            )?;
        }
        Some(node_index)
    }

    fn target_node_hint(&self, qname: &DomainName) -> ImageTargetNode {
        if !qname.is_equal_or_subdomain_of(&self.origin) {
            if domain_is_suffix_parent_of_origin(qname, &self.origin) {
                return ImageTargetNode::OutOfZoneParentSuffix;
            }
            return ImageTargetNode::OutOfZone;
        }
        self.find_node(qname)
            .map_or(ImageTargetNode::InZoneMissing, ImageTargetNode::InZoneNode)
    }

    fn dname_synthesized_target_node_hint(
        &self,
        target: &ImageSingleNameTarget,
        synthesized_target: &DomainName,
        original_qname: &DomainName,
        prefix_len: usize,
    ) -> ImageTargetNode {
        match target.node_hint {
            ImageTargetNode::InZoneNode(mut node) => {
                for label in original_qname.labels()[..prefix_len].iter().rev() {
                    let Some(child) = self.find_child(node, label) else {
                        return ImageTargetNode::InZoneMissing;
                    };
                    node = child;
                }
                ImageTargetNode::InZoneNode(node)
            }
            ImageTargetNode::InZoneMissing => ImageTargetNode::InZoneMissing,
            ImageTargetNode::OutOfZoneParentSuffix => self.target_node_hint(synthesized_target),
            ImageTargetNode::OutOfZone => ImageTargetNode::OutOfZone,
        }
    }

    fn query_node_handles(
        &self,
        qname: &DomainName,
        qname_ascii_lowercase: bool,
    ) -> (Option<u32>, Option<u32>) {
        let Some(labels) = relative_label_slice(qname, &self.origin) else {
            return (None, None);
        };

        let mut node_index = 0u32;
        let mut closest = Some(node_index);
        for label in labels.iter().rev() {
            let Some(child) =
                self.find_child_with_ascii_lowercase_hint(node_index, label, qname_ascii_lowercase)
            else {
                return (None, closest);
            };
            node_index = child;
            closest = Some(node_index);
        }
        (Some(node_index), Some(node_index))
    }

    fn blob<'a>(&self, arena: &'a [u8], range: BlobRange) -> &'a [u8] {
        let start = range.offset as usize;
        let end = start + range.len as usize;
        &arena[start..end]
    }

    fn rdata_blob(&self, range: RdataRange) -> &[u8] {
        self.blob(&self.rdata, range.blob_range())
    }
}

impl ZoneImageLookupPlan {
    fn positive() -> Self {
        Self {
            rcode: Rcode::NoError,
            answer_rrsets: SmallVec::new(),
            answer_items: SmallVec::new(),
            authority_rrsets: SmallVec::new(),
            additional_rrsets: SmallVec::new(),
            owner_overrides: SmallVec::new(),
            dynamic_answers: SmallVec::new(),
            selected_authorities: SmallVec::new(),
            selected_additionals: SmallVec::new(),
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
            answer_wire_upper_bound: 0,
            body_wire_upper_bound: 0,
            referral_ns_rrset: u32::MAX,
            authority_soa_index: NO_AUTHORITY_SOA_INDEX,
            flags: PLAN_FLAG_AUTHORITATIVE,
            termination: None,
        }
    }

    fn referral(ns_rrset: ZoneImageRrsetId, ns_metrics: ZoneImageRrsetPlanMetrics) -> Self {
        let mut plan = Self::positive();
        plan.clear_flag(PLAN_FLAG_AUTHORITATIVE);
        plan.referral_ns_rrset = ns_rrset.0;
        plan.push_authority_rrset(ns_rrset, ns_metrics);
        plan
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
        self.set_flag(PLAN_FLAG_AUTHORITATIVE, true);
        self.termination = Some(termination);
        self.referral_ns_rrset = u32::MAX;
        self.authority_rrsets.clear();
        self.authority_record_count = 0;
        self.body_wire_upper_bound = self.answer_wire_upper_bound;
        self.authority_soa_index = NO_AUTHORITY_SOA_INDEX;
        self.clear_flag(PLAN_FLAG_AUTHORITY_HAS_SOA);
        self.clear_flag(PLAN_FLAG_AUTHORITY_FIRST_RRSET_IS_SOA);
        self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
        self.additional_rrsets.clear();
        self.additional_record_count = 0;
        self.body_wire_upper_bound = self.answer_wire_upper_bound;
        self.selected_authorities.clear();
        self.selected_additionals.clear();
        self
    }

    pub fn answer_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.answer_rrsets
    }

    pub(crate) fn has_custom_answer_items(&self) -> bool {
        !self.answer_items.is_empty()
    }

    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    pub fn authoritative(&self) -> bool {
        self.has_flag(PLAN_FLAG_AUTHORITATIVE)
    }

    pub(crate) fn answer_has_records(&self) -> bool {
        self.has_flag(PLAN_FLAG_ANSWER_HAS_RECORDS)
    }

    pub(crate) fn authority_has_soa(&self) -> bool {
        self.has_flag(PLAN_FLAG_AUTHORITY_HAS_SOA)
    }

    pub(crate) fn authority_soa_index(&self) -> Option<usize> {
        if self.authority_has_soa() && self.authority_soa_index != NO_AUTHORITY_SOA_INDEX {
            Some(usize::from(self.authority_soa_index))
        } else {
            None
        }
    }

    pub(crate) fn authority_first_rrset_is_soa(&self) -> bool {
        self.has_flag(PLAN_FLAG_AUTHORITY_FIRST_RRSET_IS_SOA)
    }

    pub fn termination(&self) -> Option<LookupTermination> {
        self.termination
    }

    pub fn synthesized_answer_count(&self) -> usize {
        self.dynamic_answers.len()
    }

    pub fn dnssec_augmented(&self) -> bool {
        self.has_flag(PLAN_FLAG_DNSSEC_AUGMENTED)
    }

    pub fn nsec3_iterations_exceeded(&self) -> bool {
        self.has_flag(PLAN_FLAG_NSEC3_ITERATIONS_EXCEEDED)
    }

    pub(crate) fn direct_answer_candidate(&self) -> bool {
        self.has_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE)
    }

    pub(crate) fn response_shape(&self) -> Option<ZoneImagePlanResponseShape> {
        let answer_count = u16::try_from(self.answer_record_count).ok()?;
        let authority_count = u16::try_from(self.authority_record_count).ok()?;
        let additional_count = u16::try_from(self.additional_record_count).ok()?;
        Some(ZoneImagePlanResponseShape {
            response_flag_bits: self.rcode.response_flag_bits(self.authoritative()),
            answer_count,
            authority_count,
            additional_count,
            section_count_header_bytes: section_count_header_bytes(
                answer_count,
                authority_count,
                additional_count,
            ),
            body_wire_upper_bound: self.body_wire_upper_bound as usize,
        })
    }

    fn total_record_count(&self) -> usize {
        self.answer_record_count
            .saturating_add(self.authority_record_count)
            .saturating_add(self.additional_record_count) as usize
    }

    #[cfg(test)]
    pub(crate) fn section_record_counts(&self) -> (usize, usize, usize) {
        (
            self.answer_record_count as usize,
            self.authority_record_count as usize,
            self.additional_record_count as usize,
        )
    }

    #[cfg(test)]
    pub(crate) fn response_body_wire_upper_bound(&self) -> usize {
        self.body_wire_upper_bound as usize
    }

    #[cfg(test)]
    pub(crate) fn answer_wire_upper_bound(&self) -> usize {
        self.answer_wire_upper_bound as usize
    }

    fn push_answer_rrset(&mut self, rrset: ZoneImageRrsetId, metrics: ZoneImageRrsetPlanMetrics) {
        self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
        self.set_flag(PLAN_FLAG_ANSWER_HAS_RECORDS, true);
        add_plan_record_count(&mut self.answer_record_count, metrics.record_count);
        add_plan_wire_upper_bound(&mut self.answer_wire_upper_bound, metrics.wire_upper_bound);
        add_plan_wire_upper_bound(&mut self.body_wire_upper_bound, metrics.wire_upper_bound);
        self.answer_rrsets.push(rrset);
        if !self.answer_items.is_empty() {
            self.answer_items.push(PlanAnswer::Rrset(rrset));
        }
    }

    fn push_answer_rrset_with_owner_wire(
        &mut self,
        rrset: ZoneImageRrsetId,
        owner_wire: OwnerOverrideWire,
        metrics: ZoneImageRrsetPlanMetrics,
    ) {
        self.ensure_answer_items();
        self.set_flag(PLAN_FLAG_WILDCARD_SYNTHESIZED, true);
        let owner_index = self.owner_overrides.len();
        self.owner_overrides.push(owner_wire);
        self.push_answer_rrset_with_owner_index(rrset, owner_index, metrics);
    }

    fn push_answer_rrset_with_owner_index(
        &mut self,
        rrset: ZoneImageRrsetId,
        owner_index: usize,
        metrics: ZoneImageRrsetPlanMetrics,
    ) {
        self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
        self.set_flag(PLAN_FLAG_ANSWER_HAS_RECORDS, true);
        add_plan_record_count(&mut self.answer_record_count, metrics.record_count);
        add_plan_wire_upper_bound(&mut self.answer_wire_upper_bound, metrics.wire_upper_bound);
        add_plan_wire_upper_bound(&mut self.body_wire_upper_bound, metrics.wire_upper_bound);
        let owner_index =
            u16::try_from(owner_index).expect("owner override index is DNS-answer-count bounded");
        self.answer_items.push(PlanAnswer::RrsetWithOwner {
            rrset_id: rrset,
            owner_index,
        });
    }

    fn push_synthesized_answer(
        &mut self,
        owner: &DomainName,
        fixed_fields: ZoneImageRecordFixedFields,
        rdata_encoding: PackedRdataEncoding,
        rdata: InlineNameWire,
    ) -> u16 {
        self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
        self.ensure_answer_items();
        self.set_flag(PLAN_FLAG_ANSWER_HAS_RECORDS, true);
        add_plan_record_count(&mut self.answer_record_count, 1);
        let owner_wire = owner_override_wire(owner);
        let wire_upper_bound = owner_wire
            .len()
            .saturating_add(10)
            .saturating_add(rdata.len());
        add_plan_wire_upper_bound(&mut self.answer_wire_upper_bound, wire_upper_bound);
        add_plan_wire_upper_bound(&mut self.body_wire_upper_bound, wire_upper_bound);
        let index = self.dynamic_answers.len();
        let answer_index =
            u16::try_from(index).expect("dynamic answer index is DNS-answer-count bounded");
        let rdlength = u16::try_from(rdata.len())
            .expect("synthesized DNS RDATA must fit the DNS rdlength field");
        self.dynamic_answers.push(ZoneImageSynthesizedRecord {
            owner_wire,
            fixed_fields,
            rdlength_bytes: rdlength.to_be_bytes(),
            rdata_encoding,
            rdata,
        });
        self.answer_items
            .push(PlanAnswer::DynamicRecord(answer_index));
        answer_index
    }

    fn push_selected_record_section(
        &mut self,
        section: DnssecSection,
        record: ZoneImageSelectedRecord,
    ) {
        match section {
            DnssecSection::Answer => {
                self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
                self.ensure_answer_items();
                self.set_flag(PLAN_FLAG_ANSWER_HAS_RECORDS, true);
                add_plan_record_count(&mut self.answer_record_count, 1);
                add_plan_wire_upper_bound(
                    &mut self.answer_wire_upper_bound,
                    record.wire_len as usize,
                );
                add_plan_wire_upper_bound(
                    &mut self.body_wire_upper_bound,
                    record.wire_len as usize,
                );
                self.answer_items.push(PlanAnswer::SelectedRecord(record));
            }
            DnssecSection::Authority => {
                self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
                add_plan_record_count(&mut self.authority_record_count, 1);
                add_plan_wire_upper_bound(
                    &mut self.body_wire_upper_bound,
                    record.wire_len as usize,
                );
                self.selected_authorities.push(record);
            }
            DnssecSection::Additional => {
                self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
                add_plan_record_count(&mut self.additional_record_count, 1);
                add_plan_wire_upper_bound(
                    &mut self.body_wire_upper_bound,
                    record.wire_len as usize,
                );
                self.selected_additionals.push(record);
            }
        }
    }

    fn push_authority_rrset(
        &mut self,
        rrset: ZoneImageRrsetId,
        metrics: ZoneImageRrsetPlanMetrics,
    ) {
        self.clear_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE);
        add_plan_record_count(&mut self.authority_record_count, metrics.record_count);
        add_plan_wire_upper_bound(&mut self.body_wire_upper_bound, metrics.wire_upper_bound);
        if metrics.rr_type == RecordType::Soa as u16 {
            self.authority_soa_index =
                u16::try_from(self.authority_rrsets.len()).unwrap_or(NO_AUTHORITY_SOA_INDEX);
            self.set_flag(PLAN_FLAG_AUTHORITY_HAS_SOA, true);
            self.set_flag(
                PLAN_FLAG_AUTHORITY_FIRST_RRSET_IS_SOA,
                self.authority_rrsets.is_empty(),
            );
        }
        self.authority_rrsets.push(rrset);
    }

    fn push_additional_rrset(
        &mut self,
        rrset: ZoneImageRrsetId,
        metrics: ZoneImageRrsetPlanMetrics,
    ) {
        add_plan_record_count(&mut self.additional_record_count, metrics.record_count);
        add_plan_wire_upper_bound(&mut self.body_wire_upper_bound, metrics.wire_upper_bound);
        self.additional_rrsets.push(rrset);
    }

    fn referral_ns_rrset(&self) -> Option<ZoneImageRrsetId> {
        if !self.authoritative() {
            rrset_id_from_policy(self.referral_ns_rrset)
        } else {
            None
        }
    }

    fn ensure_answer_items(&mut self) {
        if self.answer_items.is_empty() {
            self.answer_items
                .extend(self.answer_rrsets.iter().copied().map(PlanAnswer::Rrset));
        }
    }

    fn mark_direct_answer_candidate(&mut self) {
        debug_assert_eq!(self.rcode, Rcode::NoError);
        debug_assert!(self.authoritative());
        debug_assert_eq!(self.answer_rrsets.len(), 1);
        debug_assert!(self.answer_items.is_empty());
        debug_assert!(self.authority_rrsets.is_empty());
        debug_assert!(self.additional_rrsets.is_empty());
        debug_assert!(self.selected_authorities.is_empty());
        debug_assert!(self.selected_additionals.is_empty());
        debug_assert!(self.dynamic_answers.is_empty());
        self.set_flag(PLAN_FLAG_DIRECT_ANSWER_CANDIDATE, true);
    }

    fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    fn set_flag(&mut self, flag: u8, enabled: bool) {
        if enabled {
            self.flags |= flag;
        } else {
            self.clear_flag(flag);
        }
    }

    fn clear_flag(&mut self, flag: u8) {
        self.flags &= !flag;
    }

    pub fn authority_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.authority_rrsets
    }

    pub fn additional_rrsets(&self) -> &[ZoneImageRrsetId] {
        &self.additional_rrsets
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZoneImagePlanResponseShape {
    pub(crate) response_flag_bits: u16,
    pub(crate) answer_count: u16,
    pub(crate) authority_count: u16,
    pub(crate) additional_count: u16,
    pub(crate) section_count_header_bytes: [u8; 6],
    pub(crate) body_wire_upper_bound: usize,
}

impl ZoneImagePlanResponseShape {
    pub(crate) fn section_count_header_bytes_with_extra_additional(
        self,
        extra_additional_count: u16,
    ) -> Option<[u8; 6]> {
        if extra_additional_count == 0 {
            return Some(self.section_count_header_bytes);
        }

        self.additional_count
            .checked_add(extra_additional_count)
            .map(|additional_count| {
                section_count_header_bytes(
                    self.answer_count,
                    self.authority_count,
                    additional_count,
                )
            })
    }
}

fn section_count_header_bytes(
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
) -> [u8; 6] {
    let answer_count = answer_count.to_be_bytes();
    let authority_count = authority_count.to_be_bytes();
    let additional_count = additional_count.to_be_bytes();
    [
        answer_count[0],
        answer_count[1],
        authority_count[0],
        authority_count[1],
        additional_count[0],
        additional_count[1],
    ]
}

fn add_plan_record_count(count: &mut u32, record_count: usize) {
    *count = count.saturating_add(u32::try_from(record_count).unwrap_or(u32::MAX));
}

fn add_plan_wire_upper_bound(bytes: &mut u32, wire_upper_bound: usize) {
    *bytes = bytes.saturating_add(u32::try_from(wire_upper_bound).unwrap_or(u32::MAX));
}

fn plan_is_nodata_candidate(plan: &ZoneImageLookupPlan, answer_has_records: bool) -> bool {
    plan.rcode == Rcode::NoError && plan.authoritative() && !answer_has_records
}

fn plan_is_nxdomain_candidate(plan: &ZoneImageLookupPlan, answer_has_records: bool) -> bool {
    plan.rcode == Rcode::NxDomain && plan.authoritative() && !answer_has_records
}

fn plan_is_wildcard_synthesis_candidate(
    plan: &ZoneImageLookupPlan,
    answer_has_records: bool,
) -> bool {
    plan.rcode == Rcode::NoError
        && plan.authoritative()
        && answer_has_records
        && plan.has_flag(PLAN_FLAG_WILDCARD_SYNTHESIZED)
}

struct ZoneImageBuilder {
    origin: DomainName,
    build_nodes: Vec<BuildNode>,
    image_rrsets: Vec<ImageRrset>,
    additional_address_rrset_flags: Vec<u64>,
    rrsig_rrset_flags: Vec<u64>,
    image_records: Vec<ImageRecord>,
    rrset_index: HashMap<(String, u16, u16), ZoneImageRrsetId>,
    rrsig_covered: Vec<ImageRrsigCovered>,
    nsec_rrsets: Vec<ZoneImageRrsetId>,
    nsec3_rrsets: Vec<ZoneImageRrsetId>,
    rrset_relations: Vec<ImageRrsetRelation>,
    rrset_relation_spans: Vec<ImageRrsetRelationSpan>,
    single_name_targets: Vec<ImageSingleNameTarget>,
    nsec_ranges: Vec<ImageNsecRange>,
    nsec3_param_sets: Vec<ImageNsec3ParamSet>,
    nsec3_ranges: Vec<ImageNsec3Range>,
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
            additional_address_rrset_flags: Vec::new(),
            rrsig_rrset_flags: Vec::new(),
            image_records: Vec::new(),
            rrset_index: HashMap::new(),
            rrsig_covered: Vec::new(),
            nsec_rrsets: Vec::new(),
            nsec3_rrsets: Vec::new(),
            rrset_relations: Vec::new(),
            rrset_relation_spans: Vec::new(),
            single_name_targets: Vec::new(),
            nsec_ranges: Vec::new(),
            nsec3_param_sets: Vec::new(),
            nsec3_ranges: Vec::new(),
            labels: Vec::new(),
            names: Vec::new(),
            rdata: Vec::new(),
            wire: Vec::new(),
        }
    }

    fn push_rrset(
        &mut self,
        owner_key: String,
        owner: &DomainName,
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdatas: &[&[u8]],
    ) -> Result<ZoneImageRrsetId, ZoneImageBuildError> {
        debug_assert!(
            !rdatas.is_empty(),
            "ZoneImage rrsets are built from grouped snapshot records"
        );
        let rrset_index = checked_u32(self.image_rrsets.len(), "rrsets").map(ZoneImageRrsetId)?;
        let owner_wire = owner.to_wire();
        let owner_wire_ref = push_blob(&mut self.names, &owner_wire, "names")?;
        let first_record = checked_u32(self.image_records.len(), "records")?;
        let wire_start = checked_u32(self.wire.len(), "wire")?;
        let fixed_fields = zone_image_record_fixed_fields(rr_type, class, ttl);

        for rdata in rdatas {
            let rdlength =
                u16::try_from(rdata.len()).map_err(|_| ZoneImageBuildError::RdataTooLarge)?;
            let rdata_ref = push_blob(&mut self.rdata, rdata, "rdata")?;
            let rdata_ref = RdataRange {
                offset: rdata_ref.offset,
                len: rdlength,
                rdata_encoding: zone_image_rdata_encoding(rr_type, rdata),
            };
            self.image_records.push(ImageRecord { rdata: rdata_ref });
            self.wire.extend_from_slice(&owner_wire);
            self.wire.extend_from_slice(&fixed_fields);
            self.wire.extend_from_slice(&rdata_ref.rdlength_bytes());
            self.wire.extend_from_slice(rdata);
        }

        let wire_end = checked_u32(self.wire.len(), "wire")?;
        let direct_copy_eligible = direct_copy_rdata_type(rr_type);
        let direct_answer_body_len =
            push_direct_answer_body(&mut self.wire, direct_copy_eligible, fixed_fields, rdatas)?;
        let negative_ttl = if rr_type == RecordType::Soa as u16 {
            rdatas
                .first()
                .and_then(|rdata| soa_minimum(rdata))
                .map_or(ttl, |minimum| ttl.min(minimum))
        } else {
            ttl
        };
        let record_count = checked_u16(rdatas.len(), "records")?;
        let ownerless_wire_len = ownerless_wire_len(
            direct_answer_body_len,
            usize::try_from(wire_end - wire_start).map_err(|_| {
                ZoneImageBuildError::TooManyItems {
                    kind: "ownerless rrset wire bytes",
                }
            })?,
            owner_wire.len(),
            usize::from(record_count),
        )?;
        self.image_rrsets.push(ImageRrset {
            owner_wire: owner_wire_ref,
            fixed_fields,
            negative_ttl_bytes: negative_ttl.to_be_bytes(),
            first_record,
            record_count,
            owner_label_count: checked_u16(owner.labels().len(), "owner labels")?,
            relation_span: u32::MAX,
            direct_answer_body_len,
            ownerless_wire_len,
            wire: BlobRange {
                offset: wire_start,
                len: wire_end - wire_start,
            },
        });
        self.rrset_index
            .insert((owner_key, rr_type, class), rrset_index);
        if rr_type == RecordType::Nsec as u16 {
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
        let labels = relative_label_slice(owner, &self.origin).ok_or_else(|| {
            ZoneImageBuildError::OutOfZoneOwner {
                owner: owner.canonical_key(),
                origin: self.origin.canonical_key(),
            }
        })?;
        let mut node_index = 0u32;
        for label in labels.iter().rev() {
            let label_key = lowercase_label_key(label);
            let existing = self.build_nodes[node_index as usize]
                .children
                .get(label_key.as_slice())
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
                        .insert(label_key.to_vec(), child);
                    child
                }
            };
        }
        self.build_nodes[node_index as usize].rrsets.push(rrset_id);
        Ok(())
    }

    fn finish(mut self, serial: Option<u32>) -> Result<ZoneImage, ZoneImageBuildError> {
        self.precompute_single_name_targets();
        self.precompute_nsec_ranges()?;
        self.precompute_nsec3_ranges()?;
        self.precompute_rrset_relation_spans()?;

        let mut nodes: Vec<NameNode> = Vec::with_capacity(self.build_nodes.len());
        let mut edges = Vec::new();
        let mut labels = self.labels;

        for (node_index, build_node) in self.build_nodes.iter().enumerate() {
            let inherited_delegation = if node_index == 0 {
                u32::MAX
            } else {
                nodes[build_node.parent as usize].nearest_in_delegation
            };
            let inherited_dname = if node_index == 0 {
                u32::MAX
            } else {
                nodes[build_node.parent as usize].nearest_in_dname
            };
            let nearest_in_delegation =
                find_build_node_in_rrset(&self.image_rrsets, build_node, RecordType::Ns as u16)
                    .filter(|_| node_index != 0)
                    .map(|rrset| rrset.0)
                    .unwrap_or(inherited_delegation);
            let nearest_in_dname =
                find_build_node_in_rrset(&self.image_rrsets, build_node, RecordType::Dname as u16)
                    .map(|rrset| rrset.0)
                    .unwrap_or(inherited_dname);
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
                low_rrtype_bitmap: NO_NODE_LOW_RRTYPE_BITMAP,
                first_rrset,
                rrset_count: checked_u16(build_node.rrsets.len(), "rrsets")?,
                parent: build_node.parent,
                depth: build_node.depth,
                nearest_in_delegation,
                nearest_in_dname,
                child_hash: u32::MAX,
            });
        }
        let (child_hashes, child_hash_slots) = build_child_hashes(&mut nodes, &edges, &labels)?;
        let node_low_rrtype_bitmaps =
            build_node_low_rrtype_bitmaps(&self.image_rrsets, &self.build_nodes, &mut nodes)?;

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
            + child_hashes.len() * mem::size_of::<ImageChildHash>()
            + child_hash_slots.len() * mem::size_of::<u16>()
            + node_low_rrtype_bitmaps.len() * mem::size_of::<u64>()
            + self.image_rrsets.len() * mem::size_of::<ImageRrset>()
            + mem::size_of::<[u64; LOW_RRTYPE_BITMAP_WORDS]>()
            + self.additional_address_rrset_flags.len() * mem::size_of::<u64>()
            + self.rrsig_rrset_flags.len() * mem::size_of::<u64>()
            + self.image_records.len() * mem::size_of::<ImageRecord>()
            + self.rrset_relations.len() * mem::size_of::<ImageRrsetRelation>()
            + self.rrset_relation_spans.len() * mem::size_of::<ImageRrsetRelationSpan>()
            + self.single_name_targets.len() * mem::size_of::<ImageSingleNameTarget>()
            + self.nsec_ranges.len() * mem::size_of::<ImageNsecRange>()
            + self.nsec3_param_sets.len() * mem::size_of::<ImageNsec3ParamSet>()
            + self.nsec3_ranges.len() * mem::size_of::<ImageNsec3Range>();
        let single_name_target_cold_bytes = self
            .single_name_targets
            .iter()
            .map(|target| domain_name_heap_bytes(&target.name))
            .sum::<usize>();
        let cold_bytes = labels.len()
            + self.names.len()
            + self.rdata.len()
            + self.wire.len()
            + single_name_target_cold_bytes;
        let origin_key = self.origin.canonical_key();
        let apex_in_soa_rrset = self
            .rrset_index
            .get(&(origin_key, RecordType::Soa as u16, 1))
            .copied();
        let low_rrtype_bitmap = build_low_rrtype_bitmap(&self.image_rrsets);
        let dnssec_denial_augmentation_possible =
            !self.nsec_ranges.is_empty() || !self.nsec3_ranges.is_empty();
        let mut dnssec_referral_relation_possible = false;
        let mut dnssec_rrsig_augmentation_possible = false;
        for relation in &self.rrset_relations {
            match relation.kind {
                ImageRrsetRelationKind::DelegationDs | ImageRrsetRelationKind::DelegationNsec => {
                    dnssec_referral_relation_possible = true;
                }
                ImageRrsetRelationKind::Rrsig => {
                    dnssec_rrsig_augmentation_possible = true;
                }
                ImageRrsetRelationKind::AdditionalAddress
                | ImageRrsetRelationKind::ReferralGlue
                | ImageRrsetRelationKind::SingleNameTarget => {}
            }
        }
        let dnssec_referral_augmentation_possible =
            dnssec_referral_relation_possible || !self.nsec3_ranges.is_empty();
        let dnssec_augmentation_possible = dnssec_denial_augmentation_possible
            || dnssec_referral_augmentation_possible
            || dnssec_rrsig_augmentation_possible;
        let any_class_delegation_policy_is_in_only = self
            .build_nodes
            .iter()
            .enumerate()
            .filter(|(node_index, _)| *node_index != 0)
            .all(|(_, node)| {
                !build_node_has_non_in_rrset(&self.image_rrsets, node, RecordType::Ns)
            });
        let any_class_dname_policy_is_in_only = self
            .build_nodes
            .iter()
            .all(|node| !build_node_has_non_in_rrset(&self.image_rrsets, node, RecordType::Dname));
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
            child_hash_count: child_hashes.len(),
            child_hash_slot_count: child_hash_slots.len(),
            child_hash_slot_bytes: child_hash_slots.len() * mem::size_of::<u16>(),
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
            child_hashes: child_hashes.into_boxed_slice(),
            child_hash_slots: child_hash_slots.into_boxed_slice(),
            node_low_rrtype_bitmaps: node_low_rrtype_bitmaps.into_boxed_slice(),
            rrsets: self.image_rrsets.into_boxed_slice(),
            low_rrtype_bitmap,
            additional_address_rrset_flags: self.additional_address_rrset_flags.into_boxed_slice(),
            rrsig_rrset_flags: self.rrsig_rrset_flags.into_boxed_slice(),
            records: self.image_records.into_boxed_slice(),
            rrset_relations: self.rrset_relations.into_boxed_slice(),
            rrset_relation_spans: self.rrset_relation_spans.into_boxed_slice(),
            single_name_targets: self.single_name_targets.into_boxed_slice(),
            nsec_ranges: self.nsec_ranges.into_boxed_slice(),
            nsec3_param_sets: self.nsec3_param_sets.into_boxed_slice(),
            nsec3_ranges: self.nsec3_ranges.into_boxed_slice(),
            apex_in_soa_rrset,
            dnssec_augmentation_possible,
            dnssec_denial_augmentation_possible,
            dnssec_referral_augmentation_possible,
            dnssec_rrsig_augmentation_possible,
            any_class_delegation_policy_is_in_only,
            any_class_dname_policy_is_in_only,
            labels: labels.into_boxed_slice(),
            names: self.names.into_boxed_slice(),
            rdata: self.rdata.into_boxed_slice(),
            wire: self.wire.into_boxed_slice(),
            stats,
        })
    }

    fn precompute_single_name_targets(&mut self) {
        for (rrset_index, rrset) in self.image_rrsets.iter().copied().enumerate() {
            if (rrset.rr_type() != RecordType::Cname as u16
                && rrset.rr_type() != RecordType::Dname as u16)
                || rrset.record_count == 0
            {
                continue;
            }

            let record = self.image_records[rrset.first_record as usize];
            let rdata = rdata_from_arena(&self.rdata, record.rdata);
            let Some(name) = single_name_rdata_bytes(rdata) else {
                continue;
            };
            let node_hint = self.build_target_node_hint(&name);
            self.single_name_targets.push(ImageSingleNameTarget {
                rrset_id: ZoneImageRrsetId(rrset_index as u32),
                name,
                rdata: record.rdata,
                node_hint,
            });
        }
    }

    fn build_target_node_hint(&self, name: &DomainName) -> ImageTargetNode {
        let Some(labels) = relative_label_slice(name, &self.origin) else {
            if domain_is_suffix_parent_of_origin(name, &self.origin) {
                return ImageTargetNode::OutOfZoneParentSuffix;
            }
            return ImageTargetNode::OutOfZone;
        };
        let mut node_index = 0u32;
        for label in labels.iter().rev() {
            let label_key = lowercase_label_key(label);
            let Some(child) = self.build_nodes[node_index as usize]
                .children
                .get(label_key.as_slice())
                .copied()
            else {
                return ImageTargetNode::InZoneMissing;
            };
            node_index = child;
        }
        ImageTargetNode::InZoneNode(node_index)
    }

    fn precompute_nsec_ranges(&mut self) -> Result<(), ZoneImageBuildError> {
        for rrset_id in &self.nsec_rrsets {
            let rrset = self.image_rrsets[rrset_id.0 as usize];
            let Some(owner_key) =
                push_canonical_order_name_arena_key(&mut self.names, rrset.owner_wire, "names")?
            else {
                continue;
            };
            for offset in 0..rrset.record_count {
                let record = self.image_records[(rrset.first_record + u32::from(offset)) as usize];
                let rdata = rdata_from_arena(&self.rdata, record.rdata);
                let Some(next_key) =
                    push_canonical_order_wire_key(&mut self.names, rdata, false, "names")?
                else {
                    continue;
                };
                let owner_before_next = cmp_canonical_order_key_wires(
                    blob_from_arena(&self.names, owner_key),
                    blob_from_arena(&self.names, next_key),
                ) == Ordering::Less;
                self.nsec_ranges.push(ImageNsecRange {
                    rrset_id: *rrset_id,
                    class: rrset.class(),
                    owner_key,
                    next_key,
                    owner_before_next,
                });
            }
        }
        Ok(())
    }

    fn precompute_nsec3_ranges(&mut self) -> Result<(), ZoneImageBuildError> {
        for index in 0..self.nsec3_rrsets.len() {
            let rrset_id = self.nsec3_rrsets[index];
            let rrset = self.image_rrsets[rrset_id.0 as usize];
            if rrset.record_count == 0 {
                continue;
            }

            let record = self.image_records[rrset.first_record as usize];
            let rdata = rdata_from_arena(&self.rdata, record.rdata);
            let Some(params) = nsec3_params_from_rdata(rdata) else {
                continue;
            };
            let hash_algorithm = params.hash_algorithm;
            let iterations = params.iterations;
            let salt = BlobRange {
                offset: record
                    .rdata
                    .offset
                    .checked_add(5)
                    .ok_or(ZoneImageBuildError::ArenaTooLarge { name: "rdata" })?,
                len: checked_u32(params.salt.len(), "rdata")?,
            };
            let Some(next_hash) = nsec3_next_hash_bytes(rdata) else {
                continue;
            };
            let Some(owner_hash) = nsec3_owner_wire_hash_bytes(
                blob_from_arena(&self.names, rrset.owner_wire),
                &self.origin,
            ) else {
                continue;
            };
            let param_set = self.intern_nsec3_param_set(hash_algorithm, iterations, salt)?;

            self.nsec3_ranges.push(ImageNsec3Range {
                rrset_id,
                class: rrset.class(),
                param_set,
                owner_hash,
                next_hash,
            });
        }
        Ok(())
    }

    fn intern_nsec3_param_set(
        &mut self,
        hash_algorithm: u8,
        iterations: u16,
        salt: BlobRange,
    ) -> Result<u16, ZoneImageBuildError> {
        let salt_bytes = blob_from_arena(&self.rdata, salt);
        for (index, param_set) in self.nsec3_param_sets.iter().enumerate() {
            if param_set.hash_algorithm == hash_algorithm
                && param_set.iterations == iterations
                && blob_from_arena(&self.rdata, param_set.salt) == salt_bytes
            {
                return checked_u16(index, "NSEC3 parameter sets");
            }
        }
        let index = checked_u16(self.nsec3_param_sets.len(), "NSEC3 parameter sets")?;
        self.nsec3_param_sets.push(ImageNsec3ParamSet {
            hash_algorithm,
            iterations,
            salt,
        });
        Ok(index)
    }

    fn precompute_rrset_relation_spans(&mut self) -> Result<(), ZoneImageBuildError> {
        for rrset_index in 0..self.image_rrsets.len() {
            let mut relations = SmallVec::<[ImageRrsetRelation; 8]>::new();
            self.push_single_name_target_relation_for_rrset(rrset_index, &mut relations);
            self.push_rrsig_relations_for_rrset(rrset_index, &mut relations)?;
            self.push_referral_glue_relations_for_rrset(rrset_index, &mut relations);
            self.push_referral_dnssec_relations_for_rrset(rrset_index, &mut relations);
            self.push_additional_relations_for_rrset(rrset_index, &mut relations);

            if relations.is_empty() {
                continue;
            }

            let first_relation = checked_u32(self.rrset_relations.len(), "rrset relations")?;
            self.rrset_relations.extend(relations.iter().copied());
            let relation_count = checked_u16(relations.len(), "rrset relations")?;
            let span = ImageRrsetRelationSpan::new(first_relation, relation_count, &relations)?;
            let span_index = checked_u32(self.rrset_relation_spans.len(), "rrset relation spans")?;
            set_rrset_flag(
                &mut self.rrsig_rrset_flags,
                rrset_index,
                span.rrsig_offset != NO_RELATION_OFFSET,
            );
            set_rrset_flag(
                &mut self.additional_address_rrset_flags,
                rrset_index,
                span.additional_address_offset != NO_RELATION_OFFSET,
            );
            self.rrset_relation_spans.push(span);
            self.image_rrsets[rrset_index].relation_span = span_index;
        }
        Ok(())
    }

    fn push_single_name_target_relation_for_rrset(
        &self,
        rrset_index: usize,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) {
        let target_index = self
            .single_name_targets
            .binary_search_by_key(&(rrset_index as u32), |target| target.rrset_id.0)
            .ok();
        let Some(target_index) = target_index else {
            return;
        };
        relations.push(ImageRrsetRelation {
            kind: ImageRrsetRelationKind::SingleNameTarget,
            rrset_id: ZoneImageRrsetId(rrset_index as u32),
            record_index: target_index as u32,
            rdata_len: 0,
            owner_wire_len: 0,
        });
    }

    fn push_rrsig_relations_for_rrset(
        &self,
        covered_index: usize,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) -> Result<(), ZoneImageBuildError> {
        let covered_rrset = self.image_rrsets[covered_index];
        let covered_type = covered_rrset.rr_type();
        if covered_type == RecordType::Rrsig as u16 {
            return Ok(());
        }

        let covered_owner = blob_from_arena(&self.names, covered_rrset.owner_wire);
        for index in &self.rrsig_covered {
            if index.covered_type != covered_type {
                continue;
            }

            let rrsig_rrset = self.image_rrsets[index.rrset_id.0 as usize];
            if rrsig_rrset.class() != covered_rrset.class()
                || blob_from_arena(&self.names, rrsig_rrset.owner_wire) != covered_owner
            {
                continue;
            }

            for offset in 0..rrsig_rrset.record_count {
                let record_index = rrsig_rrset.first_record + u32::from(offset);
                let record = self.image_records[record_index as usize];
                let rdata = rdata_from_arena(&self.rdata, record.rdata);
                if rrsig_type_covered_rdata(rdata) != Some(covered_type) {
                    continue;
                }
                relations.push(ImageRrsetRelation {
                    kind: ImageRrsetRelationKind::Rrsig,
                    rrset_id: index.rrset_id,
                    record_index,
                    rdata_len: record.rdata.len,
                    owner_wire_len: checked_u8(
                        blob_len(rrsig_rrset.owner_wire),
                        "selected RRSIG owner wire length",
                    )?,
                });
            }
        }
        Ok(())
    }

    fn push_additional_relations_for_rrset(
        &self,
        rrset_index: usize,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) {
        let rrset = self.image_rrsets[rrset_index];
        let rr_type = rrset.rr_type();
        if !rr_type_may_have_additional_address_target(rr_type) {
            return;
        }

        let mut resolved = SmallVec::<[ZoneImageRrsetId; 4]>::new();
        for offset in 0..rrset.record_count {
            let record = self.image_records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = rdata_from_arena(&self.rdata, record.rdata);
            let Some(target_wire) = additional_address_target_wire_rdata(rr_type, rdata) else {
                continue;
            };
            if !wire_name_is_equal_or_subdomain_of_domain(target_wire, &self.origin) {
                continue;
            }

            self.push_address_relations_for_target_wire(
                target_wire,
                rrset.class(),
                ImageRrsetRelationKind::AdditionalAddress,
                &mut resolved,
                relations,
            );
        }
    }

    fn push_referral_glue_relations_for_rrset(
        &self,
        rrset_index: usize,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) {
        let rrset = self.image_rrsets[rrset_index];
        if rrset.rr_type() != RecordType::Ns as u16 {
            return;
        }

        let owner_wire = blob_from_arena(&self.names, rrset.owner_wire);
        let owner_label_count = usize::from(rrset.owner_label_count);
        if wire_name_equals_domain_with_label_count_ignore_ascii_case(
            owner_wire,
            owner_label_count,
            &self.origin,
        ) {
            return;
        }
        let mut resolved = SmallVec::<[ZoneImageRrsetId; 4]>::new();
        for offset in 0..rrset.record_count {
            let record = self.image_records[(rrset.first_record + u32::from(offset)) as usize];
            let rdata = rdata_from_arena(&self.rdata, record.rdata);
            let Some(target_wire) = single_name_rdata_wire(rdata) else {
                continue;
            };
            if !wire_name_is_equal_or_subdomain_of_wire(target_wire, owner_wire, owner_label_count)
            {
                continue;
            }

            self.push_address_relations_for_target_wire(
                target_wire,
                rrset.class(),
                ImageRrsetRelationKind::ReferralGlue,
                &mut resolved,
                relations,
            );
        }
    }

    fn push_referral_dnssec_relations_for_rrset(
        &self,
        rrset_index: usize,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) {
        let rrset = self.image_rrsets[rrset_index];
        if rrset.rr_type() != RecordType::Ns as u16 {
            return;
        }

        let owner_wire = blob_from_arena(&self.names, rrset.owner_wire);
        if wire_name_equals_domain_with_label_count_ignore_ascii_case(
            owner_wire,
            usize::from(rrset.owner_label_count),
            &self.origin,
        ) {
            return;
        }
        let Some(owner_key) = canonical_key_from_uncompressed_wire(owner_wire) else {
            return;
        };
        if let Some(ds) =
            self.find_rrset_by_owner_key(owner_key.as_str(), RecordType::Ds as u16, rrset.class())
        {
            relations.push(ImageRrsetRelation {
                kind: ImageRrsetRelationKind::DelegationDs,
                rrset_id: ds,
                record_index: u32::MAX,
                rdata_len: 0,
                owner_wire_len: 0,
            });
        } else if let Some(nsec) =
            self.find_rrset_by_owner_key(owner_key.as_str(), RecordType::Nsec as u16, rrset.class())
        {
            relations.push(ImageRrsetRelation {
                kind: ImageRrsetRelationKind::DelegationNsec,
                rrset_id: nsec,
                record_index: u32::MAX,
                rdata_len: 0,
                owner_wire_len: 0,
            });
        }
    }

    fn find_rrset_by_owner_key(
        &self,
        owner_key: &str,
        rr_type: u16,
        class: u16,
    ) -> Option<ZoneImageRrsetId> {
        self.rrset_index
            .get(&(owner_key.to_owned(), rr_type, class))
            .copied()
    }

    fn push_address_relations_for_target_wire(
        &self,
        target_wire: &[u8],
        class: u16,
        kind: ImageRrsetRelationKind,
        resolved: &mut SmallVec<[ZoneImageRrsetId; 4]>,
        relations: &mut SmallVec<[ImageRrsetRelation; 8]>,
    ) {
        let Some(target_key) = canonical_key_from_uncompressed_wire(target_wire) else {
            return;
        };
        for address_type in [RecordType::A as u16, RecordType::Aaaa as u16] {
            if let Some(rrset_id) =
                self.find_rrset_by_owner_key(target_key.as_str(), address_type, class)
                && !resolved.contains(&rrset_id)
            {
                resolved.push(rrset_id);
                relations.push(ImageRrsetRelation {
                    kind,
                    rrset_id,
                    record_index: u32::MAX,
                    rdata_len: 0,
                    owner_wire_len: 0,
                });
            }
        }
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

fn lowercase_label_key(label: &[u8]) -> LowercaseLabelKey {
    let mut key = LowercaseLabelKey::with_capacity(label.len());
    for byte in label {
        key.push(byte.to_ascii_lowercase());
    }
    key
}

fn cmp_lowercase_label(stored_lowercase: &[u8], query_label: &[u8]) -> Ordering {
    cmp_lowercase_label_with_ascii_lowercase_hint(stored_lowercase, query_label, false)
}

fn cmp_lowercase_label_with_ascii_lowercase_hint(
    stored_lowercase: &[u8],
    query_label: &[u8],
    query_label_ascii_lowercase: bool,
) -> Ordering {
    if query_label_ascii_lowercase {
        return stored_lowercase.cmp(query_label);
    }

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

fn lowercase_stored_label_eq_with_ascii_lowercase_hint(
    stored_lowercase: &[u8],
    query_label: &[u8],
    query_label_ascii_lowercase: bool,
) -> bool {
    if stored_lowercase == query_label {
        return true;
    }
    if query_label_ascii_lowercase {
        return false;
    }

    stored_lowercase.len() == query_label.len()
        && stored_lowercase
            .iter()
            .zip(query_label)
            .all(|(left, right)| *left == right.to_ascii_lowercase())
}

fn append_stored_record_fields_wire(
    owner_wire: &[u8],
    fixed_fields: ZoneImageRecordFixedFields,
    rdata_range: RdataRange,
    rdata: &[u8],
    out: &mut Vec<u8>,
) {
    debug_assert_eq!(rdata.len(), rdata_range.len());
    out.extend_from_slice(owner_wire);
    out.extend_from_slice(&fixed_fields);
    out.extend_from_slice(&rdata_range.rdlength_bytes());
    out.extend_from_slice(rdata);
}

fn zone_image_rdata_encoding(rr_type: u16, rdata: &[u8]) -> PackedRdataEncoding {
    match rr_type {
        rr_type
            if rr_type == RecordType::Ns as u16
                || rr_type == RecordType::Cname as u16
                || rr_type == RecordType::Ptr as u16 =>
        {
            if wire_name_len_at(rdata, 0) == Some(rdata.len()) {
                PackedRdataEncoding::single_name()
            } else {
                PackedRdataEncoding::copy()
            }
        }
        rr_type if rr_type == RecordType::Soa as u16 => {
            let Some(mname_len) = wire_name_len_at(rdata, 0) else {
                return PackedRdataEncoding::copy();
            };
            let Some(rname_len) = wire_name_len_at(rdata, mname_len) else {
                return PackedRdataEncoding::copy();
            };
            let timers_offset = mname_len + rname_len;
            if timers_offset + 20 == rdata.len()
                && let (Ok(mname_len), Ok(rname_len)) =
                    (u8::try_from(mname_len), u8::try_from(rname_len))
            {
                PackedRdataEncoding::soa(mname_len, rname_len)
            } else {
                PackedRdataEncoding::copy()
            }
        }
        rr_type if rr_type == RecordType::Mx as u16 => {
            if rdata.len() >= 3 && wire_name_len_at(rdata, 2) == Some(rdata.len() - 2) {
                PackedRdataEncoding::mx()
            } else {
                PackedRdataEncoding::copy()
            }
        }
        _ => PackedRdataEncoding::copy(),
    }
}

fn synthesized_wire_record(record: &ZoneImageSynthesizedRecord) -> ZoneImageWireRecord<'_> {
    ZoneImageWireRecord {
        owner_wire: &record.owner_wire,
        fixed_fields: record.fixed_fields,
        rdlength_bytes: record.rdlength_bytes,
        rdata_encoding: record.rdata_encoding,
        rdata: &record.rdata,
    }
}

fn append_synthesized_record_wire(record: &ZoneImageSynthesizedRecord, out: &mut Vec<u8>) {
    out.extend_from_slice(&record.owner_wire);
    out.extend_from_slice(&record.fixed_fields);
    out.extend_from_slice(&record.rdlength_bytes);
    out.extend_from_slice(&record.rdata);
}

#[cfg(test)]
fn synthesized_record_wire_len(record: &ZoneImageSynthesizedRecord) -> usize {
    record
        .owner_wire
        .len()
        .saturating_add(10)
        .saturating_add(record.rdata.len())
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

fn push_canonical_order_name_arena_key(
    arena: &mut Vec<u8>,
    range: BlobRange,
    arena_name: &'static str,
) -> Result<Option<BlobRange>, ZoneImageBuildError> {
    let source_start = range.offset as usize;
    let source_end = source_start.saturating_add(range.len as usize);
    let Some(source) = arena.get(source_start..source_end) else {
        return Ok(None);
    };
    let Some((labels, consumed)) = canonical_wire_label_ranges(source) else {
        return Ok(None);
    };
    if consumed != source.len() {
        return Ok(None);
    }

    let offset = u32::try_from(arena.len())
        .map_err(|_| ZoneImageBuildError::ArenaTooLarge { name: arena_name })?;
    for (start, len) in labels.iter().rev() {
        let start = source_start + *start;
        let end = start + *len;
        if arena.get(start..end).is_none() {
            return Ok(None);
        }
        arena.push(*len as u8);
        for index in start..end {
            arena.push(arena[index].to_ascii_lowercase());
        }
    }
    arena.push(0);
    if arena.len() > u32::MAX as usize {
        return Err(ZoneImageBuildError::ArenaTooLarge { name: arena_name });
    }
    let len = u32::try_from(arena.len() - offset as usize)
        .map_err(|_| ZoneImageBuildError::ArenaTooLarge { name: arena_name })?;
    Ok(Some(BlobRange { offset, len }))
}

fn push_canonical_order_wire_key(
    arena: &mut Vec<u8>,
    wire_name: &[u8],
    require_full_name: bool,
    arena_name: &'static str,
) -> Result<Option<BlobRange>, ZoneImageBuildError> {
    let Some((labels, consumed)) = canonical_wire_label_ranges(wire_name) else {
        return Ok(None);
    };
    if require_full_name && consumed != wire_name.len() {
        return Ok(None);
    }

    let offset = u32::try_from(arena.len())
        .map_err(|_| ZoneImageBuildError::ArenaTooLarge { name: arena_name })?;
    for (start, len) in labels.iter().rev() {
        let label = &wire_name[*start..*start + *len];
        arena.push(*len as u8);
        arena.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    arena.push(0);
    if arena.len() > u32::MAX as usize {
        return Err(ZoneImageBuildError::ArenaTooLarge { name: arena_name });
    }
    let len = u32::try_from(arena.len() - offset as usize)
        .map_err(|_| ZoneImageBuildError::ArenaTooLarge { name: arena_name })?;
    Ok(Some(BlobRange { offset, len }))
}

fn canonical_wire_label_ranges(
    wire_name: &[u8],
) -> Option<(SmallVec<[(usize, usize); 16]>, usize)> {
    let mut labels = SmallVec::<[(usize, usize); 16]>::new();
    let mut offset = 0usize;
    let mut total_len = 1usize;
    loop {
        let len = *wire_name.get(offset)?;
        offset += 1;
        match len & 0xc0 {
            0x00 if len == 0 => return Some((labels, offset)),
            0x00 => {
                let label_len = usize::from(len);
                total_len = total_len.checked_add(1 + label_len)?;
                if total_len > 255 {
                    return None;
                }
                let end = offset.checked_add(label_len)?;
                wire_name.get(offset..end)?;
                labels.push((offset, label_len));
                offset = end;
            }
            _ => return None,
        }
    }
}

fn canonical_key_from_uncompressed_wire(wire_name: &[u8]) -> Option<String> {
    let (labels, consumed) = canonical_wire_label_ranges(wire_name)?;
    if consumed != wire_name.len() {
        return None;
    }
    if labels.is_empty() {
        return Some(".".to_owned());
    }

    let mut key = String::with_capacity(wire_name.len().saturating_sub(1));
    for (start, len) in labels {
        for byte in &wire_name[start..start + len] {
            key.push(byte.to_ascii_lowercase() as char);
        }
        key.push('.');
    }
    Some(key)
}

fn blob_from_arena(arena: &[u8], range: BlobRange) -> &[u8] {
    let start = range.offset as usize;
    let end = start + range.len as usize;
    &arena[start..end]
}

fn rdata_from_arena(arena: &[u8], range: RdataRange) -> &[u8] {
    blob_from_arena(arena, range.blob_range())
}

fn blob_len(range: BlobRange) -> usize {
    range.len as usize
}

pub(crate) fn zone_image_record_fixed_fields(
    rr_type: u16,
    class: u16,
    ttl: u32,
) -> ZoneImageRecordFixedFields {
    let mut fields = [0u8; 8];
    fields[..2].copy_from_slice(&rr_type.to_be_bytes());
    fields[2..4].copy_from_slice(&class.to_be_bytes());
    fields[4..8].copy_from_slice(&ttl.to_be_bytes());
    fields
}

fn direct_answer_record_prefix(fixed_fields: ZoneImageRecordFixedFields) -> [u8; 10] {
    let mut prefix = [0u8; 10];
    prefix[..2].copy_from_slice(&0xc00cu16.to_be_bytes());
    prefix[2..].copy_from_slice(&fixed_fields);
    prefix
}

fn synthesized_cname_fixed_fields_from_rrset(rrset: ImageRrset) -> ZoneImageRecordFixedFields {
    let mut fixed_fields = rrset.fixed_fields;
    fixed_fields[..2].copy_from_slice(&(RecordType::Cname as u16).to_be_bytes());
    fixed_fields
}

fn push_direct_answer_body(
    wire: &mut Vec<u8>,
    direct_copy_eligible: bool,
    fixed_fields: ZoneImageRecordFixedFields,
    rdatas: &[&[u8]],
) -> Result<u32, ZoneImageBuildError> {
    if !direct_copy_eligible {
        return Ok(0);
    }
    if rdatas.len() <= 1 {
        return Ok(DIRECT_ANSWER_BODY_RECORDS_FALLBACK);
    }
    let offset = checked_u32(wire.len(), "wire")?;
    let record_prefix = direct_answer_record_prefix(fixed_fields);
    for rdata in rdatas {
        let rdlength =
            u16::try_from(rdata.len()).map_err(|_| ZoneImageBuildError::RdataTooLarge)?;
        wire.extend_from_slice(&record_prefix);
        wire.extend_from_slice(&rdlength.to_be_bytes());
        wire.extend_from_slice(rdata);
    }
    let len = checked_u32(
        wire.len()
            .checked_sub(offset as usize)
            .ok_or(ZoneImageBuildError::TooManyItems {
                kind: "direct answer body bytes",
            })?,
        "direct answer body bytes",
    )?;
    if len == DIRECT_ANSWER_BODY_RECORDS_FALLBACK {
        return Err(ZoneImageBuildError::TooManyItems {
            kind: "direct answer body bytes",
        });
    }
    Ok(len)
}

fn ownerless_wire_len(
    direct_answer_body_len: u32,
    rrset_wire_len: usize,
    owner_wire_len: usize,
    record_count: usize,
) -> Result<u32, ZoneImageBuildError> {
    let len = if direct_answer_body_len != 0
        && direct_answer_body_len != DIRECT_ANSWER_BODY_RECORDS_FALLBACK
    {
        let compressed_owner_bytes =
            2usize
                .checked_mul(record_count)
                .ok_or(ZoneImageBuildError::TooManyItems {
                    kind: "ownerless rrset wire bytes",
                })?;
        (direct_answer_body_len as usize).checked_sub(compressed_owner_bytes)
    } else {
        let owner_wire_bytes =
            owner_wire_len
                .checked_mul(record_count)
                .ok_or(ZoneImageBuildError::TooManyItems {
                    kind: "ownerless rrset wire bytes",
                })?;
        rrset_wire_len.checked_sub(owner_wire_bytes)
    }
    .ok_or(ZoneImageBuildError::TooManyItems {
        kind: "ownerless rrset wire bytes",
    })?;

    checked_u32(len, "ownerless rrset wire bytes")
}

fn direct_answer_non_owner_wire_len(rrset: &ImageRrset) -> usize {
    rrset.ownerless_wire_len as usize
}

fn find_build_node_in_rrset(
    image_rrsets: &[ImageRrset],
    node: &BuildNode,
    rr_type: u16,
) -> Option<ZoneImageRrsetId> {
    node.rrsets.iter().copied().find(|rrset_id| {
        let rrset = image_rrsets[rrset_id.0 as usize];
        rrset.rr_type() == rr_type && rrset.class() == 1
    })
}

fn build_node_has_non_in_rrset(
    image_rrsets: &[ImageRrset],
    node: &BuildNode,
    rr_type: RecordType,
) -> bool {
    node.rrsets.iter().copied().any(|rrset_id| {
        let rrset = image_rrsets[rrset_id.0 as usize];
        rrset.rr_type() == rr_type as u16 && rrset.class() != 1
    })
}

fn build_low_rrtype_bitmap(rrsets: &[ImageRrset]) -> [u64; LOW_RRTYPE_BITMAP_WORDS] {
    let mut bitmap = [0u64; LOW_RRTYPE_BITMAP_WORDS];
    for rrset in rrsets {
        let rr_type = usize::from(rrset.rr_type());
        let word = rr_type / u64::BITS as usize;
        if word < bitmap.len() {
            bitmap[word] |= 1u64 << (rr_type % u64::BITS as usize);
        }
    }
    bitmap
}

fn low_rrtype_bitmap_may_contain(bitmap: &[u64; LOW_RRTYPE_BITMAP_WORDS], rr_type: u16) -> bool {
    let rr_type = usize::from(rr_type);
    let word = rr_type / u64::BITS as usize;
    if word >= bitmap.len() {
        return true;
    }
    bitmap[word] & (1u64 << (rr_type % u64::BITS as usize)) != 0
}

fn build_node_low_rrtype_bitmaps(
    rrsets: &[ImageRrset],
    build_nodes: &[BuildNode],
    nodes: &mut [NameNode],
) -> Result<Vec<u64>, ZoneImageBuildError> {
    let mut bitmaps = Vec::new();
    for (node_index, build_node) in build_nodes.iter().enumerate() {
        if build_node.rrsets.len() <= 1 {
            continue;
        }
        let mut bitmap = 0u64;
        for rrset_id in &build_node.rrsets {
            let rr_type = rrsets[rrset_id.0 as usize].rr_type();
            if rr_type < u64::BITS as u16 {
                bitmap |= 1u64 << rr_type;
            }
        }
        nodes[node_index].low_rrtype_bitmap =
            checked_u16(bitmaps.len(), "node low RRtype bitmap index")?;
        bitmaps.push(bitmap);
    }
    Ok(bitmaps)
}

fn node_low_rrtype_bitmap_may_contain(bitmap: u64, rr_type: u16) -> bool {
    if rr_type >= u64::BITS as u16 {
        return true;
    }
    bitmap & (1u64 << rr_type) != 0
}

fn domain_name_heap_bytes(name: &DomainName) -> usize {
    name.labels()
        .iter()
        .map(|label| mem::size_of::<Vec<u8>>() + label.len())
        .sum()
}

fn domain_is_suffix_parent_of_origin(name: &DomainName, origin: &DomainName) -> bool {
    let name_label_count = name.label_count();
    let origin_label_count = origin.label_count();
    if name_label_count >= origin_label_count {
        return false;
    }

    name.labels()
        .iter()
        .zip(origin.labels()[origin_label_count - name_label_count..].iter())
        .all(|(name_label, origin_label)| name_label.eq_ignore_ascii_case(origin_label))
}

fn build_child_hashes(
    nodes: &mut [NameNode],
    edges: &[NameEdge],
    labels: &[u8],
) -> Result<(Vec<ImageChildHash>, Vec<u16>), ZoneImageBuildError> {
    let mut hashes = Vec::new();
    let mut slots = Vec::new();

    for node_index in 0..nodes.len() {
        let node = nodes[node_index];
        let edge_count = usize::from(node.edge_count);
        if edge_count < CHILD_HASH_FANOUT_THRESHOLD {
            continue;
        }

        let slot_count = edge_count.saturating_mul(2).next_power_of_two();
        let first_slot = checked_u32(slots.len(), "child hash slots")?;
        let slot_count_u32 = checked_u32(slot_count, "child hash slots")?;
        slots.resize(slots.len() + slot_count, u16::MAX);
        let mask = slot_count - 1;

        for edge_offset in 0..edge_count {
            let edge = edges[node.first_edge as usize + edge_offset];
            let label = blob_from_arena(labels, edge.label);
            let mut slot = child_label_hash(label) & mask;
            loop {
                let slot_index = first_slot as usize + slot;
                if slots[slot_index] == u16::MAX {
                    slots[slot_index] = checked_u16(edge_offset, "child hash edge offsets")?;
                    break;
                }
                slot = (slot + 1) & mask;
            }
        }

        let hash_index = checked_u32(hashes.len(), "child hashes")?;
        nodes[node_index].child_hash = hash_index;
        hashes.push(ImageChildHash {
            first_slot,
            slot_mask: slot_count_u32 - 1,
        });
    }

    Ok((hashes, slots))
}

fn checked_u32(value: usize, kind: &'static str) -> Result<u32, ZoneImageBuildError> {
    u32::try_from(value).map_err(|_| ZoneImageBuildError::TooManyItems { kind })
}

fn checked_u16(value: usize, kind: &'static str) -> Result<u16, ZoneImageBuildError> {
    u16::try_from(value).map_err(|_| ZoneImageBuildError::TooManyItems { kind })
}

fn checked_u8(value: usize, kind: &'static str) -> Result<u8, ZoneImageBuildError> {
    u8::try_from(value).map_err(|_| ZoneImageBuildError::TooManyItems { kind })
}

fn qclass_matches(class: u16, qclass: u16) -> bool {
    qclass == 255 || class == qclass
}

fn set_rrset_flag(flags: &mut Vec<u64>, rrset_index: usize, enabled: bool) {
    let word_index = rrset_index / 64;
    if flags.len() <= word_index {
        flags.resize(word_index + 1, 0);
    }
    if enabled {
        flags[word_index] |= 1u64 << (rrset_index % 64);
    }
}

fn rrset_flag(flags: &[u64], rrset_index: usize) -> bool {
    let Some(flags) = flags.get(rrset_index / 64) else {
        return false;
    };
    flags & (1u64 << (rrset_index % 64)) != 0
}

fn direct_copy_rdata_type(rr_type: u16) -> bool {
    rr_type != RecordType::Ns as u16
        && rr_type != RecordType::Cname as u16
        && rr_type != RecordType::Ptr as u16
        && rr_type != RecordType::Soa as u16
        && rr_type != RecordType::Mx as u16
        && rr_type != RecordType::Opt as u16
        && rr_type != RecordType::Tkey as u16
        && rr_type != RecordType::Tsig as u16
        && rr_type != RecordType::Ixfr as u16
        && rr_type != RecordType::Axfr as u16
}

fn rrset_id_from_policy(rrset_id: u32) -> Option<ZoneImageRrsetId> {
    (rrset_id != u32::MAX).then_some(ZoneImageRrsetId(rrset_id))
}

fn chain_state_start(
    qname: &DomainName,
    original_node: Option<u32>,
    remaining: usize,
) -> ChainState<'_> {
    ChainState {
        original_qname: qname,
        original_node,
        visited_target_nodes: SmallVec::new(),
        remaining,
    }
}

fn target_matches_original_query(
    target: &DomainName,
    target_wire: IndirectionTargetWire<'_>,
    target_node: ImageTargetNode,
    state: &ChainState<'_>,
    plan: &ZoneImageLookupPlan,
) -> bool {
    match (target_node, state.original_node) {
        (ImageTargetNode::InZoneNode(target_node), Some(original_node)) => {
            target_node == original_node
        }
        _ => target_wire.as_wire(plan).is_some_and(|wire| {
            wire_name_equals_domain_with_label_count_ignore_ascii_case(
                wire,
                target.label_count(),
                state.original_qname,
            )
        }),
    }
}

impl<'a> IndirectionTargetWire<'a> {
    fn as_wire(self, plan: &'a ZoneImageLookupPlan) -> Option<&'a [u8]> {
        match self {
            IndirectionTargetWire::Borrowed(wire) => Some(wire),
            IndirectionTargetWire::DynamicAnswer(index) => plan
                .dynamic_answers
                .get(usize::from(index))
                .map(|record| record.rdata.as_slice()),
        }
    }
}

fn insert_selected_record(
    seen: &mut SmallVec<[ZoneImageSelectedRecord; 4]>,
    selected: ZoneImageSelectedRecord,
) -> bool {
    if seen.contains(&selected) {
        return false;
    }
    seen.push(selected);
    true
}

fn single_name_rdata_bytes(rdata: &[u8]) -> Option<DomainName> {
    DomainName::from_uncompressed_wire(rdata).ok()
}

fn single_name_rdata_wire(rdata: &[u8]) -> Option<&[u8]> {
    wire_name_slice_at(rdata, 0, true)
}

fn rrsig_type_covered_rdata(rdata: &[u8]) -> Option<u16> {
    if rdata.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([rdata[0], rdata[1]]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Nsec3Params<'a> {
    hash_algorithm: u8,
    iterations: u16,
    salt: &'a [u8],
}

fn nsec3_params_from_rdata(rdata: &[u8]) -> Option<Nsec3Params<'_>> {
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
        salt: &rdata[5..5 + salt_len],
    })
}

fn nsec3_next_hash_bytes(rdata: &[u8]) -> Option<[u8; 20]> {
    let params = nsec3_params_from_rdata(rdata)?;
    let hash_len_offset = 5 + params.salt.len();
    let hash_len = *rdata.get(hash_len_offset)? as usize;
    let hash_start = hash_len_offset + 1;
    let hash_end = hash_start.checked_add(hash_len)?;
    if hash_end > rdata.len() {
        return None;
    }

    fixed_sha1_hash_bytes(&rdata[hash_start..hash_end])
}

#[cfg(test)]
fn nsec3_hash_domain_cache_index<'a>(
    name: &DomainName,
    params: Nsec3Params<'a>,
    cache: &mut SmallVec<[(Nsec3Params<'a>, Option<[u8; 20]>); 1]>,
) -> usize {
    nsec3_hash_label_view_cache_index(
        NameLabelView {
            prefix: None,
            labels: name.labels(),
            ascii_lowercase: false,
        },
        params,
        cache,
    )
}

#[cfg(test)]
fn nsec3_hash_label_view_cache_index<'a>(
    name: NameLabelView<'_>,
    params: Nsec3Params<'a>,
    cache: &mut SmallVec<[(Nsec3Params<'a>, Option<[u8; 20]>); 1]>,
) -> usize {
    if let Some(index) = cache
        .iter()
        .position(|(cached_params, _)| *cached_params == params)
    {
        return index;
    }

    let hash = nsec3_hash_label_view(name, params);
    cache.push((params, hash));
    cache.len() - 1
}

#[cfg(test)]
fn nsec3_hash_canonical_wire(canonical: &[u8], params: Nsec3Params<'_>) -> Option<String> {
    if params.hash_algorithm != 1 {
        return None;
    }

    let mut digest = Sha1::new();
    digest.update(canonical);
    digest.update(params.salt);
    let mut hash = digest.finalize();

    for _ in 0..params.iterations {
        let mut digest = Sha1::new();
        let hash_bytes: &[u8] = hash.as_ref();
        digest.update(hash_bytes);
        digest.update(params.salt);
        hash = digest.finalize();
    }

    let hash_bytes: &[u8] = hash.as_ref();
    Some(base32hex_no_padding_lower(hash_bytes))
}

#[cfg(test)]
fn nsec3_hash_domain(name: &DomainName, params: Nsec3Params<'_>) -> Option<String> {
    nsec3_hash_label_view(
        NameLabelView {
            prefix: None,
            labels: name.labels(),
            ascii_lowercase: false,
        },
        params,
    )
    .map(|hash| base32hex_no_padding_lower(&hash))
}

fn nsec3_hash_wire_name(wire_name: &[u8], params: Nsec3Params<'_>) -> Option<[u8; 20]> {
    if params.hash_algorithm != 1 {
        return None;
    }

    let mut digest = Sha1::new();
    update_sha1_with_canonical_wire_name(&mut digest, wire_name)?;
    digest.update(params.salt);
    let mut hash = digest.finalize();

    for _ in 0..params.iterations {
        let mut digest = Sha1::new();
        let hash_bytes: &[u8] = hash.as_ref();
        digest.update(hash_bytes);
        digest.update(params.salt);
        hash = digest.finalize();
    }

    Some(sha1_output_to_array(hash))
}

fn nsec3_hash_label_view(name: NameLabelView<'_>, params: Nsec3Params<'_>) -> Option<[u8; 20]> {
    if params.hash_algorithm != 1 {
        return None;
    }

    let mut digest = Sha1::new();
    update_sha1_with_canonical_label_view(&mut digest, name);
    digest.update(params.salt);
    let mut hash = digest.finalize();

    for _ in 0..params.iterations {
        let mut digest = Sha1::new();
        let hash_bytes: &[u8] = hash.as_ref();
        digest.update(hash_bytes);
        digest.update(params.salt);
        hash = digest.finalize();
    }

    Some(sha1_output_to_array(hash))
}

fn update_sha1_with_canonical_wire_name(digest: &mut Sha1, wire_name: &[u8]) -> Option<()> {
    let mut offset = 0usize;
    loop {
        let len = *wire_name.get(offset)?;
        offset += 1;
        if len & 0xc0 != 0 {
            return None;
        }
        if len == 0 {
            if offset == wire_name.len() {
                digest.update([0]);
                return Some(());
            }
            return None;
        }
        let label_end = offset.checked_add(len as usize)?;
        let label = wire_name.get(offset..label_end)?;
        digest.update([len]);
        for byte in label {
            digest.update([byte.to_ascii_lowercase()]);
        }
        offset = label_end;
    }
}

fn update_sha1_with_canonical_label_view(digest: &mut Sha1, name: NameLabelView<'_>) {
    if let Some(prefix) = name.prefix {
        digest.update([prefix.len() as u8]);
        for byte in prefix {
            digest.update([if name.ascii_lowercase {
                *byte
            } else {
                byte.to_ascii_lowercase()
            }]);
        }
    }
    for label in name.labels {
        digest.update([label.len() as u8]);
        if name.ascii_lowercase {
            digest.update(label);
        } else {
            for byte in label {
                digest.update([byte.to_ascii_lowercase()]);
            }
        }
    }
    digest.update([0]);
}

fn sha1_output_to_array(hash: impl AsRef<[u8]>) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(hash.as_ref());
    bytes
}

fn nsec3_owner_wire_hash_bytes(owner_wire: &[u8], origin: &DomainName) -> Option<[u8; 20]> {
    let (&hash_label_len, rest) = owner_wire.split_first()?;
    let hash_label_len = usize::from(hash_label_len);
    if hash_label_len == 0 || hash_label_len > 63 || rest.len() < hash_label_len {
        return None;
    }
    let (hash_label, mut suffix_wire) = rest.split_at(hash_label_len);

    for origin_label in origin.labels() {
        let (&owner_label_len, rest) = suffix_wire.split_first()?;
        if usize::from(owner_label_len) != origin_label.len() || rest.len() < origin_label.len() {
            return None;
        }
        let (owner_label, rest) = rest.split_at(origin_label.len());
        if !owner_label.eq_ignore_ascii_case(origin_label) {
            return None;
        }
        suffix_wire = rest;
    }

    if suffix_wire != [0] {
        return None;
    }

    base32hex_sha1_no_padding_decode_lower(hash_label)
}

#[cfg(test)]
fn nsec3_owner_hash_bytes(owner: &DomainName, origin: &DomainName) -> Option<[u8; 20]> {
    let origin_labels = origin.labels();
    let owner_labels = owner.labels();
    if owner_labels.len() != origin_labels.len() + 1 {
        return None;
    }

    if !owner_labels[1..]
        .iter()
        .zip(origin_labels)
        .all(|(owner_label, origin_label)| owner_label.eq_ignore_ascii_case(origin_label))
    {
        return None;
    }

    nsec3_owner_wire_hash_bytes(&owner.to_wire(), origin)
}

fn fixed_sha1_hash_bytes(bytes: &[u8]) -> Option<[u8; 20]> {
    let mut hash = [0u8; 20];
    if bytes.len() != hash.len() {
        return None;
    }
    hash.copy_from_slice(bytes);
    Some(hash)
}

fn nsec3_range_covers_hash(owner_hash: &[u8; 20], next_hash: &[u8; 20], hash: &[u8; 20]) -> bool {
    if owner_hash < next_hash {
        owner_hash < hash && hash < next_hash
    } else if owner_hash > next_hash {
        owner_hash < hash || hash < next_hash
    } else {
        hash != owner_hash
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn base32hex_no_padding_decode_lower(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((encoded.len() * 5) / 8);
    let mut buffer = 0u16;
    let mut bits = 0u8;

    for byte in encoded {
        let value = base32hex_value(byte.to_ascii_lowercase())?;
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u16 << bits) - 1;
        }
    }

    if bits > 0 && buffer != 0 {
        return None;
    }
    Some(out)
}

fn base32hex_sha1_no_padding_decode_lower(encoded: &[u8]) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    let mut out_len = 0usize;
    let mut buffer = 0u16;
    let mut bits = 0u8;

    for byte in encoded {
        let value = base32hex_value(byte.to_ascii_lowercase())?;
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        while bits >= 8 {
            if out_len == out.len() {
                return None;
            }
            bits -= 8;
            out[out_len] = (buffer >> bits) as u8;
            out_len += 1;
            buffer &= (1u16 << bits) - 1;
        }
    }

    if bits > 0 && buffer != 0 {
        return None;
    }
    (out_len == out.len()).then_some(out)
}

fn base32hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'v' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn nsec_range_keys_cover_label_view(
    owner_key: &[u8],
    next_key: &[u8],
    owner_before_next: bool,
    name: NameLabelView<'_>,
) -> bool {
    let owner_vs_name = cmp_canonical_order_wire_key_to_label_view(owner_key, name);
    let next_vs_name = cmp_canonical_order_wire_key_to_label_view(next_key, name);
    if owner_before_next {
        owner_vs_name == Ordering::Less && next_vs_name == Ordering::Greater
    } else {
        owner_vs_name == Ordering::Less || next_vs_name == Ordering::Greater
    }
}

fn cmp_canonical_order_key_wires(left: &[u8], right: &[u8]) -> Ordering {
    let mut left_cursor = 0usize;
    let mut right_cursor = 0usize;
    loop {
        let left_label = next_canonical_order_wire_label(left, &mut left_cursor);
        let right_label = next_canonical_order_wire_label(right, &mut right_cursor);
        match (left_label, right_label) {
            (Some(left), Some(right)) => match cmp_lowercase_label(left, right) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn cmp_canonical_order_wire_key_to_label_view(key: &[u8], name: NameLabelView<'_>) -> Ordering {
    let mut key_cursor = 0usize;
    let mut name_labels = name.labels.iter().rev();
    let mut prefix = name.prefix;
    loop {
        let left = next_canonical_order_wire_label(key, &mut key_cursor);
        let right = name_labels.next().map(Vec::as_slice).or_else(|| {
            let label = prefix;
            prefix = None;
            label
        });
        match (left, right) {
            (Some(left), Some(right)) => match cmp_lowercase_label_with_ascii_lowercase_hint(
                left,
                right,
                name.ascii_lowercase,
            ) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn next_canonical_order_wire_label<'a>(key: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let len = *key.get(*cursor)? as usize;
    *cursor += 1;
    if len == 0 {
        return None;
    }
    let start = *cursor;
    let end = start.checked_add(len)?;
    let label = key.get(start..end)?;
    *cursor = end;
    Some(label)
}

fn wire_name_equals_domain_with_label_count_ignore_ascii_case(
    wire: &[u8],
    wire_label_count: usize,
    name: &DomainName,
) -> bool {
    if wire_label_count != name.label_count() {
        return false;
    }

    let mut offset = 0usize;
    for label in name.labels() {
        let Some(&wire_len) = wire.get(offset) else {
            return false;
        };
        let label_len = wire_len as usize;
        offset += 1;
        if label_len != label.len() || offset + label_len > wire.len() {
            return false;
        }
        if !wire[offset..offset + label_len].eq_ignore_ascii_case(label) {
            return false;
        }
        offset += label_len;
    }
    wire.get(offset) == Some(&0) && offset + 1 == wire.len()
}

fn wire_name_is_equal_or_subdomain_of_domain(name_wire: &[u8], origin: &DomainName) -> bool {
    let origin_label_count = origin.label_count();
    let Some((name_labels, consumed)) = canonical_wire_label_ranges(name_wire) else {
        return false;
    };
    if consumed != name_wire.len() || name_labels.len() < origin_label_count {
        return false;
    }

    let name_suffix = &name_labels[name_labels.len() - origin_label_count..];
    name_suffix
        .iter()
        .zip(origin.labels())
        .all(|((start, len), origin_label)| {
            *len == origin_label.len()
                && name_wire[*start..*start + *len].eq_ignore_ascii_case(origin_label)
        })
}

fn wire_name_is_equal_or_subdomain_of_wire(
    name_wire: &[u8],
    zone_wire: &[u8],
    zone_label_count: usize,
) -> bool {
    let Some((name_labels, name_consumed)) = canonical_wire_label_ranges(name_wire) else {
        return false;
    };
    if name_consumed != name_wire.len() || zone_label_count > name_labels.len() {
        return false;
    }
    let Some((zone_labels, consumed)) = canonical_wire_label_ranges(zone_wire) else {
        return false;
    };
    if consumed != zone_wire.len() || zone_labels.len() != zone_label_count {
        return false;
    }

    let name_suffix = &name_labels[name_labels.len() - zone_label_count..];
    zone_labels
        .iter()
        .zip(name_suffix)
        .all(|((zone_start, zone_len), (name_start, name_len))| {
            *zone_len == *name_len
                && zone_wire[*zone_start..*zone_start + *zone_len]
                    .eq_ignore_ascii_case(&name_wire[*name_start..*name_start + *name_len])
        })
}

fn additional_address_target_wire_rdata(rr_type: u16, rdata: &[u8]) -> Option<&[u8]> {
    match rr_type {
        rr_type if rr_type == RecordType::Ns as u16 => single_name_rdata_wire(rdata),
        rr_type if rr_type == RecordType::Mx as u16 => mx_exchange_wire_rdata(rdata),
        rr_type if rr_type == RecordType::Srv as u16 => srv_target_wire_rdata(rdata),
        rr_type if rr_type == RecordType::Naptr as u16 => naptr_replacement_wire_rdata(rdata),
        rr_type if rr_type == RecordType::Svcb as u16 || rr_type == RecordType::Https as u16 => {
            svcb_target_name_wire_rdata(rdata)
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

fn wire_name_slice_at(rdata: &[u8], offset: usize, require_end: bool) -> Option<&[u8]> {
    let len = wire_name_len_at(rdata, offset)?;
    let end = offset.checked_add(len)?;
    if end > rdata.len() || (require_end && end != rdata.len()) {
        return None;
    }
    Some(&rdata[offset..end])
}

fn mx_exchange_wire_rdata(rdata: &[u8]) -> Option<&[u8]> {
    if rdata.len() < 3 {
        return None;
    }

    wire_name_slice_at(rdata, 2, true)
}

fn srv_target_wire_rdata(rdata: &[u8]) -> Option<&[u8]> {
    if rdata.len() < 7 {
        return None;
    }

    wire_name_slice_at(rdata, 6, true)
}

fn naptr_replacement_wire_rdata(rdata: &[u8]) -> Option<&[u8]> {
    if rdata.len() < 7 {
        return None;
    }

    let mut offset = 4;
    for _ in 0..3 {
        offset = skip_character_string(rdata, offset)?;
    }

    wire_name_slice_at(rdata, offset, true)
}

fn svcb_target_name_wire_rdata(rdata: &[u8]) -> Option<&[u8]> {
    if rdata.len() < 3 {
        return None;
    }

    wire_name_slice_at(rdata, 2, false)
}

fn skip_character_string(rdata: &[u8], offset: usize) -> Option<usize> {
    let len = *rdata.get(offset)? as usize;
    let next = offset.checked_add(1)?.checked_add(len)?;
    (next <= rdata.len()).then_some(next)
}

fn soa_minimum(rdata: &[u8]) -> Option<u32> {
    let rname_offset = wire_name_len_at(rdata, 0)?;
    let consumed_rname = wire_name_len_at(rdata, rname_offset)?;
    let serial_offset = rname_offset.checked_add(consumed_rname)?;
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
    fn compact_rdata_range_keeps_image_record_and_rrset_metadata_bounded() {
        assert_eq!(mem::size_of::<RdataRange>(), mem::size_of::<BlobRange>());
        assert_eq!(mem::size_of::<ImageRecord>(), mem::size_of::<BlobRange>());
        assert_eq!(mem::size_of::<ImageRrsetRelation>(), 12);
        assert_eq!(mem::size_of::<ImageRrset>(), 48);
        assert_eq!(mem::size_of::<PackedRdataEncoding>(), 2);
        assert_eq!(mem::size_of::<ZoneImageSelectedRecord>(), 24);
        assert_eq!(mem::size_of::<ZoneImageWireRecord<'static>>(), 48);
    }

    #[test]
    fn plan_answer_indexes_stay_compact() {
        assert_eq!(mem::size_of::<PlanAnswer>(), 28);
        assert_eq!(mem::align_of::<PlanAnswer>(), 4);
        assert_eq!(
            mem::size_of::<IndirectionTargetWire<'static>>(),
            mem::size_of::<Option<&'static [u8]>>()
        );
        let plan = ZoneImageLookupPlan::positive();
        assert_eq!(
            mem::size_of_val(&plan.authority_soa_index),
            mem::size_of::<u16>()
        );
        assert_eq!(plan.authority_soa_index, NO_AUTHORITY_SOA_INDEX);
        let response_shape = plan
            .response_shape()
            .expect("empty positive plan section counts fit DNS header fields");
        assert_eq!(
            mem::size_of_val(&response_shape.answer_count),
            mem::size_of::<u16>()
        );
        assert_eq!(
            mem::size_of_val(&response_shape.authority_count),
            mem::size_of::<u16>()
        );
        assert_eq!(
            mem::size_of_val(&response_shape.additional_count),
            mem::size_of::<u16>()
        );
        let dnssec_state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: 0,
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 0,
        };
        assert_eq!(
            mem::size_of_val(&dnssec_state.original_authority_rrset_count),
            mem::size_of::<u16>()
        );
    }

    #[test]
    fn soa_rdata_encoding_carries_both_prevalidated_name_spans() {
        let rdata = soa_rdata();
        let encoding = zone_image_rdata_encoding(RecordType::Soa as u16, &rdata);

        assert_eq!(encoding.soa_lengths(), Some((17, 25)));
        assert!(PackedRdataEncoding::copy().soa_lengths().is_none());
        assert!(PackedRdataEncoding::single_name().soa_lengths().is_none());
        assert!(PackedRdataEncoding::mx().soa_lengths().is_none());
    }

    #[test]
    fn soa_minimum_reads_prevalidated_wire_names_without_domain_parse() {
        let rdata = soa_rdata();

        assert_eq!(soa_minimum(&rdata), Some(300));

        let mut compressed_mname = rdata.clone();
        compressed_mname[0] = 0xc0;
        assert_eq!(soa_minimum(&compressed_mname), None);

        let mut trailing = rdata.clone();
        trailing.push(0);
        assert_eq!(soa_minimum(&trailing), None);
    }

    #[test]
    fn plan_summary_owner_key_is_built_directly_from_wire() {
        let owner = DomainName::from_absolute_str("MiXeD.Example.TEST.").unwrap();
        let owner_wire = owner.to_wire();
        let mut compressed = owner_wire.clone();
        compressed[0] = 0xc0;
        let mut trailing = owner_wire.clone();
        trailing.push(0);

        assert_eq!(
            canonical_owner_key_from_wire(&owner_wire).as_deref(),
            Ok("mixed.example.test.")
        );
        assert_eq!(
            canonical_owner_key_from_wire(&compressed),
            Err(ZoneImageBuildError::InvalidCompiledOwner)
        );
        assert_eq!(
            canonical_owner_key_from_wire(&trailing),
            Err(ZoneImageBuildError::InvalidCompiledOwner)
        );
    }

    #[test]
    fn additional_relation_targets_borrow_validated_wire_names() {
        let target_wire = name_rdata("Mail.Example.TEST.");
        let mut compressed = target_wire.clone();
        compressed[0] = 0xc0;
        let mut trailing = target_wire.clone();
        trailing.push(0);

        let mx = mx_rdata("Mail.Example.TEST.");
        let srv = srv_rdata("Mail.Example.TEST.");
        let mut svcb = svc_param_rdata("Mail.Example.TEST.");
        svcb.extend_from_slice(&[0, 1, 0, 0]);
        let svcb_target_len = wire_name_len_at(&svcb, 2).expect("valid SVCB target length");

        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &target_wire),
            Some(target_wire.as_slice())
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Mx as u16, &mx),
            Some(&mx[2..])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Srv as u16, &srv),
            Some(&srv[6..])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Svcb as u16, &svcb),
            Some(&svcb[2..2 + svcb_target_len])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &compressed),
            None
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &trailing),
            None
        );
    }

    #[test]
    fn compile_rejects_rdata_that_cannot_fit_wire_rdlength() {
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("oversized.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![vec![0; usize::from(u16::MAX) + 1]],
            )],
        );

        assert_eq!(
            ZoneImage::compile(&snapshot),
            Err(ZoneImageBuildError::RdataTooLarge)
        );
    }

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

        let snapshot_lookup = snapshot
            .offline_oracle()
            .lookup(&qname, RecordType::A as u16, 1);
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
        let record_count = image.append_plan_wire(&plan, &mut wire);
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
    fn exact_lookup_concrete_class_uses_single_compiled_rrset_match() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("multi.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(46),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![0; 16]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    3,
                    300,
                    vec![vec![198, 51, 100, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let ZoneImageLookupOutcome::Found(in_plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1)
        else {
            panic!("expected concrete IN A lookup to find an answer");
        };
        assert_eq!(
            plan_answer_classes_types(&image, &in_plan),
            vec![(1, RecordType::A as u16)]
        );

        let ZoneImageLookupOutcome::Found(any_class_plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255)
        else {
            panic!("expected ANY-class A lookup to find answers");
        };
        assert_eq!(
            plan_answer_classes_types(&image, &any_class_plan),
            vec![(1, RecordType::A as u16), (3, RecordType::A as u16)]
        );
    }

    #[test]
    fn single_rrset_owner_lookup_uses_direct_match_semantics() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let node = image.find_node(&qname).expect("single-RRset owner node");
        assert_eq!(image.nodes[node as usize].rrset_count, 1);

        assert!(matches!(
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert!(matches!(
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(&qname, RecordType::Aaaa as u16, 1),
            ZoneImageLookupOutcome::NoData
        );

        let semantic = ZoneImage::compile(&semantic_snapshot()).expect("semantic image compiles");
        let empty_owner = DomainName::from_absolute_str("ent.example.test.").unwrap();
        let empty_node = semantic
            .find_node(&empty_owner)
            .expect("empty non-terminal node exists");
        assert_eq!(semantic.nodes[empty_node as usize].rrset_count, 0);
        assert_eq!(
            semantic.lookup_exact_plan(&empty_owner, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
    }

    #[test]
    fn exact_lookup_skips_absent_low_rrtype_after_node_classification() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let existing = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let outside = DomainName::from_absolute_str("www.example.invalid.").unwrap();

        assert!(!image.low_rrtype_may_exist(RecordType::Txt as u16));
        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Txt as u16, 255),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&missing, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::NameError
        );
        assert_eq!(
            image.lookup_exact_plan(&outside, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::OutOfZone
        );
    }

    #[test]
    fn leaf_child_lookup_returns_missing_with_current_closest_node() {
        let image = ZoneImage::compile(&sample_snapshot()).expect("zone image compiles");
        let leaf = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing_below_leaf = DomainName::from_absolute_str("missing.www.example.test.")
            .expect("absolute name parses");
        let leaf_node = image.find_node(&leaf).expect("leaf node exists");

        assert_eq!(image.nodes[leaf_node as usize].edge_count, 0);
        assert_eq!(image.find_child(leaf_node, b"missing"), None);
        assert_eq!(
            image.query_node_handles(&missing_below_leaf, true),
            (None, Some(leaf_node))
        );
    }

    #[test]
    fn authority_soa_ttl_override_uses_plan_index_without_scan() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let answer_plan = image.lookup_response_plan(
            &www,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let a_rrset = answer_plan.answer_rrsets()[0];
        let soa_rrset = image.soa_rrset(1).expect("SOA exists");

        let mut plan = ZoneImageLookupPlan::positive();
        image.push_authority_rrset_to_plan(&mut plan, a_rrset);
        image.push_authority_rrset_to_plan(&mut plan, soa_rrset);

        assert_eq!(plan.authority_soa_index(), Some(1));
        assert!(plan.authority_has_soa());
        assert!(!plan.authority_first_rrset_is_soa());

        let mut actual = Vec::new();
        assert_eq!(image.append_plan_wire(&plan, &mut actual), 2);

        let mut expected = Vec::new();
        image.append_rrset_wire(a_rrset, &mut expected);
        image.append_rrset_wire_with_fixed_fields(
            soa_rrset,
            image.negative_authority_soa_fixed_fields(soa_rrset),
            &mut expected,
        );
        assert_eq!(actual, expected);

        let mut unmodified = Vec::new();
        image.append_rrset_wire(a_rrset, &mut unmodified);
        image.append_rrset_wire(soa_rrset, &mut unmodified);
        assert_ne!(
            actual, unmodified,
            "authority SOA TTL should use the negative TTL override"
        );
    }

    #[test]
    fn authority_removability_uses_plan_soa_position() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let answer_plan = image.lookup_response_plan(
            &www,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let a_rrset = answer_plan.answer_rrsets()[0];
        let soa_rrset = image.soa_rrset(1).expect("SOA exists");

        let mut plan = ZoneImageLookupPlan::positive();
        image.push_authority_rrset_to_plan(&mut plan, a_rrset);
        image.push_authority_rrset_to_plan(&mut plan, soa_rrset);
        assert_eq!(plan.authority_soa_index(), Some(1));

        let mut authority_removability = Vec::new();
        image.visit_plan_record_sections_with_authority_removability(
            &plan,
            |_| {},
            |record, removable| {
                authority_removability.push((
                    u16::from_be_bytes([record.fixed_fields[0], record.fixed_fields[1]]),
                    removable,
                ));
            },
            |_| {},
        );

        assert_eq!(
            authority_removability,
            vec![
                (RecordType::A as u16, true),
                (RecordType::Soa as u16, false)
            ]
        );
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
            let image_plan = image.lookup_response_plan(
                &qname,
                rr_type,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            );
            let snapshot_lookup = snapshot.offline_oracle().lookup(&qname, rr_type, 1);
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
        let mx_only = DomainName::from_absolute_str("mx-only.example.test.").unwrap();
        let nsec_only = DomainName::from_absolute_str("nsec-only.example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let wildcard_qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(45),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
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
                    exact.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::A as u16,
                    3,
                    300,
                    vec![vec![198, 51, 100, 10]],
                ),
                Rrset::new(
                    exact,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![vec![0, 1, 2, 3]],
                ),
                Rrset::new(
                    mx_only.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    nsec_only.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("next.example.test.")],
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
                    mail.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let exact_minimal = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &exact_minimal),
            vec![RecordType::A as u16]
        );

        let mx_only_minimal = image.lookup_response_plan(
            &mx_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &mx_only_minimal),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(mx_only_minimal.additional_rrsets().len(), 1);
        let mx_only_full = image.lookup_response_plan(
            &mx_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &mx_only_full),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(mx_only_full.additional_rrsets().len(), 1);
        let nsec_only_minimal = image.lookup_response_plan(
            &nsec_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(nsec_only_minimal.answer_rrsets().is_empty());
        assert!(nsec_only_minimal.authority_has_soa());

        let exact_full = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &exact_full),
            vec![
                RecordType::A as u16,
                RecordType::Mx as u16,
                RecordType::Txt as u16
            ]
        );
        assert_eq!(exact_full.additional_rrsets().len(), 1);

        let exact_full_any_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_full_any_class),
            vec![
                (1, RecordType::A as u16),
                (1, RecordType::Mx as u16),
                (1, RecordType::Txt as u16),
                (3, RecordType::A as u16),
            ]
        );

        let exact_full_chaos_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            3,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_full_chaos_class),
            vec![(3, RecordType::A as u16)]
        );
        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("multi.example.test.").unwrap(),
                RecordType::A as u16,
                3
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        let exact_minimal_chaos_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            3,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_minimal_chaos_class),
            vec![(3, RecordType::A as u16)]
        );

        let wildcard_full = image.lookup_response_plan(
            &wildcard_qname,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &wildcard_full),
            vec![RecordType::Mx as u16, RecordType::Txt as u16]
        );
        assert_eq!(wildcard_full.additional_rrsets().len(), 1);
        assert_eq!(wildcard_full.owner_overrides.len(), 1);
        assert!(!wildcard_full.owner_overrides.spilled());
        assert!(!wildcard_full.owner_overrides[0].spilled());
        assert!(wildcard_full.answer_items.iter().all(|item| {
            matches!(
                item,
                PlanAnswer::RrsetWithOwner {
                    owner_index,
                    ..
                } if wildcard_full.owner_overrides[usize::from(*owner_index)].as_slice()
                    == wildcard_qname.to_wire().as_slice()
            )
        }));

        let wildcard_minimal = image.lookup_response_plan(
            &wildcard_qname,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &wildcard_minimal),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(wildcard_minimal.additional_rrsets().len(), 1);
        assert_eq!(wildcard_minimal.owner_overrides.len(), 1);
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
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    mail.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Mx as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.synthesized_answer_count(), 0);
        assert!(matches!(
            plan.answer_items.as_slice(),
            [PlanAnswer::RrsetWithOwner { .. }]
        ));
        assert_eq!(plan.owner_overrides.len(), 1);
        assert!(!plan.owner_overrides.spilled());
        assert!(!plan.owner_overrides[0].spilled());
        assert_eq!(plan.additional_rrsets().len(), 1);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::Mx as u16, 1)
            )
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
    fn wildcard_non_target_rrsets_skip_additional_planning() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(matches!(
            plan.answer_items.as_slice(),
            [PlanAnswer::RrsetWithOwner { .. }]
        ));
        assert_eq!(plan.additional_rrsets(), &[]);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::A as u16, 1)
            )
        );
    }

    #[test]
    fn wildcard_direct_copy_owner_override_uses_compiled_body_length_for_accounting() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        let [
            PlanAnswer::RrsetWithOwner {
                rrset_id,
                owner_index,
            },
        ] = plan.answer_items.as_slice()
        else {
            panic!("expected one wildcard owner-override answer");
        };
        let rrset = image.rrsets[rrset_id.0 as usize];
        assert_ne!(
            rrset.direct_answer_body_len, 0,
            "wildcard A answer should have a compiled direct-copy body template"
        );
        let record_count = usize::from(rrset.record_count);
        assert_eq!(
            rrset.ownerless_wire_len as usize,
            record_count * (8 + 2 + 4),
            "compiled ownerless wire length should carry TYPE/CLASS/TTL, RDLENGTH, and A RDATA bytes"
        );
        let compiled_non_owner_wire_len = direct_answer_non_owner_wire_len(&rrset);
        let expected_answer_wire_len = plan.owner_overrides[usize::from(*owner_index)]
            .len()
            .saturating_mul(record_count)
            .saturating_add(compiled_non_owner_wire_len);

        assert_eq!(
            plan.answer_wire_upper_bound(),
            expected_answer_wire_len,
            "wildcard direct-copy owner override accounting should reuse the compiled non-owner body length"
        );
    }

    #[test]
    fn indirection_additionals_are_gated_by_target_rrset_type() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let canonical = DomainName::from_absolute_str("canonical.example.test.").unwrap();
        let service_target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("canonical.example.test.")],
                ),
                Rrset::new(
                    canonical.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    canonical,
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("target.example.test.")],
                ),
                Rrset::new(
                    service_target,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 11]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let address_plan = image.lookup_response_plan(
            &alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &address_plan),
            [RecordType::Cname as u16, RecordType::A as u16]
        );
        assert_eq!(address_plan.additional_rrsets(), &[]);
        assert_eq!(
            image.plan_summary(&address_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::A as u16, 1)
            )
        );

        let service_plan = image.lookup_response_plan(
            &alias,
            RecordType::Srv as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &service_plan),
            [RecordType::Cname as u16, RecordType::Srv as u16]
        );
        assert_eq!(service_plan.additional_rrsets().len(), 1);
        assert_eq!(
            image.plan_summary(&service_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::Srv as u16, 1)
            )
        );
    }

    #[test]
    fn dnssec_denial_candidate_reuses_answer_presence_classification() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let exact_qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let exact_plan = image.lookup_response_plan(
            &exact_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(exact_plan.answer_items.is_empty());
        assert!(exact_plan.answer_has_records());
        let exact_denial_candidate =
            plan_is_nodata_candidate(&exact_plan, exact_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&exact_plan, exact_plan.answer_has_records());
        assert!(!exact_denial_candidate);
        assert!(!plan_is_wildcard_synthesis_candidate(
            &exact_plan,
            exact_plan.answer_has_records()
        ));

        let wildcard_qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let wildcard_plan = image.lookup_response_plan(
            &wildcard_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(!wildcard_plan.answer_items.is_empty());
        assert!(wildcard_plan.answer_has_records());
        let wildcard_denial_candidate =
            plan_is_nodata_candidate(&wildcard_plan, wildcard_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&wildcard_plan, wildcard_plan.answer_has_records());
        assert!(!wildcard_denial_candidate);
        assert!(plan_is_wildcard_synthesis_candidate(
            &wildcard_plan,
            wildcard_plan.answer_has_records()
        ));

        let dname_qname = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let dname_plan = image.lookup_response_plan(
            &dname_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(
            !dname_plan.dynamic_answers.is_empty(),
            "DNAME positive plan should keep a synthesized CNAME answer"
        );
        assert!(dname_plan.answer_has_records());
        let dname_denial_candidate =
            plan_is_nodata_candidate(&dname_plan, dname_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&dname_plan, dname_plan.answer_has_records());
        assert!(!dname_denial_candidate);
        assert!(!plan_is_wildcard_synthesis_candidate(
            &dname_plan,
            dname_plan.answer_has_records()
        ));

        let nxdomain_qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let nxdomain_plan = image.lookup_response_plan(
            &nxdomain_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(!nxdomain_plan.answer_has_records());
        assert!(nxdomain_plan.authority_has_soa());
        assert!(nxdomain_plan.authority_first_rrset_is_soa());
        let nxdomain_denial_candidate =
            plan_is_nodata_candidate(&nxdomain_plan, nxdomain_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&nxdomain_plan, nxdomain_plan.answer_has_records());
        assert!(nxdomain_denial_candidate);
        let servfail_plan = nxdomain_plan
            .clone()
            .into_servfail(LookupTermination::CnameLoop);
        assert!(!servfail_plan.authority_has_soa());
        assert!(!servfail_plan.authority_first_rrset_is_soa());
    }

    #[test]
    fn dnssec_nodata_augmentation_uses_plan_nodata_precondition() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(69),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec = image
            .find_rrset(&qname, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Aaaa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(!plan.answer_has_records());
        assert!(plan.authority_has_soa());

        let hinted_augmented = image.augment_lookup_plan_with_dnssec_ascii_lowercase_hint(
            plan.clone(),
            &qname,
            1,
            100,
            true,
        );
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(
            hinted_augmented, augmented,
            "lowercase-hinted DNSSEC denial augmentation must match the conservative path"
        );

        assert!(
            augmented.authority_rrsets.contains(&nsec),
            "NODATA DNSSEC augmentation should trust the no-answer plan bit and append the exact-name NSEC proof"
        );
        assert!(augmented.dnssec_augmented());
    }

    #[test]
    fn dnssec_augmentation_skips_unsigned_images() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(!image.dnssec_augmentation_possible);
        assert!(!image.dnssec_denial_augmentation_possible);
        assert!(!image.dnssec_referral_augmentation_possible);
        assert!(!image.dnssec_rrsig_augmentation_possible);
        assert_eq!(
            image.augment_lookup_plan_with_dnssec(plan.clone(), &qname, 1, 100),
            plan
        );

        let signed = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(65),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ))
        .expect("signed zone image compiles");
        assert!(signed.dnssec_augmentation_possible);
        assert!(!signed.dnssec_denial_augmentation_possible);
        assert!(!signed.dnssec_referral_augmentation_possible);
        assert!(signed.dnssec_rrsig_augmentation_possible);

        let denial_only = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(66),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("denial-only zone image compiles");
        assert!(denial_only.dnssec_augmentation_possible);
        assert!(denial_only.dnssec_denial_augmentation_possible);
        assert!(!denial_only.dnssec_referral_augmentation_possible);
        assert!(!denial_only.dnssec_rrsig_augmentation_possible);

        let proof_family_only = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(67),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("proof-family-only zone image compiles");
        let positive_plan = proof_family_only.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(positive_plan.answer_has_records());
        assert_eq!(
            proof_family_only.augment_lookup_plan_with_dnssec(
                positive_plan.clone(),
                &qname,
                1,
                100,
            ),
            positive_plan,
            "proof-family-only images should skip DNSSEC state for positive non-wildcard plans"
        );
    }

    #[test]
    fn dnssec_dedupe_state_seeding_follows_capability_gates() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let signed = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(67),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ))
        .expect("rrsig-only zone image compiles");
        let soa = signed
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA rrset exists");
        let mut plan = signed.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        plan.push_authority_rrset(soa, signed.rrset_plan_metrics(soa));
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        signed.add_rrsig_augmentations(&mut plan, &mut state);
        assert!(state.appended_authority_rrsets.is_empty());
        assert_eq!(state.seen_selected_records.len(), 1);

        let denial_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(68),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    origin.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("denial-only zone image compiles");
        let soa = denial_only
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA rrset exists");
        let nsec = denial_only
            .find_rrset(&origin, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");
        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_authority_rrset(soa, denial_only.rrset_plan_metrics(soa));
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        denial_only.push_authority_rrset(&mut plan, soa, &mut state);
        assert!(state.appended_authority_rrsets.is_empty());
        assert_eq!(plan.authority_rrsets.as_slice(), [soa]);
        assert!(!state.dnssec_augmented);
        denial_only.push_authority_rrset(&mut plan, nsec, &mut state);
        assert_eq!(state.appended_authority_rrsets.as_slice(), [nsec]);
        assert_eq!(plan.authority_rrsets.as_slice(), [soa, nsec]);
        assert!(state.dnssec_augmented);
        denial_only.push_authority_rrset(&mut plan, nsec, &mut state);
        assert_eq!(state.appended_authority_rrsets.as_slice(), [nsec]);
        assert_eq!(plan.authority_rrsets.as_slice(), [soa, nsec]);
        assert!(
            denial_only
                .initial_dnssec_seen_selected_records(&plan)
                .is_empty()
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
            let plan = image.lookup_response_plan(
                &qname,
                rr_type,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            );
            let mut wire = Vec::new();
            image.append_plan_wire(&plan, &mut wire);
            let (answer_count, authority_count, additional_count) = plan.section_record_counts();
            let (
                accounted_answer_count,
                accounted_authority_count,
                accounted_additional_count,
                accounted_wire_upper_bound,
            ) = image.plan_accounting_direct(&plan);
            let response_shape = plan
                .response_shape()
                .expect("test plan section counts fit DNS header fields");

            assert_eq!(
                image.plan_wire_upper_bound(&plan),
                wire.len(),
                "wire upper bound mismatch for {qname}"
            );
            assert_eq!(
                plan.response_body_wire_upper_bound(),
                image.plan_wire_upper_bound(&plan),
                "carried response wire bound mismatch for {qname}"
            );
            assert_eq!(
                accounted_wire_upper_bound,
                wire.len(),
                "combined wire upper bound mismatch for {qname}"
            );
            assert_eq!(
                (
                    accounted_answer_count,
                    accounted_authority_count,
                    accounted_additional_count
                ),
                (answer_count, authority_count, additional_count),
                "combined section counts mismatch for {qname}"
            );
            assert_eq!(
                plan.total_record_count(),
                answer_count
                    .saturating_add(authority_count)
                    .saturating_add(additional_count),
                "derived total record count mismatch for {qname}"
            );
            assert_eq!(
                (
                    response_shape.response_flag_bits,
                    usize::from(response_shape.answer_count),
                    usize::from(response_shape.authority_count),
                    usize::from(response_shape.additional_count),
                    response_shape.body_wire_upper_bound,
                ),
                (
                    plan.rcode().response_flag_bits(plan.authoritative()),
                    answer_count,
                    authority_count,
                    additional_count,
                    image.plan_wire_upper_bound(&plan),
                ),
                "response shape accounting mismatch for {qname}"
            );
            assert_eq!(
                response_shape.section_count_header_bytes,
                test_section_count_header_bytes(
                    response_shape.answer_count,
                    response_shape.authority_count,
                    response_shape.additional_count,
                ),
                "response shape count bytes mismatch for {qname}"
            );
            assert_eq!(
                response_shape.section_count_header_bytes_with_extra_additional(1),
                response_shape
                    .additional_count
                    .checked_add(1)
                    .map(|additional_count| {
                        test_section_count_header_bytes(
                            response_shape.answer_count,
                            response_shape.authority_count,
                            additional_count,
                        )
                    }),
                "response shape EDNS count bytes mismatch for {qname}"
            );
        }
    }

    fn test_section_count_header_bytes(
        answer_count: u16,
        authority_count: u16,
        additional_count: u16,
    ) -> [u8; 6] {
        let answer_count = answer_count.to_be_bytes();
        let authority_count = authority_count.to_be_bytes();
        let additional_count = additional_count.to_be_bytes();
        [
            answer_count[0],
            answer_count[1],
            authority_count[0],
            authority_count[1],
            additional_count[0],
            additional_count[1],
        ]
    }

    #[test]
    fn direct_answer_plan_preserves_delegation_dname_and_additional_semantics() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let direct = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let delegated_glue = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let under_dname = DomainName::from_absolute_str("www.subtree.example.test.").unwrap();
        let delegated_child = DomainName::from_absolute_str("child.example.test.").unwrap();

        let direct_plan = image
            .lookup_direct_answer_plan(&direct, RecordType::A as u16, 1)
            .expect("direct A plan is present");
        assert!(direct_plan.direct_answer_candidate());
        let semantic_direct_plan = image.lookup_response_plan(
            &direct,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(semantic_direct_plan.direct_answer_candidate());
        let direct_a = direct_plan.answer_rrsets()[0];
        let direct_rrset = image
            .direct_rrset_wire(direct_a)
            .expect("direct A RRset wire exists");
        assert_eq!(
            direct_rrset.section_count_header_bytes(false),
            test_section_count_header_bytes(direct_rrset.record_count(), 0, 0),
            "direct RRset should carry no-EDNS section-count bytes"
        );
        assert_eq!(
            direct_rrset.section_count_header_bytes(true),
            test_section_count_header_bytes(direct_rrset.record_count(), 0, 1),
            "direct RRset should carry EDNS-adjusted section-count bytes"
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
        let cname = image
            .find_rrset(&alias, RecordType::Cname as u16, 1)
            .expect("CNAME RRset exists");
        assert!(
            image.direct_rrset_wire(cname).is_none(),
            "eligible-only direct RRset view must reject compressible RDATA types"
        );
    }

    #[test]
    fn direct_answer_preflight_uses_compiled_low_rrtype_bitmap() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let private_type = 65_280u16;
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(owner.clone(), private_type, 1, 300, vec![vec![1, 2, 3, 4]]),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(image.low_rrtype_may_exist(RecordType::A as u16));
        assert!(
            !image.low_rrtype_may_exist(RecordType::Txt as u16),
            "low RR type absent from the compiled image should skip direct preflight"
        );
        assert!(
            image.low_rrtype_may_exist(private_type),
            "private/high RR types keep the conservative direct-preflight path"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, RecordType::Txt as u16, 1)
                .is_none(),
            "direct preflight must reject RR types known absent from the image"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, private_type, 1)
                .is_some(),
            "high RR types are not ruled out by the low-type bitmap"
        );
    }

    #[test]
    fn node_local_low_rrtype_bitmap_skips_absent_present_types() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let private_type = 65_280u16;
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
                Rrset::new(
                    owner.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![0; 16]],
                ),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![target.to_wire()],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(
            image.low_rrtype_may_exist(RecordType::Cname as u16),
            "the image-wide bitmap remains conservative when CNAME exists elsewhere"
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&owner, RecordType::Cname as u16),
            Some(false),
            "the owner-local bitmap should reject an absent low RR type before scanning RRsets"
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&alias, RecordType::Cname as u16),
            Some(true)
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&owner, private_type),
            Some(true),
            "high/private RR types keep the conservative per-node lookup path"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, RecordType::Cname as u16, 1)
                .is_none()
        );
        assert!(
            image
                .lookup_direct_answer_plan(&alias, RecordType::Cname as u16, 1)
                .is_some()
        );
        assert_eq!(
            image.lookup_exact_plan(&owner, RecordType::Cname as u16, 255),
            ZoneImageLookupOutcome::NoData,
            "QCLASS=ANY exact lookup should use the same owner-local absent-type gate"
        );
    }

    #[test]
    fn semantic_planning_skips_absent_low_rrtype_exact_probe_but_keeps_cname_fallback() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let absent_low_type = RecordType::Hinfo as u16;

        assert!(!image.low_rrtype_may_exist(absent_low_type));
        let plan = image.lookup_response_plan(
            &alias,
            absent_low_type,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), [RecordType::Cname as u16]);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(&alias, absent_low_type, 1))
        );
    }

    #[test]
    fn semantic_planning_skips_indirection_probes_when_image_has_no_cname_or_dname_rrsets() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(54),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(!image.low_rrtype_may_exist(RecordType::Cname as u16));
        assert!(!image.low_rrtype_may_exist(RecordType::Dname as u16));
        let plan = image.lookup_response_plan(
            &owner,
            RecordType::Txt as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), []);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&owner, RecordType::Txt as u16, 1)
            )
        );
    }

    #[test]
    fn wildcard_planning_skips_absent_low_rrtype_and_absent_cname_probe() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    wildcard,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(!image.low_rrtype_may_exist(RecordType::Txt as u16));
        assert!(!image.low_rrtype_may_exist(RecordType::Cname as u16));
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Txt as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), []);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::Txt as u16, 1)
            )
        );
    }

    #[test]
    fn node_policy_hints_precompute_in_delegation_and_dname_covers() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_host = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let dname = DomainName::from_absolute_str("dname.example.test.").unwrap();
        let dname_host = DomainName::from_absolute_str("host.dname.example.test.").unwrap();
        let chaos = DomainName::from_absolute_str("chaos.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(52),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    dname.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    dname_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 2]],
                ),
                Rrset::new(
                    chaos.clone(),
                    RecordType::Ns as u16,
                    3,
                    300,
                    vec![name_rdata("ns.chaos.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_node = image.find_node(&child).expect("child node exists");
        let child_host_node = image
            .find_node(&child_host)
            .expect("child host node exists");
        let dname_node = image.find_node(&dname).expect("DNAME node exists");
        let dname_host_node = image
            .find_node(&dname_host)
            .expect("DNAME child node exists");
        let chaos_node = image.find_node(&chaos).expect("CHAOS node exists");

        let child_ns = image
            .find_rrset_at_node(child_node, RecordType::Ns as u16, 1)
            .expect("IN delegation exists");
        let dname_rrset = image
            .find_rrset_at_node(dname_node, RecordType::Dname as u16, 1)
            .expect("IN DNAME exists");
        let chaos_ns = image
            .find_rrset_at_node(chaos_node, RecordType::Ns as u16, 3)
            .expect("CHAOS delegation exists");

        assert_eq!(image.delegation_for_node(child_node, 1), Some(child_ns));
        assert_eq!(
            image.delegation_for_node(child_host_node, 1),
            Some(child_ns)
        );
        assert_eq!(image.delegation_for_node(chaos_node, 1), None);
        assert_eq!(image.delegation_for_node(chaos_node, 3), Some(chaos_ns));
        assert!(
            !image.any_class_delegation_policy_is_in_only,
            "non-IN delegation keeps QCLASS=ANY on conservative scan"
        );
        assert_eq!(image.delegation_for_node(chaos_node, 255), Some(chaos_ns));

        assert_eq!(image.dname_for_node(None, dname_node, 1), Some(dname_rrset));
        assert_eq!(image.dname_for_node(Some(dname_node), dname_node, 1), None);
        assert_eq!(
            image.dname_for_node(Some(dname_host_node), dname_host_node, 1),
            Some(dname_rrset)
        );
        assert!(image.covering_dname_blocks_direct_answer(dname_host_node, 1));

        let in_only_snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(53),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    dname.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    child_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 3]],
                ),
                Rrset::new(
                    dname_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 4]],
                ),
            ],
        );
        let in_only = ZoneImage::compile(&in_only_snapshot).expect("IN-only image compiles");
        let in_only_child_node = in_only
            .find_node(&child)
            .expect("IN-only child node exists");
        let in_only_child_host_node = in_only
            .find_node(&child_host)
            .expect("IN-only child host node exists");
        let in_only_dname_host_node = in_only
            .find_node(&dname_host)
            .expect("IN-only DNAME child node exists");
        let in_only_child_ns = in_only
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("IN-only child NS exists");
        let in_only_dname_rrset = in_only
            .find_rrset(&dname, RecordType::Dname as u16, 1)
            .expect("IN-only DNAME exists");
        assert!(in_only.any_class_delegation_policy_is_in_only);
        assert!(in_only.any_class_dname_policy_is_in_only);
        assert_eq!(
            in_only.delegation_for_node(in_only_child_host_node, 255),
            Some(in_only_child_ns)
        );
        assert!(
            !in_only.covering_delegation_blocks_direct_answer(
                in_only_child_node,
                RecordType::Ds as u16,
                255
            ),
            "DS at a delegation owner should use compiled policy ownership without blocking"
        );
        assert!(
            in_only.covering_delegation_blocks_direct_answer(
                in_only_child_host_node,
                RecordType::Ds as u16,
                255
            ),
            "DS below a delegation should still be blocked by the covering delegation"
        );
        assert_eq!(
            in_only.dname_for_node(Some(in_only_dname_host_node), in_only_dname_host_node, 255),
            Some(in_only_dname_rrset)
        );
        assert!(in_only.covering_dname_blocks_direct_answer(in_only_dname_host_node, 255));
    }

    #[test]
    fn ds_at_delegation_owner_uses_compiled_node_ownership() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let mixed_case_child = DomainName::from_absolute_str("CHILD.Example.TEST.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(51),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_node = image.find_node(&child).expect("child node exists");
        let child_ns = image
            .find_rrset_at_node(child_node, RecordType::Ns as u16, 1)
            .expect("IN delegation exists");
        assert_eq!(
            image.rrsets[child_ns.0 as usize].owner_label_count as usize,
            child.label_count()
        );

        let plan = image.lookup_response_plan(
            &mixed_case_child,
            RecordType::Ds as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(
            plan_answer_types(&image, &plan),
            vec![RecordType::Ds as u16]
        );
        assert!(plan.authority_rrsets().is_empty());
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &mixed_case_child,
                RecordType::Ds as u16,
                1
            ))
        );
        let any_plan = image.lookup_response_plan(
            &mixed_case_child,
            RecordType::Ds as u16,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &any_plan),
            vec![RecordType::Ds as u16]
        );
        assert!(any_plan.authority_rrsets().is_empty());

        let below_child = DomainName::from_absolute_str("below.child.example.test.").unwrap();
        let referral_plan = image.lookup_response_plan(
            &below_child,
            RecordType::Ds as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(referral_plan.answer_rrsets().is_empty());
        assert_eq!(referral_plan.authority_rrsets(), &[child_ns]);
        let any_referral_plan = image.lookup_response_plan(
            &below_child,
            RecordType::Ds as u16,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(any_referral_plan.answer_rrsets().is_empty());
        assert_eq!(any_referral_plan.authority_rrsets(), &[child_ns]);
    }

    #[test]
    fn referral_dnssec_uses_precomputed_delegation_proof_relations() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let secure_child = DomainName::from_absolute_str("secure.example.test.").unwrap();
        let mixed_secure_child = DomainName::from_absolute_str("SECURE.Example.TEST.").unwrap();
        let unsigned_child = DomainName::from_absolute_str("unsigned.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    secure_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.secure.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.secure.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    mixed_secure_child,
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
                Rrset::new(
                    unsigned_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.unsigned.example.test.")],
                ),
                Rrset::new(
                    unsigned_child.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let secure_ns = image
            .find_rrset(&secure_child, RecordType::Ns as u16, 1)
            .expect("secure child NS exists");
        let secure_ds = image
            .find_rrset(&secure_child, RecordType::Ds as u16, 1)
            .expect("secure child DS exists");
        let unsigned_ns = image
            .find_rrset(&unsigned_child, RecordType::Ns as u16, 1)
            .expect("unsigned child NS exists");
        let unsigned_nsec = image
            .find_rrset(&unsigned_child, RecordType::Nsec as u16, 1)
            .expect("unsigned child NSEC exists");

        let secure_relation = image
            .precomputed_referral_dnssec_rrset(secure_ns)
            .expect("secure child has precomputed DS proof relation");
        let secure_span = image
            .rrset_relation_span(image.rrsets[secure_ns.0 as usize].relation_span)
            .expect("secure child NS has a relation span");
        assert_eq!(secure_relation.kind, ImageRrsetRelationKind::DelegationDs);
        assert_eq!(secure_relation.rrset_id, secure_ds);
        assert_eq!(secure_span.single_name_target_offset, NO_RELATION_OFFSET);
        assert_eq!(secure_span.rrsig_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.additional_address_offset, NO_RELATION_OFFSET);
        assert_eq!(
            image
                .rrset_relations_of_kind(secure_ns, ImageRrsetRelationKind::ReferralGlue)
                .len(),
            1
        );
        assert_eq!(
            image
                .rrset_relations_of_kind(secure_ns, ImageRrsetRelationKind::DelegationDs)
                .len(),
            1
        );

        let unsigned_relation = image
            .precomputed_referral_dnssec_rrset(unsigned_ns)
            .expect("unsigned child has precomputed NSEC proof relation");
        assert_eq!(
            unsigned_relation.kind,
            ImageRrsetRelationKind::DelegationNsec
        );
        assert_eq!(unsigned_relation.rrset_id, unsigned_nsec);

        let qname = DomainName::from_absolute_str("www.secure.example.test.").unwrap();
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.referral_ns_rrset(), Some(secure_ns));
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert!(augmented.authority_rrsets().contains(&secure_ds));
    }

    #[test]
    fn referral_dnssec_relation_owner_key_is_built_from_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let secure_child = DomainName::from_absolute_str("secure.example.test.").unwrap();
        let mixed_secure_child = DomainName::from_absolute_str("SECURE.Example.TEST.").unwrap();
        let mut compressed = mixed_secure_child.to_wire();
        compressed[0] = 0xc0;
        let mut trailing = mixed_secure_child.to_wire();
        trailing.push(0);
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(153),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    mixed_secure_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.secure.example.test.")],
                ),
                Rrset::new(
                    secure_child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let secure_ns = image
            .find_rrset(&secure_child, RecordType::Ns as u16, 1)
            .expect("secure child NS exists");

        assert_eq!(
            canonical_key_from_uncompressed_wire(mixed_secure_child.to_wire().as_slice())
                .as_deref(),
            Some("secure.example.test.")
        );
        assert_eq!(canonical_key_from_uncompressed_wire(&compressed), None);
        assert_eq!(canonical_key_from_uncompressed_wire(&trailing), None);
        assert_eq!(
            image
                .precomputed_referral_dnssec_rrset(secure_ns)
                .expect("mixed-case NS owner finds DS by direct wire key")
                .kind,
            ImageRrsetRelationKind::DelegationDs
        );
    }

    #[test]
    fn referral_dnssec_requires_plan_referral_handle() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![1, 2, 3, 4]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_ns = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("child NS exists");
        let child_ds = image
            .find_rrset(&child, RecordType::Ds as u16, 1)
            .expect("child DS exists");
        let mut legacy_shape = ZoneImageLookupPlan::positive();
        legacy_shape.clear_flag(PLAN_FLAG_AUTHORITATIVE);
        image.push_authority_rrset_to_plan(&mut legacy_shape, child_ns);
        assert_eq!(legacy_shape.referral_ns_rrset(), None);

        let augmented = image.augment_lookup_plan_with_dnssec(
            legacy_shape,
            &DomainName::from_absolute_str("www.child.example.test.").unwrap(),
            1,
            100,
        );

        assert!(!augmented.authority_rrsets().contains(&child_ds));
    }

    #[test]
    fn referral_dnssec_nsec3_fallback_hashes_stored_owner_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let child_hash = nsec3_hash_domain(&child, params).expect("hash computes");
        let nsec3_owner =
            DomainName::from_absolute_str(&format!("{child_hash}.example.test.")).unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    nsec3_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_ns = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("child NS exists");
        let child_nsec3 = image
            .find_rrset(&nsec3_owner, RecordType::Nsec3 as u16, 1)
            .expect("child NSEC3 exists");
        assert!(
            image.precomputed_referral_dnssec_rrset(child_ns).is_none(),
            "fallback path should be exercised when no DS/NSEC relation exists"
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.referral_ns_rrset(), Some(child_ns));
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert!(augmented.authority_rrsets().contains(&child_nsec3));
    }

    #[test]
    fn dnssec_denial_helpers_skip_empty_range_families() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let nsec_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(69),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    origin.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("NSEC-only zone image compiles");
        let nsec = nsec_only
            .find_rrset(&origin, RecordType::Nsec as u16, 1)
            .expect("NSEC proof rrset exists");
        let mut plan = ZoneImageLookupPlan::nxdomain();
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        nsec_only.push_nsec3_for_name(&qname, 1, false, &mut plan, &mut state);
        assert!(plan.authority_rrsets.is_empty());
        assert!(state.appended_authority_rrsets.is_empty());
        assert!(!state.dnssec_augmented);
        let nxdomain_plan = nsec_only.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let augmented = nsec_only.augment_lookup_plan_with_dnssec(nxdomain_plan, &qname, 1, 100);
        assert!(
            augmented.authority_rrsets().contains(&nsec),
            "NSEC-only NXDOMAIN should skip NSEC3 helper entry and keep NSEC proof selection"
        );

        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let qname_hash = nsec3_hash_domain(&qname, params).expect("hash computes");
        let nsec3_owner =
            DomainName::from_absolute_str(&format!("{qname_hash}.example.test.")).unwrap();
        let nsec3_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(70),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 70]],
                ),
                Rrset::new(
                    nsec3_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        ))
        .expect("NSEC3-only zone image compiles");
        let mut plan = ZoneImageLookupPlan::nxdomain();
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        nsec3_only.push_nsec_covering_name(&qname, 1, &mut plan, &mut state);
        assert!(plan.authority_rrsets.is_empty());
        assert!(state.appended_authority_rrsets.is_empty());
        assert!(!state.dnssec_augmented);

        let nsec3 = nsec3_only
            .find_rrset(&nsec3_owner, RecordType::Nsec3 as u16, 1)
            .expect("NSEC3 proof rrset exists");
        let nodata_plan = nsec3_only.lookup_response_plan(
            &qname,
            RecordType::Aaaa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(nodata_plan.answer_rrsets().is_empty());
        let augmented = nsec3_only.augment_lookup_plan_with_dnssec(nodata_plan, &qname, 1, 100);
        assert!(
            augmented.authority_rrsets().contains(&nsec3),
            "NSEC3-only exact NODATA should skip exact NSEC probing and use the NSEC3 family"
        );
    }

    #[test]
    fn answer_additionals_use_precomputed_rrset_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let service = DomainName::from_absolute_str("service.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(46),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![
                        mx_rdata("mail.example.test."),
                        mx_rdata("mail.example.test."),
                    ],
                ),
                Rrset::new(
                    mail.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
                Rrset::new(
                    service.clone(),
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("missing-target.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let mx = image
            .find_rrset(&qname, RecordType::Mx as u16, 1)
            .expect("MX rrset exists");
        let precomputed = image.precomputed_additional_rrsets(mx).collect::<Vec<_>>();
        let span = image
            .rrset_relation_span(image.rrsets[mx.0 as usize].relation_span)
            .expect("MX has a relation span");

        assert_eq!(precomputed.len(), 1);
        assert_eq!(span.single_name_target_offset, NO_RELATION_OFFSET);
        assert_eq!(span.rrsig_offset, NO_RELATION_OFFSET);
        assert_eq!(span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_eq!(span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_ne!(span.additional_address_offset, NO_RELATION_OFFSET);
        assert!(image.has_precomputed_additional_address_relations(mx.0 as usize));
        assert_eq!(
            image.rrsets[precomputed[0].0 as usize].rr_type(),
            RecordType::A as u16
        );
        assert!(!image.has_precomputed_additional_address_relations(precomputed[0].0 as usize));

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Mx as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.additional_rrsets(), precomputed.as_slice());
        assert!(!plan.direct_answer_candidate());

        let address_plan = image.lookup_response_plan(
            &mail,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(address_plan.additional_rrsets().is_empty());
        assert!(address_plan.direct_answer_candidate());

        let srv = image
            .find_rrset(&service, RecordType::Srv as u16, 1)
            .expect("SRV rrset exists");
        assert!(!image.has_precomputed_additional_address_relations(srv.0 as usize));
        let plan_without_additionals = image.lookup_response_plan(
            &service,
            RecordType::Srv as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(plan_without_additionals.additional_rrsets().is_empty());
        assert_eq!(
            image
                .plan_summary(&plan_without_additionals)
                .expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&service, RecordType::Srv as u16, 1)
            )
        );
    }

    #[test]
    fn referral_glue_uses_precomputed_delegation_filtered_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let sibling_ns = DomainName::from_absolute_str("ns.sibling.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(49),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        name_rdata("ns.child.example.test."),
                        name_rdata("ns.child.example.test."),
                        name_rdata("ns.sibling.example.test."),
                    ],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    sibling_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let ns_rrset = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("delegation NS rrset exists");
        let glue = image
            .precomputed_referral_glue_rrsets(ns_rrset)
            .collect::<Vec<_>>();

        assert_eq!(glue.len(), 1);
        assert_eq!(
            image.rrset_owner_wire(glue[0]).expect("glue owner wire"),
            name_rdata("ns.child.example.test.").as_slice()
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.authority_rrsets(), &[ns_rrset]);
        assert_eq!(plan.additional_rrsets(), glue.as_slice());
    }

    #[test]
    fn referral_glue_delegation_owner_filter_uses_stored_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("CHILD.Example.TEST.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let sibling_ns = DomainName::from_absolute_str("ns.sibling.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(149),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        name_rdata("NS.Child.Example.TEST."),
                        name_rdata("ns.sibling.example.test."),
                    ],
                ),
                Rrset::new(
                    child_ns.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    sibling_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let ns_rrset = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("delegation NS rrset exists");
        let owner_wire = image
            .rrset_owner_wire(ns_rrset)
            .expect("delegation owner wire");
        let mut trailing = owner_wire.to_vec();
        trailing.push(0);
        let glue = image
            .precomputed_referral_glue_rrsets(ns_rrset)
            .collect::<Vec<_>>();
        let child_ns_wire = child_ns.to_wire();
        let sibling_ns_wire = DomainName::from_absolute_str("ns.sibling.example.test.")
            .unwrap()
            .to_wire();

        assert!(wire_name_is_equal_or_subdomain_of_wire(
            &child_ns_wire,
            owner_wire,
            child.label_count(),
        ));
        assert!(!wire_name_is_equal_or_subdomain_of_wire(
            &sibling_ns_wire,
            owner_wire,
            child.label_count(),
        ));
        assert!(!wire_name_is_equal_or_subdomain_of_wire(
            &child_ns_wire,
            &trailing,
            child.label_count(),
        ));
        assert_eq!(glue.len(), 1);
        assert_eq!(
            image.rrset_owner_wire(glue[0]).expect("glue owner wire"),
            child_ns.to_wire().as_slice()
        );
    }

    #[test]
    fn nsec_covering_lookup_uses_precomputed_range_keys() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("a.example.test.").unwrap();
        let covered = DomainName::from_absolute_str("M.Example.TEST.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(52),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec = image
            .find_rrset(&owner, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");

        assert_eq!(image.nsec_ranges.len(), 1);
        assert_eq!(image.nsec_ranges[0].rrset_id, nsec);
        assert_eq!(image.nsec_rrset_covering_name(&covered, 1), Some(nsec));
    }

    #[test]
    fn nsec_canonical_order_keys_are_built_directly_from_wire_names() {
        let owner_wire = DomainName::from_absolute_str("A.Example.TEST.")
            .unwrap()
            .to_wire();
        let mut names = owner_wire.clone();
        let owner_key = push_canonical_order_name_arena_key(
            &mut names,
            BlobRange {
                offset: 0,
                len: owner_wire.len() as u32,
            },
            "names",
        )
        .expect("owner wire key builds")
        .expect("owner wire is valid");
        assert_eq!(
            blob_from_arena(&names, owner_key),
            b"\x04test\x07example\x01a\x00"
        );

        let mut rdata = nsec_rdata("Z.Example.TEST.");
        let mut arena = Vec::new();
        let next_key = push_canonical_order_wire_key(&mut arena, &rdata, false, "names")
            .expect("next-owner wire key builds")
            .expect("next owner is valid");
        assert_eq!(
            blob_from_arena(&arena, next_key),
            b"\x04test\x07example\x01z\x00"
        );
        assert!(
            push_canonical_order_wire_key(&mut arena, &rdata, true, "names")
                .expect("trailing NSEC bitmap is handled")
                .is_none(),
            "full-name mode rejects trailing NSEC bitmap bytes"
        );

        rdata[0] = 0xc0;
        assert!(
            push_canonical_order_wire_key(&mut arena, &rdata, false, "names")
                .expect("compressed NSEC next-owner wire is rejected without build error")
                .is_none()
        );
    }

    #[test]
    fn dnssec_authority_augmentation_seeds_existing_rrset_dedupe() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("a.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(69),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    owner.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let soa = image
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA exists");
        let nsec = image
            .find_rrset(&owner, RecordType::Nsec as u16, 1)
            .expect("NSEC exists");
        let mut plan = ZoneImageLookupPlan::nodata();
        plan.push_authority_rrset(soa, image.rrset_plan_metrics(soa));
        plan.push_authority_rrset(nsec, image.rrset_plan_metrics(nsec));

        let augmented = image.augment_lookup_plan_with_dnssec(plan, &owner, 1, 100);

        assert_eq!(
            augmented
                .authority_rrsets()
                .iter()
                .filter(|rrset| **rrset == nsec)
                .count(),
            1,
            "DNSSEC authority dedupe is seeded from existing authority rrsets"
        );
    }

    #[test]
    fn nsec3_hash_cache_reuses_hash_for_matching_parameters() {
        let name = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        let canonical = name.to_canonical_wire();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 2,
            salt: &[0xaa, 0xbb],
        };
        let mut cache = SmallVec::<[(Nsec3Params<'_>, Option<[u8; 20]>); 1]>::new();

        let canonical_hash = nsec3_hash_canonical_wire(&canonical, params)
            .and_then(|hash| base32hex_no_padding_decode_lower(hash.as_bytes()))
            .expect("NSEC3 hash computes");
        let first_index = nsec3_hash_domain_cache_index(&name, params, &mut cache);
        let first = cache[first_index].1.expect("NSEC3 hash computes");
        let second_index = nsec3_hash_domain_cache_index(&name, params, &mut cache);
        let second = cache[second_index].1.expect("cached NSEC3 hash computes");

        assert_eq!(first.as_slice(), canonical_hash.as_slice());
        assert_eq!(first, second);
        assert_eq!(first_index, second_index);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn nsec3_owner_hash_bytes_decodes_owner_label_without_allocating() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x25; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), Some(hash));
    }

    #[test]
    fn nsec3_owner_hash_bytes_matches_origin_suffix_case_insensitively() {
        let origin = DomainName::from_absolute_str("Example.TEST.").unwrap();
        let hash = [0xa5; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), Some(hash));
    }

    #[test]
    fn nsec3_owner_hash_bytes_rejects_extra_owner_prefix_labels() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x5a; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner =
            DomainName::from_absolute_str(&format!("extra.{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), None);
    }

    #[test]
    fn nsec3_owner_wire_hash_bytes_rejects_malformed_or_compressed_owner_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x3c; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();
        let mut trailing = owner.to_wire();
        trailing.push(0);
        let mut compressed_suffix = Vec::with_capacity(hash_label.len() + 3);
        compressed_suffix.push(hash_label.len() as u8);
        compressed_suffix.extend_from_slice(hash_label.as_bytes());
        compressed_suffix.extend_from_slice(&[0xc0, 0x0c]);

        assert_eq!(nsec3_owner_wire_hash_bytes(&trailing, &origin), None);
        assert_eq!(
            nsec3_owner_wire_hash_bytes(&compressed_suffix, &origin),
            None
        );
    }

    #[test]
    fn nsec3_lookup_uses_precomputed_range_metadata() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let other_qname = DomainName::from_absolute_str("other.example.test.").unwrap();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let owner_hash = nsec3_hash_domain(&qname, params).expect("hash computes");
        let other_owner_hash = nsec3_hash_domain(&other_qname, params).expect("hash computes");
        let owner = DomainName::from_absolute_str(&format!("{owner_hash}.example.test.")).unwrap();
        let other_owner =
            DomainName::from_absolute_str(&format!("{other_owner_hash}.example.test.")).unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
                Rrset::new(
                    other_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec3 = image
            .find_rrset(&owner, RecordType::Nsec3 as u16, 1)
            .expect("NSEC3 rrset exists");
        let mut iterations_exceeded = false;

        assert_eq!(image.nsec3_ranges.len(), 2);
        assert_eq!(image.nsec3_param_sets.len(), 1);
        assert!(
            image.nsec3_ranges.iter().all(|range| range.param_set == 0),
            "NSEC3 ranges with shared algorithm/iterations/salt should share one parameter set"
        );
        let range = image
            .nsec3_ranges
            .iter()
            .find(|range| range.rrset_id == nsec3)
            .expect("compiled NSEC3 range for queried owner exists");
        assert_eq!(
            range.owner_hash,
            base32hex_sha1_no_padding_decode_lower(owner_hash.as_bytes())
                .expect("owner hash decodes")
        );
        assert_eq!(
            image.nsec3_rrset_for_name(&qname, 1, &mut iterations_exceeded, 100, false),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_name(&qname, 1, &mut iterations_exceeded, 100, true),
            Some(nsec3),
            "lowercase-hinted NSEC3 hashing must match the conservative path"
        );
        assert_eq!(
            image.nsec3_rrset_for_label_view(
                NameLabelView {
                    prefix: None,
                    labels: qname.labels(),
                    ascii_lowercase: false,
                },
                1,
                &mut iterations_exceeded,
                100,
            ),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_label_view(
                NameLabelView {
                    prefix: None,
                    labels: qname.labels(),
                    ascii_lowercase: true,
                },
                1,
                &mut iterations_exceeded,
                100,
            ),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_wire_name(&qname.to_wire(), 1, &mut iterations_exceeded, 100),
            Some(nsec3)
        );
        assert!(!iterations_exceeded);
    }

    #[test]
    fn widest_child_lookup_profile_exports_sorted_max_fanout_labels() {
        let image = ZoneImage::compile(&sample_snapshot()).expect("zone image compiles");
        let profile = image
            .widest_child_lookup_profile()
            .expect("profile exists for non-empty image");

        assert!(profile.fanout >= 2);
        assert_eq!(profile.fanout, profile.labels.len());
        assert!(
            profile
                .labels
                .windows(2)
                .all(|labels| labels[0] < labels[1])
        );
    }

    #[test]
    fn closest_encloser_proof_name_uses_compiled_trie_depth() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("absent.ent.example.test.").unwrap();
        let (_, closest_node) = image.query_node_handles(&qname, true);

        assert_eq!(
            image.closest_encloser_proof_name(&qname),
            Some(DomainName::from_absolute_str("ent.example.test.").unwrap())
        );
        assert_eq!(
            image.closest_encloser_proof_name_from_node(&qname, closest_node),
            Some(DomainName::from_absolute_str("ent.example.test.").unwrap())
        );
        assert_eq!(
            image
                .closest_encloser_labels_from_node(&qname, closest_node)
                .expect("closest labels"),
            DomainName::from_absolute_str("ent.example.test.")
                .unwrap()
                .labels()
        );
        assert_eq!(
            image.closest_encloser_proof_name(
                &DomainName::from_absolute_str("absent.wild.example.test.").unwrap()
            ),
            Some(DomainName::from_absolute_str("wild.example.test.").unwrap())
        );
        assert_eq!(
            image.closest_encloser_proof_name(
                &DomainName::from_absolute_str("absent.example.test.").unwrap()
            ),
            Some(DomainName::from_absolute_str("example.test.").unwrap())
        );
    }

    #[test]
    fn query_node_handles_return_exact_and_closest_in_one_walk() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let exact = image
            .find_node(&DomainName::from_absolute_str("ent.example.test.").unwrap())
            .expect("exact node exists");
        let root = image
            .find_node(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("root node exists");

        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("ent.example.test.").unwrap(),
                true,
            ),
            (Some(exact), Some(exact))
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("absent.ent.example.test.").unwrap(),
                true,
            ),
            (None, Some(exact))
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("outside.example.invalid.").unwrap(),
                true,
            ),
            (None, None)
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("example.test.").unwrap(),
                true,
            ),
            (Some(root), Some(root))
        );
    }

    #[test]
    fn query_node_handles_lowercase_hint_matches_canonical_path() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let lowercase = DomainName::from_absolute_str("ent.example.test.").unwrap();
        let mixed_case = DomainName::from_absolute_str("ENT.Example.Test.").unwrap();

        assert_eq!(
            image.query_node_handles(&lowercase, true),
            image.query_node_handles(&mixed_case, false)
        );
        assert_eq!(
            image.lookup_response_plan_with_ascii_lowercase_hint(
                &lowercase,
                RecordType::A as u16,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
                true,
            ),
            image.lookup_response_plan(
                &mixed_case,
                RecordType::A as u16,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            )
        );
        assert_eq!(
            image.lookup_direct_answer_plan_with_ascii_lowercase_hint(
                &lowercase,
                RecordType::A as u16,
                1,
                true,
            ),
            image.lookup_direct_answer_plan(&mixed_case, RecordType::A as u16, 1)
        );
    }

    #[test]
    fn single_child_lookup_uses_case_insensitive_direct_edge_check() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let single = DomainName::from_absolute_str("only.example.test.").unwrap();
        let image = ZoneImage::compile(&ZoneSnapshot::active(
            origin,
            Some(55),
            vec![Rrset::new(
                single,
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 55]],
            )],
        ))
        .expect("single-child image compiles");

        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("ONLY.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("other.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn small_child_lookup_uses_case_insensitive_linear_scan() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let image = ZoneImage::compile(&ZoneSnapshot::active(
            origin,
            Some(56),
            ["alpha", "bravo", "charlie", "delta"]
                .into_iter()
                .map(|label| {
                    Rrset::new(
                        DomainName::from_absolute_str(&format!("{label}.example.test.")).unwrap(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![192, 0, 2, 56]],
                    )
                })
                .collect(),
        ))
        .expect("small-child image compiles");

        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("CHARLIE.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("echo.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn high_fanout_child_hash_index_preserves_exact_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let mut rrsets = vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            600,
            vec![soa_rdata()],
        )];
        for index in 0..CHILD_HASH_FANOUT_THRESHOLD {
            rrsets.push(Rrset::new(
                DomainName::from_absolute_str(&format!("host{index}.example.test.")).unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 1]],
            ));
        }
        let image =
            ZoneImage::compile(&ZoneSnapshot::active(origin, Some(54), rrsets)).expect("compiles");

        assert_eq!(image.child_hashes.len(), 1);
        assert_eq!(image.nodes[0].child_hash, 0);
        assert!(image.child_hash_slots.len() >= CHILD_HASH_FANOUT_THRESHOLD);
        for qname in [
            "host0.example.test.",
            "HOST0.example.test.",
            "host512.example.test.",
            "host1023.example.test.",
        ] {
            assert!(matches!(
                image.lookup_exact_plan(
                    &DomainName::from_absolute_str(qname).unwrap(),
                    RecordType::A as u16,
                    1,
                ),
                ZoneImageLookupOutcome::Found(_)
            ));
        }
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("absent.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn single_name_target_precompute_uses_whole_uncompressed_wire_names() {
        let target = DomainName::from_absolute_str("Target.Example.TEST.").unwrap();
        let target_wire = target.to_wire();
        assert_eq!(single_name_rdata_bytes(&target_wire), Some(target));

        let mut trailing = target_wire.clone();
        trailing.push(0);
        assert_eq!(single_name_rdata_bytes(&trailing), None);
        assert_eq!(single_name_rdata_bytes(&[0xc0, 0x00]), None);
    }

    #[test]
    fn cname_and_dname_targets_use_precomputed_single_name_table() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let dname_target = DomainName::from_absolute_str("target-tree.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(50),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    alias.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Cname)],
                ),
                Rrset::new(
                    target.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target-tree.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 20]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let cname_rrset = image
            .find_rrset(&alias, RecordType::Cname as u16, 1)
            .expect("CNAME rrset exists");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        assert_eq!(
            image.rrsets[dname_rrset.0 as usize].owner_label_count as usize,
            subtree.labels().len()
        );

        let cname_target = image
            .single_name_rrset_target(cname_rrset)
            .expect("CNAME target is precomputed");
        let cname_span = image
            .rrset_relation_span(image.rrsets[cname_rrset.0 as usize].relation_span)
            .expect("CNAME has a relation span");
        let target_wire = target.to_wire();
        assert_eq!(cname_target.name, target);
        assert_eq!(image.single_name_target_wire(cname_target), target_wire);
        assert_eq!(image.rdata_blob(cname_target.rdata), target_wire.as_slice());
        assert_eq!(cname_span.single_name_target_offset, 0);
        assert_ne!(cname_span.rrsig_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.additional_address_offset, NO_RELATION_OFFSET);
        assert_eq!(
            image
                .rrset_relations_of_kind(cname_rrset, ImageRrsetRelationKind::SingleNameTarget)
                .len(),
            1
        );
        assert_eq!(
            image
                .rrset_relations_of_kind(cname_rrset, ImageRrsetRelationKind::Rrsig)
                .len(),
            1
        );
        assert_eq!(
            cname_target.node_hint,
            ImageTargetNode::InZoneNode(image.find_node(&target).expect("target node exists"))
        );

        let dname_target_ref = image
            .single_name_rrset_target(dname_rrset)
            .expect("DNAME target is precomputed");
        assert_eq!(dname_target_ref.name, dname_target);
        assert_eq!(
            dname_target_ref.node_hint,
            ImageTargetNode::InZoneNode(
                image
                    .find_node(&dname_target)
                    .expect("DNAME replacement target node exists")
            )
        );
        assert_eq!(
            dname_query.with_replaced_wire_suffix(
                image
                    .rrset_owner_wire(dname_rrset)
                    .expect("DNAME owner wire"),
                &dname_target_ref.name,
            ),
            Some(DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap())
        );

        let cname_plan = image.lookup_response_plan(
            &alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            image.plan_summary(&cname_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::A as u16, 1)
            )
        );

        let dname_plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(dname_plan.dynamic_answers.len(), 1);
        let synthesized = &dname_plan.dynamic_answers[0];
        assert_eq!(
            synthesized.fixed_fields,
            synthesized_cname_fixed_fields_from_rrset(image.rrsets[dname_rrset.0 as usize])
        );
        assert_eq!(
            synthesized.rdata_encoding,
            PackedRdataEncoding::single_name(),
            "DNAME synthesized CNAME RDATA should carry the checked single-name encoding"
        );
        assert!(
            !synthesized.owner_wire.spilled(),
            "common DNAME synthesized owner wire should stay inline"
        );
        assert!(
            !synthesized.rdata.spilled(),
            "common DNAME synthesized target wire should stay inline"
        );
        assert_eq!(
            synthesized.rdata.as_slice(),
            DomainName::from_absolute_str("leaf.target-tree.example.test.")
                .unwrap()
                .to_wire()
                .as_slice()
        );
        assert_eq!(
            image.plan_summary(&dname_plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }

    #[test]
    fn dname_target_resolution_preserves_existing_target_nodata() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let generated_target =
            DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(62),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target-tree.example.test.")],
                ),
                Rrset::new(
                    generated_target,
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        assert!(
            !image.low_rrtype_may_exist(RecordType::A as u16),
            "the DNAME target-resolution exact probe can be skipped for absent low RR types"
        );
        assert!(
            !image.low_rrtype_may_exist(RecordType::Cname as u16),
            "the DNAME target-resolution CNAME fallback can be skipped when the image has no CNAME RRsets"
        );

        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }

    #[test]
    fn dname_out_of_zone_literal_target_can_synthesize_in_zone_target() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("example.alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        assert_eq!(
            image
                .single_name_rrset_target(dname_rrset)
                .expect("DNAME target precomputes")
                .node_hint,
            ImageTargetNode::OutOfZoneParentSuffix
        );

        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::Soa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            plan.dynamic_answers[0].rdata.as_slice(),
            origin.to_wire().as_slice()
        );
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::Soa as u16,
                1
            ))
        );
    }

    #[test]
    fn unrelated_out_of_zone_dname_target_stays_out_of_zone_without_synthesized_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("invalid.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        let target = image
            .single_name_rrset_target(dname_rrset)
            .expect("DNAME target precomputes");

        assert_eq!(target.node_hint, ImageTargetNode::OutOfZone);
        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            plan.dynamic_answers[0].rdata.as_slice(),
            DomainName::from_absolute_str("leaf.invalid.")
                .unwrap()
                .to_wire()
                .as_slice()
        );
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }

    #[test]
    fn cname_loop_tracking_borrows_original_query_name() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("ALIAS.Example.TEST.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let mixed_case_alias = DomainName::from_absolute_str("Alias.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &mixed_case_alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.termination(), Some(LookupTermination::CnameLoop));
        assert_eq!(
            plan.section_record_counts().0,
            1,
            "partial CNAME chain is preserved on loop"
        );
        assert_eq!(
            plan.response_body_wire_upper_bound(),
            image.plan_wire_upper_bound(&plan),
            "SERVFAIL conversion preserves the carried answer body bound"
        );
        assert_eq!(
            plan.total_record_count(),
            plan.section_record_counts().0,
            "SERVFAIL conversion derives total count from the remaining partial-answer count"
        );
    }

    #[test]
    fn cname_loop_tracking_detects_existing_target_node_cycle() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let first = DomainName::from_absolute_str("first.example.test.").unwrap();
        let second = DomainName::from_absolute_str("second.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    first.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("second.example.test.")],
                ),
                Rrset::new(
                    second,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("first.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let plan = image.lookup_response_plan(
            &first,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.termination(), Some(LookupTermination::CnameLoop));
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&first, RecordType::A as u16, 1)
            )
        );
    }

    #[test]
    fn dnssec_rrsig_augmentation_uses_precomputed_record_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(47),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![
                        rrsig_rdata(RecordType::A),
                        rrsig_rdata(RecordType::Rrsig),
                        rrsig_rdata(RecordType::Nsec),
                    ],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let a_rrset = image
            .find_rrset(&qname, RecordType::A as u16, 1)
            .expect("A rrset exists");
        let precomputed = image.precomputed_rrsig_records(a_rrset).collect::<Vec<_>>();
        let rrsig_rrset = image
            .find_rrset(&qname, RecordType::Rrsig as u16, 1)
            .expect("RRSIG rrset exists");

        assert_eq!(precomputed.len(), 1);
        assert!(image.has_precomputed_rrsig_relations(a_rrset.0 as usize));
        assert!(!image.has_precomputed_rrsig_relations(rrsig_rrset.0 as usize));
        assert!(
            image
                .precomputed_rrsig_records(rrsig_rrset)
                .next()
                .is_none(),
            "compile-time relation builder should not emit selected RRSIG relations for an RRSIG RRset"
        );
        assert_eq!(
            rrsig_type_covered_rdata(
                image.blob(
                    &image.rdata,
                    image.records[precomputed[0].record_index as usize]
                        .rdata
                        .blob_range(),
                ),
            ),
            Some(RecordType::A as u16)
        );
        let rrsig_record = image.records[precomputed[0].record_index as usize];
        let expected_wire_len = image
            .blob(
                &image.names,
                image.rrsets[precomputed[0].rrset_id.0 as usize].owner_wire,
            )
            .len()
            .saturating_add(10)
            .saturating_add(rrsig_record.rdata.len());
        assert_eq!(precomputed[0].rdata_len as usize, rrsig_record.rdata.len());
        assert_eq!(
            precomputed[0].owner_wire_len as usize,
            image
                .blob(
                    &image.names,
                    image.rrsets[precomputed[0].rrset_id.0 as usize].owner_wire
                )
                .len()
        );
        assert_eq!(
            image.selected_record_from_relation(precomputed[0]).wire_len as usize,
            expected_wire_len
        );
        assert_eq!(
            image
                .selected_record_from_relation(precomputed[0])
                .fixed_fields,
            image.rrsets[precomputed[0].rrset_id.0 as usize].fixed_fields,
            "selected DNSSEC handles should carry immutable fixed fields"
        );
        assert_eq!(
            image.selected_record_from_relation(precomputed[0]).rdata,
            rrsig_record.rdata,
            "selected DNSSEC handles should carry the immutable RDATA range"
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(augmented.synthesized_answer_count(), 0);
        assert_eq!(augmented.dynamic_answers.len(), 0);
        let [.., PlanAnswer::SelectedRecord(selected)] = augmented.answer_items.as_slice() else {
            panic!("expected selected RRSIG answer record");
        };
        let signature = image.selected_wire_record(*selected);
        assert_eq!(selected.fixed_fields, signature.fixed_fields);
        assert_eq!(selected.rdata.rdlength_bytes(), signature.rdlength_bytes);
        assert_eq!(selected.rdata.rdata_encoding, signature.rdata_encoding);
        assert_eq!(
            u16::from_be_bytes([signature.fixed_fields[0], signature.fixed_fields[1]]),
            RecordType::Rrsig as u16
        );
        assert_eq!(
            selected.wire_len as usize,
            signature
                .owner_wire
                .len()
                .saturating_add(10)
                .saturating_add(signature.rdata.len())
        );
        assert_eq!(
            image.selected_record_wire_len(*selected),
            selected.wire_len as usize
        );
        assert_eq!(
            rrsig_type_covered_rdata(signature.rdata),
            Some(RecordType::A as u16)
        );

        let rrsig_plan = image.lookup_response_plan(
            &qname,
            RecordType::Rrsig as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let rrsig_augmented = image.augment_lookup_plan_with_dnssec(rrsig_plan, &qname, 1, 100);
        assert!(
            !rrsig_augmented
                .answer_items
                .iter()
                .any(|item| matches!(item, PlanAnswer::SelectedRecord(_))),
            "RRSIG query augmentation should rely on the empty compiled relation slice, not a runtime RRset-type guard"
        );
    }

    #[test]
    fn dnssec_rrsig_augmentation_deduplicates_selected_record_handles() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(48),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
                    ]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A), rrsig_rdata(RecordType::Aaaa)],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let a_rrset = image
            .find_rrset(&qname, RecordType::A as u16, 1)
            .expect("A rrset exists");
        let aaaa_rrset = image
            .find_rrset(&qname, RecordType::Aaaa as u16, 1)
            .expect("AAAA rrset exists");
        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_answer_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));
        plan.push_authority_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));

        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(selected_answer_count(&augmented.answer_items), 1);
        assert_eq!(augmented.dynamic_answers.len(), 0);
        assert_eq!(augmented.selected_authorities.len(), 0);
        assert_eq!(augmented.selected_additionals.len(), 0);

        let mut section_plan = ZoneImageLookupPlan::positive();
        section_plan.push_authority_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));
        section_plan.push_additional_rrset(aaaa_rrset, image.rrset_plan_metrics(aaaa_rrset));
        let section_augmented = image.augment_lookup_plan_with_dnssec(section_plan, &qname, 1, 100);

        assert_eq!(selected_answer_count(&section_augmented.answer_items), 0);
        assert_eq!(section_augmented.dynamic_answers.len(), 0);
        assert_eq!(section_augmented.selected_authorities.len(), 1);
        assert_eq!(section_augmented.selected_additionals.len(), 1);
        let authority_signature =
            image.selected_wire_record(section_augmented.selected_authorities[0]);
        let additional_signature =
            image.selected_wire_record(section_augmented.selected_additionals[0]);
        assert_eq!(
            rrsig_type_covered_rdata(authority_signature.rdata),
            Some(RecordType::A as u16)
        );
        assert_eq!(
            rrsig_type_covered_rdata(additional_signature.rdata),
            Some(RecordType::Aaaa as u16)
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
        assert_eq!(
            stats.child_hash_slot_bytes,
            stats.child_hash_slot_count * mem::size_of::<u16>()
        );
        assert!(stats.max_child_fanout >= 1);
        assert!(stats.max_rrsets_per_name >= 1);
        assert!(stats.max_depth >= 1);
        assert!(stats.rdata_bytes > 0);
        assert!(stats.wire_bytes > stats.rdata_bytes);
        assert!(stats.hot_bytes > 0);
        assert!(stats.cold_bytes > 0);
        assert!(stats.bytes_per_record > 0);
        let apex_soa = image
            .find_rrset_at_node(0, RecordType::Soa as u16, 1)
            .expect("sample apex SOA is indexed");
        assert_eq!(image.apex_in_soa_rrset, Some(apex_soa));
        assert_eq!(image.soa_rrset(1), Some(apex_soa));
        assert_eq!(image.soa_rrset(255), Some(apex_soa));
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
        let snapshot_lookup = snapshot.offline_oracle().lookup(qname, rr_type, qclass);
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
                    zone_image_record_fixed_fields(record.rr_type, record.class, record.ttl),
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
                .map(|rrset_id| image.rrsets[rrset_id.0 as usize].rr_type())
                .collect();
        }
        plan.answer_items
            .iter()
            .map(|item| {
                let rrset_id = match item {
                    PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                        rrset_id
                    }
                    PlanAnswer::DynamicRecord(_) | PlanAnswer::SelectedRecord(_) => {
                        panic!("expected rrset answer")
                    }
                };
                image.rrsets[rrset_id.0 as usize].rr_type()
            })
            .collect()
    }

    fn plan_answer_classes_types(image: &ZoneImage, plan: &ZoneImageLookupPlan) -> Vec<(u16, u16)> {
        if plan.answer_items.is_empty() {
            return plan
                .answer_rrsets()
                .iter()
                .map(|rrset_id| {
                    let rrset = image.rrsets[rrset_id.0 as usize];
                    (rrset.class(), rrset.rr_type())
                })
                .collect();
        }
        plan.answer_items
            .iter()
            .map(|item| {
                let rrset_id = match item {
                    PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                        rrset_id
                    }
                    PlanAnswer::DynamicRecord(_) | PlanAnswer::SelectedRecord(_) => {
                        panic!("expected rrset answer")
                    }
                };
                let rrset = image.rrsets[rrset_id.0 as usize];
                (rrset.class(), rrset.rr_type())
            })
            .collect()
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        DomainName::from_absolute_str(name).unwrap().to_wire()
    }

    fn selected_answer_count(items: &[PlanAnswer]) -> usize {
        items
            .iter()
            .filter(|item| matches!(item, PlanAnswer::SelectedRecord(_)))
            .count()
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

    fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
        let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 5, 0, 3]);
        rdata.extend_from_slice(&300u32.to_be_bytes());
        rdata.extend_from_slice(&0u32.to_be_bytes());
        rdata.extend_from_slice(&0u32.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(
            &DomainName::from_absolute_str("example.test.")
                .unwrap()
                .to_wire(),
        );
        rdata.extend_from_slice(b"signature");
        rdata
    }

    fn nsec3_rdata_with_next_hash(
        hash_algorithm: u8,
        iterations: u16,
        salt: &[u8],
        next_hash: &[u8],
    ) -> Vec<u8> {
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&iterations.to_be_bytes());
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(next_hash);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn nsec_rdata(next_owner: &str) -> Vec<u8> {
        let mut rdata = DomainName::from_absolute_str(next_owner).unwrap().to_wire();
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
}
