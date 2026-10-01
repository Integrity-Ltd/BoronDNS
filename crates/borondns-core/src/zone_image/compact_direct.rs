//! Experimental serving-only descriptors. The ordinary resolver remains the
//! fallback; this index never decides zone authority or negative answers.
use super::*;
#[cfg(feature = "experimental-dense-answers")]
use std::sync::Arc;

const KEY_BYTES: usize = 24;
const MAX_PROBES: usize = 4;

#[cfg(feature = "experimental-fused-serving")]
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "experimental-dense-answers"), derive(Copy))]
pub(crate) struct FusedDirectAnswer {
    // By default every eligible body is inline. Dense storage keeps <=64-byte
    // bodies inline and shares longer bodies. Beyond MAX_BODY_LEN the ordinary
    // compact/general resolver remains available; this is not a DNS limit.
    #[cfg(not(feature = "experimental-dense-answers"))]
    body: [u8; Self::MAX_BODY_LEN],
    #[cfg(feature = "experimental-dense-answers")]
    body: DenseAnswerBody,
    body_len: u8,
    count: u16,
}

/// Up to four A records stay in the hash bucket. Longer templates
/// retain the same eligibility limit, but do not enlarge every bucket. Their
/// immutable allocation is shared only when a directory shard is copied.
#[cfg(feature = "experimental-dense-answers")]
#[derive(Debug, Clone)]
#[cfg(not(feature = "experimental-compact-a-answers"))]
enum DenseAnswerBody {
    Inline([u8; 64]),
    Overflow(Arc<[u8]>),
}

#[cfg(feature = "experimental-compact-a-answers")]
#[derive(Debug, Clone)]
enum DenseAnswerBody {
    Inline([u8; 32]),
    CompactA { ttl: [u8; 4], addresses: [u8; 32] },
    Overflow(Arc<[u8]>),
}

#[cfg(feature = "experimental-fused-serving")]
impl FusedDirectAnswer {
    pub(crate) const MAX_BODY_LEN: usize = 128;

    pub(crate) fn new(body: &[u8], count: u16) -> Option<Self> {
        if body.len() > Self::MAX_BODY_LEN {
            return None;
        }
        #[cfg(not(feature = "experimental-dense-answers"))]
        let storage = {
            let mut inline = [0; Self::MAX_BODY_LEN];
            inline[..body.len()].copy_from_slice(body);
            inline
        };
        #[cfg(all(
            feature = "experimental-dense-answers",
            not(feature = "experimental-compact-a-answers")
        ))]
        let storage = if body.len() <= 64 {
            let mut inline = [0; 64];
            inline[..body.len()].copy_from_slice(body);
            DenseAnswerBody::Inline(inline)
        } else {
            DenseAnswerBody::Overflow(Arc::from(body))
        };
        #[cfg(feature = "experimental-compact-a-answers")]
        let storage = if let Some((ttl, addresses)) = compact_a_body(body, count) {
            DenseAnswerBody::CompactA { ttl, addresses }
        } else if body.len() <= 32 {
            let mut inline = [0; 32];
            inline[..body.len()].copy_from_slice(body);
            DenseAnswerBody::Inline(inline)
        } else {
            DenseAnswerBody::Overflow(Arc::from(body))
        };
        Some(Self {
            body: storage,
            body_len: body.len() as u8,
            count,
        })
    }
    pub(crate) fn view(&self) -> ZoneImageDirectRrset<'_> {
        #[cfg(not(feature = "experimental-dense-answers"))]
        let body = ZoneImageDirectRrsetBody::Template(&self.body[..usize::from(self.body_len)]);
        #[cfg(all(
            feature = "experimental-dense-answers",
            not(feature = "experimental-compact-a-answers")
        ))]
        let body = ZoneImageDirectRrsetBody::Template(match &self.body {
            DenseAnswerBody::Inline(bytes) => &bytes[..usize::from(self.body_len)],
            DenseAnswerBody::Overflow(bytes) => bytes,
        });
        #[cfg(feature = "experimental-compact-a-answers")]
        let body = match &self.body {
            DenseAnswerBody::Inline(bytes) => {
                ZoneImageDirectRrsetBody::Template(&bytes[..usize::from(self.body_len)])
            }
            DenseAnswerBody::CompactA { ttl, addresses } => ZoneImageDirectRrsetBody::CompactA {
                ttl: *ttl,
                addresses: &addresses[..usize::from(self.count) * 4],
            },
            DenseAnswerBody::Overflow(bytes) => ZoneImageDirectRrsetBody::Template(bytes),
        };
        ZoneImageDirectRrset {
            body_wire_len: usize::from(self.body_len),
            section_count_header_bytes: section_count_header_bytes(self.count, 0, 0),
            section_count_header_bytes_with_edns: section_count_header_bytes(self.count, 0, 1),
            body,
        }
    }
}

#[cfg(feature = "experimental-compact-a-answers")]
fn compact_a_body(body: &[u8], count: u16) -> Option<([u8; 4], [u8; 32])> {
    let count = usize::from(count);
    if count == 0 || count > 8 || body.len() != count * 16 {
        return None;
    }
    let first = body.get(..16)?;
    if first[..6] != [0xc0, 0x0c, 0, 1, 0, 1] || first[10..12] != [0, 4] {
        return None;
    }
    let ttl: [u8; 4] = first[6..10].try_into().ok()?;
    let mut addresses = [0; 32];
    for (index, record) in body.as_chunks::<16>().0.iter().enumerate() {
        if record[..6] != first[..6] || record[6..10] != ttl || record[10..12] != [0, 4] {
            return None;
        }
        addresses[index * 4..index * 4 + 4].copy_from_slice(&record[12..16]);
    }
    Some((ttl, addresses))
}

#[cfg(feature = "experimental-packed-serving")]
mod packed;
#[cfg(feature = "experimental-packed-serving")]
pub(super) use packed::PackedDirectIndex;

/// Stage-local index metadata. Construct all queries' handles before probing
/// entries, so the image header is no longer on each query's dependent chain.
#[cfg(feature = "experimental-staged-serving")]
pub(crate) struct PreparedCompactLookup<'a> {
    #[cfg(not(feature = "experimental-packed-serving"))]
    table: &'a [DirectAnswerEntry],
    #[cfg(feature = "experimental-packed-serving")]
    table: &'a [[u8; 64]],
    wire: &'a [u8],
    key: [u8; KEY_BYTES],
    len: usize,
    qtype: u16,
    hash: usize,
}

#[cfg(feature = "experimental-staged-serving")]
#[derive(Default)]
pub(crate) struct FirstCompactEntry(DirectAnswerEntry);

#[cfg(feature = "experimental-staged-serving")]
impl PreparedCompactLookup<'_> {
    pub(crate) fn read_first(&self) -> FirstCompactEntry {
        #[cfg(feature = "experimental-packed-serving")]
        {
            FirstCompactEntry(packed::decode(
                &self.table[self.hash & (self.table.len() - 1)],
            ))
        }
        #[cfg(not(feature = "experimental-packed-serving"))]
        FirstCompactEntry(self.table[self.hash & (self.table.len() - 1)])
    }

    pub(crate) fn resolve(&self, first: &FirstCompactEntry) -> Option<ZoneImageDirectRrset<'_>> {
        for probe in 0..MAX_PROBES {
            #[cfg(feature = "experimental-packed-serving")]
            let loaded;
            let entry = if probe == 0 {
                &first.0
            } else {
                #[cfg(feature = "experimental-packed-serving")]
                {
                    loaded = packed::decode(
                        &self.table[self.hash.wrapping_add(probe) & (self.table.len() - 1)],
                    );
                    &loaded
                }
                #[cfg(not(feature = "experimental-packed-serving"))]
                &self.table[self.hash.wrapping_add(probe) & (self.table.len() - 1)]
            };
            if entry.key_len == 0 {
                return None;
            }
            if usize::from(entry.key_len) != self.len
                || entry.rr_type != self.qtype
                || entry.key != self.key
            {
                continue;
            }
            let start = usize::try_from(entry.wire_offset).ok()?;
            let end = start.checked_add(entry.body_len as usize)?;
            let count = entry.record_count as u16;
            return Some(ZoneImageDirectRrset {
                body_wire_len: entry.body_len as usize,
                section_count_header_bytes: section_count_header_bytes(count, 0, 0),
                section_count_header_bytes_with_edns: section_count_header_bytes(count, 0, 1),
                body: ZoneImageDirectRrsetBody::Template(self.wire.get(start..end)?),
            });
        }
        None
    }
}

/// One cache line holds the relative owner key, exact RR type, response counts
/// and precompiled body location. No node, edge or ImageRrset read is needed.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DirectAnswerEntry {
    wire_offset: u64,
    key: [u8; KEY_BYTES],
    body_len: u32,
    record_count: u32,
    rr_type: u16,
    key_len: u8,
}

fn key_hash(key: &[u8], rr_type: u16) -> usize {
    // This is not a security hash. Both successful and unsuccessful lookups
    // have at most MAX_PROBES; colliding entries use the existing resolver.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ u64::from(rr_type);
    for byte in key {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3);
    }
    (hash ^ (hash >> 32)) as usize
}

impl ZoneImage {
    /// Bound extra publication work independently of a large zone's RR count.
    /// The complete resolver remains available for every excluded image/query.
    #[cfg(feature = "experimental-fused-serving")]
    pub(crate) fn visit_fused_answers(&self, mut visit: impl FnMut(&[u8], u16, &[u8], u16)) {
        if self.stats.rrset_count > 64 {
            return;
        }
        let origin = self.origin.to_wire();
        for slot in self.compact_direct.table() {
            let entry = packed::decode(slot);
            if entry.key_len == 0
                || entry.body_len as usize > FusedDirectAnswer::MAX_BODY_LEN
                || entry.rr_type == RecordType::Ds as u16
            {
                continue;
            }
            let mut owner = Vec::with_capacity(usize::from(entry.key_len) - 1 + origin.len());
            owner.extend_from_slice(&entry.key[..usize::from(entry.key_len) - 1]);
            owner.extend_from_slice(&origin);
            // Wire label lengths are <=63, so only label text changes here.
            owner.make_ascii_lowercase();
            let begin = entry.wire_offset as usize;
            let end = begin + entry.body_len as usize;
            visit(
                &owner,
                entry.rr_type,
                &self.compact_direct.wire()[begin..end],
                entry.record_count as u16,
            );
        }
    }
    #[cfg(feature = "experimental-staged-serving")]
    pub(crate) fn prepare_compact_relative(
        &self,
        qname: &DomainName,
        relative_labels: usize,
        qtype: u16,
        qclass: u16,
        lowercase: bool,
    ) -> Option<PreparedCompactLookup<'_>> {
        if self.compact_direct.is_empty() || qclass != 1 {
            return None;
        }
        let mut key = [0; KEY_BYTES];
        let mut len = 0;
        for label in qname.labels().get(..relative_labels)? {
            if len + 1 + label.len() >= KEY_BYTES {
                return None;
            }
            key[len] = label.len() as u8;
            len += 1;
            key[len..len + label.len()].copy_from_slice(label);
            if !lowercase {
                key[len..len + label.len()].make_ascii_lowercase();
            }
            len += label.len();
        }
        len += 1;
        Some(PreparedCompactLookup {
            #[cfg(not(feature = "experimental-packed-serving"))]
            table: &self.compact_direct,
            #[cfg(not(feature = "experimental-packed-serving"))]
            wire: &self.wire,
            #[cfg(feature = "experimental-packed-serving")]
            table: self.compact_direct.table(),
            #[cfg(feature = "experimental-packed-serving")]
            wire: self.compact_direct.wire(),
            key,
            len,
            qtype,
            hash: key_hash(&key[..len], qtype),
        })
    }

    pub(super) fn build_compact_direct_index(&mut self) {
        let origin_len = self.origin.wire_len();
        let mut entries = Vec::new();
        for (node_index, node) in self.nodes.iter().enumerate() {
            if !self.ordinary_name_exists(node_index as u32) {
                continue;
            }
            for offset in 0..node.rrset_count {
                let rrset_id = node.first_rrset + u32::from(offset);
                let rrset = self.rrsets[rrset_id as usize];
                if rrset.class() != 1
                    || rrset.rr_type() == 255
                    || rr_type_may_have_additional_address_target(rrset.rr_type())
                    || rrset.direct_answer_body_len == 0
                    || rrset.direct_answer_body_len == DIRECT_ANSWER_BODY_RECORDS_FALLBACK
                    || u16::try_from(rrset.record_count).is_err()
                    || self.covering_delegation_blocks_direct_answer(
                        node_index as u32,
                        rrset.rr_type(),
                        1,
                    )
                    || self.covering_dname_blocks_direct_answer(node_index as u32, 1)
                {
                    continue;
                }
                let owner = self.blob(&self.names, rrset.owner_wire);
                let Some(prefix_len) = owner.len().checked_sub(origin_len) else {
                    continue;
                };
                if prefix_len >= KEY_BYTES {
                    continue;
                }
                let mut key = [0; KEY_BYTES];
                key[..prefix_len].copy_from_slice(&owner[..prefix_len]);
                key[..prefix_len].make_ascii_lowercase();
                entries.push(DirectAnswerEntry {
                    wire_offset: rrset.wire.offset + rrset.wire.len,
                    key,
                    body_len: rrset.direct_answer_body_len,
                    record_count: rrset.record_count,
                    rr_type: rrset.rr_type(),
                    key_len: (prefix_len + 1) as u8,
                });
            }
        }
        if entries.is_empty() {
            return;
        }
        let Some(slots) = entries
            .len()
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
        else {
            return;
        };
        let mut table = vec![DirectAnswerEntry::default(); slots];
        for entry in entries {
            let hash = key_hash(&entry.key[..usize::from(entry.key_len)], entry.rr_type);
            for probe in 0..MAX_PROBES {
                let slot = &mut table[hash.wrapping_add(probe) & (slots - 1)];
                if slot.key_len == 0 {
                    *slot = entry;
                    break;
                }
            }
        }
        #[cfg(feature = "experimental-packed-serving")]
        {
            let Some(packed) = PackedDirectIndex::new(&table, &self.wire) else {
                return;
            };
            self.stats.hot_bytes += packed.allocated_bytes();
            self.compact_direct = packed;
        }
        #[cfg(not(feature = "experimental-packed-serving"))]
        {
            self.stats.hot_bytes += table.len() * mem::size_of::<DirectAnswerEntry>();
            self.compact_direct = table.into_boxed_slice();
        }
        self.stats.bytes_per_record = (self.stats.hot_bytes + self.stats.cold_bytes)
            .checked_div(self.stats.record_count)
            .unwrap_or_default();
    }

    pub(crate) fn lookup_compact_direct(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        lowercase: bool,
    ) -> Option<ZoneImageDirectRrset<'_>> {
        if self.compact_direct.is_empty()
            || qclass != 1
            || !qname.is_equal_or_subdomain_of(&self.origin)
        {
            return None;
        }
        let relative_labels = qname.label_count() - self.origin.label_count();
        self.lookup_compact_relative(qname, relative_labels, qtype, qclass, lowercase)
    }

    /// Caller has already established the query's relationship to this image.
    /// Production bypass is only through SelectedZoneQuery, which binds the
    /// query and image to the same immutable authority-selection result.
    pub(crate) fn lookup_compact_relative(
        &self,
        qname: &DomainName,
        relative_labels: usize,
        qtype: u16,
        qclass: u16,
        lowercase: bool,
    ) -> Option<ZoneImageDirectRrset<'_>> {
        if self.compact_direct.is_empty() || qclass != 1 {
            return None;
        }
        let mut key = [0; KEY_BYTES];
        let mut len = 0;
        for label in qname.labels().get(..relative_labels)? {
            if len + 1 + label.len() >= KEY_BYTES {
                return None;
            }
            key[len] = label.len() as u8;
            len += 1;
            key[len..len + label.len()].copy_from_slice(label);
            if !lowercase {
                key[len..len + label.len()].make_ascii_lowercase();
            }
            len += label.len();
        }
        len += 1; // Relative root terminator; empty slots use key_len == 0.
        let hash = key_hash(&key[..len], qtype);
        for probe in 0..MAX_PROBES {
            #[cfg(feature = "experimental-packed-serving")]
            let entry = packed::decode(
                &self.compact_direct.table()
                    [hash.wrapping_add(probe) & (self.compact_direct.len() - 1)],
            );
            #[cfg(not(feature = "experimental-packed-serving"))]
            let entry =
                &self.compact_direct[hash.wrapping_add(probe) & (self.compact_direct.len() - 1)];
            if entry.key_len == 0 {
                return None;
            }
            if usize::from(entry.key_len) != len || entry.rr_type != qtype || entry.key != key {
                continue;
            }
            let count = entry.record_count as u16;
            let wire = ZoneImageDirectRrset {
                body_wire_len: entry.body_len as usize,
                section_count_header_bytes: section_count_header_bytes(count, 0, 0),
                section_count_header_bytes_with_edns: section_count_header_bytes(count, 0, 1),
                body: ZoneImageDirectRrsetBody::Template(self.blob(
                    #[cfg(feature = "experimental-packed-serving")]
                    self.compact_direct.wire(),
                    #[cfg(not(feature = "experimental-packed-serving"))]
                    &self.wire,
                    BlobRange {
                        offset: entry.wire_offset,
                        len: u64::from(entry.body_len),
                    },
                )),
            };
            return Some(wire);
        }
        None
    }
}
