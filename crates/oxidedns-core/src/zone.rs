use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use tracing::warn;

use crate::dns::{AnyResponseMode, DEFAULT_MAX_CNAME_CHAIN, DomainName, LookupResult, RecordType};

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
    rrsets: HashMap<RrsetKey, Rrset>,
}

impl ZoneSnapshot {
    pub fn loading(origin: DomainName) -> Self {
        Self {
            origin,
            state: ZoneState::Loading,
            serial: None,
            soa_timers: None,
            rrsets: HashMap::new(),
        }
    }

    pub fn active(origin: DomainName, serial: Option<u32>, rrsets: Vec<Rrset>) -> Self {
        let mut by_key = HashMap::new();
        for rrset in rrsets {
            by_key.insert(
                RrsetKey::new(&rrset.owner, rrset.rr_type, rrset.class),
                rrset,
            );
        }
        let soa_timers = soa_timers_from_rrsets(&origin, &by_key);

        Self {
            origin,
            state: ZoneState::Active,
            serial,
            soa_timers,
            rrsets: by_key,
        }
    }

    pub fn with_state(&self, state: ZoneState) -> Self {
        Self {
            origin: self.origin.clone(),
            state,
            serial: self.serial,
            soa_timers: self.soa_timers,
            rrsets: self.rrsets.clone(),
        }
    }

    pub fn soa_record(&self, qclass: u16) -> Option<ResourceRecord> {
        self.soa_rrset(qclass)
            .and_then(|rrset| rrset.records().into_iter().next())
    }

    pub fn records(&self) -> Vec<ResourceRecord> {
        self.rrsets.values().flat_map(Rrset::records).collect()
    }

    pub fn lookup(&self, qname: &DomainName, qtype: u16, qclass: u16) -> LookupResult {
        self.lookup_with_options(
            qname,
            qtype,
            qclass,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        )
    }

    pub fn lookup_with_options(
        &self,
        qname: &DomainName,
        qtype: u16,
        qclass: u16,
        max_cname_chain: usize,
        any_response: AnyResponseMode,
    ) -> LookupResult {
        if let Some(delegation) = self.delegation_for(qname, qclass)
            && !(qtype == RecordType::Ds as u16
                && qname.canonical_key() == delegation.owner.canonical_key())
        {
            let authorities = delegation.records();
            let additionals = self.glue_for_ns_records(&authorities, qclass);
            return LookupResult::referral(authorities, additionals);
        }

        if qtype == 255 {
            let answers = self
                .any_rrsets_at_name(qname, qclass, any_response)
                .into_iter()
                .flat_map(Rrset::records)
                .collect::<Vec<_>>();

            if !answers.is_empty() {
                let additionals = self.additionals_for_answer_records(&answers, qclass);
                return LookupResult::positive_with_additionals(answers, additionals);
            }
        } else if let Some(rrset) = self.rrset(qname, qtype, qclass) {
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

        if self.name_exists(qname, qclass) || self.is_empty_non_terminal(qname, qclass) {
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
            warn!(
                qname = %current,
                "CNAME chain limit reached; returning constructed response"
            );
            return LookupResult::positive_records(answers);
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
            warn!(
                qname = %target,
                "CNAME chain loop detected; returning constructed response"
            );
            return LookupResult::positive_records(answers);
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
        let target = dname_records.first().and_then(dname_target)?;
        let synthesized_target = qname.with_replaced_suffix(&dname_rrset.owner, &target)?;

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
        self.rrsets
            .values()
            .filter(|rrset| {
                rrset.rr_type == RecordType::Ns as u16
                    && (qclass == 255 || rrset.class == qclass)
                    && rrset.owner != self.origin
                    && qname.is_equal_or_subdomain_of(&rrset.owner)
            })
            .max_by_key(|rrset| rrset.owner.label_count())
    }

    fn dname_for(&self, qname: &DomainName, qclass: u16) -> Option<&Rrset> {
        self.rrsets
            .values()
            .filter(|rrset| {
                rrset.rr_type == RecordType::Dname as u16
                    && (qclass == 255 || rrset.class == qclass)
                    && rrset.owner != *qname
                    && qname.is_equal_or_subdomain_of(&rrset.owner)
            })
            .max_by_key(|rrset| rrset.owner.label_count())
    }

    fn glue_for_ns_records(
        &self,
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
            if self.name_exists(&candidate, qclass)
                || self.is_empty_non_terminal(&candidate, qclass)
            {
                return Some(candidate);
            }
            if candidate == self.origin {
                return None;
            }
            candidate = candidate.parent()?;
        }
    }

    fn rrset(&self, owner: &DomainName, rr_type: u16, qclass: u16) -> Option<&Rrset> {
        if qclass == 255 {
            let owner_key = owner.canonical_key();
            self.rrsets
                .values()
                .find(|rrset| rrset.owner.canonical_key() == owner_key && rrset.rr_type == rr_type)
        } else {
            self.rrsets.get(&RrsetKey {
                owner: owner.canonical_key(),
                rr_type,
                class: qclass,
            })
        }
    }

    fn rrsets_at_name(&self, owner: &DomainName, qclass: u16) -> Vec<&Rrset> {
        let owner_key = owner.canonical_key();
        self.rrsets
            .values()
            .filter(|rrset| {
                rrset.owner.canonical_key() == owner_key && (qclass == 255 || rrset.class == qclass)
            })
            .collect()
    }

    fn any_rrsets_at_name(
        &self,
        owner: &DomainName,
        qclass: u16,
        any_response: AnyResponseMode,
    ) -> Vec<&Rrset> {
        let mut rrsets = self.rrsets_at_name(owner, qclass);
        rrsets.sort_by_key(|rrset| (rrset.class, rrset.rr_type));
        if any_response == AnyResponseMode::Minimal {
            rrsets.truncate(1);
        }
        rrsets
    }

    fn name_exists(&self, name: &DomainName, qclass: u16) -> bool {
        let owner = name.canonical_key();
        self.rrsets.values().any(|rrset| {
            rrset.owner.canonical_key() == owner && (qclass == 255 || rrset.class == qclass)
        })
    }

    fn is_empty_non_terminal(&self, name: &DomainName, qclass: u16) -> bool {
        if self.name_exists(name, qclass) {
            return false;
        }

        self.rrsets.values().any(|rrset| {
            (qclass == 255 || rrset.class == qclass) && rrset.owner.is_equal_or_subdomain_of(name)
        })
    }

    fn soa_rrset(&self, qclass: u16) -> Option<&Rrset> {
        let class = if qclass == 255 { 1 } else { qclass };
        self.rrsets
            .get(&RrsetKey::new(&self.origin, RecordType::Soa as u16, class))
    }
}

fn soa_timers_from_rrsets(
    origin: &DomainName,
    rrsets: &HashMap<RrsetKey, Rrset>,
) -> Option<SoaTimers> {
    let soa = rrsets.get(&RrsetKey::new(origin, RecordType::Soa as u16, 1))?;
    soa.rdatas.first().and_then(|rdata| soa_timers(rdata))
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

#[derive(Debug, Default, Clone)]
pub struct ZoneStore {
    zones: Arc<RwLock<HashMap<String, Arc<ZoneSnapshot>>>>,
}

impl ZoneStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_loading(&self, origin: DomainName) {
        self.zones
            .write()
            .expect("zone store lock poisoned")
            .insert(
                origin.canonical_key(),
                Arc::new(ZoneSnapshot::loading(origin)),
            );
    }

    pub fn insert_snapshot(&self, snapshot: ZoneSnapshot) {
        self.zones
            .write()
            .expect("zone store lock poisoned")
            .insert(snapshot.origin.canonical_key(), Arc::new(snapshot));
    }

    pub fn expire_zone(&self, origin: &DomainName) -> bool {
        let mut zones = self.zones.write().expect("zone store lock poisoned");
        let key = origin.canonical_key();
        let Some(snapshot) = zones.get(&key) else {
            return false;
        };
        if snapshot.state == ZoneState::Expired {
            return false;
        }

        let expired = snapshot.with_state(ZoneState::Expired);
        zones.insert(key, Arc::new(expired));
        true
    }

    pub fn get(&self, origin: &str) -> Option<Arc<ZoneSnapshot>> {
        self.zones
            .read()
            .expect("zone store lock poisoned")
            .get(origin)
            .cloned()
    }

    pub fn find_exact_zone(&self, origin: &DomainName) -> Option<Arc<ZoneSnapshot>> {
        self.zones
            .read()
            .expect("zone store lock poisoned")
            .get(&origin.canonical_key())
            .cloned()
    }

    pub fn find_zone(&self, qname: &DomainName) -> Option<Arc<ZoneSnapshot>> {
        self.zones
            .read()
            .expect("zone store lock poisoned")
            .values()
            .filter(|zone| qname.is_equal_or_subdomain_of(&zone.origin))
            .max_by_key(|zone| zone.origin.label_count())
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.zones.read().expect("zone store lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.zones
            .read()
            .expect("zone store lock poisoned")
            .is_empty()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrset {
    pub owner: DomainName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    rdatas: Vec<Vec<u8>>,
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
            rdatas,
        }
    }

    pub fn records(&self) -> Vec<ResourceRecord> {
        self.records_with_owner(&self.owner)
    }

    pub fn records_with_owner(&self, owner: &DomainName) -> Vec<ResourceRecord> {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RrsetKey {
    owner: String,
    rr_type: u16,
    class: u16,
}

impl RrsetKey {
    fn new(owner: &DomainName, rr_type: u16, class: u16) -> Self {
        Self {
            owner: owner.canonical_key(),
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
            store.find_exact_zone(&origin).expect("expired zone").state,
            ZoneState::Expired
        );
        assert!(!store.expire_zone(&origin));
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
}
