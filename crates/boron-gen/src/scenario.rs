use std::fmt;

use borondns_core::dns::{DomainName, RecordType};
use serde::Serialize;
use thiserror::Error;

const DNS_CLASS_IN: u16 = 1;
const DEFAULT_TTL: u32 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentProfile {
    RegistryNsec3,
    Mixed,
    LargeRrset,
}

impl fmt::Display for ContentProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryNsec3 => formatter.write_str("registry-nsec3"),
            Self::Mixed => formatter.write_str("mixed"),
            Self::LargeRrset => formatter.write_str("large-rrset"),
        }
    }
}

impl std::str::FromStr for ContentProfile {
    type Err = ScenarioError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "registry-nsec3" => Ok(Self::RegistryNsec3),
            "mixed" => Ok(Self::Mixed),
            "large-rrset" => Ok(Self::LargeRrset),
            _ => Err(ScenarioError::InvalidProfile(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub profile: ContentProfile,
    pub origin: String,
    pub catalog_origin: String,
    pub zones: u64,
    pub names_per_zone: u64,
    pub records_per_name: u32,
    pub txt_rdata_bytes: u16,
    pub nsec3_records_per_zone: u64,
    pub nsec3_iterations: u16,
    pub nsec3_opt_out: bool,
    pub structural_rrsigs: bool,
    pub ds_every: u32,
    pub seed: u64,
    pub serial: u32,
    pub ttl: u32,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            profile: ContentProfile::RegistryNsec3,
            origin: "load.borongen.".to_owned(),
            catalog_origin: "catalog.borongen.".to_owned(),
            zones: 1,
            names_per_zone: 1_000,
            records_per_name: 4,
            txt_rdata_bytes: 128,
            nsec3_records_per_zone: 1_000,
            nsec3_iterations: 0,
            nsec3_opt_out: true,
            structural_rrsigs: true,
            ds_every: 20,
            seed: 0x626f_726f_6e67_656e,
            serial: 1,
            ttl: DEFAULT_TTL,
        }
    }
}

#[derive(Debug, Error)]
pub enum ScenarioError {
    #[error("unsupported content profile {0}")]
    InvalidProfile(String),
    #[error("{field} must be an absolute DNS name: {value}")]
    InvalidName { field: &'static str, value: String },
    #[error("origin and catalog origin must be different")]
    ConflictingOrigins,
    #[error("{field} must be greater than zero")]
    ZeroValue { field: &'static str },
    #[error("registry-nsec3 requires at least two NSEC3 records per member zone")]
    TooFewNsec3Records,
    #[error("TXT RDATA size must be at least one byte")]
    EmptyTxt,
    #[error("TXT payload {0} requires RDATA larger than the DNS 65,535-byte limit")]
    TxtRdataTooLong(u16),
    #[error("generated DNS name exceeds the DNS wire-name limit")]
    GeneratedNameTooLong,
    #[error("generated record count overflowed u64")]
    RecordCountOverflow,
    #[error("generated record RDATA exceeds the DNS u16 RDLENGTH limit")]
    RdataTooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneKind {
    Catalog,
    Member(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedRecord {
    pub owner: DomainName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl GeneratedRecord {
    pub fn wire_len(&self) -> usize {
        self.owner.to_wire().len() + 10 + self.rdata.len()
    }
}

#[derive(Debug, Clone)]
pub struct Scenario {
    config: ScenarioConfig,
    origin: DomainName,
    catalog_origin: DomainName,
    origin_key: String,
    catalog_key: String,
    manifest: Manifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub format: &'static str,
    pub generator: &'static str,
    pub profile: ContentProfile,
    pub origin: String,
    pub catalog_origin: String,
    pub zones: u64,
    pub names_per_zone: u64,
    pub records_per_name: u32,
    pub txt_rdata_bytes: u16,
    pub nsec3_records_per_zone: u64,
    pub nsec3_iterations: u16,
    pub nsec3_opt_out: bool,
    pub nsec3_ring_is_hash_ordered_and_linked: bool,
    pub nsec3_hashes_are_owner_name_preimages: bool,
    pub structural_rrsigs: bool,
    pub signatures_are_cryptographically_valid: bool,
    pub ds_every: u32,
    pub seed: u64,
    pub serial: u32,
    pub ttl: u32,
    pub catalog_snapshot_records: u64,
    pub catalog_axfr_records: u64,
    pub member_snapshot_records_each: u64,
    pub member_axfr_records_each: u64,
    pub all_member_snapshot_records: u64,
}

impl Scenario {
    pub fn new(config: ScenarioConfig) -> Result<Self, ScenarioError> {
        if config.zones == 0 {
            return Err(ScenarioError::ZeroValue { field: "zones" });
        }
        if config.names_per_zone == 0 {
            return Err(ScenarioError::ZeroValue {
                field: "names_per_zone",
            });
        }
        if config.records_per_name == 0 {
            return Err(ScenarioError::ZeroValue {
                field: "records_per_name",
            });
        }
        if config.txt_rdata_bytes == 0 {
            return Err(ScenarioError::EmptyTxt);
        }
        let txt_payload = usize::from(config.txt_rdata_bytes);
        if config.profile == ContentProfile::Mixed
            && txt_payload + txt_payload.div_ceil(255) > usize::from(u16::MAX)
        {
            return Err(ScenarioError::TxtRdataTooLong(config.txt_rdata_bytes));
        }
        if config.ds_every == 0 {
            return Err(ScenarioError::ZeroValue { field: "ds_every" });
        }
        if config.profile == ContentProfile::RegistryNsec3 && config.nsec3_records_per_zone < 2 {
            return Err(ScenarioError::TooFewNsec3Records);
        }

        let origin = parse_name("origin", &config.origin)?;
        let catalog_origin = parse_name("catalog_origin", &config.catalog_origin)?;
        let origin_key = origin.canonical_key();
        let catalog_key = catalog_origin.canonical_key();
        if origin_key == catalog_key {
            return Err(ScenarioError::ConflictingOrigins);
        }

        validate_generated_names(&config, &origin, &catalog_origin)?;
        let catalog_snapshot_records = config
            .zones
            .checked_add(4)
            .ok_or(ScenarioError::RecordCountOverflow)?;
        let catalog_axfr_records = catalog_snapshot_records
            .checked_add(1)
            .ok_or(ScenarioError::RecordCountOverflow)?;
        let member_snapshot_records_each = member_snapshot_record_count(&config)?;
        let member_axfr_records_each = member_snapshot_records_each
            .checked_add(1)
            .ok_or(ScenarioError::RecordCountOverflow)?;
        let all_member_snapshot_records = member_snapshot_records_each
            .checked_mul(config.zones)
            .ok_or(ScenarioError::RecordCountOverflow)?;

        let manifest = Manifest {
            format: "boron-gen-scenario-v1",
            generator: "boron-gen",
            profile: config.profile,
            origin: origin_key.clone(),
            catalog_origin: catalog_key.clone(),
            zones: config.zones,
            names_per_zone: config.names_per_zone,
            records_per_name: config.records_per_name,
            txt_rdata_bytes: config.txt_rdata_bytes,
            nsec3_records_per_zone: if config.profile == ContentProfile::RegistryNsec3 {
                config.nsec3_records_per_zone
            } else {
                0
            },
            nsec3_iterations: config.nsec3_iterations,
            nsec3_opt_out: config.nsec3_opt_out,
            nsec3_ring_is_hash_ordered_and_linked: config.profile == ContentProfile::RegistryNsec3,
            nsec3_hashes_are_owner_name_preimages: false,
            structural_rrsigs: config.structural_rrsigs,
            signatures_are_cryptographically_valid: false,
            ds_every: config.ds_every,
            seed: config.seed,
            serial: config.serial,
            ttl: config.ttl,
            catalog_snapshot_records,
            catalog_axfr_records,
            member_snapshot_records_each,
            member_axfr_records_each,
            all_member_snapshot_records,
        };

        Ok(Self {
            config,
            origin,
            catalog_origin,
            origin_key,
            catalog_key,
            manifest,
        })
    }

    pub fn config(&self) -> &ScenarioConfig {
        &self.config
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn catalog_origin(&self) -> &DomainName {
        &self.catalog_origin
    }

    pub fn zone_origin(&self, index: u64) -> Result<DomainName, ScenarioError> {
        if self.config.zones == 1 {
            return Ok(self.origin.clone());
        }
        parse_generated_name(format!("z{index:016x}.{}", self.origin_key))
    }

    pub fn locate_zone(&self, name: &DomainName) -> Option<ZoneKind> {
        let key = name.canonical_key();
        if key == self.catalog_key {
            return Some(ZoneKind::Catalog);
        }
        if self.config.zones == 1 {
            return (key == self.origin_key).then_some(ZoneKind::Member(0));
        }

        let prefix = key.strip_suffix(&self.origin_key)?;
        let encoded = prefix.strip_prefix('z')?.strip_suffix('.')?;
        if encoded.len() != 16 {
            return None;
        }
        let index = u64::from_str_radix(encoded, 16).ok()?;
        (index < self.config.zones).then_some(ZoneKind::Member(index))
    }

    pub fn soa(&self, zone: ZoneKind) -> Result<GeneratedRecord, ScenarioError> {
        let origin = self.zone_name(zone)?;
        Ok(record(
            origin.clone(),
            RecordType::Soa as u16,
            self.config.ttl,
            soa_rdata(&origin, self.config.serial)?,
        ))
    }

    pub fn records(&self, zone: ZoneKind) -> Result<ZoneRecordIter<'_>, ScenarioError> {
        ZoneRecordIter::new(self, zone)
    }

    fn zone_name(&self, zone: ZoneKind) -> Result<DomainName, ScenarioError> {
        match zone {
            ZoneKind::Catalog => Ok(self.catalog_origin.clone()),
            ZoneKind::Member(index) => self.zone_origin(index),
        }
    }
}

pub struct ZoneRecordIter<'a> {
    scenario: &'a Scenario,
    kind: ZoneKind,
    origin: DomainName,
    stage: u8,
    owner_index: u64,
    slot: u64,
    nsec3_index: u64,
}

impl<'a> ZoneRecordIter<'a> {
    fn new(scenario: &'a Scenario, kind: ZoneKind) -> Result<Self, ScenarioError> {
        Ok(Self {
            scenario,
            kind,
            origin: scenario.zone_name(kind)?,
            stage: 0,
            owner_index: 0,
            slot: 0,
            nsec3_index: 0,
        })
    }

    fn next_catalog(&mut self) -> Option<Result<GeneratedRecord, ScenarioError>> {
        loop {
            match self.stage {
                0 => {
                    self.stage = 1;
                    return Some(self.scenario.soa(self.kind));
                }
                1 => {
                    self.stage = 2;
                    return Some(ns_record(&self.origin, self.scenario.config.ttl));
                }
                2 => {
                    self.stage = 3;
                    return Some(apex_ns_address_record(
                        &self.origin,
                        self.scenario.config.ttl,
                        self.scenario.config.seed,
                        0,
                    ));
                }
                3 => {
                    self.stage = 4;
                    let owner = match child_name("version", &self.origin) {
                        Ok(owner) => owner,
                        Err(error) => return Some(Err(error)),
                    };
                    return Some(Ok(record(
                        owner,
                        RecordType::Txt as u16,
                        self.scenario.config.ttl,
                        vec![1, b'2'],
                    )));
                }
                4 if self.owner_index < self.scenario.config.zones => {
                    let index = self.owner_index;
                    self.owner_index += 1;
                    let owner = match child_name(&format!("m{index:016x}.zones"), &self.origin) {
                        Ok(owner) => owner,
                        Err(error) => return Some(Err(error)),
                    };
                    let member = match self.scenario.zone_origin(index) {
                        Ok(member) => member,
                        Err(error) => return Some(Err(error)),
                    };
                    return Some(Ok(record(
                        owner,
                        RecordType::Ptr as u16,
                        self.scenario.config.ttl,
                        member.to_wire(),
                    )));
                }
                4 => self.stage = 5,
                5 => {
                    self.stage = 6;
                    return Some(self.scenario.soa(self.kind));
                }
                _ => return None,
            }
        }
    }

    fn next_member(&mut self, zone_index: u64) -> Option<Result<GeneratedRecord, ScenarioError>> {
        loop {
            match self.stage {
                0 => {
                    self.stage = 1;
                    return Some(self.scenario.soa(self.kind));
                }
                1 => {
                    self.stage = 2;
                    return Some(ns_record(&self.origin, self.scenario.config.ttl));
                }
                2 => {
                    self.stage = 3;
                    return Some(apex_ns_address_record(
                        &self.origin,
                        self.scenario.config.ttl,
                        self.scenario.config.seed,
                        zone_index,
                    ));
                }
                3 if self.scenario.config.profile == ContentProfile::RegistryNsec3 => {
                    self.stage = 4;
                    return Some(Ok(record(
                        self.origin.clone(),
                        RecordType::Nsec3Param as u16,
                        self.scenario.config.ttl,
                        nsec3param_rdata(&self.scenario.config),
                    )));
                }
                3 => self.stage = 4,
                4 if self.scenario.config.structural_rrsigs
                    && self.slot < u64::from(apex_rrsig_count(&self.scenario.config)) =>
                {
                    let covered = match self.slot {
                        0 => RecordType::Soa as u16,
                        1 => RecordType::Ns as u16,
                        2 => RecordType::A as u16,
                        _ => RecordType::Nsec3Param as u16,
                    };
                    self.slot += 1;
                    let signature_owner = if covered == RecordType::A as u16 {
                        match child_name("ns", &self.origin) {
                            Ok(owner) => owner,
                            Err(error) => return Some(Err(error)),
                        }
                    } else {
                        self.origin.clone()
                    };
                    return Some(rrsig_record(
                        &signature_owner,
                        &self.origin,
                        covered,
                        self.scenario.config.ttl,
                        self.scenario.config.seed,
                        zone_index,
                        u64::from(covered),
                    ));
                }
                4 => {
                    self.stage = 5;
                    self.slot = 0;
                }
                5 if self.owner_index < self.scenario.config.names_per_zone => {
                    if let Some(record) = self.next_content_record(zone_index) {
                        return Some(record);
                    }
                    self.owner_index += 1;
                    self.slot = 0;
                }
                5 => {
                    self.stage = 6;
                    self.slot = 0;
                }
                6 if self.scenario.config.profile == ContentProfile::RegistryNsec3
                    && self.nsec3_index < self.scenario.config.nsec3_records_per_zone =>
                {
                    if self.slot == 0 {
                        self.slot = 1;
                        return Some(nsec3_record(
                            &self.origin,
                            &self.scenario.config,
                            zone_index,
                            self.nsec3_index,
                        ));
                    }
                    self.slot = 0;
                    let current = self.nsec3_index;
                    self.nsec3_index += 1;
                    if self.scenario.config.structural_rrsigs {
                        let owner = match nsec3_owner(
                            &self.origin,
                            &self.scenario.config,
                            zone_index,
                            current,
                        ) {
                            Ok(owner) => owner,
                            Err(error) => return Some(Err(error)),
                        };
                        return Some(rrsig_record(
                            &owner,
                            &self.origin,
                            RecordType::Nsec3 as u16,
                            self.scenario.config.ttl,
                            self.scenario.config.seed,
                            zone_index,
                            current,
                        ));
                    }
                }
                6 => self.stage = 7,
                7 => {
                    self.stage = 8;
                    return Some(self.scenario.soa(self.kind));
                }
                _ => return None,
            }
        }
    }

    fn next_content_record(
        &mut self,
        zone_index: u64,
    ) -> Option<Result<GeneratedRecord, ScenarioError>> {
        match self.scenario.config.profile {
            ContentProfile::RegistryNsec3 => self.next_registry_record(zone_index),
            ContentProfile::Mixed => self.next_mixed_record(zone_index),
            ContentProfile::LargeRrset => self.next_large_rrset_record(zone_index),
        }
    }

    fn next_registry_record(
        &mut self,
        zone_index: u64,
    ) -> Option<Result<GeneratedRecord, ScenarioError>> {
        let sampled_ds = self
            .owner_index
            .is_multiple_of(u64::from(self.scenario.config.ds_every));
        let content_slots = 4 + u64::from(sampled_ds);
        let signature_slots = if self.scenario.config.structural_rrsigs {
            3 + u64::from(sampled_ds)
        } else {
            0
        };
        if self.slot >= content_slots + signature_slots {
            return None;
        }

        let owner = match generated_owner(self.owner_index, &self.origin) {
            Ok(owner) => owner,
            Err(error) => return Some(Err(error)),
        };
        let ns1 = match child_name("a", &owner) {
            Ok(name) => name,
            Err(error) => return Some(Err(error)),
        };
        let ns2 = match child_name("b", &owner) {
            Ok(name) => name,
            Err(error) => return Some(Err(error)),
        };
        let slot = self.slot;
        self.slot += 1;
        let ttl = self.scenario.config.ttl;

        let result = match slot {
            0 => Ok(record(
                owner.clone(),
                RecordType::Ns as u16,
                ttl,
                ns1.to_wire(),
            )),
            1 => Ok(record(
                owner.clone(),
                RecordType::Ns as u16,
                ttl,
                ns2.to_wire(),
            )),
            2 => Ok(record(
                ns1.clone(),
                RecordType::A as u16,
                ttl,
                ipv4_glue_rdata(self.scenario.config.seed, zone_index, self.owner_index, 0),
            )),
            3 => Ok(record(
                ns2.clone(),
                RecordType::A as u16,
                ttl,
                ipv4_glue_rdata(self.scenario.config.seed, zone_index, self.owner_index, 1),
            )),
            4 if sampled_ds => Ok(record(
                owner.clone(),
                RecordType::Ds as u16,
                ttl,
                ds_rdata(self.scenario.config.seed, zone_index, self.owner_index),
            )),
            _ => {
                let signature_slot = slot - content_slots;
                let (signature_owner, covered) = match signature_slot {
                    0 => (owner, RecordType::Ns as u16),
                    1 => (ns1, RecordType::A as u16),
                    2 => (ns2, RecordType::A as u16),
                    _ => (owner, RecordType::Ds as u16),
                };
                return Some(rrsig_record(
                    &signature_owner,
                    &self.origin,
                    covered,
                    ttl,
                    self.scenario.config.seed,
                    zone_index,
                    self.owner_index ^ u64::from(covered),
                ));
            }
        };
        Some(result)
    }

    fn next_mixed_record(
        &mut self,
        zone_index: u64,
    ) -> Option<Result<GeneratedRecord, ScenarioError>> {
        let records_per_name = u64::from(self.scenario.config.records_per_name);
        let data_slots = records_per_name + 2;
        let signature_slots = if self.scenario.config.structural_rrsigs {
            3
        } else {
            0
        };
        if self.slot >= data_slots + signature_slots {
            return None;
        }
        let owner = match generated_owner(self.owner_index, &self.origin) {
            Ok(owner) => owner,
            Err(error) => return Some(Err(error)),
        };
        let slot = self.slot;
        self.slot += 1;
        let ttl = self.scenario.config.ttl;
        if slot < records_per_name {
            return Some(Ok(record(
                owner,
                RecordType::A as u16,
                ttl,
                ipv4_rdata(
                    self.scenario.config.seed,
                    zone_index,
                    self.owner_index,
                    slot,
                ),
            )));
        }
        if slot == records_per_name {
            return Some(Ok(record(
                owner,
                RecordType::Aaaa as u16,
                ttl,
                ipv6_rdata(self.scenario.config.seed, zone_index, self.owner_index),
            )));
        }
        if slot == records_per_name + 1 {
            return Some(txt_record(
                owner,
                ttl,
                self.scenario.config.txt_rdata_bytes,
                self.scenario.config.seed,
                zone_index,
                self.owner_index,
            ));
        }

        let covered = match slot - data_slots {
            0 => RecordType::A as u16,
            1 => RecordType::Aaaa as u16,
            _ => RecordType::Txt as u16,
        };
        Some(rrsig_record(
            &owner,
            &self.origin,
            covered,
            ttl,
            self.scenario.config.seed,
            zone_index,
            self.owner_index ^ u64::from(covered),
        ))
    }

    fn next_large_rrset_record(
        &mut self,
        zone_index: u64,
    ) -> Option<Result<GeneratedRecord, ScenarioError>> {
        let records_per_name = u64::from(self.scenario.config.records_per_name);
        let signature_slots = u64::from(self.scenario.config.structural_rrsigs);
        if self.slot >= records_per_name + signature_slots {
            return None;
        }
        let owner = match generated_owner(self.owner_index, &self.origin) {
            Ok(owner) => owner,
            Err(error) => return Some(Err(error)),
        };
        let slot = self.slot;
        self.slot += 1;
        if slot < records_per_name {
            return Some(Ok(record(
                owner,
                RecordType::A as u16,
                self.scenario.config.ttl,
                ipv4_rdata(
                    self.scenario.config.seed,
                    zone_index,
                    self.owner_index,
                    slot,
                ),
            )));
        }
        Some(rrsig_record(
            &owner,
            &self.origin,
            RecordType::A as u16,
            self.scenario.config.ttl,
            self.scenario.config.seed,
            zone_index,
            self.owner_index,
        ))
    }
}

impl Iterator for ZoneRecordIter<'_> {
    type Item = Result<GeneratedRecord, ScenarioError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.kind {
            ZoneKind::Catalog => self.next_catalog(),
            ZoneKind::Member(index) => self.next_member(index),
        }
    }
}

fn parse_name(field: &'static str, value: &str) -> Result<DomainName, ScenarioError> {
    DomainName::from_absolute_str(value).map_err(|_| ScenarioError::InvalidName {
        field,
        value: value.to_owned(),
    })
}

fn parse_generated_name(value: String) -> Result<DomainName, ScenarioError> {
    DomainName::from_absolute_str(&value).map_err(|_| ScenarioError::GeneratedNameTooLong)
}

fn validate_generated_names(
    config: &ScenarioConfig,
    origin: &DomainName,
    catalog: &DomainName,
) -> Result<(), ScenarioError> {
    let origin_key = origin.canonical_key();
    let catalog_key = catalog.canonical_key();
    let zone_key = if config.zones > 1 {
        let key = format!("z{:016x}.{origin_key}", config.zones - 1);
        parse_generated_name(key.clone())?;
        key
    } else {
        origin_key
    };
    parse_generated_name(format!("ns.{zone_key}"))?;
    parse_generated_name(format!("hostmaster.{zone_key}"))?;
    let owner_key = format!("n{:016x}.{zone_key}", config.names_per_zone - 1);
    parse_generated_name(owner_key.clone())?;
    parse_generated_name(format!("ns.{catalog_key}"))?;
    parse_generated_name(format!("hostmaster.{catalog_key}"))?;
    parse_generated_name(format!("version.{catalog_key}"))?;
    parse_generated_name(format!("m{:016x}.zones.{catalog_key}", config.zones - 1))?;
    if config.profile == ContentProfile::RegistryNsec3 {
        parse_generated_name(format!("a.{owner_key}"))?;
        parse_generated_name(format!("b.{owner_key}"))?;
        parse_generated_name(format!("{}.{zone_key}", "0".repeat(32)))?;
    }
    Ok(())
}

fn member_snapshot_record_count(config: &ScenarioConfig) -> Result<u64, ScenarioError> {
    let apex = 3u64
        .checked_add(u64::from(config.profile == ContentProfile::RegistryNsec3))
        .and_then(|value| {
            value.checked_add(if config.structural_rrsigs {
                apex_rrsig_count(config).into()
            } else {
                0
            })
        })
        .ok_or(ScenarioError::RecordCountOverflow)?;

    let content = match config.profile {
        ContentProfile::RegistryNsec3 => {
            let sampled = (config.names_per_zone - 1)
                .checked_div(u64::from(config.ds_every))
                .and_then(|value| value.checked_add(1))
                .ok_or(ScenarioError::RecordCountOverflow)?;
            let base = config
                .names_per_zone
                .checked_mul(4)
                .and_then(|value| value.checked_add(sampled))
                .ok_or(ScenarioError::RecordCountOverflow)?;
            if config.structural_rrsigs {
                base.checked_add(
                    config
                        .names_per_zone
                        .checked_mul(3)
                        .and_then(|value| value.checked_add(sampled))
                        .ok_or(ScenarioError::RecordCountOverflow)?,
                )
                .ok_or(ScenarioError::RecordCountOverflow)?
            } else {
                base
            }
        }
        ContentProfile::Mixed => {
            let per_name = u64::from(config.records_per_name)
                .checked_add(2)
                .and_then(|value| value.checked_add(if config.structural_rrsigs { 3 } else { 0 }))
                .ok_or(ScenarioError::RecordCountOverflow)?;
            config
                .names_per_zone
                .checked_mul(per_name)
                .ok_or(ScenarioError::RecordCountOverflow)?
        }
        ContentProfile::LargeRrset => {
            let per_name = u64::from(config.records_per_name)
                .checked_add(u64::from(config.structural_rrsigs))
                .ok_or(ScenarioError::RecordCountOverflow)?;
            config
                .names_per_zone
                .checked_mul(per_name)
                .ok_or(ScenarioError::RecordCountOverflow)?
        }
    };
    let nsec3 = if config.profile == ContentProfile::RegistryNsec3 {
        config
            .nsec3_records_per_zone
            .checked_mul(if config.structural_rrsigs { 2 } else { 1 })
            .ok_or(ScenarioError::RecordCountOverflow)?
    } else {
        0
    };
    apex.checked_add(content)
        .and_then(|value| value.checked_add(nsec3))
        .ok_or(ScenarioError::RecordCountOverflow)
}

fn apex_rrsig_count(config: &ScenarioConfig) -> u32 {
    if !config.structural_rrsigs {
        0
    } else if config.profile == ContentProfile::RegistryNsec3 {
        4
    } else {
        3
    }
}

fn record(owner: DomainName, rr_type: u16, ttl: u32, rdata: Vec<u8>) -> GeneratedRecord {
    GeneratedRecord {
        owner,
        rr_type,
        class: DNS_CLASS_IN,
        ttl,
        rdata,
    }
}

fn child_name(label_prefix: &str, origin: &DomainName) -> Result<DomainName, ScenarioError> {
    parse_generated_name(format!("{label_prefix}.{}", origin.canonical_key()))
}

fn generated_owner(index: u64, origin: &DomainName) -> Result<DomainName, ScenarioError> {
    child_name(&format!("n{index:016x}"), origin)
}

fn soa_rdata(origin: &DomainName, serial: u32) -> Result<Vec<u8>, ScenarioError> {
    let mname = child_name("ns", origin)?;
    let rname = child_name("hostmaster", origin)?;
    let mut rdata = Vec::with_capacity(mname.to_wire().len() + rname.to_wire().len() + 20);
    rdata.extend_from_slice(&mname.to_wire());
    rdata.extend_from_slice(&rname.to_wire());
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3_600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&604_800u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    Ok(rdata)
}

fn ns_record(origin: &DomainName, ttl: u32) -> Result<GeneratedRecord, ScenarioError> {
    let ns = child_name("ns", origin)?;
    Ok(record(
        origin.clone(),
        RecordType::Ns as u16,
        ttl,
        ns.to_wire(),
    ))
}

fn apex_ns_address_record(
    origin: &DomainName,
    ttl: u32,
    seed: u64,
    zone_index: u64,
) -> Result<GeneratedRecord, ScenarioError> {
    let ns = child_name("ns", origin)?;
    Ok(record(
        ns,
        RecordType::A as u16,
        ttl,
        ipv4_glue_rdata(seed, zone_index, u64::MAX, 0),
    ))
}

fn nsec3param_rdata(config: &ScenarioConfig) -> Vec<u8> {
    let salt = nsec3_salt(config.seed);
    let mut rdata = Vec::with_capacity(5 + salt.len());
    rdata.push(1);
    rdata.push(0);
    rdata.extend_from_slice(&config.nsec3_iterations.to_be_bytes());
    rdata.push(salt.len() as u8);
    rdata.extend_from_slice(&salt);
    rdata
}

fn nsec3_record(
    origin: &DomainName,
    config: &ScenarioConfig,
    zone_index: u64,
    index: u64,
) -> Result<GeneratedRecord, ScenarioError> {
    let owner = nsec3_owner(origin, config, zone_index, index)?;
    let count = config.nsec3_records_per_zone;
    let next_index = if index + 1 == count { 0 } else { index + 1 };
    let next_hash = synthetic_nsec3_hash(config.seed ^ zone_index, next_index, count);
    let salt = nsec3_salt(config.seed);
    let mut rdata = Vec::with_capacity(6 + salt.len() + next_hash.len() + 9);
    rdata.push(1);
    rdata.push(u8::from(config.nsec3_opt_out));
    rdata.extend_from_slice(&config.nsec3_iterations.to_be_bytes());
    rdata.push(salt.len() as u8);
    rdata.extend_from_slice(&salt);
    rdata.push(next_hash.len() as u8);
    rdata.extend_from_slice(&next_hash);
    // Window 0, seven octets: NSEC3 (50), plus RRSIG (46) when emitted.
    rdata.extend_from_slice(&[
        0,
        7,
        0,
        0,
        0,
        0,
        0,
        if config.structural_rrsigs { 0x02 } else { 0 },
        0x20,
    ]);
    Ok(record(owner, RecordType::Nsec3 as u16, config.ttl, rdata))
}

fn nsec3_owner(
    origin: &DomainName,
    config: &ScenarioConfig,
    zone_index: u64,
    index: u64,
) -> Result<DomainName, ScenarioError> {
    let hash = synthetic_nsec3_hash(
        config.seed ^ zone_index,
        index,
        config.nsec3_records_per_zone,
    );
    child_name(&base32hex_no_padding(&hash), origin)
}

fn rrsig_record(
    owner: &DomainName,
    signer: &DomainName,
    covered: u16,
    ttl: u32,
    seed: u64,
    zone_index: u64,
    ordinal: u64,
) -> Result<GeneratedRecord, ScenarioError> {
    let signer_wire = signer.to_wire();
    let mut rdata = Vec::with_capacity(18 + signer_wire.len() + 64);
    rdata.extend_from_slice(&covered.to_be_bytes());
    rdata.push(13);
    rdata.push(owner.label_count().min(u8::MAX as usize) as u8);
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata.extend_from_slice(&2_147_483_647u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    rdata.extend_from_slice(&0x4242u16.to_be_bytes());
    rdata.extend_from_slice(&signer_wire);
    for chunk in 0..8u64 {
        rdata.extend_from_slice(
            &mix64(seed ^ zone_index.rotate_left(17) ^ ordinal ^ chunk).to_be_bytes(),
        );
    }
    if rdata.len() > u16::MAX as usize {
        return Err(ScenarioError::RdataTooLong);
    }
    Ok(record(owner.clone(), RecordType::Rrsig as u16, ttl, rdata))
}

fn txt_record(
    owner: DomainName,
    ttl: u32,
    payload_len: u16,
    seed: u64,
    zone_index: u64,
    owner_index: u64,
) -> Result<GeneratedRecord, ScenarioError> {
    let mut remaining = usize::from(payload_len);
    let string_count = remaining.div_ceil(255);
    let mut rdata = Vec::new();
    rdata
        .try_reserve_exact(remaining.saturating_add(string_count))
        .map_err(|_| ScenarioError::RdataTooLong)?;
    let mut byte_index = 0u64;
    while remaining > 0 {
        let chunk = remaining.min(255);
        rdata.push(chunk as u8);
        for _ in 0..chunk {
            let value = mix64(seed ^ zone_index ^ owner_index ^ byte_index);
            rdata.push(b'a' + (value % 26) as u8);
            byte_index += 1;
        }
        remaining -= chunk;
    }
    if rdata.len() > u16::MAX as usize {
        return Err(ScenarioError::RdataTooLong);
    }
    Ok(record(owner, RecordType::Txt as u16, ttl, rdata))
}

fn ds_rdata(seed: u64, zone_index: u64, owner_index: u64) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(36);
    rdata.extend_from_slice(&0x4242u16.to_be_bytes());
    rdata.push(13);
    rdata.push(2);
    for chunk in 0..4u64 {
        rdata.extend_from_slice(
            &mix64(seed ^ zone_index ^ owner_index.rotate_left(9) ^ chunk).to_be_bytes(),
        );
    }
    rdata
}

fn ipv4_rdata(seed: u64, zone_index: u64, owner_index: u64, rr_index: u64) -> Vec<u8> {
    debug_assert!(rr_index <= u64::from(u32::MAX));
    let offset = mix64(seed ^ zone_index.rotate_left(11) ^ owner_index) as u32;
    let value = (rr_index as u32)
        .wrapping_mul(0x9e37_79b1)
        .wrapping_add(offset);
    value.to_be_bytes().to_vec()
}

fn ipv4_glue_rdata(seed: u64, zone_index: u64, owner_index: u64, rr_index: u64) -> Vec<u8> {
    let value = mix64(seed ^ zone_index.rotate_left(11) ^ owner_index ^ rr_index);
    vec![198, 18, (value >> 8) as u8, value as u8]
}

fn ipv6_rdata(seed: u64, zone_index: u64, owner_index: u64) -> Vec<u8> {
    let first = mix64(seed ^ zone_index ^ owner_index);
    let second = mix64(seed ^ zone_index.rotate_left(29) ^ owner_index.rotate_left(7));
    let mut rdata = Vec::with_capacity(16);
    rdata.extend_from_slice(&first.to_be_bytes());
    rdata.extend_from_slice(&second.to_be_bytes());
    rdata
}

fn nsec3_salt(seed: u64) -> [u8; 4] {
    (seed as u32).to_be_bytes()
}

pub fn synthetic_nsec3_hash(seed: u64, index: u64, count: u64) -> [u8; 20] {
    debug_assert!(count > 0);
    debug_assert!(index < count);
    let prefix = (((index as u128) << 64) / u128::from(count)) as u64;
    let mut hash = [0u8; 20];
    hash[..8].copy_from_slice(&prefix.to_be_bytes());
    let first_suffix = mix64(seed ^ index);
    let second_suffix = mix64(seed.rotate_left(23) ^ index.rotate_left(31));
    hash[8..16].copy_from_slice(&first_suffix.to_be_bytes());
    hash[16..20].copy_from_slice(&second_suffix.to_be_bytes()[..4]);
    hash
}

pub fn base32hex_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for &byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_nsec3_hashes_are_strictly_ordered_and_base32hex_width_is_stable() {
        let count = 10_003;
        let mut previous = None;
        for index in 0..count {
            let hash = synthetic_nsec3_hash(7, index, count);
            if let Some(previous) = previous {
                assert!(previous < hash);
            }
            assert_eq!(base32hex_no_padding(&hash).len(), 32);
            previous = Some(hash);
        }
    }

    #[test]
    fn registry_iterator_count_matches_manifest_and_ring_links_exactly() {
        let config = ScenarioConfig {
            zones: 2,
            names_per_zone: 23,
            nsec3_records_per_zone: 17,
            ..ScenarioConfig::default()
        };
        let scenario = Scenario::new(config).unwrap();
        let records = scenario
            .records(ZoneKind::Member(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            records.len() as u64,
            scenario.manifest().member_axfr_records_each
        );
        assert_eq!(records.first(), records.last());

        let nsec3 = records
            .iter()
            .filter(|record| record.rr_type == RecordType::Nsec3 as u16)
            .collect::<Vec<_>>();
        assert_eq!(nsec3.len(), 17);
        for index in 0..nsec3.len() {
            let owner_wire = nsec3[index].owner.to_wire();
            let label_len = owner_wire[0] as usize;
            let owner_label = std::str::from_utf8(&owner_wire[1..1 + label_len]).unwrap();
            assert_eq!(
                owner_label,
                base32hex_no_padding(&synthetic_nsec3_hash(
                    scenario.config.seed ^ 1,
                    index as u64,
                    17,
                ))
            );
            let rdata = &nsec3[index].rdata;
            let salt_len = rdata[4] as usize;
            let next_len_offset = 5 + salt_len;
            let next_len = rdata[next_len_offset] as usize;
            let next = &rdata[next_len_offset + 1..next_len_offset + 1 + next_len];
            assert_eq!(
                next,
                &synthetic_nsec3_hash(
                    scenario.config.seed ^ 1,
                    ((index + 1) % nsec3.len()) as u64,
                    17,
                )
            );
        }
    }

    #[test]
    fn every_profile_count_matches_manifest_without_materializing_configuration_state() {
        for profile in [
            ContentProfile::RegistryNsec3,
            ContentProfile::Mixed,
            ContentProfile::LargeRrset,
        ] {
            let config = ScenarioConfig {
                profile,
                names_per_zone: 31,
                records_per_name: 7,
                nsec3_records_per_zone: 19,
                ..ScenarioConfig::default()
            };
            let scenario = Scenario::new(config).unwrap();
            let count = scenario
                .records(ZoneKind::Member(0))
                .unwrap()
                .map(|record| record.map(|_| 1u64))
                .sum::<Result<u64, _>>()
                .unwrap();
            assert_eq!(count, scenario.manifest().member_axfr_records_each);
        }
    }

    #[test]
    fn repeated_catalog_and_member_generation_is_byte_stable() {
        let scenario = Scenario::new(ScenarioConfig {
            zones: 3,
            names_per_zone: 37,
            nsec3_records_per_zone: 29,
            ..ScenarioConfig::default()
        })
        .unwrap();
        for zone in [ZoneKind::Catalog, ZoneKind::Member(2)] {
            let first = scenario
                .records(zone)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let second = scenario
                .records(zone)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(first, second);
        }
    }

    #[test]
    fn hostile_scenario_counts_fail_before_record_generation() {
        assert!(matches!(
            Scenario::new(ScenarioConfig {
                zones: u64::MAX,
                ..ScenarioConfig::default()
            }),
            Err(ScenarioError::RecordCountOverflow)
        ));
        assert!(matches!(
            Scenario::new(ScenarioConfig {
                names_per_zone: u64::MAX,
                ..ScenarioConfig::default()
            }),
            Err(ScenarioError::RecordCountOverflow)
        ));
    }

    #[test]
    fn mixed_txt_rdata_limit_is_rejected_before_generation() {
        assert!(
            Scenario::new(ScenarioConfig {
                profile: ContentProfile::Mixed,
                txt_rdata_bytes: 65_279,
                ..ScenarioConfig::default()
            })
            .is_ok()
        );
        assert!(matches!(
            Scenario::new(ScenarioConfig {
                profile: ContentProfile::Mixed,
                txt_rdata_bytes: 65_280,
                ..ScenarioConfig::default()
            }),
            Err(ScenarioError::TxtRdataTooLong(65_280))
        ));
    }

    #[test]
    fn nested_generated_names_are_validated_before_listener_start() {
        let origin = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(43)
        );
        assert!(DomainName::from_absolute_str(&origin).is_ok());
        assert!(matches!(
            Scenario::new(ScenarioConfig {
                origin,
                ..ScenarioConfig::default()
            }),
            Err(ScenarioError::GeneratedNameTooLong)
        ));
    }

    #[test]
    fn generated_zone_lookup_is_formula_based() {
        let scenario = Scenario::new(ScenarioConfig {
            zones: 4,
            ..ScenarioConfig::default()
        })
        .unwrap();
        assert_eq!(
            scenario.locate_zone(&scenario.zone_origin(3).unwrap()),
            Some(ZoneKind::Member(3))
        );
        assert_eq!(
            scenario.locate_zone(scenario.catalog_origin()),
            Some(ZoneKind::Catalog)
        );
        assert_eq!(
            scenario.locate_zone(
                &DomainName::from_absolute_str("zffffffffffffffff.load.borongen.").unwrap()
            ),
            None
        );
    }

    #[test]
    fn large_rrset_u32_boundary_is_counted_and_streamed_without_preallocation() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::LargeRrset,
            names_per_zone: 1,
            records_per_name: u32::MAX,
            structural_rrsigs: false,
            ..ScenarioConfig::default()
        })
        .unwrap();
        assert_eq!(
            scenario.manifest().member_snapshot_records_each,
            u64::from(u32::MAX) + 3
        );
        assert_eq!(
            scenario.manifest().member_axfr_records_each,
            u64::from(u32::MAX) + 4
        );

        let first_thousand = scenario
            .records(ZoneKind::Member(0))
            .unwrap()
            .take(1_000)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(first_thousand.len(), 1_000);
        assert_eq!(
            first_thousand
                .iter()
                .filter(|record| record.rr_type == RecordType::A as u16)
                .count(),
            998
        );
    }

    #[test]
    fn large_rrset_u32_boundary_still_emits_structural_signature() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::LargeRrset,
            names_per_zone: 1,
            records_per_name: u32::MAX,
            structural_rrsigs: true,
            ..ScenarioConfig::default()
        })
        .unwrap();
        assert_eq!(
            scenario.manifest().member_snapshot_records_each,
            u64::from(u32::MAX) + 7
        );

        let mut records = scenario.records(ZoneKind::Member(0)).unwrap();
        records.stage = 5;
        records.owner_index = 0;
        records.slot = u64::from(u32::MAX) - 1;
        let final_address = records.next_content_record(0).unwrap().unwrap();
        assert_eq!(final_address.rr_type, RecordType::A as u16);
        let signature = records.next_content_record(0).unwrap().unwrap();
        assert_eq!(signature.rr_type, RecordType::Rrsig as u16);
        assert!(records.next_content_record(0).is_none());
    }

    #[test]
    fn large_rrset_ipv4_sequence_is_unique_beyond_the_old_u16_boundary() {
        let addresses = (0..=u64::from(u16::MAX) + 1)
            .map(|index| ipv4_rdata(7, 11, 13, index))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(addresses.len(), usize::from(u16::MAX) + 2);
    }
}
