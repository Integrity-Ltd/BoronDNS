use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::validate_xot_server_name,
    dns::{DomainName, RecordType},
    zone::{CatalogZoneView, Rrset},
};

// ODS-NFR-MAINT-004 principal functional requirement references for RFC 9432
// catalog-zone parsing and provisioned member-zone derivation:
// - ODS-FR-PROV-001 ODS-FR-PROV-002 ODS-FR-PROV-003 ODS-FR-PROV-004
// - ODS-FR-PROV-005 ODS-FR-PROV-006 ODS-FR-PROV-007 ODS-FR-PROV-008
// - ODS-FR-PROV-009 ODS-FR-PROV-010 ODS-FR-PROV-011 ODS-FR-PROV-012
// - ODS-FR-PROV-013 ODS-FR-PROV-014
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMember {
    pub member_node: DomainName,
    pub zone: DomainName,
    pub transfer: CatalogMemberTransferExtension,
}

/// Parsing state for the optional per-member transfer extension.
///
/// `Malformed` is deliberately distinct from `Absent`: callers may safely use
/// their configured fallback for an absent extension, while a malformed update
/// must not silently replace a previously accepted transfer policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogMemberTransferExtension {
    Absent,
    Valid(CatalogMemberTransfer),
    Malformed,
}

impl CatalogMemberTransferExtension {
    #[must_use]
    pub fn valid(&self) -> Option<&CatalogMemberTransfer> {
        match self {
            Self::Valid(transfer) => Some(transfer),
            Self::Absent | Self::Malformed => None,
        }
    }

    #[must_use]
    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMemberTransfer {
    pub primaries: Vec<CatalogMemberPrimary>,
    pub tsig_key_name: Option<DomainName>,
    pub xfr: Option<CatalogMemberXfr>,
    pub notify_sources: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMemberPrimary {
    pub addr: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogMemberTransport {
    Tcp,
    Xot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMemberXfr {
    pub transport: Option<CatalogMemberTransport>,
    pub port: Option<u16>,
    pub server_name: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CatalogError {
    #[error("catalog zone {catalog} is missing RFC 9432 schema version 2")]
    MissingOrUnsupportedVersion { catalog: DomainName },

    #[error("catalog zone {catalog} has malformed RFC 9432 schema version data")]
    MalformedVersion { catalog: DomainName },

    #[error("catalog zone {catalog} has malformed member PTR data at {owner}")]
    MalformedMemberPtr {
        catalog: DomainName,
        owner: DomainName,
    },

    #[error("catalog zone {catalog} lists duplicate member zone {member}")]
    DuplicateMember {
        catalog: DomainName,
        member: DomainName,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCatalogMembers {
    pub members: Vec<CatalogMember>,
    pub dropped: usize,
}

pub fn parse_catalog_members(
    catalog_view: CatalogZoneView<'_>,
) -> Result<Vec<CatalogMember>, CatalogError> {
    parse_catalog_members_bounded(catalog_view, usize::MAX).map(|parsed| parsed.members)
}

pub fn parse_catalog_members_bounded(
    catalog_view: CatalogZoneView<'_>,
    max_members: usize,
) -> Result<ParsedCatalogMembers, CatalogError> {
    parse_catalog_members_bounded_with_filter(catalog_view, max_members, |_| true)
}

pub fn parse_catalog_members_bounded_with_filter(
    catalog_view: CatalogZoneView<'_>,
    max_members: usize,
    mut accept_member: impl FnMut(&DomainName) -> bool,
) -> Result<ParsedCatalogMembers, CatalogError> {
    validate_catalog_version(&catalog_view)?;

    let catalog = catalog_view.origin();
    let zones_owner_key = catalog_child_owner_key("zones", catalog);
    let mut retained = BTreeMap::<String, (DomainName, DomainName)>::new();
    // Duplicate validity applies to every structurally valid member PTR, even
    // when policy filters it or the retention cap drops it. Keep only a fixed
    // size collision-resistant key per PTR target: the set is bounded by the
    // rrsets already resident in the validated snapshot, while full member and
    // extension allocation remains O(max_members).
    let mut seen_member_keys = HashSet::<[u8; 32]>::new();
    let mut member_records = 0usize;

    for rrset in catalog_view.rrsets() {
        if rrset.class != 1 || rrset.rr_type != RecordType::Ptr as u16 {
            continue;
        }
        if rrset
            .owner
            .parent()
            .map(|parent| parent.canonical_key())
            .as_deref()
            != Some(zones_owner_key.as_str())
        {
            continue;
        }
        let [rdata] = rrset.rdatas() else {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: rrset.owner.clone(),
            });
        };
        let (member, consumed) =
            DomainName::parse(rdata, 0).map_err(|_| CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: rrset.owner.clone(),
            })?;
        if consumed != rdata.len() {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: rrset.owner.clone(),
            });
        }
        let member_key = member.canonical_key();
        let seen_key = Sha256::digest(member_key.as_bytes()).into();
        if !seen_member_keys.insert(seen_key) {
            return Err(CatalogError::DuplicateMember {
                catalog: catalog.clone(),
                member,
            });
        }
        if !accept_member(&member) {
            continue;
        }
        member_records = member_records.saturating_add(1);
        if retained.len() < max_members {
            retained.insert(member_key, (rrset.owner.clone(), member));
        } else if retained
            .last_key_value()
            .is_some_and(|(largest, _)| member_key < *largest)
        {
            retained.pop_last();
            retained.insert(member_key, (rrset.owner.clone(), member));
        }
    }

    let retained_node_keys = retained
        .values()
        .map(|(owner, _)| owner.canonical_key())
        .collect::<HashSet<_>>();
    let extension_rrsets_by_member = extension_rrsets_by_member(catalog_view, &retained_node_keys);
    let members = retained
        .into_values()
        .map(|(owner, member)| CatalogMember {
            transfer: parse_member_transfer_extension(
                &owner,
                extension_rrsets_by_member
                    .get(owner.canonical_key().as_str())
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            ),
            member_node: owner,
            zone: member,
        })
        .collect::<Vec<_>>();
    Ok(ParsedCatalogMembers {
        dropped: member_records.saturating_sub(members.len()),
        members,
    })
}

fn extension_rrsets_by_member<'a>(
    catalog_view: CatalogZoneView<'a>,
    retained_member_keys: &HashSet<String>,
) -> HashMap<String, Vec<&'a Rrset>> {
    let mut rrsets_by_member = HashMap::<String, Vec<&Rrset>>::new();
    for rrset in catalog_view.rrsets() {
        if rrset.class != 1 {
            continue;
        }
        let owner_key = rrset.owner.canonical_key();
        let Some(member_key) = extension_member_key(&owner_key) else {
            continue;
        };
        if retained_member_keys.contains(member_key)
            && recognized_extension_rrset(rrset, &owner_key)
        {
            rrsets_by_member
                .entry(member_key.to_owned())
                .or_default()
                .push(rrset);
        }
    }
    rrsets_by_member
}

fn extension_member_key(owner_key: &str) -> Option<&str> {
    if let Some(rest) = owner_key.strip_prefix("primaries.ext.") {
        return Some(rest);
    }
    if let Some(rest) = owner_key.strip_prefix("_udns-xfr.") {
        return Some(rest);
    }
    if let Some(rest) = owner_key.strip_prefix("_udns-notify.") {
        return Some(rest);
    }
    None
}

fn recognized_extension_rrset(rrset: &Rrset, owner_key: &str) -> bool {
    if owner_key.starts_with("primaries.ext.") {
        matches!(
            rrset.rr_type,
            value if value == RecordType::A as u16
                || value == RecordType::Aaaa as u16
                || value == RecordType::Txt as u16
        )
    } else {
        rrset.rr_type == RecordType::Txt as u16
    }
}

fn parse_member_transfer_extension(
    member_node: &DomainName,
    extension_rrsets: &[&Rrset],
) -> CatalogMemberTransferExtension {
    let primary_base = format!("primaries.ext.{}", member_node.canonical_key());
    let xfr_owner = format!("_udns-xfr.{}", member_node.canonical_key());
    let notify_owner = format!("_udns-notify.{}", member_node.canonical_key());
    let mut primaries = Vec::new();
    let mut key_names_by_owner = HashMap::<String, Vec<DomainName>>::new();
    let mut xfr = None;
    let mut notify_sources = Vec::new();
    let mut malformed = false;

    for rrset in extension_rrsets {
        if rrset.class != 1 {
            continue;
        }
        let owner_key = rrset.owner.canonical_key();
        if owner_key == primary_base {
            match rrset.rr_type {
                value if value == RecordType::A as u16 => {
                    for rdata in rrset.rdatas() {
                        let Ok(bytes) = <[u8; 4]>::try_from(rdata.as_slice()) else {
                            malformed = true;
                            continue;
                        };
                        primaries.push(CatalogMemberPrimary {
                            addr: IpAddr::V4(Ipv4Addr::from(bytes)),
                        });
                    }
                }
                value if value == RecordType::Aaaa as u16 => {
                    for rdata in rrset.rdatas() {
                        let Ok(bytes) = <[u8; 16]>::try_from(rdata.as_slice()) else {
                            malformed = true;
                            continue;
                        };
                        primaries.push(CatalogMemberPrimary {
                            addr: IpAddr::V6(Ipv6Addr::from(bytes)),
                        });
                    }
                }
                value if value == RecordType::Txt as u16 => {
                    for rdata in rrset.rdatas() {
                        let Some(text) = parse_single_txt(rdata) else {
                            malformed = true;
                            continue;
                        };
                        let Ok(text) = std::str::from_utf8(text) else {
                            malformed = true;
                            continue;
                        };
                        let Ok(name) = DomainName::from_absolute_str(text.trim()) else {
                            malformed = true;
                            continue;
                        };
                        key_names_by_owner
                            .entry(owner_key.clone())
                            .or_default()
                            .push(name);
                    }
                }
                _ => {}
            }
        } else if owner_key == xfr_owner && rrset.rr_type == RecordType::Txt as u16 {
            for rdata in rrset.rdatas() {
                let Some(text) = parse_txt_utf8(rdata) else {
                    malformed = true;
                    continue;
                };
                let Some(parsed) = parse_udns_xfr_txt(text) else {
                    malformed = true;
                    continue;
                };
                if xfr.as_ref().is_some_and(|current| current != &parsed) {
                    malformed = true;
                    continue;
                }
                xfr = Some(parsed);
            }
        } else if owner_key == notify_owner && rrset.rr_type == RecordType::Txt as u16 {
            for rdata in rrset.rdatas() {
                let Some(text) = parse_txt_utf8(rdata) else {
                    malformed = true;
                    continue;
                };
                let Some(mut sources) = parse_udns_notify_txt(text) else {
                    malformed = true;
                    continue;
                };
                notify_sources.append(&mut sources);
            }
        }
    }

    if malformed {
        return CatalogMemberTransferExtension::Malformed;
    }

    let mut key_names = key_names_by_owner
        .into_values()
        .flatten()
        .collect::<Vec<_>>();
    key_names.sort_by_key(|name| name.canonical_key());
    key_names.dedup_by_key(|name| name.canonical_key());
    let tsig_key_name = match key_names.as_slice() {
        [] => None,
        [name] => Some(name.clone()),
        _ => return CatalogMemberTransferExtension::Malformed,
    };

    notify_sources.sort();
    notify_sources.dedup();

    if primaries.is_empty() && tsig_key_name.is_none() && xfr.is_none() && notify_sources.is_empty()
    {
        CatalogMemberTransferExtension::Absent
    } else {
        CatalogMemberTransferExtension::Valid(CatalogMemberTransfer {
            primaries,
            tsig_key_name,
            xfr,
            notify_sources,
        })
    }
}

fn parse_txt_utf8(rdata: &[u8]) -> Option<&str> {
    std::str::from_utf8(parse_single_txt(rdata)?).ok()
}

fn parse_udns_xfr_txt(text: &str) -> Option<CatalogMemberXfr> {
    let mut transport = None;
    let mut port = None;
    let mut server_name = None;
    let mut recognized_fields = HashSet::new();
    for (key, value) in parse_semicolon_fields(text) {
        match key {
            "transport" => {
                if !recognized_fields.insert(key) {
                    return None;
                }
                match value {
                    "tcp" => transport = Some(CatalogMemberTransport::Tcp),
                    "xot" => transport = Some(CatalogMemberTransport::Xot),
                    _ => return None,
                }
            }
            "port" => {
                if !recognized_fields.insert(key) {
                    return None;
                }
                let parsed = value.parse::<u16>().ok()?;
                if parsed == 0 {
                    return None;
                }
                port = Some(parsed);
            }
            "server_name" => {
                if !recognized_fields.insert(key) || validate_xot_server_name(value).is_err() {
                    return None;
                }
                server_name = Some(value.to_owned());
            }
            "mode" => {
                if !recognized_fields.insert(key) {
                    return None;
                }
            }
            "" => {}
            _ => {}
        }
    }
    Some(CatalogMemberXfr {
        transport,
        port,
        server_name,
    })
}

fn parse_udns_notify_txt(text: &str) -> Option<Vec<IpAddr>> {
    let mut sources = Vec::new();
    for (key, value) in parse_semicolon_fields(text) {
        match key {
            "source" | "sources" => {
                for source in value.split(',') {
                    let source = source.trim();
                    if source.is_empty() {
                        continue;
                    }
                    sources.push(source.parse::<IpAddr>().ok()?);
                }
            }
            "" => {}
            _ => {}
        }
    }
    Some(sources)
}

fn parse_semicolon_fields(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.split(';').map(|field| {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        (key.trim(), value.trim())
    })
}

fn validate_catalog_version(catalog_view: &CatalogZoneView<'_>) -> Result<(), CatalogError> {
    let catalog = catalog_view.origin();
    let version_owner_key = catalog_child_owner_key("version", catalog);
    let version_records = catalog_view.rrsets().find_map(|rrset| {
        (rrset.class == 1
            && rrset.rr_type == RecordType::Txt as u16
            && rrset.owner.canonical_key() == version_owner_key)
            .then(|| rrset.rdatas())
    });

    let Some([rdata]) = version_records else {
        return Err(CatalogError::MissingOrUnsupportedVersion {
            catalog: catalog.clone(),
        });
    };
    let text = parse_single_txt(rdata).ok_or_else(|| CatalogError::MalformedVersion {
        catalog: catalog.clone(),
    })?;
    if text == b"2" {
        Ok(())
    } else {
        Err(CatalogError::MissingOrUnsupportedVersion {
            catalog: catalog.clone(),
        })
    }
}

fn catalog_child_owner_key(label: &str, catalog: &DomainName) -> String {
    let catalog_key = catalog.canonical_key();
    if catalog_key == "." {
        format!("{label}.")
    } else {
        format!("{label}.{catalog_key}")
    }
}

fn parse_single_txt(rdata: &[u8]) -> Option<&[u8]> {
    let (&len, rest) = rdata.split_first()?;
    let len = len as usize;
    if rest.len() == len { Some(rest) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{Rrset, ZoneSnapshot};

    #[test]
    fn parses_rfc9432_member_ptrs() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("group.a.zones.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![3, b'o', b'p', b's']],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].zone.canonical_key(), "alpha.example.");
    }

    #[test]
    fn bounded_catalog_parse_retains_deterministic_smallest_members_and_counts_drops() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let mut rrsets = vec![Rrset::new(
            DomainName::from_absolute_str("version.catalog.example.").unwrap(),
            RecordType::Txt as u16,
            1,
            0,
            vec![vec![1, b'2']],
        )];
        for (node, member) in [
            ("z", "zulu.example."),
            ("c", "charlie.example."),
            ("y", "yankee.example."),
            ("a", "alpha.example."),
            ("b", "bravo.example."),
        ] {
            rrsets.push(Rrset::new(
                DomainName::from_absolute_str(&format!("{node}.zones.catalog.example.")).unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![DomainName::from_absolute_str(member).unwrap().to_wire()],
            ));
        }
        let snapshot = ZoneSnapshot::active(catalog, None, rrsets);

        let parsed = parse_catalog_members_bounded(snapshot.catalog_zone_view(), 3).unwrap();

        assert_eq!(parsed.dropped, 2);
        assert_eq!(
            parsed
                .members
                .iter()
                .map(|member| member.zone.canonical_key())
                .collect::<Vec<_>>(),
            ["alpha.example.", "bravo.example.", "charlie.example."]
        );
    }

    #[test]
    fn bounded_catalog_parse_rejects_duplicate_targets_when_all_members_are_dropped() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let duplicate = DomainName::from_absolute_str("duplicate.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog.clone(),
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![duplicate.to_wire()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![duplicate.to_wire()],
                ),
            ],
        );

        assert_eq!(
            parse_catalog_members_bounded(snapshot.catalog_zone_view(), 0),
            Err(CatalogError::DuplicateMember {
                catalog,
                member: duplicate,
            })
        );
    }

    #[test]
    fn bounded_catalog_parse_rejects_duplicate_targets_filtered_by_policy() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let duplicate = DomainName::from_absolute_str("static.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog.clone(),
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![duplicate.to_wire()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![duplicate.to_wire()],
                ),
            ],
        );

        assert_eq!(
            parse_catalog_members_bounded_with_filter(snapshot.catalog_zone_view(), 1, |_| false),
            Err(CatalogError::DuplicateMember {
                catalog,
                member: duplicate,
            })
        );
    }

    #[test]
    fn parses_catalog_version_and_member_owner_case_insensitively() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("VERSION.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.ZONES.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("Alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].zone.canonical_key(), "alpha.example.");
    }

    #[test]
    fn parses_catalog_with_non_ascii_origin_without_display_roundtrip() {
        let catalog_wire = catalog_origin_wire_with_long_escaped_label();
        let catalog = domain_from_wire(&catalog_wire);
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    domain_from_wire(&child_wire("version", &catalog_wire)),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    domain_from_wire(&child_wire("a.zones", &catalog_wire)),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].zone.canonical_key(), "alpha.example.");
    }

    #[test]
    fn empty_catalog_member_ptr_rrset_is_malformed_without_panicking() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog.clone(),
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    Vec::new(),
                ),
            ],
        );

        assert_eq!(
            parse_catalog_members(snapshot.catalog_zone_view()),
            Err(CatalogError::MalformedMemberPtr {
                catalog,
                owner: DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
            })
        );
    }

    #[test]
    fn parses_opt_in_member_transfer_extension_records() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.")
                        .unwrap(),
                    RecordType::A as u16,
                    1,
                    0,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.")
                        .unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("member-key.example.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_udns-xfr.a.zones.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("transport=tcp;port=5300;mode=axfr-ixfr")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_udns-notify.a.zones.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("sources=198.51.100.1,2001:db8::1")],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        let CatalogMemberTransferExtension::Valid(transfer) = &members[0].transfer else {
            panic!("expected valid transfer extension");
        };
        assert_eq!(
            transfer.primaries,
            vec![CatalogMemberPrimary {
                addr: "192.0.2.53".parse().unwrap()
            }]
        );
        assert_eq!(
            transfer
                .tsig_key_name
                .as_ref()
                .map(DomainName::canonical_key),
            Some("member-key.example.".to_owned())
        );
        assert_eq!(transfer.xfr.as_ref().and_then(|xfr| xfr.port), Some(5300));
        assert_eq!(transfer.notify_sources.len(), 2);
    }

    #[test]
    fn ignores_subdomain_member_transfer_extension_owner() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("grp1.primaries.ext.a.zones.catalog.example.")
                        .unwrap(),
                    RecordType::A as u16,
                    1,
                    0,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].transfer, CatalogMemberTransferExtension::Absent);
    }

    #[test]
    fn marks_malformed_member_transfer_extension_without_dropping_member() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog,
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("2")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("alpha.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_udns-xfr.a.zones.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![txt("transport=udp;port=0")],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].zone.canonical_key(), "alpha.example.");
        assert_eq!(
            members[0].transfer,
            CatalogMemberTransferExtension::Malformed
        );
    }

    #[test]
    fn rejects_conflicting_xfr_txt_policies_but_accepts_identical_duplicates() {
        let member_node =
            DomainName::from_absolute_str("a.zones.catalog.example.").expect("member node");
        let owner =
            DomainName::from_absolute_str("_udns-xfr.a.zones.catalog.example.").expect("XFR owner");
        let conflicting = Rrset::new(
            owner.clone(),
            RecordType::Txt as u16,
            1,
            0,
            vec![
                txt("transport=tcp;port=53"),
                txt("transport=xot;port=853;server_name=primary.example"),
            ],
        );
        assert_eq!(
            parse_member_transfer_extension(&member_node, &[&conflicting]),
            CatalogMemberTransferExtension::Malformed
        );

        let identical = Rrset::new(
            owner,
            RecordType::Txt as u16,
            1,
            0,
            vec![
                txt("transport=xot;port=853;server_name=primary.example"),
                txt("transport=xot;port=853;server_name=primary.example"),
            ],
        );
        assert!(matches!(
            parse_member_transfer_extension(&member_node, &[&identical]),
            CatalogMemberTransferExtension::Valid(_)
        ));
    }

    #[test]
    fn rejects_duplicate_xfr_fields_and_non_production_sni_names() {
        for text in [
            "transport=xot;transport=xot",
            "port=853;port=853",
            "server_name=primary.example;server_name=primary.example",
            "mode=axfr;mode=axfr",
            "transport=xot;server_name=-primary.example",
            "transport=xot;server_name=primary..example",
            "transport=xot;server_name=primary.example.",
            "transport=xot;server_name=primary_example",
        ] {
            assert_eq!(parse_udns_xfr_txt(text), None, "accepted {text:?}");
        }
        assert_eq!(
            parse_udns_xfr_txt("transport=xot;port=853;server_name=primary.example"),
            Some(CatalogMemberXfr {
                transport: Some(CatalogMemberTransport::Xot),
                port: Some(853),
                server_name: Some("primary.example".to_owned()),
            })
        );
    }

    #[test]
    fn rejects_duplicate_member_zones() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let member = DomainName::from_absolute_str("alpha.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog.clone(),
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![member.to_wire()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![member.to_wire()],
                ),
            ],
        );

        assert_eq!(
            parse_catalog_members(snapshot.catalog_zone_view()),
            Err(CatalogError::DuplicateMember { catalog, member })
        );
    }

    #[test]
    fn accepts_rfc9432_example_special_use_and_wildcard_member_names() {
        let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog.clone(),
            None,
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("example.com.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![DomainName::from_absolute_str("invalid.").unwrap().to_wire()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("c.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![
                        DomainName::from_absolute_str("*.wild.example.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
            ],
        );

        let members = parse_catalog_members(snapshot.catalog_zone_view()).unwrap();

        let member_zones = members
            .iter()
            .map(|member| member.zone.canonical_key())
            .collect::<Vec<_>>();
        assert_eq!(
            member_zones,
            vec![
                "*.wild.example.".to_owned(),
                "example.com.".to_owned(),
                "invalid.".to_owned(),
            ]
        );
    }

    fn txt(value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        assert!(bytes.len() < 256);
        let mut rdata = vec![bytes.len() as u8];
        rdata.extend_from_slice(bytes);
        rdata
    }

    fn domain_from_wire(wire: &[u8]) -> DomainName {
        DomainName::from_uncompressed_wire(wire).expect("valid test name wire")
    }

    fn catalog_origin_wire_with_long_escaped_label() -> Vec<u8> {
        let mut wire = Vec::with_capacity(18);
        wire.push(16);
        wire.extend(std::iter::repeat_n(0x80, 16));
        wire.push(0);
        wire
    }

    fn child_wire(labels: &str, suffix_wire: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        for label in labels.split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.extend_from_slice(suffix_wire);
        wire
    }
}
