use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use thiserror::Error;

use crate::{
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
    pub transfer: Option<CatalogMemberTransfer>,
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

pub fn parse_catalog_members(
    catalog_view: CatalogZoneView<'_>,
) -> Result<Vec<CatalogMember>, CatalogError> {
    validate_catalog_version(&catalog_view)?;

    let catalog = catalog_view.origin();
    let zones_owner = DomainName::from_absolute_str(&format!("zones.{catalog}"))
        .expect("valid catalog origin builds valid zones owner");
    let zones_owner_key = zones_owner.canonical_key();
    let mut ptr_records_by_owner = BTreeMap::<String, Vec<_>>::new();
    let extension_rrsets_by_member = extension_rrsets_by_member(catalog_view);

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
        if rrset.rdatas().is_empty() {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: rrset.owner.clone(),
            });
        }
        ptr_records_by_owner
            .entry(rrset.owner.canonical_key())
            .or_default()
            .extend(rrset.rdatas().iter().map(|rdata| (&rrset.owner, rdata)));
    }

    let mut seen_members = HashSet::new();
    let mut members = Vec::new();
    for records in ptr_records_by_owner.into_values() {
        if records.len() != 1 {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: records
                    .first()
                    .expect("non-empty grouped PTR records")
                    .0
                    .clone(),
            });
        }
        let (owner, rdata) = records
            .into_iter()
            .next()
            .expect("single grouped PTR record");
        let (member, consumed) =
            DomainName::parse(rdata, 0).map_err(|_| CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: owner.clone(),
            })?;
        if consumed != rdata.len() {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: owner.clone(),
            });
        }
        if !seen_members.insert(member.canonical_key()) {
            return Err(CatalogError::DuplicateMember {
                catalog: catalog.clone(),
                member,
            });
        }
        members.push(CatalogMember {
            member_node: owner.clone(),
            zone: member,
            transfer: parse_member_transfer_extension(
                owner,
                extension_rrsets_by_member
                    .get(owner.canonical_key().as_str())
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            ),
        });
    }

    members.sort_by_key(|member| member.zone.canonical_key());
    Ok(members)
}

fn extension_rrsets_by_member<'a>(
    catalog_view: CatalogZoneView<'a>,
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
        rrsets_by_member.entry(member_key).or_default().push(rrset);
    }
    rrsets_by_member
}

fn extension_member_key(owner_key: &str) -> Option<String> {
    if let Some(rest) = owner_key.strip_prefix("primaries.ext.") {
        return Some(rest.to_owned());
    }
    if let Some(rest) = owner_key.strip_prefix("_udns-xfr.") {
        return Some(rest.to_owned());
    }
    if let Some(rest) = owner_key.strip_prefix("_udns-notify.") {
        return Some(rest.to_owned());
    }
    None
}

fn parse_member_transfer_extension(
    member_node: &DomainName,
    extension_rrsets: &[&Rrset],
) -> Option<CatalogMemberTransfer> {
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
        if owner_key == primary_base || owner_key.ends_with(&format!(".{primary_base}")) {
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
        return None;
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
        _ => return None,
    };

    notify_sources.sort();
    notify_sources.dedup();

    if primaries.is_empty() && tsig_key_name.is_none() && xfr.is_none() && notify_sources.is_empty()
    {
        None
    } else {
        Some(CatalogMemberTransfer {
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
    for (key, value) in parse_semicolon_fields(text) {
        match key {
            "transport" => match value {
                "tcp" => transport = Some(CatalogMemberTransport::Tcp),
                "xot" => transport = Some(CatalogMemberTransport::Xot),
                _ => return None,
            },
            "port" => {
                let parsed = value.parse::<u16>().ok()?;
                if parsed == 0 {
                    return None;
                }
                port = Some(parsed);
            }
            "server_name" => {
                if value.is_empty() || value.contains(char::is_whitespace) {
                    return None;
                }
                server_name = Some(value.to_owned());
            }
            "mode" => {}
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
    let version_owner = DomainName::from_absolute_str(&format!("version.{catalog}"))
        .expect("valid catalog origin builds valid version owner");
    let version_owner_key = version_owner.canonical_key();
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

        let transfer = members[0].transfer.as_ref().expect("transfer extension");
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
    fn ignores_malformed_member_transfer_extension_without_dropping_member() {
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
        assert_eq!(members[0].transfer, None);
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
}
