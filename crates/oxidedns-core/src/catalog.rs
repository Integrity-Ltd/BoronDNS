use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::{
    dns::{DomainName, RecordType},
    zone::ZoneSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMember {
    pub member_node: DomainName,
    pub zone: DomainName,
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

pub fn parse_catalog_members(snapshot: &ZoneSnapshot) -> Result<Vec<CatalogMember>, CatalogError> {
    validate_catalog_version(snapshot)?;

    let catalog = &snapshot.origin;
    let zones_owner = DomainName::from_absolute_str(&format!("zones.{catalog}"))
        .expect("valid catalog origin builds valid zones owner");
    let mut ptr_records_by_owner = HashMap::<String, Vec<_>>::new();

    for record in snapshot.records() {
        if record.class != 1 || record.rr_type != RecordType::Ptr as u16 {
            continue;
        }
        if record.owner.parent().as_ref() != Some(&zones_owner) {
            continue;
        }
        ptr_records_by_owner
            .entry(record.owner.canonical_key())
            .or_default()
            .push(record);
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
                    .owner
                    .clone(),
            });
        }
        let record = records
            .into_iter()
            .next()
            .expect("single grouped PTR record");
        let (member, consumed) =
            DomainName::parse(&record.rdata, 0).map_err(|_| CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: record.owner.clone(),
            })?;
        if consumed != record.rdata.len() {
            return Err(CatalogError::MalformedMemberPtr {
                catalog: catalog.clone(),
                owner: record.owner.clone(),
            });
        }
        if member == *catalog || !seen_members.insert(member.canonical_key()) {
            return Err(CatalogError::DuplicateMember {
                catalog: catalog.clone(),
                member,
            });
        }
        members.push(CatalogMember {
            member_node: record.owner,
            zone: member,
        });
    }

    members.sort_by_key(|member| member.zone.canonical_key());
    Ok(members)
}

fn validate_catalog_version(snapshot: &ZoneSnapshot) -> Result<(), CatalogError> {
    let catalog = &snapshot.origin;
    let version_owner = DomainName::from_absolute_str(&format!("version.{catalog}"))
        .expect("valid catalog origin builds valid version owner");
    let version_records = snapshot
        .records()
        .into_iter()
        .filter(|record| {
            record.class == 1
                && record.rr_type == RecordType::Txt as u16
                && record.owner == version_owner
        })
        .collect::<Vec<_>>();

    let [record] = version_records.as_slice() else {
        return Err(CatalogError::MissingOrUnsupportedVersion {
            catalog: catalog.clone(),
        });
    };
    let text = parse_single_txt(&record.rdata).ok_or_else(|| CatalogError::MalformedVersion {
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
    use crate::zone::Rrset;

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

        let members = parse_catalog_members(&snapshot).unwrap();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].zone.canonical_key(), "alpha.example.");
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
            parse_catalog_members(&snapshot),
            Err(CatalogError::DuplicateMember { catalog, member })
        );
    }
}
