# RRL Release Threshold Baseline

This document records the current RRL threshold baseline for Engineering MVP
release review. It is not final approval of the SRS Appendix C.5 pending
decision for `Slip = 2`; release notes must continue to list that item as
pending until the project decision is closed.

The baseline follows `docs/OxideDNS-Secondary-SRS-v0.9.1.md` section 4.17 and is
mirrored by `config/oxidedns.example.toml`.

| Setting | Baseline | SRS requirement | Release-review status |
| --- | ---: | --- | --- |
| RRL enabled | `true` | ODS-FR-RRL-001 | Implemented SRS body default |
| IPv4 source prefix length | `24` | ODS-FR-RRL-002 | Implemented SRS body default |
| IPv6 source prefix length | `56` | ODS-FR-RRL-002 | Implemented SRS body default |
| Positive response rate | `20/s` | ODS-FR-RRL-003 | OxideDNS project default, not a vendor default |
| NXDOMAIN response rate | `5/s` | ODS-FR-RRL-003 | OxideDNS project default, not a vendor default |
| NODATA response rate | `10/s` | ODS-FR-RRL-003 | OxideDNS project default, not a vendor default |
| Referral response rate | `10/s` | ODS-FR-RRL-003 | OxideDNS project default, not a vendor default |
| Error response rate | `5/s` | ODS-FR-RRL-003 | OxideDNS project default, not a vendor default |
| Slip | `2` | ODS-FR-RRL-005 | Implemented SRS body default; C.5 confirmation pending |
| Maximum tracked keys | `100000` | ODS-FR-RRL-010 | Implemented SRS body default |
| Summary log interval | `60s` | ODS-FR-RRL-011 | Implemented SRS body default |

`scripts/rrl-evidence-campaign.sh` writes a retained
`threshold-decision.tsv` artifact with this baseline alongside each RRL
campaign. The campaign's stress interop script intentionally sets per-category
rates to zero to force deterministic drop/slip behavior; those stress settings
are test inputs and do not change the release baseline above.
