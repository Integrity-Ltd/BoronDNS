# RRL Release Threshold Baseline

This document records the current RRL threshold baseline for Engineering MVP
release review. SRS Appendix C.5 resolves the `Slip = 2` default in v0.9.1;
release notes still need retained operational evidence before formal SRS
acceptance can claim that the whole RRL threshold profile has been reviewed for
the accepted release.

The baseline follows `docs/BoronDNS-Secondary-SRS-v0.9.1.md` section 4.17 and is
mirrored by `config/borondns.example.toml`.

| Setting | Baseline | SRS requirement | Release-review status |
| --- | ---: | --- | --- |
| RRL enabled | `true` | BDS-FR-RRL-001 | Implemented SRS body default |
| IPv4 source prefix length | `24` | BDS-FR-RRL-002 | Implemented SRS body default |
| IPv6 source prefix length | `56` | BDS-FR-RRL-002 | Implemented SRS body default |
| Positive response rate | `20/s` | BDS-FR-RRL-003 | BoronDNS project default, not a vendor default |
| NXDOMAIN response rate | `5/s` | BDS-FR-RRL-003 | BoronDNS project default, not a vendor default |
| NODATA response rate | `10/s` | BDS-FR-RRL-003 | BoronDNS project default, not a vendor default |
| Referral response rate | `10/s` | BDS-FR-RRL-003 | BoronDNS project default, not a vendor default |
| Error response rate | `5/s` | BDS-FR-RRL-003 | BoronDNS project default, not a vendor default |
| Slip | `2` | BDS-FR-RRL-005 | Resolved SRS v0.9.1 default; retain operational evidence before formal acceptance |
| Maximum tracked keys | `100000` | BDS-FR-RRL-010 | Implemented SRS body default |
| Summary log interval | `60s` | BDS-FR-RRL-011 | Implemented SRS body default |

`scripts/rrl-evidence-campaign.sh` writes a retained
`threshold-decision.tsv` artifact with this baseline alongside each RRL
campaign. The campaign's stress interop script intentionally sets per-category
rates to zero to force deterministic drop/slip behavior; those stress settings
are test inputs and do not change the release baseline above.
