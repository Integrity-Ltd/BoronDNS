# RRL defaults

Response rate limiting is enabled by default. These are BoronDNS project
defaults, not a throughput guarantee or another server's vendor defaults.
They match `[rrl]` in [the example configuration](../config/borondns.example.toml)
and [SRS section 4.17](BoronDNS-Secondary-SRS-v1.0.0.md).

| Setting | Default | Requirement |
| --- | ---: | --- |
| RRL enabled | `true` | BDS-FR-RRL-001 |
| IPv4 source prefix length | `24` | BDS-FR-RRL-002 |
| IPv6 source prefix length | `56` | BDS-FR-RRL-002 |
| Positive response rate | `20/s` | BDS-FR-RRL-003 |
| NXDOMAIN response rate | `5/s` | BDS-FR-RRL-003 |
| NODATA response rate | `10/s` | BDS-FR-RRL-003 |
| Referral response rate | `10/s` | BDS-FR-RRL-003 |
| Error response rate | `5/s` | BDS-FR-RRL-003 |
| Slip | `2` | BDS-FR-RRL-005 |
| Maximum tracked keys | `100000` | BDS-FR-RRL-010 |
| Summary log interval | `60s` | BDS-FR-RRL-011 |

Rates apply to the RRL classification key, not to the server's total QPS.
With `slip = 2`, every second rate-limited UDP response is sent truncated, allowing
a legitimate client to retry over TCP; the other responses are dropped.
See the [operator guide](operator-deployment-guide.md) for configuration and
monitoring.

`scripts/rrl-evidence-campaign.sh` records these defaults in
`threshold-decision.tsv`. Its stress interop test deliberately uses zero rates
to force deterministic drop/slip behavior. Those are test settings, not changes
to the defaults. Keep deployment tuning and its measurements with the campaign
evidence.
