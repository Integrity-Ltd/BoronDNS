# Operational objectives

Choose service objectives for your deployment before adding alert thresholds.
These are starting points, not availability guarantees or claims that a
particular host meets the project's performance targets.

## Suggested objectives

| Objective | Starting point | How to measure it |
| --- | --- | --- |
| DNS availability | At least 99.9% successful external probes outside declared maintenance; choose representative zones and query types. | Probe both UDP and TCP from client-facing networks. Check answer content, not just response arrival. |
| Complete zone coverage | Every expected zone is ACTIVE after its initial transfer window. | Per-zone state/serial metrics and an external list of expected zones. `/readyz` only requires one active zone. |
| Update freshness | A primary update becomes visible within a window appropriate to the zone's update rate and transfer size. | Compare primary and secondary serials; measure NOTIFY-to-publication time and periodic-refresh behavior. |
| Query latency | Set a p99 budget at a stated load, query mix, answer size, and loss rate. | Client measurements plus server processing histograms when detailed metrics are enabled. |
| Memory and storage | Leave capacity for transfer/publication overlap and detect unexplained growth after warm-up. | RSS/cgroup usage, transfer-budget metrics, zone-cache space, and a stable workload description. |
| Rolling restart | Remove a draining node from traffic and finish shutdown within its configured grace period. | Readiness, supervisor logs, and client probes during the restart. |
| Clock synchronization | Keep drift well below TSIG and DNS Cookie tolerances; investigate drift above one second on managed NTP/PTP hosts. | Host time monitoring and authentication failures. BoronDNS's time endpoint currently reports `unknown`. |

Treat sustained LOADING, EXPIRED zones, transfer failures, and unexpected
TSIG/NOTIFY failures as actionable. The default loading warning threshold is
one hour; a small estate may need a much shorter alert window. Avoid restarting
every secondary automatically when the shared primary is unavailable.

Keep the expected zone inventory, maintenance exclusions, probe locations,
query mix, thresholds, and alert routing with deployment configuration. A
Grafana panel or a successful short benchmark is not an availability record.

## Relationship to project targets

The [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) defines development/release targets;
this guide supplies operational guidance for `BDS-NFR-MAINT-009`.
The reference throughput and latency requirements
(`BDS-NFR-PERF-001`, `002`, and `003`) apply to their stated hardware and
load profile. Memory-growth, drain, and clock requirements are
`BDS-NFR-REL-003`, `005`, and `007`.

Use the release's measured evidence to assess those targets. Set site
objectives from your own capacity and redundancy design rather than copying a
reference-host throughput number into a service promise.
