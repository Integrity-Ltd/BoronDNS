# Operational SLO Guide

Status: informative operator SLO publication for `BDS-NFR-MAINT-009`.

This guide records suggested operational service-level objectives for BoronDNS
deployments. It is not a formal SRS acceptance claim. Engineering MVP provides
the evidence commands and handoff paths; formal SRS acceptance still depends on
later performance, reliability, soak, and external-operator evidence execution
tracked in `docs/mvp-gap-register.md`.

## Suggested Operational SLOs

| Objective | Suggested target | Evidence source |
| --- | --- | --- |
| Authoritative service readiness | `/readyz` is HTTP 200 for at least 99.9% of one-minute probes outside declared maintenance when at least one zone is expected ACTIVE | `GET /readyz`, zone-state metrics, maintenance record |
| Initial and refresh transfer health | Every configured zone reaches ACTIVE inside the operator's expected transfer window; long-LOADING behavior beyond `[limits].zsm_loading_warning_threshold_secs` is actionable | `/readyz`, `borondns_secondary_zone_loading_seconds`, `zone_loading_threshold_exceeded` logs |
| Direct-hit latency | On the Reference Hardware Profile, keep p99 direct-hit UDP query processing below 1 ms at up to 50% of the `BDS-NFR-PERF-001` throughput target, matching `BDS-NFR-PERF-002` | release benchmark artifacts; smoke metrics are not enough for acceptance |
| Near-capacity latency | On the Reference Hardware Profile, keep p99 query processing below 10 ms at up to 90% of the `BDS-NFR-PERF-001` throughput target, matching `BDS-NFR-PERF-003` | release benchmark artifacts |
| Memory growth | Under a declared stable workload, post-warm-up RSS shows no unexplained continuing growth across the release-selected observation window, matching `BDS-NFR-REL-003` | fuzz/resource or optional soak report with workload, warm-up point, duration, threshold, and RSS samples |
| Rolling restart drain | After SIGTERM, `/readyz` reports draining and TCP listeners stop accepting new connections within 100 ms, matching `BDS-NFR-REL-005` | signal/rolling-restart artifacts |
| Clock synchronisation | Host clock drift stays well below the configured TSIG and DNS Cookie tolerance windows; investigate clock synchronisation drift above 1 second for NTP/PTP-managed hosts, matching the operational premise of `BDS-NFR-REL-007` | host time-sync monitoring, TSIG BADTIME and cookie-invalid metrics/logs |

The first two rows are practical day-one Engineering MVP operating checks. Rows
that depend on the Reference Hardware Profile, release-selected extended-runtime evidence, or release-retained
artifacts are formal release/operations targets; they are not evidence that the
bounded local Engineering MVP has completed those long-running runs.

Operators should tune SLO thresholds to their zone count, primary behavior,
anycast or load-balancer design, and query mix. A release note may publish
stricter or looser deployment-specific SLOs, but it must not weaken the
normative SRS acceptance targets.
