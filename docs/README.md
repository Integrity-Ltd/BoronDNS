# BoronDNS documentation

Start with the guide for your task. Current behavior, formal requirements, and
dated test results have different purposes; a historical measurement is not a
performance guarantee for the current release.

## Run BoronDNS

- [Operator guide](operator-deployment-guide.md): install, configure, upgrade,
  and troubleshoot a server.
- [Build from source](devops-getting-started.md): development prerequisites,
  local checks, and package builds.
- [Configuration reference](configuration.md): runtime settings and environment
  overrides.
- [Catalog zones](catalog-zone-rfc9432.md): member discovery and transfer policy.
- [Health and metrics](health-metrics-interface.md): HTTP probes and Prometheus.
- [Observability API](observability-api.md): optional JSON status endpoints.
- [Operational SLOs](operational-slos.md): deployment targets and measurement.
- [Debian VM profile](debian12-beta-vm-profile.md): one container deployment example.
- [Recovery reference](operator-recovery.md): interpreting retained campaign and
  publication state after an interrupted operation.
- [Security policy](../SECURITY.md): vulnerability reports and maintenance.

## Understand the implementation

- [Architecture](architecture.md): components, data flow, and trust boundaries.
- [Feature reference](implemented-feature-scope.md): supported behavior and limits.
- [Query storage and packet I/O](memory-io-data-plane-design.md): current layout
  and the reasons behind it.
- [ZoneImage status](zone-image-implementation-status.md): implementation map,
  measured decisions, and remaining work.
- [Capacity limits](zone-image-capacity-limits.md): wire, storage, ingestion, and
  memory bounds.
- [Large-zone design](zone-image-large-zone-design.md) and
  [snapshot responsibilities](zone-snapshot-narrowing-design.md): storage tradeoffs.
- [Future optimization work](future-optimization-tracks.md): what would justify
  further changes.
- [RR type catalogue](rr-type-catalogue.md): structured validation and opaque types.
- [Interface compatibility](interface-compatibility-policy.md): public interfaces
  and versioning.

## Test and measure

- [Test plan](test-plan.md): routine checks, integration tests, and release work.
- [BoronGun](boron-gun.md): generate query load;
  [developer notes](boron-gun-mvp-plan.md) cover its implementation and validation.
- [BoronGen](boron-gen.md): generate synthetic primary zones;
  [design](boron-gen-design.md) explains determinism and resource use.
- [Client benchmarks](dns-client-benchmark.md) and
  [loss matrix](dns-server-loss-matrix-benchmark.md): choose a measurement.
- [Knot comparison](knot-comparison-benchmark.md): matched setup and retained results.
- [IXFR scaling](ixfr-scaling-2026-08.md): measured update costs and their limits.
- [Fuzzing](../fuzz/README.md), [two-host campaigns](two-host-fuzz-soak-campaign.md),
  and [large-surface soaks](large-surface-soak.md): sustained testing.
- [BIND interoperability](manual-bind-interop.md): primary/secondary lab checks.
- [Reference verification profile](reference-verification-profile.md) and
  [RRL thresholds](rrl-release-thresholds.md): formal measurement conditions.

## Requirements and release work

The [BoronDNS SRS](BoronDNS-Secondary-SRS-v1.0.0.md) is the requirements baseline.
Some requirements are future full-acceptance targets. Use the evidence records
below to establish what has actually been verified. The separate
[BoronGun SRS](BoronGun-SRS-v0.1.md) covers the support tool.

| Document | Use it for |
| --- | --- |
| [Release scope](engineering-mvp-scope.md) | Product and verification boundaries |
| [Readiness checklist](engineering-mvp-readiness.md) | Reviewing a candidate |
| [Development plan](implementation-plan.md) | Priorities and ownership |
| [Acceptance register](release-acceptance-gap-register.md) | Open evidence and acceptance decisions |
| [Verification ledger](verification-ledger.md) | Evidence by requirement family |
| [Traceability matrix](appendix-a-traceability-matrix.md) | Requirement IDs mapped to evidence |
| [RFC assertions](rfc-compliance-assertions.md) | Scoped standards claims |
| [RFC traceability policy](rfc-traceability-policy.md) | How to maintain those claims |
| [Project decisions](project-decision-register.md) | Accepted and pending policy choices |
| [SRS review dispositions](srs-review-disposition.md) | Rationale for past review decisions |
| [Release evidence guide](release-evidence-guide.md) | Capture and publish evidence |
| [Evidence commands](evidence-command-catalog.md) | Script inventory |
| [Release notes template](release-notes-template.md) | Detailed acceptance notes when needed |

The `engineering-mvp-*` filenames remain for existing links and scripts; they
do not mean the 1.0 product is still a prototype.

Machine-readable companions include the [interface baseline](interface-stability-baseline.tsv),
[unsafe-code registry](unsafe-boundaries.tsv), [low-level dependency registry](unsafe-prone-dependencies.tsv),
[DNSSEC matrix](dnssec-conformance-matrix.tsv), and [zone lifecycle matrix](zsm-engineering-mvp-matrix.tsv).

## Historical evidence

These reports describe specific commits and environments. Check their scope
before using a result in a release decision.

- [Final 0.9.1 fuzz campaign](fuzz-soak-v0.9.1-2026-08.md)
- [Knot tuning experiments, June 2026](knot-tuning-2026-06.md)
- [BoronGen validation, July 2026](boron-gen-validation-2026-07.md)
- [Large-memory campaign, July 2026](boron-gen-two-host-campaign-2026-07.md)
- [ZoneImage proposal decisions](zone-image-proposal-disposition-2026-07.md) and
  [follow-up results](zone-image-action-items-2026-07.md)
- [Rust audit remediation, August 2026](rust-audit-remediation-2026-08.md)
- v0.2.0: [primary interop](primary-interop-matrix-v0.2.0.md),
  [XoT evidence](xot-release-evidence-v0.2.0.md),
  [reproducibility](reproducible-build-v0.2.0.md), and
  [package/container smoke](package-docker-smoke-v0.2.0.md)

## Editing documentation

Explain current behavior once in its reference guide and link to it elsewhere.
Keep instructions runnable, name prerequisites, and verify settings against the
code. Put measurements in dated evidence with the commit, configuration, and
limitations. Update requirements only when the intended product contract
changes; an implementation gap needs to be recorded, not written away.

Prefer a short procedure or explanation over a running implementation diary.
Git history preserves old plans. Keep stable requirement IDs and evidence paths
when editing registers, and update the documentation checks when their expected
structure changes. Those checks should protect content and links, not mandate
particular sentences.
