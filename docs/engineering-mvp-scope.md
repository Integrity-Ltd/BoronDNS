# Engineering MVP Scope

The Engineering MVP is the current local target for OxideDNS. It is not the SRS
`ODS-VER-008` release-acceptance gate.

## In Scope

- A deployable secondary-authoritative DNS server for the core operational path.
- Deterministic unit and integration tests that run in the normal local check
  profile.
- Short runtime smoke and interop captures that prove the implemented behavior
  is wired through the binary.
- Configuration, CLI, logging, health, metrics, shutdown, dependency, unused
  code, unsafe-boundary, and traceability checks.
- Documentation that records current implementation evidence and the remaining
  release-acceptance gaps without claiming final SRS acceptance.
- Implemented post-Alpha protocol slices listed in `docs/implementation-plan.md`
  and `docs/mvp-gap-register.md`, including IXFR, XoT, passive DNSSEC serving,
  RRL, DNS Cookies, catalog zones, broad EDNS behavior, EDE, and CHAOS queries.
  These are not removed from Engineering MVP scope merely because they exceed a
  minimal static-zone secondary-server trim.

## Out Of Scope

The Engineering MVP must not require completed long-running evidence. The
following are later SRS acceptance or release/operations activities:

- 24-hour fuzz campaigns per parser target.
- 30-day soak execution.
- Reference Hardware/Profile benchmark campaigns.
- Production-depth `info` verbosity profiling under release traffic.
- External operator acceptance.
- Independent reproducible-build comparison.
- Signed release artifact production.

Setup scripts, schemas, runbooks, and handoff directories for those later
activities may exist in this repository for later release/operations use. They
are not Engineering MVP deliverables and are not Engineering MVP evidence.

## Check Profile

`scripts/check.sh` is the local Engineering MVP quality gate. It may validate
script syntax and dry-run campaign wiring, but it must not execute the
long-running activities or generate long-running handoff evidence listed above.

`scripts/engineering-mvp-evidence.sh` is the bounded local evidence snapshot for
the Engineering MVP profile. By default it runs only the narrow local evidence
commands listed in the gap register, applies a per-command timeout, and records
broader release/operations commands as deferred rather than executing them.
