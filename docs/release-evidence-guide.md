# Release Evidence Guide

Status: release and operations evidence runbook for formal SRS acceptance.

This guide owns the mechanics of `scripts/release-evidence-snapshot.sh` and the
handoff directories used by later release/operations runs. It is separate from
the Operator Deployment Guide so day-one deployment instructions stay focused on
running OxideDNS.

The Engineering MVP does not require completed long-running evidence. A
generated handoff directory proves that the setup and artifact shape exist; it
does not prove that the benchmark, soak, reproducible-build comparison,
production-depth logging profile, release-signing review, or external operator
acceptance has been completed.

## Snapshot Profiles

`scripts/engineering-mvp-evidence.sh` writes the bounded Engineering MVP
evidence profile under `target/evidence/engineering-mvp/<timestamp>/`. It runs
repository checks, parser fuzz compile checks, invariant audits, portability
inventory/probes, unused/dead-code audit, resource smoke evidence, coverage
evidence, unsafe-dependency enumeration, and interface-compatibility evidence.
It does not run the real-primary interop scripts or `scripts/perf-smoke.sh` in
the default bounded profile; those commands are recorded as deferred
release/operations work.

`scripts/release-evidence-snapshot.sh` writes release-candidate command logs
under `target/evidence/<timestamp>/`. By default it captures:

- repository check output;
- fuzz compile check output;
- cargo-deny output;
- tool versions;
- git state;
- the current verification command list;
- Test Plan shape check output;
- portability evidence under `portability-evidence/`;
- unused/dead-code audit artifacts under `unused-code-audit/`;
- resource smoke artifacts under `resource-evidence/`;
- `cargo-llvm-cov` threshold artifacts under `coverage-evidence/`;
- `cargo geiger` unsafe dependency enumeration under
  `unsafe-dependency-evidence/`;
- production-depth info verbosity setup under `info-verbosity-handoff/`;
- interface compatibility baseline and optional release-diff output under
  `interface-compatibility/`;
- Reference Hardware/Profile benchmark setup/report files under
  `benchmark-handoff/`;
- long-run soak setup/report files under `soak-handoff/`;
- reproducible-build setup files under `reproducible-build-handoff/`;
- release-governance setup files under `release-handoff/`.

The unsafe dependency evidence records scanner caveats and must be reviewed
before it is treated as complete. The info-verbosity, interface-compatibility,
benchmark, soak, reproducible-build, and release-governance handoffs are
release/operations template sets for delegated runs unless their
release-specific inputs are supplied.

## Optional Evidence Runs

Set `OXIDEDNS_EVIDENCE_RUN_FUZZ=1` to run the fuzz campaign helper inside the
snapshot and retain its `campaign-summary.tsv`.

Set `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` to run the retained RRL evidence
campaign under the snapshot. Use `OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` or
`OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` to choose iteration-count or wall-clock
duration mode.

Set `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` to run the broader interop commands listed
in `docs/evidence-command-catalog.md` as part of the snapshot. Successful
real-primary interop runs write `primary-version.txt` under their
`target/interop/...` workdir. The snapshot copies new files into
`interop-primary-versions/` with an index so each pass/fail result can be tied
to the tested primary implementation version, OS or container package context,
configuration artifacts, transport, and security mode. A skipped script is
missing evidence, not passing evidence.

Set `OXIDEDNS_RELEASE_NOTES` to a completed release-notes markdown file to run
the release-note gate and verify that retained primary-version artifact paths
are published in the notes.

Set `OXIDEDNS_PERF_BASELINE` to a whitespace-delimited history file with rows
shaped as `release metric value` to compare retained `perf-smoke-metrics.env`
values against the rolling baseline.
`OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT` overrides the default 10 percent
regression threshold.

## Handoff Directories

Use the standalone handoff scripts when a release/operations owner needs only
one evidence package instead of a full snapshot.

| Handoff | Command | Purpose |
| --- | --- | --- |
| Benchmark | `scripts/capture-benchmark-handoff.sh` | Creates the Reference Hardware/Profile benchmark runbook, report template, metric/resource TSV schemas, baseline-history template, requirement traceability map, release-note snippet, and operator sign-off template. |
| Info verbosity | `scripts/capture-info-verbosity-handoff.sh` | Creates the production-depth `info` verbosity profile runbook, report template, log-volume/structured-field/metrics TSV schemas, requirement traceability map, release-note snippet, and operator sign-off template. |
| Soak | `scripts/capture-soak-handoff.sh` | Creates the 30-day soak report template, RSS/file-descriptor/metrics/event TSV schemas, weekly summary template, requirement traceability map, and operator sign-off template. |
| Release governance | `scripts/capture-release-handoff.sh` | Creates the evidence attachment map, role ownership TSV, scheduled CI/manual-run plan, signing runbook, release-note fill plan, external-operator acceptance template, and release-readiness checklist. |

For the formal SRS MVP release gate, release notes must also include the
external operator acceptance signature, accepting operator identity, and
accepted scope statement required by `ODS-VER-008` and `ODS-VER-015`.

## Primary Interop Evidence

The Operator Deployment Guide lists the day-one primary interoperability scripts
operators are most likely to run directly. The full command inventory consumed
by the release snapshot is `docs/evidence-command-catalog.md`; that file is the
source for the broader `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` command set.

Retain each successful real-primary run's `primary-version.txt`, redacted
configuration, relevant packet/log artifacts, and traceability TSVs when the
script produces them. Release notes must publish the primary versions and
configuration modes used for accepted interop evidence.
