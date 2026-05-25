#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_BENCHMARK_HANDOFF_DIR:-$repo_root/target/evidence/benchmark-handoff-$timestamp}"

profile="${OXIDEDNS_BENCHMARK_PROFILE:-Reference Hardware Profile}"
query_mix="${OXIDEDNS_BENCHMARK_QUERY_MIX:-Reference Query Mix}"
regression_threshold_pct="${OXIDEDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT:-10}"
min_duration_seconds="${OXIDEDNS_BENCHMARK_MIN_DURATION_SECONDS:-300}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    printf '%s must be a positive integer: %s\n' "$name" "$value" >&2
    exit 64
  }
}

require_positive_integer OXIDEDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT "$regression_threshold_pct"
require_positive_integer OXIDEDNS_BENCHMARK_MIN_DURATION_SECONDS "$min_duration_seconds"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/benchmark-env.env" <<EOF
OXIDEDNS_BENCHMARK_PROFILE=$profile
OXIDEDNS_BENCHMARK_QUERY_MIX=$query_mix
OXIDEDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT=$regression_threshold_pct
OXIDEDNS_BENCHMARK_MIN_DURATION_SECONDS=$min_duration_seconds
EOF

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
ODS-NFR-PERF-001	benchmark-report-template.md; metric-results.tsv	setup-ready	record UDP authoritative query throughput on the Reference Hardware Profile
ODS-NFR-PERF-002	benchmark-report-template.md; metric-results.tsv	setup-ready	record p99 direct-hit UDP latency at 50 percent target throughput
ODS-NFR-PERF-003	benchmark-report-template.md; metric-results.tsv	setup-ready	record p99 query latency at 90 percent target throughput
ODS-NFR-PERF-004	benchmark-report-template.md; metric-results.tsv	setup-ready	record TCP throughput and latency under pipelined query load
ODS-NFR-PERF-005	benchmark-report-template.md; metric-results.tsv	setup-ready	record AXFR ingestion throughput and publication latency
ODS-NFR-PERF-006	benchmark-report-template.md; metric-results.tsv	setup-ready	record IXFR refresh throughput and publication latency where primary support permits it
ODS-NFR-PERF-007	benchmark-report-template.md; metric-results.tsv	setup-ready	record DNSSEC passive-serve latency and response-size impact
ODS-NFR-PERF-008	benchmark-report-template.md; metric-results.tsv	setup-ready	record overload behavior and recovery timing at configured limits
ODS-NFR-RES-001	resource-results.tsv	setup-ready	record RSS/VSZ/thread/file-descriptor samples during each benchmark phase
ODS-NFR-RES-002	resource-results.tsv	setup-ready	record measured bytes per transferred record and compare with the release target
ODS-NFR-RES-003	resource-results.tsv	setup-ready	record idle CPU and steady-state CPU under representative traffic
ODS-NFR-RES-004	resource-results.tsv	setup-ready	record file-descriptor formula inputs, observed fd count, and OS limits
ODS-NFR-RES-005	resource-results.tsv	setup-ready	record published OCI image size and binary size
ODS-NFR-RES-006	resource-results.tsv	setup-ready	record capacity limit behavior and failure mode for configured resource caps
ODS-VER-008	benchmark-report-template.md; operator-signoff.md	setup-ready	attach completed benchmark report to MVP release evidence before final SRS acceptance
ODS-VER-010	release-notes-snippet.md	setup-ready	publish completed benchmark result and evidence paths in release notes
ODS-VER-012	baseline-history-template.tsv	setup-ready	update rolling baseline and triage regressions above threshold
ODS-VER-015	operator-signoff.md	setup-ready	record responsible release/operations owner and external operator scope/signature
EOF

cat >"$evidence_dir/metric-results.tsv" <<'EOF'
requirement_id	metric_name	unit	target_value	measured_value	status	duration_seconds	workload_profile	artifact_path	notes
EOF

cat >"$evidence_dir/resource-results.tsv" <<'EOF'
timestamp_utc	phase	requirement_id	rss_bytes	vsz_bytes	threads	fd_count	soft_fd_limit	hard_fd_limit	binary_size_bytes	oci_image_size_bytes	records_loaded	bytes_per_record	idle_cpu_percent	notes
EOF

cat >"$evidence_dir/baseline-history-template.tsv" <<'EOF'
release	metric	value	unit	profile	query_mix	evidence_artifact
EOF

cat >"$evidence_dir/workload-profile-template.md" <<EOF
# OxideDNS Benchmark Workload Profile

- Profile name: $profile
- Query mix: $query_mix
- Release:
- Commit:
- Binary identity:
- Hardware:
- Kernel:
- Container runtime:
- NIC and driver:
- DNS interface:
- Transfer interface:
- Management interface:
- Zone corpus:
- Record count:
- DNSSEC corpus:
- Primary implementations and versions:
- Query generator:
- Query-source distribution:
- UDP payload policy:
- TCP pipelining profile:
- RRL policy:
- DNS Cookie policy:
- TSIG/XoT profile:
- Deviations from Reference Hardware/Profile:
EOF

cat >"$evidence_dir/benchmark-runbook.md" <<'EOF'
# OxideDNS Benchmark Runbook

1. Build the release candidate with `cargo build --locked --release`.
2. Record `git rev-parse HEAD`, `rustc --version`, `cargo --version`, kernel,
   CPU, memory, NIC, driver, and container runtime versions.
3. Fill `workload-profile-template.md` before running load.
4. Start OxideDNS with DNS, transfer, and management interfaces separated.
5. Load the release zone corpus from real or fixture primaries.
6. Record readiness, transfer, zone-state, query, latency, RCODE, and resource
   metrics before load, during each phase, and after load.
7. Run each required throughput, latency, transfer, overload, and resource
   phase for at least the configured minimum duration.
8. Fill `metric-results.tsv`, `resource-results.tsv`, and
   `benchmark-report-template.md`.
9. Update `baseline-history-template.tsv` or the release baseline store with
   the accepted candidate values.
10. Run `scripts/check-perf-regression.py` against the rolling history and
    record any regression triage in the release notes.
EOF

cat >"$evidence_dir/operator-signoff.md" <<'EOF'
# OxideDNS Benchmark Operator Sign-off

- Release:
- Evidence snapshot:
- Benchmark evidence directory:
- Release/operations owner:
- External operator, if applicable:
- Accepted scope:
- Requirements covered:
  - ODS-NFR-PERF-001..ODS-NFR-PERF-008
  - ODS-NFR-RES-001..ODS-NFR-RES-006
  - ODS-VER-008
  - ODS-VER-010
  - ODS-VER-012
  - ODS-VER-015
- Result:
- Regressions triaged:
- Exceptions or accepted deviations:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/release-notes-snippet.md" <<'EOF'
## Benchmark Evidence Summary

- Benchmark handoff or completed artifact path:
- Reference Hardware/Profile used:
- Query mix:
- Regression baseline history:
- Regression threshold:
- New failed performance/resource requirements:
- New deferred performance/resource requirements:
- Accepted deviations:
- Release/operations owner:
EOF

cat >"$evidence_dir/benchmark-report-template.md" <<EOF
# OxideDNS Reference Hardware/Profile Benchmark Report

## Scope

- Release:
- Commit:
- Evidence snapshot:
- Benchmark start UTC:
- Benchmark end UTC:
- Minimum phase duration: $min_duration_seconds seconds
- Profile: $profile
- Query mix: $query_mix
- Regression threshold: $regression_threshold_pct percent
- Primary implementation versions:
- Configuration profile:
- Reference Hardware/Profile deviations:

## Required Attachments

- \`workload-profile-template.md\` completed for the run
- \`metric-results.tsv\`
- \`resource-results.tsv\`
- \`baseline-history-template.tsv\` or release baseline export
- Query-generator raw output
- OxideDNS metrics snapshots
- OxideDNS logs
- \`operator-signoff.md\`

## Required Metric Families

- UDP authoritative throughput
- Direct-hit p99 latency at 50 percent capacity
- Near-capacity p99 latency at 90 percent capacity
- TCP query throughput and pipelined latency
- AXFR ingestion throughput and publication latency
- IXFR refresh throughput and publication latency, where supported
- DNSSEC passive-serve latency and response-size impact
- Overload behavior and recovery timing
- RSS, VSZ, threads, file descriptors, idle CPU, binary size, OCI image size,
  bytes per transferred record, and configured resource-cap behavior

## Regression Method

Use the median of the last five accepted release measurements for the same
metric on the same profile. A performance/resource regression is a degradation
above $regression_threshold_pct percent unless the release notes record an
accepted rationale and remediation owner.

## Results

- Overall benchmark result:
- Failed requirements:
- Deferred requirements:
- Regression triage:
- Accepted deviations:
- Remediation owners:
- Target remediation releases:
EOF

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Benchmark Handoff

Created UTC: $timestamp

This directory is the local project MVP setup artifact for later
release/operations execution of Reference Hardware/Profile benchmarks. It does
not claim that production benchmarks have run. It provides the runbook, report
template, metric/resource TSV schemas, baseline-history format, requirement
traceability, release-note snippet, environment values, and sign-off scaffold
needed for later SRS acceptance.

Run configuration:

\`\`\`
OXIDEDNS_BENCHMARK_PROFILE=$profile
OXIDEDNS_BENCHMARK_QUERY_MIX=$query_mix
OXIDEDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT=$regression_threshold_pct
OXIDEDNS_BENCHMARK_MIN_DURATION_SECONDS=$min_duration_seconds
\`\`\`

Artifacts:

- \`benchmark-report-template.md\`
- \`benchmark-runbook.md\`
- \`requirements-traceability.tsv\`
- \`metric-results.tsv\`
- \`resource-results.tsv\`
- \`baseline-history-template.tsv\`
- \`workload-profile-template.md\`
- \`operator-signoff.md\`
- \`release-notes-snippet.md\`
- \`benchmark-env.env\`
EOF

printf 'benchmark_handoff_dir=%s\n' "$evidence_dir"
