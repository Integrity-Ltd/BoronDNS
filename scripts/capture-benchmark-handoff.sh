#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BORONDNS_BENCHMARK_HANDOFF_DIR:-$repo_root/target/evidence/benchmark-handoff-$timestamp}"

profile="${BORONDNS_BENCHMARK_PROFILE:-Reference Hardware Profile}"
query_mix="${BORONDNS_BENCHMARK_QUERY_MIX:-Reference Query Mix}"
regression_threshold_pct="${BORONDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT:-10}"
min_duration_seconds="${BORONDNS_BENCHMARK_MIN_DURATION_SECONDS:-300}"

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s must be a positive integer: %s\n' "$name" "$value" >&2
        exit 64
    }
}

require_positive_integer BORONDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT "$regression_threshold_pct"
require_positive_integer BORONDNS_BENCHMARK_MIN_DURATION_SECONDS "$min_duration_seconds"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/benchmark-env.env" <<EOF
BORONDNS_BENCHMARK_PROFILE=$profile
BORONDNS_BENCHMARK_QUERY_MIX=$query_mix
BORONDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT=$regression_threshold_pct
BORONDNS_BENCHMARK_MIN_DURATION_SECONDS=$min_duration_seconds
EOF

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
BDS-NFR-PERF-001	benchmark-report-template.md; metric-results.tsv	setup-ready	record UDP authoritative query throughput on the Reference Hardware Profile
BDS-NFR-PERF-002	benchmark-report-template.md; metric-results.tsv	setup-ready	record p99 direct-hit UDP latency at 50 percent target throughput
BDS-NFR-PERF-003	benchmark-report-template.md; metric-results.tsv	setup-ready	record p99 query latency at 90 percent target throughput
BDS-NFR-PERF-004	benchmark-report-template.md; metric-results.tsv	setup-ready	record AXFR ingestion throughput including validation and publication
BDS-NFR-PERF-005	benchmark-report-template.md; metric-results.tsv	setup-ready	record process initialization time for up to 1000 zones, excluding transfer completion
BDS-NFR-PERF-006	benchmark-report-template.md; metric-results.tsv	setup-ready	record TCP throughput with at least 32 in-flight queries per connection
BDS-NFR-PERF-007	benchmark-report-template.md; metric-results.tsv	setup-ready	record HMAC-SHA256 verification throughput under signed NOTIFY load
BDS-NFR-PERF-008	benchmark-report-template.md; metric-results.tsv	setup-ready	record NSEC DNSSEC-augmented query throughput with DO=1
BDS-NFR-RES-001	resource-results.tsv	setup-ready	record published container image uncompressed size
BDS-NFR-RES-002	resource-results.tsv	setup-ready	record measured bytes per transferred record and compare with the release target
BDS-NFR-RES-003	resource-results.tsv	setup-ready	record service of 10000 zones and 10 million records with 16 GiB available memory
BDS-NFR-RES-004	resource-results.tsv	setup-ready	record file-descriptor formula inputs, observed fd count, and OS limits
BDS-NFR-RES-005	resource-results.tsv	setup-ready	record that concurrent AXFR and IXFR sessions stay within the configured transfer limit
BDS-NFR-RES-006	resource-results.tsv	setup-ready	record idle CPU over five minutes for 1000 active zones with one million records after 60 seconds without queries
BDS-VER-008	benchmark-report-template.md; operator-signoff.md	setup-ready	record measured targets and accepted limitations for the public-beta milestone
BDS-VER-010	release-notes-snippet.md	setup-ready	retain benchmark results in canonical evidence and link them from release notes where relevant
BDS-VER-012	baseline-history-template.tsv	setup-ready	update rolling baseline and triage regressions above threshold
BDS-VER-015	operator-signoff.md	setup-ready	record the release engineer and Architecture Owner review; record optional external review when available
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
# BoronDNS Benchmark Workload Profile

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
# BoronDNS Benchmark Runbook

1. Select the release binary to test, or build the candidate with
   `cargo build --locked --release` and record its feature set.
2. Record `git rev-parse HEAD`, `rustc --version`, `cargo --version`, kernel,
   CPU, memory, NIC, driver, and container runtime versions.
3. Fill `workload-profile-template.md` before running load.
4. Start BoronDNS with the reference query/management interface separation and
   writable zone cache. Record any separate transfer interface and all deviations.
5. Load the release zone corpus from real or fixture primaries.
6. Record readiness, transfer, zone-state, query, latency, RCODE, and resource
   metrics before load, during each phase, and after load.
7. Run each required throughput, latency, transfer, and resource phase for at
   least the configured minimum duration. Use the requirement's own timing
   window for initialization and idle-CPU measurements.
8. Fill `metric-results.tsv`, `resource-results.tsv`, and
   `benchmark-report-template.md`.
9. Update `baseline-history-template.tsv` or the release baseline store with
   the accepted candidate values.
10. Run `scripts/check-perf-regression.py` against the rolling history and
    record any regression triage in the release notes.
EOF

cat >"$evidence_dir/operator-signoff.md" <<'EOF'
# BoronDNS Benchmark Operator Sign-off

- Release:
- Evidence snapshot:
- Benchmark evidence directory:
- Release/operations owner:
- External operator, if applicable:
- Accepted scope:
- Requirements covered:
  - BDS-NFR-PERF-001..BDS-NFR-PERF-008
  - BDS-NFR-RES-001..BDS-NFR-RES-006
  - BDS-VER-008
  - BDS-VER-010
  - BDS-VER-012
  - BDS-VER-015
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
# BoronDNS Reference Hardware/Profile Benchmark Report

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
- BoronDNS metrics snapshots
- BoronDNS logs
- \`operator-signoff.md\`

## Required Metric Families

- UDP authoritative throughput
- Direct-hit p99 latency at 50 percent capacity
- Near-capacity p99 latency at 90 percent capacity
- AXFR ingestion throughput and publication latency
- Process initialization time with up to 1,000 zones
- TCP query throughput and pipelined latency
- HMAC-SHA256 verification throughput under signed NOTIFY load
- NSEC DNSSEC-augmented query throughput and response-size impact
- RSS, VSZ, threads, file descriptors, idle CPU, binary size, OCI image size,
  bytes per transferred record, zone capacity, and concurrent transfer limits

## Additional Scenarios

Select IXFR scaling, simultaneous query/transfer load, NSEC3, or overload/recovery
measurements when relevant. Record their workload and evidence without assigning
them to an unrelated SRS performance requirement.

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
# BoronDNS Benchmark Handoff

Created UTC: $timestamp

This release-candidate setup artifact contains the runbook and report formats
for a Reference Hardware/Profile benchmark. Fill them with measured results;
generation alone does not run or pass a benchmark. The TSV column names
\`local_mvp_status\` and \`later_release_ops_action\` are retained for compatibility.
Use the current requirements in \`docs/BoronDNS-Secondary-SRS-v1.0.0.md\` and the
workload in \`docs/reference-verification-profile.md\` when interpreting results.

Run configuration:

\`\`\`
BORONDNS_BENCHMARK_PROFILE=$profile
BORONDNS_BENCHMARK_QUERY_MIX=$query_mix
BORONDNS_BENCHMARK_REGRESSION_THRESHOLD_PCT=$regression_threshold_pct
BORONDNS_BENCHMARK_MIN_DURATION_SECONDS=$min_duration_seconds
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
