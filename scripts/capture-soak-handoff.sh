#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BORONDNS_SOAK_HANDOFF_DIR:-$repo_root/target/evidence/soak-handoff-$timestamp}"

duration_days="${BORONDNS_SOAK_DURATION_DAYS:-30}"
baseline_hour="${BORONDNS_SOAK_BASELINE_HOUR:-24}"
memory_growth_threshold_pct="${BORONDNS_SOAK_MEMORY_GROWTH_THRESHOLD_PCT:-10}"
snapshot_cadence="${BORONDNS_SOAK_SNAPSHOT_CADENCE:-weekly}"

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s must be a positive integer: %s\n' "$name" "$value" >&2
        exit 64
    }
}

require_positive_integer BORONDNS_SOAK_DURATION_DAYS "$duration_days"
require_positive_integer BORONDNS_SOAK_BASELINE_HOUR "$baseline_hour"
require_positive_integer BORONDNS_SOAK_MEMORY_GROWTH_THRESHOLD_PCT "$memory_growth_threshold_pct"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/soak-env.env" <<EOF
BORONDNS_SOAK_DURATION_DAYS=$duration_days
BORONDNS_SOAK_BASELINE_HOUR=$baseline_hour
BORONDNS_SOAK_MEMORY_GROWTH_THRESHOLD_PCT=$memory_growth_threshold_pct
BORONDNS_SOAK_SNAPSHOT_CADENCE=$snapshot_cadence
EOF

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
ODS-NFR-REL-003	soak-report-template.md; rss-samples.tsv; weekly-summary-template.md	setup-ready	run 30-day soak, record 24-hour baseline and day-30 RSS, compute growth percentage
ODS-NFR-REL-006	soak-report-template.md; operational-events.tsv	setup-ready	record overload, recovery, restart, and primary-failure observations during soak
ODS-NFR-RES-001	rss-samples.tsv; fd-samples.tsv	setup-ready	record process RSS and file-descriptor samples throughout the soak
ODS-NFR-OBS-001	metrics-samples.tsv; weekly-summary-template.md	setup-ready	record readiness, zone-state, transfer, query, RCODE, and latency metrics
ODS-VER-008	soak-report-template.md; operator-signoff.md	setup-ready	attach completed soak report to formal SRS MVP release evidence before final SRS acceptance
ODS-VER-010	soak-report-template.md	setup-ready	publish completed soak result and evidence paths in release notes
ODS-VER-015	operator-signoff.md	setup-ready	record responsible release/operations owner and external operator scope/signature
EOF

cat >"$evidence_dir/rss-samples.tsv" <<'EOF'
timestamp_utc	elapsed_hours	process_id	rss_bytes	vsz_bytes	threads	fd_count	active_zones	configured_zones	qps_observed	notes
EOF

cat >"$evidence_dir/fd-samples.tsv" <<'EOF'
timestamp_utc	elapsed_hours	process_id	fd_count	soft_limit	hard_limit	notes
EOF

cat >"$evidence_dir/metrics-samples.tsv" <<'EOF'
timestamp_utc	elapsed_hours	readyz_status	active_zones	configured_zones	transfer_failures_total	query_total	rcode_noerror_total	rcode_servfail_total	rcode_refused_total	latency_p99_seconds	notes
EOF

cat >"$evidence_dir/operational-events.tsv" <<'EOF'
timestamp_utc	elapsed_hours	event_type	severity	requirement_id	description	operator_action	outcome
EOF

cat >"$evidence_dir/weekly-summary-template.md" <<'EOF'
# BoronDNS Soak Weekly Summary

- Soak evidence directory:
- Week number:
- Covered UTC interval:
- Commit:
- Binary identity:
- Configuration profile:
- Primary implementation and version:
- Workload summary:
- Readiness summary:
- Transfer/retry/expire summary:
- RSS range and trend:
- File-descriptor range and trend:
- Query/RCODE/latency summary:
- Operational events reviewed:
- Open issues:
- Release/operations owner:
EOF

cat >"$evidence_dir/operator-signoff.md" <<'EOF'
# BoronDNS Soak Operator Sign-off

- Release:
- Evidence snapshot:
- Soak evidence directory:
- Release/operations owner:
- External operator, if applicable:
- Accepted scope:
- Requirements covered:
  - ODS-NFR-REL-003
  - ODS-NFR-REL-006
  - ODS-NFR-RES-001
  - ODS-NFR-OBS-001
  - ODS-VER-008
  - ODS-VER-010
  - ODS-VER-015
- Result:
- Exceptions or accepted deviations:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/soak-report-template.md" <<EOF
# BoronDNS 30-Day Soak Report

## Scope

- Release:
- Commit:
- Evidence snapshot:
- Soak start UTC:
- Soak end UTC:
- Duration target: $duration_days days
- RSS baseline mark: hour $baseline_hour
- Memory growth threshold: $memory_growth_threshold_pct percent
- Snapshot cadence: $snapshot_cadence
- Reference Hardware/Profile deviations:
- Reference Query Mix variant:
- Primary implementation versions:
- Configuration profile:

## Required Attachments

- \`rss-samples.tsv\`
- \`fd-samples.tsv\`
- \`metrics-samples.tsv\`
- \`operational-events.tsv\`
- Weekly summary files based on \`weekly-summary-template.md\`
- \`operator-signoff.md\`

## Measurement Method

Record process RSS, VSZ, thread count, file-descriptor count, readiness, zone
state, transfer counters, query counters, RCODE counters, and query-latency
summary samples at the site cadence. The release/operations owner may collect
the values with Prometheus, systemd/cgroup accounting, container runtime stats,
or host tools, but the completed report must name the source used for each
metric.

For ODS-NFR-REL-003, compute:

\`\`\`
growth_pct = ((rss_day_30_bytes - rss_hour_${baseline_hour}_bytes) / rss_hour_${baseline_hour}_bytes) * 100
\`\`\`

The acceptance threshold is \`growth_pct <= $memory_growth_threshold_pct\` for
stable zone size and stable client-source-prefix distribution. If the workload
or zone corpus changes materially during the soak, record the deviation and do
not claim unqualified ODS-NFR-REL-003 evidence.

## Results

- Hour-$baseline_hour RSS bytes:
- Day-$duration_days RSS bytes:
- Growth percent:
- Threshold pass/fail:
- Readiness anomalies:
- Transfer anomalies:
- Query/latency anomalies:
- Resource anomalies:
- Operational events requiring remediation:

## Requirement Mapping

Use \`requirements-traceability.tsv\` as the release-candidate handoff map. The completed
release evidence must attach this report and the filled TSV/summary artifacts to
the release snapshot and publish their paths in the release notes.

## Release/Operations Decision

- Soak result:
- Failed or deferred requirements:
- Remediation owner:
- Target remediation release:
- External operator acceptance impact:
EOF

cat >"$evidence_dir/README.md" <<EOF
# BoronDNS Soak Handoff

Created UTC: $timestamp

This directory is the release-candidate setup artifact for later
release/operations execution of the long-duration soak. It does not claim that
the 30-day soak has run. It provides the report template, sample TSV schemas,
requirement traceability, environment values, and sign-off template needed for
the later ODS-VER-008 acceptance run.

Run configuration:

\`\`\`
BORONDNS_SOAK_DURATION_DAYS=$duration_days
BORONDNS_SOAK_BASELINE_HOUR=$baseline_hour
BORONDNS_SOAK_MEMORY_GROWTH_THRESHOLD_PCT=$memory_growth_threshold_pct
BORONDNS_SOAK_SNAPSHOT_CADENCE=$snapshot_cadence
\`\`\`

Artifacts:

- \`soak-report-template.md\`
- \`requirements-traceability.tsv\`
- \`rss-samples.tsv\`
- \`fd-samples.tsv\`
- \`metrics-samples.tsv\`
- \`operational-events.tsv\`
- \`weekly-summary-template.md\`
- \`operator-signoff.md\`
- \`soak-env.env\`
EOF

printf 'soak_handoff_dir=%s\n' "$evidence_dir"
