#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_INFO_VERBOSITY_HANDOFF_DIR:-$repo_root/target/evidence/info-verbosity-handoff-$timestamp}"

profile_duration_seconds="${OXIDEDNS_INFO_VERBOSITY_PROFILE_DURATION_SECONDS:-3600}"
sample_interval_seconds="${OXIDEDNS_INFO_VERBOSITY_SAMPLE_INTERVAL_SECONDS:-60}"
log_rate_window_seconds="${OXIDEDNS_INFO_VERBOSITY_LOG_RATE_WINDOW_SECONDS:-60}"

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s must be a positive integer: %s\n' "$name" "$value" >&2
        exit 64
    }
}

require_positive_integer OXIDEDNS_INFO_VERBOSITY_PROFILE_DURATION_SECONDS "$profile_duration_seconds"
require_positive_integer OXIDEDNS_INFO_VERBOSITY_SAMPLE_INTERVAL_SECONDS "$sample_interval_seconds"
require_positive_integer OXIDEDNS_INFO_VERBOSITY_LOG_RATE_WINDOW_SECONDS "$log_rate_window_seconds"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/info-verbosity-env.env" <<EOF
OXIDEDNS_INFO_VERBOSITY_PROFILE_DURATION_SECONDS=$profile_duration_seconds
OXIDEDNS_INFO_VERBOSITY_SAMPLE_INTERVAL_SECONDS=$sample_interval_seconds
OXIDEDNS_INFO_VERBOSITY_LOG_RATE_WINDOW_SECONDS=$log_rate_window_seconds
EOF

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
ODS-IF-LOG-001	info-verbosity-report-template.md; log-volume-samples.tsv	setup-ready	record configured info-level runtime log stream and format
ODS-IF-LOG-002	info-verbosity-report-template.md; log-volume-samples.tsv	setup-ready	record stderr/stdout routing and log collector source
ODS-IF-LOG-005	structured-field-samples.tsv	setup-ready	record canonical structured fields under release traffic
ODS-IF-LOG-006	log-volume-samples.tsv; operational-events.tsv	setup-ready	record warning/error visibility without excessive info noise
ODS-IF-LOG-007	log-volume-samples.tsv; profile-summary.tsv	setup-ready	record bounded log volume and rate under production-representative traffic
ODS-IF-LOG-008	profile-summary.tsv	setup-ready	attach lazy-formatting audit and profile timing/resource evidence
ODS-NFR-OBS-001	profile-summary.tsv; metrics-samples.tsv	setup-ready	record observability under representative query/transfer/metrics load
ODS-NFR-OBS-004	metrics-samples.tsv	setup-ready	record metrics availability while info logging is enabled
ODS-NFR-OBS-005	info-verbosity-report-template.md	setup-ready	record operator-facing logging profile decision in release notes
ODS-VER-008	operator-signoff.md	setup-ready	attach completed profile before final SRS acceptance when required
ODS-VER-010	release-notes-snippet.md	setup-ready	publish completed profile or delegation path in release notes
ODS-VER-015	operator-signoff.md	setup-ready	record release/operations owner and acceptance scope
EOF

cat >"$evidence_dir/log-volume-samples.tsv" <<'EOF'
timestamp_utc	elapsed_seconds	window_seconds	log_level	log_format	bytes_total	lines_total	info_lines	warn_lines	error_lines	truncated_lines	source_artifact	notes
EOF

cat >"$evidence_dir/structured-field-samples.tsv" <<'EOF'
timestamp_utc	elapsed_seconds	category	event	zone	primary	source_addr	error_kind	source_artifact	notes
EOF

cat >"$evidence_dir/metrics-samples.tsv" <<'EOF'
timestamp_utc	elapsed_seconds	readyz_status	active_zones	configured_zones	query_total	transfer_failures_total	metrics_scrape_status	metrics_scrape_seconds	notes
EOF

cat >"$evidence_dir/profile-summary.tsv" <<'EOF'
metric	unit	value	source_artifact	notes
profile_duration_seconds	seconds			
sample_interval_seconds	seconds			
log_rate_window_seconds	seconds			
average_log_bytes_per_minute	bytes_per_minute			
peak_log_bytes_per_minute	bytes_per_minute			
average_info_lines_per_minute	lines_per_minute			
peak_info_lines_per_minute	lines_per_minute			
warn_error_lines_total	lines			
truncated_lines_total	lines			
metrics_scrape_p99_seconds	seconds			
rss_before_bytes	bytes			
rss_after_bytes	bytes			
cpu_profile_artifact	path			
EOF

cat >"$evidence_dir/operational-events.tsv" <<'EOF'
timestamp_utc	elapsed_seconds	event_type	severity	requirement_id	description	operator_action	outcome
EOF

cat >"$evidence_dir/operator-signoff.md" <<'EOF'
# OxideDNS Info Verbosity Profile Operator Sign-off

- Release:
- Evidence snapshot:
- Info verbosity evidence directory:
- Release/operations owner:
- External operator, if applicable:
- Traffic profile:
- Log collector:
- Metrics collector:
- Accepted scope:
- Result:
- Exceptions or accepted deviations:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/release-notes-snippet.md" <<'EOF'
## Info Verbosity Profile

- Info verbosity handoff or completed artifact path:
- Traffic profile:
- Profile duration:
- Average log bytes per minute:
- Peak log bytes per minute:
- Warning/error visibility result:
- Metrics availability result:
- Accepted deviations:
- Release/operations owner:
EOF

cat >"$evidence_dir/info-verbosity-runbook.md" <<'EOF'
# OxideDNS Info Verbosity Profile Runbook

1. Start OxideDNS with `log_level = "info"` and the release-selected structured log
   format, normally `json` or `logfmt`.
2. Run production-representative DNS query, transfer, NOTIFY, health, and
   metrics traffic for the configured profile duration.
3. Retain raw stdout/stderr logs, log collector export, `/metrics` samples,
   `/readyz` samples, process status before/after, and CPU profile output when
   host permissions allow it.
4. Fill `log-volume-samples.tsv` with per-window log byte and line counts.
5. Fill `structured-field-samples.tsv` with representative canonical fields for
   startup, query/RCODE metrics context, transfer, notify, rrl, cookie, and xot
   categories that appear in the profile.
6. Fill `metrics-samples.tsv` and `profile-summary.tsv`.
7. Attach `scripts/audit-log-fields.py`, `scripts/audit-log-lazy-formatting.py`,
   and `scripts/capture-health-metrics-evidence.sh` output from the same
   release snapshot as supporting local evidence.
8. Record the result in release notes and obtain operator sign-off.
EOF

cat >"$evidence_dir/info-verbosity-report-template.md" <<EOF
# OxideDNS Production-Depth Info Verbosity Profile

## Scope

- Release:
- Commit:
- Evidence snapshot:
- Profile start UTC:
- Profile end UTC:
- Duration target: $profile_duration_seconds seconds
- Sample interval: $sample_interval_seconds seconds
- Log rate window: $log_rate_window_seconds seconds
- Log format:
- Traffic profile:
- Zone corpus:
- Primary implementations and versions:
- Log collector:
- Metrics collector:
- Reference Hardware/Profile deviations:

## Required Attachments

- Raw OxideDNS stdout/stderr or collector export
- \`log-volume-samples.tsv\`
- \`structured-field-samples.tsv\`
- \`metrics-samples.tsv\`
- \`profile-summary.tsv\`
- \`operational-events.tsv\`
- process status before/after
- CPU profile or skipped-permission note
- \`operator-signoff.md\`

## Acceptance Review Questions

- Is \`info\` verbosity useful to an operator without requiring \`debug\` or
  \`trace\` during normal production incidents?
- Is steady-state info-level log volume bounded and compatible with the
  operator's collector budget?
- Are warning/error events visible and not hidden by high-volume info output?
- Do canonical structured fields remain present for release-relevant event
  categories?
- Do health and metrics endpoints remain responsive while info logging is
  enabled under representative load?

## Result

- Overall result:
- Failed or deferred requirements:
- Accepted deviations:
- Remediation owner:
- Target remediation release:
EOF

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Info Verbosity Handoff

Created UTC: $timestamp

This directory is the Engineering MVP setup artifact for later
release/operations profiling of \`info\` verbosity under production-representative
traffic. It does not claim that production-depth profiling has run. It provides
the runbook, report template, sample TSV schemas, requirement traceability,
release-note snippet, environment values, and sign-off scaffold needed for the
later acceptance profile.

Run configuration:

\`\`\`
OXIDEDNS_INFO_VERBOSITY_PROFILE_DURATION_SECONDS=$profile_duration_seconds
OXIDEDNS_INFO_VERBOSITY_SAMPLE_INTERVAL_SECONDS=$sample_interval_seconds
OXIDEDNS_INFO_VERBOSITY_LOG_RATE_WINDOW_SECONDS=$log_rate_window_seconds
\`\`\`

Artifacts:

- \`info-verbosity-report-template.md\`
- \`info-verbosity-runbook.md\`
- \`requirements-traceability.tsv\`
- \`log-volume-samples.tsv\`
- \`structured-field-samples.tsv\`
- \`metrics-samples.tsv\`
- \`profile-summary.tsv\`
- \`operational-events.tsv\`
- \`release-notes-snippet.md\`
- \`operator-signoff.md\`
- \`info-verbosity-env.env\`
EOF

printf 'info_verbosity_handoff_dir=%s\n' "$evidence_dir"
