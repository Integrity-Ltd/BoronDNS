#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/check-release-notes.sh RELEASE_NOTES.md [EVIDENCE_SNAPSHOT_DIR]

Checks the SRS v0.7 release-note gate shape for ODS-VER-010, ODS-VER-013,
ODS-VER-014, and ODS-VER-015. When an evidence snapshot directory is provided,
each retained interop primary-version artifact listed in its INDEX.tsv must be
referenced by snapshot-relative path in the release notes.
EOF
}

if (( $# < 1 || $# > 2 )); then
  usage
  exit 64
fi

notes_file="$1"
snapshot_dir="${2:-}"

if [[ ! -f "$notes_file" ]]; then
  printf 'release notes file not found: %s\n' "$notes_file" >&2
  exit 66
fi

require_text() {
  local needle="$1"
  if ! grep -F "$needle" "$notes_file" >/dev/null 2>&1; then
    printf 'release notes missing required text: %s\n' "$needle" >&2
    exit 1
  fi
}

for heading in \
  "## Verification Summary" \
  "## Regression Delta" \
  "## Interop Primary Versions" \
  "## Failed Requirement Decisions" \
  "## RFC Compliance Assertions" \
  "## Verification Responsibility Sign-off"; do
  require_text "$heading"
done

for category in ODS-FR ODS-NFR ODS-IF ODS-INV ODS-NEG; do
  require_text "$category"
done

for status in Verified Deferred Failed; do
  require_text "$status"
done

for regression_field in \
  "Performance/resource regression threshold" \
  "regression.performance_threshold_pct" \
  "Regression baseline window" \
  "Requirement or metric" \
  "Baseline value" \
  "Candidate value" \
  "Delta percent" \
  "Root cause" \
  "Fix or accepted rationale" \
  "Target remediation release" \
  "Regression triage status"; do
  require_text "$regression_field"
done

for security_field in \
  "Dependency audit result" \
  "Vulnerability disclosure changes" \
  "Vulnerability disclosure policy reviewed" \
  "Release signing mechanism and verification instructions" \
  "Security audit findings and remediation actions"; do
  require_text "$security_field"
done

if grep -F "TBD" "$notes_file" >/dev/null 2>&1; then
  printf 'release notes still contain TBD placeholders\n' >&2
  exit 1
fi

if [[ -n "$snapshot_dir" ]]; then
  index="$snapshot_dir/interop-primary-versions/INDEX.tsv"
  if [[ -f "$index" ]]; then
    while IFS=$'\t' read -r _source_path snapshot_path; do
      [[ "$snapshot_path" == "snapshot_path" || -z "$snapshot_path" ]] && continue
      require_text "$snapshot_path"
    done <"$index"
  fi
fi

printf 'release notes gate passed: %s\n' "$notes_file"
