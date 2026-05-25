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
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
  "## Appendix C.5 Decision Review" \
  "## RFC Compliance Assertions" \
  "## Long-Running Evidence Handoff" \
  "## Release/Operations Handoff" \
  "## Verification Responsibility Sign-off"; do
  require_text "$heading"
done

for category in ODS-FR ODS-NFR ODS-IF ODS-INV ODS-NEG; do
  require_text "$category"
done

for status in Verified Deferred Failed; do
  require_text "$status"
done

for rfc_field in \
  "RFC number" \
  "RFC title" \
  "Compliance status" \
  "Scope qualifier" \
  "Unresolved compliance gaps" \
  "Target resolution release" \
  "SRS revision" \
  "Evidence pointer" \
  "Primary documentation sync" \
  "Fully Compliant" \
  "Partially Compliant" \
  "Not Compliant" \
  "Informative Only" \
  "docs/operator-deployment-guide.md#rfc-compliance-assertions"; do
  require_text "$rfc_field"
done

for primary_doc in \
  "$repo_root/docs/rfc-compliance-assertions.md" \
  "$repo_root/docs/operator-deployment-guide.md"; do
  if [[ ! -f "$primary_doc" ]]; then
    printf 'primary RFC compliance documentation missing: %s\n' "$primary_doc" >&2
    exit 1
  fi
done

for primary_doc_text in \
  "# RFC Compliance Assertions" \
  "## RFC Compliance Assertions" \
  "ODS-VER-014" \
  "RFC number" \
  "Compliance status" \
  "SRS v0.7"; do
  if ! grep -F "$primary_doc_text" "$repo_root/docs/rfc-compliance-assertions.md" "$repo_root/docs/operator-deployment-guide.md" >/dev/null 2>&1; then
    printf 'primary RFC compliance documentation missing required text: %s\n' "$primary_doc_text" >&2
    exit 1
  fi
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

for c5_field in \
  "Decision for this release" \
  "Target release" \
  "Evidence or rationale" \
  "Pending"; do
  require_text "$c5_field"
done

for handoff_field in \
  "Fuzz campaign handoff or completed artifacts" \
  "Info verbosity profile handoff or completed artifacts" \
  "Reference Hardware/Profile benchmark handoff or completed artifacts" \
  "Soak handoff or completed 30-day report" \
  "Release/operations owner for delegated long-running evidence" \
  "Deferred execution rationale"; do
  require_text "$handoff_field"
done

for release_handoff_field in \
  "Release handoff artifact" \
  "Scheduled CI/manual-run plan" \
  "Release readiness checklist" \
  "External operator acceptance artifact" \
  "Signing runbook or completed signing manifest"; do
  require_text "$release_handoff_field"
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
