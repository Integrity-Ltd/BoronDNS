#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_INTERFACE_COMPATIBILITY_DIR:-$repo_root/target/evidence/interface-compatibility-$timestamp}"
previous_baseline="${OXIDEDNS_PREVIOUS_INTERFACE_BASELINE:-}"

mkdir -p "$evidence_dir"

cp "$repo_root/docs/interface-stability-baseline.tsv" "$evidence_dir/current-interface-baseline.tsv"
cp "$repo_root/docs/interface-compatibility-policy.md" "$evidence_dir/interface-compatibility-policy.md"

if [[ -n "$previous_baseline" ]]; then
    python3 "$repo_root/scripts/check-interface-compatibility.py" \
        --previous "$previous_baseline" \
        >"$evidence_dir/interface-compatibility-check.log" 2>&1
    diff_status="previous-baseline-compared"
else
    python3 "$repo_root/scripts/check-interface-compatibility.py" \
        >"$evidence_dir/interface-compatibility-check.log" 2>&1
    diff_status="initial-baseline-no-previous-release"
fi

cat >"$evidence_dir/interface-compatibility-summary.env" <<EOF
OXIDEDNS_INTERFACE_COMPATIBILITY_CREATED_UTC=$timestamp
OXIDEDNS_INTERFACE_COMPATIBILITY_STATUS=$diff_status
OXIDEDNS_INTERFACE_COMPATIBILITY_PREVIOUS_BASELINE=$previous_baseline
OXIDEDNS_INTERFACE_COMPATIBILITY_CURRENT_BASELINE=current-interface-baseline.tsv
EOF

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
ODS-NFR-MAINT-006	current-interface-baseline.tsv; interface-compatibility-check.log	setup-ready	compare against the previous accepted release baseline and publish additions deprecations and breaking changes in release notes
ODS-IF-CONF-002	current-interface-baseline.tsv; interface-compatibility-policy.md	setup-ready	keep schema changes aligned with the backward-compatibility policy
ODS-VER-010	release-notes-snippet.md	setup-ready	publish interface changes and compatibility-diff result in release notes
ODS-VER-012	interface-compatibility-check.log	setup-ready	treat unapproved interface removal or semantic change as a release-blocking regression
ODS-VER-015	release-engineer-signoff.md	setup-ready	record release engineer review and approval for compatibility status
EOF

cat >"$evidence_dir/release-notes-snippet.md" <<'EOF'
## Interface Compatibility Summary

- Interface compatibility evidence:
- Previous accepted baseline:
- Current baseline:
- Interface additions:
- Interface deprecations:
- Interface breaking changes:
- Major-version approval rationale, if any:
- Release engineer:
EOF

cat >"$evidence_dir/release-engineer-signoff.md" <<'EOF'
# OxideDNS Interface Compatibility Sign-off

- Release:
- Evidence snapshot:
- Interface compatibility evidence directory:
- Previous accepted baseline:
- Current baseline:
- Compatibility result:
- Additions reviewed:
- Deprecations reviewed:
- Breaking changes reviewed:
- Major-version approval:
- Release engineer:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Interface Compatibility Evidence

Created UTC: $timestamp

This directory records the local MVP setup artifact for ODS-NFR-MAINT-006.
Without a previous accepted release baseline, it establishes the current
baseline and policy shape. When \`OXIDEDNS_PREVIOUS_INTERFACE_BASELINE\` is set, the
checker compares the current baseline against that file and blocks removals
unless \`OXIDEDNS_INTERFACE_MAJOR_RELEASE=1\` is set.

Status: $diff_status

Artifacts:

- \`current-interface-baseline.tsv\`
- \`interface-compatibility-policy.md\`
- \`interface-compatibility-check.log\`
- \`interface-compatibility-summary.env\`
- \`requirements-traceability.tsv\`
- \`release-notes-snippet.md\`
- \`release-engineer-signoff.md\`
EOF

printf 'interface_compatibility_dir=%s\n' "$evidence_dir"
