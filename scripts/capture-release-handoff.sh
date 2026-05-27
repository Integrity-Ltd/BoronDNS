#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_RELEASE_HANDOFF_DIR:-$repo_root/target/evidence/release-handoff-$timestamp}"

release_name="${OXIDEDNS_RELEASE_NAME:-unassigned-release}"
release_owner="${OXIDEDNS_RELEASE_OWNER:-unassigned-release-engineer}"
architecture_owner="${OXIDEDNS_ARCHITECTURE_OWNER:-DT}"
external_operator="${OXIDEDNS_EXTERNAL_OPERATOR:-unassigned-external-operator}"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/release-handoff-env.env" <<EOF
OXIDEDNS_RELEASE_NAME=$release_name
OXIDEDNS_RELEASE_OWNER=$release_owner
OXIDEDNS_ARCHITECTURE_OWNER=$architecture_owner
OXIDEDNS_EXTERNAL_OPERATOR=$external_operator
EOF

cat >"$evidence_dir/evidence-attachment-map.tsv" <<'EOF'
requirement_id	evidence_category	setup_artifact	completed_release_artifact	required_release_note_section	local_mvp_status	later_release_ops_action
ODS-VER-008	formal SRS MVP acceptance gate	release-readiness-checklist.md	completed release checklist and external operator acceptance	Verification Responsibility Sign-off	setup-ready	complete every gate row before claiming formal SRS acceptance
ODS-VER-010	release publication	release-notes-fill-plan.md	completed release notes checked by scripts/check-release-notes.sh	all release-note sections	setup-ready	publish evidence pointers and requirement outcomes
ODS-VER-011	cadence governance	scheduled-ci-plan.md	CI/scheduler run logs or release engineer manual run record	Release/Operations Handoff	setup-ready	record continuous, periodic, and gate execution ownership
ODS-VER-012	regression policy	release-notes-fill-plan.md	regression delta table and perf/resource comparison output	Regression Delta	setup-ready	triage every functional or performance/resource regression
ODS-VER-013	interop version retention	evidence-attachment-map.tsv	interop-primary-versions/INDEX.tsv and referenced primary-version files	Interop Primary Versions	setup-ready	attach every retained real-primary version artifact
ODS-VER-014	RFC compliance assertions	release-notes-fill-plan.md	completed RFC compliance table with release evidence pointers	RFC Compliance Assertions	setup-ready	copy and update docs/rfc-compliance-assertions.md posture
ODS-VER-015	verification roles	release-ownership.tsv; external-operator-acceptance.md	signed responsibility and external-operator rows	Verification Responsibility Sign-off	setup-ready	record named owners, scopes, and sign-off state
ODS-NFR-MAINT-006	interface compatibility	interface-compatibility/	completed interface baseline diff and release-note change classification	Interface Changes	setup-ready	compare current interface baseline against previous accepted release and classify additions deprecations and breaking changes
ODS-NFR-MAINT-005	reproducible build	reproducible-build-handoff/	completed independent build comparison and artifact digest manifest	Maintainability Measurements	setup-ready	run two clean independent builds from the same commit/toolchain and record bit-identical comparison before claiming reproducible-build evidence
ODS-NFR-MAINT-008	release signing	signing-runbook.md	signed artifact manifest and verification commands	Security and Dependency Review	setup-ready	sign public/MVP artifacts or label internal unsigned builds
ODS-NFR-SEC-007	security release review	release-readiness-checklist.md	security policy review and audit/remediation records	Security and Dependency Review	setup-ready	record policy review, vulnerability exceptions, and security audit outcome
SRS-C5	pending project decisions	appendix-c5-decision-register.tsv	completed C.5 decision/deferral review	Appendix C.5 Decision Review	setup-ready	resolve or explicitly defer every Pending C.5 item before claiming formal SRS acceptance
EOF

python3 - "$repo_root/docs/OxideDNS-Secondary-SRS-v0.9.1.md" "$evidence_dir/appendix-c5-decision-register.tsv" <<'PY'
import sys
from pathlib import Path

srs_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
text = srs_path.read_text(encoding="utf-8")

try:
    section = text.split("## C.5 Items Flagged for Project Decision", 1)[1]
    section = section.split("## C.6 Post-MVP / v2 Scope Items", 1)[0]
except IndexError as exc:
    raise SystemExit("failed to locate SRS Appendix C.5 decision table") from exc

rows: list[list[str]] = []
for line in section.splitlines():
    line = line.strip()
    if not line.startswith("|"):
        continue
    cells = [cell.strip().replace("\t", " ") for cell in line.strip("|").split("|")]
    if len(cells) != 4:
        continue
    if cells[0] == "Item" or set(cells[0]) <= {"-"}:
        continue
    decision = cells[3]
    if decision == "Pending":
        action = "release review must resolve or explicitly defer with owner and target release"
    else:
        action = "confirm implementation and evidence remain aligned with recorded decision"
    rows.append([*cells, action])

if not rows:
    raise SystemExit("no SRS Appendix C.5 decision rows parsed")

with out_path.open("w", encoding="utf-8") as handle:
    handle.write("item\tflagged_at\trecommendation\tdecision\trelease_action\n")
    for row in rows:
        handle.write("\t".join(row) + "\n")
PY

cat >"$evidence_dir/release-ownership.tsv" <<EOF
role	default_owner	scope	signoff_required	release_notes_section
Architecture Owner	$architecture_owner	Release verification result review	yes	Verification Responsibility Sign-off
Release engineer	$release_owner	Gate execution, evidence snapshot, release notes, signing handoff	yes	Verification Responsibility Sign-off
Test/verification owner	$release_owner	Verification evidence completeness and regression triage	yes	Verification Responsibility Sign-off
Operations owner	$release_owner	Long-running fuzz, benchmark, soak scheduling and completion	yes	Long-Running Evidence Handoff
External operator	$external_operator	Production-representative formal SRS MVP acceptance scope	yes	Verification Responsibility Sign-off
Security reviewer	unassigned-security-reviewer	Security policy review, dependency audit review, vulnerability exceptions	yes	Security and Dependency Review
EOF

cat >"$evidence_dir/scheduled-ci-plan.md" <<'EOF'
# OxideDNS Scheduled CI and Manual Release Run Plan

This is the Engineering MVP handoff for ODS-VER-011. It is not proof that hosted CI or
scheduled jobs have run.

## Continuous

- Owner: CI, or release engineer until hosted CI exists.
- Required command: `./scripts/check.sh`
- Required retained evidence: release snapshot `logs/check-sh.log`
- Blocking rule: any non-zero exit blocks merge/release candidacy.

## Periodic

- Owner: CI scheduler or manual release engineer.
- Weekly during release acceptance:
  - `scripts/fuzz-campaign.sh --duration 86400`
  - Reference Hardware/Profile benchmark execution using `benchmark-handoff/`
  - soak weekly summary while the 30-day soak is active
- Monthly:
  - BIND, NSD, and Knot interoperability/differential comparison refresh.
- Required retained evidence:
  - fuzz `campaign-summary.tsv`
  - completed benchmark report and metric/resource TSVs
  - soak weekly summaries and final report
  - interop primary-version artifacts

## Gate

- Owner: release engineer.
- Required command: `scripts/release-evidence-snapshot.sh`
- Optional gate environment:
  - `OXIDEDNS_EVIDENCE_RUN_INTEROP=1`
  - `OXIDEDNS_EVIDENCE_RUN_FUZZ=1`
  - `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1`
  - `OXIDEDNS_RELEASE_NOTES=<completed release notes>`
- Blocking rule: skipped long-running or external-operator evidence may be
  delegated only when release notes record owner, rationale, and evidence
  attachment path; skipped evidence is not passing SRS acceptance evidence.
EOF

cat >"$evidence_dir/signing-runbook.md" <<'EOF'
# OxideDNS Release Signing Runbook

This is the Engineering MVP handoff for ODS-NFR-MAINT-008. It does not sign artifacts.

## Preferred Sigstore/Cosign Path

1. Build release artifacts with `cargo build --locked --release` or the release
   packaging workflow.
2. Record artifact names, SHA256 digests, commit, Rust version, and build
   profile in the release artifact manifest.
3. Sign each public/MVP artifact with Cosign keyless signing.
4. Retain the Cosign signature and transparency-log bundle with the release
   evidence.
5. Add `cosign verify-blob` instructions to release notes or the artifact
   manifest, including expected certificate identity and OIDC issuer.

## OpenPGP Fallback

Use detached OpenPGP signatures only when Cosign cannot be used for the target
distribution channel. The release notes must include the public key or
fingerprint location and a detached-signature verification command.

## Internal Unsigned Builds

An unsigned build must be labelled `unsigned/internal` and must not be treated
as an MVP or public release artifact.
EOF

cat >"$evidence_dir/release-notes-fill-plan.md" <<'EOF'
# OxideDNS Release Notes Fill Plan

Use `docs/release-notes-template.md` as the source structure. Before running
`scripts/check-release-notes.sh`, replace every placeholder and attach evidence
from the release snapshot.

Required evidence pointer sources:

- `git-status.txt`, `git-log.txt`, and `logs/tool-versions.log`
- `logs/check-sh.log`
- `logs/cargo-deny.log`
- `logs/audit-safe-rust.log`
- `unsafe-dependency-evidence/`
- `logs/audit-maintainability.log`
- `logs/audit-unused-code.log`
- `coverage-evidence/`
- `interface-compatibility/`
- `reproducible-build-handoff/`
- `release-handoff/appendix-c5-decision-register.tsv`
- `benchmark-handoff/` or completed benchmark artifacts
- `soak-handoff/` or completed 30-day soak artifacts
- `fuzz-campaign/campaign-summary.tsv` or delegated fuzz handoff
- `interop-primary-versions/INDEX.tsv`
- `release-handoff/`

The release notes gate rejects `TBD` placeholders and, when a snapshot is
provided, requires every retained interop primary-version artifact listed in
`interop-primary-versions/INDEX.tsv` to be referenced. The Security and
Dependency Review section must also summarize the
`unsafe-dependency-evidence/geiger-summary.env` completeness status and any
scanner caveats retained in `geiger-warnings.tsv` or `geiger-not-scanned.tsv`.
EOF

cat >"$evidence_dir/external-operator-acceptance.md" <<EOF
# OxideDNS External Operator Acceptance

- Release: $release_name
- Evidence snapshot:
- External operator: $external_operator
- Acceptance scope:
- Production-representative environment:
- Zone corpus:
- Primary implementations:
- DNS interface:
- Transfer interface:
- Management interface:
- Long-running evidence delegated to operator:
  - fuzz campaign:
  - Reference Hardware/Profile benchmark:
  - 30-day soak:
- Accepted failed/deferred requirements:
- Operational restrictions:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/release-readiness-checklist.md" <<'EOF'
# OxideDNS Release Readiness Checklist

- [ ] `./scripts/check.sh` passed on the release candidate commit.
- [ ] `scripts/release-evidence-snapshot.sh` captured the candidate evidence.
- [ ] Release notes contain no placeholders and pass `scripts/check-release-notes.sh`.
- [ ] Dependency audit and source/license checks reviewed.
- [ ] First-party Rust source line count and coverage measurements recorded in
      release notes.
- [ ] Interface compatibility evidence attached and release notes classify
      additions, deprecations, and breaking changes.
- [ ] Reproducible-build handoff attached, or completed independent
      bit-identical build comparison and artifact manifest attached.
- [ ] Reproducible-build handoff is not treated as completed
      ODS-NFR-MAINT-005 evidence unless the independent comparison is filled.
- [ ] Safe-Rust audit, transitive unsafe enumeration, scanner caveats, and
      unsafe exception review attached.
- [ ] Security policy reviewed for this release candidate.
- [ ] Interop primary versions attached for all real-primary evidence used.
- [ ] Long-running fuzz evidence completed or delegated with owner and path.
- [ ] Reference Hardware/Profile benchmark evidence completed or delegated with
      owner and path.
- [ ] 30-day soak evidence completed or delegated with owner and path.
- [ ] Regression delta reviewed and triaged.
- [ ] RFC compliance assertions copied and updated with release evidence paths.
- [ ] Appendix C.5 pending decisions resolved or explicitly deferred with owner
      and target release.
- [ ] Public/MVP artifacts signed, or internal builds labelled unsigned/internal.
- [ ] External operator acceptance recorded for formal SRS acceptance.
- [ ] Architecture Owner sign-off recorded.
- [ ] Release engineer sign-off recorded.
EOF

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Release/Operations Handoff

Created UTC: $timestamp

This directory is the Engineering MVP setup artifact for release-governance
handoff. It does not claim that release acceptance has completed. It provides
the attachment map, scheduled CI/manual-run plan, signing runbook,
release-notes fill plan, external-operator acceptance scaffold, and readiness
checklist needed to complete later SRS acceptance evidence.

Release defaults:

\`\`\`
OXIDEDNS_RELEASE_NAME=$release_name
OXIDEDNS_RELEASE_OWNER=$release_owner
OXIDEDNS_ARCHITECTURE_OWNER=$architecture_owner
OXIDEDNS_EXTERNAL_OPERATOR=$external_operator
\`\`\`

Artifacts:

- \`evidence-attachment-map.tsv\`
- \`appendix-c5-decision-register.tsv\`
- \`release-ownership.tsv\`
- \`scheduled-ci-plan.md\`
- \`signing-runbook.md\`
- \`release-notes-fill-plan.md\`
- \`external-operator-acceptance.md\`
- \`release-readiness-checklist.md\`
- \`release-handoff-env.env\`
EOF

printf 'release_handoff_dir=%s\n' "$evidence_dir"
