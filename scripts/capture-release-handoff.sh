#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BORONDNS_RELEASE_HANDOFF_DIR:-$repo_root/target/evidence/release-handoff-$timestamp}"

release_name="${BORONDNS_RELEASE_NAME:-unassigned-release}"
release_owner="${BORONDNS_RELEASE_OWNER:-unassigned-release-engineer}"
architecture_owner="${BORONDNS_ARCHITECTURE_OWNER:-DT}"
external_operator="${BORONDNS_EXTERNAL_OPERATOR:-unassigned-external-operator}"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/release-handoff-env.env" <<EOF
BORONDNS_RELEASE_NAME=$release_name
BORONDNS_RELEASE_OWNER=$release_owner
BORONDNS_ARCHITECTURE_OWNER=$architecture_owner
BORONDNS_EXTERNAL_OPERATOR=$external_operator
EOF

cat >"$evidence_dir/evidence-attachment-map.tsv" <<'EOF'
requirement_id	evidence_category	setup_artifact	completed_release_artifact	required_release_note_section	local_mvp_status	later_release_ops_action
BDS-VER-008	1.0 public-beta acceptance gate	release-readiness-checklist.md	completed release checklist and optional external operator review	Verification Responsibility Sign-off	setup-ready	complete every required gate row before claiming public-beta acceptance
BDS-VER-010	release publication	release-notes-fill-plan.md	concise public release notes and retained canonical evidence	all release-note sections	setup-ready	identify version, artifacts, support posture, material limitations, and verification instructions; detailed dossier checking is optional
BDS-VER-011	cadence governance	scheduled-ci-plan.md	CI/scheduler run logs or release engineer manual run record	Release/Operations Handoff	setup-ready	record continuous, periodic, and gate execution ownership
BDS-VER-012	regression policy	release-notes-fill-plan.md	regression delta table and perf/resource comparison output	Regression Delta	setup-ready	triage every functional or performance/resource regression
BDS-VER-013	interop version retention	evidence-attachment-map.tsv	interop-primary-versions/INDEX.tsv and referenced primary-version files	Interop Primary Versions	setup-ready	attach every retained real-primary version artifact
BDS-VER-014	RFC compliance assertions	release-notes-fill-plan.md	canonical RFC compliance register with release evidence pointers	RFC Compliance Assertions	setup-ready	review docs/rfc-compliance-assertions.md and link to its current assertions
BDS-VER-015	verification roles	release-ownership.tsv; external-operator-acceptance.md	signed required project responsibility rows and any optional external review	Verification Responsibility Sign-off	setup-ready	record named owners, scopes, and sign-off state
BDS-NFR-MAINT-006	interface compatibility	interface-compatibility/	completed interface baseline diff and release-note change classification	Interface Changes	setup-ready	compare current interface baseline against previous accepted release and classify additions deprecations and breaking changes
BDS-NFR-MAINT-005	reproducible build	reproducible-build-handoff/	completed two-build binary comparison and artifact digest manifest	Maintainability Measurements	setup-ready	retain the workflow comparison; independent-builder and archive/image claims require additional evidence
BDS-NFR-MAINT-008	release signing	signing-runbook.md	signed checksum manifest and verification output	Security and Dependency Review	setup-ready	verify the signed tag, Sigstore manifest signature, and public artifact checksums
BDS-NFR-SEC-007	security release review	release-readiness-checklist.md	security policy review and audit/remediation records	Security and Dependency Review	setup-ready	record policy review, vulnerability exceptions, and security audit outcome
PROJECT-DECISIONS	pending project decisions	appendix-c5-decision-register.tsv	completed C.5 decision/deferral review	Appendix C.5 Decision Review	setup-ready	resolve or explicitly defer every Pending project-decision item before claiming formal SRS acceptance
EOF

python3 - "$repo_root/docs/project-decision-register.md" "$evidence_dir/appendix-c5-decision-register.tsv" <<'PY'
import re
import sys
from pathlib import Path

register_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
text = register_path.read_text(encoding="utf-8")

try:
    section = text.split("## Decision Register", 1)[1]
except IndexError as exc:
    raise SystemExit("failed to locate project decision register table") from exc

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
    status_text = re.sub(r"[*_`]", "", decision).strip()
    if re.match(r"^Pending(?:\s|:|$)", status_text, re.IGNORECASE):
        action = "release review must resolve or explicitly defer with owner and target release"
    else:
        action = "confirm implementation and evidence remain aligned with recorded decision"
    rows.append([*cells, action])

if not rows:
    raise SystemExit("no project decision rows parsed")

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
External operator	$external_operator	Optional production-representative review	no	Verification Responsibility Sign-off
Security reviewer	unassigned-security-reviewer	Security policy review, dependency audit review, vulnerability exceptions	yes	Security and Dependency Review
EOF

cat >"$evidence_dir/scheduled-ci-plan.md" <<'EOF'
# BoronDNS Scheduled CI and Manual Release Run Plan

Use this BDS-VER-011 plan to record selected runs and their owners. Generation
does not run checks or establish a passing result.

## Continuous

- Owner: maintainers through the local/SSH gate; CI where configured.
- Required command: `./scripts/check.sh`
- Required retained evidence: release snapshot `logs/check-sh.log`
- Blocking rule: any non-zero exit blocks merge/release candidacy.

The hosted workflow exists for v-prefixed tags and manual dispatch. It verifies
source provenance, builds/tests packages, signs, and publishes. It does not run
`scripts/check.sh`; retain that gate's result before tagging.

## Periodic

- Owner: CI scheduler or manual release engineer.
- Weekly during release acceptance:
  - `scripts/fuzz-campaign.sh --duration 86400`
  - Reference Hardware/Profile benchmark execution using `benchmark-handoff/`
  - extended-runtime resource summaries at the cadence declared for the run
- Monthly during an active release-acceptance cycle:
  - BIND, NSD, and Knot interoperability/differential comparison refresh.
- Required retained evidence:
  - fuzz `campaign-summary.tsv`
  - completed benchmark report and metric/resource TSVs
  - resource summaries for the declared run duration
  - interop primary-version artifacts

## Gate

- Owner: release engineer.
- Local quality gate and clean-container packaging rehearsal run before tagging.
- Use `scripts/release-evidence-snapshot.sh` when collecting the broad evidence profile.
- Select additional snapshot work with:
  - `BORONDNS_EVIDENCE_RUN_INTEROP=1`
  - `BORONDNS_EVIDENCE_RUN_FUZZ=1`
  - `BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1`
  - `BORONDNS_RELEASE_NOTES=<completed optional evidence dossier>`
- Record a result for every check required by the release claim. Record deferrals
  and their effect on acceptance; skipped evidence is not a pass. External
  operator review is optional supporting evidence. BDS-VER-008 public-beta
  acceptance is separate from full SRS target acceptance.
EOF

cat >"$evidence_dir/signing-runbook.md" <<'EOF'
# BoronDNS Release Signing Runbook

This is the release-candidate handoff for BDS-NFR-MAINT-008. It does not sign artifacts.

## Official Release Path

1. Retain the candidate's local quality-gate result and complete
   `scripts/release-preflight-container.sh` from the clean commit.
2. Create an annotated `v*` tag signed by the repository-trusted maintainer key.
3. The tag workflow rebuilds and checks packages, authenticates its handoff, and
   keylessly signs `release-handoff.sha256` with Cosign. It publishes that
   manifest, its Sigstore bundle, and the files covered by its checksums.
4. Verify the manifest signature against the exact tag workflow identity and
   GitHub OIDC issuer, then check each downloaded artifact's digest.
5. Retain verification output and include the verification command in public notes.

See `docs/release-evidence-guide.md` for exact commands. The personal OpenPGP
key authorizes the source tag; Sigstore authenticates the generated checksum
manifest. The current workflow does not implement detached OpenPGP artifact
signing as an automatic fallback.

## Internal Unsigned Builds

Label an unsigned diagnostic build `unsigned/internal`; it is not an official
public release artifact.
EOF

cat >"$evidence_dir/release-notes-fill-plan.md" <<'EOF'
# BoronDNS Release Notes Fill Plan

Public notes identify version, artifacts, support posture, material limitations,
interface changes, and artifact-verification instructions. The tag workflow
generates concise publication notes and does not invoke the dossier checker.

Use `docs/release-notes-template.md` when a consolidated, detailed evidence
dossier is useful. For that optional format, replace placeholders before running
`scripts/check-release-notes.sh`. Public notes may link to canonical evidence.

Evidence sources, when collected for the release:

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
- `soak-handoff/` or completed release-selected extended-runtime artifacts
- `fuzz-campaign/campaign-summary.tsv` or delegated fuzz handoff
- `interop-primary-versions/INDEX.tsv`
- `release-handoff/`

The optional dossier checker rejects `TBD` placeholders and, when a snapshot is
provided, requires every retained interop primary-version artifact listed in
`interop-primary-versions/INDEX.tsv` to be referenced. The Security and
Dependency Review section must also summarize the
`unsafe-dependency-evidence/geiger-summary.env` completeness status and any
scanner caveats retained in `geiger-warnings.tsv` or `geiger-not-scanned.tsv`.
EOF

cat >"$evidence_dir/external-operator-acceptance.md" <<EOF
# BoronDNS External Operator Acceptance

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
  - release-selected extended-runtime evidence:
- Accepted failed/deferred requirements:
- Operational restrictions:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/release-readiness-checklist.md" <<'EOF'
# BoronDNS Release Readiness Checklist

- [ ] `./scripts/check.sh` passed on the release candidate commit.
- [ ] Selected evidence retained through a snapshot, focused logs, or workflow artifacts.
- [ ] Public notes identify version, artifacts, support posture, material limitations,
      interface changes, and verification instructions.
- [ ] If a detailed dossier is supplied, it passes `scripts/check-release-notes.sh`.
- [ ] Dependency audit and source/license checks reviewed.
- [ ] Required source audit and coverage measurements retained in canonical evidence.
- [ ] Interface compatibility evidence attached and release notes classify
      additions, deprecations, and breaking changes.
- [ ] Current-commit two-build binary comparison and packaged-byte verification retained.
- [ ] Any additional independent-builder or archive/image reproducibility claim
      has its own completed evidence; a handoff template does not establish it.
- [ ] Safe-Rust audit, transitive unsafe enumeration, scanner caveats, and
      unsafe exception review attached.
- [ ] Security policy reviewed for this release candidate.
- [ ] Interop primary versions attached for all real-primary evidence used.
- [ ] Fuzz, interoperability, performance, and extended-runtime results selected
      for changed risks are complete, or deferrals state their effect on acceptance.
- [ ] Any quantitative Reference Hardware/Profile claim has matching measurements;
      public-beta limitations are distinct from full SRS target acceptance.
- [ ] Regression delta reviewed and triaged.
- [ ] Canonical RFC compliance assertions reviewed and linked to current evidence.
- [ ] Appendix C.5 pending decisions resolved or explicitly deferred with owner
      and target release.
- [ ] Public release tag, checksum-manifest signature, and artifact digests verified.
- [ ] Optional external review recorded if available, with reviewed scope and conclusions.
- [ ] Architecture Owner sign-off recorded.
- [ ] Release engineer sign-off recorded.
EOF

cat >"$evidence_dir/README.md" <<EOF
# BoronDNS Release/Operations Handoff

Created UTC: $timestamp

This directory is the release-candidate setup artifact for release-governance
handoff. It does not claim that release acceptance has completed. It provides
the attachment map, scheduled CI/manual-run plan, signing runbook,
release-notes fill plan, external-operator acceptance template, and readiness
checklist needed to complete later SRS acceptance evidence.

Release defaults:

\`\`\`
BORONDNS_RELEASE_NAME=$release_name
BORONDNS_RELEASE_OWNER=$release_owner
BORONDNS_ARCHITECTURE_OWNER=$architecture_owner
BORONDNS_EXTERNAL_OPERATOR=$external_operator
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
