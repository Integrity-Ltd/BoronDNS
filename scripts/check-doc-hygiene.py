#!/usr/bin/env python3
"""Check current documentation for stale provenance and rename artifacts."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL_NUMBERED_HEADING = re.compile(r"^## ([0-9]+)\. ")

BANNED_PHRASES = [
    "Tibor's SRS",
    "GPT-style",
    "ChatGPT",
    "Claude",
    "AI slop",
    "hallucinat",
    "RustDNS",
    "OxydeDNS",
    "uDNS",
    "udns",
    "raw email intentionally",
    "Per VER-007 deferred",
    "All C.5 entries remain active release-review risks",
    "first-pass Engineering MVP",
    "first-pass family matrix",
    "preliminary AXFR-backed",
    "current MVP scaffold",
    "policy scaffold",
    "sign-off scaffold",
    "acceptance scaffold",
    "handoff scaffolds",
    "release-campaign scaffold",
    "Status: new MVP target",
    "The v0.9 SRS draft used",
    "The first slice groups",
    "case inventories will become more granular",
    "Status: working review register",
    "Earlier SRS drafts used",
    "Architecture and Release Governance Scaffold",
    "release-governance scaffold",
    "within the ODS-NFR-MAINT-001 target",
    "RFC 8914 EDE planned for v2",
    "`BTreeMap`-backed zone store",
    "Architecture Document will choose the initial implementation",
    "to be produced in PID Phase 2",
    "to be produced alongside this SRS",
    "v0.1–v0.2 design phase",
    "local project MVP",
    "project MVP in this repository",
    "Current MVP choice",
    "current MVP uses",
    "The MVP zone store",
    "The current MVP has",
    "not hidden MVP requirements",
    "The MVP profile",
    "No MVP or public release artifact",
    "preferred MVP path",
    "through MVP,",
    "Catalog Zone MVP based",
    "catalog-zone-mvp-rfc9432.md",
    "Implemented MVP behavior:",
    "Out of MVP scope:",
    "catalog-zone MVP extension",
    "Current MVP posture",
    "(MVP testers)",
    "as MVP requirement",
    "the MVP decision",
    "External operator, MVP only",
    "| MVP / Partial |",
    "| MVP / Deferred |",
    "Alpha subset; MVP full",
    "Alpha base; MVP expanded catalogue",
    "MVP acceptance work",
    "MVP\n  acceptance still needs",
    "v0.9/v0.9.1",
    "../gpt-pro-review.md",
    "DNS wire core and UDP query handling are implemented:",
    "AXFR acquisition and IXFR refresh/fallback are implemented:",
    "Health endpoints, metrics, logging, and process interfaces are implemented:",
    "health.livez_timeout_ms",
    "ODS_HEALTH_LIVEZ_TIMEOUT_MS",
    "TSIG secret loading from environment",
    "TSIG environment-variable loading",
    "environment-variable secret provisioning",
    "query.processing_timeout_ms",
    "oxidedns_dnssec_nsec3_cap_exceeded_total",
    "per-zone warning/metric",
    "0.1.2 Engineering Tuning Goal",
    "The 0.1.2 performance slice",
    "Hosted CI is intentionally deferred while the repository remains private",
    "## Release Scaffolding",
    "The planned pieces are:",
    "future work and should cover",
    "EDNS Refresh",
    "EDNS Expire",
    "Prometheus-compatible text metrics",
]

SOURCE_BANNED_PHRASES = [
    "rds_environment",
    "RDS environment",
    "unrecognised_rds",
    "unrecognized_rds",
]

SCRIPT_BANNED_PHRASES = [
    "did not set response DO bit",
    "set response DO bit",
]

REQUIRED_TEXT_BY_PATH = {
    "README.md": [
        "The implemented Engineering MVP is wider than a minimal static-zone secondary",
        "Retained feature slices stay in scope exactly as bounded in",
        "IXFR with AXFR fallback, outbound XoT transfers",
        "passive DNSSEC serving, RRL, DNS Cookies, RFC 9432 catalog zones",
        "bounded EDE diagnostics, and opt-in CHAOS identification",
        "Adjacent features are not implied unless that scope document names them.",
    ],
    "docs/mvp-gap-register.md": [
        "kind of blocker",
        "Non-normative quality candidate",
        "Formal release evidence target",
        "Rows marked",
        "not an Engineering MVP blocker unless promoted to a requirement",
        "documentation ownership map",
    ],
    "docs/catalog-zone-rfc9432.md": [
        "RFC 9432 §4.1",
        "IANA Special-Use names",
        "RFC 9432 §5.2",
    ],
    "docs/README.md": [
        "## Document Ownership Rules",
        "What is required behavior?",
        "What is the local Engineering MVP boundary?",
        "What is still open?",
        "What evidence exists by requirement family?",
        "What requirement ranges map to evidence?",
        "How are RFC traceability rules maintained?",
        "How is the implementation structured?",
        "Where is RR catalogue implementation detail kept?",
        "Where are deferred optimization tracks detailed?",
        "What is the health and metrics HTTP contract?",
        "How does an operator run it?",
        "What is the formal benchmark environment?",
        "How was the external review handled?",
        "Where are project decisions recorded?",
        "implementation plan stays at milestone level",
        "## Documentation Growth Control",
        "Before adding a new document or repeating status text",
        "Avoid copying requirement text,",
        "evidence status, command inventories",
        "When a review finding exposes drift, edit the owner first",
        "## Release Templates",
    ],
    "docs/rr-type-catalogue.md": [
        "# RR Type Catalogue Implementation Notes",
        "Current Known-Type Set",
        "Out-Of-Catalogue Behavior",
        "CAA, HIP, and SPF type 99",
        "Adding CAA, SSHFP, ZONEMD, CDS, CDNSKEY, or another type",
        "scripts/interop-bind-packet-torture-docker.sh",
    ],
    "docs/dns-client-benchmark.md": [
        "## Engineering Tuning Boundary",
        "This benchmark guide owns local measurement and tuning evidence only.",
        "keep release-build tuning history in `CHANGELOG.md`",
        "docs/future-optimization-tracks.md",
    ],
    "docs/health-metrics-interface.md": [
        "`ODS-NFR-OBS-003..009`",
        "current `oxidedns_dnssec_nsec3_iterations_exceed_cap_total` evidence is",
        "coupled to emitted EDE INFO-CODE 27",
        "with `edns.extended_dns_errors = \"off\"",
        "owned by `docs/mvp-gap-register.md`",
    ],
    "docs/implementation-plan.md": [
        "This plan deliberately stays at feature-slice granularity.",
        "it is not the canonical inventory of every evidence script",
        "At plan level, Engineering MVP scope is the deployable secondary-authoritative",
        "exact retained feature slices, source ownership, representative evidence",
        "put normative behavior changes in `docs/OxideDNS-Secondary-SRS-v0.9.1.md`",
        "put evidence state by requirement family in `docs/verification-ledger.md`",
        "does not duplicate the acceptance",
        "may require additional retained evidence without narrowing the",
    ],
    "docs/test-plan.md": [
        "Hosted continuous CI for every main-branch candidate is intentionally deferred",
        "tag-push/workflow-dispatch release workflow",
        "artifact publication automation",
        "it is not the standing Continuous gate",
    ],
    "docs/engineering-mvp-scope.md": [
        "The retained post-Alpha slices are code-backed scope, not planning notes.",
        "source paths, implementation markers, representative test markers, evidence",
        "implemented-feature scope, review disposition, gap register, and this boundary",
    ],
    "docs/implemented-feature-scope.md": [
        "The external review's suggested minimal MVP cut is treated as a floor for code",
        "not a replacement for the current Engineering MVP",
        "If code removes one of these slices, update this document",
        "nearby behavior that is not claimed by the slice",
    ],
    "docs/release-notes-template.md": [
        "pointer aligned with the canonical register and Operator Deployment Guide summary",
        "docs/rfc-compliance-assertions.md; docs/operator-deployment-guide.md#rfc-compliance-assertions",
    ],
}

FORBIDDEN_TEXT_BY_PATH = {
    "docs/README.md": [
        "Current implementation and evidence status is recorded in\n`implementation-plan.md`",
        "Engineering MVP and SRS acceptance implementation\n  plan",
        "Current Engineering MVP scope** in the scope, readiness, implementation, and",
        "`implementation-plan.md`: milestone boundary and implementation direction",
    ],
    "docs/appendix-a-traceability-matrix.md": [
        "docs/implementation-plan.md",
    ],
    "docs/verification-ledger.md": [
        "docs/implementation-plan.md",
    ],
    "docs/implementation-plan.md": [
        "This plan records implementation direction and milestone boundaries",
        "This plan records implementation direction and the current feature boundary",
        "30-day soak test completed without anomaly",
        "signed release artifacts produced",
        "at least one production-representative external operator has independently",
        "interoperability with NSD, Knot DNS, and BIND 9 primaries",
        "Engineering MVP scope includes:",
        "Historically deferred from Alpha to the formal SRS MVP release gate",
        "IXFR, full TSIG, XoT, DNSSEC serving, RRL,",
    ],
    "SECURITY.md": [
        "MVP and later release artifacts must be signed",
        "must not be treated as an MVP or public release artifact",
    ],
}


def current_doc_paths() -> list[Path]:
    paths = [ROOT / "README.md"]
    paths.extend(sorted((ROOT / "docs").glob("*.md")))
    return [path for path in paths if path.is_file()]


def current_source_paths() -> list[Path]:
    paths: list[Path] = []
    for directory in [ROOT / "crates", ROOT / "config"]:
        if directory.exists():
            paths.extend(
                path
                for path in directory.rglob("*")
                if path.is_file()
                and path.suffix in {".rs", ".toml", ".md"}
                and "target" not in path.parts
            )
    return sorted(paths)


def current_script_paths() -> list[Path]:
    return sorted(
        path
        for path in (ROOT / "scripts").glob("*")
        if path.is_file() and path.name != "check-doc-hygiene.py"
    )


def main() -> int:
    violations: list[str] = []
    for path in current_doc_paths():
        text = path.read_text(encoding="utf-8")
        normalized_text = " ".join(text.split())
        numbered_headings: dict[str, int] = {}
        relative = path.relative_to(ROOT)
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = TOP_LEVEL_NUMBERED_HEADING.match(line)
            if match is None:
                continue
            heading_number = match.group(1)
            if heading_number in numbered_headings:
                violations.append(
                    f"{relative}: duplicate top-level numbered heading "
                    f"{heading_number!r} at lines "
                    f"{numbered_headings[heading_number]} and {line_number}"
                )
            else:
                numbered_headings[heading_number] = line_number
        for phrase in BANNED_PHRASES:
            if phrase in text:
                violations.append(f"{relative}: stale phrase {phrase!r}")
        relative_string = path.relative_to(ROOT).as_posix()
        for phrase in REQUIRED_TEXT_BY_PATH.get(relative_string, []):
            if phrase not in normalized_text:
                violations.append(
                    f"{relative_string}: missing required phrase {phrase!r}"
                )
        for phrase in FORBIDDEN_TEXT_BY_PATH.get(relative_string, []):
            if phrase in normalized_text:
                violations.append(
                    f"{relative_string}: duplicated checklist phrase {phrase!r}"
                )

    for path in current_source_paths():
        text = path.read_text(encoding="utf-8")
        for phrase in SOURCE_BANNED_PHRASES:
            if phrase in text:
                relative = path.relative_to(ROOT)
                violations.append(f"{relative}: stale source phrase {phrase!r}")

    for path in current_script_paths():
        text = path.read_text(encoding="utf-8")
        for phrase in SCRIPT_BANNED_PHRASES:
            if phrase in text:
                relative = path.relative_to(ROOT)
                violations.append(
                    f"{relative}: stale evidence-script phrase {phrase!r}"
                )

    if violations:
        for violation in violations:
            print(f"doc_hygiene=failed {violation}", file=sys.stderr)
        return 1

    print(
        "doc_hygiene=passed "
        f"docs={len(current_doc_paths())} sources={len(current_source_paths())} "
        f"scripts={len(current_script_paths())}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
