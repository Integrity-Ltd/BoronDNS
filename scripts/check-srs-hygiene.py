#!/usr/bin/env python3
"""Check the current SRS for review-derived hygiene regressions."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SRS = ROOT / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md"

FORBIDDEN_TEXT = {
    "RDS denotes": "old rename namespace artifact",
    "ZoneProvider": "architecture internals do not belong in the SRS",
    "ZoneSpec": "architecture internals do not belong in the SRS",
    "ZoneSetDelta": "architecture internals do not belong in the SRS",
    "trait PacketIo": "trait names belong in architecture, not SRS requirements",
    "trait ZoneStore": "trait names belong in architecture, not SRS requirements",
    "`HashMap`": "concrete store type belongs in architecture, not SRS requirements",
    "Arc<": "concrete pointer type belongs in architecture, not SRS requirements",
    "`RwLock`": "concrete lock type belongs in architecture, not SRS requirements",
    "atomic pointer swap": "concrete publication mechanism belongs in architecture",
    "seqlock": "concrete publication mechanism belongs in architecture",
    "response DO bit should be set": "wrong RFC 6840 response-DO wording",
    "response contains DNSSEC augmentation": "wrong RFC 6840 response-DO wording",
    "excluding RFC 8482 minimal-ANY": "minimal-ANY is implemented current scope",
    "Reference Hardware Profile of Appendix E.1": "stale Appendix E reference",
    "Reference Query Mix of Appendix E.2": "stale Appendix E reference",
    "Reference Hardware Profile (E.1)": "stale Appendix E heading",
    "Reference Query Mix (E.2)": "stale Appendix E heading",
    "concrete, atomic, testable requirements": "SRS no longer claims strict atomicity",
    "decomposed into atomic requirements": "SRS no longer claims strict atomicity",
    "the Test Plan's CI configuration MUST enact the classification": "private Engineering MVP does not claim hosted CI enacts every cadence",
}

REQUIRED_TEXT = [
    "Each requirement should express a single, testable assertion.",
    "its verification text must identify the observable sub-cases to be tested.",
    "concrete, traceable, testable requirements",
    "where a requirement intentionally groups a coherent operational case",
    "the response OPT RR's TTL field MUST copy the query's DO bit exactly",
    "the response DO bit is not a signal that augmentation records were included",
    "This SRS makes that stronger as a project policy",
    "Except for RRSIG records",
    "RRSIG records are handled by DNSSEC-specific rules",
    "RFC 4035 §2.2 exception",
    "RRSIG records do not form ordinary RRsets",
    "*Source.* RFC 2181 §5; RFC 4035 §2.2; RFC 4034 §3.",
    "*Source.* RFC 2181 §5.2; RFC 4035 §2.2; RFC 4034 §3.",
    "Under the Reference Query Mix of Appendix E.3, on hardware matching the Reference Hardware Profile of Appendix E.2",
    "The published Linux release artifact targets `x86_64-unknown-linux-musl`",
    "Developer and distribution builds that use another target MAY dynamically link",
    "MUST NOT be described as scratch-compatible unless binary inspection proves the claim",
    "The active verification automation for the current project stage MUST enact the Continuous classification",
    "Periodic and Gate rows are release/operations handoff obligations until hosted CI, scheduled jobs, or formal release-gate automation are enabled",
]

SUFFIXED_ID_RE = re.compile(r"\bODS-(?:FR|NFR|IF)-[A-Z0-9]{3,6}-[0-9]{3}[a-z]\b")


def main() -> int:
    text = SRS.read_text(encoding="utf-8")
    errors: list[str] = []

    for needle, reason in FORBIDDEN_TEXT.items():
        if needle in text:
            errors.append(f"forbidden SRS text {needle!r}: {reason}")

    for needle in REQUIRED_TEXT:
        if needle not in text:
            errors.append(f"missing required SRS hygiene text: {needle!r}")

    suffixed_ids = sorted(set(SUFFIXED_ID_RE.findall(text)))
    if suffixed_ids:
        errors.append(
            "suffixed current requirement identifiers found: "
            + ", ".join(suffixed_ids)
        )

    if errors:
        for error in errors:
            print(f"srs_hygiene=failed {error}", file=sys.stderr)
        return 1

    print(f"srs_hygiene=passed path={SRS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
