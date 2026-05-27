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
    "*Source.* Operational visibility; RFC 8906.\n*Verification.* Counter inspection under controlled cookie traffic.": "DNS Cookie counters should cite DNS Cookie RFCs, not RFC 8906 alone",
    "RFC 8906 (operational visibility)": "RFC 8906 is response-behavior guidance, not a logging/metrics standard",
    "Operational requirement informed by RFC 8906; security": "RFC 8906 is response-behavior guidance, not a TSIG logging source",
    "Operational requirement informed by RFC 8906.\n*Verification.* Counter inspection": "RFC 8906 is response-behavior guidance, not a generic counter source",
    "DNS Cookies is widely deployed in BIND 9, NSD, Knot DNS, and PowerDNS": "avoid unsourced implementation-deployment claims",
    "provides anti-spoofing benefit comparable to TSIG": "DNS Cookies are not TSIG-equivalent authentication",
    "dominant default in widely deployed implementations": "avoid unsourced implementation-default claims",
    "reference values from BIND and Knot": "implementation-specific cookie references need retained interop evidence",
    "strongest improvement-per-codebase-octet": "avoid marketing-style rationale in the SRS",
    "RFC 9018 §2 (Server Cookie timestamp)": "RFC 9018 server-cookie timestamp is section 4.3",
    "RFC 9018 §3.2": "RFC 9018 server-cookie construction is section 4",
    "As of 2026 this comprises Knot DNS": "avoid time-frozen XoT implementation claims",
    "NSD does not implement XoT server-side at the time of writing": "NSD XoT support is version/build dependent and must be tested",
    "stable XoT server support since": "avoid unsourced release-history claims in normative SRS text",
    "The design specified below follows the Vixie / Schryver model implemented in BIND 9": "RRL implementation models differ; define the OxideDNS model directly",
    "Vixie / Schryver RRL design; BIND 9 RRL implementation": "avoid treating BIND behavior as the direct source for OxideDNS RRL semantics",
    "BIND 9 default RRL configuration": "OxideDNS RRL thresholds are project defaults, not BIND defaults",
    "operational benchmarking against existing secondary-only authoritative servers (NSD, Knot DNS)": "performance targets must not be presented as existing cross-server benchmark evidence",
    "comparable to NSD and Knot on equivalent hardware": "performance targets require retained OxideDNS benchmark evidence before conformance claims",
    "performance is expected to scale roughly with available CPU and network resources": "avoid unsupported performance scaling claims",
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
    "*Source.* Operational visibility for the RFC 7873 §5.2 cookie processing cases and RFC 9018 server-cookie validation profile.",
    "not a source for logging or metrics requirements",
    "DNS Cookies is a lightweight DNS transaction-security mechanism that provides limited protection against off-path spoofing",
    "not as general client identity or TSIG-equivalent authorization",
    "RFC 9018 §4, §4.3, §4.4",
    "OxideDNS defaults to the lenient project policy because it preserves interoperability with clients that do not yet have a Server Cookie",
    "DNS Cookies add useful UDP off-path spoofing resistance with modest operational complexity",
    "XoT-secured transfers per §4.10, against each primary in the list whose tested version supports XoT",
    "The tested primary version and the XoT capability decision MUST be recorded per ODS-VER-013",
    "SHOULD include NSD XoT evidence when the selected NSD version exposes TLS-protected `provide-xfr`/`request-xfr` configuration",
    "This subsection therefore defines the OxideDNS project model explicitly",
    "OxideDNS project default baseline, recorded in `docs/rrl-release-thresholds.md`",
    "These defaults are project defaults, not inherited vendor defaults.",
    "formal project acceptance targets for the OxideDNS reference verification profile",
    "not formal conformance evidence for the quantitative NFR targets",
    "Project reference-hardware throughput target; formal acceptance evidence required before asserting conformance.",
    "Conformance to the §5 numerical targets is asserted only against this Profile after the Appendix E.4 recordkeeping artifacts are retained.",
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
