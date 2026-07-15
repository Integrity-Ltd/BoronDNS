#!/usr/bin/env python3
"""Check the RFC compliance assertion register shape.

The register is the operator-facing ODS-VER-014 source. Keep the check narrow:
it verifies the table has the expected schema and that implemented
post-review Engineering MVP protocol features are represented explicitly.
"""

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTER = REPO_ROOT / "docs" / "rfc-compliance-assertions.md"
SRS = REPO_ROOT / "docs" / "BoronDNS-Secondary-SRS-v0.9.1.md"
RELEASE_NOTES_TEMPLATE = REPO_ROOT / "docs" / "release-notes-template.md"

EXPECTED_COLUMNS = [
    "RFC number",
    "RFC title",
    "Compliance status",
    "Scope qualifier",
    "Unresolved compliance gaps",
    "Target resolution milestone",
    "SRS revision",
    "Evidence pointer",
]

REQUIRED_CURRENT_RFCS = {
    "RFC 1995": "IXFR",
    "RFC 4034": "passive DNSSEC record formats",
    "RFC 4035": "passive DNSSEC response behavior",
    "RFC 5001": "NSID",
    "RFC 5155": "NSEC3 serving",
    "RFC 6840": "DNSSEC DO/AD/CD clarifications",
    "RFC 6891": "base EDNS response behavior",
    "RFC 7314": "excluded EDNS EXPIRE boundary",
    "RFC 7828": "EDNS TCP keepalive",
    "RFC 7830": "EDNS padding",
    "RFC 7873": "DNS Cookies",
    "RFC 8914": "bounded Extended DNS Errors",
    "RFC 9018": "interoperable DNS Server Cookies",
    "RFC 9103": "XoT",
    "RFC 9432": "catalog zones",
}

REQUIRED_EVIDENCE_SNIPPETS = {
    "RFC 1035": [
        "bounded CHAOS-class handling",
        "scripts/interop-chaos-queries.sh",
    ],
    "RFC 5001": [
        "optional NSID fallback for CHAOS self-identification",
        "scripts/interop-chaos-queries.sh",
    ],
    "RFC 8482": [
        "qtype_any_defaults_to_minimal_real_rrset_response",
        "qtype_any_full_mode_returns_all_owner_rrsets",
    ],
    "RFC 6840": [
        "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        "preserves_rd_and_clears_ra_z_ad_cd_bits",
    ],
    "RFC 8914": [
        "ede_not_ready_is_opt_in_for_loading_zones",
        "nsec3_iterations_over_cap_omits_proofs_and_emits_ede_when_enabled",
    ],
    "RFC 7314": [
        "Informative Only",
        "explicitly excluded Experimental EDNS zone-expire signalling",
        "does not claim RFC 7314 compliance",
    ],
    "RFC 9103": [
        "TLS 1.3-only protocol profile",
        "no cleartext fallback",
        "current-version capability decisions",
    ],
    "RFC 5246": [
        "Informative Only",
        "does not use TLS 1.2 for the formal XoT client profile",
        "separate explicit policy",
    ],
    "RFC 8446": [
        "TLS 1.3",
        "TLS protocol implementation is library-owned",
    ],
}

VALID_STATUSES = {
    "Fully Compliant",
    "Partially Compliant",
    "Not Compliant",
    "Informative Only",
}


def parse_rows() -> list[dict[str, str]]:
    lines = REGISTER.read_text(encoding="utf-8").splitlines()
    header_index = None
    for index, line in enumerate(lines):
        if line.startswith("| RFC number | RFC title |"):
            header_index = index
            break
    if header_index is None:
        raise SystemExit("RFC compliance table header not found")

    columns = [cell.strip() for cell in lines[header_index].strip("|").split("|")]
    if columns != EXPECTED_COLUMNS:
        raise SystemExit(
            "RFC compliance table columns changed: "
            f"expected {EXPECTED_COLUMNS!r}, found {columns!r}"
        )

    rows: list[dict[str, str]] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("| RFC "):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(EXPECTED_COLUMNS):
            raise SystemExit(f"Malformed RFC compliance row: {line}")
        row = dict(zip(EXPECTED_COLUMNS, cells, strict=True))
        rows.append(row)
    return rows


def main() -> int:
    rows = parse_rows()
    by_rfc = {row["RFC number"]: row for row in rows}
    dns_root = REPO_ROOT / "crates" / "borondns-core" / "src"
    source_text = (dns_root / "dns.rs").read_text(encoding="utf-8")
    source_text += "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((dns_root / "dns_tests").glob("*.rs"))
    )
    for path in (SRS, RELEASE_NOTES_TEMPLATE):
        text = path.read_text(encoding="utf-8")
        if "Target resolution milestone" not in text:
            raise SystemExit(
                f"{path.relative_to(REPO_ROOT)} must use "
                "'Target resolution milestone' for ODS-VER-014"
            )
        if "Target resolution release" in text:
            raise SystemExit(
                f"{path.relative_to(REPO_ROOT)} still uses stale "
                "'Target resolution release' wording"
            )

    missing = sorted(set(REQUIRED_CURRENT_RFCS) - set(by_rfc))
    if missing:
        details = ", ".join(
            f"{rfc} ({REQUIRED_CURRENT_RFCS[rfc]})" for rfc in missing
        )
        raise SystemExit(f"RFC compliance register missing current rows: {details}")

    for rfc, feature in REQUIRED_CURRENT_RFCS.items():
        row = by_rfc[rfc]
        if row["Compliance status"] not in VALID_STATUSES:
            raise SystemExit(f"{rfc} has invalid compliance status")
        if row["SRS revision"] != "SRS v0.9.1":
            raise SystemExit(f"{rfc} is not tied to SRS v0.9.1")
        if not row["Evidence pointer"]:
            raise SystemExit(f"{rfc} ({feature}) lacks an evidence pointer")
        if row["Target resolution milestone"] not in {"Formal SRS MVP", "N/A"}:
            raise SystemExit(f"{rfc} ({feature}) has an unexpected target milestone")

    for rfc, snippets in REQUIRED_EVIDENCE_SNIPPETS.items():
        row_text = " | ".join(by_rfc[rfc].values())
        for snippet in snippets:
            if snippet not in row_text:
                raise SystemExit(
                    f"{rfc} compliance row must include {snippet!r}"
                )
            if (
                snippet.startswith("qtype_")
                or snippet.startswith("response_")
                or snippet.startswith("preserves_")
                or snippet.startswith("ede_")
                or snippet.startswith("nsec3_")
            ) and snippet not in source_text:
                raise SystemExit(f"{rfc} evidence pointer references missing {snippet!r}")

    print(
        "RFC compliance assertion check passed: "
        f"{len(rows)} rows, {len(REQUIRED_CURRENT_RFCS)} current feature rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
