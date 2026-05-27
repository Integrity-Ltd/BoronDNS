#!/usr/bin/env python3
"""Check SRS requirement identifier registry consistency."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRS = ROOT / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md"

REQUIRED_CATEGORIES = {
    "FR": ("Functional Requirement", "Required", "§4"),
    "NFR": ("Non-Functional Requirement", "Required", "§5"),
    "IF": ("External Interface Requirement", "Required", "§6"),
    "INV": ("Architectural Invariant", "Omitted", "§3"),
    "NEG": ("Negative (Prohibition) Requirement", "Omitted", "§4.18"),
    "VER": ("Verification Requirement", "Omitted", "§7"),
}

STALE_TEXT = [
    "RDS denotes",
    "VER is the only category added beyond",
    "the next SRS revision should incorporate VER",
]

SUFFIXED_ID_RE = re.compile(r"\bODS-(?:FR|NFR|IF)-[A-Z0-9]{3,6}-[0-9]{3}[a-z]\b")


def fail(message: str) -> None:
    raise SystemExit(message)


def category_rows(text: str) -> dict[str, tuple[str, str, str]]:
    try:
        table = text.split("### D.5.1 Categories", 1)[1].split(
            "### D.5.2 Area code registry", 1
        )[0]
    except IndexError:
        fail("SRS does not contain parseable D.5.1/D.5.2 identifier registry")

    rows: dict[str, tuple[str, str, str]] = {}
    for line in table.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] in {"---", "Category"}:
            continue
        rows[cells[0]] = (cells[1], cells[2], cells[3])
    return rows


def main() -> int:
    text = SRS.read_text(encoding="utf-8")
    errors: list[str] = []

    for stale in STALE_TEXT:
        if stale in text:
            errors.append(f"stale identifier-registry text remains: {stale}")

    suffixed_ids = sorted(set(SUFFIXED_ID_RE.findall(text)))
    if suffixed_ids:
        errors.append(
            "suffixed requirement identifiers found in current SRS: "
            + ", ".join(suffixed_ids)
        )

    rows = category_rows(text)
    missing = sorted(set(REQUIRED_CATEGORIES) - set(rows))
    if missing:
        errors.append("missing category registry rows: " + ", ".join(missing))

    for category, expected in REQUIRED_CATEGORIES.items():
        observed = rows.get(category)
        if observed is not None and observed != expected:
            errors.append(
                f"category {category} registry row mismatch: "
                f"expected {expected!r}, found {observed!r}"
            )

    if errors:
        for error in errors:
            print(f"srs_identifier_registry=failed {error}", file=sys.stderr)
        return 1

    print(
        "srs_identifier_registry=passed "
        f"categories={','.join(sorted(REQUIRED_CATEGORIES))}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
