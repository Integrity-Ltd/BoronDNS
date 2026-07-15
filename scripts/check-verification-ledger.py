#!/usr/bin/env python3
"""Validate requirement references in the verification ledger."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRS_PATH = ROOT / "docs" / "BoronDNS-Secondary-SRS-v0.9.1.md"
LEDGER_PATH = ROOT / "docs" / "verification-ledger.md"

ID_PATTERN = (
    r"ODS-(?:(?:FR|NFR|IF)-[A-Z0-9]{3,6}|(?:INV|NEG|VER))-[0-9]{3}"
)
ID_RE = re.compile(ID_PATTERN)
RANGE_RE = re.compile(rf"({ID_PATTERN})\.\.({ID_PATTERN})")
SRS_DEF_RE = re.compile(rf"^\*\*({ID_PATTERN})\b", re.MULTILINE)
VALID_STATES = {"Not Verified", "Partial", "Verified", "Deferred"}
MAX_LEDGER_ROWS = 15
MAX_EVIDENCE_POINTER_CHARS = 320
MAX_NOTE_CHARS = 300
STALE_COUNT_RE = re.compile(
    r"\ball\s+[0-9]+\s+SRS v0\.9\.1 requirement IDs\b"
)


def requirement_prefix(requirement_id: str) -> str:
    return requirement_id.rsplit("-", 1)[0]


def requirement_number(requirement_id: str) -> int:
    return int(requirement_id.rsplit("-", 1)[1])


def expand_range(start: str, end: str) -> list[str]:
    start_prefix = requirement_prefix(start)
    end_prefix = requirement_prefix(end)
    if start_prefix != end_prefix:
        raise ValueError(f"range crosses prefixes: {start}..{end}")

    start_number = requirement_number(start)
    end_number = requirement_number(end)
    if start_number > end_number:
        raise ValueError(f"range start is after end: {start}..{end}")

    return [
        f"{start_prefix}-{number:03d}"
        for number in range(start_number, end_number + 1)
    ]


def ledger_rows(ledger_text: str) -> list[tuple[int, list[str]]]:
    rows: list[tuple[int, list[str]]] = []
    for line_number, line in enumerate(ledger_text.splitlines(), start=1):
        if not line.startswith("| "):
            continue
        if line.startswith("| ---") or line.startswith("| Area "):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if len(columns) == 6:
            rows.append((line_number, columns))
    return rows


def main() -> int:
    errors: list[str] = []

    srs_text = SRS_PATH.read_text(encoding="utf-8")
    ledger_text = LEDGER_PATH.read_text(encoding="utf-8")
    srs_ids = set(SRS_DEF_RE.findall(srs_text))

    range_spans = [match.span() for match in RANGE_RE.finditer(ledger_text)]
    referenced_ids: set[str] = set()

    for match in RANGE_RE.finditer(ledger_text):
        start, end = match.groups()
        try:
            expanded = expand_range(start, end)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        referenced_ids.update(expanded)

    for match in ID_RE.finditer(ledger_text):
        if any(start <= match.start() < end for start, end in range_spans):
            continue
        referenced_ids.add(match.group(0))

    missing_ids = sorted(referenced_ids - srs_ids)
    if missing_ids:
        errors.append(
            "ledger references requirement IDs not defined in the SRS: "
            + ", ".join(missing_ids)
        )

    rows = ledger_rows(ledger_text)
    if not rows:
        errors.append("ledger table has no data rows")
    if len(rows) > MAX_LEDGER_ROWS:
        errors.append(
            f"ledger table has {len(rows)} rows; keep it coarse-grained "
            f"with at most {MAX_LEDGER_ROWS} rows and put detail in Appendix A "
            "or the gap register"
        )

    for match in STALE_COUNT_RE.finditer(ledger_text):
        line_number = ledger_text.count("\n", 0, match.start()) + 1
        errors.append(
            f"line {line_number}: avoid hardcoded SRS requirement counts; "
            "refer to the generated checker instead"
        )

    for line_number, columns in rows:
        state = columns[3]
        if state not in VALID_STATES:
            errors.append(
                f"line {line_number}: invalid evidence state {state!r}; "
                f"expected one of {', '.join(sorted(VALID_STATES))}"
            )
        evidence_pointers = columns[4]
        if len(evidence_pointers) > MAX_EVIDENCE_POINTER_CHARS:
            errors.append(
                f"line {line_number}: evidence pointer cell is "
                f"{len(evidence_pointers)} characters; keep the ledger "
                f"summary below {MAX_EVIDENCE_POINTER_CHARS} characters"
            )
        notes = columns[5]
        if len(notes) > MAX_NOTE_CHARS:
            errors.append(
                f"line {line_number}: notes cell is {len(notes)} characters; "
                f"keep the ledger summary below {MAX_NOTE_CHARS} characters"
            )

    if errors:
        for error in errors:
            print(f"verification ledger check failed: {error}", file=sys.stderr)
        return 1

    print(
        "verification ledger check passed: "
        f"{len(referenced_ids)} requirement IDs validated against "
        f"{SRS_PATH.relative_to(ROOT)} across {len(rows)} ledger rows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
