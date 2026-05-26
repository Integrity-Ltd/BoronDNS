#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path


HEADER = [
    "requirement_id",
    "phase",
    "status",
    "verification_method",
    "local_evidence",
    "short_artifact_inputs",
    "remaining_release_gap",
]

REQUIRED_IDS = {
    *(f"ODS-FR-ZSM-{index:03d}" for index in range(1, 7)),
    "ODS-FR-ZSM-006a",
    *(f"ODS-FR-ZSM-{index:03d}" for index in range(7, 14)),
}
VALID_PHASES = {"Engineering-MVP"}
VALID_STATUSES = {"partial"}
VALID_METHODS = {"unit-test", "integration-test"}


def fail(message: str) -> None:
    raise SystemExit(message)


def evidence_path_and_symbol(item: str) -> tuple[str, str | None] | None:
    item = item.strip()
    if not item:
        return None
    path, separator, symbol = item.partition("::")
    path = path.strip()
    if "/" not in path and not path.endswith((".md", ".toml", ".rs", ".sh", ".py")):
        return None
    return path, symbol.strip() if separator else None


def require_symbol(repo_root: Path, path: str, symbol: str | None, context: str) -> None:
    if symbol is None:
        return
    text = (repo_root / path).read_text(encoding="utf-8")
    if symbol not in text:
        fail(f"{context}: evidence symbol not found in {path}: {symbol}")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    matrix_path = repo_root / "docs" / "zsm-engineering-mvp-matrix.tsv"
    srs_text = (repo_root / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md").read_text(
        encoding="utf-8"
    )

    with matrix_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != HEADER:
            fail(f"{matrix_path} must use TSV header: {HEADER}")
        rows = list(reader)

    seen: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        context = f"{matrix_path}:{row_number}"
        requirement_id = row["requirement_id"]
        if not requirement_id:
            fail(f"{context}: requirement_id is required")
        if requirement_id in seen:
            fail(f"{context}: duplicate requirement {requirement_id}")
        if requirement_id not in REQUIRED_IDS:
            fail(f"{context}: unexpected requirement {requirement_id}")
        if requirement_id not in srs_text:
            fail(f"{context}: requirement not found in SRS {requirement_id}")
        if row["phase"] not in VALID_PHASES:
            fail(f"{context}: phase must be one of {sorted(VALID_PHASES)}")
        if row["status"] not in VALID_STATUSES:
            fail(f"{context}: status must be one of {sorted(VALID_STATUSES)}")
        if row["verification_method"] not in VALID_METHODS:
            fail(
                f"{context}: verification_method must be one of "
                f"{sorted(VALID_METHODS)}"
            )
        for key in HEADER:
            if not row[key].strip():
                fail(f"{context}: {key} is required")

        for key in ("local_evidence", "short_artifact_inputs"):
            for item in row[key].split(";"):
                parsed = evidence_path_and_symbol(item)
                if parsed is None:
                    continue
                path, symbol = parsed
                if not (repo_root / path).exists():
                    fail(f"{context}: evidence path does not exist: {path}")
                require_symbol(repo_root, path, symbol, context)

        gap = row["remaining_release_gap"].lower()
        if "release" not in gap:
            fail(f"{context}: remaining_release_gap must name release work")
        if requirement_id in {"ODS-FR-ZSM-002", "ODS-FR-ZSM-009", "ODS-FR-ZSM-010"}:
            if "engineering mvp" not in gap:
                fail(f"{context}: long-running rows must name Engineering MVP boundary")
        seen[requirement_id] = row

    missing = REQUIRED_IDS - set(seen)
    if missing:
        fail(f"{matrix_path} missing ZSM requirement rows: {sorted(missing)}")

    print(f"zsm_engineering_mvp_matrix_check=passed rows={len(rows)}")


if __name__ == "__main__":
    main()
