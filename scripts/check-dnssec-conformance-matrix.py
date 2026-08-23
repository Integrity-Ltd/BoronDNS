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
    "retained_artifact_inputs",
    "remaining_release_gap",
]

REQUIRED_IDS = {f"BDS-FR-DNSSEC-{index:03d}" for index in range(1, 15)}
VALID_PHASES = {"Engineering-MVP"}
VALID_STATUSES = {"partial"}
VALID_METHODS = {"conformance-test", "static-analysis"}


def fail(message: str) -> None:
    raise SystemExit(message)


def evidence_path(item: str) -> str | None:
    item = item.strip()
    if not item:
        return None
    path = item.split("::", 1)[0].strip()
    if "/" not in path and not path.endswith((".md", ".toml", ".rs", ".sh", ".py")):
        return None
    return path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    matrix_path = repo_root / "docs" / "dnssec-conformance-matrix.tsv"
    srs_text = (repo_root / "docs" / "BoronDNS-Secondary-SRS-v1.0.0.md").read_text(
        encoding="utf-8"
    )

    with matrix_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != HEADER:
            fail(f"{matrix_path} must use TSV header: {HEADER}")
        rows = list(reader)

    seen: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        requirement_id = row["requirement_id"]
        if not requirement_id:
            fail(f"{matrix_path}:{row_number}: requirement_id is required")
        if requirement_id in seen:
            fail(f"{matrix_path}:{row_number}: duplicate requirement {requirement_id}")
        if requirement_id not in REQUIRED_IDS:
            fail(f"{matrix_path}:{row_number}: unexpected requirement {requirement_id}")
        if requirement_id not in srs_text:
            fail(f"{matrix_path}:{row_number}: requirement not found in SRS {requirement_id}")
        if row["phase"] not in VALID_PHASES:
            fail(f"{matrix_path}:{row_number}: phase must be one of {sorted(VALID_PHASES)}")
        if row["status"] not in VALID_STATUSES:
            fail(f"{matrix_path}:{row_number}: status must be one of {sorted(VALID_STATUSES)}")
        if row["verification_method"] not in VALID_METHODS:
            fail(
                f"{matrix_path}:{row_number}: verification_method must be one of "
                f"{sorted(VALID_METHODS)}"
            )
        if "docs/implementation-plan.md" in row["local_evidence"]:
            fail(
                f"{matrix_path}:{row_number}: implementation-plan.md is a "
                "milestone-direction document, not DNSSEC conformance evidence"
            )
        for key in HEADER:
            if not row[key].strip():
                fail(f"{matrix_path}:{row_number}: {key} is required")

        for item in row["local_evidence"].split(";"):
            path = evidence_path(item)
            if path is None:
                continue
            if not (repo_root / path).exists():
                fail(f"{matrix_path}:{row_number}: evidence path does not exist: {path}")

        if "release" not in row["remaining_release_gap"].lower():
            fail(f"{matrix_path}:{row_number}: remaining_release_gap must name release work")
        seen[requirement_id] = row

    missing = REQUIRED_IDS - set(seen)
    if missing:
        fail(f"{matrix_path} missing DNSSEC requirement rows: {sorted(missing)}")

    print(f"dnssec_conformance_matrix_check=passed rows={len(rows)}")


if __name__ == "__main__":
    main()
