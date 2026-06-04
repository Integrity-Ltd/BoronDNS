#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit("python tomllib is required to inspect Cargo.lock") from exc


HEADER = ["package", "boundary_ids", "status", "allowed_paths", "rationale"]


def fail(message: str) -> None:
    raise SystemExit(message)


def read_tsv(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != HEADER:
            fail(f"{path} must use TSV header: {HEADER}")
        rows = list(reader)

    packages: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        package = row["package"]
        if not package:
            fail(f"{path}:{row_number}: package is required")
        if package in packages:
            fail(f"{path}:{row_number}: duplicate package {package}")
        if row["status"] not in {"current", "deferred"}:
            fail(f"{path}:{row_number}: status must be current or deferred")
        for field in HEADER:
            if not row[field]:
                fail(f"{path}:{row_number}: {field} is required")
        packages[package] = row
    return packages


def read_boundary_statuses(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["id"]: row["status"]
            for row in csv.DictReader(handle, delimiter="\t")
        }


def locked_packages(path: Path) -> set[str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {package["name"] for package in data.get("package", [])}


def rust_crate_name(package: str) -> str:
    return package.replace("-", "_")


def first_party_rust_sources(repo_root: Path) -> list[Path]:
    paths = sorted((repo_root / "crates").glob("*/src/**/*.rs"))
    paths.extend(sorted((repo_root / "crates").glob("*/build.rs")))
    paths.extend(sorted((repo_root / "fuzz").glob("**/*.rs")))
    return paths


def crate_reference_re(crate_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(^|\W)(use\s+{re.escape(crate_name)}\b|"
        rf"extern\s+crate\s+{re.escape(crate_name)}\b|"
        rf"{re.escape(crate_name)}::)"
    )


def assert_current_dependency_confined(
    repo_root: Path, trigger_path: Path, package: str, row: dict[str, str]
) -> None:
    allowed_paths = {item for item in row["allowed_paths"].split(";") if item}
    if not allowed_paths:
        fail(f"{trigger_path}: {package} current row must declare allowed_paths")
    live_allowed_paths = {path for path in allowed_paths if not path.startswith("future:")}
    if not live_allowed_paths:
        fail(f"{trigger_path}: {package} current row must declare live source allowed_paths")
    for relative_path in live_allowed_paths:
        if not (repo_root / relative_path).is_file():
            fail(f"{trigger_path}: {package} allowed path does not exist: {relative_path}")

    crate_name = rust_crate_name(package)
    reference_re = crate_reference_re(crate_name)
    violations: list[str] = []
    observed_allowed_reference = False
    for path in first_party_rust_sources(repo_root):
        relative_path = path.relative_to(repo_root).as_posix()
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not reference_re.search(line):
                continue
            if relative_path in live_allowed_paths:
                observed_allowed_reference = True
            else:
                violations.append(f"{relative_path}:{line_number}:{line.strip()}")

    if violations:
        formatted = "\n".join(f"- {violation}" for violation in violations)
        fail(
            f"unsafe-prone dependency {package!r} is referenced outside its "
            f"declared adapter paths:\n{formatted}"
        )
    if not observed_allowed_reference:
        if "transitive-only" in row["rationale"].lower():
            return
        fail(
            f"unsafe-prone dependency {package!r} is current but no first-party "
            "source reference was observed in its declared allowed_paths"
        )


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    trigger_path = repo_root / "docs" / "unsafe-prone-dependencies.tsv"
    boundary_path = repo_root / "docs" / "unsafe-boundaries.tsv"
    lock_path = repo_root / "Cargo.lock"

    triggers = read_tsv(trigger_path)
    boundary_statuses = read_boundary_statuses(boundary_path)
    present = locked_packages(lock_path)

    for package, row in sorted(triggers.items()):
        boundary_ids = [item for item in row["boundary_ids"].split(";") if item]
        missing_boundaries = [
            boundary_id for boundary_id in boundary_ids if boundary_id not in boundary_statuses
        ]
        if missing_boundaries:
            fail(
                f"{trigger_path}: {package} references unknown unsafe boundary ids: "
                f"{missing_boundaries}"
            )
        if package not in present:
            continue
        if row["status"] != "current":
            fail(
                f"unsafe-prone dependency {package!r} is present in Cargo.lock but "
                f"docs/unsafe-prone-dependencies.tsv marks it {row['status']}; "
                "promote the dependency and its unsafe-boundary row only with "
                "architecture, test-plan, and adapter evidence updates"
            )
        inactive_boundaries = [
            boundary_id
            for boundary_id in boundary_ids
            if boundary_statuses[boundary_id] != "current"
        ]
        if inactive_boundaries:
            fail(
                f"unsafe-prone dependency {package!r} is current but mapped to "
                f"non-current unsafe boundary rows: {inactive_boundaries}"
            )
        assert_current_dependency_confined(repo_root, trigger_path, package, row)

    print("unsafe_prone_dependency_gate=passed")


if __name__ == "__main__":
    main()
