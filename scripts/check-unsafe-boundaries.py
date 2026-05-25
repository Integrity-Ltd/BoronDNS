#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from pathlib import Path


HEADER = [
    "id",
    "status",
    "path",
    "boundary_kind",
    "safe_api",
    "unsafe_surface",
    "required_tests",
    "evidence",
]

REQUIRED_CURRENT = {
    "posix-signal-disposition": "crates/oxidedns-server/src/process_signals.rs",
    "posix-rlimit": "crates/oxidedns-server/src/resource_limits.rs",
}

CURRENT_SOURCE_SHAPE = {
    "posix-signal-disposition": "libc::signal(signal, libc::SIG_IGN)",
    "posix-rlimit": "libc::getrlimit(libc::RLIMIT_NOFILE",
}

REQUIRED_DEFERRED = {
    "xdp-af-xdp",
    "io-uring-packet-io",
    "nsd-packed-zone-store",
    "response-cache",
}

DEFERRED_REQUIRED_TERMS = {
    "xdp-af-xdp": {
        "adapter",
        "backend",
        "dedicated",
        "fault",
        "test",
        "unsafe",
        "safety",
        "/// # safety",
        "// safety:",
        "privileged",
        "no-xdp-default",
        "no runtime",
        "loading",
    },
    "io-uring-packet-io": {
        "adapter",
        "backend",
        "dedicated",
        "fault",
        "test",
        "unsafe",
        "safety",
        "/// # safety",
        "// safety:",
        "cancellation",
        "buffer lifetime",
        "buffer reuse",
        "fallback",
    },
    "nsd-packed-zone-store": {
        "adapter",
        "backend",
        "dedicated",
        "fault",
        "test",
        "unsafe",
        "safety",
        "/// # safety",
        "// safety:",
        "alignment",
        "bounds",
        "atomic",
        "publication",
    },
    "response-cache": {
        "adapter",
        "backend",
        "dedicated",
        "fault",
        "test",
        "unsafe",
        "safety",
        "/// # safety",
        "// safety:",
        "ttl",
        "invalidation",
        "dnssec",
        "zone-refresh",
    },
}

ALLOW_UNSAFE_RE = re.compile(r"#!?\[allow\(unsafe_code\)\]")
UNSAFE_CONSTRUCT_RE = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b|extern\b)")


def fail(message: str) -> None:
    raise SystemExit(message)


def read_registry(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != HEADER:
            fail(f"{path} must use the expected TSV header: {HEADER}")
        rows = list(reader)

    seen: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        row_id = row["id"]
        if not row_id:
            fail(f"{path}:{row_number}: id is required")
        if row_id in seen:
            fail(f"{path}:{row_number}: duplicate boundary id {row_id}")
        for key in HEADER:
            if not row[key]:
                fail(f"{path}:{row_number}: {key} is required")
        if row["status"] not in {"current", "deferred"}:
            fail(f"{path}:{row_number}: status must be current or deferred")
        seen[row_id] = row
    return seen


def current_allowlist_from_source(repo_root: Path) -> set[str]:
    matches: set[str] = set()
    for path in sorted((repo_root / "crates").glob("*/src/**/*.rs")):
        text = path.read_text(encoding="utf-8")
        if ALLOW_UNSAFE_RE.search(text):
            matches.add(path.relative_to(repo_root).as_posix())
    return matches


def assert_safety_comments(repo_root: Path, relative_path: str) -> None:
    path = repo_root / relative_path
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not UNSAFE_CONSTRUCT_RE.search(line):
            continue
        context = "\n".join(lines[max(0, index - 8) : index])
        if "SAFETY:" not in context and "# Safety" not in context:
            fail(
                f"{relative_path}:{index + 1}: unsafe construct lacks "
                "preceding SAFETY rationale or # Safety docs"
            )


def assert_current_source_shape(repo_root: Path, row_id: str, relative_path: str) -> None:
    required = CURRENT_SOURCE_SHAPE.get(row_id)
    if required is None:
        return
    text = (repo_root / relative_path).read_text(encoding="utf-8")
    if required not in text:
        fail(
            f"{relative_path}: current unsafe boundary {row_id} no longer contains "
            f"expected source shape: {required}"
        )


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    registry_path = repo_root / "docs" / "unsafe-boundaries.tsv"
    registry = read_registry(registry_path)

    missing_current = set(REQUIRED_CURRENT) - set(registry)
    if missing_current:
        fail(f"{registry_path} missing current unsafe boundary rows: {sorted(missing_current)}")

    missing_deferred = REQUIRED_DEFERRED - set(registry)
    if missing_deferred:
        fail(f"{registry_path} missing deferred unsafe-prone rows: {sorted(missing_deferred)}")

    source_allowlist = current_allowlist_from_source(repo_root)
    registry_allowlist = {
        row["path"]
        for row in registry.values()
        if row["status"] == "current" and not row["path"].startswith("future:")
    }
    if source_allowlist != registry_allowlist:
        fail(
            "unsafe allowlist and docs/unsafe-boundaries.tsv disagree: "
            f"source={sorted(source_allowlist)} registry={sorted(registry_allowlist)}"
        )

    for row_id, row in registry.items():
        if row["status"] != "current":
            continue
        relative_path = row["path"]
        if relative_path.startswith("future:"):
            fail(f"{registry_path}: {row_id} current row must point at a live source path")
        if not (repo_root / relative_path).is_file():
            fail(f"{registry_path}: {row_id} current row path does not exist: {relative_path}")
        if "test" not in row["required_tests"].lower():
            fail(f"{registry_path}: {row_id} must name adapter tests")
        if "scripts/" not in row["evidence"] or "SAFETY" not in row["evidence"]:
            fail(
                f"{registry_path}: {row_id} must name retained script evidence "
                "and SAFETY-rationale evidence"
            )
        assert_safety_comments(repo_root, relative_path)
        assert_current_source_shape(repo_root, row_id, relative_path)

    for row_id, relative_path in REQUIRED_CURRENT.items():
        row = registry[row_id]
        if row["status"] != "current" or row["path"] != relative_path:
            fail(f"{registry_path}: {row_id} must be current at {relative_path}")

    for row_id in REQUIRED_DEFERRED:
        row = registry[row_id]
        if row["status"] != "deferred":
            fail(f"{registry_path}: {row_id} must remain deferred until implementation starts")
        if not row["path"].startswith("future:"):
            fail(f"{registry_path}: {row_id} must not point at a live source path while deferred")
        joined = " ".join(row.values()).lower()
        for term in sorted(DEFERRED_REQUIRED_TERMS[row_id]):
            if term not in joined:
                fail(f"{registry_path}: {row_id} must document {term} expectations")

    print("unsafe_boundary_registry=passed")


if __name__ == "__main__":
    main()
