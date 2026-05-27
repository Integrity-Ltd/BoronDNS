#!/usr/bin/env python3
"""Check current documentation for stale provenance and rename artifacts."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

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
    "Status: new MVP target",
    "The v0.9 SRS draft used",
    "RFC 8914 EDE planned for v2",
    "`BTreeMap`-backed zone store",
    "Architecture Document will choose the initial implementation",
    "v0.1–v0.2 design phase",
]

SOURCE_BANNED_PHRASES = [
    "rds_environment",
    "RDS environment",
    "unrecognised_rds",
    "unrecognized_rds",
]


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


def main() -> int:
    violations: list[str] = []
    for path in current_doc_paths():
        text = path.read_text(encoding="utf-8")
        for phrase in BANNED_PHRASES:
            if phrase in text:
                relative = path.relative_to(ROOT)
                violations.append(f"{relative}: stale phrase {phrase!r}")

    for path in current_source_paths():
        text = path.read_text(encoding="utf-8")
        for phrase in SOURCE_BANNED_PHRASES:
            if phrase in text:
                relative = path.relative_to(ROOT)
                violations.append(f"{relative}: stale source phrase {phrase!r}")

    if violations:
        for violation in violations:
            print(f"doc_hygiene=failed {violation}", file=sys.stderr)
        return 1

    print(
        "doc_hygiene=passed "
        f"docs={len(current_doc_paths())} sources={len(current_source_paths())}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
