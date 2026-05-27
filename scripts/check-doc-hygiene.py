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
    "RFC 8914 EDE planned for v2",
    "`BTreeMap`-backed zone store",
    "Architecture Document will choose the initial implementation",
    "v0.1–v0.2 design phase",
]


def current_doc_paths() -> list[Path]:
    paths = [ROOT / "README.md"]
    paths.extend(sorted((ROOT / "docs").glob("*.md")))
    return [path for path in paths if path.is_file()]


def main() -> int:
    violations: list[str] = []
    for path in current_doc_paths():
        text = path.read_text(encoding="utf-8")
        for phrase in BANNED_PHRASES:
            if phrase in text:
                relative = path.relative_to(ROOT)
                violations.append(f"{relative}: stale phrase {phrase!r}")

    if violations:
        for violation in violations:
            print(f"doc_hygiene=failed {violation}", file=sys.stderr)
        return 1

    print(f"doc_hygiene=passed files={len(current_doc_paths())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
