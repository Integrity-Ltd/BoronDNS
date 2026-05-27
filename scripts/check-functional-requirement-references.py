#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


SRS_PATH = Path("docs/OxideDNS-Secondary-SRS-v0.9.1.md")
FUNCTIONAL_ID_RE = re.compile(r"\bODS-FR-[A-Z]+-\d{3}\b")
COMMENT_PREFIXES = ("//", "///", "//!", "/*", "*", "*/")


def fail(message: str) -> None:
    raise SystemExit(message)


def srs_functional_ids(repo_root: Path) -> set[str]:
    text = (repo_root / SRS_PATH).read_text(encoding="utf-8")
    try:
        functional_section = text.split("## 4.", 1)[1].split("## 5.", 1)[0]
    except IndexError:
        fail(f"{SRS_PATH} does not contain parseable sections 4 and 5")
    return set(FUNCTIONAL_ID_RE.findall(functional_section))


def rust_source_paths(repo_root: Path) -> list[Path]:
    paths = sorted((repo_root / "crates").glob("*/src/**/*.rs"))
    paths.extend(sorted((repo_root / "crates").glob("*/build.rs")))
    return paths


def comment_requirement_ids(path: Path) -> set[str]:
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith(COMMENT_PREFIXES):
            continue
        ids.update(FUNCTIONAL_ID_RE.findall(stripped))
    return ids


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    required = srs_functional_ids(repo_root)
    observed: dict[str, list[str]] = {requirement_id: [] for requirement_id in required}

    for path in rust_source_paths(repo_root):
        relative = path.relative_to(repo_root).as_posix()
        for requirement_id in comment_requirement_ids(path):
            if requirement_id in observed:
                observed[requirement_id].append(relative)

    missing = sorted(
        (requirement_id for requirement_id, paths in observed.items() if not paths),
        key=lambda item: (item.rsplit("-", 1)[0], item.rsplit("-", 1)[1]),
    )
    if missing:
        formatted = "\n".join(f"- {requirement_id}" for requirement_id in missing)
        fail(
            "Functional requirement IDs from SRS section 4 are missing "
            f"from Rust source comments:\n{formatted}"
        )

    print(f"functional_requirement_references=passed count={len(required)}")


if __name__ == "__main__":
    main()
