#!/usr/bin/env python3
"""Static audit for SRS ODS-IF-LOG-005 canonical log field names."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOTS = [REPO_ROOT / "crates"]
LOG_MACROS = {"trace", "debug", "info", "warn", "error"}
CANONICAL_CATEGORIES = {
    "query",
    "transfer",
    "notify",
    "tsig",
    "xot",
    "rrl",
    "cookie",
    "chaos",
    "control_plane",
    "configuration_warning",
    "signal",
    "startup",
    "shutdown",
}


def iter_rust_files() -> list[Path]:
    files: list[Path] = []
    for root in RUST_ROOTS:
        files.extend(path for path in root.rglob("*.rs") if "target" not in path.parts)
    return sorted(files)


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def find_macro_close(source: str, open_paren: int) -> int | None:
    depth = 0
    index = open_paren
    in_string = False
    in_char = False
    line_comment = False
    block_comment_depth = 0
    escaped = False

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue

        if block_comment_depth:
            if char == "/" and next_char == "*":
                block_comment_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_comment_depth -= 1
                index += 2
                continue
            index += 1
            continue

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                in_char = False
            index += 1
            continue

        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment_depth = 1
            index += 2
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "'":
            in_char = True
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1

    return None


def iter_log_macro_bodies(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    bodies: list[tuple[int, str, str]] = []
    pattern = re.compile(r"\b(trace|debug|info|warn|error)!\s*\(")
    for match in pattern.finditer(source):
        macro_name = match.group(1)
        if macro_name not in LOG_MACROS:
            continue
        open_paren = source.find("(", match.start())
        close_paren = find_macro_close(source, open_paren)
        if close_paren is None:
            bodies.append(
                (
                    line_number(source, match.start()),
                    macro_name,
                    source[open_paren + 1 :],
                )
            )
            continue
        bodies.append(
            (
                line_number(source, match.start()),
                macro_name,
                source[open_paren + 1 : close_paren],
            )
        )
    return bodies


def main() -> int:
    print("canonical_log_field_audit=started")
    failures: list[str] = []
    categories: set[str] = set()
    macro_count = 0

    for path in iter_rust_files():
        rel_path = path.relative_to(REPO_ROOT)
        for line, macro_name, body in iter_log_macro_bodies(path):
            macro_count += 1
            location = f"{rel_path}:{line}:{macro_name}!"

            if re.search(r"(?<![A-Za-z0-9_])%peer(?![A-Za-z0-9_\.])", body):
                failures.append(f"{location}: use peer_ip/peer_port instead of %peer")
            if re.search(r"(?<![A-Za-z0-9_])peer\s*=", body):
                failures.append(f"{location}: use peer_ip/peer_port instead of peer")
            if re.search(r"(?<![A-Za-z0-9_])failure_cause\s*=", body):
                failures.append(f"{location}: use canonical error field instead of failure_cause")
            if re.search(r"(?<![A-Za-z0-9_])last_failure_cause\s*=", body):
                failures.append(
                    f"{location}: use canonical error field instead of last_failure_cause"
                )

            for category in re.findall(r"(?<![A-Za-z0-9_])category\s*=\s*\"([^\"]+)\"", body):
                categories.add(category)
                if category not in CANONICAL_CATEGORIES:
                    failures.append(
                        f"{location}: category={category!r} is outside ODS-IF-LOG-005"
                    )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print("canonical_log_field_audit=failed")
        return 1

    print(f"tracing_macro_sites={macro_count}")
    print("categories=" + ",".join(sorted(categories)))
    print("canonical_log_field_audit=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
