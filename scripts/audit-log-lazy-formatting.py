#!/usr/bin/env python3
"""Static audit for SRS ODS-IF-LOG-008 lazy debug/trace log formatting."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOTS = [REPO_ROOT / "crates"]
LAZY_LOG_MACROS = {"debug", "trace"}
EAGER_PATTERNS = [
    (re.compile(r"\bformat!\s*\("), "format!"),
    (re.compile(r"\bformat_args!\s*\("), "format_args!"),
    (re.compile(r"\bString::from\s*\("), "String::from"),
    (re.compile(r"\.to_string\s*\("), ".to_string()"),
    (re.compile(r"\.to_owned\s*\("), ".to_owned()"),
]


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


def iter_lazy_log_macro_bodies(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    bodies: list[tuple[int, str, str]] = []
    pattern = re.compile(r"(?:(?:\btracing::)|\b)(trace|debug)!\s*\(")
    for match in pattern.finditer(source):
        macro_name = match.group(1)
        if macro_name not in LAZY_LOG_MACROS:
            continue
        open_paren = source.find("(", match.start())
        close_paren = find_macro_close(source, open_paren)
        body = source[open_paren + 1 : close_paren if close_paren is not None else len(source)]
        bodies.append((line_number(source, match.start()), macro_name, body))
    return bodies


def main() -> int:
    print("lazy_log_formatting_audit=started")
    failures: list[str] = []
    macro_count = 0

    for path in iter_rust_files():
        rel_path = path.relative_to(REPO_ROOT)
        for line, macro_name, body in iter_lazy_log_macro_bodies(path):
            macro_count += 1
            location = f"{rel_path}:{line}:{macro_name}!"
            for pattern, label in EAGER_PATTERNS:
                if pattern.search(body):
                    failures.append(
                        f"{location}: eager {label} allocation inside lazy log macro"
                    )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print("lazy_log_formatting_audit=failed")
        return 1

    print(f"debug_trace_macro_sites={macro_count}")
    print("eager_formatting_patterns=0")
    print("lazy_log_formatting_audit=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
