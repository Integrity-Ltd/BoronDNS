#!/usr/bin/env python3
"""Regression tests for the maintainability source and module audit."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_MODULE = REPO_ROOT / "scripts" / "audit_maintainability.py"


def load_audit_module():
    spec = importlib.util.spec_from_file_location("audit_maintainability", AUDIT_MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str = "fn fixture() {}\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_test_only_include_directories_are_not_production(audit) -> None:
    with tempfile.TemporaryDirectory(prefix="borondns-maintainability-audit.") as temporary:
        root = Path(temporary)
        write(root / "crates/example/src/lib.rs")
        write(root / "crates/example/src/contest.rs")
        write(root / "crates/example/src/tests.rs")
        write(root / "crates/example/src/tests/case.rs")
        write(root / "crates/example/src/config_tests/case.rs")
        write(root / "crates/example/src/dns_tests/case.rs")
        write(root / "crates/example/src/zone_image_tests/case.rs")
        write(root / "crates/example/build.rs")

        discovered = {
            path.as_posix()
            for path in audit.discover_production_source_files(root)
        }

        assert discovered == {
            "crates/example/build.rs",
            "crates/example/src/contest.rs",
            "crates/example/src/lib.rs",
        }


def test_cfg_test_blocks_are_not_counted(audit) -> None:
    lines = [
        "fn production() {}",
        "#[cfg(test)]",
        "mod tests {",
        "    fn test_only() {}",
        "}",
        "fn production_too() {}",
    ]

    assert audit.production_lines(lines) == [
        "fn production() {}",
        "fn production_too() {}",
    ]


def test_module_map_must_match_discovered_production_files(audit) -> None:
    discovered = [Path("crates/example/src/lib.rs"), Path("crates/example/src/server.rs")]

    try:
        audit.validate_module_map(discovered, [("crates/example/src/lib.rs", "boundary")])
    except audit.AuditError as error:
        assert "missing from module map" in str(error)
        assert "crates/example/src/server.rs" in str(error)
    else:
        raise AssertionError("an incomplete module map was accepted")

    try:
        audit.validate_module_map(
            discovered,
            [
                ("crates/example/src/lib.rs", "boundary"),
                ("crates/example/src/server.rs", "server"),
                ("crates/example/src/removed.rs", "stale"),
            ],
        )
    except audit.AuditError as error:
        assert "not production source" in str(error)
        assert "crates/example/src/removed.rs" in str(error)
    else:
        raise AssertionError("a stale module-map entry was accepted")


def test_architecture_table_must_match_module_map(audit) -> None:
    module_map = [
        ("crates/example/src/lib.rs", "boundary"),
        ("crates/example/src/server.rs", "server"),
    ]
    architecture = """\
## Module Organisation

| Module | Major functional area mapping | Architecture note |
| --- | --- | --- |
| `crates/example/src/lib.rs` | boundary | note |
| `crates/example/src/removed.rs` | stale | note |

## Current Implementation Decisions
"""

    try:
        audit.validate_architecture_module_map(architecture, module_map)
    except audit.AuditError as error:
        assert "missing entries" in str(error)
        assert "crates/example/src/server.rs" in str(error)
        assert "stale entries" in str(error)
        assert "crates/example/src/removed.rs" in str(error)
    else:
        raise AssertionError("an out-of-sync architecture table was accepted")


def test_repository_module_map_is_complete(audit) -> None:
    discovered = audit.discover_production_source_files(REPO_ROOT)
    audit.validate_module_map(discovered, audit.MODULE_MAP)


def main() -> None:
    audit = load_audit_module()
    test_test_only_include_directories_are_not_production(audit)
    test_cfg_test_blocks_are_not_counted(audit)
    test_module_map_must_match_discovered_production_files(audit)
    test_architecture_table_must_match_module_map(audit)
    test_repository_module_map_is_complete(audit)
    print("maintainability audit tests passed")


if __name__ == "__main__":
    main()
