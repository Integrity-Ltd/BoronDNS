#!/usr/bin/env python3
"""Keep the low-level dependency registry precise and fail closed on new users."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dependency_gate", ROOT / "scripts/check-unsafe-prone-dependencies.py"
)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REGISTRY = ROOT / "docs/unsafe-prone-dependencies.tsv"
PRIVILEGE = "crates/borondns-server/src/privilege.rs"


class RustixConfinementTests(unittest.TestCase):
    def test_current_registry_covers_privilege_verification(self):
        row = GATE.read_tsv(REGISTRY)["rustix"]
        self.assertIn("posix-privilege-drop", row["boundary_ids"].split(";"))
        self.assertIn(PRIVILEGE, row["allowed_paths"].split(";"))
        GATE.assert_current_dependency_confined(ROOT, REGISTRY, "rustix", row)

    def test_omitting_privilege_adapter_reproduces_failure(self):
        row = GATE.read_tsv(REGISTRY)["rustix"].copy()
        row["allowed_paths"] = ";".join(
            path for path in row["allowed_paths"].split(";") if path != PRIVILEGE
        )
        with self.assertRaisesRegex(SystemExit, "privilege.rs"):
            GATE.assert_current_dependency_confined(ROOT, REGISTRY, "rustix", row)

    def test_allowing_adapter_does_not_allow_other_modules(self):
        with tempfile.TemporaryDirectory(
            prefix="borondns-dependency-gate-"
        ) as directory:
            root = Path(directory)
            adapter = root / PRIVILEGE
            adapter.parent.mkdir(parents=True)
            adapter.write_text("let groups = rustix::process::getgroups()?;\n")
            row = {"allowed_paths": PRIVILEGE, "rationale": "privilege verification"}
            GATE.assert_current_dependency_confined(root, REGISTRY, "rustix", row)
            (adapter.parent / "dns.rs").write_text("use rustix::process::getgroups;\n")
            with self.assertRaisesRegex(SystemExit, "dns.rs"):
                GATE.assert_current_dependency_confined(root, REGISTRY, "rustix", row)


if __name__ == "__main__":
    unittest.main()
