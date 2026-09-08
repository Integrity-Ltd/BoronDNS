#!/usr/bin/env python3
"""Mutation tests for the source audit; these complement runtime regressions."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = "crates/borondns-server/src/lib.rs"
IMAGE = "crates/borondns-core/src/zone_image.rs"
LIFECYCLE = "crates/borondns-server/src/zone_persistence/catalog_lifecycle.rs"


class InvariantAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="borondns-invariant-audit-")
        cls.root = Path(cls.temp.name)
        paths = [ROOT / "Cargo.toml", ROOT / "docs/unsafe-boundaries.tsv",
                 ROOT / "scripts/audit-invariants.sh"]
        paths.extend((ROOT / "crates").rglob("*.rs"))
        paths.extend((ROOT / "crates").glob("*/Cargo.toml"))
        for source in paths:
            dest = cls.root / source.relative_to(ROOT)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def audit(self):
        return subprocess.run(
            ["bash", str(self.root / "scripts/audit-invariants.sh")],
            text=True, capture_output=True, timeout=60, check=False,
        )

    def test_current_source_passes(self):
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mutations_are_rejected(self):
        cases = [
            ("crates/borondns-core/src/dns.rs", None,
             "\nfn audit_probe() { std::fs::write(\"x\", b\"x\"); }\n",
             "BDS-INV-002"),
            ("crates/borondns-server/src/zone_persistence/unreviewed.rs", None,
             'fn audit_probe() { std::fs::write("x", b"x"); }', "BDS-INV-004"),
            (LIFECYCLE, "open_bounded_regular(&path, 32, 32)",
             "open_bounded_regular(&path, 64, 64)", "catalog lifecycle token boundary"),
            (LIFECYCLE, "create_new(true)", "create(true)", "catalog lifecycle token boundary"),
            (LIFECYCLE, "file.sync_all()", "file.flush()", "catalog lifecycle token boundary"),
            (IMAGE, "owner_label_count: u16", "owner_label_count: u32",
             "DNAME synthesis lost"),
            (IMAGE, "chain_state_start(qname, exact_node, max_cname_chain - 1, any_response)",
             "chain_state_start(qname, exact_node, max_cname_chain, any_response)",
             "DNAME synthesis lost"),
            (SERVER, "Current(ZoneMetadata)", "Current(Arc<ZoneSnapshot>)",
             "refresh current outcome"),
            (SERVER, "} => (metadata, true, catalog_members, promoted_cache),",
             "} => (metadata, true, catalog_members, None),", "refresh updated success"),
            (SERVER, "    maintenance.await;",
             "    /* maintenance omitted */", "refresh maintenance acknowledgement ordering"),
        ]
        for function in ["lookup_dname", "resolve_dname_at"]:
            original = (self.root / IMAGE).read_text()
            start = original.index(f"    fn {function}")
            call = original.index("self.resolve_indirection_target(", start)
            # Include the full prefix to mutate the intended function, not a
            # different resolver call elsewhere in this large implementation.
            before = original[start:call + len("self.resolve_indirection_target(")]
            cases.append((IMAGE, before, before.replace(
                "self.resolve_indirection_target(", "self.bypass_continuation("),
                "DNAME synthesis lost"))
        for path, before, after, expected in cases:
            with self.subTest(path=path, mutation=before):
                target = self.root / path
                original = target.read_text() if target.exists() else None
                if before is not None:
                    self.assertIn(before, original)
                    changed = original.replace(before, after, 1)
                else:
                    changed = after + (original or "")
                target.write_text(changed)
                try:
                    result = self.audit()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    # Match the failure summary, not the always-printed check name.
                    summary = result.stdout[result.stdout.rfind("architectural_invariant_audit="):]
                    self.assertIn(expected, summary + result.stderr, result.stdout)
                finally:
                    if original is None:
                        target.unlink()
                    else:
                        target.write_text(original)


if __name__ == "__main__":
    unittest.main()
