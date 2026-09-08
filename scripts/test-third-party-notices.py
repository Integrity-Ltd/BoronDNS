#!/usr/bin/env python3
"""License inventory tests; fixtures never invoke Cargo or fetch packages."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "notices", Path(__file__).with_name("package-third-party-notices.py")
)
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)


class NoticesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="borondns-notices-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def package(self, name="dependency", version="1.2.3"):
        root = self.root / name
        root.mkdir()
        (root / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        (root / "LICENSE-MIT").write_text("Copyright Example <authors>\nMIT terms\n")
        return {
            "id": name,
            "name": name,
            "version": version,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "repository": "https://example.invalid/source",
            "license": "MIT",
            "license_file": None,
            "manifest_path": str(root / "Cargo.toml"),
        }

    def test_retains_attribution_nested_notices_and_full_license_text(self):
        package = self.package()
        root = Path(package["manifest_path"]).parent
        (root / "vendor").mkdir()
        (root / "vendor" / "NOTICE").write_text("Vendored attribution")
        (root / "LICENSES").mkdir()
        (root / "LICENSES" / "BSD-3-Clause.txt").write_text("Additional BSD conditions")
        (root / "README.md").write_text("Authors and license details")
        entry = NOTICES.package_entry(package)
        self.assertEqual(
            [p[0] for p in entry["documents"]],
            [
                "LICENSE-MIT",
                "LICENSES/BSD-3-Clause.txt",
                "README.md",
                "vendor/NOTICE",
            ],
        )
        rendered = NOTICES.render(
            [entry], "runtime notice", "x86_64-unknown-linux-musl"
        )
        self.assertIn("Copyright Example &lt;authors&gt;", rendered)
        self.assertIn("Vendored attribution", rendered)
        self.assertIn("dependency 1.2.3", rendered)
        self.assertNotIn(str(self.root), rendered)

    def test_missing_license_or_empty_documents_fails_closed(self):
        package = self.package()
        path = Path(package["manifest_path"]).parent / "LICENSE-MIT"
        for text in ("", " \n"):
            path.write_text(text)
            with self.assertRaisesRegex(ValueError, "license"):
                NOTICES.package_entry(package)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "license"):
            NOTICES.package_entry(package)

    def test_declared_license_file_is_included_even_with_an_unusual_name(self):
        package = self.package()
        package["license_file"] = "LEGAL.txt"
        (Path(package["manifest_path"]).parent / "LEGAL.txt").write_text(
            "Special terms"
        )
        self.assertIn(
            "LEGAL.txt", [p[0] for p in NOTICES.package_entry(package)["documents"]]
        )

    def test_symlink_license_cannot_escape_package(self):
        package = self.package()
        root = Path(package["manifest_path"]).parent
        (root / "LICENSE-MIT").unlink()
        (self.root / "outside").write_text("outside secret")
        (root / "LICENSE-MIT").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ValueError, "symlink"):
            NOTICES.package_entry(package)

    def test_selected_graph_includes_build_dependencies_but_not_dev_only(self):
        def edge(name, kind=None):
            return {"pkg": name, "dep_kinds": [{"kind": kind}]}

        metadata = {
            "packages": [
                {"id": n, "name": n}
                for n in ("borondns-cli", "runtime", "build", "dev")
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "borondns-cli",
                        "deps": [edge("runtime"), edge("dev", "dev")],
                    },
                    {"id": "runtime", "deps": [edge("build", "build")]},
                    {"id": "build", "deps": []},
                    {"id": "dev", "deps": []},
                ]
            },
        }
        selected = NOTICES.selected_packages(metadata, ["borondns-cli"])
        self.assertEqual(
            {p["id"] for p in selected}, {"borondns-cli", "runtime", "build"}
        )
        with self.assertRaisesRegex(ValueError, "missing"):
            NOTICES.selected_packages(metadata, ["missing-root"])

    def test_render_is_stable_and_contains_runtime_notices(self):
        a = NOTICES.package_entry(self.package("a"))
        b = NOTICES.package_entry(self.package("b"))
        self.assertEqual(
            NOTICES.render([b, a], "Runtime & musl", "target"),
            NOTICES.render([a, b], "Runtime & musl", "target"),
        )
        self.assertIn(
            "Runtime &amp; musl", NOTICES.render([a], "Runtime & musl", "target")
        )


if __name__ == "__main__":
    unittest.main()
