#!/usr/bin/env python3
"""Regression tests for Markdown navigation checks; no builds or network calls."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "doc_hygiene", Path(__file__).with_name("check-doc-hygiene.py")
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DocumentationChecks(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="borondns-doc-check-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve()
        self.patch_root = patch.object(CHECKER, "ROOT", self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)
        self.guide = self.make_file("docs/guide.md", "# Guide\n\n## Installation\n")
        self.make_file("docs/reference.md", "# Reference\n\n## Config settings\n")

    def make_file(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_local_and_same_document_links(self) -> None:
        self.assertEqual([], CHECKER.link_errors(
            self.guide,
            "[config](reference.md#config-settings) [install](#installation)\n"
            "[source](../docs/reference.md) [web](https://example.net/missing)\n"
            "[mail](mailto:security@example.net)\n",
        ))

    def test_missing_file_and_heading_are_rejected(self) -> None:
        errors = CHECKER.link_errors(
            self.guide, "[file](absent.md) [heading](reference.md#absent)"
        )
        self.assertEqual(2, len(errors))
        self.assertTrue(any("broken local link" in error for error in errors))
        self.assertTrue(any("unknown heading" in error for error in errors))

    def test_reference_style_and_space_in_filename(self) -> None:
        self.make_file("docs/spaced name.md", "# A title\n")
        self.assertEqual([], CHECKER.link_errors(
            self.guide, "[ref]: <spaced name.md#a-title>\n"
            "[inline](spaced%20name.md#a-title)\n",
        ))
        self.assertTrue(CHECKER.link_errors(self.guide, "[ref]: missing.md\n"))

    def test_link_cannot_leave_repository(self) -> None:
        errors = CHECKER.link_errors(self.guide, "[outside](../../outside.md)")
        self.assertEqual(["link leaves repository: ../../outside.md"], errors)

    def test_examples_are_not_live_links(self) -> None:
        text = """# Guide
`[example](missing.md)`
```markdown
[example](also-missing.md)
# Not a real heading
```
~~~~markdown
```
[example](still-missing.md)
~~~~
"""
        self.assertEqual([], CHECKER.link_errors(self.guide, text))
        self.assertEqual({"guide"}, CHECKER.heading_anchors(text))

    def test_duplicate_and_explicit_anchors(self) -> None:
        text = """# Guide
## Setup
## Setup
## Setup-1
<a id="legacy-setup"></a>
"""
        self.assertEqual(
            {"guide", "setup", "setup-1", "setup-1-1", "legacy-setup"},
            CHECKER.heading_anchors(text),
        )

    def test_numbered_sections_and_title(self) -> None:
        self.guide.write_text("## 1. First\n## 1. Second\n", encoding="utf-8")
        errors = CHECKER.check_doc(self.guide)
        self.assertIn("missing document title", errors)
        self.assertIn("duplicate numbered section: 1", errors)

    def test_editorial_rewording_is_allowed(self) -> None:
        self.guide.write_text(
            "# Running a server\n\nStart here.\n", encoding="utf-8"
        )
        self.assertEqual([], CHECKER.check_doc(self.guide))

    def test_document_discovery_uses_publishable_paths(self) -> None:
        self.make_file("docs/ignored-lab.md", "# Private lab\n")
        self.make_file("target/generated.md", "# Generated\n")
        self.make_file("docs/new.md", "# New guide\n")
        tracked_and_unignored = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="docs/guide.md\0docs/reference.md\0docs/new.md\0"
                   "target/generated.md\0docs/deleted.md\0", stderr="",
        )
        with patch.object(CHECKER.subprocess, "run", return_value=tracked_and_unignored) as run:
            paths = CHECKER.current_doc_paths()
        self.assertEqual(
            {"guide.md", "reference.md", "new.md"}, {path.name for path in paths}
        )
        self.assertIn("--exclude-standard", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
