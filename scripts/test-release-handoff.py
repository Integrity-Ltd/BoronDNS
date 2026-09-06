#!/usr/bin/env python3
"""Check decision classification through the real handoff generator."""

from __future__ import annotations

import csv
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseHandoffTests(unittest.TestCase):
    def test_formatted_pending_decisions_require_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="borondns-handoff-test-") as scratch:
            root = Path(scratch)
            (root / "scripts").mkdir()
            (root / "docs").mkdir()
            script = root / "scripts/capture-release-handoff.sh"
            shutil.copyfile(ROOT / "scripts/capture-release-handoff.sh", script)
            (root / "docs/project-decision-register.md").write_text(
                "# Project decisions\n\n## Decision Register\n\n"
                "| Item | Flagged at | Recommendation | Decision |\n"
                "| --- | --- | --- | --- |\n"
                "| Plain pending | review | Review | Pending |\n"
                "| Formatted pending | review | Review | "
                "**Pending: acceptance evidence is missing** |\n"
                "| Emphasized status | review | Review | "
                "**Pending**: owner review is needed |\n"
                "| Resolved | review | Keep | "
                "**Resolved: the previous Pending item is closed** |\n",
                encoding="utf-8",
            )
            output = root / "handoff"
            env = os.environ.copy()
            env["BORONDNS_RELEASE_HANDOFF_DIR"] = str(output)
            subprocess.run(
                ["bash", str(script)], env=env, check=True,
                capture_output=True, text=True, timeout=30,
            )
            with (output / "appendix-c5-decision-register.tsv").open(
                encoding="utf-8", newline=""
            ) as handle:
                rows = {row["item"]: row for row in csv.DictReader(handle, delimiter="\t")}

            self.assertEqual(set(rows), {
                "Plain pending", "Formatted pending", "Emphasized status", "Resolved"
            })
            for item in ("Plain pending", "Formatted pending", "Emphasized status"):
                self.assertIn("resolve or explicitly defer", rows[item]["release_action"])
            self.assertNotIn("resolve or explicitly defer", rows["Resolved"]["release_action"])
            self.assertEqual(
                rows["Formatted pending"]["decision"],
                "**Pending: acceptance evidence is missing**",
            )


if __name__ == "__main__":
    unittest.main()
