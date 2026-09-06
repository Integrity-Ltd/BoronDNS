#!/usr/bin/env python3
"""Check release handoff decisions and shared rehearsal workspace setup."""

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
    def preflight_workspace_setup(self) -> str:
        # Exercise the actual setup/cleanup without starting package builds.
        script = (ROOT / "scripts/release-preflight-inner.sh").read_text(
            encoding="utf-8"
        )
        start = 'work_root="$BORONDNS_PREFLIGHT_WORKSPACE"\n'
        end = 'git -c advice.detachedHead=false clone'
        self.assertEqual(script.count(start), 1)
        self.assertEqual(script.count(end), 1)
        return start + script.split(start, 1)[1].split(end, 1)[0]

    def test_preflight_child_temp_paths_stay_in_shared_workspace(self) -> None:
        # Nested containers use the host daemon, which cannot bind paths from
        # the preflight container's private /tmp directory.
        setup = self.preflight_workspace_setup()
        with tempfile.TemporaryDirectory(prefix="borondns-preflight-path-test-") as scratch:
            root = Path(scratch)
            shared = root / "shared"
            private = root / "private"
            shared.mkdir()
            private.mkdir()
            for inherited_tmp in (None, str(private)):
                with self.subTest(inherited_tmp=inherited_tmp):
                    env = os.environ.copy()
                    env["BORONDNS_PREFLIGHT_WORKSPACE"] = str(shared)
                    env["BORONDNS_PREFLIGHT_OWNER_UID"] = str(os.getuid())
                    env["BORONDNS_PREFLIGHT_OWNER_GID"] = str(os.getgid())
                    env.pop("TMPDIR", None)
                    if inherited_tmp is not None:
                        env["TMPDIR"] = inherited_tmp
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", setup + "\nmktemp -d\n"],
                        env=env, check=True, capture_output=True, text=True, timeout=10,
                    )
                    created = Path(result.stdout.strip())
                    try:
                        self.assertEqual(created.parent, shared)
                    finally:
                        # The probe creates only an empty directory, including
                        # on the pre-fix failure path outside the shared tree.
                        created.rmdir()

    @unittest.skipUnless(os.geteuid() == 0, "ownership transfer requires root")
    def test_preflight_returns_root_created_files_to_operator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="borondns-preflight-owner-test-") as scratch:
            shared = Path(scratch) / "shared"
            shared.mkdir(mode=0o700)
            operator_uid = operator_gid = 65534
            os.chown(shared, operator_uid, operator_gid)
            outside = Path(scratch) / "outside"
            outside.touch(mode=0o600)
            env = os.environ.copy()
            env.update({
                "BORONDNS_PREFLIGHT_WORKSPACE": str(shared),
                "BORONDNS_PREFLIGHT_OWNER_UID": str(operator_uid),
                "BORONDNS_PREFLIGHT_OWNER_GID": str(operator_gid),
                "TEST_OUTSIDE": str(outside),
            })
            subprocess.run(
                ["bash", "-euo", "pipefail", "-c", self.preflight_workspace_setup()
                 + '\nmkdir -m 0500 "$work_root/root-created"\n'
                 + 'touch "$work_root/root-created/output"\n'
                 + 'ln -s "$TEST_OUTSIDE" "$work_root/link"\n'],
                env=env, check=True, capture_output=True, text=True, timeout=10,
            )
            for path in (shared, shared / "root-created", shared / "root-created/output"):
                self.assertEqual((path.stat().st_uid, path.stat().st_gid),
                                 (operator_uid, operator_gid))
                self.assertEqual(path.stat().st_mode & 0o600, 0o600)
            self.assertEqual(shared.stat().st_mode & 0o077, 0)
            self.assertEqual(outside.stat().st_uid, 0)
            self.assertEqual(outside.stat().st_mode & 0o777, 0o600)

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
