#!/usr/bin/env python3
"""Exercise native-package version checks without Cargo or package managers."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NativePackageVersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="borondns-package-version-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        # Deliberately not the current release; a package-level version must not
        # be mistaken for the workspace version, either.
        (self.root / "Cargo.toml").write_text(
            '[package]\nversion = "0.0.2"\n\n'
            '[workspace.package]\nversion = "7.8.9"\n'
            '[dependencies]\nversion = "0.0.3"\n'
        )
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("BORONDNS_", "GITHUB_", "GIT_"))
        }

    def resolve(self, **environment):
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c",
             'source "$1/scripts/native-package-common.sh"; native_package_version "$1"',
             "test", str(self.root)],
            env=self.env | environment, text=True, capture_output=True,
        )

    def assert_version(self, **environment):
        result = self.resolve(**environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "7.8.9\n")

    def assert_rejected(self, **environment):
        result = self.resolve(**environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native package version", result.stderr)

    def test_workspace_is_the_version_source(self):
        self.assert_version()

    def test_native_notices_require_a_nonempty_regular_file(self):
        notices = self.root / "THIRD-PARTY-NOTICES.html"
        def resolve_notices():
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c",
                 'source "$1/scripts/native-package-common.sh"; native_package_notices fixture.bin',
                 "test", str(self.root)],
                env=self.env | {"BORONDNS_PACKAGE_NOTICES": str(notices)},
                text=True, capture_output=True,
            )
        self.assertNotEqual(resolve_notices().returncode, 0)
        notices.touch()
        self.assertNotEqual(resolve_notices().returncode, 0)
        notices.write_text("<html>Fixture notices</html>")
        result = resolve_notices()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(notices))
        notices.unlink()
        notices.symlink_to(self.root / "Cargo.toml")
        self.assertNotEqual(resolve_notices().returncode, 0)

    def test_matching_tags_and_overrides_are_assertions(self):
        self.assert_version(
            BORONDNS_RELEASE_TAG="v7.8.9", GITHUB_REF="refs/tags/v7.8.9",
            GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="v7.8.9",
            BORONDNS_DEB_VERSION="7.8.9", BORONDNS_RPM_VERSION="7.8.9",
        )

    def test_every_tag_source_is_checked(self):
        for environment in [
            {"BORONDNS_RELEASE_TAG": "v7.8.8"},
            {"GITHUB_REF": "refs/tags/v7.8.8"},
            {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v7.8.8"},
            {"GITHUB_REF_TYPE": "tag"},
            {"BORONDNS_RELEASE_TAG": "v7.8.9", "GITHUB_REF": "refs/tags/v7.8.8"},
            {"BORONDNS_RELEASE_TAG": "v7.8.9-beta"},
            {"BORONDNS_RELEASE_TAG": ""},
        ]:
            with self.subTest(environment=environment):
                self.assert_rejected(**environment)

    def test_branch_name_is_not_a_release_tag(self):
        self.assert_version(GITHUB_REF="refs/heads/main", GITHUB_REF_TYPE="branch",
                            GITHUB_REF_NAME="main")

    def test_overrides_cannot_relabel_a_release(self):
        for key in ("BORONDNS_DEB_VERSION", "BORONDNS_RPM_VERSION"):
            for value in ("1.0.0", "7.8.10", ""):
                with self.subTest(key=key, value=value):
                    self.assert_rejected(**{key: value})

    def test_invalid_or_ambiguous_workspace_version_fails_closed(self):
        for manifest in (
            '[workspace.package]\nversion = "7.8.9-beta"\n',
            '[workspace.package]\nversion = "07.8.9"\n',
            '[workspace.package]\nversion = "7.8.9\n',
            '[workspace.package]\n',
            '[workspace.package]\nversion = "7.8.9"\nversion = "7.8.9"\n',
        ):
            with self.subTest(manifest=manifest):
                (self.root / "Cargo.toml").write_text(manifest)
                self.assert_rejected()

    def test_local_exact_release_tags_must_match(self):
        def git(*args):
            subprocess.run(["git", "-C", str(self.root), *args], env=self.env,
                           check=True, capture_output=True)
        git("init", "-q")
        git("add", "Cargo.toml")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        git("-c", "tag.gpgsign=false", "tag", "v7.8.9")
        self.assert_version()
        git("-c", "tag.gpgsign=false", "tag", "v7.8.8")
        self.assert_rejected()

    def test_builder_entrypoints_reject_mismatch_before_packaging(self):
        for kind in ("deb", "rpm"):
            result = subprocess.run(
                ["bash", str(self.root / "scripts" / f"package-{kind}.sh")],
                env=self.env | {"BORONDNS_RELEASE_TAG": "v7.8.8"},
                text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("native package version", result.stderr)
            self.assertFalse((self.root / "target").exists())

    def test_binary_version_must_match_and_command_must_succeed(self):
        binary = self.root / "borondns"
        for output, status, accepted in (
            ("borondns 7.8.9\nbuild commit: fixture", 0, True),
            ("borondns 7.8.9", 0, True),
            ("borondns 7.8.8", 0, False),
            ("boron-gun 7.8.9", 0, False),
            ("borondns 7.8.9", 1, False),
        ):
            with self.subTest(output=output, status=status):
                binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\nexit {status}\n")
                binary.chmod(0o755)
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     'source "$1/scripts/native-package-common.sh"; '
                     'native_package_check_binary_version "$1/borondns" borondns 7.8.9',
                     "test", str(self.root)],
                    env=self.env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_builders_reject_stale_binaries_before_creating_output(self):
        tools = self.root / "tools"
        tools.mkdir()
        for name in ("dpkg-deb", "rpmbuild"):
            tool = tools / name
            tool.write_text("#!/bin/sh\necho 'packager must not execute' >&2\nexit 99\n")
            tool.chmod(0o755)
        binary = self.root / "borondns"
        binary.write_text("#!/bin/sh\necho 'borondns 7.8.8'\n")
        binary.chmod(0o755)
        for kind in ("deb", "rpm"):
            result = subprocess.run(
                ["bash", str(self.root / "scripts" / f"package-{kind}.sh")],
                env=self.env | {
                    "PATH": f"{tools}:{self.env['PATH']}",
                    "SOURCE_DATE_EPOCH": "1700000000",
                    "BORONDNS_RELEASE_TAG": "v7.8.9",
                    f"BORONDNS_{kind.upper()}_BORONDNS_BIN": str(binary),
                    f"BORONDNS_{kind.upper()}_BORON_GUN_BIN": str(binary),
                }, text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reports borondns 7.8.8; expected borondns 7.8.9", result.stderr)
            self.assertNotIn("packager must not execute", result.stderr)
            self.assertFalse((self.root / "target").exists())


if __name__ == "__main__":
    unittest.main()
