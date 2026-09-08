#!/usr/bin/env python3
"""Physical benchmark safety checks; no real SSH or detached processes."""

import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "SERVER_SSH": "server.invalid",
    "PLAYER_SSH": "player.invalid",
    "INTERFACE": "testnic0",
    "TARGET_IP": "198.18.0.1",
    "SOURCE_IP": "198.18.0.2",
}
MACS = {"SOURCE_MAC": "02:00:00:00:00:01", "TARGET_MAC": "02:00:00:00:00:02"}


class PhysicalInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="borondns-physical-inputs-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        for name in ("ssh", "systemd-run", "setsid", "nohup"):
            stub = self.bin / name
            stub.write_text("#!/bin/sh\necho UNSAFE_EXTERNAL_CALL >&2\nexit 93\n")
            stub.chmod(0o700)
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("BORONDNS_PHYSICAL_")
        }
        self.env["PATH"] = f"{self.bin}:{os.environ['PATH']}"
        self.env["BORONDNS_PHYSICAL_DETACHED_RUN_DIR"] = str(self.work / "run")
        for suffix, value in REQUIRED.items():
            self.env[f"BORONDNS_PHYSICAL_{suffix}"] = value

    def run_script(self, name, *args):
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / name), *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def assert_refused(self, result, setting):
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn(setting, result.stderr)
        self.assertNotIn("UNSAFE_EXTERNAL_CALL", result.stdout + result.stderr)

    def test_direct_wrapper_refuses_each_missing_target_before_ssh(self):
        for suffix in REQUIRED:
            key = f"BORONDNS_PHYSICAL_{suffix}"
            with self.subTest(setting=key):
                value = self.env.pop(key)
                self.assert_refused(
                    self.run_script("physical-udp-knot-comparison.sh"), key
                )
                self.env[key] = value

    def test_boron_gun_requires_both_explicit_valid_macs(self):
        self.env["BORONDNS_PHYSICAL_PLAYER_TOOL"] = "boron-gun"
        for suffix, value in MACS.items():
            self.env[f"BORONDNS_PHYSICAL_{suffix}"] = value
        for suffix in MACS:
            key = f"BORONDNS_PHYSICAL_{suffix}"
            original = self.env[key]
            for invalid in ("", "not-a-mac", "02:00:00:00:00:01;bad"):
                with self.subTest(setting=key, value=invalid):
                    self.env[key] = invalid
                    self.assert_refused(
                        self.run_script("physical-udp-knot-comparison.sh"), key
                    )
            self.env[key] = original

    def test_detached_start_refuses_missing_target_without_launch(self):
        del self.env["BORONDNS_PHYSICAL_SERVER_SSH"]
        self.assert_refused(
            self.run_script("physical-udp-detached-batch.sh", "start"),
            "BORONDNS_PHYSICAL_SERVER_SSH",
        )
        self.assertFalse((self.work / "run").exists())

    def test_valid_kxdpgun_and_boron_gun_inputs(self):
        for player in ("kxdpgun", "boron-gun"):
            self.env["BORONDNS_PHYSICAL_PLAYER_TOOL"] = player
            if player == "boron-gun":
                for suffix, value in MACS.items():
                    self.env[f"BORONDNS_PHYSICAL_{suffix}"] = value
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1/scripts/physical-benchmark-inputs.sh"; physical_validate_inputs',
                    "test",
                    str(ROOT),
                ],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_custom_detached_harness_requires_player_selection(self):
        self.env["BORONDNS_PHYSICAL_DETACHED_HARNESS"] = str(
            ROOT / "scripts/physical-dns-server-loss-matrix.sh"
        )
        self.assert_refused(
            self.run_script("physical-udp-detached-batch.sh", "start"),
            "BORONDNS_PHYSICAL_PLAYER_TOOL",
        )
        self.assertFalse((self.work / "run").exists())

    def test_detached_help_does_not_require_target(self):
        del self.env["BORONDNS_PHYSICAL_SERVER_SSH"]
        result = self.run_script("physical-udp-detached-batch.sh", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_detached_status_does_not_require_target(self):
        del self.env["BORONDNS_PHYSICAL_SERVER_SSH"]
        run = self.work / "completed-run"
        run.mkdir()
        (run / "status").write_text("complete\n")
        (run / "exit-code").write_text("0\n")
        result = self.run_script("physical-udp-detached-batch.sh", "status", str(run))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=complete", result.stdout)
        self.assertNotIn("UNSAFE_EXTERNAL_CALL", result.stdout + result.stderr)

    def test_players_use_only_the_immutable_row_query_snapshot(self):
        text = (ROOT / "scripts/physical-udp-knot-comparison.sh").read_text()
        self.assertTrue(
            '-i "$workdir/$run_dir/querydb"' in text, "kxdpgun must use row querydb"
        )
        self.assertTrue(
            '--query-list "$workdir/$run_dir/querydb"' in text,
            "BoronGun must use row querydb",
        )
        self.assertFalse("-i querydb" in text, "shared kxdpgun querydb is unsafe")
        self.assertFalse(
            "--query-list querydb" in text, "shared BoronGun querydb is unsafe"
        )

    def test_workload_probe_precedes_every_perf_capture(self):
        text = (ROOT / "scripts/physical-udp-knot-comparison.sh").read_text()
        lines = text.splitlines()
        captures = 0
        for index, line in enumerate(lines):
            if line.lstrip().startswith('run_server_perf_start "$run_abs"'):
                captures += 1
                self.assertIn("prepare_player_workload", lines[index - 1])
        self.assertGreater(captures, 0)

    def test_kxdpgun_optional_macs_preserve_remote_positional_arguments(self):
        text = (ROOT / "scripts/physical-udp-knot-comparison.sh").read_text()
        player = text.split("run_player_kxdpgun() {", 1)[1]
        invocation = next(
            line
            for line in player.splitlines()
            if line.strip().startswith('ssh_control "$player_ssh" bash -s --')
        )
        variables = set(re.findall(r"\$\{?([a-z_]+)", invocation))
        values = dict.fromkeys(variables, "fixture")
        values.update(
            boron_gun_source_mac="",
            boron_gun_target_mac="",
            boron_gun_response_timeout_ms="1000",
        )
        setup = "\n".join(
            f"{key}={shlex.quote(value)}" for key, value in values.items()
        )
        setup += '\nBORONDNS_PHYSICAL_SOURCE_MAC=""\nBORONDNS_PHYSICAL_TARGET_MAC=""\n'
        setup += "\n".join(
            line
            for line in text.split("perf_record=", 1)[0].splitlines()
            if line.startswith(("boron_gun_source_mac=", "boron_gun_target_mac="))
        )
        remote = player.split("<<'REMOTE'\n", 1)[1].split(
            'mkdir -p "$workdir/$run_dir"', 1
        )[0]
        # OpenSSH serializes its command arguments into one shell command; empty
        # argv values disappear unless the caller encodes them explicitly.
        result = subprocess.run(
            [
                "bash",
                "-c",
                setup
                + '\nssh_control() { shift; bash -c "$*"; }\n'
                + invocation
                + "\n"
                + remote
                + 'printf "%s %s %s\\n" "$boron_gun_source_mac" "$boron_gun_target_mac" "$boron_gun_response_timeout_ms"\nREMOTE\n',
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "__unused__ __unused__ 1000")

    def test_summary_includes_workload_identity_and_response_classification(self):
        text = (ROOT / "scripts/physical-udp-knot-comparison.sh").read_text()
        for field in (
            "querydb_sha256",
            "query_count",
            "response_validation",
            "response_rcodes",
        ):
            self.assertTrue(field in text, f"summary is missing {field}")

    def test_workload_policy_refuses_invalid_value_before_ssh(self):
        self.env["BORONDNS_PHYSICAL_WORKLOAD_POLICY"] = "ignore-errors"
        self.assert_refused(
            self.run_script("physical-udp-knot-comparison.sh"),
            "BORONDNS_PHYSICAL_WORKLOAD_POLICY",
        )

    def stage_workload_with_fake_ssh(self, corrupt=False):
        for name in ("stage", "control", "player", "row"):
            (self.work / name).mkdir()
        query = b"host000082.perf.test. A\n"
        (self.work / "stage/querydb").write_bytes(query)
        (self.work / "player/querydb").write_text("wrong.other.test. A\n")
        env = dict(self.env, TEST_WORK=str(self.work), TEST_ROOT=str(ROOT))
        env["CORRUPT_PLAYER"] = "true" if corrupt else "false"
        result = subprocess.run(
            [
                "bash",
                "-c",
                r"""
set -euo pipefail
source "$TEST_ROOT/scripts/physical-benchmark-workload.sh"
ssh_control_dir="$TEST_WORK/control"
stage_abs="$TEST_WORK/stage"
out_abs="$TEST_WORK/server-evidence"
player_workdir_abs="$TEST_WORK/player"
workload_verifier="$TEST_ROOT/scripts/physical-benchmark-workload.py"
workload_policy=positive
server_ssh=server
player_ssh=player
ssh_control() {
    local host="$1" command="$2"
    bash -c "$command"
    if [[ "$CORRUPT_PLAYER" == true && "$host" == player && "$command" == "cat > "*"/querydb'" ]]; then
        printf 'poison.other.test. A\n' >>"$prepared_player_remote_dir/querydb"
    fi
}
snapshot_physical_workload
printf 'changed.after.snapshot. A\n' >"$stage_abs/querydb"
stage_player_querydb "$TEST_WORK/row" fixture
printf '%s\n' "$prepared_player_remote_dir"
""",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result, query

    def test_row_snapshot_ignores_changed_stage_and_preserves_global_player_file(self):
        result, original = self.stage_workload_with_fake_ssh()
        self.assertEqual(result.returncode, 0, result.stderr)
        row = Path(result.stdout.strip())
        self.assertEqual((row / "querydb").read_bytes(), original)
        self.assertEqual(
            (self.work / "server-evidence/workload/querydb").read_bytes(), original
        )
        self.assertEqual(
            (self.work / "player/querydb").read_text(), "wrong.other.test. A\n"
        )
        manifest = json.loads((row / "manifest.json").read_text())
        self.assertEqual(manifest["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(manifest["query_count"], 1)
        self.assertEqual((row / "querydb").stat().st_mode & 0o777, 0o400)
        self.assertEqual(
            (self.work / "row/workload-manifest.json").read_bytes(),
            (row / "manifest.json").read_bytes(),
        )

    def test_corrupted_player_upload_fails_before_probe_or_load(self):
        result, _ = self.stage_workload_with_fake_ssh(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("player workload snapshot hash mismatch", result.stderr)

    def test_packet_baseline_refresh_handles_read_only_proc_copies(self):
        row = self.work / "readonly-row"
        row.mkdir()
        names = (
            "server-proc-net-dev-before.txt",
            "server-proc-net-snmp-before.txt",
            "server-proc-net-softnet-before.txt",
        )
        for name in names:
            path = row / name
            path.write_text("old baseline\n")
            path.chmod(0o444)
        for tool in ("tc", "ethtool"):
            path = self.bin / tool
            path.write_text("#!/bin/sh\necho fixture\n")
            path.chmod(0o700)
        result = subprocess.run(
            [
                "bash",
                "-c",
                r"""
set -euo pipefail
source "$1/scripts/physical-benchmark-workload.sh"
server_ssh=fixture
ssh_control() { shift; "$@"; }
refresh_server_packet_baseline "$2" testnic0
""",
                "fixture",
                str(ROOT),
                str(row),
            ],
            env=self.env,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in names:
            self.assertNotEqual((row / name).read_text(), "old baseline\n")


if __name__ == "__main__":
    unittest.main()
