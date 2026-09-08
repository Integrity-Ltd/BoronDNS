#!/usr/bin/env python3
"""Local, bounded regression tests; no real benchmark hosts are contacted."""

import importlib.util
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "workload", Path(__file__).with_name("physical-benchmark-workload.py")
)
WORKLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKLOAD)


class WorkloadTests(unittest.TestCase):
    def test_manifest_sampling_and_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "queries"
            path.write_text(
                "; comment\n\n"
                + "".join(f"host{i}.example. A # comment\n" for i in range(100))
            )
            manifest = WORKLOAD.make_manifest(path, "positive")
            self.assertEqual(manifest["query_count"], 100)
            self.assertEqual(len(manifest["samples"]), 32)
            self.assertEqual(manifest["samples"][0]["name"], "host0.example.")
            self.assertEqual(manifest["samples"][-1]["name"], "host99.example.")
            for bad in (
                "example. BADTYPE",
                "example. A IN",
                "x..test A",
                "example. TYPE65536",
            ):
                path.write_text(bad)
                with self.assertRaises(ValueError):
                    WORKLOAD.make_manifest(path, "positive")

    def test_refused_high_packet_rate_is_not_positive_qps(self):
        report = WORKLOAD.classify(
            "total replies: 42000000 (4,700,000 pps) (100.0 %)\n"
            "responded REFUSED: 42000000 (100.0 %)\n",
            "kxdpgun",
            "positive",
        )
        self.assertFalse(report["passed"])

    def test_rcode_counting_mixed_and_missing(self):
        log = "total replies: 100\nresponded NOERROR: 60\nresponded NXDOMAIN: 40\n"
        self.assertTrue(WORKLOAD.classify(log, "kxdpgun", "mixed")["passed"])
        self.assertFalse(WORKLOAD.classify(log, "kxdpgun", "positive")["passed"])
        self.assertFalse(
            WORKLOAD.classify("total replies: 100", "kxdpgun", "mixed")["passed"]
        )
        self.assertFalse(
            WORKLOAD.classify(log.replace("60", "59"), "kxdpgun", "mixed")["passed"]
        )
        self.assertFalse(
            WORKLOAD.classify(log + "responded NOERROR: 60\n", "kxdpgun", "mixed")[
                "passed"
            ]
        )
        self.assertFalse(
            WORKLOAD.classify(log + "total replies: 100\n", "kxdpgun", "mixed")[
                "passed"
            ]
        )

    def test_boron_gun_count_is_not_rcode_evidence(self):
        report = WORKLOAD.classify(
            json.dumps({"summary": True, "positive_total": 42}), "boron-gun", "positive"
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["validation"], "unverified")

    def test_packet_guards(self):
        query = {"name": "example.", "type": 1}
        question = WORKLOAD.encode_name(query["name"]) + struct.pack("!HH", 1, 1)
        valid = (
            struct.pack("!6H", 17, 0x8400, 1, 1, 0, 0)
            + question
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + b"\xc0\x00\x02\x01"
        )
        self.assertEqual(WORKLOAD.parse_response(valid, 17, query)["rcode"], "NOERROR")
        invalid = [
            valid[:-1],
            valid + b"x",
            valid[:12] + b"\xc0\x0c",
            valid[:2] + b"\x86\x00" + valid[4:],
        ]
        for packet in invalid:
            with self.assertRaises(ValueError):
                WORKLOAD.parse_response(packet, 17, query)
        with self.assertRaises(ValueError):
            WORKLOAD.parse_response(valid, 18, query)
        with self.assertRaises(ValueError):
            WORKLOAD.parse_response(valid, 17, {"name": "other.", "type": 1})

    def test_positive_requires_requested_type_at_reachable_owner(self):
        query = {"name": "example.", "type": 1}
        question = WORKLOAD.encode_name(query["name"]) + struct.pack("!HH", 1, 1)
        cname = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 5, 1, 60, 8)
            + WORKLOAD.encode_name("target.")
        )
        address = (
            WORKLOAD.encode_name("target.")
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + b"\xc0\x00\x02\x01"
        )

        def response(answers, count):
            return WORKLOAD.parse_response(
                struct.pack("!6H", 17, 0x8400, 1, count, 0, 0) + question + answers,
                17,
                query,
            )

        self.assertTrue(response(cname + address, 2)["has_requested_answer"])
        self.assertFalse(response(cname, 1)["has_requested_answer"])
        self.assertFalse(response(address, 1)["has_requested_answer"])
        self.assertFalse(response(b"", 0)["has_requested_answer"])

    def test_cli_failure_writes_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(WORKLOAD.__file__)),
                    "manifest",
                    str(Path(directory) / "absent"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(output.read_text())["passed"])

    def test_udp_positive_refused_and_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "queries"
            path.write_text("example. A\n")
            manifest = WORKLOAD.make_manifest(path, "positive")
            cases = (
                ("positive", 0x8400, 1, True),
                ("positive", 0x8405, 0, False),
                ("positive", 0x8400, 0, False),
                ("positive", 0x8000, 1, False),
                ("mixed", 0x8403, 0, True),
                ("mixed", 0x8400, 0, True),
                ("mixed", 0x8402, 0, False),
            )
            for policy, flags, answer_count, expected in cases:
                manifest = WORKLOAD.make_manifest(path, policy)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                    server.bind(("127.0.0.1", 0))
                    server.settimeout(2)

                    def reply(flags=flags, answer_count=answer_count):
                        packet, address = server.recvfrom(65535)
                        header = packet[:2] + struct.pack(
                            "!5H",
                            flags,
                            1,
                            answer_count,
                            0,
                            0,
                        )
                        answer = (
                            b""
                            if not answer_count
                            else b"\xc0\x0c"
                            + struct.pack("!HHIH", 1, 1, 60, 4)
                            + b"\xc0\x00\x02\x01"
                        )
                        server.sendto(header + packet[12:] + answer, address)

                    thread = threading.Thread(target=reply)
                    thread.start()
                    report = WORKLOAD.probe(
                        path,
                        manifest,
                        "127.0.0.1",
                        server.getsockname()[1],
                        "127.0.0.1",
                    )
                    thread.join(3)
                    self.assertEqual(report["passed"], expected)
            manifest["samples"][0]["name"] = "attacker.example."
            with self.assertRaises(ValueError):
                WORKLOAD.probe(path, manifest, "127.0.0.1", 9, "127.0.0.1")

    def test_total_time_budget_stops_network_and_reports_every_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "queries"
            path.write_text("".join(f"host{i}.example. A\n" for i in range(40)))
            manifest = WORKLOAD.make_manifest(path, "positive")
            with (
                patch.object(WORKLOAD.time, "monotonic", side_effect=[0] + [31] * 32),
                patch.object(WORKLOAD.socket, "socket") as connection,
            ):
                report = WORKLOAD.probe(path, manifest, "127.0.0.1", 9, "127.0.0.1")
                connection.assert_not_called()
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["observations"]), 32)
            self.assertTrue(
                all(
                    "budget exhausted" in row["error"] for row in report["observations"]
                )
            )
            path.write_text("changed.example. A\n")
            with self.assertRaises(ValueError):
                WORKLOAD.probe(path, manifest, "127.0.0.1", 9, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
