#!/usr/bin/env python3
"""Regression tests for retained performance evidence on policy failure."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ANALYZER = REPO_ROOT / "scripts" / "analyze-boron-gen-query-performance.py"
LABEL = "qps-000000060000-repetition-001"


def write_snapshot(
    directory: pathlib.Path,
    suffix: str,
    *,
    rx_packets: int,
    tx_packets: int,
    udp_in: int,
    udp_errors: int,
    udp_rcvbuf_errors: int,
    softnet_processed: int,
) -> None:
    (directory / f"proc-net-dev-{LABEL}-{suffix}.txt").write_text(
        "Inter-| Receive | Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|"
        "bytes packets errs drop fifo colls carrier compressed\n"
        f"eth0: {rx_packets * 100} {rx_packets} 0 0 0 0 0 0 "
        f"{tx_packets * 200} {tx_packets} 0 0 0 0 0 0\n",
        encoding="utf-8",
    )
    (directory / f"proc-stat-{LABEL}-{suffix}.txt").write_text(
        f"cpu {softnet_processed} 0 0 {softnet_processed} 0 0 0 0 0 0\n",
        encoding="utf-8",
    )
    (directory / f"proc-net-snmp-{LABEL}-{suffix}.txt").write_text(
        "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors "
        "SndbufErrors InCsumErrors IgnoredMulti MemErrors\n"
        f"Udp: {udp_in} 0 {udp_errors} {tx_packets} "
        f"{udp_rcvbuf_errors} 0 0 0 0\n",
        encoding="utf-8",
    )
    (directory / f"proc-net-softnet-stat-{LABEL}-{suffix}.txt").write_text(
        f"{softnet_processed:08x} 00000000 00000000 00000000\n",
        encoding="utf-8",
    )


def make_fixture(root: pathlib.Path) -> None:
    server = root / "network" / "server"
    client = root / "network" / "client"
    server.mkdir(parents=True)
    client.mkdir(parents=True)
    (root / f"{LABEL}.log").write_text(
        "dns_load_client_summary sent=100 received=80 errors=0 dropped=20 "
        "responses_per_second=80 latency_us_p50=10 latency_us_p90=20 "
        "latency_us_p99=30 latency_us_p999=40\n",
        encoding="utf-8",
    )
    write_snapshot(
        server,
        "before",
        rx_packets=1000,
        tx_packets=1000,
        udp_in=1000,
        udp_errors=10,
        udp_rcvbuf_errors=10,
        softnet_processed=1000,
    )
    write_snapshot(
        server,
        "after",
        rx_packets=1100,
        tx_packets=1080,
        udp_in=1080,
        udp_errors=30,
        udp_rcvbuf_errors=30,
        softnet_processed=1200,
    )
    write_snapshot(
        client,
        "before",
        rx_packets=2000,
        tx_packets=2000,
        udp_in=2000,
        udp_errors=0,
        udp_rcvbuf_errors=0,
        softnet_processed=2000,
    )
    write_snapshot(
        client,
        "after",
        rx_packets=2080,
        tx_packets=2100,
        udp_in=2080,
        udp_errors=0,
        udp_rcvbuf_errors=0,
        softnet_processed=2200,
    )


def run_analyzer(root: pathlib.Path, max_drop_permille: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(ANALYZER),
            str(root),
            "1",
            "60000",
            "eth0",
            "eth0",
            "ssh",
            str(max_drop_permille),
        ],
        check=False,
        text=True,
        capture_output=True,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="borondns-performance-analyzer.") as temporary:
        root = pathlib.Path(temporary)
        make_fixture(root)

        failed = run_analyzer(root, 100)
        assert failed.returncode == 1, failed
        assert "dropped 20/100 exceeds 100/1000" in failed.stderr
        summary = json.loads((root / "performance-summary.json").read_text())
        acceptance = json.loads((root / "performance-acceptance.json").read_text())
        assert summary["acceptance"]["passed"] is False
        assert acceptance["failures"][0]["kind"] == "drop_limit"
        assert summary["repetitions"][0]["server_udp_in_errors"] == 20
        assert summary["repetitions"][0]["server_udp_rcvbuf_errors"] == 20
        assert (root / "performance-results.tsv").stat().st_size > 0

        passed = run_analyzer(root, 250)
        assert passed.returncode == 0, passed
        summary = json.loads((root / "performance-summary.json").read_text())
        acceptance = json.loads((root / "performance-acceptance.json").read_text())
        assert summary["acceptance"]["passed"] is True
        assert acceptance["failures"] == []

    print("BoronGen query performance analyzer tests passed")


if __name__ == "__main__":
    main()
