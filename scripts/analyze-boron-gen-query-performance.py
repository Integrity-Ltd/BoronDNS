#!/usr/bin/env python3
"""Summarize BoronGen query-performance evidence before enforcing policy."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import statistics
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("repetitions", type=int)
    parser.add_argument("target_qps_steps")
    parser.add_argument("server_device")
    parser.add_argument("client_device")
    parser.add_argument("mode", choices=("local", "ssh"))
    parser.add_argument("max_drop_permille", type=int)
    return parser.parse_args()


def load_client_summary(path: pathlib.Path) -> dict[str, str]:
    line = path.read_text(encoding="utf-8").strip().splitlines()[-1]
    fields = {}
    for token in line.split():
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    if not line.split() or line.split()[0] != "dns_load_client_summary":
        raise SystemExit(f"{path}: missing dns_load_client_summary")
    return fields


def net_values(path: pathlib.Path, device: str) -> dict[str, int]:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if ":" not in raw:
            continue
        name, values = raw.split(":", 1)
        if name.strip() != device:
            continue
        fields = [int(value) for value in values.split()]
        return {
            "rx_bytes": fields[0],
            "rx_packets": fields[1],
            "rx_errors": fields[2],
            "rx_drops": fields[3],
            "tx_bytes": fields[8],
            "tx_packets": fields[9],
            "tx_errors": fields[10],
            "tx_drops": fields[11],
        }
    raise SystemExit(f"{path}: device {device!r} missing from /proc/net/dev")


def cpu_values(path: pathlib.Path) -> tuple[int, int]:
    first = path.read_text(encoding="utf-8").splitlines()[0].split()
    if not first or first[0] != "cpu":
        raise SystemExit(f"{path}: aggregate CPU row missing")
    values = [int(value) for value in first[1:]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def cpu_percent(before_path: pathlib.Path, after_path: pathlib.Path) -> float:
    before_total, before_idle = cpu_values(before_path)
    after_total, after_idle = cpu_values(after_path)
    total = after_total - before_total
    idle = after_idle - before_idle
    if total <= 0:
        return math.nan
    return 100.0 * (total - idle) / total


def snmp_udp_values(path: pathlib.Path) -> dict[str, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, header in enumerate(lines[:-1]):
        values = lines[index + 1]
        if not header.startswith("Udp:") or not values.startswith("Udp:"):
            continue
        names = header.split()[1:]
        numbers = [int(value) for value in values.split()[1:]]
        if len(names) != len(numbers):
            raise SystemExit(f"{path}: malformed /proc/net/snmp UDP rows")
        parsed = dict(zip(names, numbers, strict=True))
        return {
            "in_datagrams": parsed.get("InDatagrams", 0),
            "in_errors": parsed.get("InErrors", 0),
            "rcvbuf_errors": parsed.get("RcvbufErrors", 0),
            "sndbuf_errors": parsed.get("SndbufErrors", 0),
            "mem_errors": parsed.get("MemErrors", 0),
        }
    raise SystemExit(f"{path}: UDP rows missing from /proc/net/snmp")


def softnet_values(path: pathlib.Path) -> dict[str, int]:
    processed = 0
    dropped = 0
    time_squeeze = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        fields = raw.split()
        if len(fields) < 3:
            raise SystemExit(f"{path}: malformed /proc/net/softnet_stat row")
        processed += int(fields[0], 16)
        dropped += int(fields[1], 16)
        time_squeeze += int(fields[2], 16)
    return {
        "processed": processed,
        "dropped": dropped,
        "time_squeeze": time_squeeze,
    }


def delta(before: dict[str, int], after: dict[str, int], key: str) -> int:
    return after[key] - before[key]


def main() -> int:
    args = parse_args()
    target_qps_steps = [int(value) for value in args.target_qps_steps.split(",")]
    rows: list[dict[str, int | float | str]] = []
    failures: list[dict[str, int | str]] = []

    for target_qps in target_qps_steps:
        step_label = "unlimited" if target_qps == 0 else f"qps-{target_qps:012d}"
        for repetition in range(1, args.repetitions + 1):
            label = f"{step_label}-repetition-{repetition:03d}"
            fields = load_client_summary(args.root / f"{label}.log")
            sent = int(fields["sent"])
            received = int(fields["received"])
            errors = int(fields["errors"])
            dropped = int(fields["dropped"])
            if errors:
                failures.append(
                    {
                        "label": label,
                        "kind": "client_errors",
                        "observed": errors,
                        "limit": 0,
                        "message": f"dns-load-client reported {errors} errors",
                    }
                )
            if sent <= 0:
                failures.append(
                    {
                        "label": label,
                        "kind": "no_packets_sent",
                        "observed": sent,
                        "limit": 0,
                        "message": "dns-load-client sent no packets",
                    }
                )
            elif dropped * 1000 > sent * args.max_drop_permille:
                failures.append(
                    {
                        "label": label,
                        "kind": "drop_limit",
                        "observed": dropped,
                        "sent": sent,
                        "limit_permille": args.max_drop_permille,
                        "message": (
                            f"dropped {dropped}/{sent} exceeds "
                            f"{args.max_drop_permille}/1000"
                        ),
                    }
                )

            server_dir = args.root / "network" / "server"
            client_dir = args.root / "network" / "client"
            server_before = net_values(
                server_dir / f"proc-net-dev-{label}-before.txt",
                args.server_device,
            )
            server_after = net_values(
                server_dir / f"proc-net-dev-{label}-after.txt",
                args.server_device,
            )
            client_before = net_values(
                client_dir / f"proc-net-dev-{label}-before.txt",
                args.client_device,
            )
            client_after = net_values(
                client_dir / f"proc-net-dev-{label}-after.txt",
                args.client_device,
            )
            server_udp_before = snmp_udp_values(
                server_dir / f"proc-net-snmp-{label}-before.txt"
            )
            server_udp_after = snmp_udp_values(
                server_dir / f"proc-net-snmp-{label}-after.txt"
            )
            client_udp_before = snmp_udp_values(
                client_dir / f"proc-net-snmp-{label}-before.txt"
            )
            client_udp_after = snmp_udp_values(
                client_dir / f"proc-net-snmp-{label}-after.txt"
            )
            server_softnet_before = softnet_values(
                server_dir / f"proc-net-softnet-stat-{label}-before.txt"
            )
            server_softnet_after = softnet_values(
                server_dir / f"proc-net-softnet-stat-{label}-after.txt"
            )
            client_softnet_before = softnet_values(
                client_dir / f"proc-net-softnet-stat-{label}-before.txt"
            )
            client_softnet_after = softnet_values(
                client_dir / f"proc-net-softnet-stat-{label}-after.txt"
            )
            server_rx_packets = delta(server_before, server_after, "rx_packets")
            server_tx_packets = delta(server_before, server_after, "tx_packets")
            client_rx_packets = delta(client_before, client_after, "rx_packets")
            client_tx_packets = delta(client_before, client_after, "tx_packets")
            if args.mode == "ssh" and min(
                server_rx_packets,
                server_tx_packets,
                client_rx_packets,
                client_tx_packets,
            ) <= 0:
                failures.append(
                    {
                        "label": label,
                        "kind": "missing_physical_nic_traffic",
                        "observed": min(
                            server_rx_packets,
                            server_tx_packets,
                            client_rx_packets,
                            client_tx_packets,
                        ),
                        "limit": 0,
                        "message": "physical NIC packet deltas are not positive",
                    }
                )
            error_keys = ("rx_errors", "rx_drops", "tx_errors", "tx_drops")
            for role, before, after in (
                ("server", server_before, server_after),
                ("client", client_before, client_after),
            ):
                for key in error_keys:
                    observed = delta(before, after, key)
                    if observed:
                        failures.append(
                            {
                                "label": label,
                                "kind": f"{role}_nic_{key}",
                                "observed": observed,
                                "limit": 0,
                                "message": f"{role} NIC {key} increased by {observed}",
                            }
                        )

            rows.append(
                {
                    "target_qps": target_qps or "unlimited",
                    "repetition": repetition,
                    "sent": sent,
                    "received": received,
                    "errors": errors,
                    "dropped": dropped,
                    "responses_per_second": float(fields["responses_per_second"]),
                    "latency_us_p50": float(fields["latency_us_p50"]),
                    "latency_us_p90": float(fields["latency_us_p90"]),
                    "latency_us_p99": float(fields["latency_us_p99"]),
                    "latency_us_p999": float(fields["latency_us_p999"]),
                    "server_rx_bytes": delta(server_before, server_after, "rx_bytes"),
                    "server_tx_bytes": delta(server_before, server_after, "tx_bytes"),
                    "server_rx_packets": server_rx_packets,
                    "server_tx_packets": server_tx_packets,
                    "client_rx_bytes": delta(client_before, client_after, "rx_bytes"),
                    "client_tx_bytes": delta(client_before, client_after, "tx_bytes"),
                    "client_rx_packets": client_rx_packets,
                    "client_tx_packets": client_tx_packets,
                    "server_udp_in_datagrams": delta(
                        server_udp_before, server_udp_after, "in_datagrams"
                    ),
                    "server_udp_in_errors": delta(
                        server_udp_before, server_udp_after, "in_errors"
                    ),
                    "server_udp_rcvbuf_errors": delta(
                        server_udp_before, server_udp_after, "rcvbuf_errors"
                    ),
                    "server_udp_sndbuf_errors": delta(
                        server_udp_before, server_udp_after, "sndbuf_errors"
                    ),
                    "server_udp_mem_errors": delta(
                        server_udp_before, server_udp_after, "mem_errors"
                    ),
                    "client_udp_in_datagrams": delta(
                        client_udp_before, client_udp_after, "in_datagrams"
                    ),
                    "client_udp_in_errors": delta(
                        client_udp_before, client_udp_after, "in_errors"
                    ),
                    "client_udp_rcvbuf_errors": delta(
                        client_udp_before, client_udp_after, "rcvbuf_errors"
                    ),
                    "client_udp_sndbuf_errors": delta(
                        client_udp_before, client_udp_after, "sndbuf_errors"
                    ),
                    "client_udp_mem_errors": delta(
                        client_udp_before, client_udp_after, "mem_errors"
                    ),
                    "server_softnet_dropped": delta(
                        server_softnet_before, server_softnet_after, "dropped"
                    ),
                    "server_softnet_time_squeeze": delta(
                        server_softnet_before, server_softnet_after, "time_squeeze"
                    ),
                    "client_softnet_dropped": delta(
                        client_softnet_before, client_softnet_after, "dropped"
                    ),
                    "client_softnet_time_squeeze": delta(
                        client_softnet_before, client_softnet_after, "time_squeeze"
                    ),
                    "server_cpu_percent": cpu_percent(
                        server_dir / f"proc-stat-{label}-before.txt",
                        server_dir / f"proc-stat-{label}-after.txt",
                    ),
                    "client_cpu_percent": cpu_percent(
                        client_dir / f"proc-stat-{label}-before.txt",
                        client_dir / f"proc-stat-{label}-after.txt",
                    ),
                }
            )

    columns = list(rows[0])
    with (args.root / "performance-results.tsv").open("w", encoding="utf-8") as output:
        output.write("\t".join(columns) + "\n")
        for row in rows:
            output.write("\t".join(str(row[column]) for column in columns) + "\n")

    aggregate_keys = (
        "responses_per_second",
        "latency_us_p50",
        "latency_us_p90",
        "latency_us_p99",
        "latency_us_p999",
        "server_cpu_percent",
        "client_cpu_percent",
        "server_udp_in_errors",
        "server_udp_rcvbuf_errors",
        "server_udp_mem_errors",
        "server_softnet_dropped",
        "server_softnet_time_squeeze",
    )
    steps = []
    for target_qps in target_qps_steps:
        step_rows = [
            row
            for row in rows
            if row["target_qps"] == (target_qps or "unlimited")
        ]
        aggregate = {
            f"median_{key}": statistics.median(row[key] for row in step_rows)
            for key in aggregate_keys
        }
        steps.append(
            {
                "target_qps": target_qps or None,
                "repetitions": step_rows,
                "aggregate": aggregate,
            }
        )
    acceptance = {
        "passed": not failures,
        "max_drop_permille": args.max_drop_permille,
        "failures": failures,
    }
    report = {
        "format": "boron-gen-query-performance-v1",
        "mode": args.mode,
        "server_device": args.server_device,
        "client_device": args.client_device,
        "acceptance": acceptance,
        # Keep the top step in these legacy fields so existing campaign readers
        # retain their original meaning while paced runs expose every step.
        "repetitions": steps[-1]["repetitions"],
        "aggregate": steps[-1]["aggregate"],
        "steps": steps,
    }
    with (args.root / "performance-summary.json").open(
        "w", encoding="utf-8"
    ) as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    with (args.root / "performance-acceptance.json").open(
        "w", encoding="utf-8"
    ) as output:
        json.dump(
            {
                "format": "boron-gen-query-performance-acceptance-v1",
                **acceptance,
            },
            output,
            indent=2,
            sort_keys=True,
        )
        output.write("\n")

    if failures:
        for failure in failures:
            print(
                f"{failure['label']}: {failure['message']}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
