#!/usr/bin/env python3
"""Select oxide-gun source ports from a reduced AF_XDP calibration artifact."""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys


SERVER_PORT_METRIC = re.compile(
    r'^oxidedns_udp_worker_source_port_datagrams_total\{worker="(\d+)",source_port="(\d+)"\} (\d+)$'
)


def parse_server_workers(metrics_path: pathlib.Path) -> dict[int, int]:
    by_port: dict[int, list[tuple[int, int]]] = collections.defaultdict(list)
    for line in metrics_path.read_text(encoding="utf-8").splitlines():
        match = SERVER_PORT_METRIC.match(line)
        if match is None:
            continue
        worker, port, datagrams = (int(value) for value in match.groups())
        by_port[port].append((worker, datagrams))

    server_by_port: dict[int, int] = {}
    for port, rows in by_port.items():
        rows.sort(key=lambda row: row[1], reverse=True)
        server_by_port[port] = rows[0][0]
    return server_by_port


def parse_requester_queues(log_path: pathlib.Path) -> tuple[dict[int, int], int]:
    summary = None
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("record_type") == "summary":
            summary = record
            break
    if summary is None:
        raise ValueError(f"{log_path} does not contain an oxide-gun summary record")

    requester_by_port: dict[int, int] = {}
    for queue in summary.get("queue_stats", []):
        rx_queue = int(queue["rx_queue"])
        for record in queue.get("rx_destination_ports", []):
            requester_by_port[int(record["port"])] = rx_queue
    return requester_by_port, int(summary.get("queue_count", 0))


def summarize(
    label: str,
    ports: list[int],
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
) -> list[str]:
    server_counts = collections.Counter(server_by_port[port] for port in ports)
    requester_counts = collections.Counter(requester_by_port[port] for port in ports)
    server_max = max(server_counts.values(), default=0)
    requester_max = max(requester_counts.values(), default=0)
    return [
        (
            f"{label}: ports={len(ports)} "
            f"server_active={len(server_counts)} server_max={server_max} "
            f"requester_active={len(requester_counts)} requester_max={requester_max}"
        ),
        f"{label}_server_top={server_counts.most_common(12)}",
        f"{label}_requester_top={requester_counts.most_common(12)}",
    ]


def summarize_requester_only(
    label: str,
    ports: list[int],
    requester_by_port: dict[int, int],
) -> list[str]:
    requester_counts = collections.Counter(requester_by_port[port] for port in ports)
    requester_max = max(requester_counts.values(), default=0)
    return [
        (
            f"{label}: ports={len(ports)} "
            f"requester_active={len(requester_counts)} requester_max={requester_max}"
        ),
        f"{label}_requester_top={requester_counts.most_common(12)}",
    ]


def select_requester_only_ports(
    requester_by_port: dict[int, int],
    port_count: int,
) -> list[int]:
    by_requester: dict[int, list[int]] = collections.defaultdict(list)
    for port, queue in requester_by_port.items():
        by_requester[queue].append(port)
    if port_count > len(by_requester):
        raise ValueError(
            f"requested {port_count} ports but only {len(by_requester)} requester queues have candidates"
        )
    selected: list[int] = []
    for queue in sorted(by_requester)[:port_count]:
        selected.append(min(by_requester[queue]))
    return selected


def select_ports(
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    port_count: int,
) -> list[int]:
    ports = sorted(set(server_by_port) & set(requester_by_port))
    by_requester: dict[int, list[int]] = collections.defaultdict(list)
    for port in ports:
        by_requester[requester_by_port[port]].append(port)
    for choices in by_requester.values():
        choices.sort(key=lambda port: (server_by_port[port], port))

    if port_count > len(by_requester):
        raise ValueError(
            f"requested {port_count} ports but only {len(by_requester)} requester queues have candidates"
        )

    requester_queues = sorted(by_requester)
    orders: list[list[int]] = [
        requester_queues,
        list(reversed(requester_queues)),
        sorted(requester_queues, key=lambda queue: len(by_requester[queue])),
        sorted(requester_queues, key=lambda queue: -len(by_requester[queue])),
    ]
    for seed in range(256):
        orders.append(
            sorted(
                requester_queues,
                key=lambda queue, seed=seed: (
                    (queue * 1_103_515_245 + 12_345 + seed * 2_654_435_761) & 0xFFFF_FFFF
                ),
            )
        )

    best: tuple[tuple[int, int, int, int], list[int]] | None = None
    for order in orders:
        selected: list[int] = []
        used_ports: set[int] = set()
        server_load: collections.Counter[int] = collections.Counter()
        for queue in order[:port_count]:
            choices = [port for port in by_requester[queue] if port not in used_ports]
            if not choices:
                break
            port = min(
                choices,
                key=lambda candidate: (
                    server_load[server_by_port[candidate]] + 1,
                    server_by_port[candidate],
                    candidate,
                ),
            )
            selected.append(port)
            used_ports.add(port)
            server_load[server_by_port[port]] += 1
        if len(selected) != port_count:
            continue
        requester_load = collections.Counter(requester_by_port[port] for port in selected)
        score = (
            max(server_load.values(), default=0),
            -len(server_load),
            max(requester_load.values(), default=0),
            sum(port * port for port in selected),
        )
        if best is None or score < best[0]:
            best = (score, selected)

    if best is None:
        raise ValueError("could not select a complete source-port list")
    return best[1]


def parse_port_list(value: str) -> list[int]:
    if not value:
        return []
    return [int(part) for part in value.split(",") if part]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=pathlib.Path, help="Calibration row artifact directory")
    parser.add_argument("--port-count", type=int, default=None)
    parser.add_argument("--existing-list", default="")
    parser.add_argument(
        "--requester-only",
        action="store_true",
        help="Select one port per requester RX queue without server worker metrics",
    )
    args = parser.parse_args()

    metrics_path = args.artifact / "metrics-after.prom"
    log_path = args.artifact / "kxdpgun.log"
    requester_by_port, queue_count = parse_requester_queues(log_path)
    if args.requester_only:
        candidate_ports = sorted(requester_by_port)
        if not candidate_ports:
            raise ValueError("no requester calibration ports were present")
        port_count = args.port_count or queue_count
        selected = select_requester_only_ports(requester_by_port, port_count)
        print(
            f"candidates={len(candidate_ports)} range={candidate_ports[0]}-{candidate_ports[-1]} "
            f"requester_queues={queue_count}"
        )
        existing = parse_port_list(args.existing_list)
        if existing:
            for line in summarize_requester_only("existing", existing, requester_by_port):
                print(line)
        for line in summarize_requester_only("selected", selected, requester_by_port):
            print(line)
        print("source_port_list=" + ",".join(str(port) for port in selected))
        print(
            "mapping="
            + ",".join(
                f"rq{requester_by_port[port]}:{port}"
                for port in sorted(selected, key=lambda port: requester_by_port[port])
            )
        )
        return 0

    server_by_port = parse_server_workers(metrics_path)
    candidate_ports = sorted(set(server_by_port) & set(requester_by_port))
    if not candidate_ports:
        raise ValueError("no ports were present in both server and requester calibration data")

    port_count = args.port_count or queue_count
    selected = select_ports(server_by_port, requester_by_port, port_count)

    print(
        f"candidates={len(candidate_ports)} range={candidate_ports[0]}-{candidate_ports[-1]} "
        f"requester_queues={queue_count}"
    )
    existing = parse_port_list(args.existing_list)
    if existing:
        for line in summarize("existing", existing, server_by_port, requester_by_port):
            print(line)
    for line in summarize("selected", selected, server_by_port, requester_by_port):
        print(line)
    print("source_port_list=" + ",".join(str(port) for port in selected))
    print(
        "mapping="
        + ",".join(
            f"rq{requester_by_port[port]}:{port}->sw{server_by_port[port]}"
            for port in sorted(selected, key=lambda port: requester_by_port[port])
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
