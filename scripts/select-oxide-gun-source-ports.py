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
    r'^borondns_udp_worker_source_port_datagrams_total\{worker="(\d+)",source_port="(\d+)"\} (\d+)$'
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


def parse_requester_weights(log_path: pathlib.Path) -> dict[int, int]:
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

    weights: dict[int, int] = {}
    for queue in summary.get("queue_stats", []):
        weights[int(queue["rx_queue"])] = int(queue.get("tx_packets_total", 0))
    if not weights:
        raise ValueError(f"{log_path} summary did not contain queue tx packet weights")
    return weights


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


def summarize_weighted(
    label: str,
    ports: list[int],
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
) -> list[str]:
    server_load: collections.Counter[int] = collections.Counter()
    for port in ports:
        queue = requester_by_port[port]
        server_load[server_by_port[port]] += requester_weights.get(queue, 1)
    weighted_values = list(server_load.values())
    weighted_max = max(weighted_values, default=0)
    weighted_min = min(weighted_values, default=0)
    return [
        (
            f"{label}_weighted: server_weight_active={len(server_load)} "
            f"server_weight_min={weighted_min} server_weight_max={weighted_max}"
        ),
        f"{label}_server_weight_top={server_load.most_common(12)}",
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


def select_weighted_ports(
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
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
    weighted_queues = sorted(
        requester_queues,
        key=lambda queue: (-requester_weights.get(queue, 1), queue),
    )
    orders: list[list[int]] = [weighted_queues]
    for seed in range(256):
        orders.append(
            sorted(
                requester_queues,
                key=lambda queue, seed=seed: (
                    -requester_weights.get(queue, 1),
                    (queue * 1_103_515_245 + 12_345 + seed * 2_654_435_761) & 0xFFFF_FFFF,
                ),
            )
        )

    best: tuple[tuple[int, int, int], dict[int, int]] | None = None
    for order in orders:
        selected_by_queue: dict[int, int] = {}
        server_load: collections.Counter[int] = collections.Counter()
        for queue in order[:port_count]:
            weight = requester_weights.get(queue, 1)
            port = min(
                by_requester[queue],
                key=lambda candidate: (
                    server_load[server_by_port[candidate]] + weight,
                    server_load[server_by_port[candidate]],
                    server_by_port[candidate],
                    candidate,
                ),
            )
            selected_by_queue[queue] = port
            server_load[server_by_port[port]] += weight
        if len(selected_by_queue) != port_count:
            continue
        score = weighted_score(selected_by_queue.values(), server_by_port, requester_by_port, requester_weights)
        if best is None or score < best[0]:
            best = (score, selected_by_queue)

    if best is None:
        raise ValueError("could not select a complete weighted source-port list")

    selected_by_queue = dict(best[1])
    best_score = best[0]
    improved = True
    while improved:
        improved = False
        selected_queues = sorted(
            selected_by_queue,
            key=lambda queue: -requester_weights.get(queue, 1),
        )
        for queue in selected_queues:
            current = selected_by_queue[queue]
            for port in by_requester[queue]:
                if port == current:
                    continue
                candidate = dict(selected_by_queue)
                candidate[queue] = port
                score = weighted_score(candidate.values(), server_by_port, requester_by_port, requester_weights)
                if score < best_score:
                    selected_by_queue = candidate
                    best_score = score
                    improved = True
                    break
            if improved:
                break

    return [selected_by_queue[queue] for queue in sorted(selected_by_queue)]


def repair_existing_ports(
    existing: list[int],
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
    max_replacements: int,
    repair_server_workers: set[int],
) -> list[int]:
    if not existing:
        raise ValueError("--repair-existing requires --existing-list")
    if max_replacements < 1:
        raise ValueError("--max-replacements must be at least 1")

    by_requester: dict[int, list[int]] = collections.defaultdict(list)
    for port in sorted(set(server_by_port) & set(requester_by_port)):
        by_requester[requester_by_port[port]].append(port)

    original_by_queue: dict[int, int] = {}
    for port in existing:
        if port not in server_by_port or port not in requester_by_port:
            raise ValueError(f"existing source port {port} is missing from calibration data")
        queue = requester_by_port[port]
        if queue in original_by_queue:
            raise ValueError(f"existing list contains more than one port for requester queue {queue}")
        original_by_queue[queue] = port

    selected_by_queue = dict(original_by_queue)
    best_weighted = weighted_score(
        selected_by_queue.values(), server_by_port, requester_by_port, requester_weights
    )
    replacements = 0
    while replacements < max_replacements:
        used_ports = set(selected_by_queue.values())
        best_candidate: tuple[
            tuple[int, ...],
            tuple[int, int, int],
            tuple[int, int, int, int],
            dict[int, int],
        ] | None = None
        for queue in sorted(selected_by_queue):
            current = selected_by_queue[queue]
            if repair_server_workers and server_by_port[current] not in repair_server_workers:
                continue
            original = original_by_queue[queue]
            for port in by_requester[queue]:
                if port == current or port in used_ports:
                    continue
                if repair_server_workers and server_by_port[port] == server_by_port[current]:
                    continue
                candidate = dict(selected_by_queue)
                candidate[queue] = port
                weighted = weighted_score(
                    candidate.values(), server_by_port, requester_by_port, requester_weights
                )
                target_load = repair_target_load(
                    candidate.values(),
                    server_by_port,
                    requester_by_port,
                    requester_weights,
                    repair_server_workers,
                )
                current_target_load = repair_target_load(
                    selected_by_queue.values(),
                    server_by_port,
                    requester_by_port,
                    requester_weights,
                    repair_server_workers,
                )
                if repair_server_workers:
                    if target_load >= current_target_load:
                        continue
                elif weighted >= best_weighted:
                    continue
                replacement_count = sum(
                    candidate[q] != original_by_queue[q] for q in candidate
                )
                delta_sum = sum(abs(candidate[q] - original_by_queue[q]) for q in candidate)
                tie_break = (
                    replacement_count,
                    delta_sum,
                    requester_weights.get(queue, 1),
                    port,
                )
                ranked = (target_load, weighted, tie_break, candidate)
                if best_candidate is None or ranked < best_candidate:
                    best_candidate = ranked

        if best_candidate is None:
            break
        _, best_weighted, _, selected_by_queue = best_candidate
        replacements += 1

    return [selected_by_queue[queue] for queue in sorted(selected_by_queue)]


def repair_target_load(
    ports: collections.abc.Iterable[int],
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
    repair_server_workers: set[int],
) -> tuple[int, ...]:
    if not repair_server_workers:
        return ()
    server_load: collections.Counter[int] = collections.Counter()
    for port in ports:
        queue = requester_by_port[port]
        server_load[server_by_port[port]] += requester_weights.get(queue, 1)
    return tuple(server_load[worker] for worker in sorted(repair_server_workers))


def weighted_score(
    ports: collections.abc.Iterable[int],
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
) -> tuple[int, int, int]:
    server_load: collections.Counter[int] = collections.Counter()
    for port in ports:
        queue = requester_by_port[port]
        server_load[server_by_port[port]] += requester_weights.get(queue, 1)
    values = list(server_load.values())
    max_load = max(values, default=0)
    min_load = min(values, default=0)
    return (max_load, max_load - min_load, sum(value * value for value in values))


def select_server_exact_ports(
    server_by_port: dict[int, int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int] | None,
    port_count: int,
) -> list[int]:
    ports = sorted(set(server_by_port) & set(requester_by_port))
    by_server: dict[int, list[int]] = collections.defaultdict(list)
    for port in ports:
        by_server[server_by_port[port]].append(port)
    for choices in by_server.values():
        choices.sort(key=lambda port: (requester_by_port[port], port))

    if port_count > len(by_server):
        raise ValueError(
            f"requested {port_count} ports but only {len(by_server)} server workers have candidates"
        )

    requester_weights = requester_weights or {}
    server_order = sorted(by_server, key=lambda worker: (len(by_server[worker]), worker))
    selected_by_server: dict[int, int] = {}
    requester_load: collections.Counter[int] = collections.Counter()
    requester_weight_load: collections.Counter[int] = collections.Counter()
    for server_worker in server_order[:port_count]:
        port = min(
            by_server[server_worker],
            key=lambda candidate: (
                requester_load[requester_by_port[candidate]] + 1,
                requester_weight_load[requester_by_port[candidate]]
                + requester_weights.get(requester_by_port[candidate], 1),
                requester_by_port[candidate],
                candidate,
            ),
        )
        selected_by_server[server_worker] = port
        requester_load[requester_by_port[port]] += 1
        requester_weight_load[requester_by_port[port]] += requester_weights.get(
            requester_by_port[port], 1
        )

    best_score = server_exact_score(
        selected_by_server.values(), requester_by_port, requester_weights
    )
    improved = True
    while improved:
        improved = False
        for server_worker in sorted(
            selected_by_server,
            key=lambda worker: len(by_server[worker]),
        ):
            current = selected_by_server[server_worker]
            for port in by_server[server_worker]:
                if port == current:
                    continue
                candidate = dict(selected_by_server)
                candidate[server_worker] = port
                score = server_exact_score(
                    candidate.values(), requester_by_port, requester_weights
                )
                if score < best_score:
                    selected_by_server = candidate
                    best_score = score
                    improved = True
                    break
            if improved:
                break

    return [selected_by_server[worker] for worker in sorted(selected_by_server)]


def server_exact_score(
    ports: collections.abc.Iterable[int],
    requester_by_port: dict[int, int],
    requester_weights: dict[int, int],
) -> tuple[int, int, int, int]:
    requester_load: collections.Counter[int] = collections.Counter()
    requester_weight_load: collections.Counter[int] = collections.Counter()
    selected = list(ports)
    for port in selected:
        queue = requester_by_port[port]
        requester_load[queue] += 1
        requester_weight_load[queue] += requester_weights.get(queue, 1)
    return (
        max(requester_load.values(), default=0),
        max(requester_weight_load.values(), default=0),
        sum(value * value for value in requester_weight_load.values()),
        sum(port * port for port in selected),
    )


def parse_port_list(value: str) -> list[int]:
    if not value:
        return []
    return [int(part) for part in value.split(",") if part]


def requester_ordered_ports(
    ports: collections.abc.Iterable[int],
    requester_by_port: dict[int, int],
) -> list[int]:
    return sorted(ports, key=lambda port: (requester_by_port[port], port))


def print_queue_and_port_lists(
    selected: list[int],
    requester_by_port: dict[int, int],
) -> None:
    ordered = requester_ordered_ports(selected, requester_by_port)
    print("queue_list=" + ",".join(str(requester_by_port[port]) for port in ordered))
    print("source_port_list=" + ",".join(str(port) for port in ordered))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=pathlib.Path, help="Calibration row artifact directory")
    parser.add_argument("--port-count", type=int, default=None)
    parser.add_argument("--existing-list", default="")
    parser.add_argument(
        "--requester-weight-log",
        type=pathlib.Path,
        help="High-rate oxide-gun log used to weight requester queues by tx_packets_total",
    )
    parser.add_argument(
        "--requester-only",
        action="store_true",
        help="Select one port per requester RX queue without server worker metrics",
    )
    parser.add_argument(
        "--server-exact",
        action="store_true",
        help="Select one port per server AF_XDP worker and emit the sparse requester queue list",
    )
    parser.add_argument(
        "--repair-existing",
        action="store_true",
        help="Preserve --existing-list order and make weighted substitutions that improve server balance",
    )
    parser.add_argument(
        "--max-replacements",
        type=int,
        default=1,
        help="Maximum substitutions allowed with --repair-existing",
    )
    parser.add_argument(
        "--repair-server-worker",
        action="append",
        type=int,
        default=[],
        help="With --repair-existing, move flows away from this calibrated server worker",
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
        print_queue_and_port_lists(selected, requester_by_port)
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
    requester_weights = (
        parse_requester_weights(args.requester_weight_log) if args.requester_weight_log else None
    )
    if args.repair_existing:
        existing = parse_port_list(args.existing_list)
        selected = repair_existing_ports(
            existing,
            server_by_port,
            requester_by_port,
            requester_weights or {},
            args.max_replacements,
            set(args.repair_server_worker),
        )
    elif args.server_exact:
        selected = select_server_exact_ports(
            server_by_port,
            requester_by_port,
            requester_weights,
            port_count,
        )
    elif requester_weights is None:
        selected = select_ports(server_by_port, requester_by_port, port_count)
    else:
        selected = select_weighted_ports(
            server_by_port,
            requester_by_port,
            requester_weights,
            port_count,
        )

    print(
        f"candidates={len(candidate_ports)} range={candidate_ports[0]}-{candidate_ports[-1]} "
        f"requester_queues={queue_count}"
    )
    existing = parse_port_list(args.existing_list)
    if existing:
        for line in summarize("existing", existing, server_by_port, requester_by_port):
            print(line)
        if requester_weights is not None:
            for line in summarize_weighted(
                "existing", existing, server_by_port, requester_by_port, requester_weights
            ):
                print(line)
    for line in summarize("selected", selected, server_by_port, requester_by_port):
        print(line)
    if requester_weights is not None:
        for line in summarize_weighted(
            "selected", selected, server_by_port, requester_by_port, requester_weights
        ):
            print(line)
    print_queue_and_port_lists(selected, requester_by_port)
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
