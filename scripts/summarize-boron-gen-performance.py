#!/usr/bin/env python3
"""Build the comparable registry-size performance curve for a campaign."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path


def number(value: str) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def summarize(plan_path: Path, results_path: Path, output_path: Path) -> None:
    with plan_path.open(encoding="utf-8", newline="") as source:
        plan = {row["id"]: row for row in csv.DictReader(source, delimiter="\t")}
    with results_path.open(encoding="utf-8", newline="") as source:
        results = list(csv.DictReader(source, delimiter="\t"))

    rows = []
    for result in results:
        scenario = result["scenario"]
        if "registry-balanced-" not in scenario:
            continue
        planned = plan.get(scenario)
        if planned is not None:
            rows.append((int(planned["names_per_zone"]), planned, result))
    rows.sort(key=lambda item: item[0])

    baseline_qps, baseline_p99 = next(
        (
            (number(result["median_qps"]), number(result["median_p99_us"]))
            for _, _, result in rows
            if result["exit_status"] == "0"
            and number(result["median_qps"]) is not None
        ),
        (None, None),
    )
    columns = (
        "scenario",
        "names_per_zone",
        "nsec3_per_zone",
        "retained_records",
        "result",
        "server_peak_bytes",
        "median_qps",
        "qps_ratio_to_smallest",
        "qps_loss_percent",
        "median_p99_us",
        "p99_ratio_to_smallest",
        "median_server_udp_rcvbuf_errors",
        "median_server_udp_mem_errors",
        "median_server_softnet_dropped",
    )
    with output_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns, delimiter="\t")
        writer.writeheader()
        for _, planned, result in rows:
            qps = number(result["median_qps"])
            p99 = number(result["median_p99_us"])
            qps_ratio = (
                None
                if qps is None or baseline_qps in (None, 0)
                else qps / baseline_qps
            )
            p99_ratio = (
                None
                if p99 is None or baseline_p99 in (None, 0)
                else p99 / baseline_p99
            )
            writer.writerow(
                {
                    "scenario": result["scenario"],
                    "names_per_zone": planned["names_per_zone"],
                    "nsec3_per_zone": planned["nsec3_per_zone"],
                    "retained_records": planned["retained_records"],
                    "result": result["result"],
                    "server_peak_bytes": result["server_peak_bytes"],
                    "median_qps": result["median_qps"],
                    "qps_ratio_to_smallest": (
                        "null" if qps_ratio is None else f"{qps_ratio:.6f}"
                    ),
                    "qps_loss_percent": (
                        "null"
                        if qps_ratio is None
                        else f"{(1 - qps_ratio) * 100:.3f}"
                    ),
                    "median_p99_us": result["median_p99_us"],
                    "p99_ratio_to_smallest": (
                        "null" if p99_ratio is None else f"{p99_ratio:.6f}"
                    ),
                    "median_server_udp_rcvbuf_errors": result.get(
                        "median_server_udp_rcvbuf_errors", "null"
                    ),
                    "median_server_udp_mem_errors": result.get(
                        "median_server_udp_mem_errors", "null"
                    ),
                    "median_server_softnet_dropped": result.get(
                        "median_server_softnet_dropped", "null"
                    ),
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    summarize(args.plan, args.results, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
