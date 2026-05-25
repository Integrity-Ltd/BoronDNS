#!/usr/bin/env python3
"""Compare performance smoke metrics against a rolling release history."""

from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path


LOWER_IS_BETTER = {
    "startup_ready_ms",
    "udp_latency_ms_min",
    "udp_latency_ms_median",
    "udp_latency_ms_p99",
    "udp_latency_ms_max",
}

HIGHER_IS_BETTER = {
    "axfr_ready_records_per_second",
    "udp_qps",
}


def read_env_metrics(path: Path) -> dict[str, float]:
    metrics: dict[str, float] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            metrics[key] = float(value)
        except ValueError:
            continue
    return metrics


def read_history(path: Path) -> dict[str, list[float]]:
    history: dict[str, list[float]] = {}
    if not path.exists():
        return history

    for index, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        columns = line.split()
        if index == 0 and "metric" in columns and "value" in columns:
            continue
        if len(columns) < 2:
            raise SystemExit(f"invalid history row: {raw_line}")
        metric = columns[-2]
        value_text = columns[-1]
        try:
            value = float(value_text)
        except ValueError as exc:
            raise SystemExit(f"invalid history value in row: {raw_line}") from exc
        history.setdefault(metric, []).append(value)
    return history


def degradation_percent(metric: str, baseline: float, candidate: float) -> float:
    if baseline == 0:
        return 0.0 if candidate == 0 else float("inf")
    if metric in LOWER_IS_BETTER:
        return ((candidate - baseline) / baseline) * 100.0
    if metric in HIGHER_IS_BETTER:
        return ((baseline - candidate) / baseline) * 100.0
    return 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--history", required=True, type=Path)
    parser.add_argument("--threshold-pct", type=float, default=10.0)
    args = parser.parse_args()

    candidate = read_env_metrics(args.candidate)
    history = read_history(args.history)
    comparable = sorted((LOWER_IS_BETTER | HIGHER_IS_BETTER) & candidate.keys())

    if not comparable:
        print("perf_regression_status=no_comparable_metrics")
        return 1

    failures: list[str] = []
    for metric in comparable:
        values = history.get(metric, [])[-5:]
        if not values:
            print(f"{metric}\tstatus=baseline_candidate\tcandidate={candidate[metric]:.6g}")
            continue
        baseline = statistics.median(values)
        degradation = degradation_percent(metric, baseline, candidate[metric])
        status = "ok" if degradation <= args.threshold_pct else "regression"
        print(
            f"{metric}\tstatus={status}\tbaseline_median={baseline:.6g}"
            f"\tcandidate={candidate[metric]:.6g}\tdegradation_pct={degradation:.3f}"
            f"\tthreshold_pct={args.threshold_pct:.3f}"
        )
        if status == "regression":
            failures.append(metric)

    if failures:
        print("perf_regression_status=failed metrics=" + ",".join(failures))
        return 1
    print("perf_regression_status=passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
