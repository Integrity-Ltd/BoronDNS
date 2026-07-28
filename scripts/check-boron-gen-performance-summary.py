#!/usr/bin/env python3
"""Regression test for registry size/performance normalization."""

from __future__ import annotations

import csv
import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize-boron-gen-performance.py")
SPEC = importlib.util.spec_from_file_location("boron_gen_summary", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot import {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        plan = root / "plan.tsv"
        results = root / "results.tsv"
        output = root / "curve.tsv"
        plan.write_text(
            "id\tprofile\tzones\tnames_per_zone\trecords_per_name\t"
            "nsec3_per_zone\tprojected_peak_gib\tmemory_high\tmemory_max\t"
            "retained_records\n"
            "07-registry-balanced-1m\tregistry-nsec3\t1\t1000000\t4\t"
            "1000000\t12\t20G\t28G\t9100008\n"
            "08-registry-balanced-10m\tregistry-nsec3\t1\t10000000\t4\t"
            "10000000\t120\t144G\t168G\t91000008\n",
            encoding="utf-8",
        )
        results.write_text(
            "finished_utc\tscenario\tattempt\texit_status\tresult\t"
            "server_peak_bytes\tgenerator_peak_bytes\telapsed_seconds\t"
            "median_qps\tmedian_p99_us\tmedian_server_cpu_percent\t"
            "median_client_cpu_percent\n"
            "now\t07-registry-balanced-1m\tattempt-001\t0\tready_and_held\t"
            "100\t10\t1\t100000\t100\t10\t10\n"
            "now\t08-registry-balanced-10m\tattempt-001\t0\tready_and_held\t"
            "1000\t10\t1\t75000\t150\t10\t10\n",
            encoding="utf-8",
        )
        MODULE.summarize(plan, results, output)
        with output.open(encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source, delimiter="\t"))
        if len(rows) != 2:
            raise SystemExit("expected two normalized curve rows")
        if rows[0]["qps_ratio_to_smallest"] != "1.000000":
            raise SystemExit("smallest successful row was not selected as baseline")
        if rows[1]["qps_loss_percent"] != "25.000":
            raise SystemExit("QPS loss normalization is incorrect")
        if rows[1]["p99_ratio_to_smallest"] != "1.500000":
            raise SystemExit("p99 normalization is incorrect")
    print("BoronGen performance summary checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
