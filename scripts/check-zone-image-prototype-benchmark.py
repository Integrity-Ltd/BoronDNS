#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


ZERO_MISMATCH_KEYS = (
    "mixed_validation_mismatches",
    "delegation_dname_stress_validation_mismatches",
    "mixed_packet_validation_mismatches",
    "hot_packet_validation_mismatches",
    "trace_packet_validation_mismatches",
    "optioned_packet_validation_mismatches",
    "boundary_packet_validation_mismatches",
    "udp_ceiling_packet_validation_mismatches",
    "ede_fallback_packet_validation_mismatches",
)

EQUAL_VALUE_PAIRS = (
    ("current_answer_count", "zone_image_answer_rrset_count"),
    ("current_hot_answer_count", "zone_image_hot_answer_rrset_count"),
    ("current_high_fanout_answer_count", "zone_image_high_fanout_answer_rrset_count"),
    ("current_mixed_record_count", "zone_image_mixed_wire_record_count"),
    ("current_mixed_packet_bytes", "zone_image_mixed_packet_bytes"),
    ("current_hot_packet_bytes", "zone_image_hot_packet_bytes"),
    ("current_trace_packet_bytes", "zone_image_trace_packet_bytes"),
    ("current_optioned_packet_bytes", "zone_image_optioned_packet_bytes"),
    ("current_delegation_dname_stress_record_count", "zone_image_delegation_dname_stress_plan_item_count"),
    ("current_delegation_dname_stress_record_count", "zone_image_delegation_dname_stress_wire_record_count"),
    ("current_mixed_rcode_checksum", "zone_image_mixed_plan_rcode_checksum"),
    ("current_mixed_rcode_checksum", "zone_image_mixed_wire_rcode_checksum"),
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_tsv(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"benchmark TSV not found: {path}")
    rows: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header != ["metric", "value"]:
            fail(f"{path}: expected header 'metric<TAB>value'")
        for line_number, line in enumerate(handle, start=2):
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 2:
                fail(f"{path}:{line_number}: expected two tab-separated fields")
            rows[fields[0]] = fields[1]
    return rows


def value(rows: dict[str, str], key: str) -> str:
    try:
        return rows[key]
    except KeyError:
        fail(f"benchmark TSV is missing required metric {key!r}")


def integer(rows: dict[str, str], key: str) -> int:
    raw = value(rows, key)
    try:
        return int(raw)
    except ValueError:
        fail(f"benchmark metric {key!r} is not an integer: {raw!r}")


def number(rows: dict[str, str], key: str) -> float:
    raw = value(rows, key)
    try:
        return float(raw)
    except ValueError:
        fail(f"benchmark metric {key!r} is not numeric: {raw!r}")


def ratio(rows: dict[str, str], current_key: str, zone_image_key: str) -> float:
    current = number(rows, current_key)
    if current <= 0:
        fail(f"current-path metric {current_key!r} must be positive")
    return number(rows, zone_image_key) / current


def check_ratio(
    rows: dict[str, str],
    failures: list[str],
    output: list[tuple[str, str]],
    name: str,
    current_key: str,
    zone_image_key: str,
    maximum: float,
) -> None:
    observed = ratio(rows, current_key, zone_image_key)
    output.append((f"{name}_ratio", f"{observed:.3f}"))
    output.append((f"{name}_max_ratio", f"{maximum:.3f}"))
    if observed > maximum:
        failures.append(
            f"{name} ratio {observed:.3f} exceeds maximum {maximum:.3f} "
            f"({zone_image_key}/{current_key})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate retained in-process ZoneImage prototype benchmark evidence."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("target/zone-image-bench/prototype-latest.tsv"),
        help="Benchmark TSV produced by scripts/benchmark-zone-image-prototype.sh",
    )
    parser.add_argument("--output", type=Path, help="Optional TSV check output path")
    parser.add_argument("--max-exact-ratio", type=float, default=0.75)
    parser.add_argument("--max-hot-exact-ratio", type=float, default=0.75)
    parser.add_argument("--max-high-fanout-exact-ratio", type=float, default=1.25)
    parser.add_argument("--max-mixed-plan-ratio", type=float, default=1.0)
    parser.add_argument("--max-mixed-wire-ratio", type=float, default=1.0)
    parser.add_argument("--max-mixed-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-hot-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-trace-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-optioned-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-stress-plan-ratio", type=float, default=0.10)
    parser.add_argument("--max-stress-wire-ratio", type=float, default=0.10)
    return parser.parse_args()


def emit(rows: list[tuple[str, str]], output: Path | None) -> None:
    text = "metric\tvalue\n" + "\n".join(f"{key}\t{value}" for key, value in rows) + "\n"
    if output is None:
        print(text, end="")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"zone_image_prototype_benchmark_check={output}")


def main() -> None:
    args = parse_args()
    rows = read_tsv(args.input)
    failures: list[str] = []
    output: list[tuple[str, str]] = [
        ("status", "pending"),
        ("input", args.input.as_posix()),
        ("benchmark_schema_version", value(rows, "benchmark_schema_version")),
        ("benchmark_kind", value(rows, "benchmark_kind")),
        ("records", value(rows, "records")),
        ("iterations", value(rows, "iterations")),
        ("high_fanout_query_cases", value(rows, "high_fanout_query_cases")),
        ("delegation_dname_stress_candidates", value(rows, "delegation_dname_stress_candidates")),
    ]

    if value(rows, "benchmark_schema_version") != "1":
        failures.append("unsupported benchmark_schema_version")
    if value(rows, "benchmark_kind") != "in_process_zone_image_prototype":
        failures.append("unexpected benchmark_kind")

    for key in (
        "zone_image_max_child_fanout",
        "zone_image_max_rrsets_per_name",
        "zone_shape_rrsets_per_owner_names_bucket_1",
    ):
        observed = integer(rows, key)
        output.append((key, str(observed)))
        if observed <= 0:
            failures.append(f"{key}={observed}, expected a positive retained layout metric")
    high_fanout_gt_256 = integer(rows, "zone_shape_child_name_fanout_names_bucket_gt_256")
    output.append(("zone_shape_child_name_fanout_names_bucket_gt_256", str(high_fanout_gt_256)))
    if integer(rows, "records") > 256 and high_fanout_gt_256 <= 0:
        failures.append(
            "zone_shape_child_name_fanout_names_bucket_gt_256=0, expected high-fanout evidence"
        )

    for key in ZERO_MISMATCH_KEYS:
        observed = integer(rows, key)
        output.append((key, str(observed)))
        if observed != 0:
            failures.append(f"{key}={observed}, expected 0")

    for current_key, zone_image_key in EQUAL_VALUE_PAIRS:
        current = value(rows, current_key)
        zone_image = value(rows, zone_image_key)
        output.append((f"{zone_image_key}_matches_{current_key}", str(current == zone_image).lower()))
        if current != zone_image:
            failures.append(f"{zone_image_key}={zone_image}, expected {current_key}={current}")

    if "zone_directory_suffix_lookup_ns_per_query" in rows:
        for key in (
            "zone_directory_zones",
            "zone_directory_query_cases",
            "zone_directory_linear_found_count",
            "zone_directory_suffix_found_count",
            "zone_directory_linear_label_checksum",
            "zone_directory_suffix_label_checksum",
        ):
            output.append((key, value(rows, key)))
        for linear_key, suffix_key in (
            ("zone_directory_linear_found_count", "zone_directory_suffix_found_count"),
            ("zone_directory_linear_label_checksum", "zone_directory_suffix_label_checksum"),
        ):
            linear = value(rows, linear_key)
            suffix = value(rows, suffix_key)
            output.append((f"{suffix_key}_matches_{linear_key}", str(linear == suffix).lower()))
            if linear != suffix:
                failures.append(f"{suffix_key}={suffix}, expected {linear_key}={linear}")
        directory_ratio = ratio(
            rows,
            "zone_directory_linear_lookup_ns_per_query",
            "zone_directory_suffix_lookup_ns_per_query",
        )
        output.append(("zone_directory_suffix_lookup_ratio", f"{directory_ratio:.3f}"))

    check_ratio(
        rows,
        failures,
        output,
        "exact_lookup",
        "current_lookup_ns_per_query",
        "zone_image_exact_lookup_ns_per_query",
        args.max_exact_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "hot_exact_lookup",
        "current_hot_lookup_ns_per_query",
        "zone_image_hot_exact_lookup_ns_per_query",
        args.max_hot_exact_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "high_fanout_exact_lookup",
        "current_high_fanout_lookup_ns_per_query",
        "zone_image_high_fanout_exact_lookup_ns_per_query",
        args.max_high_fanout_exact_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "mixed_plan",
        "current_mixed_response_ns_per_query",
        "zone_image_mixed_plan_ns_per_query",
        args.max_mixed_plan_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "mixed_wire",
        "current_mixed_response_ns_per_query",
        "zone_image_mixed_wire_ns_per_query",
        args.max_mixed_wire_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "mixed_packet",
        "current_mixed_packet_ns_per_query",
        "zone_image_mixed_packet_ns_per_query",
        args.max_mixed_packet_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "hot_packet",
        "current_hot_packet_ns_per_query",
        "zone_image_hot_packet_ns_per_query",
        args.max_hot_packet_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "trace_packet",
        "current_trace_packet_ns_per_query",
        "zone_image_trace_packet_ns_per_query",
        args.max_trace_packet_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "optioned_packet",
        "current_optioned_packet_ns_per_query",
        "zone_image_optioned_packet_ns_per_query",
        args.max_optioned_packet_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "delegation_dname_stress_plan",
        "current_delegation_dname_stress_response_ns_per_query",
        "zone_image_delegation_dname_stress_plan_ns_per_query",
        args.max_stress_plan_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "delegation_dname_stress_wire",
        "current_delegation_dname_stress_response_ns_per_query",
        "zone_image_delegation_dname_stress_wire_ns_per_query",
        args.max_stress_wire_ratio,
    )

    output[0] = ("status", "failed" if failures else "passed")
    output.extend((f"failure_{index}", failure) for index, failure in enumerate(failures, start=1))
    emit(output, args.output)

    if failures:
        for failure in failures:
            print(f"prototype benchmark check failure: {failure}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
