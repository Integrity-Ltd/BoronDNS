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
    ("current_boundary_packet_bytes", "zone_image_boundary_packet_bytes"),
    ("current_udp_ceiling_packet_bytes", "zone_image_udp_ceiling_packet_bytes"),
    ("current_delegation_dname_stress_record_count", "zone_image_delegation_dname_stress_plan_item_count"),
    ("current_delegation_dname_stress_record_count", "zone_image_delegation_dname_stress_wire_record_count"),
    ("current_mixed_rcode_checksum", "zone_image_mixed_plan_rcode_checksum"),
    ("current_mixed_rcode_checksum", "zone_image_mixed_wire_rcode_checksum"),
)

REQUIRED_QUERY_MIXES = {
    "query_mix_mixed": {
        "positive_a",
        "cname",
        "wildcard",
        "referral_glue",
        "nodata",
        "nxdomain",
        "dname",
        "opaque_unknown",
    },
    "query_mix_optioned": {"edns_nsid", "dns_cookie", "edns_padding"},
    "query_mix_boundary": {
        "qtype_any_full",
        "dnssec_positive_do",
        "dnssec_nodata_do",
        "response_build_truncation",
    },
    "query_mix_udp_ceiling": {
        "no_edns_512",
        "edns_payload_512",
        "edns_payload_1232",
        "edns_payload_4096",
    },
    "query_mix_notify_soa_validation": {"exact_owner", "mixed_case_owner"},
    "query_mix_chaos_classification": {"exact_qname", "mixed_case_qname"},
}

REQUIRED_POSITIVE_CASE_COUNTS = (
    "mixed_query_cases",
    "trace_packet_query_cases",
    "optioned_packet_cases",
    "boundary_packet_cases",
    "udp_ceiling_packet_cases",
    "notify_soa_validation_cases",
    "chaos_classification_cases",
    "ede_fallback_packet_cases",
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


def check_memory_ratio(
    rows: dict[str, str],
    failures: list[str],
    output: list[tuple[str, str]],
    name: str,
    bytes_key: str,
    records_key: str,
    maximum: float,
) -> None:
    records = integer(rows, records_key)
    if records <= 0:
        failures.append(f"{records_key}={records}, expected positive record count")
        return
    observed = number(rows, bytes_key) / records
    output.append((name, f"{observed:.3f}"))
    output.append((f"{name}_max", f"{maximum:.3f}"))
    if observed > maximum:
        failures.append(
            f"{name} {observed:.3f} exceeds maximum {maximum:.3f} "
            f"({bytes_key}/{records_key})"
        )


def check_memory_value(
    rows: dict[str, str],
    failures: list[str],
    output: list[tuple[str, str]],
    key: str,
    maximum: float,
) -> None:
    observed = number(rows, key)
    output.append((key, f"{observed:.3f}"))
    output.append((f"{key}_max", f"{maximum:.3f}"))
    if observed > maximum:
        failures.append(f"{key} {observed:.3f} exceeds maximum {maximum:.3f}")


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
    parser.add_argument("--max-absent-low-exact-ratio", type=float, default=1.10)
    parser.add_argument("--max-absent-present-low-any-exact-ratio", type=float, default=1.10)
    parser.add_argument("--max-absent-low-direct-preflight-ratio", type=float, default=0.75)
    parser.add_argument(
        "--max-absent-present-low-direct-preflight-ratio",
        type=float,
        default=1.10,
    )
    parser.add_argument("--max-absent-low-response-plan-ratio", type=float, default=1.10)
    parser.add_argument("--max-cname-free-absent-low-response-plan-ratio", type=float, default=1.10)
    parser.add_argument(
        "--max-indirection-free-absent-low-response-plan-ratio",
        type=float,
        default=1.10,
    )
    parser.add_argument("--max-mixed-plan-ratio", type=float, default=1.0)
    parser.add_argument("--max-mixed-wire-ratio", type=float, default=1.0)
    parser.add_argument("--max-mixed-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-hot-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-trace-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-optioned-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-boundary-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-udp-ceiling-packet-ratio", type=float, default=1.25)
    parser.add_argument("--max-notify-soa-mixed-case-ratio", type=float, default=1.50)
    parser.add_argument("--max-chaos-mixed-case-ratio", type=float, default=1.50)
    parser.add_argument("--max-control-metadata-ratio", type=float, default=1.25)
    parser.add_argument("--max-zone-metadata-cached-key-ratio", type=float, default=1.0)
    parser.add_argument("--max-stress-plan-ratio", type=float, default=0.10)
    parser.add_argument("--max-stress-wire-ratio", type=float, default=0.10)
    parser.add_argument("--max-zone-image-hot-bytes-per-record", type=float, default=160.0)
    parser.add_argument("--max-zone-image-bytes-per-record", type=float, default=256.0)
    parser.add_argument("--max-stress-hot-bytes-per-record", type=float, default=160.0)
    parser.add_argument("--max-stress-bytes-per-record", type=float, default=256.0)
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

    for key, expected_values in REQUIRED_QUERY_MIXES.items():
        observed_values = set(value(rows, key).split(","))
        missing_values = sorted(expected_values - observed_values)
        unexpected_values = sorted(observed_values - expected_values)
        output.append((f"{key}_coverage", ",".join(sorted(observed_values))))
        if missing_values:
            failures.append(f"{key} missing required cases: {','.join(missing_values)}")
        if unexpected_values:
            failures.append(f"{key} has unexpected cases: {','.join(unexpected_values)}")

    for key in REQUIRED_POSITIVE_CASE_COUNTS:
        observed = integer(rows, key)
        output.append((key, str(observed)))
        if observed <= 0:
            failures.append(f"{key}={observed}, expected positive packet coverage")

    for key in (
        "zone_image_child_hashes",
        "zone_image_child_hash_slots",
        "zone_image_child_hash_slot_bytes",
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
    if integer(rows, "zone_image_child_hashes") <= 0:
        failures.append("zone_image_child_hashes=0, expected retained generated child-hash evidence")
    child_hash_slots = integer(rows, "zone_image_child_hash_slots")
    child_hash_slot_bytes = integer(rows, "zone_image_child_hash_slot_bytes")
    output.append(
        (
            "zone_image_child_hash_slot_bytes_match_u16_slots",
            str(child_hash_slot_bytes == child_hash_slots * 2).lower(),
        )
    )
    if child_hash_slot_bytes != child_hash_slots * 2:
        failures.append(
            "zone_image_child_hash_slot_bytes does not match u16 slot storage"
        )
    stress_child_hash_slots = integer(rows, "zone_image_delegation_dname_stress_child_hash_slots")
    stress_child_hash_slot_bytes = integer(
        rows, "zone_image_delegation_dname_stress_child_hash_slot_bytes"
    )
    for key in (
        "zone_image_delegation_dname_stress_child_hashes",
        "zone_image_delegation_dname_stress_child_hash_slots",
        "zone_image_delegation_dname_stress_child_hash_slot_bytes",
    ):
        output.append((key, value(rows, key)))
    output.append(
        (
            "zone_image_delegation_dname_stress_child_hash_slot_bytes_match_u16_slots",
            str(stress_child_hash_slot_bytes == stress_child_hash_slots * 2).lower(),
        )
    )
    if stress_child_hash_slot_bytes != stress_child_hash_slots * 2:
        failures.append(
            "zone_image_delegation_dname_stress_child_hash_slot_bytes does not match "
            "u16 slot storage"
        )

    check_memory_ratio(
        rows,
        failures,
        output,
        "zone_image_hot_bytes_per_record",
        "zone_image_hot_bytes",
        "zone_image_records",
        args.max_zone_image_hot_bytes_per_record,
    )
    check_memory_value(
        rows,
        failures,
        output,
        "zone_image_bytes_per_record",
        args.max_zone_image_bytes_per_record,
    )
    check_memory_ratio(
        rows,
        failures,
        output,
        "zone_image_delegation_dname_stress_hot_bytes_per_record",
        "zone_image_delegation_dname_stress_hot_bytes",
        "zone_image_delegation_dname_stress_records",
        args.max_stress_hot_bytes_per_record,
    )
    check_memory_value(
        rows,
        failures,
        output,
        "zone_image_delegation_dname_stress_bytes_per_record",
        args.max_stress_bytes_per_record,
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
        if "zone_directory_cached_active_count_ns_per_query" in rows:
            for key in (
                "zone_directory_linear_active_count_checksum",
                "zone_directory_cached_active_count_checksum",
            ):
                output.append((key, value(rows, key)))
            linear = value(rows, "zone_directory_linear_active_count_checksum")
            cached = value(rows, "zone_directory_cached_active_count_checksum")
            output.append(
                (
                    "zone_directory_cached_active_count_checksum_matches_linear",
                    str(cached == linear).lower(),
                )
            )
            if cached != linear:
                failures.append(
                    "zone_directory_cached_active_count_checksum="
                    f"{cached}, expected linear checksum {linear}"
                )
            active_count_ratio = ratio(
                rows,
                "zone_directory_linear_active_count_ns_per_query",
                "zone_directory_cached_active_count_ns_per_query",
            )
            output.append(
                ("zone_directory_cached_active_count_ratio", f"{active_count_ratio:.3f}")
            )
        if "zone_directory_control_metadata_ns_per_query" in rows:
            for key in (
                "zone_directory_full_metadata_found_count",
                "zone_directory_control_metadata_found_count",
                "zone_directory_full_metadata_serial_checksum",
                "zone_directory_control_metadata_serial_checksum",
                "zone_directory_full_metadata_shape_count",
                "zone_directory_control_metadata_shape_count",
            ):
                output.append((key, value(rows, key)))
            for full_key, control_key in (
                (
                    "zone_directory_full_metadata_found_count",
                    "zone_directory_control_metadata_found_count",
                ),
                (
                    "zone_directory_full_metadata_serial_checksum",
                    "zone_directory_control_metadata_serial_checksum",
                ),
            ):
                full = value(rows, full_key)
                control = value(rows, control_key)
                output.append((f"{control_key}_matches_{full_key}", str(control == full).lower()))
                if control != full:
                    failures.append(f"{control_key}={control}, expected {full_key}={full}")
            if integer(rows, "zone_directory_full_metadata_shape_count") <= 0:
                failures.append(
                    "zone_directory_full_metadata_shape_count=0, expected status metadata "
                    "to retain shape evidence"
                )
            if integer(rows, "zone_directory_control_metadata_shape_count") != 0:
                failures.append(
                    "zone_directory_control_metadata_shape_count is nonzero, expected narrow "
                    "control metadata to omit status-only shapes"
                )
            control_metadata_ratio = ratio(
                rows,
                "zone_directory_full_metadata_ns_per_query",
                "zone_directory_control_metadata_ns_per_query",
            )
            output.append(
                ("zone_directory_control_metadata_ratio", f"{control_metadata_ratio:.3f}")
            )
            output.append(
                (
                    "zone_directory_control_metadata_max_ratio",
                    f"{args.max_control_metadata_ratio:.3f}",
                )
            )
            if control_metadata_ratio > args.max_control_metadata_ratio:
                failures.append(
                    f"zone_directory_control_metadata_ratio {control_metadata_ratio:.3f} "
                    f"exceeds maximum {args.max_control_metadata_ratio:.3f}"
                )
        if "zone_directory_serial_gated_transfer_snapshot_ns_per_query" in rows:
            for key in (
                "zone_directory_serial_gated_transfer_snapshot_found_count",
                "zone_directory_serial_gated_transfer_snapshot_no_serial_skip_count",
                "zone_directory_serial_gated_transfer_snapshot_serial_checksum",
            ):
                output.append((key, value(rows, key)))
            found_count = integer(
                rows, "zone_directory_serial_gated_transfer_snapshot_found_count"
            )
            no_serial_skip_count = integer(
                rows, "zone_directory_serial_gated_transfer_snapshot_no_serial_skip_count"
            )
            if found_count <= 0:
                failures.append(
                    "zone_directory_serial_gated_transfer_snapshot_found_count=0, "
                    "expected serial-bearing transfer views"
                )
            if no_serial_skip_count <= 0:
                failures.append(
                    "zone_directory_serial_gated_transfer_snapshot_no_serial_skip_count=0, "
                    "expected no-serial zones to be skipped before snapshot exposure"
                )
            serial_gated_ratio = ratio(
                rows,
                "zone_directory_control_metadata_ns_per_query",
                "zone_directory_serial_gated_transfer_snapshot_ns_per_query",
            )
            output.append(
                (
                    "zone_directory_serial_gated_transfer_snapshot_ratio",
                    f"{serial_gated_ratio:.3f}",
                )
            )
        if "zone_metadata_cached_origin_key_ns_per_query" in rows:
            for key in (
                "zone_metadata_origin_key_rebuild_count",
                "zone_metadata_cached_origin_key_count",
                "zone_metadata_origin_key_rebuild_checksum",
                "zone_metadata_cached_origin_key_checksum",
            ):
                output.append((key, value(rows, key)))
            for rebuild_key, cached_key in (
                (
                    "zone_metadata_origin_key_rebuild_count",
                    "zone_metadata_cached_origin_key_count",
                ),
                (
                    "zone_metadata_origin_key_rebuild_checksum",
                    "zone_metadata_cached_origin_key_checksum",
                ),
            ):
                rebuild = value(rows, rebuild_key)
                cached = value(rows, cached_key)
                output.append(
                    (f"{cached_key}_matches_{rebuild_key}", str(cached == rebuild).lower())
                )
                if cached != rebuild:
                    failures.append(f"{cached_key}={cached}, expected {rebuild_key}={rebuild}")
            cached_key_ratio = ratio(
                rows,
                "zone_metadata_origin_key_rebuild_ns_per_query",
                "zone_metadata_cached_origin_key_ns_per_query",
            )
            output.append(("zone_metadata_cached_origin_key_ratio", f"{cached_key_ratio:.3f}"))
            output.append(
                (
                    "zone_metadata_cached_origin_key_max_ratio",
                    f"{args.max_zone_metadata_cached_key_ratio:.3f}",
                )
            )
            if cached_key_ratio > args.max_zone_metadata_cached_key_ratio:
                failures.append(
                    f"zone_metadata_cached_origin_key_ratio {cached_key_ratio:.3f} "
                    f"exceeds maximum {args.max_zone_metadata_cached_key_ratio:.3f}"
                )
        if "zone_directory_offline_snapshot_cached_sort_ns_per_query" in rows:
            for key in (
                "zone_directory_offline_snapshot_rebuild_sort_count",
                "zone_directory_offline_snapshot_cached_sort_count",
                "zone_directory_offline_snapshot_rebuild_sort_checksum",
                "zone_directory_offline_snapshot_cached_sort_checksum",
            ):
                output.append((key, value(rows, key)))
            for rebuild_key, cached_key in (
                (
                    "zone_directory_offline_snapshot_rebuild_sort_count",
                    "zone_directory_offline_snapshot_cached_sort_count",
                ),
                (
                    "zone_directory_offline_snapshot_rebuild_sort_checksum",
                    "zone_directory_offline_snapshot_cached_sort_checksum",
                ),
            ):
                rebuild = value(rows, rebuild_key)
                cached = value(rows, cached_key)
                output.append(
                    (f"{cached_key}_matches_{rebuild_key}", str(cached == rebuild).lower())
                )
                if cached != rebuild:
                    failures.append(f"{cached_key}={cached}, expected {rebuild_key}={rebuild}")
            offline_snapshot_ratio = ratio(
                rows,
                "zone_directory_offline_snapshot_rebuild_sort_ns_per_query",
                "zone_directory_offline_snapshot_cached_sort_ns_per_query",
            )
            output.append(
                (
                    "zone_directory_offline_snapshot_cached_sort_ratio",
                    f"{offline_snapshot_ratio:.3f}",
                )
            )
        if "zone_directory_entry_state_expire_ns_per_query" in rows:
            for key in (
                "zone_directory_snapshot_state_clone_count",
                "zone_directory_entry_state_expire_count",
                "zone_directory_snapshot_state_clone_serial_checksum",
                "zone_directory_entry_state_expire_serial_checksum",
            ):
                output.append((key, value(rows, key)))
            for clone_key, entry_key in (
                (
                    "zone_directory_snapshot_state_clone_count",
                    "zone_directory_entry_state_expire_count",
                ),
                (
                    "zone_directory_snapshot_state_clone_serial_checksum",
                    "zone_directory_entry_state_expire_serial_checksum",
                ),
            ):
                clone_value = value(rows, clone_key)
                entry_value = value(rows, entry_key)
                output.append(
                    (f"{entry_key}_matches_{clone_key}", str(entry_value == clone_value).lower())
                )
                if entry_value != clone_value:
                    failures.append(f"{entry_key}={entry_value}, expected {clone_key}={clone_value}")
            expire_ratio = ratio(
                rows,
                "zone_directory_snapshot_state_clone_ns_per_query",
                "zone_directory_entry_state_expire_ns_per_query",
            )
            output.append(("zone_directory_entry_state_expire_ratio", f"{expire_ratio:.3f}"))
        if "zone_metadata_cached_origin_name_ns_per_query" in rows:
            for key in (
                "zone_metadata_origin_name_rebuild_count",
                "zone_metadata_cached_origin_name_count",
                "zone_metadata_origin_name_rebuild_checksum",
                "zone_metadata_cached_origin_name_checksum",
            ):
                output.append((key, value(rows, key)))
            for rebuild_key, cached_key in (
                (
                    "zone_metadata_origin_name_rebuild_count",
                    "zone_metadata_cached_origin_name_count",
                ),
                (
                    "zone_metadata_origin_name_rebuild_checksum",
                    "zone_metadata_cached_origin_name_checksum",
                ),
            ):
                rebuild = value(rows, rebuild_key)
                cached = value(rows, cached_key)
                output.append((f"{cached_key}_matches_{rebuild_key}", str(cached == rebuild).lower()))
                if cached != rebuild:
                    failures.append(f"{cached_key}={cached}, expected {rebuild_key}={rebuild}")
            cached_name_ratio = ratio(
                rows,
                "zone_metadata_origin_name_rebuild_ns_per_query",
                "zone_metadata_cached_origin_name_ns_per_query",
            )
            output.append(("zone_metadata_cached_origin_name_ratio", f"{cached_name_ratio:.3f}"))

    for key in (
        "notify_soa_validation_exact_noerror_count",
        "notify_soa_validation_mixed_case_noerror_count",
        "notify_soa_validation_exact_rcode_checksum",
        "notify_soa_validation_mixed_case_rcode_checksum",
        "notify_soa_validation_exact_bytes",
        "notify_soa_validation_mixed_case_bytes",
    ):
        output.append((key, value(rows, key)))
    iterations = integer(rows, "iterations")
    for key in (
        "notify_soa_validation_exact_noerror_count",
        "notify_soa_validation_mixed_case_noerror_count",
    ):
        observed = integer(rows, key)
        if observed != iterations:
            failures.append(f"{key}={observed}, expected iterations={iterations}")
    for key in (
        "notify_soa_validation_exact_rcode_checksum",
        "notify_soa_validation_mixed_case_rcode_checksum",
    ):
        observed = integer(rows, key)
        if observed != 0:
            failures.append(f"{key}={observed}, expected 0")
    exact_bytes = value(rows, "notify_soa_validation_exact_bytes")
    mixed_case_bytes = value(rows, "notify_soa_validation_mixed_case_bytes")
    output.append(
        (
            "notify_soa_validation_mixed_case_bytes_match_exact",
            str(mixed_case_bytes == exact_bytes).lower(),
        )
    )
    if mixed_case_bytes != exact_bytes:
        failures.append(
            "notify_soa_validation_mixed_case_bytes="
            f"{mixed_case_bytes}, expected exact bytes {exact_bytes}"
        )
    check_ratio(
        rows,
        failures,
        output,
        "notify_soa_mixed_case_validation",
        "notify_soa_validation_exact_ns_per_query",
        "notify_soa_validation_mixed_case_ns_per_query",
        args.max_notify_soa_mixed_case_ratio,
    )

    for key in (
        "chaos_classification_exact_noerror_count",
        "chaos_classification_mixed_case_noerror_count",
        "chaos_classification_exact_rcode_checksum",
        "chaos_classification_mixed_case_rcode_checksum",
        "chaos_classification_exact_bytes",
        "chaos_classification_mixed_case_bytes",
    ):
        output.append((key, value(rows, key)))
    for key in (
        "chaos_classification_exact_noerror_count",
        "chaos_classification_mixed_case_noerror_count",
    ):
        observed = integer(rows, key)
        if observed != iterations:
            failures.append(f"{key}={observed}, expected iterations={iterations}")
    for key in (
        "chaos_classification_exact_rcode_checksum",
        "chaos_classification_mixed_case_rcode_checksum",
    ):
        observed = integer(rows, key)
        if observed != 0:
            failures.append(f"{key}={observed}, expected 0")
    chaos_exact_bytes = value(rows, "chaos_classification_exact_bytes")
    chaos_mixed_case_bytes = value(rows, "chaos_classification_mixed_case_bytes")
    output.append(
        (
            "chaos_classification_mixed_case_bytes_match_exact",
            str(chaos_mixed_case_bytes == chaos_exact_bytes).lower(),
        )
    )
    if chaos_mixed_case_bytes != chaos_exact_bytes:
        failures.append(
            "chaos_classification_mixed_case_bytes="
            f"{chaos_mixed_case_bytes}, expected exact bytes {chaos_exact_bytes}"
        )
    check_ratio(
        rows,
        failures,
        output,
        "chaos_mixed_case_classification",
        "chaos_classification_exact_ns_per_query",
        "chaos_classification_mixed_case_ns_per_query",
        args.max_chaos_mixed_case_ratio,
    )

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
    if "zone_image_absent_low_exact_lookup_ns_per_query" in rows:
        absent_low = number(rows, "zone_image_absent_low_exact_lookup_ns_per_query")
        absent_high = number(rows, "zone_image_absent_high_exact_lookup_ns_per_query")
        absent_ratio = absent_low / absent_high if absent_high > 0 else float("inf")
        output.append(("absent_low_exact_lookup_ratio", f"{absent_ratio:.3f}"))
        output.append(
            (
                "absent_low_exact_lookup_max_ratio",
                f"{args.max_absent_low_exact_ratio:.3f}",
            )
        )
        if absent_ratio > args.max_absent_low_exact_ratio:
            failures.append(
                f"absent low-RRtype exact lookup ratio {absent_ratio:.3f} exceeds "
                f"maximum {args.max_absent_low_exact_ratio:.3f}"
            )
        for key in (
            "zone_image_absent_low_exact_answer_rrset_count",
            "zone_image_absent_high_exact_answer_rrset_count",
        ):
            observed = integer(rows, key)
            output.append((key, str(observed)))
            if observed != 0:
                failures.append(f"{key}={observed}, expected 0")
    if "zone_image_absent_low_direct_preflight_ns_per_query" in rows:
        absent_low = number(rows, "zone_image_absent_low_direct_preflight_ns_per_query")
        absent_high = number(rows, "zone_image_absent_high_direct_preflight_ns_per_query")
        absent_ratio = absent_low / absent_high if absent_high > 0 else float("inf")
        output.append(("absent_low_direct_preflight_ratio", f"{absent_ratio:.3f}"))
        output.append(
            (
                "absent_low_direct_preflight_max_ratio",
                f"{args.max_absent_low_direct_preflight_ratio:.3f}",
            )
        )
        if absent_ratio > args.max_absent_low_direct_preflight_ratio:
            failures.append(
                f"absent low-RRtype direct preflight ratio {absent_ratio:.3f} exceeds "
                f"maximum {args.max_absent_low_direct_preflight_ratio:.3f}"
            )
        for key in (
            "zone_image_absent_low_direct_preflight_answer_rrset_count",
            "zone_image_absent_high_direct_preflight_answer_rrset_count",
        ):
            observed = integer(rows, key)
            output.append((key, str(observed)))
            if observed != 0:
                failures.append(f"{key}={observed}, expected 0")
    if "zone_image_absent_present_low_direct_preflight_ns_per_query" in rows:
        absent_present_low = number(
            rows, "zone_image_absent_present_low_direct_preflight_ns_per_query"
        )
        absent_high = number(rows, "zone_image_absent_high_direct_preflight_ns_per_query")
        absent_ratio = absent_present_low / absent_high if absent_high > 0 else float("inf")
        output.append(("absent_present_low_direct_preflight_ratio", f"{absent_ratio:.3f}"))
        output.append(
            (
                "absent_present_low_direct_preflight_max_ratio",
                f"{args.max_absent_present_low_direct_preflight_ratio:.3f}",
            )
        )
        if absent_ratio > args.max_absent_present_low_direct_preflight_ratio:
            failures.append(
                f"absent present-low-RRtype direct preflight ratio {absent_ratio:.3f} exceeds "
                f"maximum {args.max_absent_present_low_direct_preflight_ratio:.3f}"
            )
        observed = integer(rows, "zone_image_absent_present_low_direct_preflight_answer_rrset_count")
        output.append(
            ("zone_image_absent_present_low_direct_preflight_answer_rrset_count", str(observed))
        )
        if observed != 0:
            failures.append(
                f"zone_image_absent_present_low_direct_preflight_answer_rrset_count={observed}, expected 0"
            )
    if "zone_image_absent_present_low_any_exact_lookup_ns_per_query" in rows:
        absent_present_low = number(
            rows, "zone_image_absent_present_low_any_exact_lookup_ns_per_query"
        )
        absent_high = number(rows, "zone_image_absent_high_any_exact_lookup_ns_per_query")
        absent_ratio = absent_present_low / absent_high if absent_high > 0 else float("inf")
        output.append(("absent_present_low_any_exact_lookup_ratio", f"{absent_ratio:.3f}"))
        output.append(
            (
                "absent_present_low_any_exact_lookup_max_ratio",
                f"{args.max_absent_present_low_any_exact_ratio:.3f}",
            )
        )
        if absent_ratio > args.max_absent_present_low_any_exact_ratio:
            failures.append(
                f"absent present-low-RRtype QCLASS=ANY exact lookup ratio {absent_ratio:.3f} exceeds "
                f"maximum {args.max_absent_present_low_any_exact_ratio:.3f}"
            )
        for key in (
            "zone_image_absent_present_low_any_exact_answer_rrset_count",
            "zone_image_absent_high_any_exact_answer_rrset_count",
        ):
            observed = integer(rows, key)
            output.append((key, str(observed)))
            if observed != 0:
                failures.append(f"{key}={observed}, expected 0")
    if "zone_image_absent_low_response_plan_ns_per_query" in rows:
        absent_low = number(rows, "zone_image_absent_low_response_plan_ns_per_query")
        absent_high = number(rows, "zone_image_absent_high_response_plan_ns_per_query")
        absent_ratio = absent_low / absent_high if absent_high > 0 else float("inf")
        output.append(("absent_low_response_plan_ratio", f"{absent_ratio:.3f}"))
        output.append(
            (
                "absent_low_response_plan_max_ratio",
                f"{args.max_absent_low_response_plan_ratio:.3f}",
            )
        )
        if absent_ratio > args.max_absent_low_response_plan_ratio:
            failures.append(
                f"absent low-RRtype response-plan ratio {absent_ratio:.3f} exceeds "
                f"maximum {args.max_absent_low_response_plan_ratio:.3f}"
            )
        for low_key, high_key in (
            (
                "zone_image_absent_low_response_plan_item_count",
                "zone_image_absent_high_response_plan_item_count",
            ),
            (
                "zone_image_absent_low_response_plan_rcode_checksum",
                "zone_image_absent_high_response_plan_rcode_checksum",
            ),
        ):
            low = value(rows, low_key)
            high = value(rows, high_key)
            output.append((f"{low_key}_matches_{high_key}", str(low == high).lower()))
            if low != high:
                failures.append(f"{low_key}={low}, expected {high_key}={high}")
    indirection_free_prefix = None
    if "zone_image_indirection_free_absent_low_response_plan_ns_per_query" in rows:
        indirection_free_prefix = "zone_image_indirection_free_absent_low_response_plan"
        ratio_prefix = "indirection_free_absent_low_response_plan"
        max_ratio = args.max_indirection_free_absent_low_response_plan_ratio
        failure_label = "Indirection-free"
    elif "zone_image_cname_free_absent_low_response_plan_ns_per_query" in rows:
        indirection_free_prefix = "zone_image_cname_free_absent_low_response_plan"
        ratio_prefix = "cname_free_absent_low_response_plan"
        max_ratio = args.max_cname_free_absent_low_response_plan_ratio
        failure_label = "CNAME-free"
    if indirection_free_prefix is not None:
        indirection_free = number(rows, f"{indirection_free_prefix}_ns_per_query")
        absent_low = number(rows, "zone_image_absent_low_response_plan_ns_per_query")
        indirection_free_ratio = indirection_free / absent_low if absent_low > 0 else float("inf")
        output.append((f"{ratio_prefix}_ratio", f"{indirection_free_ratio:.3f}"))
        output.append(
            (
                f"{ratio_prefix}_max_ratio",
                f"{max_ratio:.3f}",
            )
        )
        if indirection_free_ratio > max_ratio:
            failures.append(
                f"{failure_label} absent low-RRtype response-plan ratio "
                f"{indirection_free_ratio:.3f} exceeds maximum {max_ratio:.3f}"
            )
        for indirection_free_key, baseline_key in (
            (
                f"{indirection_free_prefix}_item_count",
                "zone_image_absent_low_response_plan_item_count",
            ),
            (
                f"{indirection_free_prefix}_rcode_checksum",
                "zone_image_absent_low_response_plan_rcode_checksum",
            ),
        ):
            indirection_free_value = value(rows, indirection_free_key)
            baseline_value = value(rows, baseline_key)
            output.append(
                (
                    f"{indirection_free_key}_matches_{baseline_key}",
                    str(indirection_free_value == baseline_value).lower(),
                )
            )
            if indirection_free_value != baseline_value:
                failures.append(
                    f"{indirection_free_key}={indirection_free_value}, expected "
                    f"{baseline_key}={baseline_value}"
                )
    if "zone_image_child_lookup_sorted_ns_per_query" in rows:
        child_lookup_metric_keys = [
            "zone_image_child_lookup_profile_fanout",
            "zone_image_child_lookup_query_cases",
            "zone_image_child_lookup_generated_hash_slots",
            "zone_image_child_lookup_compact_generated_hash_slots",
            "zone_image_child_lookup_generated_hash_slot_bytes",
            "zone_image_child_lookup_compact_generated_hash_slot_bytes",
            "zone_image_child_lookup_byte_bucket_index_bytes",
            "zone_image_child_lookup_sorted_found_count",
            "zone_image_child_lookup_hashmap_found_count",
            "zone_image_child_lookup_byte_bucket_found_count",
            "zone_image_child_lookup_generated_hash_found_count",
            "zone_image_child_lookup_compact_generated_hash_found_count",
            "zone_image_child_lookup_sorted_index_checksum",
            "zone_image_child_lookup_hashmap_index_checksum",
            "zone_image_child_lookup_byte_bucket_index_checksum",
            "zone_image_child_lookup_generated_hash_index_checksum",
            "zone_image_child_lookup_compact_generated_hash_index_checksum",
        ]
        if "zone_image_child_lookup_length_bucket_ns_per_query" in rows:
            child_lookup_metric_keys.extend(
                [
                    "zone_image_child_lookup_length_bucket_index_bytes",
                    "zone_image_child_lookup_length_bucket_found_count",
                    "zone_image_child_lookup_length_bucket_index_checksum",
                ]
            )
        if "zone_image_child_lookup_last_byte_bucket_ns_per_query" in rows:
            child_lookup_metric_keys.extend(
                [
                    "zone_image_child_lookup_last_byte_bucket_index_bytes",
                    "zone_image_child_lookup_last_byte_bucket_found_count",
                    "zone_image_child_lookup_last_byte_bucket_index_checksum",
                ]
            )
        for key in child_lookup_metric_keys:
            output.append((key, value(rows, key)))
        if integer(rows, "zone_image_child_lookup_profile_fanout") <= 256:
            failures.append("child lookup profile did not retain a high-fanout node")
        child_lookup_equal_pairs = [
            (
                "zone_image_child_lookup_sorted_found_count",
                "zone_image_child_lookup_hashmap_found_count",
            ),
            (
                "zone_image_child_lookup_sorted_found_count",
                "zone_image_child_lookup_byte_bucket_found_count",
            ),
            (
                "zone_image_child_lookup_sorted_found_count",
                "zone_image_child_lookup_generated_hash_found_count",
            ),
            (
                "zone_image_child_lookup_sorted_found_count",
                "zone_image_child_lookup_compact_generated_hash_found_count",
            ),
            (
                "zone_image_child_lookup_sorted_index_checksum",
                "zone_image_child_lookup_hashmap_index_checksum",
            ),
            (
                "zone_image_child_lookup_sorted_index_checksum",
                "zone_image_child_lookup_byte_bucket_index_checksum",
            ),
            (
                "zone_image_child_lookup_sorted_index_checksum",
                "zone_image_child_lookup_generated_hash_index_checksum",
            ),
            (
                "zone_image_child_lookup_sorted_index_checksum",
                "zone_image_child_lookup_compact_generated_hash_index_checksum",
            ),
        ]
        if "zone_image_child_lookup_length_bucket_ns_per_query" in rows:
            child_lookup_equal_pairs.extend(
                [
                    (
                        "zone_image_child_lookup_sorted_found_count",
                        "zone_image_child_lookup_length_bucket_found_count",
                    ),
                    (
                        "zone_image_child_lookup_sorted_index_checksum",
                        "zone_image_child_lookup_length_bucket_index_checksum",
                    ),
                ]
            )
        if "zone_image_child_lookup_last_byte_bucket_ns_per_query" in rows:
            child_lookup_equal_pairs.extend(
                [
                    (
                        "zone_image_child_lookup_sorted_found_count",
                        "zone_image_child_lookup_last_byte_bucket_found_count",
                    ),
                    (
                        "zone_image_child_lookup_sorted_index_checksum",
                        "zone_image_child_lookup_last_byte_bucket_index_checksum",
                    ),
                ]
            )
        for baseline_key, candidate_key in child_lookup_equal_pairs:
            baseline = value(rows, baseline_key)
            candidate = value(rows, candidate_key)
            output.append(
                (
                    f"{candidate_key}_matches_{baseline_key}",
                    str(candidate == baseline).lower(),
                )
            )
            if candidate != baseline:
                failures.append(f"{candidate_key}={candidate}, expected {baseline_key}={baseline}")
        sorted_lookup = number(rows, "zone_image_child_lookup_sorted_ns_per_query")
        if sorted_lookup <= 0:
            failures.append("zone_image_child_lookup_sorted_ns_per_query must be positive")
        else:
            output.append(
                (
                    "zone_image_child_lookup_hashmap_ratio",
                    f"{number(rows, 'zone_image_child_lookup_hashmap_ns_per_query') / sorted_lookup:.3f}",
                )
            )
            output.append(
                (
                    "zone_image_child_lookup_generated_hash_ratio",
                    f"{number(rows, 'zone_image_child_lookup_generated_hash_ns_per_query') / sorted_lookup:.3f}",
                )
            )
            output.append(
                (
                    "zone_image_child_lookup_compact_generated_hash_ratio",
                    f"{number(rows, 'zone_image_child_lookup_compact_generated_hash_ns_per_query') / sorted_lookup:.3f}",
                )
            )
            output.append(
                (
                    "zone_image_child_lookup_byte_bucket_ratio",
                    f"{number(rows, 'zone_image_child_lookup_byte_bucket_ns_per_query') / sorted_lookup:.3f}",
                )
            )
            if "zone_image_child_lookup_length_bucket_ns_per_query" in rows:
                output.append(
                    (
                        "zone_image_child_lookup_length_bucket_ratio",
                        f"{number(rows, 'zone_image_child_lookup_length_bucket_ns_per_query') / sorted_lookup:.3f}",
                    )
                )
            if "zone_image_child_lookup_last_byte_bucket_ns_per_query" in rows:
                output.append(
                    (
                        "zone_image_child_lookup_last_byte_bucket_ratio",
                        f"{number(rows, 'zone_image_child_lookup_last_byte_bucket_ns_per_query') / sorted_lookup:.3f}",
                    )
                )
    if "zone_image_small_child_lookup_sorted_ns_per_query" in rows:
        small_child_lookup_metric_keys = [
            "zone_image_small_child_lookup_fanout",
            "zone_image_small_child_lookup_query_cases",
            "zone_image_small_child_lookup_sorted_found_count",
            "zone_image_small_child_lookup_linear_found_count",
            "zone_image_small_child_lookup_sorted_index_checksum",
            "zone_image_small_child_lookup_linear_index_checksum",
        ]
        for key in small_child_lookup_metric_keys:
            output.append((key, value(rows, key)))
        if integer(rows, "zone_image_small_child_lookup_fanout") != 4:
            failures.append("small child lookup fixture must retain fanout 4")
        for baseline_key, candidate_key in [
            (
                "zone_image_small_child_lookup_sorted_found_count",
                "zone_image_small_child_lookup_linear_found_count",
            ),
            (
                "zone_image_small_child_lookup_sorted_index_checksum",
                "zone_image_small_child_lookup_linear_index_checksum",
            ),
        ]:
            baseline = value(rows, baseline_key)
            candidate = value(rows, candidate_key)
            output.append(
                (
                    f"{candidate_key}_matches_{baseline_key}",
                    str(candidate == baseline).lower(),
                )
            )
            if candidate != baseline:
                failures.append(f"{candidate_key}={candidate}, expected {baseline_key}={baseline}")
        small_sorted_lookup = number(rows, "zone_image_small_child_lookup_sorted_ns_per_query")
        if small_sorted_lookup <= 0:
            failures.append("zone_image_small_child_lookup_sorted_ns_per_query must be positive")
        else:
            output.append(
                (
                    "zone_image_small_child_lookup_linear_ratio",
                    f"{number(rows, 'zone_image_small_child_lookup_linear_ns_per_query') / small_sorted_lookup:.3f}",
                )
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
        "boundary_packet",
        "current_boundary_packet_ns_per_query",
        "zone_image_boundary_packet_ns_per_query",
        args.max_boundary_packet_ratio,
    )
    check_ratio(
        rows,
        failures,
        output,
        "udp_ceiling_packet",
        "current_udp_ceiling_packet_ns_per_query",
        "zone_image_udp_ceiling_packet_ns_per_query",
        args.max_udp_ceiling_packet_ratio,
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
