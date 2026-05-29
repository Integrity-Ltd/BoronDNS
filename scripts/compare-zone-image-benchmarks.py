#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


COMPARABLE_KEYS = (
    "transport",
    "records_configured",
    "stress_candidates_configured",
    "server_threads",
    "client_threads",
    "client_window",
    "udp_batch_size",
    "listen_address",
    "client_server",
    "client_bind",
    "client_mode",
    "remote_client_ssh",
    "require_non_loopback_device",
    "network_snapshot_dir",
    "duration_seconds",
    "query_mode",
    "trace_queries",
    "pipeline_timing_enabled",
)
PROVENANCE_KEYS = (
    "git_revision",
    "git_dirty",
    "kernel_version",
    "rustc_version",
    "cargo_version",
    "build_profile",
    "server_bin_sha256",
    "client_bin_sha256",
    "remote_client_bin_sha256",
)

LOOPBACK_OR_WILDCARD_ADDRESSES = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}
WEAK_PROVENANCE_VALUES = {"", "none", "unknown"}


def fail(message: str) -> None:
    raise SystemExit(message)


def result_path(path: Path) -> Path:
    if path.is_dir():
        path = path / "benchmark-results.tsv"
    if not path.is_file():
        fail(f"benchmark results not found: {path}")
    return path


def artifact_dir(path: Path) -> Path:
    return path if path.is_dir() else path.parent


def read_results(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    with result_path(path).open(encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header[:2] != ["metric", "value"]:
            fail(f"{path}: expected benchmark-results.tsv header 'metric<TAB>value'")
        for line_number, line in enumerate(handle, start=2):
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 2:
                fail(f"{path}:{line_number}: expected at least metric and value columns")
            rows[fields[0]] = fields[1]
    return rows


def value(results: dict[str, str], key: str) -> str:
    try:
        return results[key]
    except KeyError:
        fail(f"benchmark result is missing required metric {key!r}")


def optional_value(results: dict[str, str], key: str, default: str = "unknown") -> str:
    return results.get(key, default)


def number(results: dict[str, str], key: str) -> float:
    raw = value(results, key)
    try:
        return float(raw)
    except ValueError:
        fail(f"benchmark metric {key!r} is not numeric: {raw!r}")


def integer(results: dict[str, str], key: str) -> int:
    raw = value(results, key)
    try:
        return int(raw)
    except ValueError:
        fail(f"benchmark metric {key!r} is not an integer: {raw!r}")


def read_counter_deltas(path: Path) -> dict[str, int]:
    if not path.is_file():
        fail(f"network counter delta file not found: {path}")
    rows: dict[str, int] = {}
    with path.open(encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header != ["metric", "before", "after", "delta", "unit"]:
            fail(f"{path}: expected proc-net-dev-delta.tsv header")
        for line_number, line in enumerate(handle, start=2):
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 5:
                fail(f"{path}:{line_number}: expected five tab-separated fields")
            metric, _before, _after, delta, unit = fields
            if unit != "count":
                continue
            try:
                rows[metric] = int(delta)
            except ValueError:
                fail(f"{path}:{line_number}: non-integer delta for {metric!r}: {delta!r}")
    return rows


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        fail("cannot compute ratio against a non-positive current-path value")
    return numerator / denominator


def format_per_response(delta: int, estimated_responses: float) -> str:
    if estimated_responses <= 0:
        return "nan"
    return f"{delta / estimated_responses:.3f}"


def append_counter_summary_failure(
    failures: list[str],
    *,
    label: str,
    results: dict[str, str],
    deltas: dict[str, int],
    summary_metric: str,
    delta_metric: str,
) -> None:
    raw = value(results, summary_metric)
    try:
        summary_delta = int(raw)
    except ValueError:
        failures.append(
            f"{label} benchmark summary metric {summary_metric} is not an integer: {raw!r}"
        )
        return
    retained_delta = deltas.get(delta_metric, 0)
    if summary_delta != retained_delta:
        failures.append(
            f"{label} benchmark summary {summary_metric}={summary_delta} does not match "
            f"retained proc-net-dev delta {delta_metric}={retained_delta}"
        )


def emit(rows: list[tuple[str, str]], output: Path | None) -> None:
    text = "metric\tvalue\n" + "\n".join(f"{key}\t{value}" for key, value in rows) + "\n"
    if output is None:
        print(text, end="")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"zone_image_benchmark_comparison={output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare current-path and ZoneImage DNS client benchmark artifacts."
    )
    parser.add_argument("--current", required=True, type=Path, help="Current-path artifact dir or benchmark-results.tsv")
    parser.add_argument("--zone-image", required=True, type=Path, help="ZoneImage artifact dir or benchmark-results.tsv")
    parser.add_argument("--output", type=Path, help="Optional TSV output path")
    parser.add_argument("--max-dropped", type=int, default=0, help="Maximum dropped responses allowed per run")
    parser.add_argument("--max-errors", type=int, default=0, help="Maximum client validation errors allowed per run")
    parser.add_argument(
        "--max-zone-image-fallbacks",
        type=int,
        default=0,
        help="Maximum ZoneImage fallback responses allowed in the ZoneImage artifact",
    )
    parser.add_argument("--min-qps-ratio", type=float, default=1.0, help="Minimum ZoneImage/current responses-per-second ratio")
    parser.add_argument("--max-p50-ratio", type=float, help="Maximum ZoneImage/current p50 latency ratio")
    parser.add_argument("--max-p99-ratio", type=float, help="Maximum ZoneImage/current p99 latency ratio")
    parser.add_argument("--max-p999-ratio", type=float, help="Maximum ZoneImage/current p999 latency ratio")
    parser.add_argument(
        "--min-network-packets-per-response",
        type=float,
        default=0.25,
        help=(
            "Minimum RX and TX packet delta per measured response when "
            "--require-non-loopback is used"
        ),
    )
    parser.add_argument(
        "--require-non-loopback",
        action="store_true",
        help="Fail unless both artifacts recorded a concrete non-loopback network device",
    )
    parser.add_argument(
        "--require-direct-and-semantic",
        action="store_true",
        help="Fail unless the ZoneImage artifact recorded both direct and semantic served hits",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    current = read_results(args.current)
    zone_image = read_results(args.zone_image)
    failures: list[str] = []
    current_network_deltas: dict[str, int] = {}
    zone_image_network_deltas: dict[str, int] = {}

    if value(current, "zone_image_serve_enabled") != "false":
        failures.append("current artifact did not record zone_image_serve_enabled=false")
    if value(zone_image, "zone_image_serve_enabled") != "true":
        failures.append("ZoneImage artifact did not record zone_image_serve_enabled=true")
    if args.min_network_packets_per_response < 0:
        failures.append("--min-network-packets-per-response must be non-negative")
    if value(current, "network_device") != value(zone_image, "network_device"):
        failures.append(
            "network_device differs: "
            f"current={value(current, 'network_device')!r} "
            f"zone_image={value(zone_image, 'network_device')!r}"
        )

    for key in COMPARABLE_KEYS:
        if value(current, key) != value(zone_image, key):
            failures.append(
                f"metric {key} differs: current={value(current, key)!r} "
                f"zone_image={value(zone_image, key)!r}"
            )
    for key in PROVENANCE_KEYS:
        if key in current or key in zone_image:
            current_provenance_value = optional_value(current, key, "missing")
            zone_image_provenance_value = optional_value(zone_image, key, "missing")
            if current_provenance_value != zone_image_provenance_value:
                failures.append(
                    f"metric {key} differs: current={current_provenance_value!r} "
                    f"zone_image={zone_image_provenance_value!r}"
                )
    for key in (
        "remote_client_local_arch",
        "remote_client_remote_arch",
        "remote_client_local_host_id",
        "remote_client_remote_host_id",
        "remote_client_same_host",
        "remote_client_allow_arch_mismatch",
    ):
        if key in current or key in zone_image:
            current_arch_value = optional_value(current, key, "missing")
            zone_image_arch_value = optional_value(zone_image, key, "missing")
            if current_arch_value != zone_image_arch_value:
                failures.append(
                    f"metric {key} differs: current={current_arch_value!r} "
                    f"zone_image={zone_image_arch_value!r}"
                )

    current_trace = sha256(artifact_dir(args.current) / "query-trace.tsv")
    zone_image_trace = sha256(artifact_dir(args.zone_image) / "query-trace.tsv")
    trace_match = current_trace is not None and current_trace == zone_image_trace
    if value(current, "query_mode") == "trace":
        if current_trace is None or zone_image_trace is None:
            failures.append("trace-mode comparison requires query-trace.tsv in both artifacts")
        elif not trace_match:
            failures.append("retained query-trace.tsv files differ")

    for label, results in (("current", current), ("zone_image", zone_image)):
        if args.require_non_loopback:
            for key in PROVENANCE_KEYS:
                if optional_value(results, key, "missing") in WEAK_PROVENANCE_VALUES | {"missing"}:
                    failures.append(
                        f"{label} benchmark provenance {key}={optional_value(results, key, 'missing')!r} "
                        "does not satisfy --require-non-loopback"
                    )
        dropped = integer(results, "dropped")
        errors = integer(results, "errors")
        if dropped > args.max_dropped:
            failures.append(f"{label} dropped {dropped} responses, limit is {args.max_dropped}")
        if errors > args.max_errors:
            failures.append(f"{label} recorded {errors} client errors, limit is {args.max_errors}")
        if args.require_non_loopback and value(results, "network_device") in {"", "lo", "unknown"}:
            failures.append(
                f"{label} network_device={value(results, 'network_device')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and value(results, "require_non_loopback_device") != "true":
            failures.append(
                f"{label} artifact did not record require_non_loopback_device=true"
            )
        if args.require_non_loopback and value(results, "client_server") in LOOPBACK_OR_WILDCARD_ADDRESSES:
            failures.append(
                f"{label} client_server={value(results, 'client_server')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and value(results, "client_mode") != "ssh":
            failures.append(
                f"{label} client_mode={value(results, 'client_mode')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and value(results, "remote_client_ssh") in {"", "none"}:
            failures.append(
                f"{label} remote_client_ssh={value(results, 'remote_client_ssh')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and optional_value(results, "remote_client_local_arch", "none") in WEAK_PROVENANCE_VALUES:
            failures.append(
                f"{label} remote_client_local_arch="
                f"{optional_value(results, 'remote_client_local_arch', 'none')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and optional_value(results, "remote_client_remote_arch", "none") in WEAK_PROVENANCE_VALUES:
            failures.append(
                f"{label} remote_client_remote_arch="
                f"{optional_value(results, 'remote_client_remote_arch', 'none')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and optional_value(results, "remote_client_allow_arch_mismatch", "none") not in {"true", "false"}:
            failures.append(
                f"{label} remote_client_allow_arch_mismatch="
                f"{optional_value(results, 'remote_client_allow_arch_mismatch', 'none')!r} "
                "does not satisfy --require-non-loopback"
            )
        if args.require_non_loopback and optional_value(results, "remote_client_allow_arch_mismatch", "none") != "false":
            failures.append(
                f"{label} remote_client_allow_arch_mismatch="
                f"{optional_value(results, 'remote_client_allow_arch_mismatch', 'none')!r}; "
                "physical NIC promotion requires architecture override disabled"
            )
        if (
            args.require_non_loopback
            and optional_value(results, "remote_client_local_arch", "none")
            != optional_value(results, "remote_client_remote_arch", "none")
        ):
            failures.append(
                f"{label} remote client architecture mismatch: "
                f"local={optional_value(results, 'remote_client_local_arch', 'none')!r} "
                f"remote={optional_value(results, 'remote_client_remote_arch', 'none')!r}"
            )
        for key in ("remote_client_local_host_id", "remote_client_remote_host_id"):
            if args.require_non_loopback and optional_value(results, key, "none") in WEAK_PROVENANCE_VALUES:
                failures.append(
                    f"{label} {key}={optional_value(results, key, 'none')!r} "
                    "does not satisfy --require-non-loopback"
                )
        if args.require_non_loopback and optional_value(results, "remote_client_same_host", "none") != "false":
            failures.append(
                f"{label} remote_client_same_host="
                f"{optional_value(results, 'remote_client_same_host', 'none')!r}; "
                "physical NIC promotion requires a distinct remote client host"
            )
        if (
            args.require_non_loopback
            and optional_value(results, "remote_client_local_host_id", "none")
            == optional_value(results, "remote_client_remote_host_id", "none")
        ):
            failures.append(
                f"{label} remote client host identity matches the local server host"
            )
        if args.require_non_loopback and optional_value(results, "remote_client_bin_sha256", "none") in WEAK_PROVENANCE_VALUES:
            failures.append(
                f"{label} remote_client_bin_sha256={optional_value(results, 'remote_client_bin_sha256', 'none')!r} "
                "does not satisfy --require-non-loopback"
            )
        if (
            args.require_non_loopback
            and optional_value(results, "remote_client_bin_sha256", "none")
            != optional_value(results, "client_bin_sha256", "none")
        ):
            failures.append(
                f"{label} remote client binary digest mismatch: "
                f"local={optional_value(results, 'client_bin_sha256', 'none')!r} "
                f"remote={optional_value(results, 'remote_client_bin_sha256', 'none')!r}"
            )

    if args.require_non_loopback:
        current_network_deltas = read_counter_deltas(
            artifact_dir(args.current) / "network" / "proc-net-dev-delta.tsv"
        )
        zone_image_network_deltas = read_counter_deltas(
            artifact_dir(args.zone_image) / "network" / "proc-net-dev-delta.tsv"
        )
        for label, deltas in (
            ("current", current_network_deltas),
            ("zone_image", zone_image_network_deltas),
        ):
            results = current if label == "current" else zone_image
            if value(results, "network_snapshot_dir") != "network":
                failures.append(
                    f"{label} artifact did not record network_snapshot_dir=network"
                )
            append_counter_summary_failure(
                failures,
                label=label,
                results=results,
                deltas=deltas,
                summary_metric="network_rx_packets_delta",
                delta_metric="rx_packets",
            )
            append_counter_summary_failure(
                failures,
                label=label,
                results=results,
                deltas=deltas,
                summary_metric="network_tx_packets_delta",
                delta_metric="tx_packets",
            )
            estimated_responses = number(results, "responses_per_second") * number(
                results, "duration_seconds"
            )
            minimum_packets = estimated_responses * args.min_network_packets_per_response
            for key in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes"):
                if deltas.get(key, 0) <= 0:
                    failures.append(
                        f"{label} network counter {key} delta must be positive "
                        "for physical NIC promotion"
                    )
            for key in ("rx_packets", "tx_packets"):
                if deltas.get(key, 0) < minimum_packets:
                    failures.append(
                        f"{label} network counter {key} delta {deltas.get(key, 0)} "
                        f"is below {args.min_network_packets_per_response:.3f} packets "
                        f"per measured response ({minimum_packets:.1f} packets)"
                    )
            for key in ("rx_errs", "rx_drop", "tx_errs", "tx_drop"):
                if deltas.get(key, 0) != 0:
                    failures.append(
                        f"{label} network counter {key} delta is {deltas.get(key, 0)}, "
                        "expected 0 for physical NIC promotion"
                    )

    current_zone_image_hits = integer(current, "zone_image_serve_hits")
    current_zone_image_direct_hits = integer(current, "zone_image_serve_direct_hits")
    current_zone_image_semantic_hits = integer(current, "zone_image_serve_semantic_hits")
    current_zone_image_fallbacks = integer(current, "zone_image_serve_fallbacks")
    zone_image_hits = integer(zone_image, "zone_image_serve_hits")
    zone_image_direct_hits = integer(zone_image, "zone_image_serve_direct_hits")
    zone_image_semantic_hits = integer(zone_image, "zone_image_serve_semantic_hits")
    zone_image_fallbacks = integer(zone_image, "zone_image_serve_fallbacks")
    if (
        current_zone_image_hits != 0
        or current_zone_image_direct_hits != 0
        or current_zone_image_semantic_hits != 0
        or current_zone_image_fallbacks != 0
    ):
        failures.append(
            "current artifact recorded ZoneImage serve hit/fallback counters despite "
            "zone_image_serve_enabled=false"
        )
    if zone_image_hits <= 0:
        failures.append("ZoneImage artifact did not record any ZoneImage served hits")
    if zone_image_direct_hits + zone_image_semantic_hits != zone_image_hits:
        failures.append(
            "ZoneImage direct/semantic served-hit counters do not add up to total served hits"
        )
    if zone_image_fallbacks > args.max_zone_image_fallbacks:
        failures.append(
            f"ZoneImage artifact recorded {zone_image_fallbacks} fallbacks, "
            f"limit is {args.max_zone_image_fallbacks}"
        )
    if args.require_direct_and_semantic:
        if zone_image_direct_hits <= 0:
            failures.append(
                "ZoneImage artifact did not record any direct-answer served hits"
            )
        if zone_image_semantic_hits <= 0:
            failures.append(
                "ZoneImage artifact did not record any semantic-plan served hits"
            )

    qps_ratio = ratio(number(zone_image, "responses_per_second"), number(current, "responses_per_second"))
    p50_ratio = ratio(number(zone_image, "latency_us_p50"), number(current, "latency_us_p50"))
    p99_ratio = ratio(number(zone_image, "latency_us_p99"), number(current, "latency_us_p99"))
    p999_ratio = ratio(number(zone_image, "latency_us_p999"), number(current, "latency_us_p999"))

    if qps_ratio < args.min_qps_ratio:
        failures.append(
            f"responses/s ratio {qps_ratio:.3f} is below minimum {args.min_qps_ratio:.3f}"
        )
    if args.max_p50_ratio is not None and p50_ratio > args.max_p50_ratio:
        failures.append(f"p50 ratio {p50_ratio:.3f} exceeds maximum {args.max_p50_ratio:.3f}")
    if args.max_p99_ratio is not None and p99_ratio > args.max_p99_ratio:
        failures.append(f"p99 ratio {p99_ratio:.3f} exceeds maximum {args.max_p99_ratio:.3f}")
    if args.max_p999_ratio is not None and p999_ratio > args.max_p999_ratio:
        failures.append(f"p999 ratio {p999_ratio:.3f} exceeds maximum {args.max_p999_ratio:.3f}")

    rows = [
        ("status", "failed" if failures else "passed"),
        ("current_artifact", artifact_dir(args.current).as_posix()),
        ("zone_image_artifact", artifact_dir(args.zone_image).as_posix()),
        ("git_revision", optional_value(current, "git_revision")),
        ("git_dirty", optional_value(current, "git_dirty")),
        ("kernel_version", optional_value(current, "kernel_version")),
        ("rustc_version", optional_value(current, "rustc_version")),
        ("cargo_version", optional_value(current, "cargo_version")),
        ("build_profile", optional_value(current, "build_profile")),
        ("server_bin_sha256", optional_value(current, "server_bin_sha256")),
        ("client_bin_sha256", optional_value(current, "client_bin_sha256")),
        ("remote_client_bin_sha256", optional_value(current, "remote_client_bin_sha256")),
        ("transport", value(current, "transport")),
        ("query_mode", value(current, "query_mode")),
        ("trace_queries", value(current, "trace_queries")),
        ("trace_sha256_match", str(trace_match).lower()),
        ("records_configured", value(current, "records_configured")),
        ("stress_candidates_configured", value(current, "stress_candidates_configured")),
        ("network_device", value(current, "network_device")),
        ("zone_image_network_device", value(zone_image, "network_device")),
        ("client_mode", value(current, "client_mode")),
        ("remote_client_ssh", value(current, "remote_client_ssh")),
        ("remote_client_local_arch", optional_value(current, "remote_client_local_arch")),
        ("remote_client_remote_arch", optional_value(current, "remote_client_remote_arch")),
        ("remote_client_local_host_id", optional_value(current, "remote_client_local_host_id")),
        ("remote_client_remote_host_id", optional_value(current, "remote_client_remote_host_id")),
        ("remote_client_same_host", optional_value(current, "remote_client_same_host")),
        (
            "remote_client_allow_arch_mismatch",
            optional_value(current, "remote_client_allow_arch_mismatch"),
        ),
        ("current_responses_per_second", value(current, "responses_per_second")),
        ("zone_image_responses_per_second", value(zone_image, "responses_per_second")),
        ("responses_per_second_ratio", f"{qps_ratio:.3f}"),
        ("current_latency_us_p50", value(current, "latency_us_p50")),
        ("zone_image_latency_us_p50", value(zone_image, "latency_us_p50")),
        ("latency_us_p50_ratio", f"{p50_ratio:.3f}"),
        ("current_latency_us_p99", value(current, "latency_us_p99")),
        ("zone_image_latency_us_p99", value(zone_image, "latency_us_p99")),
        ("latency_us_p99_ratio", f"{p99_ratio:.3f}"),
        ("current_latency_us_p999", value(current, "latency_us_p999")),
        ("zone_image_latency_us_p999", value(zone_image, "latency_us_p999")),
        ("latency_us_p999_ratio", f"{p999_ratio:.3f}"),
        ("current_dropped", value(current, "dropped")),
        ("zone_image_dropped", value(zone_image, "dropped")),
        ("current_errors", value(current, "errors")),
        ("zone_image_errors", value(zone_image, "errors")),
        ("current_zone_image_serve_hits", str(current_zone_image_hits)),
        ("zone_image_serve_hits", str(zone_image_hits)),
        ("current_zone_image_serve_direct_hits", str(current_zone_image_direct_hits)),
        ("zone_image_serve_direct_hits", str(zone_image_direct_hits)),
        ("current_zone_image_serve_semantic_hits", str(current_zone_image_semantic_hits)),
        ("zone_image_serve_semantic_hits", str(zone_image_semantic_hits)),
        ("current_zone_image_serve_fallbacks", str(current_zone_image_fallbacks)),
        ("zone_image_serve_fallbacks", str(zone_image_fallbacks)),
        ("max_zone_image_fallbacks", str(args.max_zone_image_fallbacks)),
        ("direct_and_semantic_checked", str(args.require_direct_and_semantic).lower()),
        ("network_counter_deltas_checked", str(args.require_non_loopback).lower()),
        (
            "min_network_packets_per_response",
            f"{args.min_network_packets_per_response:.3f}",
        ),
    ]
    if args.require_non_loopback:
        current_estimated_responses = number(current, "responses_per_second") * number(
            current, "duration_seconds"
        )
        zone_image_estimated_responses = number(
            zone_image, "responses_per_second"
        ) * number(zone_image, "duration_seconds")
        rows.extend(
            [
                ("current_estimated_responses", f"{current_estimated_responses:.3f}"),
                ("current_network_rx_packets_delta", str(current_network_deltas.get("rx_packets", 0))),
                ("current_network_tx_packets_delta", str(current_network_deltas.get("tx_packets", 0))),
                (
                    "current_network_rx_packets_per_response",
                    format_per_response(
                        current_network_deltas.get("rx_packets", 0),
                        current_estimated_responses,
                    ),
                ),
                (
                    "current_network_tx_packets_per_response",
                    format_per_response(
                        current_network_deltas.get("tx_packets", 0),
                        current_estimated_responses,
                    ),
                ),
                ("current_network_rx_bytes_delta", str(current_network_deltas.get("rx_bytes", 0))),
                ("current_network_tx_bytes_delta", str(current_network_deltas.get("tx_bytes", 0))),
                ("current_network_rx_drop_delta", str(current_network_deltas.get("rx_drop", 0))),
                ("current_network_tx_drop_delta", str(current_network_deltas.get("tx_drop", 0))),
                ("current_network_rx_errs_delta", str(current_network_deltas.get("rx_errs", 0))),
                ("current_network_tx_errs_delta", str(current_network_deltas.get("tx_errs", 0))),
                ("zone_image_estimated_responses", f"{zone_image_estimated_responses:.3f}"),
                ("zone_image_network_rx_packets_delta", str(zone_image_network_deltas.get("rx_packets", 0))),
                ("zone_image_network_tx_packets_delta", str(zone_image_network_deltas.get("tx_packets", 0))),
                (
                    "zone_image_network_rx_packets_per_response",
                    format_per_response(
                        zone_image_network_deltas.get("rx_packets", 0),
                        zone_image_estimated_responses,
                    ),
                ),
                (
                    "zone_image_network_tx_packets_per_response",
                    format_per_response(
                        zone_image_network_deltas.get("tx_packets", 0),
                        zone_image_estimated_responses,
                    ),
                ),
                ("zone_image_network_rx_bytes_delta", str(zone_image_network_deltas.get("rx_bytes", 0))),
                ("zone_image_network_tx_bytes_delta", str(zone_image_network_deltas.get("tx_bytes", 0))),
                ("zone_image_network_rx_drop_delta", str(zone_image_network_deltas.get("rx_drop", 0))),
                ("zone_image_network_tx_drop_delta", str(zone_image_network_deltas.get("tx_drop", 0))),
                ("zone_image_network_rx_errs_delta", str(zone_image_network_deltas.get("rx_errs", 0))),
                ("zone_image_network_tx_errs_delta", str(zone_image_network_deltas.get("tx_errs", 0))),
            ]
        )
    rows.extend((f"failure_{index}", failure) for index, failure in enumerate(failures, start=1))
    emit(rows, args.output)

    if failures:
        for failure in failures:
            print(f"comparison failure: {failure}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
