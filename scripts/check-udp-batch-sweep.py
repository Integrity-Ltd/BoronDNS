#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
from pathlib import Path


REQUIRED_COLUMNS = (
    "udp_batch_size",
    "artifact_dir",
    "responses_per_second",
    "qps_ratio_to_baseline",
    "latency_us_p50",
    "p50_ratio_to_baseline",
    "latency_us_p99",
    "p99_ratio_to_baseline",
    "dropped",
    "errors",
    "udp_receive_batches",
    "udp_received_datagrams",
    "receive_datagrams_per_batch",
    "udp_send_batches",
    "udp_sent_datagrams",
    "send_datagrams_per_batch",
    "zone_image_serve_hits",
    "zone_image_serve_direct_hits",
    "zone_image_serve_semantic_hits",
    "zone_image_serve_failures",
    "network_device",
    "network_rx_packets_delta",
    "network_tx_packets_delta",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_summary(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        fail(f"UDP batch sweep summary not found: {path}")
    with path.open(encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header != list(REQUIRED_COLUMNS):
            fail(
                f"{path}: unexpected header; expected "
                + ",".join(REQUIRED_COLUMNS)
            )
        rows: list[dict[str, str]] = []
        for line_number, line in enumerate(handle, start=2):
            fields = line.rstrip("\n").split("\t")
            if len(fields) != len(header):
                fail(
                    f"{path}:{line_number}: expected {len(header)} tab-separated fields, "
                    f"got {len(fields)}"
                )
            rows.append(dict(zip(header, fields, strict=True)))
    return rows


def integer(row: dict[str, str], key: str) -> int:
    raw = row[key]
    try:
        return int(raw)
    except ValueError:
        fail(f"metric {key!r} is not an integer: {raw!r}")


def number(row: dict[str, str], key: str) -> float:
    raw = row[key]
    try:
        value = float(raw)
    except ValueError:
        fail(f"metric {key!r} is not numeric: {raw!r}")
    if not math.isfinite(value):
        fail(f"metric {key!r} is not finite: {raw!r}")
    return value


def append_ratio_check(
    output: list[tuple[str, str]],
    failures: list[str],
    name: str,
    observed: str,
    numerator: float,
    baseline: float,
) -> None:
    expected = numerator / baseline
    try:
        actual = float(observed)
    except ValueError:
        failures.append(f"{name} ratio is not numeric: {observed!r}")
        return
    output.append((f"{name}_expected", f"{expected:.3f}"))
    output.append((f"{name}_observed", f"{actual:.3f}"))
    if abs(actual - expected) > 0.002:
        failures.append(
            f"{name} ratio {actual:.3f} does not match recomputed {expected:.3f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate retained BoronDNS UDP batch sweep summary TSV."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-dropped", type=int, default=0)
    parser.add_argument("--max-errors", type=int, default=0)
    parser.add_argument("--max-zone-image-failures", type=int, default=0)
    args = parser.parse_args()

    rows = read_summary(args.input)
    failures: list[str] = []
    output: list[tuple[str, str]] = []
    if len(rows) < 2:
        failures.append("sweep summary must contain at least two batch-size rows")

    batch_sizes = [integer(row, "udp_batch_size") for row in rows]
    if any(batch_size <= 0 for batch_size in batch_sizes):
        failures.append("all UDP batch sizes must be positive")
    if len(set(batch_sizes)) != len(batch_sizes):
        failures.append("UDP batch sizes must be unique")
    if batch_sizes != sorted(batch_sizes):
        failures.append("UDP batch sizes must be sorted ascending")

    baseline = rows[0]
    baseline_batch = integer(baseline, "udp_batch_size")
    baseline_qps = number(baseline, "responses_per_second")
    baseline_p50 = number(baseline, "latency_us_p50")
    baseline_p99 = number(baseline, "latency_us_p99")
    baseline_receive_per_batch = number(baseline, "receive_datagrams_per_batch")
    baseline_send_per_batch = number(baseline, "send_datagrams_per_batch")

    output.append(("row_count", str(len(rows))))
    output.append(("baseline_udp_batch_size", str(baseline_batch)))
    output.append(("max_udp_batch_size", str(max(batch_sizes))))
    output.append(("baseline_responses_per_second", f"{baseline_qps:.3f}"))

    batching_gain_rows = 0
    for index, row in enumerate(rows):
        batch_size = batch_sizes[index]
        responses_per_second = number(row, "responses_per_second")
        p50 = number(row, "latency_us_p50")
        p99 = number(row, "latency_us_p99")
        receive_batches = integer(row, "udp_receive_batches")
        received_datagrams = integer(row, "udp_received_datagrams")
        send_batches = integer(row, "udp_send_batches")
        sent_datagrams = integer(row, "udp_sent_datagrams")
        receive_per_batch = number(row, "receive_datagrams_per_batch")
        send_per_batch = number(row, "send_datagrams_per_batch")
        dropped = integer(row, "dropped")
        errors = integer(row, "errors")
        zone_image_hits = integer(row, "zone_image_serve_hits")
        zone_image_direct = integer(row, "zone_image_serve_direct_hits")
        zone_image_semantic = integer(row, "zone_image_serve_semantic_hits")
        zone_image_failures = integer(row, "zone_image_serve_failures")

        row_prefix = f"batch_{batch_size}"
        if responses_per_second <= 0:
            failures.append(f"{row_prefix} responses_per_second must be positive")
        if p50 <= 0 or p99 <= 0:
            failures.append(f"{row_prefix} latency percentiles must be positive")
        if p99 < p50:
            failures.append(f"{row_prefix} p99 latency is lower than p50 latency")
        if dropped > args.max_dropped:
            failures.append(
                f"{row_prefix} dropped {dropped} responses, limit is {args.max_dropped}"
            )
        if errors > args.max_errors:
            failures.append(
                f"{row_prefix} errors {errors} responses, limit is {args.max_errors}"
            )
        if zone_image_failures > args.max_zone_image_failures:
            failures.append(
                f"{row_prefix} ZoneImage failures {zone_image_failures}, "
                f"limit is {args.max_zone_image_failures}"
            )
        if zone_image_hits <= 0:
            failures.append(f"{row_prefix} ZoneImage serve hits must be positive")
        if zone_image_direct + zone_image_semantic > zone_image_hits:
            failures.append(
                f"{row_prefix} direct+semantic ZoneImage hits exceed total hits"
            )
        if received_datagrams <= 0 or sent_datagrams <= 0:
            failures.append(f"{row_prefix} UDP datagram counters must be positive")
        if receive_batches <= 0 or send_batches <= 0:
            failures.append(f"{row_prefix} UDP batch counters must be positive")
        append_ratio_check(
            output,
            failures,
            f"{row_prefix}_qps",
            row["qps_ratio_to_baseline"],
            responses_per_second,
            baseline_qps,
        )
        append_ratio_check(
            output,
            failures,
            f"{row_prefix}_p50",
            row["p50_ratio_to_baseline"],
            p50,
            baseline_p50,
        )
        append_ratio_check(
            output,
            failures,
            f"{row_prefix}_p99",
            row["p99_ratio_to_baseline"],
            p99,
            baseline_p99,
        )
        append_ratio_check(
            output,
            failures,
            f"{row_prefix}_receive_datagrams_per_batch",
            row["receive_datagrams_per_batch"],
            float(received_datagrams),
            float(receive_batches),
        )
        append_ratio_check(
            output,
            failures,
            f"{row_prefix}_send_datagrams_per_batch",
            row["send_datagrams_per_batch"],
            float(sent_datagrams),
            float(send_batches),
        )
        if batch_size > baseline_batch and (
            receive_per_batch > baseline_receive_per_batch
            and send_per_batch > baseline_send_per_batch
        ):
            batching_gain_rows += 1

    output.append(("batching_gain_rows", str(batching_gain_rows)))
    if batching_gain_rows == 0:
        failures.append(
            "no non-baseline row increased both receive and send datagrams per batch"
        )

    output_rows = [("status", "failed" if failures else "passed"), *output]
    if failures:
        output_rows.extend((f"failure_{index}", failure) for index, failure in enumerate(failures, start=1))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            handle.write("metric\tvalue\n")
            for key, value in output_rows:
                handle.write(f"{key}\t{value}\n")

    if failures:
        raise SystemExit(
            "UDP batch sweep check failed: " + "; ".join(failures)
        )

    print(f"udp_batch_sweep_check={args.output or 'passed'}")


if __name__ == "__main__":
    main()
