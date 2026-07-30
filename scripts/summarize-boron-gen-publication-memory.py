#!/usr/bin/env python3
"""Join structured publication phases to bounded-load cgroup samples."""

from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import json
import pathlib
import sys
from typing import Any


OUTPUT_FIELDS = [
    "timestamp_utc",
    "phase_unix_seconds",
    "zone",
    "event",
    "phase",
    "rrset_count",
    "record_count",
    "build_node_count",
    "node_count",
    "edge_count",
    "name_arena_bytes",
    "rdata_arena_bytes",
    "wire_arena_bytes",
    "nsec_range_count",
    "nsec3_range_count",
    "relation_count",
    "hot_bytes",
    "cold_bytes",
    "sample_unix_seconds",
    "sample_offset_seconds",
    "memory_current",
    "memory_peak",
    "memory_high",
    "memory_max",
    "active_state",
    "sub_state",
]

PHASE_EVENTS = {
    "zone_image_build_phase",
    "zone_store_publication_phase",
    "zone_transfer_publication_phase",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--journal", required=True, type=pathlib.Path)
    parser.add_argument("--samples", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args()


def parse_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp has no timezone: {value!r}")
    return parsed.astimezone(dt.timezone.utc)


def structured_payload(line: str) -> dict[str, Any] | None:
    offset = line.find("{")
    if offset < 0:
        return None
    try:
        payload = json.loads(line[offset:])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def load_phases(path: pathlib.Path) -> list[dict[str, Any]]:
    phases = []
    with path.open(encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, 1):
            payload = structured_payload(line)
            if payload is None:
                continue
            fields = payload.get("fields", payload)
            if not isinstance(fields, dict) or fields.get("event") not in PHASE_EVENTS:
                continue
            timestamp_text = payload.get("timestamp")
            phase = fields.get("phase")
            if not isinstance(timestamp_text, str) or not isinstance(phase, str):
                raise ValueError(
                    f"{path}:{line_number}: publication phase lacks timestamp or phase"
                )
            timestamp = parse_timestamp(timestamp_text)
            phases.append(
                {
                    "_timestamp": timestamp,
                    "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
                    "phase_unix_seconds": int(timestamp.timestamp()),
                    **fields,
                }
            )
    phases.sort(key=lambda item: item["_timestamp"])
    return phases


def load_samples(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source, delimiter="\t")
        required = {
            "unix_seconds",
            "memory_current",
            "memory_peak",
            "memory_high",
            "memory_max",
            "active_state",
            "sub_state",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError(f"{path}: resource-sample header is incomplete")
        samples = [row for row in reader if row["unix_seconds"].isdigit()]
    samples.sort(key=lambda row: int(row["unix_seconds"]))
    if not samples:
        raise ValueError(f"{path}: no usable resource samples")
    return samples


def nearest_sample(
    phase_unix: int, samples: list[dict[str, str]], sample_times: list[int]
) -> dict[str, str]:
    insertion = bisect.bisect_left(sample_times, phase_unix)
    candidates = []
    if insertion < len(samples):
        candidates.append(samples[insertion])
    if insertion > 0:
        candidates.append(samples[insertion - 1])
    return min(
        candidates,
        key=lambda sample: (
            abs(int(sample["unix_seconds"]) - phase_unix),
            int(sample["unix_seconds"]) > phase_unix,
        ),
    )


def output_rows(
    path: pathlib.Path,
    phases: list[dict[str, Any]],
    samples: list[dict[str, str]],
) -> None:
    sample_times = [int(sample["unix_seconds"]) for sample in samples]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            delimiter="\t",
            fieldnames=OUTPUT_FIELDS,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for phase in phases:
            sample = nearest_sample(
                int(phase["phase_unix_seconds"]), samples, sample_times
            )
            row = dict(phase)
            row.update(
                {
                    "sample_unix_seconds": sample["unix_seconds"],
                    "sample_offset_seconds": int(sample["unix_seconds"])
                    - int(phase["phase_unix_seconds"]),
                    "memory_current": sample["memory_current"],
                    "memory_peak": sample["memory_peak"],
                    "memory_high": sample["memory_high"],
                    "memory_max": sample["memory_max"],
                    "active_state": sample["active_state"],
                    "sub_state": sample["sub_state"],
                }
            )
            writer.writerow({field: row.get(field, "") for field in OUTPUT_FIELDS})


def main() -> int:
    args = parse_args()
    phases = load_phases(args.journal)
    samples = load_samples(args.samples)
    output_rows(args.output, phases, samples)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
