#!/usr/bin/env python3
"""Summarize physical benchmark summary.tsv by allowed requester loss bands."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


DEFAULT_BANDS = (0.0, 1.0, 2.0, 3.0, 5.0, 10.0)


def parse_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def summarize(rows: list[dict[str, str]], bands: tuple[float, ...]) -> list[dict[str, str]]:
    targets = sorted({row.get("target", "") for row in rows if row.get("target")})
    out: list[dict[str, str]] = []
    for target in targets:
        target_rows = [row for row in rows if row.get("target") == target]
        for band in bands:
            candidates = []
            for row in target_rows:
                reply_percent = parse_float(row.get("reply_percent", ""))
                loss_percent = max(0.0, 100.0 - reply_percent)
                if loss_percent <= band:
                    candidates.append((parse_int(row.get("replies_per_second", "")), loss_percent, row))
            if not candidates:
                out.append(
                    {
                        "target": target,
                        "allowed_loss_percent": format_band(band),
                        "rate": "",
                        "replies_per_second": "",
                        "reply_percent": "",
                        "loss_percent": "",
                        "server_udp_backend": "",
                        "workers": "",
                        "player_tool": "",
                    }
                )
                continue
            replies_per_second, loss_percent, row = max(candidates, key=lambda item: item[0])
            out.append(
                {
                    "target": target,
                    "allowed_loss_percent": format_band(band),
                    "rate": row.get("rate", ""),
                    "replies_per_second": str(replies_per_second),
                    "reply_percent": row.get("reply_percent", ""),
                    "loss_percent": f"{loss_percent:.6f}",
                    "server_udp_backend": row.get("server_udp_backend", ""),
                    "workers": row.get("workers", ""),
                    "player_tool": row.get("player_tool", ""),
                }
            )
    return out


def format_band(value: float) -> str:
    if value == 0.0:
        return "0"
    if value.is_integer():
        return str(int(value))
    return str(value)


def write_tsv(rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "target",
        "allowed_loss_percent",
        "rate",
        "replies_per_second",
        "reply_percent",
        "loss_percent",
        "server_udp_backend",
        "workers",
        "player_tool",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument(
        "--bands",
        default=",".join(format_band(band) for band in DEFAULT_BANDS),
        help="Comma-separated allowed loss percentages.",
    )
    args = parser.parse_args()

    bands = tuple(parse_float(part) for part in args.bands.split(",") if part.strip())
    write_tsv(summarize(load_rows(args.summary), bands))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
