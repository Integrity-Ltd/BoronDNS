#!/usr/bin/env python3
"""Generate deterministic dns-load-client traces for BoronGen zones."""

from __future__ import annotations

import argparse
import math
import sys


PROFILES = ("registry-nsec3", "mixed", "large-rrset")


def absolute_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("DNS name must not be empty")
    return value if value.endswith(".") else f"{value}."


def positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def zone_origin(origin: str, zones: int, zone_index: int) -> str:
    if zones == 1:
        return origin
    return f"z{zone_index:016x}.{origin}"


def sampled_pairs(zones: int, names: int, count: int) -> list[tuple[int, int]]:
    total = zones * names
    count = min(count, total)
    pairs: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    edges = (
        (0, 0),
        (zones - 1, names - 1),
        (zones // 2, names // 2),
        (0, names - 1),
        (zones - 1, 0),
    )
    for pair in edges:
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
        if len(pairs) == count:
            return pairs
    step = max(1, 0x9E3779B185EBCA87 % total)
    while math.gcd(step, total) != 1:
        step += 1
    candidate = 0
    while len(pairs) < count:
        linear = (candidate * step) % total
        zone_index, name_index = divmod(linear, names)
        pair = (zone_index, name_index)
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
        candidate += 1
    return pairs


def positive_row(profile: str, owner: str, label: str) -> str:
    if profile == "registry-nsec3":
        return f"{owner} NS IN do rcode=NOERROR answers=0 {label}_delegation"
    if profile == "mixed":
        return f"{owner} A IN do rcode=NOERROR answers=1 {label}_mixed_a"
    return f"{owner} A IN do rcode=NOERROR answers=0 {label}_wide_rrset"


def generate(
    *,
    profile: str,
    origin: str,
    zones: int,
    names_per_zone: int,
    sample_count: int,
    hot_count: int,
    negative_count: int,
) -> list[str]:
    pairs = sampled_pairs(zones, names_per_zone, sample_count)
    first_zone = zone_origin(origin, zones, 0)
    first_owner = f"n{0:016x}.{first_zone}"
    lines = [
        "# BoronGen deterministic query trace",
        (
            f"# profile={profile} origin={origin} zones={zones} "
            f"names_per_zone={names_per_zone}"
        ),
        "# qname qtype qclass edns expected label",
    ]
    lines.extend(
        positive_row(profile, first_owner, "hot") for _ in range(hot_count)
    )
    for zone_index, name_index in pairs:
        member = zone_origin(origin, zones, zone_index)
        owner = f"n{name_index:016x}.{member}"
        lines.append(positive_row(profile, owner, "spread"))
        if profile == "registry-nsec3":
            lines.append(
                f"a.{owner} A IN do rcode=NOERROR answers=0 spread_glue_referral"
            )
        elif profile == "mixed":
            lines.append(
                f"{owner} AAAA IN do rcode=NOERROR answers=1 spread_mixed_aaaa"
            )
            lines.append(
                f"{owner} TXT IN do rcode=NOERROR answers=1 spread_mixed_txt"
            )
    for index in range(negative_count):
        zone_index = (index * 0x9E3779B1) % zones
        member = zone_origin(origin, zones, zone_index)
        lines.append(
            f"missing{index:016x}.{member} A IN do "
            "rcode=NXDOMAIN answers=0 nsec_negative"
        )
    lines.append(f"{first_zone} SOA IN do rcode=NOERROR answers=1 apex_soa")
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--origin", required=True, type=absolute_name)
    parser.add_argument("--zones", required=True, type=positive)
    parser.add_argument("--names-per-zone", required=True, type=positive)
    parser.add_argument("--sample-count", type=positive, default=256)
    parser.add_argument("--hot-count", type=positive, default=128)
    parser.add_argument("--negative-count", type=positive, default=128)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lines = generate(
        profile=args.profile,
        origin=args.origin,
        zones=args.zones,
        names_per_zone=args.names_per_zone,
        sample_count=args.sample_count,
        hot_count=args.hot_count,
        negative_count=args.negative_count,
    )
    sys.stdout.write("\n".join(lines))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
