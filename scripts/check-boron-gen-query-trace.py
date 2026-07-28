#!/usr/bin/env python3
"""Regression checks for BoronGen performance trace generation."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate-boron-gen-query-trace.py")
SPEC = importlib.util.spec_from_file_location("boron_gen_trace", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot import {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def query_rows(profile: str, zones: int = 1) -> list[str]:
    return [
        row
        for row in MODULE.generate(
            profile=profile,
            origin="perf.borongen.",
            zones=zones,
            names_per_zone=1_000,
            sample_count=16,
            hot_count=8,
            negative_count=8,
        )
        if row and not row.startswith("#")
    ]


def main() -> int:
    first = query_rows("registry-nsec3", zones=4)
    second = query_rows("registry-nsec3", zones=4)
    if first != second:
        raise SystemExit("trace generation is not deterministic")
    if not any("z0000000000000003.perf.borongen." in row for row in first):
        raise SystemExit("multi-zone trace did not cover the final member zone")
    if not any(" NS IN do rcode=NOERROR answers=0 " in row for row in first):
        raise SystemExit("registry trace lacks delegation lookups")
    if not any("rcode=NXDOMAIN answers=0 nsec_negative" in row for row in first):
        raise SystemExit("registry trace lacks DNSSEC negative lookups")
    bounded = MODULE.generate(
        profile="registry-nsec3",
        origin="tiny.borongen.",
        zones=2,
        names_per_zone=3,
        sample_count=256,
        hot_count=1,
        negative_count=1,
    )
    bounded_spread = [row for row in bounded if "spread_delegation" in row]
    if len(bounded_spread) != 6:
        raise SystemExit("finite small-zone trace was not capped at six unique pairs")

    mixed = query_rows("mixed")
    if not any(" A IN do rcode=NOERROR answers=1 " in row for row in mixed):
        raise SystemExit("mixed trace lacks positive A lookups")
    if not any(" AAAA IN do rcode=NOERROR answers=1 " in row for row in mixed):
        raise SystemExit("mixed trace lacks positive AAAA lookups")
    if not any(" TXT IN do rcode=NOERROR answers=1 " in row for row in mixed):
        raise SystemExit("mixed trace lacks positive TXT lookups")

    wide = query_rows("large-rrset")
    if not any("wide_rrset" in row and "answers=0" in row for row in wide):
        raise SystemExit("large-RRset trace does not permit a truncated UDP answer")
    for row in first + mixed + wide:
        fields = row.split()
        if len(fields) < 7:
            raise SystemExit(f"malformed trace row: {row}")
        if not fields[0].endswith("."):
            raise SystemExit(f"non-absolute query name: {row}")
    print("BoronGen query trace checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
