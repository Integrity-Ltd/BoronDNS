#!/usr/bin/env python3
"""Check that the documented RRL release baseline matches SRS/config defaults."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "borondns.example.toml"
SRS = ROOT / "docs" / "BoronDNS-Secondary-SRS-v0.9.1.md"
DECISION_REGISTER = ROOT / "docs" / "project-decision-register.md"
DOC = ROOT / "docs" / "rrl-release-thresholds.md"

EXPECTED = {
    "enabled": "true",
    "ipv4_prefix_len": "24",
    "ipv6_prefix_len": "56",
    "positive_per_second": "20",
    "nxdomain_per_second": "5",
    "nodata_per_second": "10",
    "referral_per_second": "10",
    "error_per_second": "5",
    "slip": "2",
    "max_keys": "100000",
    "summary_log_interval_secs": "60",
}

DOC_NEEDLES = {
    "enabled": "| RRL enabled | `true` | ODS-FR-RRL-001 |",
    "ipv4_prefix_len": "| IPv4 source prefix length | `24` | ODS-FR-RRL-002 |",
    "ipv6_prefix_len": "| IPv6 source prefix length | `56` | ODS-FR-RRL-002 |",
    "positive_per_second": "| Positive response rate | `20/s` | ODS-FR-RRL-003 |",
    "nxdomain_per_second": "| NXDOMAIN response rate | `5/s` | ODS-FR-RRL-003 |",
    "nodata_per_second": "| NODATA response rate | `10/s` | ODS-FR-RRL-003 |",
    "referral_per_second": "| Referral response rate | `10/s` | ODS-FR-RRL-003 |",
    "error_per_second": "| Error response rate | `5/s` | ODS-FR-RRL-003 |",
    "slip": "| Slip | `2` | ODS-FR-RRL-005 |",
    "max_keys": "| Maximum tracked keys | `100000` | ODS-FR-RRL-010 |",
    "summary_log_interval_secs": "| Summary log interval | `60s` | ODS-FR-RRL-011 |",
}

SRS_NEEDLES = {
    "positive_per_second": "positive responses: 20 responses per second",
    "nxdomain_per_second": "NXDOMAIN responses: 5 responses per second",
    "nodata_per_second": "NODATA responses: 10 responses per second",
    "referral_per_second": "referral responses: 10 responses per second",
    "error_per_second": "error responses: 5 responses per second",
    "slip": "default value 2",
    "max_keys": "default of 100000",
    "summary_log_interval_secs": "default 60 seconds",
}

DECISION_REGISTER_NEEDLES = {
    "c5_resolved_slip": "Resolved (v0.9.1): `rrl.slip` default is 2",
}

DOC_STATUS_NEEDLES = [
    "SRS Appendix C.5 resolves the `Slip = 2` default in v0.9.1",
    "Resolved SRS v0.9.1 default; retain operational evidence before formal acceptance",
]

STALE_DOC_NEEDLES = [
    "C.5 confirmation pending",
    "Appendix C.5 pending decision for `Slip = 2`",
    "release notes must continue to list that item as pending",
]


def fail(message: str) -> None:
    print(f"RRL threshold check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_toml_scalar(text: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}\s*=\s*(.+?)\s*$", text)
    if not match:
        fail(f"{CONFIG} missing {key}")
    return match.group(1).strip().strip('"')


def main() -> None:
    config = CONFIG.read_text(encoding="utf-8")
    srs = SRS.read_text(encoding="utf-8")
    decision_register = DECISION_REGISTER.read_text(encoding="utf-8")
    doc = DOC.read_text(encoding="utf-8")

    for key, expected in EXPECTED.items():
        actual = extract_toml_scalar(config, key)
        if actual != expected:
            fail(f"{CONFIG}:{key} is {actual!r}, expected {expected!r}")

    for key, needle in DOC_NEEDLES.items():
        if needle not in doc:
            fail(f"{DOC} missing baseline row for {key}: {needle}")

    for needle in DOC_STATUS_NEEDLES:
        if needle not in doc:
            fail(f"{DOC} missing current RRL decision status text: {needle}")

    for needle in STALE_DOC_NEEDLES:
        if needle in doc:
            fail(f"{DOC} contains stale RRL decision status text: {needle}")

    for key, needle in SRS_NEEDLES.items():
        if needle not in srs:
            fail(f"{SRS} missing expected SRS text for {key}: {needle}")

    for key, needle in DECISION_REGISTER_NEEDLES.items():
        if needle not in decision_register:
            fail(f"{DECISION_REGISTER} missing expected decision text for {key}: {needle}")

    print(f"RRL threshold baseline check passed: {DOC}")


if __name__ == "__main__":
    main()
