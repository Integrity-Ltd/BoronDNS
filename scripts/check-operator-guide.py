#!/usr/bin/env python3
"""Check that the Operator Deployment Guide covers required SRS v0.7 topics."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "operator-deployment-guide.md"

REQUIRED_TEXT = [
    "## Service Level Objectives",
    "ODS-NFR-MAINT-009",
    "native process",
    "OCI-compatible container",
    "VM image",
    "single-zone single-primary",
    "multi-zone multi-primary",
    "TSIG-protected",
    "XoT-protected",
    "DNSSEC-served",
    "Prometheus",
    "Grafana",
    "ICMP",
    "firewall",
    "clock synchronisation",
    "long-LOADING",
    "soak-handoff",
    "privilege",
    "security@integrity.hu",
    "ODS-FR-XOT-012",
]

SLO_TEXT = [
    "ODS-NFR-PERF-001",
    "ODS-NFR-PERF-002",
    "ODS-NFR-PERF-003",
    "ODS-NFR-REL-003",
    "ODS-NFR-REL-005",
    "ODS-NFR-REL-007",
]


def fail(message: str) -> None:
    print(f"Operator guide check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    for needle in REQUIRED_TEXT + SLO_TEXT:
        if needle not in text:
            fail(f"{GUIDE} missing required text: {needle}")
    print(f"Operator guide check passed: {GUIDE}")


if __name__ == "__main__":
    main()
