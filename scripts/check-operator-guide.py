#!/usr/bin/env python3
"""Check that the Operator Deployment Guide covers required SRS v0.9.1 topics."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "operator-deployment-guide.md"
CLI_MAIN = ROOT / "crates" / "oxidedns-cli" / "src" / "main.rs"

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
    "info-verbosity-handoff",
    "benchmark-handoff",
    "soak-handoff",
    "release-handoff",
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
    "Suggested operational SLOs",
    "formal release/operations targets",
    "bounded local Engineering MVP has completed those long-running runs",
]

FORBIDDEN_TEXT = [
    "Suggested Engineering MVP SLOs",
    "scripts that double as Engineering MVP and SRS acceptance evidence collection commands",
]


def fail(message: str) -> None:
    print(f"Operator guide check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    for needle in FORBIDDEN_TEXT:
        if needle in text:
            fail(f"{GUIDE} contains stale wording: {needle}")
    for needle in REQUIRED_TEXT + SLO_TEXT:
        if needle not in text:
            fail(f"{GUIDE} missing required text: {needle}")
    cli_text = CLI_MAIN.read_text(encoding="utf-8")
    for env_name in sorted(set(re.findall(r'"(ODS_[A-Z0-9_]+)"\s*=>', cli_text))):
        if env_name not in text:
            fail(f"{GUIDE} missing documented environment override: {env_name}")
    print(f"Operator guide check passed: {GUIDE}")


if __name__ == "__main__":
    main()
