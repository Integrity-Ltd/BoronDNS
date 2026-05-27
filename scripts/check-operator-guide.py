#!/usr/bin/env python3
"""Check that the Operator Deployment Guide covers required SRS v0.9.1 topics."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "operator-deployment-guide.md"
RELEASE_GUIDE = ROOT / "docs" / "release-evidence-guide.md"
SLO_GUIDE = ROOT / "docs" / "operational-slos.md"
DEBIAN_PROFILE = ROOT / "docs" / "debian12-beta-vm-profile.md"
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
    "release-evidence-guide.md",
    "privilege",
    "security@integrity.hu",
    "ODS-FR-XOT-012",
    "docs/operational-slos.md",
    "debian12-beta-vm-profile.md",
]

RELEASE_GUIDE_TEXT = [
    "scripts/release-evidence-snapshot.sh",
    "scripts/engineering-mvp-evidence.sh",
    "info-verbosity-handoff",
    "benchmark-handoff",
    "soak-handoff",
    "release-handoff",
    "reproducible-build-handoff",
    "OXIDEDNS_EVIDENCE_RUN_FUZZ",
    "OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN",
    "OXIDEDNS_EVIDENCE_RUN_INTEROP",
    "OXIDEDNS_RELEASE_NOTES",
    "OXIDEDNS_PERF_BASELINE",
    "ODS-VER-008",
    "ODS-VER-015",
]

SLO_TEXT = [
    "informative operator SLO publication",
    "ODS-NFR-PERF-001",
    "ODS-NFR-PERF-002",
    "ODS-NFR-PERF-003",
    "ODS-NFR-REL-003",
    "ODS-NFR-REL-005",
    "ODS-NFR-REL-007",
    "Suggested Operational SLOs",
    "formal release/operations targets",
    "bounded local Engineering MVP has completed those long-running runs",
]

DEBIAN_PROFILE_TEXT = [
    "Debian 12 beta-test VM",
    "Docker CE",
    "nftables",
    "fail2ban",
    "docker load",
    "--network host",
    "CAP_NET_BIND_SERVICE",
    "OXIDEDNS_DOCKER_ALPINE_VERSION",
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
    release_text = RELEASE_GUIDE.read_text(encoding="utf-8")
    slo_text = SLO_GUIDE.read_text(encoding="utf-8")
    debian_profile_text = DEBIAN_PROFILE.read_text(encoding="utf-8")
    for needle in FORBIDDEN_TEXT:
        if needle in text:
            fail(f"{GUIDE} contains stale wording: {needle}")
    for needle in REQUIRED_TEXT:
        if needle not in text:
            fail(f"{GUIDE} missing required text: {needle}")
    for needle in SLO_TEXT:
        if needle not in slo_text:
            fail(f"{SLO_GUIDE} missing required text: {needle}")
    for needle in DEBIAN_PROFILE_TEXT:
        if needle not in debian_profile_text:
            fail(f"{DEBIAN_PROFILE} missing required text: {needle}")
    for needle in RELEASE_GUIDE_TEXT:
        if needle not in release_text:
            fail(f"{RELEASE_GUIDE} missing required text: {needle}")
    cli_text = CLI_MAIN.read_text(encoding="utf-8")
    for env_name in sorted(set(re.findall(r'"(ODS_[A-Z0-9_]+)"\s*=>', cli_text))):
        if env_name not in text:
            fail(f"{GUIDE} missing documented environment override: {env_name}")
    print(f"Operator guide check passed: {GUIDE}")


if __name__ == "__main__":
    main()
