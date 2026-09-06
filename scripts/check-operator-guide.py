#!/usr/bin/env python3
"""Check operator documentation coverage without prescribing its prose."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "operator-deployment-guide.md"
CONFIG_GUIDE = ROOT / "docs" / "configuration.md"
RECOVERY_GUIDE = ROOT / "docs" / "operator-recovery.md"
SLO_GUIDE = ROOT / "docs" / "operational-slos.md"
DEBIAN_PROFILE = ROOT / "docs" / "debian12-beta-vm-profile.md"
HEALTH_GUIDE = ROOT / "docs" / "health-metrics-interface.md"
OBSERVABILITY_GUIDE = ROOT / "docs" / "observability-api.md"
CLI_MAIN = ROOT / "crates" / "borondns-cli" / "src" / "main.rs"

# These are settings, commands, protocol names, and artifact identifiers that
# an operator must be able to find. Narrative wording and headings may change.
REQUIRED_TOPICS = {
    GUIDE: (
        "/etc/borondns-secondary/config.toml",
        "zone_cache_directory",
        "CAP_NET_BIND_SERVICE",
        "LimitNOFILE",
        "ICMP",
        "SIGTERM",
        "SIGHUP",
        "/readyz",
        "SOA",
        "Prometheus",
        "release-handoff.sha256",
        "release-handoff.sha256.sigstore.json",
        "--mount type=volume",
        "security@integrity.hu",
    ),
    CONFIG_GUIDE: (
        "BORONDNS_CONFIG",
        "health.bind_address",
        "health.bind_port",
        "health.default_port",
        "interfaces.mgmt",
        "interfaces.transfer",
        "[[zones]]",
        "primaries",
        "notify_sources",
        "tsig_key",
        "secret_file",
        "transfer_primaries",
        'transport = "xot"',
        "client_cert",
        "client_key",
        "[[catalog_zones]]",
        "allow-legacy-private",
        "DNSSEC",
        "secrets.toml",
        "rotate_tsig",
        "max_transfer_resident_bytes",
        "sharded_rrset_threshold",
    ),
    RECOVERY_GUIDE: (
        "BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP",
        "retained_removal_quarantine_N_parent_identity",
        "publication_recovery_root_identity",
        "publication_recovery_root_binding=journal-parent-directory",
        "_parent_root_relative",
        "device:inode:owner:type",
        "campaign_verify_retained_cleanup_journal",
        "cleanup_prepared_verified",
        "phase=prepared",
        "phase=retained",
    ),
    SLO_GUIDE: (
        "/readyz",
        "serial",
        "p99",
        "clock",
        "BDS-NFR-MAINT-009",
        "BDS-NFR-PERF-001",
        "BDS-NFR-REL-003",
    ),
    DEBIAN_PROFILE: (
        "Debian 12",
        "nftables",
        "docker load",
        "--network host",
        "--cap-add NET_BIND_SERVICE",
        "--cap-add SETUID",
        "--cap-add SETGID",
        "run_as_user",
        "--mount type=volume",
        "base_image_digest",
    ),
    HEALTH_GUIDE: (
        "/livez",
        "/readyz",
        "/healthz",
        "/metrics",
        "health.max_connections",
        "metrics.hot_path_detail",
        "borondns_secondary_zone_soa_serial",
        "Retry-After",
    ),
    OBSERVABILITY_GUIDE: (
        "bearer_token_file",
        "include_zone_detail",
        "zone_not_found",
        "not_tracked",
        "unknown",
        "metrics_detail",
        "schema_version",
    ),
}


def fail(message: str) -> None:
    print(f"Operator guide check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def markdown_targets(text: str) -> set[str]:
    return set(re.findall(r"\]\(([^\s)]+)\)", text))


def main() -> None:
    documents = {}
    for path, markers in REQUIRED_TOPICS.items():
        text = path.read_text(encoding="utf-8")
        documents[path] = text
        for marker in markers:
            if marker not in text:
                fail(f"{path.relative_to(ROOT)} missing topic: {marker}")

    # Splitting reference material out of the deployment guide is deliberate.
    # Require working entry points rather than duplicating its contents there.
    guide_targets = {
        target.split("#", 1)[0]
        for target in markdown_targets(documents[GUIDE])
    }
    for filename in (
        "configuration.md",
        "operator-recovery.md",
        "health-metrics-interface.md",
        "observability-api.md",
        "operational-slos.md",
        "debian12-beta-vm-profile.md",
        "release-evidence-guide.md",
        "implemented-feature-scope.md",
    ):
        if filename not in guide_targets:
            fail(f"operator guide missing link to {filename}")
        if not (GUIDE.parent / filename).is_file():
            fail(f"operator guide links to missing {filename}")

    # Derive the exhaustive override set from the CLI, not a second hand-kept
    # catalogue. Each must be documented in the linked configuration guide.
    cli_text = CLI_MAIN.read_text(encoding="utf-8")
    env_names = sorted(set(re.findall(r'"(BORONDNS_[A-Z0-9_]+)"\s*=>', cli_text)))
    if not env_names:
        fail("no CLI environment overrides found; extraction needs review")
    for env_name in env_names:
        if env_name not in documents[CONFIG_GUIDE]:
            fail(f"configuration guide missing environment override: {env_name}")
    print(
        f"Operator guide check passed: {len(documents)} linked guides; "
        f"{len(env_names)} CLI overrides documented"
    )


if __name__ == "__main__":
    main()
