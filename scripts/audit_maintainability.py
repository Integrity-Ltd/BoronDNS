#!/usr/bin/env python3
"""Measure first-party production Rust and validate its architecture map."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys


MIN_LINES = 5_000
MAX_LINES = 15_000

MODULE_MAP = [
    ("crates/borondns-core/src/dns.rs", "DNS wire parsing, EDNS handling, and authoritative response construction"),
    ("crates/borondns-core/src/axfr.rs", "AXFR/IXFR query construction, transfer parsing, and zone publication validation"),
    ("crates/borondns-core/src/catalog.rs", "RFC 9432 catalog-zone schema and member parsing"),
    ("crates/borondns-core/src/config.rs", "static TOML configuration model and validation"),
    ("crates/borondns-core/src/tsig.rs", "TSIG signing, verification, and error response helpers"),
    ("crates/borondns-core/src/zone.rs", "memory-resident zone snapshots and lookup state"),
    ("crates/borondns-core/src/zone_image.rs", "immutable zone image, semantic lookup plans, and wire-section response construction"),
    ("crates/borondns-core/src/lib.rs", "core crate public API boundary"),
    ("crates/borondns-server/src/lib.rs", "runtime orchestration, catalog reconciliation, refresh scheduling, and NOTIFY/TSIG integration"),
    ("crates/borondns-server/src/udp.rs", "UDP listener and packet serving path"),
    ("crates/borondns-server/src/tcp.rs", "TCP listener, connection limits, and DNS-over-TCP framing"),
    ("crates/borondns-server/src/health_metrics.rs", "health endpoints, metrics rendering, and runtime counters"),
    ("crates/borondns-server/src/observability.rs", "in-process JSON observability/management API with bearer-token auth"),
    ("crates/borondns-server/src/rate_limit.rs", "RRL, notify log limiting, and packet response categorisation helpers"),
    ("crates/borondns-server/src/transfer.rs", "SOA polling, AXFR/IXFR transfer sessions, and XoT transport"),
    ("crates/borondns-server/src/transfer_plan.rs", "transfer target planning and primary rotation"),
    ("crates/borondns-server/src/secret_store.rs", "reloadable filesystem-backed TSIG/XoT secret store"),
    ("crates/borondns-server/src/dns_cookie.rs", "DNS Cookie secret and runtime settings helpers"),
    ("crates/borondns-server/src/config_validation.rs", "runtime configuration validation and warnings"),
    ("crates/borondns-server/src/runtime_status.rs", "runtime readiness/draining status model"),
    ("crates/borondns-server/src/shutdown.rs", "graceful shutdown and task draining helpers"),
    ("crates/borondns-server/src/errors.rs", "runtime and transfer error types"),
    ("crates/borondns-server/src/build_info.rs", "build metadata constants"),
    ("crates/borondns-server/src/af_xdp.rs", "feature-gated server AF_XDP packet-I/O adapter"),
    ("crates/borondns-server/src/std_udp_mmsg.rs", "standard UDP recvmmsg/sendmmsg batch adapter"),
    ("crates/borondns-server/src/std_udp_socket.rs", "standard UDP socket creation, reuseport, and CPU affinity adapter"),
    ("crates/borondns-server/src/privilege.rs", "audited POSIX privilege-drop FFI boundary"),
    ("crates/borondns-server/src/process_hardening.rs", "audited POSIX process-hardening FFI boundary"),
    ("crates/borondns-server/src/process_signals.rs", "audited POSIX signal disposition FFI boundary"),
    ("crates/borondns-server/src/resource_limits.rs", "audited POSIX file-descriptor limit FFI boundary"),
    ("crates/borondns-server/build.rs", "build metadata embedding for version and metrics labels"),
    ("crates/borondns-cli/src/main.rs", "command-line entrypoints"),
    ("crates/boron-gun/src/main.rs", "BoronGun load-generator CLI and portable UDP backend"),
    ("crates/boron-gun/src/xdp_backend.rs", "BoronGun lab-only AF_XDP backend"),
    ("crates/boron-gun-ebpf/src/lib.rs", "BoronGun lab-only XDP drop program"),
    ("crates/borondns-server-ebpf/src/lib.rs", "feature-gated BoronDNS XDP redirect program"),
    ("crates/boron-gen/src/lib.rs", "BoronGen public API boundary"),
    ("crates/boron-gen/src/main.rs", "BoronGen scenario and synthetic-primary CLI"),
    ("crates/boron-gen/src/scenario.rs", "deterministic bounded-memory zone and record generation"),
    ("crates/boron-gen/src/server.rs", "synthetic primary UDP/TCP service and transfer handling"),
    ("crates/boron-gen/src/wire.rs", "generated DNS response and AXFR wire encoding"),
]


class AuditError(RuntimeError):
    """The maintained evidence does not describe the production source tree."""


def is_test_only_source(path: Path) -> bool:
    return path.name == "tests.rs" or any(
        part == "tests" or part.endswith("_tests") for part in path.parts
    )


def discover_production_source_files(repo_root: Path) -> list[Path]:
    source_files = [
        path.relative_to(repo_root)
        for path in sorted((repo_root / "crates").glob("*/src/**/*.rs"))
        if not is_test_only_source(path.relative_to(repo_root))
    ]
    source_files.extend(
        path.relative_to(repo_root)
        for path in sorted((repo_root / "crates").glob("*/build.rs"))
    )
    return sorted(source_files)


def count_braces(line: str) -> int:
    return line.count("{") - line.count("}")


def production_lines(lines: list[str]) -> list[str]:
    """Exclude inline cfg(test) blocks from the SRS line-count measurement."""
    result: list[str] = []
    pending_cfg_test = False
    skip_depth: int | None = None

    for line in lines:
        stripped = line.strip()

        if skip_depth is not None:
            skip_depth += count_braces(line)
            if skip_depth <= 0:
                skip_depth = None
            continue

        if pending_cfg_test:
            if stripped.startswith("#["):
                continue
            depth = count_braces(line)
            pending_cfg_test = False
            if depth > 0:
                skip_depth = depth
            continue

        if stripped == "#[cfg(test)]":
            pending_cfg_test = True
            continue

        result.append(line)

    return result


def validate_module_map(
    source_files: list[Path], module_map: list[tuple[str, str]]
) -> None:
    discovered = {path.as_posix() for path in source_files}
    mapped = {path for path, _purpose in module_map}
    missing = sorted(discovered - mapped)
    stale = sorted(mapped - discovered)
    errors: list[str] = []
    if missing:
        errors.append("production source missing from module map: " + ", ".join(missing))
    if stale:
        errors.append("module-map entry is not production source: " + ", ".join(stale))
    if errors:
        raise AuditError("; ".join(errors))


def validate_architecture_module_map(
    architecture: str, module_map: list[tuple[str, str]]
) -> None:
    section_marker = "## Module Organisation"
    if section_marker not in architecture:
        raise AuditError("architecture is missing the Module Organisation section")
    section = architecture.split(section_marker, 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\| `([^`]+)` \|", section, flags=re.MULTILINE))
    mapped = {path for path, _purpose in module_map}
    missing = sorted(mapped - documented)
    stale = sorted(documented - mapped)
    errors: list[str] = []
    if missing:
        errors.append("architecture module mapping is missing entries: " + ", ".join(missing))
    if stale:
        errors.append("architecture module mapping has stale entries: " + ", ".join(stale))
    if errors:
        raise AuditError("; ".join(errors))


def audit(repo_root: Path) -> int:
    source_files = discover_production_source_files(repo_root)
    validate_module_map(source_files, MODULE_MAP)

    line_counts: list[tuple[Path, int]] = []
    total = 0
    for relative_path in source_files:
        path = repo_root / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise AuditError(f"failed to read Rust source as UTF-8: {relative_path}") from error
        count = len(production_lines(content.splitlines()))
        line_counts.append((relative_path, count))
        total += count

    if total < MIN_LINES:
        status = "under_target"
    elif total > MAX_LINES:
        status = "over_target"
    else:
        status = "within_target"

    print(f"first_party_rust_source_lines={total}")
    print(f"srs_target_min={MIN_LINES}")
    print(f"srs_target_max={MAX_LINES}")
    print(f"status={status}")
    print()
    print("per_file_lines:")
    for path, count in line_counts:
        print(f"  {path}: {count}")

    print()
    print("module_map:")
    for path, purpose in MODULE_MAP:
        print(f"  {path}: {purpose}")
    print()
    print(f"module_count={len(MODULE_MAP)}")

    architecture = (repo_root / "docs" / "architecture.md").read_text(encoding="utf-8")
    validate_architecture_module_map(architecture, MODULE_MAP)

    if status != "within_target":
        print()
        print(
            "warning=BDS-NFR-MAINT-001 line count is outside the 5,000-15,000 "
            "target; release review needs an architecture/release-note "
            "justification or a refactor plan"
        )
        required_rationale = "Current BDS-NFR-MAINT-001 over-target rationale"
        if required_rationale not in architecture:
            raise AuditError(
                "architecture missing current BDS-NFR-MAINT-001 over-target rationale"
            )
        if os.environ.get("BORONDNS_MAINT_ENFORCE") == "1":
            return 1
    return 0


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        return audit(repo_root)
    except (AuditError, OSError) as error:
        print(f"error={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
